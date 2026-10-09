//! SOTER 宿主「起来了，但是哑的」的体检。
//!
//! 现象（实测 nubia NX721J，2026-10-09）：开机起来的那份 `com.tencent.soter.soterserver`
//! 收得到 App 侧的 SOTER 调用，却**一笔都不往 SOTER HAL 发** —— 它自己的 HAL 客户端是死的。
//! A 端的接管挂在「宿主发往 HAL 的那笔出站事务」上（payload 的
//! `hook/intercept/ioctl/write.rs`），它不发，就等于整条链断在宿主里：App 那边一直报
//! 「系统错误，可删除系统指纹，重新录入后再试」，而 daemon 这边看起来一切正常 —— 进程在、
//! 载荷也注进去了、每次载荷起来那个开机自检还能转发成功。只有把宿主换成新实例才会好。
//!
//! 判据只能靠宿主自己报上来的观测（[`observe`]）：payload 的 `log_call` 每观察一笔 SOTER
//! 调用，就顺 RPC 递给 `IMaintenanceService::reportHookEvent`，**跟 WebUI 的「启用调试日志」
//! 开关无关**（那个开关关着时 daemon 一个 sink 都不写，所以这条路不能读日志）。一个窗口里
//! 同时满足：
//!
//! * App 侧（`side=app`）调用 ≥ [`MIN_APP_OPS`]，其中至少 [`MIN_MUTATIONS`] 笔带 `mutation=1`
//!   —— 建 ASK/AuthKey、删钥匙这类**必然**要动 HAL 的东西，宿主缓存不掉；
//! * HAL 侧（`side=hal` / `side=hal-hidl`）一笔都没有。
//!
//! 那就是哑了。daemon 不去动进程：它跑在 keystore uid，杀不动 system 域的宿主。它把结论写进
//! [`STUCK_PATH`]，由 root 的启动器 `daemon-injector` 读走、重启宿主（那份脚本里
//! `SOTER_STUCK_FILE` 一段）。顺手写一份 [`STATUS_PATH`] 供排查：日志关着的时候，
//! 这两个文件是唯一看得见计数的地方。
//!
//! 反过来也要小心别误伤：健康的宿主每笔 App 侧调用都会带出至少一笔 HAL 侧事务，所以正常
//! 窗口里 `hal` 一定不为 0；而 `getVersion` / `getExtraParam` 这种根本不碰 HAL 的调用单独
//! 剔掉 —— App 能把它们轮询一天，拿它们当证据就是把好宿主踢掉。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;

/// 一个统计窗口的长度。判断节拍按下限来算：App 一次开通流程（微信那种）两三秒里就能打出
/// 十几笔调用，30 秒足够攒够证据，也不至于让用户干等太久。
const WINDOW: Duration = Duration::from_secs(30);
/// 窗口里至少要看到的 App 侧调用笔数（`getVersion` / `getExtraParam` 不算）。
const MIN_APP_OPS: u64 = 2;
/// 其中至少要有这么多笔 `mutation=1` 的：这是「必然到 HAL」的那一类，误判风险最低。
const MIN_MUTATIONS: u64 = 1;
/// 两次报「哑了」之间的最短间隔。已经踢过一次还是哑的，说明不是这个原因，
/// 那就每 10 分钟试一次，别把宿主当开关按。
const REPEAT_COOLDOWN: Duration = Duration::from_secs(600);
/// 体检线程的节拍。窗口（[`WINDOW`]）靠它来关，所以它得比窗口密得多。
const TICK: Duration = Duration::from_secs(5);

/// 判出「哑了」时写的标记文件。启动器读一行、删掉、然后把宿主重启。
const STUCK_PATH: &str = crate::root_path!("soter_host_stuck");
/// 每个窗口写一份的计数，纯排查用（日志关着时也能看）。
const STATUS_PATH: &str = crate::root_path!("soter_host_health");

/// 一条观测归哪一类。字段跟 payload 里 `log_call` 拼出来的那行严格对应：
/// `event=soter side=<app|hal|hal-hidl> code=N op=NAME uid=… bytes=N[ mutation=1]…`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sample {
    Hal,
    App { mutation: bool },
}

/// 按一行观测归类。不是 SOTER 观测、或者是不走 HAL 的那些，返回 `None`。
fn classify(message: &str) -> Option<Sample> {
    if !message.contains("event=soter ") {
        return None;
    }
    // `side=hal` 这一条同时盖住 `side=hal-hidl`：HIDL 那几家（trustonic / 小米）走的
    // 是同一个判断。
    if message.contains("side=hal") {
        return Some(Sample::Hal);
    }
    if !message.contains("side=app") {
        return None;
    }
    // App 面向那两个不走 HAL 的：问版本、问额外参数都是宿主自己就能答的，
    // 而且 App 会反复轮询，拿它们当「哑了」的证据是纯误伤。
    if message.contains(" op=getVersion ") || message.contains(" op=getExtraParam ") {
        return None;
    }
    Some(Sample::App {
        mutation: message.contains(" mutation=1"),
    })
}

/// 一个窗口里数出来的东西。
#[derive(Default, Debug)]
struct Window {
    app: u64,
    hal: u64,
    mutations: u64,
}

impl Window {
    fn record(&mut self, sample: Sample) {
        match sample {
            Sample::Hal => self.hal += 1,
            Sample::App { mutation } => {
                self.app += 1;
                if mutation {
                    self.mutations += 1;
                }
            }
        }
    }
}

struct State {
    window: Window,
    start: Instant,
    last_report: Option<Instant>,
}

/// 一个窗口的结论。计数原样带出来（写状态文件用），`mute` 才是「去把宿主踢了」。
#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    app: u64,
    hal: u64,
    mutations: u64,
    mute: bool,
}

/// 窗口够长了就算一次，返回结论；还没到点返回 `None`。
///
/// `mute` 只在「够格 + 不在冷却里」才为真 —— 冷却本身就是「已经踢过一次了」的意思。
fn judge(state: &mut State, now: Instant) -> Option<Verdict> {
    if now.saturating_duration_since(state.start) < WINDOW {
        return None;
    }
    let window = std::mem::take(&mut state.window);
    state.start = now;
    let eligible =
        window.hal == 0 && window.app >= MIN_APP_OPS && window.mutations >= MIN_MUTATIONS;
    let cooled = state
        .last_report
        .is_none_or(|at| now.saturating_duration_since(at) >= REPEAT_COOLDOWN);
    let mute = eligible && cooled;
    if mute {
        state.last_report = Some(now);
    }
    Some(Verdict {
        app: window.app,
        hal: window.hal,
        mutations: window.mutations,
        mute,
    })
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();
static STARTED: AtomicBool = AtomicBool::new(false);

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| {
        Mutex::new(State {
            window: Window::default(),
            start: Instant::now(),
            last_report: None,
        })
    })
}

/// 起体检线程（幂等）。
///
/// **结算必须自己按时间跑，不能挂在观测上**：一开始把 `judge` 摆在 [`observe`] 里，实测两个
/// 问题 —— 空闲时窗口永远不关，健康度文件根本不出现；更要命的是哑窗口会等到**下一笔**观测才
/// 结算，而下一笔已经是恢复后的健康流量（带着 hal 侧）时，那个哑窗口就被判成不哑，真出事反而
/// 漏判。现在 `observe` 只记数，结算全交给这个线程。
pub fn start() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("ommega-soter-health".to_string())
        .spawn(|| loop {
            std::thread::sleep(TICK);
            let verdict = {
                let mut state = state()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                judge(&mut state, Instant::now())
            };
            if let Some(verdict) = verdict {
                report(verdict);
            }
        });
    if let Err(error) = spawned {
        STARTED.store(false, Ordering::SeqCst);
        log::warn!("soter host health thread did not start: {error}");
    }
}

/// 记一笔观测。由 `IMaintenanceService::reportHookEvent` 调用，跑在 binder 线程上，
/// 所以这里只做整数累加，不碰文件、不做判断。
pub fn observe(message: &str) {
    let Some(sample) = classify(message) else {
        return;
    };
    let mut state = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.window.record(sample);
}

/// 结算一个窗口：先把计数写进健康度文件，判出哑了再写标记。
///
/// 文件操作全在拿锁之外做：这里是体检线程，不是热路径。写不动只记日志 —— 顶多自愈不生效，
/// 不该影响别的。
fn report(verdict: Verdict) {
    if let Err(error) = write_mirror(
        STATUS_PATH,
        &format!(
            "soter_host_health: app={} hal={} mutation={} window={}s\n",
            verdict.app,
            verdict.hal,
            verdict.mutations,
            WINDOW.as_secs()
        ),
    ) {
        log::debug!("soter host health could not be written to {STATUS_PATH}: {error:#}");
    }

    if !verdict.mute {
        return;
    }
    log::warn!(
        "SOTER 宿主像是哑了：{} 秒里收了 {} 笔 App 侧调用（其中 {} 笔建/删料），一笔都没到 HAL —— 让启动器把它换成新实例",
        WINDOW.as_secs(),
        verdict.app,
        verdict.mutations
    );
    let body = format!(
        "SOTER 宿主哑了：{}s 窗口里 {} 笔 App 侧调用（{} 笔建/删料）、0 笔 HAL 侧 —— 换成新实例\n",
        WINDOW.as_secs(),
        verdict.app,
        verdict.mutations
    );
    if let Err(error) = write_mirror(STUCK_PATH, &body) {
        log::warn!("{STUCK_PATH} 写不进去（自愈这条就断了）：{error:#}");
    }
}

/// 先写临时文件再 rename，读的一方永远读不到半截；内容没变不动文件。
///
/// 跟 `soter_cpu_id` 那份一个写法（同一个约定：keystore 域写的镜像放 `/data/misc/keystore/ommega/`，
/// 0644 让 root 的启动器读得到）。
fn write_mirror(path: &str, body: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    if std::fs::read_to_string(path).ok().as_deref() == Some(body) {
        return Ok(());
    }
    let tmp = format!("{path}.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 线上真实形状的几行（nubia NX721J 上微信开通那一次抓的），分类得跟它们走。
    fn app_line(op: &str) -> String {
        format!(
            "event=soter side=app code=8 op={op} uid=10490 alias=\"SoterAuthKeyV2_salt11d8ba34_scene1\" session=None challenge_len=0 key=\"\" bytes=184"
        )
    }

    #[test]
    fn both_hal_flavours_count_as_hal() {
        assert_eq!(
            classify("event=soter side=hal code=10 op=hasAuthKey uid=10490 bytes=164"),
            Some(Sample::Hal)
        );
        assert_eq!(
            classify(
                "event=soter side=hal-hidl code=12 op=hasAuthKey uid=10490 bytes=164 wire_code=12"
            ),
            Some(Sample::Hal)
        );
    }

    #[test]
    fn app_lines_count_and_mutations_are_flagged() {
        let line = format!(
            "{} mutation=1 caller_uid=10490",
            app_line("generateAuthKey")
        );
        assert_eq!(
            classify(&line),
            Some(Sample::App { mutation: true }),
            "建料那笔要标出来"
        );
        assert_eq!(
            classify(&app_line("hasAuthKey")),
            Some(Sample::App { mutation: false })
        );
    }

    /// 不走 HAL 的两条不准算：App 轮询起来一天不停，算进去就是把好宿主踢掉。
    #[test]
    fn the_two_local_only_app_ops_are_ignored() {
        assert_eq!(classify(&app_line("getVersion")), None);
        assert_eq!(classify(&app_line("getExtraParam")), None);
    }

    /// 别的观测（日志自述、binder 诊断）不能掺进来。
    #[test]
    fn unrelated_reports_are_ignored() {
        assert_eq!(
            classify("event=logging role=Payload path=/x enabled=true"),
            None
        );
        assert_eq!(
            classify("event=binder unknown-descriptor token=\"x\" code=1 uid=0 bytes=8"),
            None
        );
    }

    fn window(app: u64, hal: u64, mutations: u64) -> Window {
        Window {
            app,
            hal,
            mutations,
        }
    }

    /// 哑的判据：有 App 侧、有建料、HAL 侧一笔没有。
    #[test]
    fn a_mute_window_is_app_ops_with_a_mutation_and_no_hal() {
        let mut state = State {
            window: window(14, 0, 3),
            start: Instant::now() - WINDOW - Duration::from_secs(1),
            last_report: None,
        };
        let verdict = judge(&mut state, Instant::now()).expect("窗口早过了");
        assert!(verdict.mute);
        assert_eq!((verdict.app, verdict.hal, verdict.mutations), (14, 0, 3));
        assert_eq!(state.window.app, 0, "判完要清窗口");
        assert!(state.last_report.is_some(), "报过就要进冷却");
    }

    /// 健康的窗口：HAL 侧有东西。这是常态（实测那一次是 app=14 / hal=32）。
    #[test]
    fn a_healthy_window_is_never_mute() {
        for (app, hal, mutations) in [(14u64, 32u64, 3u64), (2, 1, 1), (30, 60, 5)] {
            let mut state = State {
                window: window(app, hal, mutations),
                start: Instant::now() - WINDOW - Duration::from_secs(1),
                last_report: None,
            };
            let verdict = judge(&mut state, Instant::now()).expect("窗口早过了");
            assert!(!verdict.mute, "app={app} hal={hal} 不该判哑");
        }
    }

    /// 只有读调用（没有建料）不判：还没到「必然要动 HAL 却不动」那一步。
    #[test]
    fn reads_without_a_mutation_do_not_convict() {
        let mut state = State {
            window: window(9, 0, 0),
            start: Instant::now() - WINDOW - Duration::from_secs(1),
            last_report: None,
        };
        assert!(!judge(&mut state, Instant::now()).unwrap().mute);
    }

    /// 窗口没到点什么都不判。
    #[test]
    fn a_short_window_waits() {
        let mut state = State {
            window: window(9, 0, 9),
            start: Instant::now(),
            last_report: None,
        };
        assert!(judge(&mut state, Instant::now()).is_none());
        assert_eq!(state.window.app, 9, "没到点不能清窗口");
    }

    /// 踢过一次还没好：冷却里不再报（不然就把宿主当开关按了），到期才再报一次。
    #[test]
    fn the_second_report_waits_for_the_cooldown() {
        let now = Instant::now();
        let mut state = State {
            window: window(5, 0, 2),
            start: now - WINDOW - Duration::from_secs(1),
            last_report: Some(now),
        };
        assert!(!judge(&mut state, now).unwrap().mute, "刚踢过就别再踢");

        let later = now + REPEAT_COOLDOWN + Duration::from_secs(1);
        state.window = window(5, 0, 2);
        state.start = later - WINDOW - Duration::from_secs(1);
        assert!(judge(&mut state, later).unwrap().mute, "过了冷却要再试");
    }

    #[test]
    fn the_mirror_is_written_atomically_and_only_when_it_changes() {
        let dir = std::env::temp_dir().join(format!("ommega-soter-health-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("soter_host_health");
        let path = path.to_str().unwrap().to_string();

        write_mirror(
            &path,
            "soter_host_health: app=1 hal=0 mutation=1 window=30s\n",
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "soter_host_health: app=1 hal=0 mutation=1 window=30s\n"
        );
        let first = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        write_mirror(
            &path,
            "soter_host_health: app=1 hal=0 mutation=1 window=30s\n",
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            first,
            "内容没变就别动文件"
        );
        write_mirror(
            &path,
            "soter_host_health: app=2 hal=0 mutation=1 window=30s\n",
        )
        .unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("app=2"));
        assert!(
            std::fs::metadata(format!("{path}.tmp")).is_err(),
            "临时文件要被 rename 掉"
        );
    }
}
