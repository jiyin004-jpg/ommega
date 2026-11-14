//! SOTER 宿主「起来了但是哑的」的体检。
//!
//! 判据全部来自宿主自己的观测（[`observe`]）：一个窗口（[`WINDOW`]）内 App 侧调用 ≥
//! [`MIN_APP_OPS`]、其中至少 [`MIN_MUTATIONS`] 笔 `mutation=1`，而 HAL 侧一笔都没有，
//! 就判它哑了。`getVersion` / `getExtraParam` 这类不碰 HAL 的调用不计入。
//!
//! daemon 跑在 keystore uid，杀不动 system 域的宿主，所以只写 [`STUCK_PATH`] 让 root
//! 启动器去重启宿主；[`STATUS_PATH`] 是每窗口一份的计数，日志关掉时靠它排查。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;

/// 统计窗口的长度。一次开通流程两三秒就能打出十几笔调用，30 秒足够攒够证据。
const WINDOW: Duration = Duration::from_secs(30);
/// 窗口里至少要看到的 App 侧调用笔数（`getVersion` / `getExtraParam` 不算）。
const MIN_APP_OPS: u64 = 2;
/// 其中至少要有这么多笔 `mutation=1` 的：这是「必然到 HAL」的那一类，误判风险最低。
const MIN_MUTATIONS: u64 = 1;
/// 两次报「哑了」的最短间隔：已换过实例仍哑说明另有原因，不必频繁重启。
const REPEAT_COOLDOWN: Duration = Duration::from_secs(600);
/// 体检线程的节拍，比窗口（[`WINDOW`]）密得多，窗口靠它来关。
const TICK: Duration = Duration::from_secs(5);

/// 判出「哑了」时写的标记文件。启动器读一行、删掉、然后把宿主重启。
const STUCK_PATH: &str = crate::root_path!("soter_host_stuck");
/// 每个窗口写一份的计数，纯排查用（日志关着时也能看）。
const STATUS_PATH: &str = crate::root_path!("soter_host_health");

/// 一条观测的归类。字段与 payload 里 `log_call` 拼出的那行严格对应：
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
    // 前缀 `side=hal` 同时盖住 `side=hal-hidl`，两种 HAL 实现走同一条判断。
    if message.contains("side=hal") {
        return Some(Sample::Hal);
    }
    if !message.contains("side=app") {
        return None;
    }
    // App 面向那两条不碰 HAL：问版本、问额外参数宿主自己就能答，而 App 会反复轮询，
    // 算进去就是纯误伤。
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

/// 一个窗口的结论。计数原样带出来（写状态文件用），`mute` 才表示要去重启宿主。
#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    app: u64,
    hal: u64,
    mutations: u64,
    mute: bool,
}

/// 窗口够长了就算一次并返回结论，还没到点返回 `None`。
/// `mute` 只在「够格且不在冷却里」时为真。
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
/// 结算必须按时间自己跑，不能挂在观测上：空闲时窗口永远不关，而哑窗口等到下一笔观测
/// （可能已是恢复后的健康流量）才结算就会漏判。`observe` 只记数，结算全在这里。
pub fn start() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("soter-health".to_string())
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
/// 文件操作全在拿锁之外做；写不动只记日志，顶多自愈不生效，不影响别的。
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
/// 0644 让 root 的启动器读得到，写法与 `soter_cpu_id` 那份镜像一致。
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

    /// 真实观测行的形状，分类必须跟着它走。
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

    /// 不走 HAL 的两条不准算：App 轮询不停，算进去会误判健康宿主。
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

    /// 健康的窗口：HAL 侧有东西，这是常态。
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

    /// 换过一次仍哑：冷却期内不再报，到期才再报一次。
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
