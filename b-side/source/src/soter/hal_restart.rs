//! SOTER HAL 半死状态的自愈：连着几次失败就把这个服务重启一次。
//!
//! 背景（PLC110 2026-09-30 实测）：HAL 会进一种半死状态 —— 建料类的 op
//! （`generate_auth_key_pair` / `has_auth_key` / `export_auth_key_public_key`）
//! 全都正常，只有走 TEE 会话的 `init_sign` 恒回 -18
//! （`SOTER_ERROR_SECURE_HW_COMMUNICATION_FAILED`）。进程还活着、也不是 D 状态，
//! 重启这个服务就好（实测 `setprop ctl.restart soter_hal`，旧 pid 退掉、init 拉新的）。
//!
//! 但要分清两种坏法（2026-10-02 补）：
//!
//! - **HAL 进程半死**：`init_sign` 恒回 -18 —— 重启这个服务有效。
//! - **TA 状态卡死在 TEE 里**：`init_sign` 回 0、`finish_sign` 恒回 258（0x102）。
//!   用户态怎么重启服务都没用（2026-10-02 现场试了 3 次，pid 18055→27813→31557
//!   全无效），**只有重启整台设备**才修得好。这一档自愈治不了，但至少不该去白杀
//!   进程 —— 判据别被 `init_sign` 的成功糊弄。
//!
//! 不收拾的后果是实打实的：服务端会按「这台结构性做不了」把这个槽位换到自签那两层，
//! App 手里变成假料，拿到的还是个误导性的 -5（「这把钥匙不在」）—— Duck Detector
//! 就是这么报 soter damaged 的，微信那边整轮开启都拿不到真材料。
//!
//! 计数规则（2026-10-02 改）：
//!
//! - **阈值 2**：一次失败可能只是偶然撞上，连着两次就动手，先把 HAL 拉回来再说。
//! - **凡非 0 都算**，只有几个「正常业务答复」不算：-5 / -6 / -8（这个槽位还没建料，
//!   新装的 App 天天问）、-26（这会儿没人按指纹）、-204（会话句柄已被顶掉）、
//!   -65528（这台机器上这个 uid 本来就没料）。剩下的 -12/-13/-18/-20、258
//!   以及一切没见过的码，都是「这台现在真做不了」，一律计入。
//! - **清零只认 `finish_sign` 的成功**。半死状态下不仅建料类 op 照样成功，
//!   **`init_sign` 也照样回 0** —— 只有 `finish_sign` 会回 258。以前把 init_sign
//!   也算「通道好」，结果探针每轮 init_sign(0) 都把计数清掉，PLC110 从 06:44
//!   坏到 09:28，自愈一次都没触发过。
//! - 冷却照旧：刚重启过就先不动，免得 HAL 真坏的时候每一笔都去 kill 一遍。
//!
//! 冷却用 `Instant`（单调钟，不含 suspend）就够 —— 它是防抖，不是精确调度。

use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 连着几次算结构性故障。
const FAILURE_LIMIT: u32 = 2;
/// 两次重启之间的最短间隔。
const RESTART_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// 正常的业务答复，不参与计数：这个槽位还没建料（-5 ASK / -6 AuthKey / -8）、
/// 这会儿没人按指纹（-26）、会话句柄已经被顶掉了（-204）、
/// 这台机器上这个 uid 本来就没料（-65528）。
///
/// -8 是 2026-10-01 从生产日志里量出来的：40k 行里有 657 次，全是建料类 op
/// （`has_auth_key` / `export_auth_key_public_key`），是 `-5` 同一种「还没准备」的意思。
/// 不排掉它的话，App 每查几回就把阈值顶满。
///
/// -204（`OPERATEID_NULL`，会话句柄无效）是 2026-10-02 在 PLC110 上翻的案：
/// 它是 TA 侧会话被别人顶掉的意思，**重启 SOTER HAL 根本修不了**，只会白丢材料
/// —— 那天自愈正是被它连触两次，把好端端的 18055 kill 掉又毫无用处。
///
/// -65528（`TEE_ERROR_ITEM_NOT_FOUND`）同日对照量出来的：在**健康**设备上一样
/// 大量出现（重启后的正常态里 `TEE_GenerateASKPair` 就回了 40 次），和 -5 是
/// 同一种「这个 uid 没建过料」。所以别按 `0xFFFFxxxx` 段一刀切，会误伤。
const BENIGN_CODES: &[i64] = &[-5, -6, -8, -26, -204, -65528];

/// 只有真签出东西来才说明通道是好的。
///
/// 2026-10-02 定案：TA 状态卡死时不仅建料类 op 正常，**`init_sign` 也照样回 0**，
/// 只有 `finish_sign` 恒回 258。所以「init_sign 成功 = 通道好」是错的。
fn proves_channel_works(op: &str) -> bool {
    matches!(op, "finish_sign")
}

/// 候选服务名：各家 HAL 在 init 里注册的名字不一样，`getprop init.svc.<名字>` 有值的
/// 那个才算（PLC110 上是 `soter_hal`，rc 文件名反而是 `vendor.trustonic.soter@1.0-service.rc`，
/// 拿文件名去 `ctl.restart` 会被拒）。
const SERVICE_CANDIDATES: &[&str] = &[
    "soter_hal",
    "android.hardware.soter@1.0-service",
    "vendor.qti.hardware.soter@1.0-service",
    "vendor.trustonic.soter@1.0-service",
    "vendor.trustonic.soter-1-0",
    "vendor.xiaomi.hardware.soterservice@1.0-service",
    "soter-1-0",
];

/// Exact executable basenames only; init service names are a separate list.
const HAL_PROCESS_CANDIDATES: &[&str] = &[
    "soter_hal",
    "android.hardware.soter@1.0-service",
    "vendor.qti.hardware.soter-service",
    "vendor.qti.hardware.soter@1.0-service",
    "vendor.trustonic.soter@1.0-service",
    "vendor.xiaomi.hardware.soterservice@1.0-service",
    "vendor.microtrust.hardware.soter@1.0-service",
];

static FAILURES: Mutex<u32> = Mutex::new(0);
static LAST_RESTART: Mutex<Option<Instant>> = Mutex::new(None);

/// TA 卡在 TEE 里的证据码：`258`（读 anti-rollback 计数器失败）。
///
/// 2026-10-03 在 PLC110 上挖到底了：Trustonic 的 `tlTeeSOTER`（TA 镜像
/// `/odm/vendor/app/mcRegistry/070f0000000000000000000000000a0a.tlbin`）把 RPMB
/// session 3 打开之后不放手 —— dmesg 里 `rpmb session 3 is already opened by
/// 070f0000-...-a0a0` 449/449 全是它自己，`Open session failed crSession =
/// 0xffffffff` 452 次，`EXPORT_PUB_KEY read counter failed (258)` 451 次。TA 从此
/// 读不到自己的持久存储，对外就是一大片 `-5`（说存在却导不出来、也建不了）加上
/// `258`。
///
/// 这一档上面所有手段都是无效的，两轮实测都验过：2026-10-02 重启 HAL 进程
/// （pid 18055→27813→31557），2026-10-03 直接 kill SOTER HAL 服务（持有者在 TEE
/// 里，叫它松手根本不听）。**只有重启整机能松开。**
const TEE_WEDGE_CODE: i64 = 258;
/// 攒到这么多才认「卡住了」。卡住时 15 分钟里就有 138 条 258，两次很容易到；
/// 而健康设备上这个码不该出现。
const WEDGE_LIMIT: u32 = 2;
/// 两次自动重启之间至少隔这么久。
const REBOOT_COOLDOWN: Duration = Duration::from_secs(6 * 3600);
/// 24 小时内最多自动重启几次。到顶就只上报（caps 里的 `soter_stuck`），不再动手
/// —— 那是「重启也修不好」的最终态，不能变成无限重启循环。
const REBOOT_MAX_PER_DAY: usize = 3;
/// 开机后多久才允许自动重启。刚起来又卡的话，这就是防重启循环的第一道闸。
const REBOOT_BOOT_GRACE: Duration = Duration::from_secs(15 * 60);

static WEDGE_SIGNALS: Mutex<u32> = Mutex::new(0);
static LAST_SELF_REBOOT: Mutex<Option<Instant>> = Mutex::new(None);
/// 现在是「卡住了、而且我们没能把它重启掉」：对外报 `soter_stuck` 就是用这个。
static WEDGE_UNRESOLVED: Mutex<bool> = Mutex::new(false);

/// 自动重启的记账文件。**必须落盘**：重启会把内存清空，只有文件能跨重启记住
/// 「今天已经重启过几次」，否则 24 小时上限形同虚设。
fn reboot_log_path() -> PathBuf {
    PathBuf::from("/data/adb/ommega/self-reboot.log")
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 一笔真活的结果。非 0 且不属于 `BENIGN_CODES` 的累加，够了就重启一次 HAL；
/// TEE 会话 op 成功清零；其余一概不碰。
///
/// `258` 单独走一条路：它说明卡住的是 TEE 里那个 TA，重启用户态服务治不了，
/// 得往上抬一级（重启整机，见 `try_self_reboot`）。
pub fn note(op: &str, error_code: i64) {
    if error_code == TEE_WEDGE_CODE {
        let signals = {
            let mut guard = lock(&WEDGE_SIGNALS);
            *guard += 1;
            *guard
        };
        if signals >= WEDGE_LIMIT {
            *lock(&WEDGE_SIGNALS) = 0;
            try_self_reboot(op, signals);
        }
        return;
    }
    let count_before = *lock(&FAILURES);
    let since_restart = lock(&LAST_RESTART).map(|at| at.elapsed());
    let (count, verdict) = step(op, error_code, count_before, since_restart);
    *lock(&FAILURES) = count;
    match verdict {
        // 真签出东西来 = 连存储一起好了：把「卡住」的牌子摘掉。
        Verdict::Reset => *lock(&WEDGE_UNRESOLVED) = false,
        Verdict::Nothing => {}
        Verdict::Cooling => log::warn!(
            "soter: 连续 {count} 次失败（op={op} code={error_code}），但距上次重启才 {:.0}s，先不动 HAL",
            since_restart.map(|d| d.as_secs_f64()).unwrap_or_default()
        ),
        Verdict::Restart => match restart_soter_hal() {
            Ok(what) => {
                log::warn!(
                    "soter: 连续 {count} 次失败（op={op} code={error_code}），重启 SOTER HAL：{what}"
                );
                *lock(&LAST_RESTART) = Some(Instant::now());
                *lock(&FAILURES) = 0;
            }
            Err(error) => {
                // 没重启成就不记冷却，下一笔再试（顺手把计数留在这儿，日志能看出次数）。
                log::warn!("soter: 连续 {count} 次失败，想重启 SOTER HAL 但没成功：{error}");
            }
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// 计数动了（或者没动），但什么都不做。
    Nothing,
    /// 通道证明是好的：计数清零。
    Reset,
    /// 该重启了。
    Restart,
    /// 攒够了，但在冷却期里。
    Cooling,
}

/// 对外上报：这台现在是不是「TA 卡在 TEE 里、而且没能重启掉」。
///
/// 只有「卡住 + 现在动不了手」（次数到顶、开机宽限期里、或者重启命令失败）才为真
/// —— 那正是操作员需要看见、需要手动接管的那个状态。
pub fn tee_wedged() -> bool {
    *lock(&WEDGE_UNRESOLVED)
}

/// 自动重启的最终判定。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RebootVerdict {
    /// 该重启了。
    Reboot,
    /// 距上次重启还太近（`Instant` 只活在内存里，所以这条只管「没重启过」的会话）。
    TooSoon,
    /// 24 小时的上限用完了：只上报，不再动手。
    DailyCap,
    /// 开机还没多久：先不动手，免得变成重启循环。
    Booting,
}

/// 纯判定，拆出来是为了能直接测（不碰设备、不抢 static）。
fn reboot_verdict(already: usize, uptime: Duration, since_last: Option<Duration>) -> RebootVerdict {
    if already >= REBOOT_MAX_PER_DAY {
        return RebootVerdict::DailyCap;
    }
    if uptime < REBOOT_BOOT_GRACE {
        return RebootVerdict::Booting;
    }
    match since_last {
        Some(age) if age < REBOOT_COOLDOWN => RebootVerdict::TooSoon,
        _ => RebootVerdict::Reboot,
    }
}

/// TA 卡在 TEE 里时的最后一招：重启整机。
///
/// 刹车三道：开机宽限期（刚起来又卡就先不动）、6 小时间隔、24 小时最多 3 次。
/// 任何一道拦住、或者重启命令没跑成，都把 `WEDGE_UNRESOLVED` 立起来对外上报
/// —— 不吭声就 reboot 完了，操作员只会看到设备反复掉线却不知道为什么。
fn try_self_reboot(op: &str, signals: u32) {
    let uptime_secs = uptime().as_secs();
    let already = reboots_last_day();
    let since_last = lock(&LAST_SELF_REBOOT).map(|at| at.elapsed());
    let verdict = reboot_verdict(already, Duration::from_secs(uptime_secs), since_last);
    if verdict != RebootVerdict::Reboot {
        *lock(&WEDGE_UNRESOLVED) = true;
    }
    match verdict {
        RebootVerdict::Reboot => {
            // 先记账再动手：`reboot` 一执行这台机器就下去了，`run()` 不一定回来得及。
            // 反过来说，万一没重启成，也只是把一次假的算进今天的额度（宁可少重启，
            // 不要多。）
            record_self_reboot();
            match reboot_device() {
                Ok(what) => {
                    *lock(&LAST_SELF_REBOOT) = Some(Instant::now());
                    log::error!(
                        "soter: TA 卡在 TEE 里（{signals} 笔 {TEE_WEDGE_CODE}，最后一笔 op={op}），\
                         用户态救不回来，重启整机：{what}（今天第 {} 次）",
                        already + 1
                    );
                }
                Err(error) => {
                    *lock(&WEDGE_UNRESOLVED) = true;
                    log::error!(
                        "soter: TA 卡在 TEE 里（{signals} 笔 {TEE_WEDGE_CODE}），\
                         想重启整机但没成功：{error}"
                    );
                }
            }
        }
        RebootVerdict::TooSoon => log::error!(
            "soter: TA 又卡在 TEE 里了（{signals} 笔 {TEE_WEDGE_CODE}），\
             但距上次自动重启才 {:.0}s，先不动手（已上报 soter_stuck）",
            since_last.map(|d| d.as_secs_f64()).unwrap_or_default()
        ),
        RebootVerdict::DailyCap => log::error!(
            "soter: TA 卡在 TEE 里（{signals} 笔 {TEE_WEDGE_CODE}），今天已经自动重启过 {already} 次，\
             不再重启 —— 重启也修不好的话需要人工介入（已上报 soter_stuck）"
        ),
        RebootVerdict::Booting => log::error!(
            "soter: 开机才 {uptime_secs}s 就见到 {TEE_WEDGE_CODE}（{signals} 笔，op={op}），\
             不动手重启，免得进重启循环（已上报 soter_stuck）"
        ),
    }
}

/// 开机时长。读不到就回 0 —— 那样判定落在 `Booting`，宁可不重启。
fn uptime() -> Duration {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|text| {
            text.split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .filter(|secs| secs.is_finite() && *secs >= 0.0)
        .map(Duration::from_secs_f64)
        .unwrap_or_default()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// 24 小时内记了几次自动重启。文件读不出来（第一次跑）就是 0。
fn reboots_last_day() -> usize {
    let now = unix_now();
    std::fs::read_to_string(reboot_log_path())
        .map(|text| {
            text.lines()
                .filter_map(|line| line.trim().parse::<u64>().ok())
                .filter(|at| now.saturating_sub(*at) <= 24 * 3600)
                .count()
        })
        .unwrap_or(0)
}

/// 把这次自动重启写进记账文件（追加一行时间戳）。写不进去就罢了 —— 最坏只是上限
/// 少拦一次。
fn record_self_reboot() {
    let path = reboot_log_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write as _;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{}", unix_now());
    }
}

/// 重启整机。Android 上 `reboot` 在 `/system/bin`，relay 是 init 拉起来的、PATH 不
/// 一定全，所以两条都试。
fn reboot_device() -> Result<String, String> {
    let mut last_error = String::from("没有可用的 reboot 命令");
    for cmd in ["/system/bin/reboot", "reboot"] {
        match run(cmd, &[]) {
            Ok(_) => return Ok(cmd.to_string()),
            Err(error) => last_error = format!("{cmd}: {error}"),
        }
    }
    Err(last_error)
}

/// 纯判定：给定「这次是哪个 op / 什么结果 / 已有计数 / 距上次重启多久」，
/// 回新的计数和该做什么。
///
/// 从 `note` 里拆出来是为了能直接测，不用去碰设备、也不用和别的测试抢那几个 static。
fn step(
    op: &str,
    error_code: i64,
    count_before: u32,
    since_restart: Option<Duration>,
) -> (u32, Verdict) {
    if error_code == 0 {
        // 只有真签出来才算通道好了；`init_sign` 成功不算（TA 卡死时它照样回 0）。
        return if proves_channel_works(op) {
            (0, Verdict::Reset)
        } else {
            (count_before, Verdict::Nothing)
        };
    }
    if BENIGN_CODES.contains(&error_code) {
        return (count_before, Verdict::Nothing);
    }
    let count = count_before + 1;
    if count < FAILURE_LIMIT {
        return (count, Verdict::Nothing);
    }
    match since_restart {
        Some(age) if age < RESTART_COOLDOWN => (count, Verdict::Cooling),
        _ => (count, Verdict::Restart),
    }
}

/// 重启 SOTER HAL，返回人话描述（进日志）。所有路子都失败就回错误。
fn restart_soter_hal() -> Result<String, String> {
    let mut last_error = String::from("没找到可用的 SOTER HAL 服务名");
    for name in SERVICE_CANDIDATES {
        if service_exists(name) {
            return match run("setprop", &["ctl.restart", name]) {
                Ok(_) => Ok(format!("ctl.restart {name}")),
                Err(error) => {
                    last_error = format!("ctl.restart {name}: {error}");
                    continue;
                }
            };
        }
    }
    // 兜底：init 服务名不认识的机器，直接把这个进程收掉，init 会按 rc 拉起来。
    match kill_hal_process() {
        Ok(pid) => Ok(format!("kill -9 {pid}")),
        Err(error) => Err(format!("{last_error}；{error}")),
    }
}

fn service_exists(name: &str) -> bool {
    let prop = format!("init.svc.{name}");
    run("getprop", &[&prop])
        .map(|out| !out.trim().is_empty())
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd} 起不来：{e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{cmd} 退出码 {:?}：{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Only restart an exact known HAL process, never an app or a substring match.
fn kill_hal_process() -> Result<String, String> {
    let listing = run("ps", &["-A", "-o", "PID,NAME"]).map_err(|e| format!("ps 用不了：{e}"))?;
    let pid = listing
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let pid = parts.next()?;
            let name = parts.next()?;
            (HAL_PROCESS_CANDIDATES.contains(&name) && pid.chars().all(|c| c.is_ascii_digit()))
                .then(|| pid.to_string())
        })
        .next()
        .ok_or_else(|| "ps 里没找到 SOTER HAL 进程".to_string())?;
    run("kill", &["-9", &pid])?;
    Ok(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_in_a_row_is_what_triggers_it() {
        let (count, verdict) = step("init_sign", -18, 0, None);
        assert_eq!((count, verdict), (1, Verdict::Nothing));
        let (count, verdict) = step("init_sign", -18, count, None);
        assert_eq!((count, verdict), (2, Verdict::Restart));
    }

    #[test]
    fn any_non_benign_code_counts() {
        // -20（TA 拿不到）、-12（没开）这类结构性故障一样算，不只是 -18。
        let (count, verdict) = step("init_sign", -20, 0, None);
        assert_eq!((count, verdict), (1, Verdict::Nothing));
        assert_eq!(step("init_sign", -20, 1, None), (2, Verdict::Restart));
        // 没见过的码也算。
        assert_eq!(step("has_auth_key", -999, 1, None).1, Verdict::Restart);
    }

    #[test]
    fn benign_codes_are_left_alone() {
        // -5/-6/-8 是「这个槽位还没建料」，-26 是「这会儿没人按指纹」，
        // -204 是「会话被顶掉了」，-65528 是「这台机器上这个 uid 没料」：都不计数。
        for code in [-5i64, -6, -8, -26, -204, -65528] {
            assert_eq!(step("has_auth_key", code, 1, None), (1, Verdict::Nothing));
            assert_eq!(step("init_sign", code, 1, None), (1, Verdict::Nothing));
        }
    }

    #[test]
    fn only_a_real_signature_clears_the_count() {
        // 真签出东西来 = 通道确实好了。
        assert_eq!(step("finish_sign", 0, 2, None), (0, Verdict::Reset));
        // init_sign 成功**不算**：TA 卡死时它照样回 0（PLC110 就是这么坏的）。
        assert_eq!(step("init_sign", 0, 2, None), (2, Verdict::Nothing));
        // 建料类 op 在半死状态下也会成功，更不能让它把计数清掉。
        assert_eq!(step("has_auth_key", 0, 2, None), (2, Verdict::Nothing));
        assert_eq!(
            step("generate_auth_key_pair", 0, 2, None),
            (2, Verdict::Nothing)
        );
        assert_eq!(
            step("export_ask_public_key", 0, 2, None),
            (2, Verdict::Nothing)
        );
    }

    #[test]
    fn the_258_killer_still_reaches_the_threshold() {
        // PLC110 2026-10-02 的真实形态：init_sign 回 0、finish_sign 恒回 258。
        // 以前 init_sign 的成功会把计数清掉，这个序列永远攒不到 2。
        let (count, verdict) = step("init_sign", 0, 0, None);
        assert_eq!((count, verdict), (0, Verdict::Nothing));
        let (count, verdict) = step("finish_sign", 258, count, None);
        assert_eq!((count, verdict), (1, Verdict::Nothing));
        // 下一轮又会来一笔成功的 init_sign，它不能把上面那笔记账抹掉。
        let (count, verdict) = step("init_sign", 0, count, None);
        assert_eq!((count, verdict), (1, Verdict::Nothing));
        let (count, verdict) = step("finish_sign", 258, count, None);
        assert_eq!((count, verdict), (2, Verdict::Restart));
    }

    #[test]
    fn a_stale_session_never_kills_the_hal() {
        // -204（会话被顶掉）重启 HAL 修不了，只会白丢材料：连多少笔都不该动手。
        let mut count = 0;
        let mut verdict = Verdict::Nothing;
        for _ in 0..5 {
            let (c, v) = step("finish_sign", -204, count, None);
            count = c;
            verdict = v;
        }
        assert_eq!(verdict, Verdict::Nothing);
        assert_eq!(count, 0);
    }

    #[test]
    fn the_cooldown_holds_it_back() {
        let (count, verdict) = step("init_sign", -18, 1, Some(Duration::from_secs(60)));
        assert_eq!((count, verdict), (2, Verdict::Cooling));
        // 冷却过了就重启。
        let (_, verdict) = step(
            "init_sign",
            -18,
            1,
            Some(RESTART_COOLDOWN + Duration::from_secs(1)),
        );
        assert_eq!(verdict, Verdict::Restart);
        // 从没重启过（None）也算过了冷却。
        assert_eq!(step("init_sign", -18, 1, None).1, Verdict::Restart);
    }

    #[test]
    fn microtrust_restart_names_are_exact_and_keep_rc_separate_from_process() {
        assert!(SERVICE_CANDIDATES.contains(&"soter-1-0"));
        assert!(!SERVICE_CANDIDATES.contains(&"vendor.microtrust.hardware.soter@1.0-service"));
        assert!(HAL_PROCESS_CANDIDATES.contains(&"vendor.microtrust.hardware.soter@1.0-service"));
        for name in [
            "soter-1-0",
            "com.tencent.soter.soterserver",
            "com.example.soter.service",
            "vendor.microtrust.hardware.soter@1.0-service-helper",
            "Vendor.microtrust.hardware.soter@1.0-service",
        ] {
            assert!(!HAL_PROCESS_CANDIDATES.contains(&name), "{name}");
        }
    }

    #[test]
    fn the_service_name_list_starts_with_the_one_plc110_uses() {
        // PLC110 实测就是这个；顺序有意义（先试它，省一轮 getprop）。
        assert_eq!(SERVICE_CANDIDATES[0], "soter_hal");
    }

    /// `258` 是 TA 卡在 TEE 里的证据：`note()` 会在进 `step()` 之前把它拦下来
    /// （去见 `try_self_reboot`）—— 那一档重启用户态 HAL 是无效的，两轮实测都验过。
    /// 这里钉住两件事：码就是实测的那个，而且它绝不属于「正常业务答复」。
    #[test]
    fn the_tee_wedge_code_is_the_measured_one_and_never_benign() {
        assert_eq!(
            TEE_WEDGE_CODE, 258,
            "0x102 read counter failed，PLC110 实测"
        );
        assert!(!BENIGN_CODES.contains(&TEE_WEDGE_CODE));
        // 万一哪天拦截被删了，它至少会落到 HAL 重启那条路上，不会被当正常答复放过。
        assert_eq!(
            step("finish_sign", TEE_WEDGE_CODE, 1, None),
            (2, Verdict::Restart)
        );
    }

    /// 重启整机那三道刹车。
    #[test]
    fn the_self_reboot_ladder_guards_the_device() {
        let warm = REBOOT_BOOT_GRACE + Duration::from_secs(1);
        // 正常情况：开机够久、今天还没重启过、也没刚重启过 → 该动手。
        assert_eq!(reboot_verdict(0, warm, None), RebootVerdict::Reboot);
        // 刚开机就卡：不动手，免得进重启循环。
        assert_eq!(
            reboot_verdict(0, Duration::from_secs(60), None),
            RebootVerdict::Booting
        );
        // 6 小时内重启过：不动手。
        assert_eq!(
            reboot_verdict(1, warm, Some(REBOOT_COOLDOWN - Duration::from_secs(1))),
            RebootVerdict::TooSoon
        );
        assert_eq!(
            reboot_verdict(1, warm, Some(REBOOT_COOLDOWN + Duration::from_secs(1))),
            RebootVerdict::Reboot
        );
        // 到顶了：停手，只上报。上限优先于其它条件。
        assert_eq!(
            reboot_verdict(REBOOT_MAX_PER_DAY, warm, None),
            RebootVerdict::DailyCap
        );
        assert_eq!(
            reboot_verdict(99, Duration::from_secs(1), None),
            RebootVerdict::DailyCap,
            "上限该盖过开机宽限期"
        );
    }
}
