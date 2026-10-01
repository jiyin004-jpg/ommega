//! SOTER HAL 半死状态的自愈：连着几次失败就把这个服务重启一次。
//!
//! 背景（PLC110 2026-09-30 实测）：HAL 会进一种半死状态 —— 建料类的 op
//! （`generate_auth_key_pair` / `has_auth_key` / `export_auth_key_public_key`）
//! 全都正常，只有走 TEE 会话的 `init_sign` 恒回 -18
//! （`SOTER_ERROR_SECURE_HW_COMMUNICATION_FAILED`）。进程还活着、也不是 D 状态，
//! 重启这个服务就好（实测 `setprop ctl.restart soter_hal`，旧 pid 退掉、init 拉新的）。
//!
//! 不收拾的后果是实打实的：服务端会按「这台结构性做不了」把这个槽位换到自签那两层，
//! App 手里变成假料，拿到的还是个误导性的 -5（「这把钥匙不在」）—— Duck Detector
//! 就是这么报 soter damaged 的，微信那边整轮开启都拿不到真材料。
//!
//! 计数规则（2026-10-01 改）：
//!
//! - **阈值 2**：一次失败可能只是偶然撞上，连着两次就动手，先把 HAL 拉回来再说。
//! - **凡非 0 都算**，只有几个「正常业务答复」不算：-5 / -6 / -8（这个槽位还没建料，
//!   新装的 App 天天问）、-26（这会儿没人按指纹）。剩下的 -12/-13/-18/-20、-204
//!   以及一切没见过的码，都是「这台现在真做不了」，一律计入。
//! - **清零只认 TEE 会话 op 的成功**（`init_sign` / `finish_sign`）。半死状态下
//!   建料类 op 照样成功，以前用它们清零，导致计数永远攒不满、HAL 一直坏着 ——
//!   那台 PLC110 从开机到被我手动顶穿就是这么过来的。
//! - 冷却照旧：刚重启过就先不动，免得 HAL 真坏的时候每一笔都去 kill 一遍。
//!
//! 冷却用 `Instant`（单调钟，不含 suspend）就够 —— 它是防抖，不是精确调度。

use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 连着几次算结构性故障。
const FAILURE_LIMIT: u32 = 2;
/// 两次重启之间的最短间隔。
const RESTART_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// 正常的业务答复，不参与计数：这个槽位还没建料（-5 ASK / -6 AuthKey / -8）、
/// 以及这会儿没人按指纹（-26）。
///
/// -8 是 2026-10-01 从生产日志里量出来的：40k 行里有 657 次，全是建料类 op
/// （`has_auth_key` / `export_auth_key_public_key`），是 `-5` 同一种「还没准备」的意思。
/// 不排掉它的话，App 每查几回就把阈值顶满。
///
/// -204 只在 `finish_sign` 上出现过 6 次（倾向是用户取消指纹），少见，先照算 ——
/// 连着两次的代价只是冷却期内多重启一次 HAL。
const BENIGN_CODES: &[i64] = &[-5, -6, -8, -26];

/// 只有走 TEE 会话的 op 成功了才说明通道是好的。建料类 op 在半死状态下照样成功。
fn is_session_op(op: &str) -> bool {
    matches!(op, "init_sign" | "finish_sign")
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
];

static FAILURES: Mutex<u32> = Mutex::new(0);
static LAST_RESTART: Mutex<Option<Instant>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 一笔真活的结果。非 0 且不属于 `BENIGN_CODES` 的累加，够了就重启一次 HAL；
/// TEE 会话 op 成功清零；其余一概不碰。
pub fn note(op: &str, error_code: i64) {
    let count_before = *lock(&FAILURES);
    let since_restart = lock(&LAST_RESTART).map(|at| at.elapsed());
    let (count, verdict) = step(op, error_code, count_before, since_restart);
    *lock(&FAILURES) = count;
    match verdict {
        Verdict::Reset | Verdict::Nothing => {}
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
        // 只有真走通了 TEE 会话才说明通道好了；建料类 op 成功不算数。
        return if is_session_op(op) {
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

/// 进程名里带 soter 的那个 HAL（`com.tencent.soter.soterserver` 是 App 那侧的服务，
/// 不算）；返回它的 pid。
fn kill_hal_process() -> Result<String, String> {
    let listing = run("ps", &["-A", "-o", "PID,NAME"]).map_err(|e| format!("ps 用不了：{e}"))?;
    let pid = listing
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let pid = parts.next()?;
            let name = parts.next()?;
            let lower = name.to_ascii_lowercase();
            let looks_like_hal = lower.contains("soter")
                && !lower.contains("soterserver")
                && (lower.contains("service") || lower.contains("hal"));
            (looks_like_hal && pid.chars().all(|c| c.is_ascii_digit())).then(|| pid.to_string())
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
        // -5 / -6 / -8 是「这个槽位还没建料」，-26 是「这会儿没人按指纹」：正常答复，不计数。
        for code in [-5i64, -6, -8, -26] {
            assert_eq!(step("has_auth_key", code, 1, None), (1, Verdict::Nothing));
            assert_eq!(step("init_sign", code, 1, None), (1, Verdict::Nothing));
        }
    }

    #[test]
    fn only_a_session_op_success_clears_the_count() {
        // init_sign / finish_sign 成功 = 通道确实好了。
        assert_eq!(step("init_sign", 0, 2, None), (0, Verdict::Reset));
        assert_eq!(step("finish_sign", 0, 2, None), (0, Verdict::Reset));
        // 建料类 op 在半死状态下也会成功，不能让它把计数清掉。
        assert_eq!(step("has_auth_key", 0, 2, None), (2, Verdict::Nothing));
        assert_eq!(step("generate_auth_key_pair", 0, 2, None), (2, Verdict::Nothing));
        assert_eq!(step("export_ask_public_key", 0, 2, None), (2, Verdict::Nothing));
    }

    #[test]
    fn the_cooldown_holds_it_back() {
        let (count, verdict) = step("init_sign", -18, 1, Some(Duration::from_secs(60)));
        assert_eq!((count, verdict), (2, Verdict::Cooling));
        // 冷却过了就重启。
        let (_, verdict) = step("init_sign", -18, 1, Some(RESTART_COOLDOWN + Duration::from_secs(1)));
        assert_eq!(verdict, Verdict::Restart);
        // 从没重启过（None）也算过了冷却。
        assert_eq!(step("init_sign", -18, 1, None).1, Verdict::Restart);
    }

    #[test]
    fn the_service_name_list_starts_with_the_one_plc110_uses() {
        // PLC110 实测就是这个；顺序有意义（先试它，省一轮 getprop）。
        assert_eq!(SERVICE_CANDIDATES[0], "soter_hal");
    }
}
