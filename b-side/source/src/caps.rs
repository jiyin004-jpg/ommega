//! Which optional capabilities this device can offer the server.
//!
//! The server routes with this: an A-side SOTER call only goes to a B-side
//! device that reported `soter`, and the status page shows both flags.  It is
//! sent as a comma separated `caps=` field on every poll (the B-side heartbeat),
//! so this has to stay cheap — the SOTER verdict is probed once and then cached.
//!
//! SOTER is split in two on purpose:
//!
//! - `soter` — the HAL answers `getDeviceId`: identity / export ops can be
//!   served.  Cheap to prove, and it is what the old relays reported.
//! - `soter_sign` — a signature was really produced once (`init_sign` +
//!   `finish_sign` both answered 0).  This is the only honest way to claim it:
//!   the TA signs only inside a fresh fingerprint match, so on a headless
//!   device the answer is `-26` and there is nothing to advertise.
//! - `soter_nosign` — the OPPOSITE, stated out loud: this device has the HAL
//!   but cannot sign unattended.  Without it a device that can never sign looks
//!   exactly like an old relay that never said anything, and the server pays a
//!   wasted round trip (task → `-26` → next layer) on every single flow.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::keymaster::attest_proxy::SYSTEM_KEYMINT_STRONGBOX;
use crate::soter;

/// Which key slot to try a real signature on: `relay.conf` carries
/// `OMMEGA_RELAY_SOTER_PROBE_UID` / `OMMEGA_RELAY_SOTER_PROBE_ALIAS`.
///
/// No target configured means no material to try — and then the honest answer is
/// "cannot sign", not a guess.  The probe only ever uses keys that are already
/// there; creating them is a mutation and needs the operator's opt-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignProbeTarget {
    pub uid: i32,
    pub alias: String,
}

/// Comma separated capability names, e.g. `soter,soter_nosign,strongbox`.
///
/// An empty string is a real answer: "this device has none of them".  The
/// server distinguishes that from a missing field (an older relay build), which
/// it treats as "not reported" and is still willing to try.
pub fn report(sign_target: Option<&SignProbeTarget>) -> String {
    let mut caps: Vec<&str> = Vec::new();
    // 只用 `soter_usable` 这一道：它内部是 `soter::probe`，会把 AIDL 两家
    // 和 HIDL 两家都真探一遍，而且带 5 分钟缓存。以前这里还有一层
    // `service_present()` 预筛，但那个只认 AIDL（HIDL 那边没有同样廉价的
    // 探法），`&&` 一短路就把 HIDL-only 的机器漏掉了。
    if soter_usable() {
        caps.push("soter");
        // HAL 肯答话只够说明身份/导出能用。签名那一步骗不了人：一加 11
        // （PHB110）、MIX 4 这些机器的 TA 只在「刚匹配过指纹」时才肯签，没人
        // 按指纹时 `finish_sign` 一律回 -26。所以「能签」得探出来，不能猜。
        if soter_sign_usable(sign_target) {
            caps.push("soter_sign");
        } else {
            caps.push("soter_nosign");
        }
    }
    if strongbox_present() {
        caps.push("strongbox");
    }
    caps.join(",")
}

/// How long a probed verdict is trusted before probing again.
const SOTER_PROBE_TTL: Duration = Duration::from_secs(300);

/// Last verdict as `(when, usable)`; `None` means never probed.
static SOTER_VERDICT: Mutex<Option<(Instant, bool)>> = Mutex::new(None);

/// Last sign verdict as `(when, target, usable)`.  The target is part of the
/// key so a config change (another uid/alias to try) re-probes immediately.
static SOTER_SIGN_VERDICT: Mutex<Option<(Instant, SignProbeTarget, bool)>> = Mutex::new(None);

/// 光看 HAL 注册没注册不够 —— 得让它真的答一次。
///
/// 实测踩过的坑：一台骁龙机器上 `vendor.qti.hardware.soter.ISoter/default` 好端端注册
/// 着，`getDeviceId` 却回 -20，KeyMint 那边 `generateKey` 也是 -49，TEE 里那套 TA 根本
/// 没起来。服务端会把别人的 SOTER 任务派过来 —— 而 SOTER 只有 B 层、没有兜底，
/// 等于把请求直接做废。
///
/// 探一次要开 binder 发个事务，心跳每 20 秒一次扛不住，所以结果缓存；失败也缓存（坏掉的
/// TEE 不会自己好），但给 TTL，免得 TA 修好了还一直报空。
fn soter_usable() -> bool {
    let mut cache = SOTER_VERDICT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, usable)) = *cache {
        if at.elapsed() < SOTER_PROBE_TTL {
            return usable;
        }
    }
    let probe = soter::probe();
    let usable = probe["supported"].as_bool().unwrap_or(false);
    if !usable {
        // 探失败的时候把原因写进日志：光看 caps= 是空的，没人知道是 HAL 没注册、
        // 还是 TA 答了个错误码。
        log::info!("soter capability probe: not usable ({probe})");
    }
    *cache = Some((Instant::now(), usable));
    usable
}

/// 真去签一次，签得动才算。缓存跟 `soter_usable` 一个路子：探一次要开 HAL、
/// 走一遍 TA，心跳 20 秒一次扛不住；失败也缓存（TA 那边「没有新鲜指纹」这种
/// 状态不会自己好，指纹按下去的时候服务端本来也会重新走流程）。
fn soter_sign_usable(target: Option<&SignProbeTarget>) -> bool {
    let Some(target) = target else {
        // 没配探针目标：手上没有现成的槽位可试。
        return false;
    };
    let mut cache = SOTER_SIGN_VERDICT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, cached, usable)) = cache.as_ref() {
        if cached == target && at.elapsed() < SOTER_PROBE_TTL {
            return *usable;
        }
    }
    let probe = soter::sign_probe(target.uid, &target.alias);
    let usable = sign_capability(true, probe["signed"].as_bool().unwrap_or(false));
    if !usable {
        // 探不出能签就把原因写进日志：光看 caps 里没有 `soter_sign`，谁也不知道
        // 是槽位上没材料、还是 TA 非要指纹。
        log::info!("soter sign capability probe: not usable ({probe})");
    }
    *cache = Some((Instant::now(), target.clone(), usable));
    usable
}

/// 只按「配没配探针目标」和「探针结论」算能不能签 —— 不含设备，主机上也能测。
fn sign_capability(target_configured: bool, probe_passed: bool) -> bool {
    target_configured && probe_passed
}

/// StrongBox is a second instance of the KeyMint HAL, so its presence is a
/// servicemanager question — no key generation involved.
fn strongbox_present() -> bool {
    rsbinder::hub::check_service(SYSTEM_KEYMINT_STRONGBOX).is_some()
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;

    /// 只按「配没配探针目标」和「探针结论」算能不能签 —— 纯函数，不碰设备。
    ///
    /// 没探针目标（没配、或槽位上没材料）就不许声称能签 —— 这正是那台一加 11
    /// 的处境：HAL 好端端的，签名那步永远回 -26。
    #[test]
    fn signing_is_never_claimed_without_a_passing_probe() {
        assert!(!sign_capability(false, false));
        assert!(!sign_capability(false, true));
        assert!(!sign_capability(true, false));
        assert!(sign_capability(true, true));
    }

    /// 探针目标带 uid + alias，比的是整体（uid 或 alias 换一个都得重新探）。
    #[test]
    fn probe_target_identity_covers_uid_and_alias() {
        let a = SignProbeTarget {
            uid: 10503,
            alias: "SoterAuthKeyV2_saltc1_scene1".to_string(),
        };
        let b = SignProbeTarget {
            uid: 10503,
            alias: "SoterAuthKeyV2_saltc1_scene1".to_string(),
        };
        let c = SignProbeTarget {
            uid: 10504,
            alias: "SoterAuthKeyV2_saltc1_scene1".to_string(),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// Whatever this device does or does not have, `report()` must be a well
    /// formed list of known names: one of them, both, or empty.  It needs a real
    /// servicemanager (and, for the SOTER verdict, a real HAL), hence Android-only.
    #[test]
    fn report_is_a_well_formed_capability_list() {
        crate::init_binder();
        let caps = report(None);
        if caps.is_empty() {
            return;
        }
        for name in caps.split(',') {
            assert!(
                name == "soter" || name == "soter_sign" || name == "soter_nosign" || name == "strongbox",
                "unexpected capability {name:?} in {caps:?}"
            );
        }
    }

    /// The SOTER verdict must be stable across calls: probing is cached, so a
    /// second call cannot disagree with the first one.
    #[test]
    fn soter_verdict_is_cached() {
        crate::init_binder();
        let first = report(None);
        let second = report(None);
        assert_eq!(first, second, "cached verdict changed between two polls");
    }

    /// 没有探针目标（默认配置）时不许报 `soter_sign`：有 HAL 就该报
    /// `soter_nosign`，报告里说的跟这台机器真干得了的事一致。
    #[test]
    fn no_probe_target_means_no_sign_claim() {
        crate::init_binder();
        let caps = report(None);
        let names: Vec<&str> = caps.split(',').filter(|s| !s.is_empty()).collect();
        assert!(!names.contains(&"soter_sign"), "没有探针目标还报了能签: {caps:?}");
        if names.contains(&"soter") {
            assert!(
                names.contains(&"soter_nosign"),
                "SOTER 能答话但不该声称能签: {caps:?}"
            );
        }
    }
}
