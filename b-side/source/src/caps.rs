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
//!   `finish_sign` both answered 0).  This is the only honest way to claim it.
//!   A headless device does not fail this: 2026-10-06 measured on PLC110
//!   (Trustonic AIDL) that the relay signs with nobody pressing a fingerprint
//!   (the signature verifies against the AuthKey public key).  "Not measured"
//!   must therefore stay "not measured" — it never means "cannot".
//! - `soter_nosign` — the OPPOSITE, stated out loud.  The server still parses
//!   the name (old relays send it), but this build **never emits it**: every
//!   code a refused sign produces is a per-attempt one (`-26` this attempt did
//!   not verify, `-204` the session was clobbered, a timeout), and inferring a
//!   device capability from those used to route sign ops away from devices
//!   that can sign perfectly well.
//! - `soter_stuck` — the TA is wedged inside the TEE: it holds the RPMB session
//!   open and never lets go, so it can no longer read its own persistent store.
//!   Export/build then answer `-5`/`258` while `has_*` still says the material is
//!   there.  Before reporting this the relay already tried to escalate (reboot
//!   the phone, see `soter::hal_restart`); this name means that escalation
//!   either could not run or did not help, so a human has to look.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::keymaster::attest_proxy::SYSTEM_KEYMINT_STRONGBOX;
use crate::soter;

/// Which key slot to try a real signature on: `relay.conf` carries
/// `OMMEGA_RELAY_SOTER_PROBE_UID` / `OMMEGA_RELAY_SOTER_PROBE_ALIAS`.
///
/// 没配也不等于签不了：那只是「手上还没有能试的槽位」，这时候什么都不上报（只报
/// `soter`），服务端照旧会试着派活；等这台机器真跑过一次 `init_sign`，槽位会被
/// 记下来当探针目标，下一次心跳就能量出结论。探针只用现成材料，**不建不删**。
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
        // HAL 肯答话只够说明身份/导出能用，证明不了它肯签。所以「能签」得真签
        // 出来一次才算（反面则一律不说：失败码推不出设备能力，见模块头）。
        //
        // 探针目标优先听配置的；没配就退到这台机器真跑过一次 `init_sign` 的那个
        // 槽位 —— 探针只为了挣正面结论，量不出来就什么都不说。
        probe_sign_capability(sign_target.cloned().or_else(learned_target).as_ref());
        // 「行」只认真签出来过一次；「不行」这个版本不报（失败码推不出设备
        // 能力，误报还会把签名 op 从这台挪走）。没量出来就只报 `soter`。
        if soter::sign_state() == soter::SignState::Proven {
            caps.push("soter_sign");
        }
        // TA 卡在 TEE 里：HAL 照样答话、身份/导出 op 也照样回，但回的是错的
        // （「说存在、却导不出来」，`-5` + `258`）。这台现在不该再被派 SOTER 活；
        // 自愈自己会先试重启整机，试不动（次数到顶/开机宽限期/重启失败）才会报
        // 这个名字，意思就是「得人工看一眼了」。
        if soter::hal_restart::tee_wedged() {
            caps.push("soter_stuck");
        }
    }
    if strongbox_present() {
        caps.push("strongbox");
    }
    caps.join(",")
}

fn learned_target() -> Option<SignProbeTarget> {
    let (uid, alias) = soter::learned_probe_target()?;
    Some(SignProbeTarget { uid, alias })
}

/// How long a probed verdict is trusted before probing again.
const SOTER_PROBE_TTL: Duration = Duration::from_secs(300);

/// Last verdict as `(when, usable)`; `None` means never probed.
static SOTER_VERDICT: Mutex<Option<(Instant, bool)>> = Mutex::new(None);

/// 上一次签名探针的时间和目标，用来限流（探一次要开 HAL、走一遍 TA，心跳
/// 20 秒一次扛不住）。
static SIGN_PROBED_AT: Mutex<Option<(Instant, Option<SignProbeTarget>)>> = Mutex::new(None);

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

/// 探针只能挣到正面结论（真签出来过），永远不能拿它去下「签不了」的断言。
///
/// 探针撞上的失败码全是「这次没量出来」：`-26` 是这一笔没验过、`-5`/`-6` 是槽位
/// 上没材料、`-204` 是会话被顶掉。2026-10-06 实测 PLC110 无人值守也签得出来，
/// 所以更没理由从失败码推「这台签不了」—— 服务端接了这个结论会把一台明明能签的
/// 机器从签名链路上踢掉，比不报还糟。
fn probe_sign_capability(target: Option<&SignProbeTarget>) {
    // sign_probe atomically checks the session lease and reserves HAL access.
    let mut cache = SIGN_PROBED_AT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, cached)) = cache.as_ref() {
        // 已经挣到结论就不用再探了；另外同一个目标 5 分钟内也不重复探。
        if soter::sign_state() != soter::SignState::Unknown
            || (cached.as_ref() == target && at.elapsed() < SOTER_PROBE_TTL)
        {
            return;
        }
    }
    match target {
        Some(target) => {
            let probe = soter::sign_probe(target.uid, &target.alias);
            if probe["skipped"].as_bool() == Some(true) {
                log::debug!(
                    "soter sign capability probe: skipped, the device is signing right now"
                );
                return; // No HAL measurement: do not consume the probe TTL.
            }
            let verdict = soter::SignVerdict::from_probe(&probe);
            if verdict != soter::SignVerdict::Signed {
                // 探不出能签就把原因写进日志：光看 caps 里没有 `soter_sign`，谁也
                // 不知道是槽位上没材料、还是 TA 非要指纹。
                log::info!("soter sign capability probe: {verdict} ({probe})");
            }
        }
        None => {
            // 手上没有能试的槽位：什么都不说，等服务端派活或者学到一个槽位。
            log::debug!("soter sign capability probe: no slot to try yet");
        }
    }
    *cache = Some((Instant::now(), target.cloned()));
}

/// StrongBox is a second instance of the KeyMint HAL, so its presence is a
/// servicemanager question — no key generation involved.
fn strongbox_present() -> bool {
    rsbinder::hub::check_service(SYSTEM_KEYMINT_STRONGBOX).is_some()
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;
    use crate::soter::SignVerdict;

    /// 探针只用现成槽位试签，量不出结论（没目标 / 没材料 / 这一笔没验过 / HAL 没
    /// 答话）时什么都不说。反面结论这个版本压根不报：`soter::sign_state` 只有
    /// 「签出来过」和「还没量出来」两档。
    #[test]
    fn a_probe_never_publishes_a_negative_verdict() {
        for verdict in [
            SignVerdict::BiometricRequired,
            SignVerdict::NoMaterial,
            SignVerdict::Unavailable,
            SignVerdict::Unknown,
        ] {
            assert_ne!(verdict, SignVerdict::Signed, "{verdict:?} 不该当成签出来过");
        }
    }

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
                name == "soter"
                    || name == "soter_sign"
                    || name == "soter_nosign"
                    || name == "soter_stuck"
                    || name == "strongbox",
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

    /// 没有探针目标（默认配置、也还没学过槽位）时既不许报 `soter_sign`，也不许报
    /// `soter_nosign`：有 HAL 就只说 `soter`，剩下的交给服务端去试。
    #[test]
    fn no_probe_target_means_no_probe_claim() {
        crate::init_binder();
        let caps = report(None);
        let names: Vec<&str> = caps.split(',').filter(|s| !s.is_empty()).collect();
        assert!(
            !names.contains(&"soter_sign"),
            "没有探针目标还报了能签: {caps:?}"
        );
        assert!(
            !names.contains(&"soter_nosign"),
            "没有探针目标就报签不了，会把能签的机器误伤: {caps:?}"
        );
    }
}
