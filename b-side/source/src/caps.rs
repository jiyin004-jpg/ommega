//! Which optional capabilities this device can offer the server.
//!
//! The server routes with this: an A-side SOTER call only goes to a B-side
//! device that reported `soter`, and the status page shows both flags.  It is
//! sent as a comma separated `caps=` field on every poll (the B-side heartbeat),
//! so this has to stay cheap — the SOTER verdict is probed once and then cached.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::keymaster::attest_proxy::SYSTEM_KEYMINT_STRONGBOX;
use crate::soter;

/// Comma separated capability names, e.g. `soter,strongbox`.
///
/// An empty string is a real answer: "this device has none of them".  The
/// server distinguishes that from a missing field (an older relay build), which
/// it treats as "not reported" and is still willing to try.
pub fn report() -> String {
    let mut caps: Vec<&str> = Vec::new();
    if soter::service_present() && soter_usable() {
        caps.push("soter");
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

/// 光看 HAL 注册没注册不够 —— 得让它真的答一次。
///
/// 实测踩过的坑：一台骁龙机器上 `vendor.qti.hardware.soter.ISoter/default` 好端端注册
/// 着，`getDeviceId` 却回 -20，KeyMint 那边 `generateKey` 也是 -49，TEE 里那套 TA 根本
/// 没起来。只看 [`soter::service_present`] 会照报 `caps=soter`，服务端于是把别人的
/// SOTER 任务派过来 —— 而 SOTER 只有 B 层、没有兜底，等于把请求直接做废。
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
    *cache = Some((Instant::now(), usable));
    usable
}

/// StrongBox is a second instance of the KeyMint HAL, so its presence is a
/// servicemanager question — no key generation involved.
fn strongbox_present() -> bool {
    rsbinder::hub::check_service(SYSTEM_KEYMINT_STRONGBOX).is_some()
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;

    /// Whatever this device does or does not have, `report()` must be a well
    /// formed list of known names: one of them, both, or empty.  It needs a real
    /// servicemanager (and, for the SOTER verdict, a real HAL), hence Android-only.
    #[test]
    fn report_is_a_well_formed_capability_list() {
        crate::init_binder();
        let caps = report();
        if caps.is_empty() {
            return;
        }
        for name in caps.split(',') {
            assert!(
                name == "soter" || name == "strongbox",
                "unexpected capability {name:?} in {caps:?}"
            );
        }
    }

    /// The SOTER verdict must be stable across calls: probing is cached, so a
    /// second call cannot disagree with the first one.
    #[test]
    fn soter_verdict_is_cached() {
        crate::init_binder();
        let first = report();
        let second = report();
        assert_eq!(first, second, "cached verdict changed between two polls");
    }
}
