//! Which optional capabilities this device can offer the server.
//!
//! The server routes with this: an A-side SOTER call only goes to a B-side
//! device that reported `soter`, and the status page shows both flags.  It is
//! sent as a comma separated `caps=` field on every poll (the B-side heartbeat),
//! so this must stay cheap and side-effect free — no HAL transactions, and in
//! particular nothing that touches the TEE signature counter.

use crate::keymaster::attest_proxy::SYSTEM_KEYMINT_STRONGBOX;
use crate::soter;

/// Comma separated capability names, e.g. `soter,strongbox`.
///
/// An empty string is a real answer: "this device has none of them".  The
/// server distinguishes that from a missing field (an older relay build), which
/// it treats as "not reported" and is still willing to try.
pub fn report() -> String {
    let mut caps: Vec<&str> = Vec::new();
    if soter::service_present() {
        caps.push("soter");
    }
    if strongbox_present() {
        caps.push("strongbox");
    }
    caps.join(",")
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
    /// servicemanager, hence Android-only.
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
}
