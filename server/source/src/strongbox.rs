//! StrongBox handling-mode switch (runtime, in-memory).
//!
//! Three modes:
//!   - Off (default): strict native semantics. A StrongBox attest failure
//!     propagates to the next fulfilment layer exactly as before (server
//!     three-layer fallback → A-side local keybox).
//!   - Smart: StrongBox-fidelity orchestration. A StrongBox attestation is
//!     served by the strongest honest source available, in this order:
//!       · the B device's real StrongBox HAL — when it works, its chain is
//!         returned as-is;
//!       · when the B device reports a *present-but-broken* StrongBox
//!         (attestation keys not provisioned / hardware type unavailable),
//!         that error is surfaced verbatim to the A-side app instead of being
//!         masked by a demotion or by the server's stored keybox;
//!       · when the B device has *no* StrongBox, the server's stored
//!         per-device keybox identity mints the (StrongBox-tagged) chain;
//!       · when the server has no stored identity either, the request fails so
//!         the A-side falls back to its local software keybox — never a
//!         self-signed StrongBox chain.
//!   - Robust (original on): Android-standard silent fallback. A B-side
//!     StrongBox capability error (not supported / attestation keys not
//!     provisioned / HAL not present) is transparently retried as a TEE
//!     request on the same B device; the downgraded chain is tagged
//!     TRUSTED_ENVIRONMENT by the B side, so this is an honest degradation,
//!     never a mislabelled StrongBox.

use std::sync::atomic::{AtomicU8, Ordering};

/// Server StrongBox handling mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StrongboxMode {
    /// Strict native semantics (original off).
    Off = 0,
    /// StrongBox-fidelity orchestration (new middle mode).
    Smart = 1,
    /// Transparent B-side TEE demotion (original on).
    Robust = 2,
}

impl StrongboxMode {
    /// Machine token used by the admin API.
    pub fn as_str(self) -> &'static str {
        match self {
            StrongboxMode::Off => "off",
            StrongboxMode::Smart => "smart",
            StrongboxMode::Robust => "robust",
        }
    }

    /// Parse the admin-API token. Accepts only the lowercase tokens
    /// `"off" | "smart" | "robust"`.
    pub fn from_str(s: &str) -> Option<StrongboxMode> {
        match s {
            "off" => Some(StrongboxMode::Off),
            "smart" => Some(StrongboxMode::Smart),
            "robust" => Some(StrongboxMode::Robust),
            _ => None,
        }
    }
}

static MODE: AtomicU8 = AtomicU8::new(StrongboxMode::Off as u8);

/// The current StrongBox handling mode.
pub fn mode() -> StrongboxMode {
    match MODE.load(Ordering::Relaxed) {
        1 => StrongboxMode::Smart,
        2 => StrongboxMode::Robust,
        _ => StrongboxMode::Off,
    }
}

/// Set the StrongBox handling mode.
pub fn set_mode(m: StrongboxMode) {
    MODE.store(m as u8, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_roundtrip() {
        for m in [StrongboxMode::Off, StrongboxMode::Smart, StrongboxMode::Robust] {
            assert_eq!(StrongboxMode::from_str(m.as_str()), Some(m));
            assert_eq!(m.as_str(), match m {
                StrongboxMode::Off => "off",
                StrongboxMode::Smart => "smart",
                StrongboxMode::Robust => "robust",
            });
        }
        assert_eq!(StrongboxMode::from_str("bogus"), None);
        assert_eq!(StrongboxMode::from_str(""), None);
        assert_eq!(StrongboxMode::from_str("ROBUST"), None);
    }

    #[test]
    fn set_get_roundtrip() {
        for m in [StrongboxMode::Off, StrongboxMode::Smart, StrongboxMode::Robust] {
            set_mode(m);
            assert_eq!(mode(), m);
        }
        // Do not leak state into other tests in this process.
        set_mode(StrongboxMode::Off);
    }
}
