//! ommegaclient-b library target.
//!
//! This crate is the **new B-side** relay agent: it receives tasks from the
//! relay_server (ommega-old), calls the *real* on-device hardware TEE to mint
//! attestation certificate chains that embed a caller-supplied application id
//! (tag 709), and forwards the result back.
//!
//! Only the modules needed for that forwarding path are kept here; the
//! software keystore body has been removed.

#![recursion_limit = "256"]

pub mod caps;
pub mod keymaster;
pub mod logging;
pub mod macros;
pub mod plat;
pub mod soter;
pub mod uplink;
pub mod wakelock;
pub mod watchdog;

/// 测试进程里要问 servicemanager 就得先把 binder 的 ProcessState 起来，
/// 否则 rsbinder 直接 panic。
#[cfg(test)]
pub fn init_binder() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rsbinder::ProcessState::init_default();
    });
}

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));
