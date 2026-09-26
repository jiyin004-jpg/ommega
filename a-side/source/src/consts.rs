use rsbinder::BinderFeatures;

/// Magic prefix used by the km_compat C++ code to mark a key that is owned by an
/// underlying Keymaster hardware device that has been wrapped by km_compat. (The
/// final zero byte indicates that the blob is not software emulated.)
pub const KEYMASTER_BLOB_HW_PREFIX: &[u8] = b"pKMblob\x00";

/// Magic prefix used by the km_compat C++ code to mark a key that is owned by an
/// software emulation device that has been wrapped by km_compat. (The final one
/// byte indicates that the blob is software emulated.)
pub const KEYMASTER_BLOB_SW_PREFIX: &[u8] = b"pKMblob\x01";

pub const RPC_SOCKET_CONTEXT: &str = "u:r:keystore:s0";

/// Peer list the injector keeps so the daemon can recognize a process it injected.
///
/// The peer pid arrives over SO_PEERCRED and cannot be forged, but the kernel hides other
/// uids' /proc entries from the keystore uid (hidepid), so their command line is not
/// readable and there is nothing else in the peer credentials to go on. The injector runs
/// as root and writes the pids it injected here; this is what the app-socket authorizer
/// matches against. Written by `ommega-injector` (the path is named there too).
pub const RPC_PEER_STATE: &str = "/data/misc/keystore/ommega/rpc.peers";

/// Second RPC rendezvous point, on the abstract unix namespace.
///
/// The file socket lives under the keystore state dir, which is 0700 keystore, so
/// an app-domain process (the SOTER host, uid 1000) cannot traverse into it. An
/// abstract socket has no filesystem entry, so DAC does not apply and admission
/// rests on SELinux plus the server authorizer. The name is duplicated in
/// `ommega-injector`'s `ipc.rs`: the two crates share no code.
pub const RPC_ABSTRACT_NAME: &[u8] = b"ommega.soter.rpc";

pub fn sid_features() -> BinderFeatures {
    let mut features = BinderFeatures::default();
    features.set_requesting_sid = true;

    features
}
