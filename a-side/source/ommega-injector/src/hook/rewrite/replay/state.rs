//! On-disk mirror of the standing unlock material.
//!
//! `replay.rs` holds the material in memory so that a *shadow* restart can be recovered
//! from. That is not enough on its own: the injector payload lives inside keystore2, so
//! whenever *keystore2* is replaced (a crash, a module update, or a hot-update restart)
//! the memory copy dies with it — and the framework never re-sends an unlock that nobody
//! asked for. The shadow then stays device-locked until the user happens to unlock again,
//! and every auth-bound key init answers `LOCKED` in the meantime.
//!
//! So the material is mirrored to one small file in the keystore-private directory and
//! reloaded when a fresh payload starts. What is at rest here is the same LSKF material
//! keystore2 itself was handed, in a directory only `keystore`/root can read — i.e. the
//! same trust domain as the CE key blobs the shadow keeps beside it. `OMMEGA_UNLOCK_STATE`
//! overrides the path, and `OMMEGA_UNLOCK_STATE=off` turns the mirror off for anyone who
//! would rather keep a `LOCKED` window than keep the material at rest.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::*;

/// Keystore-private directory that the payload (uid `keystore`) can write even while the
/// device is locked; see the module docs for the choice.
pub(super) const DEFAULT_STATE_PATH: &str = "/data/misc/keystore/ommega/unlock.state";
const STATE_PATH_ENV: &str = "OMMEGA_UNLOCK_STATE";
const DISABLED: &str = "off";
const STATE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct StateFile {
    version: u32,
    #[serde(default, rename = "user")]
    users: Vec<StateUser>,
}

#[derive(Serialize, Deserialize)]
struct StateUser {
    user_id: i32,
    /// Absent means "this device has no LSKF", which is material worth replaying too:
    /// `onDeviceUnlocked` without a password is exactly what such a device needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<Vec<u8>>,
    caller_uid: i64,
    caller_pid: i64,
    caller_sid: String,
}

/// Where the mirror lives. The environment wins (`off` disables the mirror), unit tests
/// never touch the real device path, everyone else gets [`DEFAULT_STATE_PATH`].
pub(super) fn state_path() -> Option<PathBuf> {
    match std::env::var(STATE_PATH_ENV) {
        Ok(value) if value == DISABLED || value.is_empty() => None,
        Ok(value) => Some(PathBuf::from(value)),
        Err(_) if cfg!(test) => None,
        Err(_) => Some(PathBuf::from(DEFAULT_STATE_PATH)),
    }
}

/// Read the mirror back. A missing, unreadable, or stale file is not an error: it only
/// means this payload starts with nothing to replay, exactly like before the mirror
/// existed.
pub(super) fn load_from(path: &Path) -> Vec<(i32, Option<Vec<u8>>, CallerInfo)> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            warn!("event=replay unlock state {path:?} is unreadable: {error}; starting empty");
            return Vec::new();
        }
    };
    let parsed: StateFile = match toml::from_str(&contents) {
        Ok(parsed) => parsed,
        Err(error) => {
            warn!("event=replay unlock state {path:?} does not parse: {error}; starting empty");
            return Vec::new();
        }
    };
    if parsed.version != STATE_VERSION {
        warn!(
            "event=replay unlock state {path:?} was written by version {} (expected {STATE_VERSION}); starting empty",
            parsed.version
        );
        return Vec::new();
    }
    parsed
        .users
        .into_iter()
        .map(|user| {
            (
                user.user_id,
                user.password,
                CallerInfo {
                    uid: user.caller_uid,
                    sid: user.caller_sid,
                    pid: user.caller_pid,
                },
            )
        })
        .collect()
}

/// Replace the mirror with `entries`, or remove it when there is nothing left to replay.
///
/// Written through a temporary file in the same directory so a crash mid-write can never
/// leave a half-parsed mirror behind. Failures are returned, never fatal: the in-memory
/// copy is what the running payload actually uses.
pub(super) fn save_to(path: &Path, entries: &[(i32, Option<Vec<u8>>, CallerInfo)]) -> Result<()> {
    if entries.is_empty() {
        match fs::remove_file(path) {
            Ok(()) => info!("event=replay unlock state {path:?} removed; nothing to replay"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!("event=replay could not remove unlock state {path:?}: {error}"),
        }
        return Ok(());
    }

    let file = StateFile {
        version: STATE_VERSION,
        users: entries
            .iter()
            .map(|(user_id, password, caller)| StateUser {
                user_id: *user_id,
                password: password.clone(),
                caller_uid: caller.uid,
                caller_pid: caller.pid,
                caller_sid: caller.sid.clone(),
            })
            .collect(),
    };
    let serialized = toml::to_string(&file).context("failed to serialize unlock state")?;

    let temporary = path.with_extension("tmp");
    {
        let mut handle = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("failed to open {temporary:?}"))?;
        handle
            .write_all(serialized.as_bytes())
            .with_context(|| format!("failed to write {temporary:?}"))?;
        let _ = handle.sync_all();
    }
    fs::rename(&temporary, path).with_context(|| format!("failed to publish {path:?}"))?;
    debug!(
        "event=replay unlock state {path:?} now holds {} user(s)",
        entries.len()
    );
    Ok(())
}
