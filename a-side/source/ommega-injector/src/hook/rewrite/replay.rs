//! Re-feed the shadow's in-memory authorization state after it restarts.
//!
//! The shadow keeps its CE super keys in memory only, exactly like AOSP keystore2:
//! they are installed when the user first unlocks and stay usable until the process
//! dies (locking the screen does not clear them). But when *our* shadow process
//! restarts, that memory is gone and the framework has no reason to send
//! `onDeviceUnlocked` a second time, so the shadow stays "device locked" forever and
//! every auth-bound key init comes back LOCKED.
//!
//! Real keystore2 only avoids this because nobody restarts it. The injector is the
//! one place that sees the unlock material the framework hands to keystore2, so the
//! material is kept here (memory only, never on disk) and replayed into the shadow as
//! soon as a new shadow generation shows up.

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use super::*;

/// No shadow generation has been fed yet.
const UNSYNCED_GENERATION: u64 = u64::MAX;

struct StandingDeviceUnlock {
    /// Password material the framework handed over; `None` on a device without an LSKF.
    password: Option<Vec<u8>>,
    /// The original caller (the framework); replayed as-is so the shadow sees the
    /// same identity it saw the first time.
    caller: CallerInfo,
}

/// The last unlock material keystore2 was given, per user. Memory only: it dies with
/// the host process, same as the real keystore2's own copy.
static DEVICE_UNLOCK: LazyLock<Mutex<HashMap<i32, StandingDeviceUnlock>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The shadow generation that already holds the state above; `UNSYNCED_GENERATION`
/// means nothing has been replayed yet.
static SYNCED_GENERATION: AtomicU64 = AtomicU64::new(UNSYNCED_GENERATION);

thread_local! {
    /// The replay itself goes through ipc; do not recurse into another replay.
    static REPLAYING: Cell<bool> = const { Cell::new(false) };
}

/// Remember the unlock material after the shadow accepted it.
///
/// A notification without a password carries no material at all: the framework sends
/// one of those right after a password unlock, and for every non-LSKF unlock (e.g.
/// fingerprint) as well. Letting it overwrite material we already hold would leave the
/// shadow with nothing to replay after its next restart, so a null password only ever
/// fills in a user we have no material for. Losing an LSKF for real arrives as
/// `onUserLskfRemoved`, which forgets the user outright.
pub(super) fn remember_device_unlock(user_id: i32, password: Option<&[u8]>, caller: &CallerInfo) {
    let has_password = {
        let mut cache = DEVICE_UNLOCK
            .lock()
            .expect("ommega device unlock cache poisoned");
        let entry = cache
            .entry(user_id)
            .or_insert_with(|| StandingDeviceUnlock {
                password: None,
                caller: caller.clone(),
            });
        if let Some(password) = password {
            if let Some(old) = entry.password.take() {
                wipe(old);
            }
            entry.password = Some(password.to_vec());
        }
        entry.caller = caller.clone();
        entry.password.is_some()
    };

    // The shadow just took this one in, so the generation it belongs to is fed.
    SYNCED_GENERATION.store(ipc::rpc_generation(), Ordering::SeqCst);
    debug!(
        "event=replay standing device unlock remembered user={} has_password={}",
        user_id, has_password
    );
}

/// Forget one user's material (user removed, LSKF removed, or the shadow rejected it).
pub(super) fn forget_device_unlock(user_id: i32) {
    let removed = DEVICE_UNLOCK
        .lock()
        .expect("ommega device unlock cache poisoned")
        .remove(&user_id);
    if let Some(mut entry) = removed {
        if let Some(password) = entry.password.take() {
            wipe(password);
        }
        debug!("event=replay standing device unlock forgotten user={user_id}");
    }
}

fn wipe(mut bytes: Vec<u8>) {
    bytes.fill(0);
}

fn cached_user_ids() -> Vec<i32> {
    DEVICE_UNLOCK
        .lock()
        .expect("ommega device unlock cache poisoned")
        .keys()
        .copied()
        .collect()
}

/// Called by the ipc layer right after it acquired a shadow client and before it sends
/// the caller's request. Does nothing unless the shadow generation changed since the
/// last replay, which is exactly "the shadow process restarted".
pub(crate) fn sync_ommega_state_after_reconnect() {
    let generation = ipc::rpc_generation();
    if SYNCED_GENERATION.load(Ordering::SeqCst) == generation {
        return;
    }
    if REPLAYING.with(|flag| flag.replace(true)) {
        return;
    }

    let users = cached_user_ids();
    info!(
        "event=replay shadow generation {generation} is new (previous {}); re-feeding state for {} cached user(s)",
        SYNCED_GENERATION.load(Ordering::SeqCst),
        users.len()
    );

    let result = replay_standing_device_unlocks();
    if result.is_ok() {
        // Only a shadow that actually answered counts as fed; a connection failure
        // keeps the material for the next attempt.
        SYNCED_GENERATION.store(ipc::rpc_generation(), Ordering::SeqCst);
    }
    REPLAYING.with(|flag| flag.set(false));

    if let Err(error) = result {
        warn!("event=replay standing device unlock replay deferred: {error:#}");
    }
}

fn replay_standing_device_unlocks() -> anyhow::Result<()> {
    let pending: Vec<(i32, Option<Vec<u8>>, CallerInfo)> = {
        let cache = DEVICE_UNLOCK
            .lock()
            .expect("ommega device unlock cache poisoned");
        cache
            .iter()
            .map(|(user_id, entry)| (*user_id, entry.password.clone(), entry.caller.clone()))
            .collect()
    };
    if pending.is_empty() {
        return Ok(());
    }

    let mut deferred = None;
    for (user_id, password, caller) in pending {
        let result = {
            let _guard = BypassGuard::enter();
            ipc::with_ommega_authorization_once(|auth| {
                Ok(auth.r#onDeviceUnlocked(Some(&caller), user_id, password.as_deref())?)
            })
        };
        match result {
            Ok(()) => {
                info!("event=replay restored device unlock user={user_id} after a shadow restart")
            }
            // The shadow is not up yet (still starting, socket gone, service not
            // registered): keep the material and try again on the next contact.
            Err(error) if !shadow_rejected_device_unlock(&error) => {
                warn!(
                    "event=replay ommega not ready for standing device unlock user={user_id}: {error:#}"
                );
                deferred = Some(error);
            }
            // The shadow answered and refused it: the material is stale (password
            // changed, super keys gone), so drop it instead of replaying forever.
            Err(error) => {
                warn!(
                    "event=replay ommega rejected standing device unlock user={user_id}: {error:#}; dropping it"
                );
                forget_device_unlock(user_id);
            }
        }
    }

    match deferred {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Did the shadow answer and refuse, or was it simply not reachable?
///
/// Only the former proves the material is stale. Connection-shaped failures carry no
/// `Status` at all (or a `TransactionFailed` one), and must keep the material around.
fn shadow_rejected_device_unlock(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Status>())
        .is_some_and(|status| status.exception_code() != ExceptionCode::TransactionFailed)
}

#[cfg(test)]
mod tests;
