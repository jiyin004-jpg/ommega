use super::*;

use std::path::PathBuf;

fn caller(uid: i64) -> CallerInfo {
    CallerInfo {
        uid,
        sid: "S-1:9".to_string(),
        pid: 4711,
    }
}

fn reset() {
    DEVICE_UNLOCK
        .lock()
        .expect("ommega device unlock cache poisoned")
        .clear();
    SYNCED_GENERATION.store(UNSYNCED_GENERATION, Ordering::SeqCst);
}

fn cached_password(user_id: i32) -> Option<Option<Vec<u8>>> {
    DEVICE_UNLOCK
        .lock()
        .expect("ommega device unlock cache poisoned")
        .get(&user_id)
        .map(|entry| entry.password.clone())
}

fn cached_caller_uid(user_id: i32) -> Option<i64> {
    DEVICE_UNLOCK
        .lock()
        .expect("ommega device unlock cache poisoned")
        .get(&user_id)
        .map(|entry| entry.caller.uid)
}

#[test]
fn remembers_the_latest_material_per_user() {
    reset();
    remember_device_unlock(0, Some(b"first"), &caller(1000));
    assert_eq!(cached_password(0), Some(Some(b"first".to_vec())));

    // A password change replaces the old material instead of piling up entries.
    remember_device_unlock(0, Some(b"second"), &caller(1000));
    assert_eq!(cached_password(0), Some(Some(b"second".to_vec())));
    assert_eq!(cached_password(10), None);

    // A device without an LSKF is remembered too: replaying "no password" is exactly
    // what such a device needs after a shadow restart.
    remember_device_unlock(10, None, &caller(1000));
    assert_eq!(cached_password(10), Some(None));
    assert_eq!(cached_password(0), Some(Some(b"second".to_vec())));
}

#[test]
fn a_null_follow_up_keeps_the_material_we_already_hold() {
    reset();
    // The framework sends onDeviceUnlocked carrying the password and then a second one
    // without it (and every fingerprint unlock is one without it). The null one must
    // not throw away what the first one gave us, or a shadow restart replays nothing.
    remember_device_unlock(0, Some(b"lskf"), &caller(1000));
    remember_device_unlock(0, None, &caller(1000));
    assert_eq!(cached_password(0), Some(Some(b"lskf".to_vec())));
    assert_eq!(cached_caller_uid(0), Some(1000));
}

#[test]
fn keeps_the_original_caller_for_the_replay() {
    reset();
    remember_device_unlock(0, None, &caller(1000));
    assert_eq!(cached_caller_uid(0), Some(1000));
}

#[test]
fn forget_drops_only_that_user() {
    reset();
    remember_device_unlock(0, Some(b"zero"), &caller(1000));
    remember_device_unlock(10, Some(b"ten"), &caller(1000));

    forget_device_unlock(0);
    assert_eq!(cached_password(0), None);
    assert_eq!(cached_password(10), Some(Some(b"ten".to_vec())));
}

#[test]
fn remembering_counts_as_feeding_the_current_generation() {
    reset();
    let generation = ipc::rpc_generation();
    remember_device_unlock(0, Some(b"pw"), &caller(1000));
    assert_eq!(SYNCED_GENERATION.load(Ordering::SeqCst), generation);
}

#[test]
fn an_empty_cache_marks_the_generation_fed_without_touching_ommega() {
    reset();
    // Nothing cached means nothing to replay, so this must not attempt a connection
    // (a unit test has no shadow to talk to and would block in the connect timeout).
    sync_ommega_state_after_reconnect();
    assert_eq!(
        SYNCED_GENERATION.load(Ordering::SeqCst),
        ipc::rpc_generation()
    );
}

#[test]
fn connection_failures_never_count_as_a_refusal() {
    // No status at all: the connect itself failed, or the daemon is not up yet.
    assert!(!shadow_rejected_device_unlock(&anyhow::anyhow!(
        "failed to connect to ommega_authorization service"
    )));
    // A bare transaction status code is not an answer from the shadow either.
    assert!(!shadow_rejected_device_unlock(&anyhow::Error::new(
        StatusCode::NameNotFound
    )));

    // An actual reply from the shadow that says "no" does drop the material: it means
    // the password is stale or the super keys are gone.
    assert!(shadow_rejected_device_unlock(&anyhow::Error::new(
        Status::new_service_specific_error(ResponseCode::LOCKED.0, None)
    )));
    assert!(shadow_rejected_device_unlock(&anyhow::Error::new(
        Status::new_service_specific_error(ResponseCode::KEY_NOT_FOUND.0, None)
    )));
}

/// A private mirror per test: the real path is disabled under `cfg!(test)`, and the
/// process id keeps parallel tests (and repeated runs) from sharing one file.
fn temp_state_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ommega-unlock-state-{}-{name}.toml",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn the_mirror_survives_a_payload_restart() {
    reset();
    let path = temp_state_path("round-trip");

    // One user with an LSKF and one without: `onDeviceUnlocked` without a password is
    // material worth replaying too, so it has to survive the same trip.
    remember_device_unlock_at(Some(&path), 0, Some(b"lskf-material"), &caller(1000));
    remember_device_unlock_at(Some(&path), 10, None, &caller(1000));

    let mut restored = super::state::load_from(&path);
    restored.sort_by_key(|(user_id, _, _)| *user_id);
    assert_eq!(restored.len(), 2);
    assert_eq!(restored[0].0, 0);
    assert_eq!(restored[0].1, Some(b"lskf-material".to_vec()));
    assert_eq!(restored[0].2.uid, 1000);
    assert_eq!(restored[1].0, 10);
    assert_eq!(restored[1].1, None);

    // The material is only ever as private as the shadow's own key material.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the mirror must not be readable by anyone else"
        );
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn forgetting_the_last_user_removes_the_mirror() {
    reset();
    let path = temp_state_path("forget");
    remember_device_unlock_at(Some(&path), 0, Some(b"zero"), &caller(1000));
    assert!(path.exists());

    // No material left means no file left: nothing may outlive the unlock it came from.
    forget_device_unlock_at(Some(&path), 0);
    assert!(!path.exists());

    remember_device_unlock_at(Some(&path), 0, Some(b"zero"), &caller(1000));
    remember_device_unlock_at(Some(&path), 10, Some(b"ten"), &caller(1000));
    forget_device_unlock_at(Some(&path), 0);
    let restored = super::state::load_from(&path);
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].0, 10);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_corrupt_or_foreign_mirror_only_means_nothing_to_replay() {
    let path = temp_state_path("corrupt");

    std::fs::write(&path, "this is not = [ toml").unwrap();
    assert!(super::state::load_from(&path).is_empty());

    // A format a later payload wrote is not something this one can guess at.
    std::fs::write(&path, "version = 99\n").unwrap();
    assert!(super::state::load_from(&path).is_empty());

    let _ = std::fs::remove_file(&path);
    assert!(super::state::load_from(&path).is_empty());
}

#[test]
fn without_a_mirror_the_material_stays_in_memory() {
    reset();
    remember_device_unlock_at(None, 0, Some(b"only-memory"), &caller(1000));
    assert_eq!(cached_password(0), Some(Some(b"only-memory".to_vec())));

    // The default path is disabled while the suite runs, so a stray unlock can never
    // write to the device's real mirror.
    if std::env::var("OMMEGA_UNLOCK_STATE").is_err() {
        assert!(super::state::state_path().is_none());
    }
}
