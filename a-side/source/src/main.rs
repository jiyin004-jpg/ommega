#![recursion_limit = "256"]

use anyhow::{Context, Result};
use std::panic;
use std::sync::Arc;
use std::{ffi::CString, os::unix::fs::PermissionsExt, path::Path};

use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::rpc;
use kmr_common::selinux::{clear_sockcreate_con, set_sockcreate_con};
use log::{debug, error, info, warn, LevelFilter};
use rsbinder::rpc::{PeerIdentity, RpcServer};

use crate::{
    consts::RPC_SOCKET_CONTEXT,
    keymaster::service::KeystoreService,
    keymaster::{
        authorization::AuthorizationManager, maintenance::MaintenanceManager, metrics::Metrics,
    },
    top::jiyin004::ommega::IKeymintService::BnKeymintService,
};

pub mod att_mgr;
pub mod config;
pub mod consts;
pub mod global;
pub mod keybox;
pub mod keymaster;
pub mod keymint;
pub mod logging;
pub mod macros;
pub mod plat;
pub mod proto;
pub mod remote;
pub mod selinux;
pub mod utils;
pub mod watchdog;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));
// include!( "./aidl.rs"); // for development only

fn storage_warn(message: String) {
    if log::log_enabled!(log::Level::Warn) {
        warn!("{message}");
    } else {
        eprintln!("Storage warning: {message}");
    }
}

fn chown_path(path: &str, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    let c_path = CString::new(path).expect("path must not contain interior NUL bytes");
    let result = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn repair_ommega_data_files() {
    let entries = match std::fs::read_dir(root_path!("data")) {
        Ok(entries) => entries,
        Err(e) => {
            storage_warn(format!("Failed to list ommega data directory: {e:?}"));
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                storage_warn(format!("Failed to read ommega data directory entry: {e:?}"));
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                storage_warn(format!("Failed to stat ommega data file {path:?}: {e:?}"));
                continue;
            }
        };
        if !file_type.is_file() {
            continue;
        }

        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            storage_warn(format!("Failed to chmod ommega data file {path:?}: {e:?}"));
        }
        let Some(path) = path.to_str() else {
            storage_warn(format!("Skipping non-UTF8 ommega data file path {path:?}"));
            continue;
        };
        if let Err(e) = chown_path(path, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown ommega data file {path}: {e:?}"));
        }
    }
}

fn prepare_android_storage() {
    for dir in [root_path!(), root_path!("data"), root_path!("logs")] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            storage_warn(format!("Failed to create ommega directory {dir}: {e:?}"));
            continue;
        }

        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o770)) {
            storage_warn(format!("Failed to chmod ommega directory {dir}: {e:?}"));
        }

        if let Err(e) = chown_path(dir, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown ommega directory {dir}: {e:?}"));
        }
    }

    if let Err(e) = crate::keybox::ensure_keybox_file(root_path!("keybox.xml")) {
        storage_warn(format!(
            "Failed to seed ommega keybox {}: {e:?}",
            root_path!("keybox.xml")
        ));
    }

    for file in [
        root_path!("keymint.log.lock"),
        root_path!("injector.log.lock"),
    ] {
        match std::fs::remove_file(file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => storage_warn(format!(
                "Failed to remove legacy ommega lock file {file}: {e:?}"
            )),
        }
    }

    for file in [
        root_path!("config.toml"),
        root_path!("config.toml.bak"),
        root_path!("keybox.xml"),
        root_path!("crash_count"),
        root_path!("logs/keymint.log"),
        root_path!("logs/keymint.log.1"),
        root_path!("logs/injector.log"),
        root_path!("logs/injector.log.1"),
    ] {
        if !Path::new(file).exists() {
            continue;
        }

        let mode = if file.ends_with(".xml") { 0o600 } else { 0o660 };

        if let Err(e) = std::fs::set_permissions(file, std::fs::Permissions::from_mode(mode)) {
            storage_warn(format!("Failed to chmod ommega file {file}: {e:?}"));
        }

        if let Err(e) = chown_path(file, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown ommega file {file}: {e:?}"));
        }
    }
}

fn create_rpc_server() -> Result<Arc<RpcServer>> {
    set_sockcreate_con(RPC_SOCKET_CONTEXT)
        .context("failed to set ommega RPC socket SELinux context")?;
    let server = RpcServer::setup_unix_server(rpc::SOCKET);
    let clear_result =
        clear_sockcreate_con().context("failed to clear ommega RPC socket SELinux context");
    let server = server.context("failed to bind ommega RPC socket")?;
    clear_result?;
    server.set_android13plus(rpc::WIRE_MAX_VERSION);
    std::fs::set_permissions(rpc::SOCKET, std::fs::Permissions::from_mode(0o660))
        .context("failed to chmod ommega RPC socket")?;

    server.set_authorizer(|peer| {
        let allowed = matches!(
            peer,
            PeerIdentity::Local { uid, .. } if *uid == KEYSTORE_UID
        );
        if !allowed {
            warn!("rejected ommega RPC peer {peer}");
        }
        allowed
    });

    Ok(server)
}

fn set_keystore_identity() -> Result<()> {
    let failed = unsafe { libc::setgid(KEYSTORE_GID) != 0 || libc::setuid(KEYSTORE_UID) != 0 };
    if failed {
        return Err(std::io::Error::last_os_error()).context("failed to enter keystore uid/gid");
    }
    Ok(())
}

fn should_resolve_module_info_bundle(android_major_version: Option<i32>) -> bool {
    !matches!(android_major_version, Some(version) if version < 16)
}

fn install_module_info_bundle_if_available() -> Result<()> {
    if !should_resolve_module_info_bundle(kmr_common::android_version::android_major_version()) {
        info!("skipping moduleHash input on pre-Android 16 system");
        return Ok(());
    }

    // We can no longer resolve module info after dropping privileges.
    debug!("resolving APEX module info with root privileges");
    match crate::keymaster::apex::resolve_module_info_bundle() {
        Ok(bundle) => {
            let source = bundle.source.as_str();
            let module_count = bundle.modules.len();
            let sha256 = hex::encode(&bundle.sha256);
            global::install_module_info_bundle(bundle)
                .context("failed to install APEX module info bundle")?;
            info!(
                "Initialized moduleHash input from {source} with {module_count} active modules (sha256={sha256})"
            );
        }
        Err(error) => {
            warn!(
                "moduleHash attestation disabled because APEX module info is unavailable: {error:#}"
            );
        }
    }

    Ok(())
}

fn main() {
    logging::init_logger();
    prepare_android_storage();
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    if let Err(error) = run() {
        error!("fatal startup error: {error:#}");
        std::process::exit(1);
    }
}

/// True if the boot root-of-trust changed on this boot and invalidated every
/// keyblob in the persistent keystore database.  Detecting the exact error the
/// TA reports (`INVALID_KEY_BLOB`) lets us distinguish "ROT changed" from real
/// corruption, so we only wipe the database in the one case where wiping is
/// the only recovery.
fn is_root_of_trust_mismatch(error: &anyhow::Error) -> bool {
    matches!(
        error
            .root_cause()
            .downcast_ref::<crate::keymaster::error::Error>(),
        Some(crate::keymaster::error::Error::Km(
            crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_KEY_BLOB,
        ))
    )
}

/// Remove the persistent keystore database (and the secure-deletion data file)
/// so that a fresh one is built against the new root of trust on restart.
/// The SDD file is re-created on demand, so dropping it is harmless.
fn clear_ommega_keymaster_db() -> Result<()> {
    let db_root = crate::global::db_root_path();
    for name in [
        "keymaster.db",
        "keymaster.db-wal",
        "keymaster.db-shm",
        "keymint.dat",
    ] {
        let path = db_root.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => info!("removed {path:?} after root-of-trust change"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!("failed to remove {path:?}: {e}"),
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    let config_file = config::bootstrap_config_file().context("failed to bootstrap config")?;
    let level = config_file
        .main
        .log_level
        .trim()
        .parse()
        .unwrap_or(LevelFilter::Debug);
    log::set_max_level(level);

    info!("starting ommega");
    crate::keymaster::permission::initialize_runtime_service_context();

    prepare_android_storage();
    plat::resetprop::bootstrap_privileged_helper()
        .context("failed to bootstrap resetprop helper")?;

    info!("initial process state");
    let _ = rsbinder::ProcessState::init_default();

    let resolved_trust =
        plat::vbmeta::bootstrap_vbmeta(&config_file).context("failed to bootstrap vbmeta")?;
    prepare_android_storage();
    config::install_runtime_config(config_file, resolved_trust)
        .context("failed to install runtime config")?;

    install_module_info_bundle_if_available().context("failed to initialize moduleHash input")?;

    crate::keymaster::entropy::register_feeder();
    let boot_level_cache = global::DB.with(|db| {
        crate::keymaster::super_key::SuperKeyManager::set_up_boot_level_cache(
            &global::SUPER_KEY,
            &mut db.borrow_mut(),
        )
    });
    if let Err(error) = boot_level_cache {
        // Changing ro.boot.vbmeta.digest / ro.boot.vbmeta.public_key_digest (the
        // WebUI boot-hash / boot-key settings) changes the device root of trust,
        // which makes every keyblob in keymaster.db undecryptable.  The old keys
        // are unusable no matter what, so drop the database and exit cleanly:
        // the daemon watchdog restarts us and a fresh DB is built against the
        // new ROT.  Any other error is a real startup failure.
        if is_root_of_trust_mismatch(&error) {
            warn!(
                "boot root-of-trust changed; clearing ommega keymaster.db and restarting to rebuild: {error:#}"
            );
            if let Err(cleanup_error) = clear_ommega_keymaster_db() {
                error!("failed to clear ommega keymaster.db after ROT change: {cleanup_error:#}");
                return Err(error);
            }
            std::process::exit(0);
        }
        return Err(error).context("failed to initialize boot-level key cache");
    }
    let boot_completed =
        crate::plat::resetprop::read_string_property("sys.boot_completed").as_deref() == Some("1");
    if boot_completed {
        crate::keymaster::maintenance::replay_early_boot_ended()
            .context("failed to replay earlyBootEnded to KeyMint wrappers")?;
    }
    std::thread::spawn(move || {
        global::await_boot_completed();
        if boot_completed {
            return;
        }
        if let Err(error) = crate::keymaster::maintenance::replay_early_boot_ended() {
            error!("failed to replay earlyBootEnded after boot completed: {error:#}");
        }
    });
    repair_ommega_data_files();

    keybox::initialize().context("failed to initialize keybox runtime")?;

    info!("setting uid/gid={} role=keystore", KEYSTORE_UID);
    set_keystore_identity()?;

    let injector_rpc_server = create_rpc_server()?;

    crate::keymaster::metrics_store::update_keystore_crash_count();

    info!("starting thread pool");
    rsbinder::ProcessState::start_thread_pool();

    info!("using injector backend");
    let server = injector_rpc_server;

    info!("creating keystore service");
    let dev = KeystoreService::new_native_binder().context("failed to create ommega service")?;

    info!("adding ommega service to RPC server");
    let service = BnKeymintService::new_binder_with_features(dev, consts::sid_features());
    server
        .add_service(rpc::SERVICE, service.as_binder())
        .context("failed to add ommega RPC service")?;

    info!("creating ommega authorization service");
    let auth = AuthorizationManager::new_ommega_binder()
        .context("failed to create ommega authorization service")?;
    info!("adding ommega authorization service to RPC server");
    server
        .add_service(rpc::AUTHORIZATION_SERVICE, auth.as_binder())
        .context("failed to add ommega authorization RPC service")?;

    info!("creating ommega maintenance service");
    let maintenance = MaintenanceManager::new_ommega_binder()
        .context("failed to create ommega maintenance service")?;
    info!("adding ommega maintenance service to RPC server");
    server
        .add_service(rpc::MAINTENANCE_SERVICE, maintenance.as_binder())
        .context("failed to add ommega maintenance RPC service")?;

    info!("creating ommega metrics service");
    let metrics =
        Metrics::new_native_binder().context("failed to create ommega metrics service")?;
    info!("adding ommega metrics service to RPC server");
    server
        .add_service(rpc::METRICS_SERVICE, metrics.as_binder())
        .context("failed to add ommega metrics RPC service")?;

    info!("serving ommega RPC socket={}", rpc::SOCKET);
    server.run().context("ommega RPC server stopped")?;
    Ok(())
}
