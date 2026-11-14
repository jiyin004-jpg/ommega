#![recursion_limit = "256"]

// 分配器不在这里定：这个 crate 会被注入进 keystore2 的 payload 链接，payload 跑在别人的
// 进程里，不能替宿主换分配器。

use anyhow::{Context, Result};
use std::panic;
use std::sync::Arc;
use std::time::Duration;
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
pub mod daemon;
pub mod global;
pub mod inproc;
pub mod keybox;
pub mod keymaster;
pub mod keymint;
pub mod logging;
pub mod macros;
pub mod plat;
pub mod proto;
pub mod remote;
pub mod selinux;
pub mod soter_cpu_id;
pub mod soter_host_health;
pub mod soter_relay;
pub mod soter_store;
pub mod stealth;
pub mod utils;
pub mod watchdog;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));
// include!( "./aidl.rs"); // for development only

fn storage_warn(message: String) {
    // The stderr branch covers the case where the logger could not be installed at all.
    // Logging switched off in the WebUI must stay quiet on both paths, so the off switch
    // really means "no logs".
    if !crate::logging::enabled() {
        return;
    }
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
    // 密钥库目录：`data/` 里是 keymint 自己的数据库，只有 keystore 域碰。
    let entries = match std::fs::read_dir(secret_path!("data")) {
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
    // 目录 0771 而非 0770：读的一方不只 keystore 域，SOTER 宿主跑在 uid 1000，
    // 要按已知路径进目录读 ATTK / cpu_id，所以 other 必须有 x（能按名访问、不能列举）。
    // logs 必须是 1777 而不是 0777：注入到 app 域的 payload 要往这里落日志，光靠
    // group 写不够；sticky 位禁止删除/改名或拿软链顶替别人的日志文件，写内容仍允许。
    for (dir, mode) in [
        (root_path!(), 0o771),
        (root_path!("logs"), 0o1777),
        // 密钥材料目录（数据库、rpc.sock）的父目录也要放开到 0771：keystore 域之外
        // 的调用方进不去就会报「unable to open database」。
        (secret_path!(), 0o771),
    ] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            storage_warn(format!("Failed to create ommega directory {dir}: {e:?}"));
            continue;
        }

        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)) {
            storage_warn(format!("Failed to chmod ommega directory {dir}: {e:?}"));
        }

        if let Err(e) = chown_path(dir, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown ommega directory {dir}: {e:?}"));
        }
    }

    // keymint 的数据库目录，keystore 独占。必须在这里建：不存在时开库直接 SIGABRT。
    let db_dir = secret_path!("data");
    if let Err(e) = std::fs::create_dir_all(db_dir) {
        storage_warn(format!(
            "Failed to create ommega db directory {db_dir}: {e:?}"
        ));
    } else {
        if let Err(e) = std::fs::set_permissions(db_dir, std::fs::Permissions::from_mode(0o770)) {
            storage_warn(format!(
                "Failed to chmod ommega db directory {db_dir}: {e:?}"
            ));
        }
        if let Err(e) = chown_path(db_dir, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!(
                "Failed to chown ommega db directory {db_dir}: {e:?}"
            ));
        }
    }

    // 已有日志文件一律 0666（app 域要读）。文件由 payload 在运行时新建、默认 0600，
    // 所以每次启动都得重设一遍。
    if let Ok(entries) = std::fs::read_dir(root_path!("logs")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
            }
        }
    }

    if let Err(e) = crate::keybox::ensure_keybox_file(root_path!("keybox_tee.xml")) {
        storage_warn(format!(
            "Failed to seed ommega keybox {}: {e:?}",
            root_path!("keybox_tee.xml")
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
        // 共享数据：注入到 SOTER 宿主（uid 1000）的 payload 要读，必须是 0644。
        root_path!("config"),
        root_path!("injector.toml"),
        root_path!("target.txt"),
        root_path!("soter_cpu_id"),
        root_path!("soter_attk.pem"),
        root_path!("soter_asks.json"),
        root_path!("uid_packages"),
        root_path!("foreground"),
        root_path!("log_flag"),
        root_path!("keybox_tee.xml"),
        root_path!("keybox_strongbox.xml"),
        root_path!("crash_count"),
        root_path!("logs/keymint.log"),
        root_path!("logs/keymint.log.1"),
        root_path!("logs/injector.log"),
        root_path!("logs/injector.log.1"),
    ] {
        if !Path::new(file).exists() {
            continue;
        }

        // keybox 是密钥材料（只有 keystore 域用），其余是共享数据：`config*` /
        // `injector.toml` 给面板和注入器读，日志给 app 域读。
        let mode = if file.ends_with(".xml") {
            0o600
        } else if file.contains("/logs/") {
            0o666
        } else {
            0o644
        };

        if let Err(e) = std::fs::set_permissions(file, std::fs::Permissions::from_mode(mode)) {
            storage_warn(format!("Failed to chmod ommega file {file}: {e:?}"));
        }

        if let Err(e) = chown_path(file, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown ommega file {file}: {e:?}"));
        }
    }
}

/// Which rendezvous point a server listens on.
#[derive(Clone, Copy)]
enum RpcBind {
    /// A filesystem socket in the keystore state dir.
    FileSocket,
    /// An abstract socket for callers that cannot traverse into the keystore state dir
    /// (the SOTER host runs as uid 1000).
    Abstract,
}

/// True if the injector recorded this pid as carrying our payload. The pid comes from
/// SO_PEERCRED and cannot be forged; hidepid hides other uids' /proc entries from the
/// keystore uid, so only this root-written list can identify the peer. A pid may be stale:
/// pids get reused.
fn peer_is_injected(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    match std::fs::read_to_string(consts::RPC_PEER_STATE) {
        Ok(state) => state.lines().any(|line| {
            line.split_whitespace()
                .next()
                .and_then(|field| field.parse::<i32>().ok())
                == Some(pid)
        }),
        Err(error) => {
            debug!(
                "cannot read the injector peer state {}: {error}",
                consts::RPC_PEER_STATE
            );
            false
        }
    }
}

/// 这个错误是不是「会合点已经有人在服务了」（`EADDRINUSE`）。
/// 绑定失败报的是 `rsbinder::StatusCode::Errno`，也可能在底下包一层 `io::Error`。
fn is_addr_in_use(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if let Some(rsbinder::StatusCode::Errno(errno)) =
            cause.downcast_ref::<rsbinder::StatusCode>()
        {
            return *errno == libc::EADDRINUSE;
        }
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
    })
}

/// 抽象会合点（`ommega.soter.rpc`）一次只能有一个主人：独立 HAL 和 keystore2 里的
/// payload 绑的是同一个名字。先绑上的服务，后到的那份不绑（返回 `None`），主流程照跑。
fn create_app_rpc_server() -> Result<Option<Arc<RpcServer>>> {
    // 重试窗口：守护重启 keymint 时旧进程可能还没释放这个名字。
    const RETRIES: u32 = 20;
    const RETRY_DELAY: Duration = Duration::from_millis(250);
    let mut waited = false;
    for attempt in 0..RETRIES {
        match create_rpc_server(RpcBind::Abstract) {
            Ok(server) => {
                if waited {
                    info!(
                        "ommega RPC abstract socket came free after {} ms",
                        attempt * 250
                    );
                }
                return Ok(Some(server));
            }
            Err(error) if is_addr_in_use(&error) => {
                if !waited {
                    info!(
                        "ommega RPC abstract socket is held by someone else; waiting up to {} ms",
                        RETRIES * 250
                    );
                    waited = true;
                }
                std::thread::sleep(RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    }
    info!(
        "ommega RPC abstract socket stays held by the in-process payload; \
         this HAL will not serve that rendezvous"
    );
    Ok(None)
}

fn create_rpc_server(bind: RpcBind) -> Result<Arc<RpcServer>> {
    set_sockcreate_con(RPC_SOCKET_CONTEXT)
        .context("failed to set ommega RPC socket SELinux context")?;
    let server = match bind {
        RpcBind::FileSocket => RpcServer::setup_unix_server(rpc::SOCKET),
        RpcBind::Abstract => RpcServer::setup_unix_server_abstract(consts::RPC_ABSTRACT_NAME),
    };
    let clear_result =
        clear_sockcreate_con().context("failed to clear ommega RPC socket SELinux context");
    let server = match bind {
        RpcBind::FileSocket => server.context("failed to bind ommega RPC socket")?,
        RpcBind::Abstract => server.context("failed to bind ommega RPC abstract socket")?,
    };
    clear_result?;
    server.set_android13plus(rpc::WIRE_MAX_VERSION);

    if matches!(bind, RpcBind::FileSocket) {
        std::fs::set_permissions(rpc::SOCKET, std::fs::Permissions::from_mode(0o660))
            .context("failed to chmod ommega RPC socket")?;
        // socket 属主必须是 keystore：本进程跑在 system(1000)，连它的是注入进 keystore2
        // 的载荷（uid 1017），0660 加上属主 1000 会被拒。这里还在降权前，能 chown。
        chown_path(rpc::SOCKET, KEYSTORE_UID, KEYSTORE_GID)
            .context("failed to chown ommega RPC socket")?;
    }

    server.set_authorizer(move |peer| {
        let allowed = match peer {
            PeerIdentity::Local { uid, .. } if *uid == KEYSTORE_UID => true,
            // 软件 SOTER TA（soterta.sh 拉起的 `ommega-inject --soterta-serve`）跑在 root：
            // 它既不是 keystore uid 也没被注入过，只能按 uid 放行 —— daemon 已 setuid 成
            // keystore，读不了 root 进程的 /proc/pid/cmdline（ptrace_may_access 回 EPERM）。
            PeerIdentity::Local { uid: 0, .. } => matches!(bind, RpcBind::Abstract),
            PeerIdentity::Local { pid, .. } => {
                matches!(bind, RpcBind::Abstract) && peer_is_injected(*pid)
            }
            _ => false,
        };
        match (allowed, bind) {
            (true, RpcBind::Abstract) => info!("accepted app RPC peer {peer}"),
            (true, RpcBind::FileSocket) => debug!("accepted ommega RPC peer {peer}"),
            (false, _) => warn!("rejected ommega RPC peer {peer}"),
        }
        allowed
    });

    Ok(server)
}

/// 降到 keystore uid 跑。
/// 不能改用 system(1000)：那样 HAL 打不开数据库，载荷也连不上 rpc.sock。
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

pub fn cli_main() {
    // `--exec-hidden <真身> <伪装名> [参数...]`：把 ELF 从 memfd 起成伪装进程。
    // 必须在自举之前处理：本进程只是启动器，处理完就变成目标程序。
    if let Some(pos) = std::env::args().position(|arg| arg == "--exec-hidden") {
        let rest: Vec<String> = std::env::args().skip(pos + 1).collect();
        if rest.len() >= 2 {
            let real = rest[0].clone();
            let fake = rest[1].clone();
            let extra = rest[2..].to_vec();
            if stealth::exec_hidden(&real, &fake, &extra) {
                unreachable!("exec_hidden only returns on failure");
            }
        }
        std::process::exit(1);
    }

    // `--exec-script <脚本> <伪装名> [参数...]`：脚本也塞进 memfd，`sh -s` 从标准输入
    // 读，cmdline 里不会出现模块目录。
    if let Some(pos) = std::env::args().position(|arg| arg == "--exec-script") {
        let rest: Vec<String> = std::env::args().skip(pos + 1).collect();
        if rest.len() >= 2 {
            let script = rest[0].clone();
            let fake = rest[1].clone();
            let extra = rest[2..].to_vec();
            let moddir = std::path::Path::new(&script)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            if stealth::exec_script_hidden(&script, &fake, &extra, &moddir) {
                unreachable!("exec_script_hidden only returns on failure");
            }
        }
        std::process::exit(1);
    }

    // 第一件事：把自己换成「系统二进制名字 + 内存里的本体」。
    // 成功则不返回（fexecve 换掉整个映像），pid 不变；失败静默降级成普通启动。
    stealth::bootstrap("daemon", &["hal", "helper", "soterta", "injector", "adbr"]);

    // cwd 不能停在模块目录 —— `/proc/<pid>/cwd` 会暴露 keybox_tee.xml 这些文件。
    let _ = std::env::set_current_dir("/");

    // 守护模式：`--daemon` 直接进守护循环，放在日志初始化之前。
    // 自举已把参数换成环境变量，`--daemon` 不会留在 cmdline 里。
    if stealth::daemon_mode() || std::env::args().any(|arg| arg == "--daemon") {
        let extra: Vec<String> = std::env::args()
            .skip(1)
            .filter(|arg| arg != "--daemon")
            .collect();
        daemon::run(extra);
    }

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

/// True if the boot root of trust changed and invalidated every keyblob in the persistent
/// keystore database. Matching the TA's `INVALID_KEY_BLOB` separates that case from real
/// corruption, so the database is only wiped when wiping is the only recovery.
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

/// Remove the persistent keystore database and the secure-deletion data file so a fresh one
/// is built against the new root of trust on restart. The SDD file is re-created on demand.
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
    // 真机 cpu_id 是 SOTER 身份的一半：后台线程，不挡启动。
    crate::soter_cpu_id::start();
    // SOTER 宿主「哑了」的体检：后台线程，判定有自己的节拍，不挂在观测到来上。
    crate::soter_host_health::start();

    install_module_info_bundle_if_available().context("failed to initialize moduleHash input")?;

    crate::keymaster::entropy::register_feeder();
    let boot_level_cache = global::DB.with(|db| {
        crate::keymaster::super_key::SuperKeyManager::set_up_boot_level_cache(
            &global::SUPER_KEY,
            &mut db.borrow_mut(),
        )
    });
    if let Err(error) = boot_level_cache {
        // ro.boot.vbmeta.digest / ro.boot.vbmeta.public_key_digest (the WebUI boot-hash and
        // boot-key settings) is part of the device root of trust: changing either makes every
        // keyblob in keymaster.db undecryptable. On that error drop the DB and exit 0 so the
        // watchdog rebuilds it; every other error is a real startup failure.
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
    // 顺序很重要（SKRoot 下）：
    //  - rpc.sock 要在还是 root-like 时建：SKRoot 的 avc 只对 root-like 放行
    //    `create`，先降权再建会被 `avc: denied { create } unix_stream_socket` 拒；
    //  - 取 AAID 必须在降权到 keystore 之后：系统的
    //    KeyAttestationApplicationIdProvider 只认 Keystore/Credstore uid。
    let injector_rpc_server = create_rpc_server(RpcBind::FileSocket)?;
    // 抽象 socket（ommega.soter.rpc）同样要在降权前绑：SKRoot 的 avc 只对 root-like
    // 放行 create。add_service 仍在降权后做，这里只先占住 listen 端。
    let app_server = create_app_rpc_server()?;
    if std::env::var("OMMEGA_KEEP_ROOT").as_deref() != Ok("1") {
        set_keystore_identity()?;
    } else {
        info!("OMMEGA_KEEP_ROOT=1: staying root (skroot fallback)");
    }

    crate::keymaster::metrics_store::update_keystore_crash_count();

    info!("starting thread pool");
    rsbinder::ProcessState::start_thread_pool();

    info!("using injector backend");
    let server = injector_rpc_server;

    info!("creating keystore service");
    let dev = KeystoreService::new_native_binder().context("failed to create ommega service")?;
    let service =
        BnKeymintService::new_binder_with_features(dev, consts::sid_features()).as_binder();

    info!("creating ommega authorization service");
    let auth = AuthorizationManager::new_ommega_binder()
        .context("failed to create ommega authorization service")?
        .as_binder();

    info!("creating ommega maintenance service");
    let maintenance = MaintenanceManager::new_ommega_binder()
        .context("failed to create ommega maintenance service")?
        .as_binder();

    info!("creating ommega metrics service");
    let metrics = Metrics::new_native_binder()
        .context("failed to create ommega metrics service")?
        .as_binder();

    let services: [(&str, rsbinder::SIBinder); 4] = [
        (rpc::SERVICE, service),
        (rpc::AUTHORIZATION_SERVICE, auth),
        (rpc::MAINTENANCE_SERVICE, maintenance),
        (rpc::METRICS_SERVICE, metrics),
    ];

    info!("adding ommega services to RPC server");
    for (name, binder) in &services {
        server
            .add_service(name, binder.clone())
            .with_context(|| format!("failed to add ommega RPC service {name}"))?;
    }

    // 第二个会合点，给 app 域调用方：SOTER 宿主进不去 file socket（keystore 目录 0700）。
    // 独立的 accept 循环，同样的 wire 版本和同一组服务，但准入更窄。
    // 绑定已在降权前完成（见上面 app_server）；抽象会合点已被 keystore2 里的 payload
    // 占住时这里就是 None，那些服务它已经挂上了。
    if let Some(app_server) = app_server.as_ref() {
        for (name, binder) in &services {
            app_server
                .add_service(name, binder.clone())
                .with_context(|| format!("failed to add ommega app RPC service {name}"))?;
        }
        let app_runner = Arc::clone(app_server);
        std::thread::spawn(move || {
            if let Err(error) = app_runner.run() {
                error!("ommega app RPC server stopped: {error:#}");
            }
        });
        info!(
            "serving ommega app RPC abstract socket={}",
            String::from_utf8_lossy(consts::RPC_ABSTRACT_NAME)
        );
    }

    info!("serving ommega RPC socket={}", rpc::SOCKET);
    server.run().context("ommega RPC server stopped")?;
    Ok(())
}
