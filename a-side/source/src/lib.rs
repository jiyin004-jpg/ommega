#![recursion_limit = "256"]

// 分配器不在这里定：这个 crate 同时被 keymint 二进制和 keystore2 里的 payload 链接，
// payload 跑在别人的进程里，不能替宿主换分配器（mimalloc 在 src/main.rs 里）。

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
    // The stderr branch exists for the case where the logger could not be
    // installed at all.  With logging switched off in the WebUI it must stay
    // quiet too, otherwise the warnings land in the root manager's service log
    // and the off switch would not mean "no logs".
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
    // 数据根 / 日志：keystore 域负责写，但读的一方不止 keystore 域 ——
    // SOTER 宿主跑在 uid 1000（`system_app`），它按已知路径进目录读文件。
    // 所以不能是 0770：`other` 连目录都进不去，SOTER 直接读不到 ATTK / cpu_id。
    // 目录给 0771（other 只有 x，不能列举但能按名访问），文件给 0644。
    //
    // logs 必须是 1777 而不是 0777：注入到 app 域（SOTER 宿主不是 keystore uid）的
    // payload 得往这里落日志，光靠 group 写不够。sticky 位拦住「删掉/改名别人的
    // 日志文件」和拿软链顶替已有日志那条路，写内容还是允许的。
    for (dir, mode) in [
        (root_path!(), 0o771),
        (root_path!("logs"), 0o1777),
        // 密钥材料目录（数据库、rpc.sock）的**父目录**也得处理：它以前只给 keystore
        // 用，是 0770 keystore，而 HAL 现在跑在 system(1000) —— 进不去就报
        // 「unable to open database」，一笔出证都做不了。
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

    // 密钥库目录：keymint 的数据库就在这，keystore 独占。
    // 这个目录必须在这里建：它不存在时开库直接 SIGABRT，整个 HAL 不起，一条链都不出。
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

    // 日志给 app 域读写（面板/排查）：目录 1777（sticky），已有文件一律 0666。
    // 文件是运行时新建的（keymint.log 由 payload 写），所以每次启动都得扇一遍，
    // 否则新文件默认 0600，只有 keystore 域读得到。
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
        // 它们曾经是 0600，结果 keystore2 那边正常、SOTER 宿主那边读不到配置。
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

        // keybox 是密钥材料（只有 keystore 域用），其余是共享数据：
        // `config*` / `injector.toml` 要给面板和注入器读，日志要给 app 域读。
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
    /// The original one: a filesystem socket in the keystore state dir.
    FileSocket,
    /// The app-domain one: an abstract socket, for callers that cannot traverse
    /// into the keystore state dir (the SOTER host runs as uid 1000).
    Abstract,
}

/// Has the injector recorded this pid as carrying our payload?
///
/// The pid comes from SO_PEERCRED and cannot be forged, which is what makes this usable as
/// an identity check: the kernel hides other uids' /proc entries from the keystore uid
/// (hidepid), so the peer's command line is out of reach and there is nothing else in the
/// peer credentials to go on. The injector does the injection as root, so it is the one that
/// can keep this list. A stale line is possible (pids do get reused), same as with any such
/// list.
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
        // socket 的属主得是 keystore：这个进程现在跑在 system(1000)，而连它的是
        // 注入进 keystore2 里的载荷（uid 1017）—— 0660 + 属主 1000 的话那边会被拒。
        // 这里还在降权之前，能 chown。
        chown_path(rpc::SOCKET, KEYSTORE_UID, KEYSTORE_GID)
            .context("failed to chown ommega RPC socket")?;
    }

    server.set_authorizer(move |peer| {
        let allowed = match peer {
            PeerIdentity::Local { uid, .. } if *uid == KEYSTORE_UID => true,
            // 软件 SOTER TA（soterta.sh 拉起的 `ommega-inject --soterta-serve`）跑在
            // root 里：它既不是 keystore uid，也没被注入过，光这两条就把它挡在外面，
            // 结果它只能本地自签 —— 微信拿自签 ASK 去腾讯验证必然“系统错误”。
            // 这里只能按 uid 放行：daemon 已经 setuid 成 keystore，读不了 root 进程的
            // /proc/pid/cmdline（ptrace_may_access 会回 EPERM），认不出命令行。
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
///
/// 试过改 system(1000)（跟真 keymint HAL 一致，`ps -A` 按 uid 筛就查不出来了），
/// 但那样 HAL 打不开数据库、载荷连不上 rpc.sock，出证直接废 —— 这条路暂时不通，
/// 先保持 keystore。真正要消掉「多一个 uid=keystore 进程」得把 keymint 逻辑并进
/// keystore2 进程里，而不是换个 uid。
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
    // `--exec-hidden <真身> <伪装名> [参数...]`：替 shell 把 ELF 从 memfd 起成伪装进程。
    // 比自举早处理：这条路上的本进程只是个启动器，处理完就变成目标程序了。
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
    // 成功的话这一行不会返回（fexecve 换掉了整个映像），pid 不变。
    // 失败就静默降级成普通启动 —— 藏不住可以，起不来不行。
    stealth::bootstrap("daemon", &["hal", "helper", "soterta", "injector", "adbr"]);

    // 兜底：不管是怎么进来的（自举成功与否、手动跑、旧路径），cwd 都不该停在
    // 模块目录 —— `/proc/<pid>/cwd` 一读就是 module.prop / keybox_tee.xml 那一堆。
    let _ = std::env::set_current_dir("/");

    // 守护模式：`keymint --daemon` 直接进守护循环（替掉原来的 `template/daemon`
    // shell 脚本）。放在最前面，连日志初始化都不需要 —— 守护只在「启用调试日志」
    // 开着时自己落文件，跟 shell 版一致。
    //
    // 参数已经被自举换成环境变量（`--daemon` 留在 cmdline 里等于自报家门）。
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
    // 真机 cpu_id 是 SOTER 身份的一半，趁早去学 —— 后台线程，不挡启动。
    crate::soter_cpu_id::start();
    // SOTER 宿主「哑了」的体检（见 soter_host_health：判定得有自己的节拍，
    // 不能挂在观测到来上）。同样是个后台线程。
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
    // 顺序很重要（SKRoot 下）：
    //  - rpc.sock 要在还是 root-like 时建：SKRoot 的 avc 只对 root-like 放行，
    //    先降权再建会被 `avc: denied { create } unix_stream_socket` 直接拒；
    //  - 降权到 keystore 才能让后面取 AAID 的 binder 身份合法 —— 系统的
    //    KeyAttestationApplicationIdProvider 只认 Keystore/Credstore uid，
    //    以 root 去要会回 “This service can only be used by Keystore or Credstore”。
    let injector_rpc_server = create_rpc_server(RpcBind::FileSocket)?;
    // 抽象 socket（ommega.soter.rpc）也得在降权前绑：keystore2 里的 payload 域是
    // keystore，而 SKRoot 的 avc 只对 root-like 放行 —— 降权后再绑会被拒，
    // 表现就是 payload 一直报 “trying the abstract socket” 却连不上。
    // 服务（add_service）仍然在降权后添加，这里只先占住 listen 端。
    let app_server = create_rpc_server(RpcBind::Abstract)?;
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

    // Second rendezvous point for app-domain callers: the SOTER host cannot reach
    // the file socket (0700 keystore dir), so it connects here instead. Served by
    // its own accept loop, same wire version, same services, narrower authorizer.
    // （绑定已在降权前完成，见上面 app_server。）
    for (name, binder) in &services {
        app_server
            .add_service(name, binder.clone())
            .with_context(|| format!("failed to add ommega app RPC service {name}"))?;
    }
    let app_runner = Arc::clone(&app_server);
    std::thread::spawn(move || {
        if let Err(error) = app_runner.run() {
            error!("ommega app RPC server stopped: {error:#}");
        }
    });
    info!(
        "serving ommega app RPC abstract socket={}",
        String::from_utf8_lossy(consts::RPC_ABSTRACT_NAME)
    );

    info!("serving ommega RPC socket={}", rpc::SOCKET);
    server.run().context("ommega RPC server stopped")?;
    Ok(())
}
