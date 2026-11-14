//! 在宿主进程里直接跑 KeyMint 服务。
//!
//! 注入到 keystore2 的 payload 与独立 HAL 是两个进程、中间过一趟 RPC socket，按 uid
//! 筛进程或按耗时测跳数都能看出来。这里把服务主体搬进宿主进程，调用改成本地直调。
//!
//! 域边界：keystore 域读得到 keymaster.db 和系统属性、能在 /system/bin 里 exec，但
//! 读不了 /data/system/packages.list、写不了系统属性；AOSP 原版不给它 inet，而远程
//! 出证必须从本进程发，所以 sepolicy 里单独开了 tcp + netd。AAID 读 daemon 落的表。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use log::{info, warn};
use rsbinder::SIBinder;

use crate::consts::sid_features;
use crate::keymaster::authorization::AuthorizationManager;
use crate::keymaster::maintenance::MaintenanceManager;
use crate::keymaster::metrics::Metrics;
use crate::keymaster::service::KeystoreService;
use crate::top::jiyin004::ommega::IKeymintService::BnKeymintService;

/// 心跳文件：告诉 daemon「进程内这套还活着、RPC 也挂上了」。
/// 判定在 daemon 侧（`src/daemon.rs:inproc_healthy`），这里只负责刷。
const HEARTBEAT_PATH: &str = "/data/misc/ommega/inproc.heartbeat";
/// 起服务失败的原因。存在它就说明这条路在这台机器上跑不了，daemon 直接退到独立 HAL。
const FAILED_PATH: &str = "/data/misc/ommega/inproc.failed";
/// 抽象 socket 是否已经绑上（心跳里的 `rpc=` 字段）。
static RPC_READY: AtomicBool = AtomicBool::new(false);

struct State {
    /// 服务名 -> 本地对象。空表示还没起完。
    services: Option<HashMap<&'static str, SIBinder>>,
    /// 起失败了的原因，避免每次调用都重试一遍。
    failed: Option<String>,
}

static STARTED: Once = Once::new();
static STATE: Mutex<State> = Mutex::new(State {
    services: None,
    failed: None,
});
static STATE_READY: Condvar = Condvar::new();

/// 已经起好了吗（不等）。
pub fn ready() -> bool {
    STATE.lock().map(|s| s.services.is_some()).unwrap_or(false)
}

/// 按服务名取本地对象；没起好或起失败都回 None，调用方自己回退到 RPC。
pub fn service(name: &str) -> Option<SIBinder> {
    let state = STATE.lock().ok()?;
    state.services.as_ref()?.get(name).cloned()
}

/// 后台起一次（幂等）。宿主进程的启动路径不能被我们拖住，所以放线程里。
pub fn request_start() {
    STARTED.call_once(|| {
        std::thread::Builder::new()
            .name("inproc-start".to_string())
            .spawn(|| {
                let result = start();
                let mut state = STATE.lock().expect("inproc state poisoned");
                match result {
                    Ok(services) => {
                        state.services = Some(services);
                        info!(
                            "in-process KeyMint services up ({} services)",
                            state.services.as_ref().map(|s| s.len()).unwrap_or(0)
                        );
                    }
                    Err(error) => {
                        let message = format!("{error:#}");
                        warn!("in-process KeyMint services failed to start: {message}");
                        // 落盘缓存失败原因：这条错在同一台机器上基本是确定的（比如 boot
                        // key 由独立 HAL 铸），不写出来 daemon 每轮要多等一分多钟。
                        let _ = std::fs::write(FAILED_PATH, format!("{message}\n"));
                        state.failed = Some(message);
                    }
                }
                STATE_READY.notify_all();
            })
            .ok();

        // 看门狗：过了宽限期还没有结论就判它起不来。否则每个调用方都要干等 15 秒，
        // 一整轮检测能被拖到十几分钟。
        std::thread::Builder::new()
            .name("inproc-gate".to_string())
            .spawn(|| {
                for _ in 0..START_TIMEOUT.as_secs() {
                    std::thread::sleep(Duration::from_secs(1));
                    let decided = STATE
                        .lock()
                        .map(|state| state.services.is_some() || state.failed.is_some())
                        .unwrap_or(true);
                    if decided {
                        return;
                    }
                }
                warn!(
                    "in-process KeyMint did not come up within {}s; treating it as unavailable",
                    START_TIMEOUT.as_secs()
                );
                let _ = std::fs::write(FAILED_PATH, "startup timed out\n");
                if let Ok(mut state) = STATE.lock() {
                    if state.failed.is_none() && state.services.is_none() {
                        state.failed = Some("startup timed out".to_string());
                    }
                }
                STATE_READY.notify_all();
            })
            .ok();
    });
}

/// 等它起完（最多 `timeout`）。返回是否可用。
pub fn wait_ready(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut state = match STATE.lock() {
        Ok(state) => state,
        Err(_) => return false,
    };
    while state.services.is_none() && state.failed.is_none() {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let (next, _) = STATE_READY
            .wait_timeout(state, deadline - now)
            .unwrap_or_else(|err| err.into_inner());
        state = next;
    }
    state.services.is_some()
}

/// 根侧落的「开机已完成」标记。
const BOOT_DONE_PATH: &str = "/data/misc/ommega/boot_done";

/// 从开始到必须有结论的宽限期。开库那一步在别的进程占着库时会一直睡下去（上游实现
/// 如此，改成带超时的重试会让整个 keystore2 abort），所以得由外部下结论。
const START_TIMEOUT: Duration = Duration::from_secs(60);

fn boot_done_present() -> bool {
    crate::global::boot_completed() || std::path::Path::new(BOOT_DONE_PATH).exists()
}

/// 把 early boot 结束重放给 KeyMint，幂等。
fn replay_early_boot_ended() {
    match crate::keymaster::maintenance::replay_early_boot_ended() {
        Ok(()) => info!("in-process early boot ended replay done"),
        Err(error) => warn!("failed to replay earlyBootEnded in-process: {error:#}"),
    }
}

/// 播种 config.toml：走临时文件 + rename，要求 `/data/misc/ommega` 可写。目录还没被
/// chown 给 keystore 时最多等 5 秒，等不到就把错误交回调用方。
fn seed_config_with_retry() -> Result<crate::config::ConfigFile> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match crate::config::bootstrap_config_file() {
            Ok(config) => return Ok(config),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn start() -> Result<HashMap<&'static str, SIBinder>> {
    let config_file = seed_config_with_retry().context("bootstrap config")?;

    // 日志归宿主：payload 已装自己的 logger，`log` 的 max_level 是全局的，
    // 这里再调一次会把 payload 自己的日志一起关掉。
    info!("starting in-process ommega KeyMint");
    crate::keymaster::permission::initialize_runtime_service_context();
    // 目录/权限只打日志不挡启动：这里已是 keystore uid，chown 别人的会 EPERM。
    crate::prepare_android_storage();
    let _ = rsbinder::ProcessState::init_default();

    let resolved_trust = crate::plat::vbmeta::bootstrap_vbmeta(&config_file)
        .context("failed to bootstrap vbmeta")?;
    crate::config::install_runtime_config(config_file, resolved_trust)
        .context("failed to install runtime config")?;

    crate::keymaster::entropy::register_feeder();
    let boot_level_cache = crate::global::DB.with(|db| {
        crate::keymaster::super_key::SuperKeyManager::set_up_boot_level_cache(
            &crate::global::SUPER_KEY,
            &mut db.borrow_mut(),
        )
    });
    boot_level_cache.context("failed to initialize boot-level key cache")?;

    crate::keybox::initialize().context("failed to initialize keybox runtime")?;
    crate::repair_ommega_data_files();
    crate::keymaster::metrics_store::update_keystore_crash_count();

    let dev = KeystoreService::new_native_binder().context("failed to create ommega service")?;
    let service = BnKeymintService::new_binder_with_features(dev, sid_features()).as_binder();
    let auth = AuthorizationManager::new_ommega_binder()
        .context("failed to create ommega authorization service")?
        .as_binder();
    let maintenance = MaintenanceManager::new_ommega_binder()
        .context("failed to create ommega maintenance service")?
        .as_binder();
    let metrics = Metrics::new_native_binder()
        .context("failed to create ommega metrics service")?
        .as_binder();

    let mut services: HashMap<&'static str, SIBinder> = HashMap::new();
    for (name, binder) in [
        (kmr_common::rpc::SERVICE, service),
        (kmr_common::rpc::AUTHORIZATION_SERVICE, auth),
        (kmr_common::rpc::MAINTENANCE_SERVICE, maintenance),
        (kmr_common::rpc::METRICS_SERVICE, metrics),
    ] {
        services.insert(name, binder);
    }
    // 顺手把抽象 socket 也挂上：SOTER 宿主（uid 1000）在别的进程里，只能走这条路。
    // 名字被独立 HAL 占着时一直重试，等它退了我们接手。
    let for_rpc: HashMap<&'static str, SIBinder> = services.clone();
    std::thread::Builder::new()
        .name("inproc-rpc".to_string())
        .spawn(move || serve_app_rpc(for_rpc))
        .ok();

    // early boot 结束的重放必须在 boot level cache 和 keybox 都就绪之后：它要建
    // KeyMint wrapper（内部走 init_keymint_ta），提前做会整条启动失败。
    // 只看根侧的 boot_done 标记，不读属性（payload 静态链接，读属性会退到 exec resetprop）。
    if boot_done_present() {
        replay_early_boot_ended();
    } else {
        // 宿主常比注入器守护先起，这一刻 boot_done 还没落。等它出现再重放，
        // 否则 EARLY_BOOT_ONLY 的钥匙开机之后仍然能 import。
        let spawned = std::thread::Builder::new()
            .name("inproc-boot-wait".to_string())
            .spawn(|| {
                for _ in 0..300 {
                    std::thread::sleep(Duration::from_secs(2));
                    if boot_done_present() {
                        replay_early_boot_ended();
                        return;
                    }
                }
                warn!("boot_done never appeared; skipping early boot ended replay");
            });
        if let Err(error) = spawned {
            warn!("failed to spawn in-process boot wait: {error}");
        }
    }

    // 心跳：daemon 靠它判断「进程内还在不在」，不看 socket 归属（回退的 HAL 也绑同一个名字）。
    std::thread::Builder::new()
        .name("inproc-beat".to_string())
        .spawn(|| loop {
            let rpc = if RPC_READY.load(Ordering::Relaxed) {
                1
            } else {
                0
            };
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let body = format!("pid={} ts={ts} rpc={rpc}\n", std::process::id());
            let _ = std::fs::write(HEARTBEAT_PATH, body);
            std::thread::sleep(Duration::from_secs(30));
        })
        .ok();

    Ok(services)
}

/// 把本地服务挂到抽象 socket 上，给 app 域的调用方（SOTER 宿主）。
/// 名字被独立 HAL 占着时绑定会失败，这是预期情况，所以是带退避的循环而非错误。
fn serve_app_rpc(services: HashMap<&'static str, SIBinder>) {
    // 绑不上（名字被 HAL 占着）是预期情况，只在原因变化时记一笔，免得刷掉有用日志。
    let mut last_error = String::new();
    loop {
        match bind_app_rpc() {
            Ok(server) => {
                last_error.clear();
                let mut ok = true;
                for (name, binder) in &services {
                    if let Err(error) = server.add_service(name, binder.clone()) {
                        warn!("failed to add {name} to in-process RPC: {error:#}");
                        ok = false;
                    }
                }
                if ok {
                    RPC_READY.store(true, Ordering::Relaxed);
                    info!(
                        "in-process RPC serving {}",
                        String::from_utf8_lossy(crate::consts::RPC_ABSTRACT_NAME)
                    );
                    if let Err(error) = server.run() {
                        warn!("in-process RPC stopped: {error:#}");
                    }
                }
                // 没挂全或 run() 已返回都说明 app 域没人应答，rpc 字段必须回 false，
                // 否则 daemon 会一直认为进程内健康、不去拉独立 HAL。
                RPC_READY.store(false, Ordering::Relaxed);
            }
            Err(error) => {
                RPC_READY.store(false, Ordering::Relaxed);
                let message = format!("{error:#}");
                if message != last_error {
                    log::debug!("in-process RPC not bound yet: {message}");
                    last_error = message;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(15));
    }
}

fn bind_app_rpc() -> Result<Arc<rsbinder::rpc::RpcServer>> {
    match crate::create_rpc_server(crate::RpcBind::Abstract) {
        Ok(server) => Ok(server),
        Err(error) => {
            // keystore 域写不了 /proc/self/attr/sockcreate（那权限只给 root 起的 HAL）。
            // 不设也行：socket 继承本进程的 u:r:keystore:s0，接入判断照样按 uid 走。
            log::debug!(
                "sockcreate context unavailable in this domain ({error:#}); binding directly"
            );
            let server = rsbinder::rpc::RpcServer::setup_unix_server_abstract(
                crate::consts::RPC_ABSTRACT_NAME,
            )
            .context("failed to bind in-process app RPC socket")?;
            server.set_android13plus(kmr_common::rpc::WIRE_MAX_VERSION);
            server.set_authorizer(app_authorizer());
            Ok(server)
        }
    }
}

/// 抽象 socket 的准入判断（file socket 那套在本域名里用不了，所以单独一份）：
/// keystore 自己、root（软件 SOTER TA）、被注入过的进程。
fn app_authorizer() -> impl Fn(&rsbinder::rpc::PeerIdentity) -> bool + Send + Sync + 'static {
    move |peer| {
        let allowed = match peer {
            rsbinder::rpc::PeerIdentity::Local { uid, .. }
                if *uid == kmr_common::consts::KEYSTORE_UID =>
            {
                true
            }
            rsbinder::rpc::PeerIdentity::Local { uid: 0, .. } => true,
            rsbinder::rpc::PeerIdentity::Local { pid, .. } => crate::peer_is_injected(*pid),
            _ => false,
        };
        if allowed {
            info!("accepted app RPC peer {peer}");
        } else {
            warn!("rejected app RPC peer {peer}");
        }
        allowed
    }
}
