//! 在宿主进程里直接跑 KeyMint 服务。
//!
//! 背景：payload 注入 keystore2 之后，它和我们的 HAL 是两个进程，中间还要过一趟
//! RPC socket。按 uid 筛进程、按调用耗时测跳数，这两种查法都能把那一跳看出来。
//! 这条路把服务主体搬进 keystore2 自己的进程，调用改成本地对象直调。
//!
//! 边界（2026-11-09 在设备上探过）：keystore 域读得到 keymaster.db 和系统属性、
//! 能在 /system/bin 里 exec，但读不了 /data/system/packages.list、写不了系统属性。
//! 网络本来是没的（AOSP 原版不给 keystore 域 inet），远程出证又必须从本进程发出去，
//! 所以我们在自己的 sepolicy 里给了 tcp + netd 那几条，见 template/sepolicy.rule。
//! AAID 不靠 packages.list，读 daemon 落的那份表；改属性（resetprop）仍旧归 helper。

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
/// 判定放在 daemon 侧（`src/daemon.rs:inproc_healthy`），这里只负责刷。
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
                        // 定死落盘：同一台机器上这条错基本是确定的（比如 boot key
                        // 是旧版本独立 HAL 铸的，进程内那套找不到），不写出来 daemon
                        // 就要每轮等心跳、白等一分多钟才退到独立 HAL。
                        let _ = std::fs::write(FAILED_PATH, format!("{message}\n"));
                        state.failed = Some(message);
                    }
                }
                STATE_READY.notify_all();
            })
            .ok();

        // 看门狗：过了宽限期还没结论（成或败都没有），就判它起不来。
        // 不这么做的后果是所有调用方每笔都干等 15 秒（见 injector 的 ipc.rs），
        // 实测能把检测器一整轮拖到十几分钟。
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

/// 进程内那套从开始到有结论的宽限期。开库那一步在“另一个进程占着库”的时候会
/// 一直睡下去（上游就是这么写的，把重试改成有超时反而会把整个 keystore2 abort 掉，
/// 实测），所以不能靠它自己回来，得有东西替它下结论。
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

fn start() -> Result<HashMap<&'static str, SIBinder>> {
    let config_file = crate::config::bootstrap_config_file().context("bootstrap config")?;

    // 日志归宿主（payload 已经装了自己的 logger，`log` 的 max_level 也是全局的，
    // 这里再调一次会把 payload 自己的日志一起关掉）。
    info!("starting in-process ommega KeyMint");
    crate::keymaster::permission::initialize_runtime_service_context();
    // 目录/权限这套在这里基本是「看一眼就过」：我们已经是 keystore uid，chown 自己
    // 会成功，chown 到别人的会 EPERM —— 只打日志，不挡启动。
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
    // 同一个流程就手把抽象 socket 也冒充上：SOTER 宿主（uid 1000）在别的进程里，
    // 只能靠这条路找过来。HAL 还在的时候名字被它占着，这里就一直重试，等它退了我们接手。
    let for_rpc: HashMap<&'static str, SIBinder> = services.clone();
    std::thread::Builder::new()
        .name("inproc-rpc".to_string())
        .spawn(move || serve_app_rpc(for_rpc))
        .ok();

    // early boot 结束的重放放在最后一步：它要建一个 KeyMint wrapper（内部会走
    // init_keymint_ta，用到 keybox 和 boot level cache），所以必须在
    // boot_level_cache 和 keybox 都就绪之后 —— 放前面不但会因 boot level key
    // 还没铸出来而让整条启动失败，也会因 keybox 未初始化而让重放自己失败。
    //
    // 根侧（daemon-injector）在 sys.boot_completed=1 后落 boot_done；这里只看它，
    // 不去读属性（payload 是静态链接的，read_string_property 会退到 exec resetprop）。
    if boot_done_present() {
        replay_early_boot_ended();
    } else {
        // 开机时 keystore2 往往比注入器守护先起（实测 13:30:13 vs 13:31），这一刻
        // boot_done 还没落。等它出现再重放，否则 early boot 状态会一直不更新，
        // EARLY_BOOT_ONLY 的钥匙开机之后仍然能 import。
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
///
/// 绑定失败最常见的理由是名字被单独跑的 HAL 占着（切过来的那段过渡期），
/// 所以这里是个带退避的循环，不把它当错误。
fn serve_app_rpc(services: HashMap<&'static str, SIBinder>) {
    // HAL 还占着名字的时候绑不上，这是预期情况；只在原因变化时记一笔，
    // 否则每轮一行会把真正有用的日志淡掉。
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
                // 心跳里的 rpc 字段跟着服务一起改口：这一轮要么没挂全、要么 run() 已经
                // 返回，就说明 app 域那边没人应答了。不回 false 的话，daemon 会一直认为
                // 进程内健康、不去拉独立 HAL，SOTER 宿主那条路就一直空着。
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
            // keystore 域写不了 /proc/self/attr/sockcreate（那份权限是给 root 起的 HAL
            // 用的）。不设也行：socket 会继承本进程的 u:r:keystore:s0，跟 HAL 当初设的
            // 是同一个值，接入判断照样按 uid 走。
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

/// 抽象 socket 的准入判断，跟 lib 里那份一样（file socket 那套在本域名里用不了，
/// 所以这里是单独一份）：keystore 自己、root（软件 SOTER TA）、被注入过的进程。
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
