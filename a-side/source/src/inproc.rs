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
use std::sync::{Condvar, Mutex, Once};
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
            .name("ommega-inproc".to_string())
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
                        state.failed = Some(message);
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
        .name("ommega-inproc-rpc".to_string())
        .spawn(move || serve_app_rpc(for_rpc))
        .ok();

    Ok(services)
}

/// 把本地服务挂到抽象 socket 上，给 app 域的调用方（SOTER 宿主）。
///
/// 绑定失败最常见的理由是名字被单独跑的 HAL 占着（切过来的那段过渡期），
/// 所以这里是个带退避的循环，不把它当错误。
fn serve_app_rpc(services: HashMap<&'static str, SIBinder>) {
    loop {
        match crate::create_rpc_server(crate::RpcBind::Abstract) {
            Ok(server) => {
                let mut ok = true;
                for (name, binder) in &services {
                    if let Err(error) = server.add_service(name, binder.clone()) {
                        warn!("failed to add {name} to in-process RPC: {error:#}");
                        ok = false;
                    }
                }
                if ok {
                    info!(
                        "in-process RPC serving {}",
                        String::from_utf8_lossy(crate::consts::RPC_ABSTRACT_NAME)
                    );
                    if let Err(error) = server.run() {
                        warn!("in-process RPC stopped: {error:#}");
                    }
                }
            }
            Err(error) => log::debug!("in-process RPC not bound yet: {error:#}"),
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}
