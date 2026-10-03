use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, Once};
use std::time::{Duration, Instant};
use std::{cmp, thread};

use anyhow::{Context, Result};
use kmr_common::rpc;
use log::{debug, warn};
use rsbinder::rpc::RpcSession;
use rsbinder::{
    hub, DeathRecipient, ExceptionCode, FromIBinder, SIBinder, Status, StatusCode, Strong, WIBinder,
};

use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::filter::PackageResolution;
use crate::top::jiyin004::ommega::IAuthorizationService::IAuthorizationService;
use crate::top::jiyin004::ommega::IKeymintService::IKeymintService;
use crate::top::jiyin004::ommega::IMaintenanceService::IMaintenanceService;

// 30s, matching inject.rs: tolerate keymint rebinding rpc.sock across a
// keystore2 restart instead of giving up after 10s.
const RPC_READY_TIMEOUT: Duration = Duration::from_secs(30);
const RPC_READY_RETRY_DELAY: Duration = Duration::from_millis(200);
const PM_SERVICE: &str = "sec_key_att_app_id_provider";

/// Second rendezvous point for app-domain callers, on the abstract namespace.
///
/// It has to match `consts::RPC_ABSTRACT_NAME` on the daemon side (the two crates
/// share no code, so the name lives in both). The file socket sits under
/// /data/misc/keystore, which is 0700 keystore: the SOTER host (system uid) cannot
/// even traverse into it. An abstract socket has no filesystem entry, so DAC does
/// not apply; admission is SELinux plus the daemon's authorizer.
pub const RPC_ABSTRACT_NAME: &[u8] = b"ommega.soter.rpc";

thread_local! {
    static PM: RefCell<Option<Strong<dyn IKeyAttestationApplicationIdProvider>>> = const { RefCell::new(None) };
    static PM_DEATH: RefCell<Option<Arc<dyn DeathRecipient>>> = const { RefCell::new(None) };
}

static PROCESS_STATE_INIT: Once = Once::new();
static RPC_CACHE: Mutex<RpcCacheState> = Mutex::new(RpcCacheState {
    generation: 0,
    cache: None,
    connecting: None,
    next_connect_attempt: 0,
    last_connect_error: None,
});
static RPC_CACHE_READY: Condvar = Condvar::new();

struct RpcCacheState {
    generation: u64,
    cache: Option<RpcCache>,
    connecting: Option<u64>,
    next_connect_attempt: u64,
    last_connect_error: Option<Arc<anyhow::Error>>,
}

struct RpcCache {
    session: RpcSession,
    services: HashMap<&'static str, SIBinder>,
}

#[derive(Clone)]
struct SharedRpcConnectError(Arc<anyhow::Error>);

impl fmt::Debug for SharedRpcConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0.as_ref(), f)
    }
}

impl fmt::Display for SharedRpcConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl std::error::Error for SharedRpcConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

fn shared_rpc_connect_error(error: &Arc<anyhow::Error>) -> anyhow::Error {
    anyhow::Error::new(SharedRpcConnectError(Arc::clone(error)))
}

struct PmDeathRecipient;

impl DeathRecipient for PmDeathRecipient {
    fn binder_died(&self, _who: &WIBinder) {
        clear_pm_cache();
        warn!("{} binder died; cache cleared", PM_SERVICE);
    }
}

pub fn ensure_process_state() {
    PROCESS_STATE_INIT.call_once(|| {
        let _ = rsbinder::ProcessState::init_default();
        debug!("rsbinder process state initialized");
    });
}

pub fn install_direct_rpc_session() -> Result<()> {
    ensure_process_state();
    let cache = connect_rpc_session("failed to connect ommega RPC socket")?;
    let old = {
        let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
        state.generation = state.generation.wrapping_add(1);
        state.last_connect_error = None;
        state.cache.replace(cache)
    };
    RPC_CACHE_READY.notify_all();
    drop(old);
    Ok(())
}

fn connect_rpc_session(connect_context: &'static str) -> Result<RpcCache> {
    let start = Instant::now();
    loop {
        match connect_rpc_session_once(connect_context) {
            Ok(session) => return Ok(session),
            Err(error) => {
                // A policy denial on the abstract rendezvous point is permanent, and an
                // app-domain target has no other way in: returning here instead of after
                // the full timeout keeps the host process from stalling half a minute on
                // every start (and stops the retry loop from spamming audit denials).
                if app_domain_rpc_denied() {
                    return Err(error)
                        .context("ommega RPC is denied by policy for this app-domain process");
                }
                if start.elapsed() >= RPC_READY_TIMEOUT {
                    return Err(error).context("ommega RPC server did not become ready in time");
                }
                thread::sleep(cmp::min(
                    RPC_READY_RETRY_DELAY,
                    RPC_READY_TIMEOUT.saturating_sub(start.elapsed()),
                ));
            }
        }
    }
}

fn connect_rpc_session_once(connect_context: &'static str) -> Result<RpcCache> {
    let session =
        match RpcSession::setup_unix_client_android13plus(rpc::SOCKET, rpc::WIRE_MAX_VERSION) {
            Ok(session) => session,
            Err(file_error) => {
                debug!(
                "ommega RPC file socket {} unusable ({file_error:#}); trying the abstract socket",
                rpc::SOCKET
            );
                RpcSession::setup_unix_client_android13plus_abstract(
                    RPC_ABSTRACT_NAME,
                    rpc::WIRE_MAX_VERSION,
                )
                .with_context(|| format!("{connect_context} (file socket: {file_error:#})"))?
            }
        };
    let service = session.get_service(rpc::SERVICE).context(connect_context)?;
    Ok(RpcCache {
        session,
        services: HashMap::from([(rpc::SERVICE, service)]),
    })
}

/// What a connect attempt to the abstract rendezvous point says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AbstractProbe {
    /// Connected: the listener is there and policy allows the connect. The probe
    /// connection is closed again immediately.
    Reachable,
    /// The kernel refused the connect for policy reasons (SELinux). Retrying cannot
    /// help, so a caller should give up instead of waiting out a timeout.
    Denied,
    /// No listener on that name; the daemon is most likely not up yet.
    Absent,
}

fn probe_abstract_rpc() -> AbstractProbe {
    let Ok((addr, len)) = crate::inject::payload_fd::build_abstract_sockaddr(RPC_ABSTRACT_NAME)
    else {
        return AbstractProbe::Absent;
    };
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return AbstractProbe::Absent;
        }
        let result = libc::connect(
            fd,
            &addr as *const libc::sockaddr_un as *const libc::sockaddr,
            len as libc::socklen_t,
        );
        let errno = if result == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        };
        libc::close(fd);

        if errno == 0 {
            AbstractProbe::Reachable
        } else if errno == libc::EACCES || errno == libc::EPERM {
            AbstractProbe::Denied
        } else {
            AbstractProbe::Absent
        }
    }
}

/// This process is not keystore itself and the abstract rendezvous point is denied
/// by policy, so no amount of retrying will produce an RPC session.
fn app_domain_rpc_denied() -> bool {
    if unsafe { libc::geteuid() } == kmr_common::consts::KEYSTORE_UID {
        return false;
    }
    probe_abstract_rpc() == AbstractProbe::Denied
}

/// Is the abstract rendezvous point reachable? A connect answers it.
///
/// The pre-injection wait uses this: a target that cannot see the file socket path
/// at all (EACCES on the keystore dir) would otherwise burn the full timeout waiting
/// for a stat that will never succeed.
pub fn abstract_rpc_reachable() -> bool {
    probe_abstract_rpc() == AbstractProbe::Reachable
}

fn ensure_rpc_cache(connect_context: &'static str) -> Result<()> {
    loop {
        let (generation, attempt) = {
            let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
            if state.cache.is_some() {
                return Ok(());
            }
            if let Some(attempt) = state.connecting {
                state = RPC_CACHE_READY
                    .wait_while(state, |state| {
                        state.cache.is_none() && state.connecting == Some(attempt)
                    })
                    .expect("RPC cache poisoned");
                if state.cache.is_some() {
                    return Ok(());
                }
                if state.connecting != Some(attempt) {
                    if let Some(error) = state.last_connect_error.as_ref() {
                        return Err(shared_rpc_connect_error(error));
                    }
                }
                drop(state);
                continue;
            }

            let attempt = state.next_connect_attempt;
            state.next_connect_attempt = state.next_connect_attempt.wrapping_add(1);
            state.connecting = Some(attempt);
            (state.generation, attempt)
        };

        let candidate = connect_rpc_session(connect_context);
        let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
        if state.connecting == Some(attempt) {
            state.connecting = None;
        }
        let mut stale_cache = None;
        let outcome = if state.cache.is_none() && state.generation == generation {
            match candidate {
                Ok(cache) => {
                    state.cache = Some(cache);
                    state.generation = state.generation.wrapping_add(1);
                    state.last_connect_error = None;
                    Some(Ok(()))
                }
                Err(error) => {
                    let error = Arc::new(error);
                    state.last_connect_error = Some(Arc::clone(&error));
                    Some(Err(shared_rpc_connect_error(&error)))
                }
            }
        } else {
            if let Ok(cache) = candidate {
                stale_cache = Some(cache);
            }
            None
        };
        RPC_CACHE_READY.notify_all();
        drop(state);
        drop(stale_cache);
        if let Some(outcome) = outcome {
            return outcome;
        }
    }
}

fn get_rpc_binder<T>(
    service_name: &'static str,
    connect_context: &'static str,
    refresh: bool,
) -> Result<Strong<T>>
where
    T: FromIBinder + ?Sized + 'static,
{
    let mut reconnected = false;
    loop {
        ensure_rpc_cache(connect_context)?;
        let (session, identity, cached) = {
            let state = RPC_CACHE.lock().expect("RPC cache poisoned");
            let Some(cache) = state.cache.as_ref() else {
                continue;
            };
            (
                cache.session.clone(),
                cache
                    .services
                    .get(rpc::SERVICE)
                    .expect("RPC cache missing base service")
                    .clone(),
                cache.services.get(service_name).cloned(),
            )
        };

        if let Some(binder) = cached.filter(|_| !refresh) {
            let client = <T as FromIBinder>::try_from(binder).context(connect_context)?;
            let state = RPC_CACHE.lock().expect("RPC cache poisoned");
            if state
                .cache
                .as_ref()
                .and_then(|cache| cache.services.get(rpc::SERVICE))
                == Some(&identity)
            {
                return Ok(client);
            }
            continue;
        }

        let result = session.get_service(service_name);
        let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
        if state
            .cache
            .as_ref()
            .and_then(|cache| cache.services.get(rpc::SERVICE))
            != Some(&identity)
        {
            drop(state);
            continue;
        }

        match result {
            Ok(binder) => {
                let client =
                    <T as FromIBinder>::try_from(binder.clone()).context(connect_context)?;
                let cache = state.cache.as_mut().expect("RPC cache identity matched");
                let old = cache.services.insert(service_name, binder);
                drop(state);
                drop(old);
                return Ok(client);
            }
            Err(StatusCode::NameNotFound) => {
                return Err(StatusCode::NameNotFound).context(connect_context);
            }
            Err(error) => {
                state.generation = state.generation.wrapping_add(1);
                let old = state.cache.take();
                drop(state);
                drop(old);
                if reconnected {
                    return Err(error).context(connect_context);
                }
                reconnected = true;
                warn!("cached RPC session failed before transaction ({error:#}); reconnecting");
            }
        }
    }
}

fn with_binder_retry<T, B, Get, Clear, Retry, F>(
    tag: &'static str,
    mut get: Get,
    mut clear: Clear,
    retryable: Retry,
    mut f: F,
) -> Result<T>
where
    B: FromIBinder + ?Sized,
    Get: FnMut() -> Result<Strong<B>>,
    Clear: FnMut(&Strong<B>),
    Retry: Fn(&anyhow::Error) -> bool,
    F: FnMut(&Strong<B>) -> Result<T>,
{
    let client = get()?;
    // 影子可能刚换了一代（重启 / 被替换），它内存里的解锁材料跟着没了；先把我们手上
    // 存着的那份补喂回去，免得这笔请求撞在「设备已锁定」上。没有材料时这行不做事。
    crate::hook::rewrite::sync_ommega_state_after_reconnect();
    match f(&client) {
        Ok(value) => Ok(value),
        Err(error) if retryable(&error) => {
            warn!("{tag} transaction hit a stale Binder; refreshing client and retrying once");
            clear(&client);
            let client = get()?;
            // 重连之后的影子是新的，同样先补料再重试。
            crate::hook::rewrite::sync_ommega_state_after_reconnect();
            let result = f(&client);
            if result.as_ref().err().is_some_and(retryable) {
                clear(&client);
            }
            result
        }
        Err(error) => Err(error),
    }
}

fn with_binder_once<T, B, Get, Clear, Stale, F>(
    get: Get,
    clear: Clear,
    stale: Stale,
    f: F,
) -> Result<T>
where
    B: FromIBinder + ?Sized,
    Get: FnOnce() -> Result<Strong<B>>,
    Clear: FnOnce(&Strong<B>),
    Stale: FnOnce(&anyhow::Error) -> bool,
    F: FnOnce(&Strong<B>) -> Result<T>,
{
    let client = get()?;
    // 同 with_binder_retry：新影子先补解锁材料再发这一笔。
    crate::hook::rewrite::sync_ommega_state_after_reconnect();
    let result = f(&client);
    if result.as_ref().err().is_some_and(stale) {
        clear(&client);
    }
    result
}

pub fn get_ommega() -> Result<Strong<dyn IKeymintService>> {
    get_rpc_binder(rpc::SERVICE, "failed to connect to ommega service", false)
}

/// 到影子那条 RPC 连接的代数。每次重连、每次因为调用失败把缓存会话丢掉，都会 +1。
/// 所以代数变了就等于「影子进程换了一代」，它内存里的东西（CE 超密钥之类）也都没了。
pub fn rpc_generation() -> u64 {
    RPC_CACHE.lock().expect("RPC cache poisoned").generation
}

pub fn with_ommega_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IKeymintService>) -> Result<T>,
{
    with_binder_retry(
        "ommega",
        get_ommega,
        |client| {
            clear_rpc_cache_if(rpc::SERVICE, &client.as_binder());
        },
        is_rpc_cache_invalidating_error,
        &mut f,
    )
}

pub fn with_ommega_once<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Strong<dyn IKeymintService>) -> Result<T>,
{
    with_binder_once(
        || get_rpc_binder(rpc::SERVICE, "failed to connect to ommega service", true),
        |client| {
            clear_rpc_cache_if(rpc::SERVICE, &client.as_binder());
        },
        is_rpc_cache_invalidating_error,
        f,
    )
}

fn get_ommega_authorization_fresh() -> Result<Strong<dyn IAuthorizationService>> {
    get_rpc_binder(
        rpc::AUTHORIZATION_SERVICE,
        "failed to connect to ommega_authorization service",
        true,
    )
}

pub fn with_ommega_authorization_once<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Strong<dyn IAuthorizationService>) -> Result<T>,
{
    with_binder_once(
        get_ommega_authorization_fresh,
        |client| {
            clear_rpc_cache_if(rpc::AUTHORIZATION_SERVICE, &client.as_binder());
        },
        is_rpc_cache_invalidating_error,
        f,
    )
}

fn get_ommega_maintenance_fresh() -> Result<Strong<dyn IMaintenanceService>> {
    get_rpc_binder(
        rpc::MAINTENANCE_SERVICE,
        "failed to connect to ommega_maintenance service",
        true,
    )
}

pub fn with_ommega_maintenance_once<T, F>(f: F) -> Result<T>
where
    F: FnOnce(&Strong<dyn IMaintenanceService>) -> Result<T>,
{
    with_binder_once(
        get_ommega_maintenance_fresh,
        |client| {
            clear_rpc_cache_if(rpc::MAINTENANCE_SERVICE, &client.as_binder());
        },
        is_rpc_cache_invalidating_error,
        f,
    )
}

/// Hook observations waiting to go to the daemon; drained by [`event_sender_loop`].
static EVENT_QUEUE: Mutex<Vec<String>> = Mutex::new(Vec::new());
static EVENT_THREAD: Once = Once::new();

/// More than this many undelivered observations means the daemon is unreachable; old lines
/// are worth less than keeping the hook's own thread moving.
const EVENT_QUEUE_LIMIT: usize = 64;
const EVENT_POLL_DELAY: Duration = Duration::from_millis(200);

/// Hand one hook observation to the daemon, for it to log.
///
/// Never blocks and never fails out loud. The hook runs on whatever thread the target gave
/// it (usually a binder thread), and an app-domain target has no other way to be heard: its
/// log file sits behind a 0700 keystore directory and logcat carries nothing from the
/// injected image. Delivery rides on the same RPC session as everything else, so a daemon
/// that is down just means dropped lines.
pub fn report_event(message: String) {
    {
        let mut queue = EVENT_QUEUE.lock().expect("event queue poisoned");
        if queue.len() >= EVENT_QUEUE_LIMIT {
            queue.remove(0);
        }
        queue.push(message);
    }
    EVENT_THREAD.call_once(|| {
        if let Err(error) = thread::Builder::new()
            .name("ommega-event".to_string())
            .spawn(event_sender_loop)
        {
            warn!("failed to start the hook event sender: {error}");
        }
    });
}

fn event_sender_loop() {
    loop {
        let message = {
            let mut queue = EVENT_QUEUE.lock().expect("event queue poisoned");
            if queue.is_empty() {
                None
            } else {
                Some(queue.remove(0))
            }
        };
        match message {
            Some(message) => {
                if let Err(error) = send_event(&message) {
                    debug!("failed to report hook event to the daemon: {error:#}");
                }
            }
            None => thread::sleep(EVENT_POLL_DELAY),
        }
    }
}

fn send_event(message: &str) -> Result<()> {
    ensure_process_state();
    with_ommega_maintenance_once(|maintenance| {
        maintenance
            .reportHookEvent(message)
            .context("reportHookEvent failed")
    })
}

/// 把一笔 SOTER 请求交给 daemon，拿回它的结论（blob 布局见 `hook::soter_relay`）。
///
/// 跟 [`report_event`] 不一样，这条是要**等结果**的：宿主拦下的那笔调用正挂着等答复，
/// 所以在此线程上同步走 RPC；失败就由调用方退回本地兜底，行不了一直重试。
pub fn forward_soter(request: &str) -> Result<Vec<u8>> {
    ensure_process_state();
    with_ommega_maintenance_once(|maintenance| {
        maintenance
            .forwardSoter(request)
            .context("forwardSoter failed")
    })
}

/// uid -> 包名解析结果的缓存时长。这层映射只在装/卸应用时变，而每笔 keystore
/// 请求都要问一次「这个 uid 是谁」（一次跨进程 binder 往返，还占着调用方正
/// 等着的那条 binder 线程），缓存一分钟能省掉绝大多数 RPC。
const UID_CACHE_TTL: Duration = Duration::from_secs(60);

pub fn resolve_packages_for_uid(uid: u32) -> PackageResolution {
    static CACHE: Mutex<Option<HashMap<u32, (Instant, PackageResolution)>>> = Mutex::new(None);
    {
        let guard = CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((stamp, hit)) = guard.as_ref().and_then(|map| map.get(&uid)) {
            if stamp.elapsed() < UID_CACHE_TTL {
                return hit.clone();
            }
        }
    }
    ensure_process_state();
    let resolved = match resolve_package_names_for_uid(uid) {
        Ok(packages) if packages.is_empty() => PackageResolution::Unknown,
        Ok(packages) => PackageResolution::Known(packages),
        Err(error) => {
            warn!("failed to resolve packages for uid {}: {:#}", uid, error);
            PackageResolution::Unknown
        }
    };
    // 只缓存解析成功的：Unknown 多半是 PM 服务一时不可用，缓存下来会一直错。
    if matches!(resolved, PackageResolution::Known(_)) {
        let mut guard = CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let map = guard.get_or_insert_with(HashMap::new);
        if map.len() > 1024 {
            map.clear();
        }
        map.insert(uid, (Instant::now(), resolved.clone()));
    }
    resolved
}

fn resolve_package_names_for_uid(uid: u32) -> Result<Vec<String>> {
    if crate::legacy::should_use_aaid_provider() {
        crate::legacy::resolve_package_names_for_uid(uid)
    } else {
        resolve_package_names_for_uid_once(uid)
    }
}

fn resolve_package_names_for_uid_once(uid: u32) -> Result<Vec<String>> {
    let app_id = with_pm_retry(|pm| {
        pm.getKeyAttestationApplicationId(uid as i32)
            .context("getKeyAttestationApplicationId failed")
    })?;
    Ok(app_id
        .packageInfos
        .into_iter()
        .map(|pkg| pkg.packageName)
        .filter(|pkg| !pkg.is_empty())
        .collect())
}

fn get_pm() -> Result<Strong<dyn IKeyAttestationApplicationIdProvider>> {
    ensure_process_state();
    PM.with(|slot| {
        if let Some(client) = slot.borrow().as_ref() {
            return Ok(client.clone());
        }

        let client: Strong<dyn IKeyAttestationApplicationIdProvider> =
            hub::check_interface(PM_SERVICE)
                .context("failed to connect to sec_key_att_app_id_provider")?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(PmDeathRecipient);
        client
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))
            .context("failed to watch sec_key_att_app_id_provider death")?;
        PM_DEATH.with(|death| *death.borrow_mut() = Some(recipient));
        *slot.borrow_mut() = Some(client.clone());
        Ok(client)
    })
}

fn with_pm_retry<T, F>(mut f: F) -> Result<T>
where
    F: FnMut(&Strong<dyn IKeyAttestationApplicationIdProvider>) -> Result<T>,
{
    with_binder_retry(
        "sec_key_att_app_id_provider",
        get_pm,
        |_| clear_pm_cache(),
        is_dead_object_error,
        &mut f,
    )
}

pub(crate) fn is_dead_object_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<Status>()
            .is_some_and(is_dead_object_status)
            || cause
                .downcast_ref::<StatusCode>()
                .is_some_and(|status| *status == StatusCode::DeadObject)
    })
}

pub(crate) fn is_stale_rpc_status_code(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::DeadObject | StatusCode::RpcError | StatusCode::NotEnoughData
    )
}

pub(crate) fn is_rpc_cache_invalidating_status_code(status: StatusCode) -> bool {
    is_stale_rpc_status_code(status)
        || status == StatusCode::NoInit
        || matches!(status, StatusCode::Errno(errno) if matches!(
            errno.abs(),
            libc::ENOENT | libc::ECONNREFUSED | libc::ECONNRESET | libc::ENOTCONN | libc::EPIPE
        ))
}

fn is_rpc_cache_invalidating_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<Status>().is_some_and(|status| {
            status.exception_code() == ExceptionCode::TransactionFailed
                && (is_rpc_cache_invalidating_status_code(status.transaction_error())
                    || status.transaction_error() == StatusCode::Unknown)
        }) || cause
            .downcast_ref::<StatusCode>()
            .is_some_and(|status| is_rpc_cache_invalidating_status_code(*status))
    })
}

fn is_dead_object_status(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && status.transaction_error() == StatusCode::DeadObject
}

fn clear_pm_cache() {
    PM.with(|slot| *slot.borrow_mut() = None);
    PM_DEATH.with(|slot| *slot.borrow_mut() = None);
}

fn clear_rpc_cache_if(service_name: &'static str, failed: &SIBinder) {
    let old = {
        let mut state = RPC_CACHE.lock().expect("RPC cache poisoned");
        let still_failed = state
            .cache
            .as_ref()
            .and_then(|cache| cache.services.get(service_name))
            == Some(failed);
        still_failed.then(|| {
            state.generation = state.generation.wrapping_add(1);
            state.cache.take()
        })
    }
    .flatten();
    drop(old);
}

#[cfg(test)]
mod tests;
