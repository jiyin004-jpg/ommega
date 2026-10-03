//! relay daemon for ommegaclient-b.
//!
//! This binary is the "new B-side" agent that talks to the existing
//! relay_server (ommega-old) using its B-side protocol:
//!
//!   * `GET  /api/b/poll/?device_id=..&machine_id=..&timeout=N` (X-Relay-Token)
//!     -> 200: {task_id, task_type, payload, target_device_id}
//!     -> 204: no task (long poll timed out)
//!   * `POST /api/b/result/` body {task_id, result, device_id}
//!     -> {status: ok}
//!
//! When an `attest` task arrives, the A-side supplies (inside `payload`):
//!   * `challenge`                    : base64, the real-time attestation nonce
//!   * `attestation_application_id`  : base64, DER-encoded `AttestationApplicationId`
//!     (this is the "appid / tag 709" the A-side wants)
//!
//! The relay daemon mints a certificate chain via the *real* on-device
//! hardware TEE (see `ommegaclient_b::keymaster::attest_proxy`) with that appid
//! embedded, then uploads `{cert_chain: [base64, ...]}` back to the server,
//! which forwards it to the A-side.
//!
//! Configuration is read from the config file `/data/adb/ommega/relay.conf`
//! (KEY=VALUE lines), falling back to environment variables:
//!   OMMEGA_RELAY_SERVER      base URL, e.g. https://example.com:8443
//!   OMMEGA_RELAY_DEVICE_ID   device id (required)
//!   OMMEGA_RELAY_MACHINE_ID  machine id (optional)
//!   OMMEGA_RELAY_TOKEN       relay B-side token (X-Relay-Token)
//!   OMMEGA_RELAY_LOG_ENABLED   file log on/off (default true)
//!   OMMEGA_RELAY_LOG_LEVEL     file log level: off|error|warn|info|debug|trace (default debug)
//!   OMMEGA_RELAY_LOGCAT_ENABLED logcat on/off (default true)
//!   OMMEGA_RELAY_LOGCAT_LEVEL   logcat level: off|error|warn|info|debug|trace (default info)
//!   OMMEGA_RELAY_BIND_IFACE    outgoing interface: none|auto|always|<ifname> (default auto)
//!   OMMEGA_RELAY_PATH_PROBE    probe /api/ping/ before each long poll (default true)
//!   OMMEGA_RELAY_WAKELOCK      hold a wake lock so the system never suspends (default true)
//!
//! Logging is read *before* the rest of the config is validated, so a broken
//! `relay.conf` still honours its log settings while reporting the error.
//!
//! The config is hot-reloaded at runtime: a background thread watches
//! `relay.conf` for modification and the `restart.all` marker, and updates the
//! live config in place (no process restart needed). The service
//! (`template/service.sh`) starts the relay directly (killing stale instances
//! first); there is no daemon wrapper.
//!
//! Both `http://` and `https://` are supported. The relay_server runs over
//! HTTPS with a self-signed certificate, so any server certificate is accepted.

use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};
use x509_cert::der::Decode as _;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use kmr_wire::keymint::{
    DateTime, Digest as KmDigest, EcCurve as KmEcCurve, KeyPurpose as KmKeyPurpose,
    PaddingMode as KmPadding,
};
use reqwest::blocking::Client;
use serde_json::{json, Value};

use ommegaclient_b::keymaster::attest_proxy::{check_app_id_der, SYSTEM_KEYMINT_STRONGBOX};
use ommegaclient_b::keymaster::tee_ops::{self, KeyAlgorithm, KeySpec};
use ommegaclient_b::wakelock;

const POLL_TIMEOUT_SEC: u32 = 15;
const CONNECT_TIMEOUT_MS: u64 = 3000;
const READ_TIMEOUT_MS: u64 = 30_000;
/// 一轮 poll 最多允许的墙钟时间。刻意比上面的 READ_TIMEOUT_MS 早一步收网：那个
/// 30s 是 reqwest 自己的总超时，用单调钟算，设备 suspend 之后就不作数了。
const POLL_WALL_LIMIT: Duration = Duration::from_secs(25);
/// 处理一个任务的上限。任务里有真 TEE 调用、还有带重试的结果回传（最坏 4×33s
/// 再加退避），所以给得宽一点，这一条只用来兜「整个循环不再往前转」。
const TASK_WALL_LIMIT: Duration = Duration::from_secs(180);
/// 探针结果缓存多久。B 端一秒能打几百个请求，每条都探一下等于把流量翻倍，
/// 所以选出来的结果留一小会儿；失败的那一份只存一秒，路不通的时候就是要急着
/// 重试 —— 设备醒着的窗口很短，得挤进去。
const PATH_TTL: Duration = Duration::from_secs(10);
const PATH_FAIL_TTL: Duration = Duration::from_secs(1);
/// 多久看一眼 wakelock 还在不在。它不是自己掉，而是可能被人解掉（卸载脚本、
/// 手滑、别的工具），补回去要快，但也不用每秒看。
const WAKELOCK_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const CONF_PATH: &str = "/data/adb/ommega/relay.conf";
const RESTART_MARKER: &str = "/data/adb/ommega/restart.all";
const RELOAD_POLL_MS: u64 = 1000;
/// Only used when the module root cannot be derived from the running binary
/// (relay started from a user-placed copy under `/data/adb/ommega/`).
const FALLBACK_MODULE_PROP: &str = "/data/adb/modules/ommega-b/module.prop";

/// Module dir of the running binary: relay lives in
/// `/data/adb/modules/<id>/libs/<abi>/relay` (or `<id>/relay`), so walking up to
/// the `modules` directory yields the module root whatever its id is.
fn module_root_from_exe() -> Option<std::path::PathBuf> {
    let exe = std::fs::read_link("/proc/self/exe").ok()?;
    let mut dir = exe.parent()?;
    loop {
        let name = dir.file_name()?.to_str()?.to_string();
        if dir.parent().is_some_and(|p| p.ends_with("modules")) && name != "modules" {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

/// Keep the KernelSU/Magisk module status (module.prop description) in sync
/// with the relay's real state. Best effort: failures are silently ignored
/// (e.g. module dir absent when running from a manual copy).
///
/// The write goes through [`write_atomic`] on purpose: `service.sh` kills stale
/// relay processes with `kill -9` before every start, and a plain `fs::write`
/// (truncate, then write) landing in that window leaves an empty `module.prop` —
/// the manager card would then show neither name nor version.
fn update_module_status(status: &str) {
    let prop_file = module_root_from_exe()
        .map(|root| root.join("module.prop"))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| std::path::PathBuf::from(FALLBACK_MODULE_PROP));
    let Ok(contents) = std::fs::read_to_string(&prop_file) else {
        return;
    };
    let mut out = String::new();
    let mut changed = false;
    for line in contents.lines() {
        if line.starts_with("description=") {
            out.push_str("description=");
            out.push_str(status);
            out.push('\n');
            changed = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if changed {
        let _ = write_atomic(&prop_file, out.as_bytes());
    }
}

/// Same-directory temp file, `fsync`, then `rename`: readers (and a `kill -9`
/// at the wrong moment) see either the old file or the new one, never a
/// half-written or empty one.
fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let tmp = dir.join(format!(".module.prop.tmp.{}", std::process::id()));
    let written = std::fs::File::create(&tmp).and_then(|mut file| {
        file.write_all(data)?;
        file.sync_all()
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return written;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// SOTER 默认并行几笔。
///
/// 2026-10-03 之前是一把全局串行锁（同一时刻只许 1 笔），线上量到排队 `wait`
/// p50 0 / p90 198 / p99 857 ms。现在放到 2：不同 uid 可以同时跑，同一个 uid 仍然
/// 串行；全局上限压得低是因为 TA 里的 RPMB 会话是独占资源 —— 留的那点空位是给
/// 机器自己（系统 / 微信在真机上直接调 TA）用的。改 relay.conf 里的
/// `OMMEGA_RELAY_SOTER_CONCURRENCY` 就能调，不用重刷模块。
const DEFAULT_SOTER_CONCURRENCY: u32 = 2;

#[derive(Clone, Debug)]
struct RelayConfig {
    server: String,
    device_id: String,
    machine_id: String,
    token: String,
    /// Allow SOTER ops that create or remove keys on the device.  Off by
    /// default: those ops change the real payment-key state.
    soter_allow_mutation: bool,
    /// SOTER 同时能压进 TA 几笔（`OMMEGA_RELAY_SOTER_CONCURRENCY`，默认 2）。
    /// 上限留小：RPMB 会话是独占资源，我们自己少占一点，机器自己那条路才有空位。
    /// 同一个 uid 无论如何都是串行的（见 `soter::handle`）。
    soter_concurrency: u32,
    /// Slot to try a real signature on when reporting the `soter_sign`
    /// capability.  Optional: without it the relay reports only `soter` until it
    /// has learnt a slot from real traffic, and never claims `soter_nosign` on
    /// evidence it does not have.
    soter_probe: Option<ommegaclient_b::caps::SignProbeTarget>,
    /// 出口网卡策略，见 `uplink::desired_iface`。默认 `auto`：先试系统默认那条
    /// 路，通了就不绑；不通再自己挑一块能打到服务端的网卡。
    bind_iface: String,
    /// 发长轮询之前先探一下路通不通。路死的时候挂 15s 长轮询没有意义，早点回来
    /// 重试反而能挤进设备醒着的那几个窗口。
    path_probe: bool,
    /// 拿一把 wakelock 按住系统，别让它 suspend。开着的时候这个进程（以及整台机器）
    /// 不会睡。**默认开** —— 灭屏掉线就是这么来的，默认把它按住才对；想要省电、
    /// 允许它睡（靠看门狗在醒过来之后救）就设成 false。
    /// 内核没这个接口时安静跳过，不算错。见 `ommegaclient_b::wakelock`。
    wakelock: bool,
}

impl RelayConfig {
    fn validate(&self) -> Result<()> {
        if self.server.is_empty() {
            return Err(anyhow!("OMMEGA_RELAY_SERVER is empty"));
        }
        if self.device_id.is_empty() {
            return Err(anyhow!("OMMEGA_RELAY_DEVICE_ID is empty"));
        }
        if self.token.is_empty() {
            return Err(anyhow!("OMMEGA_RELAY_TOKEN is empty"));
        }
        Ok(())
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.trim().is_empty())
}

/// File mtime (seconds) if present, else None.
fn file_mtime(path: &str) -> Option<u64> {
    let md = std::fs::metadata(path).ok()?;
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

/// Parse a `KEY=VALUE` boolean: `1`, `true`, `yes`, `on` (any case) are true.
fn parse_bool(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// 签名探针目标：uid 和 alias 都给全了才认 —— 只有 uid 时不知道该拿哪个槽位
/// 去签。缺一个就当没配：只报能答话，不报能签也不报签不了。
fn parse_probe_target(
    uid: Option<&str>,
    alias: Option<&str>,
) -> Option<ommegaclient_b::caps::SignProbeTarget> {
    let (uid, alias) = (uid?, alias?);
    match uid.trim().parse::<i32>() {
        Ok(uid) => Some(ommegaclient_b::caps::SignProbeTarget {
            uid,
            alias: alias.trim().to_string(),
        }),
        Err(e) => {
            log::warn!("OMMEGA_RELAY_SOTER_PROBE_UID 不是整数（{uid:?}：{e}），当作没配");
            None
        }
    }
}

/// Load config from `/data/adb/ommega/relay.conf` (KEY=VALUE lines).
fn load_config_from_file() -> Result<RelayConfig> {
    let raw = std::fs::read_to_string(CONF_PATH).with_context(|| format!("read {CONF_PATH}"))?;
    let mut m: std::collections::HashMap<&str, String> = std::collections::HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().to_string();
            if !k.is_empty() {
                m.insert(k, v);
            }
        }
    }
    let server = m
        .get("OMMEGA_RELAY_SERVER")
        .cloned()
        .context("OMMEGA_RELAY_SERVER missing in relay.conf")?;
    let device_id = m
        .get("OMMEGA_RELAY_DEVICE_ID")
        .cloned()
        .context("OMMEGA_RELAY_DEVICE_ID missing in relay.conf")?;
    let token = m
        .get("OMMEGA_RELAY_TOKEN")
        .cloned()
        .context("OMMEGA_RELAY_TOKEN missing in relay.conf")?;
    let machine_id = m
        .get("OMMEGA_RELAY_MACHINE_ID")
        .cloned()
        .unwrap_or_default();
    let soter_allow_mutation = m
        .get("OMMEGA_RELAY_SOTER_MUTATION")
        .is_some_and(|v| parse_bool(v));
    let soter_concurrency = m
        .get("OMMEGA_RELAY_SOTER_CONCURRENCY")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_SOTER_CONCURRENCY);
    let soter_probe = parse_probe_target(
        m.get("OMMEGA_RELAY_SOTER_PROBE_UID").map(|s| s.as_str()),
        m.get("OMMEGA_RELAY_SOTER_PROBE_ALIAS").map(|s| s.as_str()),
    );
    // 没配就是 `auto`：先走系统默认路由，通了就什么都不用绑（一台正常机器到这儿
    // 就结束了，系统自己的 WiFi→蜂窝 切换也留着）；默认那条打不通时才去挑网卡。
    // 想完全不绑配 `none`，想总是挑配 `always`，也可以直接写网卡名。
    let bind_iface = m
        .get("OMMEGA_RELAY_BIND_IFACE")
        .cloned()
        .unwrap_or_else(|| "auto".to_string());
    let path_probe = m
        .get("OMMEGA_RELAY_PATH_PROBE")
        .map(|v| parse_bool(v))
        .unwrap_or(true);
    let wakelock = m
        .get("OMMEGA_RELAY_WAKELOCK")
        .map(|v| parse_bool(v))
        .unwrap_or(true);
    let server = server.trim_end_matches('/').to_string();
    Ok(RelayConfig {
        server,
        device_id,
        machine_id,
        token,
        soter_allow_mutation,
        soter_concurrency,
        soter_probe,
        bind_iface,
        path_probe,
        wakelock,
    })
}

fn parse_log_level(v: &str) -> Option<log::LevelFilter> {
    Some(match v.trim().to_ascii_lowercase().as_str() {
        "off" => log::LevelFilter::Off,
        "error" => log::LevelFilter::Error,
        "warn" | "warning" => log::LevelFilter::Warn,
        "info" => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => return None,
    })
}

/// Extract the `OMMEGA_RELAY_LOG_*` and `OMMEGA_RELAY_LOGCAT_*` keys from raw
/// relay.conf content. Absent keys fall back to the defaults (file log on
/// debug, logcat on info) so an existing relay.conf without them keeps its
/// previous behaviour.
fn parse_log_config(raw: &str) -> (bool, log::LevelFilter, bool, log::LevelFilter) {
    let mut file_enabled = true;
    // 默认 info：debug 是排查时手动开的。文件 sink 每条记录要 flock + stat +
    // write + flush，常驻进程里默认开着不划算。
    let mut file_level = log::LevelFilter::Info;
    let mut logcat_enabled = true;
    let mut logcat_level = log::LevelFilter::Info;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if k == "OMMEGA_RELAY_LOG_ENABLED" {
                file_enabled = v.eq_ignore_ascii_case("true") || v == "1";
            } else if k == "OMMEGA_RELAY_LOG_LEVEL" {
                if let Some(lv) = parse_log_level(v) {
                    file_level = lv;
                }
            } else if k == "OMMEGA_RELAY_LOGCAT_ENABLED" {
                logcat_enabled = v.eq_ignore_ascii_case("true") || v == "1";
            } else if k == "OMMEGA_RELAY_LOGCAT_LEVEL" {
                if let Some(lv) = parse_log_level(v) {
                    logcat_level = lv;
                }
            }
        }
    }
    (file_enabled, file_level, logcat_enabled, logcat_level)
}

/// Read the logging switches *before* the full RelayConfig is loaded/validated,
/// so a broken relay.conf still honours its log settings while reporting the
/// error. Order: relay.conf -> environment -> defaults (file log on info,
/// logcat on info).
fn preload_log_config() -> (bool, log::LevelFilter, bool, log::LevelFilter) {
    if let Ok(raw) = std::fs::read_to_string(CONF_PATH) {
        return parse_log_config(&raw);
    }
    let file_enabled = env("OMMEGA_RELAY_LOG_ENABLED")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(true);
    let file_level = env("OMMEGA_RELAY_LOG_LEVEL")
        .and_then(|v| parse_log_level(&v))
        .unwrap_or(log::LevelFilter::Info);
    let logcat_enabled = env("OMMEGA_RELAY_LOGCAT_ENABLED")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(true);
    let logcat_level = env("OMMEGA_RELAY_LOGCAT_LEVEL")
        .and_then(|v| parse_log_level(&v))
        .unwrap_or(log::LevelFilter::Info);
    (file_enabled, file_level, logcat_enabled, logcat_level)
}

/// Prefer the config file; fall back to environment variables (the wrapper may
/// supply them directly). Returns the chosen source for logging.
fn load_config() -> Result<(RelayConfig, &'static str)> {
    if let Ok(cfg) = load_config_from_file() {
        cfg.validate()?;
        return Ok((cfg, "file"));
    }
    let server = env("OMMEGA_RELAY_SERVER")
        .context("OMMEGA_RELAY_SERVER not set and relay.conf unreadable")?;
    let device_id = env("OMMEGA_RELAY_DEVICE_ID")
        .context("OMMEGA_RELAY_DEVICE_ID not set and relay.conf unreadable")?;
    let token = env("OMMEGA_RELAY_TOKEN")
        .context("OMMEGA_RELAY_TOKEN not set and relay.conf unreadable")?;
    let machine_id = env("OMMEGA_RELAY_MACHINE_ID").unwrap_or_default();
    let soter_allow_mutation = env("OMMEGA_RELAY_SOTER_MUTATION").is_some_and(|v| parse_bool(&v));
    let soter_concurrency = env("OMMEGA_RELAY_SOTER_CONCURRENCY")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_SOTER_CONCURRENCY);
    let soter_probe = parse_probe_target(
        env("OMMEGA_RELAY_SOTER_PROBE_UID").as_deref(),
        env("OMMEGA_RELAY_SOTER_PROBE_ALIAS").as_deref(),
    );
    let bind_iface = env("OMMEGA_RELAY_BIND_IFACE").unwrap_or_else(|| "auto".to_string());
    let path_probe = env("OMMEGA_RELAY_PATH_PROBE")
        .map(|v| parse_bool(&v))
        .unwrap_or(true);
    let wakelock = env("OMMEGA_RELAY_WAKELOCK")
        .map(|v| parse_bool(&v))
        .unwrap_or(true);
    let server = server.trim_end_matches('/').to_string();
    let cfg = RelayConfig {
        server,
        device_id,
        machine_id,
        token,
        soter_allow_mutation,
        soter_concurrency,
        soter_probe,
        bind_iface,
        path_probe,
        wakelock,
    };
    cfg.validate()?;
    Ok((cfg, "env"))
}

// ---------------------------------------------------------------------------
// HTTP client (reqwest-based with rustls).
//
// Uses reqwest's blocking client with rustls TLS backend.  The relay_server
// uses a self-signed certificate, so certificate verification is disabled.
// reqwest provides built-in connection pooling, keep-alive, and chunked
// transfer encoding support — all things the old hand-rolled client lacked.
//
// The client is rebuilt on config hot-reload so that a server URL change
// does not leave stale pooled connections pointing at the old address.
// ---------------------------------------------------------------------------

/// 缓存里的客户端，连同它是照哪块出口网卡建的。网卡是这个身份的一部分：
/// 它跟着网络状态变，照 A 端那样钉进 `OnceLock` 会把第一次的判断冻住。
struct CachedClient {
    iface: Option<String>,
    client: Arc<Client>,
}

/// Shared reqwest blocking client.  Wrapped in `RwLock<Option<CachedClient>>` so
/// the config watcher can drop it (forcing a rebuild) without blocking
/// in-flight requests (the old `Arc` stays alive until its last user drops it).
static HTTP_CLIENT: RwLock<Option<CachedClient>> = RwLock::new(None);

fn build_http_client(iface: Option<&str>) -> Result<Client> {
    let mut builder = Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .timeout(Duration::from_millis(READ_TIMEOUT_MS));
    if let Some(name) = iface {
        // `SO_BINDTODEVICE`：把 socket 钉在物理出口上，免得被路由规则抓进隧道。
        builder = builder.interface(name);
    }
    builder.build().context("build reqwest client")
}

/// 这条请求该从哪块网卡出去。探针失败时调用方会把客户端丢掉，下次重建就会重新
/// 竞速一遍 —— 链路换了、挂了都能自己跟上。
fn resolve_iface(cfg: &RelayConfig) -> Option<String> {
    ommegaclient_b::uplink::desired_iface(&cfg.bind_iface, &cfg.server)
}

/// Returns the shared HTTP client, building it on first use (or rebuilding it
/// when the chosen outgoing interface changed).
fn get_http_client(cfg: &RelayConfig) -> Result<Arc<Client>> {
    let iface = resolve_iface(cfg);
    // Fast path: read lock, return if present and still for the same uplink.
    if let Ok(guard) = HTTP_CLIENT.read() {
        if let Some(cached) = guard.as_ref() {
            if cached.iface == iface {
                return Ok(cached.client.clone());
            }
        }
    }
    // Slow path: write lock, build if still absent.
    let mut guard = HTTP_CLIENT
        .write()
        .map_err(|_| anyhow!("HTTP client lock poisoned"))?;
    if let Some(cached) = guard.as_ref() {
        if cached.iface == iface {
            return Ok(cached.client.clone());
        }
    }
    if let Some(name) = iface.as_deref() {
        log::info!("relay 出口绑定到网卡 {name}");
    } else if guard.as_ref().is_some() {
        log::info!("relay 出口改回系统默认路由（不再绑定）");
    }
    let client = Arc::new(build_http_client(iface.as_deref())?);
    *guard = Some(CachedClient {
        iface,
        client: Arc::clone(&client),
    });
    Ok(client)
}

/// Drops the shared HTTP client so the next request rebuilds it.
/// Called from the config watcher when the server URL changes, and from the
/// worker when a probe says the current uplink stopped carrying traffic.
fn reset_http_client() {
    if let Ok(mut guard) = HTTP_CLIENT.write() {
        *guard = None;
        // 出口选择也跟着作废：下轮重建会重新探、重新挑，别抱着一个刚证明
        // 打不通的结论不放。
        ommegaclient_b::uplink::invalidate_pick();
        log::info!("HTTP client reset (connection pool cleared)");
    }
}

/// 上一次探路的结果：哪块网卡、什么时候探的、通不通。
static PATH_CHECK: Mutex<Option<(Option<String>, Instant, bool)>> = Mutex::new(None);

/// 发长轮询之前先确认路还通着。
///
/// 链路已经死的时候，一个 15s 长轮询不会带回任何东西，只会把设备醒着的那点
/// 窗口全耗在里面；探针几百毫秒就能给个答复，不通就早点回去重试。当前这条路
/// 刚刚证明打不通的时候，顺手把客户端丢掉 —— 下一轮重建会重新竞速，自己换一条。
///
/// 代价是每 10 秒多一个几字节的 `/api/ping/`（相对 B 端一分钟几百个请求可以
/// 忽略）；不想付这个代价就把 `OMMEGA_RELAY_PATH_PROBE` 关掉。
fn path_ready(cfg: &RelayConfig) -> bool {
    if !cfg.path_probe {
        return true;
    }
    let iface = resolve_iface(cfg);
    if let Ok(guard) = PATH_CHECK.lock() {
        if let Some((cached_iface, at, ok)) = guard.as_ref() {
            let ttl = if *ok { PATH_TTL } else { PATH_FAIL_TTL };
            if *cached_iface == iface && at.elapsed() < ttl {
                return *ok;
            }
        }
    }
    let ok = ommegaclient_b::uplink::probe(&cfg.server, iface.as_deref());
    if let Ok(mut guard) = PATH_CHECK.lock() {
        *guard = Some((iface.clone(), Instant::now(), ok));
    }
    if !ok {
        log::warn!(
            "出口探针没打通（网卡: {}），这轮不发长轮询",
            iface.as_deref().unwrap_or("系统默认")
        );
        reset_http_client();
    }
    ok
}

fn http_request(
    cfg: &RelayConfig,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>)> {
    let client = get_http_client(cfg)?;
    let mut req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        other => client.request(
            reqwest::Method::from_bytes(other.as_bytes())
                .map_err(|_| anyhow!("invalid HTTP method: {other}"))?,
            url,
        ),
    };
    for (k, v) in headers {
        req = req.header(k, v);
    }
    if let Some(b) = body {
        req = req.body(b.to_vec());
    }
    let t0 = std::time::Instant::now();
    let resp = req
        .send()
        .with_context(|| format!("http {method} {url} failed"))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .bytes()
        .with_context(|| format!("http {method} {url} read body failed"))?;
    let read_ms = t0.elapsed().as_millis();
    log::info!(
        "http {} {} -> status={} {} bytes in {}ms, body_head: {:?}",
        method,
        url,
        status,
        bytes.len(),
        read_ms,
        String::from_utf8_lossy(&bytes[..bytes.len().min(120)])
    );
    Ok((status, bytes.to_vec()))
}

// ---------------------------------------------------------------------------
// Relay protocol helpers.
// ---------------------------------------------------------------------------

fn poll_tasks(cfg: &RelayConfig) -> Result<Option<(String, String, Value)>> {
    // 带上本机能力声明：服务端靠它把 SOTER 任务路由到真能做的设备上，状态页也
    // 显示这几个。SOTER 那一支会真去签一次（命中缓存时不再碰 HAL），其余只查
    // 服务实例在不在，没有副作用。
    let caps = ommegaclient_b::caps::report(cfg.soter_probe.as_ref());
    let url = format!(
        "{}/api/b/poll/?device_id={}&machine_id={}&timeout={}&caps={}",
        cfg.server, cfg.device_id, cfg.machine_id, POLL_TIMEOUT_SEC, caps
    );
    let headers = vec![("X-Relay-Token".to_string(), cfg.token.clone())];
    let (status, body) =
        http_request(cfg, "GET", &url, &headers, None).with_context(|| "b/poll failed")?;
    log::info!("b/poll status={status} body_len={}", body.len());
    match status {
        204 => Ok(None),
        200 => {
            let v: Value = serde_json::from_slice(&body).with_context(|| "b/poll bad json")?;
            let task_id = v
                .get("task_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("b/poll missing task_id"))?
                .to_string();
            let task_type = v
                .get("task_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let payload = v.get("payload").cloned().unwrap_or(Value::Null);
            Ok(Some((task_id, task_type, payload)))
        }
        other => Err(anyhow!("b/poll unexpected status {other}")),
    }
}

/// POST the task result to the server, retrying transient failures
/// (network errors / 5xx) with exponential backoff so a task is not lost to a
/// single glitch. Permanent 4xx rejections (bad token, unknown task) are not
/// retried.
fn post_result(cfg: &RelayConfig, task_id: &str, result: &Value) -> Result<()> {
    const MAX_ATTEMPTS: u32 = 4;
    let url = format!("{}/api/b/result/", cfg.server);
    let body = json!({
        "task_id": task_id,
        "result": result,
        "device_id": cfg.device_id,
    });
    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("X-Relay-Token".to_string(), cfg.token.clone()),
    ];
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match http_request(
            cfg,
            "POST",
            &url,
            &headers,
            Some(body.to_string().as_bytes()),
        ) {
            Ok((200, _body)) => {
                log::info!("b/result task={task_id} accepted (HTTP 200)");
                return Ok(());
            }
            Ok((status, _body)) => {
                if (400..500).contains(&status) {
                    log::warn!("b/result task={task_id} rejected: HTTP {status}");
                    return Err(anyhow!("b/result rejected with HTTP {status}"));
                }
                log::warn!(
                    "b/result task={task_id} HTTP {status} (attempt {attempt}/{MAX_ATTEMPTS})"
                );
                last_err = Some(anyhow!("b/result unexpected status {status}"));
            }
            Err(e) => {
                log::warn!(
                    "b/result task={task_id} network error: {e:#} (attempt {attempt}/{MAX_ATTEMPTS})"
                );
                last_err = Some(e);
            }
        }
        if attempt < MAX_ATTEMPTS {
            std::thread::sleep(Duration::from_secs(1 << (attempt - 1)));
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("b/result failed after {MAX_ATTEMPTS} attempts")))
}

// ---------------------------------------------------------------------------
// Task handlers.
// ---------------------------------------------------------------------------

fn b64_decode(v: &Value) -> Result<Vec<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("expected base64 string, got {v}"))?;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow!("bad base64: {e}"))
}

/// Attestation inputs pulled from a task payload:
/// `(attestation_application_id, challenge)`.
type AttestationContext = (Vec<u8>, Vec<u8>);

fn extract_attestation_context(payload: &Value) -> Result<AttestationContext> {
    // `attestation_application_id` may live at the top level or nested under
    // `device_attest_context` (the relay_server accepts both).
    let nested = payload.get("device_attest_context");
    let app_id = payload
        .get("attestation_application_id")
        .or_else(|| nested.and_then(|n| n.get("attestation_application_id")))
        .ok_or_else(|| anyhow!("payload missing attestation_application_id (tag 709)"))?;
    let challenge = payload
        .get("challenge")
        .ok_or_else(|| anyhow!("payload missing challenge"))?;

    let app_id_der = b64_decode(app_id).with_context(|| "decode attestation_application_id")?;
    let challenge = b64_decode(challenge).with_context(|| "decode challenge")?;
    Ok((app_id_der, challenge))
}

/// Parses the A-side requested key parameters from a task payload into a
/// [`tee_ops::KeySpec`]. Fields may live at the top level or nested under
/// `device_attest_context`; absent fields keep the KeySpec defaults (EC P-256,
/// SHA-256, etc.).
fn parse_key_spec(payload: &Value) -> Result<KeySpec> {
    let nested = payload.get("device_attest_context");
    let get =
        |k: &str| -> Option<&Value> { payload.get(k).or_else(|| nested.and_then(|n| n.get(k))) };
    let get_i64 = |k: &str| get(k).and_then(Value::as_i64);
    let get_arr = |k: &str| -> Vec<&Value> {
        get(k)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .collect()
    };

    // Algorithm family: prefer the explicit KeyMint `key_algorithm` int (raw
    // AIDL enum: 1 = RSA, 3 = EC); fall back to the top-level JCA `algorithm`
    // string. Reject unknown algorithms loudly instead of silently minting a
    // mismatched EC key.
    let algorithm = match get_i64("key_algorithm") {
        Some(1) => KeyAlgorithm::Rsa2048,
        Some(3) => KeyAlgorithm::EcP256,
        Some(other) => {
            return Err(anyhow!("unsupported key_algorithm: {other}"));
        }
        None => key_algorithm(payload),
    };

    let collect_enum = |vals: Vec<&Value>| -> Vec<i32> {
        vals.iter()
            .filter_map(|v| v.as_i64())
            .map(|n| n as i32)
            .collect()
    };

    Ok(KeySpec {
        algorithm,
        ec_curve: get_i64("ec_curve").and_then(|v| KmEcCurve::try_from(v as i32).ok()),
        key_size: get_i64("key_size").map(|v| v as u32),
        purposes: collect_enum(get_arr("purpose"))
            .iter()
            .filter_map(|&n| KmKeyPurpose::try_from(n).ok())
            .collect(),
        digests: collect_enum(get_arr("digest"))
            .iter()
            .filter_map(|&n| KmDigest::try_from(n).ok())
            .collect(),
        mgf_digest: get_i64("mgf_digest").and_then(|v| KmDigest::try_from(v as i32).ok()),
        paddings: collect_enum(get_arr("padding"))
            .iter()
            .filter_map(|&n| KmPadding::try_from(n).ok())
            .collect(),
        rsa_public_exponent: get_i64("rsa_public_exponent").map(|v| v as u64),
        cert_subject_der: get("certificate_subject")
            .map(|v| b64_decode(v).with_context(|| "decode certificate_subject"))
            .transpose()?,
        cert_not_before: get_i64("certificate_not_before_ms")
            .map(|ms| DateTime { ms_since_epoch: ms }),
        cert_not_after: get_i64("certificate_not_after_ms")
            .map(|ms| DateTime { ms_since_epoch: ms }),
        // `certificate_serial` (A-side CERTIFICATE_SERIAL tag) is optional;
        // when present the real TEE mints the leaf with that serial instead of
        // a random 16-byte value.
        cert_serial: get("certificate_serial")
            .map(|v| b64_decode(v).with_context(|| "decode certificate_serial"))
            .transpose()?,
        // Device properties / ID attestation (710..=717, plus 723 for the second
        // IMEI; 718 is VENDOR_PATCHLEVEL, never an ID) forwarded by the A-side as
        // `[tag, base64(value)]` pairs. These are the values the *A-side*
        // device wants attested, so a TEE that does not own them answers
        // `CannotAttestIds` (-66) — expected when the balancer serves this request
        // with a different B端. The task then fails, the A-side gets no chain from
        // this layer, and the server keybox layer (which writes the IDs into the
        // minted leaf itself) takes over with values that actually match the
        // requesting device. Minting a chain while silently dropping the IDs would
        // be worse: the chain would claim to come from a real TEE and carry no
        // device properties at all. Malformed entries are dropped so a request
        // carrying junk still mints a key.
        attestation_ids: get("attestation_ids")
            .and_then(Value::as_array)
            .map(|pairs| {
                pairs
                    .iter()
                    .filter_map(|pair| {
                        let pair = pair.as_array()?;
                        let tag = u32::try_from(pair.first()?.as_i64()?).ok()?;
                        let value = b64_decode(pair.get(1)?).ok()?;
                        // 718 is VENDOR_PATCHLEVEL, so it is not an ID tag; the
                        // second IMEI is 723 (`TagType.BYTES | 723`).
                        ((710..=717).contains(&tag) || tag == 723).then_some((tag, value))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        // User-authentication / authorization-list entries forwarded by the
        // A-side as `[tag, value]` pairs (502 USER_SECURE_ID, 503
        // NO_AUTH_REQUIRED, 504 USER_AUTH_TYPE, 505 AUTH_TIMEOUT, 506
        // ALLOW_WHILE_ON_BODY, 507 TRUSTED_USER_PRESENCE_REQUIRED, 508
        // TRUSTED_CONFIRMATION_REQUIRED, 509 UNLOCKED_DEVICE_REQUIRED). These go
        // straight into the real TEE request: the TEE keeps USER_SECURE_ID inside
        // the key blob, enforces USER_AUTH_TYPE/AUTH_TIMEOUT, and stamps them (but
        // not NO_AUTH_REQUIRED) into the leaf. Duplicated tags are dropped, and
        // NO_AUTH_REQUIRED is dropped whenever a real auth requirement came along
        // — KeyMint rejects that contradictory combination, and the A-side
        // fallback (the server keybox layer) drops it the same way.
        user_auth: {
            let mut tags = Vec::new();
            for pair in get("user_auth")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(pair) = pair.as_array() else {
                    continue;
                };
                let Some(tag) = pair.first().and_then(Value::as_i64) else {
                    continue;
                };
                let Ok(tag) = u32::try_from(tag) else {
                    continue;
                };
                if !(502..=509).contains(&tag) || tags.iter().any(|(t, _)| *t == tag) {
                    continue;
                }
                let value = pair.get(1).and_then(Value::as_i64).unwrap_or(1);
                tags.push((tag, value));
            }
            if tags.iter().any(|(tag, _)| *tag != 503) {
                tags.retain(|(tag, _)| *tag != 503);
            }
            tags
        },
    })
}

fn b64(v: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}

fn cert_chain_json(chain: &[Vec<u8>]) -> Vec<Value> {
    chain.iter().map(|der| Value::String(b64(der))).collect()
}

/// Logs every certificate in a chain: index, DER length and the parsed
/// subject/issuer when x509_cert can decode it (helps debugging what the real
/// TEE actually minted vs what the server expects).
fn log_cert_chain(tag: &str, chain: &[Vec<u8>]) {
    // 每笔 attest 都无条件把整条链 DER 解一遍、拼 subject/issuer 字符串，
    // 而结果只进日志 —— 关了就直接不做（否则白花的时间全加在 A 端等结果的
    // 关键路径上）。
    if !log::log_enabled!(log::Level::Info) {
        return;
    }
    if chain.is_empty() {
        log::info!("cert_chain[{tag}]: EMPTY");
        return;
    }
    let mut lines = Vec::new();
    for (i, der) in chain.iter().enumerate() {
        let parsed = x509_cert::Certificate::from_der(der).ok().map(|c| {
            let tbs = c.tbs_certificate();
            format!("subject={} issuer={}", tbs.subject(), tbs.issuer())
        });
        match parsed {
            Some(info) => lines.push(format!("#{i} {}B {info}", der.len())),
            None => lines.push(format!("#{i} {}B (unparsable)", der.len())),
        }
    }
    log::info!(
        "cert_chain[{tag}]: {} certs :: {}",
        chain.len(),
        lines.join(" | ")
    );
}

/// Picks a signing key algorithm from the payload (defaults to EC P-256).
fn key_algorithm(payload: &Value) -> KeyAlgorithm {
    let algo = payload
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("");
    let up = algo.to_uppercase();
    if up.contains("RSA") {
        KeyAlgorithm::Rsa2048
    } else {
        KeyAlgorithm::EcP256
    }
}

fn alias_of(payload: &Value, default: &str) -> String {
    payload
        .get("alias")
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

fn handle_generate_attest(_task_type: &str, payload: &Value) -> Result<Value> {
    let (app_id_der, challenge) = extract_attestation_context(payload)?;
    check_app_id_der(&app_id_der).with_context(|| {
        "attestation_application_id is not a valid AttestationApplicationId DER"
    })?;
    let alias = alias_of(payload, "attest");
    let spec = parse_key_spec(payload)?;
    // The requested purposes are forwarded unchanged (see
    // tee_ops::build_attestation_params). For an App Attest Key this mirrors
    // AOSP keystore2: a lone PURPOSE_ATTEST_KEY is accepted by the real TEE
    // (verified working on-device); such a key is later used only as an
    // `AttestationKey` when the A-side signs a child certificate.

    // The A-side forwards the requesting security level (1 = TEE, 2 = StrongBox)
    // in `device_attest_context.attestation_security_level`. A StrongBox request
    // is served by this B-side device's real `/strongbox` HAL when one exists;
    // otherwise we return an explicit error so the A-side falls back to its own
    // local software keybox (never silently mislabelling a TEE chain as StrongBox).
    let security_level = payload
        .get("device_attest_context")
        .and_then(|c| c.get("attestation_security_level"))
        .and_then(Value::as_i64)
        .unwrap_or(1);

    let session = if security_level == 2 {
        match tee_ops::generate_attest_key_on(
            SYSTEM_KEYMINT_STRONGBOX,
            &alias,
            &challenge,
            &app_id_der,
            &spec,
        ) {
            Ok(session) => session,
            Err(e) => {
                let err_str = format!("{e:#}");
                // Distinguish the root cause so operators can tell apart:
                //   - HAL not present (binder connect failed)
                //   - HAL present but attestation keys not provisioned (-74)
                //   - HAL present but hardware unavailable (-68)
                //   - Parameter/version incompatibility (other KeyMint errors)
                // AOSP keystore2 does not retry on -74 (it is a hard
                // failure that propagates to the caller); the three-tier
                // server fallback then handles recovery without ever
                // mislabelling a TEE chain as StrongBox.
                let reason = if err_str.contains("[km_error=-74]") {
                    "HAL exists but attestation keys not provisioned (factory provisioning issue)"
                } else if err_str.contains("[km_error=-68]") {
                    "HAL exists but hardware type unavailable"
                } else if err_str.contains("[km_error=") {
                    "HAL rejected key generation (possible parameter/version mismatch)"
                } else if err_str.contains("empty certificate chain") {
                    "HAL accepted key generation but returned no attestation certificate chain"
                } else if err_str.contains("connect")
                    || err_str.contains("NameNotFound")
                    || err_str.contains("not found")
                {
                    "StrongBox HAL service not present on this device"
                } else {
                    "strongbox generateKey failed"
                };
                log::warn!("B-side StrongBox unavailable ({reason}): {err_str}");
                return Ok(json!({ "error": format!("strongbox not supported: {reason}") }));
            }
        }
    } else {
        tee_ops::generate_attest_key(&alias, &challenge, &app_id_der, &spec)?
    };

    log_cert_chain("attest", &session.cert_chain);
    Ok(json!({
        "alias": alias,
        "cert_chain": cert_chain_json(&session.cert_chain),
        "public_key": b64(&tee_ops::public_key_from_session(&session)?),
    }))
}

fn handle_sign(_task_type: &str, payload: &Value) -> Result<Value> {
    let alias = alias_of(payload, "attest");
    let algorithm = payload
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("SHA256withECDSA")
        .to_string();
    let data = b64_decode(
        payload
            .get("data")
            .ok_or_else(|| anyhow!("payload missing data"))?,
    )?;
    let sig = tee_ops::sign(&alias, &data, &algorithm)?;
    Ok(json!({
        "alias": alias,
        "algorithm": algorithm,
        "data": b64(&sig),
    }))
}

fn handle_decrypt(_task_type: &str, payload: &Value) -> Result<Value> {
    let alias = alias_of(payload, "attest");
    let algorithm = payload
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or("RSA/ECB/PKCS1Padding")
        .to_string();
    let data = b64_decode(
        payload
            .get("data")
            .ok_or_else(|| anyhow!("payload missing data"))?,
    )?;
    let plain = tee_ops::decrypt(&alias, &data, &algorithm)?;
    Ok(json!({
        "alias": alias,
        "algorithm": algorithm,
        "data": b64(&plain),
    }))
}

/// SOTER forwarding: the payload selects a HAL op (see `ommegaclient_b::soter`).
///
/// Read-only ops always run; the ops that create or remove keys are gated by
/// `OMMEGA_RELAY_SOTER_MUTATION` because they change real device key state.
fn handle_soter(cfg: &RelayConfig, _task_type: &str, payload: &Value) -> Result<Value> {
    // 实时配置：每轮轮询先把 SOTER 的并行上限推给 soter 模块（探针那条路读这个值）。
    ommegaclient_b::soter::set_max_concurrency(cfg.soter_concurrency);
    ommegaclient_b::soter::handle(payload, cfg.soter_allow_mutation, cfg.soter_concurrency)
}

fn handle_task(cfg: &RelayConfig, task_id: &str, task_type: &str, payload: &Value) -> Result<()> {
    let handler: fn(&RelayConfig, &str, &Value) -> Result<Value> = match task_type {
        "attest" => |_cfg, task_type, payload| handle_generate_attest(task_type, payload),
        "sign" => |_cfg, task_type, payload| handle_sign(task_type, payload),
        "decrypt" => |_cfg, task_type, payload| handle_decrypt(task_type, payload),
        // SOTER forwarding needs the config (mutation policy), so it gets the
        // config-aware handler signature directly.
        "soter" => handle_soter,
        other => {
            log::warn!("task {task_id} type={other} not supported, reporting failure");
            post_result(
                cfg,
                task_id,
                &json!({ "error": format!("unsupported task type: {other}") }),
            )?;
            return Ok(());
        }
    };

    let start = std::time::Instant::now();
    log::info!("processing task {task_id} type={task_type}");
    let result = match handler(cfg, task_type, payload) {
        Ok(v) => v,
        Err(e) => {
            log::error!("task {task_id} type={task_type} failed: {e:#}");
            json!({ "error": format!("{e:#}") })
        }
    };
    let outcome = if result.get("error").is_some() {
        "failed"
    } else {
        "ok"
    };
    log::info!(
        "task {task_id} type={task_type} {outcome} in {:?}",
        start.elapsed()
    );
    post_result(cfg, task_id, &result)
}

/// Background thread: hot-reload the config when `relay.conf` changes or the
/// `restart.all` marker appears. The live config is updated in place via the
/// shared `RwLock`, so the poll loop keeps running and never conflicts with the
/// wrapper (the wrapper does not kill the relay on config changes).
fn spawn_config_watcher(shared: Arc<RwLock<RelayConfig>>, last_mtime: u64) {
    thread::spawn(move || {
        let mut last = last_mtime;
        loop {
            thread::sleep(Duration::from_millis(RELOAD_POLL_MS));

            let restart_requested = std::path::Path::new(RESTART_MARKER).exists();
            let changed = file_mtime(CONF_PATH).is_some_and(|m| m != last);

            if !restart_requested && !changed {
                continue;
            }
            // Re-read; if it fails (e.g. transient), keep the previous config.
            let reloaded = match load_config() {
                Ok((cfg, source)) => Some((cfg, source)),
                Err(e) => {
                    log::warn!("config reload failed, keeping previous: {e:#}");
                    None
                }
            };
            if let Some((cfg, source)) = reloaded {
                if let Ok(mut guard) = shared.write() {
                    log::info!(
                        "config hot-reloaded from {source}: server={} device={}",
                        cfg.server,
                        cfg.device_id
                    );
                    *guard = cfg;
                    // Drop the HTTP client so the next request rebuilds it
                    // with fresh connections to the (possibly new) server.
                    reset_http_client();
                }
                if let Some(m) = file_mtime(CONF_PATH) {
                    last = m;
                }
            }
            // Clear the restart marker so a single touch triggers one reload.
            let _ = std::fs::remove_file(RESTART_MARKER);
        }
    });
}

/// 一台 B 端能同时做几条活。
///
/// 2026-09-30 实测：这台机器上 attest 的排队平均 886ms，而它自己只跑 98ms ——
/// 一条重活把整条队堵在后面，跟谁先谁后无关。所以默认开两路：取一条、做一条的
/// 循环变成两路各自长轮询，下一单不用等上一单跑完。HAL 本身（KeyMint / soter）
/// 就是多线程 binder 服务，两路并发不会打架。想回到单线程设
/// `OMMEGA_RELAY_WORKERS=1`。
fn worker_count() -> usize {
    std::env::var("OMMEGA_RELAY_WORKERS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| (1..=8).contains(n))
        .unwrap_or(2)
}

fn run_loop(shared: Arc<RwLock<RelayConfig>>) {
    let workers = worker_count();
    log::info!("relay loop starting with {workers} worker(s)");
    if workers <= 1 {
        worker_loop(shared);
        return;
    }
    let mut handles = Vec::with_capacity(workers);
    for i in 0..workers {
        let shared = Arc::clone(&shared);
        handles.push(std::thread::spawn(move || {
            log::info!("relay worker {i} up");
            worker_loop(shared);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn worker_loop(shared: Arc<RwLock<RelayConfig>>) {
    // 正常情况下服务端会挂着 15s 长轮询，一轮一个请求。但它要是立刻回 204
    // （老版本服务端、代理提前收掉连接等），这里不设下限就变成“能跑多快跑多快”，
    // 直接把服务器打满。失败路径同理，用指数退避兜住。
    const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
    const MAX_ERROR_BACKOFF: Duration = Duration::from_secs(30);
    // 长轮询卡死之后没人管，是线上那几次几小时静默 gap 的成因：请求停在 reqwest
    // 的 read 上，那一路超时都用单调钟算，设备 suspend 之后永远不到 —— 进程活着，
    // 却再也不发轮询，service.sh 的 wait 也一直陪着等。这里按开机时长盯住，超了
    // 就退出去让 service.sh 重启。细节见 watchdog 模块。
    let watchdog = ommegaclient_b::watchdog::SuspendWatchdog::spawn(
        ommegaclient_b::watchdog::DEFAULT_TICK,
        |over_ms| {
            log::error!(
                "已经卡了 {over_ms}ms 没往前走（设备多半刚从 suspend 醒来），退出让 service.sh 重新拉起"
            );
            log::Log::flush(log::logger());
            std::process::exit(2);
        },
    );
    let mut error_backoff = Duration::from_secs(1);
    loop {
        // Read the latest live config (may be updated by the watcher).
        let cfg = match shared.read() {
            Ok(g) => g.clone(),
            Err(_) => {
                log::error!("config lock poisoned");
                std::thread::sleep(Duration::from_millis(1000));
                continue;
            }
        };
        // 配置里改过的 SOTER 并行上限立即生效（改 relay.conf 不用重启/重刷）。
        ommegaclient_b::soter::set_max_concurrency(cfg.soter_concurrency);
        let started = Instant::now();
        watchdog.arm(POLL_WALL_LIMIT);
        // 先探路再发长轮询：链路死的时候挂 15s 长轮询只会把设备醒着的那点窗口
        // 全耗完，快点回来重试才有机会。探针也放在看门狗底下：它一样会被
        // suspend 冻住，超了还是得退出去重拉。
        if !path_ready(&cfg) {
            watchdog.disarm();
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let polled = poll_tasks(&cfg);
        watchdog.disarm();
        match polled {
            Ok(Some((task_id, task_type, payload))) => {
                error_backoff = Duration::from_secs(1);
                log::info!("poll received task {task_id} type={task_type}");
                watchdog.arm(TASK_WALL_LIMIT);
                let handled = handle_task(&cfg, &task_id, &task_type, &payload);
                watchdog.disarm();
                if let Err(e) = handled {
                    log::error!("handle_task failed: {e:#}");
                }
            }
            Ok(None) => {
                // 立刻返回的空轮询说明长轮询没生效，压到最小间隔再打。
                error_backoff = Duration::from_secs(1);
                let waited = started.elapsed();
                if waited < MIN_POLL_INTERVAL {
                    std::thread::sleep(MIN_POLL_INTERVAL - waited);
                }
            }
            Err(e) => {
                log::warn!("poll failed: {e:#}; retrying in {error_backoff:?}");
                std::thread::sleep(error_backoff);
                error_backoff = (error_backoff * 2).min(MAX_ERROR_BACKOFF);
            }
        }
    }
}

/// 拿住 wakelock，让系统别 suspend。
///
/// 默认开。拿不到就安静跳过：没开 `CONFIG_PM_WAKELOCKS` 的内核根本没这个文件，
/// 那种机型上 relay 就只能继续靠看门狗等醒过来 —— 少个能力，不是个错误，
/// 不该每次都哀一声。
fn hold_wakelock() -> Option<wakelock::WakeLock> {
    let name = wakelock::DEFAULT_NAME;
    let wl = match wakelock::WakeLock::acquire(name) {
        Ok(wl) => wl,
        Err(e) => {
            log::debug!("拿 wakelock 不成（{e}），这台机器只能继续靠看门狗");
            return None;
        }
    };
    if !wl.held_now() {
        log::debug!("写了 wakelock 但内核那边没记上（{name}），当做没拿住");
        return None;
    }
    log::info!("wakelock {name} 已拿住，系统不会进 suspend");
    spawn_wakelock_keeper(name.to_string());
    Some(wl)
}

/// 锁得一直拿着。万一被谁解掉（或者重启后内核状态没了），自己补回去。
/// 补不回去连试几次就算了 —— 内核没这个接口的时候别一直在日志里念叨。
fn spawn_wakelock_keeper(name: String) {
    thread::spawn(move || {
        let mut failed = 0;
        loop {
            thread::sleep(WAKELOCK_CHECK_INTERVAL);
            if wakelock::held(&name) {
                failed = 0;
                continue;
            }
            if wakelock::reacquire(&name) {
                log::info!("wakelock {name} 掉了，已经补回去");
                failed = 0;
            } else {
                failed += 1;
                log::debug!("wakelock {name} 掉了而且补不回去（第 {failed} 次）");
                if failed >= 3 {
                    log::debug!("wakelock {name} 补不回去，停止自检");
                    return;
                }
            }
        }
    });
}

fn main() {
    let (log_enabled, log_level, logcat_enabled, logcat_level) = preload_log_config();
    ommegaclient_b::logging::init_logger(log_enabled, log_level, logcat_enabled, logcat_level);
    let (cfg, source) = match load_config() {
        Ok(c) => c,
        Err(e) => {
            log::error!("relay config error: {e:#}");
            update_module_status("Ommega Attestation Relay Module ❌ 启动失败");
            std::process::exit(1);
        }
    };
    let shared: Arc<RwLock<RelayConfig>> = Arc::new(RwLock::new(cfg));
    // 先把系统按住再干活：醒着的时候才轮得到我们轮询。拿住之后这个变量要一直活着
    // （所以是带名字的绑定，不是 `let _ =`），到进程结束才会 Drop 释放。
    let _wakelock = if shared.read().map(|c| c.wakelock).unwrap_or(true) {
        hold_wakelock()
    } else {
        // 关掉的时候得把上一任留下的锁解掉，否则配置里写 false 等于没写。
        if wakelock::clear_stale(wakelock::DEFAULT_NAME) {
            log::info!(
                "wakelock 关着，顺手把上次留下的 {} 解了",
                wakelock::DEFAULT_NAME
            );
        }
        None
    };
    let last_mtime = file_mtime(CONF_PATH).unwrap_or(0);
    spawn_config_watcher(shared.clone(), last_mtime);
    // We drive the real hardware keymint (a binder HAL) directly, so a binder
    // process state must be up before we start serving tasks.
    let _ = rsbinder::ProcessState::init_default();
    {
        let g = shared.read().map(|g| g.clone()).unwrap_or(RelayConfig {
            server: String::new(),
            device_id: String::new(),
            machine_id: String::new(),
            token: String::new(),
            soter_allow_mutation: false,
            soter_concurrency: DEFAULT_SOTER_CONCURRENCY,
            soter_probe: None,
            bind_iface: "auto".to_string(),
            path_probe: true,
            wakelock: true,
        });
        log::info!(
            "relay daemon starting (config from {source}) server={} device={} machine={}",
            g.server,
            g.device_id,
            g.machine_id
        );
    }
    update_module_status("Ommega Attestation Relay Module ✅ 运行中");
    // Reload persisted TEE sessions so aliases from before a relay restart stay
    // usable (key blobs are self-contained and still valid for begin/finish).
    ommegaclient_b::keymaster::tee_ops::load_all_sessions();
    run_loop(shared);
}
