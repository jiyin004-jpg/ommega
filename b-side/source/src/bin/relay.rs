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

use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};
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

const POLL_TIMEOUT_SEC: u32 = 20;
const CONNECT_TIMEOUT_MS: u64 = 3000;
const READ_TIMEOUT_MS: u64 = 30_000;
const CONF_PATH: &str = "/data/adb/ommega/relay.conf";
const RESTART_MARKER: &str = "/data/adb/ommega/restart.all";
const RELOAD_POLL_MS: u64 = 1000;
const MODULE_PROP: &str = "/data/adb/modules/ommegaclient_b/module.prop";

/// Keep the KernelSU/Magisk module status (module.prop description) in sync
/// with the relay's real state. Best effort: failures are silently ignored
/// (e.g. module dir absent when running from a manual copy).
fn update_module_status(status: &str) {
    let Ok(contents) = std::fs::read_to_string(MODULE_PROP) else {
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
        let _ = std::fs::write(MODULE_PROP, out);
    }
}

#[derive(Clone, Debug)]
struct RelayConfig {
    server: String,
    device_id: String,
    machine_id: String,
    token: String,
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

/// Load config from `/data/adb/ommega/relay.conf` (KEY=VALUE lines).
fn load_config_from_file() -> Result<RelayConfig> {
    let raw = std::fs::read_to_string(CONF_PATH)
        .with_context(|| format!("read {CONF_PATH}"))?;
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
    let machine_id = m.get("OMMEGA_RELAY_MACHINE_ID").cloned().unwrap_or_default();
    let server = server.trim_end_matches('/').to_string();
    Ok(RelayConfig {
        server,
        device_id,
        machine_id,
        token,
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
    let mut file_level = log::LevelFilter::Debug;
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
/// error. Order: relay.conf -> environment -> defaults (file log on debug,
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
        .unwrap_or(log::LevelFilter::Debug);
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
    let server = server.trim_end_matches('/').to_string();
    let cfg = RelayConfig {
        server,
        device_id,
        machine_id,
        token,
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

/// Shared reqwest blocking client.  Wrapped in `RwLock<Option<Arc<...>>>` so
/// the config watcher can drop it (forcing a rebuild) without blocking
/// in-flight requests (the old `Arc` stays alive until its last user drops it).
static HTTP_CLIENT: RwLock<Option<Arc<Client>>> = RwLock::new(None);

fn build_http_client() -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .timeout(Duration::from_millis(READ_TIMEOUT_MS))
        .build()
        .context("build reqwest client")
}

/// Returns the shared HTTP client, building it on first use.
fn get_http_client() -> Result<Arc<Client>> {
    // Fast path: read lock, return if present.
    if let Ok(guard) = HTTP_CLIENT.read() {
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
    }
    // Slow path: write lock, build if still absent.
    let mut guard = HTTP_CLIENT.write().map_err(|_| anyhow!("HTTP client lock poisoned"))?;
    if let Some(client) = guard.as_ref() {
        return Ok(client.clone());
    }
    let client = Arc::new(build_http_client()?);
    *guard = Some(client.clone());
    Ok(client)
}

/// Drops the shared HTTP client so the next request rebuilds it.
/// Called from the config watcher when the server URL changes.
fn reset_http_client() {
    if let Ok(mut guard) = HTTP_CLIENT.write() {
        *guard = None;
        log::info!("HTTP client reset (connection pool cleared)");
    }
}

fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>)> {
    let client = get_http_client()?;
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
    let url = format!(
        "{}/api/b/poll/?device_id={}&machine_id={}&timeout={}",
        cfg.server, cfg.device_id, cfg.machine_id, POLL_TIMEOUT_SEC
    );
    let headers = vec![(
        "X-Relay-Token".to_string(),
        cfg.token.clone(),
    )];
    let (status, body) = http_request("GET", &url, &headers, None)
        .with_context(|| "b/poll failed")?;
    log::info!("b/poll status={status} body_len={}", body.len());
    match status {
        204 => Ok(None),
        200 => {
            let v: Value =
                serde_json::from_slice(&body).with_context(|| "b/poll bad json")?;
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
        match http_request("POST", &url, &headers, Some(body.to_string().as_bytes())) {
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

    let app_id_der = b64_decode(app_id)
        .with_context(|| "decode attestation_application_id")?;
    let challenge = b64_decode(challenge).with_context(|| "decode challenge")?;
    Ok((app_id_der, challenge))
}

/// Parses the A-side requested key parameters from a task payload into a
/// [`tee_ops::KeySpec`]. Fields may live at the top level or nested under
/// `device_attest_context`; absent fields keep the KeySpec defaults (EC P-256,
/// SHA-256, etc.).
fn parse_key_spec(payload: &Value) -> Result<KeySpec> {
    let nested = payload.get("device_attest_context");
    let get = |k: &str| -> Option<&Value> {
        payload.get(k).or_else(|| nested.and_then(|n| n.get(k)))
    };
    let get_i64 = |k: &str| get(k).and_then(Value::as_i64);
    let get_arr = |k: &str| -> Vec<&Value> {
        get(k).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]).iter().collect()
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
        vals.iter().filter_map(|v| v.as_i64()).map(|n| n as i32).collect()
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
    log::info!("cert_chain[{tag}]: {} certs :: {}", chain.len(), lines.join(" | "));
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
    check_app_id_der(&app_id_der)
        .with_context(|| "attestation_application_id is not a valid AttestationApplicationId DER")?;
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
                log::warn!(
                    "B-side StrongBox unavailable ({reason}): {err_str}"
                );
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
        "public_key": b64(&tee_ops::get_public_key(&alias)?),
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

fn handle_task(cfg: &RelayConfig, task_id: &str, task_type: &str, payload: &Value) -> Result<()> {
    let handler: fn(&str, &Value) -> Result<Value> = match task_type {
        "attest" => handle_generate_attest,
        "sign" => handle_sign,
        "decrypt" => handle_decrypt,
        other => {
            log::warn!("task {task_id} type={other} not supported, reporting failure");
            post_result(cfg, task_id, &json!({ "error": format!("unsupported task type: {other}") }))?;
            return Ok(());
        }
    };

    let start = std::time::Instant::now();
    log::info!("processing task {task_id} type={task_type}");
    let result = match handler(task_type, payload) {
        Ok(v) => v,
        Err(e) => {
            log::error!("task {task_id} type={task_type} failed: {e:#}");
            json!({ "error": format!("{e:#}") })
        }
    };
    let outcome = if result.get("error").is_some() { "failed" } else { "ok" };
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

fn run_loop(shared: Arc<RwLock<RelayConfig>>) {
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
        match poll_tasks(&cfg) {
            Ok(Some((task_id, task_type, payload))) => {
                log::info!("poll received task {task_id} type={task_type}");
                if let Err(e) = handle_task(&cfg, &task_id, &task_type, &payload) {
                    log::error!("handle_task failed: {e:#}");
                }
            }
            Ok(None) => { /* long poll timed out, loop again */ }
            Err(e) => {
                log::warn!("poll failed: {e:#}; retrying");
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
    }
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
