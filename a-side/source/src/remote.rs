// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Remote TEE relay client (A-side).
//!
//! When `[remote].enabled` is set in `config.toml`, attestation / sign / decrypt
//! for A-side keys are forwarded to the relay_server (and from there to a B-side
//! real hardware TEE).  This module uses `reqwest::blocking::Client` to talk to
//! the relay_server API, mirroring the protocol used by the B-side relay agent
//! (`ommegaclient-b`).
//!
//! The relay_server uses a self-signed certificate by default, so
//! `tls_insecure` (default true) accepts any server certificate — matching the
//! B-side client behaviour.
//!
//! A reqwest client is kept in a process-wide slot and handed out per request;
//! it is rebuilt only when `tls_insecure` or the outgoing interface changes.
//! Each client has its own internal connection pool, so concurrent requests
//! are not serialised through a single connection — fixing the previous single-
//! connection pool bottleneck.  reqwest also natively supports chunked transfer
//! encoding and HTTP keep-alive, both of which the hand-written client did not.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use reqwest::blocking::Client;
use reqwest::Method;
use serde_json::{json, Value};

use crate::config;

const CONNECT_TIMEOUT_MS: u64 = 3000;
const READ_TIMEOUT_MS: u64 = 30_000;

/// A relay-server client.  All configuration is read from `config().remote`.
pub struct RemoteRelay;

// ── reqwest client management ──────────────────────────────────────────

/// A cached client together with the inputs it was built from.
///
/// The interface is part of the identity because it follows VPN state: pinning
/// it in a `OnceLock` the way `tls_insecure` used to be pinned would freeze
/// whatever was decided the first time a request went out.
struct CachedClient {
    insecure: bool,
    iface: Option<String>,
    client: Client,
}

/// The connection pool.  Rebuilt only when `tls_insecure` or the chosen
/// interface changes; otherwise the same client (and its pool) is reused.
static CLIENT_CACHE: Mutex<Option<CachedClient>> = Mutex::new(None);

/// Returns a reqwest blocking client for the current `tls_insecure` setting and
/// the interface traffic should leave from.
fn get_client() -> Result<Client> {
    let (insecure, iface) = {
        let guard = config::config()
            .read()
            .map_err(|_| anyhow!("config lock poisoned"))?;
        (guard.remote.tls_insecure, desired_iface(&guard.remote))
    };

    let mut slot = CLIENT_CACHE
        .lock()
        .map_err(|_| anyhow!("client cache lock poisoned"))?;

    if let Some(cached) = slot.as_ref() {
        if cached.insecure == insecure && cached.iface == iface {
            return Ok(cached.client.clone());
        }
    }

    if let Some(name) = iface.as_deref() {
        log::info!("relay traffic bound to interface {name}");
    }
    let client = build_client(insecure, iface.as_deref());
    *slot = Some(CachedClient {
        insecure,
        iface,
        client,
    });

    Ok(slot
        .as_ref()
        .expect("client was just stored")
        .client
        .clone())
}

fn build_client(insecure: bool, iface: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .timeout(Duration::from_millis(READ_TIMEOUT_MS))
        // This client only ever talks to our own relay server.  The environment
        // proxies reqwest picks up by default exist for tools that browse the
        // open internet; on a forwarding path they only redirect the request
        // somewhere it does not belong.
        .no_proxy()
        .user_agent("ommegaclient-a/1.3");

    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }

    if let Some(name) = iface {
        // `SO_BINDTODEVICE`: pin the socket to a physical uplink so the routing
        // rules that steer traffic into a VPN tunnel do not capture it.
        builder = builder.interface(name);
    }

    builder
        .build()
        .expect("failed to build reqwest blocking client")
}

// ── outgoing interface selection ───────────────────────────────────────

/// What the `bind_iface` config value means.
#[derive(Debug, PartialEq, Eq)]
enum BindChoice {
    /// `none` / `off` — never bind.
    Never,
    /// Empty or `auto` (the default) — bind only while a VPN is up.
    Auto,
    /// `always` / `on` — always bind to a physical uplink.
    Always,
    /// A literal interface name, used as given.
    Named(String),
}

fn classify_bind_iface(raw: &str) -> BindChoice {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("none") || v.eq_ignore_ascii_case("off") {
        BindChoice::Never
    } else if v.eq_ignore_ascii_case("always") || v.eq_ignore_ascii_case("on") {
        BindChoice::Always
    } else if v.is_empty() || v.eq_ignore_ascii_case("auto") {
        BindChoice::Auto
    } else {
        BindChoice::Named(v.to_string())
    }
}

const SYS_CLASS_NET: &str = "/sys/class/net";

/// Decides which interface (if any) this request should leave from.
///
/// Why bind at all: with a VPN up, the OS steers ordinary traffic into the
/// tunnel — netd points the connection's fwmark at the VPN network and the
/// default route ends up on `tun`.  Traffic to our own relay server gets caught
/// by the same rules, so it goes through the tunnel too: slower, jittery, and in
/// the bad cases simply unreachable.  The only way to keep a socket out of that
/// is to name its outgoing device (`SO_BINDTODEVICE`, which is what reqwest's
/// `.interface()` sets).
///
/// Why `auto` binds only when a VPN is present: pinning one interface would also
/// throw away the OS's own "WiFi dropped, fall back to cellular" switching,
/// which is pure downside when there is no VPN to avoid.  Deployments that want
/// a fixed interface can name it explicitly.
fn desired_iface(cfg: &config::RemoteConfig) -> Option<String> {
    match classify_bind_iface(&cfg.bind_iface) {
        BindChoice::Never => None,
        BindChoice::Always => pick_uplink_iface(),
        BindChoice::Auto if vpn_active() => pick_uplink_iface(),
        BindChoice::Auto => None,
        // An explicit name is taken at face value: whether it exists or works is
        // the kernel's call, not ours.
        BindChoice::Named(name) => Some(name),
    }
}

/// Whether a VPN is currently up.  `VpnService` always leaves a `tun` device in
/// `/sys/class/net` and the older pptp/l2tp paths leave a `ppp`; the names are
/// always `tun0` / `ppp0` shaped, so a prefix check is enough.
fn vpn_active() -> bool {
    let Ok(entries) = std::fs::read_dir(SYS_CLASS_NET) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("tun") || n.starts_with("ppp") || n.starts_with("tap"))
    })
}

/// Picks a physical uplink interface.
///
/// Measured on a Z60 Ultra (Android 16), two traps: `dummy0` and `lo` both
/// report `operstate=unknown` with `carrier=1`, indistinguishable from a real
/// NIC by state alone, so virtual devices have to be excluded by name; and the
/// cellular `rmnet_data*` interfaces also report `unknown` (they have no real
/// link-layer state), so testing for `up` alone would skip them.
///
/// That is still not enough: `rmnet_data0/1` sit at `operstate=unknown` with no
/// IP address most of the time, and binding to one of those means binding to a
/// device with no route.  `/proc/net/route` lists exactly the interfaces that
/// currently hold an IPv4 address (two rows on the device above: `wlan0` and
/// `rmnet_data3`), which makes it a precise cross-filter.
fn pick_uplink_iface() -> Option<String> {
    let with_ip = ifaces_with_ipv4();
    if with_ip.is_empty() {
        return None;
    }

    let entries = std::fs::read_dir(SYS_CLASS_NET).ok()?;
    let mut best: Option<(u8, String)> = None;
    for e in entries.flatten() {
        let entry_name = e.file_name();
        let Some(name) = entry_name.to_str() else {
            continue;
        };
        if is_virtual_iface(name) || !with_ip.iter().any(|n| n == name) {
            continue;
        }
        let state = std::fs::read_to_string(format!("{SYS_CLASS_NET}/{name}/operstate"))
            .unwrap_or_default();
        let state = state.trim();
        if state != "up" && state != "unknown" {
            continue;
        }
        let rank = uplink_rank(name);
        if best.as_ref().is_none_or(|(r, _)| rank < *r) {
            best = Some((rank, name.to_string()));
        }
    }
    best.map(|(_, name)| name)
}

/// The interfaces currently holding an IPv4 address, as listed in
/// `/proc/net/route` (header row skipped).
fn ifaces_with_ipv4() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let Ok(text) = std::fs::read_to_string("/proc/net/route") else {
        return names;
    };
    for line in text.lines().skip(1) {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// Virtual or otherwise unsuitable devices: tunnels, bridges, loopback, dummy,
/// and the VPN's own interfaces.
fn is_virtual_iface(name: &str) -> bool {
    const VIRTUAL: &[&str] = &[
        "lo",
        "dummy",
        "tun",
        "tap",
        "ppp",
        "sit",
        "ip6",
        "ip_",
        "gre",
        "gretap",
        "erspan",
        "ifb",
        "p2p",
        "r_rmnet",
        "veth",
        "br",
        "bond",
        "vlan",
        "nrm",
        "rmnet_ipa",
    ];
    VIRTUAL.iter().any(|prefix| name.starts_with(prefix))
}

/// Preference among physical uplinks: wired, then WiFi, then cellular, then
/// anything else.  Matches how Android itself ranks networks.
fn uplink_rank(name: &str) -> u8 {
    if name.starts_with("eth") {
        0
    } else if name.starts_with("wlan") {
        1
    } else if name.starts_with("rmnet") {
        2
    } else {
        3
    }
}

/// Minimal HTTP(S) request helper backed by reqwest.
///
/// Returns `(status, body)`.  HTTP error responses (4xx / 5xx) are returned as
/// `Ok` with the corresponding status code — only transport-level failures
/// produce `Err`.  This matches the original hand-written client contract so
/// callers (`post_json` and its retry logic) behave identically.
fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>)> {
    let client = get_client()?;
    let method = method
        .parse::<Method>()
        .map_err(|e| anyhow!("invalid HTTP method {method}: {e}"))?;

    let mut req = client.request(method, url);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    if let Some(b) = body {
        req = req.body(b.to_vec());
    }

    let resp = req
        .send()
        .with_context(|| format!("HTTP request to {url}"))?;

    let status = resp.status().as_u16();
    let body_bytes = resp
        .bytes()
        .with_context(|| format!("reading response body from {url}"))?
        .to_vec();

    Ok((status, body_bytes))
}

// ── RemoteRelay public API ─────────────────────────────────────────────

impl RemoteRelay {
    fn remote() -> Result<config::RemoteConfig> {
        let guard = config::config()
            .read()
            .map_err(|_| anyhow!("config lock poisoned"))?;
        Ok(guard.remote.clone())
    }

    fn base_url() -> Result<String> {
        let r = Self::remote()?;
        if !r.enabled {
            return Err(anyhow!("remote relay not enabled"));
        }
        if r.url.is_empty() {
            return Err(anyhow!("remote url not configured"));
        }
        Ok(r.url.trim_end_matches('/').to_string())
    }

    fn token() -> Result<String> {
        let r = Self::remote()?;
        if r.token.is_empty() {
            return Err(anyhow!("remote token not configured"));
        }
        Ok(r.token)
    }

    fn device_id() -> Result<String> {
        let r = Self::remote()?;
        if r.device_id.is_empty() {
            return Err(anyhow!("remote device_id not configured"));
        }
        Ok(r.device_id)
    }

    /// POST a JSON body to a relay endpoint.  Returns `Ok(Some(json))` on 2xx
    /// with a JSON body, `Ok(None)` if the remote is unreachable/non-2xx.
    fn post_json(path: &str, body: &Value) -> Result<Option<Value>> {
        let url = format!("{}{}", Self::base_url()?, path);
        let body_str = serde_json::to_string(body)?;
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Relay-Token".to_string(), Self::token()?),
        ];
        // Transient transport failures (connect timeout, network jitter, TLS
        // handshake) are retried once before giving up. Without the retry a
        // single dropped attempt falls back to the local software keybox and
        // briefly emits a self-signed chain. HTTP error responses are NOT
        // retried — the server answered, and its body carries the real result.
        let (status, resp) = match http_request("POST", &url, &headers, Some(body_str.as_bytes())) {
            Ok(v) => v,
            Err(first) => {
                log::warn!("remote {path} transport error, retrying once: {first:#}");
                http_request("POST", &url, &headers, Some(body_str.as_bytes()))
                    .map_err(|second| anyhow!("{first:#}; retry also failed: {second:#}"))?
            }
        };
        if !(200..300).contains(&status) {
            log::warn!("remote {path} HTTP {status}");
            return Ok(None);
        }
        if resp.is_empty() {
            return Ok(None);
        }
        // A 2xx response that is not JSON is a server/protocol error, not
        // "remote unavailable" — surface it loudly instead of silently falling
        // back to the local software keybox (which would emit a self-signed
        // chain and hide the real failure).
        serde_json::from_slice(&resp)
            .map(Some)
            .map_err(|e| anyhow!("relay returned malformed JSON (status {status}): {e}"))
    }

    /// Forward an attestation request.  `challenge` is the caller's nonce.
    pub fn attest(
        challenge: &[u8],
        alias: &str,
        app_id_der: &[u8],
        params: &kmr_ta::device::RemoteAttestParams,
        cert_serial: Option<&[u8]>,
    ) -> Result<Option<Value>> {
        let mut ctx = serde_json::Map::new();
        ctx.insert(
            "attestation_application_id".to_string(),
            Value::String(base64_encode(app_id_der)),
        );
        // Use the device's real verified-boot key/hash from the resolved trust
        // config (client-a forwards `AndroidDeviceUtils.bootKey/bootHash`).
        let (vb_key, vb_hash) = Self::verified_boot_values();
        ctx.insert(
            "verified_boot_key".to_string(),
            Value::String(base64_encode(&vb_key)),
        );
        ctx.insert(
            "verified_boot_hash".to_string(),
            Value::String(base64_encode(&vb_hash)),
        );
        ctx.insert("device_locked".to_string(), Value::Bool(true));
        ctx.insert("verified_boot_state".to_string(), Value::from(0));
        ctx.insert(
            "creation_datetime_ms".to_string(),
            Value::from(Self::now_ms()),
        );
        // Forward the app's key-generation parameters (mirroring client-a) so
        // the B-side TEE mints a key matching the request, not an EC-P256 default.
        if let Some(algo) = params.key_algorithm {
            ctx.insert("key_algorithm".to_string(), Value::from(algo));
        }
        if let Some(size) = params.key_size {
            ctx.insert("key_size".to_string(), Value::from(size));
        }
        if let Some(curve) = params.ec_curve {
            ctx.insert("ec_curve".to_string(), Value::from(curve));
        }
        if !params.purpose.is_empty() {
            ctx.insert(
                "purpose".to_string(),
                Value::Array(params.purpose.iter().copied().map(Value::from).collect()),
            );
        }
        if !params.digest.is_empty() {
            ctx.insert(
                "digest".to_string(),
                Value::Array(params.digest.iter().copied().map(Value::from).collect()),
            );
        }
        if !params.padding.is_empty() {
            ctx.insert(
                "padding".to_string(),
                Value::Array(params.padding.iter().copied().map(Value::from).collect()),
            );
        }
        if let Some(mgf) = params.mgf_digest {
            ctx.insert("mgf_digest".to_string(), Value::from(mgf));
        }
        if let Some(exponent) = params.rsa_public_exponent {
            ctx.insert("rsa_public_exponent".to_string(), Value::from(exponent));
        }
        if let Some(subject) = &params.certificate_subject {
            ctx.insert(
                "certificate_subject".to_string(),
                Value::String(base64_encode(subject)),
            );
        }
        if let Some(not_before) = params.certificate_not_before_ms {
            ctx.insert(
                "certificate_not_before_ms".to_string(),
                Value::from(not_before),
            );
        }
        if let Some(not_after) = params.certificate_not_after_ms {
            ctx.insert(
                "certificate_not_after_ms".to_string(),
                Value::from(not_after),
            );
        }
        if let Some(serial) = cert_serial {
            ctx.insert(
                "certificate_serial".to_string(),
                Value::String(base64_encode(serial)),
            );
        }
        // Forward the requesting security level (1 = TEE, 2 = StrongBox) so the
        // relay tags the attestation extension the same way the A-side reported
        // it. Without this a STRONGBOX request minted remotely is mislabelled as
        // TEE (the relay's `attestation_security_level` default is 1).
        if let Some(security_level) = params.security_level {
            ctx.insert(
                "attestation_security_level".to_string(),
                Value::from(i64::from(security_level)),
            );
        }
        // Forward the device's OS version + security patch level so the relay
        // can emit KM_TAG_OS_VERSION (705) / KM_TAG_OS_PATCH_LEVEL (706) in the
        // teeEnforced authorization list. Software attestations that omit these
        // two tags are flagged as tampered by self-check apps (e.g. 密钥认证
        // 1.7's `checkTagOrderMisordered` requires 704/705/706 all present).
        let os_version = match config::config().read() {
            Ok(g) => (g.trust.os_version.max(0) as u32) * 10000,
            Err(_) => {
                (kmr_common::android_version::android_major_version().unwrap_or(16) as u32) * 10000
            }
        };
        if os_version > 0 {
            ctx.insert("os_version".to_string(), Value::from(os_version));
        }
        let os_patch_level = match config::config().read() {
            Ok(g) => patch_level_to_yyyymm(&g.trust.os_patchlevel),
            Err(_) => None,
        }
        .or_else(|| {
            crate::plat::resetprop::read_string_property("ro.build.version.security_patch")
                .as_deref()
                .and_then(patch_level_to_yyyymm)
        });
        if let Some(patch) = os_patch_level {
            ctx.insert("os_patch_level".to_string(), Value::from(patch));
        }
        // KeyMint 3.0+ also carries per-partition patch levels
        // (KM_TAG_VENDOR_PATCH_LEVEL 707 / KM_TAG_BOOT_PATCH_LEVEL 708).
        // Real TEE attestations include them; omitting them makes the server
        // keybox layer fail STRONG integrity checks that expect them.
        // Prefer the device's real partition patch props; the resolved config
        // `[trust]` values can be stale/malformed (e.g. a bogus "2026-30").
        let vendor_patch_level =
            crate::plat::resetprop::read_string_property("ro.vendor.build.security_patch")
                .as_deref()
                .and_then(patch_level_to_yyyymm)
                .or_else(|| match config::config().read() {
                    Ok(g) => patch_level_to_yyyymm(&g.trust.vendor_patchlevel),
                    Err(_) => None,
                })
                .or(os_patch_level);
        if let Some(patch) = vendor_patch_level {
            ctx.insert("vendor_patch_level".to_string(), Value::from(patch));
        }
        let boot_patch_level =
            crate::plat::resetprop::read_string_property("ro.boot.build.security_patch")
                .as_deref()
                .and_then(patch_level_to_yyyymm)
                .or_else(|| match config::config().read() {
                    Ok(g) => patch_level_to_yyyymm(&g.trust.boot_patchlevel),
                    Err(_) => None,
                })
                .or(os_patch_level);
        if let Some(patch) = boot_patch_level {
            ctx.insert("boot_patch_level".to_string(), Value::from(patch));
        }
        // The B-side reads `device_attest_context` (nested form) for the
        // appid and optional serial; the full key params are passed through.
        let body = json!({
            "challenge": base64_encode(challenge),
            "alias": alias,
            "device_id": Self::device_id()?,
            "device_attest_context": Value::Object(ctx),
        });
        Self::post_json("/api/attest/", &body)
    }

    /// Millis since epoch (used for `creation_datetime_ms`).
    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Resolved verified-boot key/hash from `config().trust` (32 bytes each).
    /// Falls back to zeros if the config lock is unavailable (never fatal).
    fn verified_boot_values() -> ([u8; 32], [u8; 32]) {
        match config::config().read() {
            Ok(g) => (g.trust.vb_key, g.trust.vb_hash),
            Err(_) => ([0u8; 32], [0u8; 32]),
        }
    }

    /// Forward a sign request for a remote key.
    pub fn sign(alias: &str, data: &[u8], algorithm: &str) -> Result<Option<Value>> {
        let body = json!({
            "alias": alias,
            "data": base64_encode(data),
            "algorithm": algorithm,
            "device_id": Self::device_id()?,
        });
        Self::post_json("/api/sign/", &body)
    }

    /// Forward a decrypt request for a remote key.
    pub fn decrypt(alias: &str, data: &[u8], algorithm: &str) -> Result<Option<Value>> {
        let body = json!({
            "alias": alias,
            "data": base64_encode(data),
            "algorithm": algorithm,
            "device_id": Self::device_id()?,
        });
        Self::post_json("/api/decrypt/", &body)
    }

    /// Forward one SOTER operation to a B-side device.
    ///
    /// `payload` is the operation plus its arguments (`{"op": "export_ask_public_key",
    /// "uid": 10373, ...}`); `device_id` is filled in here so the server prefers a
    /// B端 carrying this device's own id and otherwise load-balances to another one
    /// that reported SOTER support.
    ///
    /// `Ok(None)` means no B-side can serve SOTER right now — the server answers a
    /// capability error (`no B-side device reporting SOTER support is online`, or
    /// the chosen device's own HAL error) and this method maps it to "not
    /// available", so the caller falls back to whatever it does without
    /// forwarding instead of inventing an answer.
    pub fn soter(payload: &Value) -> Result<Option<Value>> {
        let mut body = match payload.as_object() {
            Some(map) => map.clone(),
            None => return Err(anyhow!("soter payload must be a JSON object")),
        };
        body.insert("device_id".to_string(), Value::from(Self::device_id()?));
        Self::post_json("/api/soter/", &Value::Object(body))
    }
}

fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Convert a "YYYY-MM-DD" patch level string to the YYYYMM integer the relay
/// expects for KM_TAG_OS_PATCH_LEVEL (706).
fn patch_level_to_yyyymm(value: &str) -> Option<u32> {
    let s = value.trim();
    // Accept both "YYYY-MM-DD" (or "YYYY-MM") and bare "YYYYMM".
    if s.len() >= 6 {
        let (year, month) = if s.as_bytes().get(4) == Some(&b'-') {
            (s[0..4].parse::<u32>().ok()?, s[5..7].parse::<u32>().ok()?)
        } else {
            (s[0..4].parse::<u32>().ok()?, s[4..6].parse::<u32>().ok()?)
        };
        if (1..=12).contains(&month) {
            return Some(year * 100 + month);
        }
    }
    None
}

/// Convenience: `true` if remote relay is enabled in config.
pub fn remote_enabled() -> bool {
    match config::config().read() {
        Ok(g) => g.remote.enabled && !g.remote.url.is_empty(),
        Err(_) => false,
    }
}

/// Convenience: `true` if the remote chain may fall back to local processing.
///
/// The flat A-side config spells this `local_hw` (`RemoteConfig::fallback_local`
/// is what the WebUI writes under that name); a lock poisoned by another thread
/// means we cannot tell, and the legacy client-a behaviour always fell back, so
/// answer `true`.
pub fn fallback_local() -> bool {
    match config::config().read() {
        Ok(g) => g.remote.fallback_local,
        Err(_) => true,
    }
}

/// Adapts [`RemoteRelay`] to the TA's [`kmr_ta::device::RemoteBackend`] trait.
pub struct RemoteRelayBackend;

impl kmr_ta::device::RemoteBackend for RemoteRelayBackend {
    fn attest(
        &self,
        challenge: &[u8],
        app_id_der: &[u8],
        alias: &str,
        cert_serial: Option<&[u8]>,
        params: &kmr_ta::device::RemoteAttestParams,
    ) -> Result<Option<Vec<Vec<u8>>>, kmr_common::Error> {
        // Transport-level failure (connect timeout / network unreachable / TLS
        // handshake) means the relay is unavailable — report `Ok(None)` so the
        // TA falls back to the local software keybox (matching client-a, which
        // treats an unreachable remote as "do it locally").
        let resp = match RemoteRelay::attest(challenge, alias, app_id_der, params, cert_serial) {
            Ok(resp) => resp,
            Err(e) => {
                log::warn!("remote relay unavailable, falling back to local: {e:#}");
                return Ok(None);
            }
        };
        let Some(resp) = resp else {
            return Ok(None);
        };
        // The relay wraps the result as `{ result: { cert_chain: [...] } }`.
        let result = resp.get("result").cloned().unwrap_or(resp);
        // Smart-mode StrongBox policy: when the relay decides the B device HAS a
        // StrongBox HAL but cannot deliver (attestation keys not provisioned /
        // hardware type unavailable), it returns a 200 body carrying the B error
        // verbatim plus a `relay_error_kind` marker. That must reach the calling
        // app as a real KeyMint error — NOT fall back to the local software
        // keybox, which would mint a StrongBox-level chain from the A-side's own
        // keybox and hide the true device state. Only these marked responses
        // error out; every other failure keeps returning `Ok(None)` so the local
        // fallback path (incl. Smart-mode branch 4) is unchanged.
        let kind = result.get("relay_error_kind").and_then(Value::as_str);
        if let Some(kind) = kind {
            let msg = result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("relay: StrongBox attestation refused by B device");
            log::warn!("remote StrongBox attestation refused by B device (kind={kind}): {msg}");
            return Err(match kind {
                "strongbox_unprovisioned" => {
                    kmr_common::km_err!(AttestationKeysNotProvisioned, "{msg}")
                }
                "strongbox_unavailable" => {
                    kmr_common::km_err!(HardwareTypeUnavailable, "{msg}")
                }
                _ => kmr_common::km_err!(UnknownError, "{msg}"),
            });
        }
        let chain = match result.get("cert_chain") {
            Some(Value::Array(certs)) => certs
                .iter()
                .filter_map(|c| c.as_str())
                .filter_map(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
                .collect::<Vec<Vec<u8>>>(),
            _ => Vec::new(),
        };
        if chain.is_empty() {
            log::warn!("remote attest returned empty cert chain");
            return Ok(None);
        }
        Ok(Some(chain))
    }

    fn sign(
        &self,
        alias: &str,
        data: &[u8],
        algorithm: &str,
    ) -> Result<Option<Vec<u8>>, kmr_common::Error> {
        let Some(resp) = RemoteRelay::sign(alias, data, algorithm)
            .map_err(|e| kmr_common::km_err!(UnknownError, "remote sign: {e:#}"))?
        else {
            return Ok(None);
        };
        let result = resp.get("result").cloned().unwrap_or(resp);
        let sig_b64 = result
            .get("signature")
            .or_else(|| result.get("data"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                kmr_common::km_err!(UnknownError, "remote sign response missing signature")
            })?;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| kmr_common::km_err!(UnknownError, "bad remote signature base64: {e}"))?;
        Ok(Some(sig))
    }

    fn decrypt(
        &self,
        alias: &str,
        data: &[u8],
        algorithm: &str,
    ) -> Result<Option<Vec<u8>>, kmr_common::Error> {
        let Some(resp) = RemoteRelay::decrypt(alias, data, algorithm)
            .map_err(|e| kmr_common::km_err!(UnknownError, "remote decrypt: {e:#}"))?
        else {
            return Ok(None);
        };
        let result = resp.get("result").cloned().unwrap_or(resp);
        let plain_b64 = result.get("data").and_then(Value::as_str).ok_or_else(|| {
            kmr_common::km_err!(UnknownError, "remote decrypt response missing data")
        })?;
        let plain = base64::engine::general_purpose::STANDARD
            .decode(plain_b64)
            .map_err(|e| kmr_common::km_err!(UnknownError, "bad remote decrypt base64: {e}"))?;
        Ok(Some(plain))
    }

    fn enabled(&self) -> bool {
        remote_enabled()
    }

    fn fallback_local(&self) -> bool {
        fallback_local()
    }
}

#[cfg(test)]
mod iface_choice_tests {
    use super::*;

    #[test]
    fn bind_iface_spellings_map_to_the_right_choice() {
        assert_eq!(classify_bind_iface(""), BindChoice::Auto);
        assert_eq!(classify_bind_iface("  auto "), BindChoice::Auto);
        assert_eq!(classify_bind_iface("none"), BindChoice::Never);
        assert_eq!(classify_bind_iface("OFF"), BindChoice::Never);
        assert_eq!(classify_bind_iface("always"), BindChoice::Always);
        assert_eq!(classify_bind_iface("On"), BindChoice::Always);
        assert_eq!(
            classify_bind_iface(" wlan0 "),
            BindChoice::Named("wlan0".to_string())
        );
        // A real device name that happens to start with a keyword must not be
        // mistaken for the keyword itself.
        assert_eq!(
            classify_bind_iface("offload0"),
            BindChoice::Named("offload0".to_string())
        );
    }

    #[test]
    fn virtual_devices_are_never_picked() {
        for name in [
            "lo",
            "dummy0",
            "tun0",
            "ppp0",
            "ip6tnl0",
            "ip_vti0",
            "ifb0",
            "sit0",
            "gre0",
            "gretap0",
            "erspan0",
            "p2p0",
            "r_rmnet_data3",
            "rmnet_ipa0",
        ] {
            assert!(is_virtual_iface(name), "{name} must count as virtual");
        }
        for name in ["wlan0", "wlan1", "eth0", "rmnet_data0", "rmnet_data3"] {
            assert!(!is_virtual_iface(name), "{name} is a real uplink");
        }
    }

    #[test]
    fn wired_beats_wifi_beats_cellular() {
        assert!(uplink_rank("eth0") < uplink_rank("wlan0"));
        assert!(uplink_rank("wlan0") < uplink_rank("rmnet_data3"));
        assert!(uplink_rank("rmnet_data0") < uplink_rank("something0"));
    }
}
