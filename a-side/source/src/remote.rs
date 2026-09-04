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
//! Two long-lived reqwest clients (insecure / verify) are kept in `OnceLock`s
//! and selected per request based on the current `tls_insecure` config value.
//! Each client has its own internal connection pool, so concurrent requests
//! are not serialised through a single Mutex — fixing the previous single-
//! connection pool bottleneck.  reqwest also natively supports chunked transfer
//! encoding and HTTP keep-alive, both of which the hand-written client did not.

use std::sync::OnceLock;
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

/// Returns a reqwest blocking client configured for the current `tls_insecure`
/// setting.  Two clients (insecure / verify) are lazily initialised and cached
/// in `OnceLock`s — each carries its own connection pool, so flipping
/// `tls_insecure` at runtime just picks the other pool.
fn get_client() -> Result<Client> {
    let insecure = config::config()
        .read()
        .map(|c| c.remote.tls_insecure)
        .unwrap_or(true);

    if insecure {
        static INSECURE_CLIENT: OnceLock<Client> = OnceLock::new();
        Ok(INSECURE_CLIENT.get_or_init(|| build_client(true)).clone())
    } else {
        static VERIFY_CLIENT: OnceLock<Client> = OnceLock::new();
        Ok(VERIFY_CLIENT.get_or_init(|| build_client(false)).clone())
    }
}

fn build_client(insecure: bool) -> Client {
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .timeout(Duration::from_millis(READ_TIMEOUT_MS))
        .user_agent("ommegaclient-a/1.3");

    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder
        .build()
        .expect("failed to build reqwest blocking client")
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
        match config::config().read() {
            Ok(g) => g.remote.fallback_local,
            Err(_) => true,
        }
    }
}
