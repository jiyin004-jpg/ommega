//! `server_keybox` mode: intercept A-side requests and fulfil them locally
//! using the stored DeviceServerIdentity (private key + certificate chain).
//!
//! Mirrors `relay_server/apps/portal/server_fulfill.py`:
//!   - sessions: device_id -> alias -> (chain_b64, leaf_key_pem, challenge, key_fp, ts)
//!   - try_handle_* return `Some(Value)` when fulfilled, `None` to fall back to
//!     the physical (A/B queue) path.

use base64::Engine;
use chrono::Utc;
use ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature as P256DerSignature, Signature as P256Signature};
use p384::ecdsa::{DerSignature as P384DerSignature, Signature as P384Signature};
use p521::ecdsa::{DerSignature as P521DerSignature, Signature as P521Signature};
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use rsa::traits::Decryptor;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cert::{self, AttestationParams, RootOfTrust};
use crate::db::{Db, DeviceIdentity};

/// AOSP keymint::kMaxChallengeSize = 128 bytes.
/// Attestation challenges larger than this are rejected to avoid
/// triggering Duck-Detector's OversizedChallengeProbe.
const MAX_CHALLENGE_SIZE: usize = 128;

const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Where server_keybox sessions (leaf private key + chain) are persisted so a
/// relay restart does not orphan the A-side's `KeyMaterial::Remote` keys.
/// The A-side derives the session alias deterministically from the attestation
/// challenge, but the private key lives here — if it is lost (e.g. a restart),
/// the app's "use attestation key" flow cannot sign child certs and hangs.
///
/// Sessions are keyed by the A-side's `ommega-remote-*` alias ALONE (not by
/// device_id): the alias is derived from (challenge, serial) on the A-side and
/// is independent of device_id. Keying by (device_id, alias) meant that any
/// device_id change (or a B-side identity re-upload under a new id) orphaned
/// every previously stored attestation key and forced a manual app reset. With
/// alias-keying, a sign request for a known alias always resolves to the same
/// leaf key — across server restarts, device_id changes and identity rotation.
const SESSION_FILE: &str = "data/sessions.json";

#[derive(Debug, Clone)]
struct Session {
    chain_pem: String,
    leaf_key_pem: String,
    created_epoch_ms: u64,
}

/// On-disk form of a session: the leaf private key is encrypted with the same
/// Fernet cipher used for the DB identities (see `crypto::encrypt_private_pem`)
/// instead of being persisted in plaintext. `decrypt_private_pem` falls back to
/// the input verbatim, so legacy plaintext rows keep loading.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SessionFile {
    chain_pem: String,
    leaf_key_pem: String,
    created_epoch_ms: u64,
}

impl From<&Session> for SessionFile {
    fn from(s: &Session) -> Self {
        SessionFile {
            chain_pem: s.chain_pem.clone(),
            leaf_key_pem: crate::crypto::encrypt_private_pem(&s.leaf_key_pem),
            created_epoch_ms: s.created_epoch_ms,
        }
    }
}

impl From<SessionFile> for Session {
    fn from(sf: SessionFile) -> Self {
        Session {
            chain_pem: sf.chain_pem,
            leaf_key_pem: crate::crypto::decrypt_private_pem(&sf.leaf_key_pem),
            created_epoch_ms: sf.created_epoch_ms,
        }
    }
}

#[derive(Default)]
struct Inner {
    /// alias -> session
    sessions: HashMap<String, Session>,
}

pub struct Fulfill {
    inner: Mutex<Inner>,
    enabled: AtomicBool,
    /// Cache of generated self-signed identities per (device_id, algorithm) so
    /// a device without a stored identity doesn't regenerate a fresh key (RSA
    /// keygen is slow) on every attestation.
    self_signed_cache: Mutex<HashMap<(String, String), DeviceIdentity>>,
    pub db: Option<Arc<Db>>,
}

impl Fulfill {
    pub fn new(enabled: bool, db: Option<Arc<Db>>) -> Arc<Self> {
        let f = Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            enabled: AtomicBool::new(enabled),
            self_signed_cache: Mutex::new(HashMap::new()),
            db,
        });
        f.load_sessions();
        f
    }

    /// Runtime switch: whether `server_keybox` local fulfilment is active.
    /// A-side requests fall back to the physical (A/B queue) path when off.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    fn session_expired(s: &Session) -> bool {
        let now_ms = Utc::now().timestamp_millis() as u64;
        now_ms.saturating_sub(s.created_epoch_ms) > SESSION_TTL.as_millis() as u64
    }

    fn purge_locked(map: &mut HashMap<String, Session>) {
        map.retain(|_, s| !Self::session_expired(s));
    }

    fn session_file() -> std::path::PathBuf {
        std::path::Path::new(SESSION_FILE).to_path_buf()
    }

    /// Restore persisted sessions at startup. Expired entries are purged.
    /// Accepts both the old `device_id -> alias -> session` layout and the
    /// current flat `alias -> session` layout (migration). Leaf private keys
    /// are stored encrypted at rest; `SessionFile -> Session` decrypts and
    /// falls back to legacy plaintext rows transparently.
    fn load_sessions(&self) {
        let path = Self::session_file();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        let mut inner = crate::util::mu(&self.inner);
        if let Ok(flat) = serde_json::from_str::<HashMap<String, SessionFile>>(&text) {
            for (alias, sf) in flat {
                inner.sessions.insert(alias, Session::from(sf));
            }
        } else if let Ok(nested) =
            serde_json::from_str::<HashMap<String, HashMap<String, SessionFile>>>(&text)
        {
            for (_device, aliases) in nested {
                for (alias, sf) in aliases {
                    inner.sessions.insert(alias, Session::from(sf));
                }
            }
        } else {
            return;
        }
        Self::purge_locked(&mut inner.sessions);
    }

    /// Write the current session map to `data/sessions.json` with leaf private
    /// keys encrypted at rest (same Fernet cipher as the DB identities).
    fn persist_sessions(&self) {
        let inner = crate::util::mu(&self.inner);
        let path = Self::session_file();
        let out: HashMap<String, SessionFile> = inner
            .sessions
            .iter()
            .map(|(a, s)| (a.clone(), SessionFile::from(s)))
            .collect();
        let Ok(text) = serde_json::to_string(&out) else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(&path, text) {
            // A lost session file means every A-side `KeyMaterial::Remote` key
            // becomes unsignable after a restart — surface it, don't swallow it.
            tracing::error!("persist_sessions: failed to write {}: {e}", path.display());
        }
    }

    fn get_session(&self, alias: &str) -> Option<Session> {
        let mut inner = crate::util::mu(&self.inner);
        Self::purge_locked(&mut inner.sessions);
        inner.sessions.get(alias).cloned()
    }

    fn put_session(&self, alias: &str, s: Session) {
        let mut inner = crate::util::mu(&self.inner);
        Self::purge_locked(&mut inner.sessions);
        inner.sessions.insert(alias.to_string(), s);
        drop(inner);
        self.persist_sessions();
    }

    /// Algorithm string implied by an A-side attest context ("ec" | "rsa"),
    /// kept in sync with `parse_ctx` below.
    ///
    /// The A-side (`remote.rs`) sends `key_algorithm` as an int (1=RSA, 3=EC)
    /// inside `device_attest_context`, NOT an `algorithm` string. We read the
    /// int first, and fall back to a JCA-style `algorithm` string when present.
    fn ctx_algorithm_str(ctx: &Value) -> String {
        if let Some(ka) = ctx.get("key_algorithm").and_then(Value::as_i64) {
            return if ka == 1 { "rsa" } else { "ec" }.to_string();
        }
        ctx.get("algorithm")
            .and_then(Value::as_str)
            .map(|a| {
                if a.to_lowercase().contains("rsa") {
                    "rsa"
                } else {
                    "ec"
                }
            })
            .unwrap_or("ec")
            .to_string()
    }

    /// Lookup a stored identity for `(device_id, algorithm)`. If no exact
    /// algorithm match exists, fall back to any identity for the same device
    /// (mirrors Django's `_get_identity` fallback_algo behaviour) so a device
    /// that only uploaded an EC key can still serve an RSA-flavoured request
    /// (and vice versa) when the certificate chain is algorithm-agnostic.
    fn identity_for(&self, device_id: &str, algorithm: &str) -> Option<DeviceIdentity> {
        let db = self.db.as_ref()?;
        if let Some(id) = db
            .get_device_identity_by_id(device_id, algorithm)
            .ok()
            .flatten()
        {
            return Some(id);
        }
        // Fallback: any active identity for this device (targeted query, no
        // full-table scan).
        db.get_any_device_identity(device_id).ok().flatten()
    }

    /// Parse the A-side `device_attest_context` object into AttestationParams.
    fn parse_ctx(&self, ctx: &Value, challenge: &[u8]) -> AttestationParams {
        let mut p = AttestationParams::default();
        p.challenge = challenge.to_vec();
        let b64 = |k: &str| {
            ctx.get(k)
                .and_then(Value::as_str)
                .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        };
        // Algorithm: prefer the int `key_algorithm` (1=RSA, 3=EC) that the
        // A-side actually sends, then fall back to a JCA `algorithm` string.
        let mut alg_from_int = false;
        if let Some(ka) = ctx.get("key_algorithm").and_then(Value::as_i64) {
            alg_from_int = true;
            if ka == 1 {
                p.algorithm = cert::KM_ALG_RSA;
            } else {
                p.algorithm = cert::KM_ALG_EC;
            }
        } else if let Some(alg) = ctx.get("algorithm").and_then(Value::as_str) {
            let a = alg.to_lowercase();
            if a.contains("rsa") {
                p.algorithm = cert::KM_ALG_RSA;
            } else {
                p.algorithm = cert::KM_ALG_EC;
            }
        }
        // Honor the A-side's requested key size / EC curve so the minted
        // leaf's public key matches the size/curve declared in the attestation
        // extension (a mismatch is flagged as a tampered key by verifiers).
        if let Some(size) = ctx.get("key_size").and_then(Value::as_i64) {
            p.key_size = size;
        }
        if let Some(curve) = ctx.get("ec_curve").and_then(Value::as_i64) {
            p.ec_curve = Some(curve);
        }
        // Fill in algorithm-dependent defaults only if not explicitly provided.
        if p.algorithm == cert::KM_ALG_RSA {
            if !alg_from_int || p.key_size == 0 {
                p.key_size = 2048;
            }
            if p.rsa_public_exponent.is_none() {
                p.rsa_public_exponent = Some(cert::rsa_exponent());
            }
            p.ec_curve = None;
        } else {
            if p.key_size == 0 {
                p.key_size = 256;
            }
            if p.ec_curve.is_none() {
                p.ec_curve = Some(cert::KM_EC_CURVE_P_256);
            }
        }
        // teeEnforced authorization list: forward the A-side's requested
        // purposes/digests/paddings so the attestation extension reflects the
        // key's actual authorization (AOSP conformance) instead of the
        // defaults. The A-side sends these as integer arrays inside
        // `device_attest_context` (see ommegaclient-a `remote.rs::attest`).
        if let Some(purposes) = ctx.get("purpose").and_then(Value::as_array) {
            let vals: Vec<i64> = purposes.iter().filter_map(Value::as_i64).collect();
            if !vals.is_empty() {
                p.purposes = vals;
            }
        }
        if let Some(digests) = ctx.get("digest").and_then(Value::as_array) {
            let vals: Vec<i64> = digests.iter().filter_map(Value::as_i64).collect();
            if !vals.is_empty() {
                p.digests = vals;
            }
        }
        if let Some(paddings) = ctx.get("padding").and_then(Value::as_array) {
            let vals: Vec<i64> = paddings.iter().filter_map(Value::as_i64).collect();
            if !vals.is_empty() {
                p.paddings = vals;
            }
        }
        if let Some(v) = ctx.get("os_version").and_then(Value::as_i64) {
            p.os_version = Some(v);
        }
        if let Some(v) = ctx.get("os_patch_level").and_then(Value::as_i64) {
            p.os_patch_level = Some(v);
        }
        // KeyMint 3.0+ per-partition patch levels (tags 707/708) and the RSA
        // OAEP MGF digest (tag 203) — emitted when the caller supplies them.
        if let Some(v) = ctx.get("vendor_patch_level").and_then(Value::as_i64) {
            p.vendor_patch_level = Some(v);
        }
        if let Some(v) = ctx.get("boot_patch_level").and_then(Value::as_i64) {
            p.boot_patch_level = Some(v);
        }
        // mgf_digest arrives as a single KeyMint int from the A-side (raw tag
        // value) but may arrive as an array from Django-style callers; accept
        // both so serverbox matches the B-side path (which uses get_i64).
        let mgf_vals: Vec<i64> = match ctx.get("mgf_digest") {
            Some(Value::Array(arr)) => arr.iter().filter_map(Value::as_i64).collect(),
            Some(other) => other.as_i64().map(|n| vec![n]).unwrap_or_default(),
            None => Vec::new(),
        };
        if !mgf_vals.is_empty() {
            p.mgf_digest = mgf_vals;
        }
        // certificate_serial: honour the caller-requested leaf serial (base64
        // big-endian bytes; AOSP convention is 1). Oversized serials are
        // ignored so we keep the safe default.
        if let Some(bytes) = ctx
            .get("certificate_serial")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .filter(|b| !b.is_empty())
        {
            let mut trimmed = bytes.as_slice();
            while trimmed.len() > 1 && trimmed[0] == 0 {
                trimmed = &trimmed[1..];
            }
            if trimmed.len() <= 8 {
                let mut v: i64 = 0;
                for &b in trimmed {
                    v = (v << 8) | b as i64;
                }
                if v > 0 {
                    p.serial = v;
                }
            }
        }
        // rsa_public_exponent: honour the caller's requested exponent.
        if let Some(v) = ctx.get("rsa_public_exponent").and_then(Value::as_i64) {
            if v > 0 {
                p.rsa_public_exponent = Some(v);
            }
        }
        // certificate_subject: caller-requested leaf subject (DER Name, base64).
        if let Some(v) = ctx
            .get("certificate_subject")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .filter(|b| !b.is_empty())
        {
            p.subject_name = Some(v);
        }
        // certificate_not_before_ms / certificate_not_after_ms: leaf validity.
        if let Some(v) = ctx.get("certificate_not_before_ms").and_then(Value::as_u64) {
            if v > 0 {
                p.not_before_ms = Some(v);
            }
        }
        if let Some(v) = ctx.get("certificate_not_after_ms").and_then(Value::as_u64) {
            if v > 0 {
                p.not_after_ms = Some(v);
            }
        }
        p.app_id = b64("attestation_application_id");
        // creation_datetime_ms: from context or default to current time (matches Django)
        p.creation_datetime_ms = ctx
            .get("creation_datetime_ms")
            .and_then(Value::as_u64)
            .unwrap_or_else(|| Utc::now().timestamp_millis() as u64);

        // Attestation version / security level
        let att_sl = ctx
            .get("attestation_security_level")
            .and_then(Value::as_i64)
            .unwrap_or(1);
        p.security_level = att_sl;
        // Use device-provided versions if available; otherwise infer from the
        // A-side's `os_version` (Android major * 10000). A chain whose
        // attest_key (minted here) and sign_key (minted by the A-side software
        // KeyMint) disagree on attestationVersion is flagged as a tampered
        // attestation key, so the minted attest_key must carry the SAME KeyMint
        // version the A-side reports for its local HAL. The old Django heuristic
        // (200 for att_sl < 2) triggers VINTF mismatch on KeyMint 3.0+ devices.
        let inferred_version = ctx
            .get("os_version")
            .and_then(Value::as_i64)
            .map(|osv| match osv / 10000 {
                v if v >= 17 => 500,
                16 => 400,
                14 | 15 => 300,
                13 => 300,
                12 => 200,
                _ => 100,
            });
        p.attestation_version = ctx
            .get("attest_record_version")
            .and_then(Value::as_i64)
            .or(inferred_version)
            .unwrap_or(300);
        p.keymaster_version = ctx
            .get("keymint_record_version")
            .and_then(Value::as_i64)
            .unwrap_or(p.attestation_version);

        let vb_key = b64("verified_boot_key");
        let vb_hash = b64("verified_boot_hash");
        // Always set RootOfTrust — matches Django's default bytes(32)
        let vb_key = vb_key.map(|mut k| {
            if k.len() != 32 { k.resize(32, 0); }
            k
        }).unwrap_or_else(|| vec![0u8; 32]);
        let vb_hash = vb_hash.map(|mut h| {
            if h.len() != 32 { h.resize(32, 0); }
            h
        }).unwrap_or_else(|| vec![0u8; 32]);
        p.root_of_trust = Some(RootOfTrust {
            verified_boot_key: vb_key,
            device_locked: ctx
                .get("device_locked")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            verified_boot_state: ctx
                .get("verified_boot_state")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            verified_boot_hash: vb_hash,
        });
        p
    }

    /// Generate the leaf + attested chain, cache it in the session.
    fn attest_and_cache(
        &self,
        identity: &DeviceIdentity,
        alias: &str,
        ctx: &Value,
        challenge: &[u8],
    ) -> anyhow::Result<(String, String)> {
        let params = self.parse_ctx(ctx, challenge);
        let (chain_pem, new_leaf_key_pem) = cert::build_attested_chain(identity, &params)?;

        let key_fp = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(new_leaf_key_pem.as_bytes()));
        tracing::info!(
            "attest_and_cache: device={} alias={alias} chain_certs={} leaf_fp={}",
            identity.device_id,
            cert::parse_chain_pem(&chain_pem).map(|d| d.len()).unwrap_or(0),
            key_fp
        );

        self.put_session(
            alias,
            Session {
                chain_pem: chain_pem.clone(),
                leaf_key_pem: new_leaf_key_pem,
                created_epoch_ms: Utc::now().timestamp_millis() as u64,
            },
        );
        Ok((chain_pem, key_fp))
    }

    fn chain_as_b64(chain_pem: &str) -> Vec<String> {
        cert::parse_chain_pem(chain_pem)
            .unwrap_or_default()
            .iter()
            .map(|der| base64::engine::general_purpose::STANDARD.encode(der))
            .collect()
    }

    /// Generate (and cache per device+algorithm) a server self-signed identity.
    /// Used as the extreme-case layer-3 fallback when neither a B device nor a
    /// stored identity can fulfil a request.
    fn self_signed_for(&self, device_id: &str, algorithm: &str) -> Option<DeviceIdentity> {
        let key = (device_id.to_string(), algorithm.to_string());
        let mut cache = crate::util::mu(&self.self_signed_cache);
        if let Some(id) = cache.get(&key) {
            return Some(id.clone());
        }
        let generated = crate::cert::generate_self_signed(algorithm).ok()?;
        let id = DeviceIdentity {
            device_id: device_id.to_string(),
            algorithm: generated.algorithm,
            certificate_chain_pem: generated.certificate_chain_pem,
            private_key_pem_cipher: generated.private_key_pem,
            active: true,
            machine_id: "self-signed".to_string(),
            created_at: String::new(),
        };
        cache.insert(key, id.clone());
        Some(id)
    }

    // ---- Interceptors ----

    /// Shared attest chain-building given an already-resolved identity. Returns
    /// `Some(result)` on success, `Some(error)` on request/chain failure.
    fn attest_from_identity(
        &self,
        body: &Value,
        identity: &DeviceIdentity,
        source: &str,
    ) -> Option<Value> {
        let alias = body
            .get("alias")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let ctx = body
            .get("device_attest_context")
            .cloned()
            .unwrap_or(Value::Null);
        let challenge = body
            .get("challenge")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
            .unwrap_or_default();
        if challenge.len() > MAX_CHALLENGE_SIZE {
            return Some(json!({
                "error": format!(
                    "challenge too large: {} bytes (max {} bytes per AOSP keymint)",
                    challenge.len(),
                    MAX_CHALLENGE_SIZE
                )
            }));
        }
        match self.attest_and_cache(identity, &alias, &ctx, &challenge) {
            Ok((chain_pem, key_fp)) => {
                let c = Self::chain_as_b64(&chain_pem);
                Some(json!({
                    "cert_chain": c,
                    "leaf_certificate": c.first().cloned().unwrap_or_default(),
                    "key_fingerprint": key_fp,
                    // Distinguishes a chain minted from the device's stored
                    // keybox (`server_keybox`) from one minted by a throwaway
                    // server self-signed identity (`server_self_signed`), and
                    // names the identity that actually signed it — without this
                    // the two are indistinguishable in the response.
                    "source": source,
                    "attested_device_id": identity.device_id,
                }))
            }
            Err(e) => Some(json!({ "error": format!("server_keybox attest failed: {e:#}") })),
        }
    }

    /// Layer-2 (stored identity): fulfil attestation with a stored server
    /// identity only. A missing identity returns an error so the handler falls
    /// through to the next layer.
    ///
    /// NOTE: ATTEST_KEY-purpose attestation is intentionally NOT rejected here.
    /// The A-side stores the returned cert chain as a `KeyMaterial::Remote`
    /// (public key only); when the app later uses that attestation key to sign
    /// a child cert, the A-side forwards the TBS signing back to this relay
    /// (`/api/sign/`), which signs with the session leaf key held here.
    /// Rejecting would break that flow.
    pub fn try_handle_attest(&self, device_id: &str, body: &Value) -> Option<Value> {
        let ctx = body
            .get("device_attest_context")
            .cloned()
            .unwrap_or(Value::Null);
        let algorithm = Self::ctx_algorithm_str(&ctx);
        let identity = match self.identity_for(device_id, &algorithm) {
            Some(id) => id,
            None => {
                return Some(json!({
                    "error": format!(
                        "server_keybox: no stored server identity for device {device_id} (algorithm {algorithm})"
                    )
                }));
            }
        };
        self.attest_from_identity(body, &identity, "server_keybox")
    }

    /// Layer-3 (self-signed): extreme-case fallback that fulfils attestation
    /// with a freshly generated (and cached) server self-signed identity.
    pub fn try_handle_attest_self_signed(&self, device_id: &str, body: &Value) -> Option<Value> {
        let ctx = body
            .get("device_attest_context")
            .cloned()
            .unwrap_or(Value::Null);
        let algorithm = Self::ctx_algorithm_str(&ctx);
        let identity = match self.self_signed_for(device_id, &algorithm) {
            Some(id) => id,
            None => {
                return Some(json!({
                    "error": format!(
                        "server_keybox: self-signed identity generation failed for device {device_id} (algorithm {algorithm})"
                    )
                }));
            }
        };
        self.attest_from_identity(body, &identity, "server_self_signed")
    }

    pub fn try_handle_sign(&self, device_id: &str, body: &Value) -> Option<Value> {
        let alias = body
            .get("alias")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let Some(s) = self.get_session(&alias) else {
            tracing::warn!(
                "try_handle_sign: no session for device={device_id} alias={alias} sessions=({:?})",
                self.inner.lock().map(|g| {
                    let keys: Vec<String> = g.sessions.keys().cloned().collect();
                    keys.join(",")
                }).unwrap_or_default()
            );
            // Fail fast with a clear error instead of falling through to the
            // A/B queue, which would wait up to the queue timeout for a B
            // device that can never sign for this orphaned session. The app's
            // "use attestation key" flow then surfaces an explicit failure
            // instead of spinning.
            return Some(json!({
                "error": format!(
                    "no server_keybox session for alias {alias}; re-attest the key to (re)create a session"
                )
            }));
        };
        // Debug: log which session leaf key is signing this request.
        tracing::info!(
            "try_handle_sign: device={device_id} alias={alias} leaf_fp={}",
            sha2::Sha256::digest(s.leaf_key_pem.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .take(8)
                .collect::<String>()
        );
        // The A-side sends the bytes to sign in `data` (base64).
        let data = body
            .get("data")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())?;
        let key = parse_leaf_key(&s.leaf_key_pem).ok()?;
        let sig = sign_data(&key, &data).ok()?;
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        // A-side reads `signature` first, then falls back to `data`; the B-side
        // returns `data`. Emit both so either consumer is satisfied.
        Some(json!({
            "signature": sig_b64,
            "data": sig_b64,
            "source": "server_keybox",
        }))
    }

    pub fn try_handle_decrypt(&self, _device_id: &str, body: &Value) -> Option<Value> {
        let alias = body
            .get("alias")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let s = self.get_session(&alias)?;
        let data = body
            .get("data")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())?;
        let key = parse_leaf_key(&s.leaf_key_pem).ok()?;
        let plain = decrypt_data(&key, &data).ok()?;
        let plain_b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        // A-side reads `data` for decrypt (same field the B-side returns).
        Some(json!({
            "data": plain_b64,
            "source": "server_keybox",
        }))
    }

    pub fn try_handle_b_upload_keybox_identity(
        &self,
        device_id: &str,
        body: &Value,
    ) -> Option<Value> {
        if !self.is_enabled() {
            return None;
        }
        let db = self.db.as_ref()?;
        let mut algorithm = body
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or("ec")
            .to_string();
        let mut chain_pem = body
            .get("certificate_chain_pem")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let mut key_pem = body
            .get("private_key_pem")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let machine_id = body
            .get("machine_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        // Support raw keybox.xml upload: extract the first usable key pair when
        // PEM fields were not supplied (mirrors Django's b_upload_keybox_identity).
        let keybox_xml = body
            .get("keybox_xml")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if !keybox_xml.is_empty() && (key_pem.is_empty() || chain_pem.is_empty()) {
            let keyboxes = match crate::keybox::parse_keybox_xml_all(&keybox_xml) {
                Ok(kb) => kb,
                Err(e) => {
                    return Some(json!({
                        "error": format!("keybox.xml parse failed: {e}")
                    }));
                }
            };
            // Prefer an EC key (attestation), else the first usable key.
            let chosen = match keyboxes
                .iter()
                .find(|k| k.algorithm == "ec")
                .or_else(|| keyboxes.first())
            {
                Some(k) => k,
                None => {
                    return Some(json!({
                        "error": "keybox.xml contained no usable <Key> entries"
                    }));
                }
            };
            key_pem = chosen.private_key_pem.clone();
            chain_pem = chosen.certificate_chain_pem.clone();
            algorithm = chosen.algorithm.clone();
        }

        if key_pem.is_empty() || chain_pem.is_empty() {
            return Some(json!({
                "error": "missing private_key_pem/certificate_chain_pem (or keybox_xml)"
            }));
        }

        // Validate the private key parses and matches the chain before storing
        // (mirrors Django's `_validate_identity_pem`), so a mismatched PEM
        // cannot produce a leaf whose signature fails to verify.
        if let Some(err) = cert::validate_identity_pem(&key_pem, &chain_pem) {
            return Some(json!({ "error": err }));
        }

        let id = DeviceIdentity {
            device_id: device_id.to_string(),
            algorithm,
            certificate_chain_pem: chain_pem,
            private_key_pem_cipher: key_pem,
            active: true,
            machine_id,
            created_at: Utc::now().to_rfc3339(),
        };
        match db.upsert_device_identity(&id) {
            Ok(()) => Some(json!({ "status": "ok" })),
            Err(e) => Some(json!({ "error": format!("db error: {e}") })),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure-Rust key helpers (EC P-256 / RSA)
// ---------------------------------------------------------------------------

enum LeafKey {
    Ec(cert::EcKey),
    Rsa(RsaPrivateKey),
}

fn parse_leaf_key(pem_data: &str) -> anyhow::Result<LeafKey> {
    // Reuse cert::parse_private_key so P-256/P-384/P-521 and RSA (PKCS#1/PKCS#8)
    // are all handled identically to the stored server identities.
    match cert::parse_private_key(pem_data.as_bytes())? {
        cert::KeyMaterial::Ec(ec) => Ok(LeafKey::Ec(ec)),
        cert::KeyMaterial::Rsa(rk) => Ok(LeafKey::Rsa(rk)),
    }
}

fn sign_data(key: &LeafKey, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    match key {
        LeafKey::Ec(cert::EcKey::P256(sk)) => {
            let signing_key = p256::ecdsa::SigningKey::from(sk);
            let sig: P256Signature = signing_key.sign(data);
            let der_sig = P256DerSignature::from(sig);
            Ok(der_sig.as_bytes().to_vec())
        }
        LeafKey::Ec(cert::EcKey::P384(sk)) => {
            let signing_key =
                p384::ecdsa::SigningKey::from(ecdsa::SigningKey::from(sk));
            let sig: P384Signature = signing_key.sign(data);
            let der_sig = P384DerSignature::from(sig);
            Ok(der_sig.as_bytes().to_vec())
        }
        LeafKey::Ec(cert::EcKey::P521(sk)) => {
            let signing_key =
                p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(sk));
            let sig: P521Signature = signing_key.sign(data);
            let der_sig = P521DerSignature::from(sig);
            Ok(der_sig.as_bytes().to_vec())
        }
        LeafKey::Rsa(rk) => {
            let signing_key = RsaSigningKey::<Sha256>::new(rk.clone());
            Ok(signing_key.sign(data).to_vec())
        }
    }
}

fn decrypt_data(key: &LeafKey, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    match key {
        LeafKey::Rsa(rk) => {
            // Try SHA-256 MGF1 first (standard OAEP).
            let decrypting_sha256 = rsa::oaep::DecryptingKey::<Sha256>::new(rk.clone());
            if let Ok(out) = decrypting_sha256.decrypt(data) {
                return Ok(out);
            }
            // Try SHA-1 MGF1 (matches Java's OAEPWithSHA-256AndMGF1Padding).
            let decrypting_sha1 =
                rsa::oaep::DecryptingKey::<Sha256, Sha1>::new(rk.clone());
            decrypting_sha1
                .decrypt(data)
                .map_err(|e| anyhow::anyhow!("rsa oaep decrypt failed (SHA-256 + SHA-1 MGF1): {e}"))
        }
        _ => anyhow::bail!("decrypt requires RSA key"),
    }
}
