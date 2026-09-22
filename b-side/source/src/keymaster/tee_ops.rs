//! Real hardware TEE operation proxy (the "everything a normal TEE does" layer).
//!
//! Building on top of [`super::attest_proxy`], this module exposes the full set
//! of TEE operations that the relay daemon needs in order to act as a drop-in
//! replacement for the old `client-b` agent:
//!
//!   * generate an attestation/signing key (with an A-side supplied appid / 709)
//!   * derive a signing key attested by an attestation key
//!   * fetch the certificate chain / public key of a previously generated key
//!   * sign data / sign a to-be-signed (TBS) blob / sign a challenge
//!   * decrypt data
//!
//! Every operation is executed by the *real* on-device hardware keymint (TEE)
//! through `get_system_keymint` + `begin`/`update`/`finish`, so the produced
//! signatures, decryptions and certificate chains are genuine TEE outputs.
//!
//! Key blobs and certificate chains are held in a process-local session table
//! keyed by alias (mirroring the behaviour of the legacy client-b agent, which
//! also keeps sessions in memory).

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use kmr_wire::{
    keymint::{
        Algorithm as KmAlgorithm, DateTime, Digest as KmDigest, EcCurve as KmEcCurve, KeyParam,
        KeyPurpose as KmKeyPurpose, PaddingMode as KmPadding,
    },
    KeySizeInBits, RsaExponent,
};

/// Certificate validity bound (now). Real TEEs require NOT_BEFORE/NOT_AFTER
/// when minting an attestation key, otherwise generateKey fails with
/// MISSING_NOT_BEFORE (ErrorCode -80).
fn now_date_time() -> DateTime {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    DateTime { ms_since_epoch: now }
}

/// Certificate validity bound (now + ~10 years).
fn after_date_time() -> DateTime {
    const TEN_YEARS_MS: i64 = 10 * 365 * 24 * 3600 * 1000;
    DateTime {
        ms_since_epoch: now_date_time().ms_since_epoch + TEN_YEARS_MS,
    }
}

use crate::android::hardware::security::keymint::{
    KeyPurpose::KeyPurpose,
};
use crate::android::hardware::security::keymint::KeyParameter::KeyParameter as KmKeyParameter;
use crate::err as ks_err;
use crate::keymaster::relay_tee::{
    clear_system_keymint, extract_km_error_code, get_system_keymint,
    key_params_to_aidl, probe_keymint_version, KEY_MINT_V5,
};

use super::attest_proxy::{SYSTEM_KEYMINT_DEFAULT, SYSTEM_KEYMINT_STRONGBOX};

/// How a generated key is meant to be used.  Mirrors the `KeyPurpose`s the
/// legacy agent used. Only distinguishes EC vs RSA (used for begin()-parameter
/// construction); the actual size/curve is carried in [`KeySpec`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyAlgorithm {
    #[default]
    EcP256,
    Rsa2048,
}

/// Key parameters requested by the A-side app, forwarded from the A-side
/// KeyMint params. The real TEE mints a key matching these instead of a fixed
/// default. Absent fields fall back to the legacy defaults (EC P-256, SHA-256,
/// etc.).
#[derive(Clone, Debug, Default)]
pub struct KeySpec {
    /// EC vs RSA key family (also drives later begin() parameter construction).
    pub algorithm: KeyAlgorithm,
    /// EC curve; defaults to P256.
    pub ec_curve: Option<KmEcCurve>,
    /// Key size in bits; defaults to 256 (EC) / 2048 (RSA).
    pub key_size: Option<u32>,
    /// Requested purposes. For business keys `Sign` (and `Decrypt` for RSA) is
    /// added so the relay's own sign/decrypt operations stay authorized; for an
    /// App Attest Key (`PURPOSE_ATTEST_KEY`) the purpose is forwarded unchanged.
    pub purposes: Vec<KmKeyPurpose>,
    /// Requested digests. `Sha256` is always added (the relay signs with it).
    pub digests: Vec<KmDigest>,
    /// Requested MGF1 digest (RSA-OAEP), when the app specified one.
    pub mgf_digest: Option<KmDigest>,
    /// Requested paddings (RSA only). The relay's operation paddings are added.
    pub paddings: Vec<KmPadding>,
    /// RSA public exponent; defaults to 65537.
    pub rsa_public_exponent: Option<u64>,
    /// Certificate subject (DER-encoded X500Name); optional.
    pub cert_subject_der: Option<Vec<u8>>,
    /// Certificate validity bounds; default to now / now+10y.
    pub cert_not_before: Option<DateTime>,
    pub cert_not_after: Option<DateTime>,
    /// Certificate serial (A-side CERTIFICATE_SERIAL tag); optional.
    pub cert_serial: Option<Vec<u8>>,
}

/// A single generated key, held for the lifetime of the relay process.
#[derive(Clone, Debug)]
pub struct TeeSession {
    pub key_blob: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
    pub algorithm: KeyAlgorithm,
    /// Which KeyMint HAL service minted this key (`SYSTEM_KEYMINT_DEFAULT`
    /// for TEE, `SYSTEM_KEYMINT_STRONGBOX` for StrongBox).  Sign/decrypt
    /// operations must drive the *same* HAL or the key blob is rejected with
    /// `INVALID_KEY_BLOB` — StrongBox blobs are not usable in the TEE and
    /// vice versa.
    pub hal_service: &'static str,
}

/// Session persistence directory.  Key blobs minted by the real TEE are
/// self-contained and remain usable after a relay restart (begin/finish works
/// on the persisted blob), so we persist every generated session here to keep
/// the A-side `isRemote` keys usable across relay restarts.
fn sessions_dir() -> PathBuf {
    PathBuf::from("/data/adb/ommega/sessions")
}

/// Session files 原本只进不出：A 端每要一个新 key（新 alias）就落一个文件，
/// 长期在线的设备会一直堆 —— 真机上到过 19967 个 / 162 MB，启动全量加载要
/// 12 秒。两个上限把它压住：超过 TTL 的删，超过数量上限的从最旧的开始删。
const SESSION_TTL_SECS: u64 = 7 * 24 * 3600;
const SESSION_MAX_FILES: usize = 2000;
/// 每这么多次保存做一轮清理（启动时另有一轮，见 `load_all_sessions`）。
const SESSION_PRUNE_EVERY: usize = 200;

/// 清理会话文件：先按 mtime 从旧到新排序，超 TTL 的或超出数量上限的都删掉，
/// 于是留下来的总是最新的那一批。全程 best-effort —— 删不掉就当没发生过，
/// 最坏结果只是这一轮没清成，不影响任何正在用的会话（它们在内存里）。
fn prune_sessions() {
    let Ok(entries) = std::fs::read_dir(sessions_dir()) else {
        return;
    };
    let mut files: Vec<(PathBuf, SystemTime)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(UNIX_EPOCH);
        files.push((path, mtime));
    }
    let total = files.len();
    if total == 0 {
        return;
    }
    files.sort_by_key(|(_, t)| *t);
    let now = SystemTime::now();
    let mut removed = 0usize;
    for (i, (path, mtime)) in files.iter().enumerate() {
        let expired = now
            .duration_since(*mtime)
            .map(|d| d.as_secs() > SESSION_TTL_SECS)
            .unwrap_or(false);
        // 排序后下标 i 之前都是更旧的，剩下 total - i 个（含自己）。
        let over_cap = total - i > SESSION_MAX_FILES;
        if (expired || over_cap) && std::fs::remove_file(path).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        log::info!(
            "pruned {removed} session file(s), kept {} of {total}",
            total - removed
        );
    }
}

/// Alias -> safe file stem.  Aliases can contain arbitrary UTF-8, so we keep
/// the printable prefix and append a short hash to guarantee uniqueness.
fn session_stem(alias: &str) -> String {
    let mut hasher = DefaultHasher::new();
    alias.hash(&mut hasher);
    let digest = hasher.finish();
    let safe: String = alias
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    format!("{safe}_{digest:016x}")
}

fn session_path(alias: &str) -> PathBuf {
    sessions_dir().join(format!("{}.json", session_stem(alias)))
}

fn load_session_from_disk(alias: &str) -> Option<TeeSession> {
    let path = session_path(alias);
    let data = std::fs::read_to_string(&path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&data).ok()?;
    let key_blob_b64 = value.get("key_blob")?.as_str()?;
    let key_blob = B64.decode(key_blob_b64).ok()?;
    let cert_chain = value
        .get("cert_chain")?
        .as_array()?
        .iter()
        .map(|c| B64.decode(c.as_str()?).ok())
        .collect::<Option<Vec<Vec<u8>>>>()?;
    let algorithm = match value.get("algorithm")?.as_str()? {
        "EcP256" => KeyAlgorithm::EcP256,
        "Rsa2048" => KeyAlgorithm::Rsa2048,
        _ => return None,
    };
    // `hal_service` was added later; old sessions without this field default
    // to the TEE HAL (the only service that existed at the time).
    let hal_service = match value.get("hal_service").and_then(|v| v.as_str()) {
        Some("strongbox") => SYSTEM_KEYMINT_STRONGBOX,
        _ => SYSTEM_KEYMINT_DEFAULT,
    };
    Some(TeeSession {
        key_blob,
        cert_chain,
        algorithm,
        hal_service,
    })
}

fn save_session_to_disk(alias: &str, session: &TeeSession) {
    let path = session_path(alias);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let algorithm = match session.algorithm {
        KeyAlgorithm::EcP256 => "EcP256",
        KeyAlgorithm::Rsa2048 => "Rsa2048",
    };
    let hal_service_label = if session.hal_service == SYSTEM_KEYMINT_STRONGBOX {
        "strongbox"
    } else {
        "tee"
    };
    let value = serde_json::json!({
        "alias": alias,
        "key_blob": B64.encode(&session.key_blob),
        "cert_chain": session.cert_chain.iter().map(|c| B64.encode(c)).collect::<Vec<_>>(),
        "algorithm": algorithm,
        "hal_service": hal_service_label,
    });
    let _ = std::fs::write(&path, serde_json::to_string(&value).unwrap_or_default());
    // 运行时也要收着点：每 SESSION_PRUNE_EVERY 次保存清一轮，否则一个长期
    // 在线的设备还是会一直堆下去。
    static SAVES: AtomicUsize = AtomicUsize::new(0);
    if SAVES.fetch_add(1, Ordering::Relaxed) % SESSION_PRUNE_EVERY == SESSION_PRUNE_EVERY - 1 {
        prune_sessions();
    }
}

fn sessions() -> &'static Mutex<HashMap<String, TeeSession>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, TeeSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn session_put(alias: &str, session: TeeSession) {
    save_session_to_disk(alias, &session);
    sessions().lock().unwrap().insert(alias.to_string(), session);
}

fn session_get(alias: &str) -> Result<TeeSession> {
    {
        let sessions = sessions().lock().unwrap();
        if let Some(session) = sessions.get(alias) {
            return Ok(session.clone());
        }
    }
    // Miss: try to recover from disk (e.g. after a relay restart).  The TEE key
    // blob is persisted, so the recovered session can still sign/decrypt.
    if let Some(session) = load_session_from_disk(alias) {
        sessions()
            .lock()
            .unwrap()
            .insert(alias.to_string(), session.clone());
        log::info!("recovered persisted session for alias '{alias}'");
        return Ok(session);
    }
    Err(anyhow!("no key for alias '{alias}' (call attest first)"))
}

/// Loads every persisted session into memory.  Called once at startup so that
/// an alias generated before a relay restart is immediately usable.
pub fn load_all_sessions() {
    // 先清一轮再加载：“只增不减”就是在这一步收住的，顺带把启动耗时压下来。
    prune_sessions();
    let Some(entries) = std::fs::read_dir(sessions_dir()).ok() else {
        return;
    };
    let mut loaded = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") {
            continue;
        }
        // Recover the alias by scanning the file's JSON (we cannot reverse the
        // filename hash); read each file and store by its alias key.
        let Ok(data) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&data) else {
            continue;
        };
        let Some(alias) = value.get("alias").and_then(|a| a.as_str()) else {
            continue;
        };
        let key_blob_b64 = value.get("key_blob").and_then(|v| v.as_str());
        let Some(key_blob) = key_blob_b64.and_then(|s| B64.decode(s).ok()) else {
            continue;
        };
        let cert_chain = value
            .get("cert_chain")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| c.as_str().and_then(|s| B64.decode(s).ok()))
                    .collect::<Vec<Vec<u8>>>()
            })
            .unwrap_or_default();
        let algorithm = match value.get("algorithm").and_then(|v| v.as_str()) {
            Some("Rsa2048") => KeyAlgorithm::Rsa2048,
            _ => KeyAlgorithm::EcP256,
        };
        let hal_service = match value.get("hal_service").and_then(|v| v.as_str()) {
            Some("strongbox") => SYSTEM_KEYMINT_STRONGBOX,
            _ => SYSTEM_KEYMINT_DEFAULT,
        };
        sessions().lock().unwrap().insert(
            alias.to_string(),
            TeeSession {
                key_blob,
                cert_chain,
                algorithm,
                hal_service,
            },
        );
        loaded += 1;
    }
    if loaded > 0 {
        log::info!("loaded {loaded} persisted TEE sessions");
    }
}

// ---------------------------------------------------------------------------
// Key generation.
// ---------------------------------------------------------------------------

/// Generates a fresh key with the *real* TEE, embedding the A-side requested
/// `AttestationApplicationId` (tag 709) in the attestation extension of the
/// returned certificate chain. The key is minted to match the A-side requested
/// [`KeySpec`] (size/curve/purpose/digest/padding/subject/validity/serial).
pub fn generate_attest_key(
    alias: &str,
    challenge: &[u8],
    app_id_der: &[u8],
    spec: &KeySpec,
) -> Result<TeeSession> {
    generate_attest_key_on(SYSTEM_KEYMINT_DEFAULT, alias, challenge, app_id_der, spec)
}

/// Same as [`generate_attest_key`] but drives a caller-chosen real KeyMint HAL
/// service. Used to mint a StrongBox attestation via the B-side device's real
/// `/strongbox` HAL when the A-side requested `security_level=StrongBox`.
pub fn generate_attest_key_on(
    service: &'static str,
    alias: &str,
    challenge: &[u8],
    app_id_der: &[u8],
    spec: &KeySpec,
) -> Result<TeeSession> {
    let keymint = get_system_keymint(service)
        .with_context(|| ks_err!("real keymint {service} connect failed"))?;
    // Probe the actual HAL version instead of assuming V5. A StrongBox HAL
    // may only implement KeyMint V2/V3; sending V5-encoded parameters can
    // cause version-mismatch errors that look like "not supported".
    let km_version = probe_keymint_version(&keymint);
    let params = build_attestation_params(app_id_der, challenge, spec, km_version)?;

    let result = match keymint.generateKey(&params, None) {
        Ok(result) => result,
        Err(status) => {
            if is_dead_object_status(&status) {
                clear_system_keymint(service);
            }
            // Extract the KeyMint ErrorCode (e.g., -74, -68) so the caller
            // can distinguish "HAL not provisioned" from "parameter rejected".
            let km_code = km_error_suffix(&status);
            return Err(anyhow!(
                "real keymint {service} generateKey failed {km_code}: {status}"
            ));
        }
    };

    let cert_chain: Vec<Vec<u8>> = result
        .certificateChain
        .into_iter()
        .map(|cert| cert.encodedCertificate)
        .collect();

    // A HAL that reports generateKey() *success* together with an empty
    // certificate chain must not be forwarded as a successful attestation:
    // sending `cert_chain: []` means the operator cannot tell which side dropped
    // the chain, and the empty session would also be persisted to
    // /data/adb/ommega/sessions. Fail loudly instead: the relay server treats an
    // error exactly like an empty chain (next layer / StrongBox demotion), so
    // behaviour is unchanged.
    if cert_chain.is_empty() {
        return Err(anyhow!(
            "real keymint {service} returned an empty certificate chain \
             (key_blob {}B) — generateKey was accepted but the key was not attested",
            result.keyBlob.len()
        ));
    }

    let session = TeeSession {
        key_blob: result.keyBlob,
        cert_chain,
        algorithm: spec.algorithm,
        hal_service: service,
    };
    session_put(alias, session.clone());
    Ok(session)
}

fn build_attestation_params(
    app_id_der: &[u8],
    challenge: &[u8],
    spec: &KeySpec,
    km_version: i32,
) -> Result<Vec<KmKeyParameter>> {
    let (algo, default_size) = match spec.algorithm {
        KeyAlgorithm::EcP256 => (KmAlgorithm::Ec, 256u32),
        KeyAlgorithm::Rsa2048 => (KmAlgorithm::Rsa, 2048u32),
    };
    let key_size = spec.key_size.unwrap_or(default_size);
    let mut params = vec![
        KeyParam::Algorithm(algo),
        KeyParam::KeySize(KeySizeInBits(key_size)),
        KeyParam::AttestationChallenge(challenge.to_vec()),
        KeyParam::AttestationApplicationId(app_id_der.to_vec()),
    ];

    // Purpose set: forward the app's requested purposes, but never ask the
    // real TEE to mint a key whose purpose is ATTEST_KEY — this qti TEE
    // rejects ATTEST_KEY-purpose key generation with ServiceSpecific(-3).
    // The A-side's "use attestation key" flow (Approach 2) only forwards the
    // child-cert TBS for a plain begin(SIGN), so an attestation key is minted
    // as a plain SIGNING key. The A-side's Remote keyblob carries the app's
    // requested ATTEST_KEY purpose, so keystore-side purpose checks still
    // pass. For business keys we add the purposes the relay itself needs for
    // its begin()/sign()/decrypt() calls (real keymint supports multiple
    // purposes on one key).
    let mut purposes = spec.purposes.clone();
    let is_attest_key = purposes.contains(&KmKeyPurpose::AttestKey);
    if is_attest_key {
        purposes.retain(|p| *p != KmKeyPurpose::AttestKey);
    }
    if !purposes.contains(&KmKeyPurpose::Sign) {
        purposes.push(KmKeyPurpose::Sign);
    }
    if algo == KmAlgorithm::Rsa && !purposes.contains(&KmKeyPurpose::Decrypt) {
        purposes.push(KmKeyPurpose::Decrypt);
    }
    for p in purposes {
        params.push(KeyParam::Purpose(p));
    }

    // Digest set: the app's requested digests plus SHA-256 (the relay always
    // signs with it). begin() later requests one of these.
    let mut digests = spec.digests.clone();
    if !digests.contains(&KmDigest::Sha256) {
        digests.push(KmDigest::Sha256);
    }
    for d in digests {
        params.push(KeyParam::Digest(d));
    }

    // Remote-proxy model: the B-side signs on behalf of the A-side, but the
    // A-side's auth token cannot reach the B-side real TEE.  Without
    // NO_AUTH_REQUIRED the TEE mints a user-auth-gated key and every relay
    // begin(SIGN) fails with KEY_USER_NOT_AUTHENTICATED (-26).  The relay
    // always signs without a token, so the key must be usable without auth.
    params.push(KeyParam::NoAuthRequired);

    match algo {
        KmAlgorithm::Rsa => {
            // Real keymint requires RSA_PUBLIC_EXPONENT on every RSA key;
            // without it generateKey fails with INVALID_ARGUMENT.
            params.push(KeyParam::RsaPublicExponent(RsaExponent(
                spec.rsa_public_exponent.unwrap_or(65537),
            )));
            // Padding set: only the app's requested paddings. We used to force
            // all four RSA paddings (PKCS1Sign/PSS/PKCS1Encrypt/OAEP) so the
            // relay's own operations could always begin(), but that also lets
            // *unauthorized* uses succeed, which a probe like DuckDetector's
            // "RSA-PSS key must reject PKCS1 sign" rejects. The relay's begin
            // padding always matches the app's (it derives from the A-side
            // algorithm string, which derives from the app's begin params), so
            // only the requested paddings are needed.
            for p in spec.paddings.iter() {
                params.push(KeyParam::Padding(*p));
            }
            // An attestation key signs the child-cert TBS with PKCS1v15
            // (SHA256withRSA); ensure that padding is authorized too, even when
            // the app only requested ATTEST_KEY use.
            if is_attest_key && !spec.paddings.contains(&KmPadding::RsaPkcs115Sign) {
                params.push(KeyParam::Padding(KmPadding::RsaPkcs115Sign));
            }
            // MGF1 digest for RSA-OAEP. Always push an explicit MGF1 digest so
            // the TEE's key authorization carries the tag. begin(DECRYPT)
            // always sends RsaOaepMgfDigest (see decrypt_begin_params; SHA1 is
            // the default when the app didn't set one). If the authorization
            // omits the tag, the real TEE rejects the operation with
            // INCOMPATIBLE_MGF_DIGEST (-78), whereas a local software keymint
            // would never check it.
            if spec.paddings.contains(&KmPadding::RsaOaep) {
                let mgf = spec.mgf_digest.unwrap_or(KmDigest::Sha1);
                params.push(KeyParam::RsaOaepMgfDigest(mgf));
            }
        }
        KmAlgorithm::Ec => {
            // The real TEE requires an explicit curve for EC keys; without it
            // generateKey fails with UNSUPPORTED_KEY_SIZE (ErrorCode -6).
            params.push(KeyParam::EcCurve(
                spec.ec_curve.unwrap_or(KmEcCurve::P256),
            ));
        }
        _ => {}
    }

    // Certificate validity bounds (app-specified or default now / now+10y);
    // real TEEs require NOT_BEFORE/NOT_AFTER (else MISSING_NOT_BEFORE -80).
    params.push(KeyParam::CertificateNotBefore(
        spec.cert_not_before.unwrap_or_else(now_date_time),
    ));
    params.push(KeyParam::CertificateNotAfter(
        spec.cert_not_after.unwrap_or_else(after_date_time),
    ));

    // Certificate subject (DER X500Name), when the app requested one.
    if let Some(subject) = &spec.cert_subject_der {
        params.push(KeyParam::CertificateSubject(subject.clone()));
    }
    // A-side requested certificate serial (CERTIFICATE_SERIAL tag). When
    // absent the TEE mints a random 16-byte serial (looks like garbage to
    // the A-side); passing it through makes the leaf serial deterministic.
    if let Some(serial) = &spec.cert_serial {
        params.push(KeyParam::CertificateSerial(serial.clone()));
    }
    key_params_to_aidl(&params, km_version)
        .with_context(|| ks_err!("encode real TEE attestation parameters"))
}

// ---------------------------------------------------------------------------
// Read-only helpers.
// ---------------------------------------------------------------------------

/// Returns the certificate chain (DER) for `alias`, leaf first.
pub fn get_cert_chain(alias: &str) -> Result<Vec<Vec<u8>>> {
    Ok(session_get(alias)?.cert_chain)
}

/// Returns the SubjectPublicKeyInfo (SPKI, DER) of the leaf certificate.
pub fn get_public_key(alias: &str) -> Result<Vec<u8>> {
    let session = session_get(alias)?;
    let leaf = session
        .cert_chain
        .first()
        .ok_or_else(|| anyhow!("certificate chain empty for '{alias}'"))?;
    spki_from_cert_der(leaf)
}

// ---------------------------------------------------------------------------
// Sign / decrypt operations (real TEE begin/update/finish).
// ---------------------------------------------------------------------------

/// Signs `data` with the TEE key for `alias`.
pub fn sign(alias: &str, data: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    let session = session_get(alias)?;
    let op_params = sign_begin_params(algorithm, session.algorithm)
        .with_context(|| ks_err!("unsupported sign algorithm {algorithm}"))?;
    run_single_input_op(&session.key_blob, session.hal_service, KeyPurpose::SIGN, &op_params, data)
}

/// Decrypts `data` with the TEE key for `alias`.
pub fn decrypt(alias: &str, data: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    let session = session_get(alias)?;
    let op_params = decrypt_begin_params(algorithm, session.algorithm)
        .with_context(|| ks_err!("unsupported decrypt algorithm {algorithm}"))?;
    run_single_input_op(&session.key_blob, session.hal_service, KeyPurpose::DECRYPT, &op_params, data)
}

/// Formats a KeyMint service-specific error code as a `[km_error=CODE]`
/// suffix when the status carries one, so failures distinguish e.g.
/// INVALID_KEY_BLOB from KEY_USER_NOT_AUTHENTICATED instead of showing a
/// generic binder error.
fn km_error_suffix(status: &rsbinder::Status) -> String {
    extract_km_error_code(status)
        .map(|c| format!("[km_error={c}]"))
        .unwrap_or_default()
}

fn run_single_input_op(
    key_blob: &[u8],
    hal_service: &'static str,
    purpose: KeyPurpose,
    op_params: &[KmKeyParameter],
    input: &[u8],
) -> Result<Vec<u8>> {
    let keymint = get_system_keymint(hal_service)
        .with_context(|| ks_err!("real keymint {hal_service} connect failed"))?;

    let begin = match keymint.begin(purpose, key_blob, op_params, None) {
        Ok(result) => result,
        Err(status) => {
            if is_dead_object_status(&status) {
                clear_system_keymint(hal_service);
            }
            let km_code = km_error_suffix(&status);
            return Err(anyhow!("real keymint {hal_service} begin failed {km_code}: {status}"));
        }
    };

    let Some(operation) = begin.operation else {
        return Err(anyhow!("real keymint {hal_service} begin returned no operation"));
    };

    // Feed the whole payload in a single update, then finish. update() may
    // return output early (e.g. a single-block RSA decrypt can deliver the
    // plaintext from update); finish() then returns whatever is left, so both
    // outputs must be concatenated or the operation's result is silently lost.
    let result = (|| -> Result<Vec<u8>> {
        let mut out = operation
            .update(input, None, None)
            .map_err(|status| {
                let km_code = km_error_suffix(&status);
                anyhow!("real keymint {hal_service} update failed {km_code}: {status}")
            })?;
        out.extend_from_slice(
            &operation
                .finish(None, None, None, None, None)
                .map_err(|status| {
                    let km_code = km_error_suffix(&status);
                    anyhow!("real keymint {hal_service} finish failed {km_code}: {status}")
                })?,
        );
        Ok(out)
    })();

    if result.is_err() {
        let _ = operation.r#abort();
    }
    result
}

// ---------------------------------------------------------------------------
// Begin-parameter builders.
// ---------------------------------------------------------------------------

fn sign_begin_params(algorithm: &str, key_algorithm: KeyAlgorithm) -> Result<Vec<KmKeyParameter>> {
    let digest = digest_for_algorithm(algorithm)?;
    let params = match key_algorithm {
        KeyAlgorithm::EcP256 => vec![KeyParam::Digest(digest)],
        KeyAlgorithm::Rsa2048 => {
            let padding = if algorithm.ends_with("/PSS") || algorithm.contains("PSS") {
                KmPadding::RsaPss
            } else {
                KmPadding::RsaPkcs115Sign
            };
            let mut p = vec![KeyParam::Digest(digest), KeyParam::Padding(padding)];
            if padding == KmPadding::RsaPss {
                // Real TEEs require the MGF digest for PSS; without it
                // begin(SIGN) fails with INCOMPATIBLE_MGF_DIGEST. PSS uses the
                // message digest as its MGF digest.
                p.push(KeyParam::RsaOaepMgfDigest(digest));
            }
            p
        }
    };
    key_params_to_aidl(&params, KEY_MINT_V5)
        .with_context(|| ks_err!("encode sign begin parameters"))
}

fn decrypt_begin_params(
    algorithm: &str,
    key_algorithm: KeyAlgorithm,
) -> Result<Vec<KmKeyParameter>> {
    let params = match key_algorithm {
        KeyAlgorithm::EcP256 => {
            return Err(anyhow!("EC keys cannot be used for decrypt"));
        }
        KeyAlgorithm::Rsa2048 => {
            if algorithm.contains("OAEP") {
                let digest = digest_for_algorithm(algorithm)?;
                let mgf = mgf_digest_for_algorithm(algorithm);
                // OAEP requires both the digest and the MGF digest at
                // begin(DECRYPT); a real TEE fails without them (A-side -1000
                // / empty plaintext), and the MGF digest must match the one the
                // encryptor used (the A-side encodes it as a /MGF1-XXX suffix).
                vec![
                    KeyParam::Padding(KmPadding::RsaOaep),
                    KeyParam::Digest(digest),
                    KeyParam::RsaOaepMgfDigest(mgf),
                ]
            } else {
                vec![KeyParam::Padding(KmPadding::RsaPkcs115Encrypt)]
            }
        }
    };
    key_params_to_aidl(&params, KEY_MINT_V5)
        .with_context(|| ks_err!("encode decrypt begin parameters"))
}

/// Parses the MGF1 digest from an OAEP algorithm string like
/// `RSA/OAEP/SHA-256/MGF1-SHA1`. Defaults to SHA1 (the standard OAEP default
/// when no MGF1 is specified).
fn mgf_digest_for_algorithm(algorithm: &str) -> KmDigest {
    let up = algorithm.to_uppercase();
    if let Some(pos) = up.find("/MGF1-") {
        let rest = &up[pos + 6..];
        if rest.starts_with("SHA256") {
            return KmDigest::Sha256;
        }
        if rest.starts_with("SHA384") {
            return KmDigest::Sha384;
        }
        if rest.starts_with("SHA512") {
            return KmDigest::Sha512;
        }
        // SHA1 or unknown -> SHA1
        return KmDigest::Sha1;
    }
    KmDigest::Sha1
}

fn digest_for_algorithm(algorithm: &str) -> Result<KmDigest> {
    let up = algorithm.to_uppercase();
    if up.contains("SHA256") || up.contains("SHA-256") {
        Ok(KmDigest::Sha256)
    } else if up.contains("SHA1") || up.contains("SHA-1") {
        Ok(KmDigest::Sha1)
    } else if up.contains("SHA384") || up.contains("SHA-384") {
        Ok(KmDigest::Sha384)
    } else if up.contains("SHA512") || up.contains("SHA-512") {
        Ok(KmDigest::Sha512)
    } else if up.starts_with("NONE") || up.contains("NONE") {
        Ok(KmDigest::None)
    } else {
        // Unknown algorithm: fail loudly instead of silently producing a
        // signature over the wrong digest (which the verifier would reject).
        Err(anyhow!("unsupported digest algorithm: {algorithm}"))
    }
}

// ---------------------------------------------------------------------------
// X.509 helpers.
// ---------------------------------------------------------------------------

fn spki_from_cert_der(der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::{der::Decode as _, der::Encode as _, Certificate};
    let cert = Certificate::from_der(der)
        .with_context(|| ks_err!("parse leaf certificate"))?;
    cert.tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .with_context(|| ks_err!("encode subject public key info"))
}

fn is_dead_object_status(status: &rsbinder::Status) -> bool {
    status.exception_code() == rsbinder::ExceptionCode::TransactionFailed
        && status.transaction_error() == rsbinder::StatusCode::DeadObject
}
