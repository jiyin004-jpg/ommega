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
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
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
    DateTime {
        ms_since_epoch: now,
    }
}

/// Certificate validity bound (now + ~10 years).
fn after_date_time() -> DateTime {
    const TEN_YEARS_MS: i64 = 10 * 365 * 24 * 3600 * 1000;
    DateTime {
        ms_since_epoch: now_date_time().ms_since_epoch + TEN_YEARS_MS,
    }
}

use crate::android::hardware::security::keymint::KeyParameter::KeyParameter as KmKeyParameter;
use crate::android::hardware::security::keymint::KeyPurpose::KeyPurpose;
use crate::err as ks_err;
use crate::keymaster::relay_tee::{
    clear_system_keymint, extract_km_error_code, get_system_keymint, key_params_to_aidl,
    probe_keymint_version, KEY_MINT_V5,
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
    /// Device-property / ID-attestation values requested by the app, as
    /// `(KeyMint tag, value)` pairs (710..=717 plus 723, the second IMEI).
    /// Forwarded verbatim into the real TEE request: Android 15's
    /// `setDevicePropertiesAttestationIncluded`
    /// fills brand/device/product/manufacturer/model from the *requesting*
    /// device and classic ID attestation adds serial/IMEI/MEID. The TEE itself
    /// validates every value against what it was provisioned with and fails with
    /// `CannotAttestIds` when the values do not belong to *this* device, so a
    /// heterogeneous B device rejects rather than attesting a foreign device.
    pub attestation_ids: Vec<(u32, Vec<u8>)>,
    /// User-authentication / authorization-list entries requested by the app, as
    /// `(KeyMint tag, value)` pairs (502 `USER_SECURE_ID`, 503
    /// `NO_AUTH_REQUIRED`, 504 `USER_AUTH_TYPE`, 505 `AUTH_TIMEOUT`, 506
    /// `ALLOW_WHILE_ON_BODY`, 507 `TRUSTED_USER_PRESENCE_REQUIRED`, 508
    /// `TRUSTED_CONFIRMATION_REQUIRED`, 509 `UNLOCKED_DEVICE_REQUIRED`).
    ///
    /// The A-side forwards these so the real TEE mints an auth-bound key with the
    /// SAME policy the app asked for — the TEE enforces `USER_AUTH_TYPE` /
    /// `AUTH_TIMEOUT` itself and stamps them into the leaf, so sending them is
    /// also what keeps the minted chain's authorization list matching the
    /// request (TrustAttestor: `hardware.attestation.user_auth_metadata` /
    /// `user_auth_policy`). `USER_SECURE_ID` is required here even though it is
    /// never attested: without it the TEE cannot bind the key to the user.
    pub user_auth: Vec<(u32, i64)>,
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
/// 运行时清理的节流间隔。清一遍是 read_dir + 对每个文件 stat，几百次系统
/// 调用；丢在 keygen 的结果路径上会直接拖住正在等答复的 A 端，所以改成按时间
/// 节流 —— 不管来多少任务，最多每 10 分钟清一次就够（磁盘上限本来就还有个
/// 文件数封顶兜着）。
const SESSION_PRUNE_INTERVAL: Duration = Duration::from_secs(600);

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
    {
        static LAST_PRUNE: Mutex<Option<Instant>> = Mutex::new(None);
        let mut guard = LAST_PRUNE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let due = match guard.as_ref() {
            Some(last) => last.elapsed() >= SESSION_PRUNE_INTERVAL,
            None => true,
        };
        if due {
            *guard = Some(Instant::now());
        }
        drop(guard);
        if due {
            prune_sessions();
        }
    }
}

fn sessions() -> &'static Mutex<HashMap<String, TeeSession>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, TeeSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn session_put(alias: &str, session: TeeSession) {
    save_session_to_disk(alias, &session);
    sessions()
        .lock()
        .unwrap()
        .insert(alias.to_string(), session);
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

/// Serialize check -> generate -> publish per alias, never across HAL services
/// or unrelated aliases. Weak entries keep completed flights from retaining locks.
#[derive(Default)]
struct AliasFlights {
    locks: Mutex<HashMap<String, Weak<Mutex<()>>>>,
}

impl AliasFlights {
    fn get_or_generate(
        &self,
        alias: &str,
        existing: impl FnOnce() -> Option<TeeSession>,
        generate: impl FnOnce() -> Result<TeeSession>,
        publish: impl FnOnce(&TeeSession),
    ) -> Result<TeeSession> {
        let lock = {
            let mut locks = self.locks.lock().unwrap();
            locks.retain(|_, lock| lock.strong_count() > 0);
            match locks.get(alias).and_then(Weak::upgrade) {
                Some(lock) => lock,
                None => {
                    let lock = Arc::new(Mutex::new(()));
                    locks.insert(alias.to_string(), Arc::downgrade(&lock));
                    lock
                }
            }
        };
        let _flight = lock.lock().unwrap();
        if let Some(session) = existing() {
            // Alias identifies a key, not a request. Even changed parameters or
            // StrongBox -> TEE demotion must not replace a delivered private key.
            // Older persisted sessions have no request fingerprint; reuse them
            // too. A genuinely new key requires a new alias.
            return Ok(session);
        }
        // Failure publishes nothing, permitting retries (including demotion).
        let session = generate()?;
        publish(&session);
        Ok(session)
    }
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
    static FLIGHTS: OnceLock<AliasFlights> = OnceLock::new();
    let session = FLIGHTS.get_or_init(AliasFlights::default).get_or_generate(
        alias,
        || session_get(alias).ok(),
        || mint_attest_key_on(service, challenge, app_id_der, spec),
        |session| session_put(alias, session.clone()),
    )?;
    if session.algorithm != spec.algorithm {
        bail!("alias already belongs to a different key algorithm");
    }
    Ok(session)
}

fn mint_attest_key_on(
    service: &'static str,
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

    Ok(TeeSession {
        key_blob: result.keyBlob,
        cert_chain,
        algorithm: spec.algorithm,
        hal_service: service,
    })
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
    // always signs without a token, so the key must be usable without auth —
    // but only as long as the app's own authorization list has not already
    // answered the question (see `needs_relay_no_auth_required`).
    if needs_relay_no_auth_required(&spec.user_auth) {
        params.push(KeyParam::NoAuthRequired);
    }

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
            params.push(KeyParam::EcCurve(spec.ec_curve.unwrap_or(KmEcCurve::P256)));
        }
        _ => {}
    }

    // Device properties / ID attestation: forward the values the app asked to be
    // attested. The A-side software path writes these from the device's own
    // provisioned IDs (`cert::AttestationIds`), so a relay-minted chain that
    // silently lacks KM_TAG_ATTESTATION_ID_* is immediately distinguishable from
    // a real one (TrustAttestor: `hardware.attestation.device_properties`).
    // A real TEE validates the values and answers `CannotAttestIds` (-75) when
    // they are not this device's own; the A-side then falls back to its local
    // software keybox, which is the honest answer for a foreign device.
    for (tag, value) in &spec.attestation_ids {
        params.push(attestation_id_param(*tag, value.clone())?);
    }

    // User-authentication / authorization-list entries. A real TEE is the
    // authority on these: it validates `USER_AUTH_TYPE`/`AUTH_TIMEOUT`, retains
    // `USER_SECURE_ID` inside the key blob (never in the attestation) and
    // stamps 504/505 — but not 503 NO_AUTH_REQUIRED — into the leaf. Without
    // them the minted chain contradicts an auth-bound request (TrustAttestor:
    // `hardware.attestation.user_auth_metadata` / `user_auth_policy`).
    for (tag, value) in &spec.user_auth {
        params.push(user_auth_param(*tag, *value)?);
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

/// Rebuild the `KeyParam` variant for a `KM_TAG_ATTESTATION_ID_*` tag - the only
/// tags the A-side forwards inside `device_attest_context.attestation_ids`.
/// Anything else is rejected loudly instead of being silently dropped.
fn attestation_id_param(tag: u32, value: Vec<u8>) -> Result<KeyParam> {
    Ok(match tag {
        710 => KeyParam::AttestationIdBrand(value),
        711 => KeyParam::AttestationIdDevice(value),
        712 => KeyParam::AttestationIdProduct(value),
        713 => KeyParam::AttestationIdSerial(value),
        714 => KeyParam::AttestationIdImei(value),
        715 => KeyParam::AttestationIdMeid(value),
        716 => KeyParam::AttestationIdManufacturer(value),
        717 => KeyParam::AttestationIdModel(value),
        // 723 (`TagType.BYTES | 723`); 718 is VENDOR_PATCHLEVEL, not an ID.
        723 => KeyParam::AttestationIdSecondImei(value),
        other => return Err(anyhow!("unsupported attestation ID tag {other}")),
    })
}

// ---------------------------------------------------------------------------
// Read-only helpers.
// ---------------------------------------------------------------------------

/// Whether the relay still has to add `NO_AUTH_REQUIRED` itself.
///
/// The A-side forwards `NO_AUTH_REQUIRED` (503) for every ordinary key, so the
/// relay adding a second one is a *duplicate tag*; and `USER_SECURE_ID` (502)
/// is the opposite requirement, so `NO_AUTH_REQUIRED` next to it is a
/// *contradiction*.  The qti TEE answers `ServiceSpecific(-40)` for both, which
/// made every such request fail on the B side and fall through to the server
/// keybox layer (whose public keybox is on Google's revocation list) instead of
/// getting a real-TEE chain.  The A-side's keybox layer drops 503 in exactly the
/// same situation (`server/src/cert.rs`), so this keeps both layers consistent.
fn needs_relay_no_auth_required(user_auth: &[(u32, i64)]) -> bool {
    !user_auth.iter().any(|(tag, _)| *tag == 502 || *tag == 503)
}

/// Rebuild the `KeyParam` variant for a user-auth tag the A-side forwarded inside
/// `device_attest_context.user_auth`. A tag that is not part of the
/// authorization list is rejected loudly instead of being silently dropped (the
/// A-side only ever sends 502..=509, so this is a wire-format guard).
fn user_auth_param(tag: u32, value: i64) -> Result<KeyParam> {
    Ok(match tag {
        502 => KeyParam::UserSecureId(value as u64),
        503 => KeyParam::NoAuthRequired,
        504 => KeyParam::UserAuthType(value as u32),
        505 => KeyParam::AuthTimeout(value as u32),
        506 => KeyParam::AllowWhileOnBody,
        507 => KeyParam::TrustedUserPresenceRequired,
        508 => KeyParam::TrustedConfirmationRequired,
        509 => KeyParam::UnlockedDeviceRequired,
        other => return Err(anyhow!("unsupported user-auth tag {other}")),
    })
}

/// Returns the certificate chain (DER) for `alias`, leaf first.
pub fn get_cert_chain(alias: &str) -> Result<Vec<Vec<u8>>> {
    Ok(session_get(alias)?.cert_chain)
}

/// Returns the SubjectPublicKeyInfo (SPKI, DER) of the leaf certificate.
pub fn get_public_key(alias: &str) -> Result<Vec<u8>> {
    public_key_from_session(&session_get(alias)?)
}

/// Extract SPKI from the exact session returned by generation, without another
/// alias lookup that could decouple the response's chain and public key.
pub fn public_key_from_session(session: &TeeSession) -> Result<Vec<u8>> {
    let leaf = session
        .cert_chain
        .first()
        .ok_or_else(|| anyhow!("certificate chain empty"))?;
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
    run_single_input_op(
        &session.key_blob,
        session.hal_service,
        KeyPurpose::SIGN,
        &op_params,
        data,
    )
}

/// Decrypts `data` with the TEE key for `alias`.
pub fn decrypt(alias: &str, data: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    let session = session_get(alias)?;
    let op_params = decrypt_begin_params(algorithm, session.algorithm)
        .with_context(|| ks_err!("unsupported decrypt algorithm {algorithm}"))?;
    run_single_input_op(
        &session.key_blob,
        session.hal_service,
        KeyPurpose::DECRYPT,
        &op_params,
        data,
    )
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
            return Err(anyhow!(
                "real keymint {hal_service} begin failed {km_code}: {status}"
            ));
        }
    };

    let Some(operation) = begin.operation else {
        return Err(anyhow!(
            "real keymint {hal_service} begin returned no operation"
        ));
    };

    // Feed the whole payload in a single update, then finish. update() may
    // return output early (e.g. a single-block RSA decrypt can deliver the
    // plaintext from update); finish() then returns whatever is left, so both
    // outputs must be concatenated or the operation's result is silently lost.
    let result = (|| -> Result<Vec<u8>> {
        let mut out = operation.update(input, None, None).map_err(|status| {
            let km_code = km_error_suffix(&status);
            anyhow!("real keymint {hal_service} update failed {km_code}: {status}")
        })?;
        out.extend_from_slice(&operation.finish(None, None, None, None, None).map_err(
            |status| {
                let km_code = km_error_suffix(&status);
                anyhow!("real keymint {hal_service} finish failed {km_code}: {status}")
            },
        )?);
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
            let up = algorithm.to_ascii_uppercase();
            let padding = if up.ends_with("WITHRSA/NOPADDING") {
                if digest != KmDigest::None {
                    return Err(anyhow!("RSA NoPadding signing requires digest NONE"));
                }
                KmPadding::None
            } else if up.contains("PSS") {
                // Keep legacy PSS algorithm names accepted.
                KmPadding::RsaPss
            } else if up.ends_with("WITHRSA") {
                KmPadding::RsaPkcs115Sign
            } else {
                return Err(anyhow!("unsupported RSA sign padding: {algorithm}"));
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
            let up = algorithm.to_ascii_uppercase();
            if up.starts_with("RSA/OAEP/") {
                let digest = digest_for_algorithm(algorithm)?;
                let mgf = mgf_digest_for_algorithm(algorithm)?;
                // OAEP requires both the digest and the MGF digest at
                // begin(DECRYPT); a real TEE fails without them (A-side -1000
                // / empty plaintext), and the MGF digest must match the one the
                // encryptor used (the A-side encodes it as a /MGF1-XXX suffix).
                vec![
                    KeyParam::Padding(KmPadding::RsaOaep),
                    KeyParam::Digest(digest),
                    KeyParam::RsaOaepMgfDigest(mgf),
                ]
            } else if up == "RSA/ECB/PKCS1PADDING" {
                vec![KeyParam::Padding(KmPadding::RsaPkcs115Encrypt)]
            } else if up == "RSA/ECB/NOPADDING" {
                vec![KeyParam::Padding(KmPadding::None)]
            } else {
                return Err(anyhow!("unsupported RSA decrypt padding: {algorithm}"));
            }
        }
    };
    key_params_to_aidl(&params, KEY_MINT_V5)
        .with_context(|| ks_err!("encode decrypt begin parameters"))
}

/// Parses the MGF1 digest from an OAEP algorithm string like
/// `RSA/OAEP/SHA-256/MGF1-SHA1`. Defaults to SHA1 (the standard OAEP default
/// when no MGF1 is specified).
fn mgf_digest_for_algorithm(algorithm: &str) -> Result<KmDigest> {
    let up = algorithm.to_ascii_uppercase();
    if let Some(pos) = up.find("/MGF1-") {
        return match up[pos + 6..].replace('-', "").as_str() {
            "SHA1" => Ok(KmDigest::Sha1),
            "SHA224" => Ok(KmDigest::Sha224),
            "SHA256" => Ok(KmDigest::Sha256),
            "SHA384" => Ok(KmDigest::Sha384),
            "SHA512" => Ok(KmDigest::Sha512),
            _ => Err(anyhow!("unsupported MGF digest algorithm: {algorithm}")),
        };
    }
    if up.contains("/MGF") {
        return Err(anyhow!("unsupported MGF algorithm: {algorithm}"));
    }
    Ok(KmDigest::Sha1)
}

fn digest_for_algorithm(algorithm: &str) -> Result<KmDigest> {
    let up = algorithm.to_uppercase();
    // MGF1 has its own digest. Never let its suffix select the message digest.
    let up = up.split("/MGF1-").next().unwrap_or(&up);
    if up.contains("SHA256") || up.contains("SHA-256") {
        Ok(KmDigest::Sha256)
    } else if up.contains("SHA224") || up.contains("SHA-224") {
        Ok(KmDigest::Sha224)
    } else if up.contains("MD5") {
        Ok(KmDigest::Md5)
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

#[cfg(test)]
mod alias_flight_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Barrier};
    use std::thread;

    #[derive(Default)]
    struct Store {
        flights: AliasFlights,
        sessions: Mutex<HashMap<String, TeeSession>>,
        generated: AtomicUsize,
    }

    impl Store {
        fn request(
            &self,
            alias: &str,
            generate: impl FnOnce() -> Result<TeeSession>,
        ) -> Result<TeeSession> {
            self.flights.get_or_generate(
                alias,
                || self.sessions.lock().unwrap().get(alias).cloned(),
                || {
                    self.generated.fetch_add(1, Ordering::SeqCst);
                    generate()
                },
                |session| {
                    self.sessions
                        .lock()
                        .unwrap()
                        .insert(alias.to_string(), session.clone());
                },
            )
        }
    }

    fn session(service: &'static str, id: u8) -> TeeSession {
        TeeSession {
            key_blob: vec![id],
            cert_chain: vec![vec![id, id]],
            algorithm: KeyAlgorithm::EcP256,
            hal_service: service,
        }
    }

    #[test]
    fn concurrent_same_alias_reuses_actual_blob_and_chain() {
        let store = Store::default();
        let start = Barrier::new(8);
        thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|id| {
                    let store = &store;
                    let start = &start;
                    scope.spawn(move || {
                        start.wait();
                        store
                            .request("same", || Ok(session(SYSTEM_KEYMINT_STRONGBOX, id)))
                            .unwrap()
                    })
                })
                .collect();
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            for result in &results {
                assert_eq!(result.key_blob, results[0].key_blob);
                assert_eq!(result.cert_chain, results[0].cert_chain);
                assert_eq!(result.hal_service, SYSTEM_KEYMINT_STRONGBOX);
            }
        });
        assert_eq!(store.generated.load(Ordering::SeqCst), 1);
        // A changed/demoted request after success cannot overwrite the key.
        let result = store
            .request("same", || panic!("successful alias must not mint again"))
            .unwrap();
        assert_eq!(result.hal_service, SYSTEM_KEYMINT_STRONGBOX);
    }

    #[test]
    fn failed_strongbox_can_retry_on_tee_but_success_is_fixed() {
        let store = Store::default();
        assert!(store
            .request("retry", || Err(anyhow!("StrongBox unavailable")))
            .is_err());
        assert!(store.sessions.lock().unwrap().is_empty());
        let retry = store
            .request("retry", || Ok(session(SYSTEM_KEYMINT_DEFAULT, 42)))
            .unwrap();
        let repeat = store
            .request("retry", || panic!("must reuse after success"))
            .unwrap();
        assert_eq!(repeat.key_blob, retry.key_blob);
        assert_eq!(repeat.cert_chain, retry.cert_chain);
        assert_eq!(repeat.hal_service, SYSTEM_KEYMINT_DEFAULT);
        assert_eq!(store.generated.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn existing_session_is_reused_without_generation() {
        let store = Store::default();
        let persisted = session(SYSTEM_KEYMINT_DEFAULT, 7);
        store
            .sessions
            .lock()
            .unwrap()
            .insert("loaded".to_string(), persisted.clone());
        let result = store
            .request("loaded", || panic!("loaded session must be reused"))
            .unwrap();
        assert_eq!(result.key_blob, persisted.key_blob);
        assert_eq!(result.cert_chain, persisted.cert_chain);
        assert_eq!(store.generated.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn different_alias_can_finish_while_first_is_generating() {
        let store = Store::default();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        thread::scope(|scope| {
            let store = &store;
            scope.spawn(move || {
                store
                    .request("blocked", || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(session(SYSTEM_KEYMINT_DEFAULT, 1))
                    })
                    .unwrap();
            });
            entered_rx.recv().unwrap();
            scope.spawn(move || {
                let result = store
                    .request("other", || Ok(session(SYSTEM_KEYMINT_DEFAULT, 2)))
                    .unwrap();
                done_tx.send(result).unwrap();
            });
            let result = done_rx.recv_timeout(Duration::from_secs(5));
            // Always release the first worker, including on regression failure.
            release_tx.send(()).unwrap();
            assert_eq!(result.unwrap().key_blob, vec![2]);
        });
        assert_eq!(store.generated.load(Ordering::SeqCst), 2);
    }
}

#[cfg(test)]
mod algorithm_digest_tests {
    use super::*;
    use crate::android::hardware::security::keymint::{
        Digest::Digest, KeyParameterValue::KeyParameterValue, PaddingMode::PaddingMode, Tag::Tag,
    };

    fn digest_param(tag: Tag, digest: KmDigest) -> KmKeyParameter {
        KmKeyParameter {
            tag,
            value: KeyParameterValue::Digest(Digest(digest as i32)),
        }
    }

    fn padding_param(padding: KmPadding) -> KmKeyParameter {
        KmKeyParameter {
            tag: Tag::PADDING,
            value: KeyParameterValue::PaddingMode(PaddingMode(padding as i32)),
        }
    }

    #[test]
    fn decrypt_padding_is_explicit_and_unknown_is_rejected() {
        for (algorithm, padding) in [
            ("RSA/ECB/NoPadding", KmPadding::None),
            ("RSA/ECB/PKCS1Padding", KmPadding::RsaPkcs115Encrypt),
        ] {
            assert_eq!(
                decrypt_begin_params(algorithm, KeyAlgorithm::Rsa2048).unwrap(),
                vec![padding_param(padding)]
            );
        }
        for algorithm in ["RSA/ECB/UNKNOWN", "RSA/ECB/PKCS7Padding", "UNKNOWN"] {
            assert!(decrypt_begin_params(algorithm, KeyAlgorithm::Rsa2048).is_err());
        }
        assert!(decrypt_begin_params("RSA/ECB/NoPadding", KeyAlgorithm::EcP256).is_err());
    }

    #[test]
    fn signing_begin_parameters_preserve_raw_pkcs1_and_legacy_pss() {
        for (algorithm, digest, padding) in [
            ("NONEwithRSA/NoPadding", KmDigest::None, KmPadding::None),
            ("NONEwithRSA", KmDigest::None, KmPadding::RsaPkcs115Sign),
            ("SHA224withRSA", KmDigest::Sha224, KmPadding::RsaPkcs115Sign),
            ("MD5withRSA", KmDigest::Md5, KmPadding::RsaPkcs115Sign),
            ("SHA256withRSA/PSS", KmDigest::Sha256, KmPadding::RsaPss),
            (
                "SHA256withRSAandMGF1/PSS",
                KmDigest::Sha256,
                KmPadding::RsaPss,
            ),
        ] {
            let mut expected = vec![digest_param(Tag::DIGEST, digest), padding_param(padding)];
            if padding == KmPadding::RsaPss {
                expected.push(digest_param(Tag::RSA_OAEP_MGF_DIGEST, digest));
            }
            assert_eq!(
                sign_begin_params(algorithm, KeyAlgorithm::Rsa2048).unwrap(),
                expected
            );
        }
        assert!(sign_begin_params("SHA256withRSA/NoPadding", KeyAlgorithm::Rsa2048).is_err());
        assert!(sign_begin_params("SHA256withRSA/UNKNOWN", KeyAlgorithm::Rsa2048).is_err());
        assert_eq!(
            sign_begin_params("SHA224withECDSA", KeyAlgorithm::EcP256).unwrap(),
            vec![digest_param(Tag::DIGEST, KmDigest::Sha224)]
        );
    }

    #[test]
    fn oaep_begin_parameters_have_independent_digest_tags() {
        assert_eq!(
            decrypt_begin_params("RSA/OAEP/SHA-384/MGF1-SHA224", KeyAlgorithm::Rsa2048).unwrap(),
            vec![
                padding_param(KmPadding::RsaOaep),
                digest_param(Tag::DIGEST, KmDigest::Sha384),
                digest_param(Tag::RSA_OAEP_MGF_DIGEST, KmDigest::Sha224),
            ]
        );
        for algorithm in [
            "RSA/OAEP/SHA256/MGF1-UNKNOWN",
            "RSA/OAEP/SHA256/MGF1-SHA256junk",
            "RSA/OAEP/SHA256/MGF2-SHA1",
        ] {
            assert!(mgf_digest_for_algorithm(algorithm).is_err());
            assert!(decrypt_begin_params(algorithm, KeyAlgorithm::Rsa2048).is_err());
        }
    }

    #[test]
    fn oaep_message_and_mgf_digests_are_independent() {
        for (algorithm, message, mgf) in [
            (
                "RSA/OAEP/SHA-384/MGF1-SHA1",
                KmDigest::Sha384,
                KmDigest::Sha1,
            ),
            (
                "RSA/OAEP/SHA-512/MGF1-SHA1",
                KmDigest::Sha512,
                KmDigest::Sha1,
            ),
            (
                "RSA/OAEP/SHA-1/MGF1-SHA256",
                KmDigest::Sha1,
                KmDigest::Sha256,
            ),
            (
                "rsa/oaep/sha-384/mgf1-sha-512",
                KmDigest::Sha384,
                KmDigest::Sha512,
            ),
            ("RSA/OAEP/SHA256", KmDigest::Sha256, KmDigest::Sha1),
        ] {
            assert_eq!(digest_for_algorithm(algorithm).unwrap(), message);
            assert_eq!(mgf_digest_for_algorithm(algorithm).unwrap(), mgf);
        }
        assert!(digest_for_algorithm("RSA/OAEP/UNKNOWN/MGF1-SHA256").is_err());
    }

    #[test]
    fn signing_digest_names_keep_existing_behavior() {
        for (algorithm, expected) in [
            ("SHA256withRSA/PSS", KmDigest::Sha256),
            ("SHA384withECDSA", KmDigest::Sha384),
            ("SHA512withRSA", KmDigest::Sha512),
            ("NONEwithECDSA", KmDigest::None),
        ] {
            assert_eq!(digest_for_algorithm(algorithm).unwrap(), expected);
        }
    }
}

// ---------------------------------------------------------------------------
// X.509 helpers.
// ---------------------------------------------------------------------------

fn spki_from_cert_der(der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::{der::Decode as _, der::Encode as _, Certificate};
    let cert = Certificate::from_der(der).with_context(|| ks_err!("parse leaf certificate"))?;
    cert.tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .with_context(|| ks_err!("encode subject public key info"))
}

fn is_dead_object_status(status: &rsbinder::Status) -> bool {
    status.exception_code() == rsbinder::ExceptionCode::TransactionFailed
        && status.transaction_error() == rsbinder::StatusCode::DeadObject
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key the app never said anything about user auth for still has to be
    /// usable without a token, so the relay adds the tag itself.
    #[test]
    fn relay_adds_no_auth_required_when_app_is_silent() {
        assert!(needs_relay_no_auth_required(&[]));
        assert!(needs_relay_no_auth_required(&[(504, 2)]));
        assert!(needs_relay_no_auth_required(&[(504, 2), (505, 30_000)]));
        assert!(needs_relay_no_auth_required(&[(506, 1)]));
        assert!(needs_relay_no_auth_required(&[(509, 1)]));
    }

    /// The A-side forwards `NO_AUTH_REQUIRED` (503) for every ordinary key. A
    /// second copy is a duplicate tag, which the qti TEE answers with
    /// `ServiceSpecific(-40)` — that is what pushed every ordinary request to
    /// the server keybox layer. Regression guard for the `user_auth=[[503,1]]`
    /// shape (200 requests in one TrustAttestor scan).
    #[test]
    fn relay_does_not_duplicate_app_no_auth_required() {
        assert!(!needs_relay_no_auth_required(&[(503, 1)]));
        assert!(!needs_relay_no_auth_required(&[(503, 1), (503, 1)]));
        assert!(!needs_relay_no_auth_required(&[
            (503, 1),
            (504, 2),
            (505, 30_000)
        ]));
        assert!(!needs_relay_no_auth_required(&[(509, 1), (503, 1)]));
    }

    /// `USER_SECURE_ID` asks for the opposite of NO_AUTH_REQUIRED; the pair is
    /// contradictory, so the relay leaves the auth binding to the app (the
    /// server keybox layer drops 503 the same way).
    #[test]
    fn relay_does_not_contradict_user_secure_id() {
        assert!(!needs_relay_no_auth_required(&[(502, 4242)]));
        assert!(!needs_relay_no_auth_required(&[(502, 4242), (504, 2)]));
        assert!(!needs_relay_no_auth_required(&[
            (502, 6_862_392_016_876_761_225),
            (504, 2)
        ]));
    }

    #[test]
    fn user_auth_tags_map_to_the_authorization_list() {
        assert!(matches!(
            user_auth_param(502, 4242).unwrap(),
            KeyParam::UserSecureId(4242)
        ));
        assert!(matches!(
            user_auth_param(503, 1).unwrap(),
            KeyParam::NoAuthRequired
        ));
        assert!(matches!(
            user_auth_param(504, 2).unwrap(),
            KeyParam::UserAuthType(2)
        ));
        assert!(matches!(
            user_auth_param(505, 30_000).unwrap(),
            KeyParam::AuthTimeout(30_000)
        ));
        assert!(matches!(
            user_auth_param(506, 1).unwrap(),
            KeyParam::AllowWhileOnBody
        ));
        assert!(matches!(
            user_auth_param(507, 1).unwrap(),
            KeyParam::TrustedUserPresenceRequired
        ));
        assert!(matches!(
            user_auth_param(508, 1).unwrap(),
            KeyParam::TrustedConfirmationRequired
        ));
        assert!(matches!(
            user_auth_param(509, 1).unwrap(),
            KeyParam::UnlockedDeviceRequired
        ));
        assert!(user_auth_param(510, 1).is_err());
    }
}
