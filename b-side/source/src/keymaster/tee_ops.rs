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
//! Key blobs and certificate chains are held in a process-local hot cache keyed by
//! alias and persisted in a SQLite file (`/data/adb/ommega-b/sessions.db`, see
//! [`session_db`]) so aliases survive a relay restart; the cache only keeps the
//! recently used ones and the rest are read back from the database by alias.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
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

use crate::android::hardware::security::keymint::AttestationKey::AttestationKey as NativeAttestationKey;
use crate::android::hardware::security::keymint::IKeyMintDevice::IKeyMintDevice;
use crate::android::hardware::security::keymint::KeyCharacteristics::KeyCharacteristics;
use crate::android::hardware::security::keymint::KeyCreationResult::KeyCreationResult;
use crate::android::hardware::security::keymint::KeyParameter::KeyParameter as KmKeyParameter;
use crate::android::hardware::security::keymint::KeyPurpose::KeyPurpose;
use crate::err as ks_err;
use crate::keymaster::relay_tee::{
    clear_system_keymint, extract_km_error_code, get_system_keymint, key_params_to_aidl,
    probe_keymint_version, KEY_MINT_V5,
};

use super::attest_proxy::{SYSTEM_KEYMINT_DEFAULT, SYSTEM_KEYMINT_STRONGBOX};
use super::session_db;

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
    /// 调用方自带的证明密钥（App AttestKey 委派）。有值时这一把 key 的证书
    /// 必须由**真 TEE** 用那把已有的 ATTEST_KEY 原生签发
    /// （`generateKey(.., AttestationKey)`），而不是由本进程另找钥匙代签。
    pub attestation_key: Option<AttestationKeyRef>,
}

/// 调用方指定的证据签发密钥：本机 session 里的 alias + 它自己的证书 Subject（DER）。
///
/// `issuer_subject_name` 让本端能先核对「请求说的那把钥匙」和「我这儿存的那把」
/// 是同一把，再交给 HAL；HAL 侧的权限来自那把钥匙 keyblob 里的 ATTEST_KEY 用途。
#[derive(Clone, Debug)]
pub struct AttestationKeyRef {
    /// 证明密钥的 key blob 本体（AOSP `AttestationKey.keyBlob`）。
    ///
    /// 有值时直接拿去给 HAL 签，不再查 session —— AK 不在本机铸（智能模式在
    /// 服务端、或换了一台 B）时，只靠 alias 会直接报
    /// `issuer key ... is not available on this device`。
    pub key_blob: Option<Vec<u8>>,
    pub alias: String,
    pub issuer_subject_name: Vec<u8>,
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

/// 会话的落盘库（SQLite）与内存热缓存。
///
/// Key blob 是自包含的，重启之后照样能 begin/finish，所以每个铸出来的会话都落一份
/// 到 `/data/adb/ommega-b/sessions.db`（见 [`super::session_db`]），A 端的 `isRemote`
/// 钥匙跨重启仍然有效。
///
/// 2026-10-03 那条教训还在：淘汰按「最后使用时间」算。之前按文件 mtime 排，可取用时
/// 从不刷新 mtime，于是「刚用过」和「几小时没用」在它眼里一样旧 —— 2000 个上限配
/// 6.7 个/分钟的新增速率，有效保留窗只有 4 小时 46 分，正在用的 alias 照样被清，
/// 紧接着签名就报 `no key for alias ... (call attest first)`（relay.log 里
/// 6c9e18291df990e9、dc70e82803071c96 就是这么死的）。现在每次取用顺手写一下
/// `used_ms`（有节流），清的才是真正没人用的。
///
/// 内存里只留最近用过的这么多条，其余的在库里按 alias 单查：原来那份 map 是全量常驻
/// 的（实测到过 19967 条 × 8 KB ≈ 160 MB），一台手机的常驻进程不该背这个。
const SESSION_MEMORY_HOT: usize = 2_000;

/// 距上次写 `used_ms` 多久才值得再写一次。取得比这更勤的会话不必每次都写：淘汰判的
/// 是小时级的窗口，差几分钟无所谓，而一次 UPDATE 也顶不上白做。
const SESSION_TOUCH_MIN_AGE_MS: i64 = 5 * 60 * 1000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|age| age.as_millis() as i64)
        .unwrap_or(0)
}

/// 内存热缓存：alias -> (最后一次使用的时间戳, 会话)。时间戳既给 LRU 用（满了丢最旧
/// 的），也给「要不要写库」的节流用。
fn sessions() -> &'static Mutex<HashMap<String, (i64, TeeSession)>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, (i64, TeeSession)>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn session_from_stored(stored: session_db::Stored) -> Option<TeeSession> {
    let algorithm = match stored.algorithm.as_str() {
        "EcP256" => KeyAlgorithm::EcP256,
        "Rsa2048" => KeyAlgorithm::Rsa2048,
        other => {
            log::warn!("persisted session has unknown algorithm '{other}'; ignoring it");
            return None;
        }
    };
    // `hal_service` 是后加的字段，缺值按 TEE 算：签名/解密必须落在铸它的那个 HAL 上，
    // 猜错只会拿到 INVALID_KEY_BLOB。
    let hal_service = if stored.hal_service == "strongbox" {
        SYSTEM_KEYMINT_STRONGBOX
    } else {
        SYSTEM_KEYMINT_DEFAULT
    };
    Some(TeeSession {
        key_blob: stored.key_blob,
        cert_chain: stored.cert_chain,
        algorithm,
        hal_service,
    })
}

fn session_to_stored(session: &TeeSession) -> session_db::Stored {
    session_db::Stored {
        key_blob: session.key_blob.clone(),
        cert_chain: session.cert_chain.clone(),
        algorithm: match session.algorithm {
            KeyAlgorithm::EcP256 => "EcP256",
            KeyAlgorithm::Rsa2048 => "Rsa2048",
        }
        .to_string(),
        hal_service: if session.hal_service == SYSTEM_KEYMINT_STRONGBOX {
            "strongbox"
        } else {
            "tee"
        }
        .to_string(),
    }
}

/// 往内存里放一份；满了按「最后使用」丢掉最旧的那些。丢的只是内存副本，库里那条还
/// 在，下次取用会从库里读回来。
fn cache_put(alias: &str, session: TeeSession, used_ms: i64) {
    let mut sessions = sessions()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    sessions.insert(alias.to_string(), (used_ms, session));
    while sessions.len() > SESSION_MEMORY_HOT {
        let Some(oldest) = sessions
            .iter()
            .min_by_key(|(_, (used_ms, _))| *used_ms)
            .map(|(alias, _)| alias.clone())
        else {
            break;
        };
        sessions.remove(&oldest);
    }
}

/// 命中内存就返回会话，并说明这次要不要把 `used_ms` 写回库里（距上次够久了才写）。
/// 内存里的位置每次都刷新，写库那步才节流。
fn cache_get(alias: &str) -> Option<(TeeSession, bool)> {
    let now = now_ms();
    let mut sessions = sessions()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (used_ms, session) = sessions.get_mut(alias)?;
    let should_touch = now.saturating_sub(*used_ms) >= SESSION_TOUCH_MIN_AGE_MS;
    *used_ms = now;
    Some((session.clone(), should_touch))
}

fn session_put(alias: &str, session: TeeSession) {
    session_db::put(alias, &session_to_stored(&session));
    cache_put(alias, session, now_ms());
    session_db::prune_if_due();
}

fn session_get(alias: &str) -> Result<TeeSession> {
    if let Some((session, should_touch)) = cache_get(alias) {
        if should_touch {
            session_db::touch(alias);
        }
        return Ok(session);
    }
    // Miss: 从库里捞（比如 relay 刚重启）。key blob 是持久化的，捞回来照样能
    // 签名/解密。
    if let Some(stored) = session_db::get(alias) {
        let session = session_from_stored(stored)
            .ok_or_else(|| anyhow!("persisted session for alias '{alias}' is unusable"))?;
        session_db::touch(alias);
        cache_put(alias, session.clone(), now_ms());
        log::info!("recovered persisted session for alias '{alias}'");
        return Ok(session);
    }
    Err(anyhow!("no key for alias '{alias}' (call attest first)"))
}

/// 启动时开库（库里空就先把旧目录导进来）并清一轮，不做全量加载。
///
/// 原来这里是「清一遍 + 全量加载」：别名被哈希进文件名、反推不出来，所以只能逐个读
/// JSON 才能把 alias 填进 map —— 实测 19967 个文件要 12 秒。现在按 alias 主键单查，
/// 那份热身既没用又白占 160 MB 内存，一并去掉了。
pub fn load_all_sessions() {
    session_db::init();
}

#[cfg(test)]
mod session_cache_tests {
    use super::*;

    /// 这几个用例都动那个全局热缓存，串着跑。
    fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn session(id: u8) -> TeeSession {
        TeeSession {
            key_blob: vec![id],
            cert_chain: vec![vec![id, id]],
            algorithm: KeyAlgorithm::EcP256,
            hal_service: SYSTEM_KEYMINT_DEFAULT,
        }
    }

    /// 内存只留最近用过的那些：塞爆之后最旧的被换出去，最新的还在，条数不多不少。
    #[test]
    fn hot_cache_keeps_the_most_recently_used() {
        let _guard = exclusive();
        let cache = sessions();
        cache.lock().unwrap().clear();
        for id in 0..SESSION_MEMORY_HOT {
            cache_put(&format!("k{id}"), session(id as u8), id as i64);
        }
        assert_eq!(cache.lock().unwrap().len(), SESSION_MEMORY_HOT);
        cache_put("newest", session(200), 10_000_000);
        let sessions = cache.lock().unwrap();
        assert_eq!(sessions.len(), SESSION_MEMORY_HOT, "多出来的只能是换出去的");
        assert!(sessions.contains_key("newest"));
        assert!(!sessions.contains_key("k0"), "最久没用过的那个被换出去");
    }

    /// 同一个 alias 在两套 HAL 上各是一把钥匙：另一个 HAL 铸的会话不能当本次结果。
    #[test]
    fn session_from_another_hal_is_not_reused() {
        let _guard = exclusive();
        let tee = session(7);
        let mut strongbox = session(9);
        strongbox.hal_service = SYSTEM_KEYMINT_STRONGBOX;
        assert_eq!(
            reusable_session(Some(tee.clone()), SYSTEM_KEYMINT_DEFAULT).map(|s| s.key_blob),
            Some(vec![7]),
            "同一个 HAL 的会话照旧复用"
        );
        assert!(
            reusable_session(Some(tee), SYSTEM_KEYMINT_STRONGBOX).is_none(),
            "TEE 的会话不能被当成 StrongBox 的"
        );
        assert_eq!(
            reusable_session(Some(strongbox), SYSTEM_KEYMINT_STRONGBOX).map(|s| s.key_blob),
            Some(vec![9])
        );
        assert!(reusable_session(None, SYSTEM_KEYMINT_DEFAULT).is_none());
    }

    /// 命中内存时位置刷新、写库节流：刚用过的不用再写，隔够久了才写一次。
    #[test]
    fn cache_hits_refresh_recency_but_throttle_the_db_write() {
        let _guard = exclusive();
        let cache = sessions();
        cache.lock().unwrap().clear();
        cache_put("alias", session(1), now_ms());
        let (hit, should_touch) = cache_get("alias").expect("刚放进去的必须在");
        assert_eq!(hit.key_blob, vec![1]);
        assert!(!should_touch, "刚写过就不用再写一遍");
        assert!(cache_get("does-not-exist").is_none());
        cache_put("alias", session(1), now_ms() - SESSION_TOUCH_MIN_AGE_MS - 1);
        assert!(cache_get("alias").unwrap().1, "隔够久了就该写一次");
    }

    /// 存进库再取回来，字段一个不差（含枚举 <-> 字符串的来回）。
    #[test]
    fn stored_round_trip_keeps_every_field() {
        let _guard = exclusive();
        let original = TeeSession {
            key_blob: vec![9; 128],
            cert_chain: vec![vec![1; 700], vec![2; 4]],
            algorithm: KeyAlgorithm::Rsa2048,
            hal_service: SYSTEM_KEYMINT_STRONGBOX,
        };
        let stored = session_to_stored(&original);
        assert_eq!(stored.algorithm, "Rsa2048");
        assert_eq!(stored.hal_service, "strongbox");
        let back = session_from_stored(stored).expect("自己写进去的算法必须认得");
        assert_eq!(back.key_blob, original.key_blob);
        assert_eq!(back.cert_chain, original.cert_chain);
        assert_eq!(back.algorithm, KeyAlgorithm::Rsa2048);
        assert_eq!(back.hal_service, SYSTEM_KEYMINT_STRONGBOX);
    }

    /// 库里存了个不认识的算法就别当会话用 —— 拿它去签名只会错得更远。
    #[test]
    fn unknown_algorithm_is_rejected() {
        let _guard = exclusive();
        let stored = session_db::Stored {
            key_blob: vec![1],
            cert_chain: vec![vec![1]],
            algorithm: "DsA1024".to_string(),
            hal_service: "tee".to_string(),
        };
        assert!(session_from_stored(stored).is_none());
    }

    /// 演练：拿「真的那份库」的副本，按别名把老钥匙取回来，再让真 TEE 用它签一次。
    /// 走的正是重启后那条路：内存空 → 查库 → key blob → HAL。
    ///
    /// 在设备上跑（库指副本，旧目录指原地）：
    ///   OMMEGA_SESSIONS_DB=/data/local/tmp/drill-copy.db \
    ///   OMMEGA_SESSIONS_DIR=/data/adb/ommega-b/sessions \
    ///   ./ommegaclient-b-<hash> --ignored --nocapture \
    ///     'keymaster::tee_ops::session_cache_tests::drill_recover_keys_from_a_db_copy'
    #[test]
    #[ignore]
    fn drill_recover_keys_from_a_db_copy() {
        let _guard = exclusive();
        sessions().lock().unwrap().clear();
        session_db::init();
        // 后面要真让 HAL 签一次，得先把 binder 的 ProcessState 起来
        crate::init_binder();

        // 文件名只是别名的变体（带 .json 后缀），真正的别名在 JSON 里，样本就随便抽 40 个
        let dir = session_db::legacy_dir();
        let mut aliases: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().map(|it| it.is_file()).unwrap_or(false))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .take(40)
            .collect();
        aliases.sort();
        assert!(!aliases.is_empty(), "{} 里没有样本", dir.display());

        let digest = [7u8; 32];
        let mut back = 0;
        let mut signed = 0;
        let mut missing = 0;
        for entry in &aliases {
            let text = std::fs::read_to_string(dir.join(entry)).expect("旧目录里那份读不到");
            let (alias, legacy) =
                session_db::parse_legacy_json(&text).expect("旧目录里那份解析不了");
            // 内存刚清过，所以这一次必然是查库
            let session = match session_get(&alias) {
                Ok(session) => session,
                Err(err) => {
                    eprintln!("  {alias}: 取不回来：{err:#}");
                    missing += 1;
                    continue;
                }
            };
            // 和旧目录里那份 JSON 对齐：迁移前后必须是同一把钥匙
            assert_eq!(
                session.key_blob, legacy.key_blob,
                "{alias} 的 key blob 对不上"
            );
            assert_eq!(
                session.cert_chain, legacy.cert_chain,
                "{alias} 的证书链对不上"
            );
            back += 1;

            let algorithm = match session.algorithm {
                KeyAlgorithm::EcP256 => "SHA256withECDSA",
                KeyAlgorithm::Rsa2048 => "SHA256withRSA",
            };
            match sign(&alias, &digest, algorithm) {
                Ok(signature) => {
                    signed += 1;
                    eprintln!(
                        "  {alias}: 库里捞回来 + 真 TEE 签名 {} 字节",
                        signature.len()
                    );
                }
                Err(err) => eprintln!("  {alias}: 捞回来了但签不了（多半是钥匙用途）：{err:#}"),
            }
        }
        eprintln!(
            "演练：样本 {} 个，从库里取回来且和旧文件逐字节一致 {} 个，取不回来 {} 个，真 TEE 签名成功 {} 个",
            aliases.len(),
            back,
            missing,
            signed
        );
        assert!(back > 0, "一把都没从库里取回来");
        assert!(signed > 0, "取回来了但一把都没签成，这条链路不算验完");
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

/// 存着的会话能不能当本次的现成结果。
///
/// 同一个 alias 在 TEE 和 StrongBox 上是两把不同的钥匙：拿另一个 HAL 铸的会话当结果，
/// 等于把 TEE 的链当 StrongBox 交给调用方，key blob 本身也不通用（签名会
/// `INVALID_KEY_BLOB`）。所以只复用同一个 HAL 的。
fn reusable_session(existing: Option<TeeSession>, service: &str) -> Option<TeeSession> {
    existing.filter(|session| session.hal_service == service)
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
        // 同一个 alias 在 TEE 和 StrongBox 上是两把不同的钥匙：存着的会话如果来自另一个
        // HAL，拿它当本次结果就是把 TEE 链当 StrongBox 交给调用方。只复用同一个 HAL 的。
        || reusable_session(session_get(alias).ok(), service),
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
    mint_attest_key_with(service, challenge, app_id_der, spec, None)
}

/// 用调用方提供的 attestation key（keyblob）给子 key 出证。
///
/// 只给自检用：确认本机 TA 到底认不认「一个不是它刚刚新生、但确实是它产的」keyblob
/// 当 attestation key。验通了才能做 A 端 remote 侧的透传。
pub fn mint_with_attestation_key(
    service: &'static str,
    challenge: &[u8],
    app_id_der: &[u8],
    spec: &KeySpec,
    attest_key_blob: &[u8],
    issuer_subject: &[u8],
) -> Result<TeeSession> {
    let ak = crate::android::hardware::security::keymint::AttestationKey::AttestationKey {
        keyBlob: attest_key_blob.to_vec(),
        attestKeyParams: vec![],
        issuerSubjectName: issuer_subject.to_vec(),
    };
    mint_attest_key_with(service, challenge, app_id_der, spec, Some(&ak))
}

fn mint_attest_key_with(
    service: &'static str,
    challenge: &[u8],
    app_id_der: &[u8],
    spec: &KeySpec,
    attest: Option<&crate::android::hardware::security::keymint::AttestationKey::AttestationKey>,
) -> Result<TeeSession> {
    let keymint = get_system_keymint(service)
        .with_context(|| ks_err!("real keymint {service} connect failed"))?;
    // Probe the actual HAL version instead of assuming V5. A StrongBox HAL
    // may only implement KeyMint V2/V3; sending V5-encoded parameters can
    // cause version-mismatch errors that look like "not supported".
    let km_version = probe_keymint_version(&keymint, service);
    let params = build_attestation_params(app_id_der, challenge, spec, km_version)?;

    // 调用方自带的证明密钥（App AttestKey 委派）：先在本机找到那把 key，确认它
    // 属于同一个 HAL、证书 Subject 与请求一致，然后交给**真 TEE** 原生签发子证书。
    // 本进程不持有任何私钥，也不用自己的批量 key 冒充。
    //
    // 请求带了 key blob（AOSP `AttestationKey.keyBlob`）时不再查 session：那把 AK
    // 可能压根不是本机铸的（智能模式铸在服务端、或换了一台 B），只要有 blob 就能签。
    let native_attest = spec.attestation_key.as_ref().and_then(|request| {
        request.key_blob.as_ref().map(|blob| {
            crate::android::hardware::security::keymint::AttestationKey::AttestationKey {
                keyBlob: blob.clone(),
                attestKeyParams: vec![],
                issuerSubjectName: request.issuer_subject_name.clone(),
            }
        })
    });
    let parent = match spec.attestation_key.as_ref() {
        Some(request) if native_attest.is_none() => Some(resolve_issuer(request, service)?),
        _ => None,
    };

    let result = match (spec.attestation_key.as_ref(), parent.as_ref()) {
        (Some(request), Some(parent)) => {
            generate_with_native_issuer(service, &*keymint, &params, request, parent)?
        }
        // `mint_with_attestation_key` 那只自检入口直接把 keyblob 传进来，照旧支持。
        _ => match keymint.generateKey(&params, native_attest.as_ref().or(attest)) {
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
        },
    };

    // 请求了 ATTEST_KEY 就核对 HAL 真给了一把**独占**的硬件证明密钥：光信
    // “我请求了”不够，要看它回的 keyCharacteristics。
    if spec.purposes.contains(&KmKeyPurpose::AttestKey) {
        validate_native_attestation_characteristics(&result.keyCharacteristics, service)?;
    }

    let mut cert_chain: Vec<Vec<u8>> = result
        .certificateChain
        .into_iter()
        .map(|cert| cert.encodedCertificate)
        .collect();

    // A HAL that reports generateKey() *success* together with an empty
    // certificate chain must not be forwarded as a successful attestation:
    // sending `cert_chain: []` means the operator cannot tell which side dropped
    // the chain, and the empty session would also be persisted to
    // /data/adb/ommega-b/sessions.db. Fail loudly instead: the relay server treats an
    // error exactly like an empty chain (next layer / StrongBox demotion), so
    // behaviour is unchanged.
    if cert_chain.is_empty() {
        return Err(anyhow!(
            "real keymint {service} returned an empty certificate chain \
             (key_blob {}B) — generateKey was accepted but the key was not attested",
            result.keyBlob.len()
        ));
    }

    // 委派时 HAL 只回子证书（AIDL: "the returned certificate chain must contain
    // only an attestation certificate signed with the specified key"），
    // 父链由本端补上——A 端要靠它校验签发关系，校验完只把子证书交给调用方。
    if let Some(parent) = parent.as_ref() {
        append_issuer_chain(&mut cert_chain, &parent.cert_chain)?;
    }

    Ok(TeeSession {
        key_blob: result.keyBlob,
        cert_chain,
        algorithm: spec.algorithm,
        hal_service: service,
    })
}

/// 本机找回调用方指定的证明密钥，并与请求里的 alias/HAL/Subject 对齐。
fn resolve_issuer(request: &AttestationKeyRef, service: &'static str) -> Result<TeeSession> {
    if request.alias.is_empty() || request.issuer_subject_name.is_empty() {
        bail!("attestation_key reference is incomplete");
    }
    let parent = session_get(&request.alias).with_context(|| {
        ks_err!(
            "issuer key '{}' is not available on this device",
            request.alias
        )
    })?;
    if parent.hal_service != service {
        bail!(
            "issuer key '{}' belongs to another HAL ({})",
            request.alias,
            parent.hal_service
        );
    }
    let leaf = parent
        .cert_chain
        .first()
        .ok_or_else(|| anyhow!("issuer certificate missing"))?;
    if certificate_subject_der(leaf)? != request.issuer_subject_name {
        bail!("issuer subject mismatch for '{}'", request.alias);
    }
    Ok(parent)
}

fn certificate_subject_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    use der::{Decode as _, Encode as _};
    let cert = x509_cert::Certificate::from_der(cert_der).context("parse issuer certificate")?;
    cert.tbs_certificate()
        .subject()
        .to_der()
        .context("encode issuer subject")
}

/// 用已有证明密钥走真 TEE 的原生委派：`generateKey(params, AttestationKey)`。
///
/// 权限来自父 keyblob 的 ATTEST_KEY 用途，**不**做 PKIX 的 CA/keyCertSign 门槛
/// （真机实测：那些叶子的 Key Usage 是 `Certificate Sign`，且没有 BasicConstraints）。
fn generate_with_native_issuer(
    service: &'static str,
    keymint: &dyn IKeyMintDevice,
    params: &[KmKeyParameter],
    request: &AttestationKeyRef,
    parent: &TeeSession,
) -> Result<KeyCreationResult> {
    let mut native = NativeAttestationKey {
        keyBlob: parent.key_blob.clone(),
        attestKeyParams: vec![],
        issuerSubjectName: request.issuer_subject_name.clone(),
    };
    match keymint.generateKey(params, Some(&native)) {
        Ok(result) => Ok(result),
        Err(status) if is_upgrade_required(&status) => {
            // HAL 要求先升级父 keyblob：升级结果先落盘、再重试一次（延续
            // begin 那条路径的「持久化后再重试」协议，不生成新 key）。
            let upgraded_blob = keymint
                .upgradeKey(&parent.key_blob, &[])
                .map_err(|status| {
                    if is_dead_object_status(&status) {
                        clear_system_keymint(service);
                    }
                    anyhow!(
                        "real keymint {service} upgradeKey failed {}: {status}",
                        km_error_suffix(&status)
                    )
                })?;
            let upgraded = TeeSession {
                key_blob: upgraded_blob,
                cert_chain: parent.cert_chain.clone(),
                algorithm: parent.algorithm,
                hal_service: parent.hal_service,
            };
            session_put(&request.alias, upgraded.clone());
            log::info!("event=issuer_keyblob_upgrade alias={}", request.alias);
            native.keyBlob = upgraded.key_blob;
            keymint.generateKey(params, Some(&native)).map_err(|status| {
                if is_dead_object_status(&status) {
                    clear_system_keymint(service);
                }
                let km_code = km_error_suffix(&status);
                anyhow!(
                    "real keymint {service} delegated generateKey failed after upgrade {km_code}: {status}"
                )
            })
        }
        Err(status) => {
            if is_dead_object_status(&status) {
                clear_system_keymint(service);
            }
            let km_code = km_error_suffix(&status);
            Err(anyhow!(
                "real keymint {service} delegated generateKey failed {km_code}: {status}"
            ))
        }
    }
}

fn is_upgrade_required(status: &rsbinder::Status) -> bool {
    // KEY_REQUIRES_UPGRADE = -62
    extract_km_error_code(status) == Some(-62)
}

/// 核对 HAL 真的给了一把独占的硬件证明密钥（光看请求不够）。
fn validate_native_attestation_characteristics(
    characteristics: &[KeyCharacteristics],
    service: &'static str,
) -> Result<()> {
    use crate::android::hardware::security::keymint::KeyParameterValue::KeyParameterValue;
    use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
    use crate::android::hardware::security::keymint::Tag::Tag;
    let expected = if service == SYSTEM_KEYMINT_STRONGBOX {
        SecurityLevel::STRONGBOX
    } else {
        SecurityLevel::TRUSTED_ENVIRONMENT
    };
    let attest_only = characteristics
        .iter()
        .filter(|entry| entry.securityLevel == expected)
        .flat_map(|entry| &entry.authorizations)
        .filter(|param| param.tag == Tag::PURPOSE)
        .map(|param| &param.value)
        .eq([&KeyParameterValue::KeyPurpose(KeyPurpose::ATTEST_KEY)]);
    if !attest_only {
        bail!("HAL did not authorize an exclusive hardware ATTEST_KEY");
    }
    Ok(())
}

/// 把父链拼到子证书后面（幂等；链不一致直接报错，不猜）。
fn append_issuer_chain(chain: &mut Vec<Vec<u8>>, parent: &[Vec<u8>]) -> Result<()> {
    if chain.is_empty() || parent.is_empty() {
        bail!("delegated certificate missing");
    }
    if chain.len() == 1 {
        chain.extend_from_slice(parent);
    } else if chain[1..] != *parent {
        bail!("unexpected delegated chain");
    }
    Ok(())
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

    // 用途原样下发（含 ATTEST_KEY）。
    //
    // 真机实测（2026-10-23，高通 sun/pineapple/taro/canoe/kalama、MTK mt6985/mt6991、
    // Kirin）：**独占 ATTEST_KEY 是能铸的**，返回 purposes=[ATTEST_KEY]、
    // Key Usage = Certificate Sign；只有 ATTEST_KEY+SIGN 同时要才回
    // `-3 INCOMPATIBLE_PURPOSE`（历史注释里那句「qti 拒绝 ATTEST_KEY」其实说的
    // 是这个混合形状）。以前把 ATTEST_KEY 翻成 SIGN 再补一个 SIGN，等于把「证明密钥」
    // 换成一把普通签名密钥：链上看不到硬件 ATTEST_KEY 授权，调用方拿它当签发密钥
    // 也只能走远程 SIGN 代签（真机恒被拒），所以那条路必须停掉。
    let is_attest_key = spec.purposes.contains(&KmKeyPurpose::AttestKey);
    let mut purposes = spec.purposes.clone();
    // DECRYPT 只在调用方真要求解密时才出现（RSA 加密类的 padding 说明它要
    // decrypt）。之前无条件给每把 RSA key 都补一个 DECRYPT，导致同一次认证里
    // RSA 叶子的授权列表比 EC 多一项 —— 检测方拿这个判
    // `hardware.attestation.algorithm_differential`。调用方要解密时本来就带着
    // DECRYPT purpose，这一补只是兜底。
    if algo == KmAlgorithm::Rsa
        && !purposes.contains(&KmKeyPurpose::Decrypt)
        && spec
            .paddings
            .iter()
            .any(|p| matches!(p, KmPadding::RsaOaep | KmPadding::RsaPkcs115Encrypt))
    {
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

    // 认证/授权列表：把调用方请求的策略**原样**下发给真 TEE。
    //
    // 以前这里一律只给一个 `NO_AUTH_REQUIRED`：因为 relay 签名给不出
    // HardwareAuthToken，带 502/504 的 key 在 begin(SIGN) 会回 -26。可那是拿
    // 「证书撒谎」换「操作能过」—— 请求要的是认证绑定，叶子却写着免认证，
    // 检测方一眼就看出 `user_auth_metadata` / `user_auth_policy` 对不上，
    // 顺便还把 USER_AUTH_TYPE 这类元信息抹掉了。
    //
    // 现在：请求里没有 502/503/504 才补一个 `NO_AUTH_REQUIRED`；有就照发（含
    // 505~509）、未知 tag 直接报错，不降级成不设限的 key。代价是认证绑定的 key
    // 在 B 上做硬件操作仍可能被拒（B 验不了 A 的 token）—— 那是明确失败，
    // 比伪造链诚实。要回到旧行为可以给 relay.conf 设
    // `OMMEGA_RELAY_USER_AUTH=force_no_auth`。
    params.extend(relay_authorization_params(&spec.user_auth)?);

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
            // 证明密钥不再靠本进程代签，所以也不再为它偷塞 PKCS1v15Sign：
            // 调用方要什么 padding 就发什么，否则叶子的授权列表比请求多一项。
            let _ = is_attest_key;
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
    // 真 TEE 只肯证明**本机自己的** ID：拿调用方（A 端那台手机）的值去问，HAL 一律
    // 回 `CannotAttestIds`（-66），整笔就掉到服务端密钥层。所以这里把值换成 B 自己
    // 那套：能读到的（brand/device/product/manufacturer/model/serial）用本机属性，
    // 读不到的（IMEI/MEID/第二 IMEI）**不发** —— 少一项好过发个假值让 HAL 拒掉整笔。
    if !spec.attestation_ids.is_empty() {
        for (tag, _requested) in &spec.attestation_ids {
            if let Some(param) = local_attestation_id_param(*tag) {
                params.push(param);
            }
        }
    }

    // User-authentication / authorization-list entries. A real TEE is the
    // authority on these: it validates `USER_AUTH_TYPE`/`AUTH_TIMEOUT`, retains
    // `USER_SECURE_ID` inside the key blob (never in the attestation) and
    // stamps 504/505 — but not 503 NO_AUTH_REQUIRED — into the leaf. Without
    // them the minted chain contradicts an auth-bound request (TrustAttestor:
    // `hardware.attestation.user_auth_metadata` / `user_auth_policy`).
    // Authorization tags 已在上面统一下发（`relay_authorization_params`），这里不再重复。

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

/// 本机自己的 ID 证明值（真 TEE 只肯签自己的）。
///
/// 拿不到的值（IMEI/MEID/第二 IMEI 这类不落在系统属性里的）返回 `None`，
/// 调用方据此跳过该 tag。
pub fn local_attestation_id_param(tag: u32) -> Option<KeyParam> {
    let value = match tag {
        710 => device_prop("ro.product.brand"),
        711 => device_prop("ro.product.device"),
        712 => device_prop("ro.product.name").or_else(|| device_prop("ro.product.product")),
        713 => device_prop("ro.serialno"),
        716 => device_prop("ro.product.manufacturer"),
        717 => device_prop("ro.product.model"),
        _ => None,
    }?
    .into_bytes();
    if value.is_empty() {
        return None;
    }
    Some(match tag {
        710 => KeyParam::AttestationIdBrand(value),
        711 => KeyParam::AttestationIdDevice(value),
        712 => KeyParam::AttestationIdProduct(value),
        713 => KeyParam::AttestationIdSerial(value),
        716 => KeyParam::AttestationIdManufacturer(value),
        717 => KeyParam::AttestationIdModel(value),
        _ => return None,
    })
}

/// 读一个系统属性（`getprop`），空值当拿不到。
pub fn device_prop(key: &str) -> Option<String> {
    let out = std::process::Command::new("getprop")
        .arg(key)
        .output()
        .ok()?;
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
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
/// 远程代理模型下 relay 永远拿不到 A 端的 auth token，B 端真 TEE 锐的 key
/// 必须一律 no-auth，否则 begin(SIGN) 返回 -26 (KeyUserNotAuthenticated)。
/// App 带来的 502/504/505 只留在 A 端 keyblob / Keystore2 里做指纹校验，
/// 不再往下传给真 TEE——否则证书说“要认证”，签名又给不出 token，死锁。
/// 组装下发真 TEE 的认证/授权 tag。
///
/// 默认：请求里**没有** 502/503/504（也就是压根没提认证策略）才补一个
/// `NO_AUTH_REQUIRED`；有就按原 tag 照发（含 505~509），未知 tag 报错——
/// 不降级成不设限的 key，也不悄悄把认证绑定的 key 改成免认证（叶子会撒谎）。
///
/// 代价：带 502 的 key 在本机 begin(SIGN) 会因拿不到 token 回 -26。想让
/// 认证绑定的 key 在 B 上照旧能用（老行为，叶子写 NO_AUTH_REQUIRED），给
/// relay.conf 设 `OMMEGA_RELAY_USER_AUTH=force_no_auth`。
fn relay_authorization_params(user_auth: &[(u32, i64)]) -> Result<Vec<KeyParam>> {
    let force_no_auth = std::env::var("OMMEGA_RELAY_USER_AUTH")
        .map(|value| value.trim().eq_ignore_ascii_case("force_no_auth"))
        .unwrap_or(false);
    let auth_bound = user_auth.iter().any(|(tag, _)| matches!(*tag, 502..=504));
    let mut params = Vec::with_capacity(user_auth.len() + 1);
    if force_no_auth || !auth_bound {
        params.push(KeyParam::NoAuthRequired);
    }
    if !force_no_auth {
        for (tag, value) in user_auth {
            let param = user_auth_param(*tag, *value)?;
            if !params.contains(&param) {
                params.push(param);
            }
        }
    }
    Ok(params)
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
    let (out, upgraded) = run_single_input_op(
        &session.key_blob,
        session.hal_service,
        KeyPurpose::SIGN,
        &op_params,
        data,
    )?;
    persist_upgraded_blob(alias, session, upgraded);
    Ok(out)
}

/// Decrypts `data` with the TEE key for `alias`.
pub fn decrypt(alias: &str, data: &[u8], algorithm: &str) -> Result<Vec<u8>> {
    let session = session_get(alias)?;
    let op_params = decrypt_begin_params(algorithm, session.algorithm)
        .with_context(|| ks_err!("unsupported decrypt algorithm {algorithm}"))?;
    let (out, upgraded) = run_single_input_op(
        &session.key_blob,
        session.hal_service,
        KeyPurpose::DECRYPT,
        &op_params,
        data,
    )?;
    persist_upgraded_blob(alias, session, upgraded);
    Ok(out)
}

/// ECDH agreement (`data` = peer public key, X.509 SubjectPublicKeyInfo DER).
/// Runs begin(AGREE_KEY) + update(peer) + finish on the real TEE.
pub fn agree(alias: &str, data: &[u8], _algorithm: &str) -> Result<Vec<u8>> {
    let session = session_get(alias)?;
    if !matches!(session.algorithm, KeyAlgorithm::EcP256) {
        return Err(anyhow!("ECDH needs an EC key, alias {alias} is RSA"));
    }
    let params = vec![KeyParam::Purpose(KmKeyPurpose::AgreeKey)];
    let op_params = key_params_to_aidl(&params, KEY_MINT_V5)
        .with_context(|| ks_err!("encode agree begin parameters"))?;
    let (out, upgraded) = run_single_input_op(
        &session.key_blob,
        session.hal_service,
        KeyPurpose::AGREE_KEY,
        &op_params,
        data,
    )?;
    persist_upgraded_blob(alias, session, upgraded);
    Ok(out)
}

/// TEE 把 blob 升过级就换掉会话里那份：下次 begin 直接用新的，不用每次都升。
/// 证书链、算法、HAL 名都不动 —— 升级只改 blob 里的版本/补丁级别记录。
fn persist_upgraded_blob(alias: &str, mut session: TeeSession, upgraded: Option<Vec<u8>>) {
    let Some(blob) = upgraded else { return };
    session.key_blob = blob;
    session_put(alias, session);
    log::info!("alias {alias}: key blob 已按 KEY_REQUIRES_UPGRADE 升级并写回会话");
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

/// `KEY_REQUIRES_UPGRADE`：blob 里记的 OS/VENDOR/BOOT patchlevel 跟本机当前值不一样时
/// TEE 就是回这个。B 端建料时带的是改写过的补丁日期（为了链上的日期好看），所以这把
/// key 天生「版本不一致」，不升级的话每一笔签名都卡在 begin。
const KM_ERROR_KEY_REQUIRES_UPGRADE: i32 = -62;

/// 返回 (操作结果, 升级后的 key blob)。第二项是 Some 时调用方要把新 blob 写回会话，
/// 否则同一把 key 每签一次都要先升一次。
fn run_single_input_op(
    key_blob: &[u8],
    hal_service: &'static str,
    purpose: KeyPurpose,
    op_params: &[KmKeyParameter],
    input: &[u8],
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let keymint = get_system_keymint(hal_service)
        .with_context(|| ks_err!("real keymint {hal_service} connect failed"))?;

    let mut upgraded: Option<Vec<u8>> = None;
    let begin = match keymint.begin(purpose, key_blob, op_params, None) {
        Ok(result) => result,
        Err(status) if extract_km_error_code(&status) == Some(KM_ERROR_KEY_REQUIRES_UPGRADE) => {
            // AIDL 的既定流程：先 upgradeKey 换一份新格式的 blob，再用它重试。
            let fresh = keymint.upgradeKey(key_blob, &[]).map_err(|status| {
                let km_code = km_error_suffix(&status);
                anyhow!("real keymint {hal_service} upgradeKey failed {km_code}: {status}")
            })?;
            let retry = keymint
                .begin(purpose, &fresh, op_params, None)
                .map_err(|status| {
                    if is_dead_object_status(&status) {
                        clear_system_keymint(hal_service);
                    }
                    let km_code = km_error_suffix(&status);
                    anyhow!(
                        "real keymint {hal_service} begin after upgrade failed {km_code}: {status}"
                    )
                })?;
            upgraded = Some(fresh);
            retry
        }
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
    Ok((result?, upgraded))
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
    use std::time::Duration;

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

    /// 请求里没提认证策略时才补一个 `NO_AUTH_REQUIRED`；提了（502/503/504）就照发，
    /// 不再偷偷改成免认证。
    #[test]
    fn relay_adds_no_auth_required_only_when_the_app_is_silent() {
        for user_auth in [vec![], vec![(506, 1)], vec![(509, 1)], vec![(505, 30_000)]] {
            assert_eq!(
                relay_authorization_params(&user_auth).unwrap(),
                vec![KeyParam::NoAuthRequired]
            );
        }
        // 只带 509 的请求：补 503 之外仍保留 509
        assert_eq!(
            relay_authorization_params(&[(509, 1)]).unwrap(),
            vec![KeyParam::NoAuthRequired, KeyParam::UnlockedDeviceRequired]
        );
    }

    /// 认证绑定的请求原样下发给真 TEE（含 502/504/505/506/507/508/509）。
    #[test]
    fn auth_bound_requests_keep_their_policy() {
        assert_eq!(
            relay_authorization_params(&[(502, 4242), (504, 3), (505, 0)]).unwrap(),
            vec![
                KeyParam::UserSecureId(4242),
                KeyParam::UserAuthType(3),
                KeyParam::AuthTimeout(0),
            ]
        );
        assert_eq!(
            relay_authorization_params(&[
                (502, 4242),
                (504, 2),
                (506, 1),
                (507, 1),
                (508, 1),
                (509, 1),
            ])
            .unwrap(),
            vec![
                KeyParam::UserSecureId(4242),
                KeyParam::UserAuthType(2),
                KeyParam::AllowWhileOnBody,
                KeyParam::TrustedUserPresenceRequired,
                KeyParam::TrustedConfirmationRequired,
                KeyParam::UnlockedDeviceRequired,
            ]
        );
        // 显式 503 不会和自动补的那个重复。
        assert_eq!(
            relay_authorization_params(&[(503, 1)]).unwrap(),
            vec![KeyParam::NoAuthRequired]
        );
    }

    /// 未知 tag 报错，绝不降级成不设限的 key。
    #[test]
    fn unknown_auth_tags_fail_instead_of_becoming_unrestricted() {
        assert!(relay_authorization_params(&[(510, 1)]).is_err());
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
