//! `server_keybox` mode: intercept A-side requests and fulfil them locally
//! using the stored DeviceServerIdentity (private key + certificate chain).
//!
//! Mirrors `relay_server/apps/portal/server_fulfill.py`:
//!   - sessions: device_id -> alias -> (chain_b64, leaf_key_pem, challenge, key_fp, ts)
//!   - try_handle_* return `Some(Value)` when fulfilled, `None` to fall back to
//!     the physical (A/B queue) path.

use base64::Engine;
use chrono::Utc;
use p256::ecdsa::{DerSignature as P256DerSignature, Signature as P256Signature};
use p384::ecdsa::{DerSignature as P384DerSignature, Signature as P384Signature};
use p521::ecdsa::{DerSignature as P521DerSignature, Signature as P521Signature};
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use crate::cert::{self, AttestationParams, RootOfTrust};
use crate::db::{Db, DeviceIdentity};

/// AOSP keymint::kMaxChallengeSize = 128 bytes.
/// Attestation challenges larger than this are rejected to avoid
/// triggering Duck-Detector's OversizedChallengeProbe.
const MAX_CHALLENGE_SIZE: usize = 128;

const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// 自动源（public 采集）专用的槽位 device id。某台设备一份身份都没存过的时候
/// 用它的材料顶上，别掉到 self_signed 那条一眼假的自签链。
const AUTO_PUBLIC_SLOT: &str = "device-b-2";

/// 距上次顶过「最后使用」多久才值得再顶一次。TTL/LRU 判的是小时级窗口，差几分钟
/// 无所谓；这条节流把「每签一次就写一次库」压成每个 alias 五分钟最多一次。
const SESSION_TOUCH_MIN_MS: u64 = 5 * 60 * 1000;

/// 会话表过期清理的节流间隔。清理是 O(会话数) 的，几千条的表在每个 sign /
/// decrypt 请求上都扫一遍纯属浪费；隔一分钟清一次就够，反正过期会话在查表
/// 时本来也拿不到东西。
const PURGE_INTERVAL_MS: u64 = 60 * 1000;

static LAST_PURGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 「超上限但没东西可删」这条告警上次打的时间，用来自助限频。
static SESSION_CAP_REPORTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
///
/// 落盘在 `sessions` 表（见 `crate::statedb`）。旧的 `data/sessions.json` 只在库
/// 里是空的时候导一次，导完原样留着当回滚源，之后不再往里写。
#[derive(Debug, Clone)]
struct Session {
    chain_pem: String,
    leaf_key_pem: String,
    /// 解析好的叶子私钥，惰性缓存。以前每次 sign/decrypt 都现 `parse_leaf_key`
    /// （PEM 框架 + EC/RSA 大整数解码），高频时纯属白烧 CPU，而这整段时间都在
    /// A 端那柄全局锁的占用窗口里。Arc 让 Session 被 clone 出去后仍共享同一份。
    cached_key: Arc<OnceLock<Arc<LeafKey>>>,
    /// 落盘用的 Fernet 密文。构造时算一次、之后每轮写盘直接复用 —— 以前是
    /// 每写一次盘就把表里所有会话重新加密一遍，几千条就是几百毫秒，还全程
    /// 持着全局锁。
    leaf_key_cipher: String,
    created_epoch_ms: u64,
    /// 最后一次被取用的时间。TTL 和 LRU 都按它算：创建早不等于该丢，一直有人用
    /// 的会话就得一直留着（B 端那把 `no key for alias` 就是这么坏的）。
    used_epoch_ms: u64,
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
    /// 老落盘格式没有这一列，读回来时缺省 0，由调用方拿创建时间顶上。
    #[serde(default)]
    used_epoch_ms: u64,
}

impl From<&Session> for SessionFile {
    fn from(s: &Session) -> Self {
        SessionFile {
            chain_pem: s.chain_pem.clone(),
            // 非空由 put_session / From<SessionFile> 保证；万一走了别的路子才现加。
            leaf_key_pem: if s.leaf_key_cipher.is_empty() {
                crate::crypto::encrypt_private_pem(&s.leaf_key_pem)
            } else {
                s.leaf_key_cipher.clone()
            },
            created_epoch_ms: s.created_epoch_ms,
            used_epoch_ms: s.used_epoch_ms,
        }
    }
}

impl From<SessionFile> for Session {
    fn from(sf: SessionFile) -> Self {
        let cipher = sf.leaf_key_pem.clone();
        let used = if sf.used_epoch_ms == 0 {
            sf.created_epoch_ms
        } else {
            sf.used_epoch_ms
        };
        Session {
            chain_pem: sf.chain_pem,
            leaf_key_pem: crate::crypto::decrypt_private_pem(&sf.leaf_key_pem),
            cached_key: Arc::new(OnceLock::new()),
            leaf_key_cipher: cipher,
            created_epoch_ms: sf.created_epoch_ms,
            used_epoch_ms: used,
        }
    }
}

impl Session {
    /// 取解析好的叶子私钥，第一次用时解析并缓存。
    fn leaf_key(&self) -> anyhow::Result<Arc<LeafKey>> {
        if let Some(k) = self.cached_key.get() {
            return Ok(k.clone());
        }
        let parsed = Arc::new(parse_leaf_key(&self.leaf_key_pem)?);
        // 并发下可能别人先塞了，谁先谁算，反正同一份 PEM 解析结果一样。
        let _ = self.cached_key.set(parsed.clone());
        Ok(self.cached_key.get().cloned().unwrap_or(parsed))
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
    /// One generation gate per logical alias, shared across device/request
    /// snapshots and fallback layers. Weak entries do not retain idle gates.
    attest_gates: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    /// Cache of generated self-signed identities per (device_id, algorithm) so
    /// a device without a stored identity doesn't regenerate a fresh key (RSA
    /// keygen is slow) on every attestation.
    self_signed_cache: Mutex<HashMap<(String, String), DeviceIdentity>>,
    pub db: Option<Arc<Db>>,
    /// 要长期保留的状态全在这一个 SQLite 文件里（会话语义今天还是内存 map 权威，
    /// 这里只做写穿 + 启动装载）。
    state: Arc<crate::statedb::StateDb>,
}

impl Fulfill {
    /// 运行期开关在 statedb 里的键。
    const MODE_KEY: &'static str = "serverbox";

    pub fn new(enabled: bool, db: Option<Arc<Db>>) -> Arc<Self> {
        let state = crate::statedb::shared();
        // 界面切过的值优先于启动配置：不然一次重启就又退回 .env 里的启动值（2026-10-17 踩过）。
        let enabled = match state.get_meta(Self::MODE_KEY) {
            Ok(Some(v)) => v == "1",
            Ok(None) => enabled,
            Err(e) => {
                tracing::warn!("fulfill: 读持久化开关失败，用启动配置: {e:#}");
                enabled
            }
        };
        let f = Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            enabled: AtomicBool::new(enabled),
            attest_gates: Mutex::new(HashMap::new()),
            self_signed_cache: Mutex::new(HashMap::new()),
            db,
            state,
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
        // 写穿到 statedb：重启后按它恢复，而不是回到 .env 里的启动值。
        if let Err(e) = self
            .state
            .set_meta(Self::MODE_KEY, if on { "1" } else { "0" })
        {
            tracing::warn!("fulfill: 持久化开关失败: {e:#}");
        }
    }

    fn session_expired(s: &Session) -> bool {
        Self::session_expired_at(s, Utc::now().timestamp_millis() as u64)
    }

    fn session_expired_at(s: &Session, now_ms: u64) -> bool {
        now_ms.saturating_sub(s.used_epoch_ms) > SESSION_TTL.as_millis() as u64
    }

    /// 内存只留「热」的一批（按最后使用从新到旧）。超出的从 map 里删掉就行 ——
    /// 库里那条还在，下次真用到再按 alias 单查回来（见 `get_session`）。
    fn enforce_memory_cap(map: &mut HashMap<String, Session>) {
        while map.len() > crate::statedb::SESSION_MEMORY_HOT {
            let oldest = map
                .iter()
                .min_by_key(|(_, s)| s.used_epoch_ms)
                .map(|(alias, _)| alias.clone());
            match oldest {
                Some(alias) => {
                    map.remove(&alias);
                }
                None => break,
            }
        }
    }

    /// 过期会话在库里也按条件删掉（原来得把 74 MB 整份重写一遍才删得掉）；
    /// 顺手把库里的条数也按 LRU 压到上限。
    fn purge_if_due(&self, map: &mut HashMap<String, Session>) {
        let now_ms = Utc::now().timestamp_millis() as u64;
        let last = LAST_PURGE.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < PURGE_INTERVAL_MS {
            return;
        }
        LAST_PURGE.store(now_ms, Ordering::Relaxed);
        map.retain(|_, s| !Self::session_expired_at(s, now_ms));
        let cutoff_ms = now_ms.saturating_sub(SESSION_TTL.as_millis() as u64) as i64;
        match self.state.delete_sessions_expired_before(cutoff_ms) {
            Ok(0) => {}
            Ok(n) => tracing::info!("sessions: 库里清掉 {n} 条过期会话"),
            Err(e) => tracing::warn!("sessions: 库里清过期会话失败：{e:#}"),
        }
        let cap = crate::statedb::SESSION_MAX;
        match self
            .state
            .trim_sessions_lru(cap, crate::statedb::SESSION_EVICT_MIN_IDLE_MS)
        {
            Ok(0) => {}
            Ok(n) => tracing::info!(
                "sessions: 库里按 LRU 淘汰 {n} 条闲置会话（上限 {cap}，只动闲置超 3 天的）"
            ),
            Err(e) => tracing::warn!("sessions: 库里按 LRU 淘汰失败：{e:#}"),
        }
        // 超上限但全是活跃会话时，上一行是 0 —— 得能看出来现在到底多少条。
        // 隔一小时才报一次，不刷屏。
        if let Ok(count) = self.state.session_count() {
            if count > cap
                && now_ms.saturating_sub(SESSION_CAP_REPORTED.swap(now_ms, Ordering::Relaxed))
                    > 3_600_000
            {
                tracing::warn!(
                    "sessions: 库里有 {count} 条会话，超过上限 {cap}，但没有可淘汰的闲置会话（宁可超限也不动在用的）"
                );
            }
        }
    }

    fn touch_persisted(&self, alias: &str, now_ms: u64) {
        if let Err(e) = self.state.touch_session(alias, now_ms as i64) {
            tracing::debug!("sessions: {alias} 的最后使用没顶进库：{e:#}");
        }
    }

    /// 启动时从库里把「最近用过的」一批会话装进内存（过期的不装）。
    ///
    /// 内存是热缓存、库是权威：只装 `SESSION_MEMORY_HOT` 条，冷的那批留在库里，
    /// 取用时按 alias 单查（见 `get_session`）。旧的 `data/sessions.json` 由
    /// `statedb` 导一次，这里只认库。
    fn load_sessions(&self) {
        let rows = match self
            .state
            .load_hot_sessions(crate::statedb::SESSION_MEMORY_HOT)
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!("sessions: state db 读不出来（{e:#}）—— 这次当没有会话");
                return;
            }
        };
        let mut inner = crate::util::mu(&self.inner);
        for (alias, row) in rows {
            inner.sessions.insert(
                alias,
                Session::from(SessionFile {
                    chain_pem: row.chain_pem,
                    leaf_key_pem: row.leaf_key_pem,
                    created_epoch_ms: row.created_epoch_ms,
                    used_epoch_ms: row.used_epoch_ms,
                }),
            );
        }
        let now_ms = Utc::now().timestamp_millis() as u64;
        inner
            .sessions
            .retain(|_, s| !Self::session_expired_at(s, now_ms));
        Self::enforce_memory_cap(&mut inner.sessions);
    }

    /// 落一条会话：一条 INSERT。
    ///
    /// 原来是「把所有会话收集一遍、序列化、整份重写」—— 实测 11714 条 / 73.9 MB，
    /// 而出证约 400 次/天，也就是 25~30 GB/天的写放大，就为了每条多出来的一行。
    fn persist_session(&self, alias: &str, session: &Session) {
        let row = crate::statedb::SessionRow {
            chain_pem: session.chain_pem.clone(),
            // 密文在 put_session 算过一次，这里直接复用；万一没算过就现加。
            leaf_key_pem: SessionFile::from(session).leaf_key_pem,
            created_epoch_ms: session.created_epoch_ms,
            used_epoch_ms: session.used_epoch_ms,
        };
        if let Err(e) = self.state.upsert_session(alias, &row) {
            // 写不进去就等于重启后 A 端那些 `KeyMaterial::Remote` 的钥匙全废，
            // 跟原来“静默丢文件”一样严重，所以是 error 不是 warn。
            tracing::error!("sessions: {alias} 没写进 state db：{e:#}");
        }
    }

    /// 取一条会话：先内存热缓存，没命中再回库单查一条。
    ///
    /// 库里热的那批在启动时装进内存；别的那批（长期没人用的）不占内存，用到
    /// 了再查回来 —— 内存就永远顶不爆。取一次就把「最后使用」顶一下（内存每次
    /// 都顶，库里节流到 `SESSION_TOUCH_MIN_MS`），TTL 与 LRU 都吃这个时间。
    fn get_session(&self, alias: &str) -> Option<Session> {
        let now_ms = Utc::now().timestamp_millis() as u64;
        let cached = {
            let mut inner = crate::util::mu(&self.inner);
            self.purge_if_due(&mut inner.sessions);
            if inner
                .sessions
                .get(alias)
                .is_some_and(|s| Self::session_expired_at(s, now_ms))
            {
                inner.sessions.remove(alias);
            }
            inner.sessions.get_mut(alias).map(|s| {
                let stale = now_ms.saturating_sub(s.used_epoch_ms) >= SESSION_TOUCH_MIN_MS;
                if stale {
                    s.used_epoch_ms = now_ms;
                }
                (s.clone(), stale)
            })
        };
        if let Some((session, stale)) = cached {
            if stale {
                self.touch_persisted(alias, now_ms);
            }
            return Some(session);
        }

        let row = match self.state.get_session_row(alias) {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!("sessions: 库里查 {alias} 失败：{e:#}");
                return None;
            }
        };
        let mut session = Session::from(SessionFile {
            chain_pem: row.chain_pem,
            leaf_key_pem: row.leaf_key_pem,
            created_epoch_ms: row.created_epoch_ms,
            used_epoch_ms: row.used_epoch_ms,
        });
        if Self::session_expired_at(&session, now_ms) {
            return None;
        }
        if now_ms.saturating_sub(session.used_epoch_ms) >= SESSION_TOUCH_MIN_MS {
            session.used_epoch_ms = now_ms;
            self.touch_persisted(alias, now_ms);
        }
        let mut inner = crate::util::mu(&self.inner);
        inner.sessions.insert(alias.to_string(), session.clone());
        Self::enforce_memory_cap(&mut inner.sessions);
        Some(session)
    }

    /// 忘掉一个 alias 的会话：B 端真机重新铸过同一个 alias（它那边才有对应的
    /// 私钥），我们手里这条跟 App 拿到的叶证书就不是一对儿了，留着只会签错。
    pub fn forget_session(&self, alias: &str) {
        let mut inner = crate::util::mu(&self.inner);
        inner.sessions.remove(alias);
        drop(inner);
        if let Err(e) = self.state.delete_session(alias) {
            tracing::warn!("sessions: 删 {alias} 没成功：{e:#}");
        }
    }

    fn put_session(&self, alias: &str, mut s: Session) -> Session {
        // 密文在这里算一次，之后每轮落盘都直接复用（见 persist_session）。
        s.leaf_key_cipher = crate::crypto::encrypt_private_pem(&s.leaf_key_pem);
        let now_ms = Utc::now().timestamp_millis() as u64;
        if s.created_epoch_ms == 0 {
            s.created_epoch_ms = now_ms;
        }
        if s.used_epoch_ms == 0 {
            s.used_epoch_ms = now_ms;
        }
        let mut inner = crate::util::mu(&self.inner);
        self.purge_if_due(&mut inner.sessions);
        // First successful publication wins, even if a caller bypasses the gate.
        if let Some(existing) = inner
            .sessions
            .get(alias)
            .filter(|s| !Self::session_expired(s))
        {
            return existing.clone();
        }
        inner.sessions.insert(alias.to_string(), s.clone());
        Self::enforce_memory_cap(&mut inner.sessions);
        s
    }

    /// Serialize check -> generate -> publish for the alias, not globally.
    /// A cancelled HTTP waiter cannot cancel its spawn_blocking worker: retries
    /// must wait for that worker and reuse its key instead of replacing it.
    /// Do not reject differing request snapshots (e.g. StrongBox -> TEE retry):
    /// failures are not cached; after success the alias's key/chain is immutable
    /// for the existing seven-day session lifetime. Attestation callers must
    /// validate the cached leaf algorithm before returning it.
    fn session_or_generate(
        &self,
        alias: &str,
        generate: impl FnOnce() -> anyhow::Result<Session>,
    ) -> anyhow::Result<(Session, bool)> {
        let gate = {
            let mut gates = crate::util::mu(&self.attest_gates);
            gates.retain(|_, gate| gate.strong_count() > 0);
            if let Some(gate) = gates.get(alias).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(Mutex::new(()));
                gates.insert(alias.to_string(), Arc::downgrade(&gate));
                gate
            }
        };
        let _guard = crate::util::mu(&gate);
        if let Some(session) = self.get_session(alias) {
            return Ok((session, false));
        }
        let session = self.put_session(alias, generate()?);
        Ok((session, true))
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

    /// Lookup a stored identity for `(device_id, algorithm)`.
    ///
    /// 顺序：`prefer_slot`（这次请求是被黑名单打下来的）时先槽位 `device-b-2`，
    /// 再按请求的 device id；都不是就挑一条能用的（见 `identity_for_id` /
    /// `get_any_usable_identity`）。serverbox 模式的正常流程和普通失败后的
    /// 兜底回落都不传 `prefer_slot`，就是「先按请求的 id」。
    ///
    /// 身份按**设备**选、不按算法选。一台真设备的 EC / RSA 两条认证用的是同一份
    /// keybox 链，两次各取一行不同身份会让中间证书 / 签发者不一样 —— 检测方报的
    /// `hardware.attestation.algorithm_differential` 就是这么来的。叶子用哪种算法
    /// 与签发者的密钥类型无关，一份身份可以同时铸 EC 和 RSA 叶子。
    ///
    /// `algorithm` 只用在退一步的那条查询上（整台设备的行都不 active 时）。
    fn identity_for(
        &self,
        device_id: &str,
        algorithm: &str,
        prefer_slot: bool,
    ) -> Option<DeviceIdentity> {
        if prefer_slot {
            // 「这次请求是被黑名单打下来的」：先看自动源（public 采集）的专用槽位
            // `device-b-2`，它没有才按请求里的设备 id 找。
            if let Some(id) = self.identity_for_id(AUTO_PUBLIC_SLOT, algorithm) {
                tracing::info!(
                    "server_keybox: device={device_id} 命中黑名单，先取槽位 {AUTO_PUBLIC_SLOT}（machine_id={}）",
                    id.machine_id
                );
                return Some(id);
            }
        }
        if let Some(id) = self.identity_for_id(device_id, algorithm) {
            return Some(id);
        }
        // 都没有就挑一条能用的顶上。自动采集的那些优先 —— 它们本来就是给所有设备
        // 共用的；手动上传 / 真机自己传上来的那份是人家的真身份，只当最后手段。
        match self.db.as_ref()?.get_any_usable_identity() {
            Ok(Some(id)) => {
                tracing::info!(
                    "server_keybox: device={device_id} 找不到身份，改用 {} 的（machine_id={}）",
                    id.device_id,
                    id.machine_id
                );
                Some(id)
            }
            _ => None,
        }
    }

    /// 按设备 id 找一份存下的身份：先不挑算法（一台设备的 EC / RSA 两条算法本来就
    /// 共用同一份身份），再退到指定算法那条（处理整台设备的行都不 active 的情况）。
    fn identity_for_id(&self, device_id: &str, algorithm: &str) -> Option<DeviceIdentity> {
        let db = self.db.as_ref()?;
        if let Some(id) = db.get_any_device_identity(device_id).ok().flatten() {
            return Some(id);
        }
        db.get_device_identity_by_id(device_id, algorithm)
            .ok()
            .flatten()
    }

    /// Parse the A-side `device_attest_context` object into AttestationParams.
    fn parse_ctx(&self, ctx: &Value, challenge: &[u8], device_id: &str) -> AttestationParams {
        let mut p = AttestationParams {
            challenge: challenge.to_vec(),
            ..Default::default()
        };
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
        // KeyMint 3.0+ per-partition patch levels (tags 718/719) and the RSA
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
        // Device properties / ID attestation (710..=717, plus 723 for the second
        // IMEI), forwarded by the A-side as `[tag, base64(value)]` pairs. A real
        // device includes these in
        // the leaf's tee-enforced list whenever the caller asked for them, so
        // dropping them here is what makes a server-minted chain look like it has
        // no device properties at all (TrustAttestor:
        // `hardware.attestation.device_properties`).
        if let Some(pairs) = ctx.get("attestation_ids").and_then(Value::as_array) {
            p.attestation_ids = pairs
                .iter()
                .filter_map(|pair| {
                    let pair = pair.as_array()?;
                    let tag = u64::try_from(pair.first()?.as_i64()?).ok()?;
                    let value = base64::engine::general_purpose::STANDARD
                        .decode(pair.get(1)?.as_str()?)
                        .ok()?;
                    // 718 stays out: this path uses it for VENDOR_PATCHLEVEL.
                    // The second IMEI is 723 (`TagType.BYTES | 723`), not 718.
                    ((710..=717).contains(&tag) || tag == 723).then_some((tag, value))
                })
                .collect();
        }
        // User-authentication / authorization-list entries ([tag, value] pairs,
        // tags 502..=509) — the policy the app asked for. Dropping them is what
        // makes a server-minted leaf claim `NO_AUTH_REQUIRED` for an auth-bound
        // key (TrustAttestor: `hardware.attestation.user_auth_metadata` and
        // `hardware.attestation.user_auth_policy`). 502 is kept in the list so
        // the B-side layer can use it; `write_auth_list` skips it when writing
        // the leaf (AOSP emits the SID for `importWrappedKey()` only).
        if let Some(pairs) = ctx.get("user_auth").and_then(Value::as_array) {
            p.user_auth = pairs
                .iter()
                .filter_map(|pair| {
                    let pair = pair.as_array()?;
                    let tag = u64::try_from(pair.first()?.as_i64()?).ok()?;
                    let value = pair.get(1).and_then(Value::as_i64).unwrap_or(1);
                    matches!(tag, 502..=509).then_some((tag, value))
                })
                .collect();
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
        let inferred_version =
            ctx.get("os_version")
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

        // verified_boot_key / verified_boot_hash 应当是 32 字节。A 端没带、或者带过来的
        // 解不出 32 字节时，不要发全 0（看着像没锁，而且所有机器都是同一串 0），按
        // 「设备 + 当前年月日时」派生一个：同一小时里稳定，换小时才换。精确到分换得太勤，
        // 同一轮会话里前后两笔就对不上。
        let stamp = boot_value_stamp();
        let vb_key = match b64("verified_boot_key") {
            Some(k) if k.len() == 32 => k,
            _ => boot_value_seed(device_id, "bootkey", &stamp).to_vec(),
        };
        let vb_hash = match b64("verified_boot_hash") {
            Some(h) if h.len() == 32 => h,
            _ => boot_value_seed(device_id, "boothash", &stamp).to_vec(),
        };
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

    /// 请求带了证明密钥 `attestation_key`，但本层没有那把密钥的 session。
    ///
    /// 返回 `false` 表示：没带证明密钥（普通链），或者带了而且找得到（可以委派）。
    pub fn attest_issuer_missing(&self, ctx: &Value) -> bool {
        let Some(alias) = ctx
            .get("attestation_key")
            .and_then(|k| k.get("alias"))
            .and_then(Value::as_str)
        else {
            return false;
        };
        if alias.is_empty() {
            return false;
        }
        self.get_session(alias).is_none()
    }

    /// 找出请求指定的那把「服务端自持」的证明密钥。
    ///
    /// 返回 `Ok(None)` 表示这把 key 不在本端（在 B 端真机）—— 那时本层不该硬逞，
    /// 交给下一层用真 TEE 签。
    fn server_issuer(&self, ctx: &Value) -> anyhow::Result<Option<(String, String)>> {
        let Some(reference) = ctx.get("attestation_key") else {
            return Ok(None);
        };
        let Some(alias) = reference.get("alias").and_then(Value::as_str) else {
            anyhow::bail!("attestation_key.alias missing");
        };
        let subject = match reference.get("issuer_subject_name").and_then(Value::as_str) {
            Some(value) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|e| anyhow::anyhow!("decode issuer_subject_name: {e}"))?,
            ),
            None => None,
        };
        let Some(session) = self.get_session(alias) else {
            return Ok(None);
        };
        // 请求说的那把钥匙必须是这条 session 的叶子，否则不予委派。
        if let Some(subject) = subject {
            let ders = cert::parse_chain_pem(&session.chain_pem)?;
            let leaf = ders
                .first()
                .ok_or_else(|| anyhow::anyhow!("issuer session has no leaf"))?;
            let (_, parsed) = cert::parse_x509_certificate(leaf)
                .map_err(|e| anyhow::anyhow!("parse issuer leaf: {e}"))?;
            if parsed.subject().as_raw() != subject.as_slice() {
                anyhow::bail!("issuer subject mismatch for alias {alias}");
            }
        }
        Ok(Some((
            session.leaf_key_pem.clone(),
            session.chain_pem.clone(),
        )))
    }

    /// Generate the leaf + attested chain, cache it in the session.
    fn attest_and_cache(
        &self,
        identity: &DeviceIdentity,
        alias: &str,
        ctx: &Value,
        challenge: &[u8],
    ) -> anyhow::Result<(String, String)> {
        let params = self.parse_ctx(ctx, challenge, &identity.device_id);
        // 一条链只能有一个级别标签。链里的 CA 是 TEE 就全 TEE，是 StrongBox 就全
        // StrongBox；同时出现两种说明这份材料是拼的（比如 TEE 的中间 CA 配了
        // StrongBox 的根），发出去就是一条自己矛盾的链。只留痕，不拦请求。
        let tagged = cert::chain_security_levels(&identity.certificate_chain_pem);
        if tagged.len() > 1 {
            tracing::warn!(
                "attest_and_cache: device={} alias={alias} 链上标了多个级别 {tagged:?}，这份身份是拼的",
                identity.device_id
            );
        }
        // 调用方带了证明密钥（App AttestKey 委派）：若那把 key 就在本服务端
        // （serverbox 模式下的 session），就用它自己签发子证书；不在本端则交给
        // 下一层（真机 B），**不**改用身份自带的签发密钥冒充。
        let issuer = self.server_issuer(ctx)?;
        let (session, generated) = self.session_or_generate(alias, || {
            let (chain_pem, leaf_key_pem) = match &issuer {
                Some((issuer_key_pem, issuer_chain_pem)) => cert::build_attested_chain_with_issuer(
                    identity,
                    &params,
                    issuer_key_pem,
                    issuer_chain_pem,
                )?,
                None => cert::build_attested_chain(identity, &params)?,
            };
            let now_ms = Utc::now().timestamp_millis() as u64;
            Ok(Session {
                chain_pem,
                leaf_key_pem,
                cached_key: Arc::new(OnceLock::new()),
                leaf_key_cipher: String::new(),
                created_epoch_ms: now_ms,
                used_epoch_ms: now_ms,
            })
        })?;
        // Normal requests derive their alias from key parameters. Defend also
        // against legacy/duplicate aliases: never return or replace an existing
        // EC key for an RSA request (or vice versa).
        let cached_algorithm = match parse_leaf_key(&session.leaf_key_pem).map_err(|e| {
            anyhow::anyhow!("cached session for alias {alias}: invalid leaf key: {e}")
        })? {
            LeafKey::Ec(_) => cert::KM_ALG_EC,
            LeafKey::Rsa(_) => cert::KM_ALG_RSA,
        };
        anyhow::ensure!(
            cached_algorithm == params.algorithm,
            "cached session algorithm mismatch for alias {alias}: cached {}, requested {}; existing session preserved",
            if cached_algorithm == cert::KM_ALG_RSA { "RSA" } else { "EC" },
            if params.algorithm == cert::KM_ALG_RSA { "RSA" } else { "EC" }
        );
        if let Some(error) = cert::validate_identity_pem(&session.leaf_key_pem, &session.chain_pem)
        {
            anyhow::bail!("cached session for alias {alias}: invalid leaf key/chain: {error}; existing session preserved");
        }
        if generated {
            self.persist_session(alias, &session);
        }
        let chain_pem = session.chain_pem;
        let new_leaf_key_pem = session.leaf_key_pem;

        // 这份材料的形状是发出去就会被认出来的那种（老公开 keybox：中间证书
        // subject 是 serialNumber 在前）——真机出链不会长这样。修不了（见
        // `cert::RdnShape`），但日志里必须留下痕迹：客户端报
        // `cloud.attestation.subject_rdn_order` 时，对着这行就能知道是哪条链。
        let shape = cert::chain_rdn_shape(&chain_pem);
        if shape.is_legacy() {
            tracing::warn!(
                "attest_and_cache: device={} alias={alias} chain shape={} (serialNumber 在 title 之前，老公开 keybox 的指纹；真机是 device-like)",
                identity.device_id,
                shape.as_str()
            );
        }

        let key_fp = base64::engine::general_purpose::STANDARD
            .encode(Sha256::digest(new_leaf_key_pem.as_bytes()));
        tracing::info!(
            "attest_and_cache: device={} alias={alias} chain_certs={} leaf_fp={}",
            identity.device_id,
            cert::parse_chain_pem(&chain_pem)
                .map(|d| d.len())
                .unwrap_or(0),
            key_fp
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
    pub fn try_handle_attest(
        &self,
        device_id: &str,
        body: &Value,
        prefer_slot: bool,
    ) -> Option<Value> {
        let ctx = body
            .get("device_attest_context")
            .cloned()
            .unwrap_or(Value::Null);
        // 调用方指定了证明密钥，但本层没有那把密钥的 session（被淘汰、服务端重启
        // 过、或那把钥匙根本在真机那层）：本层**不能**用别的签发密钥偷偷铸一张
        // 普通链，那会让调用方的证明密钥和链脱钩。回一个带标记的错误，句柄层
        // 直接把它交给 A，A 再映射成 InvalidKeyBlob 让应用作废重建。
        if self.attest_issuer_missing(&ctx) {
            let alias = ctx
                .get("attestation_key")
                .and_then(|k| k.get("alias"))
                .and_then(Value::as_str)
                .unwrap_or("");
            tracing::info!(
                "server_keybox: attestation key {alias} has no session on this server; refusing to substitute another issuer"
            );
            return Some(json!({
                "error": format!(
                    "attestation issuer {alias} is not available on the server keybox layer"
                ),
                "relay_error_kind": "issuer_missing",
            }));
        }
        let algorithm = Self::ctx_algorithm_str(&ctx);
        // 控制台可以按安全级别钉死用哪份身份（StrongBox 一份、TEE 一份）。钉了就按钉的
        // 来，不再看这次请求的是哪台 B（也不走「黑名单先看槽位」那条）。
        let level = ctx
            .get("attestation_security_level")
            .and_then(Value::as_i64)
            .unwrap_or(1);
        let pinned = crate::identity_policy::device_for_level(level);
        let identity = if level >= 2 {
            // StrongBox 只认控制台钉死的那份。没钉、或钉的那份不在库里，就报错——
            // 不能退到 `identity_for` 的「随便一份能用身份」：那个池子里放的是源采集和
            // 真机 TEE 的材料，链上标的是 TEE / 软件，拿到 level=2 的请求上就是级别串了。
            let Some(id) = pinned.as_deref() else {
                tracing::warn!(
                    "server_keybox: level=2 请求没有钉死 StrongBox 身份，拒绝出链（请求 device={device_id}）"
                );
                return Some(json!({
                    "error": "server_keybox: strongbox identity is not pinned in the console",
                    "relay_error_kind": "strongbox_identity_unpinned",
                }));
            };
            tracing::info!(
                "server_keybox: level=2 按控制台指定用 StrongBox 身份 {id}（请求 device={device_id}）"
            );
            match self.identity_for_id(id, &algorithm) {
                Some(identity) => identity,
                None => {
                    return Some(json!({
                        "error": format!(
                            "server_keybox: no stored strongbox identity for {id} (algorithm {algorithm})"
                        ),
                        "relay_error_kind": "strongbox_identity_missing",
                    }));
                }
            }
        } else {
            let lookup_id = match pinned.as_deref() {
                Some(id) => {
                    tracing::info!(
                        "server_keybox: level={level} 按控制台指定用身份 {id}（请求 device={device_id}）"
                    );
                    id
                }
                None => device_id,
            };
            match self.identity_for(lookup_id, &algorithm, prefer_slot && pinned.is_none()) {
                Some(identity) => identity,
                None => {
                    return Some(json!({
                        "error": format!(
                            "server_keybox: no stored server identity for device {lookup_id} (algorithm {algorithm})"
                        )
                    }));
                }
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
            // 别把整个 session 表打出来：线上几百条会话，每一条被 warn 一次就是几十 KB，
            // 日志全被它撑满了（读日志时根本翻不动）。这里只要「内存里现在还热着几条」够定位。
            let hot = self.inner.lock().map(|g| g.sessions.len()).unwrap_or(0);
            tracing::warn!(
                "try_handle_sign: no session for device={device_id} alias={alias} hot_sessions={hot}"
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
        let Some(data) = body
            .get("data")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        else {
            return Some(json!({ "error": "server_keybox sign: missing or bad base64 data" }));
        };
        let algorithm = body
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or("SHA256withECDSA");
        let key = match s.leaf_key() {
            Ok(key) => key,
            Err(e) => {
                return Some(json!({
                    "error": format!("server_keybox sign: unusable leaf key: {e}")
                }))
            }
        };
        // session 在（上面已命中），这里失败就不能再当「本层不适用」：一降级到设备层
        // 只会拿到 `no key for alias`，把真正的原因（算法不支持 / 填充对不上）盖掉。
        let sig = match sign_data(&key, &data, algorithm) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::warn!(
                    "try_handle_sign: alias={alias} algorithm={algorithm} failed: {e:#}"
                );
                return Some(json!({
                    "error": format!("server_keybox sign failed for {algorithm}: {e:#}")
                }));
            }
        };
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
        // 没 session 才是真的「本层不管」，交给下一层。
        let s = self.get_session(&alias)?;
        let Some(data) = body
            .get("data")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        else {
            return Some(json!({ "error": "server_keybox decrypt: missing or bad base64 data" }));
        };
        let algorithm = body
            .get("algorithm")
            .and_then(Value::as_str)
            .unwrap_or("RSA/OAEP/SHA-256/MGF1-SHA1");
        let key = match s.leaf_key() {
            Ok(key) => key,
            Err(e) => {
                return Some(json!({
                    "error": format!("server_keybox decrypt: unusable leaf key: {e}")
                }))
            }
        };
        let plain = match decrypt_data(&key, &data, algorithm) {
            Ok(plain) => plain,
            Err(e) => {
                tracing::warn!(
                    "try_handle_decrypt: alias={alias} algorithm={algorithm} failed: {e:#}"
                );
                return Some(json!({
                    "error": format!("server_keybox decrypt failed for {algorithm}: {e:#}")
                }));
            }
        };
        let plain_b64 = base64::engine::general_purpose::STANDARD.encode(plain);
        // A-side reads `data` for decrypt (same field the B-side returns).
        Some(json!({
            "data": plain_b64,
            "source": "server_keybox",
        }))
    }

    /// ECDH against the session's leaf key. `data` is the peer public key in
    /// X.509 SubjectPublicKeyInfo DER; the result is the raw shared secret (the
    /// x coordinate), matching what KeyMint returns from finish(AGREE_KEY).
    pub fn try_handle_agree(&self, _device_id: &str, body: &Value) -> Option<Value> {
        let alias = body
            .get("alias")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // 没 session 就是本层不管，交给下一层。
        let s = self.get_session(&alias)?;
        let Some(data) = body
            .get("data")
            .and_then(Value::as_str)
            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
        else {
            return Some(json!({ "error": "server_keybox agree: missing or bad base64 data" }));
        };
        let key = match s.leaf_key() {
            Ok(key) => key,
            Err(e) => {
                return Some(json!({
                    "error": format!("server_keybox agree: unusable leaf key: {e}")
                }))
            }
        };
        match ecdh_shared_secret(&key, &data) {
            Ok(secret) => Some(json!({
                "secret": base64::engine::general_purpose::STANDARD.encode(secret),
                "source": "server_keybox",
            })),
            Err(e) => {
                tracing::warn!("try_handle_agree: alias={alias} failed: {e:#}");
                Some(json!({ "error": format!("server_keybox agree failed: {e:#}") }))
            }
        }
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

/// 和 `cert::KeyMaterial` 一样，RSA 私钥装箱，免得整个 enum 被它撑大。
enum LeafKey {
    Ec(cert::EcKey),
    Rsa(Box<RsaPrivateKey>),
}

impl std::fmt::Debug for LeafKey {
    /// 只标类型，不打印私钥（`EcKey` 自己没实现 Debug，也别为了日志把它引进来）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeafKey::Ec(_) => f.write_str("LeafKey::Ec(..)"),
            LeafKey::Rsa(_) => f.write_str("LeafKey::Rsa(..)"),
        }
    }
}

fn ecdh_shared_secret(key: &LeafKey, peer_spki: &[u8]) -> anyhow::Result<Vec<u8>> {
    match key {
        LeafKey::Ec(cert::EcKey::P256(sk)) => {
            use p256::pkcs8::DecodePublicKey;
            let peer = p256::PublicKey::from_public_key_der(peer_spki)
                .map_err(|e| anyhow::anyhow!("bad P-256 peer key: {e}"))?;
            let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        LeafKey::Ec(cert::EcKey::P384(sk)) => {
            use p384::pkcs8::DecodePublicKey;
            let peer = p384::PublicKey::from_public_key_der(peer_spki)
                .map_err(|e| anyhow::anyhow!("bad P-384 peer key: {e}"))?;
            let shared = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
            Ok(shared.raw_secret_bytes().to_vec())
        }
        LeafKey::Ec(_) => anyhow::bail!("ECDH is only wired for P-256/P-384 identities"),
        LeafKey::Rsa(_) => anyhow::bail!("ECDH needs an EC key, this identity is RSA"),
    }
}

fn parse_leaf_key(pem_data: &str) -> anyhow::Result<LeafKey> {
    // Reuse cert::parse_private_key so P-256/P-384/P-521 and RSA (PKCS#1/PKCS#8)
    // are all handled identically to the stored server identities.
    match cert::parse_private_key(pem_data.as_bytes())? {
        cert::KeyMaterial::Ec(ec) => Ok(LeafKey::Ec(ec)),
        cert::KeyMaterial::Rsa(rk) => Ok(LeafKey::Rsa(rk)),
    }
}

/// A 端转发过来的 `algorithm` 串里带的摘要。
///
/// 服务端这几条密钥是给 remote 模式兜底的，必须按**请求的真实算法**签/解：
/// `NONEwithECDSA` 的输入本身就是摘要（再哈希一层验签必挂），`SHA384withRSA`
/// 的 DigestInfo 前缀也跟 SHA-256 不一样。以前这里一律按曲线默认摘要算，
/// 于是 `NONEwithECDSA` 与任何非 SHA-256 的请求都静默算错。
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeafDigest {
    None,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl LeafDigest {
    fn from_algorithm(algorithm: &str) -> LeafDigest {
        let up = algorithm.to_ascii_uppercase();
        if up.contains("NONE") {
            LeafDigest::None
        } else if up.contains("SHA1") || up.contains("SHA-1") {
            LeafDigest::Sha1
        } else if up.contains("SHA224") || up.contains("SHA-224") {
            LeafDigest::Sha224
        } else if up.contains("SHA384") || up.contains("SHA-384") {
            LeafDigest::Sha384
        } else if up.contains("SHA512") || up.contains("SHA-512") {
            LeafDigest::Sha512
        } else {
            LeafDigest::Sha256
        }
    }
}

fn hash_with(digest: LeafDigest, data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use sha2::Digest as _;
    Ok(match digest {
        LeafDigest::None => data.to_vec(),
        LeafDigest::Sha1 => Sha1::digest(data).to_vec(),
        LeafDigest::Sha224 => sha2::Sha224::digest(data).to_vec(),
        LeafDigest::Sha256 => Sha256::digest(data).to_vec(),
        LeafDigest::Sha384 => sha2::Sha384::digest(data).to_vec(),
        LeafDigest::Sha512 => sha2::Sha512::digest(data).to_vec(),
    })
}

/// 按请求的算法签名。EC 一律走 `sign_prehash`（`NONE` 直接签摘要，其余先按请求
/// 摘要哈希一遍再签），RSA 的 PKCS#1/PSS 也跟着摘要走。
fn sign_data(key: &LeafKey, data: &[u8], algorithm: &str) -> anyhow::Result<Vec<u8>> {
    use ecdsa::signature::hazmat::PrehashSigner as _;
    let digest = LeafDigest::from_algorithm(algorithm);
    let up = algorithm.to_ascii_uppercase();
    match key {
        LeafKey::Ec(cert::EcKey::P224(sk)) => {
            let z = hash_with(digest, data)?;
            let signing_key = p224::ecdsa::SigningKey::from(sk);
            let sig: p224::ecdsa::Signature = signing_key.sign_prehash(&z)?;
            Ok(p224::ecdsa::DerSignature::from(sig).as_bytes().to_vec())
        }
        LeafKey::Ec(cert::EcKey::P256(sk)) => {
            let z = hash_with(digest, data)?;
            let signing_key = p256::ecdsa::SigningKey::from(sk);
            let sig: P256Signature = signing_key.sign_prehash(&z)?;
            Ok(P256DerSignature::from(sig).as_bytes().to_vec())
        }
        LeafKey::Ec(cert::EcKey::P384(sk)) => {
            let z = hash_with(digest, data)?;
            let signing_key = p384::ecdsa::SigningKey::from(ecdsa::SigningKey::from(sk));
            let sig: P384Signature = signing_key.sign_prehash(&z)?;
            Ok(P384DerSignature::from(sig).as_bytes().to_vec())
        }
        LeafKey::Ec(cert::EcKey::P521(sk)) => {
            let z = hash_with(digest, data)?;
            let signing_key = p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(sk));
            let sig: P521Signature = signing_key.sign_prehash(&z)?;
            Ok(P521DerSignature::from(sig).as_bytes().to_vec())
        }
        LeafKey::Rsa(rk) => {
            let rk = rk.as_ref().clone();
            let z = hash_with(digest, data)?;
            if up.contains("PSS") {
                sign_rsa_pss(&rk, digest, &z)
            } else if up.contains("NOPADDING") {
                anyhow::bail!("RSA NoPadding signing is not supported by the server keybox layer");
            } else {
                sign_rsa_pkcs1(&rk, digest, &z)
            }
        }
    }
}

fn sign_rsa_pkcs1(
    rk: &RsaPrivateKey,
    digest: LeafDigest,
    hashed: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use rsa::Pkcs1v15Sign;
    let sig = match digest {
        // Sha1 的 `AssociatedOid` 要 sha1 crate 的 oid feature（Cargo.toml 已开）。
        LeafDigest::Sha1 => rk.sign(Pkcs1v15Sign::new::<Sha1>(), hashed),
        LeafDigest::Sha224 => rk.sign(Pkcs1v15Sign::new::<sha2::Sha224>(), hashed),
        LeafDigest::Sha256 => rk.sign(Pkcs1v15Sign::new::<Sha256>(), hashed),
        LeafDigest::Sha384 => rk.sign(Pkcs1v15Sign::new::<sha2::Sha384>(), hashed),
        LeafDigest::Sha512 => rk.sign(Pkcs1v15Sign::new::<sha2::Sha512>(), hashed),
        // PKCS#1 v1.5 的 DigestInfo 必须标一个摘要；真机也不会用 NONE 走这条。
        // DIGEST=NONE 的 PKCS#1 签名是「type-1 填充 + 裸模幂」，不能套任何 DigestInfo。
        // 之前这里用 `new::<Sha256>()`，签出来的是「SHA-256 DigestInfo || data」，
        // Java 的 NONEwithRSA 验签自然过不了（aprobe C03）。
        LeafDigest::None => rk.sign(Pkcs1v15Sign::new_unprefixed(), hashed),
    }?;
    Ok(sig)
}

fn sign_rsa_pss(rk: &RsaPrivateKey, digest: LeafDigest, hashed: &[u8]) -> anyhow::Result<Vec<u8>> {
    use rsa::Pss;
    let mut rng = rand::rngs::OsRng;
    let sig = match digest {
        LeafDigest::Sha1 => rk.sign_with_rng(&mut rng, Pss::new::<Sha1>(), hashed),
        LeafDigest::Sha224 => rk.sign_with_rng(&mut rng, Pss::new::<sha2::Sha224>(), hashed),
        LeafDigest::Sha384 => rk.sign_with_rng(&mut rng, Pss::new::<sha2::Sha384>(), hashed),
        LeafDigest::Sha512 => rk.sign_with_rng(&mut rng, Pss::new::<sha2::Sha512>(), hashed),
        LeafDigest::None | LeafDigest::Sha256 => {
            rk.sign_with_rng(&mut rng, Pss::new::<Sha256>(), hashed)
        }
    }?;
    Ok(sig)
}

/// 按请求的算法解密。`PKCS1` / `NoPadding` / `OAEP` 三种都要认：
/// 以前只实现了 OAEP，于是 `RSA/ECB/PKCS1Padding` 这条在服务端 keybox 层
/// 直接失败、被当成"本层不适用"，最后落到设备层报 `no key for alias`。
fn decrypt_data(key: &LeafKey, data: &[u8], algorithm: &str) -> anyhow::Result<Vec<u8>> {
    let up = algorithm.to_ascii_uppercase();
    let LeafKey::Rsa(rk) = key else {
        anyhow::bail!("decrypt requires RSA key");
    };
    let rk = rk.as_ref();
    if up.contains("PKCS1") || up.contains("PKCS#1") {
        return Ok(rk.decrypt(rsa::Pkcs1v15Encrypt, data)?);
    }
    if up.contains("NOPADDING") {
        // 原始 RSA：m = c^d mod n，按模长补零输出。
        // c 必须严格小于 n，否则是非法代表（A 端已经预拦，这里再兵一道）。
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};
        let n = rk.n();
        let d = rk.d();
        let c = rsa::BigUint::from_bytes_be(data);
        if &c >= n {
            anyhow::bail!("ciphertext representative out of range");
        }
        let m = c.modpow(d, n);
        let mut out = vec![0u8; rk.size()];
        let bytes = m.to_bytes_be();
        let offset = out.len().saturating_sub(bytes.len());
        out[offset..].copy_from_slice(&bytes);
        return Ok(out);
    }
    // OAEP：摘要与 MGF1 摘要可以不同（Java 的 OAEPWithSHA-256AndMGF1Padding 就是
    // 摘要 SHA-256、MGF1 用 SHA-1）。按算法串里的两段分别取。
    let digest = LeafDigest::from_algorithm(&up);
    let mgf = if up.contains("MGF1-SHA1") {
        LeafDigest::Sha1
    } else {
        LeafDigest::from_algorithm(up.split("MGF1").nth(1).unwrap_or(&up))
    };
    decrypt_oaep(rk, digest, mgf, data)
}

// 每档失败只盖写同一个 `last`、真正读在 match 之后，编译器会报 unused_assignments，
// 这里就在函数上下方方便一下。
#[allow(unused_assignments)]
fn decrypt_oaep(
    rk: &RsaPrivateKey,
    digest: LeafDigest,
    mgf: LeafDigest,
    data: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use rsa::Oaep;
    // 宏体里直接写 `last` 会被宏卫生当成新绑定，所以只能拿参数把 slot 传进去。
    macro_rules! try_scheme {
        ($slot:ident, $d:ty, $m:ty) => {
            match rk.decrypt(Oaep::new_with_mgf_hash::<$d, $m>(), data) {
                Ok(out) => return Ok(out),
                Err(e) => $slot = Some(anyhow::anyhow!("{e}")),
            }
        };
    }
    let mut last: Option<anyhow::Error> = None;
    match (digest, mgf) {
        (LeafDigest::Sha1, LeafDigest::Sha1) => try_scheme!(last, Sha1, Sha1),
        (LeafDigest::Sha1, LeafDigest::Sha256) => try_scheme!(last, Sha1, Sha256),
        (LeafDigest::Sha1, _) => try_scheme!(last, Sha1, Sha1),
        (LeafDigest::Sha224, LeafDigest::Sha1) => try_scheme!(last, sha2::Sha224, Sha1),
        (LeafDigest::Sha224, LeafDigest::Sha256) => try_scheme!(last, sha2::Sha224, Sha256),
        (LeafDigest::Sha224, _) => try_scheme!(last, sha2::Sha224, Sha1),
        (LeafDigest::Sha256, LeafDigest::Sha1) => try_scheme!(last, Sha256, Sha1),
        (LeafDigest::Sha256, LeafDigest::Sha224) => try_scheme!(last, Sha256, sha2::Sha224),
        (LeafDigest::Sha256, LeafDigest::Sha384) => try_scheme!(last, Sha256, sha2::Sha384),
        (LeafDigest::Sha256, LeafDigest::Sha512) => try_scheme!(last, Sha256, sha2::Sha512),
        (LeafDigest::Sha256, LeafDigest::Sha256) | (LeafDigest::Sha256, LeafDigest::None) => {
            try_scheme!(last, Sha256, Sha256)
        }
        (LeafDigest::Sha384, LeafDigest::Sha1) => try_scheme!(last, sha2::Sha384, Sha1),
        (LeafDigest::Sha384, LeafDigest::Sha384) => try_scheme!(last, sha2::Sha384, sha2::Sha384),
        (LeafDigest::Sha384, _) => try_scheme!(last, sha2::Sha384, Sha256),
        (LeafDigest::Sha512, LeafDigest::Sha1) => try_scheme!(last, sha2::Sha512, Sha1),
        (LeafDigest::Sha512, LeafDigest::Sha512) => try_scheme!(last, sha2::Sha512, sha2::Sha512),
        (LeafDigest::Sha512, _) => try_scheme!(last, sha2::Sha512, Sha256),
        (LeafDigest::None, _) => try_scheme!(last, Sha256, Sha1),
    }
    // 老调用方没带算法串时按历史上能用的两种组合再兜一遍。
    try_scheme!(last, Sha256, Sha256);
    try_scheme!(last, Sha256, Sha1);
    match last {
        Some(e) => Err(anyhow::anyhow!("rsa oaep decrypt failed: {e}")),
        None => Err(anyhow::anyhow!("rsa oaep decrypt failed")),
    }
}

/// 「年月日时」时间戳，给合成的 boot 值当种子用。
///
/// 到小时为止：分/秒级会让同一轮会话里前后两笔的 boot key 不一样，看着更像假的。
fn boot_value_stamp() -> String {
    chrono::Utc::now().format("%Y%m%d%H").to_string()
}

/// 按 (用途, 设备, 时间戳) 派生一个 32 字节值。
///
/// 同一台设备、同一个小时内结果相同；换小时或换设备都会变。`kind` 把 boot key 和
/// boot hash 分开，避免两者变成同一串。
fn boot_value_seed(device_id: &str, kind: &str, stamp: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-boot-value|");
    hasher.update(kind.as_bytes());
    hasher.update(b"|");
    hasher.update(device_id.as_bytes());
    hasher.update(b"|");
    hasher.update(stamp.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    // Isolated memory-only cache: tests must not load or replace real sessions.
    fn fulfill() -> Fulfill {
        Fulfill {
            inner: Mutex::new(Inner::default()),
            enabled: AtomicBool::new(true),
            attest_gates: Mutex::new(HashMap::new()),
            self_signed_cache: Mutex::new(HashMap::new()),
            db: None,
            // 每个测试自己的内存库，并行跑的用例别互相看到对方写的会话。
            state: Arc::new(crate::statedb::StateDb::open_in_memory().unwrap()),
        }
    }

    fn session(key: &str) -> Session {
        let now = Utc::now().timestamp_millis() as u64;
        Session {
            chain_pem: format!("chain-{key}"),
            leaf_key_pem: key.to_string(),
            cached_key: Arc::new(OnceLock::new()),
            leaf_key_cipher: String::new(),
            created_epoch_ms: now,
            used_epoch_ms: now,
        }
    }

    #[test]
    fn late_worker_and_retry_share_key_while_other_alias_proceeds() {
        let f = fulfill();
        let calls = AtomicUsize::new(0);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (other_tx, other_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let worker_f = &f;
            let worker_calls = &calls;
            let late = scope.spawn(move || {
                worker_f
                    .session_or_generate("same", || {
                        worker_calls.fetch_add(1, Ordering::SeqCst);
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(session("original"))
                    })
                    .unwrap()
                    .0
            });
            entered_rx.recv().unwrap();
            let retry = scope.spawn(|| {
                f.session_or_generate("same", || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(session("replacement"))
                })
                .unwrap()
                .0
            });
            scope.spawn(|| {
                let s = f
                    .session_or_generate("other", || Ok(session("independent")))
                    .unwrap()
                    .0;
                other_tx.send(s).unwrap();
            });
            // No sleep: the other alias must complete while the first is held.
            let independent = other_rx.recv_timeout(Duration::from_secs(5));
            release_tx.send(()).unwrap();
            assert_eq!(independent.unwrap().leaf_key_pem, "independent");
            let original = late.join().unwrap();
            let returned = retry.join().unwrap();
            assert_eq!(original.leaf_key_pem, returned.leaf_key_pem);
            assert_eq!(original.chain_pem, returned.chain_pem);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                f.get_session("same").unwrap().leaf_key_pem,
                returned.leaf_key_pem
            );
        });
    }

    #[test]
    fn failed_snapshot_allows_demotion_but_success_cannot_be_replaced() {
        let f = fulfill();
        assert!(f
            .session_or_generate("alias", || anyhow::bail!("StrongBox failed"))
            .is_err());
        let (tee, generated) = f
            .session_or_generate("alias", || Ok(session("TEE")))
            .unwrap();
        assert!(generated);
        let (retry, generated) = f
            .session_or_generate("alias", || panic!("must reuse success"))
            .unwrap();
        assert!(!generated);
        assert_eq!(retry.chain_pem, tee.chain_pem);
        assert_eq!(retry.leaf_key_pem, tee.leaf_key_pem);
        assert_eq!(retry.created_epoch_ms, tee.created_epoch_ms);
        // Defensive publication also preserves an already returned key.
        assert_eq!(
            f.put_session("alias", session("StrongBox")).leaf_key_pem,
            tee.leaf_key_pem
        );
    }

    #[test]
    fn cached_leaf_algorithm_mismatch_is_rejected_without_replacement() {
        let f = fulfill();
        for (cached, requested) in [("ec", cert::KM_ALG_RSA), ("rsa", cert::KM_ALG_EC)] {
            let material = cert::generate_self_signed(cached).unwrap();
            let mut original = session(&material.private_key_pem);
            original.chain_pem = material.certificate_chain_pem;
            crate::util::mu(&f.inner)
                .sessions
                .insert("legacy-alias".into(), original.clone());
            // An invalid issuer proves rejection occurs on the actual cached
            // material, without generating a replacement.
            let identity = DeviceIdentity {
                device_id: "device".into(),
                algorithm: "ec".into(),
                certificate_chain_pem: String::new(),
                private_key_pem_cipher: String::new(),
                active: true,
                machine_id: String::new(),
                created_at: String::new(),
            };
            let response = f.attest_from_identity(
                &json!({"alias": "legacy-alias", "device_attest_context": {"key_algorithm": requested}}),
                &identity,
                "server_keybox",
            )
            .unwrap();
            let error = response["error"].as_str().unwrap();
            assert!(
                error.contains("cached session algorithm mismatch"),
                "{error}"
            );
            assert!(error.contains("existing session preserved"));
            assert!(response.get("cert_chain").is_none());
            let retained = f.get_session("legacy-alias").unwrap();
            assert_eq!(retained.chain_pem, original.chain_pem);
            assert_eq!(retained.leaf_key_pem, original.leaf_key_pem);
            assert_eq!(retained.created_epoch_ms, original.created_epoch_ms);

            // Matching private-key algorithm alone is insufficient: the chain
            // leaf must match that key too.
            let other =
                cert::generate_self_signed(if cached == "ec" { "rsa" } else { "ec" }).unwrap();
            crate::util::mu(&f.inner)
                .sessions
                .get_mut("legacy-alias")
                .unwrap()
                .chain_pem = other.certificate_chain_pem;
            let error = f
                .attest_and_cache(
                    &identity,
                    "legacy-alias",
                    &json!({"algorithm": cached}),
                    b"",
                )
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid leaf key/chain"), "{error}");
        }
    }

    #[test]
    fn loaded_session_is_reused_and_expired_session_is_recreated() {
        let f = fulfill();
        let material = cert::generate_self_signed("ec").unwrap();
        let mut old = session(&material.private_key_pem);
        old.chain_pem = material.certificate_chain_pem;
        old.created_epoch_ms -= 1000;
        crate::util::mu(&f.inner)
            .sessions
            .insert("alias".into(), old.clone());
        let (reused, generated) = f
            .session_or_generate("alias", || panic!("loaded session must be reused"))
            .unwrap();
        assert!(!generated);
        assert_eq!(reused.created_epoch_ms, old.created_epoch_ms);
        // Even an identity rotation / differing device snapshot cannot mint a
        // replacement. Invalid issuer material would fail if generation ran.
        let identity = DeviceIdentity {
            device_id: "rotated-device".into(),
            algorithm: "ec".into(),
            certificate_chain_pem: String::new(),
            private_key_pem_cipher: String::new(),
            active: true,
            machine_id: String::new(),
            created_at: String::new(),
        };
        let (chain, fingerprint) = f
            .attest_and_cache(
                &identity,
                "alias",
                &json!({"attestation_security_level": 2}),
                b"different",
            )
            .unwrap();
        assert_eq!(chain, old.chain_pem);
        assert_eq!(
            fingerprint,
            base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest(old.leaf_key_pem.as_bytes()))
        );
        crate::util::mu(&f.inner)
            .sessions
            .get_mut("alias")
            .unwrap()
            .used_epoch_ms =
            Utc::now().timestamp_millis() as u64 - SESSION_TTL.as_millis() as u64 - 1;
        let (fresh, generated) = f
            .session_or_generate("alias", || Ok(session("fresh")))
            .unwrap();
        assert!(generated);
        assert_eq!(fresh.leaf_key_pem, "fresh");
    }

    /// 热缓存里没有的会话得回库查出来，而且用一次就把「最后使用」顶到当下。
    #[test]
    fn cold_session_is_read_back_from_the_db_and_touched() {
        let f = fulfill();
        let material = cert::generate_self_signed("ec").unwrap();
        // 10 分钟前用过：没到 7 天 TTL，但超出「顶时间」的节流窗，能被看出去
        let old = Utc::now().timestamp_millis() as u64 - 10 * 60 * 1000;
        let row = crate::statedb::SessionRow {
            chain_pem: material.certificate_chain_pem.clone(),
            leaf_key_pem: material.private_key_pem.clone(),
            created_epoch_ms: old,
            used_epoch_ms: old,
        };
        f.state.upsert_session("cold", &row).unwrap();
        // 内存里故意不放 —— 模拟「冷的那批没装进热缓存」
        assert!(crate::util::mu(&f.inner).sessions.is_empty());

        let got = f.get_session("cold").expect("回库查得到");
        assert_eq!(got.chain_pem, material.certificate_chain_pem);
        assert!(got.used_epoch_ms > old);
        // 查回来之后进了热缓存
        assert!(crate::util::mu(&f.inner).sessions.contains_key("cold"));

        // 库里那条的「最后使用」也被顶了
        let persisted = f
            .state
            .get_session_row("cold")
            .unwrap()
            .unwrap()
            .used_epoch_ms;
        assert!(persisted > old, "取用一次就得顶最后使用");
    }

    /// 内存热缓存超出上限时，淘汰的是最久没用的那个；库里那条还在。
    #[test]
    fn memory_cache_evicts_the_least_recently_used() {
        let mut map: HashMap<String, Session> = HashMap::new();
        for i in 0..(crate::statedb::SESSION_MEMORY_HOT + 5) {
            let mut s = session(&format!("k{i}"));
            s.used_epoch_ms = (i + 1) as u64;
            map.insert(format!("al{i}"), s);
        }
        Fulfill::enforce_memory_cap(&mut map);
        assert_eq!(map.len(), crate::statedb::SESSION_MEMORY_HOT);
        // 最久没用的前五个被挤掉，最新的那个还在
        for i in 0..5 {
            assert!(!map.contains_key(&format!("al{i}")), "al{i} 该被淘汰");
        }
        assert!(map.contains_key(&format!("al{}", crate::statedb::SESSION_MEMORY_HOT + 4)));
    }
}

#[cfg(test)]
mod boot_value_tests {
    use super::*;

    /// 合成的 boot 值要「同一小时内稳定、换小时/换设备/换用途就变」，长度必须 32。
    #[test]
    fn synthesized_boot_values_are_stable_within_the_hour() {
        let a = boot_value_seed("device-b-x", "bootkey", "2026102903");
        assert_eq!(a.len(), 32);
        assert_eq!(a, boot_value_seed("device-b-x", "bootkey", "2026102903"));
        assert_ne!(a, boot_value_seed("device-b-x", "bootkey", "2026102904"));
        assert_ne!(a, boot_value_seed("device-b-y", "bootkey", "2026102903"));
        assert_ne!(a, boot_value_seed("device-b-x", "boothash", "2026102903"));
        assert_ne!(a, [0u8; 32]);
    }
}

#[cfg(test)]
mod layer_crypto_tests {
    use super::*;

    fn rsa_leaf() -> (RsaPrivateKey, LeafKey) {
        let mut rng = rand::rngs::OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let leaf = LeafKey::Rsa(key.clone().into());
        (key, leaf)
    }

    fn p256_leaf() -> (p256::SecretKey, LeafKey) {
        let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
        (sk.clone(), LeafKey::Ec(cert::EcKey::P256(sk.clone())))
    }

    /// PKCS#1 v1.5 解密：以前这条完全没实现，`RSA/ECB/PKCS1Padding` 的请求在
    /// 服务端 keybox 层直接失败、被当成"本层不适用"，最后落到设备层报 key_not_found。
    #[test]
    fn pkcs1_decrypt_round_trips() {
        let (priv_key, leaf) = rsa_leaf();
        let msg = b"ommega-pkcs1-check";
        use rsa::traits::PublicKeyParts;
        let pub_key = priv_key.to_public_key();
        let enc = pub_key
            .encrypt(&mut rand::rngs::OsRng, rsa::Pkcs1v15Encrypt, msg)
            .expect("encrypt");
        assert_eq!(enc.len(), priv_key.size());
        let out = decrypt_data(&leaf, &enc, "RSA/ECB/PKCS1Padding").expect("pkcs1 decrypt");
        assert_eq!(out, msg);
    }

    /// OAEP 仍然可用（摘要 SHA-256 + MGF1 SHA-1，Java 的老组合）。
    #[test]
    fn oaep_decrypt_still_works() {
        let (priv_key, leaf) = rsa_leaf();
        let msg = b"ommega-oaep-check";
        let pub_key = priv_key.to_public_key();
        let enc = pub_key
            .encrypt(&mut rand::rngs::OsRng, rsa::Oaep::new::<Sha256>(), msg)
            .expect("encrypt");
        let out = decrypt_data(&leaf, &enc, "RSA/OAEP/SHA-256/MGF1-SHA256").expect("oaep decrypt");
        assert_eq!(out, msg);
    }

    /// `NONEwithECDSA`：输入本身就是摘要，服务端必须直接签摘要，不能再哈希一层。
    #[test]
    fn raw_ecdsa_signs_the_digest_as_is() {
        use ecdsa::signature::hazmat::PrehashVerifier as _;
        let (sk, leaf) = p256_leaf();
        let digest = [0x5au8; 32];
        let sig = sign_data(&leaf, &digest, "NONEwithECDSA").expect("sign");
        let verifier = *p256::ecdsa::SigningKey::from(&sk).verifying_key();
        let sig = P256Signature::from_der(&sig).expect("der");
        verifier
            .verify_prehash(&digest, &sig)
            .expect("NONEwithECDSA signature must verify against the raw digest");
    }

    /// SHA384withRSA：PKCS#1 的 DigestInfo 前缀必须跟着摘要走。
    #[test]
    fn sha384_rsa_signature_verifies() {
        let (priv_key, leaf) = rsa_leaf();
        let msg = b"ommega-sha384-check";
        let sig = sign_data(&leaf, msg, "SHA384withRSA").expect("sign");
        let hashed = sha2::Sha384::digest(msg);
        priv_key
            .to_public_key()
            .verify(rsa::Pkcs1v15Sign::new::<sha2::Sha384>(), &hashed, &sig)
            .expect("SHA384withRSA signature must verify");
    }
}
