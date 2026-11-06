//! 服务端侧的两层 SOTER：keybox 层（用服务端存的那把设备身份）和自签层（现
//! 生成、进程内复用）。
//!
//! SOTER 的"证书"不是 X.509，是 `[i32 le JSON 长度][JSON][256 字节 RSA-PSS
//! 签名]`，JSON 长这样（键序就是现场抓到的键序，字段名别改）：
//!
//! ```json
//! {"pub_key":"<ASK 公钥 PEM>","cpu_id":"<32 位十六进制>","counter":<数字>,
//!  "uid":"<字符串>","rsa_pss_saltlen":32}
//! ```
//!
//! 签名用 ATTK 私钥做 RSA-PSS-SHA256，盐长 32。也就是说：手里只要有（或者现
//! 生成）一对 RSA 密钥，就能造出一份"ASK 的签名拿这把 ATTK 公钥验得过"的自洽
//! 产物 —— 这正是这两层要干的事。腾讯那边认不认是另一回事（SOTER 的根在腾讯，
//! 谁也没有），这两层的意义是让 A 端的本地流程先能闭环，跟认证那边 keybox /
//! self_signed 两层是一个道理。
//!
//! 层与层的分工：
//!   - `keybox`：用服务端数据库里这台设备名下的身份私钥。只有它带的是 RSA 才
//!     能干 SOTER（keybox 里常见的是 EC，那就这层处理不了，回退下一层）。
//!   - `attk`：服务端密钥模式专用。用控制台上传的那把 ATTK（RSA 私钥 + 它自己的
//!     `cpu_id`）铸料 —— 身份就是那把 ATTK 的，A 端转过来的真机号在这儿不作数。
//!     多个 ATTK 时选哪把由 `crate::soter_policy` 的身份规则决定。
//!   - `self_signed`：现生成一把 RSA-2048，进程内复用；服务端一重启就等于换了
//!     一把新身份，A 端要重新取 ATTK 公钥。
//!
//! 物料是按「身份」隔离的：ASK / AuthKey 的缓存键前面都带一层 `scope`
//! （见 `material_scope`）。换了 ATTK 就等于换了一整套钥匙，不会拿 A 的 ASK 去配
//! B 的 AuthKey —— 那种状态下 App 导出的公钥和签名用的私钥对不上，会自己把该 uid
//! 下的钥匙全删掉重来。
//!
//! 处理不了的 op 会返回带 `error` 的对象，调用方据此回退下一层。
//!
//! 换层是策略（没物料 / 超时 / 不认这个 op 就往下换），但**同一个槽位的材料
//! 必须只出自一层**：一半是 B 的 ASK、一半是 keybox 的 AuthKey，App 手里就是
//! 自相矛盾的状态（`hasAuthKey` 一会儿有一会儿没，导出的公钥和签名的私钥也
//! 对不上）。所以：
//!
//!   - 谁来服务这个槽位就把它钉在谁身上（`pin_layer`，落盘不丢），下次先问它；
//!   - 它真不灵了再换（换层仍是策略），换成了钉子跟着挪；
//!   - 每层自己也得把整个流程走完：ASK 自描述、AuthKey 自描述、签名现场，
//!     三份信封一个不少，签名的那把钥匙和导出的公钥对得上。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::pss::SigningKey as PssSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::statedb;

/// SOTER 的成功码。
const OK: i32 = 0;
/// "这把钥匙不在这台设备上"。实测 `hasAskAlready(10371)` 就返回它。
const NOT_FOUND: i32 = -5;
/// AuthKey 还没建（`has_auth_key` / `export_auth_key_public_key` 查不到时）。
/// 真机 TA 这里答 -6（AUTH_KEY_NOT_READY），答 -5 会被当成「ASK 没建」。
const AUTH_KEY_NOT_READY: i32 = -6;
/// `finish_sign` 拿到一个不存在的 session。真机 TA 用 -1000，不是 -5。
const SESSION_UNKNOWN: i32 = -1000;
/// ASK 里写死的盐长。实测真机（PLC110，MTK Kinibi，Android 16）三份文档都写 32，
/// 签名也真是 32 —— 自己的声明和签名得对得上，验签方才验得过。
const ASK_SALT_LEN: i32 = 32;

// ---------------------------------------------------------------------------
// 物料
// ---------------------------------------------------------------------------

/// 一对 RSA 密钥 + 它的公钥 PEM（SOTER 里 ATTK 公钥就长这样）。
struct MintKey {
    attk_pem: String,
    private: Arc<RsaPrivateKey>,
}

impl MintKey {
    fn from_pem(pem: &str) -> Result<Self> {
        let private = parse_rsa_private(pem)?;
        let public = rsa::RsaPublicKey::from(&private);
        let attk_pem = public
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .context("failed to encode the RSA public key as PEM")?;
        Ok(Self {
            attk_pem,
            private: Arc::new(private),
        })
    }

    fn generate() -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).context("RSA keygen failed")?;
        let public = rsa::RsaPublicKey::from(&private);
        let attk_pem = public
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .context("failed to encode the RSA public key as PEM")?;
        Ok(Self {
            attk_pem,
            private: Arc::new(private),
        })
    }

    /// 落盘用：私钥的 PKCS#8 PEM。
    fn to_pem(&self) -> Result<String> {
        use pkcs8::EncodePrivateKey as _;
        Ok(self
            .private
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .context("failed to encode the private key as PEM")?
            .to_string())
    }

    /// RSA-PSS-SHA256，盐长 = `ASK_SALT_LEN`（20，跟真机 TA 对齐、也跟 JSON 里那个
    /// `rsa_pss_saltlen` 字段一致）。
    ///
    /// 这里必须显式 `new_with_salt_len`：`PssSigningKey::new` 给的是摘要长度（32），
    /// 跟 `ASK_SALT_LEN` 恰好同为 32；写成显式的，以后谁改常量都不会忘了同步签名。
    /// 验签方（App / openssl `rsa_pss_saltlen:32`）是按 JSON 里声明的值严卡盐长的。
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing = PssSigningKey::<Sha256>::new_with_salt_len(
            (*self.private).clone(),
            ASK_SALT_LEN as usize,
        );
        let mut rng = rand::rngs::OsRng;
        Ok(signing.sign_with_rng(&mut rng, message).to_bytes().to_vec())
    }
}

fn parse_rsa_private(pem: &str) -> Result<RsaPrivateKey> {
    let trimmed = pem.trim();
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(trimmed) {
        return Ok(key);
    }
    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    RsaPrivateKey::from_pkcs1_pem(trimmed).context("neither a PKCS#8 nor a PKCS#1 RSA private key")
}

/// 进程内的 SOTER 物料库。
struct Store {
    self_signed: Mutex<Option<Arc<MintKey>>>,
    /// 专给探测机作答的那一把（见 `crate::soter_probe`），自己一份、永不轮换。
    builtin: Mutex<Option<Arc<MintKey>>>,
    /// `soter_attk` 行 id -> 这把 ATTK 解出来的物料（服务端密钥模式）。
    /// 按 id 缓存：控制台删掉再传就是新的一行，不会串。
    attk: Mutex<HashMap<i64, Arc<MintKey>>>,
    /// `{device}|{layer}` -> 这一层的 ASK。
    ///
    /// 真机的 SOTER 里 ATTK 和 ASK 是两把钥匙：ASK 证书用 ATTK 签、AuthKey 证书用
    /// ASK 签、finishSign 用 AuthKey 签。以前这里只有一把（ASK 兼作 ATTK），
    /// `exportAskPublicKey` 和 `exportAttkPublicKey` 吐同一把公钥 —— App 拿到的就是
    /// 真机上永远不会出现的形状，会直接把该 uid 下的钥匙全删掉重来（A 端本地兜底
    /// 已经这么修过一轮，见 a-side `soter_local.rs`）。
    ask: Mutex<HashMap<String, Arc<MintKey>>>,
    /// `{device}|{uid}|{alias}` -> AuthKey
    auth: Mutex<HashMap<String, Arc<MintKey>>>,
    /// `{device}|{uid}` -> 签名计数器
    counters: Mutex<HashMap<String, u64>>,
    /// 删过的 ASK 墓碑：`{scope}|{device}|{uid}`。
    ///
    /// 真机的删除是黏的：`remove_all_uid_key` 之后 `export*` 不能现造一把新的顶上。
    /// 服务端物料本来就在内存里，墓碑也一起在内存（重启后两边一起没，口径一致）。
    gone_ask: Mutex<HashSet<String>>,
    /// `{device}|{uid}` -> 下一次会话号
    next_session: Mutex<i64>,
    /// 会话号 -> 这一次要签的挑战
    sessions: Mutex<HashMap<i64, SignSession>>,
    /// `{device}|{uid}` -> 这个槽位归哪一层（带时间戳，见 `SlotPin`）。
    slots: Mutex<HashMap<String, SlotPin>>,
    /// `{device}|{uid}` -> 上一次把「最近见到」刷进库的时间（节流用）。
    owner_touch: Mutex<HashMap<String, i64>>,
}

/// 钉在槽位上的那一层，加个时间。
///
/// 为什么要有时间：B 端只是打了个嗝（比如一次长轮询空档超时），keybox 抢答成功，
/// 槽位就钉在 keybox 上了 —— 而 keybox 递给 App 的是假链，腾讯不认，这轮开启注定
/// 失败。要是钉子永不过期，后面的重试也永远拿不到 B 的真料，一次抖动就变成永久
/// 失败。给个寿命：一轮流程内（几秒到几分钟）接着钉保证不自相矛盾，过期之后
/// 重新评，该回 B 就回 B。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SlotPin {
    layer: String,
    at_millis: i64,
    /// 这个槽位上认出来的账号指纹（`owner_token` 给出来的）。`layer` 为空、只有
    /// 这个字段的记录表示「还没服务过这个槽位，只知道上面有谁」。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    owners: Vec<Owner>,
}

/// 槽位上记着的一个账号指纹 + 最后一次见到它的时间。
///
/// 时间是给两条缓存规矩用的：这一族满了按它做 LRU（换掉最久没见的），以及久了
/// 没见就按 TTL 丢掉。指纹本身不带时间，所以时间得跟它放一起。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Owner {
    token: String,
    last_seen_ms: i64,
}

/// 钉子活多久。取 30 分钟：比一轮开启流程长得多，又短到不至于把一次抖动变成
/// 永久失败（微信缓存的 cpu_id 变了会自己重走一轮流程，所以跨层也是能自愈的）。
const SLOT_PIN_TTL_MILLIS: i64 = 30 * 60 * 1000;

/// 账号指纹活多久（按最后一次见到算）。比会话的 7 天长得多 —— 它只是「这个槽位
/// 上还有几个号」的判据，攒着不占多少地方；过早忘掉反而会让连坐拦截失手。
const OWNER_TTL_MILLIS: i64 = 30 * 24 * 60 * 60 * 1000;

/// 账号指纹过期清理的节流间隔（扫一遍是 O(槽位数)）。
const OWNER_PURGE_INTERVAL_MS: i64 = 10 * 60 * 1000;
static LAST_OWNER_PURGE: AtomicI64 = AtomicI64::new(0);

struct SignSession {
    requested: String,
    device: String,
    layer: String,
    /// `attk` 层开出来的会话归哪一把 ATTK。finish 得用同一把签，否则验不过。
    attk_id: Option<i64>,
    uid: i32,
    alias: String,
    /// 挑战原文。真机把这段原文写进签名 JSON 的 `raw` 里，不是解出来的字节。
    raw: String,
}

/// Only an exact requested-device/session owner may route a server finish.
pub fn session_layer(requested: &str, session: i64) -> Option<String> {
    let sessions = store().sessions.lock().ok()?;
    let owner = sessions.get(&session)?;
    (owner.requested == requested).then(|| owner.layer.clone())
}

/// 这张会话当初是哪把 ATTK 开的（`attk` 层之外的会话回 `None`）。
pub fn session_attk(requested: &str, session: i64) -> Option<i64> {
    let sessions = store().sessions.lock().ok()?;
    let owner = sessions.get(&session)?;
    (owner.requested == requested)
        .then_some(owner.attk_id)
        .flatten()
}

/// 控制台上传的 ATTK：私钥 + 它对应的 `cpu_id`（SOTER 的身份就是这两样）。
#[derive(Clone, Debug)]
pub struct AttkMaterial {
    pub id: i64,
    pub name: String,
    pub cpu_id: String,
    pub pem: String,
}

fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| Store {
        self_signed: Mutex::new(None),
        builtin: Mutex::new(None),
        attk: Mutex::new(HashMap::new()),
        ask: Mutex::new(HashMap::new()),
        gone_ask: Mutex::new(load_gone_asks()),
        auth: Mutex::new(HashMap::new()),
        counters: Mutex::new(HashMap::new()),
        next_session: Mutex::new(chrono::Utc::now().timestamp_millis()),
        sessions: Mutex::new(HashMap::new()),
        slots: Mutex::new(load_slots()),
        owner_touch: Mutex::new(HashMap::new()),
    })
}

/// 取这一层的物料。`key_pem` 只有 keybox 层才需要（服务端存的那把设备身份私钥），
/// `attk` 只有服务端密钥模式才需要。
fn material(
    layer: &str,
    key_pem: Option<&str>,
    attk: Option<&AttkMaterial>,
) -> Result<Arc<MintKey>> {
    if layer == "keybox" {
        let pem = key_pem.ok_or_else(|| anyhow!("服务端在这台设备名下没有 RSA 身份的私钥"))?;
        return Ok(Arc::new(MintKey::from_pem(pem)?));
    }
    if layer == "attk" {
        let attk = attk.ok_or_else(|| {
            anyhow!("服务端密钥模式没有可用的 ATTK（控制台上传一把，或换回真机模式）")
        })?;
        let mut map = store()
            .attk
            .lock()
            .map_err(|_| anyhow!("attk material lock poisoned"))?;
        if let Some(existing) = map.get(&attk.id) {
            return Ok(existing.clone());
        }
        let fresh = Arc::new(MintKey::from_pem(&attk.pem)?);
        map.insert(attk.id, fresh.clone());
        return Ok(fresh);
    }
    if layer == "builtin" {
        return builtin_key();
    }
    self_signed_key()
}

/// 这一层的物料挂在哪份身份下。
///
/// ASK / AuthKey 的缓存键都以它打头：`attk` 层按 ATTK 行 id 分（换一把就是换一整套），
/// 其余三层各是各的。不这么分的话，控制台换一把 ATTK 之后旧 AuthKey 还留在表里，
/// 而它的 ASK 已经换成新的了 —— App 导出的公钥和签名用的私钥对不上。
fn material_scope(layer: &str, attk: Option<&AttkMaterial>) -> String {
    match layer {
        "attk" => attk
            .map(|a| format!("attk:{}", a.id))
            .unwrap_or_else(|| "attk:none".to_string()),
        "keybox" => "keybox".to_string(),
        "builtin" => "builtin".to_string(),
        _ => "self_signed".to_string(),
    }
}

/// 会话收尾时按「当初开它的那把身份」算 scope（`attk` 层要回到同一把 ATTK 上）。
fn moment_scope(layer: &str, attk_id: Option<i64>) -> String {
    match layer {
        "attk" => match attk_id {
            Some(id) => format!("attk:{id}"),
            None => "attk:none".to_string(),
        },
        "keybox" => "keybox".to_string(),
        "builtin" => "builtin".to_string(),
        _ => "self_signed".to_string(),
    }
}

/// ATTK 被删/换了：物料缓存、它签出来的 ASK/AuthKey、以及这个身份的墓碑一起丢。
pub fn forget_attk(id: i64) {
    if let Ok(mut map) = store().attk.lock() {
        map.remove(&id);
    }
    let prefix = format!("attk:{id}|");
    if let Ok(mut map) = store().ask.lock() {
        map.retain(|key, _| !key.starts_with(&prefix));
    }
    if let Ok(mut map) = store().auth.lock() {
        map.retain(|key, _| !key.starts_with(&prefix));
    }
    if let Ok(mut set) = store().gone_ask.lock() {
        set.retain(|key| !key.starts_with(&prefix));
    }
    if let Err(e) = statedb::shared().clear_gone_ask_prefix(&prefix) {
        tracing::warn!("soter: 按身份清墓碑失败（{prefix}）：{e:#}");
    }
    // 落盘的那份也得跟着走，不然重启后旧 ATTK 铸的 ASK 又回来了。
    if let Err(e) = statedb::shared().mint_key_delete_prefix(&prefix) {
        tracing::warn!("soter: 按身份清落盘料失败（{prefix}）：{e:#}");
    }
}

/// 探测机专用的那把 ASK。跟自签层分开，是因为探测流量会一直让 `generate_ask_key_pair`
/// 换钥匙 —— 换的是全局那一把，会把钉在那一层上、正跑着一轮的槽位劈成两半。
fn builtin_key() -> Result<Arc<MintKey>> {
    let mut guard = store()
        .builtin
        .lock()
        .map_err(|_| anyhow!("builtin material lock poisoned"))?;
    if guard.is_none() {
        *guard = Some(Arc::new(MintKey::generate()?));
    }
    guard
        .clone()
        .ok_or_else(|| anyhow!("builtin material disappeared"))
}

fn self_signed_key() -> Result<Arc<MintKey>> {
    let mut guard = store()
        .self_signed
        .lock()
        .map_err(|_| anyhow!("self-signed material lock poisoned"))?;
    if guard.is_none() {
        *guard = Some(Arc::new(MintKey::generate()?));
    }
    guard
        .clone()
        .ok_or_else(|| anyhow!("self-signed material disappeared"))
}

fn rotate_self_signed_key() -> Result<Arc<MintKey>> {
    let fresh = Arc::new(MintKey::generate()?);
    let mut guard = store()
        .self_signed
        .lock()
        .map_err(|_| anyhow!("self-signed material lock poisoned"))?;
    *guard = Some(fresh.clone());
    Ok(fresh)
}

/// 这一层的 ASK（按需生成、进程内缓存）。
///
/// 键里带 **uid**：真机的 ASK 是 per-user、per-uid 的（`generateAskKeyPair(uid)` 建的就是
/// 那个 uid 的 ASK），`exportAskPublicKey(uid)` 吐的是那个 uid 的公钥。以前这里只按
/// 设备缓存，同设备上所有应用拿到同一把 ASK —— 真机上永远不会出现的形状，多用户下
/// 更糟：工作资料的应用会拿到机主那把的公钥。
///
/// 跟 ATTK 分开存：真机上这两把公钥永远不相等，`exportAskPublicKey` 和
/// `exportAttkPublicKey` 吐同一把会让 App 把该 uid 下的钥匙全删掉重来。
fn layer_ask_key(scope: &str, uid: i32, layer: &str) -> Result<Arc<MintKey>> {
    let id = format!("{scope}|{uid}|{layer}");
    // 先在锁里看一眼；生成 RSA 放到锁外。
    //
    // 以前是抱着整张表的锁去 keygen（2048 位 RSA，几十到上百毫秒），一堆 A 机同时
    // 进来时全部串在这一把锁上 —— 一个新建 ASK 能把别的设备、别的 uid 的请求一起拖住。
    if let Some(existing) = store()
        .ask
        .lock()
        .map_err(|_| anyhow!("ask material lock poisoned"))?
        .get(&id)
        .cloned()
    {
        return Ok(existing);
    }
    // 进程重启后内存是空的，但库里那把还是用户的 ASK —— 先把它捞回来，不能现造一把。
    if let Some(loaded) = load_persisted_key(&id, persists(scope)) {
        if let Ok(mut map) = store().ask.lock() {
            map.insert(id, loaded.clone());
        }
        return Ok(loaded);
    }
    let fresh = Arc::new(MintKey::generate()?);
    let mut map = store()
        .ask
        .lock()
        .map_err(|_| anyhow!("ask material lock poisoned"))?;
    // 两个请求同时给同一个 uid 建料：先进去的算数，后到的用它的（不能各建一把）。
    if let Some(existing) = map.get(&id) {
        return Ok(existing.clone());
    }
    map.insert(id.clone(), fresh.clone());
    drop(map);
    persist_key(&id, "ask", &fresh, persists(scope));
    Ok(fresh)
}

/// 哪些层的料落盘。
///
/// 只落 `attk` 层：它是「服务端自己出一整套身份」那条路，进程重启换一把 ASK 就等于
/// 跟 App 手里缓存的公钥对不上（拿同一个身份重签，验不过就自删重来）。自签层不动：
/// 它本来就是一次性的假身份，重启换一把反而干净。
fn persists(scope: &str) -> bool {
    scope.starts_with("attk:")
}

/// 从库里捞一把落过盘的物料（没开落盘、库里没有、解不开都当没有）。
fn load_persisted_key(slot: &str, persisted: bool) -> Option<Arc<MintKey>> {
    if !persisted {
        return None;
    }
    let (_kind, cipher) = match statedb::shared().mint_key_get(slot) {
        Ok(hit) => hit?,
        Err(e) => {
            tracing::warn!("soter: 读物料落盘记录失败（{slot}）：{e:#}");
            return None;
        }
    };
    // 跟 `sessions.leaf_key_pem` 一个口径：加密是在写的时候做的，这里解得回来才算数。
    let pem = crate::crypto::decrypt_private_pem(&cipher);
    match MintKey::from_pem(&pem) {
        Ok(key) => Some(Arc::new(key)),
        Err(e) => {
            tracing::warn!("soter: 落盘的物料 {slot} 解不出来（{e:#}），当没有");
            None
        }
    }
}

fn persist_key(slot: &str, kind: &str, key: &MintKey, persisted: bool) {
    if !persisted {
        return;
    }
    let pem = match key.to_pem() {
        Ok(pem) => pem,
        Err(e) => {
            tracing::warn!("soter: 物料 {slot} 转不成 PEM，没法落盘：{e:#}");
            return;
        }
    };
    let cipher = crate::crypto::encrypt_private_pem(&pem);
    let now = chrono::Utc::now().timestamp_millis();
    if let Err(e) = statedb::shared().mint_key_put(slot, kind, &cipher, now) {
        tracing::warn!("soter: 物料 {slot} 落盘失败：{e:#}（进程重启后会换成新的一把）");
    }
}

fn ask_gone_key(scope: &str, device_id: &str, uid: i32) -> String {
    format!("{scope}|{device_id}|{uid}")
}

fn ask_is_gone(scope: &str, device_id: &str, uid: i32) -> bool {
    let key = ask_gone_key(scope, device_id, uid);
    store()
        .gone_ask
        .lock()
        .map(|set| set.contains(&key))
        .unwrap_or(false)
}

fn clear_ask_gone(scope: &str, device_id: &str, uid: i32) {
    let key = ask_gone_key(scope, device_id, uid);
    if let Ok(mut set) = store().gone_ask.lock() {
        set.remove(&key);
    }
    if let Err(e) = statedb::shared().clear_gone_ask(&key) {
        tracing::warn!("soter: 墓碑解不开（{key}）：{e:#}");
    }
}

fn mark_ask_gone(scope: &str, device_id: &str, uid: i32) {
    let key = ask_gone_key(scope, device_id, uid);
    if let Ok(mut set) = store().gone_ask.lock() {
        set.insert(key.clone());
    }
    // 真机删了就是删了，重启也得算数 —— 墓碑落库。
    if let Err(e) = statedb::shared().mark_gone_ask(&key) {
        tracing::warn!("soter: 墓碑落库失败（{key}）：{e:#}，只能先记在内存");
    }
}

/// 启动时把墓碑从库里读回来。库读不出来就当空（宁可多给一次机会，也不要卡住服务）。
fn load_gone_asks() -> HashSet<String> {
    match statedb::shared().gone_asks() {
        Ok(rows) => rows.into_iter().collect(),
        Err(e) => {
            tracing::warn!("soter: 墓碑表从 state db 读不出来（{e:#}），按空的算");
            HashSet::new()
        }
    }
}

/// 重建 ASK（`generate_ask_key_pair` 就是它）：只换这个 uid 的那一把。
fn rotate_layer_ask_key(scope: &str, uid: i32, layer: &str) -> Result<Arc<MintKey>> {
    let id = format!("{scope}|{uid}|{layer}");
    let fresh = Arc::new(MintKey::generate()?);
    let mut map = store()
        .ask
        .lock()
        .map_err(|_| anyhow!("ask material lock poisoned"))?;
    map.insert(id.clone(), fresh.clone());
    drop(map);
    persist_key(&id, "ask", &fresh, persists(scope));
    Ok(fresh)
}

/// ATTK 换了以后旧的 ASK 证书就废了（ASK 证书是 ATTK 签的），这个身份下所有 uid 的
/// ASK 缓存要一并丢掉。
fn drop_layer_ask_keys(scope: &str) {
    let prefix = format!("{scope}|");
    if let Ok(mut map) = store().ask.lock() {
        map.retain(|key, _| !key.starts_with(&prefix));
    }
    if persists(scope) {
        if let Err(e) = statedb::shared().mint_key_delete_prefix(&prefix) {
            tracing::warn!("soter: 按身份清落盘的 ASK 失败（{prefix}）：{e:#}");
        }
    }
}

// ---------------------------------------------------------------------------
// 槽位钉层
// ---------------------------------------------------------------------------

/// 钉子存哪儿：跟会话表同一个 SQLite 文件（`crate::statedb`），不再各写各的 JSON。
fn slot_id(device_id: &str, uid: i32) -> String {
    format!("{device_id}|{uid}")
}

/// 启动时把槽位表整个装进内存；读路径之后一个 DB 查询都不加。
fn load_slots() -> HashMap<String, SlotPin> {
    let snap = match statedb::shared().slots_snapshot() {
        Ok(snap) => snap,
        Err(e) => {
            tracing::warn!("soter: 槽位表从 state db 读不出来（{e:#}），按空的算");
            return HashMap::new();
        }
    };
    let mut map: HashMap<String, SlotPin> = HashMap::new();
    for (id, layer, at_millis) in snap.slots {
        map.insert(
            id,
            SlotPin {
                layer,
                at_millis,
                owners: Vec::new(),
            },
        );
    }
    // 只记了账号、没钉过层的槽位：补一条 layer 空的记录，跟旧 JSON 时的形状一致。
    for (id, family, token, last_seen_ms) in snap.owners {
        map.entry(id)
            .or_insert_with(|| SlotPin {
                layer: String::new(),
                at_millis: 0,
                owners: Vec::new(),
            })
            .owners
            .push(Owner {
                token: format!("{family}:{token}"),
                last_seen_ms,
            });
    }
    map
}

/// 钉子是不是还新鲜。
fn pin_is_fresh(at_millis: i64, now_millis: i64) -> bool {
    now_millis - at_millis <= SLOT_PIN_TTL_MILLIS
}

/// 这个槽位归哪一层（没钉过、或者钉子过期了就是 None）。
pub fn pinned_layer(device_id: &str, uid: i32) -> Option<String> {
    let now = chrono::Utc::now().timestamp_millis();
    let guard = store().slots.lock().ok()?;
    let pin = guard.get(&slot_id(device_id, uid))?;
    // `layer` 空的记录只记了账号（`note_owner` 建的），不算服务过这个槽位。
    (!pin.layer.is_empty() && pin_is_fresh(pin.at_millis, now)).then(|| pin.layer.clone())
}

/// 把槽位钉在某一层上。第一次服务这个槽位、或者换层之后都要调。
pub fn pin_layer(device_id: &str, uid: i32, layer: &str) {
    if device_id.is_empty() {
        // 请求里没点名设备（route 到哪台都可能）时钉子没有意义，不钉。
        return;
    }
    let now = chrono::Utc::now().timestamp_millis();
    let id = slot_id(device_id, uid);
    let Ok(mut map) = store().slots.lock() else {
        return;
    };
    if let Some(pin) = map.get(&id) {
        if pin.layer == layer && pin_is_fresh(pin.at_millis, now) {
            return;
        }
    }
    // 换层时这个槽位上认出来的账号得留着：那是连坐判断的判据（`note_owner`）。
    let owners = map.get(&id).map(|p| p.owners.clone()).unwrap_or_default();
    map.insert(
        id.clone(),
        SlotPin {
            layer: layer.to_string(),
            at_millis: now,
            owners,
        },
    );
    drop(map);
    if let Err(e) = statedb::shared().upsert_slot(&id, layer, now) {
        tracing::warn!("soter: 槽位钉子没写进 state db（{id}）：{e:#}");
    }
}

/// 槽位的钥匙被清掉了（`remove_all_uid_key`），钉子也拔掉：下一次走什么层都行。
///
/// **只拔钉子，账号记录留着**。账号记录是「这个槽位上原本有几个号」的判据；清
/// 钥匙的时候连它一起删，等于把证据也抹了，下一次别人问就答不出来。清的是钥匙，
/// 不是「这里曾经有过哪些号」这件事。
pub fn unpin_layer(device_id: &str, uid: i32) {
    let id = slot_id(device_id, uid);
    let Ok(mut map) = store().slots.lock() else {
        return;
    };
    if let Some(pin) = map.get_mut(&id) {
        pin.layer.clear();
        pin.at_millis = 0;
    }
    drop(map);
    if let Err(e) = statedb::shared().delete_slot_pin(&id) {
        tracing::warn!("soter: 槽位（{id}）的钉子没从 state db 拔掉：{e:#}");
    }
}

/// 太久没见到的账号记录按 TTL 丢掉（内存和库一起）。看一眼是 O(槽位数) 的，
/// 节流到 `OWNER_PURGE_INTERVAL_MS`。
fn purge_owners_if_due() {
    let now = chrono::Utc::now().timestamp_millis();
    let last = LAST_OWNER_PURGE.load(Ordering::Relaxed);
    if now.saturating_sub(last) < OWNER_PURGE_INTERVAL_MS {
        return;
    }
    LAST_OWNER_PURGE.store(now, Ordering::Relaxed);
    let cutoff = now - OWNER_TTL_MILLIS;
    let swept = {
        let Ok(mut map) = store().slots.lock() else {
            return;
        };
        let mut swept = 0usize;
        for pin in map.values_mut() {
            let before = pin.owners.len();
            // 时间戳 0 的不清：那是「不知道什么时候见的」，不是「很久没见」。
            pin.owners
                .retain(|o| o.last_seen_ms == 0 || o.last_seen_ms >= cutoff);
            swept += before - pin.owners.len();
        }
        // layer 空的槽位本来就只是「账号登记」，账号清完了整条就可以扔掉。
        map.retain(|_, pin| !pin.layer.is_empty() || !pin.owners.is_empty());
        // owner_touch 只是节流用的时间戳，槽位没了就跟着丢。
        if let Ok(mut touch) = store().owner_touch.lock() {
            touch.retain(|id, _| map.contains_key(id));
        }
        swept
    };
    match statedb::shared().purge_owners_expired_before(cutoff) {
        Ok(n) if n > 500 => tracing::warn!(
            "soter: 账号指纹过期一次清掉 {n} 条（内存 {swept} 条）—— 量偏大，留意时间戳是不是有问题"
        ),
        Ok(n) if n > 0 || swept > 0 => {
            tracing::info!("soter: 账号指纹过期清掉 {n} 条（内存 {swept} 条）")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("soter: 账号指纹过期清理失败：{e:#}"),
    }
}

// ---------------------------------------------------------------------------
// 这个槽位上一个账号还是好几个
// ---------------------------------------------------------------------------
//
// 为什么要数：SOTER 的钥匙在 TA 里按 uid 存一包，`remove_all_uid_key`（HAL 12 /
// AIDL 7 `removeAppGlobalSecureKey`）清的是整包 —— ASK 加上这个 uid 上**每一个**
// 账号的 AuthKey。而微信自己就会打这一枪，逆向 classes13.dex 看得很清楚：
//
//   - `d36/p0.a(false)`：ASK 公钥上传腾讯校验失败 → `q26.a.r()` 当场清；
//   - `d36/m0`（Soter.TaskInit）：`WechatASK` 状态非 0（含「从没写过」的默认 -1）
//     并且 ASK 存在 → 清；
//   - `d36/q0.f()`：ASK 生成被取消 → 清。
//
// 真机上微信一个 uid 只有一个号，清的是自己；我们这里十几个号挤一个 uid（实测一台
// B 端最多 28 个 `WechatAuthKeyPay&<微信号>`）。一枪下去，同 uid 上别人的开通记录
// 一起没了 —— 私钥只在 TA 里，重建出来是新的，腾讯那边存着的公钥对不上，之后
// 指纹支付就一直失败。所以要数清楚，好把这一枪拦下来（见 `handlers::soter`）。

/// 一个槽位里每一族最多记几个账号指纹（跟 `statedb::OWNER_FAMILY_CAP` 同一口径）。
///
/// 这里原来是三族合计 64 条。实测单个 uid 上最多已经 33 个账号（三族共 95 条指纹），
/// 也就是早就在截断了 —— 而线上几百个人一起用，一个 uid 上堆到上百个号完全可能。
/// 截断只会漏保护（判据取同族条数，多算不了），但没必要省这点空间。
const OWNER_CAP: usize = statedb::OWNER_FAMILY_CAP;

/// 同一族里已经记过的账号没必要每次请求都刷一遍「最近见到」，一个槽位一小时一次就够。
const OWNER_TOUCH_INTERVAL_MS: i64 = 60 * 60 * 1000;

/// 从别名里抠出「这是谁的钥匙」。
///
/// 微信一个账号会留下三族别名，而且盐各不相同 —— 同一个账号的旧盐是 `md5(微信号)`、
/// 新盐是 `md5(uin)`，所以本来就得按族分开数：
///
///   - `WechatAuthKeyPay&<微信号>`（scene1 的旧名字）
///   - `SoterAuthKeyV2_salt<md5(uin)[0:8]>_sceneN`（现在的名字）
///   - `SoterAuthKey_salt<md5(微信号)[0:8]>_sceneN`（旧名字，迁移时被删）
///
/// 别的别名（工具自己造的）不算，免得一份探针流量把槽位看成「共用」。
fn owner_token(alias: &str) -> Option<String> {
    if let Some(pos) = alias.find("WechatAuthKeyPay&") {
        let account = alias[pos + "WechatAuthKeyPay&".len()..].trim();
        return (!account.is_empty() && account != "null").then(|| format!("wx:{account}"));
    }
    if let Some(pos) = alias.find("SoterAuthKeyV2_salt") {
        return salt_after(&alias[pos + "SoterAuthKeyV2_salt".len()..]).map(|s| format!("v2:{s}"));
    }
    if let Some(pos) = alias.find("SoterAuthKey_salt") {
        return salt_after(&alias[pos + "SoterAuthKey_salt".len()..]).map(|s| format!("v1:{s}"));
    }
    None
}

/// `SoterAuthKey*_salt<盐>_sceneN` 里那个盐。
fn salt_after(rest: &str) -> Option<String> {
    let salt = rest.split('_').next().unwrap_or("");
    (!salt.is_empty()).then(|| salt.to_string())
}

/// 这个槽位上记着的账号指纹（太久没见到的按 TTL 不算）。
pub fn owners_of(device_id: &str, uid: i32) -> Vec<String> {
    let now = chrono::Utc::now().timestamp_millis();
    store()
        .slots
        .lock()
        .ok()
        .and_then(|map| {
            map.get(&slot_id(device_id, uid)).map(|p| {
                p.owners
                    .iter()
                    // 0 = 不知道什么时候见的，按「还有效」算（`purge` 那边也不清它）。
                    .filter(|o| o.last_seen_ms == 0 || now - o.last_seen_ms <= OWNER_TTL_MILLIS)
                    .map(|o| o.token.clone())
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// 这个槽位上有几个账号。同一个族里出现两个指纹才算两个：一个账号在每一族里最多
/// 只有一个指纹，所以「同族两个」是「两个账号」的充分条件，也不会把同一个账号的
/// 旧盐新盐算成两个人。
pub fn owner_count(device_id: &str, uid: i32) -> usize {
    let mut wx = std::collections::HashSet::new();
    let mut v1 = std::collections::HashSet::new();
    let mut v2 = std::collections::HashSet::new();
    for token in owners_of(device_id, uid) {
        match token.split_once(':') {
            Some(("wx", id)) => {
                wx.insert(id.to_string());
            }
            Some(("v1", id)) => {
                v1.insert(id.to_string());
            }
            Some(("v2", id)) => {
                v2.insert(id.to_string());
            }
            _ => {}
        }
    }
    wx.len().max(v1.len()).max(v2.len())
}

/// 记下这个槽位上一个账号的指纹。请求里没点名设备（route 到哪台都行）时不记。
pub fn note_owner(device_id: &str, uid: i32, alias: &str) {
    if device_id.is_empty() {
        return;
    }
    let Some(token) = owner_token(alias) else {
        return;
    };
    // 拆出来的两段要活到后面，所以拷一份，别把 `token` 借住（push 的时候要 move 它）。
    let (family, value) = match token.split_once(':') {
        Some((f, v)) => (f.to_string(), v.to_string()),
        None => return,
    };
    let id = slot_id(device_id, uid);
    let now = chrono::Utc::now().timestamp_millis();
    let Ok(mut map) = store().slots.lock() else {
        return;
    };
    let entry = map.entry(id.clone()).or_insert_with(|| SlotPin {
        layer: String::new(),
        at_millis: 0,
        owners: Vec::new(),
    });
    // 记过的只把「最近见到」顶到当下（内存里每次都顶；库里节流，见 touch_owner）。
    if let Some(o) = entry.owners.iter_mut().find(|o| o.token == token) {
        o.last_seen_ms = now;
        drop(map);
        touch_owner(&id, &family, &value);
        return;
    }
    // 同一族按条数封顶，不是三族合计：一个账号在每一族最多留一个指纹。
    // 满了就把这一族最久没见到的那条换出去（LRU）—— 丢的是没人用的那个，
    // 正在用的号不会被新号挤掉。
    let family_prefix = format!("{family}:");
    let in_family = entry
        .owners
        .iter()
        .filter(|o| o.token.starts_with(&family_prefix))
        .count();
    if in_family >= OWNER_CAP {
        if let Some(idx) = entry
            .owners
            .iter()
            .enumerate()
            .filter(|(_, o)| o.token.starts_with(&family_prefix))
            .min_by_key(|(_, o)| o.last_seen_ms)
            .map(|(i, _)| i)
        {
            entry.owners.remove(idx);
        }
    }
    entry.owners.push(Owner {
        token: token.clone(),
        last_seen_ms: now,
    });
    drop(map);

    match statedb::shared().add_owner(&id, &family, &value, now, OWNER_CAP) {
        Ok(add) => {
            if add.inserted {
                // 这行日志就是线上「一个 uid 挤了几个号」的读数。
                tracing::info!(
                    "soter: 槽位 {device_id}|{uid} 上认到第 {} 个账号指纹（{family}）",
                    add.family_count
                );
            }
            if let Ok(mut touch) = store().owner_touch.lock() {
                touch.insert(id, now);
            }
        }
        Err(e) => tracing::warn!("soter: 账号指纹没写进 state db（{id}）：{e:#}"),
    }
}

/// 记过的账号：需要时把「最近见到」的时间刷进库（节流到 `OWNER_TOUCH_INTERVAL_MS`）。
fn touch_owner(slot_id: &str, family: &str, value: &str) {
    let now = chrono::Utc::now().timestamp_millis();
    let Ok(mut touch) = store().owner_touch.lock() else {
        return;
    };
    if let Some(last) = touch.get(slot_id) {
        if now - *last < OWNER_TOUCH_INTERVAL_MS {
            return;
        }
    }
    touch.insert(slot_id.to_string(), now);
    drop(touch);
    if let Err(e) = statedb::shared().add_owner(slot_id, family, value, now, OWNER_CAP) {
        tracing::debug!("soter: 账号指纹的最近见到没刷上（{slot_id}）：{e:#}");
    }
}

/// uid 级全清要不要降级成「只答成功、不真清」。
///
/// **默认不降级（真清）。** 接口说删就得删：答成功却没删，应用唯一的自救路径就失效
/// 了 —— 2026-10-20 实测微信就是踩这条进死循环（答 0 之后 `has_ask_already` 还是 0，
/// 它就一直重建）。真要保留旧的「防连坐」降级，设 `RELAY_SOTER_SCOPE_WIPE=1`。
fn scope_wipe_from(value: Option<&str>) -> bool {
    matches!(value, Some("1") | Some("true") | Some("yes") | Some("on"))
}

pub fn scope_wipe_enabled() -> bool {
    scope_wipe_from(std::env::var("RELAY_SOTER_SCOPE_WIPE").ok().as_deref())
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

/// 跑一层服务端 SOTER。
///
/// 返回 `None` 表示"这一层不认识这个 op"，`Some` 里带 `error` 表示这层试过但没
/// 成 —— 两种情况调用方都该继续回退下一层。成功就是一份跟 B 端形状一致的应答。
///
/// 层名三选一：`keybox`（服务端存的设备身份）、`self_signed`（极端兜底）、`builtin`
/// （探测机就地作答专用，见 `crate::soter_probe`）。`builtin` 的料是自己一把、永不
/// 轮换，就是不想让探测流量一直换全局 ASK、把别人正跑着的槽位劈成两半。
/// 这两层认得的 op；不认得的直接让下一层试，连物料都不用取。
const KNOWN_OPS: &[&str] = &[
    "probe",
    "get_device_id",
    "export_attk_public_key",
    "export_ask_public_key",
    "export_auth_key_public_key",
    "has_ask_already",
    "has_auth_key",
    "generate_ask_key_pair",
    "generate_attk_key_pair",
    "generate_auth_key_pair",
    "init_sign",
    "finish_sign",
    "remove_auth_key",
    "remove_all_uid_key",
    "verify_attk_key_pair",
];

pub fn run(layer: &str, device_id: &str, body: &Value, key_pem: Option<&str>) -> Option<Value> {
    run_layer(layer, device_id, body, key_pem, None)
}

/// 带身份的版本：`attk` 层（服务端密钥模式）需要把上传的那把 ATTK 递进来。
pub fn run_layer(
    layer: &str,
    device_id: &str,
    body: &Value,
    key_pem: Option<&str>,
    attk: Option<&AttkMaterial>,
) -> Option<Value> {
    // 账号指纹的 TTL 清理：节流在里面，不会拖慢请求。
    purge_owners_if_due();
    let op = body.get("op").and_then(Value::as_str).unwrap_or("probe");
    // 身份号（cpu_id）从哪来：
    //   - `attk` 层：就是上传那把 ATTK 的 cpu_id。A 端转过来的真机号在这儿不作数 ——
    //     ASK 证书是这把 ATTK 签的，签的是一台机器、App 却按另一台去验，谁也验不过。
    //   - 其余三层：A 端把真机的 cpu_id 一起转过来了就用它的。同一台设备上，本地兜底
    //     那条路、服务端这几层、还有 B 端 TEE 必须报同一个号，否则「两次 cpuid 不一致」
    //     的检测项就亮红。没给（老 A 端）或者给得不成样子才回落到按时间现造的虚拟号。
    let product = if layer == "attk" {
        let own = attk.map(|a| a.cpu_id.trim()).unwrap_or("");
        if is_soter_cpu_id(own) {
            own.to_string()
        } else {
            tracing::warn!(
                "soter: attk 层的 cpu_id {own:?} 形状不对（要 32 个十六进制字符），\
                 先按当前时间现造一个顶上"
            );
            time_device_id()
        }
    } else {
        docs_cpu_id(body).unwrap_or_else(|| {
            if body.get(CPU_ID_FIELD).is_some() {
                tracing::warn!(
                    "soter: {layer} 层收到形状不对的 cpu_id {:?}，按当前时间现造一个",
                    body.get(CPU_ID_FIELD)
                );
            }
            // 老 A 端不带 cpu_id：按当时的年月日时分现造一个。同一分钟内稳定，
            // 一轮 ASK/AuthKey 流程跑在同一分钟里就能对上；不再用按设备名派生的那个，
            // 免得到处都是同一个号、探测器一对比就认出来。
            time_device_id()
        })
    };

    if !KNOWN_OPS.contains(&op) {
        return None;
    }

    // 物料按身份分家（见 `material_scope`），换 ATTK 不会拿旧 AuthKey 顶上。
    let scope = material_scope(layer, attk);

    let key = match material(layer, key_pem, attk) {
        Ok(key) => key,
        Err(e) => {
            return Some(json!({
                "error": format!("layer '{layer}' cannot serve SOTER: {e:#}"),
            }));
        }
    };

    let result: Result<Value> = (|| -> Result<Value> {
        match op {
            "probe" => Ok(json!({
                "op": "probe",
                "supported": true,
                "layer": layer,
                "service": "ommega-server-soter",
                "interface": "server-side",
                "version": 1,
                "device_id": product,
            })),
            "get_device_id" => {
                // 带上层名：A 端要靠它分辨这个号是真机报的还是服务端自己造的（只有
                // 真机那个值能当设备身份转出去，见 `docs_cpu_id`）。
                // 形状跟平台：高通回 16 字节 raw（hex 出来就是 cpu_id），MTK 回
                // 32 个 ASCII 十六进制字符 + `\0`（33 字节）。
                let profile = profile_of(&product);
                let raw = if profile.device_id_ascii {
                    let mut bytes = product.as_bytes().to_vec();
                    bytes.push(0);
                    bytes
                } else {
                    hex_bytes(&product).unwrap_or_default()
                };
                let mut out = data_result(op, OK, &raw);
                out["layer"] = json!(layer);
                Ok(out)
            }
            "export_attk_public_key" => Ok(data_result(op, OK, key.attk_pem.as_bytes())),
            // 导出的是 **ASK** 的公钥（跟 ATTK 是两把），文档用 ATTK 签 —— 与真机一致。
            "export_ask_public_key" => {
                let uid = uid_of(body)?;
                // 删过就不再现造（墓碑）：真机删了就是没了。
                if ask_is_gone(&scope, device_id, uid) {
                    return Ok(code_result(op, NOT_FOUND));
                }
                let ask = layer_ask_key(&scope, uid, layer)?;
                ask_result(op, layer, &scope, &ask, &key, &product, uid)
            }
            // `has_ask_already`：
            //
            //   - `attk` 层（服务端密钥模式）：**如实回答**。这一层的 ASK 是用上传的
            //     那把真 ATTK 签的，App 拿着它能走完上报，所以它跟自签层不是一回事：
            //     一直答 -5 的话 App 每轮都判「没有 ASK」，建一把、导一把、上报、
            //     清掉重来，永远走不到下一步（2026-11-06 微信实测就是这个圈）。
            //     为不然重启就换身份，ASK/AuthKey 跟计数器都是落盘的。
            //
            //   - 自签 / keybox 两层：**不许声称「ASK 已存在」**（2026-10-11 实测的
            //     毒化根源）。它们现造的 ASK 腾讯永远不会认，照答 OK 会让 App 跳过
            //     上报、拿着假 ASK 去建 AuthKey，被拒了再自删重试 —— B 不在线时兑
            //     一次底就把该槽位永久毒化。现在答 `NOT_FOUND`（「没有」），App 会
            //     老实地重新生成并**上报**，真机一回来就能走通。
            "has_ask_already" => {
                if layer != "attk" {
                    return Ok(code_result(op, NOT_FOUND));
                }
                let uid = uid_of(body)?;
                if ask_is_gone(&scope, device_id, uid) {
                    return Ok(code_result(op, NOT_FOUND));
                }
                let id = format!("{scope}|{uid}|{layer}");
                let in_memory = store()
                    .ask
                    .lock()
                    .map(|map| map.contains_key(&id))
                    .unwrap_or(false);
                let on_disk =
                    !in_memory && statedb::shared().mint_key_get(&id).ok().flatten().is_some();
                Ok(code_result(
                    op,
                    if in_memory || on_disk { OK } else { NOT_FOUND },
                ))
            }
            "verify_attk_key_pair" => Ok(code_result(op, OK)),
            "has_auth_key" => Ok(code_result(
                op,
                if auth_key(device_id, &scope, body).is_some() {
                    OK
                } else {
                    AUTH_KEY_NOT_READY
                },
            )),
            "export_auth_key_public_key" => match auth_key(device_id, &scope, body) {
                // 回的是「AuthKey 的自描述 + 签名」的信封，签名用 **ASK** 私钥 ——
                // 真机上 AuthKey 证书就是 ASK 签的，App 拿 exportAskPublicKey 的
                // 公钥验这一份（用 ATTK 签就验不过）。
                Some(auth) => {
                    if ask_is_gone(&scope, device_id, uid_of(body)?) {
                        return Ok(code_result(op, AUTH_KEY_NOT_READY));
                    }
                    let ask = layer_ask_key(&scope, uid_of(body)?, layer)?;
                    let counter = counter_for(&counter_key(&scope, device_id, uid_of(body)?));
                    let document = key_doc(&auth.attk_pem, &product, counter, uid_of(body)?)?;
                    let signature = ask.sign(&document)?;
                    let mut out = envelope_result(op, &document, &signature)?;
                    out["layer"] = json!(layer);
                    Ok(out)
                }
                None => Ok(code_result(op, AUTH_KEY_NOT_READY)),
            },
            "generate_auth_key_pair" => {
                let fresh = std::sync::Arc::new(
                    MintKey::generate().context("RSA keygen for the auth key failed")?,
                );
                let id = auth_key_id(device_id, &scope, body)?;
                if let Ok(mut map) = store().auth.lock() {
                    map.insert(id.clone(), fresh.clone());
                }
                persist_key(&id, "auth", &fresh, persists(&scope));
                Ok(code_result(op, OK))
            }
            "remove_auth_key" => {
                let id = auth_key_id(device_id, &scope, body)?;
                if let Ok(mut map) = store().auth.lock() {
                    map.remove(&id);
                }
                if persists(&scope) {
                    if let Err(e) = statedb::shared().mint_key_delete(&id) {
                        tracing::warn!("soter: 删落盘的 AuthKey 失败（{id}）：{e:#}");
                    }
                }
                Ok(code_result(op, OK))
            }
            "remove_all_uid_key" => {
                let uid = uid_of(body)?;
                let prefix = format!("{scope}|{device_id}|{uid}|");
                if let Ok(mut map) = store().auth.lock() {
                    map.retain(|k, _| !k.starts_with(&prefix));
                }
                // ASK 的槽位串里没带设备名（`{scope}|{uid}|ask`），单独按它删。
                let ask_id = format!("{scope}|{uid}|{layer}");
                if let Ok(mut map) = store().ask.lock() {
                    map.remove(&ask_id);
                }
                if persists(&scope) {
                    let db = statedb::shared();
                    if let Err(e) = db.mint_key_delete(&ask_id) {
                        tracing::warn!("soter: 删落盘的 ASK 失败（{ask_id}）：{e:#}");
                    }
                    if let Err(e) = db.mint_key_delete_prefix(&prefix) {
                        tracing::warn!("soter: 删落盘的 AuthKey 失败（{prefix}）：{e:#}");
                    }
                }
                // 不能靠“缓存没了就现造”顶上去：盖个墓碑，等 generate 才解。
                mark_ask_gone(&scope, device_id, uid);
                // 钥匙没了，槽位的钉子也跟着拔：下次哪一层服务它都算从头来。
                unpin_layer(device_id, uid);
                Ok(code_result(op, OK))
            }
            // 重建 ASK：只换 ASK，不动 ATTK（两把）。AuthKey 是 ASK 签的，
            // 换了 ASK 它们也就验不过了，App 会自己重新生成。
            "generate_ask_key_pair" => {
                clear_ask_gone(&scope, device_id, uid_of(body)?);
                rotate_layer_ask_key(&scope, uid_of(body)?, layer)?;
                unpin_layer(device_id, uid_of(body)?);
                Ok(code_result(op, OK))
            }
            "generate_attk_key_pair" => {
                // 自签层换一把新 ATTK；keybox 层这把是服务端存的身份，轮换不了
                // —— 但也不能回错误：一报错调用方就往下换层，这个槽位的材料立刻
                // 劈成两半。它的 ATTK 本来就在，回成功，让流程留在这层里。
                if layer == "self_signed" {
                    rotate_self_signed_key()?;
                } else if layer == "keybox" {
                    tracing::info!(
                        "soter: layer={layer} 拿着服务端存的身份，{op} 不轮换、直接回成功"
                    );
                }
                // ATTK 换了，旧 ASK 证书就废了（ASK 证书是 ATTK 签的）。
                drop_layer_ask_keys(&scope);
                unpin_layer(device_id, uid_of(body)?);
                Ok(code_result(op, OK))
            }
            "init_sign" => {
                let uid = uid_of(body)?;
                let alias = alias_of(body)?;
                if auth_key(device_id, &scope, body).is_none() {
                    // AuthKey 没建就是没建，真机这里答 -6（AUTH_KEY_NOT_READY）；
                    // 答 -5 会被上层当成「ASK 还没准备好」。
                    return Ok(code_result(op, AUTH_KEY_NOT_READY));
                }
                let raw = body
                    .get("challenge")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let session = {
                    let mut next = store()
                        .next_session
                        .lock()
                        .map_err(|_| anyhow!("session lock poisoned"))?;
                    *next += 1;
                    let session = *next;
                    let mut sessions = store()
                        .sessions
                        .lock()
                        .map_err(|_| anyhow!("session lock poisoned"))?;
                    sessions.insert(
                        session,
                        SignSession {
                            requested: body
                                .get("device_id")
                                .and_then(Value::as_str)
                                .unwrap_or(device_id)
                                .to_string(),
                            device: device_id.to_string(),
                            layer: layer.to_string(),
                            attk_id: attk.map(|a| a.id),
                            uid,
                            alias,
                            raw,
                        },
                    );
                    session
                };
                Ok(json!({
                    "op": "init_sign",
                    "error_code": OK,
                    "session": session,
                }))
            }
            "finish_sign" => {
                let session = body.get("session").and_then(Value::as_i64).unwrap_or(0);
                let sign_session = match store().sessions.lock().ok().and_then(|mut m| {
                    let requested = body
                        .get("device_id")
                        .and_then(Value::as_str)
                        .unwrap_or(device_id);
                    let owner = m.get(&session)?;
                    if owner.requested != requested
                        || owner.device != device_id
                        || owner.layer != layer
                    {
                        return None;
                    }
                    m.remove(&session)
                }) {
                    Some(s) => s,
                    None => return Ok(code_result(op, SESSION_UNKNOWN)),
                };
                // 会话里记着它当初由哪把身份开出来，这里按同一个 scope 取 AuthKey。
                let session_scope = moment_scope(layer, sign_session.attk_id);
                let key = match store().auth.lock().ok().and_then(|m| {
                    m.get(&format!(
                        "{session_scope}|{device_id}|{}|{}",
                        sign_session.uid, sign_session.alias
                    ))
                    .cloned()
                }) {
                    Some(key) => key,
                    None => return Ok(code_result(op, NOT_FOUND)),
                };
                // 签的是那段 JSON 原文，不是 challenge 的字节；回「JSON + 签名」的信封
                let counter =
                    counter_for(&counter_key(&session_scope, device_id, sign_session.uid));
                let document = sign_doc(
                    &product,
                    sign_session.uid,
                    &sign_session.raw,
                    counter,
                    layer,
                )?;
                match key.sign(&document) {
                    Ok(signature) => Ok(envelope_result(op, &document, &signature)?),
                    Err(e) => Err(e),
                }
            }
            _ => unreachable!("op '{op}' was checked before dispatch"),
        }
    })();

    match result {
        Ok(value) => Some(value),
        Err(e) => Some(json!({ "error": format!("{e:#}") })),
    }
}

// ---------------------------------------------------------------------------
// 参数与应答形状
// ---------------------------------------------------------------------------

fn uid_of(body: &Value) -> Result<i32> {
    body.get("uid")
        .and_then(Value::as_i64)
        .map(|v| v as i32)
        .ok_or_else(|| anyhow!("soter payload needs the owning Android app uid"))
}

fn alias_of(body: &Value) -> Result<String> {
    body.get("alias")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("soter payload needs the key alias"))
}

fn auth_key_id(device_id: &str, scope: &str, body: &Value) -> Result<String> {
    Ok(format!(
        "{scope}|{device_id}|{}|{}",
        uid_of(body)?,
        alias_of(body)?
    ))
}

fn auth_key(device_id: &str, scope: &str, body: &Value) -> Option<Arc<MintKey>> {
    let id = auth_key_id(device_id, scope, body).ok()?;
    if let Some(hit) = store().auth.lock().ok()?.get(&id).cloned() {
        return Some(hit);
    }
    // 重启后内存是空的：库里那把还是用户的 AuthKey，捞回来接着用。
    let loaded = load_persisted_key(&id, persists(scope))?;
    if let Ok(mut map) = store().auth.lock() {
        map.insert(id, loaded.clone());
    }
    Some(loaded)
}

/// 请求里那个「真机 cpu_id」的字段名。A 端转发时带上，B 端不带（B 自己也改不了它）。
pub(crate) const CPU_ID_FIELD: &str = "cpu_id";

/// A 端转过来的真机 `cpu_id`，形状对（32 个十六进制字符）就用它。
///
/// 为什么要认它：SOTER 的身份就是 `(cpu_id, uid)`。同一次开通流程里，`get_device_id`、
/// ASK 文档、AuthKey 文档、签名现场四处的 `cpu_id` 只要有一处跟真机报的不一样，微信和
/// 检测器就会判成「设备换了」/「两次 cpuid 不一致」，然后拿新身份重走一遍（检测器直接
/// 记一条红）。真机那个号只有 B 端 TEE 有，所以 A 端学会了转过来，这里照抄。
fn docs_cpu_id(body: &Value) -> Option<String> {
    let text = body.get(CPU_ID_FIELD)?.as_str()?.trim();
    is_soter_cpu_id(text).then(|| text.to_string())
}

/// 真机 cpu_id 的形状：32 个十六进制字符（真机的都是 `09000000` 打头，但不拿前缀卡死，
/// 以后换代次也不用改）。
fn is_soter_cpu_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// 32 字符 hex 转 16 字节。旧版 getDeviceId 答复的二进制形状，现在已经改成跟真机
/// 一样的 ASCII + NUL 了；留着是因为偶尔还要把 `cpu_id` 对成 16 字节看一眼。
#[allow(dead_code)]
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// 请求里没带 cpu_id 时现造一个设备号：`09000000` +
/// `sha256("ommega-server-soter-time:" + YYYYMMDDHHMM)` 前 12 字节。
///
/// 按分钟：同一分钟的 ASK / AuthKey / 签名现场报同一个号，不会一轮流程中途换身份；
/// 又不会跟别的设备、别的时间撞成同一串值。
fn time_device_id() -> String {
    let stamp = chrono::Utc::now().format("%Y%m%d%H%M").to_string();
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-server-soter-time:");
    hasher.update(stamp.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::from("09000000");
    for byte in &digest[..12] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 早先用过的「按设备名派生」的虚拟 SOTER 设备号。现在不再当兜底用（兜底那个是
/// [`time_device_id`]），留在这里只给测试当「跟按时间造的绝不是同一个」的对照组。
#[cfg(test)]
fn virtual_device_id(device_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-server-soter:");
    hasher.update(device_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::from("09000000");
    for byte in &digest[..12] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn counter_for(key: &str) -> u64 {
    let persisted = persists(key);
    let Ok(mut map) = store().counters.lock() else {
        return 1;
    };
    // 重启后计数器不能从 1 重新数：App 会看它（真机上同一个 uid 只增不减）。
    if !map.contains_key(key) && persisted {
        if let Ok(Some(value)) = statedb::shared().mint_counter_get(key) {
            map.insert(key.to_string(), value.max(0) as u64);
        }
    }
    let entry = map.entry(key.to_string()).or_insert(0);
    *entry += 1;
    let value = *entry;
    drop(map);
    if persisted {
        if let Err(e) = statedb::shared().mint_counter_put(key, value as i64) {
            tracing::warn!("soter: 计数器落盘失败（{key}）：{e:#}");
        }
    }
    value
}

/// 签名计数器的键：身份 + 设备 + uid。身份也得算进去，否则同一台设备换一把 ATTK
/// 后计数器継续从旧值走，真机上「同一个 uid 的计数器只增不减」那个规律就对不上了。
fn counter_key(scope: &str, device_id: &str, uid: i32) -> String {
    format!("{scope}|{device_id}|{uid}")
}

/// 真机形状是按平台分的（两台实测）：
///   - 高通（SM8635）：`cpu_id` 以 `00000000` 开头、getDeviceId 回 16 字节 raw、
///     文档里**不带** `rsa_pss_saltlen` 字段；
///   - MTK（MT6991 / Kinibi）：`cpu_id` 以 `09000000` 开头、getDeviceId 回 32 ASCII + NUL、
///     文档带 `rsa_pss_saltlen:32`。
///
/// 服务端拿不到 A/B 的 SoC，但 `cpu_id` 本身带着平台前缀 —— 自己造的时候按它选形状，
/// 跟转发过来的那个真机号保持一致。
#[derive(Clone, Copy)]
struct Platform {
    declares_salt: bool,
    device_id_ascii: bool,
}

fn profile_of(cpu_id: &str) -> Platform {
    if cpu_id.starts_with("09000000") {
        Platform {
            declares_salt: true,
            device_id_ascii: true,
        }
    } else {
        Platform {
            declares_salt: false,
            device_id_ascii: false,
        }
    }
}

/// 一份自描述文档（ASK 或 AuthKey 的都用它）。键序照现场抓到的来：`pub_key` /
/// `cpu_id` / `counter` / `uid`（+ MTK 那套的 `rsa_pss_saltlen`），`uid` 是字符串。
fn key_doc(pub_key_pem: &str, device_id: &str, counter: u64, uid: i32) -> Result<Vec<u8>> {
    let mut doc = json!({
        "pub_key": pub_key_pem,
        "cpu_id": device_id,
        "counter": counter,
        "uid": uid.to_string(),
    });
    if profile_of(device_id).declares_salt {
        doc["rsa_pss_saltlen"] = json!(ASK_SALT_LEN);
    }
    serde_json::to_vec(&doc).context("failed to serialize the key document")
}

/// 签名现场那份 JSON。字段名和键序照 B 端 TEE 现场抓的来（`raw` 在最前），一个
/// 都不能少 —— App 会把它们存下来当设备指纹。服务端两层是虚拟设备，指纹和 TEE
/// 这几个字段没有真值，用固定值加这台设备派生的 fid 填，稳定可复现就行。
fn sign_doc(cpu_id: &str, uid: i32, raw: &str, counter: u64, layer: &str) -> Result<Vec<u8>> {
    let mut doc = json!({
        "raw": raw,
        "fid": fid_of(cpu_id),
        "counter": counter,
        "tee_n": "ommega-server-soter",
        "tee_v": env!("CARGO_PKG_VERSION"),
        "fp_n": "server",
        "fp_v": layer,
        "cpu_id": cpu_id,
        "uid": uid.to_string(),
    });
    if profile_of(cpu_id).declares_salt {
        doc["rsa_pss_saltlen"] = json!(ASK_SALT_LEN);
    }
    serde_json::to_vec(&doc).context("failed to serialize the sign document")
}

/// 虚拟设备的指纹 id：跟真机一个形状（十位十进制），同一台设备每次都一样。
fn fid_of(cpu_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-server-soter-fid:");
    hasher.update(cpu_id.as_bytes());
    let digest = hasher.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 4_000_000_000;
    (1_000_000_000u64 + n as u64).to_string()
}

/// 信封应答：`[i32 le JSON 长度][JSON][256 字节签名]` —— 跟 B 端一个形状，
/// A 端那一套解析就能直接用。
fn envelope_result(op: &str, document: &[u8], signature: &[u8]) -> Result<Value> {
    let mut data = Vec::with_capacity(4 + document.len() + signature.len());
    data.extend_from_slice(&(document.len() as i32).to_le_bytes());
    data.extend_from_slice(document);
    data.extend_from_slice(signature);
    let mut out = data_result(op, OK, &data);
    out["json_bytes"] = json!(document.len());
    out["signature"] = json!(b64(signature));
    out["payload"] = serde_json::from_slice(document)?;
    Ok(out)
}

/// ASK 的自描述文档：`pub_key` 是 **ASK 的公钥**，签名用 **ATTK** —— 真机上 ASK 证书
/// 就是 ATTK 签的，App 先拿 exportAttkPublicKey 再验这一份。
fn ask_result(
    op: &str,
    layer: &str,
    scope: &str,
    ask: &MintKey,
    attk: &MintKey,
    device_id: &str,
    uid: i32,
) -> Result<Value> {
    let counter = counter_for(&counter_key(scope, device_id, uid));
    let document = key_doc(&ask.attk_pem, device_id, counter, uid)?;
    let signature = attk.sign(&document)?;
    let mut out = envelope_result(op, &document, &signature)?;
    out["layer"] = json!(layer);
    Ok(out)
}

/// 跟 B 端 `data_result` 一模一样的形状，A 端那边一套解析就够用。
fn data_result(op: &str, error_code: i32, data: &[u8]) -> Value {
    let mut out = json!({
        "op": op,
        "error_code": error_code,
        "length": data.len(),
        "data": b64(data),
    });
    if let Some(text) = printable(data) {
        out["text"] = json!(text);
    }
    out
}

fn code_result(op: &str, error_code: i32) -> Value {
    json!({ "op": op, "error_code": error_code })
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn printable(data: &[u8]) -> Option<&str> {
    if data.is_empty() {
        return None;
    }
    if !data
        .iter()
        .all(|b| (0x20..=0x7e).contains(b) || matches!(b, b'\n' | b'\r' | b'\t'))
    {
        return None;
    }
    std::str::from_utf8(data).ok()
}

/// 测试用：把 ASK payload 拆回 (JSON, 签名)，字节序跟 B 端一致（小端）。
#[cfg(test)]
pub fn split_ask_payload(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < 4 {
        return Err(anyhow!("ASK payload is too short to hold the JSON length"));
    }
    let len = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if len <= 0 || 4 + len as usize > data.len() {
        return Err(anyhow!(
            "ASK inner JSON length {len} does not fit the payload"
        ));
    }
    let len = len as usize;
    Ok((&data[4..4 + len], &data[4 + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `get_device_id` 的答复（实测真机是 32 个 ASCII 十六进制字符 + `\0`，共 33 字节）
    /// 取成字符串，好跟 `cpu_id` 那种 32 字符串直接比。
    fn device_id_text(value: &Value) -> String {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(value["data"].as_str().expect("data"))
            .expect("base64");
        assert_eq!(raw.len(), 33, "真机形状是 33 字节：32 个字符 + NUL");
        assert_eq!(raw[32], 0, "末尾那个字节是 NUL");
        String::from_utf8(raw[..32].to_vec()).expect("hex text is ascii")
    }

    use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
    use rsa::signature::Verifier;

    fn ask_payload_for(device: &str, uid: i64) -> Value {
        run(
            "self_signed",
            device,
            &json!({ "op": "export_ask_public_key", "uid": uid }),
            None,
        )
        .expect("self-signed layer should handle export_ask_public_key")
    }

    fn ask_payload(uid: i64) -> Value {
        ask_payload_for("device-a-test", uid)
    }

    #[test]
    fn probe_reports_supported() {
        let value = run(
            "self_signed",
            "device-a-test",
            &json!({ "op": "probe" }),
            None,
        )
        .expect("probe is handled");
        assert_eq!(value["supported"], json!(true));
        assert_eq!(value["layer"], json!("self_signed"));
    }

    #[test]
    fn ask_payload_verifies_against_the_exported_attk() {
        let payload = ask_payload(10373);
        assert_eq!(payload["error_code"], json!(0));
        let data = base64::engine::general_purpose::STANDARD
            .decode(payload["data"].as_str().expect("data is base64"))
            .expect("payload decodes");
        let (document, signature) = split_ask_payload(&data).expect("ASK payload splits");
        assert_eq!(signature.len(), 256, "RSA-2048 signature is 256 bytes");

        let attk = run(
            "self_signed",
            "device-a-test",
            &json!({ "op": "export_attk_public_key" }),
            None,
        )
        .expect("attk export is handled");
        let pem = attk["text"].as_str().expect("ATTK PEM is printable");
        use pkcs8::DecodePublicKey as _;
        let public = rsa::RsaPublicKey::from_public_key_pem(pem).expect("ATTK PEM parses");
        let verifying = PssVerifyingKey::<Sha256>::new_with_salt_len(public, ASK_SALT_LEN as usize);
        let signature = PssSignature::try_from(signature).expect("signature parses");
        verifying
            .verify(document, &signature)
            .expect("the ASK document must verify with the exported ATTK key");
    }

    /// 真机上 ASK 和 ATTK 是两把钥匙：`exportAskPublicKey` 吐的是 ASK 公钥，`exportAttkPublicKey`
    /// 吐的是 ATTK 公钥，两者永远不相等。以前这层只有一把（ASK 兼作 ATTK），App 拿到
    /// 同一把公钥会把该 uid 下的钥匙全删掉重来。
    #[test]
    fn ask_and_attk_are_two_different_keys() {
        let device = "device-a-ask-attk-split";
        let uid = 10373i64;
        let ask = ask_payload_for(device, uid);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(ask["data"].as_str().expect("data is base64"))
            .expect("payload decodes");
        let (ask_document, ask_signature) = split_ask_payload(&raw).expect("ASK payload splits");
        let ask_public = pem_of(core::str::from_utf8(ask_document).expect("json is utf-8"));

        let attk = run(
            "self_signed",
            device,
            &json!({ "op": "export_attk_public_key" }),
            None,
        )
        .expect("attk export is handled");
        let attk_public = attk["text"].as_str().expect("ATTK PEM is printable");

        assert_ne!(
            ask_public, attk_public,
            "ASK and ATTK must be different keys, exactly like a real device"
        );
        assert!(
            verifies(attk_public, ask_document, ask_signature),
            "the ASK document is signed by ATTK"
        );
        assert!(
            !verifies(&ask_public, ask_document, ask_signature),
            "the ASK document must not verify with the ASK key itself"
        );
    }

    #[test]
    fn ask_document_keeps_the_field_names_and_the_uid_string() {
        let payload = ask_payload(10373);
        let doc = &payload["payload"];
        assert_eq!(
            doc["pub_key"]
                .as_str()
                .map(|s| s.contains("BEGIN PUBLIC KEY")),
            Some(true)
        );
        assert_eq!(doc["uid"], json!("10373"), "uid is a string in SOTER");
        assert_eq!(doc["rsa_pss_saltlen"], json!(32));
        assert!(doc["counter"].as_u64().unwrap_or(0) > 0);

        let cpu_id = doc["cpu_id"].as_str().expect("cpu_id is a string");
        assert_eq!(cpu_id.len(), 32);
        assert!(cpu_id.starts_with("09000000"));

        // 键序照抄现场抓到的 JSON，应用是按位置也不吃亏。
        let text = String::from_utf8(
            split_ask_payload(
                &base64::engine::general_purpose::STANDARD
                    .decode(payload["data"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap()
            .0
            .to_vec(),
        )
        .unwrap();
        let order: Vec<usize> = ["pub_key", "cpu_id", "counter", "uid", "rsa_pss_saltlen"]
            .iter()
            .map(|k| text.find(&format!("\"{k}\"")).expect("key present"))
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "key order changed: {text}"
        );
    }

    /// 删过的槽位不能“导出时现造”：`remove_all_uid_key` 之后 export 回 -5，
    /// 只有重新 `generate_ask_key_pair` 才解。
    #[test]
    fn a_deleted_slot_does_not_grow_back() {
        let device = "device-a-gone";
        let uid = 4321i64;
        let op = |body: Value| run("self_signed", device, &body, None).expect("handled");

        assert_eq!(
            op(json!({ "op": "generate_ask_key_pair", "uid": uid }))["error_code"],
            json!(0)
        );
        assert_eq!(
            op(json!({ "op": "export_ask_public_key", "uid": uid }))["error_code"],
            json!(0)
        );
        assert_eq!(
            op(json!({ "op": "remove_all_uid_key", "uid": uid }))["error_code"],
            json!(0)
        );
        assert_eq!(
            op(json!({ "op": "export_ask_public_key", "uid": uid }))["error_code"],
            json!(-5),
            "删了就不能再凭 export 现造"
        );
        // 重建之后又好了。
        assert_eq!(
            op(json!({ "op": "generate_ask_key_pair", "uid": uid }))["error_code"],
            json!(0)
        );
        assert_eq!(
            op(json!({ "op": "export_ask_public_key", "uid": uid }))["error_code"],
            json!(0)
        );
    }

    /// `attk` 层跟兜底层不一样：它的 ASK 是用上传的真 ATTK 签的，所以 `has_ask_already`
    /// 得如实回答，而且重启不能换钥匙（钥匙跟计数器都落盘）。
    ///
    /// 2026-11-06 微信实测：这一层一直答 -5，App 每轮都判「没有 ASK」—— 建一把、导一把、
    /// 上报腾讯、清掉重来，永远走不到下一步。
    #[test]
    fn the_attk_layer_answers_has_ask_honestly_across_a_restart() {
        use pkcs8::{EncodePrivateKey as _, LineEnding};

        let device = "device-a-attk-ask-state";
        let uid = 10_777i64;
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("rsa keygen");
        let material = AttkMaterial {
            id: 900_777,
            name: "test-attk-ask".to_string(),
            cpu_id: "09000000777788889999000011112222".to_string(),
            pem: key
                .to_pkcs8_pem(LineEnding::LF)
                .expect("pkcs8 pem")
                .to_string(),
        };
        let call = |body: Value| {
            run_layer("attk", device, &body, None, Some(&material))
                .expect("the attk layer handles every known op")
        };
        let code = |op: &str| call(json!({ "op": op, "uid": uid }))["error_code"].clone();
        let ask_pub = || {
            call(json!({ "op": "export_ask_public_key", "uid": uid }))["payload"]["pub_key"].clone()
        };

        assert_eq!(code("has_ask_already"), json!(-5), "没建过就得说没有");
        assert_eq!(code("generate_ask_key_pair"), json!(0));
        assert_eq!(
            code("has_ask_already"),
            json!(0),
            "建过就得说有 —— 一直回 -5，App 每轮都会自删重建"
        );
        let first = ask_pub();

        // 模拟进程重启：内存里那把丢掉，库里那份还在。
        let scope = material_scope("attk", Some(&material));
        let slot = format!("{scope}|{uid}|attk");
        store().ask.lock().expect("ask map").remove(&slot);
        assert_eq!(code("has_ask_already"), json!(0), "重启后仍然算有");
        assert_eq!(ask_pub(), first, "重启后得捞回同一把 ASK，不能现造一把新的");

        // 计数器同理：只增不减。
        let counter_a = call(json!({ "op": "export_ask_public_key", "uid": uid }))["payload"]
            ["counter"]
            .as_u64()
            .expect("counter");
        store()
            .counters
            .lock()
            .expect("counters")
            .remove(&counter_key(&scope, device, uid as i32));
        let counter_b = call(json!({ "op": "export_ask_public_key", "uid": uid }))["payload"]
            ["counter"]
            .as_u64()
            .expect("counter");
        assert_eq!(counter_b, counter_a + 1, "计数器不能从 1 重新数");

        assert_eq!(code("remove_all_uid_key"), json!(0));
        assert_eq!(code("has_ask_already"), json!(-5), "删了就是没有");
        assert!(
            statedb::shared()
                .mint_key_get(&slot)
                .ok()
                .flatten()
                .is_none(),
            "删了库里也不能接着留"
        );
    }

    /// 服务端密钥模式（`attk` 层）：身份就是控制台上传的那一把 ATTK。
    ///
    /// 三件事得同时成立：cpu_id 用 ATTK 自己的（A 端转什么都不算数）、ASK 文档用它的
    /// 私钥签、换一把 ATTK 就等于换了一整套料（旧的 AuthKey 不会再被认成新的）。
    #[test]
    fn the_attk_layer_signs_with_the_uploaded_identity() {
        use pkcs8::{
            DecodePublicKey as _, EncodePrivateKey as _, EncodePublicKey as _, LineEnding,
        };

        let device = "device-a-attk";
        let own_cpu = "09000000111122223333444455556666";
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("rsa keygen");
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pkcs8 pem")
            .to_string();
        let own_public = rsa::RsaPublicKey::from(&key)
            .to_public_key_pem(LineEnding::LF)
            .expect("public pem");
        let material = AttkMaterial {
            id: 900_001,
            name: "test-attk".to_string(),
            cpu_id: own_cpu.to_string(),
            pem: pem.clone(),
        };
        let call = |body: Value| {
            run_layer("attk", device, &body, None, Some(&material))
                .expect("the attk layer handles every known op")
        };

        // 1. getDeviceId 报的就是这把 ATTK 的 cpu_id，A 端转过来的真机号盖不掉它。
        let id = call(json!({
            "op": "get_device_id",
            "device_id": device,
            "cpu_id": "09000000deadbeefdeadbeefdeadbeef",
        }));
        assert_eq!(device_id_text(&id), own_cpu);
        assert_eq!(id["layer"], json!("attk"));

        // 2. ASK 文档：cpu_id 是 ATTK 的、pub_key 是 ASK 的、签名是 ATTK 私钥签的。
        let uid = 1_010_490i64; // user 10 的微信，uid 本身是完整的
        let ask = call(json!({ "op": "export_ask_public_key", "uid": uid, "device_id": device }));
        assert_eq!(ask["payload"]["cpu_id"], json!(own_cpu));
        assert_eq!(ask["payload"]["uid"], json!(uid.to_string()));
        let raw = base64::engine::general_purpose::STANDARD
            .decode(ask["data"].as_str().expect("data is base64"))
            .expect("payload decodes");
        let (ask_doc, ask_sig) = split_ask_payload(&raw).expect("ASK payload splits");
        let ask_public = pem_of(core::str::from_utf8(ask_doc).expect("json is utf-8"));
        assert!(
            verifies(&own_public, ask_doc, ask_sig),
            "ASK 证书必须由上传的那把 ATTK 签"
        );
        assert!(
            !verifies(&ask_public, ask_doc, ask_sig),
            "ASK 不是自己签自己"
        );
        let exported = call(json!({ "op": "export_attk_public_key" }));
        let exported_pem = exported["text"].as_str().expect("ATTK PEM is printable");
        assert!(rsa::RsaPublicKey::from_public_key_pem(exported_pem).is_ok());
        assert_eq!(exported_pem, own_public, "导出的 ATTK 公钥就是上传那把");

        // 3. AuthKey 用 ASK 签，签名现场用 AuthKey 签，一条链自洽。
        assert_eq!(
            call(
                json!({ "op": "generate_auth_key_pair", "uid": uid, "alias": "pay", "device_id": device })
            )["error_code"],
            json!(0)
        );
        assert_eq!(
            call(json!({ "op": "has_auth_key", "uid": uid, "alias": "pay", "device_id": device }))
                ["error_code"],
            json!(0)
        );
        let auth = call(
            json!({ "op": "export_auth_key_public_key", "uid": uid, "alias": "pay", "device_id": device }),
        );
        let raw = base64::engine::general_purpose::STANDARD
            .decode(auth["data"].as_str().expect("data is base64"))
            .expect("auth payload decodes");
        let (auth_doc, auth_sig) = split_ask_payload(&raw).expect("auth payload splits");
        assert!(
            verifies(&ask_public, auth_doc, auth_sig),
            "AuthKey 证书是 ASK 签的"
        );
        let auth_public = pem_of(core::str::from_utf8(auth_doc).expect("json is utf-8"));

        let init = call(
            json!({ "op": "init_sign", "uid": uid, "alias": "pay", "challenge": "raw", "device_id": device }),
        );
        let session = init["session"].as_i64().expect("init returns a session");
        let finish = call(json!({
            "op": "finish_sign",
            "uid": uid,
            "alias": "pay",
            "session": session,
            "device_id": device,
        }));
        assert_eq!(finish["error_code"], json!(0));
        let raw = base64::engine::general_purpose::STANDARD
            .decode(finish["data"].as_str().expect("data is base64"))
            .expect("sign payload decodes");
        let (sign_doc, sign_sig) = split_ask_payload(&raw).expect("sign payload splits");
        assert!(
            verifies(&auth_public, sign_doc, sign_sig),
            "签名现场是 AuthKey 签的"
        );

        // 4. 换一把 ATTK（同层、不同 id）就是另一套料：新身份手里没有刚才那张会话/钥匙。
        let other = AttkMaterial {
            id: 900_002,
            name: "test-attk-2".to_string(),
            cpu_id: "09000000aaaabbbbccccddddeeeeffff".to_string(),
            pem: RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
                .expect("rsa keygen")
                .to_pkcs8_pem(LineEnding::LF)
                .expect("pkcs8 pem")
                .to_string(),
        };
        let ask_other = run_layer(
            "attk",
            device,
            &json!({ "op": "export_ask_public_key", "uid": uid, "device_id": device }),
            None,
            Some(&other),
        )
        .expect("handled");
        assert_eq!(
            ask_other["payload"]["cpu_id"],
            json!(other.cpu_id),
            "换一把 ATTK，cpu_id 跟着换"
        );
        let auth_other = run_layer(
            "attk",
            device,
            &json!({ "op": "has_auth_key", "uid": uid, "alias": "pay", "device_id": device }),
            None,
            Some(&other),
        )
        .expect("handled");
        assert_eq!(
            auth_other["error_code"],
            json!(-6),
            "另一把 ATTK 不认识前一把建过的 AuthKey"
        );
    }

    /// 多用户 / 多身份：同一个身份下，ASK 与 AuthKey 按 **uid** 分。
    ///
    /// 真机的 `generateAskKeyPair(uid)` 建的就是那个 uid 的 ASK，`hasAuthKey(uid, alias)`
    /// 也只认那个 uid 自己建的。工作资料（1000000+）和分身（99900000+）里的同一个应用
    /// 是另一个 uid，所以不能共用一把。
    #[test]
    fn ask_and_auth_are_per_uid_inside_one_identity() {
        let device = "device-a-per-uid";
        let layer = "self_signed";
        let ask_for = |uid: i64| {
            let value = run(
                layer,
                device,
                &json!({ "op": "export_ask_public_key", "uid": uid }),
                None,
            )
            .expect("handled");
            value["payload"]["pub_key"]
                .as_str()
                .expect("ASK pem")
                .to_string()
        };

        let owner = ask_for(10490);
        let work_profile = ask_for(1_010_490);
        assert_ne!(owner, work_profile, "不同用户不能共用一把 ASK");
        assert_eq!(ask_for(10490), owner, "同一 uid 一轮流程里不能换 ASK");

        // 重建这个 uid 的 ASK：只换它自己，别人的不动。
        assert_eq!(
            run(
                layer,
                device,
                &json!({ "op": "generate_ask_key_pair", "uid": 10490 }),
                None
            )
            .expect("handled")["error_code"],
            json!(0)
        );
        assert_ne!(ask_for(10490), owner);
        assert_eq!(ask_for(1_010_490), work_profile);

        // AuthKey 同理：在机主上建的，工作资料那边就当没建。
        assert_eq!(
            run(
                layer,
                device,
                &json!({ "op": "generate_auth_key_pair", "uid": 10490, "alias": "pay" }),
                None
            )
            .expect("handled")["error_code"],
            json!(0)
        );
        assert_eq!(
            run(
                layer,
                device,
                &json!({ "op": "has_auth_key", "uid": 1_010_490, "alias": "pay" }),
                None
            )
            .expect("handled")["error_code"],
            json!(-6)
        );
    }

    /// 高通那套（实测 SM8635 / peridot）：`cpu_id` 以 `00000000` 开头，`getDeviceId` 回
    /// 16 字节 raw，ASK 文档里**不带** `rsa_pss_saltlen` 字段。
    #[test]
    fn a_qti_cpu_id_switches_to_the_qti_shape() {
        let cpu = "00000000002750e110768fdc8351ee88";
        let device = "device-a-qti";

        let id = run(
            "self_signed",
            device,
            &json!({ "op": "get_device_id", "cpu_id": cpu }),
            None,
        )
        .expect("handled");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(id["data"].as_str().expect("data"))
            .expect("base64");
        assert_eq!(raw.len(), 16, "高通回 16 字节 raw");
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, cpu);

        let ask = run(
            "self_signed",
            device,
            &json!({ "op": "export_ask_public_key", "uid": 10490, "cpu_id": cpu }),
            None,
        )
        .expect("handled");
        assert_eq!(ask["payload"]["cpu_id"], json!(cpu));
        assert!(
            ask["payload"].get("rsa_pss_saltlen").is_none(),
            "高通那套不带盐长字段：{}",
            ask["payload"]
        );
    }

    /// A 端把真机 cpu_id 转过来了就得原样落进文档，不能自己再派生一个 —— 同一台设备上
    /// 本地兜底、服务端两层、真机三处报同一个号，检测器才不报「两次 cpuid 不一致」。
    #[test]
    fn a_forwarded_cpu_id_is_used_verbatim() {
        let forwarded = "090000005171734c42866bea148b21f5";
        let device = "device-a-cpuid";

        let id = run(
            "self_signed",
            device,
            &json!({ "op": "get_device_id", "cpu_id": forwarded }),
            None,
        )
        .expect("handled");
        assert_eq!(device_id_text(&id), forwarded);
        // 层名是给 A 端分辨「这个号是真机报的还是服务端造的」用的。
        assert_eq!(id["layer"], json!("self_signed"));

        let ask = run(
            "self_signed",
            device,
            &json!({ "op": "export_ask_public_key", "uid": 1, "cpu_id": forwarded }),
            None,
        )
        .expect("handled");
        assert_eq!(ask["payload"]["cpu_id"], json!(forwarded));
        assert_ne!(
            ask["payload"]["cpu_id"],
            json!(virtual_device_id(device)),
            "有真值就不能回落到虚拟号"
        );

        // 没转真值（老 A 端、或者它自己还没学到）就按当时的年月日时分现造一个，层名一样要有。
        let plain = run(
            "self_signed",
            device,
            &json!({ "op": "get_device_id" }),
            None,
        )
        .expect("handled");
        assert_eq!(device_id_text(&plain), time_device_id());
        assert_eq!(plain["layer"], json!("self_signed"));
        assert_ne!(
            device_id_text(&plain),
            virtual_device_id(device),
            "不再用按设备名派生的虚拟号"
        );
    }

    /// 没带 cpu_id / 带得不成样子时，按当前时间现造一个（同一分钟内稳定）。
    #[test]
    fn a_malformed_cpu_id_falls_back_to_the_time_based_one() {
        let device = "device-a-badcpuid";
        let cases = [
            json!(""),
            json!("09000000"),
            json!("zz0000005171734c42866bea148b21f5"),
            json!("090000005171734c42866bea148b21f50"),
            json!(1234),
        ];
        for bad in cases {
            let id = run(
                "self_signed",
                device,
                &json!({ "op": "get_device_id", "cpu_id": bad }),
                None,
            )
            .expect("handled");
            let text = device_id_text(&id);
            assert_eq!(text.len(), 32, "{bad:?}");
            assert!(text.starts_with("09000000"), "{bad:?}: {text}");
            assert!(
                text.chars().all(|c| c.is_ascii_hexdigit()),
                "{bad:?}: {text}"
            );
            assert_ne!(text, virtual_device_id(device), "{bad:?}");
        }
        // 同一分钟里两次调用应当一样（一轮 ASK / AuthKey 不会中途换号）。
        assert_eq!(time_device_id(), time_device_id());
    }

    #[test]
    fn has_ask_already_is_reported_missing_by_the_fallback_layers() {
        // 兜底层现造的 ASK 腾讯永远不认，所以它不能声称「已存在」——那会让应用跳过上报
        // 并把假 ASK 当真（2026-10-11 实测的毒化）。
        for layer in ["self_signed", "builtin"] {
            let value = run(
                layer,
                "device-a-test",
                &json!({ "op": "has_ask_already", "uid": 10373 }),
                None,
            )
            .expect("handled");
            assert_eq!(
                value["error_code"],
                json!(NOT_FOUND),
                "{layer} should report missing"
            );
        }

        // `verify_attk_key_pair` 照旧成功：那笔不参与「上报不上报」的判定。
        let value = run(
            "self_signed",
            "device-a-test",
            &json!({ "op": "verify_attk_key_pair", "uid": 10373 }),
            None,
        )
        .expect("handled");
        assert_eq!(value["error_code"], json!(OK));
    }

    #[test]
    fn auth_key_absent_is_not_found_then_generate_creates_it() {
        let device = "device-a-auth";
        let absent = run(
            "self_signed",
            device,
            &json!({ "op": "has_auth_key", "uid": 7, "alias": "SoterAuthKey" }),
            None,
        )
        .expect("handled");
        assert_eq!(absent["error_code"], json!(AUTH_KEY_NOT_READY));

        let generated = run(
            "self_signed",
            device,
            &json!({ "op": "generate_auth_key_pair", "uid": 7, "alias": "SoterAuthKey" }),
            None,
        )
        .expect("handled");
        assert_eq!(generated["error_code"], json!(0));

        let present = run(
            "self_signed",
            device,
            &json!({ "op": "has_auth_key", "uid": 7, "alias": "SoterAuthKey" }),
            None,
        )
        .expect("handled");
        assert_eq!(present["error_code"], json!(0));
    }

    #[test]
    fn keybox_layer_without_rsa_material_is_a_layer_failure() {
        let value = run(
            "keybox",
            "device-a-test",
            &json!({ "op": "get_device_id" }),
            None,
        )
        .expect("handled, but as a failure");
        assert!(
            value.get("error").is_some(),
            "a keybox layer without RSA material must let the next layer try"
        );
    }

    // -----------------------------------------------------------------------
    // 闭环：每层都得把整个流程走完，而且签名那把钥匙和导出的公钥对得上
    // -----------------------------------------------------------------------

    /// 拆信封：`[i32 le JSON 长度][JSON][签名]`。
    fn split_envelope(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let len = i32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        (data[4..4 + len].to_vec(), data[4 + len..].to_vec())
    }

    fn data_of(value: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(value["data"].as_str().expect("data is base64"))
            .expect("payload decodes")
    }

    /// 从一份 JSON 里抠出 `pub_key` 的 PEM。
    fn pem_of(document: &str) -> String {
        const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
        const END: &str = "-----END PUBLIC KEY-----";
        let start = document.find(BEGIN).expect("the document carries a pem");
        let end = document.find(END).expect("the pem has a tail") + END.len();
        document[start..end].replace("\\n", "\n")
    }

    /// 拿一把 PEM 公钥验一段签名（RSA-PSS-SHA256，盐长按真机那套 20 严卡）。
    fn verifies(pem: &str, message: &[u8], signature: &[u8]) -> bool {
        use pkcs8::DecodePublicKey as _;
        let Ok(public) = rsa::RsaPublicKey::from_public_key_pem(pem) else {
            return false;
        };
        let Ok(signature) = PssSignature::try_from(signature) else {
            return false;
        };
        PssVerifyingKey::<Sha256>::new_with_salt_len(public, ASK_SALT_LEN as usize)
            .verify(message, &signature)
            .is_ok()
    }

    /// 这一层的 ASK（也就是它的身份）公钥 PEM。
    fn ask_pem(device: &str, uid: i64) -> String {
        let ask = run(
            "self_signed",
            device,
            &json!({ "op": "export_ask_public_key", "uid": uid }),
            None,
        )
        .expect("ASK export is handled");
        let (document, _) = split_envelope(&data_of(&ask));
        pem_of(&String::from_utf8(document).expect("json is utf-8"))
    }

    /// 一把能当 keybox 身份的 RSA 私钥 PEM。
    fn test_rsa_pem() -> String {
        use rsa::pkcs8::EncodePrivateKey as _;
        MintKey::generate()
            .expect("keygen")
            .private
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .expect("pem")
            .to_string()
    }

    #[test]
    fn the_auth_key_document_is_signed_by_the_layer_identity() {
        let device = "device-a-authdoc";
        let uid = 10373i64;
        let alias = "SoterAuthKeyPay";
        // 先留一把“生成前”的 ASK 公钥：整套用例并行跑时，同一层的 ASK 可能被
        // 别的用例顶掉重铸，导出一次跟导出两次看到的未必是同一把。不管怎么转，
        // 只要信封能被这一层的其中一把验过，就说明它确实是这一层签的。
        let ask_before = ask_pem(device, uid);
        assert_eq!(
            run(
                "self_signed",
                device,
                &json!({ "op": "generate_auth_key_pair", "uid": uid, "alias": alias }),
                None,
            )
            .expect("handled")["error_code"],
            json!(0)
        );

        let auth = run(
            "self_signed",
            device,
            &json!({ "op": "export_auth_key_public_key", "uid": uid, "alias": alias }),
            None,
        )
        .expect("handled");
        let (document, signature) = split_envelope(&data_of(&auth));
        assert_eq!(signature.len(), 256, "RSA-2048 signature is 256 bytes");

        let text = String::from_utf8(document.clone()).expect("json is utf-8");
        let order: Vec<usize> = ["pub_key", "cpu_id", "counter", "uid", "rsa_pss_saltlen"]
            .iter()
            .map(|k| text.find(&format!("\"{k}\"")).expect("key present"))
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "key order changed: {text}"
        );

        // App 是先拿 ASK 公钥再验这个信封的 —— 验得过，AuthKey 这条链才算自洽
        assert!(
            verifies(&ask_before, &document, &signature)
                || verifies(&ask_pem(device, uid), &document, &signature),
            "the AuthKey document must verify with the ASK key"
        );
    }

    #[test]
    fn the_sign_document_closes_the_loop() {
        let device = "device-a-signdoc";
        let uid = 10373i64;
        let alias = "SoterAuthKeyPay";
        assert_eq!(
            run(
                "self_signed",
                device,
                &json!({ "op": "generate_auth_key_pair", "uid": uid, "alias": alias }),
                None,
            )
            .expect("handled")["error_code"],
            json!(0)
        );
        let init = run(
            "self_signed",
            device,
            &json!({ "op": "init_sign", "uid": uid, "alias": alias, "challenge": "0a1b2c3d" }),
            None,
        )
        .expect("handled");
        assert_eq!(init["error_code"], json!(0), "init_sign: {init}");
        let session = init["session"].as_i64().expect("session is a number");

        let finish = run(
            "self_signed",
            device,
            &json!({ "op": "finish_sign", "session": session }),
            None,
        )
        .expect("handled");
        let (document, signature) = split_envelope(&data_of(&finish));
        let text = String::from_utf8(document.clone()).expect("json is utf-8");

        let order: Vec<usize> = [
            "raw",
            "fid",
            "counter",
            "tee_n",
            "tee_v",
            "fp_n",
            "fp_v",
            "cpu_id",
            "uid",
            "rsa_pss_saltlen",
        ]
        .iter()
        .map(|k| text.find(&format!("\"{k}\":")).expect("key present"))
        .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "key order changed: {text}"
        );
        assert!(
            text.contains("\"raw\":\"0a1b2c3d\""),
            "raw 得是挑战原文，不是解出来的字节: {text}"
        );

        // 拿导出的 AuthKey 公钥验这段 JSON —— 验得过才叫闭环
        let auth = run(
            "self_signed",
            device,
            &json!({ "op": "export_auth_key_public_key", "uid": uid, "alias": alias }),
            None,
        )
        .expect("handled");
        let (auth_document, _) = split_envelope(&data_of(&auth));
        let auth_pem = pem_of(&String::from_utf8(auth_document).expect("json is utf-8"));
        assert!(
            verifies(&auth_pem, &document, &signature),
            "the sign document must verify with the AuthKey"
        );
    }

    #[test]
    fn the_keybox_layer_keeps_serving_a_generate_request() {
        // 以前它回错误 ⇒ 调用方换层 ⇒ 同槽位的材料立刻劈成两半。
        let pem = test_rsa_pem();
        let value = run(
            "keybox",
            "device-a-keyboxgen",
            &json!({ "op": "generate_ask_key_pair", "uid": 10373 }),
            Some(&pem),
        )
        .expect("handled");
        assert!(value.get("error").is_none(), "不该报错: {value}");
        assert_eq!(value["error_code"], json!(0));
    }

    #[test]
    fn slots_are_pinned_to_the_layer_that_served_them() {
        let device = "device-a-pin-test";
        assert!(pinned_layer(device, 4242).is_none());

        pin_layer(device, 4242, "keybox");
        assert_eq!(pinned_layer(device, 4242).as_deref(), Some("keybox"));

        // 换层之后钉子跟着挑
        pin_layer(device, 4242, "b");
        assert_eq!(pinned_layer(device, 4242).as_deref(), Some("b"));

        unpin_layer(device, 4242);
        assert!(pinned_layer(device, 4242).is_none());

        // 请求里没点名设备时不钉（route 到哪台都行的请求）
        pin_layer("", 4242, "keybox");
        assert!(pinned_layer("", 4242).is_none());
    }

    #[test]
    fn a_rebuilt_ask_drops_the_slot_pin() {
        let device = "device-a-pin-rebuild";
        let uid = 5150i64;
        pin_layer(device, uid as i32, "keybox");
        assert_eq!(pinned_layer(device, uid as i32).as_deref(), Some("keybox"));

        run(
            "self_signed",
            device,
            &json!({ "op": "generate_ask_key_pair", "uid": uid }),
            None,
        )
        .expect("handled");

        assert!(
            pinned_layer(device, uid as i32).is_none(),
            "App 重建 ASK 的时候，槽位得重新评层，不能钉死在上一轮那一层"
        );
    }

    #[test]
    fn a_stale_pin_is_ignored() {
        let now = 1_700_000_000_000i64;
        assert!(pin_is_fresh(now, now));
        assert!(pin_is_fresh(now, now + SLOT_PIN_TTL_MILLIS));
        assert!(!pin_is_fresh(now, now + SLOT_PIN_TTL_MILLIS + 1));
    }

    #[test]
    fn fallback_session_owner_is_exact_and_finish_cannot_steal_it() {
        let device = "fallback-session-owner-test";
        run(
            "self_signed",
            device,
            &json!({"op": "generate_auth_key_pair", "uid": 8, "alias": "pay"}),
            None,
        )
        .unwrap();
        let init = run("self_signed", device, &json!({"device_id": device, "op": "init_sign", "uid": 8, "alias": "pay", "challenge": "raw"}), None).unwrap();
        let session = init["session"].as_i64().unwrap();
        assert_eq!(
            session_layer(device, session).as_deref(),
            Some("self_signed")
        );
        assert_eq!(session_layer("other", session), None);
        assert_eq!(session_layer(device, -987654321), None);
        let finish = json!({"device_id": device, "op": "finish_sign", "session": session});
        assert_eq!(
            run("self_signed", "other", &finish, None).unwrap()["error_code"],
            json!(SESSION_UNKNOWN)
        );
        assert_eq!(
            session_layer(device, session).as_deref(),
            Some("self_signed")
        );
        assert_eq!(
            run("self_signed", device, &finish, None).unwrap()["error_code"],
            json!(0)
        );
        assert_eq!(session_layer(device, session), None);
        assert_eq!(
            run("self_signed", device, &finish, None).unwrap()["error_code"],
            json!(SESSION_UNKNOWN)
        );
    }

    #[test]
    fn owner_tokens_are_per_family_and_ignore_foreign_aliases() {
        assert_eq!(
            owner_token("WechatAuthKeyPay&hubssh").as_deref(),
            Some("wx:hubssh")
        );
        assert_eq!(
            owner_token("SoterAuthKeyV2_salt612a30de_scene1").as_deref(),
            Some("v2:612a30de")
        );
        assert_eq!(
            owner_token("SoterAuthKey_salt9f8e7d6c_scene2").as_deref(),
            Some("v1:9f8e7d6c")
        );
        // 微信那条「名字存成 WechatAuthKeyPay&null 就判定 init error」的兼容路径
        // （`dm4/g0.java`）留给它的别名不算一个账号。
        assert_eq!(owner_token("WechatAuthKeyPay&null"), None);
        assert_eq!(owner_token("other:probe"), None);
        assert_eq!(owner_token(""), None);
    }

    #[test]
    fn a_slot_with_two_accounts_of_one_family_is_shared() {
        let device = "device-a-owner-shared";
        let uid = 6101;
        assert_eq!(owner_count(device, uid), 0);

        note_owner(device, uid, "WechatAuthKeyPay&hubssh");
        note_owner(device, uid, "SoterAuthKeyV2_saltaaaaaaaa_scene1");
        assert_eq!(
            owner_count(device, uid),
            1,
            "一个账号的三族别名只能算一个账号"
        );

        note_owner(device, uid, "SoterAuthKeyV2_saltbbbbbbbb_scene1");
        assert_eq!(owner_count(device, uid), 2, "同族两个指纹就是两个账号");

        note_owner(device, uid, "WechatAuthKeyPay&hubssh");
        assert_eq!(owner_count(device, uid), 2, "同一个指纹重复报不长数");

        // 只记了账号、没服务过这个槽位，不算钉过层
        assert!(pinned_layer(device, uid).is_none());
        // 钉层不能把这个槽位上的账号记录冲掉
        pin_layer(device, uid, "b");
        assert_eq!(owner_count(device, uid), 2);
        assert_eq!(pinned_layer(device, uid).as_deref(), Some("b"));

        // 没点名设备就不记（route 到哪台都行的请求）
        note_owner("", uid, "SoterAuthKeyV2_saltcccccccc_scene1");
        assert_eq!(owner_count("", uid), 0);

        // 清钥匙只拔钉子：账号记录得留着，否则下次没人答得出这里原本有几个号
        unpin_layer(device, uid);
        assert!(pinned_layer(device, uid).is_none(), "钉子拔了");
        assert_eq!(owner_count(device, uid), 2, "账号记录不该被清钥匙带走");
    }

    #[test]
    fn a_full_family_evicts_the_least_recently_seen_owner() {
        let device = "device-a-owner-lru";
        let uid = 6202;
        let base = chrono::Utc::now().timestamp_millis();
        // 直接把这一族填满（时间从旧到新）。不走 note_owner，因为它的时间戳总是
        // 当下，排不出「谁更久没见」。
        {
            let mut map = store().slots.lock().unwrap();
            let mut owners = Vec::new();
            for i in 0..OWNER_CAP {
                owners.push(Owner {
                    token: format!("v2:old{i:04}"),
                    last_seen_ms: base + i as i64,
                });
            }
            map.insert(
                slot_id(device, uid),
                SlotPin {
                    layer: String::new(),
                    at_millis: 0,
                    owners,
                },
            );
        }
        // 新号进来：这一族满了，换出去的是最久没见到的 old0000
        note_owner(device, uid, "SoterAuthKeyV2_saltnewaccount_scene1");
        let owners = owners_of(device, uid);
        assert_eq!(owners.len(), OWNER_CAP, "满了是等量替换，不是变长");
        assert!(owners.iter().any(|t| t == "v2:newaccount"), "新号得进来");
        assert!(
            !owners.iter().any(|t| t == "v2:old0000"),
            "最久没见到的被换出去"
        );
        assert!(
            owners.iter().any(|t| t == "v2:old0001"),
            "只换一个，别的不动"
        );
    }

    #[test]
    fn the_wipe_downgrade_is_off_by_default() {
        assert!(!scope_wipe_from(None));
        for on in ["1", "true", "yes", "on"] {
            assert!(scope_wipe_from(Some(on)), "{on} 应该打开降级");
        }
        for off in ["0", "false", "no", "off", ""] {
            assert!(!scope_wipe_from(Some(off)), "{off} 不降级（真清）");
        }
    }

    #[test]
    fn the_builtin_layer_answers_a_probe_flow_and_never_rotates() {
        // 探测机（春秋/鸭子）的那一套：ASK 在、AuthKey 现建、签名会话能用。
        // 见 `crate::soter_probe`：这套回答只给探测机，不落 B 端。
        let device = "device-a-probe-builtin";
        let uid = 24601i64;
        let alias = "chunqiu_soter_probe_1791022575713";
        let call = |body: Value| run("builtin", device, &body, None).expect("handled");

        let builtin_before = builtin_key().expect("builtin material");

        assert_eq!(
            call(json!({"op": "has_ask_already", "uid": uid}))["error_code"],
            json!(NOT_FOUND)
        );
        // 没建过的钥匙就是没建过，真机答 -6（AUTH_KEY_NOT_READY）。
        assert_eq!(
            call(json!({"op": "has_auth_key", "uid": uid, "alias": alias}))["error_code"],
            json!(AUTH_KEY_NOT_READY)
        );
        assert_eq!(
            call(json!({"op": "init_sign", "uid": uid, "alias": alias, "challenge": "0a1b"}))
                ["error_code"],
            json!(AUTH_KEY_NOT_READY)
        );

        assert_eq!(
            call(json!({"op": "generate_auth_key_pair", "uid": uid, "alias": alias}))["error_code"],
            json!(0)
        );
        assert_eq!(
            call(json!({"op": "has_auth_key", "uid": uid, "alias": alias}))["error_code"],
            json!(0)
        );
        let init =
            call(json!({"op": "init_sign", "uid": uid, "alias": alias, "challenge": "0a1b"}));
        assert_eq!(init["error_code"], json!(0));
        let session = init["session"]
            .as_i64()
            .filter(|s| *s != 0)
            .expect("session");
        assert_eq!(
            call(json!({"op": "finish_sign", "uid": uid, "alias": alias, "session": session}))
                ["error_code"],
            json!(0)
        );

        // 重建 ASK：探测机不会看「换没换」，而换的又是全局那一把 —— 只会把正跑着的一轮
        // 劈成两半，还可能把别人的钉层换掉。所以内置层不轮换。
        assert_eq!(
            call(json!({"op": "generate_ask_key_pair", "uid": uid}))["error_code"],
            json!(0)
        );
        assert!(
            Arc::ptr_eq(&builtin_before, &builtin_key().expect("builtin material")),
            "内置层的 ASK 被探测流量换掉了"
        );

        // 清账：别把这一局的 AuthKey 留给同一个 uid 的别的用例（uid 号是复用的）。
        assert_eq!(
            call(json!({"op": "remove_all_uid_key", "uid": uid}))["error_code"],
            json!(0)
        );
        assert_eq!(
            call(json!({"op": "has_auth_key", "uid": uid, "alias": alias}))["error_code"],
            json!(AUTH_KEY_NOT_READY)
        );
    }

    #[test]
    fn unknown_op_is_not_handled() {
        assert!(run(
            "self_signed",
            "device-a-test",
            &json!({ "op": "nope" }),
            None
        )
        .is_none());
    }
}
