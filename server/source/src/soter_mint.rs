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
//!   - `self_signed`：现生成一把 RSA-2048，进程内复用；服务端一重启就等于换了
//!     一把新身份，A 端要重新取 ATTK 公钥。
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

use std::collections::HashMap;
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
/// ASK 里写死的盐长，SHA-256 摘要长度。
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

    /// RSA-PSS-SHA256，盐长 = 摘要长度 = 32，正好对上 JSON 里那个字段。
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing = PssSigningKey::<Sha256>::new((*self.private).clone());
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
    /// `{device}|{uid}|{alias}` -> AuthKey
    auth: Mutex<HashMap<String, Arc<MintKey>>>,
    /// `{device}|{uid}` -> 签名计数器
    counters: Mutex<HashMap<String, u64>>,
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

fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| Store {
        self_signed: Mutex::new(None),
        builtin: Mutex::new(None),
        auth: Mutex::new(HashMap::new()),
        counters: Mutex::new(HashMap::new()),
        next_session: Mutex::new(chrono::Utc::now().timestamp_millis()),
        sessions: Mutex::new(HashMap::new()),
        slots: Mutex::new(load_slots()),
        owner_touch: Mutex::new(HashMap::new()),
    })
}

/// 取这一层的物料。`key_pem` 只有 keybox 层才需要（服务端存的那把设备身份私钥）。
fn material(layer: &str, key_pem: Option<&str>) -> Result<Arc<MintKey>> {
    if layer == "keybox" {
        let pem = key_pem.ok_or_else(|| anyhow!("服务端在这台设备名下没有 RSA 身份的私钥"))?;
        return Ok(Arc::new(MintKey::from_pem(pem)?));
    }
    if layer == "builtin" {
        return builtin_key();
    }
    self_signed_key()
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
/// 默认开。`RELAY_SOTER_SCOPE_WIPE=0` 关掉（回滚用，不用重新编译）。
fn scope_wipe_from(value: Option<&str>) -> bool {
    !matches!(value, Some("0") | Some("false") | Some("no") | Some("off"))
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
    // 账号指纹的 TTL 清理：节流在里面，不会拖慢请求。
    purge_owners_if_due();
    let op = body.get("op").and_then(Value::as_str).unwrap_or("probe");
    let product = virtual_device_id(device_id);

    if !KNOWN_OPS.contains(&op) {
        return None;
    }

    let key = match material(layer, key_pem) {
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
            "get_device_id" => Ok(data_result(op, OK, product.as_bytes())),
            "export_attk_public_key" => Ok(data_result(op, OK, key.attk_pem.as_bytes())),
            "export_ask_public_key" => ask_result(op, layer, &key, &product, uid_of(body)?),
            "has_ask_already" => Ok(code_result(op, OK)),
            "verify_attk_key_pair" => Ok(code_result(op, OK)),
            "has_auth_key" => Ok(code_result(
                op,
                if auth_key(device_id, body).is_some() {
                    OK
                } else {
                    NOT_FOUND
                },
            )),
            "export_auth_key_public_key" => match auth_key(device_id, body) {
                // 回的是「AuthKey 的自描述 + 签名」的信封，签名得用这一层的身份
                // （也就是 ASK）私钥 —— App 是先拿 ASK 公钥再验这个的。只回一把
                // 裸 PEM 的话，宿主拿它当信封解，解出来的是垃圾。
                Some(auth) => {
                    let counter = counter_for(&slot_id(device_id, uid_of(body)?));
                    let document = key_doc(&auth.attk_pem, &product, counter, uid_of(body)?)?;
                    let signature = key.sign(&document)?;
                    let mut out = envelope_result(op, &document, &signature)?;
                    out["layer"] = json!(layer);
                    Ok(out)
                }
                None => Ok(code_result(op, NOT_FOUND)),
            },
            "generate_auth_key_pair" => {
                let fresh = MintKey::generate().context("RSA keygen for the auth key failed")?;
                let id = auth_key_id(device_id, body)?;
                if let Ok(mut map) = store().auth.lock() {
                    map.insert(id, Arc::new(fresh));
                }
                Ok(code_result(op, OK))
            }
            "remove_auth_key" => {
                let id = auth_key_id(device_id, body)?;
                if let Ok(mut map) = store().auth.lock() {
                    map.remove(&id);
                }
                Ok(code_result(op, OK))
            }
            "remove_all_uid_key" => {
                let uid = uid_of(body)?;
                let prefix = format!("{device_id}|{uid}|");
                if let Ok(mut map) = store().auth.lock() {
                    map.retain(|k, _| !k.starts_with(&prefix));
                }
                // 钥匙没了，槽位的钉子也跟着拔：下次哪一层服务它都算从头来。
                unpin_layer(device_id, uid);
                Ok(code_result(op, OK))
            }
            "generate_ask_key_pair" | "generate_attk_key_pair" => {
                // 自签层就是换一把新的。keybox 层那把是服务端存的身份，轮换不了
                // —— 但也不能回错误：一报错调用方就往下换层，这个槽位的材料立刻
                // 劈成两半。它的 ASK 本来就在，回成功，让流程留在这层里。
                if layer == "self_signed" {
                    rotate_self_signed_key()?;
                } else if layer == "keybox" {
                    tracing::info!(
                        "soter: layer={layer} 拿着服务端存的身份，{op} 不轮换、直接回成功"
                    );
                }
                // `builtin`（探测机）也不轮换：那一把 ASK 换了只会把正在跑的一轮劈成
                // 两半，而探测机根本不看「换没换」。
                // 重建 ASK = 全新一轮流程（App 正在把旧的扔掉），槽位的钉子也该摘掉：
                // 后面哪一层服务这一轮，它就重新钉到哪一层。
                unpin_layer(device_id, uid_of(body)?);
                Ok(code_result(op, OK))
            }
            "init_sign" => {
                let uid = uid_of(body)?;
                let alias = alias_of(body)?;
                if auth_key(device_id, body).is_none() {
                    // 没有 AuthKey 就是没有，-5；跟真机上"这把钥匙不在"是同一个码。
                    return Ok(code_result(op, NOT_FOUND));
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
                    None => return Ok(code_result(op, NOT_FOUND)),
                };
                let key = match store().auth.lock().ok().and_then(|m| {
                    m.get(&format!(
                        "{device_id}|{}|{}",
                        sign_session.uid, sign_session.alias
                    ))
                    .cloned()
                }) {
                    Some(key) => key,
                    None => return Ok(code_result(op, NOT_FOUND)),
                };
                // 签的是那段 JSON 原文，不是 challenge 的字节；回「JSON + 签名」的信封
                let counter = counter_for(&slot_id(device_id, sign_session.uid));
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

fn auth_key_id(device_id: &str, body: &Value) -> Result<String> {
    Ok(format!("{device_id}|{}|{}", uid_of(body)?, alias_of(body)?))
}

fn auth_key(device_id: &str, body: &Value) -> Option<Arc<MintKey>> {
    let id = auth_key_id(device_id, body).ok()?;
    store().auth.lock().ok()?.get(&id).cloned()
}

/// 虚拟 SOTER 设备号。真机上是 `09000000` + 12 字节随机，这里用请求里的设备 id
/// 派生，好处是同一台 A 端设备每次拿到的都一样。
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
    let Ok(mut map) = store().counters.lock() else {
        return 1;
    };
    let entry = map.entry(key.to_string()).or_insert(0);
    *entry += 1;
    *entry
}

/// 一份自描述文档（ASK 或 AuthKey 的都用它）。键序照现场抓到的来：`pub_key` /
/// `cpu_id` / `counter` / `uid` / `rsa_pss_saltlen`，`uid` 是字符串别写成数字。
fn key_doc(pub_key_pem: &str, device_id: &str, counter: u64, uid: i32) -> Result<Vec<u8>> {
    let doc = json!({
        "pub_key": pub_key_pem,
        "cpu_id": device_id,
        "counter": counter,
        "uid": uid.to_string(),
        "rsa_pss_saltlen": ASK_SALT_LEN,
    });
    serde_json::to_vec(&doc).context("failed to serialize the key document")
}

/// 签名现场那份 JSON。字段名和键序照 B 端 TEE 现场抓的来（`raw` 在最前），一个
/// 都不能少 —— App 会把它们存下来当设备指纹。服务端两层是虚拟设备，指纹和 TEE
/// 这几个字段没有真值，用固定值加这台设备派生的 fid 填，稳定可复现就行。
fn sign_doc(cpu_id: &str, uid: i32, raw: &str, counter: u64, layer: &str) -> Result<Vec<u8>> {
    let doc = json!({
        "raw": raw,
        "fid": fid_of(cpu_id),
        "counter": counter,
        "tee_n": "ommega-server-soter",
        "tee_v": env!("CARGO_PKG_VERSION"),
        "fp_n": "server",
        "fp_v": layer,
        "cpu_id": cpu_id,
        "uid": uid.to_string(),
        "rsa_pss_saltlen": ASK_SALT_LEN,
    });
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

fn ask_result(op: &str, layer: &str, key: &MintKey, device_id: &str, uid: i32) -> Result<Value> {
    let counter = counter_for(&slot_id(device_id, uid));
    let document = key_doc(&key.attk_pem, device_id, counter, uid)?;
    let signature = key.sign(&document)?;
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
    use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
    use rsa::signature::Verifier;

    fn ask_payload(uid: i64) -> Value {
        run(
            "self_signed",
            "device-a-test",
            &json!({ "op": "export_ask_public_key", "uid": uid }),
            None,
        )
        .expect("self-signed layer should handle export_ask_public_key")
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
        let verifying = PssVerifyingKey::<Sha256>::new(public);
        let signature = PssSignature::try_from(signature).expect("signature parses");
        verifying
            .verify(document, &signature)
            .expect("the ASK document must verify with the exported ATTK key");
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

    #[test]
    fn has_ask_already_and_verify_are_successful() {
        for op in ["has_ask_already", "verify_attk_key_pair"] {
            let value = run(
                "self_signed",
                "device-a-test",
                &json!({ "op": op, "uid": 10373 }),
                None,
            )
            .expect("handled");
            assert_eq!(value["error_code"], json!(0), "{op} should report success");
        }
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
        assert_eq!(absent["error_code"], json!(NOT_FOUND));

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

    /// 拿一把 PEM 公钥验一段签名（RSA-PSS-SHA256）。
    fn verifies(pem: &str, message: &[u8], signature: &[u8]) -> bool {
        use pkcs8::DecodePublicKey as _;
        let Ok(public) = rsa::RsaPublicKey::from_public_key_pem(pem) else {
            return false;
        };
        let Ok(signature) = PssSignature::try_from(signature) else {
            return false;
        };
        PssVerifyingKey::<Sha256>::new(public)
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
            verifies(&ask_pem(device, uid), &document, &signature),
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
            json!(NOT_FOUND)
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
            json!(NOT_FOUND)
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
    fn the_wipe_downgrade_switch_defaults_on() {
        assert!(scope_wipe_from(None));
        assert!(scope_wipe_from(Some("1")));
        assert!(scope_wipe_from(Some("true")));
        for off in ["0", "false", "no", "off"] {
            assert!(!scope_wipe_from(Some(off)), "{off} 应该关掉降级");
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
            json!(0)
        );
        // 没建过的钥匙就是没建过，跟真机同一个码。
        assert_eq!(
            call(json!({"op": "has_auth_key", "uid": uid, "alias": alias}))["error_code"],
            json!(NOT_FOUND)
        );
        assert_eq!(
            call(json!({"op": "init_sign", "uid": uid, "alias": alias, "challenge": "0a1b"}))
                ["error_code"],
            json!(NOT_FOUND)
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
            json!(NOT_FOUND)
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
