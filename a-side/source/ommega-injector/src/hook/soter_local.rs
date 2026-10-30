//! A 端本地的 SOTER 后端（自签兜底）。
//!
//! 这台机器的 SOTER TA 是没 provisioning 的 —— 实测 `generateAskKeyPair` 直接回
//! -20，key 一把都建不出来，所以本地真 HAL 这条腿是瘸的。这个模块补的就是那一
//! 块：拿编译进来的 ATTK（构建时现生成的那把自签 RSA）签 ASK 的认证信封，
//! ASK 本身按 uid 用到才现生成、落盘复用。
//!
//! 形状跟服务端 `soter_mint.rs` 一模一样（那边的测试验过：ASK 的签名拿导出的
//! ATTK 公钥验得过）。要吐信封的三处都是同一个形状：
//!
//! ```text
//! [i32 le JSON 长度][JSON][256 字节 RSA-PSS-SHA256 签名]
//! ```
//!
//! - `exportAskPublicKey`：JSON 是 ASK 的自描述（`pub_key` 就是本机 ASK 公钥），
//!   拿 ASK 自己签 —— 本地模式里 ASK 兼 ATTK，跟服务端 self_signed 那层一个道理；
//! - `exportAuthKeyPublicKey`：JSON 是 AuthKey 的自描述，**拿 ASK 私钥签**。App 是
//!   先拿到 ASK 公钥、再拿它验这个信封的，签错了它验不过；
//! - `finishSign`：JSON 是这次签名的现场（`raw` / `fid` / `counter` / `tee_*` /
//!   `fp_*` / `cpu_id` / `uid`），**拿 AuthKey 签那段 JSON 原文**。真机签的不是
//!   challenge 的字节，而是这段 JSON（B 端实测：App 验的也是 JSON 原文）。
//!
//! 键序全照真机现场抓到的来，字段名一个都别改，`uid` 是字符串不是数字。
//!
//! 设备信息（`cpu_id` / `fp_n` / `fp_v` / `tee_n` / `tee_v` / `fid`）按本机属性推：
//! `cpu_id` 先看 daemon 学来的那份真机值（[`kmr_common::soter_relay::CPU_ID_PATHS`]），
//! 没有才按 `ro.boot.serialno` 派生一个；指纹和 TEE 也从属性读，读不到才退回兜底值。
//! 不要把它写成编死的常量 —— 那样装过这套的机器全是同一个设备，业务侧一眼假。
//!
//! 心里得有数的边界：自签的链**骗得过 App 本地**（它拿我们给的公钥验我们签的
//! 东西，当然验得过），**骗不过业务服务端的证书链校验**。私钥就编在 binary 里，
//! 谁扒出来都能用 —— 这是兜底，不是安全方案。
//!
//! 参数校验、错误码这些都跟着真机宿主那套走（-5 是"这把钥匙不在这台设备上"，
//! 实测宿主也是这么回的），这样上层看不出区别。

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::pss::SigningKey as PssSigningKey;
use rsa::pss::VerifyingKey as PssVerifyingKey;
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256 as PssSha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::RsaPrivateKey;

use crate::hook::soter;

/// SOTER 的成功码。
const OK: i32 = 0;
/// "这把钥匙不在这台设备上"。实测 hasAskAlready / exportAuthKeyPublicKey 都回它。
const NOT_FOUND: i32 = -5;
/// AuthKey 还没建。真机 TA 这里答 -6（AUTH_KEY_NOT_READY），答 -5 会被当成 ASK 没就绪。
const AUTH_KEY_NOT_READY: i32 = -6;
/// ASK 里写死的盐长，也正好是 SHA-256 的摘要长度。
const SALT_LEN: i32 = 32;
/// 编译进来的 ATTK（构建时按当时时间现生成的一把自签 RSA）。
/// ASK 不内置：每个 uid 的 ASK 都是用到时现生成、落盘复用。
const ATTK_PEM: &[u8] = include_bytes!("../../assets/soter_attk.pem");
/// 换本地兜底 ATTK 用的文件（PKCS#8 PEM，`openssl genpkey -algorithm RSA` 那种）。
/// 存在且解析得过就用它，跟 keybox 一个路子：丢文件进去、重启 SOTER 宿主就生效。
///
/// 两个位置对应两个域，谁在哪个域里读得到就认谁：
/// - `/data/misc/ommega/`：payload 落进 app 域（SOTER 宿主是 uid 1000）时读得到；
/// - `/data/misc/keystore/ommega/`：跟真配置同一个目录，keystore 域读得到。
const ATTK_FILE_PATHS: [&str; 2] = [
    "/data/misc/ommega/soter_attk.pem",
    "/data/misc/keystore/ommega/soter_attk.pem",
];
/// 环境变量覆盖 ATTK，写测试和临时探针用。
const ATTK_FILE_ENV: &str = "OMMEGA_SOTER_ATTK_PEM";

/// counter 起点。真机上这个号早就几千了（PLC110 实测 7394），从 1 开始会被当回滚。
const COUNTER_BASE: u64 = 10_000;

/// 强制覆盖 cpu_id 的文件。拿别台设备的 ATTK 重放时要跟那台报同一个号，
/// 否则服务端按 cpu_id 查不到设备。daemon 不认识这个文件名，不会写回。
const CPU_ID_OVERRIDE: &str = "/data/misc/ommega/soter_cpu_id.force";
/// `fid` 在序列号读不到时的兜底种子。`cpu_id` **不用**它 —— 那个号只从真实属性来，
/// 读不到就不报，绝不编一个（见 [`cpu_id`]）。
const FALLBACK_SEED: &str = "ommega-a-side-local";

/// 从一段可能夹着注释的文件里抽出 PEM 本体（`-----BEGIN` 到 `-----END`）。
///
/// WebUI 导入的 ATTK 文件可以在里面写一行 `cpu_id: 09000000…`，daemon 会拿它设
/// `soter_cpu_id.force`；这里把这些非 PEM 行滤掉再交给解析器。
fn pem_block(pem: &str) -> String {
    let mut out = String::with_capacity(pem.len());
    let mut inside = false;
    for line in pem.lines() {
        if line.contains("-----BEGIN") {
            inside = true;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
        if line.contains("-----END") {
            inside = false;
        }
    }
    out
}

/// 一对 RSA，加它的公钥 PEM（SOTER 里的"证书"就是拿这个验的）。
#[derive(Clone)]
struct Key {
    private: RsaPrivateKey,
    /// 公钥 PEM，`exportXxxPublicKey` 吐出去的就是它。
    pem: String,
}

impl Key {
    fn from_pem(pem: &str) -> Option<Self> {
        // 文件里允许带 `cpu_id: 09000000…` 这类注释行（WebUI 导入时 daemon 靠它设 force），
        // PEM 解析器不认那些行，先只取 BEGIN…END 之间那段。
        let block = pem_block(pem);
        let private = RsaPrivateKey::from_pkcs8_pem(block.trim()).ok()?;
        let pem = rsa::RsaPublicKey::from(&private)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .ok()?;
        Some(Self { private, pem })
    }

    fn generate() -> Option<Self> {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).ok()?;
        let pem = rsa::RsaPublicKey::from(&private)
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .ok()?;
        Some(Self { private, pem })
    }

    /// RSA-PSS-SHA256，盐长 = 摘要长度 = 32，跟 JSON 里那个字段对得上。
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        let signing = PssSigningKey::<PssSha256>::new(self.private.clone());
        let mut rng = OsRng;
        Some(signing.sign_with_rng(&mut rng, message).to_bytes().to_vec())
    }
}

/// 本地签名自检：拿当前生效的 ASK 签一段固定文本，再用它的公钥验一遍。
///
/// 这是给面板「加载即得结论」用的 —— 只走本地密码学，微秒级返回，**不碰网络也
/// 不碰 TEE**，所以不会阻塞任何签名路径。失败只说明「这次没成」，不当成「这台机器
/// 不能签」（跟 `SignState` 那套一个口径）。
pub(crate) fn selftest() -> anyhow::Result<()> {
    state().ok_or_else(|| anyhow::anyhow!("soter local state unavailable"))?;
    let message: &[u8] = b"ommega-soter-selftest";
    let attk = current_attk().ok_or_else(|| anyhow::anyhow!("soter local ATTK unavailable"))?;
    let raw = attk
        .sign(message)
        .ok_or_else(|| anyhow::anyhow!("the local ATTK could not sign"))?;
    let signature = rsa::pss::Signature::try_from(raw.as_slice())
        .map_err(|error| anyhow::anyhow!("malformed signature: {error}"))?;
    let public = rsa::RsaPublicKey::from(&attk.private);
    PssVerifyingKey::<PssSha256>::new(public)
        .verify(message, &signature)
        .map_err(|error| anyhow::anyhow!("the signature did not verify: {error}"))
}

/// 一次 initSign 挂起来的会话。
struct SignSession {
    uid: i32,
    alias: String,
    /// 挑战原文，宿主传下来什么样就存什么样。真机把它写进签名 JSON 的 `raw` 里，
    /// 我们照做，不去解它（解了反而签的不是 App 要的东西）。
    raw: String,
}

/// 后端状态。签发用的 key 一开始就加载好（编译进来的，失败就是编坏了）。
struct State {
    /// 签名根（ATTK）。本地模式里它就是 `exportAttkPublicKey` 吐的那把，全设备只有一把。
    /// 外面用 [`current_attk`] 取，文件换了会现读，跟 keybox 一个路子。
    attk: Mutex<Key>,
    /// 对外导出的 ASK。真机是一把 ATTK 挂 N 把 ASK、每个 uid 一把，这里按 uid 存。
    asks: Mutex<HashMap<i32, Key>>,
    /// `{uid}|{alias}` -> AuthKey。
    auth: Mutex<HashMap<String, Key>>,
    /// uid -> 签名计数器（ASK JSON 里的 counter）。
    counters: Mutex<HashMap<i32, u64>>,
    /// 哪些 uid 上已经「建过 ASK」。
    ///
    /// 9 号以前写死答 NOT_FOUND（防毒化，2026-10-11 那次事故），后果是 5 号刚建完、
    /// 再问还是「没有」，App 和检测器（Duck 的 keyPrep）就永远卡在「ASK 没准备好」，
    /// 只能一遍遍重来。这里记一笔，让本地这条路的 ASK 生命周期自洽。
    ask_built: Mutex<HashSet<i32>>,
    /// 会话号 -> 这一次要签的挑战。
    sessions: Mutex<HashMap<i64, SignSession>>,
    /// 下一个会话号。起点用当前毫秒，看起来像真的。
    next_session: Mutex<i64>,
}

/// ATTK 到底从哪儿来的（换 key 之后一眼看得出生效没有）。
static ATTK_ORIGIN: OnceLock<String> = OnceLock::new();
/// uid -> 该 uid 的 ASK 来自哪里（per-uid store / 旧 per-uid 文件迁移 / 现生成）。
static ASK_ORIGINS: std::sync::LazyLock<Mutex<HashMap<i32, String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// ATTK 和已经加载过的 ASK 的来源描述，`state()` 初始化之前是 `None`。
#[cfg(test)]
pub(crate) fn ask_origin() -> Option<String> {
    let attk = ATTK_ORIGIN.get()?;
    let mut parts: Vec<String> = match ASK_ORIGINS.lock() {
        Ok(map) => map
            .iter()
            .map(|(uid, origin)| format!("uid={uid}:{origin}"))
            .collect(),
        Err(_) => Vec::new(),
    };
    parts.sort();
    if parts.is_empty() {
        Some(format!("attk={attk}"))
    } else {
        Some(format!("attk={attk}; {}", parts.join(", ")))
    }
}

/// 按候选顺序找一把可用的 ATTK：环境变量指定的文件 → 两个候选文件 → 编进来的那把。
///
/// `override_path` 是给测试用的显式覆盖（不去碰进程环境变量，免得多线程下互相干扰）。
fn load_attk_key_with(override_path: Option<std::path::PathBuf>) -> Option<(Key, String)> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    let from_env =
        override_path.or_else(|| std::env::var_os(ATTK_FILE_ENV).map(std::path::PathBuf::from));
    if let Some(path) = from_env {
        candidates.push(path);
    }
    candidates.extend(ATTK_FILE_PATHS.iter().map(std::path::PathBuf::from));

    for path in candidates {
        let Ok(pem) = std::fs::read_to_string(&path) else {
            continue;
        };
        match Key::from_pem(&pem) {
            Some(key) => return Some((key, path.display().to_string())),
            // 文件在那儿但读不出私钥：别当没事，也别拿它顶，继续往下找。
            None => log::warn!(
                "soter local attk at {} is not a usable PKCS#8 PEM; ignoring it",
                path.display()
            ),
        }
    }

    let pem = std::str::from_utf8(ATTK_PEM).ok()?;
    Some((Key::from_pem(pem)?, "embedded attk".to_string()))
}

fn load_attk_key() -> Option<(Key, String)> {
    load_attk_key_with(None)
}

/// 旧版按 uid 散落的 ASK 文件位置（读到就迁进 store，然后把旧文件删掉）。
fn legacy_ask_file_paths(uid: i32) -> [String; 2] {
    [
        format!("/data/misc/keystore/ommega/soter_ask_{uid}.pem"),
        format!("/data/misc/ommega/soter_ask_{uid}.pem"),
    ]
}

/// 所有 uid 的 ASK 和 AuthKey 存在这一个文件里，不要按 uid/alias 散成一堆 pem。
/// 结构是两层：
///
/// ```json
/// { "asks": { "10496": "<pem>" }, "authkeys": { "10496|SoterAuthKey": "<pem>" } }
/// ```
///
/// 旧版只有一层（`{ "10496": "<pem>" }`），读的时候当成 `asks` 处理。
const ASK_STORE_PATHS: [&str; 2] = [
    "/data/misc/keystore/ommega/soter_asks.json",
    "/data/misc/ommega/soter_asks.json",
];
const ASK_SECTION: &str = "asks";
const AUTH_SECTION: &str = "authkeys";

/// 落盘那一瞬间的互斥：读改写不是原子操作，两个 uid 同时进来会互相盖掉。
static ASK_STORE_LOCK: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

fn read_ask_store() -> serde_json::Map<String, serde_json::Value> {
    for path in ASK_STORE_PATHS {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(serde_json::Value::Object(mut map)) => {
                // 旧版扁平格式：顶层全是 uid，整个当成 asks。
                let flat = !map.is_empty() && map.keys().all(|key| key.parse::<i32>().is_ok());
                if flat {
                    let mut wrapped = serde_json::Map::new();
                    wrapped.insert(ASK_SECTION.to_string(), serde_json::Value::Object(map));
                    return wrapped;
                }
                map.retain(|key, _| key == ASK_SECTION || key == AUTH_SECTION);
                return map;
            }
            _ => log::warn!("soter local ask store at {path} is not a json object; ignoring it"),
        }
    }
    serde_json::Map::new()
}

fn write_ask_store(map: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let text = serde_json::to_string_pretty(map).ok()?;
    for path in ASK_STORE_PATHS {
        if let Some(dir) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // 写临时文件再 rename：中途掉电也不会留个半个 json。
        let tmp = format!("{path}.tmp");
        if std::fs::write(&tmp, text.as_bytes()).is_ok() && std::fs::rename(&tmp, path).is_ok() {
            return Some(path.to_string());
        }
        let _ = std::fs::remove_file(&tmp);
        log::warn!("soter local cannot write the ask store at {path}");
    }
    None
}

fn section_of<'a>(
    map: &'a mut serde_json::Map<String, serde_json::Value>,
    section: &str,
) -> &'a mut serde_json::Map<String, serde_json::Value> {
    let entry = map
        .entry(section.to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !entry.is_object() {
        *entry = serde_json::Value::Object(serde_json::Map::new());
    }
    entry
        .as_object_mut()
        .expect("the section was just replaced with an object")
}

fn read_store_pem(section: &str, key: &str) -> Option<String> {
    let map = read_ask_store();
    let table = map.get(section)?.as_object()?;
    match table.get(key)? {
        serde_json::Value::String(pem) => Some(pem.clone()),
        _ => None,
    }
}

fn store_pem(section: &str, key: &str, pem: &str) -> Option<String> {
    let _guard = ASK_STORE_LOCK.lock().ok()?;
    let mut map = read_ask_store();
    section_of(&mut map, section)
        .insert(key.to_string(), serde_json::Value::String(pem.to_string()));
    write_ask_store(&map)
}

fn forget_pem(section: &str, key: &str) {
    let Ok(_guard) = ASK_STORE_LOCK.lock() else {
        return;
    };
    let mut map = read_ask_store();
    let removed = section_of(&mut map, section).remove(key).is_some();
    if removed {
        write_ask_store(&map);
    }
}

/// 删掉某个 uid 的全部东西：ASK、这个 uid 名下所有 AuthKey、以及旧版散落的 pem。
fn forget_uid_keys(uid: i32) {
    let Ok(_guard) = ASK_STORE_LOCK.lock() else {
        return;
    };
    let mut map = read_ask_store();
    section_of(&mut map, ASK_SECTION).remove(&uid.to_string());
    let prefix = format!("{uid}|");
    section_of(&mut map, AUTH_SECTION).retain(|key, _| !key.starts_with(&prefix));
    write_ask_store(&map);
    for path in legacy_ask_file_paths(uid) {
        let _ = std::fs::remove_file(path);
    }
}

/// ATTK 文件的 mtime。换文件（WebUI 写新的、用户手放）时靠它判断要不要重读。
static ATTK_STAMP: Mutex<Option<std::time::SystemTime>> = Mutex::new(None);

fn attk_stamp() -> Option<std::time::SystemTime> {
    ATTK_FILE_PATHS
        .iter()
        .filter_map(|path| {
            std::fs::metadata(path)
                .and_then(|meta| meta.modified())
                .ok()
        })
        .max()
}

/// 当前生效的 ATTK。文件没变就吃缓存，变了就现读 —— 换 key 不用重启 payload。
fn current_attk() -> Option<Key> {
    let state = state()?;
    let stamp = attk_stamp();
    let mut cached = state.attk.lock().ok()?;
    if let Ok(mut known) = ATTK_STAMP.lock() {
        if *known == stamp {
            return Some(cached.clone());
        }
        if let Some((key, origin)) = load_attk_key() {
            *cached = key.clone();
            *known = stamp;
            log::info!("event=soter ATTK hot-reloaded from {origin}");
            return Some(key);
        }
    }
    Some(cached.clone())
}

/// 取（必要时造）某个 uid 的 ASK。
///
/// 真机的形状是一把 ATTK 下挂 N 把 ASK、每个 uid 一把，这里照做：
/// 先看内存，再按 uid 读文件，再兼容旧的全局文件，最后现生成一对并落盘。
fn ask_for(state: &State, uid: i32) -> Option<Key> {
    if let Some(key) = state.asks.lock().ok()?.get(&uid).cloned() {
        return Some(key);
    }

    let (key, origin) = load_or_generate_ask(uid)?;
    if let Ok(mut map) = state.asks.lock() {
        map.insert(uid, key.clone());
    }
    if let Ok(mut map) = ASK_ORIGINS.lock() {
        map.insert(uid, origin.clone());
    }
    if let Ok(mut set) = state.ask_built.lock() {
        set.insert(uid);
    }
    log::info!("soter local ASK for uid {uid} loaded from {origin}");
    Some(key)
}

/// 读某个 uid 的 ASK：环境变量 → 单文件 store → 旧的 per-uid 文件（读到就迁走）→
/// 旧的全局文件 → 现生成并写进 store。
fn load_or_generate_ask(uid: i32) -> Option<(Key, String)> {
    if let Some(pem) = read_store_pem(ASK_SECTION, &uid.to_string()) {
        match Key::from_pem(&pem) {
            Some(key) => return Some((key, format!("store:uid={uid}"))),
            None => log::warn!(
                "soter local ask for uid {uid} in the store is not a usable PKCS#8 PEM; ignoring it"
            ),
        }
    }

    // 旧版按 uid 散落的 pem：读到就迁进 store，然后把旧文件删掉，不再留一堆文件。
    for path in legacy_ask_file_paths(uid) {
        let Ok(pem) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some(key) = Key::from_pem(&pem) else {
            log::warn!(
                "soter local ask for uid {uid} at {path} is not a usable PKCS#8 PEM; ignoring it"
            );
            continue;
        };
        let origin = match store_pem(ASK_SECTION, &uid.to_string(), &pem) {
            Some(store) => {
                let _ = std::fs::remove_file(&path);
                format!("migrated:{path}->{store}")
            }
            None => format!("file:{path}"),
        };
        return Some((key, origin));
    }

    generate_ask_for(uid)
}

/// 给某个 uid 现生成一把 ASK，写进 [`ASK_STORE_PATHS`] 的单文件 store。
/// 落盘失败就只在内存里用（重启会换新，App 会当 ASK 变了把本地钥匙清掉），所以告警。
fn generate_ask_for(uid: i32) -> Option<(Key, String)> {
    let key = Key::generate()?;
    let private_pem = key.private.to_pkcs8_pem(LineEnding::LF).ok()?;

    if let Some(store) = store_pem(ASK_SECTION, &uid.to_string(), &private_pem) {
        log::info!("soter local generated a new ASK for uid {uid} in {store}");
        return Some((key, format!("generated:{store}#uid={uid}")));
    }

    log::warn!("soter local is using an in-memory ASK for uid {uid}; it changes after restart");
    Some((key, format!("generated:memory:{uid}")))
}

fn state() -> Option<&'static State> {
    static STATE: OnceLock<Option<State>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            let (attk, origin) = load_attk_key()?;
            log::info!("soter local ATTK loaded from {origin}");
            let _ = ATTK_ORIGIN.set(origin);
            if let Ok(mut known) = ATTK_STAMP.lock() {
                *known = attk_stamp();
            }
            Some(State {
                attk: Mutex::new(attk),
                asks: Mutex::new(HashMap::new()),
                auth: Mutex::new(HashMap::new()),
                counters: Mutex::new(HashMap::new()),
                ask_built: Mutex::new(HashSet::new()),
                sessions: Mutex::new(HashMap::new()),
                next_session: Mutex::new(now_millis()),
            })
        })
        .as_ref()
}

/// 单调递增的下限。重启后即使文件丢了/读不到，也拿着它保证不回退。
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 一台"看起来像真机"的设备号：`09000000` + 12 字节十六进制。
///
/// 两个真实来源：daemon 写下的那份文件，或按本机真实序列号现派生；一个都拿不到就
/// 是空串（不编号，本地这条路也就不答，见 [`answer`]）。
pub(crate) fn device_id() -> String {
    cpu_id()
}

/// 当前该报的 cpu_id。
///
/// 不缓存：
/// `line!` 之前这里是「30 秒看一次文件」的缓存，后来改成每次都现读（daemon 学到新值就
/// 立即跟上，少一份状态少一个错），但常量和结构体没清，编译会报三个 dead_code。
/// 真机 cpu_id 一辈子不换，这里读文件的开销可以忽略。
/// 本地兜底这条路上该报的 cpu_id：**只按本机真实序列号派生**。
///
/// 不能读 `/data/misc/ommega/soter_cpu_id` 那份：那是转发给服务端用的 **B 端真机号**
/// （见 `src/soter_cpu_id.rs`）。本地兜底是 A 端自己的软件 TA，跟 B 不是同一台设备，
/// 拿 B 的号会让同一个 uid 下出现两个不同的 cpu_id —— 检测器一条「两次 cpuid 不一致」
/// 直接判红。两份身份各用各的：转发走 B 的号，本地走本机号。
fn cpu_id() -> String {
    // 顺序：daemon 学来的那份（`CPU_ID_PATHS` 文件 / 环境变量）→ 本机序列号派生。
    //
    // 优先用文件是因为那个位置就是给 app 域准备的（`system_app_data_file`），一定读得到；
    // 而 `prop()` 在注入进去的 payload 里读不到 `ro.boot.serialno`（NX721J 实测：shell 的
    // `getprop` 能读到序列号，payload 里却拿不到），于是 `cpu_id()` 空、整层不答。
    //
    // 代价：文件里存的是 daemon 从真机学来的号，不是本机序列号派生的那个。同一 uid 下
    // 转发和本地报不同号时检测器会判「两次 cpuid 不一致」；但「不答」比「号不一致」更糟
    // （前者整条链路直接不通），所以先取文件。
    // 强制覆盖：重放别台设备的 ATTK 时，cpu_id 也得跟那台一致。
    if let Ok(text) = std::fs::read_to_string(CPU_ID_OVERRIDE) {
        if let Some(value) = kmr_common::soter_relay::parse_cpu_id(&text) {
            log::info!("event=soter cpu_id forced by {CPU_ID_OVERRIDE}");
            return value;
        }
        log::warn!("event=soter {CPU_ID_OVERRIDE} exists but holds no valid cpu_id");
    }
    let (learned, source) = load_cpu_id();
    if let Some(value) = learned {
        log::debug!("event=soter cpu_id from {source}");
        return value;
    }
    device_info().derived_cpu_id.clone().unwrap_or_default()
}

/// 找一份学来的 cpu_id：环境变量 > 两个候选文件。找不到返回 `(None, "derived")`，
/// 调用方再用本机真实序列号现派生那份兜底（两处都没有才空着）。
fn load_cpu_id() -> (Option<String>, String) {
    let env = std::env::var_os(kmr_common::soter_relay::CPU_ID_ENV)
        .map(|raw| raw.to_string_lossy().into_owned());
    load_cpu_id_from(&kmr_common::soter_relay::CPU_ID_PATHS, env)
}

/// `load_cpu_id` 里跟「从哪读」无关的那半（测试要拿临时文件跑，不进进程环境）。
fn load_cpu_id_from(paths: &[&str], env: Option<String>) -> (Option<String>, String) {
    if let Some(raw) = env {
        match kmr_common::soter_relay::parse_cpu_id(raw.trim()) {
            Some(id) => return (Some(id), "env".to_string()),
            None => log::warn!(
                "soter local {} is not a usable cpu_id; ignoring it",
                kmr_common::soter_relay::CPU_ID_ENV
            ),
        }
    }
    for path in paths {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        match kmr_common::soter_relay::parse_cpu_id(&text) {
            Some(id) => return (Some(id), format!("file {path}")),
            // 文件在那儿但里面没有合形状的值：别当没事，也别拿它顶，继续往下找。
            None => log::warn!("soter local cpu_id at {path} has no usable value; ignoring it"),
        }
    }
    (None, "derived".to_string())
}

// ---------------------------------------------------------------------------
// 本机设备信息：本地模式该拿这台机器自己的东西填，不编常量
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
extern "C" {
    /// bionic 里现成的属性读取，返回写进 value 的长度（0 = 没这条属性）。
    fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
}

/// 读一条系统属性。
///
/// 走 `getprop` 命令而不是 `__system_property_get`：后者在 dlopen 进来的 payload 里实测
/// 读不到（NX721J：shell 里 `getprop ro.boot.serialno` 能拿到序列号，payload 里
/// `__system_property_get` 返回 0，静默当成“没这条属性”）。签名这条路径每毫秒都算数，
/// 但多 fork 一次 `getprop` 换“真能读到”比省那点开销值。
#[cfg(target_os = "android")]
pub(crate) fn prop(name: &str) -> Option<String> {
    let output = std::process::Command::new("/system/bin/getprop")
        .arg(name)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// 非 Android（开发机上 `cargo check` 这种）读不到属性，一律当没有，走兜底值。
#[cfg(not(target_os = "android"))]
fn prop(_name: &str) -> Option<String> {
    None
}

/// 这台机器的 SOTER 设备信息。属性只读一次，之后复用。
struct DeviceInfo {
    /// 按本机真实序列号现派生的那个号，`09000000` + 12 字节十六进制。只当兜底：
    /// daemon 那份文件没读到、又没有环境变量时才用它；序列号都读不到就是 `None`。
    derived_cpu_id: Option<String>,
    fp_n: String,
    fp_v: String,
    tee_n: String,
    tee_v: String,
    /// 签名 JSON 里那个 `fid`（指纹 id）。
    fid: String,
}

fn device_info() -> &'static DeviceInfo {
    static INFO: OnceLock<DeviceInfo> = OnceLock::new();
    INFO.get_or_init(|| {
        let serial = prop("ro.boot.serialno").or_else(|| prop("ro.serialno"));
        // 这条是为了查「本地层为何不答」：`answer()` 只要 `cpu_id()` 空就整笔不答，
        // 而空的原因可能是属性读不到、也可能是派生失败，光看一条 WARN 分不清。
        log::info!(
            "event=soter device_info serial={:?} derived_cpu_id={:?}",
            serial,
            serial.as_deref().map(cpu_id_from)
        );
        DeviceInfo {
            derived_cpu_id: serial.as_deref().map(cpu_id_from),
            fp_n: fingerprint_name(),
            fp_v: fingerprint_version(),
            tee_n: tee_name(),
            tee_v: tee_version(),
            fid: fid_from(serial.as_deref()),
        }
    })
}

/// 32 字符 hex 转 16 字节。真机 getDeviceId 出的是二进制，不是文本。
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

/// 一台像真机的设备号：`09000000` + 12 字节十六进制。只拿真实序列号算，没有就不算。
fn cpu_id_from(serial: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-a-side-soter:");
    hasher.update(serial.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::from("09000000");
    for byte in &digest[..12] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 指纹 id。真值在 TA 里，本地拿不到 —— 按本机派生一个稳定的十进制串，形状跟真机
/// 一致（B 端是 `3650688678` 这种十位）。
fn fid_from(serial: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-a-side-soter-fid:");
    hasher.update(serial.unwrap_or(FALLBACK_SEED).as_bytes());
    let digest = hasher.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 4_000_000_000;
    (1_000_000_000u64 + n as u64).to_string()
}

/// 指纹厂商。ZTE/nubia 把型号写在 feature 开关里，认不出来就看 `ro.hardware.fingerprint`。
fn fingerprint_name() -> String {
    if prop("ro.vendor.feature.zte_fingerprint_default_goodix_g7_aidl").is_some()
        || prop("ro.vendor.feature.zte_fingerprint_default_goodix_gf96xx_g7_cali").is_some()
    {
        return "Goodix".to_string();
    }
    prop("ro.hardware.fingerprint").unwrap_or_else(|| "unknown".to_string())
}

/// 指纹固件版本。有真版本号就用真的，没有就退回传感器型号。
fn fingerprint_version() -> String {
    for name in [
        "persist.vendor.fingerprint.fw_version",
        "vendor.fingerprint.fw_version",
        "persist.goodix.fw_version",
    ] {
        if let Some(value) = prop(name) {
            return value;
        }
    }
    if prop("ro.vendor.feature.zte_fingerprint_default_goodix_gf96xx_g7_cali").is_some() {
        return "GF96xx".to_string();
    }
    "unknown".to_string()
}

/// TEE 名字。A 端这批是 QTI 平台，跑的是 QSEE。
fn tee_name() -> String {
    match prop("ro.soc.manufacturer").as_deref() {
        Some("QTI") | Some("Qualcomm") | Some("Qualcomm Technologies, Inc") => "QSEE".to_string(),
        _ => prop("ro.hardware").unwrap_or_else(|| "unknown".to_string()),
    }
}

/// TEE 版本。真机上是 TA 报的版本串，本地拿不到 —— 拿本机的 SoC 型号加安全补丁拼
/// 一个：都是真的、每台机器不一样、也不会变来变去。
fn tee_version() -> String {
    let soc = prop("ro.soc.model").unwrap_or_default();
    let patch = prop("ro.vendor.build.security_patch")
        .or_else(|| prop("ro.build.version.security_patch"))
        .unwrap_or_default();
    match (soc.is_empty(), patch.is_empty()) {
        (false, false) => format!("{soc}-{patch}"),
        (false, true) => soc,
        (true, false) => patch,
        (true, true) => "unknown".to_string(),
    }
}

/// 后端给出来的一笔应答。
///
/// 三个分支跟 HAL 的方法签名一一对应，别混：形状错了宿主解出来的是垃圾。
pub(crate) enum Answer {
    /// 只有返回值的那些 op（generate* / has* / remove*）。
    Code(i32),
    /// 签名里带 `out SoterBufferReturn` 的那些（exportXxxPublicKey / finishSign /
    /// getDeviceId）：返回值加一份数据。`data` 为 `None` 就是「这个 out 是空的」，
    /// 那 4 字节非空标记写 0 —— 形状不能省。
    Buffer { code: i32, data: Option<Vec<u8>> },
    /// `initSign` 的回复，它返回的是 `SoterInitReturn`（status + session）。
    Init { status: i32, session: i64 },
}

/// 本地后端写了实现的那些 HAL 号码（就是 `answer` 里那几个 match 臂）。
///
/// 2 / 6 / 14 是产线 provisioning（工程模式那页的 SOTER key 就看 14 号）：原厂 TA
/// 没 provisioning 时整族回 -20，宿主那半边也不发这三个，所以只能我们顶 —— 软件 TA
/// 里 ASK 兼 ATTK，VERIFY 永远成功、EXPORT 交 ASK 那份自描述。
pub(crate) const HANDLED_CODES: [u32; 14] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// 这个号码本地答得了吗。`true` 只说「有对应的实现」——参数不够的时候 `answer`
/// 照样返回 `None`，上层会原样透给真 HAL，所以这里不用把参数也掰开看一遍。
pub(crate) fn answerable(code: u32) -> bool {
    HANDLED_CODES.contains(&code)
}

/// 这个会话号是不是本进程开的。
///
/// `initSign` 那笔要是服务端说「你本地答」（白名单外的检测器一类），会话就存在这里；
/// 那 `finishSign` 也必须回来本地答 —— 去问远程就是 B 端不认识这个句柄，直接回 -204。
pub(crate) fn has_session(session: i64) -> bool {
    state()
        .and_then(|state| {
            state
                .sessions
                .lock()
                .ok()
                .map(|map| map.contains_key(&session))
        })
        .unwrap_or(false)
}

/// 按号码算一笔应答。认不出来、或者少参数就返回 `None`，让上层透给真 HAL。///
/// 只处理 HAL 那半边（`call.hal`）：App 面向那半边是宿主自己的事，它会把我们的
/// 结果原样包成 `SoterExportResult` 递给 App，不用我们操心。
pub(crate) fn answer(call: &soter::SoterCall) -> Option<Answer> {
    let result = answer_inner(call);
    // 记一笔应答。光看「调用进去了」不够 —— 得知道它回来了什么，
    // 才能分清是没答（透传）还是答错（形状/码不对）。`data` 只记长度，不刷字节。
    match &result {
        Some(Answer::Code(code)) => {
            log::info!("event=soter local answer op={} code={}", call.code, code)
        }
        Some(Answer::Buffer { code, data }) => log::info!(
            "event=soter local answer op={} code={} len={}",
            call.code,
            code,
            data.as_ref().map(|bytes| bytes.len()).unwrap_or(0)
        ),
        Some(Answer::Init { status, session }) => log::info!(
            "event=soter local answer op={} status={} session={}",
            call.code,
            status,
            session
        ),
        None => log::info!(
            "event=soter local answer op={} = none (passthrough)",
            call.code
        ),
    }
    result
}

/// 实际的应答逻辑，外壳在 [`answer`]。
fn answer_inner(call: &soter::SoterCall) -> Option<Answer> {
    if !call.hal {
        return None;
    }
    // 产线 provisioning 三兄弟最先处理：不碰本机身份、也不建钥匙，跟 cpu_id 那条
    // 前置检查无关（工程模式跑在 vendor 域，那份 cpu_id 文件它常常读不到）。
    match call.code {
        14 => return Some(Answer::Code(OK)),
        6 => return Some(Answer::Code(OK)),
        2 => {
            return Some(Answer::Buffer {
                code: OK,
                data: Some(ask_public_document(call.uid.unwrap_or(-1))),
            })
        }
        _ => {}
    }
    let state = state()?;
    // 没有任何真实来源（daemon 那份没读到、本机序列号也读不到）时，这台机器没有可报的
    // 身份。不许编一个（编出来的号在业务侧一眼假），这一笔干脆不答，让上层去透传。
    if cpu_id().is_empty() {
        log::warn!("event=soter local has no real cpu_id; not answering this call locally");
        return None;
    }
    match call.code {
        // exportAskPublicKey(uid) —— 这个 uid 的 ASK 自描述，由 ATTK 签（ATTK 是 ASK 的根）
        1 => {
            let uid = call.uid?;
            let counter = bump_counter(state, uid);
            let ask = ask_for(state, uid)?;
            let document = ask_json(&ask.pem, uid, counter).ok()?;
            let signature = current_attk()?.sign(&document)?;
            Some(Answer::Buffer {
                code: OK,
                data: Some(envelope(&document, &signature)),
            })
        }
        // exportAuthKeyPublicKey(uid, alias) —— 回的是 AuthKey 的自描述信封，
        // 拿 ASK 私钥签（App 先有 ASK 公钥，验的就是这把）。
        3 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            match auth_key(state, uid, alias) {
                Some(key) => {
                    let counter = bump_counter(state, uid);
                    let document = auth_json(&key, uid, counter);
                    // 这层必须用 **该 uid 的 ASK** 签：App 手里只有这个 uid 的 ASK 公钥。
                    // （ASK 自己那一层才是 ATTK 签的，两者别搞混。）
                    let signature = ask_for(state, uid)?.sign(&document)?;
                    Some(Answer::Buffer {
                        code: OK,
                        data: Some(envelope(&document, &signature)),
                    })
                }
                None => Some(Answer::Buffer {
                    code: AUTH_KEY_NOT_READY,
                    data: None,
                }),
            }
        }
        // finishSign(session) —— 签的是那段 JSON 原文（不是 challenge 的字节），
        // 拿 AuthKey 签，回「JSON + 签名」的信封。
        4 => {
            let session = call.session?;
            let pending = state.sessions.lock().ok()?.remove(&session);
            let found = pending.and_then(|s| auth_key(state, s.uid, &s.alias).map(|k| (s, k)));
            match found {
                Some((s, key)) => {
                    let counter = bump_counter(state, s.uid);
                    let document = sign_json(s.uid, &s.raw, counter);
                    let signature = key.sign(&document)?;
                    Some(Answer::Buffer {
                        code: OK,
                        data: Some(envelope(&document, &signature)),
                    })
                }
                // 本地没这个会话：说明 initSign 是托管端落的号，这边的会话表里压根没有。
                // 回 -1000 会让「远端建会话、本地收尾」那条路永远签不成（检测器的
                // T12 就是这么挂的），得退回去让上层转给托管端。
                None => None,
            }
        }
        // generateAskKeyPair(uid) —— 真机上这是给这个 uid 建 ASK，这里按需生成并落盘。
        // **不要重置 counter**：重置就回退了，App 会当重放把钥匙删掉。
        5 => {
            let uid = call.uid?;
            // 先把该 uid 的 ASK 备好（必要时现生成），下一次 9 号才能答「有」。
            ask_for(state, uid)?;
            if let Ok(mut set) = state.ask_built.lock() {
                set.insert(uid);
            }
            Some(Answer::Code(OK))
        }
        // generateAuthKeyPair(uid, alias)
        7 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            let key = Key::generate()?;
            // 落盘：真机的 AuthKey 重启还在，我们也不能只吊在内存里。
            if let Ok(private_pem) = key.private.to_pkcs8_pem(LineEnding::LF) {
                store_pem(AUTH_SECTION, &auth_id(uid, alias), &private_pem);
            }
            state.auth.lock().ok()?.insert(auth_id(uid, alias), key);
            Some(Answer::Code(OK))
        }
        // getDeviceId()
        8 => Some(Answer::Buffer {
            code: OK,
            // 回 16 字节 raw：真机 TA 出的是二进制，检测器转 hex 后再跟 cpu_id 比。
            // 把 hex 文本当字节发出去，检测器看到的是 "30393030…"，对不上。
            data: Some(hex_bytes(&device_id()).unwrap_or_default()),
        }),
        // hasAskAlready(uid) —— 兜底层**必须**答「没有」。
        //
        // 我们这把 ASK 是本地自签的，腾讯那边永远不认；而应用只在「没有 ASK」时才把它
        // 上报腾讯。以前这里答 OK（= 有），应用于是跳过上报、拿着假 ASK 去建 AuthKey，
        // 被腾讯拒了再自删重试 —— 一次本地兜底就把这个槽位毒化了（2026-10-11 实测；
        // 服务端 `soter_mint` 那两层同一个毛病，已一并改掉）。
        // 答 NOT_FOUND 之后应用会老实重新生成并上报；真机那条路一回来就能走通。
        9 => {
            // 本地这把 ASK 一直在（内置或自定义），但「这个 uid 上报过没有」得按 5 号
            // 的真实建料记录答，否则 App 永远在「建完→问→没有」之间循环。
            let uid = call.uid?;
            let built = state
                .ask_built
                .lock()
                .map(|set| set.contains(&uid))
                .unwrap_or(false);
            Some(Answer::Code(if built { OK } else { NOT_FOUND }))
        }
        // hasAuthKey(uid, alias)
        10 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            let present = auth_key(state, uid, alias).is_some();
            Some(Answer::Code(if present { OK } else { AUTH_KEY_NOT_READY }))
        }
        // initSign(uid, alias, challenge)
        11 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            if auth_key(state, uid, alias).is_none() {
                return Some(Answer::Init {
                    status: AUTH_KEY_NOT_READY,
                    session: 0,
                });
            }
            // 挑战原文照存：真机把它写进签名 JSON 的 `raw` 里，我们照做。
            let raw = call.challenge.as_deref()?.to_string();
            let mut next = state.next_session.lock().ok()?;
            *next += 1;
            let session = *next;
            state.sessions.lock().ok()?.insert(
                session,
                SignSession {
                    uid,
                    alias: alias.to_string(),
                    raw,
                },
            );
            Some(Answer::Init {
                status: OK,
                session,
            })
        }
        // removeAllUidKey(uid) —— 连同该 uid 的 ASK 一起删（ASK 是 per-uid 的），
        // 下次 9 号就答「没有」，App 重建料并重新上报。
        12 => {
            let uid = call.uid?;
            let prefix = format!("{uid}|");
            if let Ok(mut map) = state.auth.lock() {
                map.retain(|k, _| !k.starts_with(&prefix));
            }
            if let Ok(mut map) = state.asks.lock() {
                map.remove(&uid);
            }
            if let Ok(mut map) = ASK_ORIGINS.lock() {
                map.remove(&uid);
            }
            forget_uid_keys(uid);
            if let Ok(mut set) = state.ask_built.lock() {
                set.remove(&uid);
            }
            Some(Answer::Code(OK))
        }
        // removeAuthKey(uid, alias)
        13 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            if let Ok(mut map) = state.auth.lock() {
                map.remove(&auth_id(uid, alias));
            }
            forget_pem(AUTH_SECTION, &auth_id(uid, alias));
            Some(Answer::Code(OK))
        }
        _ => None,
    }
}

/// 产线 provisioning（`exportAttkPublicKey`）要的那份“ATTK 公钥”。软件 TA 里 ASK 兼
/// ATTK，所以这里交出去的就是 ASK 的自描述信封（跟 1 号 `exportAskPublicKey` 同一份东西）。
pub(crate) fn ask_public_document(uid: i32) -> Vec<u8> {
    let Some(state) = state() else {
        return Vec::new();
    };
    let counter = bump_counter(state, uid);
    let Some(attk) = current_attk() else {
        return Vec::new();
    };
    let Ok(document) = ask_json(&attk.pem, uid, counter) else {
        return Vec::new();
    };
    let Some(signature) = attk.sign(&document) else {
        return Vec::new();
    };
    envelope(&document, &signature)
}

fn auth_id(uid: i32, alias: &str) -> String {
    format!("{uid}|{alias}")
}

/// 取某个 uid 的 AuthKey。内存里没有（payload 重新注入过）就从 store 读回来，
/// 读到了缓进内存，下次不用再碰磁盘。
fn auth_key(state: &State, uid: i32, alias: &str) -> Option<Key> {
    let id = auth_id(uid, alias);
    if let Some(key) = state.auth.lock().ok()?.get(&id).cloned() {
        return Some(key);
    }

    let pem = read_store_pem(AUTH_SECTION, &id)?;
    let key = Key::from_pem(&pem)?;
    if let Ok(mut map) = state.auth.lock() {
        map.insert(id, key.clone());
    }
    Some(key)
}

fn bump_counter(state: &State, uid: i32) -> u64 {
    // counter 必须单调递增，而且**重启不能回退**：App 会记着上次看到的值，
    // 小回去就当成重放，把本地钥匙删了重来。所以落到文件里。
    let path = format!("/data/misc/ommega/soter_counter.{uid}");
    let disk = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let mem = state
        .counters
        .lock()
        .ok()
        .and_then(|map| map.get(&uid).copied())
        .unwrap_or(0);
    let next = disk.max(mem).max(COUNTER_BASE).max(now_secs()) + 1;
    if let Ok(mut map) = state.counters.lock() {
        map.insert(uid, next);
    }
    let _ = std::fs::write(&path, format!("{next}\n"));
    next
}

/// 包 SOTER 的信封：`[i32 le JSON 长度][JSON][签名]`。三处回信封的地方都走它，
/// 字节序跟真机一致（小端）。
fn envelope(document: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + document.len() + signature.len());
    out.extend_from_slice(&(document.len() as i32).to_le_bytes());
    out.extend_from_slice(document);
    out.extend_from_slice(signature);
    out
}

/// AuthKey 那份 JSON，`pub_key` 是 AuthKey 自己的公钥 —— **拿 ASK 私钥签**。
fn auth_json(key: &Key, uid: i32, counter: u64) -> Vec<u8> {
    format!(
        "{{\"pub_key\":{},\"cpu_id\":\"{}\",\"counter\":{},\"uid\":\"{}\",\"rsa_pss_saltlen\":{}}}",
        json_string(&key.pem),
        cpu_id(),
        counter,
        uid,
        SALT_LEN
    )
    .into_bytes()
}

/// 签名现场那份 JSON。字段名和键序照 B 端 TEE 现场抓的来（`raw` 在最前），一个
/// 都不能少 —— App 会把它们存下来当设备指纹。
fn sign_json(uid: i32, raw: &str, counter: u64) -> Vec<u8> {
    let info = device_info();
    format!(
        "{{\"raw\":{},\"fid\":{},\"counter\":{},\"tee_n\":{},\"tee_v\":{},\"fp_n\":{},\"fp_v\":{},\"cpu_id\":{},\"uid\":{},\"rsa_pss_saltlen\":{}}}",
        json_string(raw),
        json_string(&info.fid),
        counter,
        json_string(&info.tee_n),
        json_string(&info.tee_v),
        json_string(&info.fp_n),
        json_string(&info.fp_v),
        json_string(&cpu_id()),
        json_string(&uid.to_string()),
        SALT_LEN
    )
    .into_bytes()
}

/// ASK 那份 JSON。键序照现场抓到的来，`uid` 是字符串别写成数字。
/// `pub_pem` 是 **ASK 自己的公钥**（可能是独立的一把，也可能是 ATTK）。
fn ask_json(pub_pem: &str, uid: i32, counter: u64) -> Result<Vec<u8>, ()> {
    let document = format!(
        "{{\"pub_key\":{},\"cpu_id\":\"{}\",\"counter\":{},\"uid\":\"{}\",\"rsa_pss_saltlen\":{}}}",
        json_string(pub_pem),
        cpu_id(),
        counter,
        uid,
        SALT_LEN
    );
    Ok(document.into_bytes())
}

/// 把一段文本包成 JSON 字符串字面量（转义引号、反斜杠和换行）。
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(code: u32, uid: Option<i32>, alias: Option<&str>) -> soter::SoterCall {
        soter::SoterCall {
            hal: true,
            hidl: false,
            // 这里只比回答内容的型号，回包形状用不上，取高通那套。
            has_return_code: true,
            code,
            wire_code: code,
            op: "test",
            uid,
            alias: alias.map(str::to_string),
            challenge: None,
            session: None,
            key: None,
            caller_uid: None,
            data_size: 0,
        }
    }

    fn as_buffer(answer: Option<Answer>) -> Vec<u8> {
        match answer {
            Some(Answer::Buffer {
                data: Some(data), ..
            }) => data,
            _ => panic!("expected a buffer answer"),
        }
    }

    #[allow(dead_code)]
    fn as_buffer_code(answer: Option<Answer>) -> i32 {
        match answer {
            Some(Answer::Buffer { code, .. }) => code,
            _ => panic!("expected a buffer answer"),
        }
    }

    fn as_code(answer: Option<Answer>) -> i32 {
        match answer {
            Some(Answer::Code(code)) => code,
            _ => panic!("expected a code answer"),
        }
    }

    #[test]
    fn the_embedded_key_loads_and_parses() {
        assert!(state().is_some(), "the compiled-in ASK key must load");
    }

    #[test]
    fn device_id_looks_like_a_real_one() {
        let id = device_id();
        assert_eq!(id.len(), 32, "SOTER device ids are 32 hex chars");
        assert!(id.starts_with("09000000"));
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id, device_id(), "the device id must be stable");
    }

    #[test]
    fn ask_payload_splits_and_verifies_with_the_embedded_key() {
        let data = as_buffer(answer(&call(1, Some(10373), None)));
        assert!(
            data.len() > 4 + 256,
            "ASK payload holds json plus a signature"
        );
        let len = i32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let document = &data[4..4 + len];
        let signature = &data[4 + len..];
        assert_eq!(signature.len(), 256, "RSA-2048 signature is 256 bytes");

        // 键序和字段名是现场抓的，别改
        let text = String::from_utf8(document.to_vec()).unwrap();
        assert!(text.starts_with("{\"pub_key\":"), "got {text}");
        for field in [
            "\"cpu_id\":",
            "\"counter\":",
            "\"uid\":\"10373\"",
            "\"rsa_pss_saltlen\":32",
        ] {
            assert!(text.contains(field), "ASK json is missing {field}: {text}");
        }

        // 文档是 ASK 的自描述，签名那把是 ATTK（ATTK 签 ASK 的认证）
        use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
        use rsa::signature::Verifier;
        let verifying = PssVerifyingKey::<PssSha256>::new(rsa::RsaPublicKey::from(
            &current_attk().unwrap().private,
        ));
        verifying
            .verify(
                document,
                &PssSignature::try_from(signature).expect("signature parses"),
            )
            .expect("the ASK document must verify");
    }

    #[test]
    fn the_app_facing_side_is_left_to_the_host() {
        let mut c = call(1, Some(10373), None);
        c.hal = false;
        assert!(answer(&c).is_none(), "only the HAL side is ours to answer");
    }

    /// 2 号（exportAttkPublicKey）现在由我们自己答（产线 provisioning 三兄弟之一），
    /// 不再透传；只有真没实现的号才交给真 HAL。
    #[test]
    fn unimplemented_codes_fall_through_to_the_real_hal() {
        assert!(
            answer(&call(2, Some(1), None)).is_some(),
            "exportAttkPublicKey 是我们自己答的"
        );
        assert!(
            answer(&call(99, Some(1), None)).is_none(),
            "99 号没人实现，得透传"
        );
    }

    #[test]
    fn missing_arguments_do_not_pretend_to_be_an_answer() {
        assert!(
            answer(&call(1, None, None)).is_none(),
            "exportAsk needs a uid"
        );
        assert!(
            answer(&call(3, Some(1), None)).is_none(),
            "exportAuth needs an alias"
        );
        assert!(
            answer(&call(4, None, None)).is_none(),
            "finishSign needs a session"
        );
    }

    #[test]
    fn device_id_answers_16_raw_bytes() {
        // 真机 TA 的 getDeviceId 出二进制（16 字节），检测器转 hex 后再跟 cpu_id 比。
        let data = as_buffer(answer(&call(8, None, None)));
        assert_eq!(data, hex_bytes(&device_id()).unwrap());
        assert_eq!(data.len(), 16);
    }

    #[test]
    fn auth_keys_are_created_found_and_removed() {
        let uid = 4242;
        assert_eq!(
            as_code(answer(&call(10, Some(uid), Some("SoterAuthKey")))),
            AUTH_KEY_NOT_READY
        );

        assert_eq!(
            as_code(answer(&call(7, Some(uid), Some("SoterAuthKey")))),
            OK
        );
        assert_eq!(
            as_code(answer(&call(10, Some(uid), Some("SoterAuthKey")))),
            OK
        );

        // 导出 AuthKey 公钥：回的是信封，里面那把公钥的自描述得拿 ASK 公钥验得过
        let auth_envelope = as_buffer(answer(&call(3, Some(uid), Some("SoterAuthKey"))));
        let (auth_document, _) = split_envelope(&auth_envelope);
        let text = String::from_utf8(auth_document).unwrap();
        assert!(text.contains("BEGIN PUBLIC KEY"), "got {text}");

        assert_eq!(
            as_code(answer(&call(13, Some(uid), Some("SoterAuthKey")))),
            OK
        );
        assert_eq!(
            as_code(answer(&call(10, Some(uid), Some("SoterAuthKey")))),
            AUTH_KEY_NOT_READY
        );
    }

    #[test]
    fn remove_all_uid_key_only_takes_that_uid() {
        let (a, b) = (5100, 5200);
        assert_eq!(as_code(answer(&call(7, Some(a), Some("k")))), OK);
        assert_eq!(as_code(answer(&call(7, Some(b), Some("k")))), OK);

        assert_eq!(as_code(answer(&call(12, Some(a), None))), OK);
        assert_eq!(
            as_code(answer(&call(10, Some(a), Some("k")))),
            AUTH_KEY_NOT_READY
        );
        assert_eq!(as_code(answer(&call(10, Some(b), Some("k")))), OK);
    }

    #[test]
    fn sign_round_trip_verifies_with_the_auth_key() {
        let uid = 6001;
        let alias = "SignMe";
        assert_eq!(as_code(answer(&call(7, Some(uid), Some(alias)))), OK);

        let mut init = call(11, Some(uid), Some(alias));
        init.challenge = Some("deadbeef".to_string());
        let session = match answer(&init) {
            Some(Answer::Init { status, session }) => {
                assert_eq!(status, OK);
                session
            }
            _ => panic!("initSign must answer with a session"),
        };

        let mut finish = call(4, None, None);
        finish.session = Some(session);
        let envelope = as_buffer(answer(&finish));
        let (document, signature) = split_envelope(&envelope);
        assert_eq!(signature.len(), 256, "RSA-2048 signature is 256 bytes");

        // 签的是 JSON 原文，`raw` 就是宿主传下来的挑战原文
        let text = String::from_utf8(document.clone()).unwrap();
        assert!(text.contains("\"raw\":\"deadbeef\""), "got {text}");

        // 拿导出的那把 AuthKey 公钥验这段 JSON —— 验得过才叫闭环
        let auth_envelope = as_buffer(answer(&call(3, Some(uid), Some(alias))));
        let (auth_document, _) = split_envelope(&auth_envelope);
        let auth_pem = pem_of(&String::from_utf8(auth_document).unwrap());
        assert!(
            verifies(&auth_pem, &document, &signature),
            "the sign document must verify with the exported AuthKey"
        );
        // 反过来，拿 ASK 的公钥是验不过的（签名那把确实是 AuthKey）
        assert!(
            !verifies(&ask_pem(uid), &document, &signature),
            "the sign document must not verify with the ASK key"
        );
    }

    #[test]
    fn init_sign_without_a_key_reports_not_found() {
        let mut c = call(11, Some(7777), Some("NoSuchKey"));
        c.challenge = Some("00".to_string());
        assert!(
            matches!(answer(&c), Some(Answer::Init { status, .. }) if status == AUTH_KEY_NOT_READY),
            "a missing auth key must come back as a -6 status"
        );
    }

    #[test]
    fn finish_sign_with_an_unknown_session_falls_through() {
        // 不认识的会话号不能本地硬回 -1000：那可能正是托管端落的号，
        // 得放行出去让它接着答。
        let mut c = call(4, None, None);
        c.session = Some(1);
        assert!(answer(&c).is_none());
    }

    /// 拆信封：`[i32 le JSON 长度][JSON][签名]`。
    fn split_envelope(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let len = i32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        (data[4..4 + len].to_vec(), data[4 + len..].to_vec())
    }

    /// 从一份 JSON 里抠出 `pub_key` 的 PEM（够用就行，不引 JSON 库）。
    fn pem_of(document: &str) -> String {
        const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
        const END: &str = "-----END PUBLIC KEY-----";
        let start = document.find(BEGIN).expect("the document carries a pem");
        let end = document.find(END).expect("the pem has a tail") + END.len();
        document[start..end].replace("\\n", "\n")
    }

    /// 拿一把 PEM 公钥验一段签名（RSA-PSS-SHA256）。
    fn verifies(pem: &str, message: &[u8], signature: &[u8]) -> bool {
        use rsa::pkcs8::DecodePublicKey;
        use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
        use rsa::signature::Verifier;
        let Ok(public) = rsa::RsaPublicKey::from_public_key_pem(pem) else {
            return false;
        };
        let Ok(signature) = PssSignature::try_from(signature) else {
            return false;
        };
        PssVerifyingKey::<PssSha256>::new(public)
            .verify(message, &signature)
            .is_ok()
    }

    /// 某个 uid 的 ASK 公钥 PEM。
    fn ask_pem(uid: i32) -> String {
        ask_for(state().unwrap(), uid)
            .expect("the uid has an ASK")
            .pem
            .clone()
    }

    #[test]
    fn the_auth_key_document_is_signed_by_the_ask() {
        let uid = 6100;
        let alias = "SoterAuthKeyPay";
        assert_eq!(as_code(answer(&call(7, Some(uid), Some(alias)))), OK);

        let envelope = as_buffer(answer(&call(3, Some(uid), Some(alias))));
        let (document, signature) = split_envelope(&envelope);
        let text = String::from_utf8(document.clone()).unwrap();

        // 字段名和键序照真机抓的来
        let order: Vec<usize> = ["pub_key", "cpu_id", "counter", "uid", "rsa_pss_saltlen"]
            .iter()
            .map(|k| text.find(&format!("\"{k}\"")).expect("key present"))
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "key order changed: {text}"
        );

        // App 是拿 ASK 公钥验这个信封的 —— 这一步验得过，AuthKey 这条链才算自洽
        assert!(
            verifies(&ask_pem(uid), &document, &signature),
            "the AuthKey document must verify with the ASK key"
        );
    }

    #[test]
    fn the_sign_document_carries_the_device_fields() {
        let uid = 6200;
        let alias = "SignFields";
        assert_eq!(as_code(answer(&call(7, Some(uid), Some(alias)))), OK);

        let mut init = call(11, Some(uid), Some(alias));
        init.challenge = Some("0a1b2c3d".to_string());
        let session = match answer(&init) {
            Some(Answer::Init { session, .. }) => session,
            _ => panic!("initSign must answer with a session"),
        };
        let mut finish = call(4, None, None);
        finish.session = Some(session);
        let (document, _) = split_envelope(&as_buffer(answer(&finish)));
        let text = String::from_utf8(document).unwrap();

        // 字段和键序照 B 端 TEE 现场抓的来，一个都不能少
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
        assert!(text.contains("\"uid\":\"6200\""), "uid is a string: {text}");
        assert!(text.contains("\"rsa_pss_saltlen\":32"), "salt len: {text}");
    }

    #[test]
    fn the_device_info_is_derived_from_this_machine() {
        let info = device_info();
        let derived = info
            .derived_cpu_id
            .as_deref()
            .expect("真机/真设备上序列号读得到；读不到这儿就该是 None");
        assert_eq!(derived.len(), 32, "SOTER device ids are 32 hex chars");
        assert!(derived.starts_with("09000000"));
        assert!(derived.chars().all(|c| c.is_ascii_hexdigit()));
        // `device_id()` 报的是「当前该报的那个」（文件里有就用文件里的，没有才用它）。
        assert_eq!(device_id(), cpu_id(), "device_id() 就是那个 cpu_id");
        assert_eq!(device_id(), device_id(), "同一个进程里报的号要稳");

        assert!(!info.fp_n.is_empty());
        assert!(!info.fp_v.is_empty());
        assert!(!info.tee_n.is_empty());
        assert!(!info.tee_v.is_empty());
        assert!(info.fid.len() >= 10, "fid 像真机那样是十位数字");
        assert!(info.fid.chars().all(|c| c.is_ascii_digit()));
    }

    /// daemon 学来的真机号一旦落到文件里，本地这一套就得报它，不能自己再派生一个。
    #[test]
    fn a_learned_cpu_id_wins_over_the_derived_one() {
        let learned = "090000005171734c42866bea148b21f5";
        let path = temp_pem("soter_cpu_id", &format!("soter_cpu_id: {learned}\n"));
        let (value, origin) = load_cpu_id_from(&[path.to_str().unwrap()], None);
        assert_eq!(value.as_deref(), Some(learned));
        assert!(origin.starts_with("file "), "origin = {origin}");
        assert_ne!(
            Some(learned),
            device_info().derived_cpu_id.as_deref(),
            "两份号必须不是一个"
        );

        // 环境变量优先于文件。
        let other = "09000000aabbccddeeff001122334455";
        let (value, origin) = load_cpu_id_from(&[path.to_str().unwrap()], Some(other.to_string()));
        assert_eq!(value.as_deref(), Some(other));
        assert_eq!(origin, "env");
    }

    /// 文件缺了、内容废了、环境变量写错了，一律当作没学到，回落本机派生值 ——
    /// 绝不拿半截东西去当设备身份。
    #[test]
    fn a_broken_cpu_id_source_falls_back_to_nothing() {
        let broken = temp_pem("soter_cpu_id_broken", "soter_cpu_id: 09000000\n");
        let missing = std::env::temp_dir().join("ommega-soter-cpu-id-does-not-exist");
        let _ = std::fs::remove_file(&missing);
        for paths in [
            vec![missing.to_str().unwrap()],
            vec![broken.to_str().unwrap()],
            vec![missing.to_str().unwrap(), broken.to_str().unwrap()],
        ] {
            let (value, origin) = load_cpu_id_from(&paths, None);
            assert_eq!(value, None, "{paths:?} 里没有合形状的值");
            assert_eq!(origin, "derived");
        }
        // 坏的环境变量不牵连后面的文件。
        let good = temp_pem(
            "soter_cpu_id_good",
            "soter_cpu_id: 09000000aabbccddeeff001122334455\n",
        );
        let (value, _) =
            load_cpu_id_from(&[good.to_str().unwrap()], Some("not-a-cpu-id".to_string()));
        assert_eq!(value.as_deref(), Some("09000000aabbccddeeff001122334455"));
    }

    #[test]
    fn json_string_escapes_the_pem() {
        let escaped = json_string("a\"b\\c\nd");
        assert_eq!(escaped, "\"a\\\"b\\\\c\\nd\"");
    }

    /// 写一份临时 PEM，返回路径（测试完不删，临时目录自有清理）。
    fn temp_pem(name: &str, contents: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("ommega-soter-ask-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// 一把随机 RSA 的私钥 PEM（PKCS#8）。
    fn fresh_pem() -> String {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    /// 编进 binary 的那把 ATTK（不经 `state()`，免得受 OnceLock 初始化顺序影响）。
    fn embedded_attk() -> Key {
        Key::from_pem(std::str::from_utf8(ATTK_PEM).unwrap()).unwrap()
    }

    #[test]
    fn a_supplied_attk_file_wins_over_the_embedded_one() {
        let pem = fresh_pem();
        let path = temp_pem("soter_attk.pem", &pem);
        let (key, origin) = load_attk_key_with(Some(path.clone())).expect("the file must be used");

        // 用的确实是文件里那把，不是编进来的那把
        assert_eq!(key.pem, Key::from_pem(&pem).unwrap().pem);
        assert_ne!(key.pem, embedded_attk().pem, "换 key 得真换掉");
        assert_eq!(origin, path.display().to_string());
    }

    #[test]
    fn a_missing_attk_file_falls_back_to_the_embedded_one() {
        let missing = std::env::temp_dir().join("ommega-soter-ask-does-not-exist.pem");
        let _ = std::fs::remove_file(&missing);
        let (key, origin) = load_attk_key_with(Some(missing)).expect("embedded key must load");
        assert_eq!(key.pem, embedded_attk().pem);
        assert_eq!(origin, "embedded attk");
    }

    #[test]
    fn a_broken_attk_file_falls_back_to_the_embedded_one() {
        let path = temp_pem("broken.pem", "-----BEGIN PRIVATE KEY-----\nnope\n");
        let (key, origin) = load_attk_key_with(Some(path)).expect("embedded key must load");
        assert_eq!(key.pem, embedded_attk().pem);
        assert_eq!(origin, "embedded attk");
    }

    #[test]
    fn the_loaded_ask_reports_where_it_came_from() {
        // 这个进程里 `state()` 建过之后，来源一定是非空的（换 key 之后靠它看生效）
        assert!(state().is_some());
        let origin = ask_origin().expect("state() 初始化时写下了来源");
        assert!(!origin.is_empty());
    }
}
