//! A 端本地的 SOTER 后端（自签兜底）。
//!
//! 用编译进来的 ATTK 签 ASK 的认证信封；ASK 按 uid 现生成、落盘复用。三种返回同一个形状
//!（与服务端 `soter_mint.rs` 一致）：
//!
//! ```text
//! [i32 le JSON 长度][JSON][256 字节 RSA-PSS-SHA256 签名]
//! ```
//!
//! - `exportAskPublicKey`：ASK 自描述，用 ATTK 私钥签；
//! - `exportAuthKeyPublicKey`：AuthKey 自描述，用 ASK 私钥签（App 拿 ASK 公钥验它）；
//! - `finishSign`：签名现场 JSON，用 AuthKey 签**原文**，不是 challenge 的字节。
//!
//! 键序和字段名照真机现场，`uid` 是字符串。设备信息（`cpu_id` / `fid` / `tee_*` / `fp_*`）
//! 按本机属性推：`cpu_id` 只认本地这份身份（ATTK force 号，否则按序列号派生），不用转发
//! 链路学来的 B 端号。
//!
//! 边界：自签链只在本机自洽，过不了业务服务端的证书校验；私钥就编在 binary 里 —— 这是
//! 兜底，不是安全方案。错误码跟真机宿主一致（-5 = 钥匙不在这台设备上）。

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use rsa::pkcs1::DecodeRsaPrivateKey;
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
/// ASK 里写死的盐长。腾讯按 JSON 里的 `rsa_pss_saltlen` 验签。
///
/// 32 是实测值：PLC110（MTK Kinibi，Android 16）真机 TA 的 ASK / AuthKey / 签名现场
/// 三份文档都写 `"rsa_pss_saltlen":32`，签名也真的是 32。本地兜底跟它对齐（声明和
/// 签名一把钥匙，客户端按声明验总能过）。
const SALT_LEN: i32 = 32;
/// 编译进来的 ATTK（构建时按当时时间现生成的一把自签 RSA）。
/// ASK 不内置：每个 uid 的 ASK 都是用到时现生成、落盘复用。
const ATTK_PEM: &[u8] = include_bytes!("../../assets/soter_attk.pem");
/// 换本地兜底 ATTK 用的文件（PKCS#8 或 PKCS#1 PEM，`openssl genpkey` / `openssl genrsa` 的都行）。
/// 存在且解析得过就用它，跟 keybox 一个路子：丢文件进去、重启 SOTER 宿主就生效。
///
/// 唯一位置是 `/data/misc/ommega/`：它的 context 是 `system_data_file`，
/// app 域（SOTER 宿主是 uid 1000）和 keystore 域都读得到，不需要在两个目录各存一份。
const ATTK_FILE_PATH: &str = "/data/misc/ommega/soter_attk.pem";
/// 环境变量覆盖 ATTK，写测试和临时探针用。
const ATTK_FILE_ENV: &str = "OMMEGA_SOTER_ATTK_PEM";

/// counter 起点：换 ATTK 时它会被清掉（连同 ASK/authkey/App 开通状态），
/// 之后每个 App 第一次请求现造 ASK，counter 从 1 开始严格 +1。
/// ATTK 换了就是新身份（新 cpu_id），腾讯那边也是新记录，从 1 合理。
const COUNTER_BASE: u64 = 1;

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
        // PKCS#8 和 PKCS#1 都认：`openssl genpkey` 给前者，`openssl genrsa` 给后者。
        let private = RsaPrivateKey::from_pkcs8_pem(block.trim())
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(block.trim()))
            .ok()?;
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

    /// RSA-PSS-SHA256，盐长 = `SALT_LEN`（跟真机 TA 对齐的 20），JSON 里那个字段也是它。
    fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        let signing =
            PssSigningKey::<PssSha256>::new_with_salt_len(self.private.clone(), SALT_LEN as usize);
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
    PssVerifyingKey::<PssSha256>::new_with_salt_len(public, SALT_LEN as usize)
        .verify(message, &signature)
        .map_err(|error| anyhow::anyhow!("the signature did not verify: {error}"))
}

/// 一次 initSign 挂起来的会话。
#[derive(Clone)]
struct SignSession {
    uid: i32,
    alias: String,
    /// 挑战原文，宿主传下来什么样就存什么样。真机把它写进签名 JSON 的 `raw` 里，
    /// 我们照做，不去解它（解了反而签的不是 App 要的东西）。
    raw: String,
    /// 开这笔会话的时刻。真机的会话会过期（服务端按 60 秒算），我们也得会过期，
    /// 否则一个早就丢掉的 init 能在表里躺到重启。
    created: Instant,
    /// 开这笔会话的调用方（内核填的 `sender_euid`）。本地兜底有时拿不到，那就只靠 TTL。
    caller: Option<i32>,
}

impl SignSession {
    /// 这次调用还能不能花掉这个会话：在 TTL 内，且调用方就是开它的那个。
    /// 两边都拿得到 caller 才比 —— 拿不到就不拿它当拒绝理由。
    fn is_usable(&self, caller: Option<i32>) -> bool {
        if self.created.elapsed() > SESSION_TTL {
            return false;
        }
        match (self.caller, caller) {
            (Some(owner), Some(actual)) => owner == actual,
            _ => true,
        }
    }
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
    candidates.extend([std::path::PathBuf::from(ATTK_FILE_PATH)]);

    for path in candidates {
        let Ok(pem) = std::fs::read_to_string(&path) else {
            continue;
        };
        match Key::from_pem(&pem) {
            Some(key) => return Some((key, path.display().to_string())),
            // 文件在那儿但读不出私钥：别当没事，也别拿它顶，继续往下找。
            None => log::warn!(
                "soter local attk at {} is not a usable RSA PEM; ignoring it",
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

/// 旧版按 uid 散落的 ASK 文件（读到就迁进 store，然后把旧文件删掉）。
fn legacy_ask_file_paths(uid: i32) -> [String; 1] {
    [format!("/data/misc/ommega/soter_ask_{uid}.pem")]
}

/// 所有 uid 的 ASK 和 AuthKey 存在这一个文件里，不要按 uid/alias 散成一堆 pem。
/// 结构是两层：
///
/// ```json
/// { "asks": { "10496": "<pem>" }, "authkeys": { "10496|SoterAuthKey": "<pem>" } }
/// ```
///
/// 位置唯一：`/data/misc/ommega/`（`system_data_file`，app 域和 keystore 域都读得到）。
const ASK_STORE_PATH: &str = "/data/misc/ommega/soter_asks.json";

/// store 路径。`OMMEGA_SOTER_ASK_STORE` 是给真机单测的隔离口：测试跟线上模块共用
/// 同一个文件会互相踩（测试刚写的墓碑被活着的载荷用它的内存态盖掉，测试断言就随
/// 着模块忙不忙随机挂），跑测试时把它指到 /data/local/tmp 下的临时文件。
fn ask_store_path() -> &'static str {
    static PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        std::env::var_os("OMMEGA_SOTER_ASK_STORE")
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| ASK_STORE_PATH.to_string())
    })
    .as_str()
}
const ASK_SECTION: &str = "asks";
const AUTH_SECTION: &str = "authkeys";
/// store 里记的「这把 ASK/AuthKey 是哪把 ATTK 签的」（ATTK 公钥的 sha256）。
///
/// 真机不用担心这个（ATTK 在 TEE 里换不了），我们能换 ATTK，就必须自己管一致性：
/// 否则换了一把 ATTK 之后，store 里旧 AuthKey 照用 —— 本地签名链自洽、微信本地
/// 验得过，但那一笔根本没再问过腾讯，表现为「不重启就能用、重启就不行」。
const ATTK_FIELD: &str = "attk";

/// 当前 ATTK 公钥的指纹（sha256 hex）。
fn attk_fingerprint() -> Option<String> {
    use rsa::sha2::{Digest, Sha256};
    let attk = current_attk()?;
    let mut hasher = Sha256::new();
    hasher.update(attk.pem.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

/// 落盘那一瞬间的互斥：读改写不是原子操作，两个 uid 同时进来会互相盖掉。
static ASK_STORE_LOCK: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

fn read_ask_store() -> serde_json::Map<String, serde_json::Value> {
    let path = ask_store_path();
    let Ok(text) = std::fs::read_to_string(path) else {
        return serde_json::Map::new();
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
            map.retain(|key, _| {
                key == ASK_SECTION
                    || key == AUTH_SECTION
                    || key == GONE_SECTION
                    || key == ATTK_FIELD
            });
            // 指纹对不上（换了 ATTK）或者是没记指纹的旧 store：整份作废，让调用方
            // 重新生成。留着只会拿旧 ATTK 签的链去跑，本地能过、腾讯不认。
            let want = attk_fingerprint();
            let got = map.get(ATTK_FIELD).and_then(|v| v.as_str());
            if !matches!((want.as_deref(), got), (Some(w), Some(g)) if w == g) {
                log::info!(
                    "soter local ask store was not minted by the current ATTK; discarding it"
                );
                return serde_json::Map::new();
            }
            map
        }
        _ => {
            log::warn!("soter local ask store at {path} is not a json object; ignoring it");
            serde_json::Map::new()
        }
    }
}

fn write_ask_store(map: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let mut out = map.clone();
    if let Some(fingerprint) = attk_fingerprint() {
        out.insert(
            ATTK_FIELD.to_string(),
            serde_json::Value::String(fingerprint),
        );
    }
    let text = serde_json::to_string_pretty(&out).ok()?;
    let path = ask_store_path();
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // 写临时文件再 rename：中途掉电也不会留个半个 json。
    // 落盘统一 0666：这份 store 是几个域一起写的（keystore 域的 payload、hal_soter、
    // system_app 宿主）。谁把 tmp 用默认 0644 rename 上去，另外几家就写不动了。
    let tmp = format!("{path}.tmp");
    if std::fs::write(&tmp, text.as_bytes()).is_ok() {
        let _ = std::fs::set_permissions(
            &tmp,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o666),
        );
        if std::fs::rename(&tmp, path).is_ok() {
            return Some(path.to_string());
        }
    }
    let _ = std::fs::remove_file(&tmp);
    // app 域（SOTER 宿主是 platform_app、带 MLS 类别）写不动这个文件：MLS 的写约束
    // 要求主体和客体级别相等。整份文本交给 daemon 代写，它跑在 s0 上，写得进去。
    // 测试用的临时 store（`OMMEGA_SOTER_ASK_STORE`）不走 RPC：那里根本没有 daemon。
    if path == ASK_STORE_PATH {
        match crate::ipc::write_soter_store(&text) {
            Ok(true) => {
                log::info!("event=soter ask store written by the daemon");
                return Some(path.to_string());
            }
            Ok(false) => log::warn!("event=soter daemon refused to write the ask store"),
            Err(error) => {
                log::warn!("event=soter daemon could not write the ask store ({error:#})")
            }
        }
    }
    log::warn!("soter local cannot write the ask store at {path}");
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

/// AUTH 段最多留这么多把 AuthKey（每把约 1.7KB PEM）。超过之后挤掉最早的一批：
/// 被挤掉的那把下次 `has_auth_key` 回 false，App 自己重签。
const MAX_AUTH_KEYS: usize = 1024;
const AUTH_KEYS_KEEP: usize = MAX_AUTH_KEYS * 3 / 4;
/// 未完成的 initSign 会话最多留这么多条，超了整表清。
const MAX_SIGN_SESSIONS: usize = 256;
/// 一个签名会话的生命周期。真机的会话不是永久的，服务端那边按 60 秒算，
/// 本地兜底也跟这个数：过期就当没这个号，让上层去重开。
const SESSION_TTL: Duration = Duration::from_secs(60);
/// 内存里那层 AuthKey 缓存，它只是 store 的缓存，满了清掉就回盘上重读。
const MAX_AUTH_CACHE: usize = MAX_AUTH_KEYS;

fn store_pem(section: &str, key: &str, pem: &str) -> Option<String> {
    let _guard = ASK_STORE_LOCK.lock().ok()?;
    let mut map = read_ask_store();
    let entries = section_of(&mut map, section);
    entries.insert(key.to_string(), serde_json::Value::String(pem.to_string()));
    if section == AUTH_SECTION && entries.len() > MAX_AUTH_KEYS {
        // 没有插入顺序可依（serde_json 的 Map 默认按 key 排序），就随便挤掉一批、
        // 压到 3/4 再慢慢长，避免每写一把都触发一次 prune。
        let mut victims: Vec<String> = entries
            .keys()
            .filter(|k| k.as_str() != key)
            .take(entries.len() - AUTH_KEYS_KEEP)
            .cloned()
            .collect();
        victims.sort();
        for victim in victims {
            entries.remove(&victim);
        }
    }
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

/// 「删过了」的墓碑段（落盘，重启也黏着）。
///
/// 真机删了就是删了：`removeAllUidKey` / `removeAuthKey` 之后，后面的 `export*` 不能
/// 现造一把新的顶上 —— 我们的实现在那之前就是“要就现生成”，于是删完还能导出，
/// 跟真机不一样（检测器就测这个）。键：`ask:<uid>` / `auth:<uid>|<alias>`。
const GONE_SECTION: &str = "gone";

fn mark_gone(key: &str) {
    store_pem(GONE_SECTION, key, "1");
}

fn clear_gone(key: &str) {
    forget_pem(GONE_SECTION, key);
}

/// 这个 key 删过（墓碑在）。
fn is_gone(key: &str) -> bool {
    read_store_pem(GONE_SECTION, key).is_some()
}

fn ask_gone_key(uid: i32) -> String {
    format!("ask:{uid}")
}

fn auth_gone_key(uid: i32, alias: &str) -> String {
    format!("auth:{uid}|{alias}")
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

/// 测试用：把本地兜底的内存态和 store 全部清掉，让“这把钥匙还没建”这类前提
/// 在重复跑时也成立。真机上手动重跑测试时，上一遍留下的 ASK/AuthKey/墓碑会把
/// 断言带偏（典型：期望 -6 拿到 0）。
#[cfg(test)]
pub(crate) fn reset_local_state_for_test() {
    if let Some(state) = state() {
        if let Ok(mut map) = state.asks.lock() {
            map.clear();
        }
        if let Ok(mut map) = state.auth.lock() {
            map.clear();
        }
        if let Ok(mut map) = state.counters.lock() {
            map.clear();
        }
        if let Ok(mut set) = state.ask_built.lock() {
            set.clear();
        }
    }
    if let Ok(mut origins) = ASK_ORIGINS.lock() {
        origins.clear();
    }
    let _ = std::fs::remove_file(ask_store_path());
}

/// ATTK 文件的 mtime。换文件（WebUI 写新的、用户手放）时靠它判断要不要重读。
static ATTK_STAMP: Mutex<Option<std::time::SystemTime>> = Mutex::new(None);

fn attk_stamp() -> Option<std::time::SystemTime> {
    std::fs::metadata(ATTK_FILE_PATH)
        .and_then(|meta| meta.modified())
        .ok()
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
            // ATTK 换了 = 新身份。内存里缓存的 ASK / AuthKey / counter / 「已建过 ASK」
            // 全是拿旧 ATTK 签的，不清的话宿主会继续拿旧链应答（本地验得过、服务端不认，
            // 典型表现就是「不重启就能用、一重启就不行」）。磁盘 store 那边有指纹校验会
            // 自己作废，这里把内存这一半补齐。
            if let Ok(mut map) = state.asks.lock() {
                map.clear();
            }
            if let Ok(mut map) = state.auth.lock() {
                map.clear();
            }
            if let Ok(mut map) = state.counters.lock() {
                map.clear();
            }
            if let Ok(mut set) = state.ask_built.lock() {
                set.clear();
            }
            log::info!(
                "event=soter ATTK hot-reloaded from {origin}; cleared in-memory ask/auth/counter"
            );
            return Some(key);
        }
    }
    Some(cached.clone())
}

/// 只看已有的 ASK（内存或盘上），不现造。
fn ask_existing(state: &State, uid: i32) -> Option<Key> {
    if let Some(key) = state.asks.lock().ok()?.get(&uid).cloned() {
        return Some(key);
    }
    let pem = read_store_pem(ASK_SECTION, &uid.to_string())?;
    let key = Key::from_pem(&pem)?;
    if let Ok(mut map) = state.asks.lock() {
        map.insert(uid, key.clone());
    }
    Some(key)
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
                "soter local ask for uid {uid} in the store is not a usable RSA PEM; ignoring it"
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
                "soter local ask for uid {uid} at {path} is not a usable RSA PEM; ignoring it"
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

/// 本地兜底报的 cpu_id。
///
/// 1. `soter_cpu_id.force`：这份 ATTK 自带的号；
/// 2. 本机序列号派生：本地 ATTK 是现造的，身份就是这台机器。
///
/// 不读 `/data/misc/ommega/soter_cpu_id`（那是转发链路学来的 B 端号）。序列号在部分域
/// 读不到，这时用 [`LOCAL_CPU_ID_PATH`] 那份缓存。
///
/// 一个来源都拿不到就报空串：这层宁可不答，也不编一个号（编出来的一眼假）。
fn cpu_id() -> String {
    let forced = std::fs::read_to_string(CPU_ID_OVERRIDE).ok();
    let derived = device_info().derived_cpu_id.as_deref();
    match local_cpu_id(forced.as_deref(), derived) {
        (value, "forced") => {
            log::info!("event=soter cpu_id forced by {CPU_ID_OVERRIDE}");
            return value;
        }
        (value, "derived") if !value.is_empty() => {
            publish_local_cpu_id(&value);
            return value;
        }
        _ => {}
    }
    read_local_cpu_id().unwrap_or_default()
}

/// 本机派生 cpu_id 的落盘位置。`system_data_file`，宿主那份 payload 读得到。
const LOCAL_CPU_ID_PATH: &str = "/data/misc/ommega/soter_local_cpu_id";

/// 把算出来的派生号落盘给 app 域的 payload 用（best effort，内容没变就不写）。
pub(crate) fn publish_local_cpu_id(value: &str) {
    if value.is_empty() || read_local_cpu_id().as_deref() == Some(value) {
        return;
    }
    let line = format!("soter_cpu_id: {value}\n");
    if std::fs::write(LOCAL_CPU_ID_PATH, line).is_ok() {
        log::info!("event=soter published local cpu_id to {LOCAL_CPU_ID_PATH}");
    }
}

fn read_local_cpu_id() -> Option<String> {
    let text = std::fs::read_to_string(LOCAL_CPU_ID_PATH).ok()?;
    kmr_common::soter_relay::parse_cpu_id(&text)
}

/// `cpu_id()` 里跟文件读写无关的那半（测试要拿假输入跑）。
fn local_cpu_id(forced: Option<&str>, derived: Option<&str>) -> (String, &'static str) {
    if let Some(text) = forced {
        match kmr_common::soter_relay::parse_cpu_id(text) {
            Some(id) => return (id, "forced"),
            None => log::warn!(
                "event=soter {CPU_ID_OVERRIDE} exists but holds no valid cpu_id; falling back to this machine's own id"
            ),
        }
    }
    (derived.unwrap_or_default().to_string(), "derived")
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
/// 走 `getprop` 命令：payload 里 `__system_property_get` 拿不到值。app 域（SOTER 宿主）
/// 连 fork 都会被拒，那种进程只能靠 [`LOCAL_CPU_ID_PATH`] 的缓存，见 [`cpu_id`]。
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
    /// 按本机真实序列号派生的号，`09000000` + 12 字节十六进制。
    /// 本地这条路报的就是它（除非这份 ATTK 自带一个 force 号）；序列号读不到就是 `None`。
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

/// 一台像真机的设备号：平台前缀（高通 `00000000` / MTK `09000000`）+ 12 字节十六进制。
/// 只拿真实序列号算，没有就不算。
fn cpu_id_from(serial: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-a-side-soter:");
    hasher.update(serial.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::from(platform().cpu_prefix);
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

/// 指纹厂商。厂商名归一成原厂那几种拼法（真机上就是 `FPC` / `Goodix` 这种），
/// 认不出来就用平台默认 —— 不要报 `unknown`，那跟报自己名字一个性质：一眼壳。
fn fingerprint_name() -> String {
    if prop("ro.vendor.feature.zte_fingerprint_default_goodix_g7_aidl").is_some()
        || prop("ro.vendor.feature.zte_fingerprint_default_goodix_gf96xx_g7_cali").is_some()
    {
        return "Goodix".to_string();
    }
    let hardware = prop("ro.hardware.fingerprint")
        .unwrap_or_default()
        .to_lowercase();
    for (needle, name) in [
        ("fpc", "FPC"),
        ("goodix", "Goodix"),
        ("silead", "Silead"),
        ("egis", "Egis"),
        ("qbt", "QBT"),
    ] {
        if hardware.contains(needle) {
            return name.to_string();
        }
    }
    platform().fp_n.to_string()
}

/// 指纹固件版本。有真版本号就用真的，没有就用平台默认。
fn fingerprint_version() -> String {
    for name in [
        "persist.vendor.fingerprint.fw_version",
        "vendor.fingerprint.fw_version",
        "ro.vendor.fingerprint.fw_version",
        "persist.goodix.fw_version",
    ] {
        if let Some(value) = prop(name) {
            return value;
        }
    }
    if prop("ro.vendor.feature.zte_fingerprint_default_goodix_gf96xx_g7_cali").is_some() {
        return "GF96xx".to_string();
    }
    platform().fp_v.to_string()
}

/// TEE 名字。真机上就是 TA 报的那个名字（高通 QSEE / MTK Kinibi），所以照平台报原厂那套，
/// 别把 `ro.hardware` 这种半成品拼法或我们自己的名字写进去。
fn tee_name() -> String {
    platform().tee_n.to_string()
}

/// TEE 版本。真版本串只有 TA 有，拿不到就按平台报原厂那个号（高通 `5` / Kinibi `10018`）。
/// 以前拿“SoC 型号 + 安全补丁”拼了个从没见过的格式，检测器一问就露。
fn tee_version() -> String {
    platform().tee_v.to_string()
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
            state.sessions.lock().ok().map(|map| {
                map.get(&session)
                    .is_some_and(|s| s.created.elapsed() <= SESSION_TTL)
            })
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
        None => {
            log::info!(
                "event=soter local answer op={} = none (passthrough)",
                call.code
            );
            // app 域进程里文件日志是哑的，本地这条路答不出来时只能顺 RPC 报给 daemon。
            crate::ipc::report_event(format!(
                "event=soter local answer op={} = none (passthrough)",
                call.code
            ));
        }
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
    let Some(state) = state() else {
        crate::ipc::report_event(format!(
            "event=soter local bail op={} reason=no-attk",
            call.code
        ));
        return None;
    };
    // 没有任何真实来源（daemon 那份没读到、本机序列号也读不到）时，这台机器没有可报的
    // 身份。不许编一个（编出来的号在业务侧一眼假），这一笔干脆不答，让上层去透传。
    if cpu_id().is_empty() {
        log::warn!("event=soter local has no real cpu_id; not answering this call locally");
        crate::ipc::report_event(format!(
            "event=soter local bail op={} reason=empty-cpu-id",
            call.code
        ));
        return None;
    }
    match call.code {
        // exportAskPublicKey(uid) —— 这个 uid 的 ASK 自描述，由 ATTK 签（ATTK 是 ASK 的根）
        1 => {
            let uid = call.uid?;
            // 有料就导出；没料但墓碑在就不现造（真机删了就是删了）。
            // 存在性与导出同源：两边都只看料和墓碑。
            let ask = match ask_existing(state, uid) {
                Some(key) => Some(key),
                None if is_gone(&ask_gone_key(uid)) => None,
                None => ask_for(state, uid),
            };
            let Some(ask) = ask else {
                return Some(Answer::Buffer {
                    code: NOT_FOUND,
                    data: None,
                });
            };
            clear_gone(&ask_gone_key(uid));
            let counter = bump_counter(state, uid);
            let document = ask_json(&ask.pem, uid, counter).ok()?;
            let signature = current_attk()?.sign(&document)?;
            let data = envelope(&document, &signature);
            log::info!(
                "soter local export ASK uid={uid} document={} envelope={}",
                document.len(),
                data.len()
            );
            Some(Answer::Buffer {
                code: OK,
                data: Some(data),
            })
        }
        // exportAuthKeyPublicKey(uid, alias) —— 回的是 AuthKey 的自描述信封，
        // 拿 ASK 私钥签（App 先有 ASK 公钥，验的就是这把）。
        3 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            // 有料就导出，跟 ASK 那条（1 号）一个口径：**存在性与导出必须同源**。
            // 以前先看墓碑，而墓碑得靠写盘才清得掉；store 写不动的时候 `ask:<uid>` 那条
            // 墓碑就永远在，于是 hasAuthKey 答有、导出却恒 -6（检测器卡在 authModel 上）。
            let Some(key) = auth_key(state, uid, alias) else {
                return Some(Answer::Buffer {
                    code: AUTH_KEY_NOT_READY,
                    data: None,
                });
            };
            clear_gone(&auth_gone_key(uid, alias));
            clear_gone(&ask_gone_key(uid));
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
        // finishSign(session) —— 签的是那段 JSON 原文（不是 challenge 的字节），
        // 拿 AuthKey 签，回「JSON + 签名」的信封。
        4 => {
            let session = call.session?;
            // 先取授权 key，确认拿得到再摘会话。反过来做的话，auth_key 这次失败
            // （store 临时读不到 / PEM 坏了）会话就已经从表里没了，宿主拿同一个
            // session 重试也找不到，这一轮签名直接失败且不可重试。
            // 会话过期了就顺手从表里抹掉；调用方对不上的不动它（那可能是别人正在用的号）。
            let peeked = state.sessions.lock().ok()?.get(&session).cloned();
            if peeked
                .as_ref()
                .is_some_and(|s| s.created.elapsed() > SESSION_TTL)
            {
                state.sessions.lock().ok()?.remove(&session);
            }
            let found = peeked
                .filter(|s| s.is_usable(call.caller_uid))
                .and_then(|s| auth_key(state, s.uid, &s.alias).map(|k| (s, k)));
            match found {
                Some((s, key)) => {
                    state.sessions.lock().ok()?.remove(&session);
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
        // generateAskKeyPair(uid) 按平台分两种：
        //   高通：每次重铸、回 0；MTK：已有就回 -5、不重铸。
        // MTK 只在本会话建过/碰过（`ask_built`）后才回 -5：9 号在上报之前一直答“没有”，
        // 5 号也直接 -5 的话应用会「问→没有→建→-5→删→再问」锁死。
        // counter 不能重置 —— 回退会被 App 当重放。
        5 => {
            let uid = call.uid?;
            clear_gone(&ask_gone_key(uid));
            if platform().generate_rotates {
                let (key, origin) = generate_ask_for(uid)?;
                if let Ok(mut map) = state.asks.lock() {
                    map.insert(uid, key);
                }
                if let Ok(mut map) = ASK_ORIGINS.lock() {
                    map.insert(uid, origin);
                }
                if let Ok(mut set) = state.ask_built.lock() {
                    set.insert(uid);
                }
                return Some(Answer::Code(OK));
            }
            let built = state
                .ask_built
                .lock()
                .map(|set| set.contains(&uid))
                .unwrap_or(false);
            if built && ask_exists(state, uid) {
                return Some(Answer::Code(NOT_FOUND));
            }
            ask_for(state, uid)?;
            if let Ok(mut set) = state.ask_built.lock() {
                set.insert(uid);
            }
            Some(Answer::Code(OK))
        }
        // generateAuthKeyPair(uid, alias) —— 高通重铸回 0；MTK 已存在时回 -5。
        7 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            clear_gone(&auth_gone_key(uid, alias));
            if !platform().generate_rotates && auth_key(state, uid, alias).is_some() {
                return Some(Answer::Code(NOT_FOUND));
            }
            let key = Key::generate()?;
            // 落盘：真机的 AuthKey 重启还在，我们也不能只吊在内存里。
            if let Ok(private_pem) = key.private.to_pkcs8_pem(LineEnding::LF) {
                store_pem(AUTH_SECTION, &auth_id(uid, alias), &private_pem);
            }
            state.auth.lock().ok()?.insert(auth_id(uid, alias), key);
            Some(Answer::Code(OK))
        }
        // getDeviceId()
        //
        // 真机回 **32 个 ASCII 十六进制字符 + 结尾 `\0`**（33 字节），不是 16 字节二进制；
        // 形状要跟真机一致。
        8 => Some(Answer::Buffer {
            code: OK,
            data: Some(device_id_reply(&device_id())),
        }),
        // hasAskAlready(uid) 必须答「没有」：本地 ASK 是自签的，腾讯不认；而应用只在
        // 「没有 ASK」时才上报。答「有」会让它跳过上报、拿假 ASK 建 AuthKey → 被拒 → 自删重试。
        9 => {
            // 本地这把 ASK 一直在（内置或自定义），「这个 uid 有没有料」就看内存/盘上
            // 真有没有，不能只看本会话建没建过：只看 `ask_built` 会出现「答没有、但
            // 导出却有料」的反向不一致，检测器那边同样是 keyPrep 失败。
            let uid = call.uid?;
            Some(Answer::Code(if ask_exists(state, uid) {
                OK
            } else {
                NOT_FOUND
            }))
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
            {
                // 没走完成功的 initSign 会话不会自己消失（探测机、App 中退、进程被杀），
                // 不清就只增不减。清了最多让那次签名重来，不会弄错任何数据。
                let mut sessions = state.sessions.lock().ok()?;
                if sessions.len() >= MAX_SIGN_SESSIONS {
                    // 先清过期的，还超才整表清。
                    sessions.retain(|_, s| s.created.elapsed() <= SESSION_TTL);
                    if sessions.len() >= MAX_SIGN_SESSIONS {
                        sessions.clear();
                    }
                }
                sessions.insert(
                    session,
                    SignSession {
                        uid,
                        alias: alias.to_string(),
                        raw,
                        created: Instant::now(),
                        caller: call.caller_uid,
                    },
                );
            }
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
            mark_gone(&ask_gone_key(uid));
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
            mark_gone(&auth_gone_key(uid, alias));
            Some(Answer::Code(OK))
        }
        _ => None,
    }
}

/// 产线 provisioning（2 号 `exportAttkPublicKey`）要的那份 ATTK 自描述：
/// `pub_key` 就是 ATTK 的公钥，签名用 ATTK 自己那把私钥 —— 真机上 ATTK 是这条链的根，
/// 它自签、ATTK 再签 ASK。注意这跟 1 号（ASK 证书）不是同一份东西：1 号的 `pub_key`
/// 是该 uid 的 ASK。
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

/// 这个 uid 的 ASK 在不在（内存缓存或盘上那份都算）。
///
/// 给 `generateAskKeyPair` 用：真机对“已经有 ASK”的请求回 -5，不重铸。
fn ask_exists(state: &State, uid: i32) -> bool {
    if state
        .asks
        .lock()
        .map(|map| map.contains_key(&uid))
        .unwrap_or(false)
    {
        return true;
    }
    read_store_pem(ASK_SECTION, &uid.to_string()).is_some()
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
        // 这层只是缓存，跟 store 一样加个上限；清了下次从盘上读回来。
        if map.len() >= MAX_AUTH_CACHE {
            map.clear();
        }
        map.insert(id, key.clone());
    }
    Some(key)
}

fn bump_counter(state: &State, uid: i32) -> u64 {
    // counter 必须单调递增、重启不能回退：App 记着上次看到的值，小回去就当重放删钥匙。
    //
    // 所有 App 共用一个文件（每行 `uid=counter`），读-改-写放在文件锁里：injector 同时跑在
    // keystore 和 SOTER 宿主几个进程里，不加锁会互相覆盖。
    const PATH: &str = "/data/misc/ommega/soter_counter";

    let mem = state
        .counters
        .lock()
        .ok()
        .and_then(|map| map.get(&uid).copied())
        .unwrap_or(0);

    let next = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(PATH)
    {
        Ok(mut file) => {
            let _lock = file.lock(); // 锁跟着 fd，文件关闭（drop）时自动释放
            let mut text = String::new();
            let _ = file.read_to_string(&mut text);
            // 文件里没这个 uid 就从 1 开始：换 ATTK 就是新身份（新 ASK、新 cpu_id），
            // App 侧开通状态也一并清了，1 是正确起点；不接内存里的旧值。
            let next = match counter_for(&text, uid) {
                Some(stored) => stored.max(mem).max(COUNTER_BASE) + 1,
                None => COUNTER_BASE,
            };
            let updated = set_counter(&text, uid, next);
            let _ = file.seek(SeekFrom::Start(0));
            // 先写后截。反过来（先 set_len(0)）的话，write_all 一旦失败（ENOSPC/EDQUOT）
            // 文件就空了，所有 uid 的计数一起丢，下轮全部从 1 开始，日志里还看不出。
            if file.write_all(updated.as_bytes()).is_ok() {
                let _ = file.set_len(updated.len() as u64);
            }
            next
        }
        // 开不了文件（权限异常）：只能拿内存里的值兜一下，至少不回退到比本进程见过的更小。
        Err(_) => mem.max(COUNTER_BASE) + 1,
    };

    if let Ok(mut map) = state.counters.lock() {
        map.insert(uid, next);
    }
    next
}

/// 从 `uid=counter` 行里取某个 uid 的计数。
fn counter_for(text: &str, uid: i32) -> Option<u64> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if key.trim().parse::<i32>().ok()? != uid {
            return None;
        }
        value.trim().parse::<u64>().ok()
    })
}

/// 把某个 uid 的计数写回去（已有就替换、没有就追加），其它行原样保留。
fn set_counter(text: &str, uid: i32, value: u64) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    let mut replaced = false;
    for line in text.lines() {
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        if key.trim().parse::<i32>().ok() == Some(uid) {
            out.push_str(&format!("{uid}={value}\n"));
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&format!("{uid}={value}\n"));
    }
    out
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
        "{{\"pub_key\":{},\"cpu_id\":\"{}\",\"counter\":{},\"uid\":\"{}\"{}}}",
        json_string(&key.pem),
        cpu_id(),
        counter,
        uid,
        salt_field()
    )
    .into_bytes()
}

/// 签名现场那份 JSON。字段名和键序照真机：`raw` 在最前，一个字段都不能少 ——App 会
/// 把它们存下来当设备指纹。形状按平台分：
///
/// | | 高通 | MTK |
/// |---|---|---|
/// | `cpu_id` | `00000000…` | `09000000…` |
/// | `getDeviceId` | 16 字节 raw | 32 个 ASCII hex + NUL |
/// | 盐长字段 | 无 | `rsa_pss_saltlen:32` |
/// | 已有料时 `generate` | 重铸、回 0 | 回 -5、不重铸 |
struct Platform {
    cpu_prefix: &'static str,
    device_id_ascii: bool,
    declares_salt: bool,
    generate_rotates: bool,
    /// 签名文档（`sign_json`）里报的 TEE / 指纹身份：真机上这四格是 TA 报的原厂值，
    /// 本地拿不到真值时就按平台报原厂那套，别写我们自己的名字和版本。
    tee_n: &'static str,
    tee_v: &'static str,
    fp_n: &'static str,
    fp_v: &'static str,
}

fn platform() -> &'static Platform {
    static P: OnceLock<Platform> = OnceLock::new();
    P.get_or_init(|| {
        let soc = prop("ro.soc.manufacturer")
            .unwrap_or_default()
            .to_lowercase();
        let board = prop("ro.board.platform").unwrap_or_default().to_lowercase();
        let mtk = soc.contains("mediatek") || soc.contains("mtk") || board.starts_with("mt");
        if mtk {
            Platform {
                cpu_prefix: "09000000",
                device_id_ascii: true,
                declares_salt: true,
                generate_rotates: false,
                tee_n: "Kinibi",
                tee_v: "10018",
                fp_n: "FPC",
                fp_v: "1",
            }
        } else {
            Platform {
                cpu_prefix: "00000000",
                device_id_ascii: false,
                declares_salt: false,
                generate_rotates: true,
                tee_n: "QSEE",
                tee_v: "5",
                fp_n: "fingerprint",
                fp_v: "1",
            }
        }
    })
}

/// 一份自描述文档的尾巴：盐长字段（高通那套不放这个字段，验签方按默认的摘要长度 32 算）。
fn salt_field() -> String {
    if platform().declares_salt {
        format!(",\"rsa_pss_saltlen\":{SALT_LEN}")
    } else {
        String::new()
    }
}

fn sign_json(uid: i32, raw: &str, counter: u64) -> Vec<u8> {
    let info = device_info();
    format!(
        "{{\"raw\":{},\"fid\":{},\"counter\":{},\"tee_n\":{},\"tee_v\":{},\"fp_n\":{},\"fp_v\":{},\"cpu_id\":{},\"uid\":{}{}}}",
        json_string(raw),
        json_string(&info.fid),
        counter,
        json_string(&info.tee_n),
        json_string(&info.tee_v),
        json_string(&info.fp_n),
        json_string(&info.fp_v),
        json_string(&cpu_id()),
        json_string(&uid.to_string()),
        salt_field()
    )
    .into_bytes()
}

/// ASK 那份 JSON。键序照现场抓到的来，`uid` 是字符串别写成数字。
/// `pub_pem` 是 **ASK 自己的公钥**（可能是独立的一把，也可能是 ATTK）。
fn ask_json(pub_pem: &str, uid: i32, counter: u64) -> Result<Vec<u8>, ()> {
    let document = format!(
        "{{\"pub_key\":{},\"cpu_id\":\"{}\",\"counter\":{},\"uid\":\"{}\"{}}}",
        json_string(pub_pem),
        cpu_id(),
        counter,
        uid,
        salt_field()
    );
    Ok(document.into_bytes())
}

/// 32 个 hex 字符转 16 字节。
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

/// `getDeviceId` 的答复字节：高通回 16 字节 raw，MTK 回 32 个 ASCII hex + NUL。
fn device_id_reply(cpu: &str) -> Vec<u8> {
    if platform().device_id_ascii {
        let mut out = cpu.as_bytes().to_vec();
        out.push(0);
        out
    } else {
        hex_bytes(cpu).unwrap_or_default()
    }
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
        assert!(id.starts_with(platform().cpu_prefix), "platform prefix");
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

        // 键序和字段名是现场抓的，别改。盐长字段按平台：MTK 带、高通不带。
        let text = String::from_utf8(document.to_vec()).unwrap();
        assert!(text.starts_with("{\"pub_key\":"), "got {text}");
        for field in ["\"cpu_id\":", "\"counter\":", "\"uid\":\"10373\""] {
            assert!(text.contains(field), "ASK json is missing {field}: {text}");
        }
        if platform().declares_salt {
            assert!(text.contains("\"rsa_pss_saltlen\":32"), "got {text}");
        } else {
            assert!(
                !text.contains("rsa_pss_saltlen"),
                "高通那套不带这个字段: {text}"
            );
        }

        // 文档是 ASK 的自描述，签名那把是 ATTK（ATTK 签 ASK 的认证）
        use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
        use rsa::signature::Verifier;
        let verifying = PssVerifyingKey::<PssSha256>::new_with_salt_len(
            rsa::RsaPublicKey::from(&current_attk().unwrap().private),
            SALT_LEN as usize,
        );
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
    fn device_id_answer_follows_the_platform_shape() {
        let data = as_buffer(answer(&call(8, None, None)));
        if platform().device_id_ascii {
            // MTK（实测 MT6991）：33 字节 = 32 个 ASCII hex + `\0`。
            assert_eq!(data.len(), 33);
            assert_eq!(&data[..32], device_id().as_bytes());
            assert_eq!(data[32], 0, "末尾那个字节是 NUL");
            assert!(data[..32].iter().all(|b| b.is_ascii_hexdigit()));
        } else {
            // 高通（实测 SM8635）：16 字节 raw，hex 出来就是 cpu_id。
            assert_eq!(data.len(), 16);
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, device_id());
        }
    }

    /// generate 的语义按平台走：MTK 第二次回 -5；高通每次重铸回 0。
    #[test]
    fn generate_follows_the_platform_semantics() {
        let uid = 4701;
        assert_eq!(as_code(answer(&call(5, Some(uid), None))), OK);
        let alias = "SecondGenerate";
        assert_eq!(as_code(answer(&call(7, Some(uid), Some(alias)))), OK);
        let first_auth = pem_of(
            &String::from_utf8(
                split_envelope(&as_buffer(answer(&call(3, Some(uid), Some(alias))))).0,
            )
            .unwrap(),
        );

        if platform().generate_rotates {
            assert_eq!(as_code(answer(&call(5, Some(uid), None))), OK);
            assert_eq!(as_code(answer(&call(7, Some(uid), Some(alias)))), OK);
            let second_auth = pem_of(
                &String::from_utf8(
                    split_envelope(&as_buffer(answer(&call(3, Some(uid), Some(alias))))).0,
                )
                .unwrap(),
            );
            assert_ne!(first_auth, second_auth, "高通那套每次 generate 都重铸");
        } else {
            assert_eq!(as_code(answer(&call(5, Some(uid), None))), NOT_FOUND);
            assert_eq!(
                as_code(answer(&call(7, Some(uid), Some(alias)))),
                NOT_FOUND,
                "MTK 那套已经在了就不重铸"
            );
            assert_eq!(as_code(answer(&call(10, Some(uid), Some(alias)))), OK);
        }
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
        PssVerifyingKey::<PssSha256>::new_with_salt_len(public, SALT_LEN as usize)
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

        // 字段名和键序照真机抓的来；盐长那格只有声明盐的platform（MTK 那套）才有，
        // 高通机型上这份文档根本没有 rsa_pss_saltlen，不能硬要求。
        let mut keys = vec!["pub_key", "cpu_id", "counter", "uid"];
        if platform().declares_salt {
            keys.push("rsa_pss_saltlen");
        }
        let order: Vec<usize> = keys
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

    /// 2 号（exportAttkPublicKey）的 ATTK 自描述：`pub_key` 就是 ATTK、签名也是 ATTK 自己。
    ///
    /// 真机上 ATTK 是这条链的根（它自签、再用它签 ASK），所以这里必须自洽：
    /// 拿 ATTK 公钥验得过，拿这个 uid 的 ASK 公钥验不过。
    #[test]
    fn the_attk_certificate_is_self_signed() {
        let uid = 6401;
        let attk_pem = current_attk().expect("attk").pem.clone();

        let envelope = as_buffer(answer(&call(2, Some(uid), None)));
        let (document, signature) = split_envelope(&envelope);
        let text = String::from_utf8(document.clone()).unwrap();
        assert_eq!(
            pem_of(&text),
            attk_pem.trim_end(),
            "pub_key 必须是 ATTK 自己那把"
        );
        assert!(
            verifies(&attk_pem, &document, &signature),
            "ATTK 证书是自签的"
        );
        assert!(
            !verifies(&ask_pem(uid), &document, &signature),
            "ATTK 证书不是 ASK 签的，别把两层搞反"
        );
    }

    /// 本地兜底也跟着 uid 分家（跟真机 TA 一样）：
    /// 机主 10490 和工作资料 1010490 是两个槽位，ASK 两把、AuthKey 各管各的。
    #[test]
    fn local_material_is_per_uid() {
        let (owner, work_profile) = (10490, 1_010_490);
        let alias = "SoterAuthKey";
        // 真机上重复跑很常见，store 里可能还留着上一遍的料。先全清，
        // 不然「工作资料没建过 AuthKey」这个前提在第二遍就跑偏了。
        reset_local_state_for_test();

        let owner_ask = ask_pem(owner);
        let work_ask = ask_pem(work_profile);
        assert_ne!(owner_ask, work_ask, "不同用户不能共用一把 ASK");
        assert_eq!(ask_pem(owner), owner_ask, "同一 uid 的 ASK 要稳定");

        // AuthKey 也在 uid 下面：机主建了，工作资料那边就当没建。
        assert_eq!(as_code(answer(&call(7, Some(owner), Some(alias)))), OK);
        assert_eq!(as_code(answer(&call(10, Some(owner), Some(alias)))), OK);
        assert_eq!(
            as_code(answer(&call(10, Some(work_profile), Some(alias)))),
            AUTH_KEY_NOT_READY
        );

        // 工作资料那边自己建一把：两边的 AuthKey 和各自的 ASK 对得上，不串。
        assert_eq!(
            as_code(answer(&call(7, Some(work_profile), Some(alias)))),
            OK
        );
        let owner_auth = pem_of(
            &String::from_utf8(
                split_envelope(&as_buffer(answer(&call(3, Some(owner), Some(alias))))).0,
            )
            .unwrap(),
        );
        let work_auth = pem_of(
            &String::from_utf8(
                split_envelope(&as_buffer(answer(&call(
                    3,
                    Some(work_profile),
                    Some(alias),
                ))))
                .0,
            )
            .unwrap(),
        );
        assert_ne!(owner_auth, work_auth, "两个 uid 的 AuthKey 不能是同一把");
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

        // 字段和键序照 B 端 TEE 现场抓的来；盐长字段按平台（MTK 带、高通不带）。
        let mut fields = vec![
            "raw", "fid", "counter", "tee_n", "tee_v", "fp_n", "fp_v", "cpu_id", "uid",
        ];
        if platform().declares_salt {
            fields.push("rsa_pss_saltlen");
        }
        let order: Vec<usize> = fields
            .iter()
            .map(|k| text.find(&format!("\"{k}\":")).expect("key present"))
            .collect();
        assert!(
            order.windows(2).all(|w| w[0] < w[1]),
            "key order changed: {text}"
        );
        assert!(text.contains("\"uid\":\"6200\""), "uid is a string: {text}");
        if platform().declares_salt {
            assert!(text.contains("\"rsa_pss_saltlen\":32"), "salt len: {text}");
        } else {
            assert!(
                !text.contains("rsa_pss_saltlen"),
                "高通那套不带这个字段: {text}"
            );
        }
    }

    /// 删过了就是删过了：`removeAllUidKey` / `removeAuthKey` 之后 `export*` 不能现造
    /// 一把新的顶上（真机的删除是黏的，检测器就测这个）。
    #[test]
    fn a_deleted_key_does_not_grow_back() {
        let uid = 4801;
        let alias = "DeletedGone";
        assert_eq!(as_code(answer(&call(5, Some(uid), None))), OK);
        assert_eq!(as_code(answer(&call(7, Some(uid), Some(alias)))), OK);

        // 删单个 AuthKey：它会消失，而且导不出来（不现造）。
        assert_eq!(as_code(answer(&call(13, Some(uid), Some(alias)))), OK);
        assert_eq!(
            as_code(answer(&call(10, Some(uid), Some(alias)))),
            AUTH_KEY_NOT_READY
        );
        assert_eq!(
            as_buffer_code(answer(&call(3, Some(uid), Some(alias)))),
            AUTH_KEY_NOT_READY
        );

        // 删整个 uid：ASK 也没了，导出不能把它变回来。
        assert_eq!(as_code(answer(&call(12, Some(uid), None))), OK);
        assert_eq!(as_buffer_code(answer(&call(1, Some(uid), None))), NOT_FOUND);
        assert_eq!(
            as_buffer_code(answer(&call(3, Some(uid), Some(alias)))),
            AUTH_KEY_NOT_READY
        );

        // 重建之后又能导出（墓碑被清）。
        assert_eq!(as_code(answer(&call(5, Some(uid), None))), OK);
        assert_eq!(as_buffer_code(answer(&call(1, Some(uid), None))), OK);
    }

    #[test]
    fn the_device_info_is_derived_from_this_machine() {
        let info = device_info();
        let derived = info
            .derived_cpu_id
            .as_deref()
            .expect("真机/真设备上序列号读得到；读不到这儿就该是 None");
        assert_eq!(derived.len(), 32, "SOTER device ids are 32 hex chars");
        assert!(derived.starts_with(platform().cpu_prefix));
        assert!(derived.chars().all(|c| c.is_ascii_hexdigit()));
        // `device_id()` 报的是「当前该报的那个」（文件里有就用文件里的，没有才用它）。
        assert_eq!(device_id(), cpu_id(), "device_id() 就是那个 cpu_id");
        assert_eq!(device_id(), device_id(), "同一个进程里报的号要稳");

        assert!(!info.fp_n.is_empty());
        assert!(!info.fp_v.is_empty());
        assert!(!info.tee_n.is_empty());
        assert!(!info.tee_v.is_empty());
        // 这四格是检测器（SoterChecker C8）直接摊给人看的，只能像原厂报的那样：
        // 不能出现我们自己的名字、版本号，也不要 `unknown` 这种一看就是壳的占位。
        for value in [&info.tee_n, &info.tee_v, &info.fp_n, &info.fp_v] {
            assert!(
                !value.eq_ignore_ascii_case("unknown"),
                "占位值不能进文档: {value}"
            );
            assert!(
                !value.to_lowercase().contains("ommega"),
                "不能报自己的名字: {value}"
            );
            assert!(
                !value.contains(env!("CARGO_PKG_VERSION")),
                "不能报自己的版本号: {value}"
            );
        }
        assert!(
            info.tee_n == "QSEE" || info.tee_n == "Kinibi",
            "tee_n 得是原厂拼法: {}",
            info.tee_n
        );
        assert!(info.fid.len() >= 10, "fid 像真机那样是十位数字");
        assert!(info.fid.chars().all(|c| c.is_ascii_digit()));
    }

    /// 本地这条路的号只认两份：这份 ATTK 自带的那份（force 文件）、本机派生那份。
    /// 转发链路学来的 B 端真机号**不参与** —— 那是另一份身份的数字。
    #[test]
    fn the_local_cpu_id_belongs_to_the_local_identity() {
        let forced = "090000005171734c42866bea148b21f5";
        let derived = device_info()
            .derived_cpu_id
            .as_deref()
            .expect("真机/真设备上序列号读得到");

        // force 文件（这份 ATTK 自己的号）优先。
        assert_eq!(
            local_cpu_id(Some(forced), Some(derived)),
            (forced.to_string(), "forced")
        );
        // 没带号就用本机派生那份。
        assert_eq!(
            local_cpu_id(None, Some(derived)),
            (derived.to_string(), "derived")
        );
        // 形状不对的 force 文件不采纳，回落本机号（绝不编一个）。
        assert_eq!(
            local_cpu_id(Some("nonsense"), Some(derived)),
            (derived.to_string(), "derived")
        );
        // 两个来源都没有：空串，上层据此整笔不答。
        assert_eq!(local_cpu_id(None, None), (String::new(), "derived"));
        assert_eq!(cpu_id(), device_id(), "device_id() 就是本地这个号");
        // 两台设备的号本来就不该一样。
        assert_ne!(forced, derived, "跟转发那条路的号必须是两个");
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

    #[test]
    fn counter_file_keeps_every_uid_on_its_own_line() {
        let text = "10491=100\n10494=200\n";
        assert_eq!(counter_for(text, 10491), Some(100));
        assert_eq!(counter_for(text, 10494), Some(200));
        assert_eq!(counter_for(text, 99999), None);

        // 已有 uid：只改那一行，别的行原样保留
        let updated = set_counter(text, 10494, 300);
        assert_eq!(updated, "10491=100\n10494=300\n");

        // 新 uid：追加到末尾
        let appended = set_counter(text, 55555, 7);
        assert_eq!(appended, "10491=100\n10494=200\n55555=7\n");
    }

    #[test]
    fn counter_file_ignores_junk_lines() {
        let text = "# 注释\nbroken\n10491=42\n\n";
        assert_eq!(counter_for(text, 10491), Some(42));
        // 垃圾行会被丢掉，但有效行仍然是有效的
        let updated = set_counter(text, 10491, 43);
        assert_eq!(counter_for(&updated, 10491), Some(43));
    }
}
