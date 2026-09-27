//! A 端本地的 SOTER 后端（自签兜底）。
//!
//! 这台机器的 SOTER TA 是没 provisioning 的 —— 实测 `generateAskKeyPair` 直接回
//! -20，key 一把都建不出来，所以本地真 HAL 这条腿是瘸的。这个模块补的就是那一
//! 块：拿 `assets/soter_ask.pem` 里那把 RSA，在用户态直接算签名，造一份"自洽"
//! 的 SOTER 应答出来。
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
//! `cpu_id` 由 `ro.boot.serialno` 派生，指纹和 TEE 也从属性读，读不到才退回兜底值。
//! 不要把它写成编死的常量 —— 那样装过这套的机器全是同一个设备，业务侧一眼假。
//!
//! 心里得有数的边界：自签的链**骗得过 App 本地**（它拿我们给的公钥验我们签的
//! 东西，当然验得过），**骗不过业务服务端的证书链校验**。私钥就编在 binary 里，
//! 谁扒出来都能用 —— 这是兜底，不是安全方案。
//!
//! 参数校验、错误码这些都跟着真机宿主那套走（-5 是"这把钥匙不在这台设备上"，
//! 实测宿主也是这么回的），这样上层看不出区别。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::pss::SigningKey as PssSigningKey;
use rsa::rand_core::OsRng;
use rsa::sha2::Sha256 as PssSha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::RsaPrivateKey;

use crate::hook::soter;

/// SOTER 的成功码。
const OK: i32 = 0;
/// "这把钥匙不在这台设备上"。实测 hasAskAlready / exportAuthKeyPublicKey 都回它。
const NOT_FOUND: i32 = -5;
/// ASK 里写死的盐长，也正好是 SHA-256 的摘要长度。
const SALT_LEN: i32 = 32;
/// 编译进来的那把私钥（PKCS#8 PEM）。
const ASK_PEM: &[u8] = include_bytes!("../../assets/soter_ask.pem");
/// 读不到序列号时的兜底种子。正常情况 `cpu_id` 是按本机 `ro.boot.serialno` 派生的
/// （每台机器一个号，同一台机器每次都一样），只有序列号都读不到才用得上它。
const FALLBACK_SEED: &str = "ommega-a-side-local";

/// 一对 RSA，加它的公钥 PEM（SOTER 里的"证书"就是拿这个验的）。
struct Key {
    private: RsaPrivateKey,
    /// 公钥 PEM，`exportXxxPublicKey` 吐出去的就是它。
    pem: String,
}

impl Key {
    fn from_pem(pem: &str) -> Option<Self> {
        let private = RsaPrivateKey::from_pkcs8_pem(pem.trim()).ok()?;
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
    /// 主 key：ASK 和 ATTK 都用它，自己签自己 —— 服务端 self_signed 那层就是这么干的。
    ask: Key,
    /// `{uid}|{alias}` -> AuthKey。
    auth: Mutex<HashMap<String, Key>>,
    /// uid -> 签名计数器（ASK JSON 里的 counter）。
    counters: Mutex<HashMap<i32, u64>>,
    /// 会话号 -> 这一次要签的挑战。
    sessions: Mutex<HashMap<i64, SignSession>>,
    /// 下一个会话号。起点用当前毫秒，看起来像真的。
    next_session: Mutex<i64>,
}

fn state() -> Option<&'static State> {
    static STATE: OnceLock<Option<State>> = OnceLock::new();
    STATE
        .get_or_init(|| {
            let pem = std::str::from_utf8(ASK_PEM).ok()?;
            let ask = Key::from_pem(pem)?;
            Some(State {
                ask,
                auth: Mutex::new(HashMap::new()),
                counters: Mutex::new(HashMap::new()),
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
/// 按本机序列号派生，同一台机器每次都一样（换号 App 会当成换了设备，得重走一遍
/// 建 key 流程），不同机器不一样 —— 这才叫设备身份。
pub(crate) fn device_id() -> String {
    device_info().cpu_id.clone()
}

// ---------------------------------------------------------------------------
// 本机设备信息：本地模式该拿这台机器自己的东西填，不编常量
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
extern "C" {
    /// bionic 里现成的属性读取，返回写进 value 的长度（0 = 没这条属性）。
    fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
}

/// 读一条系统属性。payload 跑在 uid 1000 的系统进程里，直接调 bionic 比 fork 一个
/// `getprop` 便宜几个数量级（签名这条路径上每毫秒都算数）。
#[cfg(target_os = "android")]
fn prop(name: &str) -> Option<String> {
    use std::ffi::CStr;
    let name = std::ffi::CString::new(name).ok()?;
    // bionic 的 PROP_VALUE_MAX 是 92，留点余量。
    let mut buf = [0 as libc::c_char; 128];
    let len = unsafe { __system_property_get(name.as_ptr(), buf.as_mut_ptr()) };
    if len <= 0 {
        return None;
    }
    let value = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_str().ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// 非 Android（开发机上 `cargo check` 这种）读不到属性，一律当没有，走兜底值。
#[cfg(not(target_os = "android"))]
fn prop(_name: &str) -> Option<String> {
    None
}

/// 这台机器的 SOTER 设备信息。属性只读一次，之后复用。
struct DeviceInfo {
    /// `09000000` + 12 字节十六进制。
    cpu_id: String,
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
        DeviceInfo {
            cpu_id: cpu_id_from(serial.as_deref()),
            fp_n: fingerprint_name(),
            fp_v: fingerprint_version(),
            tee_n: tee_name(),
            tee_v: tee_version(),
            fid: fid_from(serial.as_deref()),
        }
    })
}

/// 一台像真机的设备号：`09000000` + 12 字节十六进制。
fn cpu_id_from(serial: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-a-side-soter:");
    hasher.update(serial.unwrap_or(FALLBACK_SEED).as_bytes());
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
/// 2 / 6 / 14 不在里面：宿主那半边根本不发这三个（它自己那份 proxy 里是空号），本地
/// 也就没写。清单放这儿是为了让拦截那侧只需要问一句「这个号你答得了吗」。
pub(crate) const HANDLED_CODES: [u32; 11] = [1, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13];

/// 这个号码本地答得了吗。`true` 只说「有对应的实现」——参数不够的时候 `answer`
/// 照样返回 `None`，上层会原样透给真 HAL，所以这里不用把参数也掰开看一遍。
pub(crate) fn answerable(code: u32) -> bool {
    HANDLED_CODES.contains(&code)
}

/// 按号码算一笔应答。认不出来、或者少参数就返回 `None`，让上层透给真 HAL。
///
/// 只处理 HAL 那半边（`call.hal`）：App 面向那半边是宿主自己的事，它会把我们的
/// 结果原样包成 `SoterExportResult` 递给 App，不用我们操心。
pub(crate) fn answer(call: &soter::SoterCall) -> Option<Answer> {
    if !call.hal {
        return None;
    }
    let state = state()?;
    match call.code {
        // exportAskPublicKey(uid) —— ASK 的自描述，拿 ASK 自己签（本地 ASK 兼 ATTK）
        1 => {
            let uid = call.uid?;
            let counter = bump_counter(state, uid);
            let document = ask_json(&state.ask, uid, counter).ok()?;
            let signature = state.ask.sign(&document)?;
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
                    let signature = state.ask.sign(&document)?;
                    Some(Answer::Buffer {
                        code: OK,
                        data: Some(envelope(&document, &signature)),
                    })
                }
                None => Some(Answer::Buffer {
                    code: NOT_FOUND,
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
                // 会话丢了就是丢了，跟真机一个码；别透给真 HAL（那条腿本来就是废的）
                None => Some(Answer::Buffer {
                    code: NOT_FOUND,
                    data: None,
                }),
            }
        }
        // generateAskKeyPair(uid) —— 真机上这是建 ASK，我们这把一开始就在，
        // 只需要把计数器归零，回成功。
        5 => {
            let uid = call.uid?;
            if let Ok(mut map) = state.counters.lock() {
                map.insert(uid, 0);
            }
            Some(Answer::Code(OK))
        }
        // generateAuthKeyPair(uid, alias)
        7 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            let key = Key::generate()?;
            state.auth.lock().ok()?.insert(auth_id(uid, alias), key);
            Some(Answer::Code(OK))
        }
        // getDeviceId()
        8 => Some(Answer::Buffer {
            code: OK,
            data: Some(device_id().into_bytes()),
        }),
        // hasAskAlready(uid) —— 我们这把一直"有"。
        9 => Some(Answer::Code(if call.uid.is_some() {
            OK
        } else {
            NOT_FOUND
        })),
        // hasAuthKey(uid, alias)
        10 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            let present = auth_key(state, uid, alias).is_some();
            Some(Answer::Code(if present { OK } else { NOT_FOUND }))
        }
        // initSign(uid, alias, challenge)
        11 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            if auth_key(state, uid, alias).is_none() {
                return Some(Answer::Init {
                    status: NOT_FOUND,
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
        // removeAllUidKey(uid)
        12 => {
            let uid = call.uid?;
            let prefix = format!("{uid}|");
            if let Ok(mut map) = state.auth.lock() {
                map.retain(|k, _| !k.starts_with(&prefix));
            }
            Some(Answer::Code(OK))
        }
        // removeAuthKey(uid, alias)
        13 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            if let Ok(mut map) = state.auth.lock() {
                map.remove(&auth_id(uid, alias));
            }
            Some(Answer::Code(OK))
        }
        _ => None,
    }
}

fn auth_id(uid: i32, alias: &str) -> String {
    format!("{uid}|{alias}")
}

fn auth_key(state: &State, uid: i32, alias: &str) -> Option<Key> {
    let map = state.auth.lock().ok()?;
    let key = map.get(&auth_id(uid, alias))?;
    Some(Key {
        private: key.private.clone(),
        pem: key.pem.clone(),
    })
}

fn bump_counter(state: &State, uid: i32) -> u64 {
    let Ok(mut map) = state.counters.lock() else {
        return 1;
    };
    let entry = map.entry(uid).or_insert(0);
    *entry += 1;
    *entry
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
    let info = device_info();
    format!(
        "{{\"pub_key\":{},\"cpu_id\":\"{}\",\"counter\":{},\"uid\":\"{}\",\"rsa_pss_saltlen\":{}}}",
        json_string(&key.pem),
        info.cpu_id,
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
        json_string(&info.cpu_id),
        json_string(&uid.to_string()),
        SALT_LEN
    )
    .into_bytes()
}

/// ASK 那份 JSON。键序照现场抓到的来，`uid` 是字符串别写成数字。
fn ask_json(key: &Key, uid: i32, counter: u64) -> Result<Vec<u8>, ()> {
    let device = device_id();
    let document = format!(
        "{{\"pub_key\":{},\"cpu_id\":\"{}\",\"counter\":{},\"uid\":\"{}\",\"rsa_pss_saltlen\":{}}}",
        json_string(&key.pem),
        device,
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
            code,
            op: "test",
            uid,
            alias: alias.map(str::to_string),
            challenge: None,
            session: None,
            key: None,
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

        // 签名拿自己的公钥验得过（这就是"自洽"的含义）
        use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
        use rsa::signature::Verifier;
        let verifying = PssVerifyingKey::<PssSha256>::new(rsa::RsaPublicKey::from(
            &state().unwrap().ask.private,
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

    #[test]
    fn unknown_codes_fall_through_to_the_real_hal() {
        assert!(
            answer(&call(2, Some(1), None)).is_none(),
            "code 2 is reserved"
        );
        assert!(answer(&call(99, Some(1), None)).is_none());
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
    fn device_id_answers_the_whole_32_chars() {
        let data = as_buffer(answer(&call(8, None, None)));
        assert_eq!(data, device_id().into_bytes());
    }

    #[test]
    fn auth_keys_are_created_found_and_removed() {
        let uid = 4242;
        assert_eq!(
            as_code(answer(&call(10, Some(uid), Some("SoterAuthKey")))),
            NOT_FOUND
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
            NOT_FOUND
        );
    }

    #[test]
    fn remove_all_uid_key_only_takes_that_uid() {
        let (a, b) = (5100, 5200);
        assert_eq!(as_code(answer(&call(7, Some(a), Some("k")))), OK);
        assert_eq!(as_code(answer(&call(7, Some(b), Some("k")))), OK);

        assert_eq!(as_code(answer(&call(12, Some(a), None))), OK);
        assert_eq!(as_code(answer(&call(10, Some(a), Some("k")))), NOT_FOUND);
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
            !verifies(&ask_pem(), &document, &signature),
            "the sign document must not verify with the ASK key"
        );
    }

    #[test]
    fn init_sign_without_a_key_reports_not_found() {
        let mut c = call(11, Some(7777), Some("NoSuchKey"));
        c.challenge = Some("00".to_string());
        assert!(
            matches!(answer(&c), Some(Answer::Init { status, .. }) if status == NOT_FOUND),
            "a missing auth key must come back as a -5 status"
        );
    }

    #[test]
    fn finish_sign_with_an_unknown_session_reports_not_found() {
        let mut c = call(4, None, None);
        c.session = Some(1);
        assert_eq!(as_buffer_code(answer(&c)), NOT_FOUND);
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

    /// 本机 ASK 的公钥 PEM。
    fn ask_pem() -> String {
        state().unwrap().ask.pem.clone()
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
            verifies(&ask_pem(), &document, &signature),
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
        assert_eq!(info.cpu_id.len(), 32, "SOTER device ids are 32 hex chars");
        assert!(info.cpu_id.starts_with("09000000"));
        assert!(info.cpu_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(info.cpu_id, device_id(), "device_id() 就是那个 cpu_id");
        assert_eq!(device_info().cpu_id, info.cpu_id, "属性只读一次，值要稳定");

        assert!(!info.fp_n.is_empty());
        assert!(!info.fp_v.is_empty());
        assert!(!info.tee_n.is_empty());
        assert!(!info.tee_v.is_empty());
        assert!(info.fid.len() >= 10, "fid 像真机那样是十位数字");
        assert!(info.fid.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn json_string_escapes_the_pem() {
        let escaped = json_string("a\"b\\c\nd");
        assert_eq!(escaped, "\"a\\\"b\\\\c\\nd\"");
    }
}
