//! A 端本地的 SOTER 后端（自签兜底）。
//!
//! 这台机器的 SOTER TA 是没 provisioning 的 —— 实测 `generateAskKeyPair` 直接回
//! -20，key 一把都建不出来，所以本地真 HAL 这条腿是瘸的。这个模块补的就是那一
//! 块：拿 `assets/soter_ask.pem` 里那把 RSA，在用户态直接算签名，造一份"自洽"
//! 的 SOTER 应答出来。
//!
//! 形状跟服务端 `soter_mint.rs` 一模一样（那边的测试验过：ASK 的签名拿导出的
//! ATTK 公钥验得过）：
//!
//! ```text
//! ASK = [i32 le JSON 长度][JSON][256 字节 RSA-PSS-SHA256 签名]
//! JSON 键序 pub_key / cpu_id / counter / uid / rsa_pss_saltlen，uid 是字符串
//! ```
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
/// 本机 SOTER 设备号的种子。真机上是 `09000000` + 12 字节随机，我们按种子派生，
/// 好处是同一台机器每次算出来都一样（设备身份不能今天一个明天一个）。
const DEVICE_SEED: &str = "ommega-a-side-local";

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
    challenge: Vec<u8>,
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
/// 真机上是 `09000000` + 12 字节随机；我们按固定种子派生，这样同一台 A 端设备
/// 每次都是同一个号 —— 换个号 App 会当成换了设备，那就要重走一遍建 key 流程。
pub(crate) fn device_id() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ommega-a-side-soter:");
    hasher.update(DEVICE_SEED.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::from("09000000");
    for byte in &digest[..12] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
        // exportAskPublicKey(uid)
        1 => {
            let uid = call.uid?;
            let counter = bump_counter(state, uid);
            let document = ask_json(&state.ask, uid, counter).ok()?;
            let signature = state.ask.sign(&document)?;
            let mut data = Vec::with_capacity(4 + document.len() + signature.len());
            data.extend_from_slice(&(document.len() as i32).to_le_bytes());
            data.extend_from_slice(&document);
            data.extend_from_slice(&signature);
            Some(Answer::Buffer {
                code: OK,
                data: Some(data),
            })
        }
        // exportAuthKeyPublicKey(uid, alias)
        3 => {
            let (uid, alias) = (call.uid?, call.alias.as_deref()?);
            match auth_key(state, uid, alias) {
                Some(key) => Some(Answer::Buffer {
                    code: OK,
                    data: Some(key.pem.clone().into_bytes()),
                }),
                None => Some(Answer::Buffer {
                    code: NOT_FOUND,
                    data: None,
                }),
            }
        }
        // finishSign(session)
        4 => {
            let session = call.session?;
            let pending = state.sessions.lock().ok()?.remove(&session);
            let found = pending.and_then(|s| auth_key(state, s.uid, &s.alias).map(|k| (s, k)));
            match found {
                Some((s, key)) => Some(Answer::Buffer {
                    code: OK,
                    data: Some(key.sign(&s.challenge)?),
                }),
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
            // 挑战是十六进制串，转回字节再签（宿主那边也是这么处理的）。
            let challenge = decode_challenge(call.challenge.as_deref()?);
            let mut next = state.next_session.lock().ok()?;
            *next += 1;
            let session = *next;
            state.sessions.lock().ok()?.insert(
                session,
                SignSession {
                    uid,
                    alias: alias.to_string(),
                    challenge,
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

/// 挑战的编码：宿主传下来的是十六进制串。解不成十六进制就按原样当字节用，
/// 宁可签一份"看起来像"的也不要在这一步就把调用打死。
fn decode_challenge(text: &str) -> Vec<u8> {
    let trimmed = text.trim();
    if trimmed.len().is_multiple_of(2) && !trimmed.is_empty() {
        let mut out = Vec::with_capacity(trimmed.len() / 2);
        let bytes = trimmed.as_bytes();
        let mut ok = true;
        for pair in bytes.chunks(2) {
            let hi = (pair[0] as char).to_digit(16);
            let lo = (pair[1] as char).to_digit(16);
            match (hi, lo) {
                (Some(hi), Some(lo)) => out.push((hi * 16 + lo) as u8),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return out;
        }
    }
    trimmed.as_bytes().to_vec()
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

        let pem = as_buffer(answer(&call(3, Some(uid), Some("SoterAuthKey"))));
        let text = String::from_utf8(pem).unwrap();
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----"), "got {text}");

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
        let signature = as_buffer(answer(&finish));
        assert_eq!(signature.len(), 256);

        // 拿导出的那把公钥验签，验得过才算数
        let pem = String::from_utf8(as_buffer(answer(&call(3, Some(uid), Some(alias))))).unwrap();
        use rsa::pkcs8::DecodePublicKey;
        use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
        use rsa::signature::Verifier;
        let public = rsa::RsaPublicKey::from_public_key_pem(&pem).expect("exported pem parses");
        PssVerifyingKey::<PssSha256>::new(public)
            .verify(
                &decode_challenge("deadbeef"),
                &PssSignature::try_from(&signature[..]).unwrap(),
            )
            .expect("the challenge signature must verify");
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

    #[test]
    fn challenge_decoding_handles_hex_and_falls_back_to_raw() {
        assert_eq!(decode_challenge("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode_challenge("00"), vec![0x00]);
        // 奇数长度或者带非十六进制字符就按原样
        assert_eq!(decode_challenge("abc"), b"abc".to_vec());
        assert_eq!(decode_challenge("zz"), b"zz".to_vec());
    }

    #[test]
    fn json_string_escapes_the_pem() {
        let escaped = json_string("a\"b\\c\nd");
        assert_eq!(escaped, "\"a\\\"b\\\\c\\nd\"");
    }
}
