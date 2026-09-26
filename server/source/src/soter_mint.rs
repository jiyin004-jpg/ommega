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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::pss::SigningKey as PssSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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
    /// `{device}|{uid}|{alias}` -> AuthKey
    auth: Mutex<HashMap<String, Arc<MintKey>>>,
    /// `{device}|{uid}` -> 签名计数器
    counters: Mutex<HashMap<String, u64>>,
    /// `{device}|{uid}` -> 下一次会话号
    next_session: Mutex<i64>,
    /// 会话号 -> 这一次要签的挑战
    sessions: Mutex<HashMap<i64, SignSession>>,
}

struct SignSession {
    uid: i32,
    alias: String,
    challenge: Vec<u8>,
}

fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| Store {
        self_signed: Mutex::new(None),
        auth: Mutex::new(HashMap::new()),
        counters: Mutex::new(HashMap::new()),
        next_session: Mutex::new(chrono::Utc::now().timestamp_millis()),
        sessions: Mutex::new(HashMap::new()),
    })
}

/// 取这一层的物料。`key_pem` 只有 keybox 层才需要（服务端存的那把设备身份私钥）。
fn material(layer: &str, key_pem: Option<&str>) -> Result<Arc<MintKey>> {
    if layer == "keybox" {
        let pem = key_pem.ok_or_else(|| anyhow!("服务端在这台设备名下没有 RSA 身份的私钥"))?;
        return Ok(Arc::new(MintKey::from_pem(pem)?));
    }
    self_signed_key()
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
// 入口
// ---------------------------------------------------------------------------

/// 跑一层服务端 SOTER。
///
/// 返回 `None` 表示"这一层不认识这个 op"，`Some` 里带 `error` 表示这层试过但没
/// 成 —— 两种情况调用方都该继续回退下一层。成功就是一份跟 B 端形状一致的应答。
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
                Some(key) => Ok(data_result(op, OK, key.attk_pem.as_bytes())),
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
                Ok(code_result(op, OK))
            }
            "generate_ask_key_pair" | "generate_attk_key_pair" => {
                // keybox 层那把是服务端存的身份，不给它轮换；自签层就是换一把新的。
                if layer != "self_signed" {
                    return Err(anyhow!(
                    "layer '{layer}' holds a stored identity, it cannot rotate the ASK/ATTK pair"
                ));
                }
                rotate_self_signed_key()?;
                Ok(code_result(op, OK))
            }
            "init_sign" => {
                let uid = uid_of(body)?;
                let alias = alias_of(body)?;
                if auth_key(device_id, body).is_none() {
                    // 没有 AuthKey 就是没有，-5；跟真机上"这把钥匙不在"是同一个码。
                    return Ok(code_result(op, NOT_FOUND));
                }
                let challenge = body
                    .get("challenge")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .as_bytes()
                    .to_vec();
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
                            uid,
                            alias,
                            challenge,
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
                let sign_session = match store()
                    .sessions
                    .lock()
                    .ok()
                    .and_then(|mut m| m.remove(&session))
                {
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
                match key.sign(&sign_session.challenge) {
                    Ok(signature) => Ok(data_result(op, OK, &signature)),
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

fn ask_json(key: &MintKey, device_id: &str, counter: u64, uid: i32) -> Result<Vec<u8>> {
    // 键序照现场抓到的来：pub_key / cpu_id / counter / uid / rsa_pss_saltlen。
    // `uid` 在 SOTER 里是字符串，别写成数字。
    let doc = json!({
        "pub_key": key.attk_pem,
        "cpu_id": device_id,
        "counter": counter,
        "uid": uid.to_string(),
        "rsa_pss_saltlen": ASK_SALT_LEN,
    });
    serde_json::to_vec(&doc).context("failed to serialize the ASK document")
}

fn ask_result(op: &str, layer: &str, key: &MintKey, device_id: &str, uid: i32) -> Result<Value> {
    let counter = counter_for(&format!("{device_id}|{uid}"));
    let document = ask_json(key, device_id, counter, uid)?;
    let signature = key.sign(&document)?;
    let mut data = Vec::with_capacity(4 + document.len() + signature.len());
    data.extend_from_slice(&(document.len() as i32).to_le_bytes());
    data.extend_from_slice(&document);
    data.extend_from_slice(&signature);

    let mut out = data_result(op, OK, &data);
    out["json_bytes"] = json!(document.len());
    out["signature"] = json!(b64(&signature));
    out["payload"] = serde_json::from_slice(&document)?;
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
