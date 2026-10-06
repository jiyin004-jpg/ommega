//! Manual SOTER check against a connected B-side device.
//!
//! This is a diagnostic, not part of the shipped relay: build it, push it, run
//! it to exercise the forwarding path (and the captured-reply decoder, which
//! needs no HAL at all) on a real device.
//!
//! ```text
//! cargo build --target aarch64-linux-android --example soter_probe
//! adb push target/aarch64-linux-android/debug/examples/soter_probe /data/local/tmp/
//! adb shell su -c /data/local/tmp/soter_probe
//! ```
//!
//! `export_ask_public_key` is included on purpose: it is the headline SOTER
//! operation, but note that the HAL re-signs its answer and therefore advances
//! the device's TEE attestation counter.  The last entry asks for a key
//! generation with mutation still disabled, which must be refused.
//!
//! `init_sign` + `finish_sign` close the loop (step 3 of the 1.6.0 SOTER
//! feedback): they are the two calls that reveal whether this device's TA wants
//! a live fingerprint before it will sign at all.  Arguments are optional:
//! `soter_probe [uid] [alias] [challenge-hex]`.

use serde_json::{json, Value};

fn main() {
    // The relay daemon does the same: a binder process state must exist before
    // any HAL call is possible.
    let _ = rsbinder::ProcessState::init_default();

    // 跟 auth key 有关的那几个调用需要一个真实存在的 uid + alias，命令行可以覆盖：
    // `soter_probe [uid] [alias] [challenge-hex]`。默认抄 A 端真机抓到的微信流量。
    let mut args = std::env::args().skip(1);
    let uid: i32 = args.next().and_then(|v| v.parse().ok()).unwrap_or(10373);
    let alias = args
        .next()
        .unwrap_or_else(|| "SoterAuthKeyV2_salt11d8ba34_scene1".to_string());
    let challenge = args
        .next()
        .unwrap_or_else(|| "0a1b2c3d4e5f60718293a4b5c6d7e8f9001122334455667788".to_string());

    // What the relay advertises with every poll (the server routes SOTER with
    // it and the status page shows it).
    // 顺手把命令行的 uid/alias 当探针目标传进去：能力声明里到底是
    // `soter_sign` 还是 `soter_nosign`，就看这一次真签名签不签得动。
    let probe_target = ommegaclient_b::caps::SignProbeTarget {
        uid,
        alias: alias.to_string(),
    };
    println!(
        "caps: {}",
        ommegaclient_b::caps::report(Some(&probe_target))
    );
    println!("target: uid={uid} alias={alias}");

    let payloads = [
        json!({ "op": "selftest" }),
        json!({ "op": "probe" }),
        json!({ "op": "get_device_id" }),
        json!({ "op": "verify_attk_key_pair" }),
        json!({ "op": "has_ask_already", "uid": 10373 }),
        json!({ "op": "has_ask_already", "uid": 10371 }),
        json!({ "op": "export_attk_public_key" }),
        json!({ "op": "export_ask_public_key", "uid": 10373 }),
        // 这个 alias 到底在不在：在的话 init_sign 失败只能解释成 TA 要现场认证，
        // 不在的话 init_sign 返回的就是正儿八经的「找不到」。
        json!({ "op": "has_auth_key", "uid": uid, "alias": alias }),
        json!({ "op": "export_auth_key_public_key", "uid": uid, "alias": alias }),
        // Must be refused: mutating ops need the relay config opt-in.
        json!({ "op": "generate_ask_key_pair", "uid": 10373 }),
    ];
    for payload in payloads {
        report(&payload);
    }

    // 这两步跟上面那些只读的调用不一样：init_sign 会真的开一个签名会话，
    // finish_sign 会让 TEE 出签名。2026-10-06 在 PLC110（Trustonic AIDL）上实测
    // 过：不用按指纹也出得来真签名（拿 AuthKey 公钥验签 OK）—— 所以这里量到的
    // 只是「能签」，量不到**不能**反推「签不了」（失败码都是这一笔的状态：
    // -26 没验过、-204 会话被顶掉）。
    println!("--- 签名会话（uid={uid} alias={alias} challenge={challenge}）---");
    let mut session = None;
    match ommegaclient_b::soter::handle(
        &json!({
            "op": "init_sign",
            "uid": uid,
            "alias": alias,
            "challenge": challenge,
        }),
        false,
        2,
    ) {
        Ok(value) => {
            println!("OK   init_sign: {}", summarize(&value));
            session = value.get("session").and_then(Value::as_i64);
        }
        Err(e) => println!("ERR  init_sign: {e:#}"),
    }
    match session {
        Some(session) => match ommegaclient_b::soter::handle(
            &json!({ "op": "finish_sign", "session": session }),
            false,
            2,
        ) {
            Ok(value) => println!("OK   finish_sign: {}", summarize(&value)),
            Err(e) => println!("ERR  finish_sign: {e:#}"),
        },
        None => println!("SKIP finish_sign: init_sign 没给出 session，TA 在第一步就没过"),
    }
}

fn report(payload: &Value) {
    let op = payload.get("op").and_then(Value::as_str).unwrap_or("?");
    match ommegaclient_b::soter::handle(payload, false, 2) {
        Ok(value) => println!("OK   {op}: {}", summarize(&value)),
        Err(e) => println!("ERR  {op}: {e:#}"),
    }
}

/// Shorten bulky fields so the output stays readable over adb.
fn summarize(value: &Value) -> String {
    let mut value = value.clone();
    for key in ["data", "signature"] {
        if let Some(Value::String(text)) = value.get(key) {
            if text.chars().count() > 64 {
                let head: String = text.chars().take(48).collect();
                value[key] = json!(format!("{head}... ({} base64 chars)", text.len()));
            }
        }
    }
    if let Some(Value::String(text)) = value.get("text") {
        if text.chars().count() > 120 {
            let head: String = text.chars().take(96).collect();
            value["text"] = json!(format!("{head}..."));
        }
    }
    value.to_string()
}
