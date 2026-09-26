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

use serde_json::{json, Value};

fn main() {
    // The relay daemon does the same: a binder process state must exist before
    // any HAL call is possible.
    let _ = rsbinder::ProcessState::init_default();

    // What the relay advertises with every poll (the server routes SOTER with
    // it and the status page shows it).
    println!("caps: {}", ommegaclient_b::caps::report());

    let payloads = [
        json!({ "op": "selftest" }),
        json!({ "op": "probe" }),
        json!({ "op": "get_device_id" }),
        json!({ "op": "verify_attk_key_pair" }),
        json!({ "op": "has_ask_already", "uid": 10373 }),
        json!({ "op": "has_ask_already", "uid": 10371 }),
        json!({ "op": "export_attk_public_key" }),
        json!({ "op": "export_ask_public_key", "uid": 10373 }),
        // Must be refused: mutating ops need the relay config opt-in.
        json!({ "op": "generate_ask_key_pair", "uid": 10373 }),
    ];
    for payload in payloads {
        report(&payload);
    }
}

fn report(payload: &Value) {
    let op = payload.get("op").and_then(Value::as_str).unwrap_or("?");
    match ommegaclient_b::soter::handle(payload, false) {
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
