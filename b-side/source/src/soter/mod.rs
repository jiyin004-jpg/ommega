//! SOTER forwarding for the B-side relay agent.
//!
//! SOTER is the Trustonic "secure keystore" HAL that Tencent (WeChat / QQ)
//! and Alipay use for app signing keys: the private keys live in the TEE and
//! the HAL exposes "create / export public key / sign / delete" operations for
//! them.  The A-side asks the relay for an operation with a task payload, we
//! run it against the *real* HAL on the B-side phone, and the answer goes back
//! as JSON — the same shape as the existing `attest` / `sign` / `decrypt`
//! forwarding.
//!
//! Task payload:
//!
//! ```json
//! { "op": "export_attk_public_key" }
//! { "op": "export_ask_public_key", "uid": 10373 }
//! { "op": "init_sign", "uid": 10373, "alias": "SoterAuthKey", "challenge": "..." }
//! ```
//!
//! `op` defaults to `probe`, which only reports whether this device can serve
//! SOTER at all (so the caller can decide to fall back).  Every other op fails
//! with a descriptive error when the HAL is missing, which is how the existing
//! forwarding path signals "this backing device cannot do that".
//!
//! The ops that create or remove keys change real device state (they touch the
//! payment-key store), so they stay disabled unless the operator opts in via
//! `OMMEGA_RELAY_SOTER_MUTATION=1` in `relay.conf`.
//!
//! See [`hal`] for the wire format (it is hand-marshalled and verified against
//! captured replies, see [`fixtures`]).

pub mod fixtures;
pub mod hal;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde_json::{json, Value};

use hal::{Soter, SoterData};

/// Ops that create or delete keys on the device.
const MUTATING_OPS: &[&str] = &[
    "generate_ask_key_pair",
    "generate_attk_key_pair",
    "generate_auth_key_pair",
    "remove_all_uid_key",
    "remove_auth_key",
];

/// Every op this module accepts.
const KNOWN_OPS: &[&str] = &[
    "probe",
    "selftest",
    "get_device_id",
    "export_attk_public_key",
    "export_ask_public_key",
    "export_auth_key_public_key",
    "init_sign",
    "finish_sign",
    "has_ask_already",
    "has_auth_key",
    "verify_attk_key_pair",
    "generate_ask_key_pair",
    "generate_attk_key_pair",
    "generate_auth_key_pair",
    "remove_all_uid_key",
    "remove_auth_key",
];

/// Handle one `soter` task payload.
///
/// `allow_mutation` comes from the relay config; it gates the ops that create
/// or delete keys.
pub fn handle(payload: &Value, allow_mutation: bool) -> Result<Value> {
    let op = payload
        .get("op")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("probe");
    if !KNOWN_OPS.contains(&op) {
        bail!("unknown soter op: {op}");
    }
    if MUTATING_OPS.contains(&op) && !allow_mutation {
        bail!(
            "soter op '{op}' creates or removes keys on the device and is disabled; \
             set OMMEGA_RELAY_SOTER_MUTATION=1 in relay.conf to allow it"
        );
    }
    if op == "selftest" {
        return Ok(fixtures::selftest());
    }
    if op == "probe" {
        return Ok(probe());
    }

    // 参数先取、HAL 后开：请求本身缺参数的话就别去碰 HAL。不然「服务没起」或者
    // SELinux 拦下来这种错误会盖掉「你 uid 没给」这种更该先说的话。
    match op {
        "get_device_id" => Ok(data_result(op, open_soter(op)?.get_device_id()?)),
        "export_attk_public_key" => Ok(data_result(op, open_soter(op)?.export_attk_public_key()?)),
        "export_ask_public_key" => {
            let uid = uid_of(payload)?;
            Ok(ask_result(op, open_soter(op)?.export_ask_public_key(uid)?))
        }
        "export_auth_key_public_key" => {
            let (uid, alias) = (uid_of(payload)?, alias_of(payload)?);
            Ok(data_result(
                op,
                open_soter(op)?.export_auth_key_public_key(uid, &alias)?,
            ))
        }
        "finish_sign" => {
            let session = session_of(payload)?;
            Ok(data_result(op, open_soter(op)?.finish_sign(session)?))
        }
        "init_sign" => {
            let (uid, alias, challenge) = (
                uid_of(payload)?,
                alias_of(payload)?,
                string_arg(payload, "challenge")?,
            );
            let session = open_soter(op)?.init_sign(uid, &alias, &challenge)?;
            Ok(json!({
                "op": op,
                "error_code": session.error_code,
                "session": session.session,
            }))
        }
        "has_ask_already" => {
            let uid = uid_of(payload)?;
            Ok(code_result(op, open_soter(op)?.has_ask_already(uid)?))
        }
        "has_auth_key" => {
            let (uid, alias) = (uid_of(payload)?, alias_of(payload)?);
            Ok(code_result(op, open_soter(op)?.has_auth_key(uid, &alias)?))
        }
        "verify_attk_key_pair" => Ok(code_result(op, open_soter(op)?.verify_attk_key_pair()?)),
        "generate_ask_key_pair" => {
            let uid = uid_of(payload)?;
            Ok(code_result(op, open_soter(op)?.generate_ask_key_pair(uid)?))
        }
        "generate_attk_key_pair" => {
            let user_id = user_id_of(payload)?;
            Ok(code_result(
                op,
                open_soter(op)?.generate_attk_key_pair(user_id)?,
            ))
        }
        "generate_auth_key_pair" => {
            let (uid, alias) = (uid_of(payload)?, alias_of(payload)?);
            Ok(code_result(
                op,
                open_soter(op)?.generate_auth_key_pair(uid, &alias)?,
            ))
        }
        "remove_all_uid_key" => {
            let uid = uid_of(payload)?;
            Ok(code_result(op, open_soter(op)?.remove_all_uid_key(uid)?))
        }
        "remove_auth_key" => {
            let (uid, alias) = (uid_of(payload)?, alias_of(payload)?);
            Ok(code_result(
                op,
                open_soter(op)?.remove_auth_key(uid, &alias)?,
            ))
        }
        other => bail!("unknown soter op: {other}"),
    }
}

/// 打开 SOTER HAL；这台机器没有就明确说没有。
fn open_soter(op: &str) -> Result<Soter> {
    Soter::open()?.ok_or_else(|| {
        anyhow!(
            "this device has no SOTER HAL ({}), cannot forward '{op}'",
            hal::SERVICE
        )
    })
}

/// 这台机器有没有 SOTER HAL —— 心跳能力上报用的。
///
/// 与 [`probe`] 的区别：`probe` 会真的调一次 HAL（能证明它确实能用，但有开销），
/// 这里只问 servicemanager，适合每 20 秒一次的心跳。
pub fn service_present() -> bool {
    hal::Soter::service_present()
}

/// Capability probe: can this device serve SOTER at all?
///
/// Unlike the other ops this never fails: `supported` is `false` when the HAL
/// is missing or cannot answer, with the reason attached.
pub fn probe() -> Value {
    match Soter::open() {
        Ok(Some(soter)) => {
            let mut out = json!({
                "op": "probe",
                "service": hal::SERVICE,
                "interface": hal::INTERFACE,
                "version": soter.interface_version().ok(),
            });
            // A device id read proves the HAL actually serves requests; a
            // registered-but-broken service must not be advertised as usable.
            match soter.get_device_id() {
                Ok(device) if device.error_code == 0 => {
                    out["supported"] = json!(true);
                    out["error_code"] = json!(device.error_code);
                    out["device_id"] = json!(device.text().unwrap_or_default());
                }
                Ok(device) => {
                    out["supported"] = json!(false);
                    out["error_code"] = json!(device.error_code);
                    out["reason"] = json!("getDeviceId returned a SOTER error code");
                }
                Err(e) => {
                    out["supported"] = json!(false);
                    out["reason"] = json!(format!("{e:#}"));
                }
            }
            out
        }
        Ok(None) => json!({
            "op": "probe",
            "supported": false,
            "service": hal::SERVICE,
            "reason": "service is not registered with the service manager",
        }),
        Err(e) => json!({
            "op": "probe",
            "supported": false,
            "service": hal::SERVICE,
            "reason": format!("{e:#}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Result shaping.
// ---------------------------------------------------------------------------

/// Base shape for the data-carrying ops: error code, payload, and the payload
/// as text when it is printable (PEM / device id), since callers usually want
/// that directly.
fn data_result(op: &str, data: SoterData) -> Value {
    let mut out = json!({
        "op": op,
        "error_code": data.error_code,
        "length": data.length,
        "data": base64::engine::general_purpose::STANDARD.encode(&data.data),
    });
    if let Some(text) = data.text() {
        out["text"] = json!(text);
    }
    out
}

/// `exportAskPublicKey` answers with `[i32 json length][json][TEE signature]`;
/// split it so callers do not have to know that.
fn ask_result(op: &str, data: SoterData) -> Value {
    let mut out = data_result(op, data.clone());
    if data.error_code == 0 {
        if let Ok((doc, signature)) = fixtures::split_ask_payload(&data.data) {
            out["json_bytes"] = json!(doc.len());
            out["signature"] = json!(base64::engine::general_purpose::STANDARD.encode(signature));
            if let Ok(parsed) = serde_json::from_slice::<Value>(doc) {
                out["payload"] = parsed;
            }
        }
    }
    out
}

/// Shape for the ops that return a bare SOTER error code (0 = success; for the
/// `has_*` ops 0 means "present", -5 means "absent").
fn code_result(op: &str, error_code: i32) -> Value {
    json!({ "op": op, "error_code": error_code })
}

// ---------------------------------------------------------------------------
// Payload arguments.
// ---------------------------------------------------------------------------

fn uid_of(payload: &Value) -> Result<i32> {
    int_arg(payload, "uid").context("soter payload needs the owning Android app uid")
}

fn user_id_of(payload: &Value) -> Result<i8> {
    let value = int_arg(payload, "user_id")?;
    i8::try_from(value).map_err(|_| anyhow!("'user_id' must fit in a signed byte, got {value}"))
}

fn session_of(payload: &Value) -> Result<i64> {
    long_arg(payload, "session").context("soter payload needs the session handle from init_sign")
}

fn alias_of(payload: &Value) -> Result<String> {
    string_arg(payload, "alias").context("soter payload needs the key 'alias'")
}

/// Accept an integer or a numeric string (the A-side stores uids as strings).
fn int_arg(payload: &Value, key: &str) -> Result<i32> {
    let value = payload.get(key).ok_or_else(|| anyhow!("missing '{key}'"))?;
    if let Some(number) = value.as_i64() {
        return i32::try_from(number).map_err(|_| anyhow!("'{key}' is out of range: {number}"));
    }
    if let Some(text) = value.as_str() {
        return text
            .trim()
            .parse::<i32>()
            .map_err(|_| anyhow!("'{key}' is not an integer: {text:?}"));
    }
    bail!("'{key}' must be an integer or a numeric string")
}

fn long_arg(payload: &Value, key: &str) -> Result<i64> {
    let value = payload.get(key).ok_or_else(|| anyhow!("missing '{key}'"))?;
    if let Some(number) = value.as_i64() {
        return Ok(number);
    }
    if let Some(text) = value.as_str() {
        return text
            .trim()
            .parse::<i64>()
            .map_err(|_| anyhow!("'{key}' is not an integer: {text:?}"));
    }
    bail!("'{key}' must be an integer or a numeric string")
}

fn string_arg(payload: &Value, key: &str) -> Result<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("missing string '{key}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_op_is_rejected() {
        let err = handle(&json!({ "op": "nope" }), true).expect_err("must reject");
        assert!(format!("{err:#}").contains("unknown soter op"));
    }

    #[test]
    fn mutating_ops_need_the_opt_in() {
        let payload = json!({ "op": "generate_ask_key_pair", "uid": 10373 });
        let err = handle(&payload, false).expect_err("must be gated");
        assert!(format!("{err:#}").contains("OMMEGA_RELAY_SOTER_MUTATION"));
    }

    #[test]
    fn missing_uid_is_reported_before_any_hal_call() {
        crate::init_binder();
        let err = handle(&json!({ "op": "export_ask_public_key" }), false).expect_err("must fail");
        assert!(format!("{err:#}").contains("uid"), "err: {err:#}");
    }

    #[test]
    fn numeric_strings_are_accepted_for_uids() {
        assert_eq!(int_arg(&json!({ "uid": "10373" }), "uid").unwrap(), 10373);
        assert_eq!(int_arg(&json!({ "uid": 10373 }), "uid").unwrap(), 10373);
    }

    #[test]
    fn user_id_must_fit_in_a_byte() {
        assert_eq!(user_id_of(&json!({ "user_id": 1 })).unwrap(), 1);
        assert!(user_id_of(&json!({ "user_id": 300 })).is_err());
    }

    #[test]
    fn selftest_op_does_not_touch_the_device() {
        let report = handle(&json!({ "op": "selftest" }), false).expect("selftest must run");
        assert_eq!(report["ok"], json!(true), "report: {report}");
    }
}
