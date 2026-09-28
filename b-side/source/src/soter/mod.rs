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
pub mod hidl;
pub mod hwbinder;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde_json::{json, Value};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

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

/// 这些 op 要真拿 uid 的密钥材料（问状态、导公钥、签名）——被本设备判过「签不了」
/// 之后，一律不再由本设备回答。
const SLOT_DENY_OPS: &[&str] = &[
    "get_device_id",
    "export_ask_public_key",
    "export_auth_key_public_key",
    "has_ask_already",
    "has_auth_key",
    "init_sign",
    "finish_sign",
];

/// 这些 op 把槽位的材料换掉了，之前那条「签不了」的记录跟着作废：让本设备重新
/// 挣一次机会（服务端那边 ASK 重建也会把槽位的层钉清掉，这里对齐）。
const SLOT_REBUILD_OPS: &[&str] = &[
    "generate_ask_key_pair",
    "remove_all_uid_key",
    "remove_auth_key",
];

/// 只有签名这两步的结论能说明「这份材料行不行」。
const SLOT_SIGN_OPS: &[&str] = &["init_sign", "finish_sign"];

/// SOTER_ERROR_VERIFICATION_FAILED。TA 说这份材料验不过 —— 不是「还没建好」。
const SOTER_VERIFICATION_FAILED: i64 = -26;

/// 记多久。一天：同一天的支付流程都交给后面那层，又不至于把一次偶发的 -26 永久
/// 钉死；手机重启/重装模块后进程重来，记录自然清空。
const SLOT_DENY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// uid -> 记下来的时刻。只放内存：AGENTS.md 里说了，要落盘得先问用户。
static SLOT_DENY: Mutex<Vec<(i32, Instant)>> = Mutex::new(Vec::new());

fn slot_deny_list() -> MutexGuard<'static, Vec<(i32, Instant)>> {
    // 锁中毒（哪个线程在持锁时 panic 了）不该让后面每个请求都失败：记录本来就是
    // 个提示，拿到脏数据顶多多问一次 HAL。
    SLOT_DENY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn slot_denied(uid: i32) -> bool {
    let now = Instant::now();
    let mut list = slot_deny_list();
    list.retain(|(_, at)| now.saturating_duration_since(*at) < SLOT_DENY_TTL);
    list.iter().any(|(recorded, _)| *recorded == uid)
}

fn deny_slot(uid: i32) {
    let now = Instant::now();
    let mut list = slot_deny_list();
    list.retain(|(_, at)| now.saturating_duration_since(*at) < SLOT_DENY_TTL);
    match list.iter_mut().find(|(recorded, _)| *recorded == uid) {
        Some(slot) => slot.1 = now,
        None => list.push((uid, now)),
    }
}

fn clear_slot_deny(uid: i32) {
    slot_deny_list().retain(|(recorded, _)| *recorded != uid);
}

/// -26 落在签名步骤上，就是「这份材料签不了」，重试也不会有别的结果。
fn is_hard_slot_failure(op: &str, result: &Value) -> bool {
    if !SLOT_SIGN_OPS.contains(&op) {
        return false;
    }
    result.get("error_code").and_then(Value::as_i64) == Some(SOTER_VERIFICATION_FAILED)
}

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

    // 这个 uid 之前已经被 TA 判过「签不了」：别再摸 HAL，直接说这层做不了，服务端
    // 自然会把它交给后面那层（keybox/mint 那两层照样能把流程走完）。重建槽位的 op
    // 例外 —— 它们就是来换材料的，顺手把记录清掉。
    if let Ok(uid) = uid_of(payload) {
        if SLOT_REBUILD_OPS.contains(&op) {
            clear_slot_deny(uid);
        } else if SLOT_DENY_OPS.contains(&op) && slot_denied(uid) {
            bail!(
                "soter op '{op}' for uid {uid} is not served by this device: its TEE \
                 rejected the key material for this slot (SOTER error \
                 {SOTER_VERIFICATION_FAILED} / VERIFICATION_FAILED), so this layer steps \
                 aside and the caller's next layer answers instead"
            );
        }
    }

    // 参数先取、HAL 后开：请求本身缺参数的话就别去碰 HAL。不然「服务没起」或者
    // SELinux 拦下来这种错误会盖掉「你 uid 没给」这种更该先说的话。
    let result: Result<Value> = match op {
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
    };
    let result = result?;

    // 签名回 -26：这层把活让出去。回 error 而不是把码原样递上去，服务端就不会把
    // 这台设备当成「能把活干完的那层」，也就不会把 (device, uid) 槽位钉在这儿；
    // 不这么改的话，光是把 -26 递上去，槽位照样被钉住，下一轮流程还得从这儿起步。
    if let Ok(uid) = uid_of(payload) {
        if is_hard_slot_failure(op, &result) {
            deny_slot(uid);
            bail!(
                "soter op '{op}' for uid {uid} got SOTER error {SOTER_VERIFICATION_FAILED} \
                 (VERIFICATION_FAILED): this device cannot sign the slot, so this layer \
                 steps aside and the caller's next layer answers instead"
            );
        }
    }

    Ok(result)
}

/// 打开 SOTER HAL；这台机器没有就明确说没有。
fn open_soter(op: &str) -> Result<Soter> {
    Soter::open()?.ok_or_else(|| {
        anyhow!(
            "this device has no SOTER HAL ({} / {}), cannot forward '{op}'",
            hal::SERVICE,
            hal::QTI_SERVICE
        )
    })
}

/// 探针签名用的挑战值（十六进制字符串，跟 A 端传下来的形状一样）。
const PROBE_CHALLENGE: &str = "00112233445566778899aabbccddeeff";

/// 真去签一次：拿一个现成的槽位走 `init_sign` + `finish_sign`。
///
/// 这是能力上报用的。`getDeviceId` 只能证明 HAL 活着，证明不了它肯签 —— 一加 11
/// （PHB110）这类机器的 AuthKey 锁在「刚匹配过指纹」后面，没人按指纹时
/// `finish_sign` 一律回 -26（TA 给的原话就是「没有新鲜指纹」）。所以「能不能签」
/// 只能靠真签一次来量，别猜。
///
/// 只用槽位上现成的材料，不建不删（改设备密钥状态得先问操作者）：没配探针目标，
/// 或者目标槽位上根本没材料（-5 / -6）时，结论都是「签不了」——比默默声称能签诚实，
/// 服务端也就不会把注定失败的签名任务派过来。
///
/// 不走 Err：这是探针，HAL 不给面子也得把原因带回去写进日志。
pub fn sign_probe(uid: i32, alias: &str) -> Value {
    let mut out = json!({ "op": "sign_probe", "uid": uid, "alias": alias });
    let soter = match Soter::open() {
        Ok(Some(soter)) => soter,
        Ok(None) => {
            out["error"] = json!("this device has no SOTER HAL");
            return out;
        }
        Err(e) => {
            out["error"] = json!(format!("{e:#}"));
            return out;
        }
    };
    let session = match soter.init_sign(uid, alias, PROBE_CHALLENGE) {
        Ok(session) => session,
        Err(e) => {
            out["error"] = json!(format!("{e:#}"));
            return out;
        }
    };
    out["init_sign"] = json!(session.error_code);
    if session.error_code != 0 {
        // -5 / -6：槽位上没有 ASK / AuthKey，探不出签名能力。
        out["signed"] = json!(false);
        return out;
    }
    match soter.finish_sign(session.session) {
        Ok(data) => {
            out["finish_sign"] = json!(data.error_code);
            out["signed"] = json!(data.error_code == 0);
        }
        Err(e) => out["error"] = json!(format!("{e:#}")),
    }
    out
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
                "backend": soter.backend().label(),
                "service": soter.backend().service(),
                "interface": soter.backend().interface(),
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
    fn a_sign_failure_takes_the_slot_off_this_device() {
        let uid = 900001;
        assert!(!slot_denied(uid));
        deny_slot(uid);
        assert!(slot_denied(uid), "uid {uid} must be remembered");
        clear_slot_deny(uid);
        assert!(!slot_denied(uid));
    }

    #[test]
    fn only_a_verification_failure_is_a_hard_sign_failure() {
        assert!(is_hard_slot_failure(
            "finish_sign",
            &json!({ "error_code": -26 })
        ));
        assert!(is_hard_slot_failure(
            "init_sign",
            &json!({ "error_code": -26 })
        ));
        // -5/-6 是「还没建」，App 靠它决定要不要建密钥；-7/-9 是会话过期/正在认证，
        // 都是正常答复，不能让这层退下去。
        for code in [0, -5, -6, -7, -9, -1000] {
            assert!(!is_hard_slot_failure(
                "finish_sign",
                &json!({ "error_code": code })
            ));
        }
        // 查询类的 -26 不进这条路（host 只对签名步骤的结论负责）。
        assert!(!is_hard_slot_failure(
            "has_auth_key",
            &json!({ "error_code": -26 })
        ));
    }

    #[test]
    fn rebuilding_the_slot_clears_the_verdict() {
        let uid = 900002;
        deny_slot(uid);
        assert!(slot_denied(uid));
        // handle() 里对这几个 op 先清记录再干活，这里直接对清记录这一步验。
        clear_slot_deny(uid);
        assert!(!slot_denied(uid));
        for op in SLOT_REBUILD_OPS {
            assert!(
                MUTATING_OPS.contains(op),
                "{op} must stay behind the opt-in"
            );
        }
    }

    #[test]
    fn a_denied_slot_is_answered_before_the_hal_is_touched() {
        let uid = 900003;
        let payload = json!({ "op": "has_auth_key", "uid": uid, "alias": "whatever" });
        deny_slot(uid);
        let err = handle(&payload, true).expect_err("a denied slot must not be answered");
        let text = format!("{err:#}");
        assert!(text.contains("not served by this device"), "err: {text}");
        assert!(
            !text.contains("no SOTER HAL"),
            "must bail before opening the HAL: {text}"
        );
        clear_slot_deny(uid);
        assert!(!slot_denied(uid));
    }

    #[test]
    fn selftest_op_does_not_touch_the_device() {
        let report = handle(&json!({ "op": "selftest" }), false).expect("selftest must run");
        assert_eq!(report["ok"], json!(true), "report: {report}");
    }
}
