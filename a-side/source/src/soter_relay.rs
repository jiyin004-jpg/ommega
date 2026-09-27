//! A 端 SOTER 接替转发的决策端：宿主拦到一笔 HAL 调用后，由这里决定问远程、走本地还是透传。
//!
//! 决策为什么在这儿而不是 payload 里：宿主是 uid 1000，读不到 A 端配置（`/data/misc/keystore/
//! ommega` 是 0770 的 keystore 目录），而 daemon 盯着那个文件（`config.rs` 里的
//! `ommega-clienta-config-watch`），所以 WebUI 改完开关，下一次调用就按新值走，不用重启。
//!
//! 回给 payload 的 blob 布局在 `kmr_common::soter_relay`，两边共用那一份实现。

use kmr_common::soter_relay::{self, Outcome};
use serde_json::Value;

use crate::remote::{fallback_local, remote_enabled, RemoteRelay};

/// 一笔 SOTER 调用的去处，`request` 是 payload 拼好的 JSON（`{"op":..,"uid":..}`）。
///
/// 认不出来的请求、远程没开、远程没答案，都会回退到「本地兜底」——那是接线之前的行为，
/// 也是唯一不会把宿主坑住的退路。
pub fn forward(request: &str) -> Vec<u8> {
    let value: Value = match serde_json::from_str(request) {
        Ok(value) => value,
        Err(error) => {
            log::warn!("event=soter relay malformed request ({error:#}); using the local backend");
            return Outcome::Local.encode();
        }
    };
    let op = value
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    if soter_relay::code_for_op(&op).is_none() {
        log::warn!("event=soter relay unknown op {op:?}; using the local backend");
        return Outcome::Local.encode();
    }

    // WebUI 的「是否远程」关着：跟接线之前一样，本地自签兜底。这一行走 info：开关拨到
    // 关之后，日志里看不到 "answered remotely" 了，得能看见为什么没看见。
    if !remote_enabled() {
        log::info!("event=soter relay op={op} remote disabled; using the local backend");
        return Outcome::Local.encode();
    }

    match RemoteRelay::soter(&value) {
        Ok(Some(reply)) => match encode_reply(&op, &reply) {
            Some(outcome) => {
                let code = reply.get("error_code").and_then(Value::as_i64).unwrap_or(0);
                log::info!(
                    "event=soter relay op={op} answered remotely code={code} out_bytes={}",
                    out_bytes(&outcome)
                );
                outcome.encode()
            }
            None => {
                log::warn!("event=soter relay op={op} reply shape unrecognised; letting the real HAL answer");
                Outcome::Passthrough.encode()
            }
        },
        Ok(None) => no_remote_answer(&op, "no B-side answer"),
        Err(error) => no_remote_answer(&op, &format!("{error:#}")),
    }
}

/// 远程没给出答案时的分岔：配置允许退回本地就退回，否则把这笔调用放给真 HAL。
///
/// 注意这里用的是「是否远程」之外的第二个开关 `local_hw`（`RemoteConfig::fallback_local`，
/// 缺省为真）：B 端不在线时，默认还是拿 A 端自签把流程走完，而不是让 app 拿到真 HAL 那个
/// 整族 ATTK 都是 -20 的答复。
fn no_remote_answer(op: &str, reason: &str) -> Vec<u8> {
    if fallback_local() {
        log::warn!("event=soter relay op={op} {reason}; falling back to the local backend");
        Outcome::Local.encode()
    } else {
        log::warn!(
            "event=soter relay op={op} {reason}; no local fallback configured, letting the real HAL answer"
        );
        Outcome::Passthrough.encode()
    }
}

/// 答复里实际带了多少字节的 out 参数。只为日志好看（远程答了「有」还是「空」一眼能分开），
/// 别处不用。
fn out_bytes(outcome: &Outcome) -> usize {
    match outcome {
        Outcome::Buffer { data, .. } => data.as_ref().map(Vec::len).unwrap_or(0),
        Outcome::Init { .. } => 8,
        _ => 0,
    }
}

/// 把服务端那份 JSON 答案翻成 payload 认的形状。形状对不上返回 `None`（上层转透传）。
///
/// 服务端/B 端的字段见 `server/source/src/handlers.rs` 的 `run_soter_task`：`error_code`
/// 是必定有的状态码，`data` 是 base64 的 out 参数（只在成功、且在 `answers_with_data` 的
/// 那几个 op 上有），`init_sign` 另有 `session`。
fn encode_reply(op: &str, reply: &Value) -> Option<Outcome> {
    let code = reply.get("error_code").and_then(Value::as_i64)? as i32;

    if soter_relay::answers_with_session(op) {
        let session = reply.get("session").and_then(Value::as_i64).unwrap_or(0);
        return Some(Outcome::Init {
            status: code,
            session,
        });
    }

    if !soter_relay::answers_with_data(op) {
        return Some(Outcome::Code(code));
    }

    let data = match reply.get("data").and_then(Value::as_str) {
        Some(text) if !text.is_empty() => {
            Some(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text).ok()?)
        }
        _ => None,
    };
    Some(Outcome::Buffer { code, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 真机实测拿回来的应答（见 `D:\ace5u-forensics` 那份状态文档），字段名和形状都是
    /// 服务端真实输出，不是照着代码猜的。
    #[test]
    fn a_device_id_answer_keeps_its_trailing_nul() {
        let reply = json!({
            "data": "MDkwMDAwMDA1MTcxNzM0YzQyODY2YmVhMTQ4YjIxZjUA",
            "error_code": 0,
            "length": 33,
            "op": "get_device_id",
            "text": "090000005171734c42866bea148b21f5"
        });
        let outcome = encode_reply("get_device_id", &reply).expect("a real reply must map");
        assert_eq!(
            outcome,
            Outcome::Buffer {
                code: 0,
                data: Some(b"090000005171734c42866bea148b21f5\0".to_vec()),
            }
        );
    }

    #[test]
    fn an_auth_key_public_key_answer_keeps_the_pem_bytes() {
        let pem = b"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n";
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pem);
        let reply = json!({"data": encoded, "error_code": 0, "length": pem.len()});
        assert_eq!(
            encode_reply("export_auth_key_public_key", &reply),
            Some(Outcome::Buffer {
                code: 0,
                data: Some(pem.to_vec()),
            })
        );
    }

    #[test]
    fn a_missing_key_is_an_answer_with_no_out_parameter() {
        let reply = json!({"data": "", "error_code": -5, "length": 0});
        assert_eq!(
            encode_reply("export_ask_public_key", &reply),
            Some(Outcome::Buffer {
                code: -5,
                data: None,
            })
        );
    }

    #[test]
    fn the_boolean_ops_are_a_bare_code() {
        let reply = json!({"error_code": -5, "op": "has_ask_already"});
        assert_eq!(
            encode_reply("has_ask_already", &reply),
            Some(Outcome::Code(-5))
        );
        let reply = json!({"error_code": 0, "op": "remove_auth_key"});
        assert_eq!(
            encode_reply("remove_auth_key", &reply),
            Some(Outcome::Code(0))
        );
    }

    #[test]
    fn init_sign_carries_the_session() {
        let reply = json!({"error_code": 0, "op": "init_sign", "session": 42});
        assert_eq!(
            encode_reply("init_sign", &reply),
            Some(Outcome::Init {
                status: 0,
                session: 42
            })
        );
    }

    #[test]
    fn an_answer_without_a_status_code_is_not_guessed() {
        assert_eq!(
            encode_reply("get_device_id", &json!({"data": "AAA="})),
            None
        );
        assert_eq!(encode_reply("init_sign", &json!({"session": 1})), None);
    }

    #[test]
    fn out_bytes_tells_an_empty_answer_from_a_filled_one() {
        assert_eq!(out_bytes(&Outcome::Code(0)), 0);
        assert_eq!(out_bytes(&Outcome::Local), 0);
        assert_eq!(out_bytes(&Outcome::Passthrough), 0);
        assert_eq!(
            out_bytes(&Outcome::Buffer {
                code: -5,
                data: None
            }),
            0
        );
        assert_eq!(
            out_bytes(&Outcome::Buffer {
                code: 0,
                data: Some(vec![0u8; 826]),
            }),
            826
        );
        assert_eq!(
            out_bytes(&Outcome::Init {
                status: 0,
                session: 1
            }),
            8
        );
    }

    #[test]
    fn a_broken_base64_out_parameter_is_not_guessed() {
        assert_eq!(
            encode_reply(
                "get_device_id",
                &json!({"error_code": 0, "data": "not base64!!"})
            ),
            None
        );
    }
}
