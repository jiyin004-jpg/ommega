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

    match RemoteRelay::soter(&request_value(&value, op.as_str())) {
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

/// SOTER 的身份是 `(cpu_id, uid)` 一起绑的：B 的密钥库里只有它自己那套应用的密钥
/// （本机实测：B 上只有 10373 那把 = B 自己的微信，其余 uid 全 `-5`，而 ASK 的 JSON 里
/// 钉着 `"uid":"10373"` 和 B 自己的 cpu_id）。所以设备替身这条线上，拿 A 端那个 uid
/// 去问 B 必然问不到 —— 得按 B 自己的身份问。
///
/// 这就是那张表存在的理由（`soter_uid_map: 10490=10373`，逗号/分号/空格分隔多条，
/// 每条的 `A=B` 里 `=` 也可以写成 `:` 或 `->`）。没配就不动：uid 猜错了答出来的东西
/// 比「没有」更坑。
fn apply_uid_map(value: &Value, raw: &str) -> Option<Value> {
    let from = value.get("uid").and_then(Value::as_i64)?;
    let to = parse_uid_map(raw).into_iter().find(|(a, _)| *a == from)?.1;
    let mut mapped = value.clone();
    mapped["uid"] = Value::from(to);
    Some(mapped)
}

/// 解析映射表；不认得的部分直接丢（配置写错一个字符不该把整条远程链路弄挂）。
pub(crate) fn parse_uid_map(raw: &str) -> Vec<(i64, i64)> {
    let mut pairs = Vec::new();
    for entry in raw.split([',', ';', '\n']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (a, b) = match entry.split_once('=') {
            Some(split) => split,
            None => match entry.split_once("->") {
                Some(split) => split,
                None => match entry.split_once(':') {
                    Some(split) => split,
                    None => continue,
                },
            },
        };
        let (Ok(a), Ok(b)) = (a.trim().parse::<i64>(), b.trim().parse::<i64>()) else {
            continue;
        };
        if !pairs.contains(&(a, b)) {
            pairs.push((a, b));
        }
    }
    pairs
}

/// 转发前的最后一步：按配置里的映射表把请求的 uid 换成 B 端对应的那个。
///
/// 换成功了记一行 info —— 拿 A 的 uid 去问 B 得到的是「没有」，换完才拿得到真材料，
/// 这条日志是区分这两种情况的唯一依据。
fn request_value(value: &Value, op: &str) -> Value {
    let raw = match crate::config::config().read() {
        Ok(cfg) => cfg.remote.soter_uid_map.clone(),
        Err(_) => String::new(),
    };
    match apply_uid_map(value, &raw) {
        Some(mapped) => {
            log::info!(
                "event=soter relay op={op} uid {} -> {} (B 端那个同名应用)",
                value.get("uid").and_then(Value::as_i64).unwrap_or(-1),
                mapped.get("uid").and_then(Value::as_i64).unwrap_or(-1),
            );
            mapped
        }
        None => value.clone(),
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
    fn a_uid_map_entry_moves_the_request_to_the_other_device() {
        let value = json!({"op": "export_ask_public_key", "uid": 10490});
        let mapped = apply_uid_map(&value, "10490=10373").expect("a mapped uid must move");
        assert_eq!(mapped["uid"], json!(10373));
        // 原请求不动（调用方还要用它记日志）。
        assert_eq!(value["uid"], json!(10490));
    }

    #[test]
    fn an_unmapped_uid_is_left_alone() {
        let value = json!({"op": "export_ask_public_key", "uid": 10490});
        assert_eq!(apply_uid_map(&value, ""), None);
        assert_eq!(apply_uid_map(&value, "10491=10373"), None);
        // 没有 uid 的说法（getDeviceId 这类）自然也不动。
        assert_eq!(
            apply_uid_map(&json!({"op": "get_device_id"}), "10490=10373"),
            None
        );
    }

    #[test]
    fn every_spelling_of_the_map_is_accepted() {
        assert_eq!(parse_uid_map("10490=10373"), vec![(10490, 10373)]);
        assert_eq!(parse_uid_map("10490:10373"), vec![(10490, 10373)]);
        assert_eq!(parse_uid_map("10490->10373"), vec![(10490, 10373)]);
        assert_eq!(
            parse_uid_map("10490=10373, 10123 = 10102;"),
            vec![(10490, 10373), (10123, 10102)]
        );
        // 同一对写两遍只算一条，顺序无关。
        assert_eq!(parse_uid_map("1=2,1=2"), vec![(1, 2)]);
    }

    #[test]
    fn a_malformed_entry_is_dropped_not_fatal() {
        assert_eq!(parse_uid_map("乱写"), Vec::new());
        assert_eq!(parse_uid_map("10490="), Vec::new());
        assert_eq!(parse_uid_map("=10373"), Vec::new());
        assert_eq!(parse_uid_map("10490=abc"), Vec::new());
        // 坏了一条，好的那一条还得留着。
        assert_eq!(parse_uid_map("乱写,10490=10373"), vec![(10490, 10373)]);
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
