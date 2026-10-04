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

/// 「这些调用只在本地兜底回答、一次都不往 B 端转」的缺省别名前缀。
///
/// 两个名字都是探针自己起的（别名尾部带毫秒时间戳，每跑一轮新铸一个），所以认前缀
/// 比认 uid 稳。**uid 完全不能信**：SOTER 的接口把 uid 当参数传，宿主不拿
/// `Binder.getCallingUid()` 覆盖它，所以探测机可以随便填 —— 实测鸭子的 AuthKey 那几笔
/// 用的是 Gmail 的 uid，ASK 用的是 `com.android.pacprocessor` 这类系统包。按 uid 或按
/// 包名认探测机都是南辕北辙。配置里写 `none` 就是关掉。
pub const DEFAULT_LOCAL_ONLY_PREFIXES: &str = "chunqiu_soter_probe_,duckdetector_soter_probe_";

/// 刚看见探测别名之后多久内，这台设备上不带别名的那几笔（ASK 那套）也按探测机处理。
///
/// 为什么要这个窗：探测机的 ASK 接口本身没有别名，uid 又是假的，本来无从辨认；但它
/// 那一轮总是先带别名铸 AuthKey / 签名，紧接着（实测同一个秒到两秒的窗口）才发那几笔
/// 不带别名的 ASK。取 4 秒：窗口只是给「同一轮」盖个戳，太长反而会把真应用的 ASK 也
/// 带进本地兜底（那样它的身份会跟真机那份对不上）。
const PROBE_WINDOW: std::time::Duration = std::time::Duration::from_secs(4);

/// 这台设备最后一次看到探测别名是什么时候。
fn note_probe_sighting() {
    if let Ok(mut guard) = LAST_PROBE.lock() {
        *guard = Some(std::time::Instant::now());
    }
}

fn probe_recently_seen() -> bool {
    let Ok(guard) = LAST_PROBE.lock() else {
        return false;
    };
    guard.map(|at| at.elapsed() < PROBE_WINDOW).unwrap_or(false)
}

static LAST_PROBE: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// 一笔 SOTER 调用的去处，`request` 是 payload 拼好的 JSON（`{"op":..,"uid":..}`）。
///
/// 认不出来的请求、远程没开、远程没答案，都会回退到「本地兜底」——那是接线之前的行为，
/// 也是唯一不会把宿主坑住的退路。
pub fn forward(request: &str) -> Vec<u8> {
    let started = std::time::Instant::now();
    let out = forward_inner(request);
    // 一笔 SOTER 调用在 daemon 这边待了多久：App 那边挂着的就是这个时间。
    // 远程不通时靠它一眼看出「是等远程等掉的，还是本地磨掉的」。
    log::info!(
        "event=soter relay took {} ms",
        started.elapsed().as_millis()
    );
    out
}

fn forward_inner(request: &str) -> Vec<u8> {
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

    // 真调用者：payload 只带内核填的 uid（`caller_uid`），包名在这边翻 —— SOTER 宿主里
    // 问不动那个服务（它只认 Keystore/Credstore 的 uid）。翻出来的 `caller_pkg` 既当下面
    // 那条「刚见过探测别名」时间窗的否决，也跟着请求转给服务端按白名单判。
    let value = with_caller_pkg(value);

    // 探测机（春秋 / 鸭子这类检测器）的这笔直接本地兜底，一次都不往 B 端转。
    //
    // 它们每跑一轮都新铸一把别名、签完也不收尾，在 B 端吃的是真 TEE 的空会话
    // （实测一天 900+ 次 init_sign，顶掉全部 init 的一半以上），而它们只看「这条路
    // 通不通」——本地兜底那份自洽的答复就够，真机会话留给真应用。
    if let Some(why) = local_only(&value) {
        log::info!("event=soter relay op={op} {why}；本地兜底作答，不往 B 端转");
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

/// 一笔调用该不该只在本地兜底回答（连远程都不问）。命中时回一句「凭什么」给日志。
///
/// 名单从配置里现读（`/data/misc/keystore/ommega/config` 的 `soter_local_only_prefixes` /
/// `soter_local_only_uids`）：宿主是 uid 1000、读不到那个 0770 的 keystore 目录，
/// 所以这个判断只能留在 daemon 这边，跟这个文件里其它开关同理。
fn local_only(value: &Value) -> Option<String> {
    let (prefixes, uids) = match crate::config::config().read() {
        Ok(cfg) => (
            cfg.remote.soter_local_only_prefixes.clone(),
            cfg.remote.soter_local_only_uids.clone(),
        ),
        Err(_) => return None,
    };
    if let Some(why) = local_only_match(value, &prefixes, &uids) {
        // 看见探测别名就把「这台设备刚跑过探测机」记一笔：它那一轮不带别名的 ASK
        // 就在几秒内，只能靠这个窗口接住。
        note_probe_sighting();
        return Some(why);
    }
    // 带了真调用者包名（新 payload）的那几笔不吃这个时间窗：这笔到底是不是探测机由
    // 服务端按包名判（名单之外一律内置）。靠窗猜会把真应用紧跟着探测机跑的那笔不带
    // 别名的 ASK 也拽到本地来 —— 它跟同一轮真机那把钥匙就对不上了（微信栽过）。
    if !has_caller_pkg(value) && probe_recently_seen() && alias_is_blank(value) {
        return Some("这台设备刚跑过探测机的流程（名字前几秒刚出现过）".to_string());
    }
    None
}

/// 这笔请求带没带「真调用者包名」（A 端带来的，或 daemon 刚翻出来的）。
fn has_caller_pkg(value: &Value) -> bool {
    value
        .get(CALLER_PKG_FIELD)
        .and_then(Value::as_str)
        .is_some_and(|pkg| !pkg.trim().is_empty())
}

/// payload 带来的「内核填的真调用者 uid」字段名（新 payload 才有）。
pub const CALLER_UID_FIELD: &str = "caller_uid";
/// uid 翻出来的包名（共享 uid 会有好几个，逗号连起来）。转发给服务端时用这个字段名。
pub const CALLER_PKG_FIELD: &str = "caller_pkg";

/// uid → 翻出来的包名 + 什么时候翻的。只有装/卸应用才会变，所以缓存一分钟。
type CallerNames = std::sync::Mutex<Vec<(u32, std::time::Instant, Option<String>)>>;
static CALLER_NAMES: CallerNames = std::sync::Mutex::new(Vec::new());

/// uid → 包名（逗号连起来），带一层短缓存。
///
/// 为什么要缓存：它每笔 SOTER 调用都要问一次系统，而那个映射只有装/卸应用才会变。
fn caller_package_for_uid(uid: i64) -> Option<String> {
    // 翻成功记一分钟就够（只有装/卸应用才会变）；翻不出来只记几秒 —— 那多半是系统那一刻
    // 没答上来（AAID 服务刚起来、那一瞬间查不到这个 uid），拿一分钟的负面缓存把「按包名判」
    // 这条路挡住不值得。
    const OK_TTL: std::time::Duration = std::time::Duration::from_secs(60);
    const MISS_TTL: std::time::Duration = std::time::Duration::from_secs(5);

    let uid = u32::try_from(uid).ok()?;
    if let Ok(entries) = CALLER_NAMES.lock() {
        if let Some((_, at, hit)) = entries.iter().find(|(cached, _, _)| *cached == uid) {
            let ttl = if hit.is_some() { OK_TTL } else { MISS_TTL };
            if at.elapsed() < ttl {
                return hit.clone();
            }
        }
    }

    let hit = match crate::plat::utils::package_names_for_uid(uid) {
        Ok(names) => {
            let joined = names.join(",");
            let hit = (!joined.is_empty()).then_some(joined);
            log::info!("event=soter caller uid {uid} -> {hit:?}");
            hit
        }
        Err(error) => {
            // 翻不出来就不带这个字段：服务端会退回别名/槽位那套老判据。
            log::warn!("event=soter caller uid {uid} 翻包名失败（{error:#}）；照旧按别名/槽位判");
            None
        }
    };

    if let Ok(mut entries) = CALLER_NAMES.lock() {
        if entries.len() > 256 {
            entries.clear();
        }
        entries.retain(|(cached, _, _)| *cached != uid);
        entries.push((uid, std::time::Instant::now(), hit.clone()));
    }
    hit
}

/// 把 payload 带来的真调用者 uid 翻成包名塞进请求，给服务端白名单用。
///
/// 请求里已经有 `caller_pkg`（或压根没带 `caller_uid`）就原样不动 —— 后者是旧 payload
/// 或者没有 App 侧事务的调用，服务端会自动退回别名/槽位那套。
fn with_caller_pkg(mut value: Value) -> Value {
    if has_caller_pkg(&value) {
        return value;
    }
    let Some(uid) = value.get(CALLER_UID_FIELD).and_then(Value::as_i64) else {
        return value;
    };
    let Some(pkg) = caller_package_for_uid(uid) else {
        return value;
    };
    if let Some(map) = value.as_object_mut() {
        map.insert(CALLER_PKG_FIELD.to_string(), Value::from(pkg));
    }
    value
}

/// 这笔调用有没有「能分辨的别名」。空别名和 `-` 都算没有（探测机那几个 ASK 就是这种）。
fn alias_is_blank(value: &Value) -> bool {
    let alias = value
        .get("alias")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    alias.is_empty() || alias == "-"
}

/// `local_only` 里跟配置来源无关的那半：名单匹配。
///
/// 两个名单都是逗号/分号/空格/换行分隔；`none` / `off` / `-` 表示整条名单关掉。
fn local_only_match(value: &Value, prefixes: &str, uids: &str) -> Option<String> {
    if let Some(uid) = value.get("uid").and_then(Value::as_i64) {
        if parse_number_list(uids).contains(&uid) {
            return Some(format!("uid {uid} 在本地兜底名单里"));
        }
    }
    let alias = value
        .get("alias")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    // 没有别名（`get_device_id` 这类）、或者调用方给的空别名（`-`）就只认 uid。
    if alias.is_empty() || alias == "-" {
        return None;
    }
    let prefix = parse_text_list(prefixes)
        .into_iter()
        .find(|prefix| alias.starts_with(prefix.as_str()))?;
    Some(format!("别名 {alias} 命中本地兜底前缀 {prefix}"))
}

/// 名单是不是「关掉」的写法。空也算关：缺省值不写就是这个意思。
fn list_disabled(raw: &str) -> bool {
    let raw = raw.trim();
    raw.is_empty() || matches!(raw.to_ascii_lowercase().as_str(), "none" | "off" | "-")
}

/// 逗号/分号/空格/换行分隔的字符串名单。
fn parse_text_list(raw: &str) -> Vec<String> {
    if list_disabled(raw) {
        return Vec::new();
    }
    raw.split([',', ';', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// 同上，元素是数字（uid）；认不出来的那一项直接丢掉，不牵连别的项。
fn parse_number_list(raw: &str) -> Vec<i64> {
    if list_disabled(raw) {
        return Vec::new();
    }
    raw.split([',', ';', ' ', '\t', '\n'])
        .filter_map(|item| item.trim().parse::<i64>().ok())
        .collect()
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

/// 转发前的最后一步：按配置里的映射表把请求的 uid 换成 B 端对应的那个，再把学到的
/// 真机 cpu_id 带上。
///
/// 换成功了记一行 info —— 拿 A 的 uid 去问 B 得到的是「没有」，换完才拿得到真材料，
/// 这条日志是区分这两种情况的唯一依据。
fn request_value(value: &Value, op: &str) -> Value {
    let raw = match crate::config::config().read() {
        Ok(cfg) => cfg.remote.soter_uid_map.clone(),
        Err(_) => String::new(),
    };
    let mapped = match apply_uid_map(value, &raw) {
        Some(mapped) => {
            log::info!(
                "event=soter relay op={op} uid {} -> {} (B 端那个同名应用)",
                value.get("uid").and_then(Value::as_i64).unwrap_or(-1),
                mapped.get("uid").and_then(Value::as_i64).unwrap_or(-1),
            );
            mapped
        }
        None => value.clone(),
    };
    with_cpu_id(mapped, crate::soter_cpu_id::current())
}

/// 把真机 cpu_id 塞进要转发的请求（`None` = 还没学到，就不带这个字段）。
///
/// 服务端拿它给那两层铸料，本地兜底那条路读的是同一份文件（`soter_local::cpu_id`）——
/// 三处报同一个号，`(cpu_id, uid)` 这个身份才不打架。调用方自己带了这个字段就不动。
fn with_cpu_id(mut value: Value, cpu_id: Option<String>) -> Value {
    let Some(map) = value.as_object_mut() else {
        return value;
    };
    if map.contains_key("cpu_id") {
        return value;
    }
    if let Some(cpu_id) = cpu_id {
        map.insert("cpu_id".to_string(), Value::from(cpu_id));
    }
    value
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
    fn a_forwarded_request_carries_the_learned_cpu_id() {
        let value = json!({"op": "export_ask_public_key", "uid": 10490});
        let some = "090000005171734c42866bea148b21f5".to_string();
        assert_eq!(
            with_cpu_id(value.clone(), Some(some.clone()))["cpu_id"],
            json!(some)
        );
        // 还没学到就一个字不加（服务端照旧用它自己派生的那个）。
        assert_eq!(with_cpu_id(value.clone(), None), value);
        // 调用方自己带着就不动（`get_device_id` 这类探针时手动指定的场合）。
        let explicit = json!({"op": "get_device_id", "cpu_id": "09000000aabbccddeeff001122334455"});
        assert_eq!(with_cpu_id(explicit.clone(), Some(some)), explicit);
        // 不是对象的请求照原样递过去，不能因为它把整条链路弄崩。
        assert_eq!(with_cpu_id(json!("nope"), None), json!("nope"));
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
    fn the_two_probe_names_default_to_the_local_backend() {
        for alias in [
            "chunqiu_soter_probe_1759500000000",
            "duckdetector_soter_probe_1759500000001",
        ] {
            let value = json!({"op": "init_sign", "uid": 10396, "alias": alias});
            assert!(
                local_only_match(&value, DEFAULT_LOCAL_ONLY_PREFIXES, "").is_some(),
                "{alias} 应当被本地兜底接住"
            );
        }
    }

    #[test]
    fn a_real_app_is_not_diverted() {
        // 微信自己那套别名一个字都不能碰（这台机器上是 uid 10490 的
        // `SoterAuthKeyV2_<salt>_scene1`）。
        let value = json!({
            "op": "init_sign",
            "uid": 10490,
            "alias": "SoterAuthKeyV2_salt11d8ba34_scene1",
        });
        assert_eq!(
            local_only_match(&value, DEFAULT_LOCAL_ONLY_PREFIXES, ""),
            None
        );
        // 没有别名的调用（`get_device_id` 这类）uid 没点名就不动。
        assert_eq!(
            local_only_match(
                &json!({"op": "get_device_id", "uid": 10490}),
                DEFAULT_LOCAL_ONLY_PREFIXES,
                ""
            ),
            None
        );
    }

    /// 探测别名出现过之后，紧跟着不带别名的 ASK 也按探测机处理（靠的是设备级的时间窗）。
    #[test]
    fn a_blank_alias_right_after_a_probe_alias_counts_as_a_probe() {
        assert!(alias_is_blank(
            &json!({"op": "has_ask_already", "uid": 10490})
        ));
        assert!(alias_is_blank(
            &json!({"op": "has_ask_already", "uid": 10490, "alias": "-"})
        ));
        assert!(alias_is_blank(
            &json!({"op": "has_ask_already", "uid": 10490, "alias": "  "})
        ));
        assert!(!alias_is_blank(
            &json!({"op": "init_sign", "alias": "SoterAuthKeyV2_salt1_scene1"})
        ));
        // 窗口本身是设备级的静态变量，测试之间共享，所以只断言「记一笔之后就是热的」
        // 这个方向，不去断言「没记过就是冷的」（别的测试可能刚记过）。
        note_probe_sighting();
        assert!(probe_recently_seen());
        assert!(!PROBE_WINDOW.is_zero());
    }

    /// 带没带真调用者包名，决定这几笔吃不吃上面那个时间窗。
    #[test]
    fn only_a_request_without_a_caller_package_uses_the_probe_window() {
        assert!(has_caller_pkg(&json!({"caller_pkg": "com.tencent.mm"})));
        assert!(has_caller_pkg(&json!({
            "op": "has_ask_already",
            "caller_pkg": "com.tencent.mm,com.tencent.mm:tools"
        })));
        // 空 / 全空格 / 类型不对都算没带。
        assert!(!has_caller_pkg(&json!({"caller_pkg": ""})));
        assert!(!has_caller_pkg(&json!({"caller_pkg": "   "})));
        assert!(!has_caller_pkg(&json!({"caller_pkg": 7})));
        assert!(!has_caller_pkg(&json!({"op": "has_ask_already"})));
    }

    /// 已经带了包名（或压根没带 uid）时，`with_caller_pkg` 不该去问系统 —— 这两条
    /// 路径不碰 AAID 服务，所以在宿主机上也能跑。
    #[test]
    fn an_existing_or_missing_caller_is_left_alone() {
        let already = json!({"op": "has_ask_already", "caller_pkg": "com.tencent.mm"});
        assert_eq!(with_caller_pkg(already.clone()), already);
        let no_uid = json!({"op": "has_ask_already", "uid": 10490});
        assert_eq!(with_caller_pkg(no_uid.clone()), no_uid);
        // uid 形状不对（负号、字符串）同样不动。
        for bad in [json!({"caller_uid": -5}), json!({"caller_uid": "x"})] {
            assert_eq!(with_caller_pkg(bad.clone()), bad);
        }
    }

    #[test]
    fn a_listed_uid_is_enough_without_an_alias() {
        // `has_ask_already` 这种调用没有别名，只能按 uid 认（uid 每台设备一套，
        // 所以这份名单是设备本地的）。
        let value = json!({"op": "has_ask_already", "uid": 10396, "alias": "-"});
        assert!(local_only_match(&value, "", "10396,10400").is_some());
        assert_eq!(local_only_match(&value, "", "10397"), None);
    }

    #[test]
    fn an_empty_or_none_list_diverts_nothing() {
        let value = json!({
            "op": "init_sign",
            "uid": 10396,
            "alias": "chunqiu_soter_probe_1",
        });
        for off in ["", "none", "off", "-", "  ", "NONE"] {
            assert_eq!(local_only_match(&value, off, ""), None, "{off:?}");
            assert_eq!(
                local_only_match(&json!({"op": "init_sign", "uid": 10396}), "", off),
                None,
                "{off:?}"
            );
        }
    }

    #[test]
    fn odd_spellings_of_the_lists_are_tolerated() {
        let value = json!({
            "op": "init_sign",
            "uid": 10396,
            "alias": "chunqiu_soter_probe_1",
        });
        // 逗号/分号/空格混着写、末尾多一个分隔符，都不该让整条名单失效。
        assert!(
            local_only_match(&value, "chunqiu_soter_probe_ ; duck_soter_probe_,", "").is_some()
        );
        assert!(local_only_match(&value, "  chunqiu_soter_probe_  ", "").is_some());
        // uid 名单里坏的那一项丢掉，好的还得留着。
        assert!(local_only_match(&value, "", "乱写, 10396").is_some());
        // 认的是前缀不是「包含」：别的前缀里夹着这个名字不算命中。
        assert_eq!(
            local_only_match(
                &json!({"op": "init_sign", "uid": 1, "alias": "SoterAuthKeyV2_chunqiu_soter_probe_x"}),
                DEFAULT_LOCAL_ONLY_PREFIXES,
                ""
            ),
            None
        );
    }

    /// 真机上手工跑的验证：把设备上那份真配置装进运行时配置，再拿真的探测别名走
    /// `local_only`（`forward()` 里就是这一步），确认它判成「本地兜底」、而微信那类真
    /// 应用的别名一个都判不出来。只读设备文件，不发请求、不改任何东西。
    ///
    /// ```text
    /// adb push <test-bin> /data/local/tmp/a-keymint-tests
    /// adb shell su -c '/data/local/tmp/a-keymint-tests --ignored --nocapture the_device_config'
    /// ```
    #[test]
    #[ignore = "读设备上的真配置（/data/misc/keystore/ommega/config），只在真机上手工跑"]
    fn the_device_config_diverts_detector_probes() {
        use crate::config::{self, ResolvedTrust, TrustValueSource};

        let config_file = config::bootstrap_config_file().expect("读设备配置");
        let trust = ResolvedTrust {
            os_version: 0,
            security_patch: String::new(),
            os_patchlevel: String::new(),
            vendor_patchlevel: String::new(),
            boot_patchlevel: String::new(),
            vb_key: [0u8; 32],
            vb_hash: [0u8; 32],
            vb_key_source: TrustValueSource::Original,
            vb_hash_source: TrustValueSource::Original,
            verified_boot_state: true,
            device_locked: true,
        };
        config::install_runtime_config(config_file, trust).expect("装上运行时配置");

        let (prefixes, uids, url, device_id) = {
            let cfg = config::config().read().expect("读运行时配置");
            (
                cfg.remote.soter_local_only_prefixes.clone(),
                cfg.remote.soter_local_only_uids.clone(),
                cfg.remote.url.clone(),
                cfg.remote.device_id.clone(),
            )
        };
        println!("设备配置 soter_local_only_prefixes = {prefixes:?}");
        println!("设备配置 soter_local_only_uids     = {uids:?}");
        println!("设备配置 url/device_id             = {url:?} / {device_id:?}");
        // url 和 device_id 只可能来自那份扁平配置，它们非空就说明文件真的被读进来了。
        assert!(!url.is_empty() && !device_id.is_empty(), "扁平配置没被读到");
        assert!(!list_disabled(&prefixes), "真配置把本地兜底名单关掉了");

        // 两台探测机的别名（名字是从生产服务端日志里抄回来的真的）。
        for alias in [
            "chunqiu_soter_probe_1791022575713",
            "duckdetector_soter_probe_1791022480012",
        ] {
            let value = json!({"op": "init_sign", "uid": 10388, "alias": alias});
            assert!(local_only(&value).is_some(), "{alias} 应当判成本地兜底");
        }

        // 真应用一个都不能碰。
        for alias in [
            "SoterAuthKeyV2_salt11d8ba34_scene1",
            "WechatAuthKeyPay&dx20079023",
            "SoterAuthKey_salt4add9b38_scene2",
        ] {
            let value = json!({"op": "init_sign", "uid": 10490, "alias": alias});
            assert_eq!(local_only(&value), None, "{alias} 不该被判成本地兜底");
        }

        // 没用别名、也没有 uid 名单的时候，光靠缺省前缀也得拦住（探测机的 op 里
        // `has_ask_already` 这类根本不给别名）。
        let no_uid = json!({"op": "init_sign", "alias": "duckdetector_soter_probe_1"});
        assert!(local_only(&no_uid).is_some(), "没有 uid 也要认前缀");

        // uid 名单是每台机器手写的（默认空），写了就必须一个不落地都拦住 —— 哪怕别名
        // 看着像微信的真钥匙（uid 命中就是命中，不必再看别名）。
        for uid in parse_number_list(&uids) {
            let value = json!({
                "op": "init_sign",
                "uid": uid,
                "alias": "SoterAuthKeyV2_salt11d8ba34_scene1",
            });
            assert!(local_only(&value).is_some(), "uid {uid} 在名单里却没拦住");
        }
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
