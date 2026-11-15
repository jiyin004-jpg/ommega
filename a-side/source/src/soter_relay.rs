//! A 端 SOTER 接替转发的决策端：宿主拦到一笔 HAL 调用后，由这里决定问远程、走本地还是透传。
//!
//! 决策必须在这儿：宿主是 uid 1000，读不到 A 端配置（`/data/misc/keystore/ommega` 是
//! 0770 的 keystore 目录）；daemon 盯着那个文件，WebUI 改完开关下一次调用就生效，不用重启。
//! 回给 payload 的 blob 布局在 `kmr_common::soter_relay`，两边共用那一份实现。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use kmr_common::soter_relay::{self, Outcome};
use serde_json::Value;

use crate::remote::{fallback_local, soter_remote_enabled, RemoteRelay};

/// 一笔 SOTER 调用的去处，`request` 是 payload 拼好的 JSON（`{"op":..,"uid":..}`）。
///
/// 认不出来的请求、远程没开、远程没答案，一律回退到「本地兜底」——这是唯一不会把宿主
/// 坑住的退路。
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

    // App 拿着脏缓存自删自建（见 `note_churn_and_maybe_heal`）：第 2 次删 AuthKey 就判。
    note_churn_and_maybe_heal(&value, &op);

    // 「SOTER 走远程」关着：本地自签兜底。与 KeyMint 的远程开关互不影响。
    if !soter_remote_enabled() {
        log::info!("event=soter relay op={op} soter remote disabled; using the local backend");
        return Outcome::Local.encode();
    }

    match RemoteRelay::soter(&request_value(&value, op.as_str())) {
        Ok(Some(reply)) => {
            // 服务端说「这笔你自己本地答」（白名单外/检测器一类）：它不造料、不占真机，
            // 把工作交给本机自己的 SOTER 能力。
            if reply.get("local_only").and_then(Value::as_bool) == Some(true) {
                log::info!("event=soter relay op={op} server asked for a local answer");
                return Outcome::Local.encode();
            }
            // Trustonic 在 ASK 已存在时会把重复的 generate 回 -5（ASK_NOT_READY），App 把
            // 它当成「ASK 没准备好」而一路自删自建。这里补查一次 has_ask_already：ASK 在
            // 就把这一笔改答成功，对 App 来说就是幂等的建料。
            let mut reply = reply;
            let mut code = reply.get("error_code").and_then(Value::as_i64).unwrap_or(0);
            if op == "generate_ask_key_pair" && code == -5 {
                if let Some(present) = relay_ask_present(&value) {
                    log::info!(
                        "event=soter relay op={op} -5 but has_ask_already=0; answering success (idempotent)"
                    );
                    reply = present;
                    code = 0;
                }
            }
            match encode_reply(&op, &reply) {
                Some(outcome) => {
                    log::info!(
                        "event=soter relay op={op} answered remotely code={code} out_bytes={}",
                        out_bytes(&outcome)
                    );
                    outcome.encode()
                }
                None => {
                    log::warn!(
                        "event=soter relay op={op} reply shape unrecognised; letting the real HAL answer"
                    );
                    Outcome::Passthrough.encode()
                }
            }
        }
        Ok(None) => no_remote_answer(&op, "no B-side answer"),
        Err(error) => no_remote_answer(&op, &format!("{error:#}")),
    }
}

// ---------------------------------------------------------------------------
// 自动自愈：App 拿着脏缓存「自删自建」
// ---------------------------------------------------------------------------

/// 同一槽位第几次「删 AuthKey」开始自愈。健康流程（微信开通）正常最多删一次，
/// 第 2 次（`> 1`）就是它在拿缓存里的旧状态打转，再等只会一直转。
const CHURN_HEAL_AT: u32 = 2;
/// 计数窗口。
const CHURN_WINDOW: Duration = Duration::from_secs(30);
/// 同一 uid 两次自愈之间的冷却：真出现「腾讯侧不认」时不能一直杀应用。
const HEAL_COOLDOWN: Duration = Duration::from_secs(600);

static CHURN: OnceLock<Mutex<HashMap<String, (u32, Instant)>>> = OnceLock::new();
static HEALED: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();

/// 只查「这个 uid 上有没有 ASK」，有就回一份成功答复。给 generate 的幂等用。
fn relay_ask_present(value: &Value) -> Option<Value> {
    let mut probe = value.clone();
    if let Some(obj) = probe.as_object_mut() {
        obj.insert(
            "op".to_string(),
            Value::String("has_ask_already".to_string()),
        );
        obj.remove("alias");
        obj.remove("challenge");
        obj.remove("session");
    }
    let body = request_value(&probe, "has_ask_already");
    match RemoteRelay::soter(&body) {
        Ok(Some(mut reply)) => {
            let present = reply
                .get("error_code")
                .and_then(Value::as_i64)
                .unwrap_or(-1);
            if present == 0 {
                if let Some(obj) = reply.as_object_mut() {
                    obj.insert("error_code".to_string(), serde_json::json!(0));
                }
                Some(reply)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// 这一笔是不是「自删自建」；是且到了第 2 次就起线程把应用和槽位重置掉。
///
/// 必须重置**应用侧的缓存**：微信把「ASK / AuthKey 已存在」记在
/// `shared_prefs/soter_status.xml` 里，一旦写上就永远跳过「生成 ASK → 上报腾讯」，只清
/// B 上的料它也不理（分身是另一份 app 数据，没有这份缓存）。
///
/// 重置三件事：`am force-stop <pkg>`（先停，免得退出时把缓存写回去）→ 备份并删掉
/// `shared_prefs/soter_status.xml`（主用户 + 分身目录）→ 让 B 清空该 uid 的料
/// （带 `force_scope_wipe`，绕过服务端「多账号不清」的保护）。
fn note_churn_and_maybe_heal(value: &Value, op: &str) {
    if !matches!(op, "remove_auth_key" | "remove_all_uid_key") {
        return;
    }
    let Some(uid) = value.get("uid").and_then(Value::as_i64) else {
        return;
    };
    let pkg = value
        .get("caller_pkg")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if pkg.is_empty() {
        // 拿不到包名就不去动别人的数据。
        return;
    }
    let key = format!("{pkg}|{uid}");
    let now = Instant::now();
    let count = {
        let map = CHURN.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, (_, at)| now.duration_since(*at) <= CHURN_WINDOW);
        let entry = guard.entry(key.clone()).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        entry.0
    };
    if count < CHURN_HEAL_AT {
        return;
    }
    // 冷却：同一 uid 十分钟内只救一次。
    {
        let map = HEALED.get_or_init(|| Mutex::new(HashMap::new()));
        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|_, at| now.duration_since(*at) <= HEAL_COOLDOWN);
        if guard.contains_key(&key) {
            return;
        }
        guard.insert(key.clone(), now);
    }
    if let Ok(mut guard) = CHURN.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        guard.remove(&key);
    }
    log::warn!(
        "event=soter selfheal pkg={pkg} uid={uid} 第 {count} 次删 AuthKey —— \
         App 拿着缓存自删自建，自动重置一次（停应用 + 删 soter_status.xml + 清 B 槽位）"
    );
    let pkg_for_thread = pkg.clone();
    std::thread::Builder::new()
        .name("soter-selfheal".to_string())
        .spawn(move || {
            if let Err(error) = heal_soter_slot(&pkg_for_thread, uid) {
                log::warn!("event=soter selfheal failed pkg={pkg_for_thread} uid={uid}: {error:#}");
            }
        })
        .ok();
}

/// 把一个应用的 SOTER 缓存和 B 上的槽位一起重置。见 [`note_churn_and_maybe_heal`]。
fn heal_soter_slot(pkg: &str, uid: i64) -> anyhow::Result<()> {
    // 1) 停应用（不重新拉起：让用户自己点开通，那时缓存已经是空的）
    let _ = std::process::Command::new("/system/bin/am")
        .args(["force-stop", pkg])
        .status();
    // 2) 删缓存：主用户 + 所有分身用户
    let mut paths = vec![format!("/data/data/{pkg}/shared_prefs/soter_status.xml")];
    for user in 0..10 {
        paths.push(format!(
            "/data/user/{user}/{pkg}/shared_prefs/soter_status.xml"
        ));
    }
    let mut removed = 0usize;
    let mut failed = 0usize;
    for path in paths {
        if !std::path::Path::new(&path).exists() {
            continue;
        }
        let _ = std::fs::copy(&path, format!("{path}.bak"));
        match std::fs::remove_file(&path) {
            Ok(()) => {
                removed += 1;
                log::info!("event=soter selfheal removed {path}");
            }
            Err(error) => {
                failed += 1;
                log::warn!("event=soter selfheal cannot remove {path}: {error}");
            }
        }
    }
    // 本地脏缓存没清掉就别去动 B 的料：payload 跑在 keystore uid 下，删
    // /data/data/<pkg> 是跨应用操作、基本都会被挡；只清 B 会把 App 上还可用的钥匙
    // 清掉再进 10 分钟冷却，比不修更糟。
    if removed == 0 && failed > 0 {
        log::warn!(
            "event=soter selfheal cannot clear local cache for {pkg}; leaving the B slot alone"
        );
        return Ok(());
    }
    // 3) 清 B 上的槽位（带 force_scope_wipe，服务端只对这一笔放行）
    let body = serde_json::json!({
        "op": "remove_all_uid_key",
        "uid": uid,
        "force_scope_wipe": true,
    });
    if crate::remote::soter_remote_enabled() {
        match RemoteRelay::soter(&body) {
            Ok(_) => log::info!("event=soter selfheal cleared B slot uid={uid}"),
            Err(error) => {
                log::warn!("event=soter selfheal clear B slot failed uid={uid}: {error:#}")
            }
        }
    } else {
        log::info!("event=soter selfheal skip clearing B slot uid={uid}: soter remote disabled");
    }
    Ok(())
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

/// uid → 包名 + 缓存时刻。
type CallerNames = std::sync::Mutex<Vec<(u32, std::time::Instant, Option<String>)>>;
static CALLER_NAMES: CallerNames = std::sync::Mutex::new(Vec::new());

/// uid → 包名（逗号连起来），带短缓存。
fn caller_package_for_uid(uid: i64) -> Option<String> {
    // 翻成功缓存一分钟，翻不出来只缓存几秒。
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
    // 一行诊断：payload 是否自带 caller_pkg、请求里有没有 uid、内核 uid 那格有没有。
    log::info!(
        "event=soter caller in op={} uid={:?} caller_uid={:?} caller_pkg={:?} src={:?}",
        value.get("op").and_then(Value::as_str).unwrap_or("-"),
        value.get("uid"),
        value.get(CALLER_UID_FIELD),
        value.get(CALLER_PKG_FIELD),
        value.get("caller_pkg_src"),
    );
    if has_caller_pkg(&value) {
        return value;
    }
    let app_uid = value.get("uid").and_then(Value::as_i64);
    let pkg = value
        .get(CALLER_UID_FIELD)
        .and_then(Value::as_i64)
        .and_then(caller_package_for_uid)
        .or_else(|| {
            // 独立 HAL 模式下内核给的调用者是 soterserver，退一级用 SOTER 参数里的 App uid。
            app_uid.and_then(caller_package_for_uid)
        })
        .or_else(|| {
            // 两个都没有：用 root 侧写的「当前前台应用」兜底。这一步必须放在这里 ——
            // 没有 `caller_uid` 是更早的 return，接在别处就永远走不到。
            crate::plat::utils::foreground_package().inspect(|pkg| {
                log::info!("event=soter caller 用前台应用兜底 -> {pkg}");
            })
        });
    let Some(pkg) = pkg else {
        return value;
    };
    if let Some(map) = value.as_object_mut() {
        map.insert(CALLER_PKG_FIELD.to_string(), Value::from(pkg));
    }
    value
}

/// 远程没给出答案时：`fallback_local` 为真就本地自签，否则放给真 HAL。
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

/// SOTER uid 替身映射（`soter_uid_map: 10490=10373`，逗号/分号/空格分隔多条，
/// `=` 也可以写成 `:` 或 `->`）。没配就不动。
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
/// 真机 cpu_id 带上。换成功了记一行 info —— 拿 A 的 uid 去问 B 得到的是「没有」，
/// 换完才拿得到真材料，这条日志是区分这两种情况的唯一依据。
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
/// `error_code` 是必定有的状态码；`data` 是 base64 的 out 参数（只在成功、且属于
/// `answers_with_data` 的那几个 op 上有）；`init_sign` 另有 `session`。
fn encode_reply(op: &str, reply: &Value) -> Option<Outcome> {
    let code = reply.get("error_code").and_then(Value::as_i64)? as i32;

    if soter_relay::answers_with_session(op) {
        let session = match reply.get("session").and_then(Value::as_i64) {
            Some(session) => session,
            // 答了成功却没有会话号：这张会话在 TA 里根本没建起来（服务端对同一形状也是
            // 这个判据，还额外要求 session != 0）。撒成 status=0/session=0 等于递一个假
            // 成功给 App，走到 finish_sign 才报错，本该在这里走透传/本地兜底的分支就吃不到了。
            None if code == 0 => return None,
            // 失败码本来就没有会话号，保留原状态码。
            None => 0,
        };
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
    // `get_device_id`：真机 / SDK 给的是 **32 字符 hex 文本**（有的还跟一个 NUL），而检测器
    // 要的是 16 字节原始值（转 hex 后跟 `cpu_id` 比）。已经是 16 字节的原样放过，幂等。
    let data = if op == "get_device_id" {
        match data.as_deref().and_then(hex_text_32) {
            Some(raw) => Some(raw),
            None => data,
        }
    } else {
        data
    };
    Some(Outcome::Buffer { code, data })
}

/// 32 字符 hex 文本 → 16 字节；容一个尾随 NUL（部分厂商 TA 会带）。其余一律 `None`。
fn hex_text_32(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = core::str::from_utf8(bytes).ok()?.trim_end_matches('\0');
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(16);
    let mut i = 0;
    while i < 32 {
        out.push(u8::from_str_radix(&text[i..i + 2], 16).ok()?);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 真机拿回来的应答，字段名和形状都是服务端真实输出。
    #[test]
    fn a_device_id_answer_is_16_raw_bytes() {
        // 服务端回 16 字节 raw；检测器的 getDeviceId 期望 16 字节，转 hex 后再跟 cpu_id 比。
        let reply = json!({
            "data": "CQAAAFFxc0xChmvqFIsh9Q==",
            "error_code": 0,
            "length": 16,
            "op": "get_device_id"
        });
        let outcome = encode_reply("get_device_id", &reply).expect("a real reply must map");
        assert_eq!(
            outcome,
            Outcome::Buffer {
                code: 0,
                data: Some(vec![
                    0x09, 0x00, 0x00, 0x00, 0x51, 0x71, 0x73, 0x4c, 0x42, 0x86, 0x6b, 0xea, 0x14,
                    0x8b, 0x21, 0xf5,
                ]),
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
        // 不是对象的请求照原样递过去。
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
