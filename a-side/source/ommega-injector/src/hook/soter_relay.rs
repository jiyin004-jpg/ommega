//! A 端 SOTER 接替转发的客户端半边：把 HAL 调用交给 daemon，把它的结论翻成本地那套
//! `Answer`。
//!
//! 开关（WebUI 的「是否远程」/ `local_hw`）由 daemon 读 —— 宿主是 uid 1000，那份配置在
//! 0770 的 keystore 目录里，我们打不开（`debug_logging` 就是为此另做了一份 `log_flag`
//! 副本）。所以这里只认 daemon 回的三种结论，blob 布局见 `kmr_common::soter_relay`。
//!
//! 拿不到结论（老版本 daemon、daemon 挂了、答复形状不认识）一律退回本地自签：那是接线
//! 之前的行为，也是唯一不会把宿主坑在「等一笔永远不来的答复」上的退路。

use kmr_common::soter_relay::{self, Outcome};
use log::debug;

use crate::hook::soter::SoterCall;
use crate::hook::soter_local::{self, Answer};

/// 这笔 HAL 调用该由谁答。`None` = 我们别答，放它去真 HAL。
///
/// 返回 `None` 时调用方 `intercept_soter_call` 会照老路透传，宿主不会卡住。
pub(crate) fn answer(call: &SoterCall) -> Option<Answer> {
    if !call.hal {
        return None;
    }
    match resolve(call) {
        Outcome::Code(code) => Some(Answer::Code(code)),
        Outcome::Buffer { code, data } => Some(Answer::Buffer { code, data }),
        Outcome::Init { status, session } => Some(Answer::Init { status, session }),
        // daemon 说用本地那套：本地也答不了（参数不够之类）就顺势透传。
        Outcome::Local => soter_local::answer(call),
        Outcome::Passthrough => None,
    }
}

/// 问 daemon 这笔该怎么答。
///
/// 只能由 daemon 决定走真机、服务端还是本地兜底 —— 它才是看「远程 keymint」开关和
/// 真应用名单的那一方（宿主读不到上那份 0770 的配置）。所以**问不到的时候不能默认
/// 本地**：白名单内的真应用本该由 B 签，一旦这里偷偷拿 A 端自己的料签，同一轮里
/// `cpu_id` 和密钥就会一半来自 A、一半来自 B（检测器的 C5b / T10 就是这么红的）。
fn resolve(call: &SoterCall) -> Outcome {
    let Some(request) = request(call) else {
        // 号码不在转发表里（空号、app 侧那套号码）：老规矩，本地能答就本地答。
        return Outcome::Local;
    };
    // 只读 op 的短 TTL 缓存：微信一轮支付会把 has_auth_key / export_* 反复问好几遍，
    // 每次都走一趟 B（那边偶发三秒多的抖动），而答案几秒内不会变。写操作来了直接清空。
    let cache_key = cache_slot(call);
    if let Some(key) = cache_key.as_deref() {
        if let Some(blob) = cache_get(key) {
            return Outcome::decode(&blob).unwrap_or(Outcome::Passthrough);
        }
    }
    let blob = match crate::ipc::forward_soter(&request) {
        Ok(blob) => blob,
        Err(error) => {
            debug!(
                "event=soter relay unavailable ({error:#}); passing through instead of \
                 signing locally"
            );
            return Outcome::Passthrough;
        }
    };
    let outcome = Outcome::decode(&blob).unwrap_or(Outcome::Passthrough);
    match cache_key {
        Some(key) => cache_put(&key, &blob, &outcome),
        None => cache_clear(),
    }
    outcome
}

/// 只读 op 的缓存槽名；写 op / 签名类返回 `None`（同时意味着要清缓存）。
fn cache_slot(call: &SoterCall) -> Option<String> {
    // 1.7.4 加的只读 op 本地缓存先关掉：微信开通一轮里会反复问 has_ask_already /
    // export_ask_public_key，而它自己又在清场重建。缓存把「清场前那把 ASK」多续三秒，
    // 微信拿到的一直是旧钥匙，比不过就再清一轮 —— 表现就是建了立刻删。
    // 1.7.3 没有这个缓存，先回到那个行为。
    let _ = call;
    return None;
    #[allow(unreachable_code)]
    let op = soter_relay::op_for_code(call.code)?;
    let readable = matches!(
        op,
        "has_auth_key" | "has_ask_already" | "export_ask_public_key" | "export_auth_key_public_key"
    );
    if !readable {
        return None;
    }
    let uid = call.uid.unwrap_or(-1);
    let alias = call.alias.as_deref().unwrap_or("");
    Some(format!("{op}|{uid}|{alias}"))
}

/// 缓存条目：原始答复字节 + 写入时刻。
type ReadCache =
    std::sync::Mutex<Option<std::collections::HashMap<String, (std::time::Instant, Vec<u8>)>>>;
static READ_CACHE: ReadCache = std::sync::Mutex::new(None);
/// 只读答复在几秒内不会变；再长就会让「刚建的钥匙」看起来还不存在。
const READ_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3);

fn cache_get(key: &str) -> Option<Vec<u8>> {
    let mut guard = READ_CACHE.lock().ok()?;
    let map = guard.as_mut()?;
    match map.get(key) {
        Some((at, blob)) if at.elapsed() <= READ_CACHE_TTL => Some(blob.clone()),
        Some(_) => {
            map.remove(key);
            None
        }
        None => None,
    }
}

fn cache_put(key: &str, blob: &[u8], outcome: &Outcome) {
    // 只缓存「成功且非空」的答复：失败码（比如 -8 没这把钥匙）不能存，
    // 否则刚生成的钥匙会被旧答案盖住。
    let ok = matches!(outcome, Outcome::Buffer { code, .. } if *code == 0)
        || matches!(outcome, Outcome::Code(0));
    let mut guard = match READ_CACHE.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    if !ok {
        map.remove(key);
        return;
    }
    if map.len() > 256 {
        map.clear();
    }
    map.insert(key.to_string(), (std::time::Instant::now(), blob.to_vec()));
}

fn cache_clear() {
    if let Ok(mut guard) = READ_CACHE.lock() {
        if let Some(map) = guard.as_mut() {
            map.clear();
        }
    }
}

/// 拼 daemon 要的 JSON。号码不在转发表里返回 `None`（不转发）。
///
/// `uid` / `session` 是数字，`alias` / `challenge` 是字符串；`challenge` 原样传宿主给的
/// 那个十六进制串，服务端/B 端会直接写进 HAL 的 String16，**不要**在这边解码（只有本地
/// 兜底那条路才需要 hex 解码）。哪些号码带哪些参数由 `soter::parse` 定，这里照抄。
fn request(call: &SoterCall) -> Option<String> {
    request_with_table(call, None)
}

/// 拼 JSON 的本体。`table` 是给测试的假 uid→包名 表；`None` 表示读真表，并允许退回前台
/// 应用兜底（测试那条路不碰真文件，也不拿前台应用顶替）。
fn request_with_table(call: &SoterCall, table: Option<&str>) -> Option<String> {
    let op = soter_relay::op_for_code(call.code)?;
    let mut out = String::from("{\"op\":");
    push_json_string(&mut out, op);
    if let Some(uid) = call.uid {
        out.push_str(",\"uid\":");
        out.push_str(&uid.to_string());
    }
    if let Some(alias) = call.alias.as_deref() {
        out.push_str(",\"alias\":");
        push_json_string(&mut out, alias);
    }
    if let Some(challenge) = call.challenge.as_deref() {
        out.push_str(",\"challenge\":");
        push_json_string(&mut out, challenge);
    }
    if let Some(session) = call.session {
        out.push_str(",\"session\":");
        out.push_str(&session.to_string());
    }
    // 真调用者是谁（App 侧事务头里内核填的 sender_euid）。取不到就不带：daemon 翻不出
    // 包名、服务端就退回别名/槽位那套老判据，跟旧 payload 一个样。
    //
    // 包名也在这边自己翻一份带上。为什么在这边翻：实测有的机器（小米那台）SOTER 根本不走
    // daemon 那段转发（daemon 侧的翻名代码一次都没跑到），服务端就一直收到 `caller_pkg=-`、
    // 认不出这是真应用。表是 root 侧 daemon-injector 写的世界可读副本，宿主域读得到。
    //
    // 查表只认 `caller_uid`（内核填的 sender_euid，伪造不了），**不认请求里的 `uid`** ——
    // 那个是应用自己填的参数，探测机（春秋/鸭子）故意填假 uid 试我们，拿它翻名就会把假 uid
    // 撞上的那个包当成真调用者，服务端可能因此把探测机当真应用派给真机。取不到 caller_uid
    // 就不带包名，跟旧 payload 一个样。
    if let Some(uid) = call.caller_uid {
        out.push_str(",\"caller_uid\":");
        out.push_str(&uid.to_string());
        let pkg = match table {
            Some(table) => lookup_in_table(table, uid as u32),
            None => caller_package_for_uid(uid as u32),
        };
        log::info!(
            "event=soter caller uid={uid} pkg={}",
            pkg.as_deref().unwrap_or("-")
        );
        if let Some(pkg) = pkg {
            out.push_str(",\"caller_pkg\":");
            push_json_string(&mut out, &pkg);
        }
    } else if let Some(uid) = call.uid.filter(|uid| *uid > 0) {
        // 没有内核给的 sender_euid：我们接管的是 HAL 层，到这里调用方已经是
        // soterserver（系统进程），App 的身份早就不在 binder 头里了。只能拿 SOTER 参数
        // 里那个 uid（App 自己填的）翻一把。它**不可信** —— 探测机（春秋/鸭子）故意填
        // 假 uid —— 所以必须带 `caller_pkg_src=arg`：服务端只拿它做负向判断（包名不在
        // 真应用白名单就服务端作答、不落 B），绝不用它放行真机。
        let pkg = match table {
            Some(table) => lookup_in_table(table, uid as u32),
            None => caller_package_for_uid(uid as u32),
        };
        log::info!(
            "event=soter arg uid={uid} pkg={}",
            pkg.as_deref().unwrap_or("-")
        );
        if let Some(pkg) = pkg {
            out.push_str(",\"caller_pkg\":");
            push_json_string(&mut out, &pkg);
            out.push_str(",\"caller_pkg_src\":\"arg\"");
        }
    }
    out.push('}');
    Some(out)
}

/// root 侧（`daemon-injector`）写的世界可读副本：一行 `<uid> <包名>`。
///
/// 为什么不用那个 0770 的 keystore 目录：宿主域（指纹进程/应用）打不开它。
const UID_TABLE_FALLBACK: &str = "/data/misc/ommega/uid_packages";
/// 表只在装/卸应用时变，缓存一分钟；前台那份短一点，别拿刚才那个应用去顶现在这笔。
const UID_TABLE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// `uid` → 包名（共享 uid 会好几个，逗号连起来）。表里没有就返回 `None`。
///
/// 不在这一层套前台应用：以前翻不到就套一个当前前台应用的名字带上去，而 daemon 那边
/// 看到「已经有 caller_pkg」就不自己翻了——于是前台恰好是别的 App 时，真应用被判成
/// 探测机（实测 SoterChecker 被当成 bin.mt.plus / com.tencent.mobileqq）。
///
/// 前台应用作为兜底保留，但只放在 daemon 那条链的最后一级（它那边能看到更多：AAID
/// 服务、packages.list、多用户/分身号），本层拿不到就不带，让 daemon 继续试。
fn caller_package_for_uid(uid: u32) -> Option<String> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Option<(std::time::Instant, String)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock().ok()?;
    if let Some((at, table)) = guard.as_ref() {
        if at.elapsed() < UID_TABLE_TTL {
            return lookup_in_table(table, uid);
        }
    }
    let table = std::fs::read_to_string(UID_TABLE_FALLBACK).ok()?;
    let hit = lookup_in_table(&table, uid);
    *guard = Some((std::time::Instant::now(), table));
    hit
}

/// 在表里找这个 uid：行形如 `10339 com.tencent.mm`，可能有多个包，逗号连起来。
fn lookup_in_table(table: &str, uid: u32) -> Option<String> {
    let mut hits: Vec<&str> = Vec::new();
    for line in table.lines() {
        let mut fields = line.split_whitespace();
        let Some(id) = fields.next() else { continue };
        let Some(name) = fields.next() else { continue };
        if id.parse::<u32>() == Ok(uid) && !name.starts_with('#') {
            hits.push(name);
        }
    }
    if hits.is_empty() {
        None
    } else {
        Some(hits.join(","))
    }
}

/// 前台应用兜底只在 daemon 那边做（`src/soter_relay.rs` 的第三级）。这一层不再走：
/// 以前它翻不到 uid 就拿前台应用的名字当 caller_pkg 发出去，而 daemon 看到已经有值就
/// 不自己翻了——前台恰好是别的 App 时，真应用被安上别人的包名（实测 SoterChecker 被
/// 当成 bin.mt.plus / com.tencent.mobileqq），整轮退回本地。
///
/// `/data/misc/ommega/foreground` 那份副本也不再读，留给 daemon 用。
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(
        code: u32,
        uid: Option<i32>,
        alias: Option<&str>,
        challenge: Option<&str>,
    ) -> SoterCall {
        SoterCall {
            hal: true,
            hidl: false,
            // 这些测试只看请求怎么拼，跟回包那一格无关，随手取高通那套。
            has_return_code: true,
            code,
            wire_code: code,
            op: "test",
            uid,
            alias: alias.map(str::to_string),
            challenge: challenge.map(str::to_string),
            session: None,
            key: None,
            caller_uid: None,
            data_size: 0,
        }
    }

    #[test]
    fn a_no_argument_call_sends_only_the_op() {
        assert_eq!(
            request(&call(8, None, None, None)).as_deref(),
            Some("{\"op\":\"get_device_id\"}")
        );
    }

    #[test]
    fn a_uid_call_sends_the_uid_as_a_number() {
        assert_eq!(
            request(&call(9, Some(10490), None, None)).as_deref(),
            Some("{\"op\":\"has_ask_already\",\"uid\":10490}")
        );
    }

    #[test]
    fn an_alias_call_keeps_the_ampersand_alias() {
        assert_eq!(
            request(&call(10, Some(10490), Some("WechatAuthKeyPay&WANGXY0051012"), None)).as_deref(),
            Some("{\"op\":\"has_auth_key\",\"uid\":10490,\"alias\":\"WechatAuthKeyPay&WANGXY0051012\"}")
        );
    }

    #[test]
    fn init_sign_passes_the_hex_challenge_through_undecoded() {
        assert_eq!(
            request(&call(11, Some(10490), Some("SoterAuthKeyV2_salt11d8ba34_scene1"), Some("0a1b2c3d"))).as_deref(),
            Some("{\"op\":\"init_sign\",\"uid\":10490,\"alias\":\"SoterAuthKeyV2_salt11d8ba34_scene1\",\"challenge\":\"0a1b2c3d\"}")
        );
    }

    #[test]
    fn finish_sign_sends_the_session() {
        let mut call = call(4, None, None, None);
        call.session = Some(0x0123_4567_89ab_cdef);
        assert_eq!(
            request(&call).as_deref(),
            Some("{\"op\":\"finish_sign\",\"session\":81985529216486895}")
        );
    }

    /// 解析出真调用者 uid 之后，转发 JSON 里得带上它，包名也从**这个** uid 翻出来。
    #[test]
    fn a_resolved_caller_uid_rides_along_in_the_request() {
        let mut call = call(11, Some(10490), Some("SoterAuthKey"), Some("0a1b"));
        call.caller_uid = Some(10490);
        assert_eq!(
            request_with_table(&call, Some("10490 com.tencent.mm\n")).as_deref(),
            Some(
                "{\"op\":\"init_sign\",\"uid\":10490,\"alias\":\"SoterAuthKey\",\"challenge\":\"0a1b\",\"caller_uid\":10490,\"caller_pkg\":\"com.tencent.mm\"}"
            )
        );
    }

    /// 表里没有这个 caller_uid 就干脆不带包名（服务端退回别名/槽位那套老判据）。
    #[test]
    fn a_caller_uid_missing_from_the_table_sends_no_package() {
        let mut call = call(11, Some(10490), Some("SoterAuthKey"), Some("0a1b"));
        call.caller_uid = Some(10490);
        assert_eq!(
            request_with_table(&call, Some("10339 com.other.app\n")).as_deref(),
            Some(
                "{\"op\":\"init_sign\",\"uid\":10490,\"alias\":\"SoterAuthKey\",\"challenge\":\"0a1b\",\"caller_uid\":10490}"
            )
        );
    }

    /// **不拿请求里那个 `uid` 翻包名**：那是应用填的，探测机就靠伪造它来试我们。
    #[test]
    fn the_request_uid_is_never_used_for_the_package_lookup() {
        let call = call(11, Some(10490), Some("SoterAuthKey"), Some("0a1b"));
        assert_eq!(
            request_with_table(&call, Some("10490 com.tencent.mm\n")).as_deref(),
            Some("{\"op\":\"init_sign\",\"uid\":10490,\"alias\":\"SoterAuthKey\",\"challenge\":\"0a1b\"}")
        );
    }

    /// 没解出调用者就一个字都不多带（旧 payload / 没有 App 侧事务时就是这个形状）。
    #[test]
    fn an_unresolved_caller_adds_no_field() {
        assert_eq!(
            request(&call(9, Some(10490), None, None)).as_deref(),
            Some("{\"op\":\"has_ask_already\",\"uid\":10490}")
        );
    }

    #[test]
    fn reserved_hal_numbers_are_not_forwarded() {
        for reserved in [0, 2, 6, 14, 15, 99] {
            assert_eq!(
                request(&call(reserved, Some(1), None, None)),
                None,
                "code {reserved}"
            );
        }
    }

    #[test]
    fn every_number_in_the_relay_table_is_forwarded() {
        for (code, _) in soter_relay::HAL_OPS {
            assert!(
                request(&call(code, Some(7), Some("a"), Some("b"))).is_some(),
                "code {code} must build a request"
            );
        }
    }

    #[test]
    fn a_quote_in_an_alias_cannot_break_the_json() {
        let mut out = String::new();
        push_json_string(&mut out, "a\"b\\c\nd\te\u{1}");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\\u0001\"");
    }
}
