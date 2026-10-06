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

/// 问 daemon 这笔该怎么答。问不到一律按本地兜底处理。
fn resolve(call: &SoterCall) -> Outcome {
    let Some(request) = request(call) else {
        // 号码不在转发表里（空号、app 侧那套号码）：老规矩，本地能答就本地答。
        return Outcome::Local;
    };
    let blob = match crate::ipc::forward_soter(&request) {
        Ok(blob) => blob,
        Err(error) => {
            debug!("event=soter relay unavailable ({error:#}); using the local backend");
            return Outcome::Local;
        }
    };
    Outcome::decode(&blob).unwrap_or(Outcome::Local)
}

/// 拼 daemon 要的 JSON。号码不在转发表里返回 `None`（不转发）。
///
/// `uid` / `session` 是数字，`alias` / `challenge` 是字符串；`challenge` 原样传宿主给的
/// 那个十六进制串，服务端/B 端会直接写进 HAL 的 String16，**不要**在这边解码（只有本地
/// 兜底那条路才需要 hex 解码）。哪些号码带哪些参数由 `soter::parse` 定，这里照抄。
fn request(call: &SoterCall) -> Option<String> {
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
    if let Some(uid) = call.caller_uid {
        out.push_str(",\"caller_uid\":");
        out.push_str(&uid.to_string());
    }
    // 包名自己翻一份带上。为什么在这边翻：实测有的机器（小米那台）SOTER 根本不走 daemon
    // 那段转发（daemon 侧的翻名代码一次都没跑到），服务端就一直收到 `caller_pkg=-`、
    // 认不出这是真应用。这里直接拿 `uid`（= 要钥匙的那个应用，微信就是 10339）自己查表：
    // 表是 root 侧 daemon-injector 写的世界可读副本，宿主域读得到。
    if let Some(uid) = call.uid {
        let pkg = caller_package_for_uid(uid as u32);
        log::info!(
            "event=soter caller uid={uid} pkg={}",
            pkg.as_deref().unwrap_or("-")
        );
        if let Some(pkg) = pkg {
            out.push_str(",\"caller_pkg\":");
            push_json_string(&mut out, &pkg);
        }
    }
    out.push('}');
    Some(out)
}

/// root 侧（`daemon-injector`）写的世界可读副本：一行 `<uid> <包名>`。
///
/// 为什么不用那个 0770 的 keystore 目录：宿主域（指纹进程/应用）打不开它。
const UID_TABLE_FALLBACK: &str = "/data/misc/ommega/uid_packages";
/// 同一份内容的前台应用副本：一行 `<epoch 秒> <包名>`，翻不到 uid 时用它兜底。
const FOREGROUND_FALLBACK: &str = "/data/misc/ommega/foreground";
/// 表只在装/卸应用时变，缓存一分钟；前台那份短一点，别拿刚才那个应用去顶现在这笔。
const UID_TABLE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// `uid` → 包名（共享 uid 会好几个，逗号连起来）。表里没有就退回前台应用。
fn caller_package_for_uid(uid: u32) -> Option<String> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Option<(std::time::Instant, String)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut guard = cache.lock().ok()?;
    if let Some((at, table)) = guard.as_ref() {
        if at.elapsed() < UID_TABLE_TTL {
            if let Some(pkg) = lookup_in_table(table, uid) {
                return Some(pkg);
            }
            return foreground_package();
        }
    }
    let table = std::fs::read_to_string(UID_TABLE_FALLBACK).ok()?;
    let hit = lookup_in_table(&table, uid);
    *guard = Some((std::time::Instant::now(), table));
    hit.or_else(foreground_package)
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

/// 前台应用兜底。文件超过 20 秒就算陈旧（写侧每 ~10 秒刷一次）。
fn foreground_package() -> Option<String> {
    let text = std::fs::read_to_string(FOREGROUND_FALLBACK).ok()?;
    let mut fields = text.split_whitespace();
    let at = fields.next()?.parse::<u64>().ok()?;
    let pkg = fields.next()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    if now.saturating_sub(at) > 20 || pkg == "-" {
        return None;
    }
    Some(pkg.to_string())
}

/// 拼一个 JSON 字符串字面量。alias 里有 `&`、challenge 是十六进制，正常都不带引号，
/// 但转发的东西不能靠「正常」活着，该转义的都转义 —— 拼坏了 daemon 那边直接拒收。
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

    /// 解析出真调用者 uid 之后，转发 JSON 里得带上它（包名由 daemon 翻）。
    #[test]
    fn a_resolved_caller_uid_rides_along_in_the_request() {
        let mut call = call(11, Some(10490), Some("SoterAuthKey"), Some("0a1b"));
        call.caller_uid = Some(10490);
        assert_eq!(
            request(&call).as_deref(),
            Some(
                "{\"op\":\"init_sign\",\"uid\":10490,\"alias\":\"SoterAuthKey\",\"challenge\":\"0a1b\",\"caller_uid\":10490}"
            )
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
