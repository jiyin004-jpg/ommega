//! 微信「指纹支付开通」那套流程的等价重写。
//!
//! 为什么要自己写一遍：开通这一步的行为全在微信 dex 里（8.0.79 的 classes13/14.dex，
//! 包名被混淆成 `f46` / `s36` / `w36` / `x36` / `y36` 这些），我们只能从外面看日志猜它
//! 在哪一步放弃。这里按反出来的顺序把同一串 HAL 调用重放一遍，每一步都照着**它自己的
//! 判据**检查答复，于是「哪一步因为答了什么被判成失败」能直接摆出来，不用再猜。
//!
//! # 微信那边到底在干什么（8.0.79）
//!
//! 入口是 `ym4.b`（SOTER 初始化 func）：它造一个 `f46.m`（`extends f46.n0`，即 TaskInit），
//! 场景号 `{1, 2, 920, 3}`、ASK 名固定 `WechatASK`，然后把它塞进 `f46.n`（任务队列）。
//! 任务按类型串起来：
//!
//! | 微信的类 | 干的事 |
//! |---|---|
//! | `f46.n0` / `f46.l0` | TaskInit：绑 `com.tencent.soter.soterserver`，探本机支不支持 |
//! | `ym4.m`（`n0` 子类） | 把场景号翻成别名：`SoterAuthKeyV2_salt%s_scene%d` |
//! | `f46.q0` | TaskPrepareAppSecureKey 的前置判断（要不要建 ASK） |
//! | `f46.o0` / `f46.p0` | 建完 ASK → 上报腾讯 → 看结果 |
//! | `f46.u0` | TaskPrepareAuthKey 的前置判断（要不要建 AuthKey） |
//! | `f46.s0` / `f46.t0` | 建完 AuthKey → 上报腾讯 → 看结果 |
//! | `f46.z` / `f46.k0` | TaskAuthentication：弹指纹圈，initSign / finishSign |
//! | `y36.b` | SoterWrapperApi，业务侧就调它 |
//! | `w36.j` | SoterCore 的 TREBLE 实现，真正发 AIDL 的地方 |
//! | `s36.a` | SoterCore 门面（`h()` 有没有 ASK / `j()` ASK 能不能用 / `r()` 删 ASK …） |
//!
//! `w36.j` 里 `com.tencent.soter.soterserver.ISoterService` 的码位（跟我们那套 HAL 号
//! 不是一回事，别混）：1 generateAppSecureKey / 2 getAppSecureKey / 3 hasAskAlready /
//! 4 generateAuthKey / 5 removeAuthKey / 6 getAuthKey / 7 removeAllUidKey / 8 hasAuthKey /
//! 9 initSigh / 10 finishSign / 13 getExtraParam。
//!
//! # 三个判据，决定了「为什么明明有料它还要重走」
//!
//! 1. **ASK 能用** = `hasAskAlready(uid) == 0` **且** `getAppSecureKey(uid)` 能解析出模型。
//!    （`w36.j.k()` = `g() && d() != null`，`s36.a.j()` 就是它。）
//! 2. **AuthKey 能用** = `hasAuthKey(uid, alias) == 0` **且** `getAuthKey(...)` 能解析。
//! 3. **能解析**的定义很挑（`w36.b.q` / `s36.a.a`）：`[i32 小端 JSON 长度][JSON][签名]`，
//!    长度 <4 丢、>1 MiB 丢、`4+长度` 必须**严格小于**总长（尾巴上必须真有签名），
//!    JSON 还得能解析。少一截签名它就当「没导出」，于是「有 ASK」也会被判成「ASK 不可用」。
//!
//! # 失败之后它自己怎么收拾（这几条是我们最容易被带进死循环的地方）
//!
//! - 建 ASK 失败 → 先 `s36.a.r()` 把 ASK 删掉再说。
//! - ASK 上报腾讯失败 → 码 1003，同样 `s36.a.r()`。
//! - 有 AuthKey 但不可用（或要重建）→ `s36.a.s(alias, false)` 删掉重来。
//! - 建 AuthKey 失败 → `s36.a.s(alias, true)`，**连 ASK 一起删**。
//! - AuthKey 上报失败 → 码 1004，业务层再 `y36.b.f(scene)` 删一遍。
//!
//! 也就是说：任何一环答错，它都会把料删掉重铸；而腾讯那边只认「第一次上报的那份 ASK」，
//! 于是我们答错一次就可能永久对不上（槽位毒化）。
//!
//! # 跑法
//!
//! 见 `examples/soter_enable_flow.rs`。默认走本机 HAL；给 `--relay` 就走服务端的
//! `/api/soter/`，跟 A 端 daemon 转发用的是同一条路。

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

/// 微信 TaskPrepareAuthKey 里「强制重建」那个开关（`f46.u0` 构造的 `z` 参数）。
pub const WECHAT_ASK_NAME: &str = "WechatASK";

/// 微信 8.0.79 里注册的场景号（`ym4.b` 里的 `{1, 2, 920, 3}`）。只用来打印。
pub const WECHAT_SCENES: [i32; 4] = [1, 2, 920, 3];

/// 一整轮开通要用的参数。
#[derive(Debug, Clone)]
pub struct Options {
    /// 宿主应用（这里就是微信）的 uid。
    pub uid: i32,
    /// 账号盐。微信那份是 `md5(登录 uin) 十六进制前 8 位`（`xm4.g0.b()`）。
    pub salt: String,
    /// 场景号，见 [`WECHAT_SCENES`]。
    pub scene: i32,
    /// challenge，十六进制字符串。空的话现掷一份。
    pub challenge: String,
    /// 强制作废现有 AuthKey 再建（微信里的 forceRegen）。
    pub force_regen: bool,
    /// 跑之前先把整个 uid 的料清掉（微信自救用的 `removeAllUidKey`）。会连坐同槽位的别号。
    pub reset: bool,
    /// 允许建料/删料。关掉就只能看现状，真缺料时流程会停在「微信会去建」那一步。
    pub allow_mutation: bool,
    /// 只看到手的料，不开签名会话（`--no-sign`）。
    pub skip_sign: bool,
    /// 真调用者的包名。走 relay 时**必须**带：服务端没包名就把这笔当探测机、
    /// 就地拿内置料答（回 `-1001`），压根不会落到 B 端。A 端 daemon 转发时也是这么带的。
    pub caller_pkg: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            uid: 0,
            salt: String::new(),
            scene: 1,
            challenge: String::new(),
            force_regen: false,
            reset: false,
            allow_mutation: true,
            skip_sign: false,
            caller_pkg: None,
        }
    }
}

impl Options {
    /// 场景号 → AuthKey 别名。跟 `xm4.g0.d(int)` 一个字一个字对。
    pub fn auth_key_name(&self) -> String {
        format!("SoterAuthKeyV2_salt{}_scene{}", self.salt, self.scene)
    }
}

/// 一步的结论。`WechatFails` 是「按微信那套判据，它这一步会认为失败并开始删料」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    WechatFails,
    Skipped,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::WechatFails => "微信会判失败",
            Verdict::Skipped => "跳过",
        }
    }
}

/// 流程里的一步。
#[derive(Debug, Clone)]
pub struct Step {
    /// 微信侧对应哪儿（类.方法）。
    pub wechat: &'static str,
    /// 这一笔 HAL / relay 的 op。
    pub op: &'static str,
    pub verdict: Verdict,
    /// 为什么是这个结论。
    pub note: String,
}

impl Step {
    fn new(
        wechat: &'static str,
        op: &'static str,
        verdict: Verdict,
        note: impl Into<String>,
    ) -> Self {
        Self {
            wechat,
            op,
            verdict,
            note: note.into(),
        }
    }
}

/// 一整轮的结论。
#[derive(Debug, Clone)]
pub struct Report {
    pub steps: Vec<Step>,
    pub ask_ok: bool,
    pub auth_ok: bool,
    pub signed: bool,
    /// 各处的 cpu_id（设备号 / ASK 文档 / AuthKey 文档 / 签名现场）。
    pub cpu_ids: Vec<(&'static str, String)>,
    /// 这一轮里导出/签名的原始字节（`[len][json][签名]`），按名字放，给人拿去用
    /// openssl 验链（见 example 里的 `--dump`）。序列是「ask」「auth」「sign」。
    pub artifacts: Vec<(String, Vec<u8>)>,
}

impl Report {
    /// 走到「真出一笔签名」才算这条路通。
    pub fn passed(&self) -> bool {
        self.signed
    }

    /// 跟微信同一套口径的总结论：ASK 和 AuthKey 都算「可用」。
    pub fn material_ok(&self) -> bool {
        self.ask_ok && self.auth_ok
    }

    /// 各处 cpu_id 不是一个值 —— 微信和检测器都会当成「设备换了」。
    pub fn cpu_id_mismatch(&self) -> Option<String> {
        let first = self.cpu_ids.first()?.1.clone();
        let bad: Vec<String> = self
            .cpu_ids
            .iter()
            .filter(|(_, v)| v != &first)
            .map(|(where_, v)| format!("{where_}={v}"))
            .collect();
        if bad.is_empty() {
            None
        } else {
            Some(format!(
                "{}={first} 跟这些对不上：{}",
                self.cpu_ids[0].0,
                bad.join(" ")
            ))
        }
    }

    /// 一条一条排出来的报告，直接给人看。
    pub fn render(&self) -> String {
        let mut out = String::new();
        let width = self.steps.iter().map(|s| s.wechat.len()).max().unwrap_or(0);
        for (i, step) in self.steps.iter().enumerate() {
            out.push_str(&format!(
                "{:>2}. {:<width$} | {:<26} | {}\n     {}\n",
                i + 1,
                step.wechat,
                step.op,
                step.verdict.label(),
                step.note,
                width = width,
            ));
        }
        out.push_str(&format!(
            "\nASK 可用={} AuthKey 可用={} 出签名={}\n",
            yes(self.ask_ok),
            yes(self.auth_ok),
            yes(self.signed)
        ));
        if let Some(mismatch) = self.cpu_id_mismatch() {
            out.push_str(&format!("cpu_id 不一致：{mismatch}\n"));
        }
        out
    }
}

fn yes(v: bool) -> &'static str {
    if v {
        "是"
    } else {
        "否"
    }
}

/// `[i32 小端 JSON 长度][JSON][签名]` 拆开之后的形状。
#[derive(Debug, Clone)]
pub struct Envelope {
    pub doc: Value,
    pub signature_len: usize,
}

/// 微信那份解析器（`w36.b.q` / `s36.a.a`）的等价实现，连它的拒收条件一起照抄。
pub fn parse_envelope(data: &[u8]) -> std::result::Result<Envelope, String> {
    if data.len() < 4 {
        return Err(format!("整块只有 {} 字节，连长度头都不够", data.len()));
    }
    let mut head = [0u8; 4];
    head.copy_from_slice(&data[..4]);
    let raw = i32::from_le_bytes(head);
    if raw < 0 {
        return Err(format!("长度头是负数（{raw}），微信直接丢"));
    }
    let len = raw as usize;
    if len > 1024 * 1024 {
        return Err(format!("JSON 长度 {len} 超过 1 MiB，微信当垃圾丢掉"));
    }
    // 这一条最坑：微信要求 `4 + len` 严格小于总长，也就是签名必须真实存在。
    if data.len() <= len + 4 {
        return Err(format!(
            "长度头说 JSON {len} 字节、整块 {} 字节 —— 尾巴上没有签名，微信会当成「没导出」",
            data.len()
        ));
    }
    let doc: Value =
        serde_json::from_slice(&data[4..4 + len]).map_err(|e| format!("JSON 解析失败：{e}"))?;
    Ok(Envelope {
        doc,
        signature_len: data.len() - 4 - len,
    })
}

/// 一份 SOTER 文档（ASK / AuthKey / 签名现场）的键位检查。
///
/// 只查「微信和检测器会看」的那几个：公钥 PEM 在不在、cpu_id 是不是 32 位十六进制、
/// uid 是不是字符串且跟请求一致、盐长是不是给了。
fn check_doc(doc: &Value, uid: i32, where_: &str) -> Result<String, String> {
    let pub_key = doc
        .get("pub_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if pub_key.is_empty() && doc.get("raw").is_none() {
        return Err(format!("{where_}文档里没有 pub_key"));
    }
    if !pub_key.is_empty() && !pub_key.contains("BEGIN PUBLIC KEY") {
        return Err(format!("{where_}的 pub_key 不是 PEM"));
    }
    let cpu_id = doc
        .get("cpu_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if cpu_id.len() != 32 || !cpu_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{where_}的 cpu_id {cpu_id:?} 不是 32 位十六进制"));
    }
    match doc.get("uid") {
        Some(Value::String(text)) => {
            if text != &uid.to_string() {
                return Err(format!("{where_}文档里的 uid 是 {text}，请求的是 {uid}"));
            }
        }
        Some(other) => return Err(format!("{where_}的 uid 是 {other}（SOTER 里必须是字符串）")),
        None => return Err(format!("{where_}文档里没有 uid")),
    }
    Ok(cpu_id.to_string())
}

#[derive(Default)]
struct Collected {
    steps: Vec<Step>,
    cpu_ids: Vec<(&'static str, String)>,
    artifacts: Vec<(String, Vec<u8>)>,
}

/// 把一整轮开通跑一遍。
///
/// `send` 是「发一笔 op、拿答复」的出口：本机 HAL 就是 `soter::handle`，走 relay 就是
/// 服务端的 `/api/soter/`。`Err` 表示这笔连答复都没拿到（链路断了），`Ok` 里的
/// `error_code` 才是 TA 的答复。
pub fn run<F>(mut send: F, opts: &Options) -> Result<Report>
where
    F: FnMut(Value) -> Result<Value>,
{
    let mut acc = Collected::default();
    let alias = opts.auth_key_name();

    // 每笔都把 caller_pkg 带上：走 relay 时服务端靠它分辨「真应用 / 探测机」，
    // 没它就会被就地拿内置料答（那边回 -1001），永远看不到 B 端的真答复。
    let caller = opts.caller_pkg.clone();
    let mut send = move |mut reply: Value| {
        if let Some(pkg) = caller.as_deref() {
            if let Some(map) = reply.as_object_mut() {
                map.insert("caller_pkg".to_string(), json!(pkg));
            }
        }
        send(reply)
    };

    // 0. 设备号。后面几份文档里的 cpu_id 必须跟它一致，不然微信 / 检测器都当成换了设备。
    let device = send(json!({ "op": "get_device_id" })).context("get_device_id 没拿到答复")?;
    let cpu_id = answer_text(&device).unwrap_or_default();
    acc.cpu_ids.push(("设备号", cpu_id.clone()));
    acc.steps.push(Step::new(
        "w36.j.l() / getExtraParam",
        "get_device_id",
        if cpu_id.is_empty() {
            Verdict::WechatFails
        } else {
            Verdict::Ok
        },
        if cpu_id.is_empty() {
            "没给出设备号，后面文档里的 cpu_id 无从对齐".to_string()
        } else {
            format!("cpu_id={cpu_id}")
        },
    ));

    // 0.5 可选的清场（微信自救那一步：清整个 uid 的槽位）。
    if opts.reset {
        if !opts.allow_mutation {
            acc.steps.push(Step::new(
                "s36.a.r() 清场",
                "remove_all_uid_key",
                Verdict::Skipped,
                "关掉了建料/删料，不执行",
            ));
        } else {
            let reply = send(json!({ "op": "remove_all_uid_key", "uid": opts.uid }))
                .context("remove_all_uid_key 没拿到答复")?;
            acc.steps.push(Step::new(
                "s36.a.r() 清场",
                "remove_all_uid_key",
                ok_code(&reply),
                format!("error_code={}", code_of(&reply)),
            ));
        }
    }

    // 1. 有没有 ASK（微信 `s36.a.h()` = `hasAskAlready`）：只有 0 算「有」。
    let has_ask = send(json!({ "op": "has_ask_already", "uid": opts.uid }))
        .context("has_ask_already 没拿到答复")?;
    let ask_present = code_of(&has_ask) == 0;
    acc.steps.push(Step::new(
        "s36.a.h() / w36.j.g()",
        "has_ask_already",
        Verdict::Ok,
        format!(
            "error_code={} → {}",
            code_of(&has_ask),
            if ask_present { "有 ASK" } else { "没有 ASK" }
        ),
    ));

    // 2. 有 ASK 的话它到底能不能用（微信 `s36.a.j()` 的第二半：模型解析得出来）。
    let mut ask_doc = None;
    let mut ask_ok = false;
    if ask_present {
        let (doc, step) = export_check(
            &mut send,
            &mut acc,
            "ask",
            "export_ask_public_key",
            json!({ "uid": opts.uid }),
            "ASK",
            opts.uid,
        )?;
        ask_ok = doc.is_some();
        ask_doc = doc;
        acc.steps.push(Step::new(
            "s36.a.c() / w36.j.d()",
            "export_ask_public_key",
            if ask_ok {
                Verdict::Ok
            } else {
                Verdict::WechatFails
            },
            step,
        ));
    } else {
        acc.steps.push(Step::new(
            "s36.a.c() / w36.j.d()",
            "export_ask_public_key",
            Verdict::Skipped,
            "没有 ASK，微信会直接走建料",
        ));
    }

    // 3. ASK 不可用 → 微信建一份（`f46.q0.g()` 判不过就排 TaskPrepareAppSecureKey）。
    if !ask_ok {
        if !opts.allow_mutation {
            acc.steps.push(Step::new(
                "f46.q0 → f46.o0",
                "generate_ask_key_pair",
                Verdict::Skipped,
                "关掉了建料/删料；微信这一步会真去建，而这里没建",
            ));
        } else {
            let gen = send(json!({ "op": "generate_ask_key_pair", "uid": opts.uid }))
                .context("generate_ask_key_pair 没拿到答复")?;
            let gen_ok = ok_code(&gen) == Verdict::Ok;
            acc.steps.push(Step::new(
                "f46.q0 → f46.o0",
                "generate_ask_key_pair",
                if gen_ok {
                    Verdict::Ok
                } else {
                    Verdict::WechatFails
                },
                format!(
                    "error_code={}{}",
                    code_of(&gen),
                    if gen_ok {
                        ""
                    } else {
                        "；微信会调 s36.a.r() 把 ASK 删掉再来"
                    }
                ),
            ));
            if gen_ok {
                let (doc, step) = export_check(
                    &mut send,
                    &mut acc,
                    "ask",
                    "export_ask_public_key",
                    json!({ "uid": opts.uid }),
                    "ASK",
                    opts.uid,
                )?;
                ask_ok = doc.is_some();
                ask_doc = doc;
                acc.steps.push(Step::new(
                    "f46.o0.onSuccess → s36.a.c()",
                    "export_ask_public_key",
                    if ask_ok {
                        Verdict::Ok
                    } else {
                        Verdict::WechatFails
                    },
                    step,
                ));
            }
        }
    }
    let _ = &ask_doc;

    // 4. 有没有 AuthKey（`s36.a.i(alias)`）。
    let has_auth = send(json!({ "op": "has_auth_key", "uid": opts.uid, "alias": alias }))
        .context("has_auth_key 没拿到答复")?;
    let auth_present = code_of(&has_auth) == 0;
    acc.steps.push(Step::new(
        "s36.a.i(alias) / w36.j.h()",
        "has_auth_key",
        Verdict::Ok,
        format!(
            "alias={alias} error_code={} → {}",
            code_of(&has_auth),
            if auth_present { "有" } else { "没有" }
        ),
    ));

    // 5. 有 AuthKey 能不能用（`s36.a.l()` = hasAuthKey && getAuthKey 解析得出来）。
    let mut auth_ok = false;
    if auth_present {
        let (doc, step) = export_check(
            &mut send,
            &mut acc,
            "auth",
            "export_auth_key_public_key",
            json!({ "uid": opts.uid, "alias": alias }),
            "AuthKey",
            opts.uid,
        )?;
        auth_ok = doc.is_some();
        acc.steps.push(Step::new(
            "s36.a.e(alias) / w36.j.f()",
            "export_auth_key_public_key",
            if auth_ok {
                Verdict::Ok
            } else {
                Verdict::WechatFails
            },
            step,
        ));
        if !auth_ok {
            acc.steps.push(Step::new(
                "s36.a.s(alias, false)",
                "remove_auth_key",
                Verdict::Skipped,
                "有 AuthKey 但导不出可用模型，微信会先把它删掉再重建",
            ));
        }
    } else {
        acc.steps.push(Step::new(
            "s36.a.e(alias) / w36.j.f()",
            "export_auth_key_public_key",
            Verdict::Skipped,
            "没有 AuthKey",
        ));
    }

    // 6. 不可用或者要求重建 → 建一份（`f46.u0.g()` → TaskPrepareAuthKey）。
    if !auth_ok || opts.force_regen {
        if !opts.allow_mutation {
            acc.steps.push(Step::new(
                "f46.u0 → f46.s0",
                "generate_auth_key_pair",
                Verdict::Skipped,
                "关掉了建料/删料；微信这一步会真去建",
            ));
        } else {
            let gen =
                send(json!({ "op": "generate_auth_key_pair", "uid": opts.uid, "alias": alias }))
                    .context("generate_auth_key_pair 没拿到答复")?;
            let gen_ok = ok_code(&gen) == Verdict::Ok;
            acc.steps.push(Step::new(
                "f46.u0 → f46.s0",
                "generate_auth_key_pair",
                if gen_ok {
                    Verdict::Ok
                } else {
                    Verdict::WechatFails
                },
                format!(
                    "alias={alias} error_code={}{}",
                    code_of(&gen),
                    if gen_ok {
                        String::new()
                    } else {
                        "；微信会调 s36.a.s(alias, true)（连 ASK 一起删）".to_string()
                    }
                ),
            ));
            if gen_ok {
                let (doc, step) = export_check(
                    &mut send,
                    &mut acc,
                    "auth",
                    "export_auth_key_public_key",
                    json!({ "uid": opts.uid, "alias": alias }),
                    "AuthKey",
                    opts.uid,
                )?;
                auth_ok = doc.is_some();
                acc.steps.push(Step::new(
                    "f46.s0.onSuccess → s36.a.e()",
                    "export_auth_key_public_key",
                    if auth_ok {
                        Verdict::Ok
                    } else {
                        Verdict::WechatFails
                    },
                    step,
                ));
            }
        }
    }

    // 7. 开签名会话。微信这里要 session 非 0（`f46.z` → `w36.j.i()`）。
    //
    // `--no-sign` 整段跳过：设备同一时刻只留一张签名会话，只是想看一眼料的时候别把
    // 人家正在用的那张顶掉。
    let mut signed = false;
    if opts.skip_sign {
        acc.steps.push(Step::new(
            "f46.z → w36.j.i()",
            "init_sign",
            Verdict::Skipped,
            "指定了 --no-sign：只看料，不开签名会话",
        ));
        acc.steps.push(Step::new(
            "w36.j.a() → SoterCore.finishSign",
            "finish_sign",
            Verdict::Skipped,
            "同上",
        ));
    } else {
        let challenge = if opts.challenge.is_empty() {
            fresh_challenge()
        } else {
            opts.challenge.clone()
        };
        let init = send(json!({
            "op": "init_sign",
            "uid": opts.uid,
            "alias": alias,
            "challenge": challenge,
        }))
        .context("init_sign 没拿到答复")?;
        let session = init.get("session").and_then(Value::as_i64).unwrap_or(0);
        let init_ok = code_of(&init) == 0 && session != 0;
        acc.steps.push(Step::new(
            "f46.z → w36.j.i()",
            "init_sign",
            if init_ok {
                Verdict::Ok
            } else {
                Verdict::WechatFails
            },
            format!(
                "error_code={} session={session}{}",
                code_of(&init),
                match (code_of(&init), init_ok) {
                    (-204, _) =>
                        "（会话被别人顶掉了：一台设备同一时刻只留一张，认开它的那个调用者）",
                    (-26, _) => "（这一笔验证没过：真应用就是指纹那步没成）",
                    (0, false) => "（给了成功码却没有会话号，微信连指纹圈都弹不出来）",
                    _ => "",
                }
            ),
        ));

        // 8. 收尾签名（`w36.j.a()` → SoterSignResult）。签名现场那份 JSON 也按同一个信封解析。
        if init_ok {
            let finish = send(json!({ "op": "finish_sign", "session": session }))
                .context("finish_sign 没拿到答复")?;
            let parsed = finish
                .get("data")
                .and_then(Value::as_str)
                .and_then(|text| base64_decode(text).ok())
                .map(|bytes| (bytes.clone(), parse_envelope(&bytes)));
            match parsed {
                Some((raw, Ok(envelope))) => {
                    signed = true;
                    acc.artifacts.push(("sign".to_string(), raw));
                    let detail = check_doc(&envelope.doc, opts.uid, "签名现场");
                    if detail.is_ok() {
                        record_cpu(&mut acc, "签名现场", &envelope.doc);
                    }
                    acc.steps.push(Step::new(
                        "w36.j.a() → SoterCore.finishSign",
                        "finish_sign",
                        if detail.is_ok() {
                            Verdict::Ok
                        } else {
                            Verdict::WechatFails
                        },
                        match &detail {
                            Ok(_) => format!(
                                "error_code=0 签名 {} 字节，raw={:?}",
                                envelope.signature_len,
                                envelope
                                    .doc
                                    .get("raw")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                            ),
                            Err(why) => format!("error_code=0 但信封有问题：{why}"),
                        },
                    ));
                }
                Some((_, Err(why))) => acc.steps.push(Step::new(
                    "w36.j.a() → SoterCore.finishSign",
                    "finish_sign",
                    Verdict::WechatFails,
                    format!("error_code={} 信封解析不了：{why}", code_of(&finish)),
                )),
                None => acc.steps.push(Step::new(
                    "w36.j.a() → SoterCore.finishSign",
                    "finish_sign",
                    Verdict::WechatFails,
                    format!("error_code={} 没带 data", code_of(&finish)),
                )),
            }
        } else {
            acc.steps.push(Step::new(
                "w36.j.a() → SoterCore.finishSign",
                "finish_sign",
                Verdict::Skipped,
                "没有会话号，微信不会走到收尾",
            ));
        }
    }

    Ok(Report {
        steps: acc.steps,
        ask_ok,
        auth_ok,
        signed,
        cpu_ids: acc.cpu_ids,
        artifacts: acc.artifacts,
    })
}

fn record_cpu(acc: &mut Collected, where_: &'static str, doc: &Value) {
    if let Some(cpu) = doc.get("cpu_id").and_then(Value::as_str) {
        acc.cpu_ids.push((where_, cpu.to_string()));
    }
}

/// 发一笔导出类 op，并按微信的判据解析它的答复。解析得出来就顺手把 cpu_id 跟原始字节
///记进 `acc`（后者就是 `--dump` 拿去 openssl 验链的东西）。
fn export_check<F>(
    send: &mut F,
    acc: &mut Collected,
    tag: &'static str,
    op: &'static str,
    args: Value,
    what: &str,
    uid: i32,
) -> Result<(Option<Value>, String)>
where
    F: FnMut(Value) -> Result<Value>,
{
    let reply = send(with_op(op, args)).with_context(|| format!("{op} 没拿到答复"))?;
    if code_of(&reply) != 0 {
        return Ok((
            None,
            format!("error_code={}，微信拿不到 {what} 模型", code_of(&reply)),
        ));
    }
    let bytes = match reply.get("data").and_then(Value::as_str) {
        Some(text) => base64_decode(text).map_err(|e| anyhow!("{op} 的 data 解不开：{e}"))?,
        None => return Ok((None, format!("error_code=0 但没给 data，{what} 模型是空的"))),
    };
    match parse_envelope(&bytes) {
        Ok(envelope) => {
            record_cpu(
                acc,
                if tag == "ask" {
                    "ASK 文档"
                } else {
                    "AuthKey 文档"
                },
                &envelope.doc,
            );
            acc.artifacts.push((tag.to_string(), bytes.clone()));
            match check_doc(&envelope.doc, uid, what) {
                Ok(cpu) => Ok((
                    Some(envelope.doc.clone()),
                    format!(
                        "整块 {} 字节（JSON+签名 {} 字节），cpu_id={cpu}",
                        bytes.len(),
                        envelope.signature_len
                    ),
                )),
                // 微信只看「能不能解析出模型」，键位不对它照样认；这里单独标出来。
                Err(why) => Ok((Some(envelope.doc.clone()), format!("能解析，但{why}"))),
            }
        }
        Err(why) => Ok((None, format!("error_code=0，但{why}"))),
    }
}

fn code_of(reply: &Value) -> i64 {
    reply
        .get("error_code")
        .and_then(Value::as_i64)
        .unwrap_or(i64::MIN)
}

/// 把 op 拼进 payload。导出类那几笔调用只给参数，op 在这里补。
fn with_op(op: &str, mut args: Value) -> Value {
    if let Some(map) = args.as_object_mut() {
        map.insert("op".to_string(), json!(op));
    }
    args
}

fn ok_code(reply: &Value) -> Verdict {
    if code_of(reply) == 0 {
        Verdict::Ok
    } else {
        Verdict::WechatFails
    }
}

fn answer_text(reply: &Value) -> Option<String> {
    if let Some(text) = reply.get("text").and_then(Value::as_str) {
        let text = text.trim().to_string();
        if !text.is_empty() {
            return Some(text);
        }
    }
    let data = reply.get("data").and_then(Value::as_str)?;
    let bytes = base64_decode(data).ok()?;
    let text = String::from_utf8(bytes)
        .ok()?
        .trim_matches('\0')
        .trim()
        .to_string();
    (!text.is_empty()).then_some(text)
}

fn fresh_challenge() -> String {
    // 没有 rand 依赖：拿纳秒跟 pid 混一下，够当一次性 challenge 用。
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mut out = String::with_capacity(32);
    for i in 0..4 {
        let chunk = nanos.wrapping_mul(i + 1) ^ (pid << (i * 7));
        out.push_str(&format!("{:08x}", chunk as u32));
    }
    out
}

// base64：b-side 已经有这个依赖，别为它再拉一个 crate。
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

fn base64_decode(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64.decode(text.trim())
}

// ---------------------------------------------------------------------------
// 单测：不碰 HAL，用一份「剧本」把状态机的每个岔路走一遍。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// 按剧本答复的假出口：每笔 op 消费一条预置答复。
    struct Script {
        replies: VecDeque<Value>,
        seen: Vec<Value>,
    }

    impl Script {
        fn new(replies: Vec<Value>) -> Self {
            Self {
                replies: replies.into(),
                seen: Vec::new(),
            }
        }
    }

    fn envelope(doc: Value, sig_len: usize) -> Vec<u8> {
        let text = serde_json::to_vec(&doc).unwrap();
        let mut out = (text.len() as i32).to_le_bytes().to_vec();
        out.extend_from_slice(&text);
        out.extend(std::iter::repeat_n(0x11u8, sig_len));
        out
    }

    fn data_reply(data: Vec<u8>) -> Value {
        json!({
            "op": "x",
            "error_code": 0,
            "data": B64.encode(data),
        })
    }

    fn ask_doc() -> Value {
        json!({
            "pub_key": "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
            "cpu_id": "090000005171734c42866bea148b21f5",
            "counter": 3,
            "uid": "10489",
            "rsa_pss_saltlen": 32,
        })
    }

    fn sign_doc() -> Value {
        json!({
            "raw": "deadbeef",
            "fid": "1234567890",
            "counter": 9,
            "tee_n": "trustonic",
            "tee_v": "1",
            "fp_n": "fp",
            "fp_v": "1",
            "cpu_id": "090000005171734c42866bea148b21f5",
            "uid": "10489",
            "rsa_pss_saltlen": 32,
        })
    }

    fn run_script(script: &mut Script, opts: &Options) -> Report {
        let replies = std::mem::take(&mut script.replies);
        let mut queue: VecDeque<Value> = replies;
        let mut seen: Vec<Value> = Vec::new();
        let report = run(
            |payload| {
                seen.push(payload.clone());
                queue
                    .pop_front()
                    .ok_or_else(|| anyhow!("剧本里没有这一笔了：{payload}"))
            },
            opts,
        )
        .expect("剧本齐的时候不该报错");
        script.seen = seen;
        report
    }

    fn opts() -> Options {
        Options {
            uid: 10489,
            salt: "11d8ba34".to_string(),
            scene: 1,
            challenge: "0a1b".to_string(),
            ..Options::default()
        }
    }

    /// 料齐、能签：一路到底，别多建料也别删料。
    #[test]
    fn healthy_slot_goes_straight_to_signature() {
        let mut script = Script::new(vec![
            json!({ "op": "get_device_id", "error_code": 0, "text": "090000005171734c42866bea148b21f5" }),
            json!({ "op": "has_ask_already", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "has_auth_key", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "init_sign", "error_code": 0, "session": 77 }),
            data_reply(envelope(sign_doc(), 256)),
        ]);
        let report = run_script(&mut script, &opts());
        let ops: Vec<String> = script
            .seen
            .iter()
            .map(|p| p["op"].as_str().unwrap_or("?").to_string())
            .collect();
        assert_eq!(
            ops,
            [
                "get_device_id",
                "has_ask_already",
                "export_ask_public_key",
                "has_auth_key",
                "export_auth_key_public_key",
                "init_sign",
                "finish_sign"
            ]
        );
        assert!(report.passed());
        assert!(report.material_ok());
        assert!(report.cpu_id_mismatch().is_none());
    }

    /// 没有 ASK：微信会先建再导出。这里必须看到 generate 之后重新 export。
    #[test]
    fn missing_ask_is_created_and_re_exported() {
        let mut script = Script::new(vec![
            json!({ "op": "get_device_id", "error_code": 0, "text": "090000005171734c42866bea148b21f5" }),
            json!({ "op": "has_ask_already", "error_code": -5 }),
            json!({ "op": "generate_ask_key_pair", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "has_auth_key", "error_code": -5 }),
            json!({ "op": "generate_auth_key_pair", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "init_sign", "error_code": 0, "session": 5 }),
            data_reply(envelope(sign_doc(), 256)),
        ]);
        let report = run_script(&mut script, &opts());
        assert!(report.passed());
        let ops: Vec<&str> = script
            .seen
            .iter()
            .map(|p| p["op"].as_str().unwrap_or("?"))
            .collect();
        assert_eq!(ops[2], "generate_ask_key_pair");
        assert_eq!(ops[3], "export_ask_public_key");
        assert_eq!(ops[5], "generate_auth_key_pair");
    }

    /// 有 ASK、但导出不带签名尾巴 —— 微信那条解析器会判「模型为空」，
    /// 于是明明「有 ASK」也要重走一遍。这一条正是最难从日志上看出来的坑。
    #[test]
    fn export_without_signature_tail_counts_as_unusable() {
        let ask = serde_json::to_vec(&ask_doc()).unwrap();
        let mut truncated = (ask.len() as i32).to_le_bytes().to_vec();
        truncated.extend_from_slice(&ask);
        let mut script = Script::new(vec![
            json!({ "op": "get_device_id", "error_code": 0, "text": "090000005171734c42866bea148b21f5" }),
            json!({ "op": "has_ask_already", "error_code": 0 }),
            data_reply(truncated),
            json!({ "op": "generate_ask_key_pair", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "has_auth_key", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "init_sign", "error_code": 0, "session": 5 }),
            data_reply(envelope(sign_doc(), 256)),
        ]);
        let report = run_script(&mut script, &opts());
        assert!(
            script
                .seen
                .iter()
                .any(|p| p["op"] == json!("generate_ask_key_pair")),
            "没签名的导出要被当成不可用"
        );
        assert!(report.passed());
    }

    /// 一处 cpu_id 对不上：微信 / 检测器会当成换了设备，报告里必须点出来。
    #[test]
    fn cpu_id_drift_is_reported() {
        let mut another = ask_doc();
        another["cpu_id"] = json!("09000000000000000000000000000001");
        let mut script = Script::new(vec![
            json!({ "op": "get_device_id", "error_code": 0, "text": "090000005171734c42866bea148b21f5" }),
            json!({ "op": "has_ask_already", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "has_auth_key", "error_code": 0 }),
            data_reply(envelope(another, 256)),
            json!({ "op": "init_sign", "error_code": 0, "session": 5 }),
            data_reply(envelope(sign_doc(), 256)),
        ]);
        let report = run_script(&mut script, &opts());
        assert!(report.cpu_id_mismatch().is_some());
    }

    /// 会话号没给（典型：-9 / -204 之类被拒）：微信弹不出指纹圈，收尾那步必须跳过。
    #[test]
    fn init_without_session_skips_finish() {
        let mut script = Script::new(vec![
            json!({ "op": "get_device_id", "error_code": 0, "text": "090000005171734c42866bea148b21f5" }),
            json!({ "op": "has_ask_already", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "has_auth_key", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "init_sign", "error_code": -204, "session": 0 }),
        ]);
        let report = run_script(&mut script, &opts());
        assert!(!report.passed());
        assert_eq!(
            script.seen.last().unwrap()["op"],
            json!("init_sign"),
            "没有会话就不该发 finish_sign"
        );
    }

    /// 清场开关打开时，第一笔就得是 remove_all_uid_key（微信自救的顺序）。
    #[test]
    fn reset_clears_the_slot_first() {
        let mut options = opts();
        options.reset = true;
        options.allow_mutation = true;
        let mut script = Script::new(vec![
            json!({ "op": "get_device_id", "error_code": 0, "text": "090000005171734c42866bea148b21f5" }),
            json!({ "op": "remove_all_uid_key", "error_code": 0 }),
            json!({ "op": "has_ask_already", "error_code": -5 }),
            json!({ "op": "generate_ask_key_pair", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "has_auth_key", "error_code": -5 }),
            json!({ "op": "generate_auth_key_pair", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "init_sign", "error_code": 0, "session": 5 }),
            data_reply(envelope(sign_doc(), 256)),
        ]);
        let report = run_script(&mut script, &options);
        assert_eq!(script.seen[1]["op"], json!("remove_all_uid_key"));
        assert!(report.passed());
    }

    /// 关掉建料之后只许看，不许建：缺料就停在「微信会去建」。
    #[test]
    fn read_only_mode_never_mutates() {
        let mut options = opts();
        options.allow_mutation = false;
        let mut script = Script::new(vec![
            json!({ "op": "get_device_id", "error_code": 0, "text": "090000005171734c42866bea148b21f5" }),
            json!({ "op": "has_ask_already", "error_code": -5 }),
            json!({ "op": "has_auth_key", "error_code": -5 }),
            json!({ "op": "init_sign", "error_code": -5, "session": 0 }),
        ]);
        let report = run_script(&mut script, &options);
        let ops: Vec<&str> = script
            .seen
            .iter()
            .map(|p| p["op"].as_str().unwrap_or("?"))
            .collect();
        assert!(!ops
            .iter()
            .any(|op| op.starts_with("generate") || op.starts_with("remove")));
        assert!(!report.passed());
    }

    /// 走 relay 时每笔都得带 caller_pkg；没带服务端就当探测机、回 -1001。
    #[test]
    fn caller_pkg_rides_on_every_request() {
        let mut options = opts();
        options.caller_pkg = Some("com.tencent.mm".to_string());
        let mut script = Script::new(vec![
            json!({ "op": "get_device_id", "error_code": 0, "text": "090000005171734c42866bea148b21f5" }),
            json!({ "op": "has_ask_already", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "has_auth_key", "error_code": 0 }),
            data_reply(envelope(ask_doc(), 256)),
            json!({ "op": "init_sign", "error_code": 0, "session": 5 }),
            data_reply(envelope(sign_doc(), 256)),
        ]);
        let _ = run_script(&mut script, &options);
        assert!(!script.seen.is_empty());
        for payload in &script.seen {
            assert_eq!(
                payload["caller_pkg"],
                json!("com.tencent.mm"),
                "每笔都要带包名：{payload}"
            );
        }
    }

    /// 微信那份别名的拼法：`SoterAuthKeyV2_salt<盐>_scene<场景>`。
    #[test]
    fn alias_matches_wechat() {
        assert_eq!(
            Options::default().auth_key_name(),
            "SoterAuthKeyV2_salt_scene1"
        );
        assert_eq!(opts().auth_key_name(), "SoterAuthKeyV2_salt11d8ba34_scene1");
    }

    /// 信封解析要跟微信一样挑：没签名、超长、JSON 坏，全都要拒。
    #[test]
    fn envelope_rejects_what_wechat_rejects() {
        let doc = serde_json::to_vec(&ask_doc()).unwrap();
        assert!(parse_envelope(b"abc").is_err(), "短于长度头");

        let mut no_tail = (doc.len() as i32).to_le_bytes().to_vec();
        no_tail.extend_from_slice(&doc);
        assert!(parse_envelope(&no_tail).is_err(), "尾巴上没签名");

        let mut huge = (1024 * 1024 + 1i32).to_le_bytes().to_vec();
        huge.extend(std::iter::repeat_n(0u8, 10));
        assert!(parse_envelope(&huge).is_err(), "超过 1 MiB");

        let mut bad_json = 3i32.to_le_bytes().to_vec();
        bad_json.extend_from_slice(b"{{{");
        bad_json.push(0x22);
        assert!(parse_envelope(&bad_json).is_err(), "JSON 坏");

        let good = envelope(ask_doc(), 256);
        let parsed = parse_envelope(&good).expect("正常信封要能解析");
        assert_eq!(parsed.signature_len, 256);
    }
}
