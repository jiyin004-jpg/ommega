//! 软件 SOTER TA。
//!
//! 原厂 `vendor.qti.hardware.soter.ISoter/default` 只是 TEE 里那个 applet 的薄代理，
//! applet 起不来时整族调用一律 -20（PKG110 / 安卓 15 实测），宿主和应用一起哑，产线
//! 工具（工程模式那页）也跟着报红。这里把服务名原样接过来，用我们自己的软件实现应答，
//! 调用方（soterserver、oplus 的 cryptoeng）一行都不用改。
//!
//! 号码表跟宿主 dex 里 `ISoter$Stub$Proxy` 对过：1/3/4/5/7/8/9/10/11/12/13 是运行时
//! 那 11 个方法；2/6/14 原厂 HAL 是空号，只有产线 provisioning（cryptoeng）会调，
//! 我们用同一套 ASK 顶上，工程模式的 SOTER key 就看 14 号那一笔是不是 0。

use rsbinder::{
    hub, Binder, Interface, Parcel, Remotable, Result as BinderResult, Stability, TransactionCode,
};

use crate::hook::soter;
use crate::hook::soter_local::{self, Answer};
use crate::hook::soter_relay;

pub const DEFAULT_SERVICE_NAME: &str = "vendor.qti.hardware.soter.ISoter/default";
const DEFAULT_DESCRIPTOR: &str = "vendor.qti.hardware.soter.ISoter";
/// 运行时服务名从哪儿来：soterta.sh 把 VINTF 里读到的 `<name>.<fqname>` 拼好，走这个
/// 环境变量传进来。各家 SOTER HAL 的接口名不一样（高通 `ISoter`、联发科 / Trustonic
/// `ITrustonicSoter`、小米另一套），猜错就是「注册了一个没人认的名字」——NX809J /
/// 安卓 16 上实测：我们的名字没人问、原厂名字又被我们停掉，SOTER 整族哑掉。
const SERVICE_ENV: &str = "OMMEGA_SOTER_SERVICE";

/// 运行时定下来的接口描述符。`Remotable::descriptor()` 要 `&'static str`，所以只在
/// 启动时 leak 一次。
static DESCRIPTOR: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
/// 这条 AIDL 接口的 buffer 类回复带不带「方法返回值」那一格：高通带，联发科不带
/// （规格见 `parcel::reply::build_soter_buffer_reply` 的注释）。启动时按描述符定。
static HAS_RETURN_CODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

fn descriptor_text() -> &'static str {
    DESCRIPTOR.get().copied().unwrap_or(DEFAULT_DESCRIPTOR)
}

fn has_return_code() -> bool {
    HAS_RETURN_CODE.load(std::sync::atomic::Ordering::Relaxed)
}

/// 服务名去掉 `/default` 那一段就是接口描述符。
fn descriptor_of(service: &str) -> &'static str {
    let head = service.split('/').next().unwrap_or(service);
    Box::leak(head.to_string().into_boxed_str())
}

fn service_name() -> String {
    // 服务名由 soterta.sh 写到文件里（不再走环境变量：environ 是 root 一句 tr 就能看的）。
    if let Ok(text) = std::fs::read_to_string("/data/adb/ommega/run/soterta.service") {
        let value = text.trim();
        if !value.is_empty() {
            return value.to_string();
        }
    }
    std::env::var(SERVICE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string())
}

/// 只读探针：连上指定服务、发一次 `code`，把回复的前几个字段打出来。
///
/// 用 rsbinder 而不是 libbinder_ndk：rsbinder 是我们自己实现对 /dev/binder 的 ioctl，
/// 回复的字节完全可控，没有 libbinder 自己的异常包装夹在中间。拿来对「真机 HAL 回的
/// 长什么样」和「我们回的有没有对上」最直接。
pub fn probe(service: &str, code: u32) -> anyhow::Result<String> {
    use rsbinder::Parcel;
    rsbinder::ProcessState::init("/dev/binder", 15)
        .map_err(|error| anyhow::anyhow!("binder init failed: {error}"))?;
    let binder = rsbinder::hub::check_service(service)
        .ok_or_else(|| anyhow::anyhow!("service {service} not found"))?;
    let descriptor = descriptor_of(service);
    let mut data = Parcel::new();
    data.write(&descriptor.to_string())?;
    let mut reply = Parcel::new();
    let transactable = binder
        .as_transactable()
        .ok_or_else(|| anyhow::anyhow!("service {service} is not transactable"))?;
    transactable.transact(code, &mut data, &mut reply)?;
    let status = reply.read::<i32>().unwrap_or(-999);
    let flag = reply.read::<i32>().unwrap_or(-999);
    let total = reply.read::<i32>().unwrap_or(-999);
    let next = reply.read::<i32>().unwrap_or(-999);
    Ok(format!(
        "status={status} flag={flag} total={total} next={next} avail={}",
        reply.data_avail()
    ))
}

/// 原厂 HAL 声明的 14 个号码。
/// 号码表：**4 槽排布（2 / 6 / 14 空号）**，这是 NX721J 上 soterserver 实际发的形状。
/// 依据：实测它发 code 5 / 9 时只带 uid（= generateAskKeyPair / hasAskAlready）；
/// APK 里那份 1–11 连号的 `ISoter.java` 是没被用到的类，按它读会丢 alias。
const EXPORT_ASK_PUBLIC_KEY: u32 = 1;
const EXPORT_ATTK_PUBLIC_KEY: u32 = 2;
const EXPORT_AUTH_KEY_PUBLIC_KEY: u32 = 3;
const FINISH_SIGN: u32 = 4;
const GENERATE_ASK_KEY_PAIR: u32 = 5;
const GENERATE_ATTK_KEY_PAIR: u32 = 6;
const GENERATE_AUTH_KEY_PAIR: u32 = 7;
const GET_DEVICE_ID: u32 = 8;
const HAS_ASK_ALREADY: u32 = 9;
const HAS_AUTH_KEY: u32 = 10;
const INIT_SIGN: u32 = 11;
const REMOVE_ALL_UID_KEY: u32 = 12;
const REMOVE_AUTH_KEY: u32 = 13;
const VERIFY_ATTK_KEY_PAIR: u32 = 14;

/// servicemanager 注册时会用这个 code 来问“你这个 binder 是什么接口”，拿不到名字就
/// 记成空列表，之后 vendor 客户端按（名字 + 接口名）取服务一律 null。
const INTERFACE_TRANSACTION: u32 = 0x5f4e_5446;

/// 不同设备 / 不同 SoterService 版本的 HAL 号码排布不一样：
/// - **4 槽排布（2/6/14 空号）**：NX721J 这类，实测 soterserver 发 9/5 时只带 uid；
/// - **1–11 连号**：APK 里另一种 `ISoter`，9 是 initSign、7 是 hasAskAlready。
///
/// 两者对同一个号的含义相反，光看 code 分不出来。但**参数长度能分**：首笔
/// `hasAskAlready` 在 4 槽里是 9、连号里是 7，而且都只带一个 int（4 字节）。
/// 于是第一次见到它就定下布局并缓存，之后把连号的号换算成 4 槽的规范号，
/// 后续所有逻辑只用一套写法。
static LAYOUTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, u8>>> =
    std::sync::OnceLock::new();
const LAYOUT_UNKNOWN: u8 = 0;
const LAYOUT_14: u8 = 1;
const LAYOUT_11: u8 = 2;

/// 调用方是谁（`/proc/<pid>/cmdline` 的第一段）。拿不到就给空串，那些调用共用
/// 一个匿名槽位，行为跟以前的全局判定一样。
fn caller_key() -> String {
    let pid = rsbinder::get_calling_pid();
    if pid <= 0 {
        return String::new();
    }
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return String::new();
    };
    let name = raw.split(|byte| *byte == 0).next().unwrap_or_default();
    String::from_utf8_lossy(name).into_owned()
}

fn layout_slot(caller: &str) -> u8 {
    let map = LAYOUTS.get_or_init(Default::default);
    let guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.get(caller).copied().unwrap_or(LAYOUT_UNKNOWN)
}

/// 布局按**调用方**分开记，不能全局一个值：同一台机器上 soterserver 和第三方检测器
/// 可能用不同版本的 ISoter 号表（4 槽 vs 1–11 连号），定成一个值会让后到的那个
/// 客户端全程调到错的方法上。MEIZU 20 Pro（391QYGDJ2244E）实测：SoterChecker 走连号
/// （7 = hasAskAlready），被按 4 槽解释成 generateAuthKeyPair，于是它读到
/// hasAsk=false、generate 记 -20、export 记 -5，五项全红。
fn note_layout(caller: &str, code: u32, avail: usize) {
    if layout_slot(caller) != LAYOUT_UNKNOWN {
        return;
    }
    let layout = match (code, avail) {
        // hasAskAlready / generateAskKeyPair：两种排布里都只带一个 int，号却不同。
        (9, 4) | (5, 4) => LAYOUT_14,
        (7, 4) | (4, 4) => LAYOUT_11,
        _ => return,
    };
    let map = LAYOUTS.get_or_init(Default::default);
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.insert(caller.to_string(), layout);
}

/// 把任意排布的号码换成 4 槽的规范号（后面的逻辑只认这套）。
fn canonical_code(caller: &str, code: u32, avail: usize) -> u32 {
    note_layout(caller, code, avail);
    if layout_slot(caller) != LAYOUT_11 {
        return code;
    }
    match code {
        2 => 3,   // exportAuthKeyPublicKey
        3 => 4,   // finishSign
        4 => 5,   // generateAskKeyPair
        5 => 7,   // generateAuthKeyPair
        6 => 8,   // getDeviceId
        7 => 9,   // hasAskAlready
        8 => 10,  // hasAuthKey
        9 => 11,  // initSign
        10 => 12, // removeAllUidKey
        11 => 13, // removeAuthKey
        other => other,
    }
}

fn op_name(code: u32) -> &'static str {
    match code {
        EXPORT_ASK_PUBLIC_KEY => "exportAskPublicKey",
        EXPORT_ATTK_PUBLIC_KEY => "exportAttkPublicKey",
        EXPORT_AUTH_KEY_PUBLIC_KEY => "exportAuthKeyPublicKey",
        FINISH_SIGN => "finishSign",
        GENERATE_ASK_KEY_PAIR => "generateAskKeyPair",
        GENERATE_ATTK_KEY_PAIR => "generateAttkKeyPair",
        GENERATE_AUTH_KEY_PAIR => "generateAuthKeyPair",
        GET_DEVICE_ID => "getDeviceId",
        HAS_ASK_ALREADY => "hasAskAlready",
        HAS_AUTH_KEY => "hasAuthKey",
        INIT_SIGN => "initSign",
        REMOVE_ALL_UID_KEY => "removeAllUidKey",
        REMOVE_AUTH_KEY => "removeAuthKey",
        VERIFY_ATTK_KEY_PAIR => "verifyAttkKeyPair",
        _ => "unknown",
    }
}

/// `int xxx(out byte[] data)` 那一类：返回值 + AIDL 原生 byte[]。
/// 不是 `SoterBufferReturn` parcelable —— cryptoeng（C++ ndk 客户端）的反汇编里就是
/// 一个 vector<uint8_t> out 加一个 int 返回，按 parcelable 拼它会在解析时越界崩。
///
/// 除这一类，其余全按 parcelable 给：soterserver、SoterChecker、工程模式那页都是
/// Java 客户端，读的就是 `SoterBufferReturn`（[非空标记][总长][byte[]][dataLength]）。
///
/// 以前只认 soterserver 一个进程名，其余一律给原生形状 —— 结果所有第三方/自带的 Java
/// 检测器都把数据解成垃圾（2026-10-20 SoterChecker 报告：`len=825 data=0`、
/// `short blob len=0`）。反过来判断之后，「给原生」变成一个要手动点名的例外。
///
/// 名单：环境变量 `OMMEGA_SOTER_NATIVE_CALLERS`（逗号分隔，按 cmdline 包含匹配）。
/// 空字符串 = 全部走 parcelable。
fn caller_wants_parcelable() -> bool {
    let pid = rsbinder::get_calling_pid();
    // 拿不到调用者就别赌：Java 客户端占绝大多数，给原生形状只会把人家数据弄坏。
    if pid <= 0 {
        return true;
    }
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return true;
    };
    let name = raw.split(|byte| *byte == 0).next().unwrap_or_default();
    !is_native_caller(name)
}

/// 缺省走原生形状的那几个（进程名包含匹配）。oplus 的 cryptoeng 是产线/CDK 那种工具，
/// 平时不出现；出现时给它原生形状，否则它按 parcelable 解析会越界崩。
const DEFAULT_NATIVE_CALLERS: &str = "cryptoeng";

fn is_native_caller(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    let list = std::env::var("OMMEGA_SOTER_NATIVE_CALLERS")
        .unwrap_or_else(|_| DEFAULT_NATIVE_CALLERS.to_string());
    list.split(',')
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .any(|pattern| contains_bytes(name, pattern.as_bytes()))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// `int xxx(out SoterBufferReturn)` 那一类：按调用方选形状。
fn write_bytes_reply(reply: &mut Parcel, data: &[u8], code: i32) -> BinderResult<()> {
    let parcelable = caller_wants_parcelable();
    let has_return_code = has_return_code();
    log::info!(
        "event=soterta shape parcelable={parcelable} code={code} data={} return_code={has_return_code}",
        data.len()
    );
    if !parcelable {
        // 原生形状（产线工具那类）：返回值 + 原始字节，跟以前一样。
        reply.write_i32(code)?;
        reply.write(&data.to_vec())?;
        return Ok(());
    }
    // AIDL 的 parcelable 只有 `[非空标记][总长][(错误码)][byte[]][dataLength]`：
    // 高通把错误码放在「方法返回值」那一格（parcelable 里没这格），联发科方法本身
    // 是 void，错误码在 parcelable 里面 —— 两家总长也因此差 4（见 parcel::reply）。
    if has_return_code {
        reply.write_i32(code)?;
    }
    reply.write_i32(1)?;
    let padded = (data.len() + 3) & !3;
    let header = if has_return_code { 12 } else { 16 };
    reply.write_i32((header + padded) as i32)?;
    if !has_return_code {
        reply.write_i32(code)?;
    }
    reply.write(&data.to_vec())?;
    reply.write_i32(data.len() as i32)?;
    Ok(())
}

/// `SoterInitReturn`：`[非空标记][总长=16][status][session]`，两家 AIDL 一样。
/// 注意这个方法是**返回 parcelable 本身**，没有“方法返回值”那一格。
fn write_init_return(reply: &mut Parcel, status: i32, session: i64) -> BinderResult<()> {
    reply.write_i32(1)?;
    reply.write_i32(16)?;
    reply.write_i32(status)?;
    reply.write_i64(session)?;
    Ok(())
}

struct SoterTa;

impl Remotable for SoterTa {
    fn descriptor() -> &'static str {
        descriptor_text()
    }

    fn on_transact(
        &self,
        code: TransactionCode,
        reader: &mut Parcel,
        reply: &mut Parcel,
    ) -> BinderResult<()> {
        log::info!("event=soterta code={code} op={}", op_name(code));
        if code == INTERFACE_TRANSACTION {
            reply.write(&descriptor_text().to_string())?;
            return Ok(());
        }
        // AIDL 的回复第一个 int 是 status（0 = OK）。Java 的 Stub$Proxy 每条回复都先
        // readException() 读它；rsbinder 做服务端不写这一格，后面所有字段就会整体
        // 错位 4 字节（soterserver 把方法返回值当 status、把非空标记当返回值，
        // exportAsk 的 exportData 就解不出来，Duck/微信卡在 askModel）。
        reply.write_i32(0)?;
        // 号码先归一到「4 槽规范号」：不同设备的排布不一样，同一台上不同客户端
        // 也可能不一样（见 note_layout），所以按调用方各自记。
        let caller = caller_key();
        let code = canonical_code(&caller, code, reader.data_avail());
        // 先按 AIDL 定义把入参读干净：读错位的话后面拿到的 uid/alias 全是垃圾。
        let mut uid = None;
        let mut alias = None;
        let mut challenge = None;
        let mut session = None;
        match code {
            EXPORT_ASK_PUBLIC_KEY
            | GENERATE_ASK_KEY_PAIR
            | HAS_ASK_ALREADY
            | REMOVE_ALL_UID_KEY
            | EXPORT_ATTK_PUBLIC_KEY
            | GENERATE_ATTK_KEY_PAIR => {
                uid = reader.read::<i32>().ok();
            }
            EXPORT_AUTH_KEY_PUBLIC_KEY
            | GENERATE_AUTH_KEY_PAIR
            | HAS_AUTH_KEY
            | REMOVE_AUTH_KEY => {
                uid = reader.read::<i32>().ok();
                alias = reader.read::<String>().ok();
            }
            INIT_SIGN => {
                uid = reader.read::<i32>().ok();
                alias = reader.read::<String>().ok();
                challenge = reader.read::<String>().ok();
            }
            FINISH_SIGN => {
                session = reader.read::<i64>().ok();
            }
            _ => {}
        }
        log::info!(
            "event=soterta args code={code} uid={uid:?} alias={alias:?} challenge_len={} session={session:?}",
            challenge.as_deref().map(|c| c.len()).unwrap_or(0)
        );

        // 产线 provisioning 那三个（原厂 HAL 是空号）：工程模式的 SOTER key 就看 14 号。
        match code {
            VERIFY_ATTK_KEY_PAIR => {
                reply.write_i32(0)?;
                return Ok(());
            }
            GENERATE_ATTK_KEY_PAIR => {
                reply.write_i32(0)?;
                return Ok(());
            }
            EXPORT_ATTK_PUBLIC_KEY => {
                // ATTK 用我们自己的 ASK 顶：软件 TA 里 ASK 兼 ATTK，公钥就是那一把。
                let document = soter_local::ask_public_document(uid.unwrap_or(-1));
                write_bytes_reply(reply, &document, 0)?;
                return Ok(());
            }
            _ => {}
        }

        // 剩下的 11 个号码走本地软件 TA：ASK/AuthKey/会话全部复用注入侧那套实现，
        // 这样接管和注入两条路签出来的东西是同一种，不会出现两种假链。
        let call = soter::SoterCall {
            hal: true,
            hidl: false,
            has_return_code: has_return_code(),
            code,
            wire_code: code,
            op: op_name(code),
            uid,
            alias: alias.clone(),
            challenge: challenge.clone(),
            session,
            key: None,
            // 不填 `caller_uid`：这里能拿到的是 soterserver（uid 1000）——它才是调这个
            // HAL 的进程，不是 App。包名交给 daemon 用请求里的 `uid` 参数去翻。
            caller_uid: None,
            data_size: 0,
        };
        // 先问 daemon（它按配置决定是转 B 端真 TEE、走服务端还是本地兜底）；
        // 问不到才有本地自签那条退路。直接调 soter_local 的话永远只能自签，
        // 微信拿这把 ASK 去腾讯验证一定被拒（就是“系统错误”）。
        // finishSign：会话要是本进程开的（init 那笔服务端让我们本地答），这一笔也必须本地答。
        // 去问远程就是 B 端不认识这个句柄，直接 -204 —— 检测器的 T12 就是这么红的。
        let local_session = code == FINISH_SIGN && session.is_some_and(soter_local::has_session);
        if local_session {
            log::info!("event=soterta finishSign session is local; answering without the relay");
        }
        let answer = if local_session {
            soter_local::answer(&call)
        } else {
            soter_relay::answer(&call)
        };
        match answer {
            Some(Answer::Code(code)) => {
                log::info!("event=soterta reply code={code}");
                reply.write_i32(code)?;
            }
            Some(Answer::Buffer { code, data }) => {
                log::info!(
                    "event=soterta reply code={code} data={}",
                    data.as_ref().map(|d| d.len()).unwrap_or(0)
                );
                write_bytes_reply(reply, data.as_deref().unwrap_or(&[]), code)?;
            }
            Some(Answer::Init { status, session }) => {
                log::info!("event=soterta reply init status={status} session={session}");
                // initSign 返回的是 parcelable 本身，没有「方法返回值」那一格。
                write_init_return(reply, status, session)?;
            }
            None => {
                log::warn!("event=soterta reply none (no answer for this call)");
                // 没有真身份可报、或参数不够：回一个明确的错误码，别回 0 让调用方
                // 拿着空数据继续跑。NOT_FOUND 跟真机一样。
                if matches!(
                    code,
                    EXPORT_ASK_PUBLIC_KEY | EXPORT_AUTH_KEY_PUBLIC_KEY | FINISH_SIGN
                ) {
                    write_bytes_reply(reply, &[], -4)?;
                } else {
                    reply.write_i32(-4)?;
                }
            }
        }
        Ok(())
    }

    fn on_dump(&self, _writer: &mut dyn std::io::Write, _args: &[String]) -> BinderResult<()> {
        Ok(())
    }
}

/// 起服务并常驻。返回即表示服务名已经抢到手。
///
/// `driver` 决定注册到哪个 servicemanager：vendor 的 AIDL HAL 习惯落在
/// `/dev/vndbinder`（vndservicemanager），应用侧的 Java 客户端只看 `/dev/binder`。
/// App 面向接口的自测端点：只在开关（环境变量或 `/data/misc/ommega/soter_app_selftest`）
/// 打开时注册。它的**接口描述符就是** `com.tencent.soter.soterserver.ISoterService`，
/// 所以 `service call ommega.soter.app/default <code> i32 <uid>` 发出来的字节跟宿主
/// 收到的那笔一模一样：解析、答复两段能单独验，不用起任何 app。
const APP_SELFTEST_ENV: &str = "OMMEGA_SOTER_APP_SELFTEST";
const APP_SELFTEST_SWITCH: &str = "/data/misc/ommega/soter_app_selftest";
const APP_SELFTEST_SERVICE: &str = "ommega.soter.app/default";

struct AppFace;

impl Remotable for AppFace {
    fn descriptor() -> &'static str {
        soter::APP_DESCRIPTOR
    }

    fn on_transact(
        &self,
        code: TransactionCode,
        reader: &mut Parcel,
        reply: &mut Parcel,
    ) -> BinderResult<()> {
        if code == INTERFACE_TRANSACTION {
            reply.write(&soter::APP_DESCRIPTOR.to_string())?;
            return Ok(());
        }
        // 这一层还没人读过 reader，data_position 是 0，直接拿整块字节就是请求原文。
        let data = unsafe { std::slice::from_raw_parts(reader.as_ptr(), reader.data_size()) };
        let Some(call) = soter::parse(data, code) else {
            log::warn!("event=soterta app-selftest code={code} unparsable");
            reply.write_i32(-1)?;
            return Ok(());
        };
        log::info!(
            "event=soterta app-selftest code={} op={} uid={:?} alias={:?}",
            code,
            call.op,
            call.uid,
            call.alias
        );
        match soter::answer_app_call(&call, call.uid.unwrap_or(-1)) {
            Some(answer) => write_app_answer(reply, &answer)?,
            None => {
                log::warn!("event=soterta app-selftest code={code} no answer");
                reply.write_i32(-1)?;
            }
        }
        Ok(())
    }

    fn on_dump(&self, _writer: &mut dyn std::io::Write, _args: &[String]) -> BinderResult<()> {
        Ok(())
    }
}

/// 把一份 App 面向的答复写进 rsbinder 的 reply（形状跟宿主自己写的一致）。
fn write_app_answer(reply: &mut Parcel, answer: &soter::AppAnswer) -> BinderResult<()> {
    // 第一格是 AIDL 的 Status（0 = OK），Java 的 `readException()` 读的就是它。
    reply.write_i32(0)?;
    match answer {
        soter::AppAnswer::Int(value) => {
            reply.write_i32(*value)?;
        }
        soter::AppAnswer::Export { code, data } => {
            reply.write_i32(1)?;
            reply.write_i32(*code)?;
            match data {
                Some(bytes) => {
                    reply.write(&bytes.clone())?;
                    reply.write_i32(bytes.len() as i32)?;
                }
                None => {
                    reply.write_i32(-1)?;
                    reply.write_i32(0)?;
                }
            }
        }
        soter::AppAnswer::Session { session, code } => {
            reply.write_i64(*session)?;
            reply.write_i32(*code)?;
        }
        soter::AppAnswer::Extra(value) => {
            // 非空标记 + writeValue(Integer) 的类型标 + 值
            reply.write_i32(1)?;
            reply.write_i32(1)?;
            reply.write_i32(*value)?;
        }
    }
    Ok(())
}

/// 自测端点开着吗。
fn app_selftest_enabled() -> bool {
    if std::path::Path::new(APP_SELFTEST_SWITCH).exists() {
        return true;
    }
    std::env::var(APP_SELFTEST_ENV).is_ok_and(|value| {
        let value = value.trim().to_ascii_lowercase();
        value == "1" || value == "true" || value == "on"
    })
}

pub fn serve(driver: &str) -> anyhow::Result<()> {
    // 第二个参数是 binder 线程池上限。传 0 会让驱动把上限设成 0：framework 那边会报
    // 「Thread Pool max thread count is 0. Cannot cache binder as linkToDeath cannot be
    // implemented」，而且 looper 会在十几秒后被驱动拒掉、进程静默退出（保活又拉起来，
    // 就是现场那个每 20 秒换一个 pid 的抖动）。这里给默认 15。
    rsbinder::ProcessState::init(driver, 15)
        .map_err(|error| anyhow::anyhow!("binder init on {driver} failed: {error}"))?;
    // 用 `System` 而不是 `Vintf`：`Vintf` 要求服务名在 VINTF 清单里有 AIDL 声明，
    // 但很多老平台只声明了 HIDL 的 `vendor.qti.hardware.soter@1.0::ISoter`（PGP110 /
    // Android 15 实测）。那种机器上 `Vintf` 会在 servicemanager 侧直接被拒（
    // `VINTF declaration error`），soterta.sh 就每 5 秒停一次原厂 HAL、再拉回来。
    //
    // 也不能用 `Vendor`：那档注册得上（不校验 VINTF），但只有 vendor 域的客户端
    // 能访问，**工程模式（system_app 域）调过来会被 servicemanager 直接拒掉**
    // —— 现场表现就是 `service check` 能查到名字、`service call` 却是
    // `Parcel(NULL)`（日志里只有一笔 INTERFACE_TRANSACTION，真调用的 code 根本
    // 没进来），工模因此判 SOTER key 失败。
    //
    // `System` 不校验 VINTF 且 system 域能访问；走 HIDL 的微信不经过这条 AIDL 服务，
    // 不受影响。
    let binder = Binder::new_with_stability(SoterTa, Stability::System);
    let service = service_name();
    let descriptor = descriptor_of(&service);
    let _ = DESCRIPTOR.set(descriptor);
    HAS_RETURN_CODE.store(
        descriptor == DEFAULT_DESCRIPTOR,
        std::sync::atomic::Ordering::Relaxed,
    );
    hub::add_service(&service, binder.as_binder())?;
    if app_selftest_enabled() {
        let face = Binder::new_with_stability(AppFace, Stability::System);
        match hub::add_service(APP_SELFTEST_SERVICE, face.as_binder()) {
            Ok(()) => {
                log::info!("event=soterta registered app selftest endpoint {APP_SELFTEST_SERVICE}")
            }
            Err(error) => log::warn!("event=soterta app selftest endpoint failed ({error:#})"),
        }
    }
    log::info!(
        "event=soterta registered {service} on {driver} (descriptor={descriptor} return_code={})",
        has_return_code()
    );
    // 本地兜底那条路的 cpu_id 得给 app 域那份 payload 备好：宿主是 platform_app，
    // exec `getprop` 被 SELinux 拒、直接读属性区也拿不到序列号。这里跑在 root 里，
    // 算一次落盘，宿主那边直接读文件。
    let local_cpu_id = crate::hook::soter_local::device_id();
    if !local_cpu_id.is_empty() {
        crate::hook::soter_local::publish_local_cpu_id(&local_cpu_id);
    }
    // 连 daemon 的 RPC 放后台：它要等 socket 就绪（最长几十秒），不能挡着注册
    // —— soterta.sh 在启动后一秒就看服务名在不在，迟一步就被当成失败回滚掉。
    std::thread::spawn(|| match crate::ipc::install_direct_rpc_session() {
        Ok(()) => log::info!("event=soterta daemon RPC ready"),
        Err(error) => {
            log::warn!("event=soterta daemon RPC unavailable ({error:#}); local signing only")
        }
    });
    // 注册完就得有人处理事务：主线程进 binder 事件循环（rsbinder 的 join_thread_pool）
    rsbinder::ProcessState::join_thread_pool()?;
    Ok(())
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    /// 布局按调用方分开记：同一台机器上两个客户端用不同号表时互不干扰。
    ///
    /// 以前是全局一个 AtomicU8，先到的 soterserver 把布局定成 4 槽，后到的
    /// SoterChecker 走连号就全程调到错的方法上（MEIZU 20 Pro 实测五项全红）。
    #[test]
    fn layouts_are_tracked_per_caller() {
        // 4 槽那套：hasAskAlready 是 9，号表原样不动。
        assert_eq!(canonical_code("/test/4slot", 9, 4), 9);
        assert_eq!(canonical_code("/test/4slot", 5, 4), 5);
        // 连号那套：7 = hasAskAlready、9 = initSign，换算成 4 槽的 9 / 11。
        assert_eq!(canonical_code("/test/11slot", 7, 4), 9);
        assert_eq!(canonical_code("/test/11slot", 9, 4), 11);
        // 两个调用方互不覆盖：先记下的 4 槽不会被后到的连号改掉。
        assert_eq!(canonical_code("/test/4slot", 5, 4), 5);
        assert_eq!(canonical_code("/test/11slot", 5, 4), 7);
    }

    /// 头一次就判不出来的调用方保持未知（号表原样），量一次号表也不会写脏。
    #[test]
    fn unknown_layout_keeps_the_raw_code() {
        assert_eq!(canonical_code("/test/unknown", 13, 4), 13);
        assert_eq!(layout_slot("/test/unknown"), LAYOUT_UNKNOWN);
    }
}
