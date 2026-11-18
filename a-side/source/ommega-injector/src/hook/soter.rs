//! SOTER 那一族的识别与解析（A 端）。
//!
//! 两条路：出站是宿主 `com.tencent.soter.soterserver` 发往 HAL 的 `ISoter` 一族描述符，
//! 入站是 App 发往宿主的 `ISoterService`。号码表见 [`describe`]；两边接口独立，号码不通用。
//!
//! 认得出来的号由本地/远程后端写应答（`soter_local` / `soter_relay`），认不出或缺参数的
//! 照旧透给真 HAL。日志格式 `event=soter …`。
//!
//! 参数里的 uid 是 App 自己填的；可信的调用者是事务头里的 `sender_euid`。

use std::cell::RefCell;
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::hook::binder::{
    binder_transaction_data, binder_transaction_data_data, binder_transaction_data_data_ptr,
    binder_transaction_data_target, BINDER_BUFFER_FLAG_HAS_PARENT, BINDER_TYPE_PTR, BR_REPLY_CMD,
    BR_TRANSACTION_COMPLETE_CMD, TF_ONE_WAY,
};
use crate::hook::soter_local::{self, Answer};
use crate::parcel::{
    build_app_export_reply, build_app_extra_param_reply, build_app_int_reply,
    build_app_session_reply, build_hidl_soter_buffer_reply, build_hidl_soter_init_reply,
    build_plain_reply, build_soter_buffer_reply, build_soter_init_reply, OwnedReply,
    HIDL_STRUCT_SIZE,
};

/// 高通 HAL 的接口描述符（SoterService 发出去的那条）。
pub(crate) const HAL_DESCRIPTOR: &str = "vendor.qti.hardware.soter.ISoter";
/// Trustonic 那套 AIDL 的描述符（联发科机型）。方法号与高通同序，1..14 共用一张表；
/// 差别只在 2 / 6 / 14：联发科上是真实现，高通那边是空号。
pub(crate) const TRUSTONIC_DESCRIPTOR: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter";
/// HIDL 那一版的描述符（`@1.0::`），跟 AIDL 那两条无关：号码、参数、回复形状都是
/// `.hal` 的声明顺序，这几条 HIDL 描述符共用一套。
pub(crate) const QTI_HIDL_DESCRIPTOR: &str = "vendor.qti.hardware.soter@1.0::ISoter";
pub(crate) const TRUSTONIC_HIDL_DESCRIPTOR: &str =
    "vendor.trustonic.hardware.soter@1.0::ITrustonicSoter";
/// 小米那套 HIDL：接口名与方法顺序跟上面两条一样，只有包名不同。
pub(crate) const XIAOMI_HIDL_DESCRIPTOR: &str = "vendor.xiaomi.hardware.soterservice@1.0::ISoter";
/// Microtrust 的 HIDL 契约（initSign=13、finishSign=14），未上机验证。
pub(crate) const MICROTRUST_HIDL_DESCRIPTOR: &str = "vendor.microtrust.hardware.soter@1.0::ISoter";
/// App 面向的接口描述符（App 发给 SoterService 的那条，走的是入站 transaction）。
pub(crate) const APP_DESCRIPTOR: &str = "com.tencent.soter.soterserver.ISoterService";

/// 描述符是哪一边的。HIDL 单独一档，因为事务号、参数形状、答复布局全是另一套：
///
/// - 事务号是 `.hal` 的声明顺序 1..14，映射见 [`HIDL_TO_INTERNAL_CODE`]，跟 AIDL 不通用。
/// - 回包开头是 `Status`（i32，0 成功；非 0 后跟一条 String16 message）。
/// - string / vector 走 binder buffer 对象：结构体与数据体在 parcel 外，按对象里的地址读。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Hal,
    HalHidl,
    App,
}

impl Side {
    /// 是不是宿主发往 HAL 的那条路（HIDL 也走拦截，只是答复形状另拼）。
    pub(crate) fn is_hal(self) -> bool {
        matches!(self, Side::Hal | Side::HalHidl)
    }
}

/// 一条被认出来的 SOTER 请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SoterCall {
    /// 描述符是哪一边的：`true` = HAL（宿主发出去），`false` = App 面向。
    pub(crate) hal: bool,
    /// 走的是 HIDL（`@1.0::` 那种描述符）：号码已换算成内部号，答复按 HIDL 布局另拼。
    pub(crate) hidl: bool,
    /// 回包里有没有「方法返回值」那一格，只对 buffer 形状的方法成立（`finishSign` /
    /// `export*` / `getDeviceId`）：高通是 `int`、联发科是 `void`。`initSign` 两家都没有。
    pub(crate) has_return_code: bool,
    pub(crate) code: u32,
    /// 线上原号（`code` 已是内部号）；只为日志对得上真实流量。
    pub(crate) wire_code: u32,
    pub(crate) op: &'static str,
    pub(crate) uid: Option<i32>,
    pub(crate) alias: Option<String>,
    pub(crate) challenge: Option<String>,
    pub(crate) session: Option<i64>,
    /// App 面向 13 号 `getExtraParam` 那个 key。
    pub(crate) key: Option<String>,
    /// 真调用者：App 侧那笔事务头里内核填的 `sender_euid`，只有 HAL 侧才有；
    /// 参数里那个 uid 是调用方自己填的，信不得。
    ///
    /// 这里不翻包名（`sec_key_att_app_id_provider` 只认 Keystore/Credstore 的 uid），
    /// 由跑在 keystore uid 的 daemon 做。
    pub(crate) caller_uid: Option<i32>,
    /// 请求体总字节数，写日志时对一眼就知道有没有漏掉参数。
    pub(crate) data_size: usize,
}

/// 参数长什么样（两个接口里同一个号码可能是不同形状，所以不能只看 code）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Args {
    None,
    Uid,
    UidAlias,
    UidAliasChallenge,
    Session,
    Key,
}

/// 号码到（方法名、参数形状）。认不出来就是别人家的流量。
fn describe(hal: bool, code: u32) -> Option<(&'static str, Args)> {
    if hal {
        // 4 槽排布，2 / 6 / 14 是空号；5 / 9 号只带 uid。
        Some(match code {
            1 => ("exportAskPublicKey", Args::Uid),
            3 => ("exportAuthKeyPublicKey", Args::UidAlias),
            4 => ("finishSign", Args::Session),
            5 => ("generateAskKeyPair", Args::Uid),
            7 => ("generateAuthKeyPair", Args::UidAlias),
            8 => ("getDeviceId", Args::None),
            9 => ("hasAskAlready", Args::Uid),
            10 => ("hasAuthKey", Args::UidAlias),
            11 => ("initSign", Args::UidAliasChallenge),
            12 => ("removeAllUidKey", Args::Uid),
            13 => ("removeAuthKey", Args::UidAlias),
            // 产线 provisioning 那三个（工程模式的 SOTER 项走 14 号）；本地后端也答。
            2 => ("exportAttkPublicKey", Args::Uid),
            6 => ("generateAttkKeyPair", Args::Uid),
            14 => ("verifyAttkKeyPair", Args::None),
            _ => return None,
        })
    } else {
        Some(match code {
            1 => ("generateAppSecureKey", Args::Uid),
            2 => ("getAppSecureKey", Args::Uid),
            3 => ("hasAskAlready", Args::Uid),
            4 => ("generateAuthKey", Args::UidAlias),
            5 => ("removeAuthKey", Args::UidAlias),
            6 => ("getAuthKey", Args::UidAlias),
            7 => ("removeAllAuthKey", Args::Uid),
            8 => ("hasAuthKey", Args::UidAlias),
            9 => ("initSigh", Args::UidAliasChallenge),
            10 => ("finishSign", Args::Session),
            11 => ("getDeviceId", Args::None),
            12 => ("getVersion", Args::None),
            13 => ("getExtraParam", Args::Key),
            _ => return None,
        })
    }
}

/// 这个号会不会改设备上的钥匙（建 / 删）：只用来标日志与 mutation 开关。
/// App 面向的 9 号（`initSigh`）也算，B 端可能顺手建 AuthKey。
pub(crate) fn is_mutation(hal: bool, code: u32) -> bool {
    if hal {
        matches!(code, 5 | 7 | 12 | 13)
    } else {
        matches!(code, 1 | 4 | 5 | 7 | 9)
    }
}

/// 请求里那个 `binder_buffer_object`（HIDL 的 string / vector 走它），字段照内核 uapi
/// 的 `struct binder_buffer_object` 摆。解析只用到 `type_` / `length` / `buffer`。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct HidlBufferObject {
    type_: u32,
    flags: u32,
    buffer: usize,
    length: usize,
    parent: usize,
    parent_offset: usize,
}

/// 一个只往前走、每一步都做边界检查的 parcel 读游标。
/// 读的是别的进程写下的字节，宁可读不出来也不能越界。
struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
    /// HIDL 那条路：string 不是内联的 String16，而是 binder 的 buffer 对象。
    hidl: bool,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], at: usize, hidl: bool) -> Self {
        Self { data, at, hidl }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.at)
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        if self.remaining() < count {
            return None;
        }
        let slice = &self.data[self.at..self.at + count];
        self.at += count;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i32(&mut self) -> Option<i32> {
        self.u32().map(|value| value as i32)
    }

    fn i64(&mut self) -> Option<i64> {
        let bytes = self.take(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Some(i64::from_le_bytes(raw))
    }

    fn u64(&mut self) -> Option<u64> {
        let bytes = self.take(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Some(u64::from_le_bytes(raw))
    }

    /// AIDL 的 String 就是 String16，跟 interface token 里的描述符一个格式：
    /// `[i32 字符数][UTF-16LE 2*字符数 字节][补到 4 字节]`（0 = 空串，-1 = null）。
    fn string(&mut self) -> Option<String> {
        let (text, at) = read_string16(self.data, self.at)?;
        self.at = at;
        Some(text)
    }

    /// 按这一路自己的写法读一个参数字符串。
    fn text(&mut self) -> Option<String> {
        if self.hidl {
            self.hidl_string()
        } else {
            self.string()
        }
    }

    /// 一个 `binder_buffer_object`。第二个 u32 是 buffer 自己的 flags
    /// （`BINDER_BUFFER_FLAG_HAS_PARENT` 在这一格），不是 `hdr.flags`，别弄反。
    fn hidl_buffer_object(&mut self) -> Option<HidlBufferObject> {
        let type_ = self.u32()?;
        let flags = self.u32()?;
        let buffer = self.abi_usize()?;
        let length = self.abi_usize()?;
        let parent = self.abi_usize()?;
        let parent_offset = self.abi_usize()?;
        Some(HidlBufferObject {
            type_,
            flags,
            buffer,
            length,
            parent,
            parent_offset,
        })
    }

    fn abi_usize(&mut self) -> Option<usize> {
        if size_of::<usize>() == size_of::<u64>() {
            self.u64().map(|value| value as usize)
        } else {
            self.u32().map(|value| value as usize)
        }
    }

    /// HIDL 的 `hidl_string`：parcel 里两个对象 —— 一个指向 16 字节的 `hidl_string` 结构体
    /// （`hidl_pointer mBuffer`(8) + `uint32_t mSize`(4) + 补位），一个指向字符本体（含 NUL）。
    /// 两者都在 parcel 外，按对象里的地址读。
    ///
    /// 地址是本进程的（宿主自己写的），但仍走 `process_vm_readv`：读不动就当认不出来。
    fn hidl_string(&mut self) -> Option<String> {
        let parent = self.hidl_buffer_object()?;
        let child = self.hidl_buffer_object()?;
        if parent.type_ != BINDER_TYPE_PTR || parent.length != HIDL_STRUCT_SIZE {
            return None;
        }
        if child.type_ != BINDER_TYPE_PTR || child.flags != BINDER_BUFFER_FLAG_HAS_PARENT {
            return None;
        }
        let mut head = [0u8; HIDL_STRUCT_SIZE];
        read_self(parent.buffer, &mut head)?;
        let pointer = usize::try_from(u64::from_le_bytes(head[0..8].try_into().ok()?)).ok()?;
        let size = u32::from_le_bytes(head[8..12].try_into().ok()?) as usize;
        // 别名、challenge 都短得很，上千字节一定是读歪了。
        if size > 4096 {
            return None;
        }
        let mut bytes = vec![0u8; size];
        read_self(pointer, &mut bytes)?;
        String::from_utf8(bytes).ok()
    }

    fn skip_padding(&mut self, written: usize) -> Option<()> {
        let pad = written.next_multiple_of(4) - written;
        if pad > 0 {
            self.take(pad)?;
        }
        Some(())
    }
}

/// 从 data 开头认接口 token，返回（哪一边、buffer 形状方法带不带 int 返回值、参数区起点）。
///
/// 见过的前缀（里面都是 i32）：
///
/// ```text
///  0 字节：[CString + 4-byte padding]                  libhwbinder / HIDL
///  0 字节：[String16]                                  legacy fixtures / AIDL
///  4 字节：[strict-mode policy][String16]              老一点的 libbinder
///  8 字节：[strict-mode policy]['SYST'][String16]       （没见过实例，但形状上说得通）
/// 12 字节：[strict-mode policy][work source]['SYST'][String16]
/// ```
///
/// 12 字节那个是 app_process 的布局：`len` 是字符数，结尾 0 是另一个 u32；老写法把结尾
/// 0 算进 `len`，两种都试。第二个返回值：高通两条是 `int`，联发科两条是 `void`，
/// `initSign` 两家都不带。
fn match_descriptor(data: &[u8]) -> Option<(Side, bool, usize)> {
    // libhwbinder writeInterfaceToken -> writeCString writes strlen + 1 bytes,
    // padded to four bytes, without any libbinder policy/work-source prefix.
    if let Some((has_return_code, next)) = read_hidl_token(data) {
        return Some((Side::HalHidl, has_return_code, next));
    }
    for prefix in [0usize, 4, 8, 12] {
        let variants: &[bool] = if prefix == 12 {
            &[true, false]
        } else {
            &[false]
        };
        for with_trailing_word in variants {
            let Some((text, mut next)) = read_string16(data, prefix) else {
                continue;
            };
            if *with_trailing_word {
                // 现代写法的终结符是单另一个 u32，不是就得落回老写法。
                if data.get(next..next + 4) != Some(&[0, 0, 0, 0][..]) {
                    continue;
                }
                next += 4;
            }
            if text == HAL_DESCRIPTOR {
                return Some((Side::Hal, true, next));
            }
            if text == TRUSTONIC_DESCRIPTOR {
                return Some((Side::Hal, false, next));
            }
            if text == QTI_HIDL_DESCRIPTOR {
                return Some((Side::HalHidl, true, next));
            }
            if text == TRUSTONIC_HIDL_DESCRIPTOR {
                return Some((Side::HalHidl, false, next));
            }
            if text == XIAOMI_HIDL_DESCRIPTOR || text == MICROTRUST_HIDL_DESCRIPTOR {
                // 第二个值在 HIDL 这条路上用不上（回复按 [`Side::HalHidl`] 另拼，
                // 不读这一格），统一填 false。
                return Some((Side::HalHidl, false, next));
            }
            if text == APP_DESCRIPTOR {
                return Some((Side::App, false, next));
            }
        }
    }
    None
}

/// Recognise only an exact, unprefixed HIDL CString token: no scanning of arbitrary
/// payload bytes, no AIDL descriptor in the CString encoding.
fn read_hidl_token(data: &[u8]) -> Option<(bool, usize)> {
    for (descriptor, has_return_code) in [
        (QTI_HIDL_DESCRIPTOR, true),
        (TRUSTONIC_HIDL_DESCRIPTOR, false),
        (XIAOMI_HIDL_DESCRIPTOR, false),
        (MICROTRUST_HIDL_DESCRIPTOR, false),
    ] {
        let bytes = descriptor.as_bytes();
        let next = (bytes.len() + 1).next_multiple_of(4);
        if data.starts_with(bytes)
            && data.get(bytes.len()) == Some(&0)
            && data
                .get(bytes.len() + 1..next)
                .is_some_and(|padding| padding.iter().all(|byte| *byte == 0))
        {
            return Some((has_return_code, next));
        }
    }
    None
}

/// 读一个 String16（i32 字符数 0 = 空串、-1 = null，然后 UTF-16LE 的 2*len 字节，
/// 补齐到 4），返回 (文本, 参数区起点)。
fn read_string16(data: &[u8], at: usize) -> Option<(String, usize)> {
    let mut cursor = Cursor::new(data, at, false);
    let len = cursor.u32()?;
    if len == u32::MAX {
        // AIDL 里 -1 表示 null
        return None;
    }
    let len = len as usize;
    if len > 512 {
        return None;
    }
    let bytes = cursor.take(len.checked_mul(2)?)?;
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    let text = String::from_utf16(&units).ok()?;
    // Android 的 writeString16 是「字符 + 一个 NUL」，再补到 4 字节对齐（空串也带）。
    // 漏这一步游标会少走 4 字节，紧跟在字符串后的字段会被读成空串。
    cursor.take(2)?;
    cursor.skip_padding(len * 2 + 2)?;
    Some((text, cursor.at))
}

/// HIDL 的号对到内部（AIDL）那套号码上。
///
/// `.hal` 里 14 个方法按声明顺序拿号（1 generateAttkKeyPair … 13 initSign、14 finishSign），
/// 跟 AIDL 的排列不同，这张表是两边 proxy 的 `transact(n, …)` 字面量对出来的，别重排。
/// 1/2/3 落到 AIDL 的 6/14/2（provisioning 号），照旧认不出来。
const HIDL_TO_INTERNAL_CODE: [u32; 14] = [6, 14, 2, 8, 5, 1, 12, 9, 7, 3, 13, 10, 11, 4];

fn hidl_internal_code(code: u32) -> Option<u32> {
    let index = code.checked_sub(1)? as usize;
    HIDL_TO_INTERNAL_CODE.get(index).copied()
}

/// 读自己进程里的内存，读不动就返回 `None`（`process_vm_readv` 失败，不是崩）。
fn read_self(address: usize, out: &mut [u8]) -> Option<()> {
    if out.is_empty() {
        return Some(());
    }
    if address == 0 {
        return None;
    }
    crate::sys::read_process_exact(nix::unistd::Pid::this(), address, out).ok()
}

/// 解析一条 transaction 的 data。认不出来就返回 `None`（正常流量都归这一类）。
pub(crate) fn parse(data: &[u8], code: u32) -> Option<SoterCall> {
    let (side, has_return_code, args_at) = match_descriptor(data)?;
    let hal = side.is_hal();
    let hidl = side == Side::HalHidl;
    // HIDL 的号换算成内部号，之后的分派全只看内部号。
    let wire_code = code;
    let code = if hidl {
        hidl_internal_code(code)?
    } else {
        code
    };
    let (op, shape) = describe(hal, code)?;
    let mut cursor = Cursor::new(data, args_at, hidl);
    let (uid, alias, challenge, session, key) = match shape {
        Args::None => (None, None, None, None, None),
        Args::Uid => (Some(cursor.i32()?), None, None, None, None),
        Args::UidAlias => (Some(cursor.i32()?), Some(cursor.text()?), None, None, None),
        Args::UidAliasChallenge => (
            Some(cursor.i32()?),
            Some(cursor.text()?),
            Some(cursor.text()?),
            None,
            None,
        ),
        Args::Session => (None, None, None, Some(cursor.i64()?), None),
        Args::Key => (None, None, None, None, Some(cursor.text()?)),
    };
    Some(SoterCall {
        hal,
        hidl,
        has_return_code,
        code,
        wire_code,
        op,
        uid,
        alias,
        challenge,
        session,
        key,
        caller_uid: None,
        data_size: data.len(),
    })
}

/// App 面向那笔请求带来的调用者 uid 只在这么长的时间内算数：一笔 App 调用和它引发的
/// HAL 调用是同一线程前后脚（毫秒级），2 秒足够又不会串到下一笔无关的调用。
const APP_CALLER_WINDOW: Duration = Duration::from_millis(2000);

thread_local! {
    /// 本线程「刚进来的那笔 App 面向 SOTER 请求」的真调用者（内核填的 `sender_euid`）与时刻。
    /// 宿主收完 App 请求会在同一个 binder 线程上同步调 HAL，所以出站那笔靠这个接上调用者。
    static APP_CALLER: RefCell<Option<(i32, Instant)>> = const { RefCell::new(None) };
}

/// 记一笔：本线程刚收到 App 面向的 SOTER 请求，调用者是 `uid`（内核填的 `sender_euid`）。
fn note_app_caller(uid: i32) {
    APP_CALLER.with(|slot| {
        *slot.borrow_mut() = if uid < 0 {
            // 内核没填（异常事务）：宁可不记，也别把 -1 当调用者去翻包名。
            None
        } else {
            Some((uid, Instant::now()))
        };
    });
}

/// 取走本线程记下的调用者 uid。取走即清：一笔 App 调用只借给紧跟着的那笔 HAL 调用。
/// 没记过、或者已经出了窗口，都返回 `None`。
fn take_app_caller_uid() -> Option<i32> {
    let (uid, at) = APP_CALLER.with(|slot| slot.borrow_mut().take())?;
    (at.elapsed() <= APP_CALLER_WINDOW).then_some(uid)
}

/// 一笔 App 面向调用留下的凭据：谁在调 + 这笔请求长什么样。
/// 光记 uid 不够：宿主可能换线程调 HAL，一笔 App 请求也可能引出好几笔 HAL 调用。
#[derive(Debug, Clone)]
struct AppCaller {
    uid: i32,
    at: Instant,
    /// App 面向那笔请求里的别名（有些接口没这一格）。
    alias: Option<String>,
    /// 会话号（`finish_sign` 那类只有会话号）。
    session: Option<i64>,
}

impl AppCaller {
    /// 同一把钥匙/同一张会话的旧凭据就不用留了：一轮流程里同一个别名会被问很多遍。
    fn same_key(&self, call: &SoterCall) -> bool {
        self.alias.as_deref() == call.alias.as_deref() && self.session == call.session
    }

    /// 这笔凭据是不是「没别名也没会话」（`has_ask_already` / `export_ask_public_key` 那套）。
    fn bare(&self) -> bool {
        self.alias.as_deref().unwrap_or("").is_empty() && self.session.is_none()
    }
}

/// 最近几笔 App 面向调用的凭据。按**进程**记，不按线程。
static RECENT_APP_CALLERS: Mutex<Vec<AppCaller>> = Mutex::new(Vec::new());

/// 凭据在进程级列表里留多久。比同线程那个 2 秒窗长，宿主把出站那几笔排后面也还赶得上。
const APP_CALLER_TTL: Duration = Duration::from_secs(10);

/// 列表最长多少笔（满了丢最旧的）。
const APP_CALLER_CAP: usize = 32;

/// 记一笔 App 面向调用，给出站那几笔回查用。`uid` 是内核填的 `sender_euid`。
fn remember_app_caller(call: &SoterCall, uid: i32) {
    let Ok(mut list) = RECENT_APP_CALLERS.lock() else {
        return;
    };
    let now = Instant::now();
    list.retain(|entry| now.saturating_duration_since(entry.at) <= APP_CALLER_TTL);
    list.retain(|entry| !entry.same_key(call));
    list.push(AppCaller {
        uid,
        at: now,
        alias: call.alias.clone(),
        session: call.session,
    });
    while list.len() > APP_CALLER_CAP {
        list.remove(0);
    }
}

/// 从最近几笔凭据里挑一笔给出站 HAL 调用用。抽成纯函数好测。
/// 顺序：别名 → 会话号 → 两边都没有时拿最近一笔。
fn pick_recent_caller(list: &[AppCaller], call: &SoterCall, now: Instant) -> Option<i32> {
    let fresh = |entry: &AppCaller| now.saturating_duration_since(entry.at) <= APP_CALLER_TTL;
    let alias = call.alias.as_deref().filter(|alias| !alias.is_empty());
    if let Some(alias) = alias {
        if let Some(hit) = list
            .iter()
            .rev()
            .find(|entry| fresh(entry) && entry.alias.as_deref() == Some(alias))
        {
            return Some(hit.uid);
        }
    }
    if let Some(session) = call.session {
        if let Some(hit) = list
            .iter()
            .rev()
            .find(|entry| fresh(entry) && entry.session == Some(session))
        {
            return Some(hit.uid);
        }
    }
    if alias.is_none() && call.session.is_none() {
        if let Some(hit) = list.iter().rev().find(|entry| fresh(entry) && entry.bare()) {
            return Some(hit.uid);
        }
    }
    // 最后一道：“认不出接口名/号”留下的那笔（无别名无会话）在 2 秒内可以去顶任意形状的
    // 出站调用（宿主换了一套 App 面向接口时只有这条路能拿到调用者）。
    // 边界：只收无别名无会话的凭据，属于别的钥匙的凭据不许顶。
    list.iter()
        .rev()
        .find(|entry| now.saturating_duration_since(entry.at) <= RAW_APP_CALLER_TTL && entry.bare())
        .map(|entry| entry.uid)
}

/// 记一笔“认不出接口名、但确实是 App 发进来的”调用者。它没有别名/会话可对，
/// 只能走时间窗（是推断，前面三条都对不上时才用）。
fn remember_raw_app_caller(uid: i32) {
    let Ok(mut list) = RECENT_APP_CALLERS.lock() else {
        return;
    };
    let now = Instant::now();
    list.retain(|entry| now.saturating_duration_since(entry.at) <= APP_CALLER_TTL);
    list.push(AppCaller {
        uid,
        at: now,
        alias: None,
        session: None,
    });
    while list.len() > APP_CALLER_CAP {
        list.remove(0);
    }
}

/// 「认不出接口名/号」那种凭据能在多短的窗内去顶一笔出站调用；它是估的。
const RAW_APP_CALLER_TTL: Duration = Duration::from_secs(2);

/// 出站那笔该带谁：先问本线程刚记下的那笔（最近、最准），再回查进程级那份列表。
fn borrow_app_caller(call: &SoterCall) -> Option<i32> {
    if let Some(uid) = take_app_caller_uid() {
        return Some(uid);
    }
    let now = Instant::now();
    if let Ok(list) = RECENT_APP_CALLERS.lock() {
        if let Some(uid) = pick_recent_caller(&list, call, now) {
            return Some(uid);
        }
    }
    // 最后按别名找主人：宿主自己发的、没有 App 在调的带别名请求（开机一套、后台建/清钥匙）
    // 就靠这个归到同一主人。
    let alias = call.alias.as_deref().filter(|alias| !alias.is_empty())?;
    let owners = ALIAS_OWNERS.lock().ok()?;
    pick_alias_owner(&owners, alias, now)
}

/// 「这把别名是谁的」：别名 → 内核填的 uid。比一轮流程活得久，宿主自己发的同别名请求也用得上。
#[derive(Debug, Clone)]
struct AliasOwner {
    alias: String,
    uid: i32,
    at: Instant,
}

static ALIAS_OWNERS: Mutex<Vec<AliasOwner>> = Mutex::new(Vec::new());

/// 别名主人记多久：够跨好几轮 App 使用，又不至于 App 卸载/清数据后一直认错主人。
const ALIAS_OWNER_TTL: Duration = Duration::from_secs(600);

/// 最多记多少把别名。
const ALIAS_OWNER_CAP: usize = 64;

/// 记下这把别名的主人（App 面向那笔的内核 uid）。
fn remember_alias_owner(alias: &str, uid: i32) {
    let Ok(mut list) = ALIAS_OWNERS.lock() else {
        return;
    };
    let now = Instant::now();
    list.retain(|owner| now.saturating_duration_since(owner.at) <= ALIAS_OWNER_TTL);
    list.retain(|owner| owner.alias != alias);
    list.push(AliasOwner {
        alias: alias.to_string(),
        uid,
        at: now,
    });
    while list.len() > ALIAS_OWNER_CAP {
        list.remove(0);
    }
}

/// 这把别名的主人是谁（过期的、不是这把的都不算）。抽成纯函数好测。
fn pick_alias_owner(list: &[AliasOwner], alias: &str, now: Instant) -> Option<i32> {
    list.iter()
        .rev()
        .find(|owner| {
            owner.alias == alias && now.saturating_duration_since(owner.at) <= ALIAS_OWNER_TTL
        })
        .map(|owner| owner.uid)
}

/// 观察一条 transaction。不是 SOTER 的就一声不吭地回去。
///
/// # Safety
///
/// 调用方得保证 `tr.data.ptr.buffer` 指向 `tr.data_size` 个可读字节 —— 在
/// `parse_write_buffer` 里，payload shadow 已经把这段换成本进程里的副本了。
pub(crate) unsafe fn observe(tr: &binder_transaction_data, inbound: bool) -> Option<SoterCall> {
    let size = tr.data_size;
    if size == 0 || size > 1024 * 1024 {
        return None;
    }
    let buffer = tr.data.ptr.buffer as *const c_void;
    if buffer.is_null() {
        return None;
    }
    // SAFETY: 见上面那条 —— 调用点保证这段字节可读。
    let data = unsafe { std::slice::from_raw_parts(buffer as *const u8, size) };
    let mut call = match parse(data, tr.code).or_else(|| {
        inbound
            .then(|| parse_untokened_app(data, tr.code, tr.sender_euid))
            .flatten()
    }) {
        Some(call) => call,
        None => {
            // 认不出的接口 token 里，看着像 SOTER 的记一条（只在 debug 级日志开着时）。
            note_unrecognised_soter_token(data, tr.code);
            // 认不出接口名也得把调用者留下：`sender_euid` 跟接口名无关，只有 App 发进来的
            // 那笔才是应用 uid（宿主自己发往 HAL 的是 1000），足以分辨方向。
            if is_app_uid(tr.sender_euid) {
                note_app_caller(tr.sender_euid);
                remember_raw_app_caller(tr.sender_euid);
            }
            return None;
        }
    };
    if call.hal {
        // 宿主发往 HAL 的那笔：接上上一笔 App 请求的真调用者，转发时带给 daemon。
        call.caller_uid = borrow_app_caller(&call);
        note_hal_activity();
    } else {
        // App 面向那笔：`sender_euid` 调用方改不了，两处都记 —— 本线程那份给出站那一笔用，
        // 进程级那份给换了线程、或一笔 App 请求引出好几笔 HAL 调用时用。
        note_app_caller(tr.sender_euid);
        if tr.sender_euid >= 0 {
            remember_app_caller(&call, tr.sender_euid);
            if let Some(alias) = call.alias.as_deref().filter(|alias| !alias.is_empty()) {
                remember_alias_owner(alias, tr.sender_euid);
            }
        }
        // 宿主待会儿在这个线程上回它：留一份，BC_REPLY 出来时对号；异步事务不记。
        if (tr.flags & TF_ONE_WAY) == 0 {
            stash_pending_app(&call, tr.sender_euid);
        }
    }
    log_call(&call);
    Some(call)
}

/// AID_APP_START：第一个“装在机器上的应用”的 uid。比它小的都是 init / system_server /
/// root / shell 这些系统身份。
pub(crate) const AID_APP_START: i32 = 10000;

/// 本进程的 cmdline（一次读好）。放宽 App 腿时要靠它避开 keystore2。
fn self_cmdline() -> &'static str {
    static CMDLINE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CMDLINE.get_or_init(|| {
        std::fs::read("/proc/self/cmdline")
            .map(|bytes| {
                let end = bytes
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..end]).into_owned()
            })
            .unwrap_or_default()
    })
}

/// 能不能走「认不出接口名也把 App 面向那笔认下来」这条兜底。三条硬约束，缺一不可：
///   1. `sender_euid` 是应用（内核填的，伪造不了）；
///   2. 当前进程不是 keystore2 —— `IKeystoreService` 的号也在 1..13 里；
///   3. 当前进程看着是 SOTER 一族（cmdline 带 soter/tencent），HAL 客户端不算。
fn untokened_app_allowed(sender_uid: i32, cmdline: &str) -> bool {
    if !is_app_uid(sender_uid) {
        return false;
    }
    if cmdline.contains("keystore") {
        return false;
    }
    // HAL 进程（`vendor.*.soter-service` / `@1.0-service`）名字里也带 soter，但它们收到的
    // 是宿主转过去的出站调用；放宽只给宿主类进程。
    if cmdline.contains("-service") {
        return false;
    }
    cmdline.contains("soter") || cmdline.contains("tencent")
}

/// 认不出接口名时仍然把 App 面向那笔认下来（只在入站方向用）。
/// ROM 可能把接口名整个换掉，但方法号与参数形状没变；起始偏移不知道（token 长度随包名变），
/// 就把每个四字节对齐位置当候选起点试一遍，只收形状对得上的那个。
fn parse_untokened_app(data: &[u8], code: u32, sender_uid: i32) -> Option<SoterCall> {
    let allowed = untokened_app_allowed(sender_uid, self_cmdline());
    parse_untokened_with(data, code, sender_uid, allowed)
}

/// [`parse_untokened_app`] 的主体：`allowed` 抽出来方便单测。
fn parse_untokened_with(
    data: &[u8],
    code: u32,
    sender_uid: i32,
    allowed: bool,
) -> Option<SoterCall> {
    if !allowed {
        return None;
    }
    // 12/13 号无参或只有一把 key，没有形状可验，放宽了容易撞上别的服务。
    if matches!(code, 12 | 13) {
        return None;
    }
    let (op, shape) = describe(false, code)?;
    for start in untokened_starts(data) {
        let mut cursor = Cursor::new(data, start, false);
        let (uid, alias, challenge, session, key) = match shape {
            Args::Uid => (cursor.i32(), None, None, None, None),
            Args::UidAlias => match (cursor.i32(), cursor.string()) {
                (Some(uid), Some(alias)) => (Some(uid), Some(alias), None, None, None),
                _ => continue,
            },
            Args::UidAliasChallenge => match (cursor.i32(), cursor.string(), cursor.string()) {
                (Some(uid), Some(alias), Some(challenge)) => {
                    (Some(uid), Some(alias), Some(challenge), None, None)
                }
                _ => continue,
            },
            Args::Session => match cursor.i64() {
                // 会话号不会是小整数；小值往往是别的服务在同一偏移上碰出来的垃圾。
                Some(session) if session.unsigned_abs() > 1_000_000_000 => {
                    (None, None, None, Some(session), None)
                }
                _ => continue,
            },
            Args::None | Args::Key => continue,
        };
        if !plausible_untokened(uid, alias.as_deref(), challenge.as_deref()) {
            continue;
        }
        return Some(SoterCall {
            hal: false,
            hidl: false,
            has_return_code: false,
            code,
            wire_code: code,
            op,
            uid,
            alias,
            challenge,
            session,
            key,
            caller_uid: Some(sender_uid),
            data_size: data.len(),
        });
    }
    None
}

/// 候选起点：每个四字节对齐位置，且它前面得是四字节零填充（一个字段的尾巴）。
/// 不要求这一条的话，参数中间任意位置都可能被当成起点，解出一堆看似合理的数字。
fn untokened_starts(data: &[u8]) -> impl Iterator<Item = usize> + '_ {
    (8..data.len().saturating_sub(8)).filter(move |start| {
        let start = *start;
        start % 4 == 0 && start >= 4 && data.get(start - 4..start) == Some(&[0, 0, 0, 0][..])
    })
}

/// 解出来的参数像不像真的。uid 落在应用号段、alias / challenge 可打印。
fn plausible_untokened(uid: Option<i32>, alias: Option<&str>, challenge: Option<&str>) -> bool {
    if let Some(uid) = uid {
        if !(AID_APP_START..2_000_000).contains(&uid) {
            return false;
        }
    } else if alias.is_none() && challenge.is_none() {
        // 一点形状都没有的（例如只有会话号的那类）靠上一层的 session 范围把关。
        return true;
    }
    if let Some(alias) = alias {
        if alias.is_empty() || alias.len() > 256 {
            return false;
        }
        if !alias
            .bytes()
            .all(|byte| (0x20..0x7f).contains(&byte) || byte == b'&')
        {
            return false;
        }
    }
    if let Some(challenge) = challenge {
        // challenge 只是宿主转给 TA 的一段原文：真机微信给的是十六进制，检测器会给
        // 别的可打印串（例如 `sotercheck-chal-...`）。只要不像读歪的二进制就收。
        if challenge.is_empty() || challenge.len() > 256 {
            return false;
        }
        if !challenge.bytes().all(|byte| (0x20..0x7f).contains(&byte)) {
            return false;
        }
    }
    true
}

/// 这个 uid 看着是不是应用：分身（999xxxxx）与多用户（10xxxxx）也算。
/// 认不出接口名时靠它分辨方向（宿主自己发往 HAL 的 sender 是 1000）。
fn is_app_uid(uid: i32) -> bool {
    uid >= AID_APP_START
}

/// 这份 data 开头那个接口 token（NUL 结尾的串），取不到就回 `None`。
fn interface_token_of(data: &[u8]) -> Option<&str> {
    let end = data.iter().position(|byte| *byte == 0)?;
    let head = data.get(..end.min(192))?;
    std::str::from_utf8(head)
        .ok()
        .filter(|text| !text.is_empty())
}

/// 认不出的接口 token 里，看着像 SOTER/腾讯的记一条（debug 级日志关着就不写）。
fn note_unrecognised_soter_token(data: &[u8], code: u32) {
    if !log::log_enabled!(log::Level::Debug) {
        return;
    }
    let Some(token) = interface_token_of(data) else {
        return;
    };
    let lowered = token.to_ascii_lowercase();
    if !(lowered.contains("soter") || lowered.contains("tencent")) {
        return;
    }
    debug!(
        "event=soter unknown-descriptor token={token:?} code={code} bytes={}",
        data.len()
    );
}

fn log_call(call: &SoterCall) {
    let side = if call.hidl {
        "hal-hidl"
    } else if call.hal {
        "hal"
    } else {
        "app"
    };
    let line = format!(
        "event=soter side={side} code={} op={} uid={} alias={:?} session={:?} challenge_len={} key={:?} bytes={}{}",
        call.code,
        call.op,
        call.uid.map(|uid| uid.to_string()).unwrap_or_default(),
        call.alias.as_deref().unwrap_or(""),
        call.session,
        call.challenge.as_ref().map(String::len).unwrap_or(0),
        call.key.as_deref().unwrap_or(""),
        call.data_size,
        if is_mutation(call.hal, call.code) {
            " mutation=1"
        } else {
            ""
        },
    );
    let wire_code = if call.hidl {
        format!(" wire_code={}", call.wire_code)
    } else {
        String::new()
    };
    let caller_uid = call
        .caller_uid
        .map(|uid| format!(" caller_uid={uid}"))
        .unwrap_or_default();
    let line = format!("{line}{caller_uid}{wire_code}");
    // logcat 之外，同一条还顺 RPC 送一份给 daemon。
    info!("{line}");
    crate::ipc::report_event(line);
    if call.challenge.is_some() {
        debug!("event=soter challenge={:?}", call.challenge);
    }
}

/// 这条出站请求我们自己答还是放它去真 HAL：范围就是本地后端有实现的号码。
/// 号不认识、参数不够的由 `intercept_soter_call` 原样透传，不会把宿主挂住。
pub(crate) fn interceptable(call: &SoterCall) -> bool {
    call.hal && soter_local::answerable(call.code)
}

// ---------------------------------------------------------------------------------
// App 面向那一半：宿主自己不干活的时候，由我们把它的答复顶掉
// ---------------------------------------------------------------------------------
//
// 有些 ROM 把 `com.tencent.soter.soterserver` 换成壳（13 个事务一律回 -200，不发 HAL 请求），
// 那种机器上只能在宿主进程里把它对 App 的那笔 BC_REPLY 换掉。
//
// 换答复而不换请求：壳没有副作用，在原位看完它回什么再把 copy 源指到我们的 parcel，
// 比抢入站事务自己拼 BC_REPLY 安全（后者要跟 transaction_stack 与 BC_FREE_BUFFER 对账）。

/// 面板/手工留的开关：`1` 强制接、`0` 强制不接。文件不在就是自动判。
const APP_SERVE_SWITCH: &str = "/data/misc/ommega/soter_app_serve";

/// root 侧（`daemon-injector` 的 `sync_soter_host_state`）写下的宿主体检结论：
/// `stub` = 宿主不发 HAL 请求，`real` = 正常宿主。这件事得由能跑 `pm path` 的 root 侧做
/// （进程里按 `/proc/self/maps` 猜 APK 会猜错）。
const HOST_STATE: &str = "/data/misc/ommega/soter_host_state";

/// 真看见宿主回 -200 之后也当它是壳（root 侧那份没写出来时的退路）。
static HOST_REFUSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 运行期现场证据攒出来的自动接管：App 面向请求的答复窗口里宿主没碰任何我们认识的
/// HAL 描述符，就认定它在这条腿上瞎（描述符换了名或不走 binder HAL），改由我们直接答。
static AUTO_APP_SERVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 「宿主瞎」的连击计数，攒满 [`APP_AUTO_SERVE_THRESHOLD`] 才动手。
static APP_BLIND_STREAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 这几个全局是进程级的，并行跑的测试会互相踩，碰它们的测试靠这把锁串行。
#[cfg(test)]
pub(crate) static AUTO_SERVE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn auto_serve_test_lock() -> std::sync::MutexGuard<'static, ()> {
    AUTO_SERVE_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// 一笔首请求就接管：误接管的代价只是换一份同源的统一供料，漏判的代价是检测器那轮判红。
/// 只排除「本来就不该有 HAL 调用」的 12/13 号。
const APP_AUTO_SERVE_THRESHOLD: usize = 1;

/// 最后一笔「宿主发往我们认识的 SOTER HAL 描述符」的时刻。
/// 有的宿主把 HAL 调用派到别的线程，所以记进程级时刻跟 App 请求的时刻比。
static LAST_HAL_ACTIVITY: Mutex<Option<Instant>> = Mutex::new(None);

/// 认一个开关值：`1/true/on/stub` = 开，`0/false/off/real` = 关。
fn switch_state_text(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "stub" => Some(true),
        "0" | "false" | "off" | "real" => Some(false),
        _ => None,
    }
}

/// 读一个开关文件。
fn switch_state(path: &str) -> Option<bool> {
    switch_state_text(&std::fs::read_to_string(path).ok()?)
}

/// `manual_switch` 的进程内缓存：开关只读一次。
static MANUAL_SWITCH: std::sync::Mutex<Option<Option<bool>>> = std::sync::Mutex::new(None);

/// 这台机器上 App 面向的 SOTER 由我们答吗。`None` = 手工开关没写。
/// 进程起来只读一次：开关意思是「开机时要不要接管」，运行期跟着文件变会一会接一会不接。
fn manual_switch() -> Option<bool> {
    let mut cached = MANUAL_SWITCH.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(value) = *cached {
        return value;
    }
    // 环境变量是给运维/测试的直通口：`OMMEGA_SOTER_APP_SERVE=1/0`。
    let value = std::env::var("OMMEGA_SOTER_APP_SERVE")
        .ok()
        .and_then(|value| switch_state_text(&value))
        .or_else(|| switch_state(APP_SERVE_SWITCH));
    *cached = Some(value);
    value
}

#[cfg(test)]
pub(crate) fn reset_manual_switch_for_test() {
    *MANUAL_SWITCH.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// 接管在我们这边成立了（已经替宿主答过「读我们造的料」那几笔）。
/// 一旦成立就不再回头：开关、宿主体检结论、现场证据全不用看了。
static MATERIAL_ENGAGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 接管已成立 → 手工开关 → 运行期自动接管 → root 侧的宿主体检结论 → 现场见过 -200。
/// 手工文件是唯一能压住自动接管的扣：写 `0` 就不接，写 `1` 不管现场证据一律接。
/// 体检结论排在现场证据后面：它只是照着 APK 里有没有 HAL 服务名猜的。
pub(crate) fn app_serving_enabled() -> bool {
    if MATERIAL_ENGAGED.load(Ordering::Relaxed) {
        return true;
    }
    if let Some(on) = manual_switch() {
        return on;
    }
    if AUTO_APP_SERVE.load(Ordering::Relaxed) {
        return true;
    }
    switch_state(HOST_STATE).unwrap_or_else(|| HOST_REFUSED.load(Ordering::Relaxed))
}

/// 「读我们造的料」的那几笔：2 = `getAppSecureKey`、6 = `getAuthKey`。
/// ASK/AuthKey 都是我们现造的，原生宿主缓存里没有，问它只会回空。
fn reads_our_material(code: u32) -> bool {
    matches!(code, 2 | 6)
}

/// 这一笔 App 面向的请求归不归我们答。接管成立就一律归我们，开关不再参与；
/// 还没成立时手工开关优先，没写的话 2/6 号默认归我们（它们读的是我们自己造的料）。
fn app_reply_ours(code: u32, manual: Option<bool>, serving_enabled: bool) -> bool {
    match (serving_enabled, manual) {
        (true, _) => true,
        (false, Some(on)) => on,
        (false, None) => reads_our_material(code),
    }
}

/// 测试用：假装本线程刚收到一笔 App 请求。
#[cfg(test)]
pub(crate) fn stash_app_call_for_test(call: SoterCall, caller_uid: i32) {
    stash_pending_app(&call, caller_uid);
}

/// 测试用：把待答的那笔清掉。
#[cfg(test)]
pub(crate) fn clear_app_call_for_test() {
    PENDING_APP.with(|slot| slot.borrow_mut().take());
}

/// 宿主回给 App 的答复里出现它自己的 `ERR_HAL_UNAVAILABLE`（-200）就记下来。
/// 形状 `[Status i32][…]`，看偏移 4 / 8 处那几个字节就够；判错的方向是「多接一笔」。
///
/// # Safety
///
/// `tr.data.ptr.buffer` 必须指向 `tr.data_size` 个可读字节（调用方已装 shadow）。
pub(crate) unsafe fn note_host_reply(tr: &binder_transaction_data) {
    if HOST_REFUSED.load(Ordering::Relaxed) {
        return;
    }
    let size = tr.data_size.min(64);
    if size < 8 || tr.data.ptr.buffer == 0 {
        return;
    }
    let data = unsafe { std::slice::from_raw_parts(tr.data.ptr.buffer as *const u8, size) };
    let refused = [4usize, 8].iter().any(|at| {
        data.len() >= at + 4
            && i32::from_le_bytes([data[*at], data[*at + 1], data[*at + 2], data[*at + 3]]) == -200
    });
    if refused {
        HOST_REFUSED.store(true, Ordering::Relaxed);
        info!("event=soter host answered -200; serving the app-facing calls ourselves");
        crate::ipc::report_event(
            "event=soter host answered -200 (ERR_HAL_UNAVAILABLE)".to_string(),
        );
    }
}

/// 测试用：把自动接管的现场证据全清零（`HOST_REFUSED` 也算，否则会污染后面的判定）。
#[cfg(test)]
pub(crate) fn reset_auto_serve_for_test() {
    AUTO_APP_SERVE.store(false, Ordering::Relaxed);
    MATERIAL_ENGAGED.store(false, Ordering::Relaxed);
    APP_BLIND_STREAK.store(0, Ordering::Relaxed);
    HOST_REFUSED.store(false, Ordering::Relaxed);
    if let Ok(mut slot) = PROBE_SILENT_UNTIL.lock() {
        *slot = None;
    }
    if let Ok(mut slot) = LAST_HAL_ACTIVITY.lock() {
        *slot = None;
    }
    // libtest 的测试线程会复用，本线程上一把留下的待答请求也要清。
    PENDING_APP.with(|slot| slot.borrow_mut().take());
    reset_manual_switch_for_test();
    std::env::remove_var("OMMEGA_SOTER_APP_SERVE");
}

/// 宿主刚收进来的那笔 App 请求，留着跟它的答复对号。
#[derive(Debug, Clone)]
struct PendingApp {
    call: SoterCall,
    /// 内核填的调用者 uid（`sender_euid`），请求参数里那个 uid 信不得。
    caller_uid: i32,
    at: Instant,
}

/// 宿主回一笔 App 请求的时限（真机是毫秒级）；超时就不认了。
const APP_REPLY_WINDOW: Duration = Duration::from_secs(10);

thread_local! {
    /// 本线程最近一笔 App 面向的 SOTER 请求。宿主收进来就在同一个 binder 线程上写 BC_REPLY，
    /// 一笔同步事务没回完那个线程不会接下一笔。
    static PENDING_APP: RefCell<Option<PendingApp>> = const { RefCell::new(None) };
}

fn stash_pending_app(call: &SoterCall, caller_uid: i32) {
    PENDING_APP.with(|slot| {
        *slot.borrow_mut() = Some(PendingApp {
            call: call.clone(),
            caller_uid,
            at: Instant::now(),
        });
    });
}

/// App 号 → HAL 内部号（4 槽那套 14 号表）。12/13 号宿主自己发，走不到这里。
fn app_code_to_hal(code: u32) -> Option<u32> {
    Some(match code {
        1 => 5,  // generateAppSecureKey → generateAskKeyPair
        2 => 1,  // getAppSecureKey → exportAskPublicKey
        3 => 9,  // hasAskAlready
        4 => 7,  // generateAuthKey → generateAuthKeyPair
        5 => 13, // removeAuthKey
        6 => 3,  // getAuthKey → exportAuthKeyPublicKey
        7 => 12, // removeAllAuthKey → removeAllUidKey
        8 => 10, // hasAuthKey
        9 => 11, // initSigh → initSign
        10 => 4, // finishSign
        11 => 8, // getDeviceId
        _ => return None,
    })
}

/// 本线程看见宿主往我们认识的 SOTER HAL 描述符发了请求：HAL 腿是活的，连击清零，
/// 自动接管也撤掉并静默一段（宁可少接一笔，也不顶着好宿主的答复不放）。
fn note_hal_activity() {
    if let Ok(mut slot) = LAST_HAL_ACTIVITY.lock() {
        *slot = Some(Instant::now());
    }
    APP_BLIND_STREAK.store(0, Ordering::Relaxed);
    if AUTO_APP_SERVE.swap(false, Ordering::Relaxed) {
        silence_probes(AUTO_REVOKE_COOLDOWN);
        info!(
            "event=soter app-serve auto-disabled: the host touched the HAL leg again; backing off"
        );
        crate::ipc::report_event(
            "event=soter app-serve auto-disabled (host HAL traffic resumed)".to_string(),
        );
    }
}

/// 我们自己答不上时的重试间隔：否则 B 端离线 + 本地不许兜底时，每一笔 App 请求
/// 都要吃满一次 relay 往返。
const PROBE_RETRY_AFTER: Duration = Duration::from_secs(60);
/// 自动接管被撤销之后的冷却，避免「接一笔、撤一笔」来回抖动。
const AUTO_REVOKE_COOLDOWN: Duration = Duration::from_secs(300);

/// 静默期截止时刻（之前一律不探、直接按旧行为放过）。
static PROBE_SILENT_UNTIL: Mutex<Option<Instant>> = Mutex::new(None);

fn silence_probes(for_how_long: Duration) {
    if let Ok(mut slot) = PROBE_SILENT_UNTIL.lock() {
        *slot = Some(Instant::now() + for_how_long);
    }
}

/// 静默期里吗（纯函数，方便单测）。
fn probes_silenced(until: Option<Instant>, now: Instant) -> bool {
    until.is_some_and(|deadline| now < deadline)
}

/// App 腿自动兜底的判据（serving 还没开时走）。
/// 请求进来到宿主回话之间宿主没碰过我们认识的 HAL 描述符 → 它回给 App 的就是真 TA 的坏话，
/// 连击攒满阈值就由我们接管。12/13 号宿主本来就不碰 HAL，不算数。
/// 我们自己答不上时连击清零、静默一分钟，行为跟没做自动接管前一样。
fn auto_serve_probe(pending: &PendingApp) -> Option<OwnedReply> {
    let now = Instant::now();
    let silenced = PROBE_SILENT_UNTIL
        .lock()
        .ok()
        .and_then(|slot| *slot)
        .is_some_and(|deadline| probes_silenced(Some(deadline), now));
    if silenced {
        return None;
    }
    let hal_recent = LAST_HAL_ACTIVITY
        .lock()
        .ok()
        .and_then(|slot| slot.map(|at| at >= pending.at))
        .unwrap_or(false);
    if hal_recent || app_code_to_hal(pending.call.code).is_none() {
        APP_BLIND_STREAK.store(0, Ordering::Relaxed);
        return None;
    }
    let Some(reply) = build_app_answer(pending) else {
        APP_BLIND_STREAK.store(0, Ordering::Relaxed);
        silence_probes(PROBE_RETRY_AFTER);
        return None;
    };
    let streak = APP_BLIND_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
    if streak < APP_AUTO_SERVE_THRESHOLD {
        info!(
            "event=soter app-serve probe: host skipped the HAL leg ({streak}/{APP_AUTO_SERVE_THRESHOLD})"
        );
        return None;
    }
    AUTO_APP_SERVE.store(true, Ordering::Relaxed);
    APP_BLIND_STREAK.store(0, Ordering::Relaxed);
    if let Ok(mut slot) = PROBE_SILENT_UNTIL.lock() {
        *slot = None;
    }
    info!(
        "event=soter app-serve auto-enabled after {APP_AUTO_SERVE_THRESHOLD} app calls with no HAL traffic; file {APP_SERVE_SWITCH}=0 still forces it off"
    );
    crate::ipc::report_event(
        "event=soter app-serve auto-enabled (host shows no HAL traffic)".to_string(),
    );
    Some(reply)
}

/// 宿主要写 BC_REPLY 了：上一笔 App 请求归我们答就把答复 parcel 交出去（`None` = 别动）。
/// 返回的 parcel 得活到 `ioctl` 返回之后（内核在这期间从它里面拷字节），调用方负责。
pub(crate) fn take_app_answer() -> Option<OwnedReply> {
    let pending = PENDING_APP.with(|slot| slot.borrow_mut().take())?;
    if pending.at.elapsed() > APP_REPLY_WINDOW {
        return None;
    }
    // 料是我们造的、导出却交给宿主是自相矛盾，所以 2/6 号默认由我们答；
    // 答成了就等于接管成立，之后不再看开关。
    if !app_reply_ours(pending.call.code, manual_switch(), app_serving_enabled()) {
        return auto_serve_probe(&pending);
    }
    let reply = build_app_answer(&pending)?;
    if reads_our_material(pending.call.code) && !MATERIAL_ENGAGED.swap(true, Ordering::Relaxed) {
        log::info!(
            "event=soter app-serve engaged by material read code={}",
            pending.call.code
        );
        crate::ipc::report_event(
            "event=soter app-serve engaged (reads our own ASK/AuthKey)".to_string(),
        );
    }
    let head = unsafe { std::slice::from_raw_parts(reply.data_ptr(), reply.data_size().min(16)) };
    let hex: String = head.iter().map(|byte| format!("{byte:02x}")).collect();
    info!(
        "event=soter app-serve code={} op={} caller_uid={} bytes={} head={hex}",
        pending.call.code,
        pending.call.op,
        pending.caller_uid,
        reply.data_size()
    );
    crate::ipc::report_event(format!(
        "event=soter app-serve code={} op={} caller_uid={}",
        pending.call.code, pending.call.op, pending.caller_uid
    ));
    Some(reply)
}

/// 一笔 App 面向调用该答什么。内容与渲染分开：宿主里是顶掉它的 BC_REPLY（拼成 parcel），
/// 自测端点里是直接写 rsbinder 的 reply —— 两边用同一张答案。
#[derive(Debug)]
pub(crate) enum AppAnswer {
    /// 只有返回值的（`generate*` / `has*` / `remove*` / `getVersion`）。
    Int(i32),
    /// `SoterExportResult`：`[resultCode][byte[]][dataLength]`。
    Export { code: i32, data: Option<Vec<u8>> },
    /// `SoterSessionResult`：`[session][resultCode]`。
    Session { session: i64, code: i32 },
    /// `SoterExtraParam` 里的一个整数。
    Extra(i32),
}

/// 原厂宿主服务层在发往 HAL 之前自己回的码：空别名 -202、空 challenge -203。
/// 漏到下一步处理的话，壳宿主机型上会变成 -200，一眼不是原厂词汇。
const APP_ERR_EMPTY_ALIAS: i32 = -202;
const APP_ERR_EMPTY_CHALLENGE: i32 = -203;

/// 算出一笔 App 面向调用的答复。`caller_uid` 是拿谁的 uid 去建/查料：
/// 宿主里是内核填的 `sender_euid`，自测端点里是命令行给的 uid。
pub(crate) fn answer_app_call(call: &SoterCall, caller_uid: i32) -> Option<AppAnswer> {
    // 这两个号宿主自己不碰 HAL，是我们自己能直接给的。
    match call.code {
        12 => return Some(AppAnswer::Int(1)),
        13 => {
            let key = call.key.as_deref()?;
            let value = match key {
                // 1 = 面容、2 = 指纹（真机取值）。检测器就认 2。
                "fingerprint_type" => 2,
                _ => 0,
            };
            return Some(AppAnswer::Extra(value));
        }
        _ => {}
    }
    // 空参数按原厂口径挡掉，顺序也一样：别名先、challenge 后。`hasAuthKey` 例外
    // （原厂对空别名不报错，只回 false）。
    let alias_empty = call.alias.as_deref().unwrap_or("").is_empty();
    match call.code {
        4 | 5 | 6 | 9 if alias_empty => {
            return Some(match call.code {
                9 => AppAnswer::Session {
                    session: 0,
                    code: APP_ERR_EMPTY_ALIAS,
                },
                6 => AppAnswer::Export {
                    code: APP_ERR_EMPTY_ALIAS,
                    data: None,
                },
                _ => AppAnswer::Int(APP_ERR_EMPTY_ALIAS),
            });
        }
        9 if call.challenge.as_deref().unwrap_or("").is_empty() => {
            return Some(AppAnswer::Session {
                session: 0,
                code: APP_ERR_EMPTY_CHALLENGE,
            });
        }
        8 if alias_empty => return Some(AppAnswer::Int(0)),
        _ => {}
    }
    let hal_code = app_code_to_hal(call.code)?;
    let (op, _) = describe(true, hal_code)?;
    // uid 一律用调用者那个（真宿主也拿 `Binder.getCallingUid()` 盖掉参数）。
    // 可以不有：`getDeviceId` / `getVersion` 这类根本没这个参数。
    let uid = if caller_uid >= 0 {
        Some(caller_uid)
    } else {
        call.uid
    };
    let hal_call = SoterCall {
        hal: true,
        hidl: false,
        has_return_code: true,
        code: hal_code,
        wire_code: hal_code,
        op,
        uid,
        alias: call.alias.clone(),
        challenge: call.challenge.clone(),
        session: call.session,
        key: None,
        caller_uid: (caller_uid >= 0).then_some(caller_uid),
        data_size: call.data_size,
    };
    // hook 只做转发/透传，不在本进程本地答：本地模式一律交给软件 TA（另一个进程里
    // 统一处理 initSign/finishSign），远程模式交给服务端。这样会话和计数器不会分裂。
    let answer = crate::hook::soter_relay::answer(&hal_call, false);
    let Some(answer) = answer else {
        // 宿主里文件日志是哑的；答不出来这件事只能顺 RPC 让 daemon 记下来。
        crate::ipc::report_event(format!(
            "event=soter app answer none code={} hal_code={hal_code} caller_uid={caller_uid}",
            call.code
        ));
        return None;
    };
    Some(match (call.code, answer) {
        (1 | 4 | 5 | 7, Answer::Code(code)) => AppAnswer::Int(code),
        // App 那边的 `has*` 是布尔：语义是「我们答成功了吗」。
        (3 | 8, Answer::Code(code)) => AppAnswer::Int(i32::from(code == 0)),
        (2 | 6 | 10 | 11, Answer::Buffer { code, data }) => AppAnswer::Export {
            code: vendor_export_code(call.code, code),
            data,
        },
        (9, Answer::Init { status, session }) => AppAnswer::Session {
            session,
            code: status,
        },
        _ => return None,
    })
}

/// App 面向那半边把「缺料」的码位对齐到原厂 TA 的词汇（内部日志里还是原值）。
/// -6 = 没这把 AuthKey（B 端给 -8、本地给 -5）；-1000 = 未知会话号（B 端给 -204）。
fn vendor_export_code(app_code: u32, code: i32) -> i32 {
    match (app_code, code) {
        (6, -5 | -8) => -6,
        (10, -204) => -1000,
        _ => code,
    }
}

/// 把一笔 App 面向的答复拼成 parcel（给顶掉 BC_REPLY 那条路用）。
fn build_app_reply(answer: &AppAnswer) -> Option<OwnedReply> {
    let built = match answer {
        AppAnswer::Int(value) => build_app_int_reply(*value),
        AppAnswer::Export { code, data } => build_app_export_reply(*code, data.as_deref()),
        AppAnswer::Session { session, code } => build_app_session_reply(*session, *code),
        AppAnswer::Extra(value) => build_app_extra_param_reply(*value),
    };
    match built {
        Ok(reply) => Some(reply),
        Err(error) => {
            warn!("event=soter app answer could not be built ({error:#})");
            None
        }
    }
}

/// 拼一笔 App 面向的答复。答不了就返回 `None`（宿主自己那份答复照旧过去）。
fn build_app_answer(pending: &PendingApp) -> Option<OwnedReply> {
    let answer = answer_app_call(&pending.call, pending.caller_uid)?;
    build_app_reply(&answer)
}

/// 把一笔答复拼成宿主能直接吃的内核命令字节流，连同一块得活着的 parcel 一起交出去。
///
/// 答复源由 [`crate::hook::soter_relay`] 定：远程优先，配置允许就退回本地自签，都没有就 `None`（透传）。
///
/// 形状 `[BR_TRANSACTION_COMPLETE][BR_REPLY]`（前者补上只为更像真机同步调用的节奏，少了也不卡）。
/// `data.ptr.buffer` 指的是第二个返回值的 parcel，所以**调用方得把这块 parcel 留到宿主把
/// `BC_FREE_BUFFER` 交回来为止** —— 两个返回值是一个整体。
pub(crate) fn build_br_reply(call: &SoterCall) -> Option<(Vec<u8>, OwnedReply)> {
    let answer = crate::hook::soter_relay::answer(call, false)?;
    note_sign_success(call, &answer);
    frame_br_reply(call, answer)
}

/// 「这台机器的 SOTER 能签」的记录文件。daemon 会预先建好、改成 0666，宿主侧只追加一行。
const SIGN_OK_PATH: &str = "/data/misc/ommega/soter_ok";

/// 签名成功就落一条记录，面板据此显示「SOTER 可用」，重启后不用等新调用。
/// 哪一层答的都算。只写本地文件：不碰网络、不碰 TEE、不阻塞，写失败就算了。
fn note_sign_success(call: &SoterCall, answer: &Answer) {
    // 只认真正出签名的那两笔（4 = finishSign，11 = init_sign）。
    if call.code != 4 && call.code != 11 {
        return;
    }
    let code = match answer {
        Answer::Code(code) => *code,
        Answer::Buffer { code, .. } => *code,
        Answer::Init { status, .. } => *status,
    };
    if code != 0 {
        return;
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(SIGN_OK_PATH)
    else {
        return;
    };
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = std::io::Write::write_all(
        &mut file,
        format!(
            "{epoch}\t{}\t{}\t{}\n",
            call.op,
            call.uid.unwrap_or(0),
            call.alias.as_deref().unwrap_or("")
        )
        .as_bytes(),
    );
}

/// Frame an already resolved answer without contacting the daemon or local key state.
fn frame_br_reply(call: &SoterCall, answer: Answer) -> Option<(Vec<u8>, OwnedReply)> {
    let reply = match answer {
        Answer::Code(code) => build_plain_reply(&code).ok()?,
        Answer::Buffer { code, data } => {
            if call.hidl {
                build_hidl_soter_buffer_reply(code, data.as_deref()).ok()?
            } else {
                build_soter_buffer_reply(code, data.as_deref(), call.has_return_code).ok()?
            }
        }
        Answer::Init { status, session } => {
            if call.hidl {
                build_hidl_soter_init_reply(status, session).ok()?
            } else {
                build_soter_init_reply(status, session).ok()?
            }
        }
    };
    let bytes = encode_br_reply(&reply);
    Some((bytes, reply))
}

/// 一个 parcel 包成 `BR_TRANSACTION_COMPLETE` + `BR_REPLY` 两条命令。
fn encode_br_reply(reply: &OwnedReply) -> Vec<u8> {
    let mut out = Vec::with_capacity(size_of::<u32>() * 2 + size_of::<binder_transaction_data>());
    out.extend_from_slice(&BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes());
    out.extend_from_slice(&BR_REPLY_CMD.to_ne_bytes());
    let tr = binder_transaction_data {
        target: binder_transaction_data_target { ptr: 0 },
        cookie: 0,
        code: 0,
        // 千万别设 TF_STATUS_CODE —— 那个标志的意思是「parcel 里只有一个 int32 错误码」，
        // 我们给的是正常回复，设上去宿主就按错误解了。
        flags: 0,
        sender_pid: 0,
        sender_euid: 0,
        data_size: reply.data_size(),
        offsets_size: reply.offsets_size(),
        data: binder_transaction_data_data {
            ptr: binder_transaction_data_data_ptr {
                buffer: reply.data_ptr() as libc::c_ulong,
                offsets: if reply.offsets.is_empty() {
                    0
                } else {
                    reply.offsets.as_ptr() as libc::c_ulong
                },
            },
        },
    };
    // SAFETY: binder_transaction_data 全是 POD，这里只是把它按字节序列化出来。
    let raw = unsafe {
        std::slice::from_raw_parts(
            (&tr as *const binder_transaction_data).cast::<u8>(),
            size_of::<binder_transaction_data>(),
        )
    };
    out.extend_from_slice(raw);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook::binder::TF_STATUS_CODE;

    /// 造一条现代的 interface token（含 strict-mode policy 前缀）。长度是字符数、不含 NUL，
    /// 之后是 NUL 与补齐（跟 `push_string` 一致）。
    fn interface_token(descriptor: &str) -> Vec<u8> {
        let units: Vec<u16> = descriptor.encode_utf16().collect();
        let mut out = Vec::new();
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for unit in &units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    fn push_i32(out: &mut Vec<u8>, value: i32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_i64(out: &mut Vec<u8>, value: i64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    /// AIDL 的 String16：字符数 + UTF-16LE + NUL 终结符 + 补齐（跟 `Cursor::string` 一份布局）。
    fn push_string(out: &mut Vec<u8>, value: &str) {
        let units: Vec<u16> = value.encode_utf16().collect();
        push_i32(out, units.len() as i32);
        for unit in &units {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&[0, 0]);
        let written = (units.len() + 1) * 2;
        let pad = written.next_multiple_of(4) - written;
        for _ in 0..pad {
            out.push(0);
        }
    }

    fn request(args: &dyn Fn(&mut Vec<u8>)) -> Vec<u8> {
        let mut data = interface_token(HAL_DESCRIPTOR);
        args(&mut data);
        data
    }

    /// `'S' 'Y' 'S' 'T'`：现代 libbinder 在 strict-mode policy 之后写的魔数。
    const INTERFACE_HEADER: u32 = 0x5359_5354;

    /// 造一条带指定前缀字数的 token：0 / 1 / 2 / 3 个 i32 头，然后 String16 + 参数。
    /// 1 = 老 libbinder；2 = policy + 'SYST'；3 = app_process 布局（policy、work source=-1、'SYST'）。
    fn token_with_header(headers: usize, args: &dyn Fn(&mut Vec<u8>)) -> Vec<u8> {
        let mut out = Vec::new();
        let policy = 0x8000_0000u32;
        let work_source = u32::MAX;
        match headers {
            1 => out.extend_from_slice(&policy.to_le_bytes()),
            2 => {
                out.extend_from_slice(&policy.to_le_bytes());
                out.extend_from_slice(&INTERFACE_HEADER.to_le_bytes());
            }
            3 => {
                for word in [policy, work_source, INTERFACE_HEADER] {
                    out.extend_from_slice(&word.to_le_bytes());
                }
            }
            _ => {}
        }
        let units: Vec<u16> = HAL_DESCRIPTOR
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        if headers == 3 {
            // 实测写法：长度是字符数，字符后面单另一个 u32 的 0。
            out.extend_from_slice(&((units.len() - 1) as u32).to_le_bytes());
            for unit in units.iter().take(units.len() - 1) {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.extend_from_slice(&0u32.to_le_bytes());
        } else {
            // 老写法：长度把结尾 0 算进去，字符后面补到 4。
            out.extend_from_slice(&(units.len() as u32).to_le_bytes());
            for unit in &units {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            while !out.len().is_multiple_of(4) {
                out.push(0);
            }
        }
        args(&mut out);
        out
    }

    /// 四种前缀都得认得出来（app_process 用的是 2 个头那个）。
    #[test]
    fn matches_every_interface_token_layout() {
        for headers in [0usize, 1, 2, 3] {
            let data = token_with_header(headers, &|out| push_i32(out, 10373));
            let call = parse(&data, 1)
                .unwrap_or_else(|| panic!("header with {headers} i32 words was not recognised"));
            assert!(call.hal);
            assert_eq!(call.op, "exportAskPublicKey");
            assert_eq!(call.uid, Some(10373));
        }
    }

    fn descriptor_of(data: &[u8]) -> Option<String> {
        for prefix in [0usize, 4, 8, 12] {
            if let Some((text, _)) = read_string16(data, prefix) {
                if text == HAL_DESCRIPTOR || text == APP_DESCRIPTOR {
                    return Some(text);
                }
            }
        }
        None
    }

    #[test]
    fn export_ask_public_key_parses_the_uid() {
        let data = request(&|out| push_i32(out, 10373));
        let call = parse(&data, 1).expect("code 1 is ours");
        assert!(call.hal);
        assert_eq!(call.op, "exportAskPublicKey");
        assert_eq!(call.uid, Some(10373));
        assert!(!is_mutation(call.hal, call.code));
    }

    #[test]
    fn init_sign_parses_uid_alias_and_challenge() {
        let data = request(&|out| {
            push_i32(out, 10373);
            push_string(out, "SoterAuthKey");
            push_string(out, "0102030405");
        });
        let call = parse(&data, 11).expect("code 11 is ours");
        assert_eq!(call.op, "initSign");
        assert_eq!(call.uid, Some(10373));
        assert_eq!(call.alias.as_deref(), Some("SoterAuthKey"));
        assert_eq!(call.challenge.as_deref(), Some("0102030405"));
    }

    /// 真机 alias 正好 34 字符（偶数），后面紧跟 challenge；少算 4 字节补齐会把 challenge 读成空串。
    #[test]
    fn a_challenge_after_a_34_char_alias_is_not_swallowed() {
        let alias = "SoterAuthKeyV2_salt11d8ba34_scene1";
        assert_eq!(alias.len(), 34);
        let challenge = "a".repeat(52);
        let mut data = interface_token(APP_DESCRIPTOR);
        push_i32(&mut data, 10490);
        push_string(&mut data, alias);
        push_string(&mut data, &challenge);
        let call = parse(&data, 9).expect("the app side parses");
        assert_eq!(call.alias.as_deref(), Some(alias));
        assert_eq!(call.challenge.as_deref(), Some(challenge.as_str()));
    }

    /// 空串也带 NUL + 补齐（4 字节），下一个字段不能被这 4 个零顶掉。
    #[test]
    fn an_empty_string_still_advances_by_its_nul_and_padding() {
        let mut data = interface_token(APP_DESCRIPTOR);
        push_i32(&mut data, 7);
        push_string(&mut data, "");
        push_string(&mut data, "after");
        let call = parse(&data, 9).expect("the app side parses");
        assert_eq!(call.alias.as_deref(), Some(""));
        assert_eq!(call.challenge.as_deref(), Some("after"));
    }

    #[test]
    fn finish_sign_parses_the_session() {
        let data = request(&|out| push_i64(out, 0x1234_5678));
        let call = parse(&data, 4).expect("code 4 is ours");
        assert_eq!(call.session, Some(0x1234_5678));
        assert_eq!(call.uid, None);
    }

    #[test]
    fn get_device_id_has_no_arguments() {
        let data = request(&|_out| {});
        let call = parse(&data, 8).expect("code 8 is ours");
        assert_eq!(call.op, "getDeviceId");
        assert_eq!(call.uid, None);
    }

    /// App 面向那笔记下的调用者 uid 借给紧跟着的那笔 HAL 调用，取走即清。
    #[test]
    fn an_app_side_caller_is_borrowed_by_the_next_hal_call() {
        // 同线程里别的测试可能记过，先清干净再验。
        let _ = take_app_caller_uid();
        note_app_caller(10490);
        assert_eq!(take_app_caller_uid(), Some(10490));
        // 取走即清：同一笔 App 调用不能借给第二笔 HAL 调用。
        assert_eq!(take_app_caller_uid(), None);
        // 内核没填 uid（负数）不算调用者。
        note_app_caller(-1);
        assert_eq!(take_app_caller_uid(), None);
        // 窗口要是个正数：太小会把同一笔流程拆开，太大就会串台。
        assert!(APP_CALLER_WINDOW >= Duration::from_millis(500));
    }

    /// 解析出来的请求本来不带 caller_uid（那是 observe 在真机上填的），别在 parse 里瞎猜。
    #[test]
    fn parse_never_invents_a_caller_uid() {
        let data = request(&|out| push_i32(out, 10373));
        let call = parse(&data, 1).expect("code 1 is ours");
        assert_eq!(call.caller_uid, None);
    }

    /// 产线 provisioning 三个号（2 / 6 / 14）是我们的，真不认识的号还是不认。
    /// 2 / 6 是 Args::Uid，得带 uid；14 无参。
    #[test]
    fn provisioning_codes_are_ours_but_unknown_codes_are_not() {
        for code in [2u32, 6] {
            let data = request(&|out| push_i32(out, 10373));
            let call =
                parse(&data, code).unwrap_or_else(|| panic!("provisioning code {code} must parse"));
            assert!(
                interceptable(&call),
                "provisioning code {code} must be intercepted"
            );
        }
        let call = parse(&request(&|_out| {}), 14).expect("verifyAttkKeyPair takes no arguments");
        assert!(interceptable(&call), "code 14 must be intercepted");

        assert!(parse(&request(&|_out| {}), 99).is_none());
        assert!(parse(&request(&|_out| {}), 15).is_none());
    }

    /// 回查调用者：按同名钥先认、再按会话号、最后才是「两边都没别名」那种。
    #[test]
    fn an_outbound_call_finds_its_caller_in_the_recent_list() {
        let now = Instant::now();
        let entry = |uid: i32, ago: u64, alias: Option<&str>, session: Option<i64>| AppCaller {
            uid,
            at: now - Duration::from_secs(ago),
            alias: alias.map(str::to_string),
            session,
        };
        let aliased = |alias: &str| {
            let data = request(&|out| {
                push_i32(out, 10490);
                push_string(out, alias);
            });
            parse(&data, 10).expect("code 10 is ours")
        };

        // 别名对得上那一笔才认（同一台设备上同时有好几把钥匙）。
        let list = vec![
            entry(10373, 1, Some("SoterAuthKeyV2_other_scene1"), None),
            entry(10490, 1, Some("SoterAuthKeyV2_salt11d8ba34_scene1"), None),
        ];
        assert_eq!(
            pick_recent_caller(&list, &aliased("SoterAuthKeyV2_salt11d8ba34_scene1"), now),
            Some(10490)
        );
        // 同一把钥匙的下一个 op（init_sign）照样认得出。
        let init = {
            let data = request(&|out| {
                push_i32(out, 10490);
                push_string(out, "SoterAuthKeyV2_salt11d8ba34_scene1");
                push_string(out, "0a1b");
            });
            parse(&data, 11).expect("code 11 is ours")
        };
        assert_eq!(
            pick_recent_caller(&list, &init, now),
            Some(10490),
            "同一个别名的另一笔也得认"
        );
        // 列表里只有别的钥匙：不能乱认。
        assert_eq!(
            pick_recent_caller(
                &[entry(10373, 1, Some("SoterAuthKeyV2_other_scene1"), None)],
                &aliased("SoterAuthKeyV2_salt11d8ba34_scene1"),
                now
            ),
            None
        );
        // 带别名的出站调用：窗口内“认不出接口”的凭据（无别名无会话）可以顶它。
        assert_eq!(
            pick_recent_caller(
                &[entry(10490, 1, None, None)],
                &aliased("SoterAuthKeyV2_salt11d8ba34_scene1"),
                now
            ),
            Some(10490)
        );

        // 只有会话号的那笔（finish_sign）：靠会话号对上。
        let finish = {
            let data = request(&|out| push_i64(out, -8465536435272201480));
            parse(&data, 4).expect("code 4 is ours")
        };
        assert_eq!(
            pick_recent_caller(
                &[entry(10490, 1, None, Some(-8465536435272201480))],
                &finish,
                now
            ),
            Some(10490)
        );
        assert_eq!(
            pick_recent_caller(&[entry(10490, 1, None, Some(7))], &finish, now),
            None,
            "会话号对不上的那笔不该被认下"
        );

        // 两边都没别名没会话（`has_ask_already` / `export_ask_public_key` 那套）：拿最近一笔。
        let bare = {
            let data = request(&|out| push_i32(out, 2000));
            parse(&data, 1).expect("code 1 is ours")
        };
        let bare_list = vec![entry(10490, 5, None, None), entry(10540, 1, None, None)];
        assert_eq!(
            pick_recent_caller(&bare_list, &bare, now),
            Some(10540),
            "没别名没会话时取最近那一笔"
        );

        // 过了窗口的那笔不算数。
        let stale = vec![entry(10490, APP_CALLER_TTL.as_secs() + 1, None, None)];
        assert_eq!(pick_recent_caller(&stale, &bare, now), None);
    }

    /// 「没别名也没会话」的判据、以及同一把钥匙的去重，别认错。
    #[test]
    fn a_bare_caller_is_only_bare_without_alias_and_session() {
        let bare = AppCaller {
            uid: 10490,
            at: Instant::now(),
            alias: None,
            session: None,
        };
        assert!(bare.bare());
        let empty_alias = AppCaller {
            alias: Some(String::new()),
            ..bare.clone()
        };
        assert!(empty_alias.bare(), "空别名也算没别名");
        let with_alias = AppCaller {
            alias: Some("SoterAuthKeyV2_x_scene1".to_string()),
            ..bare.clone()
        };
        assert!(!with_alias.bare());
        let with_session = AppCaller {
            session: Some(7),
            ..bare.clone()
        };
        assert!(!with_session.bare(), "有会话号就不算没别名那类");

        let data = request(&|out| {
            push_i32(out, 10490);
            push_string(out, "SoterAuthKeyV2_x_scene1");
        });
        let call = parse(&data, 10).expect("code 10 is ours");
        assert!(with_alias.same_key(&call));
        assert!(!bare.same_key(&call));
    }

    /// 别名主人：同名那把能认出来，别的名字不认，过期的也不认。
    #[test]
    fn an_alias_owner_is_found_by_the_exact_name() {
        let now = Instant::now();
        let owner = |alias: &str, uid: i32, ago: u64| AliasOwner {
            alias: alias.to_string(),
            uid,
            at: now - Duration::from_secs(ago),
        };
        let list = vec![
            owner("SoterAuthKeyV2_other_scene1", 10373, 30),
            owner("SoterAuthKeyV2_salt11d8ba34_scene1", 10490, 30),
        ];
        assert_eq!(
            pick_alias_owner(&list, "SoterAuthKeyV2_salt11d8ba34_scene1", now),
            Some(10490)
        );
        assert_eq!(pick_alias_owner(&list, "Wechatuid10248__scene0", now), None);
        // 同一把别名又用过一次：以后记的那笔为准。
        let reused = vec![
            owner("SoterAuthKey_x", 10490, 300),
            owner("SoterAuthKey_x", 10500, 1),
        ];
        assert_eq!(
            pick_alias_owner(&reused, "SoterAuthKey_x", now),
            Some(10500)
        );
        // 过了窗口不认。
        let stale = vec![owner(
            "SoterAuthKey_x",
            10490,
            ALIAS_OWNER_TTL.as_secs() + 1,
        )];
        assert_eq!(pick_alias_owner(&stale, "SoterAuthKey_x", now), None);
        // 空别名本来就不该走到这儿。
        assert_eq!(pick_alias_owner(&reused, "", now), None);
    }

    /// uid 是不是应用：分身（999xxxxx）和多用户（10xxxxx）都算，0 / 1000 / 2000 不算。
    #[test]
    fn only_app_uids_count_as_the_caller() {
        assert!(is_app_uid(10490));
        assert!(is_app_uid(99910365));
        assert!(is_app_uid(1_010_392));
        assert!(is_app_uid(AID_APP_START));
        assert!(!is_app_uid(0));
        assert!(!is_app_uid(1000));
        assert!(!is_app_uid(2000));
        assert!(!is_app_uid(-1));
    }

    /// 「认不出接口名」那条推断只能活短窗口：2 秒内拿它，超了就不认（免得把别的应用算错）。
    #[test]
    fn an_unparsed_app_caller_only_counts_for_a_short_window() {
        let now = Instant::now();
        let entry = |ago: u64| AppCaller {
            uid: 10339,
            at: now - Duration::from_secs(ago),
            alias: None,
            session: None,
        };
        // 带别名的出站调用：窗口内（2 秒）能顶 —— 宿主换了一套接口时就靠这一条。
        let data = request(&|out| {
            push_i32(out, 10339);
            push_string(out, "SoterAuthKeyV2_salt11d8ba34_scene1");
        });
        let call = parse(&data, 10).expect("code 10 is ours");
        assert_eq!(pick_recent_caller(&[entry(1)], &call, now), Some(10339));
        assert_eq!(
            pick_recent_caller(&[entry(3)], &call, now),
            None,
            "出了 2 秒窗就不认"
        );
        assert_eq!(pick_recent_caller(&[], &call, now), None);
    }

    /// 诊断用：从 transaction 开头那串 token 里把接口名读出来；读不出来就回 None，不硬猜。
    #[test]
    fn the_interface_token_of_a_transaction_is_readable() {
        assert_eq!(
            interface_token_of(b"vendor.qti.hardware.soter.ISoter\0junk"),
            Some("vendor.qti.hardware.soter.ISoter")
        );
        assert_eq!(
            interface_token_of(b"android.system.keystore2.IKeystoreService\0"),
            Some("android.system.keystore2.IKeystoreService")
        );
        // 没 NUL 终结符 / 空 token / 不是 UTF-8，都不猜。
        assert_eq!(interface_token_of(b"no-nul-here"), None);
        assert_eq!(interface_token_of(b"\0"), None);
        assert_eq!(interface_token_of(&[0xff, 0xfe, 0x00]), None);
        assert_eq!(interface_token_of(b""), None);
    }

    #[test]
    fn other_services_are_ignored() {
        let mut data = interface_token("android.hardware.security.keymint.IKeyMintDevice");
        push_i32(&mut data, 1);
        assert!(parse(&data, 1).is_none(), "KeyMint traffic is not SOTER");
        assert_eq!(descriptor_of(&data), None);
    }

    #[test]
    fn has_auth_key_parses_the_alias() {
        let data = request(&|out| {
            push_i32(out, 10373);
            push_string(out, "SoterAuthKey");
        });
        let call = parse(&data, 10).expect("code 10 is ours");
        assert_eq!(call.op, "hasAuthKey");
        assert_eq!(call.alias.as_deref(), Some("SoterAuthKey"));
    }

    #[test]
    fn the_trustonic_descriptor_is_also_a_hal_request() {
        // 联发科机型（一加 PLC110）上宿主发出去的是 Trustonic 那条，号码跟高通那份同序。
        let mut data = interface_token(TRUSTONIC_DESCRIPTOR);
        push_i32(&mut data, 1000);
        let call = parse(&data, 9).expect("trustonic hasAskAlready");
        assert!(call.hal, "Trustonic 那侧也算 HAL");
        assert_eq!(call.op, "hasAskAlready");
        assert_eq!(call.uid, Some(1000));

        // 带参数的那个也一样能解出来（3 号 exportAuthKeyPublicKey）。
        let mut data = interface_token(TRUSTONIC_DESCRIPTOR);
        push_i32(&mut data, 10373);
        push_string(&mut data, "SoterAuthKey");
        let call = parse(&data, 3).expect("trustonic exportAuthKeyPublicKey");
        assert_eq!(call.op, "exportAuthKeyPublicKey");
        assert_eq!(call.alias.as_deref(), Some("SoterAuthKey"));
    }

    #[test]
    fn the_hidl_descriptors_are_recognised_and_intercepted() {
        // 宿主 dex 里 HIDL 那套代理类也在，描述符跟 AIDL 不是同一条；现在照样拦，
        // 答复换成 HIDL 布局（`build_hidl_*`）。hasAuthKey 在 HIDL 线上是 12。
        for descriptor in [
            QTI_HIDL_DESCRIPTOR,
            TRUSTONIC_HIDL_DESCRIPTOR,
            XIAOMI_HIDL_DESCRIPTOR,
            MICROTRUST_HIDL_DESCRIPTOR,
        ] {
            let mut keep: Vec<Box<[u8]>> = Vec::new();
            let mut data = hidl_token(descriptor);
            push_i32(&mut data, 1000);
            push_hidl_string(&mut data, &mut keep, "SoterAuthKey");
            let call = parse(&data, 12).unwrap_or_else(|| panic!("{descriptor} hasAuthKey"));
            assert!(call.hal && call.hidl, "HIDL 那侧归 HAL，也得单独标出来");
            assert_eq!(call.code, 10, "换算成内部那套号码");
            assert_eq!(call.op, "hasAuthKey");
            assert!(interceptable(&call), "HIDL 现在也拦");
            drop(keep);
        }
    }

    #[test]
    fn microtrust_hidl_sign_codes_use_the_existing_mapping() {
        let mut keep: Vec<Box<[u8]>> = Vec::new();
        let mut data = hidl_token(MICROTRUST_HIDL_DESCRIPTOR);
        push_i32(&mut data, 10373);
        push_hidl_string(&mut data, &mut keep, "SoterAuthKey");
        push_hidl_string(&mut data, &mut keep, "abcd");
        let call = parse(&data, 13).expect("Microtrust initSign");
        assert!(call.hal && call.hidl);
        assert_eq!(call.code, 11);
        assert_eq!(call.op, "initSign");
        assert_eq!(call.uid, Some(10373));
        assert_eq!(call.alias.as_deref(), Some("SoterAuthKey"));
        assert_eq!(call.challenge.as_deref(), Some("abcd"));

        let mut data = hidl_token(MICROTRUST_HIDL_DESCRIPTOR);
        push_i64(&mut data, 42);
        let call = parse(&data, 14).expect("Microtrust finishSign");
        assert!(call.hal && call.hidl);
        assert_eq!(call.code, 4);
        assert_eq!(call.op, "finishSign");
        assert_eq!(call.session, Some(42));
    }

    #[test]
    fn token_without_the_strict_mode_prefix_still_parses() {
        // 老布局：没有前面那个 policy 的 i32。
        let units: Vec<u16> = HAL_DESCRIPTOR.encode_utf16().collect();
        let mut data = Vec::new();
        data.extend_from_slice(&(units.len() as u32).to_le_bytes());
        for unit in &units {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
        while !data.len().is_multiple_of(4) {
            data.push(0);
        }
        push_i32(&mut data, 4242);
        let call = parse(&data, 9).expect("the older layout must parse too");
        assert_eq!(call.uid, Some(4242));
    }

    #[test]
    fn the_app_facing_descriptor_is_recognised_as_the_app_side() {
        let mut data = interface_token(APP_DESCRIPTOR);
        push_i32(&mut data, 1000);
        push_string(&mut data, "SoterAuthKey");
        push_string(&mut data, "abcd");
        // App 面向那边 9 号是 initSigh（腾讯自家拼错的），入参 uid + alias + challenge。
        let call = parse(&data, 9).expect("the app side parses too");
        assert!(!call.hal);
        assert_eq!(call.op, "initSigh");
        assert_eq!(call.uid, Some(1000));
        assert_eq!(call.alias.as_deref(), Some("SoterAuthKey"));
        assert_eq!(call.challenge.as_deref(), Some("abcd"));
        assert!(
            is_mutation(call.hal, call.code),
            "initSigh may create an AuthKey"
        );
    }

    #[test]
    fn the_same_code_means_different_things_on_the_two_sides() {
        // 10 号：HAL 那边是 hasAuthKey(uid, alias)，App 那边是 finishSign(session)。
        let hal = request(&|out| {
            push_i32(out, 10373);
            push_string(out, "SoterAuthKey");
        });
        let hal_call = parse(&hal, 10).expect("hal 10");
        assert_eq!(hal_call.op, "hasAuthKey");
        assert_eq!(hal_call.alias.as_deref(), Some("SoterAuthKey"));

        let mut app = interface_token(APP_DESCRIPTOR);
        push_i64(&mut app, 7);
        let app_call = parse(&app, 10).expect("app 10");
        assert_eq!(app_call.op, "finishSign");
        assert_eq!(app_call.session, Some(7));
        assert_eq!(app_call.alias, None);
    }

    #[test]
    fn get_extra_param_carries_the_key() {
        let mut data = interface_token(APP_DESCRIPTOR);
        push_string(&mut data, "udfp");
        let call = parse(&data, 13).expect("app 13");
        assert_eq!(call.op, "getExtraParam");
        assert_eq!(call.key.as_deref(), Some("udfp"));
        assert_eq!(call.uid, None);
    }

    #[test]
    fn truncated_argument_area_does_not_panic_and_does_not_match() {
        let mut data = interface_token(HAL_DESCRIPTOR);
        push_i32(&mut data, 10373);
        for cut in 0..data.len() {
            let _ = parse(&data[..cut], 11);
            let _ = parse(&data[..cut], 13);
        }
        assert!(parse(&data, 11).is_none(), "code 11 needs three arguments");
    }

    #[test]
    fn mutation_codes_are_flagged() {
        for code in [5, 7, 12, 13] {
            assert!(is_mutation(true, code), "hal {code} mutates the keystore");
        }
        for code in [1, 3, 4, 8, 9, 10, 11] {
            assert!(!is_mutation(true, code), "hal {code} only reads");
        }
        for code in [1, 4, 5, 7, 9] {
            assert!(is_mutation(false, code), "app {code} mutates the keystore");
        }
        for code in [2, 3, 6, 8, 10, 11, 12, 13] {
            assert!(!is_mutation(false, code), "app {code} only reads");
        }
    }

    #[test]
    fn a_cursor_never_reads_past_the_end() {
        let mut cursor = Cursor::new(&[1, 2, 3], 0, false);
        assert!(cursor.u32().is_none());
        assert_eq!(cursor.remaining(), 3);
        assert!(cursor.take(4).is_none());
        assert!(cursor.take(3).is_some());
        assert_eq!(cursor.remaining(), 0);
    }

    #[test]
    fn an_unknown_descriptor_is_skipped_silently() {
        // 把「认不出就安静走开」这条行为钉住：别在热路径上刷日志。
        let data = interface_token("com.example.whatever.IFoo");
        assert!(parse(&data, 1).is_none());
        assert_eq!(descriptor_of(&data), None);
    }

    #[test]
    fn a_synthetic_reply_is_framed_the_way_the_host_expects() {
        let data = token_with_header(3, &|_out| {});
        let call = parse(&data, 8).expect("code 8 is getDeviceId");
        assert!(interceptable(&call));

        let (bytes, reply) = frame_br_reply(
            &call,
            Answer::Buffer {
                code: 0,
                data: Some(b"090000001234567890abcdef12345678".to_vec()),
            },
        )
        .expect("the device id answer must frame");
        assert_eq!(&bytes[..4], &BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes());
        assert_eq!(&bytes[4..8], &BR_REPLY_CMD.to_ne_bytes());
        assert_eq!(bytes.len(), 8 + size_of::<binder_transaction_data>());

        // 反解出来那个 tr：它得指向那块的 parcel，标志位干净
        let tr = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(8) as *const binder_transaction_data)
        };
        assert_eq!(tr.data_size, reply.data_size());
        // SAFETY: 这个 union 的 ptr 分支是我们自己刚写进去的，读它只是为了拿到缓冲区地址
        let buffer = unsafe { tr.data.ptr.buffer } as usize;
        assert_eq!(buffer, reply.data_ptr() as usize);
        assert_eq!(
            tr.offsets_size, 0,
            "a SOTER reply carries no binder objects"
        );
        assert_eq!(
            tr.flags & TF_STATUS_CODE,
            0,
            "a normal reply must not be flagged as an error"
        );
        assert_ne!(tr.data_size, 0, "getDeviceId answers with a real payload");
    }

    #[test]
    fn every_code_the_local_backend_can_answer_is_intercepted() {
        // 本地后端有实现的号码全部拦下来自己回；2 / 6 带 uid，14 无参。
        for code in [1u32, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13] {
            let data = token_with_header(3, &|out| {
                push_i32(out, 10373);
                push_string(out, "SoterAuthKey");
                push_string(out, "0102030405");
            });
            let call = parse(&data, code).unwrap_or_else(|| panic!("code {code} must parse"));
            assert!(interceptable(&call), "code {code} must be intercepted");
        }

        // 2 / 6 / 14 是产线 provisioning，本地后端同样答、照样拦；2 / 6 带 uid，14 无参。
        for code in [2u32, 6] {
            let data = request(&|out| push_i32(out, 10373));
            let call = parse(&data, code).unwrap_or_else(|| panic!("code {code} must parse"));
            assert!(interceptable(&call), "code {code} must be intercepted");
        }
        let call = parse(&request(&|_out| {}), 14).expect("code 14 must parse");
        assert!(interceptable(&call), "code 14 must be intercepted");
    }

    #[test]
    fn empty_alias_and_challenge_keep_the_vendors_codes() {
        // 原厂宿主在服务层就把这两类挡掉、不发 HAL：空别名 -202、空 challenge -203。
        fn call(code: u32, alias: &str, challenge: Option<&str>) -> SoterCall {
            SoterCall {
                hal: false,
                hidl: false,
                has_return_code: true,
                code,
                wire_code: code,
                op: "test",
                uid: Some(10373),
                alias: Some(alias.to_string()),
                challenge: challenge.map(str::to_string),
                session: None,
                key: None,
                caller_uid: Some(10373),
                data_size: 0,
            }
        }

        for code in [4u32, 5] {
            match answer_app_call(&call(code, "", None), 10373) {
                Some(AppAnswer::Int(rc)) => assert_eq!(rc, -202, "app {code}"),
                other => panic!("app {code}: 期望 -202，拿到 {other:?}"),
            }
        }
        match answer_app_call(&call(6, "", None), 10373) {
            Some(AppAnswer::Export { code: rc, data }) => {
                assert_eq!(rc, -202);
                assert!(data.is_none(), "空别名不该带导出数据");
            }
            other => panic!("app 6: 期望 -202，拿到 {other:?}"),
        }
        // 9 号是别名先、challenge 后，顺序跟原厂一致。
        match answer_app_call(&call(9, "", Some("0102")), 10373) {
            Some(AppAnswer::Session { session, code: rc }) => assert_eq!((session, rc), (0, -202)),
            other => panic!("app 9 空别名：期望 -202，拿到 {other:?}"),
        }
        match answer_app_call(&call(9, "SoterAuthKey", Some("")), 10373) {
            Some(AppAnswer::Session { session, code: rc }) => assert_eq!((session, rc), (0, -203)),
            other => panic!("app 9 空 challenge：期望 -203，拿到 {other:?}"),
        }
        // hasAuthKey 例外：原厂对空别名只回 false，不报错。
        match answer_app_call(&call(8, "", None), 10373) {
            Some(AppAnswer::Int(rc)) => assert_eq!(rc, 0, "hasAuthKey 空别名就是 false"),
            other => panic!("app 8: 期望 0，拿到 {other:?}"),
        }
    }

    #[test]
    fn every_answer_shape_frames_a_reply_the_host_can_read() {
        // Explicit answers keep framing independent of live daemon RPC, RSA signing,
        // and process-global key/session state. Test both AIDL buffer layouts.
        let cases: [(u32, Vec<u8>); 5] = [
            (1, request(&|out| push_i32(out, 10373))),
            (
                3,
                request(&|out| {
                    push_i32(out, 10373);
                    push_string(out, "SoterAuthKey");
                }),
            ),
            (8, request(&|_out| {})),
            (9, request(&|out| push_i32(out, 10373))),
            (
                11,
                request(&|out| {
                    push_i32(out, 10373);
                    push_string(out, "SoterAuthKey");
                    push_string(out, "0102030405");
                }),
            ),
        ];
        for has_return_code in [true, false] {
            for (code, data) in &cases {
                let mut call = parse(data, *code).expect("a known hal code");
                call.has_return_code = has_return_code;
                let answer = match code {
                    1 | 8 => Answer::Buffer {
                        code: 0,
                        data: Some(b"test".to_vec()),
                    },
                    3 => Answer::Buffer {
                        code: -5,
                        data: None,
                    },
                    9 => Answer::Code(-5),
                    11 => Answer::Init {
                        status: 0,
                        session: 0x1234_5678,
                    },
                    _ => unreachable!(),
                };
                let (bytes, reply) = frame_br_reply(&call, answer)
                    .unwrap_or_else(|| panic!("the answer must frame for code {code}"));
                assert_eq!(&bytes[..4], &BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes());
                assert_eq!(&bytes[4..8], &BR_REPLY_CMD.to_ne_bytes());
                assert_eq!(bytes.len(), 8 + size_of::<binder_transaction_data>());
                let tr = unsafe {
                    std::ptr::read_unaligned(bytes.as_ptr().add(8) as *const binder_transaction_data)
                };
                assert_eq!(tr.data_size, reply.data_size());
                assert_eq!(tr.flags & TF_STATUS_CODE, 0);
                assert_eq!(tr.offsets_size, 0);
                // SAFETY: the reply owns the live parcel referenced by this frame.
                assert_eq!(
                    unsafe { tr.data.ptr.buffer } as usize,
                    reply.data_ptr() as usize
                );
                let payload =
                    unsafe { std::slice::from_raw_parts(reply.data_ptr(), reply.data_size()) };
                let mut expected = vec![0i32]; // Binder Status::Ok
                match code {
                    9 => expected.push(-5),
                    11 => expected.extend([1, 16, 0, 0x1234_5678, 0]),
                    1 | 3 | 8 => {
                        let status = if *code == 3 { -5 } else { 0 };
                        let len = if *code == 3 { 0 } else { 4 };
                        if has_return_code {
                            expected.push(status);
                        }
                        expected.extend([1, if has_return_code { 12 + len } else { 16 + len }]);
                        if !has_return_code {
                            expected.push(status);
                        }
                        expected.push(len);
                        if len != 0 {
                            expected.push(i32::from_le_bytes(*b"test"));
                        }
                        expected.push(len);
                    }
                    _ => unreachable!(),
                }
                let expected: Vec<u8> = expected.into_iter().flat_map(i32::to_le_bytes).collect();
                assert_eq!(
                    payload, expected,
                    "code {code}, return code {has_return_code}"
                );
            }
        }
    }

    // -------------------------------------------------------------------
    // HIDL 那一套
    // -------------------------------------------------------------------

    fn push_abi_usize(out: &mut Vec<u8>, value: usize) {
        if size_of::<usize>() == 8 {
            out.extend_from_slice(&(value as u64).to_le_bytes());
        } else {
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
    }

    /// 一个 `binder_buffer_object`：`{hdr{type}, flags, buffer, length, parent, parent_offset}`。
    fn push_hidl_buffer_object(
        out: &mut Vec<u8>,
        buffer: usize,
        length: usize,
        flags: u32,
        parent: usize,
    ) {
        out.extend_from_slice(&BINDER_TYPE_PTR.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        push_abi_usize(out, buffer);
        push_abi_usize(out, length);
        push_abi_usize(out, parent);
        push_abi_usize(out, 0);
    }

    /// HIDL 的一个 string 参数：parcel 里两个对象，结构体和字符在外面。
    /// `keep` 持有那些内存，得活到 parse 完。
    fn push_hidl_string(out: &mut Vec<u8>, keep: &mut Vec<Box<[u8]>>, value: &str) {
        let mut chars = value.as_bytes().to_vec();
        chars.push(0);
        let chars: Box<[u8]> = chars.into_boxed_slice();
        let chars_pointer = chars.as_ptr() as usize;
        keep.push(chars);

        // hidl_pointer(8) + uint32 mSize + bool mOwnsBuffer + 3 补位
        let mut head = vec![0u8; HIDL_STRUCT_SIZE].into_boxed_slice();
        head[0..8].copy_from_slice(&(chars_pointer as u64).to_le_bytes());
        head[8..12].copy_from_slice(&(value.len() as u32).to_le_bytes());
        let head_pointer = head.as_ptr() as usize;
        keep.push(head);

        push_hidl_buffer_object(out, head_pointer, HIDL_STRUCT_SIZE, 0, 0);
        push_hidl_buffer_object(
            out,
            chars_pointer,
            value.len() + 1,
            BINDER_BUFFER_FLAG_HAS_PARENT,
            0,
        );
    }

    /// Legacy String16 HIDL fixture, retained independently of real CString tokens.
    fn hidl_token(descriptor: &str) -> Vec<u8> {
        let mut out = Vec::new();
        push_string(&mut out, descriptor);
        out
    }

    /// libhwbinder Parcel::writeCString: strlen + 1, then zero padding to four.
    fn hidl_cstring_token(descriptor: &str) -> Vec<u8> {
        let mut out = descriptor.as_bytes().to_vec();
        out.push(0);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }

    #[test]
    fn real_hidl_cstring_tokens_align_uid_and_session() {
        for descriptor in [
            QTI_HIDL_DESCRIPTOR,
            TRUSTONIC_HIDL_DESCRIPTOR,
            XIAOMI_HIDL_DESCRIPTOR,
            MICROTRUST_HIDL_DESCRIPTOR,
        ] {
            let mut data = hidl_cstring_token(descriptor);
            let args_at = data.len();
            assert_eq!(args_at, (descriptor.len() + 1).next_multiple_of(4));
            assert_eq!(match_descriptor(&data).unwrap().2, args_at);
            push_i32(&mut data, 10490);
            let call = parse(&data, 8).expect("CString hasAskAlready");
            assert!(call.hal && call.hidl);
            assert_eq!(
                (call.code, call.wire_code, call.op),
                (9, 8, "hasAskAlready")
            );
            assert_eq!(call.uid, Some(10490));
            assert!(parse(&data[..data.len() - 1], 8).is_none());

            let mut data = hidl_cstring_token(descriptor);
            push_i64(&mut data, 0x1234_5678_9abc_def0);
            let call = parse(&data, 14).expect("CString finishSign");
            assert!(call.hal && call.hidl);
            assert_eq!((call.code, call.wire_code, call.op), (4, 14, "finishSign"));
            assert_eq!(call.session, Some(0x1234_5678_9abc_def0));
            assert!(parse(&data[..data.len() - 1], 14).is_none());
        }
    }

    #[test]
    fn real_hidl_cstring_init_preserves_embedded_string_boundaries() {
        let alias = "SoterAuthKeyV2_salt11d8ba34_scene1";
        let challenge = "0102030405060708";
        let object_size = 8 + 4 * size_of::<usize>();
        for descriptor in [QTI_HIDL_DESCRIPTOR, TRUSTONIC_HIDL_DESCRIPTOR] {
            let mut keep = Vec::new();
            let mut data = hidl_cstring_token(descriptor);
            push_i32(&mut data, 10490);
            let objects_at = data.len();
            push_hidl_string(&mut data, &mut keep, alias);
            push_hidl_string(&mut data, &mut keep, challenge);
            // The second string's child points to object index 2, not index 0.
            let parent_at = objects_at + 3 * object_size + 8 + 2 * size_of::<usize>();
            let mut parent = Vec::new();
            push_abi_usize(&mut parent, 2);
            data[parent_at..parent_at + parent.len()].copy_from_slice(&parent);
            assert_eq!(data.len(), objects_at + 4 * object_size);
            let mut cursor = Cursor::new(&data, objects_at, true);
            for (index, text) in [(0, alias), (2, challenge)] {
                let head = cursor.hidl_buffer_object().unwrap();
                let child = cursor.hidl_buffer_object().unwrap();
                assert_eq!(head.length, HIDL_STRUCT_SIZE);
                assert_eq!(child.length, text.len() + 1);
                assert_eq!(child.flags, BINDER_BUFFER_FLAG_HAS_PARENT);
                assert_eq!(child.parent, index);
                assert_eq!(child.parent_offset, 0);
            }
            assert_eq!(cursor.remaining(), 0);
            let call = parse(&data, 13).expect("CString initSign");
            assert!(call.hal && call.hidl);
            assert_eq!((call.code, call.wire_code, call.op), (11, 13, "initSign"));
            assert_eq!(call.uid, Some(10490));
            assert_eq!(call.alias.as_deref(), Some(alias));
            assert_eq!(call.challenge.as_deref(), Some(challenge));
            for cut in 0..data.len() {
                assert!(parse(&data[..cut], 13).is_none(), "truncated at {cut}");
            }
        }
    }

    #[test]
    fn real_hidl_cstring_finish_reply_has_embedded_vector_boundaries() {
        let mut data = hidl_cstring_token(QTI_HIDL_DESCRIPTOR);
        push_i64(&mut data, 42);
        let call = parse(&data, 14).expect("CString finishSign");
        let vector = b"signed-json";
        let (_, reply) = frame_br_reply(
            &call,
            Answer::Buffer {
                code: 0,
                data: Some(vector.to_vec()),
            },
        )
        .expect("HIDL vector reply");
        let payload = unsafe { std::slice::from_raw_parts(reply.data_ptr(), reply.data_size()) };
        assert_eq!(&payload[..8], &[0; 8]);
        let object_size = 8 + 4 * size_of::<usize>();
        assert_eq!(payload.len(), 8 + 2 * object_size + 4);
        assert_eq!(reply.offsets.as_ref(), &[8, 8 + object_size]);
        let mut cursor = Cursor::new(payload, 8, true);
        let head = cursor.hidl_buffer_object().unwrap();
        let child = cursor.hidl_buffer_object().unwrap();
        assert_eq!(head.type_, BINDER_TYPE_PTR);
        assert_eq!(head.length, HIDL_STRUCT_SIZE);
        assert_eq!(child.type_, BINDER_TYPE_PTR);
        assert_eq!(child.flags, BINDER_BUFFER_FLAG_HAS_PARENT);
        assert_eq!(child.length, vector.len());
        assert_eq!((child.parent, child.parent_offset), (0, 0));
        assert_eq!(cursor.i32().unwrap() as usize, vector.len());
        assert_eq!(cursor.remaining(), 0);
        let mut header = [0; HIDL_STRUCT_SIZE];
        read_self(head.buffer, &mut header).unwrap();
        assert_eq!(
            u64::from_le_bytes(header[..8].try_into().unwrap()),
            child.buffer as u64
        );
        assert_eq!(
            u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize,
            vector.len()
        );
        let mut actual = vec![0; vector.len()];
        read_self(child.buffer, &mut actual).unwrap();
        assert_eq!(actual, vector);
    }

    #[test]
    fn cstring_tokens_reject_non_hidl_and_non_exact_payloads() {
        for descriptor in [
            HAL_DESCRIPTOR,
            TRUSTONIC_DESCRIPTOR,
            APP_DESCRIPTOR,
            "vendor.qti.hardware.soter@1.0::ISoterExtra",
            "android.hardware.security.keymint@1.0::IKeyMintDevice",
        ] {
            assert!(parse(&hidl_cstring_token(descriptor), 4).is_none());
        }
        let token = hidl_cstring_token(QTI_HIDL_DESCRIPTOR);
        for cut in 0..token.len() {
            assert!(parse(&token[..cut], 4).is_none());
        }
        for prefix in [vec![0; 4], vec![0; 8], vec![0; 12], vec![0xff; 1]] {
            let mut data = prefix;
            data.extend_from_slice(&token);
            assert!(parse(&data, 4).is_none());
        }
        let mut no_nul = token.clone();
        no_nul[QTI_HIDL_DESCRIPTOR.len()] = b'x';
        assert!(parse(&no_nul, 4).is_none());
        let mut bad_padding = token;
        *bad_padding.last_mut().unwrap() = 0xff;
        assert!(parse(&bad_padding, 4).is_none());
    }

    #[test]
    fn reads_a_hidl_request_and_remaps_its_code() {
        // 线上 10 号 = exportAuthKeyPublicKey（`.hal` 的声明顺序），AIDL 那边是 3 号。
        let mut keep: Vec<Box<[u8]>> = Vec::new();
        let mut data = hidl_token(QTI_HIDL_DESCRIPTOR);
        push_i32(&mut data, 10373);
        push_hidl_string(&mut data, &mut keep, "SoterAuthKeyV2_salt11d8ba34_scene1");

        let call = parse(&data, 10).expect("the HIDL request must be recognised");
        assert!(call.hal && call.hidl);
        assert_eq!(call.code, 3, "换算成内部那套号码");
        assert_eq!(call.wire_code, 10);
        assert_eq!(call.op, "exportAuthKeyPublicKey");
        assert_eq!(call.uid, Some(10373));
        assert_eq!(
            call.alias.as_deref(),
            Some("SoterAuthKeyV2_salt11d8ba34_scene1"),
            "别名从 buffer 对象里读出来，一个字节都不能少"
        );
        drop(keep);
    }

    #[test]
    fn reads_a_hidl_init_sign_with_two_strings() {
        // initSign 线上是 13 号，uid + 两个 string。
        let mut keep: Vec<Box<[u8]>> = Vec::new();
        let mut data = hidl_token(TRUSTONIC_HIDL_DESCRIPTOR);
        push_i32(&mut data, 10490);
        push_hidl_string(&mut data, &mut keep, "SoterAuthKeyV2_salt4d605b62_scene1");
        push_hidl_string(&mut data, &mut keep, "0102030405060708");

        let call = parse(&data, 13).expect("the HIDL initSign must be recognised");
        assert_eq!(call.code, 11);
        assert_eq!(call.uid, Some(10490));
        assert_eq!(call.challenge.as_deref(), Some("0102030405060708"));
        drop(keep);
    }

    #[test]
    fn hidl_provisioning_codes_are_recognised_too() {
        // 1/2/3（generateAttkKeyPair / verifyAttkKeyPair / exportAttkPublicKey）换算过去
        // 是 AIDL 的 6/14/2，本地后端也答；2 / 6 带 uid，14 无参。
        let with_uid = {
            let mut data = hidl_token(QTI_HIDL_DESCRIPTOR);
            push_i32(&mut data, 10373);
            data
        };
        let plain = hidl_token(QTI_HIDL_DESCRIPTOR);
        for (wire, internal, op, data) in [
            (1u32, 6u32, "generateAttkKeyPair", &with_uid),
            (2u32, 14u32, "verifyAttkKeyPair", &plain),
            (3u32, 2u32, "exportAttkPublicKey", &with_uid),
        ] {
            let call = parse(data, wire).unwrap_or_else(|| panic!("HIDL {wire} must parse"));
            assert_eq!(
                call.code, internal,
                "HIDL {wire} maps to internal {internal}"
            );
            assert_eq!(call.op, op);
            assert!(interceptable(&call), "HIDL {wire} must be intercepted");
        }
    }

    #[test]
    fn the_hidl_code_map_is_a_permutation_of_the_aidl_one() {
        // 14 个方法一一对应，换算表不能出现重号、也不能掉出那套 1..14。
        let mut seen = std::collections::BTreeSet::new();
        for code in 1..=14u32 {
            let internal = hidl_internal_code(code).expect("every HIDL code maps");
            assert!((1..=14).contains(&internal), "{internal} 不在 1..14 里");
            assert!(seen.insert(internal), "内部号 {internal} 被用了两次");
        }
    }

    #[test]
    fn a_hidl_call_is_answered_in_the_hidl_shape() {
        // getDeviceId：HIDL 线上 4 号、内部 8 号。应答里应当是两个 buffer 对象。
        let data = hidl_token(QTI_HIDL_DESCRIPTOR);
        let call = parse(&data, 4).expect("HIDL 4 is getDeviceId");
        assert_eq!((call.code, call.op), (8, "getDeviceId"));
        assert!(interceptable(&call), "HIDL 那条路现在也拦");

        let (bytes, reply) = frame_br_reply(
            &call,
            Answer::Buffer {
                code: 0,
                data: Some(b"090000001234567890abcdef12345678".to_vec()),
            },
        )
        .expect("the HIDL device id answer must frame");
        assert_eq!(&bytes[..4], &BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes());
        assert_eq!(&bytes[4..8], &BR_REPLY_CMD.to_ne_bytes());
        let tr = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(8) as *const binder_transaction_data)
        };
        assert_eq!(tr.data_size, reply.data_size());
        assert_eq!(tr.flags & TF_STATUS_CODE, 0);
        assert_eq!(
            tr.offsets_size,
            2 * size_of::<usize>(),
            "结构体和元素各一个对象"
        );

        let head = unsafe { std::slice::from_raw_parts(reply.data_ptr(), reply.data_size()) };
        assert_eq!(&head[..8], &[0u8; 8], "hardware::Status ok + 错误码 0");
        let type_ = u32::from_le_bytes(head[8..12].try_into().unwrap());
        assert_eq!(type_, BINDER_TYPE_PTR, "8 那里就该是对象 A");
    }

    /// App 号 → HAL 号的表：1..11 都得落到本地后端答得了的号上；12/13 号不发 HAL 请求。
    #[test]
    fn every_app_transaction_maps_to_a_hal_number_the_local_backend_answers() {
        for code in 1..=11u32 {
            let hal = app_code_to_hal(code).unwrap_or_else(|| panic!("app {code}"));
            assert!(soter_local::answerable(hal), "app {code} -> hal {hal}");
        }
        assert_eq!(app_code_to_hal(12), None, "getVersion 不落地为 HAL 调用");
        assert_eq!(app_code_to_hal(13), None, "getExtraParam 同理");
        // 两个含义最容易弄反的：generate 该去 5、has 该去 9。
        assert_eq!(app_code_to_hal(1), Some(5));
        assert_eq!(app_code_to_hal(3), Some(9));
    }

    /// App 面向的答复字节流：`[Status][…]`，跟宿主自己写的那份一模一样。
    /// 写错一格客户端就会把字段读歪，所以这里直接把字节钉住。
    #[test]
    fn the_app_facing_replies_match_the_host_wire_layout() {
        let raw = |reply: &OwnedReply| unsafe {
            std::slice::from_raw_parts(reply.data_ptr(), reply.data_size()).to_vec()
        };

        // SoterExportResult：Status + 非空标记 + resultCode + byte[] + dataLength
        let with_data = build_app_export_reply(0, Some(&[1, 2, 3, 4])).unwrap();
        assert_eq!(
            raw(&with_data),
            vec![
                0, 0, 0, 0, // Status ok
                1, 0, 0, 0, // 非空标记（客户端 `readTypedObject` 先读这一格）
                0, 0, 0, 0, // resultCode
                4, 0, 0, 0, 1, 2, 3, 4, // byte[]
                4, 0, 0, 0, // dataLength
            ]
        );
        // 没数据那一支跟宿主一样是 `writeByteArray(null)`（-1）+ 长度 0。
        let empty = build_app_export_reply(-6, None).unwrap();
        assert_eq!(
            raw(&empty),
            vec![
                0, 0, 0, 0, // Status ok
                1, 0, 0, 0, // 非空标记
                0xfa, 0xff, 0xff, 0xff, // resultCode -6
                0xff, 0xff, 0xff, 0xff, // null 数组
                0, 0, 0, 0, // dataLength
            ]
        );
        // SoterSessionResult：session 在前、resultCode 在后（跟 HAL 那份相反），
        // 前面同样得有一个非空标记。
        let session = build_app_session_reply(0x1122_3344_5566_7788, 0).unwrap();
        assert_eq!(
            raw(&session),
            vec![
                0, 0, 0, 0, // Status ok
                1, 0, 0, 0, // 非空标记
                0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // session
                0, 0, 0, 0, // resultCode
            ]
        );
        // SoterExtraParam：非空标记 + writeValue(Integer) 的类型标 + 值。
        let extra = build_app_extra_param_reply(2).unwrap();
        assert_eq!(
            raw(&extra),
            vec![0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0]
        );
    }

    /// 没东西可答（没有待答请求 / 不在窗口内）就什么都不动 —— 宿主自己那份答复照旧过去。
    #[test]
    fn no_pending_app_call_means_we_leave_the_host_answer_alone() {
        let _guard = auto_serve_test_lock();
        reset_auto_serve_for_test();
        assert!(take_app_answer().is_none());
    }

    /// 自动兜底用的空别名 generateAuthKey（4 号）：走纯校验路径回 -202，不碰 daemon。
    fn blind_app_call() -> SoterCall {
        SoterCall {
            hal: false,
            hidl: false,
            has_return_code: true,
            code: 4,
            wire_code: 4,
            op: "generateAuthKey",
            uid: Some(10373),
            alias: Some(String::new()),
            challenge: None,
            session: None,
            key: None,
            caller_uid: Some(10373),
            data_size: 0,
        }
    }

    /// 这三个自动接管测试共用一份进程级现场证据，并行跑会互相清零，拿这把锁串行化。
    use super::auto_serve_test_lock;

    /// 自动接管开了没有。只看进程内那个标记，不渗文件/环境变量那头。
    fn auto_serve_on() -> bool {
        AUTO_APP_SERVE.load(Ordering::Relaxed)
    }

    /// 2/6 号读的是我们自己造的料，没写过开关时默认归我们答；写 `0` 就是不接；
    /// 接管成立后开关不参与判断。
    #[test]
    fn reads_our_material_is_served_by_default() {
        assert!(app_reply_ours(2, None, false));
        assert!(app_reply_ours(6, None, false));
        assert!(!app_reply_ours(4, None, false));
        assert!(app_reply_ours(4, None, true));
        assert!(app_reply_ours(2, Some(true), false));
        assert!(!app_reply_ours(2, Some(false), false));
        // 接管成立以后手工开关不再参与
        assert!(app_reply_ours(4, Some(false), true));
    }

    /// 宿主没碰 HAL 的首笔请求就接管（阈值 1）：当笔就用我们的答复顶掉，之后每笔都答。
    #[test]
    fn auto_app_serve_engages_after_a_blind_streak() {
        let _guard = auto_serve_test_lock();
        reset_auto_serve_for_test();
        assert!(!auto_serve_on(), "还没接管");

        // 首笔盲请求当场接管。
        stash_app_call_for_test(blind_app_call(), 10373);
        let reply = take_app_answer().expect("首笔盲请求必须由我们答");
        assert!(reply.data_size() > 0);
        assert!(auto_serve_on(), "接管开了就一直在");

        // 之后每一笔都直接答，不再攒。
        stash_app_call_for_test(blind_app_call(), 10373);
        assert!(take_app_answer().is_some());
        reset_auto_serve_for_test();
    }

    /// 宿主要去碰过我们认识的 HAL 描述符，这台机器的腿就是好的，永不自动接管。
    #[test]
    fn recent_hal_activity_keeps_the_auto_serve_off() {
        let _guard = auto_serve_test_lock();
        reset_auto_serve_for_test();
        for _ in 0..APP_AUTO_SERVE_THRESHOLD + 1 {
            // 请求进来之后宿主去碰了 HAL：先 stash、再记 HAL 活动，跟真机时序一致。
            stash_app_call_for_test(blind_app_call(), 10373);
            note_hal_activity();
            assert!(take_app_answer().is_none(), "HAL 腿活着就不该接");
        }
        assert!(!auto_serve_on());
        reset_auto_serve_for_test();
    }

    /// 12/13 号宿主本来就自己答（不碰 HAL），不许算进「宿主瞎」的连击里。
    #[test]
    fn host_served_codes_do_not_count_toward_the_blind_streak() {
        let _guard = auto_serve_test_lock();
        reset_auto_serve_for_test();
        for code in [12u32, 13] {
            let mut call = blind_app_call();
            call.code = code;
            call.wire_code = code;
            call.op = "host-served";
            call.key = Some("fingerprint_type".to_string());
            stash_app_call_for_test(call, 10373);
            assert!(take_app_answer().is_none());
        }
        assert!(!auto_serve_on());
        reset_auto_serve_for_test();
    }

    /// 误判之后能自己退回来：接管开着时又看到宿主碰了我们认识的 HAL，就撤掉并静默一段。
    #[test]
    fn a_revoked_auto_serve_backs_off_instead_of_flapping() {
        let _guard = auto_serve_test_lock();
        reset_auto_serve_for_test();
        // 先让它接一笔，接管就开着。
        stash_app_call_for_test(blind_app_call(), 10373);
        assert!(take_app_answer().is_some());
        assert!(auto_serve_on());

        // 宿主腿又活了：接管被撤、并进入静默期。
        note_hal_activity();
        assert!(!auto_serve_on(), "看到 HAL 流量就该撤");
        let silenced = PROBE_SILENT_UNTIL.lock().map(|slot| *slot).ok().flatten();
        assert!(
            probes_silenced(silenced, Instant::now()),
            "撤掉之后要静默，否则下一笔又接、来回抖"
        );

        // 静默期里再来的盲请求不好使（等于旧行为）。
        stash_app_call_for_test(blind_app_call(), 10373);
        assert!(take_app_answer().is_none(), "静默期里不该接");
        assert!(!auto_serve_on());
        reset_auto_serve_for_test();
    }

    /// 我们自己答不上时的退避判定（纯函数）。
    #[test]
    fn the_probe_backoff_is_a_hard_deadline() {
        let now = Instant::now();
        assert!(!probes_silenced(None, now), "没设过就不静默");
        assert!(probes_silenced(Some(now + Duration::from_secs(1)), now));
        assert!(!probes_silenced(Some(now - Duration::from_secs(1)), now));
    }

    /// 接口名被 ROM 换掉时也能把 App 面向那笔认下来：只靠 sender 是应用 + 参数形状对得上。
    #[test]
    fn an_unknown_interface_name_still_yields_the_app_side() {
        let mut data = interface_token("com.example.rom.soter.IRenamed");
        push_i32(&mut data, 10490);
        push_string(&mut data, "SoterAuthKeyV2_x_scene1");
        assert!(
            parse(&data, 8).is_none(),
            "token 不认识，严格解释那里就该放过"
        );
        let call = parse_untokened_with(&data, 8, 10490, true).expect("放宽路径得认出来");
        assert!(!call.hal);
        assert_eq!(call.code, 8);
        assert_eq!(call.op, "hasAuthKey");
        assert_eq!(call.uid, Some(10490));
        assert_eq!(call.alias.as_deref(), Some("SoterAuthKeyV2_x_scene1"));
        assert_eq!(call.caller_uid, Some(10490), "调用者要用内核填的那个");
    }

    /// 放宽那三条约束，一条不满足就都不能认。
    #[test]
    fn the_untokened_side_needs_all_three_gates() {
        let mut data = interface_token("com.example.rom.soter.IRenamed");
        push_i32(&mut data, 10490);
        push_string(&mut data, "SoterAuthKey");

        assert!(!untokened_app_allowed(
            1000,
            "com.tencent.soter.soterserver"
        ));
        assert!(!untokened_app_allowed(10490, "/system/bin/keystore2"));
        assert!(!untokened_app_allowed(10490, "vendor.example.cryptoeng"));
        assert!(untokened_app_allowed(
            10490,
            "com.tencent.soter.soterserver"
        ));
        // HAL 进程名字里也带 soter，但它们不直接服务 App，不放宽。
        assert!(!untokened_app_allowed(
            10490,
            "vendor.qti.hardware.soter-service"
        ));
        assert!(!untokened_app_allowed(
            10490,
            "vendor.qti.hardware.soter@1.0-service"
        ));
        // 多用户/分身的宿主实例（cmdline 带冒号）照旧放宽。
        assert!(untokened_app_allowed(
            99910365,
            "com.tencent.soter.soterserver:u0a123"
        ));

        assert!(parse_untokened_with(&data, 8, 10490, false).is_none());
    }

    /// 12/13 号没有形状可验，不放宽（那两个宿主本来自己答）。
    #[test]
    fn the_shapeless_codes_are_never_guessed() {
        let mut data = interface_token("com.example.rom.soter.IRenamed");
        push_i32(&mut data, 10490);
        for code in [12u32, 13] {
            assert!(
                parse_untokened_with(&data, code, 10490, true).is_none(),
                "code {code} 没形状可验，不能猜"
            );
        }
    }

    /// 解出来的参数不像真的就不认（uid 落在应用号段以外、alias 带控制字符、随机字节）。
    #[test]
    fn implausible_values_do_not_pass_the_shape_check() {
        let mut data = interface_token("com.example.rom.soter.IRenamed");
        push_i32(&mut data, 1000);
        push_string(&mut data, "SoterAuthKey");
        assert!(parse_untokened_with(&data, 8, 10490, true).is_none());

        let mut data = interface_token("com.example.rom.soter.IRenamed");
        push_i32(&mut data, 10490);
        push_string(&mut data, "bad\u{1}alias");
        assert!(parse_untokened_with(&data, 8, 10490, true).is_none());

        let junk: Vec<u8> = (0..64u8).map(|byte| byte.wrapping_mul(37)).collect();
        assert!(parse_untokened_with(&junk, 8, 10490, true).is_none());
    }
}
