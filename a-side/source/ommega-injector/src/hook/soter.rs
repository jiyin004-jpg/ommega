//! SOTER 那一族的识别与解析（A 端）。
//!
//! A 端的 SOTER 宿主是 `com.tencent.soter.soterserver`（system uid 1000，纯 Java）。
//! 它把 App 的请求转成对高通 HAL 的 binder 调用 `vendor.qti.hardware.soter.ISoter`，
//! 我们自己那份 hook 就装在宿主进程里，所以要认的是**写出去**的那条 transaction：
//! data 开头的 interface token 是那个描述符，`code` 是下面表里的号。
//!
//! 号码是从 APK 里 `ISoter$Stub$Proxy` 的 `transact(n, …)` 反查出来的（不是按声明
//! 顺序猜的，声明顺序和号不一样）。它只有 11 个方法、号跳着用，2 / 6 / 14 是空号 ——
//! 也就是这版运行时 HAL 没有 `exportAttkPublicKey`、`generateAttkKeyPair`、
//! `verifyAttkKeyPair`，那三个在量产 provisioning 那条路上。
//!
//! | code | 方法 | 入参 |
//! |------|------|------|
//! | 1  | exportAskPublicKey       | i32 uid |
//! | 3  | exportAuthKeyPublicKey   | i32 uid, String alias |
//! | 4  | finishSign               | i64 session |
//! | 5  | generateAskKeyPair       | i32 uid |
//! | 7  | generateAuthKeyPair      | i32 uid, String alias |
//! | 8  | getDeviceId              | — |
//! | 9  | hasAskAlready            | i32 uid |
//! | 10 | hasAuthKey               | i32 uid, String alias |
//! | 11 | initSign                 | i32 uid, String alias, String challenge |
//! | 12 | removeAllUidKey          | i32 uid |
//! | 13 | removeAuthKey            | i32 uid, String alias |
//!
//! 这一版既认也答：认得出来的号码就由本地/远程后端写应答（`soter_local`、`soter_relay`），
//! 认不出来或者缺参数的照旧透给真 HAL。日志进 logcat，格式是 `event=soter …`，好过滤。
//!
//! 两边号码表得分开：两个接口是各自独立的 AIDL，号码不通用。App 面向那边
//! （`ISoterService`，1..13 连着、没空号，9 号是腾讯自家拼错的 `initSigh`）：
//!
//! | code | 方法 | 入参 |
//! |------|------|------|
//! | 1  | generateAppSecureKey | i32 uid |
//! | 2  | getAppSecureKey       | i32 uid |
//! | 3  | hasAskAlready         | i32 uid |
//! | 4  | generateAuthKey       | i32 uid, String alias |
//! | 5  | removeAuthKey         | i32 uid, String alias |
//! | 6  | getAuthKey            | i32 uid, String alias |
//! | 7  | removeAllAuthKey      | i32 uid |
//! | 8  | hasAuthKey            | i32 uid, String alias |
//! | 9  | initSigh              | i32 uid, String alias, String challenge |
//! | 10 | finishSign            | i64 session |
//! | 11 | getDeviceId           | — |
//! | 12 | getVersion            | — |
//! | 13 | getExtraParam         | String key |
//!
//! uid 是 App 自己的（SoterService 用 `Binder.getCallingUid()`），不是 binder 的
//! 调用者 uid；所以作用域判定要看这个参数。

use std::ffi::c_void;
use std::mem::size_of;

use log::{debug, info};

use crate::hook::binder::{
    binder_transaction_data, binder_transaction_data_data, binder_transaction_data_data_ptr,
    binder_transaction_data_target, BINDER_BUFFER_FLAG_HAS_PARENT, BINDER_TYPE_PTR, BR_REPLY_CMD,
    BR_TRANSACTION_COMPLETE_CMD,
};
use crate::hook::soter_local::{self, Answer};
use crate::parcel::{
    build_hidl_soter_buffer_reply, build_hidl_soter_init_reply, build_plain_reply,
    build_soter_buffer_reply, build_soter_init_reply, OwnedReply, HIDL_STRUCT_SIZE,
};

/// 高通 HAL 的接口描述符（SoterService 发出去的那条）。
pub(crate) const HAL_DESCRIPTOR: &str = "vendor.qti.hardware.soter.ISoter";
/// Trustonic 那套 AIDL 的描述符。联发科机型上没有高通那个 HAL，宿主发出去的是这条
/// （实测一加 PLC110：`vendor.trustonic.hardware.soter.ITrustonicSoter/default`，vintf 里声明成
/// aidl）。方法号与高通那份同序同名，1..14 一张表就能盖住，所以解析那半段完全复用；
/// 差别只在 2 / 6 / 14 这三个 provisioning 方法：联发科上是真实现，高通那边是空号。
pub(crate) const TRUSTONIC_DESCRIPTOR: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter";
/// HIDL 那一版的描述符。名字里带版本号（`@1.0::`），跟 AIDL 那两条完全不是一回事：
/// 宿主 dex 里两种代理类都在（`...@1.0::ISoter@Proxy` / `...@1.0::ITrustonicSoter@Proxy`），
/// 哪条路通得看系统里装的是哪种实现，所以两条都得认。
pub(crate) const QTI_HIDL_DESCRIPTOR: &str = "vendor.qti.hardware.soter@1.0::ISoter";
pub(crate) const TRUSTONIC_HIDL_DESCRIPTOR: &str =
    "vendor.trustonic.hardware.soter@1.0::ITrustonicSoter";
/// App 面向的接口描述符（App 发给 SoterService 的那条，走的是入站 transaction）。
pub(crate) const APP_DESCRIPTOR: &str = "com.tencent.soter.soterserver.ISoterService";

/// 描述符是哪一边的。
///
/// HIDL 单独一档是因为那边的事务号、参数形状、答复布局跟 AIDL 全是两套东西。规格是从
/// AOSP / libhidl 与宿主 dex 里抠出来的硬事实，别再从头猜：
///
/// - 事务号不是什么 hash，就是 `.hal` 里的声明顺序 1..14（宿主 dex 里是 `transact(4, ...)`
///   这种字面量）。但**映射跟 AIDL 不是一套**（见 [`HIDL_TO_INTERNAL_CODE`]）。
/// - 回包开头是一个 `Status`（一个 i32，0 即成功；非 0 时后面还跟一条 String16 的 message）。
/// - 请求与回包里的 string / vector 走 binder 的 buffer 对象：parcel 里只躺对象，
///   结构体和数据体都在 parcel 外面，靠对象里的地址去读。跟 AIDL 那种内联的
///   「长度 + 字节 / String16」完全是两回事。
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
    /// 走的是 HIDL（`@1.0::` 那种描述符）。只影响拦截：HIDL 现在只观察。
    pub(crate) hidl: bool,
    /// 回包里有没有「方法返回值」那一格。高通那套签名是 `int xxx(...)`、联发科是 `void`，
    /// 这一格有没有决定了错误码放哪、答复总长怎么算（见 `parcel::reply` 里那两个构造器）。
    pub(crate) has_return_code: bool,
    pub(crate) code: u32,
    /// 线上那个号。HIDL 那套号跟内部（AIDL）那套不是一个排列，解析时已经换算成内部号了，
    /// 这里留一份原值只为看日志时对得上真实流量。
    pub(crate) wire_code: u32,
    pub(crate) op: &'static str,
    pub(crate) uid: Option<i32>,
    pub(crate) alias: Option<String>,
    pub(crate) challenge: Option<String>,
    pub(crate) session: Option<i64>,
    /// App 面向 13 号 `getExtraParam` 那个 key。
    pub(crate) key: Option<String>,
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
        // 高通 HAL：声明了 14 个方法，运行时只用得上这 11 个，2 / 6 / 14 是空号。
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

/// 这个号会不会改设备上的钥匙（建 / 删）。观察阶段只用来标日志，接转发时这几个
/// 必须走 mutation 开关。
///
/// App 面向的 9 号（`initSigh`）也算 —— B 端那边它可能顺手把 AuthKey 建出来。
pub(crate) fn is_mutation(hal: bool, code: u32) -> bool {
    if hal {
        matches!(code, 5 | 7 | 12 | 13)
    } else {
        matches!(code, 1 | 4 | 5 | 7 | 9)
    }
}

/// 请求里那个 `binder_buffer_object`（HIDL 的 string / vector 走它）。
///
/// 字段照内核 uapi 的 `struct binder_buffer_object` 摆，`buffer` / `length` / `parent` /
/// `parent_offset` 的宽度跟 ABI 走。解析一个字符串只用到 `type_`、`length` 和 `buffer`，
/// 其余几个留着是为了跟结构体对得上（也方便以后要看 parent 链的时候用）。
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
///
/// 读的是别的进程写下来的字节，宁可读不出来也不能越界。
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
    ///
    /// 以前这里按「字节长度 + 字符数 + 字节」读，还拿 `from_utf8_lossy` 解 —— 两处都错：
    /// 那第二个 i32 其实是 UTF-16 数据的前 4 个字节（等于白吃掉头两个字符），而 UTF-16
    /// 的字节被当 UTF-8 逐字节收下，`\0` 就全留在串里了。日志里那串
    /// `alias="t\0e\0r\0A\0u\0t\0h\0K\0e\0y\0V\02\0_\0s\0a\0l\0t"`（真名
    /// `SoterAuthKeyV2_salt`）就是这两个错叠出来的，而且串被截成一半。别名是本地
    /// 后端的键、也是要转给 B 端的东西，必须一个字节不差。
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

    /// 一个 `binder_buffer_object`。
    ///
    /// 第二个 u32 是 buffer 自己的 flags（`BINDER_BUFFER_FLAG_HAS_PARENT` 在这一格），
    /// 不是 `hdr.flags` —— 内核的定义是 `{hdr{type}, flags, buffer, length, parent,
    /// parent_offset}`，别把这两格弄反了。
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

    /// HIDL 的 `hidl_string`：parcel 里只躺两个对象 —— 一个指向那 16 字节的
    /// `hidl_string` 结构体（`hidl_pointer mBuffer`(8) + `uint32_t mSize`(4) + 补位），
    /// 一个指向字符本身（长度是 size+1，尾巴上有 NUL）。结构体和字符都在 parcel 外面，
    /// 只能按对象里写的地址去读。
    ///
    /// 那些地址就是我们自己这个进程里的（宿主就是发这笔 transaction 的那个进程，
    /// 是它自己的 libhwbinder 写下的指针），但仍旧走 `process_vm_readv` 去读：读不动
    /// 就当认不出来，不能为了解析一串日志把宿主读崩。
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

/// interface token 在真实流量里见过这几种前缀（里面都是 i32）：
///
/// ```text
///  0 字节：[String16]                                  hwbinder / HIDL —— 没有 strict-mode
///  4 字节：[strict-mode policy][String16]              老一点的 libbinder
///  8 字节：[strict-mode policy]['SYST'][String16]       （没见过实例，但形状上说得通）
/// 12 字节：[strict-mode policy][work source]['SYST'][String16]
/// ```
///
/// 最后一个就是真机实测的 app_process 布局：`writeInterfaceToken` 出来的是
/// `[policy][workSource]['SYST'][len][字符][0][参数]`，注意这里的 `len` 是**字符数**，
/// 结尾那个 0 是**单另一个 u32**；而老的 String16 写法把结尾 0 算进 `len` 里。
/// 两种都试，谁的 UTF-16 解出来正好等于我们认的串就用谁。
/// 别省这一步：少了 12 字节那个前缀，App 侧的 SOTER 流量一条都认不出来。
///
/// 第二个返回值是「这个接口的方法带不带 int 返回值」，跟着描述符一起定：
/// 高通那两条（AIDL 与 HIDL）都是 `int`，联发科那两条都是 `void`。
fn match_descriptor(data: &[u8]) -> Option<(Side, bool, usize)> {
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
            if text == APP_DESCRIPTOR {
                return Some((Side::App, false, next));
            }
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
    // Android 的 writeString16 是「字符 + 一个 NUL」，再把 (len+1)*2 补到 4 字节对齐。
    // 空串也带着这个 NUL。之前空串直接返回、非空串只按 2*len 补位，两种情况下游标都少走
    // 4 字节，于是紧跟在字符串后面的那个字段被读成空串 —— 微信 initSigh 的 challenge
    // （50 多个字符）就是这么丢的，B 端签出来的 JSON 里 raw 是空的。
    cursor.take(2)?;
    cursor.skip_padding(len * 2 + 2)?;
    Some((text, cursor.at))
}

/// HIDL 的号对到内部（AIDL）那套号码上。
///
/// `.hal` 里 14 个方法按声明顺序拿号：1 generateAttkKeyPair、2 verifyAttkKeyPair、
/// 3 exportAttkPublicKey、4 getDeviceId、5 generateAskKeyPair、6 exportAskPublicKey、
/// 7 removeAllUidKey、8 hasAskAlready、9 generateAuthKeyPair、10 exportAuthKeyPublicKey、
/// 11 removeAuthKey、12 hasAuthKey、13 initSign、14 finishSign。
/// AIDL 那套的声明顺序是另一个排列，这张表是宿主 dex 里两个代理类各自的
/// `transact(n, …)` 字面量对出来的（HIDL 4 = AIDL 8 getDeviceId、HIDL 6 = AIDL 1
/// exportAskPublicKey …），不是按名字猜的，别重排。
/// 1/2/3 落到 AIDL 的 6/14/2 上，那是运行时没有的 provisioning 号，所以照旧认不出来
/// —— 跟 AIDL 那半边一致。
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
    // HIDL 的号是 `.hal` 的声明顺序，跟 AIDL 那套不是一个排列。认出来之后就换算成内部号：
    // 参数形状、下面那几层分派（本地/远程、mutation 开关）全都只看内部号。
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
        data_size: data.len(),
    })
}

/// 观察一条写出去的 transaction。不是 SOTER 的就一声不吭地回去。
///
/// # Safety
///
/// 调用方得保证 `tr.data.ptr.buffer` 指向 `tr.data_size` 个可读字节 —— 在
/// `parse_write_buffer` 里，payload shadow 已经把这段换成本进程里的副本了。
pub(crate) unsafe fn observe(tr: &binder_transaction_data) -> Option<SoterCall> {
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
    let call = parse(data, tr.code)?;
    log_call(&call);
    Some(call)
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
    let line = format!("{line}{wire_code}");
    // 本地那一路（logcat / 日志文件）在 app 域的进程里是哑的，所以同一条还顺 RPC 送一份给
    // daemon 记：宿主的观测只有这一条路能看见。
    info!("{line}");
    crate::ipc::report_event(line);
    if call.challenge.is_some() {
        debug!("event=soter challenge={:?}", call.challenge);
    }
}

/// 这条出站请求，我们自己答还是放它去真 HAL。
///
/// 拦截范围就是本地后端写了实现的那 11 个号码：这台机器的真 HAL 对整族 ATTK 都是
/// -20（连 provisioning 都拒），留着它只会把宿主一路坑下去；而这 11 个号码无论最后
/// 是远程答、本地答还是配置说不许兜底，走的都是同一套拦截与回填。号码不认识、参数
/// 不够的仍在 `intercept_soter_call` 里原样透传，不会把宿主挂住。
pub(crate) fn interceptable(call: &SoterCall) -> bool {
    call.hal && soter_local::answerable(call.code)
}

/// 把一笔答复拼成宿主能直接吃的内核命令字节流，连同一块得活着的 parcel 一起交出去。
///
/// 答复从哪来由 [`crate::hook::soter_relay`] 定：远程（B 端 TEE）优先，配置允许就退回
/// A 端本地自签，两边都没有就返回 `None` 让调用方透传。
///
/// 形状是 `[BR_TRANSACTION_COMPLETE][BR_REPLY]`。为什么前面那条也得给：宿主
/// `waitForResponse` 的写法是「读一个 cmd，碰到 COMPLETE 就 break 出 switch 回循环顶部」，
/// 接着它再调一次 `talkWithDriver`；那一刻 `mIn` 里还剩 68 字节没读，libbinder 算出的
/// `needRead = dataPosition >= dataSize` 为假，于是那次 ioctl 的 read_size 是 0，
/// 内核直接返回、不会覆盖缓冲区，第二次才把 BR_REPLY 收下。少给前一条也不会卡
/// （``dataAvail()`` 非 0 就会接着读），补上只是更像真机上同步调用的节奏。
///
/// 返回的字节流里 `data.ptr.buffer` 指的是第二个返回值的 parcel，所以**调用方得把这块
/// parcel 一直留到宿主把 `BC_FREE_BUFFER` 交回来为止** —— 这两个返回值是一个整体。
/// `OwnedReply` 里装的是堆上的 `Parcel`，移交给调用方不会挪动数据本身，指针依旧有效。
pub(crate) fn build_br_reply(call: &SoterCall) -> Option<(Vec<u8>, OwnedReply)> {
    let reply = match crate::hook::soter_relay::answer(call)? {
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
                build_soter_init_reply(status, session, call.has_return_code).ok()?
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

    /// 造一条现代的 interface token（含 strict-mode policy 前缀）。
    ///
    /// 长度写的是**字符数，不含 NUL**，后面才是 NUL 和补齐 —— 跟 `push_string` 一样
    /// 跟着 Android `writeString16` 的真实布局来，别再写成「长度含 NUL」那套。
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

    /// AIDL 的 String16：字符数 + UTF-16LE + NUL 终结符 + 补齐。（跟 Cursor::string 一份
    /// 布局，别再造一套出来，不然测试绿着、真机流量照样读错。）
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

    /// `'S' 'Y' 'S' 'T'`，现代 libbinder 在 strict-mode policy 之后写的那个魔数
    /// （放进 u32 里是最低位是 'T'）。
    const INTERFACE_HEADER: u32 = 0x5359_5354;

    /// 造一条带指定前缀字数的 token：0 / 1 / 2 / 3 个 i32 头，然后 String16 + 参数。
    ///
    /// 1 个 = 老 libbinder；2 个 = policy + 'SYST'；3 个 = 真机实测的 app_process 布局
    /// （policy、work source=-1、'SYST'，然后长度字段是字符数、结尾单另一个 0）。
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

    /// 四种前缀都得认得出来，尤其是 2 个头那个（app_process 实测就是这个，
    /// 少了它 App 侧的 SOTER 流量一条都认不出来）。
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

    /// 真机上的 alias 正好是 34 个字符（偶数长度），后面紧跟 challenge。之前少算 4 字节
    /// 补齐，读出来的 challenge 是空串 —— 这条专门盯住那个坑。
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

    #[test]
    fn reserved_codes_are_not_ours() {
        let data = request(&|_out| {});
        assert!(parse(&data, 2).is_none(), "code 2 is a hole in this HAL");
        assert!(parse(&data, 6).is_none(), "code 6 is a hole in this HAL");
        assert!(parse(&data, 14).is_none(), "code 14 is a hole in this HAL");
        assert!(parse(&data, 99).is_none());
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
        // 宿主 dex 里 HIDL 那套代理类（`...@1.0::ISoter@Proxy`）也在，描述符跟 AIDL 不是
        // 同一条。现在照样拦 —— 答复换成 HIDL 的布局（`build_hidl_*`），不再只观察。
        // hasAuthKey 在 HIDL 线上是声明顺序的第 12 个，AIDL 那边是 10。
        for descriptor in [QTI_HIDL_DESCRIPTOR, TRUSTONIC_HIDL_DESCRIPTOR] {
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

        let (bytes, reply) = build_br_reply(&call).expect("the local backend answers getDeviceId");
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
        // 本地后端写了实现的 11 个号码全部拦下来自己回。
        for code in [1u32, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13] {
            let data = token_with_header(3, &|out| {
                push_i32(out, 10373);
                push_string(out, "SoterAuthKey");
                push_string(out, "0102030405");
            });
            let call = parse(&data, code).unwrap_or_else(|| panic!("code {code} must parse"));
            assert!(interceptable(&call), "code {code} must be intercepted");
        }

        // 2 / 6 / 14 是宿主那半边不发、我们也不认的空号
        for code in [2u32, 6, 14] {
            assert!(parse(&request(&|_out| {}), code).is_none());
        }
    }

    #[test]
    fn every_answer_shape_frames_a_reply_the_host_can_read() {
        // 三种形状各来一笔：Buffer 带数据（ASK / 设备号）、Buffer 空 out（钥匙不在
        // 本机）、Init（会话）。形状错了宿主解出来的是垃圾，所以这里按帧解一遍。
        let cases: [(u32, Vec<u8>); 4] = [
            (1, request(&|out| push_i32(out, 10373))),
            (
                3,
                request(&|out| {
                    push_i32(out, 10373);
                    push_string(out, "SoterAuthKey");
                }),
            ),
            (8, request(&|_out| {})),
            (
                11,
                request(&|out| {
                    push_i32(out, 10373);
                    push_string(out, "SoterAuthKey");
                    push_string(out, "0102030405");
                }),
            ),
        ];
        for (code, data) in cases {
            let call = parse(&data, code).expect("a known hal code");
            let (bytes, reply) = build_br_reply(&call)
                .unwrap_or_else(|| panic!("the local backend must answer code {code}"));
            assert_eq!(&bytes[..4], &BR_TRANSACTION_COMPLETE_CMD.to_ne_bytes());
            assert_eq!(&bytes[4..8], &BR_REPLY_CMD.to_ne_bytes());
            let tr = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().add(8) as *const binder_transaction_data)
            };
            assert_eq!(tr.data_size, reply.data_size());
            assert_ne!(tr.data_size, 0, "code {code} answers with a payload");
            assert_eq!(tr.flags & TF_STATUS_CODE, 0);
            assert_eq!(tr.offsets_size, 0);
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

    /// 一个 `binder_buffer_object`：`{hdr{type}, flags, buffer, length, parent, parent_offset}`，
    /// 后面四格宽度跟 ABI 走。
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
    ///
    /// `keep` 是那些外面那块内存的持有者 —— 对象里写的是它们的地址，解析的时候真去 deref，
    /// 所以调用方得让它们活到 parse 完。
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

    /// hwbinder 的接口 token：没有 strict-mode 那几个 i32 头，开头就是一个 String16。
    fn hidl_token(descriptor: &str) -> Vec<u8> {
        let mut out = Vec::new();
        push_string(&mut out, descriptor);
        out
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
    fn hidl_provisioning_codes_stay_unrecognised() {
        // 1/2/3（generateAttkKeyPair / verifyAttkKeyPair / exportAttkPublicKey）换算过去是
        // AIDL 的 6/14/2 —— 运行时没有那三个号，所以跟 AIDL 那半边一样认不出来。
        for code in [1u32, 2, 3] {
            let data = hidl_token(QTI_HIDL_DESCRIPTOR);
            assert!(parse(&data, code).is_none(), "HIDL {code} 不该认");
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

        let (bytes, reply) = build_br_reply(&call).expect("the local backend answers it");
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
}
