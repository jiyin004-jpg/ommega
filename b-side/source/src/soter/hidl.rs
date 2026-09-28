//! HIDL 版 SOTER 客户端（`vendor.qti.hardware.soter@1.0::ISoter`）。
//!
//! AIDL 那两家（`vendor.trustonic.hardware.soter.ITrustonicSoter` /
//! `vendor.qti.hardware.soter.ISoter`）走的是 `/dev/binder`，见 [`super::hal`]。
//! 这一家跑在 `/dev/hwbinder` 上，事务号和参数形状跟 AIDL 那两套都不一样：
//!
//! ```text
//! HIDL  = `.hal` 里的声明顺序 1..14
//! AIDL  = 按方法名字母序排的 1..14
//! ```
//!
//! 两边对不上的地方很多（HIDL 4 = AIDL 8 的 getDeviceId、HIDL 6 = AIDL 1 的
//! exportAskPublicKey …），A 端那张 `HIDL_TO_INTERNAL_CODE` 表就是把这一对一关系
//! 抠出来的结果，这里按 HIDL 的号发即可，不用再换算。
//!
//! 跟 AIDL 另一个大差别是参数和返回值里的字符串 / vector：AIDL 是内联的
//! 「长度 + 字节」，HIDL 是 binder 的 buffer 对象，parcel 里只躺对象，数据体在
//! parcel 外面。这部分由 [`super::hwbinder::Parcel`] 负责。
//!
//! 服务发现也要多一步：HIDL 不认 `servicemanager`，得先问 `hwservicemanager`
//! （`/dev/hwbinder` 的 handle 0）要句柄。`IServiceManager::get(fqName, instance)`
//! 就在 1.0 里，事务号 1。

use anyhow::{bail, Context, Result};

use super::hal::{SoterData, SoterSession};
use super::hwbinder::{HwBinder, Parcel, Reply};
use super::hwbinder::{BINDER_TYPE_BINDER, BINDER_TYPE_HANDLE, BINDER_TYPE_WEAK_BINDER, BINDER_TYPE_WEAK_HANDLE};

/// HIDL 的服务全名。注意 instance 是单独一个参数，不在这个名字里。
pub const HIDL_QTI_FQNAME: &str = "vendor.qti.hardware.soter@1.0::ISoter";

/// Trustonic 那套的 HIDL 名字。跟 AIDL 那边一样是两家vendor各来一份，
/// 一台机器只注册其中一个（宿主 dex 里 `@1.0::ISoter@Proxy` 与
/// `@1.0::ITrustonicSoter@Proxy` 两个代理类都在，哪条通得看系统装的是哪种）。
pub const HIDL_TRUSTONIC_FQNAME: &str = "vendor.trustonic.hardware.soter@1.0::ITrustonicSoter";

/// 两家 HIDL 后端，按解析顺序（跟 AIDL 那份 [`super::hal::Backend::ALL`] 同序）。
pub const BACKENDS: [&str; 2] = [HIDL_TRUSTONIC_FQNAME, HIDL_QTI_FQNAME];

/// 默认实例名。设备上只注册这一个。
pub const HIDL_DEFAULT_INSTANCE: &str = "default";

/// 问服务句柄用的接口。`get` 在 1.0 就是两参数版本，后来几个版本没改过签名。
pub const HW_SERVICE_MANAGER_DESCRIPTOR: &str = "android.hidl.manager@1.0::IServiceManager";

/// `IServiceManager::get(fqName, instance)` 的事务号。
const TX_ISERVICEMANAGER_GET: u32 = 1;

/// `hwservicemanager` 固定占着 hwbinder 的 0 号句柄（它就是 context manager）。
const HWSERVICEMANAGER_HANDLE: u32 = 0;

// HIDL 的事务号 = `.hal` 里的声明顺序。别按名字重排，也别跟 AIDL 那套混。
const TX_GENERATE_ATTK_KEY_PAIR: u32 = 1;
const TX_VERIFY_ATTK_KEY_PAIR: u32 = 2;
const TX_EXPORT_ATTK_PUBLIC_KEY: u32 = 3;
const TX_GET_DEVICE_ID: u32 = 4;
const TX_GENERATE_ASK_KEY_PAIR: u32 = 5;
const TX_EXPORT_ASK_PUBLIC_KEY: u32 = 6;
const TX_REMOVE_ALL_UID_KEY: u32 = 7;
const TX_HAS_ASK_ALREADY: u32 = 8;
const TX_GENERATE_AUTH_KEY_PAIR: u32 = 9;
const TX_EXPORT_AUTH_KEY_PUBLIC_KEY: u32 = 10;
const TX_REMOVE_AUTH_KEY: u32 = 11;
const TX_HAS_AUTH_KEY: u32 = 12;
const TX_INIT_SIGN: u32 = 13;
const TX_FINISH_SIGN: u32 = 14;

/// 16 字节的 HIDL 头结构体。
const HIDL_STRUCT_SIZE: usize = 16;

/// 一个活的 HIDL SOTER 代理。
pub struct HidlSoter {
    conn: HwBinder,
    handle: u32,
    descriptor: &'static str,
}

impl HidlSoter {
    /// 顺着 `hwservicemanager` 把服务找出来，两家vendor依次试。
    ///
    /// `Ok(None)` 是「这台机器上两家都没注册」；「有 /dev/hwbinder 但没这家服务」
    /// 也归到 `Ok(None)`（跟 AIDL 那边的语义对齐）。
    pub fn open() -> Result<Option<Self>> {
        for fq_name in BACKENDS {
            if let Some(soter) = Self::open_named(fq_name, HIDL_DEFAULT_INSTANCE, fq_name)? {
                return Ok(Some(soter));
            }
        }
        Ok(None)
    }

    /// 指定 fqName / instance / 之后用来写 interface token 的描述符。
    pub fn open_named(fq_name: &str, instance: &str, descriptor: &'static str) -> Result<Option<Self>> {
        // 没有 /dev/hwbinder 就是这台设备根本不跑 HIDL，直接说没有。
        let conn = match HwBinder::open() {
            Ok(conn) => conn,
            Err(e) => {
                if !std::path::Path::new("/dev/hwbinder").exists() {
                    return Ok(None);
                }
                return Err(e);
            }
        };
        let handle = fetch_service_handle(&conn, fq_name, instance)?;
        match handle {
            Some(handle) => Ok(Some(Self {
                conn,
                handle,
                descriptor,
            })),
            None => Ok(None),
        }
    }

    pub fn descriptor(&self) -> &'static str {
        self.descriptor
    }

    /// SOTER 的 HIDL 版本。名字里写死了 `@1.0`，所以这里不用发事务去问 ——
    /// 真去问的话那个 `getInterfaceVersion` 属于 `IBase`，还得换一次 interface
    /// token，为个常量不值当。
    pub fn interface_version(&self) -> i32 {
        1
    }

    /// 拿到的服务句柄。
    ///
    /// **只能在 `self` 自己的连接上使**（见 [`Self::call_on_own_connection`]）。
    /// 句柄号是 per-`binder_proc` 的：每开一次 `/dev/hwbinder` 就是内核里一个新
    /// proc，换条连接这个号就作废，内核会回 `BR_FAILED_REPLY`。
    pub fn handle(&self) -> u32 {
        self.handle
    }

    /// 用本代理自己的连接和句柄发一笔别的事务（探针拿它问 `IBase::ping`）。
    ///
    /// 这个入口存在的意义就是不给「把句柄借到别的连接上发」留口子：内核按
    /// 发送方 proc 的 refs 表翻句柄，句柄只有在收到它的那条连接上才算数。
    pub fn call_on_own_connection(&self, descriptor: &str, code: u32) -> Result<Reply> {
        let mut parcel = Parcel::new();
        parcel.write_interface_token(descriptor);
        self.conn.transact(self.handle, code, &parcel)
    }

    /// 发一笔先把 interface token 写好的事务。
    ///
    /// `pub` 是为了让探针能拿同一个连接去问别的接口（比如 `IBase::ping`）——
    /// 服务端能不能认、句柄是不是真的活的，就看这一下了。
    pub fn call(&self, code: u32, fill: impl FnOnce(&mut Parcel)) -> Result<Reply> {
        let mut parcel = Parcel::new();
        parcel.write_interface_token(self.descriptor);
        fill(&mut parcel);
        self.conn.transact(self.handle, code, &parcel)
    }

    pub fn get_device_id(&self) -> Result<SoterData> {
        let reply = self.call(TX_GET_DEVICE_ID, |_| {})?;
        decode_data(&self.conn, &reply)
    }

    pub fn export_attk_public_key(&self) -> Result<SoterData> {
        let reply = self.call(TX_EXPORT_ATTK_PUBLIC_KEY, |_| {})?;
        decode_data(&self.conn, &reply)
    }

    pub fn export_ask_public_key(&self, uid: i32) -> Result<SoterData> {
        let reply = self.call(TX_EXPORT_ASK_PUBLIC_KEY, |p| {
            p.write_u32(uid as u32);
        })?;
        decode_data(&self.conn, &reply)
    }

    pub fn export_auth_key_public_key(&self, uid: i32, alias: &str) -> Result<SoterData> {
        let reply = self.call(TX_EXPORT_AUTH_KEY_PUBLIC_KEY, |p| {
            p.write_u32(uid as u32);
            p.write_hidl_string(alias);
        })?;
        decode_data(&self.conn, &reply)
    }

    pub fn finish_sign(&self, session: i64) -> Result<SoterData> {
        let reply = self.call(TX_FINISH_SIGN, |p| {
            p.write_u64(session as u64);
        })?;
        decode_data(&self.conn, &reply)
    }

    pub fn init_sign(&self, uid: i32, alias: &str, challenge: &str) -> Result<SoterSession> {
        let reply = self.call(TX_INIT_SIGN, |p| {
            p.write_u32(uid as u32);
            p.write_hidl_string(alias);
            p.write_hidl_string(challenge);
        })?;
        let mut cur = Cursor::new(&reply);
        cur.status()?;
        let error_code = cur.i32()?;
        let session = cur.u64()? as i64;
        Ok(SoterSession {
            error_code,
            session,
        })
    }

    pub fn verify_attk_key_pair(&self) -> Result<i32> {
        let reply = self.call(TX_VERIFY_ATTK_KEY_PAIR, |_| {})?;
        decode_code(&reply)
    }

    pub fn has_ask_already(&self, uid: i32) -> Result<i32> {
        let reply = self.call(TX_HAS_ASK_ALREADY, |p| {
            p.write_u32(uid as u32);
        })?;
        decode_code(&reply)
    }

    pub fn has_auth_key(&self, uid: i32, alias: &str) -> Result<i32> {
        let reply = self.call(TX_HAS_AUTH_KEY, |p| {
            p.write_u32(uid as u32);
            p.write_hidl_string(alias);
        })?;
        decode_code(&reply)
    }

    pub fn generate_ask_key_pair(&self, uid: i32) -> Result<i32> {
        let reply = self.call(TX_GENERATE_ASK_KEY_PAIR, |p| {
            p.write_u32(uid as u32);
        })?;
        decode_code(&reply)
    }

    /// `uint8_t copyNum`。HIDL 的 `writeUint8` 就是 1 个字节，不补对齐。
    pub fn generate_attk_key_pair(&self, copy_num: i8) -> Result<i32> {
        let reply = self.call(TX_GENERATE_ATTK_KEY_PAIR, |p| {
            p.write_bytes(&(copy_num as u8).to_le_bytes());
        })?;
        decode_code(&reply)
    }

    pub fn generate_auth_key_pair(&self, uid: i32, alias: &str) -> Result<i32> {
        let reply = self.call(TX_GENERATE_AUTH_KEY_PAIR, |p| {
            p.write_u32(uid as u32);
            p.write_hidl_string(alias);
        })?;
        decode_code(&reply)
    }

    pub fn remove_all_uid_key(&self, uid: i32) -> Result<i32> {
        let reply = self.call(TX_REMOVE_ALL_UID_KEY, |p| {
            p.write_u32(uid as u32);
        })?;
        decode_code(&reply)
    }

    pub fn remove_auth_key(&self, uid: i32, alias: &str) -> Result<i32> {
        let reply = self.call(TX_REMOVE_AUTH_KEY, |p| {
            p.write_u32(uid as u32);
            p.write_hidl_string(alias);
        })?;
        decode_code(&reply)
    }
}

/// 用 `IServiceManager::get(fqName, instance)` 把服务句柄要过来。
///
/// 返回 `Ok(None)` 表示 hwservicemanager 认得这个名字但没登记（服务不在）；
/// 名字里的包/接口根本不存在时它也是给个空 binder，两种都算「没有」。
fn fetch_service_handle(conn: &HwBinder, fq_name: &str, instance: &str) -> Result<Option<u32>> {
    let mut parcel = Parcel::new();
    parcel.write_interface_token(HW_SERVICE_MANAGER_DESCRIPTOR);
    parcel.write_hidl_string(fq_name);
    parcel.write_hidl_string(instance);

    let reply = conn
        .transact(HWSERVICEMANAGER_HANDLE, TX_ISERVICEMANAGER_GET, &parcel)
        .with_context(|| format!("IServiceManager::get({fq_name}, {instance})"))?;

    let mut cur = Cursor::new(&reply);
    cur.status()?;
    // 回包是一个 `interface service`，HIDL 那边就是个 hidl_binder。
    cur.binder_handle()
}

/// 解析应答的游标。所有方法都是「先一个 Status，再方法自己的字段」。
struct Cursor<'a> {
    reply: &'a Reply,
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(reply: &'a Reply) -> Self {
        Self { reply, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .context("reply cursor overflow")?;
        if end > self.reply.data.len() {
            bail!(
                "reply truncated: want {n} bytes at {}, only {} available",
                self.at,
                self.reply.data.len()
            );
        }
        let slice = &self.reply.data[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(b);
        Ok(u64::from_le_bytes(raw))
    }

    fn abi_usize(&mut self) -> Result<usize> {
        if std::mem::size_of::<usize>() == 8 {
            Ok(self.u64()? as usize)
        } else {
            Ok(self.u32()? as usize)
        }
    }

    /// HIDL 里 `hardware::Status` 是个 i32：0 就是没事。
    ///
    /// 非 0 时后面还跟一条 String16 的 message，但那条路我们从来不期待走到 —— 真走到了
    /// 说明 HAL 自己崩了，报个带 code 的错就够，别再去解那条消息。
    fn status(&mut self) -> Result<()> {
        let code = self.i32()?;
        if code != 0 {
            bail!("HIDL reply carried a non-OK Status ({code})");
        }
        Ok(())
    }

    /// 一个 `binder_buffer_object`，只取我们关心的三格。
    fn buffer_object(&mut self) -> Result<(u32, usize, usize)> {
        let ty = self.u32()?;
        let _flags = self.u32()?;
        let buffer = self.abi_usize()?;
        let length = self.abi_usize()?;
        let _parent = self.abi_usize()?;
        let _parent_offset = self.abi_usize()?;
        Ok((ty, buffer, length))
    }

    /// 读 `hidl_vec<uint8_t>` 的 out 参数：两个对象，第一个指向 16 字节的头结构体
    /// （里面第一格是元素地址、第二格是元素个数），第二个指向元素本身。
    ///
    /// 返回元素字节。空 vector 在 parcel 里就是 A 指向头、B 的 buffer 为 0。
    fn hidl_vec_u8(&mut self, conn: &HwBinder) -> Result<Vec<u8>> {
        let (_ty_a, head_addr, head_len) = self.buffer_object()?;
        if head_len != HIDL_STRUCT_SIZE {
            bail!(
                "hidl_vec header object claims {} bytes, expected {}",
                head_len,
                HIDL_STRUCT_SIZE
            );
        }
        let (_ty_b, elems_addr, elems_len) = self.buffer_object()?;

        // 头结构体里第一格是指针、第二格是 size。元素地址要跟第二个对象对得上，
        // 对不上就是我们把对象顺序读反了，宁可报错也不猜。
        let head = conn
            .read_mapped(head_addr, HIDL_STRUCT_SIZE)
            .context("hidl_vec header is outside our binder mapping")?;
        let mut ptr_raw = [0u8; 8];
        ptr_raw.copy_from_slice(&head[0..8]);
        let head_ptr = u64::from_le_bytes(ptr_raw) as usize;
        let mut size_raw = [0u8; 4];
        size_raw.copy_from_slice(&head[8..12]);
        let head_size = u32::from_le_bytes(size_raw) as usize;

        if head_size == 0 && elems_addr == 0 {
            return Ok(Vec::new());
        }
        if head_ptr != elems_addr {
            bail!(
                "hidl_vec header points at {head_ptr:#x} but the element object says {elems_addr:#x}"
            );
        }
        if head_size != elems_len {
            bail!(
                "hidl_vec header says {head_size} elements but the element object says {elems_len}"
            );
        }
        conn.read_mapped(elems_addr, elems_len)
            .context("hidl_vec elements are outside our binder mapping")
    }

    /// `interface T` 在 parcel 里是一个 `hidl_binder`：非 null 就是 `flat_binder_object`，
    /// null 就是单个 i32 的 0。返回句柄（`BINDER_TYPE_HANDLE` 那格，远程对象的情形）。
    fn binder_handle(&mut self) -> Result<Option<u32>> {
        let object_at = self.at;

        // 内核把应答里每个对象的字节位置记在偏移表里。有表就得对得上：对不上说明
        // 「Status 之后紧跟对象」这个假设在这条回包上不成立，硬读出来的只可能是别的
        // 字段里的一串字节。拿它当句柄使，下一笔事务就是 `BR_FAILED_REPLY`（内核：
        // 这个 proc 里没有这个 ref）。所以宁可报错，也不交出一个来路不明的句柄。
        if !self.reply.offsets.is_empty() && !self.reply.offsets.contains(&(object_at as u64)) {
            bail!(
                "reply object at {object_at} is outside the kernel's offset table {:?}",
                self.reply.offsets
            );
        }

        // 先判 null 的情形：parcel 里只有 4 个字节的 0。
        let mark = self.u32()?;
        if mark == 0 {
            return Ok(None);
        }
        if object_at + 24 > self.reply.data.len() {
            bail!(
                "truncated reply binder object at {object_at}: only {} bytes left",
                self.reply.data.len() - object_at
            );
        }
        // 非 null：这一格其实是 `flat_binder_object` 的 type，接着是 flags，再往后
        // 是 `binder` / `handle` 那格和 cookie。本地对象和远程句柄都接受 —— 服务
        // 可能就在自己进程里（passthrough / 同进程 HAL）。
        if !matches!(
            mark,
            BINDER_TYPE_HANDLE | BINDER_TYPE_BINDER | BINDER_TYPE_WEAK_HANDLE | BINDER_TYPE_WEAK_BINDER
        ) {
            bail!("unexpected binder object type {mark:#x} in an interface reply");
        }
        let _flags = self.u32()?;
        // `union { binder_uintptr_t binder; __u32 handle; }` —— uapi 里 HANDLE 那格
        // 就是 `__u32`，后面 4 个字节按 ABI 属于 union 的另一半（实际是 `cookie` 的
        // 头半截）。读 8 字节再截断只在对方把 cookie 后半填成 0 时才碰巧对，读 4 字节
        // 才是照着结构来。
        let handle = self.u32()?;
        let _union_upper = self.u32()?;
        let _cookie = self.u64()?;
        if handle == 0 {
            return Ok(None);
        }
        Ok(Some(handle))
    }
}

/// `generates (SoterErrorCode error, vec<uint8_t> data, soter_size_t length)` 的应答。
fn decode_data(conn: &HwBinder, reply: &Reply) -> Result<SoterData> {
    let mut cur = Cursor::new(reply);
    cur.status()?;
    let error_code = cur.i32()?;
    let data = cur.hidl_vec_u8(conn)?;
    let length = cur.u32()? as i32;
    Ok(SoterData {
        error_code,
        data,
        length,
    })
}

/// `generates (SoterErrorCode error)` 的应答。
fn decode_code(reply: &Reply) -> Result<i32> {
    let mut cur = Cursor::new(reply);
    cur.status()?;
    cur.i32()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soter::hwbinder::Parcel;

    /// 造一个「空 vec」的应答体：A 指向 16 字节头（元素指针 0、个数 0），B 是空对象。
    fn empty_vec_reply(error: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0i32.to_le_bytes()); // Status
        out.extend_from_slice(&error.to_le_bytes());
        push_buffer_object(&mut out, 0x1000, 16, 0, 0);
        push_buffer_object(&mut out, 0, 0, 0, 0);
        out.extend_from_slice(&0u32.to_le_bytes()); // length
        out
    }

    /// 造一个 `flat_binder_object`：`type / flags / union(8) / cookie(8)`，共 24 字节。
    fn push_binder_object(out: &mut Vec<u8>, handle: u32, ty: u32) {
        out.extend_from_slice(&ty.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&handle.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
    }

    fn push_buffer_object(out: &mut Vec<u8>, buffer: u64, length: u64, flags: u32, parent: u64) {
        out.extend_from_slice(&0x7074_2A85u32.to_le_bytes()); // BINDER_TYPE_PTR
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&buffer.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&parent.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // parent_offset
    }

    #[test]
    fn transaction_numbers_say_hello_before_signing() {
        // `.hal` 里的声明顺序，跟 AIDL 那套完全不是一个排列。
        assert_eq!(TX_GENERATE_ATTK_KEY_PAIR, 1);
        assert_eq!(TX_GET_DEVICE_ID, 4);
        assert_eq!(TX_EXPORT_ASK_PUBLIC_KEY, 6);
        assert_eq!(TX_INIT_SIGN, 13);
        assert_eq!(TX_FINISH_SIGN, 14);
    }

    #[test]
    fn interface_token_is_a_plain_c_string_padded_to_four() {
        let mut p = Parcel::new();
        p.write_interface_token(HIDL_QTI_FQNAME);
        // 37 个字符 + NUL = 38，再补 2 个零到 4 字节边界。
        assert_eq!(p.data().len(), 40);
        assert_eq!(&p.data()[37..], &[0u8, 0, 0], "NUL 加两个补位");
    }

    #[test]
    fn a_string_argument_costs_two_buffer_objects() {
        let mut p = Parcel::new();
        p.write_interface_token(HIDL_QTI_FQNAME);
        let before = p.data().len();
        p.write_hidl_string("SoterAuthKey");
        assert_eq!(p.data().len() - before, 80, "two 40-byte objects");
        assert_eq!(p.offsets().len(), 2);
    }

    #[test]
    fn the_string_objects_chain_to_each_other() {
        let mut p = Parcel::new();
        p.write_hidl_string("abc");
        let data = p.data();
        // 第一个对象：type=PTR、指向 16 字节头、没有 HAS_PARENT。
        assert_eq!(&data[0..4], &0x7074_2A85u32.to_le_bytes());
        assert_eq!(&data[4..8], &0u32.to_le_bytes(), "root has no parent flag");
        assert_eq!(&data[16..24], &16u64.to_le_bytes(), "header is 16 bytes");
        // 第二个对象：带 HAS_PARENT，parent 指回第一个对象在偏移表里的下标 0。
        let second = 40;
        assert_eq!(&data[second..second + 4], &0x7074_2A85u32.to_le_bytes());
        assert_eq!(
            &data[second + 4..second + 8],
            &1u32.to_le_bytes(),
            "HAS_PARENT"
        );
        assert_eq!(&data[second + 16..second + 24], &4u64.to_le_bytes(), "abc + NUL");
        assert_eq!(&data[second + 24..second + 32], &0u64.to_le_bytes(), "parent index");
        assert_eq!(p.offsets(), &[0u64, 40u64]);
    }

    #[test]
    fn the_header_points_at_the_characters() {
        let mut p = Parcel::new();
        p.write_hidl_string("hello");
        // keep[0] 是字符块、keep[1] 是那个 16 字节头；头里第一格要指着字符块。
        let chars_addr = p.keep()[0].as_ptr() as usize;
        assert_eq!(&p.keep()[0][..], b"hello\0");
        let head = p.keep()[1].to_vec();
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&head[0..8]);
        assert_eq!(u64::from_le_bytes(raw) as usize, chars_addr);
        let mut size_raw = [0u8; 4];
        size_raw.copy_from_slice(&head[8..12]);
        assert_eq!(u32::from_le_bytes(size_raw), 5, "mSize is the string length, not +1");
    }

    #[test]
    fn an_empty_vector_registers_one_object_and_one_placeholder() {
        let mut p = Parcel::new();
        p.write_hidl_vec_u8(&[]);
        assert_eq!(p.data().len(), 80, "header object + a null one");
        assert_eq!(p.offsets().len(), 1, "a null buffer is not registered");
        let data = p.data();
        assert_eq!(&data[40..44], &0x7074_2A85u32.to_le_bytes());
        assert_eq!(&data[44..48], &0u32.to_le_bytes(), "the placeholder has no flags");
        assert_eq!(&data[48..56], &0u64.to_le_bytes(), "and no buffer");
    }

    #[test]
    fn a_populated_vector_carries_the_elements() {
        let mut p = Parcel::new();
        p.write_hidl_vec_u8(&[1, 2, 3]);
        assert_eq!(p.offsets().len(), 2);
        let data = p.data();
        assert_eq!(&data[56..64], &3u64.to_le_bytes(), "three elements");
        assert_eq!(&p.keep()[0][..], &[1u8, 2, 3]);
    }

    #[test]
    fn status_must_be_zero() {
        let reply = Reply {
            data: 1i32.to_le_bytes().to_vec(),
            offsets: Vec::new(),
        };
        let mut cur = Cursor::new(&reply);
        assert!(cur.status().is_err(), "a non-zero Status is a failure");
    }

    #[test]
    fn a_truncated_reply_is_an_error_not_a_panic() {
        let reply = Reply {
            data: vec![],
            offsets: Vec::new(),
        };
        let mut cur = Cursor::new(&reply);
        assert!(cur.status().is_err());
        assert!(cur.i32().is_err());
        assert!(cur.u64().is_err());
    }

    #[test]
    fn code_reply_carries_the_error_code_after_status() {
        let reply = Reply {
            data: {
                let mut v = 0i32.to_le_bytes().to_vec();
                v.extend_from_slice(&(-5i32).to_le_bytes());
                v
            },
            offsets: Vec::new(),
        };
        assert_eq!(decode_code(&reply).unwrap(), -5);
    }

    #[test]
    fn a_data_reply_parses_down_to_the_length_field() {
        // 头结构体指向的地址不在映射里，所以只验到「对象和长度都读对了」为止 ——
        // 再往后一步就是读 mmap，真机才有。
        let reply = Reply {
            data: empty_vec_reply(0),
            offsets: Vec::new(),
        };
        let mut cur = Cursor::new(&reply);
        assert!(cur.status().is_ok());
        assert_eq!(cur.i32().unwrap(), 0);
        let (ty, buffer, length) = cur.buffer_object().unwrap();
        assert_eq!(ty, 0x7074_2A85);
        assert_eq!(buffer, 0x1000);
        assert_eq!(length, 16);
        let (_ty, buffer, length) = cur.buffer_object().unwrap();
        assert_eq!(buffer, 0, "an empty vector has a null element object");
        assert_eq!(length, 0);
        assert_eq!(cur.u32().unwrap(), 0);
    }

    #[test]
    fn a_handle_object_yields_the_uapi_u32_descriptor() {
        let mut data = 0i32.to_le_bytes().to_vec(); // Status
        push_binder_object(&mut data, 7, BINDER_TYPE_HANDLE);
        let reply = Reply {
            data,
            offsets: vec![4],
        };
        let mut cur = Cursor::new(&reply);
        assert!(cur.status().is_ok());
        assert_eq!(cur.binder_handle().unwrap(), Some(7));
    }

    #[test]
    fn an_object_off_the_kernel_offset_table_is_refused() {
        // 假如回包在 Status 和对象之间还有一格（内核的偏移表会说对象在 8），我们按
        // `[Status][object]` 算出来的 4 就对不上表 —— 硬读出来的那串字节不是句柄。
        let mut data = 0i32.to_le_bytes().to_vec();
        data.extend_from_slice(&7i32.to_le_bytes());
        push_binder_object(&mut data, 1, BINDER_TYPE_HANDLE);
        let reply = Reply {
            data,
            offsets: vec![8],
        };
        let mut cur = Cursor::new(&reply);
        assert!(cur.status().is_ok());
        let err = cur.binder_handle().unwrap_err().to_string();
        assert!(err.contains("offset table"), "{err}");
    }

    #[test]
    fn a_truncated_binder_object_is_an_error_not_a_panic() {
        // Status 后面只剩半截对象。
        let mut data = 0i32.to_le_bytes().to_vec();
        data.extend_from_slice(&BINDER_TYPE_HANDLE.to_le_bytes());
        let reply = Reply {
            data,
            offsets: vec![4],
        };
        let mut cur = Cursor::new(&reply);
        assert!(cur.status().is_ok());
        assert!(cur.binder_handle().is_err());
    }

    #[test]
    fn a_null_interface_is_a_single_zero_word() {
        let reply = Reply {
            data: {
                let mut v = 0i32.to_le_bytes().to_vec();
                v.extend_from_slice(&0u32.to_le_bytes());
                v
            },
            offsets: Vec::new(),
        };
        let mut cur = Cursor::new(&reply);
        assert!(cur.status().is_ok());
        let handle = cur.binder_handle().unwrap();
        assert!(handle.is_none());
    }
}
