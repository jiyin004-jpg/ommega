//! 最小可用的 hwbinder 客户端传输层。
//!
//! HIDL 的 HAL 走 `/dev/hwbinder`，它跟 `/dev/binder` 是同一个内核驱动、同一套
//! ioctl 协议（`BINDER_WRITE_READ` + `BC_TRANSACTION` + `binder_transaction_data`），
//! 所以这里不重造协议，只把三处真不一样的地方补上：
//!
//! 1. 设备节点换成 `/dev/hwbinder`；
//! 2. interface token 是裸的 C 字符串（`Parcel::writeInterfaceToken` 在 libhwbinder
//!    里就是 `writeCString`），不是普通 binder 那种「先 i32 字符数、再 UTF-16」；
//! 3. 字符串和 vector 走 `binder_buffer_object`（`BINDER_TYPE_PTR`）：parcel 里只躺
//!    对象，真正的数据结构在 parcel 外面，靠对象里写的地址去读，内核负责翻译。
//!
//! 为什么不用 rsbinder：它能换驱动路径，但 `Parcel` 只实现了 `flat_binder_object`，
//! 没有 `BINDER_TYPE_PTR` 的写入口，而 HIDL 传字符串和 vec 绕不开它。
//!
//! 这个模块只做「一个进程里的一次同步调用」，不建线程池、不收异步事务：relay 是
//! 一问一答的客户端，够用就行。

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};

// ---------------------------------------------------------------------------
// 内核 uapi 那一套（只抄这个模块用得到的）。
// ---------------------------------------------------------------------------

/// `binder_size_t` / `binder_uintptr_t` 在 64 位下都是 8 字节。
type BinderSize = u64;

const BINDER_CURRENT_PROTOCOL_VERSION: i32 = 8;

const BINDER_WRITE_READ: u64 = 0xC030_6201; // _IOWR('b', 1, struct binder_write_read) —— 48 字节
const BINDER_VERSION: u64 = 0xC004_6209; // _IOWR('b', 9, struct binder_version) —— 4 字节

/// 命令号本身只占低 8 位能表示的范围，但内核的 `_IO` 宏会给它套上方向位和类型位，
/// 所以这里换算回来时得先砍掉高位再比。`_IOC_NRMASK` / `_IOC_TYPEMASK` 都是 0xff。
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_NRMASK: u32 = (1 << IOC_NRBITS) - 1;
const IOC_TYPEMASK: u32 = (1 << IOC_TYPEBITS) - 1;

const fn cmd_nr(cmd: u32) -> u32 {
    (cmd >> IOC_NRSHIFT) & IOC_NRMASK
}

/// 命令的类型字符（`'c'` / `'r'`），用来确认这条命令确实是 binder 的。
const fn cmd_type(cmd: u32) -> u32 {
    (cmd >> IOC_TYPESHIFT) & IOC_TYPEMASK
}

// 命令号按内核 uapi 的 `_IOC(dir, type, nr, size)` 展开。方向位要跟宏里写的一致：
// 大多数 BR_ 用的是 `_IO`（dir=0），但 `BR_INCREFS` 那一族是 `_IOW`、`BR_TRANSACTION`
// 那一族是 `_IOR` —— 弄反了数值就不同，匹配会落空。
//
// 顺带说一句：真正必需的是低 8 位的命令号，方向位和 size 位只在内核那边校验，我们
// 拿来匹配时其实只看 nr。但既然要对齐 uapi 就对齐得完整些，将来别人对着头文件核对
// 也一目了然。
const fn io_noarg(dir: u32, ty: u8, nr: u32) -> u32 {
    (dir << 30) | ((ty as u32) << IOC_TYPESHIFT) | nr
}
const fn io_arg(dir: u32, ty: u8, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | ((ty as u32) << IOC_TYPESHIFT) | nr
}

const _IOC_NONE: u32 = 0;
const _IOC_WRITE: u32 = 1;
const _IOC_READ: u32 = 2;

pub const BC_TRANSACTION: u32 = io_arg(_IOC_WRITE, b'c', 0, 64);

/// `BC_TRANSACTION_SG`：跟 [`BC_TRANSACTION`] 同一件事，但在 `binder_transaction_data`
/// 后面多带一个 `buffers_size`，告诉内核给 buffer 对象的数据体留多少地方。
///
/// 带 buffer 对象（HIDL 的 string 和 vector）的事务必须走这个，走 `BC_TRANSACTION`
/// 的话内核拿 `extra_buffers_size = 0`，直接判成 "too large buffer"。
/// 结构是 `_IOW('c', 1, struct binder_transaction_data_sg)`，64 + 8 = 72 字节。
pub const BC_TRANSACTION_SG: u32 = io_arg(_IOC_WRITE, b'c', 17, 72);

pub const BC_FREE_BUFFER: u32 = io_arg(_IOC_WRITE, b'c', 3, __SIZEOF_BINDER_UINTPTR);
const BC_ENTER_LOOPER: u32 = io_noarg(_IOC_WRITE, b'c', 12);
const BC_EXIT_LOOPER: u32 = io_noarg(_IOC_WRITE, b'c', 13);

const BR_ERROR: u32 = io_arg(_IOC_READ, b'r', 0, 4);
const BR_OK: u32 = io_noarg(_IOC_NONE, b'r', 1);
const BR_TRANSACTION: u32 = io_arg(_IOC_READ, b'r', 2, 64);
const BR_REPLY: u32 = io_arg(_IOC_READ, b'r', 3, 64);
const BR_ACQUIRE_RESULT: u32 = io_arg(_IOC_READ, b'r', 4, 4);
const BR_DEAD_REPLY: u32 = io_noarg(_IOC_NONE, b'r', 5);
const BR_TRANSACTION_COMPLETE: u32 = io_noarg(_IOC_NONE, b'r', 6);
const BR_INCREFS: u32 = io_arg(_IOC_READ, b'r', 7, 16);
const BR_ACQUIRE: u32 = io_arg(_IOC_READ, b'r', 8, 16);
const BR_RELEASE: u32 = io_arg(_IOC_READ, b'r', 9, 16);
const BR_DECREFS: u32 = io_arg(_IOC_READ, b'r', 10, 16);
const BR_ATTEMPT_ACQUIRE: u32 = io_arg(_IOC_READ, b'r', 11, 16);
const BR_NOOP: u32 = io_noarg(_IOC_NONE, b'r', 12);
const BR_SPAWN_LOOPER: u32 = io_noarg(_IOC_NONE, b'r', 13);
const BR_FINISHED: u32 = io_noarg(_IOC_NONE, b'r', 14);
const BR_DEAD_BINDER: u32 = io_arg(_IOC_READ, b'r', 15, 8);
const BR_CLEAR_DEATH_NOTIFICATION_DONE: u32 = io_arg(_IOC_READ, b'r', 16, 8);
const BR_FAILED_REPLY: u32 = io_noarg(_IOC_NONE, b'r', 17);
const BR_FROZEN_REPLY: u32 = io_noarg(_IOC_NONE, b'r', 18);
const BR_ONEWAY_SPAM_SUSPECT: u32 = io_noarg(_IOC_NONE, b'r', 19);
/// `BR_TRANSACTION_SEC_CTX` 跟 `BR_TRANSACTION` 共用事务号 2，靠大小区分（72 vs 64）。
const BR_TRANSACTION_SEC_CTX: u32 = io_arg(_IOC_READ, b'r', 2, 72);

/// `binder_uintptr_t` 的宽度（64 位）。
const __SIZEOF_BINDER_UINTPTR: u32 = 8;

/// `B_PACK_CHARS(c1, c2, c3, c4)` = `c1<<24 | c2<<16 | c3<<8 | c4`。
/// 四种对象类型的最后一个字符都是 `B_TYPE_LARGE` = 0x85，中间固定是 `'*'`。
const fn pack_chars(c1: u8, c2: u8, c3: u8, c4: u8) -> u32 {
    ((c1 as u32) << 24) | ((c2 as u32) << 16) | ((c3 as u32) << 8) | (c4 as u32)
}

pub const BINDER_TYPE_BINDER: u32 = pack_chars(b's', b'b', b'*', 0x85);
pub const BINDER_TYPE_WEAK_BINDER: u32 = pack_chars(b'w', b'b', b'*', 0x85);
pub const BINDER_TYPE_HANDLE: u32 = pack_chars(b's', b'h', b'*', 0x85);
pub const BINDER_TYPE_WEAK_HANDLE: u32 = pack_chars(b'w', b'h', b'*', 0x85);
pub const BINDER_TYPE_FD: u32 = pack_chars(b'f', b'd', b'*', 0x85);
pub const BINDER_TYPE_PTR: u32 = pack_chars(b'p', b't', b'*', 0x85);
pub const BINDER_BUFFER_FLAG_HAS_PARENT: u32 = 0x01;

/// 事务标志：只走本进程，且让内核读完把 buffer 清掉。
pub const TF_ONE_WAY: u32 = 0x01;
pub const TF_ACCEPT_FDS: u32 = 0x10;

/// HIDL 那副骨架（`hidl_pointer` + `uint32_t mSize` + `bool mOwnsBuffer` + 补位）
/// 固定 16 字节。指针槽两个 ABI 都是 8 字节（`hidl_pointer` 内部是
/// `union { T*; uint64_t; }`，AOSP 有 `static_assert(sizeof(*this) == 8)`），
/// 32 位进程只填低 4 字节、高位留 0，所以这个布局在两边一样。
pub const HIDL_STRUCT_SIZE: usize = 16;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct BinderWriteRead {
    write_size: BinderSize,
    write_consumed: BinderSize,
    write_buffer: BinderSize,
    read_size: BinderSize,
    read_consumed: BinderSize,
    read_buffer: BinderSize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct BinderVersion {
    protocol_version: i32,
}

/// `struct binder_transaction_data`。`target` 和 `data` 在内核里是 union，这里摊成
/// 结构体：union 里成员都是 8 字节对齐的，摊开后偏移不变（`target` 用 `ptr` 那格的
/// 宽度，发送时把 handle 填在低 4 字节）。
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct BinderTransactionData {
    /// union { __u32 handle; binder_uintptr_t ptr; } —— 发送时只填低 4 字节。
    target: u64,
    cookie: u64,
    code: u32,
    flags: u32,
    sender_pid: i32,
    sender_euid: u32,
    data_size: BinderSize,
    offsets_size: BinderSize,
    /// union { struct { buffer, offsets } ptr; __u8 buf[8]; }
    data_buffer: u64,
    data_offsets: u64,
}

/// 内核给的应答 parcel：数据在 mmap 区里，读完要把地址交回 `BC_FREE_BUFFER`。
#[derive(Debug, Clone)]
pub struct Reply {
    pub data: Vec<u8>,
    pub offsets: Vec<BinderSize>,
}

// ---------------------------------------------------------------------------
// Parcel 写入。
// ---------------------------------------------------------------------------

/// 一个只负责「攒字节 + 记偏移表」的 parcel。
///
/// 偏移表里记的是每个 `binder_object_*` 在 data 里的字节下标 —— 内核按这张表去认哪些
/// 位置是「对象」，好做地址翻译。写一个 buffer 对象就记一次。
///
/// `keep` 是保命用的：HIDL 的字符串和 vector 在 parcel 里只留地址，真正的字节得在
/// 别处活着，而且地址在 ioctl 返回前不能变。堆上分配的 `Box<[u8]>` 满足这两条，
/// 存在这里等 Parcel 自己 drop 的时候一起放。
#[derive(Default)]
pub struct Parcel {
    data: Vec<u8>,
    offsets: Vec<BinderSize>,
    keep: Vec<Box<[u8]>>,
}

impl Parcel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn offsets(&self) -> &[BinderSize] {
        &self.offsets
    }

    /// 挂着的那几块堆内存，测试要用它验回填的指针。
    pub fn keep(&self) -> &[Box<[u8]>] {
        &self.keep
    }

    /// 写一段字节，然后补到 4 字节边界。
    ///
    /// 补位不是可选项：内核 `binder_get_object` 里有一句 `!IS_ALIGNED(offset, sizeof(u32))`，
    /// 偏移表里的对象偏移只要不是 4 的倍数，整个事务就被当成非法。AOSP 的
    /// `Parcel::writeInplace` 每次写完都会 `pad_size(len)` 补零，就是为这个。
    fn write(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        while self.data.len() % 4 != 0 {
            self.data.push(0);
        }
    }

    pub fn write_i32(&mut self, value: i32) {
        self.write(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.write(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.write(&value.to_le_bytes());
    }

    /// `Parcel::writeInterfaceToken` 在 libhwbinder 里的实现就是 `writeCString` ——
    /// 名字当字符串写，带结尾的 NUL。别写成普通 binder 的 UTF-16 那套。
    ///
    /// NUL 跟字符一起写、一起补位，别分两次 —— 分两次会在中间先补一轮，长度就错了。
    pub fn write_interface_token(&mut self, interface: &str) {
        let mut buf = Vec::with_capacity(interface.len() + 1);
        buf.extend_from_slice(interface.as_bytes());
        buf.push(0);
        self.write(&buf);
    }

    /// 写一个裸字节串。`uint8_t` 这种单字节参数靠它，补位由 `write` 负责。
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.write(bytes);
    }

    /// 所有 buffer 对象的长度按 8 对齐求和。
    ///
    /// 这个数要跟命令一起交给内核（`BC_TRANSACTION_SG` 的 `buffers_size`），内核拿它
    /// 给 buffer 对象的数据体留地方；报少了就直接 "too large buffer"。
    /// AOSP 里对应 `Parcel::ipcBufferSize`。
    pub fn buffers_size(&self) -> usize {
        let mut total = 0usize;
        for &at in &self.offsets {
            let at = at as usize;
            // 偏移表里每条都指着 data 里的一个对象；只算 buffer 对象那几种。
            if at + 4 > self.data.len() {
                continue;
            }
            let ty = u32::from_le_bytes([
                self.data[at],
                self.data[at + 1],
                self.data[at + 2],
                self.data[at + 3],
            ]);
            if ty != BINDER_TYPE_PTR || at + 24 > self.data.len() {
                continue;
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&self.data[at + 16..at + 24]);
            total += (u64::from_le_bytes(raw) as usize + 7) & !7usize;
        }
        total
    }

    /// 把一段字节挂到一个新分配的堆块上，返回它的稳定地址。
    /// 地址会一直有效，直到整个 Parcel 被丢掉。
    fn lash(&mut self, bytes: Vec<u8>) -> usize {
        let block: Box<[u8]> = bytes.into_boxed_slice();
        let addr = block.as_ptr() as usize;
        self.keep.push(block);
        addr
    }

    /// 把 `n` 字节清零挂上去，同样返回稳定地址（用来放 `hidl_string` 那 16 字节头）。
    fn lash_zeroed(&mut self, n: usize) -> usize {
        self.lash(vec![0u8; n])
    }

    /// 查上一块挂上去的字节的可写地址。
    ///
    /// 返回 `*mut u8` 是故意的：`hidl_string` 的结构体里要回填一个指向字符区的指针，
    /// 而那个字段得在 `Box` 落位之后才能算。
    fn last_block_mut(&mut self) -> *mut u8 {
        match self.keep.last_mut() {
            Some(block) => block.as_mut_ptr(),
            None => std::ptr::null_mut(),
        }
    }

    /// 一个 HIDL 的 `hidl_string`：parcel 里躺两个对象，一个指向 16 字节的
    /// `hidl_string` 结构体，一个指向字符本身。
    ///
    /// 结构体是 `{ hidl_pointer<char> mBuffer; uint32_t mSize; bool mOwnsBuffer; }`
    /// 加上补位，一共 16 字节；`mBuffer` 必须跟第二个对象里的 `buffer` 指向同一块内存，
    /// 接收方会去比这一对（AOSP 的 `readEmbeddedBuffer` 就是这么校的）。
    pub fn write_hidl_string(&mut self, value: &str) {
        // 字符区带上结尾的 NUL —— HIDL 的 `setToExternal` 里有一个 `CHECK(data[size] == '\0')`，
        // 接收方拿到的是直接指向这块内存的指针，少一个字节就炸。
        let mut chars = value.as_bytes().to_vec();
        chars.push(0);
        let char_addr = self.lash(chars);

        // 结构体里先把指针那格留空，等块挂上去拿到地址再回填。
        let head_addr = self.lash_zeroed(HIDL_STRUCT_SIZE);
        // SAFETY: 刚挂上去的块地址有效、可写，长度就是 HIDL_STRUCT_SIZE。
        unsafe {
            let head = self.last_block_mut();
            std::ptr::copy_nonoverlapping(
                (char_addr as u64).to_le_bytes().as_ptr(),
                head,
                8,
            );
            std::ptr::copy_nonoverlapping(
                (value.len() as u32).to_le_bytes().as_ptr(),
                head.add(8),
                4,
            );
        }

        // 第一个对象：指向那个结构体。没有 HAS_PARENT，它是链条的根。
        let parent_handle = self.offsets.len() as BinderSize;
        self.write_buffer_object(head_addr, HIDL_STRUCT_SIZE, 0, 0, 0, true);
        // 第二个对象：指向字符。带 HAS_PARENT，`parent` 是结构体对象在偏移表里的下标，
        // `parent_offset` 是结构体里指针那一格的偏移（`offsetof(hidl_string, mBuffer)` = 0）。
        self.write_buffer_object(
            char_addr,
            value.len() + 1,
            BINDER_BUFFER_FLAG_HAS_PARENT,
            parent_handle as usize,
            0,
            true,
        );
    }

    /// 一个 HIDL 的 `vec<uint8_t>`。
    ///
    /// 布局跟 `hidl_string` 一模一样（指向 16 字节的 `hidl_vec` 头 + 指向元素），
    /// 区别只在长度是元素个数、且不带 NUL。空 vector 走 `readNullableEmbeddedBuffer`
    /// 那一套：元素指针和长度都给 0，而且内核不登记 buffer 为 0 的对象，所以两个对象
    /// 只登记前一个。
    pub fn write_hidl_vec_u8(&mut self, value: &[u8]) {
        let (elem_addr, elem_len) = if value.is_empty() {
            (0usize, 0usize)
        } else {
            (self.lash(value.to_vec()), value.len())
        };

        let head_addr = self.lash_zeroed(HIDL_STRUCT_SIZE);
        // SAFETY: 同上，刚挂上去的块可写且够长。
        unsafe {
            let head = self.last_block_mut();
            std::ptr::copy_nonoverlapping((elem_addr as u64).to_le_bytes().as_ptr(), head, 8);
            std::ptr::copy_nonoverlapping(
                (value.len() as u32).to_le_bytes().as_ptr(),
                head.add(8),
                4,
            );
        }

        if value.is_empty() {
            self.write_buffer_object(head_addr, HIDL_STRUCT_SIZE, 0, 0, 0, true);
            self.write_buffer_object(0, 0, 0, 0, 0, false);
        } else {
            let parent_handle = self.offsets.len() as BinderSize;
            self.write_buffer_object(head_addr, HIDL_STRUCT_SIZE, 0, 0, 0, true);
            self.write_buffer_object(
                elem_addr,
                elem_len,
                BINDER_BUFFER_FLAG_HAS_PARENT,
                parent_handle as usize,
                0,
                true,
            );
        }
    }

    /// 往 data 里写一个 `binder_buffer_object` 并把它的下标记进偏移表。
    ///
    /// 内核 uapi 的顺序是 `{hdr{type}, flags, buffer, length, parent, parent_offset}`，
    /// 后四个字段宽度跟 ABI 走。`buffer = 0` 的对象内核不登记（AOSP 的 `writeObject`
    /// 就是这么做的），所以空 vector 不会在偏移表里留下痕迹。
    pub fn write_buffer_object(
        &mut self,
        buffer: usize,
        length: usize,
        flags: u32,
        parent: usize,
        parent_offset: usize,
        register: bool,
    ) {
        let at = self.data.len() as BinderSize;
        self.write_u32(BINDER_TYPE_PTR);
        self.write_u32(flags);
        self.write_u64(buffer as u64);
        self.write_u64(length as u64);
        self.write_u64(parent as u64);
        self.write_u64(parent_offset as u64);
        if register {
            self.offsets.push(at);
        }
    }
}

// ---------------------------------------------------------------------------
// 连接。
// ---------------------------------------------------------------------------

/// `/dev/hwbinder` 上的一条连接。
///
/// 同步调用要独占「发命令 → 收应答」这一轮，所以整条连接挂一把锁；relay 的 SOTER 任务
/// 本来就串行，锁不会成为瓶颈。
pub struct HwBinder {
    fd: OwnedFd,
    /// mmap 出来的接收区。内核把应答 parcel 放进这里，所以地址得一直有效。
    map: *mut u8,
    map_len: usize,
    /// 整条连接上只能有一轮「发命令 → 收应答」在跑，不然会串包。
    gate: Mutex<()>,
}

// SAFETY: fd 和 mmap 都是进程级资源，只要不在没有同步的前提下并发收发就安全；
// `out` 有锁，map 只在内核写、我们自己读。
unsafe impl Send for HwBinder {}
unsafe impl Sync for HwBinder {}

impl HwBinder {
    /// 打开 `/dev/hwbinder` 并探一次协议版本。
    pub fn open() -> Result<Self> {
        Self::open_path("/dev/hwbinder", DEFAULT_MAP_LEN)
    }

    /// 接收区大小，探针打印用。
    pub fn map_len(&self) -> usize {
        self.map_len
    }

    pub fn open_path(path: &str, map_len: usize) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open {path} (HIDL 服务不在这个设备上就没这个节点)"))?;
        let fd: OwnedFd = file.into();
        let mut version = BinderVersion::default();
        // SAFETY: fd 是刚打开的设备，BINDER_VERSION 只读 4 字节。
        let rc = unsafe { libc_ioctl(fd.as_raw_fd(), BINDER_VERSION, &mut version) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            bail!("BINDER_VERSION on {path} failed: {err}");
        }
        if version.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION {
            bail!(
                "{path} speaks binder protocol {} but this build expects {}",
                version.protocol_version,
                BINDER_CURRENT_PROTOCOL_VERSION
            );
        }

        // mmap 是给接收用的：内核把应答 parcel 映射进来，`binder_transaction_data`
        // 里给的地址就落在这块里。
        // SAFETY: fd 有效，map_len 非零，属性跟 AOSP 的 ProcessState::open_driver 一致。
        let map = unsafe {
            libc_mmap(
                std::ptr::null_mut(),
                map_len,
                PROT_READ,
                MAP_PRIVATE | MAP_NORESERVE,
                fd.as_raw_fd(),
                0,
            )
        };
        if map == MAP_FAILED {
            let err = io::Error::last_os_error();
            bail!("mmap {map_len} bytes of {path} failed: {err}");
        }
        Ok(Self {
            fd,
            map: map as *mut u8,
            map_len,
            gate: Mutex::new(()),
        })
    }

    /// 一块地址是不是落在我们 mmap 出来的接收区里。
    ///
    /// 应答里的 `binder_buffer_object` 指向的数据是内核映射过来的，理应都在这块里；
    /// 读之前验一下，免得一个错位的地址把进程读崩。
    pub fn is_mapped(&self, addr: usize, len: usize) -> bool {
        let start = self.map as usize;
        let end = start + self.map_len;
        addr >= start && addr.checked_add(len).map_or(false, |e| e <= end)
    }

    /// 把 mmap 区里一段拷出来。调用方先用 [`Self::is_mapped`] 验过。
    pub fn read_mapped(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        if !self.is_mapped(addr, len) {
            return None;
        }
        // SAFETY: 上面确认这段落在我们自己的映射里。
        Some(unsafe { std::slice::from_raw_parts(addr as *const u8, len) }.to_vec())
    }

    /// 发一笔同步事务，等应答。
    ///
    /// `handle` 是目标服务的句柄（0 是 hwservicemanager），`code` 是事务号。
    pub fn transact(&self, handle: u32, code: u32, parcel: &Parcel) -> Result<Reply> {
        let _gate = self
            .gate
            .lock()
            .map_err(|_| anyhow::anyhow!("hwbinder 连接锁中毒"))?;
        let mut tr = BinderTransactionData {
            target: handle as u64,
            cookie: 0,
            code,
            // TF_ACCEPT_FDS 跟 AOSP 的 transact 一致：HIDL 时不时会带 fd 过来。
            flags: TF_ACCEPT_FDS,
            sender_pid: 0,
            sender_euid: 0,
            data_size: parcel.data().len() as BinderSize,
            // 内核这里是字节数，不是元素个数。
            offsets_size: (parcel.offsets().len() * std::mem::size_of::<BinderSize>()) as BinderSize,
            data_buffer: parcel.data().as_ptr() as u64,
            data_offsets: if parcel.offsets().is_empty() {
                0
            } else {
                parcel.offsets().as_ptr() as u64
            },
        };
        if tr.data_buffer == 0 {
            // 零长度 parcel 也过得去，但给个非空地址更省心（内核会当成 0 长度）。
            tr.data_buffer = parcel.data().as_ptr() as u64;
        }

        let mut out = Vec::with_capacity(4 + std::mem::size_of::<BinderTransactionData>() + 8);
        out.extend_from_slice(&BC_TRANSACTION_SG.to_le_bytes());
        // 结构体是 POD，按字节序列化就行。
        // SAFETY: BinderTransactionData 全是 POD，没有内部指针。
        let raw = unsafe {
            std::slice::from_raw_parts(
                (&tr as *const BinderTransactionData).cast::<u8>(),
                std::mem::size_of::<BinderTransactionData>(),
            )
        };
        out.extend_from_slice(raw);
        // 尾巴上的 `buffers_size`：内核拿它给 buffer 对象的数据体留地方。
        out.extend_from_slice(&(parcel.buffers_size() as u64).to_le_bytes());
        // SAFETY: 上面刚填好命令流。
        //
        // 接收侧用一块普通堆内存，不用那张 mmap —— AOSP 的 `talkWithDriver` 也是把
        // `bwr.read_buffer` 指到 `Parcel` 的堆内存上，内核拿 `put_user` 往里写命令流。
        // mmap 区只用来放应答里 buffer 对象指向的数据体。
        let mut inbox = vec![0u8; 4096];
        let mut wwr = BinderWriteRead {
            write_size: out.len() as BinderSize,
            write_consumed: 0,
            write_buffer: out.as_ptr() as BinderSize,
            read_size: inbox.len() as BinderSize,
            read_consumed: 0,
            read_buffer: inbox.as_mut_ptr() as BinderSize,
        };
        // SAFETY: fd 有效，wwr 的 write_buffer 指向本次调用期间有效的 out，read_buffer
        // 指向我们自己的 mmap 区。
        let rc = unsafe { libc_ioctl_wwr(self.fd.as_raw_fd(), &mut wwr) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            return Err(err).with_context(|| format!("BINDER_WRITE_READ for code {code} failed"));
        }

        // read_buffer 是内核写进来的命令流，长度是 read_consumed。
        // SAFETY: 内核保证 read_consumed <= read_size，也就是 <= inbox.len()。
        let reply_bytes = unsafe {
            std::slice::from_raw_parts(inbox.as_ptr(), wwr.read_consumed as usize)
        };
        self.parse_commands(reply_bytes, code)
    }

    /// 走一遍应答里的命令流，挑出 `BR_REPLY`；顺手把要释放的 buffer 还回内核。
    fn parse_commands(&self, bytes: &[u8], code: u32) -> Result<Reply> {
        let mut at = 0usize;
        let mut reply: Option<Reply> = None;
        while at + 4 <= bytes.len() {
            let cmd = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
            at += 4;
            if cmd_type(cmd) != b'r' as u32 {
                bail!("expected a BR_ command in the reply stream, got {cmd:#x}");
            }
            let nr = cmd_nr(cmd);
            match cmd {
                BR_NOOP | BR_OK | BR_TRANSACTION_COMPLETE | BR_SPAWN_LOOPER | BR_FINISHED
                | BR_ONEWAY_SPAM_SUSPECT => {}
                BR_DEAD_REPLY => bail!("binder target died while handling code {code}"),
                BR_FAILED_REPLY => bail!("binder failed to deliver code {code} (bad handle?)"),
                BR_FROZEN_REPLY => bail!("binder target is frozen, code {code}"),
                BR_ERROR => {
                    if at + 4 > bytes.len() {
                        bail!("truncated BR_ERROR");
                    }
                    let err = i32::from_le_bytes([
                        bytes[at],
                        bytes[at + 1],
                        bytes[at + 2],
                        bytes[at + 3],
                    ]);
                    bail!("binder reported error {err} for code {code}");
                }
                BR_ACQUIRE_RESULT => {
                    at = at.checked_add(4).context("truncated BR_ACQUIRE_RESULT")?;
                }
                BR_INCREFS | BR_ACQUIRE | BR_RELEASE | BR_DECREFS | BR_ATTEMPT_ACQUIRE => {
                    at = at.checked_add(16).context("truncated ref-count command")?;
                }
                BR_DEAD_BINDER | BR_CLEAR_DEATH_NOTIFICATION_DONE => {
                    at = at.checked_add(8).context("truncated death command")?;
                }
                BR_TRANSACTION | BR_REPLY | BR_TRANSACTION_SEC_CTX => {
                    let size = if cmd == BR_TRANSACTION_SEC_CTX {
                        72 // binder_transaction_data + secctx 指针
                    } else {
                        64
                    };
                    if at + size > bytes.len() {
                        bail!("truncated transaction data");
                    }
                    // 只有 BR_REPLY 才是给我们的应答；服务端才收 BR_TRANSACTION。
                    if cmd == BR_REPLY {
                        let mut raw = [0u8; 64];
                        raw.copy_from_slice(&bytes[at..at + 64]);
                        // SAFETY: 64 字节正好是 BinderTransactionData 的大小，POD。
                        let tr: BinderTransactionData = unsafe {
                            std::ptr::read_unaligned(raw.as_ptr().cast::<BinderTransactionData>())
                        };
                        reply = Some(self.collect_reply(&tr)?);
                    }
                    at += size;
                }
                other => {
                    // 不认识的命令不能瞎猜它带多少参数，再往下走必然错位，直接停。
                    bail!("unknown BR_ command {other:#x} (nr={nr}) in the reply stream");
                }
            }
        }
        reply.ok_or_else(|| anyhow::anyhow!("no BR_REPLY for code {code} in the binder stream"))
    }

    /// 把内核放进 mmap 区的应答 parcel 拷出来，然后把这块 buffer 交回去。
    fn collect_reply(&self, tr: &BinderTransactionData) -> Result<Reply> {
        let size = tr.data_size as usize;
        let offsets_size = tr.offsets_size as usize;
        let data_ptr = tr.data_buffer as usize;
        let offsets_ptr = tr.data_offsets as usize;

        // 应答 parcel 的地址应该落在我们自己 mmap 的那块里；不满足就是流错位了。
        let map_start = self.map as usize;
        let map_end = map_start + self.map_len;
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        if size > 0 {
            if data_ptr < map_start || data_ptr + size > map_end {
                bail!(
                    "reply parcel at {data_ptr:#x} is outside our mapping [{map_start:#x},{map_end:#x})"
                );
            }
            // SAFETY: 上面确认这段落在我们自己的映射里。
            data = unsafe { std::slice::from_raw_parts(data_ptr as *const u8, size) }.to_vec();
        }
        if offsets_size > 0 {
            if offsets_ptr < map_start || offsets_ptr + offsets_size > map_end {
                bail!("reply offset table at {offsets_ptr:#x} is outside our mapping");
            }
            // SAFETY: 同上。内核这里给的是字节数，除以一个槽的宽度才是元素个数。
            offsets = unsafe {
                std::slice::from_raw_parts(
                    offsets_ptr as *const BinderSize,
                    offsets_size / std::mem::size_of::<BinderSize>(),
                )
            }
            .to_vec();
        }

        // 交回 buffer，不然内核那块一直占着。
        if data_ptr != 0 {
            let mut cmd = Vec::with_capacity(4 + 8);
            cmd.extend_from_slice(&BC_FREE_BUFFER.to_le_bytes());
            cmd.extend_from_slice(&(data_ptr as BinderSize).to_le_bytes());
            let mut wwr = BinderWriteRead {
                write_size: cmd.len() as BinderSize,
                write_consumed: 0,
                write_buffer: cmd.as_ptr() as BinderSize,
                read_size: 0,
                read_consumed: 0,
                read_buffer: 0,
            };
            // SAFETY: cmd 活到 ioctl 返回。失败了也只是泄漏一块内核 buffer，不影响
            // 已经拷出来的应答，所以只记日志。
            let rc = unsafe { libc_ioctl_wwr(self.fd.as_raw_fd(), &mut wwr) };
            if rc != 0 {
                log::warn!(
                    "BC_FREE_BUFFER for {data_ptr:#x} failed: {}",
                    io::Error::last_os_error()
                );
            }
        }

        Ok(Reply { data, offsets })
    }
}

impl Drop for HwBinder {
    fn drop(&mut self) {
        if !self.map.is_null() {
            // SAFETY: map 是 open 时 mmap 出来、还没解映射的。
            unsafe {
                libc_munmap(self.map as *mut std::ffi::c_void, self.map_len);
            }
        }
    }
}

/// AOSP 的 `ProcessState` 默认 1MB；relay 的事务都很小，够用。
const DEFAULT_MAP_LEN: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// libc 摘要 —— B 端只在这里需要几个符号，不值得为它引一个 libc 依赖。
// 这些都是稳定 ABI，声明形状照着 libc crate 抄。
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types)]
mod ffi {
    pub type c_int = i32;
    pub type c_void = core::ffi::c_void;
    pub type c_ulong = u64;
    pub type off_t = i64;

    extern "C" {
        pub fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        pub fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: off_t,
        ) -> *mut c_void;
        pub fn munmap(addr: *mut c_void, length: usize) -> c_int;
    }
}

use ffi::c_void;

const PROT_READ: i32 = 0x1;
const MAP_PRIVATE: i32 = 0x02;
const MAP_NORESERVE: i32 = 0x4000;

const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void;

/// `ioctl` 是变参函数，Rust 里没法直接包一层；这里按每个请求的形状分别包。
///
/// SAFETY: 调用方保证 `arg` 指向的内存对这次请求来说大小和可写性都对。
unsafe fn libc_ioctl(fd: i32, request: u64, arg: *mut BinderVersion) -> i32 {
    ffi::ioctl(fd, request, arg)
}

/// SAFETY: 调用方保证 `wwr` 指向的内存按 `BINDER_WRITE_READ` 的形状初始化过，
/// 且 `write_buffer` / `read_buffer` 指向的内存在这次调用期间有效。
unsafe fn libc_ioctl_wwr(fd: i32, wwr: *mut BinderWriteRead) -> i32 {
    ffi::ioctl(fd, BINDER_WRITE_READ, wwr)
}

unsafe fn libc_mmap(
    addr: *mut c_void,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> *mut c_void {
    ffi::mmap(addr, length, prot, flags, fd, offset)
}

/// SAFETY: `addr` / `length` 必须来自一次成功的 mmap。
unsafe fn libc_munmap(addr: *mut c_void, length: usize) {
    let _ = ffi::munmap(addr, length);
}

/// 不给编译器留「这个模块什么都没用」的抱怨口子：BC_ENTER_LOOPER 之类的常量这里
/// 用不上，但留着是为了以后要收异步事务时不用再翻一遍 uapi。
#[allow(dead_code)]
fn _keep_alive() {
    let _ = (BC_ENTER_LOOPER, BC_EXIT_LOOPER, BINDER_TYPE_HANDLE, TF_ONE_WAY);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_command_numbers_match_the_kernel_macros() {
        // _IOW('c', 0, struct binder_transaction_data) = 0x40406300
        assert_eq!(BC_TRANSACTION, 0x4040_6300, "BC_TRANSACTION");
        // _IOW('c', 1, struct binder_transaction_data_sg) = 64 + 8 = 72 = 0x48
        assert_eq!(BC_TRANSACTION_SG, 0x4048_6311, "BC_TRANSACTION_SG");
        // _IOW('c', 3, binder_uintptr_t) = 0x40086303
        assert_eq!(BC_FREE_BUFFER, 0x4008_6303, "BC_FREE_BUFFER");
        // _IOWR('b', 1, struct binder_write_read) = 0xC0306201
        assert_eq!(BINDER_WRITE_READ, 0xC030_6201, "BINDER_WRITE_READ");
        // _IOWR('b', 9, struct binder_version) = 0xC0046209
        assert_eq!(BINDER_VERSION, 0xC004_6209, "BINDER_VERSION");
        // _IOR('r', 3, struct binder_transaction_data) = 0x80407203
        assert_eq!(BR_REPLY, 0x8040_7203, "BR_REPLY");
        // _IOW('r', 15, binder_uintptr_t) = 0x4008720f（注意是 _IOW，方向位 1）
        // _IOR('r', 15, binder_uintptr_t) = 0x8008720f（_IOR 的方向位是 2）
        assert_eq!(BR_DEAD_BINDER, 0x8008_720f, "BR_DEAD_BINDER");
    }

    #[test]
    fn binder_type_ptr_is_pack_chars_p_t_star_large() {
        // 跟 rsbinder 的 sys::binder 里那个 bindgen 出来的常量对齐。
        assert_eq!(BINDER_TYPE_PTR, 1886661253);
    }

    #[test]
    fn transaction_data_layout_is_64_bytes() {
        assert_eq!(std::mem::size_of::<BinderTransactionData>(), 64);
        assert_eq!(std::mem::size_of::<BinderWriteRead>(), 48);
        assert_eq!(std::mem::size_of::<BinderVersion>(), 4);
    }

    #[test]
    fn interface_token_is_a_plain_c_string() {
        let mut p = Parcel::new();
        p.write_interface_token("vendor.qti.hardware.soter@1.0::ISoter");
        // 裸 ASCII + NUL（38），再按 AOSP 的 `pad_size` 补到 4 字节边界。
        let padded_len = ("vendor.qti.hardware.soter@1.0::ISoter".len() + 1 + 3) & !3;
        assert_eq!(p.data().len(), padded_len);
        assert_eq!(*p.data().last().unwrap(), 0, "must be NUL terminated");
        assert!(p.offsets().is_empty(), "a token is not a binder object");
    }

    #[test]
    fn buffer_object_records_its_offset_and_uses_the_uapi_field_order() {
        let mut p = Parcel::new();
        p.write_i32(0); // 让对象不在 0 偏移上，顺便验证下标记的是字节位置
        p.write_buffer_object(0x1234_5678, 16, 0, 0, 0, true);
        assert_eq!(p.data().len(), 4 + 40, "one buffer object is 40 bytes at 64-bit");
        assert_eq!(p.offsets(), &[4u64]);
        // type / flags / buffer / length / parent / parent_offset
        assert_eq!(&p.data()[4..8], &BINDER_TYPE_PTR.to_le_bytes());
        assert_eq!(&p.data()[8..12], &0u32.to_le_bytes());
        assert_eq!(&p.data()[12..20], &0x1234_5678u64.to_le_bytes());
        assert_eq!(&p.data()[20..28], &16u64.to_le_bytes());
    }

    #[test]
    fn null_buffer_objects_are_not_registered() {
        // 空 vector 就长这样：内核的 writeObject 对 buffer == 0 的对象不登记偏移表。
        let mut p = Parcel::new();
        p.write_buffer_object(0, 0, 0, 0, 0, false);
        assert!(p.offsets().is_empty());
        assert_eq!(p.data().len(), 40);
    }
}
