//! HIDL 版 Keymaster 4.x 客户端（`android.hardware.keymaster@4.x::IKeymasterDevice`）。
//!
//! [`super::relay_tee`] 走的 AIDL KeyMint（`android.hardware.security.keymint`）自
//! Android 12 起才有，且只有新出厂设备强制要求。Android 11 出厂、升级到 12/13 的
//! 设备仍然只有 HIDL `android.hardware.keymaster@4.x`：`servicemanager` 里不存在
//! `...IKeyMintDevice/default`，`getService` 只回 `NameNotFound`。这类设备要做本地
//! 真 TEE 兜底，就必须自己会说 HIDL。
//!
//! 不引 C++、也不引 `hidl-gen` 生成的绑定：HIDL 传输层（`/dev/hwbinder` +
//! `hwservicemanager` + buffer object）由 [`crate::soter::hwbinder`] 提供，本模块只叠
//! `IKeymasterDevice` 这一层的「事务号 + 参数形状」。
//!
//! # 事务号
//!
//! HIDL 的事务号 = `.hal` 里的**声明顺序**，从 1 开始，不按名字重排。本模块对着
//! `hardware/interfaces/keymaster/4.0/IKeymasterDevice.hal` 逐条数出来：
//!
//! ```text
//!  1 getHardwareInfo            11 attestKey
//!  2 getHmacSharingParameters   12 upgradeKey
//!  3 computeSharedHmac          13 deleteKey
//!  4 verifyAuthorization        14 deleteAllKeys
//!  5 addRngEntropy              15 destroyAttestationIds
//!  6 generateKey                16 begin
//!  7 importKey                  17 update
//!  8 importWrappedKey           18 finish
//!  9 getKeyCharacteristics      19 abort
//! 10 exportKey
//! ```
//!
//! `@4.1` 是 `extends @4.0::IKeymasterDevice`，所以 1..19 号**一个都没变**，4.1 新增
//! 的 `deviceLocked` / `earlyBootEnded` 顺延成 20 / 21。
//!
//! # 4.0 把 `generateKey` 拆成了两步
//!
//! Keymaster 4.0/4.1 的 `generateKey(vec<KeyParameter> keyParams)` **没有
//! `attestKeyParams` 形参**；认证链要走单独的 `attestKey(keyToAttest, attestParams)`，
//! 返回 `vec<vec<uint8_t>>`。一次 KeyMint 语义的 `generateKey` 落到 KM4 上就是
//! `generateKey` + `attestKey` 两次事务，keyblob 是两次调用的中间产物 —— 不能靠换个
//! 服务名绕过去，见 [`Self::generate_key`]。
//!
//! # 结构体布局
//!
//! HIDL 的 struct 形参在 parcel 里是**一整块 buffer object，内容是 C++ ABI 的内存
//! 镜像**（`Parcel::write(const T&)` 即 `writeBuffer(sizeof(T), &val)`）；里面的
//! `vec` / `string` 成员是嵌在结构体里的 16 字节头，各自再挂一个 `HAS_PARENT` 子
//! buffer object。字段偏移必须算准。
//!
//! `KeyParameter` 在 `types.hal` 里被摊平过，**没有 union 判别符** —— `Tag` 自己就是
//! 判别符：
//!
//! ```text
//! struct KeyParameter {
//!     Tag tag;              // u32            @ 0
//!     IntegerParams f;      // union, 8 字节   @ 8   (u32/u64/bool 挤在一起)
//!     vec<uint8_t> blob;    // 16 字节头       @ 16
//! };                        // 共 32 字节，对齐 8
//! ```
//!
//! `hidl_vec<T>` / `hidl_string` 的 16 字节头是
//! `{u64 指针, u32 长度, u8 自有标志, 3 字节补位}`，与
//! [`crate::soter::hwbinder`] 的 `write_hidl_string` 一致。

use anyhow::{bail, Context, Result};

use crate::soter::hidl::HW_SERVICE_MANAGER_DESCRIPTOR;
use crate::soter::hwbinder::{
    HwBinder, Parcel, Reply, BINDER_BUFFER_FLAG_HAS_PARENT, BINDER_TYPE_BINDER, BINDER_TYPE_HANDLE,
    BINDER_TYPE_WEAK_BINDER, BINDER_TYPE_WEAK_HANDLE, HIDL_STRUCT_SIZE,
};

// ---------------------------------------------------------------------------
// 服务名。
// ---------------------------------------------------------------------------

/// `@4.1` 的服务全名。instance 是单独一个参数，不在这个名字里。
pub const KM4_FQNAME_V41: &str = "android.hardware.keymaster@4.1::IKeymasterDevice";

/// `@4.0` 的服务全名。
pub const KM4_FQNAME_V40: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";

/// `@3.0` 的服务全名。**只用来在诊断里点名**：3.0 的接口形状跟 4.x 不一样
/// （`getHardwareFeatures`、多一个 `addRngEntropy` 的位置、`generateKey` 带
/// `attestKeyParams`），本模块不实现它。
pub const KM4_FQNAME_V30: &str = "android.hardware.keymaster@3.0::IKeymasterDevice";

/// 默认实例名。
pub const KM4_DEFAULT_INSTANCE: &str = "default";

/// `IServiceManager::get(fqName, instance)` 的事务号（1.0 起没变过）。
const TX_ISERVICEMANAGER_GET: u32 = 1;

/// `hwservicemanager` 固定占着 hwbinder 的 0 号句柄（它就是 context manager）。
const HWSERVICEMANAGER_HANDLE: u32 = 0;

// ---------------------------------------------------------------------------
// `IKeymasterDevice@4.0` 的事务号（= `.hal` 声明顺序）。
// ---------------------------------------------------------------------------

// 全部 `pub`：这张表是协议契约，供调用方/探针核对。
pub const TX_GET_HARDWARE_INFO: u32 = 1;
pub const TX_GET_HMAC_SHARING_PARAMETERS: u32 = 2;
pub const TX_COMPUTE_SHARED_HMAC: u32 = 3;
pub const TX_VERIFY_AUTHORIZATION: u32 = 4;
pub const TX_ADD_RNG_ENTROPY: u32 = 5;
pub const TX_GENERATE_KEY: u32 = 6;
pub const TX_IMPORT_KEY: u32 = 7;
pub const TX_IMPORT_WRAPPED_KEY: u32 = 8;
pub const TX_GET_KEY_CHARACTERISTICS: u32 = 9;
pub const TX_EXPORT_KEY: u32 = 10;
pub const TX_ATTEST_KEY: u32 = 11;
pub const TX_UPGRADE_KEY: u32 = 12;
pub const TX_DELETE_KEY: u32 = 13;
pub const TX_DELETE_ALL_KEYS: u32 = 14;
pub const TX_DESTROY_ATTESTATION_IDS: u32 = 15;
pub const TX_BEGIN: u32 = 16;
pub const TX_UPDATE: u32 = 17;
pub const TX_FINISH: u32 = 18;
pub const TX_ABORT: u32 = 19;

/// `@4.1` 在 4.0 的 19 个之后顺延。
pub const TX_DEVICE_LOCKED: u32 = 20;
pub const TX_EARLY_BOOT_ENDED: u32 = 21;

// ---------------------------------------------------------------------------
// 版本。
// ---------------------------------------------------------------------------

/// 对端**真正接受**的 HIDL Keymaster 版本。
///
/// 它由 interface descriptor 自检得出，不是 `getService` 时用的那个名字 ——
/// 两者在厂商实现上会不一致，见 [`accepted_version`]。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Km4Version {
    /// `@4.0`（Android 11 出厂设备的常见形态）。
    V40,
    /// `@4.1`（Android 12 上仍然用 HIDL keymaster 的机器）。
    V41,
}

impl Km4Version {
    /// 服务全名。正常情况下它同时也是对端校验的 interface descriptor；
    /// 不一致时以自检结果为准，见 [`accepted_version`]。
    pub fn fq_name(self) -> &'static str {
        match self {
            Self::V40 => KM4_FQNAME_V40,
            Self::V41 => KM4_FQNAME_V41,
        }
    }

    /// 另一个版本。descriptor 自检失败时用来兜底。
    fn other(self) -> Self {
        match self {
            Self::V40 => Self::V41,
            Self::V41 => Self::V40,
        }
    }

    /// 往 `KeyMintHardwareInfo` / 认证链里记的版本号。4.1 起改成 `主版本*10+次版本`。
    pub fn hal_version(self) -> i32 {
        match self {
            Self::V40 => 400,
            Self::V41 => 410,
        }
    }

    /// 4.1 才有的那两个方法（`deviceLocked` / `earlyBootEnded`）。
    pub fn has_v41_methods(self) -> bool {
        matches!(self, Self::V41)
    }
}

/// 探测顺序：新版本优先。一台机器只会注册其中一个。
const PROBE_ORDER: [Km4Version; 2] = [Km4Version::V41, Km4Version::V40];

// ---------------------------------------------------------------------------
// `types.hal` 里的 TagType 位前缀与 Tag 数值。
// ---------------------------------------------------------------------------

const TT_ENUM: u32 = 1 << 28;
const TT_ENUM_REP: u32 = 2 << 28;
const TT_UINT: u32 = 3 << 28;
const TT_ULONG: u32 = 5 << 28;
const TT_DATE: u32 = 6 << 28;
const TT_BOOL: u32 = 7 << 28;
const TT_BYTES: u32 = 9 << 28;
const TT_ULONG_REP: u32 = 10 << 28;

pub const TAG_INVALID: u32 = 0;
pub const TAG_PURPOSE: u32 = TT_ENUM_REP | 1;
pub const TAG_ALGORITHM: u32 = TT_ENUM | 2;
pub const TAG_KEY_SIZE: u32 = TT_UINT | 3;
pub const TAG_BLOCK_MODE: u32 = TT_ENUM_REP | 4;
pub const TAG_DIGEST: u32 = TT_ENUM_REP | 5;
pub const TAG_PADDING: u32 = TT_ENUM_REP | 6;
pub const TAG_CALLER_NONCE: u32 = TT_BOOL | 7;
pub const TAG_MIN_MAC_LENGTH: u32 = TT_UINT | 8;
pub const TAG_EC_CURVE: u32 = TT_ENUM | 10;
pub const TAG_RSA_PUBLIC_EXPONENT: u32 = TT_ULONG | 200;
pub const TAG_INCLUDE_UNIQUE_ID: u32 = TT_BOOL | 202;
pub const TAG_BLOB_USAGE_REQUIREMENTS: u32 = TT_ENUM | 301;
pub const TAG_BOOTLOADER_ONLY: u32 = TT_BOOL | 302;
pub const TAG_ROLLBACK_RESISTANCE: u32 = TT_BOOL | 303;
pub const TAG_HARDWARE_TYPE: u32 = TT_ENUM | 304;
pub const TAG_ACTIVE_DATETIME: u32 = TT_DATE | 400;
pub const TAG_ORIGINATION_EXPIRE_DATETIME: u32 = TT_DATE | 401;
pub const TAG_USAGE_EXPIRE_DATETIME: u32 = TT_DATE | 402;
pub const TAG_MIN_SECONDS_BETWEEN_OPS: u32 = TT_UINT | 403;
pub const TAG_MAX_USES_PER_BOOT: u32 = TT_UINT | 404;
pub const TAG_USER_ID: u32 = TT_UINT | 501;
pub const TAG_USER_SECURE_ID: u32 = TT_ULONG_REP | 502;
pub const TAG_NO_AUTH_REQUIRED: u32 = TT_BOOL | 503;
pub const TAG_USER_AUTH_TYPE: u32 = TT_ENUM | 504;
pub const TAG_AUTH_TIMEOUT: u32 = TT_UINT | 505;
pub const TAG_ALLOW_WHILE_ON_BODY: u32 = TT_BOOL | 506;
pub const TAG_TRUSTED_USER_PRESENCE_REQUIRED: u32 = TT_BOOL | 507;
pub const TAG_TRUSTED_CONFIRMATION_REQUIRED: u32 = TT_BOOL | 508;
pub const TAG_UNLOCKED_DEVICE_REQUIRED: u32 = TT_BOOL | 509;
pub const TAG_APPLICATION_ID: u32 = TT_BYTES | 601;
pub const TAG_APPLICATION_DATA: u32 = TT_BYTES | 700;
pub const TAG_CREATION_DATETIME: u32 = TT_DATE | 701;
pub const TAG_ORIGIN: u32 = TT_ENUM | 702;
pub const TAG_ROOT_OF_TRUST: u32 = TT_BYTES | 704;
pub const TAG_OS_VERSION: u32 = TT_UINT | 705;
pub const TAG_OS_PATCHLEVEL: u32 = TT_UINT | 706;
pub const TAG_UNIQUE_ID: u32 = TT_BYTES | 707;
pub const TAG_ATTESTATION_CHALLENGE: u32 = TT_BYTES | 708;
pub const TAG_ATTESTATION_APPLICATION_ID: u32 = TT_BYTES | 709;
pub const TAG_ATTESTATION_ID_BRAND: u32 = TT_BYTES | 710;
pub const TAG_ATTESTATION_ID_DEVICE: u32 = TT_BYTES | 711;
pub const TAG_ATTESTATION_ID_PRODUCT: u32 = TT_BYTES | 712;
pub const TAG_ATTESTATION_ID_SERIAL: u32 = TT_BYTES | 713;
pub const TAG_ATTESTATION_ID_IMEI: u32 = TT_BYTES | 714;
pub const TAG_ATTESTATION_ID_MEID: u32 = TT_BYTES | 715;
pub const TAG_ATTESTATION_ID_MANUFACTURER: u32 = TT_BYTES | 716;
pub const TAG_ATTESTATION_ID_MODEL: u32 = TT_BYTES | 717;
pub const TAG_VENDOR_PATCHLEVEL: u32 = TT_UINT | 718;
pub const TAG_BOOT_PATCHLEVEL: u32 = TT_UINT | 719;
pub const TAG_ASSOCIATED_DATA: u32 = TT_BYTES | 1000;
pub const TAG_NONCE: u32 = TT_BYTES | 1001;
pub const TAG_MAC_LENGTH: u32 = TT_UINT | 1003;
pub const TAG_RESET_SINCE_ID_ROTATION: u32 = TT_BOOL | 1004;
pub const TAG_CONFIRMATION_TOKEN: u32 = TT_BYTES | 1005;

// 认证链相关：KM4 用 `attestKey()` 的参数传，Tag 号跟 KeyMint 一致。
pub const TAG_CERTIFICATE_SERIAL: u32 = TT_ULONG | 1006;
pub const TAG_CERTIFICATE_SUBJECT: u32 = TT_BYTES | 1007;
pub const TAG_CERTIFICATE_NOT_BEFORE: u32 = TT_DATE | 1008;
pub const TAG_CERTIFICATE_NOT_AFTER: u32 = TT_DATE | 1009;

// ---------------------------------------------------------------------------
// 值。
// ---------------------------------------------------------------------------

/// 一个 `KeyParameter` 的值。`IntegerParams` 是个 8 字节的联合体，靠 `Tag` 自己
/// 决定往哪一格写，所以这里只要把「写到联合体的哪一格」表达清楚。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KmValue {
    /// 只有 tag 有意义（`TagType:BOOL` 那类，或者 `INVALID`）。
    /// 联合体全 0，blob 空。
    None,
    /// 写进联合体的 `integer` 格（u32）。
    Integer(u32),
    /// 写进 `longInteger` 格（u64）。`RSA_PUBLIC_EXPONENT` / `USER_SECURE_ID` 用这个。
    LongInteger(u64),
    /// 写进 `dateTime` 格（u64，毫秒）。
    DateTime(u64),
    /// 写进 `blob` 格。
    Blob(Vec<u8>),
}

/// 一个 `KeyParameter`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KmParam {
    pub tag: u32,
    pub value: KmValue,
}

impl KmParam {
    pub fn integer(tag: u32, v: u32) -> Self {
        Self {
            tag,
            value: KmValue::Integer(v),
        }
    }
    pub fn long(tag: u32, v: u64) -> Self {
        Self {
            tag,
            value: KmValue::LongInteger(v),
        }
    }
    pub fn datetime(tag: u32, ms: u64) -> Self {
        Self {
            tag,
            value: KmValue::DateTime(ms),
        }
    }
    pub fn blob(tag: u32, v: impl Into<Vec<u8>>) -> Self {
        Self {
            tag,
            value: KmValue::Blob(v.into()),
        }
    }
    /// `TagType:BOOL` 的 tag：存在即真。
    pub fn flag(tag: u32) -> Self {
        Self {
            tag,
            value: KmValue::None,
        }
    }
}

/// `KeyCharacteristics`：两份参数表。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KmCharacteristics {
    pub software_enforced: Vec<KmParam>,
    pub hardware_enforced: Vec<KmParam>,
}

/// 一次 `generateKey()` 的结果。KM4 里 keyblob 和参数表是一起回来的。
#[derive(Clone, Debug)]
pub struct KmGeneratedKey {
    pub key_blob: Vec<u8>,
    pub characteristics: KmCharacteristics,
}

/// `begin()` 的结果。
#[derive(Clone, Debug)]
pub struct KmBeginResult {
    pub operation_handle: u64,
    pub out_params: Vec<KmParam>,
}

// ---------------------------------------------------------------------------
// 结构体布局（C++ ABI，HIDL 按内存镜像传）。
// ---------------------------------------------------------------------------

/// `sizeof(KeyParameter)`。
pub const KM_PARAM_SIZE: usize = 32;
/// `offsetof(KeyParameter, value.<标量成员>)`：标量那一格和 `blob` 头不重合。
const KM_PARAM_F_OFF: usize = 8;
/// `offsetof(KeyParameter, value.blob)`：16 字节的 `hidl_vec` 头。
const KM_PARAM_BLOB_OFF: usize = 16;

/// `sizeof(KeyCharacteristics)`：两个 16 字节头挨着。
const KEY_CHARACTERISTICS_SIZE: usize = 32;

/// `sizeof(HardwareAuthToken)`。
pub const HARDWARE_AUTH_TOKEN_SIZE: usize = 56;
const AUTH_TOKEN_MAC_OFF: usize = 40;

/// `sizeof(VerificationToken)`。
const VERIFICATION_TOKEN_SIZE: usize = 56;
const VERIFICATION_TOKEN_VERIFIED_OFF: usize = 16;
const VERIFICATION_TOKEN_MAC_OFF: usize = 40;

// ---------------------------------------------------------------------------
// 代理。
// ---------------------------------------------------------------------------

/// 一个活的 HIDL Keymaster 4.x 代理。
///
/// 句柄是 per-`binder_proc` 的，所以连接和句柄必须成对活着 —— 这个结构体把两者
/// 绑在一起，外面拿不到「借句柄去别的连接上发」的口子。
pub struct HidlKeymaster {
    conn: HwBinder,
    handle: u32,
    version: Km4Version,
}

impl HidlKeymaster {
    /// 顺着 `hwservicemanager` 把 4.1 → 4.0 依次试一遍。
    ///
    /// `Ok(None)` 表示这台机器两个版本都没注册 —— 对只有 HIDL `@3.0` 的机器
    /// （Android 10 及更早）就是这个结果，本模块不接。
    pub fn open() -> Result<Option<Self>> {
        // 没有 /dev/hwbinder 就是这台设备根本不跑 HIDL。
        if !std::path::Path::new("/dev/hwbinder").exists() {
            return Ok(None);
        }
        let conn = HwBinder::open().context("open /dev/hwbinder")?;
        for wanted in PROBE_ORDER {
            if let Some(handle) =
                fetch_service_handle(&conn, wanted.fq_name(), KM4_DEFAULT_INSTANCE)?
            {
                // 服务在，但注册名不等于对端认的 descriptor，得自检。
                let version = accepted_version(&conn, handle, wanted)?.with_context(|| {
                    format!(
                        "{}/{} answered getService but rejected both the {} and {} \
                         interface descriptors",
                        wanted.fq_name(),
                        KM4_DEFAULT_INSTANCE,
                        wanted.fq_name(),
                        wanted.other().fq_name()
                    )
                })?;
                if version != wanted {
                    log::info!(
                        "{}/{} accepts only the {} interface descriptor, not {}",
                        wanted.fq_name(),
                        KM4_DEFAULT_INSTANCE,
                        version.fq_name(),
                        wanted.fq_name()
                    );
                }
                return Ok(Some(Self {
                    conn,
                    handle,
                    version,
                }));
            }
        }
        Ok(None)
    }

    /// 指定服务全名和实例名。`fq_name` 必须是本模块认得的两个之一。
    pub fn open_named(fq_name: &str, instance: &str) -> Result<Option<Self>> {
        let wanted = match fq_name {
            KM4_FQNAME_V41 => Km4Version::V41,
            KM4_FQNAME_V40 => Km4Version::V40,
            other => bail!(
                "{other} is not a Keymaster 4.x interface this client speaks \
                 (only {KM4_FQNAME_V41} and {KM4_FQNAME_V40})"
            ),
        };
        if !std::path::Path::new("/dev/hwbinder").exists() {
            return Ok(None);
        }
        let conn = HwBinder::open().context("open /dev/hwbinder")?;
        match fetch_service_handle(&conn, fq_name, instance)? {
            Some(handle) => {
                let version = accepted_version(&conn, handle, wanted)?.with_context(|| {
                    format!(
                        "{fq_name}/{instance} answered getService but rejected both the {} \
                         and {} interface descriptors",
                        wanted.fq_name(),
                        wanted.other().fq_name()
                    )
                })?;
                Ok(Some(Self {
                    conn,
                    handle,
                    version,
                }))
            }
            None => Ok(None),
        }
    }

    pub fn version(&self) -> Km4Version {
        self.version
    }

    pub fn handle(&self) -> u32 {
        self.handle
    }

    /// 发一笔先把 interface token 写好、再交给 `fill` 补参数的事务。
    fn call(&self, code: u32, fill: impl FnOnce(&mut Parcel)) -> Result<Reply> {
        let mut parcel = Parcel::new();
        // HIDL 的 interface token 就是服务全名（带 `@版本`）。
        parcel.write_interface_token(self.version.fq_name());
        fill(&mut parcel);
        self.conn
            .transact(self.handle, code, &parcel)
            .with_context(|| format!("{} transact {code}", self.version.fq_name()))
    }

    // -----------------------------------------------------------------------
    // 1. getHardwareInfo
    // -----------------------------------------------------------------------

    /// 返回 `(security_level, keymaster_name, author_name)`。
    ///
    /// 回包是一个 `SecurityLevel` 加两个 `hidl_string`，不碰结构体布局，因此也用作
    /// interface descriptor 自检的探针。
    pub fn get_hardware_info(&self) -> Result<(u32, String, String)> {
        let reply = self.call(TX_GET_HARDWARE_INFO, |_| {})?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let level = r.u32()?;
        let name = r.hidl_string()?;
        let author = r.hidl_string()?;
        Ok((level, name, author))
    }

    // -----------------------------------------------------------------------
    // 2/3. HMAC 共享参数 —— 不实现
    // -----------------------------------------------------------------------
    //
    // `getHmacSharingParameters()` / `computeSharedHmac()` 用于让 TEE 和 StrongBox
    // 两个实例协商共享 HMAC 键，relay 链路上没有调用点，故不实现。
    // 回包是 `HmacSharingParameters`（`vec<uint8_t> seed` + 内联 `uint8_t[32]`），
    // 解码形状与其它方法不同：要补就按 `types.hal` 字段顺序写，别套用 `vec` 解码。

    // -----------------------------------------------------------------------
    // 5. addRngEntropy
    // -----------------------------------------------------------------------

    /// `addRngEntropy(vec<uint8_t>)`：只带一个顶层 `vec<uint8_t>` 形参，不碰结构体布局。
    pub fn add_rng_entropy(&self, entropy: &[u8]) -> Result<()> {
        let reply = self.call(TX_ADD_RNG_ENTROPY, |p| {
            p.write_hidl_vec_u8(entropy);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "addRngEntropy")
    }

    // -----------------------------------------------------------------------
    // 6. generateKey
    // -----------------------------------------------------------------------

    /// `generateKey(vec<KeyParameter>)` → `(ErrorCode, vec<uint8_t> keyBlob, KeyCharacteristics)`。
    ///
    /// **注意**：KM4 没有 `attestKeyParams`。要认证链得再调一次 [`Self::attest_key`]。
    pub fn generate_key(&self, key_params: &[KmParam]) -> Result<KmGeneratedKey> {
        let reply = self.call(TX_GENERATE_KEY, |p| {
            write_key_params(p, key_params);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "generateKey")?;
        let key_blob = r.embedded_vec_u8()?;
        let characteristics = r.key_characteristics()?;
        Ok(KmGeneratedKey {
            key_blob,
            characteristics,
        })
    }

    // -----------------------------------------------------------------------
    // 9. getKeyCharacteristics
    // -----------------------------------------------------------------------

    pub fn get_key_characteristics(
        &self,
        key_blob: &[u8],
        client_id: &[u8],
        app_data: &[u8],
    ) -> Result<KmCharacteristics> {
        let reply = self.call(TX_GET_KEY_CHARACTERISTICS, |p| {
            p.write_hidl_vec_u8(key_blob);
            p.write_hidl_vec_u8(client_id);
            p.write_hidl_vec_u8(app_data);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "getKeyCharacteristics")?;
        r.key_characteristics()
    }

    // -----------------------------------------------------------------------
    // 11. attestKey
    // -----------------------------------------------------------------------

    /// `attestKey(vec<uint8_t> keyToAttest, vec<KeyParameter> attestParams)`
    /// → `(ErrorCode, vec<vec<uint8_t>> certChain)`。
    ///
    /// 这就是 KeyMint 里 `generateKey(keyParams, attestKeyParams)` 的
    /// `attestKeyParams` 那一半，KM4 上必须单独发。
    pub fn attest_key(
        &self,
        key_to_attest: &[u8],
        attest_params: &[KmParam],
    ) -> Result<Vec<Vec<u8>>> {
        let reply = self.call(TX_ATTEST_KEY, |p| {
            p.write_hidl_vec_u8(key_to_attest);
            write_key_params(p, attest_params);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "attestKey")?;
        r.vec_of_vec_u8()
    }

    // -----------------------------------------------------------------------
    // 13/14. 删除
    // -----------------------------------------------------------------------

    pub fn delete_key(&self, key_blob: &[u8]) -> Result<()> {
        let reply = self.call(TX_DELETE_KEY, |p| {
            p.write_hidl_vec_u8(key_blob);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "deleteKey")
    }

    pub fn delete_all_keys(&self) -> Result<()> {
        let reply = self.call(TX_DELETE_ALL_KEYS, |_| {})?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "deleteAllKeys")
    }

    // -----------------------------------------------------------------------
    // 16..19. 操作
    // -----------------------------------------------------------------------

    /// `begin(KeyPurpose purpose, vec<uint8_t> keyBlob, vec<KeyParameter> inParams,
    /// HardwareAuthToken authToken)`.
    ///
    /// `purpose` 是 `enum : uint32_t`，在 parcel 里是内联的 u32。
    pub fn begin(
        &self,
        purpose: u32,
        key_blob: &[u8],
        in_params: &[KmParam],
    ) -> Result<KmBeginResult> {
        let reply = self.call(TX_BEGIN, |p| {
            p.write_u32(purpose);
            p.write_hidl_vec_u8(key_blob);
            write_key_params(p, in_params);
            write_empty_auth_token(p);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "begin")?;
        let out_params = r.key_params_top_level()?;
        let operation_handle = r.u64()?;
        Ok(KmBeginResult {
            operation_handle,
            out_params,
        })
    }

    /// `update(...)` → `(ErrorCode, uint32_t inputConsumed, vec<KeyParameter> outParams,
    /// vec<uint8_t> output)`。
    pub fn update(
        &self,
        operation_handle: u64,
        in_params: &[KmParam],
        input: &[u8],
    ) -> Result<(u32, Vec<KmParam>, Vec<u8>)> {
        let reply = self.call(TX_UPDATE, |p| {
            p.write_u64(operation_handle);
            write_key_params(p, in_params);
            p.write_hidl_vec_u8(input);
            write_empty_auth_token(p);
            write_empty_verification_token(p);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "update")?;
        let input_consumed = r.u32()?;
        let out_params = r.key_params_top_level()?;
        let output = r.embedded_vec_u8()?;
        Ok((input_consumed, out_params, output))
    }

    /// `finish(...)` → `(ErrorCode, vec<KeyParameter> outParams, vec<uint8_t> output)`。
    ///
    /// `signature` 只在 `KeyPurpose::VERIFY` 时才非空。
    pub fn finish(
        &self,
        operation_handle: u64,
        in_params: &[KmParam],
        input: &[u8],
        signature: &[u8],
    ) -> Result<(Vec<KmParam>, Vec<u8>)> {
        let reply = self.call(TX_FINISH, |p| {
            p.write_u64(operation_handle);
            write_key_params(p, in_params);
            p.write_hidl_vec_u8(input);
            p.write_hidl_vec_u8(signature);
            write_empty_auth_token(p);
            write_empty_verification_token(p);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "finish")?;
        let out_params = r.key_params_top_level()?;
        let output = r.embedded_vec_u8()?;
        Ok((out_params, output))
    }

    pub fn abort(&self, operation_handle: u64) -> Result<()> {
        let reply = self.call(TX_ABORT, |p| {
            p.write_u64(operation_handle);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "abort")
    }

    // -----------------------------------------------------------------------
    // 4.1 独有
    // -----------------------------------------------------------------------

    /// `deviceLocked(bool passwordOnly, VerificationToken)`。4.1 才有，4.0 上直接报错。
    pub fn device_locked(&self, password_only: bool) -> Result<()> {
        if !self.version.has_v41_methods() {
            bail!(
                "{} does not declare deviceLocked (it is @4.1 only)",
                self.version.fq_name()
            );
        }
        let reply = self.call(TX_DEVICE_LOCKED, |p| {
            // HIDL 的 bool 在 parcel 里占 1 字节，后面补齐到 4 字节对齐。
            p.write_bytes(&[u8::from(password_only), 0, 0, 0]);
            write_empty_verification_token(p);
        })?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "deviceLocked")
    }

    /// `earlyBootEnded()`。4.1 才有。
    pub fn early_boot_ended(&self) -> Result<()> {
        if !self.version.has_v41_methods() {
            bail!(
                "{} does not declare earlyBootEnded (it is @4.1 only)",
                self.version.fq_name()
            );
        }
        let reply = self.call(TX_EARLY_BOOT_ENDED, |_| {})?;
        let mut r = ReplyReader::new(&self.conn, &reply);
        r.status()?;
        let code = r.i32()?;
        check_error_code(code, "earlyBootEnded")
    }
}

// ---------------------------------------------------------------------------
// 服务发现。
// ---------------------------------------------------------------------------

/// 问 `hwservicemanager` 要一个服务句柄。
///
/// `Ok(None)` = 这个名字没登记（不是错误，是这台机器没有）。
fn fetch_service_handle(conn: &HwBinder, fq_name: &str, instance: &str) -> Result<Option<u32>> {
    let mut parcel = Parcel::new();
    parcel.write_interface_token(HW_SERVICE_MANAGER_DESCRIPTOR);
    parcel.write_hidl_string(fq_name);
    parcel.write_hidl_string(instance);

    let reply = conn
        .transact(HWSERVICEMANAGER_HANDLE, TX_ISERVICEMANAGER_GET, &parcel)
        .with_context(|| format!("IServiceManager::get({fq_name}, {instance})"))?;

    let mut r = ReplyReader::new(conn, &reply);
    r.status()?;
    let handle = r.binder_handle()?;
    if let Some(handle) = handle {
        // 趁这条应答 buffer 还没交回内核，先把句柄做成一次强引用；否则下一次事务
        // 开头 `BC_FREE_BUFFER` 会把内核翻译应答时给的 ref 减掉，句柄就作废了。
        conn.acquire_handle(handle)
            .with_context(|| format!("acquire the handle for {fq_name}/{instance}"))?;
    }
    Ok(handle)
}

// ---------------------------------------------------------------------------
// interface descriptor 自检。
// ---------------------------------------------------------------------------

/// 用 `getHardwareInfo` 试一笔，看对端认不认这个版本对应的 interface descriptor。
///
/// 选它当探针是因为它在 4.0 和 4.1 上都是事务号 1、不带参数、没有副作用。
fn descriptor_answers(conn: &HwBinder, handle: u32, version: Km4Version) -> Result<bool> {
    let mut parcel = Parcel::new();
    parcel.write_interface_token(version.fq_name());
    let reply = conn.transact(handle, TX_GET_HARDWARE_INFO, &parcel)?;
    Ok(reply_is_body(&reply))
}

/// 问出对端真正接受的 interface descriptor，并据此定版本。
///
/// 正常情况下它就是请求服务时用的那个全名，所以先试它。但**厂商实现会两张皮**：
/// 服务以 `@4.1` 之名注册进 hwservicemanager，`onTransact` 里 `enforceInterface`
/// 校验的却是 `@4.0` 的 descriptor —— 发 `@4.1` 的 token 会被 `BAD_TYPE`
/// （`0x80000001` = `-2147483647`）拒掉，只有 `@4.0` 的 token 能通；而
/// `get("@4.1")` 和 `get("@4.0")` 返回**同一个句柄**，光看句柄发现不了。
///
/// 所以版本必须自检，不能由注册名推。认哪个 descriptor 就按哪个版本算，这样 4.1
/// 独有的 `deviceLocked` / `earlyBootEnded` 不会被发到只实现 4.0 的对端（那会得到
/// `UNKNOWN_TRANSACTION`）。
fn accepted_version(
    conn: &HwBinder,
    handle: u32,
    wanted: Km4Version,
) -> Result<Option<Km4Version>> {
    for version in [wanted, wanted.other()] {
        if descriptor_answers(conn, handle, version)? {
            return Ok(Some(version));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// 编码：往 parcel 里写 HIDL 形参。
// ---------------------------------------------------------------------------

/// 写一个 `vec<KeyParameter>` 形参。
///
/// parcel 里的对象顺序（接收端就是按这个顺序往下消费的）：
///
/// ```text
///   0: 16 字节的 hidl_vec 头        (指向 1，长度 = 元素个数)
///   1: N * 32 字节的元素数组        (HAS_PARENT -> 0，parent_offset 0)
///   2..: 每个元素一个子对象          (HAS_PARENT -> 1，parent_offset = 元素偏移 + 16)
/// ```
///
/// 第 2 组是**每个元素都有**，不是只有 blob 参数才有 —— 见下面那段注释。
fn write_key_params(parcel: &mut Parcel, params: &[KmParam]) {
    if params.is_empty() {
        // 空 vector：头对象照写（元素指针和长度都是 0），再补一个 buffer=0 的哑对象。
        // 哑对象也必须进偏移表 —— 接收端是按偏移表逐个对象往下走的，少了这一格它
        // 会认为「该有的元素区对象不存在」而回 BAD_VALUE，而不是当成空 vector。
        let head_addr = parcel.lash_bytes(&[0u8; HIDL_STRUCT_SIZE]);
        let head_idx = parcel.offsets().len();
        parcel.write_buffer_object(head_addr, HIDL_STRUCT_SIZE, 0, 0, 0, true);
        parcel.write_buffer_object(0, 0, BINDER_BUFFER_FLAG_HAS_PARENT, head_idx, 0, true);
        return;
    }

    // 先把所有 blob 挂上去：结构体里的 blob 头要回填它们的地址，所以必须在拼
    // 元素数组之前拿到。
    let mut blob_addrs: Vec<Option<usize>> = Vec::with_capacity(params.len());
    for p in params {
        blob_addrs.push(match &p.value {
            KmValue::Blob(b) if !b.is_empty() => Some(parcel.lash_bytes(b)),
            _ => None,
        });
    }

    // 拼元素数组（C++ ABI 镜像）。
    let mut elems = vec![0u8; params.len() * KM_PARAM_SIZE];
    for (i, p) in params.iter().enumerate() {
        let o = i * KM_PARAM_SIZE;
        elems[o..o + 4].copy_from_slice(&p.tag.to_le_bytes());
        match &p.value {
            KmValue::None => {
                // `TagType:BOOL` 的语义是「tag 存在即为真」，但真 TEE 里有的实现会
                // 顺手去读 `boolValue`。把那一格写成 1，两种读法都成立。
                if tag_type(p.tag) == Some(TT_BOOL) {
                    elems[o + KM_PARAM_F_OFF] = 1;
                }
            }
            KmValue::Integer(v) => {
                elems[o + KM_PARAM_F_OFF..o + KM_PARAM_F_OFF + 4].copy_from_slice(&v.to_le_bytes())
            }
            KmValue::LongInteger(v) | KmValue::DateTime(v) => {
                elems[o + KM_PARAM_F_OFF..o + KM_PARAM_F_OFF + 8].copy_from_slice(&v.to_le_bytes())
            }
            KmValue::Blob(b) => {
                let addr = blob_addrs[i].unwrap_or(0);
                elems[o + KM_PARAM_BLOB_OFF..o + KM_PARAM_BLOB_OFF + 8]
                    .copy_from_slice(&(addr as u64).to_le_bytes());
                elems[o + KM_PARAM_BLOB_OFF + 8..o + KM_PARAM_BLOB_OFF + 12]
                    .copy_from_slice(&(b.len() as u32).to_le_bytes());
                // 自有标志留 0：那块内存归 parcel 的 `keep` 管，不归接收端。
            }
        }
    }

    let elems_addr = parcel.lash_bytes(&elems);
    let mut head = [0u8; HIDL_STRUCT_SIZE];
    head[0..8].copy_from_slice(&(elems_addr as u64).to_le_bytes());
    // 头里那一格是**元素个数**。
    head[8..12].copy_from_slice(&(params.len() as u32).to_le_bytes());
    let head_addr = parcel.lash_bytes(&head);

    let head_idx = parcel.offsets().len();
    parcel.write_buffer_object(head_addr, HIDL_STRUCT_SIZE, 0, 0, 0, true);
    let elems_idx = parcel.offsets().len();
    parcel.write_buffer_object(
        elems_addr,
        elems.len(),
        BINDER_BUFFER_FLAG_HAS_PARENT,
        head_idx,
        0,
        true,
    );

    for (i, p) in params.iter().enumerate() {
        let field_off = i * KM_PARAM_SIZE + KM_PARAM_BLOB_OFF;
        match &p.value {
            KmValue::Blob(b) if !b.is_empty() => {
                // 非空 blob 一定有地址；出现 None 说明编码器自身矛盾：退回空子对象，
                // 让 HAL 走参数错误，不能 panic —— 本函数不返回 Result，没有别的
                // 上报路径。
                let addr = blob_addrs[i].unwrap_or(0);
                parcel.write_buffer_object(
                    addr,
                    b.len(),
                    BINDER_BUFFER_FLAG_HAS_PARENT,
                    elems_idx,
                    field_off,
                    true,
                );
            }
            _ => {
                // 标量参数和空 blob 也必须挂一个空子对象：HIDL 读取端对
                // `KeyParameterValue` 里的 `vec<uint8_t> blob` 成员是无条件读的，
                // 判别式不参与决定「要不要读」。少一个子对象，读序列就错位，
                // 服务端 `onTransact` 回 BAD_VALUE(-22)。
                parcel.write_buffer_object(
                    0,
                    0,
                    BINDER_BUFFER_FLAG_HAS_PARENT,
                    elems_idx,
                    field_off,
                    true,
                );
            }
        }
    }
}

/// 写一个 `HardwareAuthToken` 形参。
///
/// ```text
///   struct HardwareAuthToken {
///       uint64_t challenge;              @ 0
///       uint64_t userId;                 @ 8
///       uint64_t authenticatorId;        @ 16
///       HardwareAuthenticatorType type;  @ 24  (u32)
///       Timestamp timestamp;             @ 32  (u64)
///       vec<uint8_t> mac;                @ 40  (16 字节头)
///   };                                   // 56 字节
/// ```
fn write_auth_token(parcel: &mut Parcel, token: &HardwareAuthToken) {
    let mac_addr = if token.mac.is_empty() {
        None
    } else {
        Some(parcel.lash_bytes(&token.mac))
    };

    let mut buf = [0u8; HARDWARE_AUTH_TOKEN_SIZE];
    buf[0..8].copy_from_slice(&token.challenge.to_le_bytes());
    buf[8..16].copy_from_slice(&token.user_id.to_le_bytes());
    buf[16..24].copy_from_slice(&token.authenticator_id.to_le_bytes());
    buf[24..28].copy_from_slice(&token.authenticator_type.to_le_bytes());
    buf[32..40].copy_from_slice(&token.timestamp.to_le_bytes());
    if let Some(addr) = mac_addr {
        buf[AUTH_TOKEN_MAC_OFF..AUTH_TOKEN_MAC_OFF + 8]
            .copy_from_slice(&(addr as u64).to_le_bytes());
        buf[AUTH_TOKEN_MAC_OFF + 8..AUTH_TOKEN_MAC_OFF + 12]
            .copy_from_slice(&(token.mac.len() as u32).to_le_bytes());
    }

    let struct_addr = parcel.lash_bytes(&buf);
    let struct_idx = parcel.offsets().len();
    parcel.write_buffer_object(struct_addr, HARDWARE_AUTH_TOKEN_SIZE, 0, 0, 0, true);
    match mac_addr {
        Some(addr) => parcel.write_buffer_object(
            addr,
            token.mac.len(),
            BINDER_BUFFER_FLAG_HAS_PARENT,
            struct_idx,
            AUTH_TOKEN_MAC_OFF,
            true,
        ),
        None => parcel.write_buffer_object(
            0,
            0,
            BINDER_BUFFER_FLAG_HAS_PARENT,
            struct_idx,
            AUTH_TOKEN_MAC_OFF,
            false,
        ),
    }
}

/// 一个「没有用户认证」的 `HardwareAuthToken`：全 0、mac 空。
/// relay 这条链路上所有操作都不带用户认证，用的就是这个。
pub struct HardwareAuthToken {
    pub challenge: u64,
    pub user_id: u64,
    pub authenticator_id: u64,
    pub authenticator_type: u32,
    pub timestamp: u64,
    pub mac: Vec<u8>,
}

impl HardwareAuthToken {
    /// `begin` / `update` / `finish` 要求的「空 token」：数值全 0、mac 空 vector。
    pub fn empty() -> Self {
        Self {
            challenge: 0,
            user_id: 0,
            authenticator_id: 0,
            authenticator_type: 0,
            timestamp: 0,
            mac: Vec::new(),
        }
    }
}

fn write_empty_auth_token(parcel: &mut Parcel) {
    write_auth_token(parcel, &HardwareAuthToken::empty());
}

/// 写一个空的 `VerificationToken`。
///
/// ```text
///   struct VerificationToken {
///       uint64_t challenge;                    @ 0
///       Timestamp timestamp;                   @ 8
///       vec<KeyParameter> parametersVerified;  @ 16
///       SecurityLevel securityLevel;           @ 32  (u32)
///       vec<uint8_t> mac;                      @ 40
///   };                                         // 56 字节
/// ```
///
/// relay 这条链路上不需要「TEE 替 StrongBox 背书」，所以 `parametersVerified` 和
/// `mac` 永远是空 vector，全字段为 0。真要用带内容的 token，得把这两个 vec 的
/// 子对象也挂上 —— 现在这个函数编不出那个情形，别拿它当通用编码器使。
fn write_empty_verification_token(parcel: &mut Parcel) {
    let buf = [0u8; VERIFICATION_TOKEN_SIZE];
    let struct_addr = parcel.lash_bytes(&buf);
    let struct_idx = parcel.offsets().len();
    parcel.write_buffer_object(struct_addr, VERIFICATION_TOKEN_SIZE, 0, 0, 0, true);
    // parametersVerified 是空 vector：哑对象。
    parcel.write_buffer_object(
        0,
        0,
        BINDER_BUFFER_FLAG_HAS_PARENT,
        struct_idx,
        VERIFICATION_TOKEN_VERIFIED_OFF,
        false,
    );
    // mac 也是空 vector。
    parcel.write_buffer_object(
        0,
        0,
        BINDER_BUFFER_FLAG_HAS_PARENT,
        struct_idx,
        VERIFICATION_TOKEN_MAC_OFF,
        false,
    );
}

// ---------------------------------------------------------------------------
// 解码：读回包。
// ---------------------------------------------------------------------------

/// 回包读取子系统：解析应答的游标（所有方法都是「先一个 `hardware::Status`，再方法
/// 自己的字段」）+ 唯一的 binder 能力：把对象里的地址读出来。
///
/// 抽成 trait 是为了让单测能注入假映射区；真机上它就是 `HwBinder`。
/// 回包对象的形状是最容易读错的地方：`vec<T>` 有没有独立的 16 字节头。
trait MappedSource {
    fn read_mapped(&self, addr: usize, len: usize) -> Option<Vec<u8>>;
}

impl MappedSource for HwBinder {
    fn read_mapped(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        HwBinder::read_mapped(self, addr, len)
    }
}

struct ReplyReader<'a> {
    conn: &'a dyn MappedSource,
    reply: &'a Reply,
    at: usize,
}

impl<'a> ReplyReader<'a> {
    fn new(conn: &'a dyn MappedSource, reply: &'a Reply) -> Self {
        Self { conn, reply, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).context("reply cursor overflow")?;
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
    /// 非 0 时回包长度很关键：**只有 4 字节**说明这是一条 `TF_STATUS_CODE` 应答 ——
    /// 服务端的 `onTransact` 拒绝了这笔事务，整个回包就是它自己的返回值，不是方法
    /// 的应答体。此时问题几乎总在 interface descriptor 上，不是 binder 传输层。
    fn status(&mut self) -> Result<()> {
        let code = self.i32()?;
        if code != 0 {
            if self.reply.data.len() == 4 {
                bail!(
                    "the service rejected this transaction with status {code} ({}); \
                     a 4-byte reply is the HAL's own onTransact return value, \
                     not a transport failure",
                    binder_status_name(code)
                );
            }
            bail!("HIDL reply carried a non-OK Status ({code})");
        }
        Ok(())
    }

    /// 诊断用：把游标后面的对象按线格式逐条打出来，游标原样恢复。
    fn dump_objects(&mut self) -> String {
        let saved = self.at;
        // 从 status/errorCode 两个标量之后开始，也就是第一个对象。
        self.at = 8;
        let mut out = String::new();
        for idx in 0..64 {
            let Ok(ty) = self.u32() else { break };
            let Ok(flags) = self.u32() else { break };
            let Ok(buffer) = self.abi_usize() else { break };
            let Ok(length) = self.abi_usize() else { break };
            let Ok(parent) = self.abi_usize() else { break };
            let Ok(parent_offset) = self.abi_usize() else {
                break;
            };
            out.push_str(&format!(
                "\n     [{idx}] ty={ty} flags={flags:#x} buf={buffer:#x} len={length} \
                 parent={parent:#x} poff={parent_offset}"
            ));
        }
        self.at = saved;
        out
    }

    /// 一个 `binder_buffer_object`，只取 `(type, buffer, length)`。
    fn buffer_object(&mut self) -> Result<(u32, usize, usize)> {
        let ty = self.u32()?;
        let _flags = self.u32()?;
        let buffer = self.abi_usize()?;
        let length = self.abi_usize()?;
        let _parent = self.abi_usize()?;
        let _parent_offset = self.abi_usize()?;
        Ok((ty, buffer, length))
    }

    /// 读一个 16 字节的 `hidl_vec` 头，返回 `(数据地址, 元素个数, 数据字节数)`。
    ///
    /// **`元素个数` 和 `字节数` 是两回事**：头里第二格是元素个数，数据对象的
    /// `length` 是 `个数 * sizeof(T)`。只有 `T = uint8_t` 时两者才碰巧相等 ——
    /// `vec<KeyParameter>` 是 32 字节一个、`vec<vec<uint8_t>>` 是 16 字节一个，
    /// 拿「个数」当字节数去读会把数组截断成 1/32 或 1/16。
    ///
    /// 头对象后面紧跟数据对象，地址必须对得上 —— 对不上说明对象顺序读反了，宁可报错
    /// 也不猜。
    fn embedded_head(&mut self) -> Result<(usize, usize, usize)> {
        let (_ty, head_addr, head_len) = self.buffer_object()?;
        if head_len != HIDL_STRUCT_SIZE {
            let dump = self.dump_objects();
            bail!(
                "hidl_vec header object claims {head_len} bytes, expected {HIDL_STRUCT_SIZE} \
                 (cursor at {}){dump}",
                self.at
            );
        }
        let (_ty, elems_addr, elems_len) = self.buffer_object()?;

        let head = self
            .conn
            .read_mapped(head_addr, HIDL_STRUCT_SIZE)
            .context("hidl_vec header is outside our binder mapping")?;
        let mut ptr_raw = [0u8; 8];
        ptr_raw.copy_from_slice(&head[0..8]);
        let head_ptr = u64::from_le_bytes(ptr_raw) as usize;
        let mut size_raw = [0u8; 4];
        size_raw.copy_from_slice(&head[8..12]);
        let count = u32::from_le_bytes(size_raw) as usize;

        if count == 0 && elems_addr == 0 {
            return Ok((0, 0, 0));
        }
        if head_ptr != elems_addr {
            bail!("hidl_vec header points at {head_ptr:#x} but the element object says {elems_addr:#x}");
        }
        Ok((elems_addr, count, elems_len))
    }

    /// `vec<uint8_t>`：元素是单字节，所以「个数」就是字节数。
    fn embedded_vec_u8(&mut self) -> Result<Vec<u8>> {
        let (addr, count, bytes_len) = self.embedded_head()?;
        if count == 0 {
            return Ok(Vec::new());
        }
        if bytes_len != count {
            bail!("vec<uint8_t> header says {count} bytes but the element object says {bytes_len}");
        }
        self.conn
            .read_mapped(addr, count)
            .context("hidl_vec elements are outside our binder mapping")
    }

    /// `hidl_string`：头里是字符个数（**不含**结尾 NUL），数据对象长度是 `个数 + 1`。
    /// 所以不能套 `embedded_vec_u8`（那个要求两者相等）。
    fn hidl_string(&mut self) -> Result<String> {
        let (_ty, head_addr, head_len) = self.buffer_object()?;
        if head_len != HIDL_STRUCT_SIZE {
            bail!("hidl_string header object claims {head_len} bytes, expected {HIDL_STRUCT_SIZE}");
        }
        let (_ty, data_addr, data_len) = self.buffer_object()?;

        let head = self
            .conn
            .read_mapped(head_addr, HIDL_STRUCT_SIZE)
            .context("hidl_string header is outside our binder mapping")?;
        let mut ptr_raw = [0u8; 8];
        ptr_raw.copy_from_slice(&head[0..8]);
        let head_ptr = u64::from_le_bytes(ptr_raw) as usize;
        let mut size_raw = [0u8; 4];
        size_raw.copy_from_slice(&head[8..12]);
        let chars = u32::from_le_bytes(size_raw) as usize;

        if chars == 0 && data_addr == 0 {
            return Ok(String::new());
        }
        if head_ptr != data_addr {
            bail!("hidl_string header points at {head_ptr:#x} but the data object says {data_addr:#x}");
        }
        // 字符区带结尾 NUL：数据对象比声明的字符数多一个字节。
        if data_len != chars + 1 {
            bail!(
                "hidl_string header says {chars} chars but the data object says {data_len} bytes"
            );
        }
        let bytes = self
            .conn
            .read_mapped(data_addr, chars)
            .context("hidl_string data is outside our binder mapping")?;
        String::from_utf8(bytes).context("hidl_string is not valid UTF-8")
    }

    /// `begin` / `update` / `finish` 的 `outParams`：**顶层形参**，线上是一个完整的
    /// `hidl_vec<KeyParameter>` —— 16 字节头对象（指针 + 元素个数）+ 元素区对象 +
    /// 每个元素的子对象。形状必须按形参是顶层还是内嵌分开读（见 [`Self::key_params`]），
    /// `vec<uint8_t>`（`generateKey` 的 keyBlob）走的也是头 + 元素。
    fn key_params_top_level(&mut self) -> Result<Vec<KmParam>> {
        let (elems_addr, count, bytes_len) = self.embedded_head()?;
        if count == 0 {
            return Ok(Vec::new());
        }
        if bytes_len != count * KM_PARAM_SIZE {
            bail!(
                "top-level vec<KeyParameter> header says {count} elements \
                 ({count} x {KM_PARAM_SIZE} bytes) but the element object says {bytes_len}"
            );
        }
        let bytes = self
            .conn
            .read_mapped(elems_addr, bytes_len)
            .context("KeyParameter array is outside our binder mapping")?;
        self.read_key_param_chunks(&bytes)
    }

    /// 嵌在 `KeyCharacteristics` 里的 `vec<KeyParameter>` **没有独立的头对象**：
    /// 那个 16 字节的头（指针 + 元素个数）就躺在结构体自己的 32 字节里，元素区直接
    /// 以 `parent_offset = 字段偏移`（softwareEnforced 是 0、hardwareEnforced 是 16）
    /// 挂上来。所以这里读到的第一个对象就是元素区本身，元素个数用字节数除以 32。
    fn key_params(&mut self) -> Result<Vec<KmParam>> {
        let (_ty, elems_addr, bytes_len) = self.buffer_object()?;
        if bytes_len == 0 {
            return Ok(Vec::new());
        }
        if bytes_len % KM_PARAM_SIZE != 0 {
            bail!(
                "vec<KeyParameter> element object is {bytes_len} bytes, \
                 not a multiple of {KM_PARAM_SIZE}"
            );
        }
        let bytes = self
            .conn
            .read_mapped(elems_addr, bytes_len)
            .context("KeyParameter array is outside our binder mapping")?;
        self.read_key_param_chunks(&bytes)
    }

    /// 把已经读出来的元素区字节按 32 字节一个解成参数，顺便吃掉每个元素的子对象。
    fn read_key_param_chunks(&mut self, bytes: &[u8]) -> Result<Vec<KmParam>> {
        let count = bytes.len() / KM_PARAM_SIZE;

        let mut out = Vec::with_capacity(count);
        // 块长是常量，用 `as_chunks` 切出来就是 `&[u8; 32]`，按下标取字段不会越界。
        // 前面已经校验过字节数是 32 的整数倍，所以余数那一截一定是空的。
        for (i, chunk) in bytes.as_chunks::<KM_PARAM_SIZE>().0.iter().enumerate() {
            let tag = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            // 线上没有联合体判别符，`Tag` 自己就说明了这一格是什么类型。
            let is_blob = tag_type(tag) == Some(TT_BYTES);

            // blob 头里的 (指针, 长度)。
            let mut ptr_raw = [0u8; 8];
            ptr_raw.copy_from_slice(&chunk[KM_PARAM_BLOB_OFF..KM_PARAM_BLOB_OFF + 8]);
            let blob_ptr = u64::from_le_bytes(ptr_raw) as usize;
            let mut size_raw = [0u8; 4];
            size_raw.copy_from_slice(&chunk[KM_PARAM_BLOB_OFF + 8..KM_PARAM_BLOB_OFF + 12]);
            let blob_len = u32::from_le_bytes(size_raw) as usize;

            // 每个元素都对应一个子对象，标量参数的也是空的：少一个子对象，对端读
            // 参数时整条序列就会错位并回 BAD_VALUE。
            let (_ty, data_addr, data_len) = self.buffer_object()?;

            let value = if is_blob {
                if data_len == 0 {
                    KmValue::Blob(Vec::new())
                } else {
                    if data_addr != blob_ptr {
                        bail!(
                            "KeyParameter[{i}] blob header points at {blob_ptr:#x} \
                             but the object says {data_addr:#x}"
                        );
                    }
                    if data_len != blob_len {
                        bail!("KeyParameter[{i}] blob header says {blob_len} bytes but the object says {data_len}");
                    }
                    KmValue::Blob(
                        self.conn
                            .read_mapped(data_addr, data_len)
                            .context("KeyParameter blob is outside our binder mapping")?,
                    )
                }
            } else {
                let word = u32::from_le_bytes([
                    chunk[KM_PARAM_F_OFF],
                    chunk[KM_PARAM_F_OFF + 1],
                    chunk[KM_PARAM_F_OFF + 2],
                    chunk[KM_PARAM_F_OFF + 3],
                ]);
                match tag_type(tag) {
                    Some(t) if t == TT_DATE => {
                        KmValue::DateTime(read_u64_at(chunk, KM_PARAM_F_OFF))
                    }
                    Some(t) if t == TT_ULONG || t == TT_ULONG_REP => {
                        KmValue::LongInteger(read_u64_at(chunk, KM_PARAM_F_OFF))
                    }
                    // ENUM / ENUM_REP / UINT 都是那一格 u32。
                    Some(t) if t == TT_ENUM || t == TT_ENUM_REP || t == TT_UINT => {
                        KmValue::Integer(word)
                    }
                    // BOOL 靠 tag 存在与否表达，那一格里没有额外信息。
                    _ => KmValue::None,
                }
            };
            out.push(KmParam { tag, value });
        }
        Ok(out)
    }

    /// `KeyCharacteristics`：两个 `vec<KeyParameter>` 挨着躺在 32 字节里。
    ///
    /// 头里的字段顺序就是 `types.hal` 的声明顺序 —— `softwareEnforced` @0、
    /// `hardwareEnforced` @16 —— 而 HIDL 是按字段顺序挂子对象的，所以这里
    /// **先读到的那个一定属于 `softwareEnforced`**，顺序不能对调。
    fn key_characteristics(&mut self) -> Result<KmCharacteristics> {
        let (_ty, _struct_addr, struct_len) = self.buffer_object()?;
        if struct_len != KEY_CHARACTERISTICS_SIZE {
            bail!(
                "KeyCharacteristics object claims {struct_len} bytes, expected {KEY_CHARACTERISTICS_SIZE}"
            );
        }
        let software_enforced = self.key_params()?;
        let hardware_enforced = self.key_params()?;
        Ok(KmCharacteristics {
            software_enforced,
            hardware_enforced,
        })
    }

    /// `vec<vec<uint8_t>>`：外层元素是 16 字节头，各自再挂一个数据对象。
    fn vec_of_vec_u8(&mut self) -> Result<Vec<Vec<u8>>> {
        let (elems_addr, count, bytes_len) = self.embedded_head()?;
        if count == 0 {
            return Ok(Vec::new());
        }
        if bytes_len != count * HIDL_STRUCT_SIZE {
            bail!(
                "vec<vec<uint8_t>> header says {count} elements, so the element object should be \
                 {} bytes, but it is {bytes_len}",
                count * HIDL_STRUCT_SIZE
            );
        }
        let heads = self
            .conn
            .read_mapped(elems_addr, bytes_len)
            .context("nested vector heads are outside our binder mapping")?;

        let mut out = Vec::with_capacity(count);
        for (i, head) in heads.as_chunks::<HIDL_STRUCT_SIZE>().0.iter().enumerate() {
            let mut ptr_raw = [0u8; 8];
            ptr_raw.copy_from_slice(&head[0..8]);
            let ptr = u64::from_le_bytes(ptr_raw) as usize;
            let mut size_raw = [0u8; 4];
            size_raw.copy_from_slice(&head[8..12]);
            let size = u32::from_le_bytes(size_raw) as usize;

            let (_ty, data_addr, data_len) = self.buffer_object()?;
            if size == 0 && data_addr == 0 {
                out.push(Vec::new());
                continue;
            }
            if data_addr != ptr {
                bail!(
                    "inner vector {i} header points at {ptr:#x} but the object says {data_addr:#x}"
                );
            }
            if data_len != size {
                bail!("inner vector {i} header says {size} bytes but the object says {data_len}");
            }
            out.push(
                self.conn
                    .read_mapped(data_addr, data_len)
                    .context("inner vector is outside our binder mapping")?,
            );
        }
        Ok(out)
    }

    /// `interface T` 在 parcel 里是一个 `hidl_binder`：null 是单个 i32 的 0，
    /// 否则是一个 `flat_binder_object`（type/flags/handle/cookie，共 24 字节）。
    fn binder_handle(&mut self) -> Result<Option<u32>> {
        let object_at = self.at;
        if !self.reply.offsets.is_empty() && !self.reply.offsets.contains(&(object_at as u64)) {
            bail!(
                "reply object at {object_at} is outside the kernel's offset table {:?}",
                self.reply.offsets
            );
        }
        let mark = self.u32()?;
        if mark == 0 {
            return Ok(None);
        }
        let handle = binder_handle_at(&self.reply.data, object_at)?;
        self.at = object_at + 24;
        Ok(Some(handle))
    }
}

/// 从一个 `flat_binder_object` 里抠出句柄。
///
/// uapi 在 64 位下的布局是 `type@0, flags@4, union{binder: u64 | handle: u32}@8,
/// cookie@16`，一共 24 字节。句柄是 union 那格的低 4 字节，也就是**偏移 8**。
///
/// 偏移 12 **不是**句柄：那是 union 内部的对齐补位，对远程句柄恒为 0。读那里会得到
/// handle 0，而 0 是 hwservicemanager —— 之后每一笔事务都会打在上下文管理器上，被
/// 它的 `enforceInterface` 以 `BAD_TYPE`(0x80000001，即 `-2147483647`) 拒掉。
fn binder_handle_at(data: &[u8], object_at: usize) -> Result<u32> {
    let object = data
        .get(object_at..object_at + 24)
        .with_context(|| format!("truncated binder object at {object_at}"))?;
    let ty = u32::from_le_bytes([object[0], object[1], object[2], object[3]]);
    // 本地对象（passthrough 的 HAL 在自己进程里）和远程句柄都接受，
    // 与 [`crate::soter::hidl`] 的判断保持一致。
    match ty {
        BINDER_TYPE_HANDLE
        | BINDER_TYPE_BINDER
        | BINDER_TYPE_WEAK_HANDLE
        | BINDER_TYPE_WEAK_BINDER => {}
        other => bail!("binder object at {object_at} has unexpected type 0x{other:08x}"),
    }
    Ok(u32::from_le_bytes([
        object[8], object[9], object[10], object[11],
    ]))
}

/// 服务端 `onTransact` 拒绝事务时回的两个状态值。
///
/// interface descriptor 不对回第一个，事务号不存在回第二个。两者**是不同的数**，
/// 可据此区分「敲错门」和「敲门的方式不对」。
const BINDER_BAD_TYPE: i32 = -2_147_483_647;
const BINDER_UNKNOWN_TRANSACTION: i32 = -74;

fn binder_status_name(code: i32) -> &'static str {
    match code {
        BINDER_BAD_TYPE => "BAD_TYPE, the interface descriptor did not match",
        BINDER_UNKNOWN_TRANSACTION => "UNKNOWN_TRANSACTION, no such transaction code",
        _ => "unrecognised status",
    }
}

/// 这条应答算不算方法的真应答体（而不是 4 字节的裸状态）。
///
/// 对端认这个 descriptor 时，`getHardwareInfo` 至少会回 status + `SecurityLevel`
/// + 两个 16 字节的 `hidl_string` 头，远不止 4 字节；不认时回的就是 4 字节裸状态。
fn reply_is_body(reply: &Reply) -> bool {
    if reply.data.len() <= 4 {
        return false;
    }
    let head = &reply.data[..4];
    i32::from_le_bytes([head[0], head[1], head[2], head[3]]) == 0
}

fn read_u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

/// 从 `Tag` 里抠出 `TagType` 位前缀。
fn tag_type(tag: u32) -> Option<u32> {
    // 低 28 位是 tag 序号，高 4 位是类型。`INVALID`(0) 没有类型。
    if tag == 0 {
        return None;
    }
    Some(tag & 0xF000_0000)
}

// ---------------------------------------------------------------------------
// ErrorCode。
// ---------------------------------------------------------------------------

/// `ErrorCode::OK` 之外的都变成错误。
fn check_error_code(code: i32, what: &str) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    bail!(
        "{what} returned ErrorCode {} ({})",
        code,
        error_code_name(code)
    )
}

/// `android.hardware.keymaster@4.0::ErrorCode` 的名字表。日志里光有个负数没法看。
pub fn error_code_name(code: i32) -> &'static str {
    match code {
        0 => "OK",
        -1 => "ROOT_OF_TRUST_ALREADY_SET",
        -2 => "UNSUPPORTED_PURPOSE",
        -3 => "INCOMPATIBLE_PURPOSE",
        -4 => "UNSUPPORTED_ALGORITHM",
        -5 => "INCOMPATIBLE_ALGORITHM",
        -6 => "UNSUPPORTED_KEY_SIZE",
        -7 => "UNSUPPORTED_BLOCK_MODE",
        -8 => "INCOMPATIBLE_BLOCK_MODE",
        -9 => "UNSUPPORTED_MAC_LENGTH",
        -10 => "UNSUPPORTED_PADDING_MODE",
        -11 => "INCOMPATIBLE_PADDING_MODE",
        -12 => "UNSUPPORTED_DIGEST",
        -13 => "INCOMPATIBLE_DIGEST",
        -14 => "INVALID_EXPIRATION_TIME",
        -15 => "INVALID_USER_ID",
        -16 => "INVALID_AUTHORIZATION_TIMEOUT",
        -17 => "UNSUPPORTED_KEY_FORMAT",
        -18 => "INCOMPATIBLE_KEY_FORMAT",
        -19 => "UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM",
        -20 => "UNSUPPORTED_KEY_VERIFICATION_ALGORITHM",
        -21 => "INVALID_INPUT_LENGTH",
        -22 => "KEY_EXPORT_OPTIONS_INVALID",
        -23 => "DELEGATION_NOT_ALLOWED",
        -24 => "KEY_NOT_YET_VALID",
        -25 => "KEY_EXPIRED",
        -26 => "KEY_USER_NOT_AUTHENTICATED",
        -27 => "OUTPUT_PARAMETER_NULL",
        -28 => "INVALID_OPERATION_HANDLE",
        -29 => "INSUFFICIENT_BUFFER_SPACE",
        -30 => "VERIFICATION_FAILED",
        -31 => "TOO_MANY_OPERATIONS",
        -32 => "UNEXPECTED_NULL_POINTER",
        -33 => "INVALID_KEY_BLOB",
        -34 => "IMPORTED_KEY_NOT_ENCRYPTED",
        -35 => "IMPORTED_KEY_DECRYPTION_FAILED",
        -36 => "IMPORTED_KEY_NOT_SIGNED",
        -37 => "IMPORTED_KEY_VERIFICATION_FAILED",
        -38 => "INVALID_ARGUMENT",
        -39 => "UNSUPPORTED_TAG",
        -40 => "INVALID_TAG",
        -41 => "MEMORY_ALLOCATION_FAILED",
        -44 => "IMPORT_PARAMETER_MISMATCH",
        -45 => "SECURE_HW_ACCESS_DENIED",
        -46 => "OPERATION_CANCELLED",
        -47 => "CONCURRENT_ACCESS_CONFLICT",
        -48 => "SECURE_HW_BUSY",
        -49 => "SECURE_HW_COMMUNICATION_FAILED",
        -50 => "UNSUPPORTED_EC_FIELD",
        -51 => "MISSING_NONCE",
        -52 => "INVALID_NONCE",
        -53 => "MISSING_MAC_LENGTH",
        -54 => "KEY_RATE_LIMIT_EXCEEDED",
        -55 => "CALLER_NONCE_PROHIBITED",
        -56 => "KEY_MAX_OPS_EXCEEDED",
        -57 => "INVALID_MAC_LENGTH",
        -58 => "MISSING_MIN_MAC_LENGTH",
        -59 => "UNSUPPORTED_MIN_MAC_LENGTH",
        -60 => "UNSUPPORTED_KDF",
        -61 => "UNSUPPORTED_EC_CURVE",
        -62 => "KEY_REQUIRES_UPGRADE",
        -63 => "ATTESTATION_CHALLENGE_MISSING",
        -64 => "KEYMASTER_NOT_CONFIGURED",
        -65 => "ATTESTATION_APPLICATION_ID_MISSING",
        -66 => "CANNOT_ATTEST_IDS",
        -67 => "ROLLBACK_RESISTANCE_UNAVAILABLE",
        -68 => "HARDWARE_TYPE_UNAVAILABLE",
        -69 => "PROOF_OF_PRESENCE_REQUIRED",
        -70 => "CONCURRENT_PROOF_OF_PRESENCE_REQUESTED",
        -71 => "NO_USER_CONFIRMATION",
        -72 => "DEVICE_LOCKED",
        -100 => "UNIMPLEMENTED",
        -101 => "VERSION_MISMATCH",
        -1000 => "UNKNOWN_ERROR",
        _ => "IMPLEMENTER_NAMESPACE_OR_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soter::hwbinder::BINDER_TYPE_PTR;

    #[test]
    fn tag_values_match_types_hal() {
        // 对着 hardware/interfaces/keymaster/4.0/types.hal 抄下来的，别手改。
        assert_eq!(TAG_PURPOSE, 0x2000_0001);
        assert_eq!(TAG_ALGORITHM, 0x1000_0002);
        assert_eq!(TAG_KEY_SIZE, 0x3000_0003);
        assert_eq!(TAG_EC_CURVE, 0x1000_000A);
        assert_eq!(TAG_RSA_PUBLIC_EXPONENT, 0x5000_00C8);
        assert_eq!(TAG_USER_SECURE_ID, 0xA000_01F6);
        assert_eq!(TAG_ATTESTATION_APPLICATION_ID, 0x9000_02C5);
        assert_eq!(TAG_CONFIRMATION_TOKEN, 0x9000_03ED);
    }

    #[test]
    fn struct_layout_is_c_abi() {
        // KeyParameter = tag(4) + pad(4) + 标量格(8) + hidl_vec 头(16) = 32。
        // 线上没有联合体判别符，所以标量那一格和 blob 头不重合。
        assert_eq!(KM_PARAM_SIZE, 32);
        assert_eq!(KM_PARAM_F_OFF, 8);
        assert_eq!(KM_PARAM_BLOB_OFF, 16);

        // HardwareAuthToken: 8+8+8+4+pad(4)+8+16 = 56
        assert_eq!(HARDWARE_AUTH_TOKEN_SIZE, 56);
        assert_eq!(AUTH_TOKEN_MAC_OFF, 40);

        // VerificationToken: 8+8+16+4+pad(4)+16 = 56
        assert_eq!(VERIFICATION_TOKEN_SIZE, 56);
        assert_eq!(VERIFICATION_TOKEN_VERIFIED_OFF, 16);
        assert_eq!(VERIFICATION_TOKEN_MAC_OFF, 40);

        // KeyCharacteristics: 两个 16 字节头
        assert_eq!(KEY_CHARACTERISTICS_SIZE, 32);
    }

    #[test]
    fn tag_type_is_the_high_nibble() {
        assert_eq!(tag_type(TAG_PURPOSE), Some(TT_ENUM_REP));
        assert_eq!(tag_type(TAG_ALGORITHM), Some(TT_ENUM));
        assert_eq!(tag_type(TAG_KEY_SIZE), Some(TT_UINT));
        assert_eq!(tag_type(TAG_CREATION_DATETIME), Some(TT_DATE));
        assert_eq!(tag_type(TAG_NO_AUTH_REQUIRED), Some(TT_BOOL));
        assert_eq!(tag_type(TAG_ATTESTATION_CHALLENGE), Some(TT_BYTES));
        assert_eq!(tag_type(TAG_INVALID), None);
    }

    #[test]
    fn error_names() {
        assert_eq!(error_code_name(0), "OK");
        assert_eq!(error_code_name(-38), "INVALID_ARGUMENT");
        assert_eq!(error_code_name(-100), "UNIMPLEMENTED");
    }

    #[test]
    fn v41_is_extension_only() {
        // 4.1 只追加，不重排：所以 4.0 的 1..19 在 4.1 上一个都没动。
        assert_eq!(TX_ABORT, 19);
        assert_eq!(TX_DEVICE_LOCKED, 20);
        assert_eq!(TX_EARLY_BOOT_ENDED, 21);
        assert!(Km4Version::V41.has_v41_methods());
        assert!(!Km4Version::V40.has_v41_methods());
    }

    /// 64 位下 `flat_binder_object` 就是 `type@0, flags@4, handle@8, cookie@16`。
    ///
    /// 这个测试盯着**偏移 8**：写成 12（union 里的对齐补位）会得到句柄 0 =
    /// hwservicemanager，之后每笔事务都被 `BAD_TYPE` 拒掉。
    #[test]
    fn binder_object_handle_is_at_offset_eight() {
        let mut data = Vec::new();
        data.extend_from_slice(&BINDER_TYPE_HANDLE.to_le_bytes()); // type
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&7u32.to_le_bytes()); // union: handle
        data.extend_from_slice(&0u32.to_le_bytes()); // union 的对齐补位
        data.extend_from_slice(&0u64.to_le_bytes()); // cookie
        assert_eq!(data.len(), 24, "64 位的 flat_binder_object 是 24 字节");
        assert_eq!(binder_handle_at(&data, 0).unwrap(), 7);
    }

    /// 类型不对要报错，别把「偏移读错、拿到 0」这种事故静默成 handle 0。
    #[test]
    fn a_non_binder_object_is_rejected() {
        let mut data = BINDER_TYPE_PTR.to_le_bytes().to_vec(); // pt* = buffer object
        data.extend_from_slice(&[0u8; 20]);
        assert!(binder_handle_at(&data, 0).is_err());
    }

    /// 截断的对象要报错，而不是越界读。
    #[test]
    fn a_truncated_binder_object_is_rejected() {
        assert!(binder_handle_at(&[0u8; 23], 0).is_err());
    }

    /// descriptor 自检的判据：真应答体 vs 4 字节裸状态。
    ///
    /// 两个形状：认 descriptor 时 `getHardwareInfo` 回 168 字节，不认时回 4 字节
    /// `BAD_TYPE`。
    #[test]
    fn descriptor_probe_distinguishes_a_body_from_a_bare_status() {
        let body = Reply {
            data: vec![0, 0, 0, 0, 1, 0, 0, 0],
            offsets: Vec::new(),
        };
        assert!(reply_is_body(&body));

        let rejected = Reply {
            data: BINDER_BAD_TYPE.to_le_bytes().to_vec(),
            offsets: Vec::new(),
        };
        assert!(!reply_is_body(&rejected));

        assert!(!reply_is_body(&Reply {
            data: Vec::new(),
            offsets: Vec::new(),
        }));
    }

    /// 两个拒绝状态必须是不同的数：一个是敲错门，一个是敲门方式不对。
    #[test]
    fn the_two_rejection_statuses_are_told_apart() {
        assert_ne!(BINDER_BAD_TYPE, BINDER_UNKNOWN_TRANSACTION);
        assert!(binder_status_name(BINDER_BAD_TYPE).contains("descriptor"));
        assert!(binder_status_name(BINDER_UNKNOWN_TRANSACTION).contains("transaction code"));
    }

    /// 自检必须把「另一个版本」也试到：以 `@4.1` 之名注册、却只认 `@4.0`
    /// descriptor 的实现只有这一步能认出来。
    #[test]
    fn descriptor_self_check_falls_back_to_the_other_version() {
        assert_eq!(Km4Version::V41.other(), Km4Version::V40);
        assert_eq!(Km4Version::V40.other(), Km4Version::V41);
        assert_ne!(Km4Version::V41.fq_name(), Km4Version::V40.fq_name());
    }

    // -----------------------------------------------------------------------
    // 线上形状：encode 侧（喂给 HAL 的 parcel）
    // -----------------------------------------------------------------------

    fn read_u64(b: &[u8], at: usize) -> u64 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&b[at..at + 8]);
        u64::from_le_bytes(raw)
    }

    fn read_u32(b: &[u8], at: usize) -> u32 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&b[at..at + 4]);
        u32::from_le_bytes(raw)
    }

    /// 空 vector：头对象照写（指针 0、元素 0），后面跟一个 buffer=0 的哑对象。
    #[test]
    fn empty_param_vector_writes_a_head_and_a_dummy_object() {
        let mut p = Parcel::new();
        write_key_params(&mut p, &[]);
        // 两个对象，每个 40 字节（type+flags 各 4，其余四个 u64）。
        assert_eq!(p.data().len(), 80);
        assert_eq!(
            p.offsets().len(),
            2,
            "哑对象也写进了偏移表（这一点还没在真机验过）"
        );
        assert_eq!(read_u32(p.data(), 0), BINDER_TYPE_PTR);
        assert_eq!(
            read_u64(p.data(), 8) as usize,
            p.keep()[0].as_ptr() as usize,
            "头对象指向那 16 字节空头"
        );
        assert_eq!(
            read_u64(p.data(), 16),
            HIDL_STRUCT_SIZE as u64,
            "头对象 16 字节"
        );
        // 空 vector 的「元素指针 / 元素个数」都在那 16 字节里，且全 0。
        assert_eq!(p.keep().len(), 1);
        assert_eq!(p.keep()[0].len(), HIDL_STRUCT_SIZE);
        assert!(p.keep()[0].iter().all(|b| *b == 0));
        // 哑对象：buffer 和 length 都是 0。
        assert_eq!(read_u64(p.data(), 40 + 8), 0);
        assert_eq!(read_u64(p.data(), 40 + 16), 0);
    }

    /// 纯标量：头对象 + 元素区对象 + 每个元素一个空子对象。
    #[test]
    fn scalar_params_carry_one_empty_child_each() {
        let params = [
            KmParam::integer(TAG_ALGORITHM, 3),
            KmParam::long(TAG_RSA_PUBLIC_EXPONENT, 65537),
            KmParam::datetime(TAG_CREATION_DATETIME, 1_700_000_000_000),
            KmParam::flag(TAG_NO_AUTH_REQUIRED),
        ];
        let mut p = Parcel::new();
        write_key_params(&mut p, &params);

        // 1 头 + 1 元素区 + 4 空子对象
        assert_eq!(p.offsets().len(), 2 + params.len());
        assert_eq!(p.data().len(), (2 + params.len()) * 40);

        // keep 里两块：块 0 是元素区，块 1 是 16 字节头。
        let elems = &p.keep()[0];
        assert_eq!(elems.len(), params.len() * KM_PARAM_SIZE);
        let head = &p.keep()[1];
        assert_eq!(
            read_u64(head, 0) as usize,
            elems.as_ptr() as usize,
            "头里是元素区地址"
        );
        assert_eq!(
            read_u32(head, 8) as usize,
            params.len(),
            "头里那一格是元素个数"
        );

        // 元素区里：tag 在 0、值在 8。
        assert_eq!(read_u32(elems, 0), TAG_ALGORITHM);
        assert_eq!(read_u32(elems, KM_PARAM_F_OFF), 3);
        assert_eq!(read_u32(elems, KM_PARAM_SIZE), TAG_RSA_PUBLIC_EXPONENT);
        assert_eq!(
            read_u64(elems, KM_PARAM_SIZE + KM_PARAM_F_OFF),
            65537,
            "ULONG 走 8 字节格"
        );
        assert_eq!(
            read_u64(elems, 2 * KM_PARAM_SIZE + KM_PARAM_F_OFF),
            1_700_000_000_000,
            "DATE 也走 8 字节格"
        );
        assert_eq!(read_u32(elems, 3 * KM_PARAM_SIZE), TAG_NO_AUTH_REQUIRED);
        assert_eq!(
            read_u32(elems, 3 * KM_PARAM_SIZE + KM_PARAM_F_OFF),
            1,
            "BOOL 那一格写 1，两种读法都成立"
        );

        // 头的指针 = 元素区对象里登记的那个地址。
        assert_eq!(read_u64(p.data(), 8) as usize, head.as_ptr() as usize);
        assert_eq!(read_u64(p.data(), 16) as usize, HIDL_STRUCT_SIZE);
        assert_eq!(
            read_u64(p.data(), 40 + 8) as usize,
            elems.as_ptr() as usize,
            "第二个对象（元素区）的 buffer"
        );
        assert_eq!(
            read_u64(p.data(), 40 + 16) as usize,
            params.len() * KM_PARAM_SIZE,
            "元素区对象的 length 是字节数，不是个数"
        );
        assert_eq!(
            read_u32(p.data(), 40 + 4),
            BINDER_BUFFER_FLAG_HAS_PARENT,
            "元素区挂在头对象下"
        );
        assert_eq!(read_u64(p.data(), 40 + 24), 0, "parent 是头对象的下标 0");
    }

    /// blob：元素里填 (指针, 长度)，并挂一个真实数据子对象；空 blob 挂空对象。
    #[test]
    fn blob_params_point_at_their_data() {
        let blob = vec![0xaau8, 0xbb, 0xcc];
        let params = [
            KmParam::blob(TAG_ATTESTATION_CHALLENGE, blob.clone()),
            KmParam::blob(TAG_APPLICATION_ID, Vec::new()),
        ];
        let mut p = Parcel::new();
        write_key_params(&mut p, &params);

        // keep：块 0 = blob 数据，块 1 = 元素区，块 2 = 头
        assert_eq!(p.keep().len(), 3);
        let blob_addr = p.keep()[0].as_ptr() as usize;
        let elems = &p.keep()[1];

        assert_eq!(read_u64(elems, KM_PARAM_BLOB_OFF) as usize, blob_addr);
        assert_eq!(read_u32(elems, KM_PARAM_BLOB_OFF + 8) as usize, blob.len());
        let mut off_raw = [0u8; 8];
        off_raw.copy_from_slice(&elems[KM_PARAM_BLOB_OFF + 8..KM_PARAM_BLOB_OFF + 16]);
        assert_eq!(
            u64::from_le_bytes(off_raw) & 0xffff_ffff_0000_0000,
            0,
            "自有标志那 4 字节留 0",
        );

        // 第二个（空 blob）元素：指针和长度都是 0。
        assert_eq!(read_u64(elems, KM_PARAM_SIZE + KM_PARAM_BLOB_OFF), 0);
        assert_eq!(read_u32(elems, KM_PARAM_SIZE + KM_PARAM_BLOB_OFF + 8), 0);

        // 子对象：第一个带数据、第二个空；两者的 parent_offset 都指向元素里的 blob 头。
        let child0 = 80; // 头(40) + 元素区(40) 之后
        assert_eq!(read_u64(p.data(), child0 + 8) as usize, blob_addr);
        assert_eq!(read_u64(p.data(), child0 + 16) as usize, blob.len());
        assert_eq!(read_u64(p.data(), child0 + 32) as usize, KM_PARAM_BLOB_OFF);
        let child1 = child0 + 40;
        assert_eq!(read_u64(p.data(), child1 + 8), 0);
        assert_eq!(
            read_u64(p.data(), child1 + 32) as usize,
            KM_PARAM_SIZE + KM_PARAM_BLOB_OFF
        );
    }

    // -----------------------------------------------------------------------
    // 线上形状：decode 侧（HAL 回来的 reply）
    // -----------------------------------------------------------------------

    /// 一块假的「binder 映射区」：地址 → 字节。真机上这段是内核 mmap 出来的。
    struct FakeMap(std::collections::HashMap<usize, Vec<u8>>);

    impl FakeMap {
        fn new(pairs: &[(usize, Vec<u8>)]) -> Self {
            let mut m = std::collections::HashMap::new();
            for (addr, bytes) in pairs {
                m.insert(*addr, bytes.clone());
            }
            Self(m)
        }
    }

    impl MappedSource for FakeMap {
        fn read_mapped(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
            let bytes = self.0.get(&addr)?;
            (bytes.len() >= len).then(|| bytes[..len].to_vec())
        }
    }

    /// 拼一个 `binder_buffer_object`（40 字节）。
    fn object(buffer: usize, length: usize, parent: usize, parent_offset: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(40);
        v.extend_from_slice(&BINDER_TYPE_PTR.to_le_bytes());
        v.extend_from_slice(&BINDER_BUFFER_FLAG_HAS_PARENT.to_le_bytes());
        v.extend_from_slice(&(buffer as u64).to_le_bytes());
        v.extend_from_slice(&(length as u64).to_le_bytes());
        v.extend_from_slice(&(parent as u64).to_le_bytes());
        v.extend_from_slice(&(parent_offset as u64).to_le_bytes());
        v
    }

    /// 一个 32 字节的 `KeyParameter`（标量）。
    fn elem_scalar(tag: u32, word: u32) -> Vec<u8> {
        let mut v = vec![0u8; KM_PARAM_SIZE];
        v[0..4].copy_from_slice(&tag.to_le_bytes());
        v[KM_PARAM_F_OFF..KM_PARAM_F_OFF + 4].copy_from_slice(&word.to_le_bytes());
        v
    }

    /// 一个 32 字节的 `KeyParameter`（blob 头）。
    fn elem_blob(tag: u32, addr: usize, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; KM_PARAM_SIZE];
        v[0..4].copy_from_slice(&tag.to_le_bytes());
        v[KM_PARAM_BLOB_OFF..KM_PARAM_BLOB_OFF + 8].copy_from_slice(&(addr as u64).to_le_bytes());
        v[KM_PARAM_BLOB_OFF + 8..KM_PARAM_BLOB_OFF + 12]
            .copy_from_slice(&(len as u32).to_le_bytes());
        v
    }

    /// 顶层形参 `vec<KeyParameter>`：头对象 + 元素区 + 每元素一个子对象。
    ///
    /// 这是 `begin/update/finish` 的 `outParams` 的真实形状。用「内嵌」读法（把
    /// 16 字节头当元素数组）会直接 bail。
    #[test]
    fn top_level_out_params_have_a_head_object() {
        const HEAD: usize = 0x1000;
        const ELEMS: usize = 0x2000;
        const BLOB: usize = 0x3000;

        let mut elems = elem_scalar(TAG_ALGORITHM, 3);
        elems.extend(elem_blob(TAG_ATTESTATION_CHALLENGE, BLOB, 2));
        let mut head = vec![0u8; HIDL_STRUCT_SIZE];
        head[0..8].copy_from_slice(&(ELEMS as u64).to_le_bytes());
        head[8..12].copy_from_slice(&2u32.to_le_bytes());

        let src = FakeMap::new(&[(HEAD, head), (ELEMS, elems), (BLOB, vec![0xaau8, 0xbb])]);

        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes()); // hardware::Status
        data.extend_from_slice(&0i32.to_le_bytes()); // ErrorCode
        data.extend(object(HEAD, HIDL_STRUCT_SIZE, 0, 0));
        data.extend(object(ELEMS, 2 * KM_PARAM_SIZE, 0, 0));
        data.extend(object(0, 0, 1, KM_PARAM_BLOB_OFF)); // 元素 0（标量）的空子对象
        data.extend(object(BLOB, 2, 1, KM_PARAM_SIZE + KM_PARAM_BLOB_OFF));
        let reply = Reply {
            data,
            offsets: Vec::new(),
        };

        let mut r = ReplyReader::new(&src, &reply);
        r.at = 8;
        let got = r.key_params_top_level().expect("顶层 outParams 要能解出来");
        assert_eq!(
            got,
            vec![
                KmParam::integer(TAG_ALGORITHM, 3),
                KmParam::blob(TAG_ATTESTATION_CHALLENGE, vec![0xaau8, 0xbb]),
            ]
        );
        assert_eq!(r.at, reply.data.len(), "游标应该刚好走完");

        // 同一个回包用「内嵌」读法必然失败：16 字节的头不是 32 的整数倍。
        let mut wrong = ReplyReader::new(&src, &reply);
        wrong.at = 8;
        let err = wrong.key_params().unwrap_err().to_string();
        assert!(
            err.contains("not a multiple of 32"),
            "内嵌读法应该在这里报错，实际: {err}"
        );
    }

    /// 嵌在 `KeyCharacteristics` 里的那种：没有独立头对象，第一个对象就是元素区。
    #[test]
    fn embedded_params_have_no_head_object() {
        const ELEMS: usize = 0x2000;
        let src = FakeMap::new(&[(ELEMS, elem_scalar(TAG_KEY_SIZE, 256))]);
        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend(object(ELEMS, KM_PARAM_SIZE, 0, 0));
        data.extend(object(0, 0, 0, KM_PARAM_F_OFF));
        let reply = Reply {
            data,
            offsets: Vec::new(),
        };

        let mut r = ReplyReader::new(&src, &reply);
        r.at = 8;
        assert_eq!(
            r.key_params().unwrap(),
            vec![KmParam::integer(TAG_KEY_SIZE, 256)]
        );

        // 反过来用顶层读法读它，也要拒绝（元素区只有 32 字节，不是 16 字节的头）。
        let mut wrong = ReplyReader::new(&src, &reply);
        wrong.at = 8;
        assert!(wrong.key_params_top_level().is_err());
    }

    /// 元素区字节数必须正好是「个数 × 32」，否则宁可报错也不猜。
    #[test]
    fn top_level_rejects_a_short_element_array() {
        const HEAD: usize = 0x1000;
        const ELEMS: usize = 0x2000;
        let mut head = vec![0u8; HIDL_STRUCT_SIZE];
        head[0..8].copy_from_slice(&(ELEMS as u64).to_le_bytes());
        head[8..12].copy_from_slice(&2u32.to_le_bytes());
        let src = FakeMap::new(&[(HEAD, head), (ELEMS, vec![0u8; KM_PARAM_SIZE])]);

        let mut data = Vec::new();
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend(object(HEAD, HIDL_STRUCT_SIZE, 0, 0));
        data.extend(object(ELEMS, KM_PARAM_SIZE, 0, 0));
        let reply = Reply {
            data,
            offsets: Vec::new(),
        };

        let mut r = ReplyReader::new(&src, &reply);
        r.at = 8;
        let err = r.key_params_top_level().unwrap_err().to_string();
        assert!(err.contains("element object says"), "实际: {err}");
    }
}
