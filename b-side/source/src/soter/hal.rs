//! Vendor SOTER HAL client.
//!
//! The B-side relay agent forwards SOTER operations to the *real* vendor HAL on
//! this device.  Two vendor families ship in the wild, and the transaction
//! numbers they use are the same (AIDL declaration order 1..14):
//!
//! ```text
//! trustonic : vendor.trustonic.hardware.soter.ITrustonicSoter/default   (MTK / Kinibi)
//! qti       : vendor.qti.hardware.soter.ISoter/default                  (Qualcomm)
//! xiaomi    : vendor.xiaomi.hardware.soterservice@1.0::ISoter           (MTK, HIDL only)
//! ```
//!
//! What differs is the outer reply framing:
//!
//! ```text
//!                    status  return  notNull  totalSize  errorCode  payload   length
//! trustonic data    : [i32]   -       [i32]    [i32]      [i32]      byte[]    [i32]
//! qti data          : [i32]   [i32]   [i32]    [i32]      -          byte[]    [i32]
//! trustonic session : [i32]   -       [i32]    [i32]=16   [i32]      i64 session
//! qti session       : [i32]   -       [i32]    [i32]=16   (order unknown, see below)
//! ```
//!
//! (`totalSize` counts itself, which is why the expected value is
//! `12 + pad4(len)` on qti and `16 + pad4(len)` on trustonic: the qti parcelable
//! carries no error code, its method's return value does.)
//!
//! Why the transactions are marshalled by hand instead of through the
//! generated AIDL stubs (the declarations live next to this module): the wire
//! forms were recovered from vendor artifacts rather than from a spec — the
//! Trustonic one from the shipped `vendor.trustonic.hardware.soter-V1-ndk.so`
//! and from replies captured off a live device, the Qualcomm one from the SOTER
//! host APK that talks to it (its `…ISoter$Proxy` literals and its parcelable
//! read order) — and they carry vendor quirks the generated stubs do not
//! reproduce, most visibly the leading `totalSize` header on `SoterData` and
//! `SoterSession`.  Doing it by hand also keeps the reply decoder testable
//! against those bytes (see [`super::fixtures`]).
//!
//! `getDeviceId` returns the payload as 32 hex characters plus a NUL byte;
//! `exportAttkPublicKey` returns a PEM block; `exportAskPublicKey` returns
//! `[i32 json length][json][TEE signature]`.  Callers get the raw bytes and
//! decide how to present them (see [`super::handle`]).

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{hub, FromIBinder, Parcel, RemoteProxy, SIBinder, StatusCode};

use crate::vendor::qti::hardware::soter::ISoter::ISoter;
use crate::vendor::trustonic::hardware::soter::ITrustonicSoter::ITrustonicSoter;

use super::hidl;

/// Trustonic service name, as registered with the (vendor) service manager.
pub const SERVICE: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter/default";

/// Trustonic interface descriptor, used as the transaction interface token.
pub const INTERFACE: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter";

/// Qualcomm service name.
pub const QTI_SERVICE: &str = "vendor.qti.hardware.soter.ISoter/default";

/// Qualcomm interface descriptor.
pub const QTI_INTERFACE: &str = "vendor.qti.hardware.soter.ISoter";

/// Which vendor HAL answered.
///
/// 同一家 vendor 可能以两种形态出现：老的 HIDL（`@1.0::`，跑 `/dev/hwbinder`）
/// 和新的 AIDL（跑 `/dev/binder`）。Android 13 以后厂商陆续搬到 AIDL，但过渡期
/// 两种都可能有，所以这几个后端都要认。两个名字对不上别当成一家。
///
/// 小米只在 HIDL 上出现过（`vendor.xiaomi.hardware.soterservice@1.0::ISoter`，天玑机
/// 实测能签），没有对应的 AIDL 形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Trustonic,
    Qti,
    TrustonicHidl,
    QtiHidl,
    XiaomiHidl,
}

impl Backend {
    /// 解析顺序。AIDL 在前：Android 13 以后厂商都搬过去了，HIDL 是过渡期的兜底。
    /// 同一家 vendor 只会注册其中一种形态。
    pub const ALL: [Backend; 5] = [
        Backend::Trustonic,
        Backend::Qti,
        Backend::TrustonicHidl,
        Backend::QtiHidl,
        Backend::XiaomiHidl,
    ];

    /// 服务名。HIDL 那边是 fqName（`@1.0::` 那个），instance 统一是 `default`。
    pub fn service(self) -> &'static str {
        match self {
            Backend::Trustonic => SERVICE,
            Backend::Qti => QTI_SERVICE,
            Backend::TrustonicHidl => hidl::HIDL_TRUSTONIC_FQNAME,
            Backend::QtiHidl => hidl::HIDL_QTI_FQNAME,
            Backend::XiaomiHidl => hidl::HIDL_XIAOMI_FQNAME,
        }
    }

    /// 事务里要写的 interface token。
    pub fn interface(self) -> &'static str {
        match self {
            Backend::Trustonic => INTERFACE,
            Backend::Qti => QTI_INTERFACE,
            Backend::TrustonicHidl => hidl::HIDL_TRUSTONIC_FQNAME,
            Backend::QtiHidl => hidl::HIDL_QTI_FQNAME,
            Backend::XiaomiHidl => hidl::HIDL_XIAOMI_FQNAME,
        }
    }

    /// Short name for logs and the capability/probe report.
    pub fn label(self) -> &'static str {
        match self {
            Backend::Trustonic => "trustonic",
            Backend::Qti => "qti",
            Backend::TrustonicHidl => "trustonic-hidl",
            Backend::QtiHidl => "qti-hidl",
            Backend::XiaomiHidl => "xiaomi-hidl",
        }
    }

    /// 是不是跑在 `/dev/hwbinder` 上的那套。
    pub fn is_hidl(self) -> bool {
        matches!(
            self,
            Backend::TrustonicHidl | Backend::QtiHidl | Backend::XiaomiHidl
        )
    }

    /// qti declares the payload methods as `int xxx(..., out SoterData data)`, so
    /// the reply carries the SOTER error code as an extra leading value and the
    /// parcelable itself holds only the payload.  HIDL 那边没这层：回包只有一
    /// 个 `Status`（跟 AIDL 同样的位置），所以不算 qti。
    fn has_return_code(self) -> bool {
        self == Backend::Qti
    }

    /// Whether the ATTK family (codes 2/6/14) can be addressed.
    ///
    /// 这是 vendor 的差别而不是 AIDL/HIDL 的差别：联发科那套（Trustonic）上是真
    /// 实现，高通那边是空号。所以两个 Trustonic 后端都算支持。
    ///
    /// The host never sends those three, so the vendor's declarations for them
    /// were never observable on Qualcomm, and guessing is not an option: on the
    /// Trustonic HAL code 6 is `generateAttkKeyPair`, i.e. a TEE state change.
    fn supports_attk_extras(self) -> bool {
        matches!(self, Backend::Trustonic | Backend::TrustonicHidl)
    }
}

// Transaction codes = AIDL declaration order (see the `.aidl` next to this
// module).  These are the vendors' codes, not a guess: they match the Bp stubs
// in `vendor.trustonic.hardware.soter-V1-ndk.so` and the literals in the SOTER
// host APK's `vendor.qti.hardware.soter.ISoter$Proxy`.  Both vendors number the
// same 14 slots the same way.
pub const TX_EXPORT_ASK_PUBLIC_KEY: u32 = 1;
pub const TX_EXPORT_ATTK_PUBLIC_KEY: u32 = 2;
pub const TX_EXPORT_AUTH_KEY_PUBLIC_KEY: u32 = 3;
pub const TX_FINISH_SIGN: u32 = 4;
pub const TX_GENERATE_ASK_KEY_PAIR: u32 = 5;
pub const TX_GENERATE_ATTK_KEY_PAIR: u32 = 6;
pub const TX_GENERATE_AUTH_KEY_PAIR: u32 = 7;
pub const TX_GET_DEVICE_ID: u32 = 8;
pub const TX_HAS_ASK_ALREADY: u32 = 9;
pub const TX_HAS_AUTH_KEY: u32 = 10;
pub const TX_INIT_SIGN: u32 = 11;
pub const TX_REMOVE_ALL_UID_KEY: u32 = 12;
pub const TX_REMOVE_AUTH_KEY: u32 = 13;
pub const TX_VERIFY_ATTK_KEY_PAIR: u32 = 14;

/// Reserved AIDL code for `getInterfaceVersion`.
pub const TX_GET_INTERFACE_VERSION: u32 = 0x00FF_FFFF;

/// Flags the in-tree keymint stubs use as well: clear the reply buffer once it
/// has been read, and keep the transaction local to this process.
const TX_FLAGS: u32 = rsbinder::FLAG_CLEAR_BUF | rsbinder::FLAG_PRIVATE_LOCAL;

/// Reply body of the `SoterData`-returning methods.
#[derive(Debug, Clone)]
pub struct SoterData {
    /// SOTER/TEE error code: 0 = success, -5 = key not found, and TEE codes
    /// such as `0xFFFF0008` pass through unchanged.
    pub error_code: i32,
    /// Payload (PEM block, JSON, device id, signature, ...).
    pub data: Vec<u8>,
    /// The length field the HAL repeats after the payload.
    pub length: i32,
}

impl SoterData {
    /// Payload as text, with the HAL's trailing NUL stripped.
    pub fn text(&self) -> Option<&str> {
        let s = std::str::from_utf8(&self.data).ok()?;
        Some(s.trim_end_matches('\0'))
    }
}

/// Reply body of `initSign`.
#[derive(Debug, Clone, Copy)]
pub struct SoterSession {
    pub error_code: i32,
    pub session: i64,
}

/// A live SOTER HAL proxy.
pub struct Soter {
    inner: Inner,
}

/// 两种形态各存各的：AIDL 那套靠 rsbinder 进程级的 proxy 缓存，HIDL 那套自己
/// 拿着 `/dev/hwbinder` 的连接和句柄。上层不用管区别。
enum Inner {
    Aidl {
        binder: SIBinder,
        backend: Backend,
    },
    Hidl {
        proxy: hidl::HidlSoter,
        backend: Backend,
    },
}

impl Soter {
    /// Resolve the HAL, trying every known vendor backend.
    ///
    /// `Ok(None)` means this device has no SOTER service at all, which is the
    /// "not supported, fall back" case for the caller.  A service that exists
    /// but refuses our descriptor is an error instead: the caller should see the
    /// reason rather than silently come up as "unsupported".
    pub fn open() -> Result<Option<Soter>> {
        let mut failure = None;
        for backend in Backend::ALL {
            match Self::open_backend(backend) {
                Ok(Some(soter)) => return Ok(Some(soter)),
                Ok(None) => {}
                Err(e) => failure = Some(e),
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(None),
        }
    }

    /// One backend: resolve the service, then stamp our descriptor onto the
    /// (process-wide cached) proxy.
    ///
    /// AIDL 那边 stamping 不是可选的 —— HAL 每笔事务都校验 interface token，
    /// 而 rsbinder 从 proxy 的 descriptor 写这个 token；那次 cast 同时是编译期
    /// 检查，确认我们重建的接口跟声明还对得上。HIDL 那边 token 由
    /// [`hidl::HidlSoter::call`] 自己写，服务要么有要么没有，不存在“名字对但
    /// 描述符不对”这种半吊子状态。
    fn open_backend(backend: Backend) -> Result<Option<Soter>> {
        let service = backend.service();
        if backend.is_hidl() {
            let proxy =
                match hidl::HidlSoter::open_named(service, hidl::HIDL_DEFAULT_INSTANCE, service)? {
                    Some(proxy) => proxy,
                    None => return Ok(None),
                };
            return Ok(Some(Soter {
                inner: Inner::Hidl { proxy, backend },
            }));
        }

        let binder = match hub::try_get_service(service) {
            Ok(Some(binder)) => binder,
            Ok(None) | Err(StatusCode::NameNotFound) => return Ok(None),
            Err(e) => bail!("getService({service}) failed: {e:?}"),
        };

        let descriptor_error = |e: rsbinder::StatusCode| {
            anyhow!(
                "{service} rejected interface descriptor {}: {e:?}",
                backend.interface()
            )
        };
        match backend {
            Backend::Trustonic => {
                let _typed: rsbinder::Strong<dyn ITrustonicSoter> =
                    FromIBinder::try_from(binder.clone()).map_err(descriptor_error)?;
            }
            Backend::Qti => {
                let _typed: rsbinder::Strong<dyn ISoter> =
                    FromIBinder::try_from(binder.clone()).map_err(descriptor_error)?;
            }
            Backend::TrustonicHidl | Backend::QtiHidl | Backend::XiaomiHidl => {
                unreachable!("handled above")
            }
        }

        Ok(Some(Soter {
            inner: Inner::Aidl { binder, backend },
        }))
    }

    /// Which vendor backend answered.
    pub fn backend(&self) -> Backend {
        match &self.inner {
            Inner::Aidl { backend, .. } | Inner::Hidl { backend, .. } => *backend,
        }
    }

    /// 这台机器有没有 AIDL 那套 SOTER HAL。
    ///
    /// 只问 servicemanager 要个 handle，不发起任何事务 —— 心跳每 20 秒一次，这里
    /// 不能有副作用（尤其不能碰 TEE 里的签名计数器）。HIDL 那边没有同样廉价的
    /// 探法（要让 hwservicemanager 发一笔 `get`，还得开 `/dev/hwbinder` 并 mmap
    /// 一兆），所以这里只报 AIDL；HIDL-only 的机器靠 [`super::probe`] 真探那一
    /// 步认出来。
    pub(crate) fn service_present() -> bool {
        Backend::ALL
            .iter()
            .filter(|backend| !backend.is_hidl())
            .any(|backend| hub::check_service(backend.service()).is_some())
    }

    /// AIDL 那套的 proxy；走到 HIDL 后端就是内部调用错了。
    fn aidl_binder(&self) -> Result<&SIBinder> {
        match &self.inner {
            Inner::Aidl { binder, .. } => Ok(binder),
            Inner::Hidl { backend, .. } => {
                bail!(
                    "{} is a HIDL backend and has no AIDL proxy",
                    backend.label()
                )
            }
        }
    }

    /// 只在不支持 ATTK 那三个号的后端上拦一下，见 [`Backend::supports_attk_extras`]。
    fn attk_only(&self, op: &str) -> Result<()> {
        let backend = self.backend();
        if backend.supports_attk_extras() {
            return Ok(());
        }
        bail!(
            "{op} is not wired up for the {} SOTER HAL: the vendor's transaction numbers for the \
             ATTK family were never observable there (the host does not use them)",
            backend.label()
        )
    }

    /// Submit one transaction and consume the reply header.
    fn call<F>(&self, code: u32, write_args: F) -> Result<Parcel>
    where
        F: FnOnce(&mut Parcel) -> Result<()>,
    {
        let binder = self.aidl_binder()?;
        let remote: &dyn RemoteProxy = binder
            .as_remote()
            .ok_or_else(|| anyhow!("SOTER proxy is not remote"))?;
        let mut data = remote
            .prepare_transact(true)
            .context("build SOTER request parcel")?;
        write_args(&mut data)?;

        let mut reply = remote
            .submit_transact(code, &data, TX_FLAGS)
            .map_err(|e| anyhow!("SOTER transaction {code} failed: {e:?}"))?
            .ok_or_else(|| anyhow!("SOTER transaction {code} returned no reply"))?;

        read_status(&mut reply)?;
        Ok(reply)
    }

    fn call_data<F>(&self, code: u32, write_args: F) -> Result<SoterData>
    where
        F: FnOnce(&mut Parcel) -> Result<()>,
    {
        let mut reply = self.call(code, write_args)?;
        read_soter_data(&mut reply, self.backend())
    }

    fn call_error<F>(&self, code: u32, write_args: F) -> Result<i32>
    where
        F: FnOnce(&mut Parcel) -> Result<()>,
    {
        let mut reply = self.call(code, write_args)?;
        read_error_code(&mut reply)
    }

    /// Stable device id (32 hex characters).
    pub fn get_device_id(&self) -> Result<SoterData> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_data(TX_GET_DEVICE_ID, |_| Ok(())),
            Inner::Hidl { proxy, .. } => proxy.get_device_id(),
        }
    }

    /// ATTK (attestation key) public key as a PEM block.
    pub fn export_attk_public_key(&self) -> Result<SoterData> {
        self.attk_only("export_attk_public_key")?;
        match &self.inner {
            Inner::Aidl { .. } => self.call_data(TX_EXPORT_ATTK_PUBLIC_KEY, |_| Ok(())),
            Inner::Hidl { proxy, .. } => proxy.export_attk_public_key(),
        }
    }

    /// ASK (app signing key) public key plus TEE signature for `uid`.
    pub fn export_ask_public_key(&self, uid: i32) -> Result<SoterData> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_data(TX_EXPORT_ASK_PUBLIC_KEY, |p| {
                p.write_i32(uid)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.export_ask_public_key(uid),
        }
    }

    /// Per-uid auth key public key.
    pub fn export_auth_key_public_key(&self, uid: i32, alias: &str) -> Result<SoterData> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_data(TX_EXPORT_AUTH_KEY_PUBLIC_KEY, |p| {
                p.write_i32(uid)?;
                p.write::<str>(alias)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.export_auth_key_public_key(uid, alias),
        }
    }

    /// Complete a signing session started by [`Self::init_sign`].
    pub fn finish_sign(&self, session: i64) -> Result<SoterData> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_data(TX_FINISH_SIGN, |p| {
                p.write_i64(session)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.finish_sign(session),
        }
    }

    /// Start a signing session against a per-uid auth key.
    pub fn init_sign(&self, uid: i32, alias: &str, challenge: &str) -> Result<SoterSession> {
        if let Inner::Hidl { proxy, .. } = &self.inner {
            return proxy.init_sign(uid, alias, challenge);
        }
        let backend = self.backend();
        let mut reply = self.call(TX_INIT_SIGN, |p| {
            p.write_i32(uid)?;
            p.write::<str>(alias)?;
            p.write::<str>(challenge)?;
            Ok(())
        })?;
        read_soter_session(&mut reply, backend)
    }

    /// 0 when `uid` already owns an ASK, -5 when it does not.
    pub fn has_ask_already(&self, uid: i32) -> Result<i32> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_error(TX_HAS_ASK_ALREADY, |p| {
                p.write_i32(uid)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.has_ask_already(uid),
        }
    }

    /// 0 when the auth key exists.
    pub fn has_auth_key(&self, uid: i32, alias: &str) -> Result<i32> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_error(TX_HAS_AUTH_KEY, |p| {
                p.write_i32(uid)?;
                p.write::<str>(alias)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.has_auth_key(uid, alias),
        }
    }

    /// Verify the device ATTK key pair.
    pub fn verify_attk_key_pair(&self) -> Result<i32> {
        self.attk_only("verify_attk_key_pair")?;
        match &self.inner {
            Inner::Aidl { .. } => self.call_error(TX_VERIFY_ATTK_KEY_PAIR, |_| Ok(())),
            Inner::Hidl { proxy, .. } => proxy.verify_attk_key_pair(),
        }
    }

    /// Create the ASK for `uid`.  **Device state change.**
    pub fn generate_ask_key_pair(&self, uid: i32) -> Result<i32> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_error(TX_GENERATE_ASK_KEY_PAIR, |p| {
                p.write_i32(uid)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.generate_ask_key_pair(uid),
        }
    }

    /// Create the device ATTK.  **Device state change.**
    ///
    /// The vendor takes the caller id as an AIDL `byte`, which the binder
    /// protocol carries as a 4-byte value (that is how both AOSP and rsbinder
    /// marshal a scalar `byte`).  HIDL 那边声明的是 `uint8_t copyNum`，同様 4 字节。
    pub fn generate_attk_key_pair(&self, user_id: i8) -> Result<i32> {
        self.attk_only("generate_attk_key_pair")?;
        match &self.inner {
            Inner::Aidl { .. } => self.call_error(TX_GENERATE_ATTK_KEY_PAIR, |p| {
                p.write_i32(i32::from(user_id))?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.generate_attk_key_pair(user_id),
        }
    }

    /// Create a per-uid, per-alias auth key.  **Device state change.**
    pub fn generate_auth_key_pair(&self, uid: i32, alias: &str) -> Result<i32> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_error(TX_GENERATE_AUTH_KEY_PAIR, |p| {
                p.write_i32(uid)?;
                p.write::<str>(alias)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.generate_auth_key_pair(uid, alias),
        }
    }

    /// Remove every key belonging to `uid`.  **Device state change.**
    pub fn remove_all_uid_key(&self, uid: i32) -> Result<i32> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_error(TX_REMOVE_ALL_UID_KEY, |p| {
                p.write_i32(uid)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.remove_all_uid_key(uid),
        }
    }

    /// Remove one auth key.  **Device state change.**
    pub fn remove_auth_key(&self, uid: i32, alias: &str) -> Result<i32> {
        match &self.inner {
            Inner::Aidl { .. } => self.call_error(TX_REMOVE_AUTH_KEY, |p| {
                p.write_i32(uid)?;
                p.write::<str>(alias)?;
                Ok(())
            }),
            Inner::Hidl { proxy, .. } => proxy.remove_auth_key(uid, alias),
        }
    }

    /// HAL interface version (every vendor here ships version 1).
    pub fn interface_version(&self) -> Result<i32> {
        match &self.inner {
            Inner::Aidl { .. } => {
                let mut reply = self.call(TX_GET_INTERFACE_VERSION, |_| Ok(()))?;
                reply.read_i32().context("SOTER reply: interface version")
            }
            Inner::Hidl { proxy, .. } => Ok(proxy.interface_version()),
        }
    }
}

/// Read and check the AIDL reply header.
pub(crate) fn read_status(parcel: &mut Parcel) -> Result<()> {
    let status = parcel
        .read::<rsbinder::Status>()
        .context("read SOTER reply status")?;
    if !status.is_ok() {
        bail!("SOTER call failed: {status:?}");
    }
    Ok(())
}

/// Read a `SoterData` reply body (the reply header must be consumed first).
pub(crate) fn read_soter_data(parcel: &mut Parcel, backend: Backend) -> Result<SoterData> {
    // qti 把错误码放在方法的返回值里，parcelable 里只有 data/length。
    let return_code = if backend.has_return_code() {
        Some(parcel.read_i32().context("SOTER reply: return code")?)
    } else {
        None
    };

    let not_null = parcel.read_i32().context("SOTER reply: notNull")?;
    if not_null == 0 {
        bail!("SOTER reply: null payload");
    }
    let total = parcel.read_i32().context("SOTER reply: totalSize")?;
    let error_code = match return_code {
        Some(code) => code,
        None => parcel.read_i32().context("SOTER reply: errorCode")?,
    };
    // The AIDL `byte[]` brings its own length prefix, so the payload is read
    // straight away; `length` is the HAL's copy of that value and follows it.
    let data: Vec<u8> = parcel.read().context("SOTER reply: data")?;
    let length = parcel.read_i32().context("SOTER reply: length")?;

    let len = data.len() as i32;
    if length != len {
        bail!("SOTER reply: payload is {len} bytes but the length field says {length}");
    }
    // The vendor reader seeks to `start + totalSize`, so a layout change would
    // otherwise show up as silently truncated payloads.  Fail loudly instead.
    // `totalSize` counts itself; qti's body has no error code of its own.
    let header = if backend.has_return_code() { 12 } else { 16 };
    let expected = header + ((len + 3) & !3);
    if total != expected {
        bail!("SOTER reply: unexpected totalSize {total}, expected {expected} for {len} bytes");
    }
    Ok(SoterData {
        error_code,
        data,
        length,
    })
}

/// Read a `SoterSession` reply body.
///
/// Both vendors send a 16-byte body (`errorCode` + `session` + alignment), but
/// the field order differs and only the Trustonic one is confirmed against a
/// live device capture.  The Qualcomm declaration (host APK) writes `session`
/// first; since the two readings are both structurally valid, prefer whichever
/// yields a plausible SOTER error code and fall back to the other.
pub(crate) fn read_soter_session(parcel: &mut Parcel, backend: Backend) -> Result<SoterSession> {
    let not_null = parcel.read_i32().context("SOTER reply: notNull")?;
    if not_null == 0 {
        bail!("SOTER reply: null session");
    }
    let total = parcel.read_i32().context("SOTER reply: totalSize")?;
    if total != 16 {
        bail!("SOTER reply: unexpected session size {total}, expected 16");
    }

    if backend == Backend::Trustonic {
        let error_code = parcel.read_i32().context("SOTER reply: errorCode")?;
        let session = parcel.read_i64().context("SOTER reply: session")?;
        return Ok(SoterSession {
            error_code,
            session,
        });
    }

    let start = parcel.data_position();
    if let (Ok(session), Ok(error_code)) = (parcel.read_i64(), parcel.read_i32()) {
        if looks_like_soter_error(error_code) {
            return Ok(SoterSession {
                error_code,
                session,
            });
        }
    }
    parcel.set_data_position(start);
    let error_code = parcel.read_i32().context("SOTER reply: errorCode")?;
    let session = parcel.read_i64().context("SOTER reply: session")?;
    Ok(SoterSession {
        error_code,
        session,
    })
}

/// Read the bare `SoterErrorCode`/`int` reply body.
pub(crate) fn read_error_code(parcel: &mut Parcel) -> Result<i32> {
    parcel.read_i32().context("SOTER reply: error code")
}

/// SOTER error codes are a small closed set (`types.hal`: 0, -1..-29, -200..-204,
/// -1000) plus raw TEE codes, which are `0xFFFFxxxx`.  Used to tell the two
/// `SoterSession` field orders apart.
fn looks_like_soter_error(code: i32) -> bool {
    matches!(code, 0 | -29..=-1 | -204..=-200 | -1000) || (code as u32) >= 0xFFFF_0000
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    use super::*;

    /// 后端名表：每家的服务名/标签不能撞，HIDL 的 token 跟服务名是同一份。
    #[test]
    fn every_backend_has_its_own_service_and_label() {
        let mut seen: Vec<&str> = Vec::new();
        for backend in Backend::ALL {
            assert!(
                !seen.contains(&backend.service()),
                "{} 的服务名跟别的后端撞了",
                backend.label()
            );
            seen.push(backend.service());
            assert_eq!(backend.is_hidl(), backend.label().ends_with("-hidl"));
            if backend.is_hidl() {
                assert_eq!(backend.interface(), backend.service());
            }
        }
        assert_eq!(Backend::XiaomiHidl.service(), hidl::HIDL_XIAOMI_FQNAME);
        assert_eq!(Backend::XiaomiHidl.interface(), hidl::HIDL_XIAOMI_FQNAME);
        assert_eq!(Backend::XiaomiHidl.label(), "xiaomi-hidl");
        assert!(Backend::XiaomiHidl.is_hidl(), "小米只在 HIDL 上出现过");
        assert!(
            !Backend::XiaomiHidl.supports_attk_extras(),
            "小米那边的 2/6/14 没验过，宿主也不发，别当它有"
        );
        assert!(
            !Backend::XiaomiHidl.has_return_code(),
            "HIDL 的回包只有 Status，没有方法返回值那一格"
        );
    }

    #[test]
    fn soter_error_codes_are_recognised() {
        for code in [0, -5, -29, -200, -204, -1000, 0xFFFF_0008u32 as i32] {
            assert!(looks_like_soter_error(code), "{code} should look like one");
        }
        for code in [1, 16, 42, 0x1122_3344, 0x11_2233_4455_6677u64 as i32] {
            assert!(!looks_like_soter_error(code), "{code} should not");
        }
    }
}
