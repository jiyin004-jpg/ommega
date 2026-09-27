//! Vendor SOTER HAL client.
//!
//! The B-side relay agent forwards SOTER operations to the *real* vendor HAL on
//! this device.  Two vendor backends ship in the wild, and the transaction
//! numbers they use are the same (AIDL declaration order 1..14):
//!
//! ```text
//! trustonic : vendor.trustonic.hardware.soter.ITrustonicSoter/default   (MTK / Kinibi)
//! qti       : vendor.qti.hardware.soter.ISoter/default                  (Qualcomm)
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

/// Trustonic service name, as registered with the (vendor) service manager.
pub const SERVICE: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter/default";

/// Trustonic interface descriptor, used as the transaction interface token.
pub const INTERFACE: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter";

/// Qualcomm service name.
pub const QTI_SERVICE: &str = "vendor.qti.hardware.soter.ISoter/default";

/// Qualcomm interface descriptor.
pub const QTI_INTERFACE: &str = "vendor.qti.hardware.soter.ISoter";

/// Which vendor HAL answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Trustonic,
    Qti,
}

impl Backend {
    /// Resolution order.  Trustonic first because that is what the fleet has
    /// been running on; a device only ever registers one of the two.
    pub const ALL: [Backend; 2] = [Backend::Trustonic, Backend::Qti];

    pub fn service(self) -> &'static str {
        match self {
            Backend::Trustonic => SERVICE,
            Backend::Qti => QTI_SERVICE,
        }
    }

    pub fn interface(self) -> &'static str {
        match self {
            Backend::Trustonic => INTERFACE,
            Backend::Qti => QTI_INTERFACE,
        }
    }

    /// Short name for logs and the capability/probe report.
    pub fn label(self) -> &'static str {
        match self {
            Backend::Trustonic => "trustonic",
            Backend::Qti => "qti",
        }
    }

    /// qti declares the payload methods as `int xxx(..., out SoterData data)`, so
    /// the reply carries the SOTER error code as an extra leading value and the
    /// parcelable itself holds only the payload.
    fn has_return_code(self) -> bool {
        self == Backend::Qti
    }

    /// Whether the ATTK family (codes 2/6/14) can be addressed.
    ///
    /// The host never sends those three, so the vendor's declarations for them
    /// were never observable on Qualcomm, and guessing is not an option: on the
    /// Trustonic HAL code 6 is `generateAttkKeyPair`, i.e. a TEE state change.
    fn supports_attk_extras(self) -> bool {
        self == Backend::Trustonic
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
    binder: SIBinder,
    backend: Backend,
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
    /// Stamping is not optional — the HAL checks the interface token on every
    /// transaction, and rsbinder writes it from the proxy's descriptor.  The
    /// cast doubles as the compile-time check that our reconstruction of the
    /// interface still matches what we declared.
    fn open_backend(backend: Backend) -> Result<Option<Soter>> {
        let service = backend.service();
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
        }

        Ok(Some(Soter { binder, backend }))
    }

    /// Which vendor backend answered.
    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// 这台机器有没有 SOTER HAL。
    ///
    /// 心跳上报能力用的，只问 servicemanager 要个 handle，不发起任何事务 ——
    /// 心跳每 20 秒一次，这里不能有副作用（尤其不能碰 TEE 里的签名计数器）。
    pub(crate) fn service_present() -> bool {
        Backend::ALL
            .iter()
            .any(|backend| hub::check_service(backend.service()).is_some())
    }

    /// 只在不支持 ATTK 那三个号的后端上拦一下，见 [`Backend::supports_attk_extras`]。
    fn attk_only(&self, op: &str) -> Result<()> {
        if self.backend.supports_attk_extras() {
            return Ok(());
        }
        bail!(
            "{op} is not wired up for the {} SOTER HAL: the vendor's transaction numbers for the \
             ATTK family were never observable there (the host does not use them)",
            self.backend.label()
        )
    }

    /// Submit one transaction and consume the reply header.
    fn call<F>(&self, code: u32, write_args: F) -> Result<Parcel>
    where
        F: FnOnce(&mut Parcel) -> Result<()>,
    {
        let remote: &dyn RemoteProxy = self
            .binder
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
        read_soter_data(&mut reply, self.backend)
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
        self.call_data(TX_GET_DEVICE_ID, |_| Ok(()))
    }

    /// ATTK (attestation key) public key as a PEM block.
    pub fn export_attk_public_key(&self) -> Result<SoterData> {
        self.attk_only("export_attk_public_key")?;
        self.call_data(TX_EXPORT_ATTK_PUBLIC_KEY, |_| Ok(()))
    }

    /// ASK (app signing key) public key plus TEE signature for `uid`.
    pub fn export_ask_public_key(&self, uid: i32) -> Result<SoterData> {
        self.call_data(TX_EXPORT_ASK_PUBLIC_KEY, |p| {
            p.write_i32(uid)?;
            Ok(())
        })
    }

    /// Per-uid auth key public key.
    pub fn export_auth_key_public_key(&self, uid: i32, alias: &str) -> Result<SoterData> {
        self.call_data(TX_EXPORT_AUTH_KEY_PUBLIC_KEY, |p| {
            p.write_i32(uid)?;
            p.write::<str>(alias)?;
            Ok(())
        })
    }

    /// Complete a signing session started by [`Self::init_sign`].
    pub fn finish_sign(&self, session: i64) -> Result<SoterData> {
        self.call_data(TX_FINISH_SIGN, |p| {
            p.write_i64(session)?;
            Ok(())
        })
    }

    /// Start a signing session against a per-uid auth key.
    pub fn init_sign(&self, uid: i32, alias: &str, challenge: &str) -> Result<SoterSession> {
        let mut reply = self.call(TX_INIT_SIGN, |p| {
            p.write_i32(uid)?;
            p.write::<str>(alias)?;
            p.write::<str>(challenge)?;
            Ok(())
        })?;
        read_soter_session(&mut reply, self.backend)
    }

    /// 0 when `uid` already owns an ASK, -5 when it does not.
    pub fn has_ask_already(&self, uid: i32) -> Result<i32> {
        self.call_error(TX_HAS_ASK_ALREADY, |p| {
            p.write_i32(uid)?;
            Ok(())
        })
    }

    /// 0 when the auth key exists.
    pub fn has_auth_key(&self, uid: i32, alias: &str) -> Result<i32> {
        self.call_error(TX_HAS_AUTH_KEY, |p| {
            p.write_i32(uid)?;
            p.write::<str>(alias)?;
            Ok(())
        })
    }

    /// Verify the device ATTK key pair.
    pub fn verify_attk_key_pair(&self) -> Result<i32> {
        self.attk_only("verify_attk_key_pair")?;
        self.call_error(TX_VERIFY_ATTK_KEY_PAIR, |_| Ok(()))
    }

    /// Create the ASK for `uid`.  **Device state change.**
    pub fn generate_ask_key_pair(&self, uid: i32) -> Result<i32> {
        self.call_error(TX_GENERATE_ASK_KEY_PAIR, |p| {
            p.write_i32(uid)?;
            Ok(())
        })
    }

    /// Create the device ATTK.  **Device state change.**
    ///
    /// The vendor takes the caller id as an AIDL `byte`, which the binder
    /// protocol carries as a 4-byte value (that is how both AOSP and rsbinder
    /// marshal a scalar `byte`).
    pub fn generate_attk_key_pair(&self, user_id: i8) -> Result<i32> {
        self.attk_only("generate_attk_key_pair")?;
        self.call_error(TX_GENERATE_ATTK_KEY_PAIR, |p| {
            p.write_i32(i32::from(user_id))?;
            Ok(())
        })
    }

    /// Create a per-uid, per-alias auth key.  **Device state change.**
    pub fn generate_auth_key_pair(&self, uid: i32, alias: &str) -> Result<i32> {
        self.call_error(TX_GENERATE_AUTH_KEY_PAIR, |p| {
            p.write_i32(uid)?;
            p.write::<str>(alias)?;
            Ok(())
        })
    }

    /// Remove every key belonging to `uid`.  **Device state change.**
    pub fn remove_all_uid_key(&self, uid: i32) -> Result<i32> {
        self.call_error(TX_REMOVE_ALL_UID_KEY, |p| {
            p.write_i32(uid)?;
            Ok(())
        })
    }

    /// Remove one auth key.  **Device state change.**
    pub fn remove_auth_key(&self, uid: i32, alias: &str) -> Result<i32> {
        self.call_error(TX_REMOVE_AUTH_KEY, |p| {
            p.write_i32(uid)?;
            p.write::<str>(alias)?;
            Ok(())
        })
    }

    /// HAL interface version (both vendors ship version 1).
    pub fn interface_version(&self) -> Result<i32> {
        let mut reply = self.call(TX_GET_INTERFACE_VERSION, |_| Ok(()))?;
        reply.read_i32().context("SOTER reply: interface version")
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
