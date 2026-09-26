//! Trustonic SOTER HAL client.
//!
//! The B-side relay agent forwards SOTER operations to the *real* vendor HAL
//! (`vendor.trustonic.hardware.soter.ITrustonicSoter`) on this device.
//!
//! Why the transactions are marshalled by hand instead of through the
//! generated AIDL stubs (the definition lives in
//! `aidl/vendor/trustonic/hardware/soter/`): the vendor HAL's wire form was
//! recovered from the shipped `vendor.trustonic.hardware.soter-V1-ndk.so` and
//! verified against replies captured from a live device, and it carries vendor
//! quirks that the generated stubs do not reproduce — most visibly a leading
//! `totalSize` header on `SoterSession`, whose declaration looks fixed size.
//! Doing it by hand also keeps the reply decoder testable against those
//! captured replies (see [`super::fixtures`]).
//!
//! Wire forms (little endian, `status` is the AIDL reply header):
//!
//! ```text
//! SoterData reply    : [status i32][notNull i32][totalSize i32][errorCode i32]
//!                      [len i32][len bytes, 4-byte padded][length i32]
//! SoterSession reply : [status i32][notNull i32][totalSize i32][errorCode i32][session i64]
//! int reply          : [status i32][value i32]
//! ```
//!
//! `getDeviceId` returns the payload as 32 hex characters plus a NUL byte;
//! `exportAttkPublicKey` returns a PEM block; `exportAskPublicKey` returns
//! `[i32 json length][json][TEE signature]`.  Callers get the raw bytes and
//! decide how to present them (see [`super::handle`]).

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{hub, FromIBinder, Parcel, RemoteProxy, SIBinder, StatusCode};

use crate::vendor::trustonic::hardware::soter::ITrustonicSoter::ITrustonicSoter;

/// Vendor service name, as registered with the (vendor) service manager.
pub const SERVICE: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter/default";

/// Vendor interface descriptor, used as the transaction interface token.
pub const INTERFACE: &str = "vendor.trustonic.hardware.soter.ITrustonicSoter";

// Transaction codes = AIDL declaration order (see the `.aidl` next to this
// module).  These are the vendor's codes, not a guess: they match the Bp stubs
// in `vendor.trustonic.hardware.soter-V1-ndk.so`.
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
}

impl Soter {
    /// Resolve the HAL.
    ///
    /// `Ok(None)` means this device has no SOTER service at all, which is the
    /// "not supported, fall back" case for the caller.
    pub fn open() -> Result<Option<Soter>> {
        let binder = match hub::try_get_service(SERVICE) {
            Ok(Some(binder)) => binder,
            Ok(None) | Err(StatusCode::NameNotFound) => return Ok(None),
            Err(e) => bail!("getService({SERVICE}) failed: {e:?}"),
        };

        // Stamp this interface's descriptor onto the (process-wide cached)
        // proxy: the HAL checks it as the transaction interface token.  The
        // cast doubles as the compile-time check that our reconstruction still
        // matches the generated interface.
        let _typed: rsbinder::Strong<dyn ITrustonicSoter> =
            FromIBinder::try_from(binder.clone())
                .map_err(|e| anyhow!("SOTER HAL rejected interface descriptor: {e:?}"))?;

        Ok(Some(Soter { binder }))
    }

    /// 这台机器有没有 SOTER HAL。
    ///
    /// 心跳上报能力用的，只问 servicemanager 要个 handle，不发起任何事务 ——
    /// 心跳每 20 秒一次，这里不能有副作用（尤其不能碰 TEE 里的签名计数器）。
    pub(crate) fn service_present() -> bool {
        hub::check_service(SERVICE).is_some()
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
        read_soter_data(&mut reply)
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
        read_soter_session(&mut reply)
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

    /// HAL interface version (the vendor ships version 1).
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
pub(crate) fn read_soter_data(parcel: &mut Parcel) -> Result<SoterData> {
    let not_null = parcel.read_i32().context("SOTER reply: notNull")?;
    if not_null == 0 {
        bail!("SOTER reply: null payload");
    }
    let total = parcel.read_i32().context("SOTER reply: totalSize")?;
    let error_code = parcel.read_i32().context("SOTER reply: errorCode")?;
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
    let expected = 16 + ((len + 3) & !3);
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
pub(crate) fn read_soter_session(parcel: &mut Parcel) -> Result<SoterSession> {
    let not_null = parcel.read_i32().context("SOTER reply: notNull")?;
    if not_null == 0 {
        bail!("SOTER reply: null session");
    }
    let total = parcel.read_i32().context("SOTER reply: totalSize")?;
    if total != 16 {
        bail!("SOTER reply: unexpected session size {total}, expected 16");
    }
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
