use std::mem::size_of;

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{
    Deserialize, FromIBinder, Parcel, Serialize, SerializeOption, Status, StatusCode, Strong,
    NON_NULL_PARCELABLE_FLAG,
};

use crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse;
use crate::android::system::keystore2::IKeystoreOperation::IKeystoreOperation;
use crate::android::system::keystore2::IKeystoreSecurityLevel::IKeystoreSecurityLevel;
use crate::android::system::keystore2::KeyEntryResponse::KeyEntryResponse;
use crate::android::system::keystore2::KeyParameters::KeyParameters;
use crate::android::system::keystore2::OperationChallenge::OperationChallenge;
use crate::hook::binder::{
    binder_object_header, flat_binder_object, flat_binder_object_handle_or_ptr,
    NativeBinderRetirement, BINDER_TYPE_BINDER, BINDER_TYPE_HANDLE, BINDER_TYPE_WEAK_BINDER,
    BINDER_TYPE_WEAK_HANDLE,
};

use super::parcel_from_ipc_parts;

#[derive(Debug)]
pub struct OwnedReply {
    parcel: Parcel,
    pub offsets: Box<[usize]>,
    pub(crate) native_operation: Option<NativeBinderRetirement>,
}

impl OwnedReply {
    pub fn data_size(&self) -> usize {
        self.parcel.data_size()
    }

    pub fn offsets_size(&self) -> usize {
        self.offsets.len() * size_of::<usize>()
    }

    pub fn data_ptr(&self) -> *const u8 {
        self.parcel.as_ptr()
    }

    pub fn data_mut_ptr(&mut self) -> *mut u8 {
        self.parcel.as_mut_ptr()
    }
}

impl Drop for OwnedReply {
    fn drop(&mut self) {
        if let Some(retirement) = self.native_operation.take() {
            crate::hook::rewrite::drop_synthetic_operation_retirement(retirement);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplyBinderCarrier {
    pub bytes: Vec<u8>,
    pub is_object: bool,
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_success_reply<T: Deserialize>(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<T> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    parcel.read().context("failed to decode reply payload")
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_reply_status(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<Status> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    parcel.read().context("failed to decode binder status")
}

pub fn parse_owned_success_reply<T: Deserialize>(reply: &mut OwnedReply) -> Result<T> {
    unsafe {
        parse_success_reply(
            reply.data_mut_ptr(),
            reply.data_size(),
            if reply.offsets.is_empty() {
                std::ptr::null_mut()
            } else {
                reply.offsets.as_mut_ptr()
            },
            reply.offsets_size(),
        )
    }
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn extract_direct_binder_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_reply_binder_carrier(&mut parcel, data)
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn parse_key_entry_reply(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<(
    ReplyBinderCarrier,
    crate::android::system::keystore2::KeyMetadata::KeyMetadata,
)> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_non_null_parcelable_flag(&mut parcel, "key-entry")?;
    read_sized_reply_payload(&mut parcel, "key-entry payload", |sub_parcel| {
        let carrier = read_reply_binder_carrier(sub_parcel, data)?;
        let metadata = sub_parcel
            .read()
            .context("failed to decode key-entry metadata payload")?;
        Ok((carrier, metadata))
    })
}

/// # Safety
///
/// `data`/`data_size` and `offsets`/`offsets_size` must describe a readable
/// Binder reply parcel for the duration of this call.
pub unsafe fn extract_create_operation_reply_carrier(
    data: *mut u8,
    data_size: usize,
    offsets: *mut usize,
    offsets_size: usize,
) -> Result<ReplyBinderCarrier> {
    let mut parcel = parcel_from_ipc_parts(data, data_size, offsets, offsets_size);
    read_ok_status(&mut parcel)?;
    read_non_null_parcelable_flag(&mut parcel, "create-operation")?;
    read_sized_reply_payload(
        &mut parcel,
        "create-operation binder carrier",
        |sub_parcel| read_reply_binder_carrier(sub_parcel, data),
    )
}

pub fn build_get_security_level_reply(
    binder: Strong<dyn IKeystoreSecurityLevel>,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    let binder_offset = parcel.data_position();
    parcel.write(&binder)?;
    Ok(owned_reply_from_parcel(parcel, [binder_offset]))
}

pub fn build_get_security_level_reply_with_carrier_bytes(
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    let start = parcel.data_position();
    let (placeholder_start, placeholder_end) =
        write_none_binder_placeholder::<dyn IKeystoreSecurityLevel>(&mut parcel)?;
    debug_assert_eq!(start, placeholder_start);
    let binder_len = placeholder_end - placeholder_start;
    if carrier_bytes.len() != binder_len {
        bail!(
            "get-security-level carrier binder size mismatch: expected {}, got {}",
            binder_len,
            carrier_bytes.len()
        );
    }

    let mut reply = owned_reply_from_parcel(parcel, carrier_is_object.then_some(start));
    unsafe {
        std::ptr::copy_nonoverlapping(
            carrier_bytes.as_ptr(),
            reply.data_mut_ptr().add(start),
            carrier_bytes.len(),
        );
    }
    Ok(reply)
}

pub fn build_interface_descriptor_reply(descriptor: &str) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&descriptor.to_string())?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

pub fn build_empty_reply() -> OwnedReply {
    owned_reply_from_parcel(Parcel::new(), std::iter::empty::<usize>())
}

pub fn build_raw_i32_reply(value: i32) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&value)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

pub fn build_null_binder_reply() -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    <rsbinder::SIBinder as SerializeOption>::serialize_option(None, &mut parcel)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

pub fn build_local_binder_carrier_bytes(
    ptr: libc::c_ulong,
    cookie: libc::c_ulong,
    flags: u32,
    stability: i32,
) -> Vec<u8> {
    let object = flat_binder_object {
        hdr: binder_object_header {
            type_: BINDER_TYPE_BINDER,
        },
        flags,
        handle_or_ptr: flat_binder_object_handle_or_ptr { binder: ptr },
        cookie,
    };
    let mut bytes = vec![0u8; size_of::<flat_binder_object>() + size_of::<i32>()];
    unsafe {
        std::ptr::write_unaligned(bytes.as_mut_ptr() as *mut flat_binder_object, object);
        std::ptr::write_unaligned(
            bytes.as_mut_ptr().add(size_of::<flat_binder_object>()) as *mut i32,
            stability,
        );
    }
    bytes
}

fn build_sized_parcelable_reply(
    write_payload: impl FnOnce(&mut Parcel, &mut Option<usize>) -> std::result::Result<(), StatusCode>,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    parcel.sized_write(|sub_parcel| write_payload(sub_parcel, &mut binder_offset))?;
    Ok(owned_reply_from_parcel(parcel, binder_offset))
}

pub fn build_key_entry_reply(reply: KeyEntryResponse) -> Result<OwnedReply> {
    let KeyEntryResponse {
        r#iSecurityLevel,
        r#metadata,
    } = reply;
    build_sized_parcelable_reply(|sub_parcel, binder_offset| {
        match r#iSecurityLevel.as_ref() {
            Some(binder) => {
                *binder_offset = Some(sub_parcel.data_position());
                sub_parcel.write(&Some(binder.clone()))?;
            }
            None => {
                let none: Option<Strong<dyn IKeystoreSecurityLevel>> = None;
                sub_parcel.write(&none)?;
            }
        }
        sub_parcel.write(&r#metadata)?;
        Ok(())
    })
}

pub fn build_key_entry_reply_with_carrier_bytes(
    metadata: crate::android::system::keystore2::KeyMetadata::KeyMetadata,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    build_parcelable_reply_with_carrier_bytes(
        "key-entry",
        carrier_bytes,
        carrier_is_object,
        |sub_parcel| {
            let span = write_none_binder_placeholder::<dyn IKeystoreSecurityLevel>(sub_parcel)?;
            sub_parcel.write(&metadata)?;
            Ok(span)
        },
    )
}

pub fn build_create_operation_reply(reply: CreateOperationResponse) -> Result<OwnedReply> {
    let CreateOperationResponse {
        r#iOperation,
        r#operationChallenge,
        r#parameters,
        r#upgradedBlob,
    } = reply;
    let operation = r#iOperation.as_ref().ok_or(StatusCode::UnexpectedNull)?;
    build_sized_parcelable_reply(|sub_parcel, binder_offset| {
        *binder_offset = Some(sub_parcel.data_position());
        sub_parcel.write(operation)?;
        sub_parcel.write(&r#operationChallenge)?;
        sub_parcel.write(&r#parameters)?;
        sub_parcel.write(&r#upgradedBlob)?;
        Ok(())
    })
}

pub fn build_create_operation_reply_with_carrier_bytes(
    operation_challenge: Option<OperationChallenge>,
    parameters: Option<KeyParameters>,
    upgraded_blob: Option<Vec<u8>>,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
) -> Result<OwnedReply> {
    build_parcelable_reply_with_carrier_bytes(
        "create-operation",
        carrier_bytes,
        carrier_is_object,
        |sub_parcel| {
            let span = write_none_binder_placeholder::<dyn IKeystoreOperation>(sub_parcel)?;
            sub_parcel.write(&operation_challenge)?;
            sub_parcel.write(&parameters)?;
            sub_parcel.write(&upgraded_blob)?;
            Ok(span)
        },
    )
}

pub fn build_plain_reply<T: Serialize>(value: &T) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(value)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

/// HAL 那边 `int xxx(..., out SoterBufferReturn)` 的回复。
///
/// 形状 `[Status][i32 返回值][i32 非空标记][SoterBufferReturn]` —— 那个标记是 AIDL
/// 给 out parcelable 留的，Java 侧就是 `if (readInt() != 0)`；不管成不成功都得写
/// 一个 int，少写后面整体错位，宿主解出来的就是垃圾。
pub fn build_soter_buffer_reply(return_code: i32, data: Option<&[u8]>) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&return_code)?;
    match data {
        Some(bytes) => {
            parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
            write_soter_buffer_return(&mut parcel, bytes)?;
        }
        None => {
            parcel.write(&0i32)?;
        }
    }
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

/// `SoterInitReturn initSign(...)` 的回复：`[Status][i32 非空标记][SoterInitReturn]`。
pub fn build_soter_init_reply(status: i32, session: i64) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    // SoterInitReturn 自己那段：4 字节总长 + status + session，总共 16
    parcel.write(&16i32)?;
    parcel.write(&status)?;
    parcel.write(&session)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

/// `SoterBufferReturn` 的编码：`[i32 本段长度][byte[] data][i32 dataLength]`。
/// 长度含它自己那 4 字节；byte[] 是 AIDL 的写法（4 字节长度 + 数据 + 补到 4 字节）。
fn write_soter_buffer_return(parcel: &mut Parcel, data: &[u8]) -> Result<()> {
    let padded = (data.len() + 3) & !3;
    let total = 4 + 4 + padded + 4;
    parcel.write(&(total as i32))?;
    parcel.write(&data.to_vec())?;
    parcel.write(&(data.len() as i32))?;
    Ok(())
}

pub fn build_void_reply() -> Result<OwnedReply> {
    build_status_reply(&Status::from(StatusCode::Ok))
}

pub fn build_status_reply(status: &Status) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(status)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

fn owned_reply_from_parcel(parcel: Parcel, offsets: impl IntoIterator<Item = usize>) -> OwnedReply {
    OwnedReply {
        parcel,
        offsets: offsets.into_iter().collect(),
        native_operation: None,
    }
}

fn read_ok_status(parcel: &mut Parcel) -> Result<()> {
    let status: Status = parcel.read().context("failed to decode binder status")?;
    if !status.is_ok() {
        bail!("binder status was not OK: {}", status);
    }
    Ok(())
}

fn read_non_null_parcelable_flag(parcel: &mut Parcel, label: &str) -> Result<()> {
    let flag: i32 = parcel
        .read()
        .with_context(|| format!("failed to decode {label} parcelable flag"))?;
    if flag != NON_NULL_PARCELABLE_FLAG {
        bail!("unexpected {label} parcelable flag: {flag}");
    }
    Ok(())
}

fn read_sized_reply_payload<T>(
    parcel: &mut Parcel,
    label: &str,
    mut read_payload: impl FnMut(&mut Parcel) -> Result<T>,
) -> Result<T> {
    let mut value = None;
    let mut read_error = None;
    parcel.sized_read(|sub_parcel| {
        match read_payload(sub_parcel) {
            Ok(payload) => value = Some(payload),
            Err(error) => read_error = Some(error),
        }
        Ok(())
    })?;
    if let Some(error) = read_error {
        return Err(error);
    }

    value.ok_or_else(|| anyhow!("missing {label}"))
}

fn read_reply_binder_carrier(parcel: &mut Parcel, base: *mut u8) -> Result<ReplyBinderCarrier> {
    let start = parcel.data_position();
    let binder_len = size_of::<flat_binder_object>() + size_of::<i32>();
    let end = start
        .checked_add(binder_len)
        .ok_or_else(|| anyhow!("binder carrier length overflow"))?;
    if end > parcel.data_size() {
        bail!(
            "binder carrier truncated: end {} exceeds parcel size {}",
            end,
            parcel.data_size()
        );
    }

    let flat = unsafe { std::ptr::read_unaligned(base.add(start) as *const flat_binder_object) };
    parcel.set_data_position(end);

    let bytes = unsafe { std::slice::from_raw_parts(base.add(start), end - start) }.to_vec();
    Ok(ReplyBinderCarrier {
        bytes,
        is_object: binder_carrier_is_object(&flat),
    })
}

fn binder_carrier_is_object(flat: &flat_binder_object) -> bool {
    match flat.hdr.type_ {
        BINDER_TYPE_BINDER | BINDER_TYPE_WEAK_BINDER => unsafe {
            flat.handle_or_ptr.binder != 0 && flat.cookie != 0
        },
        BINDER_TYPE_HANDLE | BINDER_TYPE_WEAK_HANDLE => unsafe { flat.handle_or_ptr.handle != 0 },
        _ => false,
    }
}

fn build_parcelable_reply_with_carrier_bytes(
    label: &str,
    carrier_bytes: &[u8],
    carrier_is_object: bool,
    write_body: impl FnOnce(&mut Parcel) -> rsbinder::Result<(usize, usize)>,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    let mut binder_offset = None;
    let mut binder_len = 0usize;
    parcel.sized_write(|sub_parcel| {
        let (start, end) = write_body(sub_parcel)?;
        binder_offset = Some(start);
        binder_len = end - start;
        Ok(())
    })?;
    if carrier_bytes.len() != binder_len {
        bail!(
            "{label} carrier binder size mismatch: expected {}, got {}",
            binder_len,
            carrier_bytes.len()
        );
    }

    let start =
        binder_offset.ok_or_else(|| anyhow!("{label} carrier binder offset was not recorded"))?;
    let mut reply = owned_reply_from_parcel(parcel, carrier_is_object.then_some(start));
    unsafe {
        std::ptr::copy_nonoverlapping(
            carrier_bytes.as_ptr(),
            reply.data_mut_ptr().add(start),
            carrier_bytes.len(),
        );
    }
    Ok(reply)
}

fn write_none_binder_placeholder<T>(parcel: &mut Parcel) -> rsbinder::Result<(usize, usize)>
where
    T: FromIBinder + SerializeOption + ?Sized,
{
    let none: Option<Strong<T>> = None;
    let start = parcel.data_position();
    parcel.write(&none)?;
    let end = parcel.data_position();
    Ok((start, end))
}

#[cfg(test)]
mod tests;
