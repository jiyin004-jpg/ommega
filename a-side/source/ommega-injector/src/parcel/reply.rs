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
    flat_binder_object, NativeBinderRetirement, BINDER_BUFFER_FLAG_HAS_PARENT, BINDER_TYPE_BINDER,
    BINDER_TYPE_HANDLE, BINDER_TYPE_PTR, BINDER_TYPE_WEAK_BINDER, BINDER_TYPE_WEAK_HANDLE,
};

use super::parcel_from_ipc_parts;

#[derive(Debug)]
pub struct OwnedReply {
    parcel: Parcel,
    pub offsets: Box<[usize]>,
    pub(crate) native_operation: Option<NativeBinderRetirement>,
    /// HIDL 答复里 `binder_buffer_object` 的 `buffer` 指向这些堆块：内核不认识这些指针，
    /// 宿主直接按地址读，块必须活到 `BC_FREE_BUFFER` 交回为止。AIDL 那条路留空。
    ///
    /// 没人读这些块，纯靠它活着，所以标记成别管 lint。
    #[allow(dead_code)]
    storage: Vec<Box<[u8]>>,
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

/// HAL 那边 `void/int xxx(..., out SoterBufferReturn)` 的回复。两家形状差一格：
///
/// ```text
/// 联发科 [Status][非空标记][总长][错误码][byte[]][dataLength]   总长 = 16 + pad4
/// 高通   [Status][返回值][非空标记][总长][byte[]][dataLength]   总长 = 12 + pad4
/// ```
///
/// 高通的错误码在方法返回值里，联发科的在 parcelable 里。两家字节数常常一模一样，写错了
/// 宿主不报错、只把垃圾当数据收下，所以不能按长度猜是哪家。`data = None` 时真 HAL 给的
/// 是**非空** parcelable（`[标记=1][总长][错误码][长度=0][长度=0]`），别写成 0 标记。
pub fn build_soter_buffer_reply(
    code: i32,
    data: Option<&[u8]>,
    has_return_code: bool,
) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    if has_return_code {
        parcel.write(&code)?;
    }
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    write_soter_buffer_return(&mut parcel, data.unwrap_or(&[]), code, has_return_code)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

/// `SoterInitReturn initSign(...)` 的回复，两家 AIDL 完全一样，不按家分：
///
/// ```text
/// [Status][非空标记=1][总长=16][错误码][session]
/// ```
///
/// 别多写「方法返回值」那一格、也别把两个字段对调：多一格时宿主 `readTypedObject` 读到的
/// 第一个 i32 正好是错误码，成功时它是 0，整个 parcelable 被判成 null，`initSign` 于是回
/// 默认值（`resultCode = 0`、`session = 0`），现象就是按完指纹「开通失败」。
pub fn build_soter_init_reply(code: i32, session: i64) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    parcel.write(&16i32)?;
    parcel.write(&code)?;
    parcel.write(&session)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

/// App 面向 `ISoterService` 那边：只有返回值的那些（`generate*` / `has*` / `remove*` /
/// `getVersion`），形状就是 `[Status][i32]`。`has*` 那两个布尔也是这一格（0/1）。
pub fn build_app_int_reply(value: i32) -> Result<OwnedReply> {
    build_plain_reply(&value)
}

/// App 面向的 `SoterExportResult`：`[Status][非空标记=1][resultCode][byte[]][dataLength]`。
///
/// 非空标记不能省：客户端代理第一步是 `readInt() != 0 ? CREATOR.createFromParcel() : null`，
/// 少写这 4 字节时读到的「标记」正好是 resultCode，成功时它是 0，整块 parcelable 被判成
/// null，`.exportData` 直接 NPE。`data = None` 写 `-1` + 长度 0（即 `writeByteArray(null)`），
/// 别写成空数组：客户端 `createByteArray()` 只有看到 -1 才回 null，看到 0 是长度为 0 的数组。
pub fn build_app_export_reply(code: i32, data: Option<&[u8]>) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    parcel.write(&code)?;
    match data {
        Some(bytes) => {
            parcel.write(&bytes.to_vec())?;
            parcel.write(&(bytes.len() as i32))?;
        }
        None => {
            parcel.write(&(-1i32))?;
            parcel.write(&0i32)?;
        }
    }
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

/// App 面向的 `SoterSessionResult`：`[Status][非空标记=1][session i64][resultCode i32]`。
/// 字段顺序跟 HAL 的 `SoterInitReturn` 相反（那边 status 在前）。
///
/// 非空标记不能省：少了它客户端拿 session 的高 32 位当标记，而我们的会话号从 1 往上加、
/// 高位恒 0，于是必然判成 null。
pub fn build_app_session_reply(session: i64, code: i32) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    parcel.write(&session)?;
    parcel.write(&code)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

/// App 面向的 `SoterExtraParam`：`[Status][非空标记=1][VAL_INTEGER=1][i32]`
/// （字段本身是个 `Object`，宿主写的是 `writeValue(Integer)`）。
pub fn build_app_extra_param_reply(value: i32) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write(&Status::from(StatusCode::Ok))?;
    parcel.write(&NON_NULL_PARCELABLE_FLAG)?;
    parcel.write(&VAL_INTEGER)?;
    parcel.write(&value)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
}

/// `Parcel.writeValue` 里整数那个类型标（frameworks/base 的 `Parcel::VAL_INTEGER`）。
const VAL_INTEGER: i32 = 1;

/// `SoterBufferReturn` 自己那段：`[总长][(错误码)][byte[]][dataLength]`。总长从它自己那
/// 4 字节算起、盖到最后的 dataLength：联发科把错误码也圈进来（16 = 4+4+4+4，再加补到 4 的
/// 数据），高通没有错误码那一格（12 = 4+4+4）。
fn write_soter_buffer_return(
    parcel: &mut Parcel,
    data: &[u8],
    code: i32,
    has_return_code: bool,
) -> Result<()> {
    let padded = (data.len() + 3) & !3;
    let header = if has_return_code { 12 } else { 16 };
    parcel.write(&((header + padded) as i32))?;
    if !has_return_code {
        parcel.write(&code)?;
    }
    parcel.write(&data.to_vec())?;
    parcel.write(&(data.len() as i32))?;
    Ok(())
}

/// HIDL 的 `hidl_pointer<T>` / `hidl_vec<T>` / `hidl_string` 共用这副 16 字节骨架：
/// `hidl_pointer`(8) + `uint32_t mSize` + `bool mOwnsBuffer` + 3 字节补位。
///
/// 指针槽两个 ABI 都是 8 字节（`union { T*; uint64_t; }`），32 位进程只填低 4 字节、高位
/// 留 0，所以这份布局不用按 ABI 分开写。
pub(crate) const HIDL_STRUCT_SIZE: usize = 16;

fn hidl_struct(pointer: usize, size: u32) -> Box<[u8]> {
    let mut buf = vec![0u8; HIDL_STRUCT_SIZE].into_boxed_slice();
    buf[0..8].copy_from_slice(&(pointer as u64).to_le_bytes());
    buf[8..12].copy_from_slice(&size.to_le_bytes());
    buf
}

/// 往 parcel 里写一个 `binder_buffer_object`。
///
/// 内核 uapi 的字段顺序是 `{hdr{type}, flags, buffer, length, parent, parent_offset}`，
/// 后四个字段的宽度跟 ABI 走（`binder_uintptr_t` / `binder_size_t`：32 位 4 字节、64 位
/// 8 字节）。字段顺序以内核头文件为准。
fn write_hidl_buffer_object(
    parcel: &mut Parcel,
    buffer: usize,
    length: usize,
    flags: u32,
    parent: usize,
    parent_offset: usize,
) -> Result<()> {
    parcel.write_u32(BINDER_TYPE_PTR)?;
    parcel.write_u32(flags)?;
    write_abi_usize(parcel, buffer)?;
    write_abi_usize(parcel, length)?;
    write_abi_usize(parcel, parent)?;
    write_abi_usize(parcel, parent_offset)?;
    Ok(())
}

fn write_abi_usize(parcel: &mut Parcel, value: usize) -> Result<()> {
    if size_of::<usize>() == size_of::<u64>() {
        parcel.write_u64(value as u64)?;
    } else {
        parcel.write_u32(value as u32)?;
    }
    Ok(())
}

/// HIDL 那边 `generates (int32 error, vec<uint8_t> data, soter_size_t length)` 的回复：
/// `[Status i32 = 0][错误码 i32][对象 A][对象 B][长度 u32]`。
///
/// 两个对象都是 `binder_buffer_object`（64 位下 40 字节）：A 指向 16 字节的 `hidl_vec`
/// 结构体，`length` 必须正好是 `sizeof(hidl_vec<uint8_t>)`；B 指向元素本身，`parent` 是 A
/// 在偏移表里的下标（0），`parent_offset` 是结构体里指针那格 `mBuffer` 的偏移（0）。宿主会
/// 读 A 指向的结构体、核对第一个指针是不是 B 的 `buffer`，所以结构体得自己拼好。
/// `data = None` 是空 vector：元素指针和长度都给 0，偏移表只登记 A。
pub fn build_hidl_soter_buffer_reply(error: i32, data: Option<&[u8]>) -> Result<OwnedReply> {
    let payload = data.unwrap_or(&[]);
    let mut storage: Vec<Box<[u8]>> = Vec::new();
    let elements = if payload.is_empty() {
        0
    } else {
        let block: Box<[u8]> = payload.to_vec().into_boxed_slice();
        let pointer = block.as_ptr() as usize;
        storage.push(block);
        pointer
    };
    let structure = hidl_struct(elements, payload.len() as u32);
    let structure_pointer = structure.as_ptr() as usize;
    storage.push(structure);

    let mut parcel = Parcel::new();
    // 回包开头是 `hardware::Status`：一个 i32，0 即成功；非 0 时后面还要跟 String16 message。
    parcel.write_i32(0)?;
    parcel.write_i32(error)?;
    let parent = parcel.data_position();
    write_hidl_buffer_object(&mut parcel, structure_pointer, HIDL_STRUCT_SIZE, 0, 0, 0)?;
    let child = parcel.data_position();
    write_hidl_buffer_object(
        &mut parcel,
        elements,
        payload.len(),
        BINDER_BUFFER_FLAG_HAS_PARENT,
        0,
        0,
    )?;
    parcel.write_u32(payload.len() as u32)?;

    let offsets = if elements == 0 {
        vec![parent]
    } else {
        vec![parent, child]
    };
    Ok(OwnedReply {
        parcel,
        offsets: offsets.into_boxed_slice(),
        native_operation: None,
        storage,
    })
}

/// HIDL 那边 `generates (int32 error, uint64 session)` 的回复：
/// `[Status i32 = 0][错误码 i32][session u64]`。
pub fn build_hidl_soter_init_reply(error: i32, session: i64) -> Result<OwnedReply> {
    let mut parcel = Parcel::new();
    parcel.write_i32(0)?;
    parcel.write_i32(error)?;
    parcel.write_i64(session)?;
    Ok(owned_reply_from_parcel(parcel, std::iter::empty::<usize>()))
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
        storage: Vec::new(),
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
