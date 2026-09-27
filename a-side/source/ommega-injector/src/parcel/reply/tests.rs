use super::*;
use crate::android::hardware::security::keymint::{
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use crate::android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse, IKeystoreOperation::IKeystoreOperation,
    KeyDescriptor::KeyDescriptor, KeyEntryResponse::KeyEntryResponse, KeyMetadata::KeyMetadata,
    KeyParameters::KeyParameters, OperationChallenge::OperationChallenge,
};

fn raw_parts(reply: &mut OwnedReply) -> (*mut u8, usize, *mut usize, usize) {
    (
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

fn null_operation_carrier_bytes() -> Vec<u8> {
    let mut parcel = Parcel::new();
    let (start, end) =
        write_none_binder_placeholder::<dyn IKeystoreOperation>(&mut parcel).unwrap();
    unsafe { std::slice::from_raw_parts(parcel.as_ptr().add(start), end - start).to_vec() }
}

fn assert_status_code<T>(result: Result<T>, expected: StatusCode) {
    let error = match result {
        Ok(_) => panic!("request should fail"),
        Err(error) => error,
    };
    let status = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<StatusCode>().copied());
    assert_eq!(status, Some(expected));
}

#[test]
fn key_entry_reply_round_trip_without_binder() {
    let response = KeyEntryResponse {
        r#iSecurityLevel: None,
        r#metadata: KeyMetadata {
            r#key: KeyDescriptor {
                domain: crate::android::system::keystore2::Domain::Domain::APP,
                nspace: 42,
                alias: Some("alias".to_string()),
                blob: None,
            },
            r#keySecurityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
            r#authorizations: Vec::new(),
            r#certificate: Some(vec![1, 2, 3]),
            r#certificateChain: Some(vec![4, 5, 6]),
            r#modificationTimeMs: 7,
        },
    };
    let mut reply = build_key_entry_reply(response).expect("key entry reply should serialize");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let parsed: KeyEntryResponse =
        unsafe { parse_success_reply(data, data_size, offsets, offsets_size) }.unwrap();
    assert!(parsed.r#iSecurityLevel.is_none());
    assert_eq!(parsed.r#metadata.r#key.nspace, 42);
    assert_eq!(
        parsed.r#metadata.r#certificate.as_deref(),
        Some(&[1, 2, 3][..])
    );
}

#[test]
fn create_operation_reply_rejects_missing_binder() {
    let response = CreateOperationResponse {
        r#iOperation: None,
        r#operationChallenge: Some(OperationChallenge { challenge: 0x1234 }),
        r#parameters: None,
        r#upgradedBlob: Some(vec![9, 8, 7]),
    };
    assert_status_code(
        build_create_operation_reply(response),
        StatusCode::UnexpectedNull,
    );
}

#[test]
fn create_operation_carrier_reply_preserves_operation_challenge() {
    let carrier = null_operation_carrier_bytes();
    let nonce = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut reply = build_create_operation_reply_with_carrier_bytes(
        Some(OperationChallenge { challenge: 0x5678 }),
        Some(KeyParameters {
            keyParameter: vec![KeyParameter {
                tag: Tag::NONCE,
                value: KeyParameterValue::Blob(nonce.clone()),
            }],
        }),
        Some(vec![1, 2, 3]),
        &carrier,
        false,
    )
    .expect("create operation carrier reply should serialize");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let mut parcel = unsafe { parcel_from_ipc_parts(data, data_size, offsets, offsets_size) };
    read_ok_status(&mut parcel).unwrap();
    read_non_null_parcelable_flag(&mut parcel, "create-operation").unwrap();
    let parsed: (
        Option<OperationChallenge>,
        Option<KeyParameters>,
        Option<Vec<u8>>,
    ) = read_sized_reply_payload(&mut parcel, "create-operation test payload", |sub_parcel| {
        read_reply_binder_carrier(sub_parcel, data)?;
        Ok((sub_parcel.read()?, sub_parcel.read()?, sub_parcel.read()?))
    })
    .unwrap();
    assert_eq!(parsed.0.map(|challenge| challenge.challenge), Some(0x5678));
    let parsed_nonce = parsed.1.as_ref().and_then(|parameters| {
        parameters.keyParameter.iter().find_map(|parameter| {
            if parameter.tag == Tag::NONCE {
                match &parameter.value {
                    KeyParameterValue::Blob(value) => Some(value.as_slice()),
                    _ => None,
                }
            } else {
                None
            }
        })
    });
    assert_eq!(parsed_nonce, Some(nonce.as_slice()));
    assert_eq!(parsed.2.as_deref(), Some(&[1, 2, 3][..]));
}

// ---------------------------------------------------------------------------
// SOTER HAReply
// ---------------------------------------------------------------------------

fn soter_bytes(reply: &mut OwnedReply) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(reply.data_mut_ptr(), reply.data_size()).to_vec() }
}

fn le_i32(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[test]
fn qti_soter_buffer_reply_has_the_exact_wire_shape() {
    let mut reply = build_soter_buffer_reply(0, Some(&[0xde, 0xad, 0xbe, 0xef]), true).unwrap();
    let bytes = soter_bytes(&mut reply);
    // Status(4) + 方法返回值(4) + 非空标记(4) + [总长(4) + byte[](8) + dataLength(4)]
    assert_eq!(bytes.len(), 28, "got {bytes:02x?}");
    assert_eq!(le_i32(&bytes, 0), 0, "binder status");
    assert_eq!(le_i32(&bytes, 4), 0, "方法返回值");
    assert_eq!(le_i32(&bytes, 8), 1, "非空标记");
    assert_eq!(
        le_i32(&bytes, 12),
        16,
        "SoterBufferReturn 自己的总长：12 + pad4(4)"
    );
    assert_eq!(le_i32(&bytes, 16), 4, "byte[] 长度");
    assert_eq!(&bytes[20..24], &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(le_i32(&bytes, 24), 4, "dataLength");
}

#[test]
fn trustonic_soter_buffer_reply_has_the_exact_wire_shape() {
    let mut reply = build_soter_buffer_reply(0, Some(&[0xde, 0xad, 0xbe, 0xef]), false).unwrap();
    let bytes = soter_bytes(&mut reply);
    // Status(4) + 非空标记(4) + [总长(4) + 错误码(4) + byte[](8) + dataLength(4)]
    // 注意总长度、字节数和高通那份一模一样，全靠字段位置区分。
    assert_eq!(bytes.len(), 28, "got {bytes:02x?}");
    assert_eq!(le_i32(&bytes, 0), 0, "binder status");
    assert_eq!(le_i32(&bytes, 4), 1, "非空标记就在返回值那一格");
    assert_eq!(le_i32(&bytes, 8), 20, "总长：16 + pad4(4)");
    assert_eq!(le_i32(&bytes, 12), 0, "错误码在 parcelable 里");
    assert_eq!(le_i32(&bytes, 16), 4, "byte[] 长度");
    assert_eq!(&bytes[20..24], &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(le_i32(&bytes, 24), 4, "dataLength");
}

#[test]
fn soter_buffer_return_pads_short_data_to_four() {
    let mut reply = build_soter_buffer_reply(0, Some(&[1, 2, 3]), false).unwrap();
    let bytes = soter_bytes(&mut reply);
    // 数据补到 4 字节，所以总长还是 16 + 4，但两个长度字段都是真实的 3
    assert_eq!(le_i32(&bytes, 8), 20);
    assert_eq!(le_i32(&bytes, 16), 3);
    assert_eq!(&bytes[20..23], &[1, 2, 3]);
    assert_eq!(le_i32(&bytes, 24), 3, "dataLength 是真实长度，不是补完的");
}

#[test]
fn a_missing_payload_still_comes_back_as_a_present_parcelable() {
    // 真 HAL 在「没数据但有错误码」时给的是非空 parcelable（长度那两格是 0），
    // 不是 null 标记 —— 写成 0 标记的话宿主直接当没答过。
    let mut reply = build_soter_buffer_reply(-5, None, false).unwrap();
    let bytes = soter_bytes(&mut reply);
    assert_eq!(bytes.len(), 24, "got {bytes:02x?}");
    assert_eq!(le_i32(&bytes, 4), 1, "非空标记");
    assert_eq!(le_i32(&bytes, 8), 16, "总长还是 16");
    assert_eq!(le_i32(&bytes, 12), -5, "错误码");
    assert_eq!(le_i32(&bytes, 16), 0, "空数据的 byte[] 长度");
    assert_eq!(le_i32(&bytes, 20), 0, "dataLength");
}

#[test]
fn trustonic_soter_init_reply_carries_error_code_then_session() {
    let mut reply = build_soter_init_reply(-5, 0x1122334455667788, false).unwrap();
    let bytes = soter_bytes(&mut reply);
    assert_eq!(bytes.len(), 24, "got {bytes:02x?}");
    assert_eq!(le_i32(&bytes, 0), 0, "binder status");
    assert_eq!(le_i32(&bytes, 4), 1, "非空标记");
    assert_eq!(le_i32(&bytes, 8), 16, "SoterInitReturn 自己的总长");
    assert_eq!(le_i32(&bytes, 12), -5, "错误码在前");
    assert_eq!(
        i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        0x1122334455667788,
        "session 在后"
    );
}

#[test]
fn qti_soter_init_reply_carries_session_then_error_code() {
    let mut reply = build_soter_init_reply(-5, 0x1122334455667788, true).unwrap();
    let bytes = soter_bytes(&mut reply);
    assert_eq!(bytes.len(), 28, "got {bytes:02x?}");
    assert_eq!(le_i32(&bytes, 0), 0, "binder status");
    assert_eq!(le_i32(&bytes, 4), -5, "方法返回值就是错误码");
    assert_eq!(le_i32(&bytes, 8), 1, "非空标记");
    assert_eq!(le_i32(&bytes, 12), 16, "总长一样是 16");
    assert_eq!(
        i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        0x1122334455667788,
        "session 在前"
    );
    assert_eq!(le_i32(&bytes, 24), -5, "parcelable 里再带一份错误码");
}

#[test]
fn a_qti_soter_buffer_reply_reads_back_the_way_the_host_reads_it() {
    let payload = vec![7u8; 200];
    let mut reply = build_soter_buffer_reply(0, Some(&payload), true).unwrap();
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let mut parcel = unsafe { parcel_from_ipc_parts(data, data_size, offsets, offsets_size) };
    // 高通宿主代理（SoterService 里的 `b/a`）：readException() → readInt() → readInt() != 0
    read_ok_status(&mut parcel).unwrap();
    let return_code: i32 = parcel.read().unwrap();
    assert_eq!(return_code, 0);
    let non_null: i32 = parcel.read().unwrap();
    assert_eq!(non_null, 1);
    // 剩下那块得交给 Java 的 createByteArray：rsbinder 的 Vec<u8> 读法跟它不一样
    // （试过，报 NotEnoughData），所以只断言游标确实落在 SoterBufferReturn 开头、
    // 剩余长度也对：4(总长) + 4(array 长) + 200 + 4(dataLength)。
    assert_eq!(
        parcel.data_avail(),
        4 + 4 + ((payload.len() + 3) & !3) + 4,
        "总长 + array 长 + 数据(补到 4) + dataLength"
    );
}

#[test]
fn a_trustonic_soter_buffer_reply_reads_back_the_way_the_host_reads_it() {
    let payload = vec![7u8; 200];
    let mut reply = build_soter_buffer_reply(0, Some(&payload), false).unwrap();
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let mut parcel = unsafe { parcel_from_ipc_parts(data, data_size, offsets, offsets_size) };
    // 联发科宿主代理（`d/a`）：readException() → if (readInt() != 0) —— 没有方法返回值那一格
    read_ok_status(&mut parcel).unwrap();
    let non_null: i32 = parcel.read().unwrap();
    assert_eq!(non_null, 1, "第一个 int 就得是非空标记");
    assert_eq!(
        parcel.data_avail(),
        4 + 4 + 4 + ((payload.len() + 3) & !3) + 4,
        "总长 + 错误码 + array 长 + 数据(补到 4) + dataLength"
    );
}

// ---------------------------------------------------------------------------
// SOTER HAReply —— HIDL 那一套
// ---------------------------------------------------------------------------

/// 内核 uapi 里 `binder_uintptr_t` / `binder_size_t` 就是 32 位 4 字节、64 位 8 字节的
/// typedef，对象里那几格宽度得跟着 ABI 走。
fn abi_usize(bytes: &[u8], at: usize) -> usize {
    if size_of::<usize>() == 8 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize
    } else {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
    }
}

fn abi_usize_width() -> usize {
    size_of::<usize>()
}

fn hidl_object_size() -> usize {
    8 + abi_usize_width() * 4
}

/// `struct binder_buffer_object`：`{hdr{type}, flags, buffer, length, parent, parent_offset}`。
#[derive(Debug, Clone, Copy)]
struct HidlObject {
    type_: u32,
    flags: u32,
    buffer: usize,
    length: usize,
    parent: usize,
    parent_offset: usize,
}

fn read_hidl_object(bytes: &[u8], at: usize) -> HidlObject {
    let width = abi_usize_width();
    HidlObject {
        type_: u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
        flags: u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()),
        buffer: abi_usize(bytes, at + 8),
        length: abi_usize(bytes, at + 8 + width),
        parent: abi_usize(bytes, at + 8 + width * 2),
        parent_offset: abi_usize(bytes, at + 8 + width * 3),
    }
}

/// 照着宿主 libhwbinder 的读法把一笔 HIDL 答复读一遍，返回 (status, 错误码, 数据)。
///
/// 这几下都是真读数器会做的：对象的位置得跟数据游标**正好相等**（`readObject` 就是这么
/// 在偏移表里找的）、对象里的地址得能 deref、带 parent 的那个元素对象还得跟父结构体里
/// 第一个指针一致（`verifyBufferObject` 查这个）。
fn read_back_hidl_buffer_reply(reply: &mut OwnedReply) -> (i32, i32, Vec<u8>) {
    let bytes = soter_bytes(reply);
    let offsets = reply.offsets.to_vec();
    let status = le_i32(&bytes, 0);
    let error = le_i32(&bytes, 4);

    let parent_at = 8;
    let parent = read_hidl_object(&bytes, parent_at);
    let child_at = parent_at + hidl_object_size();
    let child = read_hidl_object(&bytes, child_at);
    let length_field = le_i32(&bytes, child_at + hidl_object_size()) as usize;

    assert_eq!(
        parent.type_, BINDER_TYPE_PTR,
        "结构体那个对象是 buffer 对象"
    );
    assert_eq!(parent.flags, 0, "外面这层不带 parent");
    assert_eq!(
        parent.length, HIDL_STRUCT_SIZE,
        "长度得正好是 sizeof(hidl_vec<uint8_t>)"
    );
    assert_eq!(offsets.first().copied(), Some(parent_at));

    // 结构体：hidl_pointer(8) + uint32 mSize + bool mOwnsBuffer + 3 字节补位
    let head = unsafe { std::slice::from_raw_parts(parent.buffer as *const u8, HIDL_STRUCT_SIZE) };
    let data_pointer = u64::from_le_bytes(head[0..8].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(head[8..12].try_into().unwrap()) as usize;
    assert_eq!(head[12], 0, "借来的 buffer，不接管所有权");
    assert_eq!(head[13..16], [0, 0, 0]);
    assert_eq!(
        data_pointer, child.buffer,
        "结构体里的第一个指针就是元素那块"
    );
    assert_eq!(size, child.length, "uint8 的元素个数就是字节数");
    assert_eq!(length_field, size, "回包最后那个 soter_size_t");

    if child.buffer == 0 {
        assert_eq!(size, 0, "空 vector 才是空指针");
        assert_eq!(
            offsets.len(),
            1,
            "空元素对象不进偏移表（AOSP 也是这么写的）"
        );
        return (status, error, Vec::new());
    }
    assert_eq!(child.type_, BINDER_TYPE_PTR);
    assert_eq!(child.flags, BINDER_BUFFER_FLAG_HAS_PARENT);
    assert_eq!(child.parent, 0, "父对象在偏移表里的下标");
    assert_eq!(child.parent_offset, 0, "offsetof(hidl_vec, mBuffer)");
    assert_eq!(offsets.get(1).copied(), Some(child_at));
    let data = unsafe { std::slice::from_raw_parts(child.buffer as *const u8, size) }.to_vec();
    (status, error, data)
}

#[test]
fn hidl_soter_buffer_reply_has_the_exact_wire_shape() {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let mut reply = build_hidl_soter_buffer_reply(0, Some(&payload)).unwrap();
    let bytes = soter_bytes(&mut reply);
    // Status(4) + error(4) + 对象 A + 对象 B + 长度(4)
    assert_eq!(
        bytes.len(),
        8 + hidl_object_size() * 2 + 4,
        "got {bytes:02x?}"
    );
    let (status, error, data) = read_back_hidl_buffer_reply(&mut reply);
    assert_eq!(status, 0, "hardware::Status::ok()");
    assert_eq!(error, 0);
    assert_eq!(data, payload);
}

#[test]
fn hidl_soter_buffer_reply_keeps_the_error_code_and_an_empty_vector() {
    // 「没数据但有错误码」在 HIDL 这边就是一个空 vector —— 元素指针给 0、长度 0，
    // 读的那侧走的是 readNullableEmbeddedBuffer，天生就认得这种，不是「不写」。
    let mut reply = build_hidl_soter_buffer_reply(-5, None).unwrap();
    let bytes = soter_bytes(&mut reply);
    assert_eq!(
        bytes.len(),
        8 + hidl_object_size() * 2 + 4,
        "got {bytes:02x?}"
    );
    let (status, error, data) = read_back_hidl_buffer_reply(&mut reply);
    assert_eq!(status, 0);
    assert_eq!(error, -5);
    assert!(data.is_empty());
}

#[test]
fn hidl_soter_buffer_reply_keeps_a_long_payload_intact() {
    let payload = vec![7u8; 200];
    let mut reply = build_hidl_soter_buffer_reply(0, Some(&payload)).unwrap();
    let (status, error, data) = read_back_hidl_buffer_reply(&mut reply);
    assert_eq!((status, error), (0, 0));
    assert_eq!(
        data, payload,
        "元素那块是单独一块内存，多少字节都不进 parcel"
    );
}

#[test]
fn hidl_soter_init_reply_carries_error_then_session() {
    let mut reply = build_hidl_soter_init_reply(-5, 0x1122334455667788).unwrap();
    let bytes = soter_bytes(&mut reply);
    assert_eq!(bytes.len(), 16, "got {bytes:02x?}");
    assert_eq!(le_i32(&bytes, 0), 0, "hardware::Status::ok()");
    assert_eq!(le_i32(&bytes, 4), -5, "错误码 ");
    assert_eq!(
        i64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        0x1122334455667788,
        "session"
    );
    assert!(reply.offsets.is_empty(), "没有对象，偏移表是空的");
}
