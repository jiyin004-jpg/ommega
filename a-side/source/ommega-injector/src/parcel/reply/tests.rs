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
