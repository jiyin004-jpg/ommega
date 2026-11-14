use super::*;

#[test]
fn bad_interface_marker_is_rejected() {
    let blob_key = blob_key_descriptor(None);
    let mut request = build_request_with_marker(KEYSTORE_SECURITY_LEVEL_INTERFACE, 0, |parcel| {
        parcel.write(&blob_key).unwrap()
    });
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut request);

    assert_status_code(
        unsafe {
            parse_security_level_request(
                data,
                data_size,
                offsets,
                offsets_size,
                crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey,
            )
        },
        StatusCode::BadType,
    );
}

#[test]
fn generated_key_descriptor_round_trip_preserves_non_null_empty_blob() {
    let key = blob_key_descriptor(Some(Vec::new()));
    let mut parcel = Parcel::new();
    parcel.write(&key).unwrap();
    parcel.set_data_position(0);

    let decoded: KeyDescriptor = parcel.read().unwrap();
    assert_eq!(decoded.blob, Some(Vec::new()));
}

#[test]
fn generated_deserializers_reject_invalid_lengths_and_presence_flags() {
    assert_status_code(
        parse_authorization_request_as_method(AuthorizationMethod::OnDeviceUnlocked, |parcel| {
            parcel.write(&0i32).unwrap();
            parcel.write(&-2i32).unwrap();
        }),
        StatusCode::UnexpectedNull,
    );
    assert_status_code(
        parse_operation_request_with_payload(
            crate::android::system::keystore2::IKeystoreOperation::transactions::r#update,
            |parcel| parcel.write(&-2i32).unwrap(),
        ),
        StatusCode::UnexpectedNull,
    );
    assert_status_code(
        parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#deleteKey,
            |parcel| parcel.write(&2i32).unwrap(),
        ),
        // 标记 2 按 AOSP 的读法算「存在」，于是接着去读描述符本体；
        // 后面什么都没有，报的是 NotEnoughData 而不是「标记非法」。
        StatusCode::NotEnoughData,
    );
}

/// nullable 参数的存在标记：AOSP 只判「非 0」（Java `readInt() != 0`、C++
/// `readInt32() != 0`），所以 2 / -1 / INT_MAX 都得当成「存在」。只认 1 的话，
/// 把标记改成别的值就能让同一条 generateKey 落到系统后端（KEY_NOT_FOUND）。
#[test]
fn non_unit_presence_marker_means_present() {
    for marker in [2i32, -1, i32::MAX] {
        let key = blob_key_descriptor(None);
        let attestation_key = blob_key_descriptor(Some(Vec::new()));
        let parsed = parse_security_level_request_with_payload(
            crate::android::system::keystore2::IKeystoreSecurityLevel::transactions::r#generateKey,
            |parcel| {
                parcel.write(&key).unwrap();
                parcel.write(&marker).unwrap();
                // 只写本体（含 sized_write 的长度），不写它自带的存在标记。
                rsbinder::Parcelable::write_to_parcel(&attestation_key, parcel)
                    .expect("attestation key body");
                parcel.write(&Vec::<KeyParameter>::new()).unwrap();
                parcel.write(&0i32).unwrap();
                parcel.write(&Vec::<u8>::new()).unwrap();
            },
        )
        .unwrap_or_else(|e| panic!("presence marker {marker} should parse: {e:?}"));

        let ParsedSecurityLevelRequest::GenerateKey {
            attestation_key, ..
        } = parsed
        else {
            panic!("generateKey request should parse");
        };
        assert_eq!(
            attestation_key.map(|k| k.blob),
            Some(Some(Vec::new())),
            "presence marker {marker} must read as present"
        );
    }
}
