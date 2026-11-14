// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Generation of certificates and attestation extensions.

use crate::keys::SigningInfo;
use core::time::Duration;
use der::asn1::{OctetStringRef, SetOfVec};
use der::{asn1::Null, oid::AssociatedOid, Enumerated, Sequence};
use der::{Decode, Encode, EncodeValue, ErrorKind, Length};
use flagset::FlagSet;
use kmr_common::crypto::{KeyMaterial, RemoteRootOfTrust};
use kmr_common::{
    crypto, der_err, get_tag_value, km_err, tag, try_to_vec, vec_try_with_capacity, Error,
    ErrorKind as CommonErrorKind,
};
use kmr_common::{get_bool_tag_value, get_opt_tag_value, FallibleAllocExt};
use kmr_wire::{
    keymint,
    keymint::{
        from_raw_tag_value, raw_tag_value, DateTime, ErrorCode, KeyCharacteristics, KeyParam,
        KeyPurpose, Tag,
    },
    KeySizeInBits, RsaExponent,
};
use spki::ObjectIdentifier;
use std::{borrow::Cow, vec::Vec};
use x509_cert::der as x509_der;
use x509_cert::der::asn1::{
    Any as X509Any, BitString as X509BitString, GeneralizedTime as X509GeneralizedTime,
    OctetString as X509OctetString, UtcTime as X509UtcTime,
};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    AlgorithmIdentifierOwned as X509AlgorithmIdentifierOwned,
    ObjectIdentifier as X509ObjectIdentifier,
    SubjectPublicKeyInfoOwned as X509SubjectPublicKeyInfoOwned,
};
use x509_cert::{
    certificate::Version,
    ext::pkix::{constraints::BasicConstraints, KeyUsage, KeyUsages},
    ext::{Extension, Extensions},
    name::Name,
    time::Time,
};

/// OID value for the Android Attestation extension.
pub const ATTESTATION_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
const X509_ATTESTATION_EXTENSION_OID: X509ObjectIdentifier =
    X509ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
/// KeyMint 4.0 起的 EAT（CBOR）形式 attestation extension，内容同 DER 版 KeyDescription。
const X509_EAT_ATTESTATION_EXTENSION_OID: X509ObjectIdentifier =
    X509ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.25");

#[derive(Sequence)]
struct Validity {
    not_before: Time,
    not_after: Time,
}

#[derive(Sequence)]
pub(crate) struct TbsCertificate {
    #[asn1(context_specific = "0", default = "Default::default")]
    version: Version,
    serial_number: SerialNumber,
    signature: X509AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: X509SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    issuer_unique_id: Option<X509BitString>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    subject_unique_id: Option<X509BitString>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<Extensions>,
}

#[derive(Sequence)]
pub(crate) struct Certificate {
    tbs_certificate: TbsCertificate,
    signature_algorithm: X509AlgorithmIdentifierOwned,
    signature: X509BitString,
}

/// Empty value to use in the `RootOfTrust.verifiedBootKey` field in attestations
/// if an empty value was passed to the bootloader.
const EMPTY_BOOT_KEY: [u8; 32] = [0u8; 32];

pub(crate) fn x509_der_error(err: x509_der::Error, context: core::fmt::Arguments<'_>) -> Error {
    log::warn!("{}: {:?} at {:?}", context, err, err.position());
    Error::from(CommonErrorKind::Der(ErrorKind::Failed))
}

/// Build an ASN.1 DER-encodable `Certificate`.
pub(crate) fn certificate(tbs_cert: TbsCertificate, sig_val: &[u8]) -> Result<Certificate, Error> {
    Ok(Certificate {
        signature_algorithm: tbs_cert.signature.clone(),
        tbs_certificate: tbs_cert,
        signature: X509BitString::new(0, sig_val)
            .map_err(|e| x509_der_error(e, format_args!("failed to build BitString")))?,
    })
}

/// Determine whether a remote key's SubjectPublicKeyInfo (SPKI DER) is RSA
/// (as opposed to EC). Only the public key of a relay attestation key is visible
/// here, and the cert's signature OID must match the key type.
pub(crate) fn remote_key_is_rsa(public_key_spki: &[u8]) -> bool {
    use x509_cert::der::Decode;
    match X509SubjectPublicKeyInfoOwned::from_der(public_key_spki) {
        Ok(spki) => spki.algorithm.oid == crypto::rsa::X509_OID,
        Err(_) => false,
    }
}

/// Build an ASN.1 DER-encodable `tbsCertificate`.
pub(crate) fn tbs_certificate<'a>(
    info: &'a Option<SigningInfo>,
    spki_der: &[u8],
    key_usage_ext_bits: &'a [u8],
    basic_constraint_ext_val: Option<&'a [u8]>,
    attestation_ext: Option<&'a [u8]>,
    chars: &'a [KeyParam],
    params: &'a [KeyParam],
) -> Result<TbsCertificate, Error> {
    let cert_serial = tag::get_cert_serial(params)?;
    let cert_subject = tag::get_cert_subject(params)?;
    let not_before = get_tag_value!(params, CertificateNotBefore, ErrorCode::MissingNotBefore)?;
    let not_after = get_tag_value!(params, CertificateNotAfter, ErrorCode::MissingNotAfter)?;

    // `AlgorithmIdentifier` parameters: RSA requires `NULL` (RFC 4055 §5);
    // ECDSA, EdDSA and ML-DSA omit them (RFC 5758 §3.2, RFC 8410 §3, RFC 9881 §2).
    let (sig_alg_oid, parameters) = match info {
        Some(info) => match info.signing_key {
            KeyMaterial::Rsa(_) => (
                crypto::rsa::SHA256_PKCS1_SIGNATURE_OID,
                Some(X509Any::null()),
            ),
            KeyMaterial::Ec(curve, _, _) => (crypto::ec::curve_to_signing_oid(curve), None),
            KeyMaterial::MlDsa(variant, _) => (crypto::mldsa::variant_to_oid(variant), None),
            // Relay attestation key: only the SPKI is visible here; pick the
            // signature OID from its algorithm (EC assumed P-256).
            KeyMaterial::Remote(ref remote) => {
                if remote_key_is_rsa(&remote.public_key) {
                    (
                        crypto::rsa::SHA256_PKCS1_SIGNATURE_OID,
                        Some(X509Any::null()),
                    )
                } else {
                    (crypto::ec::ECDSA_SHA256_SIGNATURE_OID, None)
                }
            }
            _ => {
                return Err(km_err!(
                    UnsupportedAlgorithm,
                    "unexpected cert signing key type"
                ));
            }
        },
        None => {
            // No signing key: the signature stays empty but the field needs a value.
            match tag::get_algorithm(params)? {
                keymint::Algorithm::Rsa => (
                    crypto::rsa::SHA256_PKCS1_SIGNATURE_OID,
                    Some(X509Any::null()),
                ),
                keymint::Algorithm::Ec => (
                    crypto::ec::curve_to_signing_oid(tag::get_ec_curve(chars)?),
                    None,
                ),
                keymint::Algorithm::MlDsa => {
                    let variant = tag::get_mldsa_variant(chars)?;
                    (crypto::mldsa::variant_to_oid(variant), None)
                }
                alg => {
                    return Err(km_err!(
                        UnsupportedAlgorithm,
                        "unexpected algorithm for public key {alg:?}",
                    ))
                }
            }
        }
    };
    let sig_alg_oid = x509_oid(sig_alg_oid)?;
    let spki = <X509SubjectPublicKeyInfoOwned as x509_der::Decode>::from_der(spki_der)
        .map_err(|e| x509_der_error(e, format_args!("failed to parse SubjectPublicKeyInfo")))?;
    let cert_issuer = match &info {
        Some(info) => &info.issuer_subject,
        None => cert_subject,
    };

    // Build certificate extensions
    let key_usage_extension = Extension {
        extn_id: KeyUsage::OID,
        critical: true,
        extn_value: X509OctetString::new(key_usage_ext_bits)
            .map_err(|e| x509_der_error(e, format_args!("failed to build OctetString")))?,
    };

    let mut cert_extensions = vec_try_with_capacity!(3)?;
    cert_extensions.push(key_usage_extension); // capacity enough

    if let Some(basic_constraint_ext_val) = basic_constraint_ext_val {
        let basic_constraint_ext = Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: X509OctetString::new(basic_constraint_ext_val)
                .map_err(|e| x509_der_error(e, format_args!("failed to build OctetString")))?,
        };
        cert_extensions.push(basic_constraint_ext); // capacity enough
    }

    if let Some(attest_extn_val) = attestation_ext {
        let attest_ext = Extension {
            extn_id: X509_ATTESTATION_EXTENSION_OID,
            critical: false,
            extn_value: X509OctetString::new(attest_extn_val)
                .map_err(|e| x509_der_error(e, format_args!("failed to build OctetString")))?,
        };
        cert_extensions.push(attest_ext) // capacity enough
    }

    Ok(TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(cert_serial).map_err(|e| {
            x509_der_error(
                e,
                format_args!("failed to build serial number for {cert_serial:?}"),
            )
        })?,
        signature: X509AlgorithmIdentifierOwned {
            oid: sig_alg_oid,
            parameters,
        },
        issuer: <Name as x509_der::Decode>::from_der(cert_issuer)
            .map_err(|e| x509_der_error(e, format_args!("failed to build issuer")))?,
        validity: Validity {
            not_before: validity_time_from_datetime(not_before)?,
            not_after: validity_time_from_datetime(not_after)?,
        },
        subject: <Name as x509_der::Decode>::from_der(cert_subject)
            .map_err(|e| x509_der_error(e, format_args!("failed to build subject")))?,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(cert_extensions),
    })
}

/// Extract the Subject field from a `keymint::Certificate` as DER-encoded data.
pub(crate) fn extract_subject(cert: &keymint::Certificate) -> Result<Vec<u8>, Error> {
    let cert = <x509_cert::Certificate as x509_der::Decode>::from_der(&cert.encoded_certificate)
        .map_err(|e| km_err!(EncodingError, "failed to parse certificate: {e:?}"))?;
    let subject_data = x509_der::Encode::to_der(cert.tbs_certificate().subject())
        .map_err(|e| km_err!(EncodingError, "failed to DER-encode subject: {e:?}"))?;
    Ok(subject_data)
}

/// 远端链声明的设备身份：brand/device/product/serial/manufacturer/model、
/// verified boot hash、bootPatchlevel 与设备锁状态。
///
/// 子叶子的 ROOT_OF_TRUST 必须逐字沿用远端链，否则与证明密钥对不上，会被判为篡改。
#[derive(Debug, Default, Clone)]
pub(crate) struct RemoteDeviceIdentity {
    pub brand: Option<Vec<u8>>,
    pub device: Option<Vec<u8>>,
    pub product: Option<Vec<u8>>,
    pub serial: Option<Vec<u8>>,
    pub manufacturer: Option<Vec<u8>>,
    pub model: Option<Vec<u8>>,
    pub verified_boot_hash: Option<Vec<u8>>,
    /// RootOfTrust 的 `deviceLocked`。远程证书由 B 端真机签发，本机属性必须与之一致。
    pub device_locked: Option<bool>,
    /// RootOfTrust 里 `verifiedBootState` 的枚举值（0=green 1=yellow 2=orange 3=red）。
    pub verified_boot_state: Option<i64>,
    /// AuthorizationList 的 `bootPatchlevel`（tag 719，YYYYMMDD）。本地证书取本机
    /// boot 镜像日期，与 B 端不一致会被检测器比出来。
    pub boot_patchlevel: Option<i64>,
}

/// 从远端叶子证书抽出设备身份；解析失败返回 `None`，不阻断生成。
pub(crate) fn parse_remote_device_identity(cert_der: &[u8]) -> Option<RemoteDeviceIdentity> {
    let cert = <x509_cert::Certificate as Decode>::from_der(cert_der).ok()?;
    let extensions = cert.tbs_certificate().extensions()?;
    let att_ext = extensions
        .iter()
        .find(|e| e.extn_id == X509_ATTESTATION_EXTENSION_OID)?;
    let att = AttestationExtension::from_der(att_ext.extn_value.as_bytes()).ok()?;

    // 硬件强制优先，其次软件层。
    let pick = |hw: &AuthorizationList<'_>, sw: &AuthorizationList<'_>| -> RemoteDeviceIdentity {
        let ids = if hw.ids.brand.is_some() || hw.ids.model.is_some() {
            &hw.ids
        } else {
            &sw.ids
        };
        RemoteDeviceIdentity {
            brand: ids.brand.as_ref().map(|v| v.to_vec()),
            device: ids.device.as_ref().map(|v| v.to_vec()),
            product: ids.product.as_ref().map(|v| v.to_vec()),
            serial: ids.serial.as_ref().map(|v| v.to_vec()),
            manufacturer: ids.manufacturer.as_ref().map(|v| v.to_vec()),
            model: ids.model.as_ref().map(|v| v.to_vec()),
            verified_boot_hash: None,
            device_locked: None,
            verified_boot_state: None,
            boot_patchlevel: None,
        }
    };
    let mut identity = pick(&att.hw_enforced, &att.sw_enforced);

    let rot_der = att
        .hw_enforced
        .rot_info
        .clone()
        .or_else(|| att.sw_enforced.rot_info.clone());
    if let Some(rot_der) = rot_der {
        if let Ok(rot) = RootOfTrust::from_der(&rot_der) {
            identity.verified_boot_hash = Some(rot.verified_boot_hash.to_vec());
            identity.device_locked = Some(rot.device_locked);
            identity.verified_boot_state = Some(rot.verified_boot_state as i64);
        }
    }
    let boot_patch = |auths: &[KeyParam]| -> Option<i64> {
        auths.iter().find_map(|param| match param {
            KeyParam::BootPatchlevel(value) => Some(i64::from(*value)),
            _ => None,
        })
    };
    identity.boot_patchlevel =
        boot_patch(&att.hw_enforced.auths).or_else(|| boot_patch(&att.sw_enforced.auths));
    Some(identity)
}

pub(crate) fn parse_remote_root_of_trust(
    cert_der: &[u8],
) -> Result<Option<RemoteRootOfTrust>, Error> {
    let cert = <x509_cert::Certificate as Decode>::from_der(cert_der)
        .map_err(|e| km_err!(UnknownError, "parse cert for root-of-trust: {e:?}"))?;
    let Some(extensions) = cert.tbs_certificate().extensions() else {
        return Ok(None);
    };
    let Some(att_ext) = extensions.iter().find(|e| {
        e.extn_id == X509_ATTESTATION_EXTENSION_OID
            || e.extn_id == X509_EAT_ATTESTATION_EXTENSION_OID
    }) else {
        return Ok(None);
    };
    let ext_value = att_ext.extn_value.as_bytes();

    // Fail-open：远端 extension 解不开（keymint 版本或厂商布局不同）时不能
    // 让 attest_key 失败，回 `Ok(None)`，由子证书退回本地 ROT/版本。
    // 远端链可能是 CBOR（EAT）形式，按 DER 解不开，需先按载荷首字节分派；
    // 少了这一支 ROT/版本会被默默丢掉，子证书与 attestation key 对不上，被当成篡改。
    if kmr_common::eat::is_cbor_attestation_extension(ext_value) {
        return match kmr_common::eat::root_of_trust(ext_value) {
            Ok(rot) => Ok(rot),
            Err(e) => {
                log::warn!("remote EAT attestation extension unparsable, ignoring ROT: {e:?}");
                Ok(None)
            }
        };
    }

    let att = match AttestationExtension::from_der(ext_value) {
        Ok(att) => att,
        Err(e) => {
            log::warn!("remote attestation extension unparsable, ignoring ROT: {e:?}");
            return Ok(None);
        }
    };
    let Some(rot_der) = att.hw_enforced.rot_info else {
        return Ok(None);
    };
    let rot = match RootOfTrust::from_der(&rot_der) {
        Ok(rot) => rot,
        Err(e) => {
            log::warn!("remote root-of-trust unparsable, ignoring ROT: {e:?}");
            return Ok(None);
        }
    };
    Ok(Some(RemoteRootOfTrust {
        verified_boot_key: rot.verified_boot_key.to_vec(),
        device_locked: rot.device_locked,
        verified_boot_state: rot.verified_boot_state as i32,
        verified_boot_hash: rot.verified_boot_hash.to_vec(),
        attestation_version: att.attestation_version,
        keymaster_version: att.keymint_version,
    }))
}

fn x509_oid(oid: ObjectIdentifier) -> Result<X509ObjectIdentifier, Error> {
    X509ObjectIdentifier::from_bytes(oid.as_bytes())
        .map_err(|_| Error::from(CommonErrorKind::Der(ErrorKind::OidMalformed)))
}

/// 校验一张「证明密钥」证书是否为硬件 ATTEST_KEY。
///
/// 原生 KeyMint 的签发权限来自 keyblob 的用途而不是 PKIX 的 CA 属性：真机铸出的
/// ATTEST_KEY 叶子 `Key Usage` 只有 Certificate Sign（可能再加 digitalSignature），
/// 且没有 BasicConstraints。所以只认证书里硬件授权的用途：
///
/// * `hw_enforced.purpose` 恰好是 `[ATTEST_KEY]`（混了别的用途就不是证明密钥），
/// * `keymint_security_level` 是 TEE / StrongBox 且与 `attestation_security_level` 一致。
///
/// 缺少 BasicConstraints 不影响判定。
pub(crate) fn validate_native_attestation_issuer(cert_der: &[u8]) -> Result<(), Error> {
    let cert = <x509_cert::Certificate as Decode>::from_der(cert_der)
        .map_err(|e| km_err!(VerificationFailed, "parse attestation issuer: {e:?}"))?;
    let extensions = cert
        .tbs_certificate()
        .extensions()
        .ok_or_else(|| km_err!(IncompatiblePurpose, "attestation issuer has no extensions"))?;
    let extension = extensions
        .iter()
        .find(|extension| extension.extn_id == X509_ATTESTATION_EXTENSION_OID)
        .ok_or_else(|| km_err!(IncompatiblePurpose, "issuer has no hardware attestation"))?;
    let attestation = AttestationExtension::from_der(extension.extn_value.as_bytes())
        .map_err(|e| km_err!(VerificationFailed, "parse native issuer attestation: {e:?}"))?;
    let hardware = matches!(
        attestation.keymint_security_level,
        SecurityLevel::TrustedEnvironment | SecurityLevel::Strongbox
    ) && attestation.attestation_security_level
        == attestation.keymint_security_level;
    let attest_only = attestation
        .hw_enforced
        .auths
        .iter()
        .filter_map(|param| match param {
            KeyParam::Purpose(purpose) => Some(*purpose),
            _ => None,
        })
        .eq([KeyPurpose::AttestKey]);
    if !hardware || !attest_only {
        return Err(km_err!(
            IncompatiblePurpose,
            "issuer lacks exclusive hardware ATTEST_KEY authorization"
        ));
    }
    Ok(())
}

/// 校验 B 端用调用方指定的那把证明密钥签发了子证书。
///
/// 结构对不上就报 `VerificationFailed`，不能回退到其它签发密钥；最后用父证书
/// 公钥实际验一遍子证书签名。
pub(crate) fn validate_remote_delegation(
    chain: &[Vec<u8>],
    issuer: &crate::device::RemoteAttestationKey,
) -> Result<(), Error> {
    use ring::signature;

    let invalid = || km_err!(VerificationFailed, "remote certificate issuer mismatch");
    if chain.len() < 2 {
        return Err(invalid());
    }
    let leaf = <x509_cert::Certificate as Decode>::from_der(&chain[0]).map_err(|_| invalid())?;
    let parent = <x509_cert::Certificate as Decode>::from_der(&chain[1]).map_err(|_| invalid())?;
    let spki = parent.tbs_certificate().subject_public_key_info();
    if spki.to_der().map_err(|_| invalid())? != issuer.public_key
        || parent
            .tbs_certificate()
            .subject()
            .to_der()
            .map_err(|_| invalid())?
            != issuer.issuer_subject_name
        || leaf.tbs_certificate().issuer() != parent.tbs_certificate().subject()
        || leaf.signature_algorithm() != leaf.tbs_certificate().signature()
    {
        return Err(invalid());
    }
    validate_native_attestation_issuer(&chain[1])?;
    let key_oid = spki.algorithm.oid.to_string();
    let signature_oid = leaf.signature_algorithm().oid.to_string();
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<X509ObjectIdentifier>().ok())
        .map(|oid| oid.to_string());
    let algorithm: &dyn signature::VerificationAlgorithm = match (
        key_oid.as_str(),
        curve_oid.as_deref(),
        signature_oid.as_str(),
    ) {
        ("1.2.840.10045.2.1", Some("1.2.840.10045.3.1.7"), "1.2.840.10045.4.3.2") => {
            &signature::ECDSA_P256_SHA256_ASN1
        }
        ("1.2.840.10045.2.1", Some("1.2.840.10045.3.1.7"), "1.2.840.10045.4.3.3") => {
            &signature::ECDSA_P256_SHA384_ASN1
        }
        ("1.2.840.10045.2.1", Some("1.3.132.0.34"), "1.2.840.10045.4.3.2") => {
            &signature::ECDSA_P384_SHA256_ASN1
        }
        ("1.2.840.10045.2.1", Some("1.3.132.0.34"), "1.2.840.10045.4.3.3") => {
            &signature::ECDSA_P384_SHA384_ASN1
        }
        ("1.2.840.113549.1.1.1", _, "1.2.840.113549.1.1.11") => {
            &signature::RSA_PKCS1_2048_8192_SHA256
        }
        ("1.2.840.113549.1.1.1", _, "1.2.840.113549.1.1.12") => {
            &signature::RSA_PKCS1_2048_8192_SHA384
        }
        ("1.2.840.113549.1.1.1", _, "1.2.840.113549.1.1.13") => {
            &signature::RSA_PKCS1_2048_8192_SHA512
        }
        ("1.3.101.112", None, "1.3.101.112") => &signature::ED25519,
        _ => {
            return Err(km_err!(
                IncompatibleAlgorithm,
                "unsupported delegated issuer signature algorithm"
            ))
        }
    };
    let public_key = spki.subject_public_key.as_bytes().ok_or_else(invalid)?;
    let signature = leaf.signature().as_bytes().ok_or_else(invalid)?;
    let tbs = leaf.tbs_certificate().to_der().map_err(|_| invalid())?;
    signature::UnparsedPublicKey::new(algorithm, public_key)
        .verify(&tbs, signature)
        .map_err(|_| {
            km_err!(
                VerificationFailed,
                "remote child certificate signature mismatch"
            )
        })
}

/// Construct x.509-cert::time::Time from `DateTime`.
/// RFC 5280 section 4.1.2.5 requires that UtcTime is used up to 2049
/// and GeneralizedTime from 2050 onwards
fn validity_time_from_datetime(when: DateTime) -> Result<Time, Error> {
    let dt_err = |_| Error::from(CommonErrorKind::Der(ErrorKind::DateTime));
    let secs_since_epoch: i64 = when.ms_since_epoch / 1000;

    if when.ms_since_epoch >= 0 {
        const MAX_UTC_TIME: Duration = Duration::from_secs(2524608000); // 2050-01-01T00:00:00Z

        let duration = Duration::from_secs(u64::try_from(secs_since_epoch).map_err(dt_err)?);
        if duration >= MAX_UTC_TIME {
            Ok(Time::GeneralTime(
                X509GeneralizedTime::from_unix_duration(duration).map_err(|e| {
                    x509_der_error(e, format_args!("failed to build GeneralTime for {when:?}"))
                })?,
            ))
        } else {
            Ok(Time::UtcTime(
                X509UtcTime::from_unix_duration(duration).map_err(|e| {
                    x509_der_error(e, format_args!("failed to build UtcTime for {when:?}"))
                })?,
            ))
        }
    } else {
        Ok(Time::GeneralTime(
            X509GeneralizedTime::from_unix_duration(Duration::from_secs(0)).map_err(|e| {
                x509_der_error(
                    e,
                    format_args!("failed to build GeneralizedTime(0) for {when:?}"),
                )
            })?,
        ))
    }
}

pub(crate) fn asn1_der_encode<T: Encode>(obj: &T) -> Result<Vec<u8>, der::Error> {
    let mut encoded_data = Vec::<u8>::new();
    obj.encode_to_vec(&mut encoded_data)?;
    Ok(encoded_data)
}

pub(crate) fn x509_der_encode<T: x509_der::Encode>(obj: &T) -> Result<Vec<u8>, x509_der::Error> {
    let mut encoded_data = Vec::<u8>::new();
    x509_der::Encode::encode_to_vec(obj, &mut encoded_data)?;
    Ok(encoded_data)
}

/// Build key usage extension bits from the key's allowed purposes.
pub(crate) fn key_usage_extension_bits(params: &[KeyParam]) -> KeyUsage {
    let mut key_usage_bits = FlagSet::<KeyUsages>::default();
    for param in params {
        if let KeyParam::Purpose(purpose) = param {
            match purpose {
                KeyPurpose::Sign | KeyPurpose::Verify => {
                    key_usage_bits |= KeyUsages::DigitalSignature;
                }
                KeyPurpose::Decrypt | KeyPurpose::Encrypt => {
                    key_usage_bits |= KeyUsages::DataEncipherment;
                    key_usage_bits |= KeyUsages::KeyEncipherment;
                }
                KeyPurpose::WrapKey => {
                    key_usage_bits |= KeyUsages::KeyEncipherment;
                }
                KeyPurpose::AgreeKey => {
                    key_usage_bits |= KeyUsages::KeyAgreement;
                }
                KeyPurpose::AttestKey => {
                    key_usage_bits |= KeyUsages::KeyCertSign;
                }
            }
        }
    }
    KeyUsage(key_usage_bits)
}

/// Build basic constraints extension value
pub(crate) fn basic_constraints_ext_value(ca_required: bool) -> BasicConstraints {
    BasicConstraints {
        ca: ca_required,
        path_len_constraint: None,
    }
}

/// Attestation extension contents
///
/// ```asn1
/// KeyDescription ::= SEQUENCE {
///     attestationVersion         INTEGER,
///     attestationSecurityLevel   SecurityLevel,
///     keyMintVersion             INTEGER,
///     keymintSecurityLevel       SecurityLevel,
///     attestationChallenge       OCTET_STRING,
///     uniqueId                   OCTET_STRING,
///     softwareEnforced           AuthorizationList,
///     hardwareEnforced           AuthorizationList,
/// }
/// ```
#[derive(Debug, Clone, Sequence, PartialEq)]
pub(crate) struct AttestationExtension<'a> {
    attestation_version: i32,
    attestation_security_level: SecurityLevel,
    keymint_version: i32,
    keymint_security_level: SecurityLevel,
    #[asn1(type = "OCTET STRING")]
    attestation_challenge: &'a [u8],
    #[asn1(type = "OCTET STRING")]
    unique_id: &'a [u8],
    sw_enforced: AuthorizationList<'a>,
    hw_enforced: AuthorizationList<'a>,
}

impl AssociatedOid for AttestationExtension<'_> {
    const OID: ObjectIdentifier = ATTESTATION_EXTENSION_OID;
}

/// Security level enumeration
/// ```asn1
/// SecurityLevel ::= ENUMERATED {
///     Software                   (0),
///     TrustedEnvironment         (1),
///     StrongBox                  (2),
/// }
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, Enumerated, PartialEq)]
enum SecurityLevel {
    Software = 0,
    TrustedEnvironment = 1,
    Strongbox = 2,
}

/// Build an ASN.1 DER-encoded attestation extension.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attestation_extension<'a>(
    keymint_version: i32,
    challenge: &'a [u8],
    app_id: &'a [u8],
    security_level: keymint::SecurityLevel,
    attestation_ids: Option<&'a crate::AttestationIdInfo>,
    params: &'a [KeyParam],
    chars: &'a [KeyCharacteristics],
    unique_id: &'a Vec<u8>,
    boot_info: &'a keymint::BootInfo,
    additional_attestation_info: &'a [KeyParam],
) -> Result<AttestationExtension<'a>, Error> {
    let mut sw_chars: &[KeyParam] = &[];
    let mut hw_chars: &[KeyParam] = &[];
    for characteristic in chars.iter() {
        match characteristic.security_level {
            keymint::SecurityLevel::Keystore | keymint::SecurityLevel::Software => {
                sw_chars = &characteristic.authorizations
            }
            l if l == security_level => hw_chars = &characteristic.authorizations,
            l => {
                return Err(km_err!(
                    InvalidTag,
                    "found characteristics for unexpected security level {l:?}",
                ))
            }
        }
    }
    let (sw_params, hw_params): (&[KeyParam], &[KeyParam]) = match security_level {
        keymint::SecurityLevel::Software => (params, &[]),
        _ => (&[], params),
    };
    // 两个列表都把 `attestation_ids` 传进去（第三个参数）：那是**已固化的设备身份**，
    // 只用于校验（AOSP 里是 `check_attestation_id!` 宏，对不上回 CannotAttestIds），
    // 不是写进列表的值。真正写进去的是 `AuthorizationList::new` 里从 keygen_params
    // 抽出来的那几项：级别非 Software 时 params 全给了 hw_enforced，所以 710..717
    // 天然只落在 teeEnforced（`device_ids_are_hardware_enforced_only` 钉住了这一点）。
    let mut sw_enforced = AuthorizationList::new(
        sw_chars,
        sw_params,
        attestation_ids,
        None,
        Some(app_id),
        additional_attestation_info,
    )?;
    // 兜底：软件强制列表里一个设备 ID 都不许有。
    //
    // 设备属性（brand/device/product/manufacturer/model）是**硬件层证明的事实**，真机
    // （TEE 和 SE 都一样）只把它写进 teeEnforced；一加/OPPO 工程模式的「StrongBox
    // Attestation Key ID Modify」把 softwareEnforced 里出现 710/711/712/716/717 直接
    // 判 Fail（日志写 Device properties should not be software enforced）。
    // 上面那条路径本来就落不到这儿，这道清空是为了 chars 里万一混进 ID tag（它不属
    // key_characteristic，理论上不会）时叶子仍然只有硬件那侧带设备属性。
    sw_enforced.ids = AttestationIds::default();
    let hw_enforced = AuthorizationList::new(
        hw_chars,
        hw_params,
        attestation_ids,
        Some(RootOfTrust::from(boot_info)),
        None,
        &[],
    )?;
    let sec_level = SecurityLevel::try_from(security_level as u32)
        .map_err(|_| km_err!(InvalidArgument, "invalid security level {security_level:?}"))?;
    let ext = AttestationExtension {
        attestation_version: keymint_version,
        attestation_security_level: sec_level,
        keymint_version,
        keymint_security_level: sec_level,
        attestation_challenge: challenge,
        unique_id,
        sw_enforced,
        hw_enforced,
    };
    Ok(ext)
}

/// Struct for creating ASN.1 DER-serialized `AuthorizationList`. The fields in the ASN.1
/// sequence are categorized into four fields in the struct based on their usage.
/// ```asn1
/// AuthorizationList ::= SEQUENCE {
///     purpose                    [1] EXPLICIT SET OF INTEGER OPTIONAL,
///     algorithm                  [2] EXPLICIT INTEGER OPTIONAL,
///     keySize                    [3] EXPLICIT INTEGER OPTIONAL,
///     blockMode                  [4] EXPLICIT SET OF INTEGER OPTIONAL,  -- Symmetric keys only
///     digest                     [5] EXPLICIT SET OF INTEGER OPTIONAL,
///     padding                    [6] EXPLICIT SET OF INTEGER OPTIONAL,
///     callerNonce                [7] EXPLICIT NULL OPTIONAL,  -- Symmetric keys only
///     minMacLength               [8] EXPLICIT INTEGER OPTIONAL,  -- Symmetric keys only
///     ecCurve                    [10] EXPLICIT INTEGER OPTIONAL,
///     mlDsaVariant               [11] EXPLICIT INTEGER OPTIONAL,
///     rsaPublicExponent          [200] EXPLICIT INTEGER OPTIONAL,
///     mgfDigest                  [203] EXPLICIT SET OF INTEGER OPTIONAL,
///     rollbackResistance         [303] EXPLICIT NULL OPTIONAL,
///     earlyBootOnly              [305] EXPLICIT NULL OPTIONAL,
///     activeDateTime             [400] EXPLICIT INTEGER OPTIONAL,
///     originationExpireDateTime  [401] EXPLICIT INTEGER OPTIONAL,
///     usageExpireDateTime        [402] EXPLICIT INTEGER OPTIONAL,
///     usageCountLimit            [405] EXPLICIT INTEGER OPTIONAL,
///     userSecureId               [502] EXPLICIT INTEGER OPTIONAL,  -- Only used on key import
///     noAuthRequired             [503] EXPLICIT NULL OPTIONAL,
///     userAuthType               [504] EXPLICIT INTEGER OPTIONAL,
///     authTimeout                [505] EXPLICIT INTEGER OPTIONAL,
///     allowWhileOnBody           [506] EXPLICIT NULL OPTIONAL,
///     trustedUserPresenceReq     [507] EXPLICIT NULL OPTIONAL,
///     trustedConfirmationReq     [508] EXPLICIT NULL OPTIONAL,
///     unlockedDeviceReq          [509] EXPLICIT NULL OPTIONAL,
///     creationDateTime           [701] EXPLICIT INTEGER OPTIONAL,
///     origin                     [702] EXPLICIT INTEGER OPTIONAL,
///     rootOfTrust                [704] EXPLICIT RootOfTrust OPTIONAL,
///     osVersion                  [705] EXPLICIT INTEGER OPTIONAL,
///     osPatchLevel               [706] EXPLICIT INTEGER OPTIONAL,
///     attestationApplicationId   [709] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdBrand         [710] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdDevice        [711] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdProduct       [712] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdSerial        [713] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdImei          [714] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdMeid          [715] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdManufacturer  [716] EXPLICIT OCTET_STRING OPTIONAL,
///     attestationIdModel         [717] EXPLICIT OCTET_STRING OPTIONAL,
///     vendorPatchLevel           [718] EXPLICIT INTEGER OPTIONAL,
///     bootPatchLevel             [719] EXPLICIT INTEGER OPTIONAL,
///     deviceUniqueAttestation    [720] EXPLICIT NULL OPTIONAL,
///     attestationIdSecondImei    [723] EXPLICIT OCTET_STRING OPTIONAL,
///     -- moduleHash contains a SHA-256 hash of DER-encoded `Modules`
///     moduleHash                 [724] EXPLICIT OCTET_STRING OPTIONAL,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationList<'a> {
    pub auths: Cow<'a, [KeyParam]>,
    /// Whether to include `UserSecureId` value if found in `auths` when encoding.
    pub encode_sid: bool,
    pub ids: AttestationIds<'a>,
    pub rot_info: Option<Vec<u8>>,
    pub app_id: Option<Cow<'a, [u8]>>,
    pub module_hash: Option<Cow<'a, [u8]>>,
}

/// Tags used in `AuthorizationList` in the schema-defined order.
const AUTHORIZATION_LIST_TAGS: &[Tag] = &[
    Tag::Purpose,
    Tag::Algorithm,
    Tag::KeySize,
    Tag::BlockMode,
    Tag::Digest,
    Tag::Padding,
    Tag::CallerNonce,
    Tag::MinMacLength,
    Tag::EcCurve,
    Tag::MlDsaVariant,
    Tag::RsaPublicExponent,
    Tag::RsaOaepMgfDigest,
    Tag::RollbackResistance,
    Tag::EarlyBootOnly,
    Tag::ActiveDatetime,
    Tag::OriginationExpireDatetime,
    Tag::UsageExpireDatetime,
    Tag::UsageCountLimit,
    Tag::UserSecureId,
    Tag::NoAuthRequired,
    Tag::UserAuthType,
    Tag::AuthTimeout,
    Tag::AllowWhileOnBody,
    Tag::TrustedUserPresenceRequired,
    Tag::TrustedConfirmationRequired,
    Tag::UnlockedDeviceRequired,
    Tag::CreationDatetime,
    Tag::Origin,
    Tag::RootOfTrust,
    Tag::OsVersion,
    Tag::OsPatchlevel,
    Tag::AttestationApplicationId,
    Tag::AttestationIdBrand,
    Tag::AttestationIdDevice,
    Tag::AttestationIdProduct,
    Tag::AttestationIdSerial,
    Tag::AttestationIdImei,
    Tag::AttestationIdMeid,
    Tag::AttestationIdManufacturer,
    Tag::AttestationIdModel,
    Tag::VendorPatchlevel,
    Tag::BootPatchlevel,
    Tag::DeviceUniqueAttestation,
    Tag::AttestationIdSecondImei,
    Tag::ModuleHash,
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttestationIds<'a> {
    brand: Option<Cow<'a, [u8]>>,
    device: Option<Cow<'a, [u8]>>,
    product: Option<Cow<'a, [u8]>>,
    serial: Option<Cow<'a, [u8]>>,
    imei: Option<Cow<'a, [u8]>>,
    imei2: Option<Cow<'a, [u8]>>,
    meid: Option<Cow<'a, [u8]>>,
    manufacturer: Option<Cow<'a, [u8]>>,
    model: Option<Cow<'a, [u8]>>,
}

impl AttestationIds<'_> {
    pub(crate) fn new_from_key_params<'a>(
        keygen_params: &'a [KeyParam],
    ) -> Result<AttestationIds<'a>, Error> {
        let mut ids = AttestationIds::default();
        for param in keygen_params {
            match param {
                KeyParam::AttestationIdBrand(v) => match ids.brand {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag brand")),
                    None => ids.brand = Some(v.into()),
                },
                KeyParam::AttestationIdDevice(v) => match ids.device {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag device")),
                    None => ids.device = Some(v.into()),
                },
                KeyParam::AttestationIdProduct(v) => match ids.product {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag product")),
                    None => ids.product = Some(v.into()),
                },
                KeyParam::AttestationIdSerial(v) => match ids.serial {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag serial")),
                    None => ids.serial = Some(v.into()),
                },
                KeyParam::AttestationIdImei(v) => match ids.imei {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag imei")),
                    None => ids.imei = Some(v.into()),
                },
                KeyParam::AttestationIdSecondImei(v) => match ids.imei2 {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag imei2")),
                    None => ids.imei2 = Some(v.into()),
                },
                KeyParam::AttestationIdMeid(v) => match ids.meid {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag meid")),
                    None => ids.meid = Some(v.into()),
                },
                KeyParam::AttestationIdManufacturer(v) => match ids.manufacturer {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag manufacturer")),
                    None => ids.manufacturer = Some(v.into()),
                },
                KeyParam::AttestationIdModel(v) => match ids.model {
                    Some(_) => return Err(km_err!(InvalidTag, "duplicate tag model")),
                    None => ids.model = Some(v.into()),
                },
                // Ignore all others.
                _ => (),
            }
        }
        Ok(ids)
    }

    pub(crate) fn is_empty(&self) -> bool {
        *self == AttestationIds::default()
    }

    pub(crate) fn check_match(&self, wanted: &crate::AttestationIdInfo) -> Result<(), Error> {
        if self
            .brand
            .as_ref()
            .is_some_and(|brand| *brand != wanted.brand)
        {
            return Err(km_err!(
                CannotAttestIds,
                "attestation ID mismatch for brand"
            ));
        }
        if self
            .device
            .as_ref()
            .is_some_and(|device| *device != wanted.device)
        {
            return Err(km_err!(
                CannotAttestIds,
                "attestation ID mismatch for device"
            ));
        }
        if self
            .product
            .as_ref()
            .is_some_and(|product| *product != wanted.product)
        {
            return Err(km_err!(
                CannotAttestIds,
                "attestation ID mismatch for product"
            ));
        }
        if self
            .serial
            .as_ref()
            .is_some_and(|serial| *serial != wanted.serial)
        {
            return Err(km_err!(
                CannotAttestIds,
                "attestation ID mismatch for serial"
            ));
        }
        // The IMEI fields can match any valid IMEI value.
        if self
            .imei
            .as_ref()
            .is_some_and(|imei| *imei != wanted.imei && *imei != wanted.imei2)
        {
            return Err(km_err!(CannotAttestIds, "attestation ID mismatch for imei"));
        }
        if self
            .imei2
            .as_ref()
            .is_some_and(|imei2| *imei2 != wanted.imei2 && *imei2 != wanted.imei)
        {
            return Err(km_err!(
                CannotAttestIds,
                "attestation ID mismatch for imei2"
            ));
        }
        if self.meid.as_ref().is_some_and(|meid| *meid != wanted.meid) {
            return Err(km_err!(CannotAttestIds, "attestation ID mismatch for meid"));
        }
        if self
            .manufacturer
            .as_ref()
            .is_some_and(|mfr| *mfr != wanted.manufacturer)
        {
            return Err(km_err!(
                CannotAttestIds,
                "attestation ID mismatch for manufacturer"
            ));
        }
        if self
            .model
            .as_ref()
            .is_some_and(|model| *model != wanted.model)
        {
            return Err(km_err!(
                CannotAttestIds,
                "attestation ID mismatch for model"
            ));
        }
        Ok(())
    }
}

impl<'a> AuthorizationList<'a> {
    /// Build an `AuthorizationList` ready for serialization. This constructor will fail if device
    /// ID attestation is required but the relevant IDs are missing or mismatched.  Any
    /// `UserSecureId` values included in `auths` will be ignored on encoding.
    fn new(
        auths: &'a [KeyParam],
        keygen_params: &'a [KeyParam],
        attestation_ids: Option<&crate::AttestationIdInfo>,
        rot_info: Option<RootOfTrust>,
        app_id: Option<&'a [u8]>,
        additional_attestation_info: &'a [KeyParam],
    ) -> Result<Self, Error> {
        let requested_ids = AttestationIds::new_from_key_params(keygen_params)?;
        if !requested_ids.is_empty() {
            match attestation_ids {
                None => return Err(km_err!(CannotAttestIds, "no attestation IDs provisioned")),
                Some(attestation_ids) => requested_ids.check_match(attestation_ids)?,
            }
        }
        let encoded_rot = if let Some(rot) = rot_info {
            Some(
                rot.to_der()
                    .map_err(|e| der_err!(e, "failed to encode RoT"))?,
            )
        } else {
            None
        };
        let module_hash = get_opt_tag_value!(additional_attestation_info, ModuleHash)?;
        Ok(Self {
            auths: auths.into(),
            encode_sid: false,
            ids: requested_ids,
            rot_info: encoded_rot,
            app_id: app_id.map(Into::into),
            module_hash: module_hash.map(Into::into),
        })
    }

    /// Build an `AuthorizationList` using a set of key parameters.
    ///
    /// The checks for the attestation ids are not run here in contrast to `AuthorizationList::new`
    /// because this method is used to construct an `AuthorizationList` in the decode path rather
    /// than in the encode path.
    ///
    /// Any (single) `UserSecureId` value in `key_params` will be included when the
    /// `AuthorizationList` is DER-encoded.
    ///
    /// Note: decode path is currently used only by `KeyMintTa::import_wrapped_key` functionality,
    /// which only uses `auth` field of `AuthorizationList`. Decoding for the whole
    /// `AuthorizationList` is added here for the completeness and anticipating a future use case of
    /// decoding the attestation extension from an X.509 certificate.
    fn new_from_key_params(key_params: Vec<KeyParam>) -> Result<Self, der::Error> {
        let mut auths = Vec::new();
        let mut ids = AttestationIds::default();
        let mut rot: Option<Vec<u8>> = None;
        let mut attest_app_id: Option<Cow<'a, [u8]>> = None;
        let mut module_hash: Option<Cow<'a, [u8]>> = None;

        // Divide key parameters into key characteristics and key generation parameters.
        for param in key_params {
            match param {
                KeyParam::RootOfTrust(encoded_rot) => rot = Some(encoded_rot),
                KeyParam::AttestationApplicationId(app_id) => attest_app_id = Some(app_id.into()),
                KeyParam::AttestationIdBrand(v) => ids.brand = Some(v.into()),
                KeyParam::AttestationIdDevice(v) => ids.device = Some(v.into()),
                KeyParam::AttestationIdProduct(v) => ids.product = Some(v.into()),
                KeyParam::AttestationIdSerial(v) => ids.serial = Some(v.into()),
                KeyParam::AttestationIdImei(v) => ids.imei = Some(v.into()),
                KeyParam::AttestationIdSecondImei(v) => ids.imei2 = Some(v.into()),
                KeyParam::AttestationIdMeid(v) => ids.meid = Some(v.into()),
                KeyParam::AttestationIdManufacturer(v) => ids.manufacturer = Some(v.into()),
                KeyParam::AttestationIdModel(v) => ids.model = Some(v.into()),
                KeyParam::ModuleHash(hash) => module_hash = Some(hash.into()),
                _ => auths.try_push(param).map_err(der_alloc_err)?,
            }
        }
        Ok(AuthorizationList {
            auths: auths.into(),
            encode_sid: true,
            ids,
            rot_info: rot,
            app_id: attest_app_id,
            module_hash,
        })
    }
}

/// Convert an error into a `der::Error` indicating allocation failure.
#[inline]
fn der_alloc_err<T>(_e: T) -> der::Error {
    der::Error::new(der::ErrorKind::Overlength, der::Length::ZERO)
}

/// Implementation of [`der::DecodeValue`] which constructs an AuthorizationList from bytes.
impl<'a> der::DecodeValue<'a> for AuthorizationList<'a> {
    type Error = der::Error;

    fn decode_value<R: der::Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        // TODO: define a MAX_SIZE for AuthorizationList and check whether the actual length from
        // the length field of header is less than the MAX_SIZE

        // Check for an empty sequence
        if header.length().is_zero() {
            return Ok(AuthorizationList {
                auths: Vec::new().into(),
                encode_sid: true,
                ids: AttestationIds::default(),
                rot_info: None,
                app_id: None,
                module_hash: None,
            });
        }
        if decoder.remaining_len() < header.length() {
            return Err(decoder.error(der::ErrorKind::Incomplete {
                expected_len: header.length(),
                actual_len: decoder.remaining_len(),
            }));
        }

        let mut key_params = Vec::new();
        let mut non_consumed_tag: Option<Tag> = None;
        for &tag in AUTHORIZATION_LIST_TAGS {
            if non_consumed_tag.is_none() {
                non_consumed_tag = decode_tag_from_bytes(decoder)?;
            }
            if non_consumed_tag == Some(tag) {
                non_consumed_tag = None;
                // Decode the length of the inner encoding
                let inner_len = Length::decode(decoder)?;
                if decoder.remaining_len() < inner_len {
                    return Err(decoder.error(der::ErrorKind::Incomplete {
                        expected_len: inner_len,
                        actual_len: decoder.remaining_len(),
                    }));
                }
                let next_tlv = decoder.tlv_bytes()?;
                decode_value_from_bytes(tag, next_tlv, &mut key_params)?;
            }
        }
        if non_consumed_tag.is_some() {
            return Err(decoder.error(der::ErrorKind::Incomplete {
                expected_len: Length::ZERO,
                actual_len: decoder.remaining_len(),
            }));
        }

        // Process the key params and construct the `AuthorizationList`
        AuthorizationList::new_from_key_params(key_params)
    }
}

// Macros to decode key parameters from their ASN.1 encoding in one of the forms:
//   field    [<tag>] EXPLICIT SET OF INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT NULL OPTIONAL
//   field    [<tag>] EXPLICIT OCTET STRING OPTIONAL
// There are three different variants for the INTEGER type.

macro_rules! key_params_from_asn1_set_of_integer {
    {$variant:ident, $tlv_bytes:expr, $key_params:expr} => {
        let vals = SetOfVec::<i32>::from_der($tlv_bytes)?;
        for val in vals.into_vec() {
            $key_params.try_push(KeyParam::$variant(val.try_into().map_err(
                |_e| der::ErrorKind::Value {tag: der::Tag::Set})?)).map_err(der_alloc_err)?;
        }
    }
}

macro_rules! key_param_from_asn1_integer {
    {$variant:ident, $int_type:ident, $tlv_bytes:expr, $key_params:expr} => {
        let val = $int_type::from_der($tlv_bytes)?;
        $key_params.try_push(KeyParam::$variant(val.try_into().map_err(
                |_e| der::ErrorKind::Value {tag: der::Tag::Integer})?)).map_err(der_alloc_err)?;
    }
}

macro_rules! key_param_from_asn1_integer_newtype {
    {$variant:ident, $int_type:ident, $newtype:ident, $tlv_bytes:expr, $key_params:expr} => {
        let val = $int_type::from_der($tlv_bytes)?;
        $key_params.try_push(KeyParam::$variant($newtype(val.try_into().map_err(
                |_e| der::ErrorKind::Value {tag: der::Tag::Integer})?))).map_err(der_alloc_err)?;
    }
}

macro_rules! key_param_from_asn1_null {
    {$variant:ident, $tlv_bytes:expr, $key_params:expr} => {
        Null::from_der($tlv_bytes)?;
        $key_params.try_push(KeyParam::$variant).map_err(der_alloc_err)?;
    };
}

macro_rules! key_param_from_asn1_integer_datetime {
    {$variant:ident, $tlv_bytes:expr, $key_params:expr} => {
        let val = i64::from_der($tlv_bytes)?;
        $key_params
            .try_push(KeyParam::$variant(DateTime{ms_since_epoch: val}))
            .map_err(der_alloc_err)?;
    };
}

macro_rules! key_param_from_asn1_octet_string {
    {$variant:ident, $tlv_bytes:expr, $key_params:expr} => {
        let val = <&OctetStringRef>::from_der($tlv_bytes)?;
        $key_params.try_push(KeyParam::$variant(try_to_vec(val.as_bytes())
                                                .map_err(der_alloc_err)?)).map_err(der_alloc_err)?;
    };
}

fn decode_value_from_bytes(
    tag: keymint::Tag,
    tlv_bytes: &[u8],
    key_params: &mut Vec<KeyParam>,
) -> Result<(), der::Error> {
    match tag {
        Tag::Purpose => {
            key_params_from_asn1_set_of_integer!(Purpose, tlv_bytes, key_params);
        }
        Tag::Algorithm => {
            key_param_from_asn1_integer!(Algorithm, i32, tlv_bytes, key_params);
        }
        Tag::KeySize => {
            key_param_from_asn1_integer_newtype!(
                KeySize,
                u32,
                KeySizeInBits,
                tlv_bytes,
                key_params
            );
        }
        Tag::BlockMode => {
            key_params_from_asn1_set_of_integer!(BlockMode, tlv_bytes, key_params);
        }
        Tag::Digest => {
            key_params_from_asn1_set_of_integer!(Digest, tlv_bytes, key_params);
        }
        Tag::Padding => {
            key_params_from_asn1_set_of_integer!(Padding, tlv_bytes, key_params);
        }
        Tag::CallerNonce => {
            key_param_from_asn1_null!(CallerNonce, tlv_bytes, key_params);
        }
        Tag::MinMacLength => {
            key_param_from_asn1_integer!(MinMacLength, u32, tlv_bytes, key_params);
        }
        Tag::EcCurve => {
            key_param_from_asn1_integer!(EcCurve, i32, tlv_bytes, key_params);
        }
        Tag::MlDsaVariant => {
            key_param_from_asn1_integer!(MlDsaVariant, i32, tlv_bytes, key_params);
        }
        Tag::RsaPublicExponent => {
            key_param_from_asn1_integer_newtype!(
                RsaPublicExponent,
                u64,
                RsaExponent,
                tlv_bytes,
                key_params
            );
        }
        Tag::RsaOaepMgfDigest => {
            key_params_from_asn1_set_of_integer!(RsaOaepMgfDigest, tlv_bytes, key_params);
        }
        Tag::RollbackResistance => {
            key_param_from_asn1_null!(RollbackResistance, tlv_bytes, key_params);
        }
        Tag::EarlyBootOnly => {
            key_param_from_asn1_null!(EarlyBootOnly, tlv_bytes, key_params);
        }
        Tag::ActiveDatetime => {
            key_param_from_asn1_integer_datetime!(ActiveDatetime, tlv_bytes, key_params);
        }
        Tag::OriginationExpireDatetime => {
            key_param_from_asn1_integer_datetime!(OriginationExpireDatetime, tlv_bytes, key_params);
        }
        Tag::UsageExpireDatetime => {
            key_param_from_asn1_integer_datetime!(UsageExpireDatetime, tlv_bytes, key_params);
        }
        Tag::UsageCountLimit => {
            key_param_from_asn1_integer!(UsageCountLimit, u32, tlv_bytes, key_params);
        }
        Tag::UserSecureId => {
            // Note that the `UserSecureId` tag has tag type `ULONG_REP` indicating that it can be
            // repeated, but the ASN.1 schema for `AuthorizationList` has this field as having type
            // `INTEGER` not `SET OF INTEGER`. This reflects the special usage of `UserSecureId`
            // in `importWrappedKey()` processing.
            key_param_from_asn1_integer!(UserSecureId, u64, tlv_bytes, key_params);
        }
        Tag::NoAuthRequired => {
            key_param_from_asn1_null!(NoAuthRequired, tlv_bytes, key_params);
        }
        Tag::UserAuthType => {
            key_param_from_asn1_integer!(UserAuthType, u32, tlv_bytes, key_params);
        }
        Tag::AuthTimeout => {
            key_param_from_asn1_integer!(AuthTimeout, u32, tlv_bytes, key_params);
        }
        Tag::AllowWhileOnBody => {
            key_param_from_asn1_null!(AllowWhileOnBody, tlv_bytes, key_params);
        }
        Tag::TrustedUserPresenceRequired => {
            key_param_from_asn1_null!(TrustedUserPresenceRequired, tlv_bytes, key_params);
        }
        Tag::TrustedConfirmationRequired => {
            key_param_from_asn1_null!(TrustedConfirmationRequired, tlv_bytes, key_params);
        }
        Tag::UnlockedDeviceRequired => {
            key_param_from_asn1_null!(UnlockedDeviceRequired, tlv_bytes, key_params);
        }
        Tag::CreationDatetime => {
            key_param_from_asn1_integer_datetime!(CreationDatetime, tlv_bytes, key_params);
        }
        Tag::Origin => {
            key_param_from_asn1_integer!(Origin, i32, tlv_bytes, key_params);
        }
        Tag::RootOfTrust => {
            key_params
                .try_push(KeyParam::RootOfTrust(
                    try_to_vec(tlv_bytes).map_err(der_alloc_err)?,
                ))
                .map_err(der_alloc_err)?;
        }
        Tag::OsVersion => {
            key_param_from_asn1_integer!(OsVersion, u32, tlv_bytes, key_params);
        }
        Tag::OsPatchlevel => {
            key_param_from_asn1_integer!(OsPatchlevel, u32, tlv_bytes, key_params);
        }
        Tag::AttestationApplicationId => {
            key_param_from_asn1_octet_string!(AttestationApplicationId, tlv_bytes, key_params);
        }
        Tag::AttestationIdBrand => {
            key_param_from_asn1_octet_string!(AttestationIdBrand, tlv_bytes, key_params);
        }
        Tag::AttestationIdDevice => {
            key_param_from_asn1_octet_string!(AttestationIdDevice, tlv_bytes, key_params);
        }
        Tag::AttestationIdProduct => {
            key_param_from_asn1_octet_string!(AttestationIdProduct, tlv_bytes, key_params);
        }
        Tag::AttestationIdSerial => {
            key_param_from_asn1_octet_string!(AttestationIdSerial, tlv_bytes, key_params);
        }
        Tag::AttestationIdImei => {
            key_param_from_asn1_octet_string!(AttestationIdImei, tlv_bytes, key_params);
        }
        Tag::AttestationIdSecondImei => {
            key_param_from_asn1_octet_string!(AttestationIdSecondImei, tlv_bytes, key_params);
        }
        Tag::AttestationIdMeid => {
            key_param_from_asn1_octet_string!(AttestationIdMeid, tlv_bytes, key_params);
        }
        Tag::AttestationIdManufacturer => {
            key_param_from_asn1_octet_string!(AttestationIdManufacturer, tlv_bytes, key_params);
        }
        Tag::AttestationIdModel => {
            key_param_from_asn1_octet_string!(AttestationIdModel, tlv_bytes, key_params);
        }
        Tag::VendorPatchlevel => {
            key_param_from_asn1_integer!(VendorPatchlevel, u32, tlv_bytes, key_params);
        }
        Tag::BootPatchlevel => {
            key_param_from_asn1_integer!(BootPatchlevel, u32, tlv_bytes, key_params);
        }
        Tag::DeviceUniqueAttestation => {
            key_param_from_asn1_null!(DeviceUniqueAttestation, tlv_bytes, key_params);
        }
        Tag::ModuleHash => {
            key_param_from_asn1_octet_string!(ModuleHash, tlv_bytes, key_params);
        }
        _ => {
            // Note: `der::Error` or `der::ErrorKind` is not expressive enough for decoding
            // tags in high tag form. Documentation of this error kind does not match this
            // situation. But we use the `der::ErrorKind` as close as possible.
            return Err(der::ErrorKind::TagNumberInvalid.into());
        }
    }
    Ok(())
}

/// Decode the tag of a field in AuthorizationList.
fn decode_tag_from_bytes<'a, R: der::Reader<'a>>(
    decoder: &mut R,
) -> Result<Option<keymint::Tag>, der::Error> {
    // Avoid reading for tags beyond the size of the encoded AuthorizationList
    if decoder.remaining_len() == Length::ZERO {
        return Ok(None);
    }
    let b1 = decoder.read_byte()?;
    if b1 & 0b11100000 != 0b10100000 {
        // KeyMint tags should be encoded as context-specific (0b10......) constructed
        // (0b..1.....) ASN.1 tag values.
        return Err(der::ErrorKind::TagNumberInvalid.into());
    }
    let b1 = b1 & 0b00011111u8;
    let raw_tag = if b1 == 0b00011111u8 {
        // High tag form, read the next byte
        let b2 = decoder.read_byte()?;
        if b2 & 0x80u8 == 0x80u8 {
            // Encoded tag length is 3, read the next byte
            let b3 = decoder.read_byte()?;
            let tag_byte: u16 = ((b2 ^ 0x80u8) as u16) << 7;
            (tag_byte | b3 as u16) as u32
        } else {
            b2 as u32
        }
    } else {
        b1 as u32
    };
    let tag = from_raw_tag_value(raw_tag);
    if tag == Tag::Invalid {
        // Note: der::Error or der::ErrorKind is not expressive enough for decoding tags
        // in high tag form. Documentation of this error kind does not match this situation.
        // Find a better way to express the error.
        Err(der::ErrorKind::TagNumberInvalid.into())
    } else {
        Ok(Some(tag))
    }
}

// Macros to extract key characteristics for ASN.1 encoding into one of the forms:
//   field    [<tag>] EXPLICIT SET OF INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT INTEGER OPTIONAL
//   field    [<tag>] EXPLICIT NULL OPTIONAL
//   field    [<tag>] EXPLICIT OCTET STRING OPTIONAL
// together with an extra variant that deals with OCTET STRING values that must match
// a provisioned attestation ID value.
macro_rules! asn1_set_of_integer {
    { $params:expr, $variant:ident } => {
        {
            let mut results = Vec::new();
            for param in $params.as_ref() {
                if let KeyParam::$variant(v) = param {
                    results.try_push(v.clone()).map_err(der_alloc_err)?;
                }
            }
            if !results.is_empty() {
                // The input key characteristics have been sorted and so are in numerical order, but
                // may contain duplicates that need to be weeded out.
                let mut set = der::asn1::SetOfVec::new();
                let mut prev_val = None;
                for val in results {
                    let val = val as i64;
                    if let Some(prev) = prev_val {
                        if prev == val {
                            continue; // skip duplicate
                        }
                    }
                    set.insert_ordered(val)?;
                    prev_val = Some(val);
                }
                Some(ExplicitTaggedValue::new(Tag::$variant, set))
            } else {
                None
            }
        }
    }
}
macro_rules! asn1_integer {
    { $params:expr, $variant:ident } => {
        if let Some(val) = get_opt_tag_value!($params.as_ref(), $variant).map_err(|_e| {
            log::warn!("failed to get {} value for ext", stringify!($variant));
            der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
        })? {
            Some(ExplicitTaggedValue::new(Tag::$variant, *val as i64))
        } else {
            None
        }
    }
}
macro_rules! asn1_integer_newtype {
    { $params:expr, $variant:ident } => {
        if let Some(val) = get_opt_tag_value!($params.as_ref(), $variant).map_err(|_e| {
            log::warn!("failed to get {} value for ext", stringify!($variant));
            der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
        })? {
            Some(ExplicitTaggedValue::new(Tag::$variant, val.0 as i64))
        } else {
            None
        }
    }
}
macro_rules! asn1_integer_datetime {
    { $params:expr, $variant:ident } => {
        if let Some(val) = get_opt_tag_value!($params.as_ref(), $variant).map_err(|_e| {
            log::warn!("failed to get {} value for ext", stringify!($variant));
            der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
        })? {
            Some(ExplicitTaggedValue::new(Tag::$variant, val.ms_since_epoch))
        } else {
            None
        }
    }
}
macro_rules! asn1_null {
    { $params:expr, $variant:ident } => {
        if get_bool_tag_value!($params.as_ref(), $variant).map_err(|_e| {
            log::warn!("failed to get {} value for ext", stringify!($variant));
            der::Error::new(der::ErrorKind::Failed, der::Length::ZERO)
        })? {
            Some(ExplicitTaggedValue::new(Tag::$variant, ()))
        } else {
            None
        }
    }
}

fn asn1_octet_string(
    tag: Tag,
    val: Option<&[u8]>,
) -> der::Result<Option<ExplicitTaggedValue<&OctetStringRef>>> {
    match val {
        Some(val) => Ok(Some(ExplicitTaggedValue::new(
            tag,
            OctetStringRef::new(val)?,
        ))),
        None => Ok(None),
    }
}

fn asn1_root_of_trust(
    tag: Tag,
    rot: Option<&[u8]>,
) -> der::Result<Option<ExplicitTaggedValue<RootOfTrust<'_>>>> {
    match rot {
        Some(rot) => Ok(Some(ExplicitTaggedValue::new(
            tag,
            RootOfTrust::from_der(rot)?,
        ))),
        None => Ok(None),
    }
}

fn asn1_val<T: Encode>(
    val: Option<ExplicitTaggedValue<T>>,
    writer: &mut impl der::Writer,
) -> der::Result<()> {
    match val {
        Some(val) => val.encode(writer),
        None => Ok(()),
    }
}

fn asn1_len<T: Encode>(val: Option<ExplicitTaggedValue<T>>) -> der::Result<Length> {
    match val {
        Some(val) => val.encoded_len(),
        None => Ok(Length::ZERO),
    }
}

impl<'a> Sequence<'a> for AuthorizationList<'a> {}

impl EncodeValue for AuthorizationList<'_> {
    fn value_len(&self) -> der::Result<Length> {
        asn1_len(asn1_set_of_integer!(self.auths, Purpose))?
            + asn1_len(asn1_integer!(self.auths, Algorithm))?
            + asn1_len(asn1_integer_newtype!(self.auths, KeySize))?
            + asn1_len(asn1_set_of_integer!(self.auths, BlockMode))?
            + asn1_len(asn1_set_of_integer!(self.auths, Digest))?
            + asn1_len(asn1_set_of_integer!(self.auths, Padding))?
            + asn1_len(asn1_null!(self.auths, CallerNonce))?
            + asn1_len(asn1_integer!(self.auths, MinMacLength))?
            + asn1_len(asn1_integer!(self.auths, EcCurve))?
            + asn1_len(asn1_integer!(self.auths, MlDsaVariant))?
            + asn1_len(asn1_integer_newtype!(self.auths, RsaPublicExponent))?
            + asn1_len(asn1_set_of_integer!(self.auths, RsaOaepMgfDigest))?
            + asn1_len(asn1_null!(self.auths, RollbackResistance))?
            + asn1_len(asn1_null!(self.auths, EarlyBootOnly))?
            + asn1_len(asn1_integer_datetime!(self.auths, ActiveDatetime))?
            + asn1_len(asn1_integer_datetime!(
                self.auths,
                OriginationExpireDatetime
            ))?
            + asn1_len(asn1_integer_datetime!(self.auths, UsageExpireDatetime))?
            + asn1_len(asn1_integer!(self.auths, UsageCountLimit))?
            + if self.encode_sid {
                asn1_len(asn1_integer!(self.auths, UserSecureId))?
            } else {
                Length::ZERO
            }
            + asn1_len(asn1_null!(self.auths, NoAuthRequired))?
            + asn1_len(asn1_integer!(self.auths, UserAuthType))?
            + asn1_len(asn1_integer!(self.auths, AuthTimeout))?
            + asn1_len(asn1_null!(self.auths, AllowWhileOnBody))?
            + asn1_len(asn1_null!(self.auths, TrustedUserPresenceRequired))?
            + asn1_len(asn1_null!(self.auths, TrustedConfirmationRequired))?
            + asn1_len(asn1_null!(self.auths, UnlockedDeviceRequired))?
            + asn1_len(asn1_integer_datetime!(self.auths, CreationDatetime))?
            + asn1_len(asn1_integer!(self.auths, Origin))?
            + asn1_len(asn1_root_of_trust(
                Tag::RootOfTrust,
                self.rot_info.as_deref(),
            )?)?
            + asn1_len(asn1_integer!(self.auths, OsVersion))?
            + asn1_len(asn1_integer!(self.auths, OsPatchlevel))?
            + asn1_len(asn1_octet_string(
                Tag::AttestationApplicationId,
                self.app_id.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdBrand,
                self.ids.brand.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdDevice,
                self.ids.device.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdProduct,
                self.ids.product.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdSerial,
                self.ids.serial.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdImei,
                self.ids.imei.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdMeid,
                self.ids.meid.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdManufacturer,
                self.ids.manufacturer.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdModel,
                self.ids.model.as_deref(),
            )?)?
            + asn1_len(asn1_integer!(self.auths, VendorPatchlevel))?
            + asn1_len(asn1_integer!(self.auths, BootPatchlevel))?
            + asn1_len(asn1_null!(self.auths, DeviceUniqueAttestation))?
            + asn1_len(asn1_octet_string(
                Tag::AttestationIdSecondImei,
                self.ids.imei2.as_deref(),
            )?)?
            + asn1_len(asn1_octet_string(
                Tag::ModuleHash,
                self.module_hash.as_deref(),
            )?)?
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        asn1_val(asn1_set_of_integer!(self.auths, Purpose), writer)?;
        asn1_val(asn1_integer!(self.auths, Algorithm), writer)?;
        asn1_val(asn1_integer_newtype!(self.auths, KeySize), writer)?;
        asn1_val(asn1_set_of_integer!(self.auths, BlockMode), writer)?;
        asn1_val(asn1_set_of_integer!(self.auths, Digest), writer)?;
        asn1_val(asn1_set_of_integer!(self.auths, Padding), writer)?;
        asn1_val(asn1_null!(self.auths, CallerNonce), writer)?;
        asn1_val(asn1_integer!(self.auths, MinMacLength), writer)?;
        asn1_val(asn1_integer!(self.auths, EcCurve), writer)?;
        asn1_val(asn1_integer!(self.auths, MlDsaVariant), writer)?;
        asn1_val(asn1_integer_newtype!(self.auths, RsaPublicExponent), writer)?;
        asn1_val(asn1_set_of_integer!(self.auths, RsaOaepMgfDigest), writer)?;
        asn1_val(asn1_null!(self.auths, RollbackResistance), writer)?;
        asn1_val(asn1_null!(self.auths, EarlyBootOnly), writer)?;
        asn1_val(asn1_integer_datetime!(self.auths, ActiveDatetime), writer)?;
        asn1_val(
            asn1_integer_datetime!(self.auths, OriginationExpireDatetime),
            writer,
        )?;
        asn1_val(
            asn1_integer_datetime!(self.auths, UsageExpireDatetime),
            writer,
        )?;
        asn1_val(asn1_integer!(self.auths, UsageCountLimit), writer)?;
        // Note that `UserSecureId` is only included in the extension for
        // importWrappedKey() cases.
        if self.encode_sid {
            asn1_val(asn1_integer!(self.auths, UserSecureId), writer)?;
        }
        asn1_val(asn1_null!(self.auths, NoAuthRequired), writer)?;
        asn1_val(asn1_integer!(self.auths, UserAuthType), writer)?;
        asn1_val(asn1_integer!(self.auths, AuthTimeout), writer)?;
        asn1_val(asn1_null!(self.auths, AllowWhileOnBody), writer)?;
        asn1_val(asn1_null!(self.auths, TrustedUserPresenceRequired), writer)?;
        asn1_val(asn1_null!(self.auths, TrustedConfirmationRequired), writer)?;
        asn1_val(asn1_null!(self.auths, UnlockedDeviceRequired), writer)?;
        asn1_val(asn1_integer_datetime!(self.auths, CreationDatetime), writer)?;
        asn1_val(asn1_integer!(self.auths, Origin), writer)?;
        // Root of trust info is a special case (not in key characteristics).
        asn1_val(
            asn1_root_of_trust(Tag::RootOfTrust, self.rot_info.as_deref())?,
            writer,
        )?;
        asn1_val(asn1_integer!(self.auths, OsVersion), writer)?;
        asn1_val(asn1_integer!(self.auths, OsPatchlevel), writer)?;
        // Attestation application ID is a special case (not in key characteristics).
        asn1_val(
            asn1_octet_string(Tag::AttestationApplicationId, self.app_id.as_deref())?,
            writer,
        )?;
        // Accuracy of attestation IDs has already been checked, so just copy across.
        asn1_val(
            asn1_octet_string(Tag::AttestationIdBrand, self.ids.brand.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdDevice, self.ids.device.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdProduct, self.ids.product.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdSerial, self.ids.serial.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdImei, self.ids.imei.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdMeid, self.ids.meid.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(
                Tag::AttestationIdManufacturer,
                self.ids.manufacturer.as_deref(),
            )?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdModel, self.ids.model.as_deref())?,
            writer,
        )?;
        asn1_val(asn1_integer!(self.auths, VendorPatchlevel), writer)?;
        asn1_val(asn1_integer!(self.auths, BootPatchlevel), writer)?;
        asn1_val(asn1_null!(self.auths, DeviceUniqueAttestation), writer)?;
        asn1_val(
            asn1_octet_string(Tag::AttestationIdSecondImei, self.ids.imei2.as_deref())?,
            writer,
        )?;
        asn1_val(
            asn1_octet_string(Tag::ModuleHash, self.module_hash.as_deref())?,
            writer,
        )?;
        Ok(())
    }
}

struct ExplicitTaggedValue<T: Encode> {
    pub tag: u32,
    pub val: T,
}

impl<T: Encode> ExplicitTaggedValue<T> {
    fn new(tag: Tag, val: T) -> ExplicitTaggedValue<T> {
        ExplicitTaggedValue {
            tag: raw_tag_value(tag),
            val,
        }
    }

    fn explicit_tag_len(&self) -> der::Result<der::Length> {
        match self.tag {
            0..=0x1e => Ok(der::Length::ONE),
            0x1f..=0x7f => Ok(der::Length::new(2)),
            0x80..=0x3fff => Ok(der::Length::new(3)),
            _ => Err(der::ErrorKind::Overflow.into()),
        }
    }

    fn explicit_tag_encode(&self, encoder: &mut dyn der::Writer) -> der::Result<()> {
        match self.tag {
            0..=0x1e => {
                // b101vvvvv is context-specific+constructed
                encoder.write_byte(0b10100000u8 | (self.tag as u8))
            }
            0x1f..=0x7f => {
                // b101 11111 indicates a context-specific+constructed long-form tag number
                encoder.write_byte(0b10111111)?;
                encoder.write_byte(self.tag as u8)
            }
            0x80..=0x3fff => {
                // b101 11111 indicates a context-specific+constructed long-form tag number
                encoder.write_byte(0b10111111)?;
                encoder.write_byte((self.tag >> 7) as u8 | 0x80u8)?;
                encoder.write_byte((self.tag & 0x007f) as u8)
            }
            _ => Err(der::ErrorKind::Overflow.into()),
        }
    }
}

/// The der library explicitly does not support `TagNumber` values bigger than 31,
/// which are required here.  Work around this by manually providing the encoding functionality.
impl<T: Encode> Encode for ExplicitTaggedValue<T> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let inner_len = self.val.encoded_len()?;
        self.explicit_tag_len() + inner_len.encoded_len()? + inner_len
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        let inner_len = self.val.encoded_len()?;
        self.explicit_tag_encode(encoder)?;
        inner_len.encode(encoder)?;
        self.val.encode(encoder)
    }
}

/// Root of Trust ASN.1 structure
/// ```asn1
///  * RootOfTrust ::= SEQUENCE {
///  *     verifiedBootKey            OCTET_STRING,
///  *     deviceLocked               BOOLEAN,
///  *     verifiedBootState          VerifiedBootState,
///  *     verifiedBootHash           OCTET_STRING,
///  * }
/// ```
#[derive(Debug, Clone, Sequence)]
struct RootOfTrust<'a> {
    #[asn1(type = "OCTET STRING")]
    verified_boot_key: &'a [u8],
    device_locked: bool,
    verified_boot_state: VerifiedBootState,
    #[asn1(type = "OCTET STRING")]
    verified_boot_hash: &'a [u8],
}

impl<'a> From<&'a keymint::BootInfo> for RootOfTrust<'a> {
    fn from(info: &keymint::BootInfo) -> RootOfTrust<'_> {
        let verified_boot_key: &[u8] = if info.verified_boot_key.is_empty() {
            // If an empty verified boot key was passed by the boot loader, set the verified boot
            // key in the attestation to all zeroes.
            &EMPTY_BOOT_KEY[..]
        } else {
            &info.verified_boot_key[..]
        };
        RootOfTrust {
            verified_boot_key,
            device_locked: info.device_boot_locked,
            verified_boot_state: info.verified_boot_state.into(),
            verified_boot_hash: &info.verified_boot_hash[..],
        }
    }
}

/// Verified Boot State as ASN.1 ENUMERATED type.
///```asn1
///  * VerifiedBootState ::= ENUMERATED {
///  *     Verified                   (0),
///  *     SelfSigned                 (1),
///  *     Unverified                 (2),
///  *     Failed                     (3),
///  * }
///```
#[repr(u32)]
#[derive(Debug, Clone, Copy, Enumerated)]
enum VerifiedBootState {
    Verified = 0,
    SelfSigned = 1,
    Unverified = 2,
    Failed = 3,
}

impl From<keymint::VerifiedBootState> for VerifiedBootState {
    fn from(state: keymint::VerifiedBootState) -> VerifiedBootState {
        match state {
            keymint::VerifiedBootState::Verified => VerifiedBootState::Verified,
            keymint::VerifiedBootState::SelfSigned => VerifiedBootState::SelfSigned,
            keymint::VerifiedBootState::Unverified => VerifiedBootState::Unverified,
            keymint::VerifiedBootState::Failed => VerifiedBootState::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestationIdInfo, KeyMintHalVersion};
    use std::vec;

    #[test]
    fn test_rsa_signature_algorithm_has_null_parameters() {
        let spki_der = hex::decode("3012300d06092a864886f70d0101010500030100").unwrap();
        let params = [
            KeyParam::Algorithm(keymint::Algorithm::Rsa),
            KeyParam::CertificateNotBefore(DateTime { ms_since_epoch: 0 }),
            KeyParam::CertificateNotAfter(DateTime { ms_since_epoch: 0 }),
        ];
        let tbs_cert = tbs_certificate(&None, &spki_der, &[], None, None, &[], &params).unwrap();
        assert_eq!(
            hex::encode(
                x509_der::Encode::to_der(tbs_cert.signature.parameters.as_ref().unwrap()).unwrap()
            ),
            "0500"
        );
    }

    #[test]
    fn test_negative_validity_time_stays_generalized() {
        let validity = Validity {
            not_before: validity_time_from_datetime(DateTime { ms_since_epoch: -1 }).unwrap(),
            not_after: validity_time_from_datetime(DateTime { ms_since_epoch: -1 }).unwrap(),
        };
        assert_eq!(
            hex::encode(x509_der::Encode::to_der(&validity).unwrap()),
            "3022180f31393730303130313030303030305a180f31393730303130313030303030305a"
        );
    }

    #[test]
    fn test_attest_ext_encode_decode() {
        let sec_level = SecurityLevel::TrustedEnvironment;
        let ext = AttestationExtension {
            attestation_version: KeyMintHalVersion::V3 as i32,
            attestation_security_level: sec_level,
            keymint_version: KeyMintHalVersion::V3 as i32,
            keymint_security_level: sec_level,
            attestation_challenge: b"abc",
            unique_id: b"xxx",
            sw_enforced: AuthorizationList::new(&[], &[], None, None, None, &[]).unwrap(),
            hw_enforced: AuthorizationList::new(
                &[KeyParam::Algorithm(keymint::Algorithm::Ec)],
                &[],
                None,
                Some(RootOfTrust {
                    verified_boot_key: &[0xbbu8; 32],
                    device_locked: false,
                    verified_boot_state: VerifiedBootState::Unverified,
                    verified_boot_hash: &[0xee; 32],
                }),
                None,
                &[],
            )
            .unwrap(),
        };
        let got = ext.to_der().unwrap();
        let want = concat!(
            "3071",   // SEQUENCE
            "0202",   // INTEGER len 2
            "012c",   // 300
            "0a01",   // ENUM len 1
            "01",     // 1 (TrustedEnvironment)
            "0202",   // INTEGER len 2
            "012c",   // 300
            "0a01",   // ENUM len 1
            "01",     // 1 (TrustedEnvironement)
            "0403",   // BYTE STRING len 3
            "616263", // b"abc"
            "0403",   // BYTE STRING len 3
            "787878", // b"xxx"
            "3000",   // SEQUENCE len 0
            "3055",   // SEQUENCE len 55
            "a203",   // EXPLICIT [2]
            "0201",   // INTEGER len 1
            "03",     // 3 (Algorithm::Ec)
            "bf8540",
            "4c",   // EXPLICIT [704] len 0x4c
            "304a", // SEQUENCE len x4a
            "0420", // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );
        assert_eq!(hex::encode(&got), want);
        let mut parsed = AttestationExtension::from_der(&got).unwrap();
        parsed.sw_enforced.encode_sid = false;
        parsed.hw_enforced.encode_sid = false;
        assert_eq!(parsed, ext);
    }

    #[test]
    fn test_explicit_tagged_value() {
        assert_eq!(
            hex::encode(ExplicitTaggedValue { tag: 2, val: 16 }.to_der().unwrap()),
            "a203020110"
        );
        assert_eq!(
            hex::encode(ExplicitTaggedValue { tag: 2, val: () }.to_der().unwrap()),
            "a2020500"
        );
        assert_eq!(
            hex::encode(ExplicitTaggedValue { tag: 503, val: 16 }.to_der().unwrap()),
            "bf837703020110"
        );
    }

    #[test]
    fn test_authorization_list_tags_ordered_by_raw_value() {
        assert!(AUTHORIZATION_LIST_TAGS
            .iter()
            .map(|tag| raw_tag_value(*tag))
            .is_sorted());
    }

    #[test]
    fn test_authorization_list_tags_are_unique() {
        let mut deduped = AUTHORIZATION_LIST_TAGS.to_vec();
        deduped.dedup();
        assert_eq!(AUTHORIZATION_LIST_TAGS.len(), deduped.len())
    }

    #[test]
    fn test_authorization_list_encode_decode() {
        let additional_attestation_info = [KeyParam::ModuleHash(vec![0xaa; 32])];
        let authorization_list = AuthorizationList::new(
            &[KeyParam::Algorithm(keymint::Algorithm::Ec)],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &additional_attestation_info,
        )
        .unwrap();
        let got = authorization_list.to_der().unwrap();
        let want: &str = concat!(
            "307b", // SEQUENCE len 123
            "a203", // EXPLICIT [2]
            "0201", // INTEGER len 1
            "03",   // 3 (Algorithm::Ec)
            "bf8540",
            "4c",   // EXPLICIT [704] len 0x4c
            "304a", // SEQUENCE len x4a
            "0420", // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "bf8554",
            "22",   // EXPLICIT [724] len 34
            "0420", // OCTET STRING len 32
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        // encode
        assert_eq!(hex::encode(&got), want);
        // decode from encoded
        let mut parsed = AuthorizationList::from_der(got.as_slice()).unwrap();
        parsed.encode_sid = false;
        assert_eq!(parsed, authorization_list);
    }

    #[test]
    fn test_authorization_list_user_secure_id_encode() {
        // Create an authorization list that includes multiple values for SecureUserId.
        let authorization_list = AuthorizationList::new(
            &[
                KeyParam::Algorithm(keymint::Algorithm::Ec),
                KeyParam::UserSecureId(42),
                KeyParam::UserSecureId(43),
                KeyParam::UserSecureId(44),
            ],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &[],
        )
        .unwrap();
        let got = authorization_list.to_der().unwrap();
        // The `SecureUserId` values are *not* included in the generated output.
        let want: &str = concat!(
            "3055", // SEQUENCE len 55
            "a203", // EXPLICIT [2]
            "0201", // INTEGER len 1
            "03",   // 3 (Algorithm::Ec)
            "bf8540",
            "4c",   // EXPLICIT [704] len 0x4c
            "304a", // SEQUENCE len x4a
            "0420", // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        );
        // encode
        assert_eq!(hex::encode(got), want);
    }

    #[test]
    fn test_authorization_list_user_secure_id_decode() {
        // Create a DER-encoded `AuthorizationList` that includes a `UserSecureId` value.
        let input = hex::decode(concat!(
            "305c",   // SEQUENCE
            "a203",   // EXPLICIT [2] len 3
            "0201",   // INTEGER len 1
            "03",     // 3 (Algorithm::Ec)
            "bf8376", // EXPLICIT [502]
            "03",     // len 3
            "0201",   // INTEGER len 1
            "02",     // 2
            "bf8540", // EXPLICIT [704]
            "4c",     // len 0x4c
            "304a",   // SEQUENCE len x4a
            "0420",   // OCTET STRING len 32
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "0101", // BOOLEAN len 1
            "00",   // false
            "0a01", // ENUMERATED len 1
            "02",   // Unverified(2)
            "0420", // OCTET STRING len 32
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ))
        .unwrap();
        let mut got = AuthorizationList::from_der(&input).unwrap();
        got.encode_sid = false;

        let want = AuthorizationList::new(
            &[
                KeyParam::Algorithm(keymint::Algorithm::Ec),
                KeyParam::UserSecureId(2),
            ],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &[],
        )
        .unwrap();

        assert_eq!(got, want);
    }

    #[test]
    fn test_authz_list_rejects_mismatched_attestation_id() {
        let attestation_ids = AttestationIdInfo {
            brand: b"good".to_vec(),
            ..Default::default()
        };
        let keygen_params = [KeyParam::AttestationIdBrand(b"bad".to_vec())];
        let error =
            AuthorizationList::new(&[], &keygen_params, Some(&attestation_ids), None, None, &[])
                .unwrap_err();

        assert!(matches!(
            error.kind(),
            CommonErrorKind::Hal(ErrorCode::CannotAttestIds, _)
        ));
    }

    #[test]
    fn test_authz_list_preserves_swapped_dual_imei() {
        let primary = b"primary-imei".to_vec();
        let secondary = b"secondary-imei".to_vec();
        let attestation_ids = AttestationIdInfo {
            imei: primary.clone(),
            imei2: secondary.clone(),
            ..Default::default()
        };
        let keygen_params = [
            KeyParam::AttestationIdImei(secondary.clone()),
            KeyParam::AttestationIdSecondImei(primary.clone()),
        ];
        let authz_list =
            AuthorizationList::new(&[], &keygen_params, Some(&attestation_ids), None, None, &[])
                .unwrap();

        assert_eq!(authz_list.ids.imei.as_deref(), Some(secondary.as_slice()));
        assert_eq!(authz_list.ids.imei2.as_deref(), Some(primary.as_slice()));
    }

    #[test]
    fn test_authz_list_encodes_empty_second_imei() {
        let attestation_ids = AttestationIdInfo::default();
        let keygen_params = [KeyParam::AttestationIdSecondImei(vec![])];
        let authz_list =
            AuthorizationList::new(&[], &keygen_params, Some(&attestation_ids), None, None, &[])
                .unwrap();

        assert_eq!(authz_list.ids.imei2.as_deref(), Some([].as_slice()));
        assert_eq!(
            hex::encode(authz_list.to_der().unwrap()),
            "3006bf8553020400"
        );
    }

    #[test]
    fn test_authorization_list_dup_encode() {
        use kmr_wire::keymint::Digest;
        let authorization_list = AuthorizationList::new(
            &[
                KeyParam::Digest(Digest::None),
                KeyParam::Digest(Digest::Sha1),
                KeyParam::Digest(Digest::Sha1), // duplicate value
            ],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &[],
        )
        .unwrap();
        let got = authorization_list.to_der().unwrap();
        assert!(AuthorizationList::from_der(got.as_slice()).is_ok());
    }

    #[test]
    fn test_authorization_list_order_fail() {
        use kmr_wire::keymint::Digest;
        let authorization_list = AuthorizationList::new(
            &[
                KeyParam::Digest(Digest::Sha1),
                KeyParam::Digest(Digest::None),
            ],
            &[],
            None,
            Some(RootOfTrust {
                verified_boot_key: &[0xbbu8; 32],
                device_locked: false,
                verified_boot_state: VerifiedBootState::Unverified,
                verified_boot_hash: &[0xee; 32],
            }),
            None,
            &[],
        )
        .unwrap();
        assert!(authorization_list.to_der().is_err());
    }

    #[test]
    fn test_decode_tag_from_bytes() {
        use der::Reader;
        let tests = [
            (
                "a2", // context-specific constructed tag=2
                Ok(Some(Tag::Algorithm)),
            ),
            (
                "be", // context-specific constructed tag=30 (not a KeyMint tag value)
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "bf1f", // context-specific constructed tag=31 (not a KeyMint tag value)
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "bf8377", // context-specific constructed tag=503=0x1F7
                Ok(Some(Tag::NoAuthRequired)),
            ),
            (
                "9f8377", // context-specific *primitive* tag=503=0x1F7
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "7f8377", // *application* constructed tag=503=0x1F7
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "bfc000", // context-specific constructed tag=16384=0x4000
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
            (
                "bf8148", // context-specific constructed tag=200=0xC8
                Ok(Some(Tag::RsaPublicExponent)),
            ),
            (
                "68", // application constructed tag=16
                Err(der::ErrorKind::TagNumberInvalid.into()),
            ),
        ];
        for (input_hex, want) in tests {
            let input = hex::decode(input_hex).unwrap();
            let mut reader = der::SliceReader::new(&input).unwrap();
            let got = decode_tag_from_bytes(&mut reader);
            assert_eq!(got, want, "for {input_hex}");
            if got.is_ok() {
                assert_eq!(reader.remaining_len(), der::Length::ZERO, "for {input_hex}");
            }
        }
    }

    /// 不管签发者是谁（主 keybox / StrongBox 那份 / 服务端身份），叶子上的级别只跟
    /// 「这次请求是什么级别」有关：传 Strongbox 进去，两个字段都必须是 2。
    #[test]
    fn attestation_level_follows_the_request_not_the_signer() {
        for (level, want) in [
            (keymint::SecurityLevel::TrustedEnvironment, 1u32),
            (keymint::SecurityLevel::Strongbox, 2u32),
        ] {
            let unique_id: Vec<u8> = Vec::new();
            let boot_info = keymint::BootInfo {
                verified_boot_key: Vec::new(),
                device_boot_locked: true,
                verified_boot_state: keymint::VerifiedBootState::Verified,
                verified_boot_hash: Vec::new(),
                boot_patchlevel: 0,
            };
            let ext = attestation_extension(
                300,
                b"challenge",
                &[],
                level,
                None,
                &[],
                &[],
                &unique_id,
                &boot_info,
                &[],
            )
            .expect("extension encodes");
            assert_eq!(ext.attestation_security_level as u32, want);
            assert_eq!(ext.keymint_security_level as u32, want);
            // 也不能因为级别不同就丢掉 hw_enforced 里的内容：级别只影响标哪个值。
            let der = asn1_der_encode(&ext).expect("extension serializes");
            let parsed = AttestationExtension::from_der(&der).expect("round-trips");
            assert_eq!(parsed.attestation_security_level as u32, want);
            assert_eq!(parsed.keymint_security_level as u32, want);
        }
    }

    /// 设备 ID（710..717）只出现在 teeEnforced，softwareEnforced 里一个都不行 ——
    /// 这正是一加/OPPO 工程模式「StrongBox Attestation Key ID Modify」的判据
    /// （`StrongBoxAttestationIdSupportChecker.verifyStrongBoxAttestedDeviceProperties`）：
    /// teeEnforced 里必须有这五项且值与 Build.* 一致，softwareEnforced 里出现了直接 Fail
    /// （"Device properties should not be software enforced"）。
    ///
    /// 注意写入的值来自调用方的 keygen params，`attestation_ids` 只是「本机已固化那套」
    /// 用来校验的；两者对不上时 `AuthorizationList::new` 回 CannotAttestIds。
    #[test]
    fn device_ids_are_hardware_enforced_only() {
        let ids = crate::AttestationIdInfo {
            brand: b"OnePlus".to_vec(),
            device: b"PLQ110".to_vec(),
            product: b"PLQ110".to_vec(),
            serial: b"3B161G007F500000".to_vec(),
            imei: b"864500000000001".to_vec(),
            imei2: Vec::new(),
            meid: Vec::new(),
            manufacturer: b"OnePlus".to_vec(),
            model: b"PLQ110".to_vec(),
        };
        // 调用方（应用/框架）请求要证明的那几项，走的就是这些 tag。
        let requested = [
            KeyParam::AttestationIdBrand(b"OnePlus".to_vec()),
            KeyParam::AttestationIdDevice(b"PLQ110".to_vec()),
            KeyParam::AttestationIdProduct(b"PLQ110".to_vec()),
            KeyParam::AttestationIdManufacturer(b"OnePlus".to_vec()),
            KeyParam::AttestationIdModel(b"PLQ110".to_vec()),
        ];
        let unique_id: Vec<u8> = Vec::new();
        let boot_info = keymint::BootInfo {
            verified_boot_key: Vec::new(),
            device_boot_locked: true,
            verified_boot_state: keymint::VerifiedBootState::Verified,
            verified_boot_hash: Vec::new(),
            boot_patchlevel: 0,
        };

        for level in [
            keymint::SecurityLevel::TrustedEnvironment,
            keymint::SecurityLevel::Strongbox,
        ] {
            let ext = attestation_extension(
                300,
                b"challenge",
                b"appid",
                level,
                Some(&ids),
                &requested,
                &[],
                &unique_id,
                &boot_info,
                &[],
            )
            .expect("extension encodes");
            let der = asn1_der_encode(&ext).expect("extension serializes");
            let parsed = AttestationExtension::from_der(&der).expect("round-trips");

            // 硬件那侧：该有的都有。
            assert_eq!(
                parsed.hw_enforced.ids.brand.as_deref(),
                Some(&b"OnePlus"[..])
            );
            assert_eq!(
                parsed.hw_enforced.ids.device.as_deref(),
                Some(&b"PLQ110"[..])
            );
            assert_eq!(
                parsed.hw_enforced.ids.product.as_deref(),
                Some(&b"PLQ110"[..])
            );
            assert_eq!(
                parsed.hw_enforced.ids.manufacturer.as_deref(),
                Some(&b"OnePlus"[..])
            );
            assert_eq!(
                parsed.hw_enforced.ids.model.as_deref(),
                Some(&b"PLQ110"[..])
            );

            // 软件那侧：一个都不能有。
            assert!(
                parsed.sw_enforced.ids.brand.is_none(),
                "{level:?}: sw 里出现了 710"
            );
            assert!(
                parsed.sw_enforced.ids.device.is_none(),
                "{level:?}: sw 里出现了 711"
            );
            assert!(
                parsed.sw_enforced.ids.product.is_none(),
                "{level:?}: sw 里出现了 712"
            );
            assert!(
                parsed.sw_enforced.ids.manufacturer.is_none(),
                "{level:?}: sw 里出现了 716"
            );
            assert!(
                parsed.sw_enforced.ids.model.is_none(),
                "{level:?}: sw 里出现了 717"
            );

            // 应用 ID（709）还在软件那侧，没被动到。
            assert_eq!(parsed.sw_enforced.app_id.as_deref(), Some(&b"appid"[..]));
        }

        // 请求里带了 ID、但本机那套对不上时，不能默默写一份假的：得报 CannotAttestIds。
        let mut wrong = ids.clone();
        wrong.brand = b"Other".to_vec();
        assert!(
            attestation_extension(
                300,
                b"challenge",
                b"appid",
                keymint::SecurityLevel::Strongbox,
                Some(&wrong),
                &requested,
                &[],
                &unique_id,
                &boot_info,
                &[],
            )
            .is_err(),
            "ID 不匹配时必须拒绝"
        );

        // chars 里混进 ID tag（这组 tag 是 NotKeyCharacteristic，理论上不会有）也只
        // 能落在被剔掉的那侧，绝不能出现在软件强制列表里。
        let chars = [keymint::KeyCharacteristics {
            security_level: keymint::SecurityLevel::Keystore,
            authorizations: vec![KeyParam::AttestationIdBrand(b"OnePlus".to_vec())],
        }];
        let ext = attestation_extension(
            300,
            b"challenge",
            b"appid",
            keymint::SecurityLevel::Strongbox,
            Some(&ids),
            &requested,
            &chars,
            &unique_id,
            &boot_info,
            &[],
        )
        .expect("chars 里混进 ID tag 也不能把整笔搅黄");
        let der = asn1_der_encode(&ext).expect("extension serializes");
        let parsed = AttestationExtension::from_der(&der).expect("round-trips");
        assert!(
            parsed.sw_enforced.ids.brand.is_none(),
            "chars 里带的 710 也不能进软件强制列表"
        );
        assert_eq!(
            parsed.hw_enforced.ids.brand.as_deref(),
            Some(&b"OnePlus"[..])
        );
    }
}
