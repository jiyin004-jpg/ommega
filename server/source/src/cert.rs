//! Certificate building for `server_keybox` mode.
//!
//! Mirrors `relay_server/apps/portal/server_fulfill.py`:
//!   - `build_attestation_extension_der()` -> KeyDescription DER
//!   - `build_attested_chain()`            -> PEM chain where the leaf carries
//!     the attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
//!
//! Pure-Rust DER encoding (yasna) + pure-Rust crypto (p256 / ecdsa / rsa),
//! no system OpenSSL required.

use ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature as P256DerSignature, Signature as P256Signature};
use p256::SecretKey as P256SecretKey;
use p384::ecdsa::{DerSignature as P384DerSignature, Signature as P384Signature};
use p384::SecretKey as P384SecretKey;
use p521::ecdsa::{DerSignature as P521DerSignature, Signature as P521Signature};
use p521::SecretKey as P521SecretKey;
use pkcs8::DecodePrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use sha2::Sha256;
use x509_parser::parse_x509_certificate;

use crate::db::DeviceIdentity;

pub const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];
const OID_ECDSA_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
const OID_ECDSA_SHA384: &[u64] = &[1, 2, 840, 10045, 4, 3, 3];
const OID_ECDSA_SHA512: &[u64] = &[1, 2, 840, 10045, 4, 3, 4];
const OID_RSA_SHA256: &[u64] = &[1, 2, 840, 113549, 1, 1, 11];
const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];
const OID_BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
const OID_COUNTRY_NAME: &[u64] = &[2, 5, 4, 6];
const OID_ORG_NAME: &[u64] = &[2, 5, 4, 10];
const OID_COMMON_NAME: &[u64] = &[2, 5, 4, 3];

pub const KM_ALG_EC: i64 = 3;
pub const KM_ALG_RSA: i64 = 1;
pub const KM_PURPOSE_SIGN: i64 = 2;
pub const KM_PURPOSE_ATTEST_KEY: i64 = 7;
pub const KM_DIGEST_SHA_256: i64 = 4; // AOSP KmDigest::SHA256 = 4
pub const KM_EC_CURVE_P_256: i64 = 1; // AOSP KmEcCurve::P_256 = 1
pub const KM_EC_CURVE_P_384: i64 = 2; // AOSP KmEcCurve::P_384 = 2
pub const KM_EC_CURVE_P_521: i64 = 3; // AOSP KmEcCurve::P_521 = 3

#[derive(Debug, Clone)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: i64,
    pub verified_boot_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttestationParams {
    pub challenge: Vec<u8>,
    pub algorithm: i64,
    pub key_size: i64,
    pub purposes: Vec<i64>,
    pub digests: Vec<i64>,
    pub paddings: Vec<i64>,
    pub ec_curve: Option<i64>,
    pub rsa_public_exponent: Option<i64>,
    /// KM_TAG_RSA_OAEP_MGF_DIGEST (203) — KeyMint 1.0+; emitted for RSA keys.
    pub mgf_digest: Vec<i64>,
    pub root_of_trust: Option<RootOfTrust>,
    pub os_version: Option<i64>,
    pub os_patch_level: Option<i64>,
    /// KM_TAG_VENDOR_PATCH_LEVEL (718) / KM_TAG_BOOT_PATCH_LEVEL (719).
    ///
    /// 注意不是 707/708：那是 KM_TAG_UNIQUE_ID / KM_TAG_ATTESTATION_CHALLENGE。
    pub vendor_patch_level: Option<i64>,
    pub boot_patch_level: Option<i64>,
    pub app_id: Option<Vec<u8>>,
    pub creation_datetime_ms: u64,
    /// Leaf certificate subject (DER Name) requested by the caller; defaults to
    /// "CN=Android Keystore Key" when absent.
    pub subject_name: Option<Vec<u8>>,
    /// Leaf validity window requested by the caller (epoch ms); 0/None falls
    /// back to creation time / the fixed 2048 notAfter.
    pub not_before_ms: Option<u64>,
    pub not_after_ms: Option<u64>,
    /// attestationVersion / keymasterVersion (mirrors Django's att_rv / km_rv).
    /// Android KeyMint v3 = 300, StrongBox v3 = 400.
    pub attestation_version: i64,
    pub keymaster_version: i64,
    /// attestationSecurityLevel / keymasterSecurityLevel (0=SW, 1=TEE, 2=StrongBox).
    pub security_level: i64,
    /// Serial number for the leaf certificate. AOSP convention is 1.
    pub serial: i64,
}

impl Default for AttestationParams {
    fn default() -> Self {
        Self {
            challenge: Vec::new(),
            algorithm: KM_ALG_EC,
            key_size: 256,
            purposes: vec![KM_PURPOSE_SIGN, KM_PURPOSE_ATTEST_KEY],
            digests: vec![KM_DIGEST_SHA_256],
            paddings: Vec::new(),
            ec_curve: Some(KM_EC_CURVE_P_256),
            rsa_public_exponent: None,
            mgf_digest: Vec::new(),
            root_of_trust: None,
            os_version: None,
            os_patch_level: None,
            vendor_patch_level: None,
            boot_patch_level: None,
            app_id: None,
            creation_datetime_ms: 0,
            subject_name: None,
            not_before_ms: None,
            not_after_ms: None,
            // Match Django's `_parse_device_attest_context` defaults:
            // KeyMint 3.0 = 300 (matches device VINTF @3).
            attestation_version: 300,
            keymaster_version: 300,
            security_level: 1,
            serial: 1,
        }
    }
}

/// KeyDescription DER (extension extnValue, the OCTET STRING wrapper is
/// applied by `ext_entry`). Mirrors Python's `UnrecognizedExtension(oid, der)`.
pub fn build_attestation_extension_der(p: &AttestationParams) -> Vec<u8> {
    key_description_der(p)
}

fn key_description_der(p: &AttestationParams) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_i64(p.attestation_version); // attestationVersion (matches Django's att_rv)
            w.next().write_enum(p.security_level); // attestationSecurityLevel (ENUMERATED)
            w.next().write_i64(p.keymaster_version); // keymasterVersion (matches Django's km_rv)
            w.next().write_enum(p.security_level); // keymasterSecurityLevel (ENUMERATED)
            w.next().write_bytes(&p.challenge);
            // uniqueId: always empty bytes (matches Django's `_octet(b"")`)
            w.next().write_bytes(b"");
            // softwareEnforced — holds CREATION_DATETIME (tag 701) and
            // ATTESTATION_APPLICATION_ID (tag 709, only if challenge is present)
            // sorted by tag to match Django's `sw_pairs.sort(key=lambda x: x[0])`
            w.next().write_sequence(|w| {
                let mut sw_tags: Vec<u64> = Vec::new();
                sw_tags.push(701); // CREATION_DATETIME — always present
                if p.app_id.is_some() {
                    sw_tags.push(709); // ATTESTATION_APPLICATION_ID
                }
                sw_tags.sort();
                for &tag in &sw_tags {
                    match tag {
                        701 => {
                            w.next().write_tagged(yasna::Tag::context(701), |w| {
                                w.write_u64(p.creation_datetime_ms);
                            });
                        }
                        709 => {
                            if let Some(app_id) = &p.app_id {
                                w.next().write_tagged(yasna::Tag::context(709), |w| {
                                    w.write_bytes(app_id);
                                });
                            }
                        }
                        _ => {}
                    }
                }
            });
            write_auth_list(w.next(), p); // teeEnforced
        })
    })
}

fn write_auth_list(w: yasna::DERWriter<'_>, p: &AttestationParams) {
    // Collect the field tags that are present, then write in sorted order
    // to match Django's `tee_pairs.sort(key=lambda x: x[0])`.
    let mut tags: Vec<u64> = Vec::new();
    if !p.purposes.is_empty() {
        tags.push(1);
    }
    if p.algorithm != 0 {
        tags.push(2);
    }
    if p.key_size != 0 {
        tags.push(3);
    }
    if !p.digests.is_empty() {
        tags.push(5);
    }
    if !p.paddings.is_empty() {
        tags.push(6);
    }
    if p.ec_curve.is_some() {
        tags.push(10);
    }
    if p.rsa_public_exponent.is_some() {
        tags.push(200);
    }
    if !p.mgf_digest.is_empty() {
        tags.push(203);
    } // RSA_OAEP_MGF_DIGEST (RSA only)
    tags.push(503); // NO_AUTH_REQUIRED — always present
    tags.push(702); // ORIGIN — always present
    tags.push(704); // ROOT_OF_TRUST — always present (Django defaults to 32 zero bytes)
    if p.os_version.is_some() {
        tags.push(705);
    }
    if p.os_patch_level.is_some() {
        tags.push(706);
    }
    // KeyAttestation 1.7's tag table: VENDOR_PATCHLEVEL=718, BOOT_PATCHLEVEL=719
    // (707/708 are UNIQUE_ID/ATTESTATION_CHALLENGE in the old keymaster numbering).
    if p.vendor_patch_level.is_some() {
        tags.push(718);
    }
    if p.boot_patch_level.is_some() {
        tags.push(719);
    }
    tags.sort();

    w.write_sequence(|w| {
        for &tag in &tags {
            match tag {
                1 => {
                    w.next().write_tagged(yasna::Tag::context(1), |w| {
                        w.write_set(|w| {
                            for v in &p.purposes {
                                w.next().write_i64(*v);
                            }
                        })
                    });
                }
                2 => {
                    w.next()
                        .write_tagged(yasna::Tag::context(2), |w| w.write_i64(p.algorithm));
                }
                3 => {
                    w.next()
                        .write_tagged(yasna::Tag::context(3), |w| w.write_i64(p.key_size));
                }
                5 => {
                    w.next().write_tagged(yasna::Tag::context(5), |w| {
                        w.write_set(|w| {
                            for v in &p.digests {
                                w.next().write_i64(*v);
                            }
                        })
                    });
                }
                6 => {
                    w.next().write_tagged(yasna::Tag::context(6), |w| {
                        w.write_set(|w| {
                            for v in &p.paddings {
                                w.next().write_i64(*v);
                            }
                        })
                    });
                }
                10 => {
                    if let Some(c) = p.ec_curve {
                        w.next()
                            .write_tagged(yasna::Tag::context(10), |w| w.write_i64(c));
                    }
                }
                200 => {
                    if let Some(e) = p.rsa_public_exponent {
                        w.next()
                            .write_tagged(yasna::Tag::context(200), |w| w.write_i64(e));
                    }
                }
                203 => {
                    w.next().write_tagged(yasna::Tag::context(203), |w| {
                        w.write_set(|w| {
                            for v in &p.mgf_digest {
                                w.next().write_i64(*v);
                            }
                        })
                    });
                }
                503 => {
                    w.next().write_tagged(yasna::Tag::context(503), |w| {
                        w.write_null();
                    });
                }
                702 => {
                    w.next().write_tagged(yasna::Tag::context(702), |w| {
                        w.write_i64(0);
                    });
                }
                704 => {
                    // Always present — matches Django's default vb_key/vb_hash = bytes(32)
                    let rot = p
                        .root_of_trust
                        .as_ref()
                        .map(|r| {
                            (
                                r.verified_boot_key.clone(),
                                r.device_locked,
                                r.verified_boot_state,
                                r.verified_boot_hash.clone(),
                            )
                        })
                        .unwrap_or_else(|| (vec![0u8; 32], true, 0i64, vec![0u8; 32]));
                    w.next().write_tagged(yasna::Tag::context(704), |w| {
                        w.write_sequence(|w| {
                            w.next().write_bytes(&rot.0);
                            w.next().write_bool(rot.1);
                            w.next().write_enum(rot.2);
                            w.next().write_bytes(&rot.3);
                        })
                    });
                }
                705 => {
                    if let Some(v) = p.os_version {
                        w.next()
                            .write_tagged(yasna::Tag::context(705), |w| w.write_i64(v));
                    }
                }
                706 => {
                    if let Some(v) = p.os_patch_level {
                        w.next()
                            .write_tagged(yasna::Tag::context(706), |w| w.write_i64(v));
                    }
                }
                718 => {
                    if let Some(v) = p.vendor_patch_level {
                        w.next()
                            .write_tagged(yasna::Tag::context(718), |w| w.write_i64(v));
                    }
                }
                719 => {
                    if let Some(v) = p.boot_patch_level {
                        w.next()
                            .write_tagged(yasna::Tag::context(719), |w| w.write_i64(v));
                    }
                }
                _ => {}
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Hand-rolled DER helpers for the X.509 certificate.
// ---------------------------------------------------------------------------

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let bytes = n.to_be_bytes();
        let mut out = Vec::new();
        for b in bytes {
            if !out.is_empty() || b != 0 {
                out.push(b);
            }
        }
        if out.is_empty() {
            out.push(0);
        }
        let mut v = vec![0x80 | out.len() as u8];
        v.extend(out);
        v
    }
}

struct Der(Vec<u8>);

impl Der {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn raw(&mut self, tag: u8, content: &[u8]) {
        self.0.push(tag);
        self.0.extend(der_len(content.len()));
        self.0.extend(content);
    }
    fn seq(&mut self, content: &[u8]) {
        self.raw(0x30, content);
    }
    fn int(&mut self, content: &[u8]) {
        self.raw(0x02, content);
    }
    fn oid(&mut self, oid: &[u64]) {
        let mut buf = Vec::new();
        buf.push((oid[0] * 40 + oid[1]) as u8);
        for o in &oid[2..] {
            let mut v = *o;
            let mut bytes = Vec::new();
            bytes.push((v & 0x7f) as u8);
            v >>= 7;
            while v > 0 {
                bytes.push(((v & 0x7f) as u8) | 0x80);
                v >>= 7;
            }
            bytes.reverse();
            buf.extend(bytes);
        }
        self.raw(0x06, &buf);
    }
    fn bool(&mut self, b: bool) {
        self.raw(0x01, if b { &[0xff] } else { &[0x00] });
    }
    fn utctime(&mut self, s: &str) {
        self.raw(0x17, s.as_bytes());
    }
    /// GeneralizedTime (tag 0x18, 4-digit year). Required for notAfter dates
    /// at/after 2050: UTCTime's two-digit year maps `50`-`99` to 1950-1999,
    /// so "500101000000Z" encodes as the year 1950 — a certificate that is
    /// already expired, which attestation verifiers flag as a tampered key.
    fn generalized_time(&mut self, s: &str) {
        self.raw(0x18, s.as_bytes());
    }
    fn bit_string(&mut self, content: &[u8]) {
        let mut c = vec![0u8];
        c.extend(content);
        self.raw(0x03, &c);
    }
    fn explicit(&mut self, tag: u8, content: &[u8]) {
        self.raw(0xa0 | tag, content);
    }
    fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

fn wrap_int(v: i64) -> Vec<u8> {
    let mut d = Der::new();
    d.int(&[v as u8]);
    d.into_vec()
}

fn alg_id(oid: &[u64], with_null: bool) -> Vec<u8> {
    let mut d = Der::new();
    d.oid(oid);
    if with_null {
        d.raw(0x05, &[]); // NULL
    }
    let mut out = Der::new();
    out.seq(&d.into_vec());
    out.into_vec()
}

fn sig_alg_for_key(key: &KeyMaterial) -> Vec<u8> {
    match key {
        // ECDSA-with-SHA256: parameters must be ABSENT (matches Google certs).
        KeyMaterial::Ec(EcKey::P256(_)) => alg_id(OID_ECDSA_SHA256, false),
        KeyMaterial::Ec(EcKey::P384(_)) => alg_id(OID_ECDSA_SHA384, false),
        KeyMaterial::Ec(EcKey::P521(_)) => alg_id(OID_ECDSA_SHA512, false),
        // sha256WithRSAEncryption: parameters must be NULL per RFC 4055.
        KeyMaterial::Rsa(_) => alg_id(OID_RSA_SHA256, true),
    }
}

fn ext_entry(oid: &[u64], critical: bool, octet: &[u8]) -> Vec<u8> {
    let mut d = Der::new();
    d.oid(oid);
    if critical {
        d.bool(true);
    }
    d.raw(0x04, octet);
    let mut out = Der::new();
    out.seq(&d.into_vec());
    out.into_vec()
}

/// EC key material for any supported NIST curve.
pub enum EcKey {
    P256(P256SecretKey),
    P384(P384SecretKey),
    P521(P521SecretKey),
}

/// RSA 私钥比 EC 那几种大出一个数量级（`RsaPrivateKey` 约 300 字节，
/// P-256 才 32 字节），不装箱的话整个 enum 都得按 RSA 的大小走，EC 分支也白背
/// 这份体积。装箱后 EC 分支只剩一个指针的代价，RSA 分支多一次分配，而密钥本来
/// 就是低频生成/低频解析的东西。
pub enum KeyMaterial {
    Ec(EcKey),
    Rsa(Box<rsa::RsaPrivateKey>),
}

pub fn parse_private_key(pem_data: &[u8]) -> anyhow::Result<KeyMaterial> {
    let s = std::str::from_utf8(pem_data)?;
    if let Ok(sk) = P256SecretKey::from_sec1_pem(s) {
        return Ok(KeyMaterial::Ec(EcKey::P256(sk)));
    }
    if let Ok(sk) = P256SecretKey::from_pkcs8_pem(s) {
        return Ok(KeyMaterial::Ec(EcKey::P256(sk)));
    }
    if let Ok(sk) = P384SecretKey::from_sec1_pem(s) {
        return Ok(KeyMaterial::Ec(EcKey::P384(sk)));
    }
    if let Ok(sk) = P384SecretKey::from_pkcs8_pem(s) {
        return Ok(KeyMaterial::Ec(EcKey::P384(sk)));
    }
    if let Ok(sk) = P521SecretKey::from_sec1_pem(s) {
        return Ok(KeyMaterial::Ec(EcKey::P521(sk)));
    }
    if let Ok(sk) = P521SecretKey::from_pkcs8_pem(s) {
        return Ok(KeyMaterial::Ec(EcKey::P521(sk)));
    }
    if let Ok(rk) = rsa::RsaPrivateKey::from_pkcs8_pem(s) {
        return Ok(KeyMaterial::Rsa(Box::new(rk)));
    }
    // PKCS#1 RSA (common in keybox.xml `<PrivateKey format="pem">`).
    use rsa::pkcs1::DecodeRsaPrivateKey;
    if let Ok(rk) = rsa::RsaPrivateKey::from_pkcs1_pem(s) {
        return Ok(KeyMaterial::Rsa(Box::new(rk)));
    }
    anyhow::bail!("unable to parse identity private key")
}

fn public_key_der(key: &KeyMaterial) -> anyhow::Result<Vec<u8>> {
    use pkcs8::EncodePublicKey;
    match key {
        KeyMaterial::Ec(EcKey::P256(sk)) => {
            Ok(sk.public_key().to_public_key_der()?.as_bytes().to_vec())
        }
        KeyMaterial::Ec(EcKey::P384(sk)) => {
            Ok(sk.public_key().to_public_key_der()?.as_bytes().to_vec())
        }
        KeyMaterial::Ec(EcKey::P521(sk)) => {
            Ok(sk.public_key().to_public_key_der()?.as_bytes().to_vec())
        }
        KeyMaterial::Rsa(rk) => Ok(rk.to_public_key().to_public_key_der()?.as_bytes().to_vec()),
    }
}

/// Validate that a PEM private key parses and matches the certificate chain's
/// leaf public key (the leaf's SubjectPublicKeyInfo). Returns `Some(error)` on
/// unparseable input or a mismatch, `None` when the key matches the chain.
///
/// Mirrors Django's `_validate_identity_pem`, used before storing an uploaded
/// identity so a mismatched PEM cannot produce a leaf whose signature fails to
/// verify.
pub fn validate_identity_pem(private_key_pem: &str, chain_pem: &str) -> Option<String> {
    let key = match parse_private_key(private_key_pem.as_bytes()) {
        Ok(k) => k,
        Err(e) => return Some(format!("cannot parse private key: {e}")),
    };
    let key_pub = match public_key_der(&key) {
        Ok(d) => d,
        Err(e) => return Some(format!("cannot derive public key from private key: {e}")),
    };
    let certs = match parse_chain_pem(chain_pem) {
        Ok(c) => c,
        Err(e) => return Some(format!("cannot parse certificate chain: {e}")),
    };
    let leaf_der = match certs.first() {
        Some(c) => c,
        None => return Some("certificate chain is empty".to_string()),
    };
    let leaf = match x509_parser::parse_x509_certificate(leaf_der) {
        Ok((_, c)) => c,
        Err(e) => return Some(format!("cannot parse leaf certificate: {e}")),
    };
    let leaf_pub = leaf.tbs_certificate.subject_pki.raw.to_vec();
    if key_pub == leaf_pub {
        None
    } else {
        Some("private key does not match the certificate chain leaf public key".to_string())
    }
}

fn sign_tbs(key: &KeyMaterial, tbs: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    match key {
        KeyMaterial::Ec(EcKey::P256(sk)) => {
            let signing_key = p256::ecdsa::SigningKey::from(sk);
            let sig: P256Signature = signing_key.sign(tbs);
            let der_sig = P256DerSignature::from(sig);
            // ECDSA-with-SHA256: parameters ABSENT (matches Google certs).
            Ok((alg_id(OID_ECDSA_SHA256, false), der_sig.as_bytes().to_vec()))
        }
        KeyMaterial::Ec(EcKey::P384(sk)) => {
            // p384::ecdsa::SigningKey only implements From for the inner
            // ecdsa_core::SigningKey, so go through that layer.
            let signing_key = p384::ecdsa::SigningKey::from(ecdsa::SigningKey::from(sk));
            let sig: P384Signature = signing_key.sign(tbs);
            let der_sig = P384DerSignature::from(sig);
            Ok((alg_id(OID_ECDSA_SHA384, false), der_sig.as_bytes().to_vec()))
        }
        KeyMaterial::Ec(EcKey::P521(sk)) => {
            let signing_key = p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(sk));
            let sig: P521Signature = signing_key.sign(tbs);
            let der_sig = P521DerSignature::from(sig);
            Ok((alg_id(OID_ECDSA_SHA512, false), der_sig.as_bytes().to_vec()))
        }
        KeyMaterial::Rsa(rk) => {
            let rk = rk.as_ref();
            let signing_key = RsaSigningKey::<Sha256>::new(rk.clone());
            let sig = signing_key.sign(tbs);
            // sha256WithRSAEncryption: parameters NULL per RFC 4055.
            Ok((alg_id(OID_RSA_SHA256, true), sig.to_vec()))
        }
    }
}

fn random_serial() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    // Ensure positive (clear high bit of first byte)
    bytes[0] &= 0x7f;
    // Remove leading zero bytes
    let mut result = bytes.to_vec();
    while result.len() > 1 && result[0] == 0 {
        result.remove(0);
    }
    result
}

/// Build a DER-encoded Name from a list of (oid, value) pairs.
/// Each attribute is encoded as UTF8String.
fn make_name(attrs: &[(&[u64], &[u8])]) -> Vec<u8> {
    let mut name_content = Der::new();
    for (oid, value) in attrs {
        let mut d = Der::new();
        d.oid(oid);
        d.raw(0x0c, value); // UTF8String
        let mut atv = Der::new();
        atv.seq(&d.into_vec()); // AttributeTypeAndValue
        let mut set = Der::new();
        set.raw(0x31, &atv.into_vec()); // SET OF
        name_content.0.extend(set.into_vec());
    }
    let mut name = Der::new();
    name.seq(&name_content.into_vec()); // Name
    name.into_vec()
}

fn default_name() -> Vec<u8> {
    // CN=Android Keystore Key (matches Django's _build_attested_chain)
    make_name(&[(OID_COMMON_NAME, b"Android Keystore Key")])
}

/// Build the attested certificate chain for `server_keybox` mode.
///
/// Mirrors Django's `_build_attested_chain`:
///   1. Generate a NEW leaf keypair (EC P-256 or RSA 2048).
///   2. Use the stored identity's private key as the ISSUER to sign the leaf.
///   3. Chain = [new_leaf, issuer_cert, ...CA_certs].
///
/// Returns (chain_pem, new_leaf_key_pem).
pub fn build_attested_chain(
    identity: &DeviceIdentity,
    p: &AttestationParams,
) -> anyhow::Result<(String, String)> {
    // 1) Load the stored private key as the ISSUER key.
    let issuer_key = parse_private_key(identity.private_key_pem_cipher.as_bytes())?;

    // 2) Parse the stored certificate chain.
    let ders = parse_chain_pem(&identity.certificate_chain_pem)?;
    if ders.is_empty() {
        anyhow::bail!(
            "empty certificate_chain_pem for device {}",
            identity.device_id
        );
    }
    let (_, issuer_cert) = parse_x509_certificate(&ders[0])
        .map_err(|e| anyhow::anyhow!("failed to parse issuer cert: {e}"))?;
    let issuer_name = issuer_cert.subject().as_raw().to_vec();

    // 3) Generate a NEW leaf key (EC P-256 or RSA 2048).
    let (leaf_key, leaf_key_pem) = generate_leaf_key(p)?;
    let spki = public_key_der(&leaf_key)?;

    // Serial number bytes from params (AOSP convention: serial=1).
    let mut serial_bytes = p.serial.to_be_bytes().to_vec();
    while serial_bytes.len() > 1 && serial_bytes[0] == 0 {
        serial_bytes.remove(0);
    }
    if serial_bytes[0] & 0x80 != 0 {
        serial_bytes.insert(0, 0);
    }

    // Subject name: honour the caller-requested leaf subject, else Django's
    // "CN=Android Keystore Key".
    let subject_name = p.subject_name.clone().unwrap_or_else(default_name);

    // notBefore: honour the caller-requested time when provided, else the
    // precise creation timestamp (matches Django).
    let not_before_ms = p
        .not_before_ms
        .filter(|&v| v > 0)
        .unwrap_or(p.creation_datetime_ms);
    let not_before_ts = chrono::DateTime::from_timestamp_millis(not_before_ms as i64)
        .unwrap_or_else(chrono::Utc::now);
    // Dates at/after 2050 must use GeneralizedTime: as UTCTime the two-digit
    // year maps `50`-`99` to 1950-1999, so "500101000000Z" would encode as an
    // already-expired 1950 certificate (see `Der::generalized_time`).
    const GT_THRESHOLD_MS: i64 = 2_524_608_000_000; // 2050-01-01T00:00:00Z

    // notBefore 与 notAfter 同规则：2050 及以后若仍用两位年 UTCTime 会回旋成 1951。
    let (not_before, not_before_is_generalized) =
        if not_before_ts.timestamp_millis() >= GT_THRESHOLD_MS {
            (not_before_ts.format("%Y%m%d%H%M%SZ").to_string(), true)
        } else {
            (not_before_ts.format("%y%m%d%H%M%SZ").to_string(), false)
        };
    // notAfter: honour the caller-requested expiry, else fixed 2048-01-01
    // (matches Django's _build_attested_chain).
    //
    // caller 的 notBefore 要是已经晚于这个默认值（2050 以后那种），再顶着
    // 2048 就会做出一张 notBefore > notAfter 的"尚未生效"证书，链校验可能被
    // 整条拒掉。这种情况把 notAfter 顺延一天，至少保证区间是正的。
    const DEFAULT_NOT_AFTER_MS: u64 = 2_461_449_600_000; // 2048-01-01T00:00:00Z
    let not_after_ms = match p.not_after_ms.filter(|&v| v > 0) {
        Some(ms) => ms,
        None if not_before_ms >= DEFAULT_NOT_AFTER_MS => not_before_ms.saturating_add(86_400_000),
        None => DEFAULT_NOT_AFTER_MS,
    };
    let (not_after, not_after_is_generalized) =
        match chrono::DateTime::from_timestamp_millis(not_after_ms as i64) {
            Some(t) if t.timestamp_millis() >= GT_THRESHOLD_MS => {
                (t.format("%Y%m%d%H%M%SZ").to_string(), true)
            }
            Some(t) => (t.format("%y%m%d%H%M%SZ").to_string(), false),
            None => ("480101000000Z".to_string(), false),
        };

    // TBSCertificate (X.509 v3)
    let mut t = Der::new();
    t.explicit(0, &wrap_int(2)); // version [0] EXPLICIT INTEGER 2
    t.int(&serial_bytes);
    // The SignatureAlgorithm in TBSCertificate uses the ISSUER key's algorithm.
    let sig_alg_tbs = sig_alg_for_key(&issuer_key);
    t.0.extend(sig_alg_tbs);
    t.0.extend(&issuer_name);
    let mut validity = Der::new();
    if not_before_is_generalized {
        validity.generalized_time(&not_before);
    } else {
        validity.utctime(&not_before);
    }
    if not_after_is_generalized {
        validity.generalized_time(&not_after);
    } else {
        validity.utctime(&not_after);
    }
    t.raw(0x30, &validity.into_vec());
    t.0.extend(&subject_name);
    t.0.extend(&spki);

    // extensions [3] EXPLICIT
    // NOTE: no BasicConstraints on the leaf — AOSP adds it only when the key
    // has KeyCertSign purpose (a CA key). Normal attestation keys (SIGN +
    // ATTEST_KEY) get KeyUsage + the attestation extension only; adding
    // CA=false here diverged from real leaves and broke STRONG integrity.
    let ext_value = build_attestation_extension_der(p);
    let ku_der = {
        let mut d = Der::new();
        d.bit_string(&[0x80, 0x00]); // digitalSignature
        d.into_vec()
    };
    let mut exts_content = Der::new();
    exts_content
        .0
        .extend(ext_entry(OID_KEY_USAGE, true, &ku_der));
    exts_content
        .0
        .extend(ext_entry(ATTESTATION_OID, false, &ext_value));
    let mut exts = Der::new();
    exts.seq(&exts_content.into_vec());
    t.explicit(3, &exts.into_vec());

    let tbs_content = t.into_vec();

    // Build the full TBSCertificate TLV (SEQUENCE wrapping the content).
    // X.509 requires the signature to cover the complete DER-encoded
    // TBSCertificate (including the SEQUENCE tag + length prefix), not just
    // the inner content. Otherwise the verifier computes a different hash.
    let mut tbs_tlv = Der::new();
    tbs_tlv.raw(0x30, &tbs_content);
    let tbs_full = tbs_tlv.into_vec();

    // Sign with the ISSUER key (stored private key), not the leaf key.
    let (sig_alg_final, signature) = sign_tbs(&issuer_key, &tbs_full)?;

    let mut cert = Der::new();
    let mut inner = Der::new();
    inner.0.extend(&tbs_full);
    inner.0.extend(sig_alg_final);
    inner.bit_string(&signature);
    cert.seq(&inner.into_vec());
    let cert_der = cert.into_vec();

    let pem_leaf = pem::encode(&pem::Pem::new("CERTIFICATE", cert_der));

    // 5) Assemble chain: [new_leaf, issuer_cert, ...CA_certs]
    //    Match Django's `full_chain = [leaf_cert] + issuer_certs`.
    let mut chain = String::new();
    chain.push_str(&pem_leaf);
    chain.push('\n');
    for der in &ders {
        chain.push_str(&pem::encode(&pem::Pem::new("CERTIFICATE", der.clone())));
        chain.push('\n');
    }

    Ok((chain, leaf_key_pem))
}

/// Generate a new leaf key matching the attestation params: EC P-256/P-384/
/// P-521, or RSA with the requested key size (default 2048). Returns
/// (KeyMaterial, PEM_string).
pub fn generate_leaf_key(p: &AttestationParams) -> anyhow::Result<(KeyMaterial, String)> {
    use pkcs8::EncodePrivateKey;

    if p.algorithm == KM_ALG_RSA {
        let mut rng = rand::rngs::OsRng;
        let size = if p.key_size >= 1024 && p.key_size <= 8192 {
            p.key_size as usize
        } else {
            2048
        };
        let private = rsa::RsaPrivateKey::new(&mut rng, size)?;
        let pem = private.to_pkcs8_pem(pkcs8::LineEnding::LF)?;
        Ok((KeyMaterial::Rsa(Box::new(private)), pem.to_string()))
    } else {
        match p.ec_curve {
            Some(KM_EC_CURVE_P_384) => {
                use p384::elliptic_curve::rand_core::OsRng;
                let secret = P384SecretKey::random(&mut OsRng);
                let pem = secret.to_sec1_pem(pkcs8::LineEnding::LF)?;
                Ok((KeyMaterial::Ec(EcKey::P384(secret)), pem.to_string()))
            }
            Some(KM_EC_CURVE_P_521) => {
                use p521::elliptic_curve::rand_core::OsRng;
                let secret = P521SecretKey::random(&mut OsRng);
                let pem = secret.to_sec1_pem(pkcs8::LineEnding::LF)?;
                Ok((KeyMaterial::Ec(EcKey::P521(secret)), pem.to_string()))
            }
            // P-256 (curve 1) is the default and must be handled explicitly;
            // previously `Some(1)` fell through to the bail below and every
            // server_keybox EC attestation failed with "unsupported EC curve 1".
            Some(KM_EC_CURVE_P_256) | None => {
                use p256::elliptic_curve::rand_core::OsRng;
                let secret = P256SecretKey::random(&mut OsRng);
                let pem = secret.to_sec1_pem(pkcs8::LineEnding::LF)?;
                Ok((KeyMaterial::Ec(EcKey::P256(secret)), pem.to_string()))
            }
            Some(other) => anyhow::bail!("server_keybox: unsupported EC curve {other}"),
        }
    }
}

/// A freshly generated self-signed identity (private key PEM + certificate
/// chain PEM) used as a last-resort fallback when a device has no uploaded
/// keybox certificate and no B-side device is online.
#[derive(Debug, Clone)]
pub struct SelfSignedIdentity {
    pub private_key_pem: String,
    pub certificate_chain_pem: String,
    pub algorithm: String,
}

/// Generate a self-signed identity for the requested algorithm.
///
/// - `ec`  -> P-256 SEC1 key, self-signed ECDSA-with-SHA256 cert.
/// - `rsa` -> 2048-bit RSA PKCS#8 key, self-signed sha256WithRSAEncryption cert.
///
/// The returned chain is a single leaf certificate (subject == issuer), so it
/// can be fed through `build_attested_chain`-style signing like a stored
/// identity's leaf key.
pub fn generate_self_signed(algorithm: &str) -> anyhow::Result<SelfSignedIdentity> {
    match algorithm.to_ascii_lowercase().as_str() {
        "rsa" => generate_self_signed_rsa(),
        _ => generate_self_signed_ec(),
    }
}

fn generate_self_signed_ec() -> anyhow::Result<SelfSignedIdentity> {
    use p256::elliptic_curve::rand_core::OsRng;

    // Generate intermediate CA key (this will be the stored identity's key)
    let intermediate_secret = p256::SecretKey::random(&mut OsRng);
    let intermediate_pem = intermediate_secret.to_sec1_pem(pkcs8::LineEnding::LF)?;
    let intermediate_key = KeyMaterial::Ec(EcKey::P256(intermediate_secret));

    // Generate root CA key
    let root_secret = p256::SecretKey::random(&mut OsRng);
    let root_key = KeyMaterial::Ec(EcKey::P256(root_secret));

    let chain_pem = build_self_signed_chain(&intermediate_key, &root_key)?;
    Ok(SelfSignedIdentity {
        private_key_pem: intermediate_pem.to_string(),
        certificate_chain_pem: chain_pem,
        algorithm: "ec".to_string(),
    })
}

fn generate_self_signed_rsa() -> anyhow::Result<SelfSignedIdentity> {
    use pkcs8::EncodePrivateKey;
    let mut rng = rand::rngs::OsRng;

    // Generate intermediate CA key (this will be the stored identity's key)
    let intermediate_private = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
    let intermediate_pem = intermediate_private.to_pkcs8_pem(pkcs8::LineEnding::LF)?;
    let intermediate_key = KeyMaterial::Rsa(Box::new(intermediate_private));

    // Generate root CA key
    let root_private = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
    let root_key = KeyMaterial::Rsa(Box::new(root_private));

    let chain_pem = build_self_signed_chain(&intermediate_key, &root_key)?;
    Ok(SelfSignedIdentity {
        private_key_pem: intermediate_pem.to_string(),
        certificate_chain_pem: chain_pem,
        algorithm: "rsa".to_string(),
    })
}

/// Build a self-signed X.509 CA chain (intermediate CA + root CA) for use as
/// the issuer identity in `build_attested_chain`.
///
/// The returned chain is [intermediate_cert_pem, root_cert_pem] so that
/// `build_attested_chain` can parse the first element as the issuer and sign a
/// new attestation leaf with the intermediate key, yielding a final chain of
/// [new_leaf, intermediate, root] — matching Django's 3-level structure.
///
/// Root CA:  self-signed, BasicConstraints ca=True pathLen=None
///           KeyUsage: digitalSignature + keyCertSign + cRLSign
/// Int CA:   signed by root, BasicConstraints ca=True pathLen=0
///           KeyUsage: digitalSignature + keyCertSign + cRLSign
fn build_self_signed_chain(
    intermediate_key: &KeyMaterial,
    root_key: &KeyMaterial,
) -> anyhow::Result<String> {
    let now = chrono::Utc::now();
    let not_before = now.format("%y%m%d%H%M%SZ").to_string(); // precise now, matches Django's _generate_self_signed_cert_chain
    let not_after_2049 = "490101000000Z".to_string(); // 2049-01-01 (UTCTime, matches Django)
                                                      // 2050-01-01 as GeneralizedTime (4-digit year). As UTCTime, "50" decodes
                                                      // to 1950 (expired) — see `Der::generalized_time`.
    let not_after_2050 = "20500101000000Z".to_string();

    // ---- Names matching Django ----
    // Root: C=US, O=Android, CN=Android Root CA
    let root_name = make_name(&[
        (OID_COUNTRY_NAME, b"US"),
        (OID_ORG_NAME, b"Android"),
        (OID_COMMON_NAME, b"Android Root CA"),
    ]);
    // Intermediate: C=US, O=Android, CN=Android Intermediate CA
    let ca_name = make_name(&[
        (OID_COUNTRY_NAME, b"US"),
        (OID_ORG_NAME, b"Android"),
        (OID_COMMON_NAME, b"Android Intermediate CA"),
    ]);

    // ---- KeyUsage DER for CA certs (digitalSignature + keyCertSign + cRLSign) ----
    let ca_ku_der = {
        let mut d = Der::new();
        d.bit_string(&[0x86, 0x00]); // digitalSignature(0) | keyCertSign(5) | cRLSign(6)
        d.into_vec()
    };

    // ---- BasicConstraints DER helpers ----
    // For root (ca=True, no pathLenConstraint):
    //   SEQUENCE { BOOLEAN TRUE }
    let bc_root_der = {
        let mut d = Der::new();
        d.bool(true);
        let mut seq = Der::new();
        seq.seq(&d.into_vec());
        seq.into_vec()
    };
    // For intermediate (ca=True, pathLenConstraint=0):
    //   SEQUENCE { BOOLEAN TRUE, INTEGER 0 }
    let bc_ca_der = {
        let mut d = Der::new();
        d.bool(true);
        d.int(&[0x00]);
        let mut seq = Der::new();
        seq.seq(&d.into_vec());
        seq.into_vec()
    };

    // ========================================================================
    // 1) Build root self-signed certificate
    // ========================================================================
    let root_spki = public_key_der(root_key)?;
    let root_serial = random_serial();

    let mut root_tbs = Der::new();
    root_tbs.explicit(0, &wrap_int(2)); // version [0] EXPLICIT INTEGER 2
    root_tbs.int(&root_serial);
    let root_sig_alg = sig_alg_for_key(root_key);
    root_tbs.0.extend(root_sig_alg);
    root_tbs.0.extend(&root_name); // issuer = root (self-signed)
    let mut validity = Der::new();
    validity.utctime(&not_before);
    validity.generalized_time(&not_after_2050);
    root_tbs.raw(0x30, &validity.into_vec());
    root_tbs.0.extend(&root_name); // subject = root
    root_tbs.0.extend(&root_spki);

    // Extensions for root
    let mut root_exts_content = Der::new();
    root_exts_content
        .0
        .extend(ext_entry(OID_KEY_USAGE, true, &ca_ku_der));
    root_exts_content
        .0
        .extend(ext_entry(OID_BASIC_CONSTRAINTS, true, &bc_root_der));
    let mut root_exts = Der::new();
    root_exts.seq(&root_exts_content.into_vec());
    root_tbs.explicit(3, &root_exts.into_vec());

    let root_tbs_content = root_tbs.into_vec();
    // Build full TBSCertificate TLV for correct signature coverage
    let mut root_tbs_tlv = Der::new();
    root_tbs_tlv.raw(0x30, &root_tbs_content);
    let root_tbs_full = root_tbs_tlv.into_vec();
    let (root_sig_alg_final, root_signature) = sign_tbs(root_key, &root_tbs_full)?;

    let mut root_cert = Der::new();
    let mut root_inner = Der::new();
    root_inner.0.extend(&root_tbs_full);
    root_inner.0.extend(root_sig_alg_final);
    root_inner.bit_string(&root_signature);
    root_cert.seq(&root_inner.into_vec());
    let root_cert_der = root_cert.into_vec();

    // ========================================================================
    // 2) Build intermediate CA certificate (signed by root)
    // ========================================================================
    let ca_spki = public_key_der(intermediate_key)?;
    let ca_serial = random_serial();

    let mut ca_tbs = Der::new();
    ca_tbs.explicit(0, &wrap_int(2)); // version [0] EXPLICIT INTEGER 2
    ca_tbs.int(&ca_serial);
    let ca_sig_alg_tbs = sig_alg_for_key(root_key); // issuer is root
    ca_tbs.0.extend(ca_sig_alg_tbs);
    ca_tbs.0.extend(&root_name); // issuer = root
    let mut ca_validity = Der::new();
    ca_validity.utctime(&not_before);
    ca_validity.utctime(&not_after_2049);
    ca_tbs.raw(0x30, &ca_validity.into_vec());
    ca_tbs.0.extend(&ca_name); // subject = intermediate
    ca_tbs.0.extend(&ca_spki);

    // Extensions for intermediate CA
    let mut ca_exts_content = Der::new();
    ca_exts_content
        .0
        .extend(ext_entry(OID_KEY_USAGE, true, &ca_ku_der));
    ca_exts_content
        .0
        .extend(ext_entry(OID_BASIC_CONSTRAINTS, true, &bc_ca_der));
    let mut ca_exts = Der::new();
    ca_exts.seq(&ca_exts_content.into_vec());
    ca_tbs.explicit(3, &ca_exts.into_vec());

    let ca_tbs_content = ca_tbs.into_vec();
    // Build full TBSCertificate TLV for correct signature coverage
    let mut ca_tbs_tlv = Der::new();
    ca_tbs_tlv.raw(0x30, &ca_tbs_content);
    let ca_tbs_full = ca_tbs_tlv.into_vec();
    // Sign with root key
    let (ca_sig_alg_final, ca_signature) = sign_tbs(root_key, &ca_tbs_full)?;

    let mut ca_cert = Der::new();
    let mut ca_inner = Der::new();
    ca_inner.0.extend(&ca_tbs_full);
    ca_inner.0.extend(ca_sig_alg_final);
    ca_inner.bit_string(&ca_signature);
    ca_cert.seq(&ca_inner.into_vec());
    let ca_cert_der = ca_cert.into_vec();

    // ========================================================================
    // 3) Assemble chain: [intermediate_cert, root_cert]
    //    build_attested_chain will prepend the new leaf, yielding
    //    [new_leaf, intermediate, root]
    // ========================================================================
    let mut chain = String::new();
    chain.push_str(&pem::encode(&pem::Pem::new("CERTIFICATE", ca_cert_der)));
    chain.push('\n');
    chain.push_str(&pem::encode(&pem::Pem::new("CERTIFICATE", root_cert_der)));
    chain.push('\n');

    Ok(chain)
}

/// Parse a PEM chain into DER certificates.
pub fn parse_chain_pem(pem: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for p in pem::parse_many(pem)? {
        if p.tag() == "CERTIFICATE" {
            out.push(p.contents().to_vec());
        }
    }
    Ok(out)
}

pub fn rsa_exponent() -> i64 {
    65537
}

// ---------------------------------------------------------------------------
// Reading a device-produced attestation record back out of its chain
// ---------------------------------------------------------------------------

/// Boot state a device reports in its own attestation record, parsed from the
/// certificate chain a B-side returns for an `attest` task.  Every field is
/// optional: chains differ per KeyMint version, and the vendor/boot patch
/// levels are vendor extensions many devices never emit.
#[derive(Debug, Clone, Default)]
pub struct DeviceBootInfo {
    pub boot_key: Option<String>,
    pub boot_hash: Option<String>,
    pub device_locked: Option<bool>,
    /// 0 = verified, 1 = self-signed, 2 = unverified, 3 = failed.
    pub verified_boot_state: Option<i64>,
    /// KeyMint attestation security level of the leaf: 0 = software, 1 = TEE,
    /// 2 = StrongBox.  Deliberately NOT part of [`DeviceBootInfo::is_empty`]:
    /// it says nothing about the device's boot state, so letting it turn an
    /// otherwise empty record non-empty would make the status page show a boot
    /// block for a chain that carries no boot information.  Smart mode reads it
    /// through [`attestation_security_level_from_chain`] instead.
    pub security_level: Option<i64>,
    /// `ATTESTATION_APPLICATION_ID` (tag 709) as the chain itself reports it:
    /// the package name(s) the key was minted for, `com.example` or
    /// `com.example@12`.  Like `security_level` it is deliberately NOT part of
    /// [`DeviceBootInfo::is_empty`] — it says nothing about the boot state, and
    /// the status page reads it through
    /// [`attestation_application_id_from_chain`] instead.
    pub aaid: Option<String>,
    /// KeyMint os_version in its packed form (e.g. 160000 = Android 16).
    pub os_version: Option<i64>,
    pub patch_system: Option<i64>,
    pub patch_vendor: Option<i64>,
    pub patch_boot: Option<i64>,
    /// Samsung's extra block, when the chain carries one.
    pub knox: Option<KnoxInfo>,
}

impl DeviceBootInfo {
    pub fn is_empty(&self) -> bool {
        self.boot_key.is_none()
            && self.boot_hash.is_none()
            && self.device_locked.is_none()
            && self.verified_boot_state.is_none()
            && self.os_version.is_none()
            && self.patch_system.is_none()
            && self.patch_vendor.is_none()
            && self.patch_boot.is_none()
            && self.knox.is_none()
    }
}

/// Samsung's Knox attestation block (OID 1.3.6.1.4.1.236.11.3.23.7).  It sits
/// next to the ASN.1 attestation extension rather than replacing it, so the
/// boot state above is parsed from that one; this is the part Knox adds.
/// `None` fields mean the vendor did not report them.
#[derive(Debug, Clone, Default)]
pub struct KnoxInfo {
    /// Echo of the challenge the caller sent, as a printable string.
    pub challenge: Option<String>,
    /// The device's own answer to "did you attest IDs" (`idAttest` entry).
    pub id_attest: Option<String>,
    /// Hash of the signed attestation record, hex.
    pub record_hash: Option<String>,
    /// Integrity statuses: 0 normal, 1 abnormal, 2 not supported.
    pub trust_boot: Option<i64>,
    pub warranty: Option<i64>,
    pub icd: Option<i64>,
    pub kernel: Option<i64>,
    pub system: Option<i64>,
    /// Caller authentication (PROCA) result, and Knox's verdict on the
    /// calling package: same 0/1/2 scale.
    pub caller_auth: Option<i64>,
    pub package_auth: Option<i64>,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Patch levels are YYYYMM for `os_patch_level` (706) but YYYYMMDD for
/// `vendor_patch_level` / `boot_patch_level` (718/719) — both forms are
/// accepted, and anything that is not a plausible date is dropped (some
/// vendors reuse these tag numbers for unrelated integers).
fn as_patch_level(value: i64) -> Option<i64> {
    let (year, month, day) = match value {
        v if (200_000..3_000_000).contains(&v) => (v / 100, v % 100, None),
        v if (20_000_000..300_000_000).contains(&v) => (v / 10_000, (v / 100) % 100, Some(v % 100)),
        _ => return None,
    };
    let day_ok = day.is_none_or(|d| (1..=31).contains(&d));
    ((2000..=2099).contains(&year) && (1..=12).contains(&month) && day_ok).then_some(value)
}

/// One TLV of a DER stream.  Context tags above 30 use the long form, which a
/// single-byte tag read would silently misparse.
struct Tlv<'a> {
    tag: u64,
    value: &'a [u8],
}

fn take_tlv<'a>(buf: &'a [u8], pos: &mut usize) -> Option<Tlv<'a>> {
    if *pos >= buf.len() {
        return None;
    }
    let mut tag = buf[*pos] as u64;
    *pos += 1;
    if tag & 0x1f == 0x1f {
        tag = 0;
        loop {
            let b = *buf.get(*pos)?;
            *pos += 1;
            tag = (tag << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let first = *buf.get(*pos)?;
    *pos += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 8 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | *buf.get(*pos)? as usize;
            *pos += 1;
        }
        len
    };
    // len 最多 8 字节可达 usize::MAX，加法必须防回绕，否则下面切片会 panic
    let end = pos.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let value = &buf[*pos..end];
    *pos = end;
    Some(Tlv { tag, value })
}

/// AuthorizationList entries are `[tag] EXPLICIT <inner TLV>`, so unwrap one
/// level before reading the value.
fn explicit_inner(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut pos = 0;
    let inner = take_tlv(bytes, &mut pos)?;
    Some((inner.tag, inner.value))
}

fn explicit_int(bytes: &[u8]) -> Option<i64> {
    let (_, raw) = explicit_inner(bytes)?;
    der_int(raw)
}

/// The big-endian integer held by a bare INTEGER/ENUMERATED TLV value.  Unlike
/// [`explicit_int`] the bytes are the value itself, not an `[n] EXPLICIT`
/// wrapper — `attestationSecurityLevel` is written as a plain ENUMERATED.
fn der_int(raw: &[u8]) -> Option<i64> {
    if raw.is_empty() || raw.len() > 8 {
        return None;
    }
    let mut value: i64 = 0;
    for b in raw {
        value = (value << 8) | i64::from(*b);
    }
    Some(value)
}

/// `AttestationApplicationId` (KeyMint tag 709) — the package identity a key
/// was minted for.  KeyMint writes it as `[709] EXPLICIT OCTET STRING` holding
/// the DER below; the EAT/CBOR form carries the same DER inside a byte string,
/// and a few implementations skip the OCTET STRING wrapper.
///
/// ```text
/// AttestationApplicationId ::= SEQUENCE {
///     packageInfos     SET OF AttestationPackageInfo,
///     signatureDigests SET OF OCTET STRING }
/// AttestationPackageInfo ::= SEQUENCE {
///     packageName OCTET STRING,
///     version     INTEGER }
/// ```
///
/// Returns the package names, `name@version` when a non-zero version is given,
/// comma-separated.  `None` when there is nothing readable in there: this is a
/// diagnostic string, so a malformed AAID is dropped rather than reported.
fn parse_attestation_application_id(entry: &[u8]) -> Option<String> {
    /// Everything beyond this is cut — the device entry has to stay small.
    const MAX_CHARS: usize = 160;
    const SEQUENCE_TAG: u64 = 0x30;

    let mut pos = 0;
    let first = take_tlv(entry, &mut pos)?;
    // The `[709]` value is the OCTET STRING, the EAT claim is the DER itself;
    // normalise to the DER.
    let der = if first.tag == SEQUENCE_TAG {
        entry
    } else {
        first.value
    };
    let mut p = 0;
    let sequence = take_tlv(der, &mut p)?;
    let mut q = 0;
    let packages = take_tlv(sequence.value, &mut q)?;
    let mut names: Vec<String> = Vec::new();
    let mut r = 0;
    while let Some(info) = take_tlv(packages.value, &mut r) {
        let mut s = 0;
        let Some(name) = take_tlv(info.value, &mut s) else {
            continue;
        };
        let mut text = String::from_utf8_lossy(name.value).into_owned();
        // Version 0 means "not given" (AOSP writes 0 when the caller did not
        // supply one), so it is left off instead of shown as `@0`.
        if let Some(version) = take_tlv(info.value, &mut s).and_then(|v| der_int(v.value)) {
            if version != 0 {
                text.push_str(&format!("@{version}"));
            }
        }
        if !text.is_empty() {
            names.push(text);
        }
    }
    if names.is_empty() {
        return None;
    }
    let mut text = names.join(", ");
    if text.chars().count() > MAX_CHARS {
        text = text.chars().take(MAX_CHARS).collect();
        text.push('…');
    }
    Some(text)
}

fn read_auth_list(list: &[u8], out: &mut DeviceBootInfo) {
    let mut pos = 0;
    while let Some(entry) = take_tlv(list, &mut pos) {
        match entry.tag {
            704 => {
                // RootOfTrust ::= SEQUENCE { key OCTET STRING, locked BOOLEAN,
                //                          state ENUMERATED, hash OCTET STRING }
                let Some((_, seq)) = explicit_inner(entry.value) else {
                    continue;
                };
                let mut p = 0;
                if let Some(key) = take_tlv(seq, &mut p) {
                    out.boot_key = Some(to_hex(key.value));
                }
                if let Some(locked) = take_tlv(seq, &mut p) {
                    out.device_locked = Some(!locked.value.is_empty() && locked.value != [0]);
                }
                if let Some(state) = take_tlv(seq, &mut p) {
                    out.verified_boot_state = state.value.last().map(|b| i64::from(*b));
                }
                if let Some(hash) = take_tlv(seq, &mut p) {
                    out.boot_hash = Some(to_hex(hash.value));
                }
            }
            705 => out.os_version = explicit_int(entry.value),
            706 => out.patch_system = explicit_int(entry.value).and_then(as_patch_level),
            // 718/719 是本服务 record builder 用的 vendor/boot patch 编号。
            // 注意 AOSP 的 707/708 是 UNIQUE_ID/ATTESTATION_CHALLENGE（OCTET
            // STRING），不能当 patch 级别的别名收进来——否则 challenge 之类
            // 的随机字节会被 explicit_int 累积成整数，落在日期区间内就编造
            // 出一条假的 patch 值。
            // ATTESTATION_APPLICATION_ID。链是“谁的身份”出的就看它，所以
            // 不能像别的 tag 那样一丢了事。
            709 => out.aaid = parse_attestation_application_id(entry.value),
            718 => out.patch_vendor = explicit_int(entry.value).and_then(as_patch_level),
            719 => out.patch_boot = explicit_int(entry.value).and_then(as_patch_level),
            _ => {}
        }
    }
}

/// KeyMint's CBOR attestation extension (OID 1.3.6.1.4.1.11129.2.1.25): the
/// same authorization lists as the ASN.1 form, but encoded as a CBOR map with
/// the claim numbers AOSP's `EatClaim` defines — KeyMint tags are renumbered
/// `-80000 - tag`, and the non-KeyMint claims start below `-82000`.  This
/// reader keeps only what the status page shows, which is why it is not a
/// general CBOR decoder.
mod eat {
    use super::{as_patch_level, parse_attestation_application_id, to_hex, DeviceBootInfo};
    use anyhow::{anyhow, bail, Result};

    const CLAIM_SECURITY_LEVEL: i64 = -76_002;
    const CLAIM_SUBMODS: i64 = -76_000;
    const CLAIM_BOOT_STATE: i64 = -76_003;
    const CLAIM_VERIFIED_BOOT_KEY: i64 = -82_001;
    const CLAIM_DEVICE_LOCKED: i64 = -82_002;
    const CLAIM_VERIFIED_BOOT_HASH: i64 = -82_003;
    const CLAIM_OFFICIAL_BUILD: i64 = -82_006;
    const CLAIM_OS_VERSION: i64 = -80_000 - 705;
    const CLAIM_OS_PATCHLEVEL: i64 = -80_000 - 706;
    const CLAIM_VENDOR_PATCHLEVEL: i64 = -80_000 - 718;
    const CLAIM_BOOT_PATCHLEVEL: i64 = -80_000 - 719;
    /// KeyMint's ATTESTATION_APPLICATION_ID (709), renumbered the same way.
    const CLAIM_ATTESTATION_APPLICATION_ID: i64 = -80_000 - 709;
    const SUBMOD_SOFTWARE: &str = "software";
    const SUBMOD_TEE: &str = "tee";
    /// Keeps a hand-crafted chain from recursing the stack away.
    const MAX_DEPTH: usize = 16;

    /// A decoded CBOR value.  Shapes no claim here uses (tags, floats,
    /// indefinite lengths) come back as `Other`.
    enum Cbor<'a> {
        Uint(u64),
        Negint(u64),
        Bytes(&'a [u8]),
        Text(&'a str),
        Bool(bool),
        Array(Vec<Cbor<'a>>),
        Map(Vec<(Cbor<'a>, Cbor<'a>)>),
        Other,
    }

    /// Fill in everything the extension attests to.  A payload that is not a
    /// CBOR map is an error; individual claims that are missing or malformed
    /// are left out, the same way `read_auth_list` treats the DER form.
    pub fn read(bytes: &[u8], out: &mut DeviceBootInfo) -> Result<()> {
        let mut pos = 0;
        let Cbor::Map(claims) = value(bytes, &mut pos, 0)? else {
            bail!("EAT attestation extension is not a CBOR map");
        };
        // 顶层 map 之后不允许尾随数据，与 DER 路径的宽严一致，畸形载荷不做半接受。
        if pos != bytes.len() {
            bail!("EAT extension has trailing data after the top-level map");
        }

        if let Some(Cbor::Bytes(key)) = get(&claims, CLAIM_VERIFIED_BOOT_KEY) {
            out.boot_key = Some(to_hex(key));
        }
        if let Some(Cbor::Bytes(hash)) = get(&claims, CLAIM_VERIFIED_BOOT_HASH) {
            out.boot_hash = Some(to_hex(hash));
        }
        if let Some(Cbor::Bool(locked)) = get(&claims, CLAIM_DEVICE_LOCKED) {
            out.device_locked = Some(*locked);
        }
        out.security_level = get(&claims, CLAIM_SECURITY_LEVEL)
            .and_then(as_int)
            .and_then(eat_security_level);

        let official_build = matches!(get(&claims, CLAIM_OFFICIAL_BUILD), Some(Cbor::Bool(true)));
        if let Some(Cbor::Array(states)) = get(&claims, CLAIM_BOOT_STATE) {
            out.verified_boot_state = verified_boot_state(states, official_build);
        }
        // AAID：多数实现把它放在 submods 的 software/tee 子 map 里（和 OS 版本
        // 那几个一样），也有放顶层的，两处都收。
        if let Some(Cbor::Bytes(app_id)) = get(&claims, CLAIM_ATTESTATION_APPLICATION_ID) {
            out.aaid = parse_attestation_application_id(app_id);
        }

        if let Some(Cbor::Map(submods)) = get(&claims, CLAIM_SUBMODS) {
            for name in [SUBMOD_SOFTWARE, SUBMOD_TEE] {
                if let Some(Cbor::Map(submod)) = get_text(submods, name) {
                    read_submod(submod, out);
                }
            }
        }
        Ok(())
    }

    /// AOSP's mapping of the five `bootState` booleans — `[verified, green,
    /// yellow, orange, debug-permanent-disable]` — plus `officialBuild`, onto
    /// KeyMint's verified-boot state.  Anything that does not fit the shape
    /// (wrong length, debug permanently disabled, official build that is not
    /// verified) is reported as no state at all.
    fn verified_boot_state(states: &[Cbor<'_>], official_build: bool) -> Option<i64> {
        if states.len() != 5 {
            return None;
        }
        let mut flags = [false; 5];
        for (flag, state) in flags.iter_mut().zip(states) {
            match state {
                Cbor::Bool(value) => *flag = *value,
                _ => return None,
            }
        }
        let verified_or_self_signed = flags[0];
        if flags[4]
            || (verified_or_self_signed != flags[1]
                && verified_or_self_signed != flags[2]
                && verified_or_self_signed != flags[3])
        {
            return None;
        }
        match (verified_or_self_signed, official_build) {
            (false, false) => Some(2), // unverified
            (false, true) => None,     // AOSP calls this impossible
            (true, true) => Some(0),   // verified
            (true, false) => Some(1),  // self-signed
        }
    }

    fn read_submod(submod: &[(Cbor<'_>, Cbor<'_>)], out: &mut DeviceBootInfo) {
        for (claim, value) in submod {
            match as_int(claim) {
                Some(CLAIM_OS_VERSION) => out.os_version = as_int(value),
                Some(CLAIM_OS_PATCHLEVEL) => {
                    out.patch_system = as_int(value).and_then(as_patch_level);
                }
                Some(CLAIM_VENDOR_PATCHLEVEL) => {
                    out.patch_vendor = as_int(value).and_then(as_patch_level);
                }
                Some(CLAIM_BOOT_PATCHLEVEL) => {
                    out.patch_boot = as_int(value).and_then(as_patch_level);
                }
                // AAID 是 bstr，里面装的是与 ASN.1 那边相同的 DER。
                Some(CLAIM_ATTESTATION_APPLICATION_ID) => {
                    if let Cbor::Bytes(app_id) = value {
                        out.aaid = parse_attestation_application_id(app_id);
                    }
                }
                _ => {}
            }
        }
    }

    fn value<'a>(buf: &'a [u8], pos: &mut usize, depth: usize) -> Result<Cbor<'a>> {
        if depth > MAX_DEPTH {
            bail!("EAT claim is nested too deeply");
        }
        let (major, arg) = head(buf, pos)?;
        match major {
            0 => Ok(Cbor::Uint(arg)),
            1 => Ok(Cbor::Negint(arg)),
            2 => Ok(Cbor::Bytes(take(buf, pos, arg)?)),
            3 => Ok(Cbor::Text(std::str::from_utf8(take(buf, pos, arg)?)?)),
            4 => {
                let mut items = Vec::new();
                for _ in 0..as_count(arg)? {
                    items.push(value(buf, pos, depth + 1)?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let mut items = Vec::new();
                for _ in 0..as_count(arg)? {
                    let key = value(buf, pos, depth + 1)?;
                    let claim = value(buf, pos, depth + 1)?;
                    items.push((key, claim));
                }
                Ok(Cbor::Map(items))
            }
            6 => {
                value(buf, pos, depth + 1)?;
                Ok(Cbor::Other)
            }
            7 => match arg {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                _ => Ok(Cbor::Other),
            },
            _ => Ok(Cbor::Other),
        }
    }

    /// Major type and argument of one CBOR item.  The reserved "indefinite
    /// length" forms are refused: KeyMint writes definite lengths.
    fn head(buf: &[u8], pos: &mut usize) -> Result<(u8, u64)> {
        let first = next(buf, pos)?;
        let width = match first & 0x1f {
            info @ 0..=23 => return Ok((first >> 5, u64::from(info))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => bail!("unsupported CBOR length encoding"),
        };
        let mut arg = 0u64;
        for _ in 0..width {
            arg = (arg << 8) | u64::from(next(buf, pos)?);
        }
        Ok((first >> 5, arg))
    }

    fn next(buf: &[u8], pos: &mut usize) -> Result<u8> {
        let byte = *buf.get(*pos).ok_or_else(|| anyhow!("truncated CBOR"))?;
        *pos += 1;
        Ok(byte)
    }

    fn take<'a>(buf: &'a [u8], pos: &mut usize, len: u64) -> Result<&'a [u8]> {
        let len = usize::try_from(len).map_err(|_| anyhow!("CBOR length out of range"))?;
        let end = pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("CBOR length overflow"))?;
        let value = buf
            .get(*pos..end)
            .ok_or_else(|| anyhow!("truncated CBOR"))?;
        *pos = end;
        Ok(value)
    }

    fn as_count(arg: u64) -> Result<usize> {
        usize::try_from(arg).map_err(|_| anyhow!("CBOR array or map is too long"))
    }

    fn get<'a>(claims: &'a [(Cbor<'a>, Cbor<'a>)], claim: i64) -> Option<&'a Cbor<'a>> {
        claims
            .iter()
            .find(|(key, _)| as_int(key) == Some(claim))
            .map(|(_, value)| value)
    }

    fn get_text<'a>(map: &'a [(Cbor<'a>, Cbor<'a>)], name: &str) -> Option<&'a Cbor<'a>> {
        map.iter()
            .find(|(key, _)| matches!(key, Cbor::Text(text) if *text == name))
            .map(|(_, value)| value)
    }

    /// EAT numbers its security level in its own scale — 1 = unrestricted,
    /// 3 = secure restricted, 4 = hardware.  Map it back onto KeyMint's
    /// 0/1/2 so the CBOR and DER paths report the same thing (same mapping as
    /// vvb2060 KeyAttestation's `EatAttestation.eatSecurityLevelToKeymint-
    /// SecurityLevel`).  Anything else is left unset.
    fn eat_security_level(level: i64) -> Option<i64> {
        match level {
            1 => Some(0),
            3 => Some(1),
            4 => Some(2),
            _ => None,
        }
    }

    /// CBOR encodes negatives as `-1 - n`, which is how `EatClaim` numbers its
    /// claims.
    fn as_int(value: &Cbor<'_>) -> Option<i64> {
        match value {
            Cbor::Uint(value) => i64::try_from(*value).ok(),
            Cbor::Negint(value) => Some(-1 - i64::try_from(*value).ok()?),
            _ => None,
        }
    }
}

/// Samsung's Knox extension (OID 1.3.6.1.4.1.236.11.3.23.7), which a Knox
/// device puts next to the ASN.1 attestation extension.
mod knox {
    use super::{explicit_inner, explicit_int, take_tlv, to_hex, KnoxInfo};

    const CHALLENGE: u64 = 0;
    const ID_ATTEST: u64 = 4;
    const INTEGRITY: u64 = 5;
    const RECORD_HASH: u64 = 6;

    const TRUST_BOOT: u64 = 0;
    const WARRANTY: u64 = 1;
    const ICD: u64 = 2;
    const KERNEL_STATUS: u64 = 3;
    const SYSTEM_STATUS: u64 = 4;
    const AUTH_RESULT: u64 = 5;

    const CALLER_AUTH_RESULT: u64 = 0;
    const CALLING_PACKAGE_AUTH_RESULT: u64 = 3;

    /// The tag *number* of a field, the way the Java reader's `getTagNo()`
    /// reports it: the context class and the constructed bit are not part of
    /// it.  Every field here is a short-form context tag, and for those
    /// `take_tlv` hands back the whole first byte (`[0]` arrives as 0xa0).
    fn tag_number(tag: u64) -> u64 {
        tag & 0x1f
    }

    /// Read the extension once, from the ASN.1 built out of it by
    /// `take_tlv`/`explicit_inner` alone; nothing here is allowed to fail the
    /// whole record, an unreadable Knox block just comes back empty.
    pub fn read(extension: &[u8]) -> Option<KnoxInfo> {
        let mut pos = 0;
        let sequence = take_tlv(extension, &mut pos)?;
        let mut info = KnoxInfo::default();
        let mut cursor = 0;
        while let Some(entry) = take_tlv(sequence.value, &mut cursor) {
            match tag_number(entry.tag) {
                CHALLENGE => info.challenge = printable(entry.value),
                ID_ATTEST => info.id_attest = printable(entry.value),
                INTEGRITY => read_integrity(entry.value, &mut info),
                RECORD_HASH => {
                    if let Some((_, hash)) = explicit_inner(entry.value) {
                        info.record_hash = Some(to_hex(hash));
                    }
                }
                _ => {}
            }
        }
        Some(info)
    }

    fn read_integrity(entry: &[u8], info: &mut KnoxInfo) {
        let Some((_, sequence)) = explicit_inner(entry) else {
            return;
        };
        let mut cursor = 0;
        while let Some(field) = take_tlv(sequence, &mut cursor) {
            match tag_number(field.tag) {
                TRUST_BOOT => info.trust_boot = explicit_int(field.value),
                WARRANTY => info.warranty = explicit_int(field.value),
                ICD => info.icd = explicit_int(field.value),
                KERNEL_STATUS => info.kernel = explicit_int(field.value),
                SYSTEM_STATUS => info.system = explicit_int(field.value),
                AUTH_RESULT => read_auth_result(field.value, info),
                _ => {}
            }
        }
    }

    fn read_auth_result(entry: &[u8], info: &mut KnoxInfo) {
        let Some((_, sequence)) = explicit_inner(entry) else {
            return;
        };
        let mut cursor = 0;
        while let Some(field) = take_tlv(sequence, &mut cursor) {
            match tag_number(field.tag) {
                CALLER_AUTH_RESULT => info.caller_auth = explicit_int(field.value),
                CALLING_PACKAGE_AUTH_RESULT => info.package_auth = explicit_int(field.value),
                _ => {}
            }
        }
    }

    /// The tagged strings are `[n] EXPLICIT PrintableString`, so the bytes
    /// come back as the string's own TLV.
    fn printable(entry: &[u8]) -> Option<String> {
        let (_, value) = explicit_inner(entry)?;
        Some(String::from_utf8_lossy(value).into_owned())
    }
}

/// Parse the leaf of a base64 DER chain (as returned in an `attest` result) and
/// extract the boot state it attests to.  `None` when the chain is unreadable
/// or carries no attestation extension.
pub fn device_boot_info_from_chain(leaf_b64: &str) -> Option<DeviceBootInfo> {
    let info = boot_info_from_leaf(&decode_leaf(leaf_b64)?)?;
    (!info.is_empty()).then_some(info)
}

/// The KeyMint attestation security level of a base64 DER leaf: 0 = software,
/// 1 = TEE, 2 = StrongBox.  `None` when the leaf is unreadable or carries no
/// attestation extension.
///
/// Smart mode uses this to refuse a silently TEE-demoted chain as a StrongBox
/// fulfilment.  It reads a field [`DeviceBootInfo::is_empty`] deliberately
/// ignores, so it goes straight through [`boot_info_from_leaf`] rather than
/// through [`device_boot_info_from_chain`].
pub fn attestation_security_level_from_chain(leaf_b64: &str) -> Option<i64> {
    boot_info_from_leaf(&decode_leaf(leaf_b64)?)?.security_level
}

/// The `ATTESTATION_APPLICATION_ID` (tag 709) of a base64 DER leaf: the package
/// name(s) the key was minted for, as the chain itself states them.  This is
/// what tells a chain the B-side *app* produced (`org.ommega.deviceb`) apart
/// from one the module produced while relaying someone else's request — the
/// requesting package — which no other field in the chain reveals.
pub fn attestation_application_id_from_chain(leaf_b64: &str) -> Option<String> {
    boot_info_from_leaf(&decode_leaf(leaf_b64)?)?.aaid
}

fn decode_leaf(leaf_b64: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(leaf_b64.trim())
        .ok()
}

/// Read the attestation extension out of a DER leaf.  Every field is optional
/// and an unreadable payload yields an empty record rather than an error; the
/// certificate itself was already verified by its chain.
fn boot_info_from_leaf(der: &[u8]) -> Option<DeviceBootInfo> {
    const ATTESTATION_OID_STR: &str = "1.3.6.1.4.1.11129.2.1.17";
    /// KeyMint's CBOR form of the same extension; a chain has one or the
    /// other, never both.
    const EAT_ATTESTATION_OID_STR: &str = "1.3.6.1.4.1.11129.2.1.25";
    /// Samsung's extra block, which rides along with the ASN.1 one.
    const KNOX_ATTESTATION_OID_STR: &str = "1.3.6.1.4.1.236.11.3.23.7";

    let (_, cert) = parse_x509_certificate(der).ok()?;
    let extension = |oid: &str| {
        cert.extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == oid)
            .map(|e| e.value)
    };

    let mut info = DeviceBootInfo::default();
    // 编码嗅探优先于 OID：CBOR map 首字节 0xa0..0xbf，而 DER KeyDescription 恒为
    // 0x30 SEQUENCE。个别设备会把 CBOR 载荷挂在旧 OID 2.1.17 下，按 OID 硬分
    // 会把 CBOR 当 DER 静默解失败（a-side 的 find_attestation_extension 同款处理）。
    let payload = extension(EAT_ATTESTATION_OID_STR).or_else(|| extension(ATTESTATION_OID_STR));
    if let Some(payload) = payload {
        // A malformed payload leaves the info empty rather than failing the
        // record; the certificate itself was already verified by its chain.
        if payload.first() == Some(&0x30) {
            read_asn1_attestation(payload, &mut info);
        } else if let Err(e) = eat::read(payload, &mut info) {
            // 解析失败只让这条记录的 EAT 字段空着，不影响证书本身（链已经验过），
            // 但不能再静默吞掉：畸形 CBOR 会让整条 claim 消失得无影无踪。
            tracing::warn!(
                "EAT payload unparsable ({} bytes, first byte {:#04x}): {e}",
                payload.len(),
                payload.first().copied().unwrap_or(0)
            );
        }
    }
    if let Some(knox) = extension(KNOX_ATTESTATION_OID_STR) {
        info.knox = knox::read(knox);
    }
    Some(info)
}

/// The ASN.1 KeyDescription: attestationVersion, attestationSecurityLevel,
/// keymasterVersion, keymasterSecurityLevel, attestationChallenge and
/// uniqueId, then the software- and tee-enforced authorization lists.
fn read_asn1_attestation(extension: &[u8], info: &mut DeviceBootInfo) {
    let mut pos = 0;
    let Some(sequence) = take_tlv(extension, &mut pos) else {
        return;
    };
    let mut cursor = 0;
    for field_index in 0..6 {
        let Some(field) = take_tlv(sequence.value, &mut cursor) else {
            return;
        };
        // KeyDescription 的第 2 个字段是 attestationSecurityLevel (ENUMERATED:
        // 0 = software, 1 = TEE, 2 = StrongBox)。Smart 模式靠它把「B 端静默降级
        // 成 TEE 的链」和「B 端真 StrongBox 链」区分开，所以这里必须留下它。
        if field_index == 1 {
            info.security_level = der_int(field.value);
        }
    }
    if let Some(software) = take_tlv(sequence.value, &mut cursor) {
        read_auth_list(software.value, info);
    }
    if let Some(tee) = take_tlv(sequence.value, &mut cursor) {
        read_auth_list(tee.value, info);
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use std::time::{Duration, Instant};

    const WARMUP: usize = 2;
    // 10 samples is enough for a rough latency figure; with 100 samples the
    // RSA-2048 keygen bench alone stalls a normal `cargo test` for minutes in
    // the unoptimized debug build. Run with `-- --ignored` for real numbers.
    const ITERATIONS: usize = 10;

    fn run_bench<F>(name: &str, mut f: F)
    where
        F: FnMut(),
    {
        // Warmup
        for _ in 0..WARMUP {
            f();
        }
        // Measurement
        let mut samples = Vec::with_capacity(ITERATIONS);
        for _ in 0..ITERATIONS {
            let start = Instant::now();
            f();
            samples.push(start.elapsed());
        }
        // Stats
        samples.sort();
        let total: Duration = samples.iter().sum();
        let avg = total / ITERATIONS as u32;
        let min = samples[0];
        let max = samples[samples.len() - 1];
        let median = samples[ITERATIONS / 2];
        let p99 = samples[(ITERATIONS as f64 * 0.99) as usize];
        println!(
            "  {name:35}  avg={avg:8.3?}  median={median:8.3?}  min={min:8.3?}  max={max:8.3?}  p99={p99:8.3?}",
            name = name,
            avg = avg,
            median = median,
            min = min,
            max = max,
            p99 = p99
        );
    }

    #[test]
    #[ignore = "crypto benchmark (slow: regenerates RSA-2048 keys per iteration; in debug this stalls a normal cargo test). Run explicitly: cargo test -- --ignored bench"]
    fn bench_sign_verify() {
        println!(
            "\n===== 签名/验签延迟基准测试 ({} 次迭代) =====\n",
            ITERATIONS
        );

        // --- EC key generation ---
        run_bench("EC P-256 keygen", || {
            let _ = generate_self_signed_ec().unwrap();
        });

        // --- RSA key generation ---
        run_bench("RSA 2048 keygen", || {
            let _ = generate_self_signed_rsa().unwrap();
        });

        // --- Pre-generated keys for signing benchmarks ---
        let ec_identity = generate_self_signed_ec().unwrap();
        let rsa_identity = generate_self_signed_rsa().unwrap();
        let ec_key = parse_private_key(ec_identity.private_key_pem.as_bytes()).unwrap();
        let rsa_key = parse_private_key(rsa_identity.private_key_pem.as_bytes()).unwrap();
        let test_data = b"benchmark test data for signing operation 1234567890";

        // --- EC sign (sign_tbs) ---
        run_bench("EC P-256 sign (32 bytes)", || {
            let _ = sign_tbs(&ec_key, test_data).unwrap();
        });

        // --- EC sign (1KB) ---
        let big_data = vec![0xABu8; 1024];
        run_bench("EC P-256 sign (1KB)", || {
            let _ = sign_tbs(&ec_key, &big_data).unwrap();
        });

        // --- RSA sign ---
        run_bench("RSA 2048 sign (32 bytes)", || {
            let _ = sign_tbs(&rsa_key, test_data).unwrap();
        });

        // --- RSA sign (1KB) ---
        run_bench("RSA 2048 sign (1KB)", || {
            let _ = sign_tbs(&rsa_key, &big_data).unwrap();
        });

        // --- Public key DER encoding ---
        run_bench("EC P-256 pubkey DER", || {
            let _ = public_key_der(&ec_key).unwrap();
        });
        run_bench("RSA 2048 pubkey DER", || {
            let _ = public_key_der(&rsa_key).unwrap();
        });

        // --- Certificate chain building ---
        let params = AttestationParams {
            challenge: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            algorithm: 3,
            key_size: 256,
            purposes: vec![2],
            digests: vec![4],
            paddings: vec![],
            ec_curve: Some(1),
            rsa_public_exponent: None,
            root_of_trust: Some(RootOfTrust {
                verified_boot_key: vec![0xBB; 32],
                device_locked: true,
                verified_boot_state: 2,
                verified_boot_hash: vec![0xCC; 32],
            }),
            os_version: Some(140000),
            os_patch_level: Some(202605),
            ..Default::default()
        };
        let identity = DeviceIdentity {
            device_id: "bench-device".to_string(),
            algorithm: "ec".to_string(),
            certificate_chain_pem: ec_identity.certificate_chain_pem.clone(),
            private_key_pem_cipher: ec_identity.private_key_pem.clone(),
            active: true,
            machine_id: "bench".to_string(),
            created_at: String::new(),
        };

        run_bench("EC attest cert chain", || {
            let _ = build_attested_chain(&identity, &params).unwrap();
        });

        let rsa_identity_for_chain = DeviceIdentity {
            device_id: "bench-device-rsa".to_string(),
            algorithm: "rsa".to_string(),
            certificate_chain_pem: rsa_identity.certificate_chain_pem.clone(),
            private_key_pem_cipher: rsa_identity.private_key_pem.clone(),
            active: true,
            machine_id: "bench".to_string(),
            created_at: String::new(),
        };
        run_bench("RSA attest cert chain", || {
            let _ = build_attested_chain(&rsa_identity_for_chain, &params).unwrap();
        });

        // --- Attestation extension DER building ---
        run_bench("Attestation extension DER", || {
            let _ = build_attestation_extension_der(&params);
        });

        // --- PEM parse ---
        run_bench("Parse PEM chain (2 certs)", || {
            let _ = parse_chain_pem(&ec_identity.certificate_chain_pem).unwrap();
        });

        println!("\n===== 基准测试完成 =====");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    // AOSP's claim numbers, spelled out again here because the reader keeps
    // its own copies private.
    const CLAIM_SUBMODS: i64 = -76_000;
    const CLAIM_BOOT_STATE: i64 = -76_003;
    const CLAIM_VERIFIED_BOOT_KEY: i64 = -82_001;
    const CLAIM_DEVICE_LOCKED: i64 = -82_002;
    const CLAIM_VERIFIED_BOOT_HASH: i64 = -82_003;
    const CLAIM_SECURITY_LEVEL: i64 = -76_002;
    const CLAIM_OFFICIAL_BUILD: i64 = -82_006;
    const CLAIM_OS_VERSION: i64 = -80_000 - 705;
    const CLAIM_OS_PATCHLEVEL: i64 = -80_000 - 706;
    const CLAIM_VENDOR_PATCHLEVEL: i64 = -80_000 - 718;
    const CLAIM_BOOT_PATCHLEVEL: i64 = -80_000 - 719;
    const CLAIM_ATTESTATION_APPLICATION_ID: i64 = -80_000 - 709;

    const EAT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 25];
    const KNOX_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 236, 11, 3, 23, 7];

    /// 测试侧的 `AttestationApplicationId` DER 编码（单包，长度都 < 128）。
    fn aaid_der(name: &str, version: i64) -> Vec<u8> {
        let mut info_body = vec![0x04, name.len() as u8];
        info_body.extend_from_slice(name.as_bytes());
        info_body.extend_from_slice(&[0x02, 0x01, version as u8]);
        let mut info = vec![0x30, info_body.len() as u8];
        info.extend_from_slice(&info_body);
        let mut package_infos = vec![0x31, info.len() as u8];
        package_infos.extend_from_slice(&info);
        let mut body = package_infos;
        body.extend_from_slice(&[0x31, 0x00]); // 空的 signatureDigests
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    // ---- test-side CBOR writer: just the shapes the EAT claims use ----

    #[derive(Clone)]
    enum Val<'a> {
        Int(i64),
        Bytes(&'a [u8]),
        Text(&'a str),
        Bool(bool),
        Arr(Vec<Val<'a>>),
        Map(Vec<(Val<'a>, Val<'a>)>),
    }

    fn cbor(value: &Val<'_>, out: &mut Vec<u8>) {
        match value {
            Val::Int(n) => {
                let (major, arg) = if *n < 0 {
                    (1, n.unsigned_abs() - 1)
                } else {
                    (0, *n as u64)
                };
                cbor_head(out, major, arg);
            }
            Val::Bytes(bytes) => {
                cbor_head(out, 2, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
            Val::Text(text) => {
                cbor_head(out, 3, text.len() as u64);
                out.extend_from_slice(text.as_bytes());
            }
            Val::Bool(value) => out.push(if *value { 0xf5 } else { 0xf4 }),
            Val::Arr(items) => {
                cbor_head(out, 4, items.len() as u64);
                for item in items {
                    cbor(item, out);
                }
            }
            Val::Map(entries) => {
                cbor_head(out, 5, entries.len() as u64);
                for (key, value) in entries {
                    cbor(key, out);
                    cbor(value, out);
                }
            }
        }
    }

    fn cbor_head(out: &mut Vec<u8>, major: u8, arg: u64) {
        let mut head = vec![major << 5];
        match arg {
            value if value < 24 => head[0] |= value as u8,
            value if value <= u64::from(u8::MAX) => {
                head[0] |= 24;
                head.push(value as u8);
            }
            value if value <= u64::from(u16::MAX) => {
                head[0] |= 25;
                head.extend_from_slice(&(value as u16).to_be_bytes());
            }
            value => {
                head[0] |= 26;
                head.extend_from_slice(&(value as u32).to_be_bytes());
            }
        }
        out.extend(head);
    }

    fn encode(claims: &Val<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        cbor(claims, &mut out);
        out
    }

    /// The five booleans `bootState` carries.
    fn flags(bits: [bool; 5]) -> Val<'static> {
        Val::Arr(bits.into_iter().map(Val::Bool).collect())
    }

    #[test]
    fn eat_reads_the_claims_the_status_page_shows() {
        let key = [0x11u8; 32];
        let hash = [0x22u8; 32];
        let payload = encode(&Val::Map(vec![
            (Val::Int(CLAIM_VERIFIED_BOOT_KEY), Val::Bytes(&key)),
            (Val::Int(CLAIM_VERIFIED_BOOT_HASH), Val::Bytes(&hash)),
            (Val::Int(CLAIM_DEVICE_LOCKED), Val::Bool(true)),
            (Val::Int(CLAIM_OFFICIAL_BUILD), Val::Bool(true)),
            (
                Val::Int(CLAIM_BOOT_STATE),
                flags([true, true, true, true, false]),
            ),
            (
                Val::Int(CLAIM_SUBMODS),
                Val::Map(vec![
                    (
                        Val::Text("software"),
                        Val::Map(vec![
                            (Val::Int(CLAIM_OS_VERSION), Val::Int(160_000)),
                            (Val::Int(CLAIM_OS_PATCHLEVEL), Val::Int(202_606)),
                            (Val::Int(CLAIM_VENDOR_PATCHLEVEL), Val::Int(20_260_701)),
                        ]),
                    ),
                    (
                        Val::Text("tee"),
                        Val::Map(vec![(
                            Val::Int(CLAIM_BOOT_PATCHLEVEL),
                            Val::Int(20_260_702),
                        )]),
                    ),
                ]),
            ),
        ]));

        let mut info = DeviceBootInfo::default();
        eat::read(&payload, &mut info).unwrap();
        assert_eq!(info.boot_key.as_deref(), Some(to_hex(&key).as_str()));
        assert_eq!(info.boot_hash.as_deref(), Some(to_hex(&hash).as_str()));
        assert_eq!(info.device_locked, Some(true));
        assert_eq!(info.verified_boot_state, Some(0)); // verified + official
        assert_eq!(info.os_version, Some(160_000));
        assert_eq!(info.patch_system, Some(202_606));
        assert_eq!(info.patch_vendor, Some(20_260_701));
        assert_eq!(info.patch_boot, Some(20_260_702));
    }

    /// Same payload shape, only `bootState` and `officialBuild` vary.
    fn eat_boot_state(bits: [bool; 5], official: bool) -> Option<i64> {
        let payload = encode(&Val::Map(vec![
            (Val::Int(CLAIM_OFFICIAL_BUILD), Val::Bool(official)),
            (Val::Int(CLAIM_BOOT_STATE), flags(bits)),
        ]));
        let mut info = DeviceBootInfo::default();
        eat::read(&payload, &mut info).unwrap();
        info.verified_boot_state
    }

    #[test]
    fn eat_maps_boot_state_the_way_aosp_does() {
        assert_eq!(
            eat_boot_state([true, true, true, true, false], true),
            Some(0)
        );
        // Verified but not an official build: self-signed.
        assert_eq!(
            eat_boot_state([true, true, true, true, false], false),
            Some(1)
        );
        assert_eq!(
            eat_boot_state([false, false, true, true, false], false),
            Some(2)
        );
        // AOSP throws on a non-verified official build; nothing is reported.
        assert_eq!(
            eat_boot_state([false, false, true, true, false], true),
            None
        );
        // debug-permanent-disable must never be set.
        assert_eq!(eat_boot_state([true, true, true, true, true], false), None);
        // The first flag has to agree with at least one of the next three.
        assert_eq!(
            eat_boot_state([true, false, false, false, false], false),
            None
        );
    }

    #[test]
    fn eat_refuses_payloads_it_cannot_read() {
        let mut info = DeviceBootInfo::default();
        assert!(eat::read(&[], &mut info).is_err());
        assert!(eat::read(&[0x82, 0x01, 0x02], &mut info).is_err()); // an array
        assert!(eat::read(&[0xa1], &mut info).is_err()); // map header, no body

        // A boot state that is not five flags is dropped, not misread.
        let payload = encode(&Val::Map(vec![(
            Val::Int(CLAIM_BOOT_STATE),
            Val::Arr(vec![Val::Bool(true); 4]),
        )]));
        let mut short = DeviceBootInfo::default();
        eat::read(&payload, &mut short).unwrap();
        assert_eq!(short.verified_boot_state, None);

        // Every truncation of a good payload is refused or comes back partial,
        // never a panic.
        let payload = encode(&Val::Map(vec![(
            Val::Int(CLAIM_VERIFIED_BOOT_KEY),
            Val::Bytes(&[0x33u8; 32]),
        )]));
        for end in 0..payload.len() {
            let mut partial = DeviceBootInfo::default();
            let _ = eat::read(&payload[..end], &mut partial);
        }

        // A hand-crafted payload cannot recurse the stack away.
        let mut deep = vec![0xa1u8; 200];
        deep.push(0x01);
        assert!(eat::read(&deep, &mut info).is_err());
    }

    // ---- DER builders, for the ASN.1 extension and the Knox block ----

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// `[tag] EXPLICIT <content>`.  `Der::explicit` only writes 0..=15, and the
    /// authorization-list tags are all well past that.
    fn explicit_tag(tag: u64, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if tag < 31 {
            out.push(0xa0 | tag as u8);
        } else {
            out.push(0xbf);
            let mut bytes = vec![(tag & 0x7f) as u8];
            let mut rest = tag >> 7;
            while rest > 0 {
                bytes.push(((rest & 0x7f) as u8) | 0x80);
                rest >>= 7;
            }
            bytes.reverse();
            out.extend(bytes);
        }
        out.extend(der_len(content.len()));
        out.extend_from_slice(content);
        out
    }

    /// A KeyDescription in the ASN.1 form: the six fields the reader skips,
    /// then the software- and tee-enforced authorization lists.
    fn asn1_extension() -> Vec<u8> {
        let root_of_trust = der(
            0x30,
            &[
                der(0x04, &[0x77u8; 32]),
                der(0x01, &[0xff]), // locked
                der(0x0a, &[0x02]), // unverified
                der(0x04, &[0x88u8; 32]),
            ]
            .concat(),
        );
        let tee = der(
            0x30,
            &[
                explicit_tag(704, &root_of_trust),
                explicit_tag(705, &der(0x02, &[0x02, 0x71, 0x00])), // 160000
                explicit_tag(706, &der(0x02, &[0x03, 0x17, 0x6e])), // 202606
                explicit_tag(718, &der(0x02, &[0x01, 0x35, 0x27, 0x5d])),
                explicit_tag(719, &der(0x02, &[0x01, 0x35, 0x27, 0x5e])),
            ]
            .concat(),
        );
        der(
            0x30,
            &[
                der(0x02, &[0x01, 0x2c]), // attestationVersion 300
                der(0x0a, &[0x01]),       // attestationSecurityLevel
                der(0x02, &[0x01, 0x2c]), // keymasterVersion
                der(0x0a, &[0x01]),       // keymasterSecurityLevel
                der(0x04, &[0x09, 0x08, 0x07]),
                der(0x04, &[]), // uniqueId
                der(0x30, &[]), // softwareEnforced
                tee,
            ]
            .concat(),
        )
    }

    #[test]
    fn asn1_attestation_is_read_from_the_tee_list() {
        let mut info = DeviceBootInfo::default();
        read_asn1_attestation(&asn1_extension(), &mut info);
        assert_eq!(
            info.boot_key.as_deref(),
            Some(to_hex(&[0x77u8; 32]).as_str())
        );
        assert_eq!(
            info.boot_hash.as_deref(),
            Some(to_hex(&[0x88u8; 32]).as_str())
        );
        assert_eq!(info.device_locked, Some(true));
        assert_eq!(info.verified_boot_state, Some(2));
        assert_eq!(info.os_version, Some(160_000));
        assert_eq!(info.patch_system, Some(202_606));
        assert_eq!(info.patch_vendor, Some(20_260_701));
        assert_eq!(info.patch_boot, Some(20_260_702));
    }

    /// The Knox block Samsung puts next to the attestation extension.
    fn knox_extension() -> Vec<u8> {
        let auth_result = der(
            0x30,
            &[
                explicit_tag(0, &der(0x02, &[0x00])),
                explicit_tag(3, &der(0x02, &[0x01])),
            ]
            .concat(),
        );
        let integrity = der(
            0x30,
            &[
                explicit_tag(0, &der(0x02, &[0x00])), // trustBoot normal
                explicit_tag(1, &der(0x02, &[0x01])), // warranty abnormal
                explicit_tag(4, &der(0x02, &[0x02])), // system not supported
                explicit_tag(5, &auth_result),
            ]
            .concat(),
        );
        der(
            0x30,
            &[
                explicit_tag(0, &der(0x13, b"chal")),
                explicit_tag(4, &der(0x13, b"idAttest")),
                explicit_tag(5, &integrity),
                explicit_tag(6, &der(0x04, &[0xaa, 0xbb])),
            ]
            .concat(),
        )
    }

    #[test]
    fn knox_reads_integrity_and_caller_auth() {
        let info = knox::read(&knox_extension()).unwrap();
        assert_eq!(info.challenge.as_deref(), Some("chal"));
        assert_eq!(info.id_attest.as_deref(), Some("idAttest"));
        assert_eq!(info.record_hash.as_deref(), Some("aabb"));
        assert_eq!(info.trust_boot, Some(0));
        assert_eq!(info.warranty, Some(1));
        assert_eq!(info.system, Some(2));
        assert_eq!(info.icd, None);
        assert_eq!(info.kernel, None);
        assert_eq!(info.caller_auth, Some(0));
        assert_eq!(info.package_auth, Some(1));
    }

    #[test]
    fn knox_keeps_what_it_can_read() {
        // Nothing in the block is allowed to fail the whole record.
        let empty = knox::read(&der(0x30, &[])).unwrap();
        assert!(empty.challenge.is_none());
        assert!(empty.trust_boot.is_none());
        assert!(empty.record_hash.is_none());
        assert!(knox::read(&[]).is_none());
        assert!(knox::read(&[0x02, 0x01, 0x00]).is_some());

        let full = knox_extension();
        for end in 0..full.len() {
            let _ = knox::read(&full[..end]);
        }
    }

    // ---- the extension dispatch, through a real certificate ----

    /// A self-signed leaf carrying `extension` under `oid`, base64 DER — the
    /// shape a B-side hands back in an `attest` result.
    fn leaf_with_extension(oid: &[u64], extension: &[u8]) -> String {
        use p256::elliptic_curve::rand_core::OsRng;
        let key = KeyMaterial::Ec(EcKey::P256(P256SecretKey::random(&mut OsRng)));
        let spki = public_key_der(&key).unwrap();
        let name = default_name();

        let mut tbs = Der::new();
        tbs.explicit(0, &wrap_int(2));
        tbs.int(&[0x01]);
        tbs.0.extend(sig_alg_for_key(&key));
        tbs.0.extend(&name);
        let mut validity = Der::new();
        validity.utctime("250101000000Z");
        validity.utctime("490101000000Z");
        tbs.raw(0x30, &validity.into_vec());
        tbs.0.extend(&name);
        tbs.0.extend(&spki);
        let mut extensions = Der::new();
        extensions.0.extend(ext_entry(oid, false, extension));
        let mut exts = Der::new();
        exts.seq(&extensions.into_vec());
        tbs.explicit(3, &exts.into_vec());

        let mut tbs_tlv = Der::new();
        tbs_tlv.raw(0x30, &tbs.into_vec());
        let tbs_full = tbs_tlv.into_vec();
        let (signature_alg, signature) = sign_tbs(&key, &tbs_full).unwrap();

        let mut cert = Der::new();
        let mut inner = Der::new();
        inner.0.extend(&tbs_full);
        inner.0.extend(signature_alg);
        inner.bit_string(&signature);
        cert.seq(&inner.into_vec());
        base64::engine::general_purpose::STANDARD.encode(cert.into_vec())
    }

    // ---- the security level Smart mode reads to spot a TEE-demoted chain ----

    /// The ASN.1 KeyDescription carries `attestationSecurityLevel` as the second
    /// field; `key_description_der` writes it as an ENUMERATED.
    #[test]
    fn chain_reports_the_asn1_security_level() {
        const ASN1_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];
        for level in [0i64, 1, 2] {
            let params = AttestationParams {
                security_level: level,
                ..Default::default()
            };
            let leaf = leaf_with_extension(ASN1_OID, &build_attestation_extension_der(&params));
            assert_eq!(
                attestation_security_level_from_chain(&leaf),
                Some(level),
                "ASN.1 attestationSecurityLevel {level}"
            );
        }
    }

    /// EAT numbers the same thing in its own scale, so the CBOR path has to be
    /// mapped onto KeyMint's 0/1/2 for the two to be comparable.
    #[test]
    fn chain_maps_the_eat_security_level() {
        for (eat_level, keymint_level) in [(1i64, 0i64), (3, 1), (4, 2)] {
            let payload = encode(&Val::Map(vec![(
                Val::Int(CLAIM_SECURITY_LEVEL),
                Val::Int(eat_level),
            )]));
            let leaf = leaf_with_extension(EAT_OID, &payload);
            assert_eq!(
                attestation_security_level_from_chain(&leaf),
                Some(keymint_level),
                "EAT security level {eat_level}"
            );
        }
        // A level outside the keymint mapping is left unset rather than guessed.
        let payload = encode(&Val::Map(vec![(
            Val::Int(CLAIM_SECURITY_LEVEL),
            Val::Int(2),
        )]));
        let leaf = leaf_with_extension(EAT_OID, &payload);
        assert_eq!(attestation_security_level_from_chain(&leaf), None);
    }

    /// A security level says nothing about the boot state, so it must not turn
    /// an otherwise empty record into one — that would put an empty boot block
    /// on the status page for a chain that attests to no boot information.
    #[test]
    fn security_level_alone_does_not_make_a_boot_record() {
        let payload = encode(&Val::Map(vec![(
            Val::Int(CLAIM_SECURITY_LEVEL),
            Val::Int(4),
        )]));
        let leaf = leaf_with_extension(EAT_OID, &payload);
        assert_eq!(attestation_security_level_from_chain(&leaf), Some(2));
        assert!(device_boot_info_from_chain(&leaf).is_none());
    }

    #[test]
    fn chain_dispatch_reads_the_eat_extension() {
        let key = [0x44u8; 32];
        let payload = encode(&Val::Map(vec![
            (Val::Int(CLAIM_VERIFIED_BOOT_KEY), Val::Bytes(&key)),
            (Val::Int(CLAIM_DEVICE_LOCKED), Val::Bool(false)),
            (Val::Int(CLAIM_OFFICIAL_BUILD), Val::Bool(true)),
            (
                Val::Int(CLAIM_BOOT_STATE),
                flags([true, true, true, true, false]),
            ),
        ]));
        let info = device_boot_info_from_chain(&leaf_with_extension(EAT_OID, &payload)).unwrap();
        assert_eq!(info.boot_key.as_deref(), Some(to_hex(&key).as_str()));
        assert_eq!(info.device_locked, Some(false));
        assert_eq!(info.verified_boot_state, Some(0));
        assert!(info.knox.is_none());
    }

    #[test]
    fn chain_dispatch_reads_the_knox_extension() {
        let leaf = leaf_with_extension(KNOX_OID, &knox_extension());
        let info = device_boot_info_from_chain(&leaf).unwrap();
        assert_eq!(info.knox.unwrap().challenge.as_deref(), Some("chal"));
    }

    #[test]
    fn chain_dispatch_reads_the_asn1_extension() {
        let identity = generate_self_signed("ec").unwrap();
        let params = AttestationParams {
            challenge: vec![0x01, 0x02],
            root_of_trust: Some(RootOfTrust {
                verified_boot_key: vec![0xAA; 32],
                device_locked: true,
                verified_boot_state: 1,
                verified_boot_hash: vec![0xBB; 32],
            }),
            os_version: Some(160_000),
            os_patch_level: Some(202_606),
            ..Default::default()
        };
        let device = DeviceIdentity {
            device_id: "test-device".to_string(),
            algorithm: "ec".to_string(),
            certificate_chain_pem: identity.certificate_chain_pem,
            private_key_pem_cipher: identity.private_key_pem,
            active: true,
            machine_id: "test".to_string(),
            created_at: String::new(),
        };
        let (chain, _) = build_attested_chain(&device, &params).unwrap();
        let leaf = parse_chain_pem(&chain).unwrap().remove(0);
        let leaf_b64 = base64::engine::general_purpose::STANDARD.encode(leaf);

        let info = device_boot_info_from_chain(&leaf_b64).unwrap();
        assert_eq!(
            info.boot_key.as_deref(),
            Some(to_hex(&[0xAAu8; 32]).as_str())
        );
        assert_eq!(
            info.boot_hash.as_deref(),
            Some(to_hex(&[0xBBu8; 32]).as_str())
        );
        assert_eq!(info.device_locked, Some(true));
        assert_eq!(info.verified_boot_state, Some(1));
        assert_eq!(info.os_version, Some(160_000));
        assert_eq!(info.patch_system, Some(202_606));
        assert!(info.knox.is_none());
    }

    /// AAID 是「这条链是谁的身份出的」唯一硬证据（服务端判读法就是靠它），
    /// 所以两种编码都要能读出来，而且不能把没有 AAID 的链读成有。
    #[test]
    fn asn1_chain_exposes_the_attestation_application_id() {
        let identity = generate_self_signed("ec").unwrap();
        let with_aaid = AttestationParams {
            challenge: vec![0x01],
            app_id: Some(aaid_der("org.ommega.deviceb", 12)),
            ..Default::default()
        };
        let device = DeviceIdentity {
            device_id: "test-device".to_string(),
            algorithm: "ec".to_string(),
            certificate_chain_pem: identity.certificate_chain_pem,
            private_key_pem_cipher: identity.private_key_pem,
            active: true,
            machine_id: "test".to_string(),
            created_at: String::new(),
        };
        let (chain, _) = build_attested_chain(&device, &with_aaid).unwrap();
        let leaf = parse_chain_pem(&chain).unwrap().remove(0);
        let leaf_b64 = base64::engine::general_purpose::STANDARD.encode(&leaf);
        assert_eq!(
            attestation_application_id_from_chain(&leaf_b64).as_deref(),
            Some("org.ommega.deviceb@12")
        );

        let no_aaid = AttestationParams {
            challenge: vec![0x01],
            ..Default::default()
        };
        let (chain, _) = build_attested_chain(&device, &no_aaid).unwrap();
        let leaf = parse_chain_pem(&chain).unwrap().remove(0);
        let leaf_b64 = base64::engine::general_purpose::STANDARD.encode(&leaf);
        assert_eq!(attestation_application_id_from_chain(&leaf_b64), None);
    }

    #[test]
    fn eat_chain_exposes_the_attestation_application_id() {
        let app_id = aaid_der("com.example.app", 1);
        // submods 里的 software 子 map（真机常见位置）
        let in_submod = encode(&Val::Map(vec![
            (Val::Int(CLAIM_VERIFIED_BOOT_KEY), Val::Bytes(&[0x11u8; 32])),
            (
                Val::Int(CLAIM_SUBMODS),
                Val::Map(vec![(
                    Val::Text("software"),
                    Val::Map(vec![(
                        Val::Int(CLAIM_ATTESTATION_APPLICATION_ID),
                        Val::Bytes(&app_id),
                    )]),
                )]),
            ),
        ]));
        let info = device_boot_info_from_chain(&leaf_with_extension(EAT_OID, &in_submod)).unwrap();
        assert_eq!(info.aaid.as_deref(), Some("com.example.app@1"));

        // 顶层摆放（版本 0 不显示）
        let top_level = encode(&Val::Map(vec![
            (Val::Int(CLAIM_VERIFIED_BOOT_KEY), Val::Bytes(&[0x11u8; 32])),
            (
                Val::Int(CLAIM_ATTESTATION_APPLICATION_ID),
                Val::Bytes(&aaid_der("com.example.app", 0)),
            ),
        ]));
        let info = device_boot_info_from_chain(&leaf_with_extension(EAT_OID, &top_level)).unwrap();
        assert_eq!(info.aaid.as_deref(), Some("com.example.app"));
    }

    /// AAID 不能把一条没有启动信息的链变成“有启动信息”，否则状态页会给它显示
    /// 一个空的启动块。
    #[test]
    fn aaid_alone_does_not_make_a_boot_record() {
        let payload = encode(&Val::Map(vec![(
            Val::Int(CLAIM_ATTESTATION_APPLICATION_ID),
            Val::Bytes(&aaid_der("com.example.app", 0)),
        )]));
        let leaf = leaf_with_extension(EAT_OID, &payload);
        assert!(device_boot_info_from_chain(&leaf).is_none());
        assert_eq!(
            attestation_application_id_from_chain(&leaf).as_deref(),
            Some("com.example.app")
        );
    }

    /// 拿真机证书对拍。android/keyattestation 的 testdata 里每张 `.pem` 边上放着一份
    /// `.json`，是 AOSP 自己解析出来的结果（Pixel 2 一路到 10、Sony Xperia 10 III 都
    /// 有）。证书不进仓库，用 `OMMEGA_REAL_CERTS` 指着那个 testdata 目录跑；没设环境
    /// 变量就跳过，免得别人 clone 下来到处找证书。
    #[test]
    fn real_device_certs_match_the_reference_values() {
        let Ok(root) = std::env::var("OMMEGA_REAL_CERTS") else {
            return;
        };
        let root = std::path::Path::new(&root);
        let mut pairs = Vec::new();
        collect_pem_json_pairs(root, &mut pairs);
        assert!(!pairs.is_empty(), "{root:?} 底下没有 .pem/.json 配对");

        let mut mismatches = Vec::new();
        for (pem_path, json_path) in &pairs {
            let name = pem_path
                .strip_prefix(root)
                .unwrap_or(pem_path)
                .display()
                .to_string();
            let (Ok(pem), Ok(json)) = (
                std::fs::read_to_string(pem_path),
                std::fs::read_to_string(json_path),
            ) else {
                mismatches.push(format!("{name}: 文件读不了"));
                continue;
            };
            // 期望值是手写的，开头允许来一行 `//` 说明。
            let json: String = json
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&json) else {
                mismatches.push(format!("{name}: 期望值不是合法 JSON"));
                continue;
            };
            let Some(leaf) = parse_chain_pem(&pem)
                .ok()
                .and_then(|mut chain| chain.drain(..).next())
            else {
                mismatches.push(format!("{name}: 证书链里没读到证书"));
                continue;
            };
            // 期望值挂在 hardwareEnforced 下面，StrongBox 那几张也一样。
            let rot = json
                .get("hardwareEnforced")
                .and_then(|h| h.get("rootOfTrust"));
            let Some(info) = device_boot_info_from_chain(
                &base64::engine::general_purpose::STANDARD.encode(leaf),
            ) else {
                // 期望值里也没有启动状态，那就没错：这张证书本来就没带 RootOfTrust
                // （marlin 那两张是纯软件认证，teeEnforced 里根本没这一项）。
                if rot.is_none() {
                    continue;
                }
                mismatches.push(format!("{name}: 期望值有启动状态，我们却没解析出来"));
                continue;
            };
            let field = |key: &str| -> Option<String> {
                rot.and_then(|r| r.get(key))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            };
            let mut check = |what: &str, ours: Option<String>, theirs: Option<String>| {
                if let Some(theirs) = theirs {
                    if ours.as_deref() != Some(theirs.as_str()) {
                        mismatches.push(format!(
                            "{name}: {what} 我们={} 期望={theirs}",
                            ours.unwrap_or_else(|| "无".into())
                        ));
                    }
                }
            };

            check(
                "boot_key",
                info.boot_key,
                field("verifiedBootKey").map(|v| base64_to_hex(&v)),
            );
            check(
                "boot_hash",
                info.boot_hash,
                field("verifiedBootHash").map(|v| base64_to_hex(&v)),
            );
            check(
                "device_locked",
                info.device_locked.map(|v| v.to_string()),
                rot.and_then(|r| r.get("deviceLocked"))
                    .and_then(|v| v.as_bool())
                    .map(|v| v.to_string()),
            );
            check(
                "verified_boot_state",
                info.verified_boot_state.map(|v| v.to_string()),
                field("verifiedBootState").and_then(|v| vb_state_number(&v).map(|n| n.to_string())),
            );
            check(
                "os_version",
                info.os_version.map(|v| v.to_string()),
                json.pointer("/hardwareEnforced/osVersion")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
            );
            for (what, ours, key) in [
                ("patch_system", info.patch_system, "osPatchLevel"),
                ("patch_vendor", info.patch_vendor, "vendorPatchLevel"),
                ("patch_boot", info.patch_boot, "bootPatchLevel"),
            ] {
                check(
                    what,
                    ours.map(|v| v.to_string()),
                    json.pointer(&format!("/hardwareEnforced/{key}"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                );
            }
        }

        assert!(
            mismatches.is_empty(),
            "{} 张证书里 {} 处对不上：\n{}",
            pairs.len(),
            mismatches.len(),
            mismatches.join("\n")
        );
        println!("真机证书对拍通过：{} 张", pairs.len());
    }

    fn collect_pem_json_pairs(
        dir: &std::path::Path,
        out: &mut Vec<(std::path::PathBuf, std::path::PathBuf)>,
    ) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                collect_pem_json_pairs(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "pem") {
                let json = path.with_extension("json");
                if json.is_file() {
                    out.push((path, json));
                }
            }
        }
    }

    /// `verifiedBootKey`/`verifiedBootHash` 在期望值里是 base64，`DeviceBootInfo`
    /// 存的是小写十六进制。
    fn base64_to_hex(value: &str) -> String {
        match base64::engine::general_purpose::STANDARD.decode(value) {
            Ok(bytes) => to_hex(&bytes),
            Err(_) => value.to_string(),
        }
    }

    /// AOSP 那份 JSON 用的是枚举名，我们存的是 KeyMint 的数值。
    fn vb_state_number(name: &str) -> Option<i64> {
        match name {
            "VERIFIED" => Some(0),
            "SELF_SIGNED" => Some(1),
            "UNVERIFIED" => Some(2),
            "FAILED" => Some(3),
            _ => None,
        }
    }
}
