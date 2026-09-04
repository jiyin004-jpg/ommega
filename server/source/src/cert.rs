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
    /// KM_TAG_VENDOR_PATCH_LEVEL (707) / KM_TAG_BOOT_PATCH_LEVEL (708).
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
    if !p.purposes.is_empty() { tags.push(1); }
    if p.algorithm != 0 { tags.push(2); }
    if p.key_size != 0 { tags.push(3); }
    if !p.digests.is_empty() { tags.push(5); }
    if !p.paddings.is_empty() { tags.push(6); }
    if p.ec_curve.is_some() { tags.push(10); }
    if p.rsa_public_exponent.is_some() { tags.push(200); }
    if !p.mgf_digest.is_empty() { tags.push(203); } // RSA_OAEP_MGF_DIGEST (RSA only)
    tags.push(503); // NO_AUTH_REQUIRED — always present
    tags.push(702); // ORIGIN — always present
    tags.push(704); // ROOT_OF_TRUST — always present (Django defaults to 32 zero bytes)
    if p.os_version.is_some() { tags.push(705); }
    if p.os_patch_level.is_some() { tags.push(706); }
    // KeyAttestation 1.7's tag table: VENDOR_PATCHLEVEL=718, BOOT_PATCHLEVEL=719
    // (707/708 are UNIQUE_ID/ATTESTATION_CHALLENGE in the old keymaster numbering).
    if p.vendor_patch_level.is_some() { tags.push(718); }
    if p.boot_patch_level.is_some() { tags.push(719); }
    tags.sort();

    w.write_sequence(|w| {
        for &tag in &tags {
            match tag {
                1 => {
                    w.next().write_tagged(yasna::Tag::context(1), |w| {
                        w.write_set(|w| {
                            for v in &p.purposes { w.next().write_i64(*v); }
                        })
                    });
                }
                2 => {
                    w.next().write_tagged(yasna::Tag::context(2), |w| w.write_i64(p.algorithm));
                }
                3 => {
                    w.next().write_tagged(yasna::Tag::context(3), |w| w.write_i64(p.key_size));
                }
                5 => {
                    w.next().write_tagged(yasna::Tag::context(5), |w| {
                        w.write_set(|w| {
                            for v in &p.digests { w.next().write_i64(*v); }
                        })
                    });
                }
                6 => {
                    w.next().write_tagged(yasna::Tag::context(6), |w| {
                        w.write_set(|w| {
                            for v in &p.paddings { w.next().write_i64(*v); }
                        })
                    });
                }
                10 => {
                    if let Some(c) = p.ec_curve {
                        w.next().write_tagged(yasna::Tag::context(10), |w| w.write_i64(c));
                    }
                }
                200 => {
                    if let Some(e) = p.rsa_public_exponent {
                        w.next().write_tagged(yasna::Tag::context(200), |w| w.write_i64(e));
                    }
                }
                203 => {
                    w.next().write_tagged(yasna::Tag::context(203), |w| {
                        w.write_set(|w| {
                            for v in &p.mgf_digest { w.next().write_i64(*v); }
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
                    let rot = p.root_of_trust.as_ref().map(|r| {
                        (r.verified_boot_key.clone(), r.device_locked, r.verified_boot_state, r.verified_boot_hash.clone())
                    }).unwrap_or_else(|| {
                        (vec![0u8; 32], true, 0i64, vec![0u8; 32])
                    });
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
                        w.next().write_tagged(yasna::Tag::context(705), |w| w.write_i64(v));
                    }
                }
                706 => {
                    if let Some(v) = p.os_patch_level {
                        w.next().write_tagged(yasna::Tag::context(706), |w| w.write_i64(v));
                    }
                }
                718 => {
                    if let Some(v) = p.vendor_patch_level {
                        w.next().write_tagged(yasna::Tag::context(718), |w| w.write_i64(v));
                    }
                }
                719 => {
                    if let Some(v) = p.boot_patch_level {
                        w.next().write_tagged(yasna::Tag::context(719), |w| w.write_i64(v));
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

pub enum KeyMaterial {
    Ec(EcKey),
    Rsa(rsa::RsaPrivateKey),
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
        return Ok(KeyMaterial::Rsa(rk));
    }
    // PKCS#1 RSA (common in keybox.xml `<PrivateKey format="pem">`).
    use rsa::pkcs1::DecodeRsaPrivateKey;
    if let Ok(rk) = rsa::RsaPrivateKey::from_pkcs1_pem(s) {
        return Ok(KeyMaterial::Rsa(rk));
    }
    anyhow::bail!("unable to parse identity private key")
}

fn public_key_der(key: &KeyMaterial) -> anyhow::Result<Vec<u8>> {
    use pkcs8::EncodePublicKey;
    match key {
        KeyMaterial::Ec(EcKey::P256(sk)) => Ok(sk.public_key().to_public_key_der()?.as_bytes().to_vec()),
        KeyMaterial::Ec(EcKey::P384(sk)) => Ok(sk.public_key().to_public_key_der()?.as_bytes().to_vec()),
        KeyMaterial::Ec(EcKey::P521(sk)) => Ok(sk.public_key().to_public_key_der()?.as_bytes().to_vec()),
        KeyMaterial::Rsa(rk) => Ok(rk
            .to_public_key()
            .to_public_key_der()?
            .as_bytes()
            .to_vec()),
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
            let signing_key =
                p384::ecdsa::SigningKey::from(ecdsa::SigningKey::from(sk));
            let sig: P384Signature = signing_key.sign(tbs);
            let der_sig = P384DerSignature::from(sig);
            Ok((alg_id(OID_ECDSA_SHA384, false), der_sig.as_bytes().to_vec()))
        }
        KeyMaterial::Ec(EcKey::P521(sk)) => {
            let signing_key =
                p521::ecdsa::SigningKey::from(ecdsa::SigningKey::from(sk));
            let sig: P521Signature = signing_key.sign(tbs);
            let der_sig = P521DerSignature::from(sig);
            Ok((alg_id(OID_ECDSA_SHA512, false), der_sig.as_bytes().to_vec()))
        }
        KeyMaterial::Rsa(rk) => {
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
        anyhow::bail!("empty certificate_chain_pem for device {}", identity.device_id);
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
    let not_before = not_before_ts.format("%y%m%d%H%M%SZ").to_string();
    // notAfter: honour the caller-requested expiry, else fixed 2048-01-01
    // (matches Django's _build_attested_chain).
    // Dates at/after 2050 must use GeneralizedTime: as UTCTime the two-digit
    // year maps `50`-`99` to 1950-1999, so "500101000000Z" would encode as an
    // already-expired 1950 certificate (see `Der::generalized_time`).
    const GT_THRESHOLD_MS: i64 = 2_524_608_000_000; // 2050-01-01T00:00:00Z
    let (not_after, not_after_is_generalized) = match p.not_after_ms.filter(|&v| v > 0) {
        Some(ms) => match chrono::DateTime::from_timestamp_millis(ms as i64) {
            Some(t) if t.timestamp_millis() >= GT_THRESHOLD_MS => {
                (t.format("%Y%m%d%H%M%SZ").to_string(), true)
            }
            Some(t) => (t.format("%y%m%d%H%M%SZ").to_string(), false),
            None => ("480101000000Z".to_string(), false),
        },
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
    validity.utctime(&not_before);
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
    exts_content.0.extend(ext_entry(OID_KEY_USAGE, true, &ku_der));
    exts_content.0.extend(ext_entry(ATTESTATION_OID, false, &ext_value));
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
        Ok((KeyMaterial::Rsa(private), pem.to_string()))
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
    let intermediate_key = KeyMaterial::Rsa(intermediate_private);

    // Generate root CA key
    let root_private = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
    let root_key = KeyMaterial::Rsa(root_private);

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
        println!("\n===== 签名/验签延迟基准测试 ({} 次迭代) =====\n", ITERATIONS);

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
