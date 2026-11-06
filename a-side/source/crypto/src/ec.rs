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

//! Pure-Rust implementation of elliptic curve functionality (replaces BoringSSL;
//! RustCrypto `p224`/`p256`/`p384`/`p521`, `ed25519-dalek`, `x25519-dalek`).
//! P-224 only covers key generation and public-key derivation (工程模式自检要用
//! secp224r1）；它的 ECDSA/ECDH 仍返回 `UnsupportedEcCurve`。

use der::Decode as _;
use der::Encode as _;
use ecdsa::signature::SignatureEncoding as _;
use ecdsa::SigningKey as EcdsaSigningKey;
use kmr_common::{
    crypto,
    crypto::{ec, ec::Key, AccumulatingOperation, CurveType, OpaqueOr},
    explicit, km_err, Error, FallibleAllocExt,
};
use kmr_wire::keymint::{self, Digest, EcCurve};
use p224::ecdsa::Signature as SigP224;
use p256::ecdsa::Signature as SigP256;
use p384::ecdsa::Signature as SigP384;

use elliptic_curve::sec1::ToEncodedPoint as _;
use sec1::EcPrivateKey;
use std::boxed::Box;
use std::vec::Vec;

/// [`crypto::Ec`] implementation based on RustCrypto.
#[derive(Default)]
pub struct OmmegaEc {
    _priv: core::marker::PhantomData<()>,
}

impl crypto::Ec for OmmegaEc {
    fn generate_nist_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        curve: ec::NistCurve,
        _params: &[keymint::KeyParam],
    ) -> Result<crypto::KeyMaterial, Error> {
        let nist_key = ec::NistKey(generate_nist_der(curve)?);
        let key = match curve {
            // P-224 只有工程模式那类自检会要（secp224r1），RustCrypto 的 p224
            // 能生成/派生公钥，密钥对本身跟 P-256 一样存 SEC1 DER。
            ec::NistCurve::P224 => Key::P224(nist_key),
            ec::NistCurve::P256 => Key::P256(nist_key),
            ec::NistCurve::P384 => Key::P384(nist_key),
            ec::NistCurve::P521 => Key::P521(nist_key),
        };
        Ok(crypto::KeyMaterial::Ec(
            curve.into(),
            CurveType::Nist,
            key.into(),
        ))
    }

    fn generate_ed25519_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<crypto::KeyMaterial, Error> {
        let mut seed = [0u8; ec::CURVE25519_PRIV_KEY_LEN];
        getrandom::fill(&mut seed)
            .map_err(|_| km_err!(UnknownError, "ed25519 keygen RNG failed"))?;
        let key = Key::Ed25519(ec::Ed25519Key(seed));
        Ok(crypto::KeyMaterial::Ec(
            EcCurve::Curve25519,
            CurveType::EdDsa,
            key.into(),
        ))
    }

    fn generate_x25519_key(
        &self,
        _rng: &mut dyn crypto::Rng,
        _params: &[keymint::KeyParam],
    ) -> Result<crypto::KeyMaterial, Error> {
        let mut seed = [0u8; ec::CURVE25519_PRIV_KEY_LEN];
        getrandom::fill(&mut seed)
            .map_err(|_| km_err!(UnknownError, "x25519 keygen RNG failed"))?;
        let key = Key::X25519(ec::X25519Key(seed));
        Ok(crypto::KeyMaterial::Ec(
            EcCurve::Curve25519,
            CurveType::Xdh,
            key.into(),
        ))
    }

    fn nist_public_key(&self, key: &ec::NistKey, curve: ec::NistCurve) -> Result<Vec<u8>, Error> {
        let priv_bytes = nist_priv_bytes(&key_from_nist(key.clone(), curve))?;
        let pub_key = match curve {
            ec::NistCurve::P224 => {
                let sk = p224::SecretKey::from_slice(&priv_bytes)
                    .map_err(|e| km_err!(UnknownError, "P-224 key: {e:?}"))?;
                sk.public_key().to_encoded_point(false).as_bytes().to_vec()
            }
            ec::NistCurve::P256 => {
                let sk = EcdsaSigningKey::<p256::NistP256>::from_slice(&priv_bytes)
                    .map_err(|e| km_err!(UnknownError, "P-256 key: {e:?}"))?;
                sk.verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
            }
            ec::NistCurve::P384 => {
                let sk = EcdsaSigningKey::<p384::NistP384>::from_slice(&priv_bytes)
                    .map_err(|e| km_err!(UnknownError, "P-384 key: {e:?}"))?;
                sk.verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
            }
            ec::NistCurve::P521 => {
                let sk = EcdsaSigningKey::<p521::NistP521>::from_slice(&priv_bytes)
                    .map_err(|e| km_err!(UnknownError, "P-521 key: {e:?}"))?;
                sk.verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()
            }
        };
        Ok(pub_key)
    }

    fn ed25519_public_key(&self, key: &ec::Ed25519Key) -> Result<Vec<u8>, Error> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&key.0);
        Ok(sk.verifying_key().to_bytes().to_vec())
    }

    fn x25519_public_key(&self, key: &ec::X25519Key) -> Result<Vec<u8>, Error> {
        let sk = x25519_dalek::StaticSecret::from(key.0);
        let pk = x25519_dalek::PublicKey::from(&sk);
        Ok(pk.as_bytes().to_vec())
    }

    fn begin_agree(&self, key: OpaqueOr<Key>) -> Result<Box<dyn AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        Ok(Box::new(OmmegaEcAgreeOperation {
            key,
            pending_input: Vec::new(),
        }))
    }

    fn begin_sign(
        &self,
        key: OpaqueOr<Key>,
        digest: Digest,
    ) -> Result<Box<dyn AccumulatingOperation>, Error> {
        let key = explicit!(key)?;
        let curve = key.curve();
        match key {
            Key::P224(key) | Key::P256(key) | Key::P384(key) | Key::P521(key) => {
                let curve = ec::NistCurve::try_from(curve)?;
                if digest == Digest::None {
                    Ok(Box::new(OmmegaEcUndigestSignOperation::new(key, curve)?))
                } else {
                    Ok(Box::new(OmmegaEcDigestSignOperation::new(
                        key, curve, digest,
                    )?))
                }
            }
            Key::Ed25519(key) => Ok(Box::new(OmmegaEd25519SignOperation::new(key)?)),
            Key::X25519(_) => Err(km_err!(
                IncompatibleAlgorithm,
                "X25519 key not valid for signing"
            )),
        }
    }
}

fn key_from_nist(key: ec::NistKey, curve: ec::NistCurve) -> Key {
    match curve {
        ec::NistCurve::P224 => Key::P224(key),
        ec::NistCurve::P256 => Key::P256(key),
        ec::NistCurve::P384 => Key::P384(key),
        ec::NistCurve::P521 => Key::P521(key),
    }
}

fn generate_nist_der(curve: ec::NistCurve) -> Result<Vec<u8>, Error> {
    let mut rng = rand_core::OsRng;
    match curve {
        ec::NistCurve::P224 => {
            let sk = p224::SecretKey::random(&mut rng);
            sec1_der(sk.to_bytes().as_slice())
        }
        ec::NistCurve::P256 => {
            let sk = EcdsaSigningKey::<p256::NistP256>::random(&mut rng);
            sec1_der(sk.to_bytes().as_slice())
        }
        ec::NistCurve::P384 => {
            let sk = EcdsaSigningKey::<p384::NistP384>::random(&mut rng);
            sec1_der(sk.to_bytes().as_slice())
        }
        ec::NistCurve::P521 => {
            let sk = EcdsaSigningKey::<p521::NistP521>::random(&mut rng);
            sec1_der(sk.to_bytes().as_slice())
        }
    }
}

/// Build a SEC1 `ECPrivateKey` DER (version 1, privateKey only).
fn sec1_der(priv_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let body = sec1::EcPrivateKey {
        private_key: priv_bytes,
        parameters: None,
        public_key: None,
    };
    body.to_der()
        .map_err(|e| km_err!(UnknownError, "encode SEC1: {e:?}"))
}

fn nist_priv_bytes(key: &Key) -> Result<Vec<u8>, Error> {
    let nist = match key {
        Key::P224(k) | Key::P256(k) | Key::P384(k) | Key::P521(k) => k,
        _ => return Err(km_err!(InvalidArgument, "not a NIST key")),
    };
    let ec_key = EcPrivateKey::from_der(&nist.0)
        .map_err(|e| km_err!(UnknownError, "failed to parse NIST key: {e:?}"))?;
    Ok(ec_key.private_key.to_vec())
}

/// ECDH operation (peer public key arrives as DER SubjectPublicKeyInfo).
pub struct OmmegaEcAgreeOperation {
    key: Key,
    pending_input: Vec<u8>,
}

impl crypto::AccumulatingOperation for OmmegaEcAgreeOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(164)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let peer_spki = spki::SubjectPublicKeyInfoRef::try_from(self.pending_input.as_slice())
            .map_err(|_| km_err!(InvalidArgument, "peer key not SPKI"))?;
        let peer_raw = peer_spki.subject_public_key.raw_bytes();
        match &self.key {
            Key::P224(_) | Key::P256(_) | Key::P384(_) | Key::P521(_) => {
                let curve = self.key.curve();
                let nist = ec::NistCurve::try_from(curve)?;
                let priv_bytes = nist_priv_bytes(&self.key)?;
                let shared = match nist {
                    ec::NistCurve::P224 => {
                        return Err(km_err!(UnsupportedEcCurve, "P-224 ECDH unsupported"))
                    }
                    ec::NistCurve::P256 => {
                        let sk = p256::SecretKey::from_slice(&priv_bytes)
                            .map_err(|e| km_err!(InvalidArgument, "P-256 key: {e:?}"))?;
                        let vk = p256::PublicKey::from_sec1_bytes(peer_raw)
                            .map_err(|e| km_err!(InvalidArgument, "peer P-256 key: {e:?}"))?;
                        let shared =
                            p256::ecdh::diffie_hellman(&sk.to_nonzero_scalar(), vk.as_affine());
                        shared.raw_secret_bytes().to_vec()
                    }
                    ec::NistCurve::P384 => {
                        let sk = p384::SecretKey::from_slice(&priv_bytes)
                            .map_err(|e| km_err!(InvalidArgument, "P-384 key: {e:?}"))?;
                        let vk = p384::PublicKey::from_sec1_bytes(peer_raw)
                            .map_err(|e| km_err!(InvalidArgument, "peer P-384 key: {e:?}"))?;
                        let shared =
                            p384::ecdh::diffie_hellman(&sk.to_nonzero_scalar(), vk.as_affine());
                        shared.raw_secret_bytes().to_vec()
                    }
                    ec::NistCurve::P521 => {
                        let sk = p521::SecretKey::from_slice(&priv_bytes)
                            .map_err(|e| km_err!(InvalidArgument, "P-521 key: {e:?}"))?;
                        let vk = p521::PublicKey::from_sec1_bytes(peer_raw)
                            .map_err(|e| km_err!(InvalidArgument, "peer P-521 key: {e:?}"))?;
                        let shared =
                            p521::ecdh::diffie_hellman(&sk.to_nonzero_scalar(), vk.as_affine());
                        shared.raw_secret_bytes().to_vec()
                    }
                };
                Ok(shared)
            }
            Key::X25519(key) => {
                if peer_raw.len() != 32 {
                    return Err(km_err!(InvalidArgument, "X25519 peer key wrong length"));
                }
                let mut pk_bytes = [0u8; 32];
                pk_bytes.copy_from_slice(peer_raw);
                let sk = x25519_dalek::StaticSecret::from(key.0);
                let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(pk_bytes));
                Ok(shared.as_bytes().to_vec())
            }
            Key::Ed25519(_) => Err(km_err!(
                IncompatibleAlgorithm,
                "Ed25519 key not valid for agreement"
            )),
        }
    }
}

/// ECDSA signing with external digest (data is hashed by caller, then signed).
pub struct OmmegaEcDigestSignOperation {
    key: Key,
    curve: ec::NistCurve,
    digest: Digest,
    pending_input: Vec<u8>,
}

impl OmmegaEcDigestSignOperation {
    fn new(key: ec::NistKey, curve: ec::NistCurve, digest: Digest) -> Result<Self, Error> {
        Ok(Self {
            key: key_from_nist(key, curve),
            curve,
            digest,
            pending_input: Vec::new(),
        })
    }
}

impl crypto::AccumulatingOperation for OmmegaEcDigestSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let digest = ec_digest_bytes(self.digest, &self.pending_input)?;
        sign_ecdsa_prehashed(&self.key, self.curve, &digest)
    }
}

/// ECDSA signing of undigested data.
pub struct OmmegaEcUndigestSignOperation {
    key: Key,
    curve: ec::NistCurve,
    pending_input: Vec<u8>,
}

impl OmmegaEcUndigestSignOperation {
    fn new(key: ec::NistKey, curve: ec::NistCurve) -> Result<Self, Error> {
        Ok(Self {
            key: key_from_nist(key, curve),
            curve,
            pending_input: Vec::new(),
        })
    }
}

impl crypto::AccumulatingOperation for OmmegaEcUndigestSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        // 真机量到的语义：输入比域宽长不是错误，ECDSA 把它当大整数，只取最左边域宽
        // 那几字节（RFC 6979 的 bits2int）；短的就左边补 0。上一版这里直接回
        // InvalidInputLength，检测器拿 128 字节的"摘要"进来就拿到 -21。
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        sign_ecdsa_prehashed(&self.key, self.curve, &self.pending_input)
    }
}

/// 按请求的摘要算一遍（EC 签名的输入是消息本体，摘要由 TA 算）。
fn ec_digest_bytes(digest: Digest, data: &[u8]) -> Result<Vec<u8>, Error> {
    use sha2::Digest as _;
    let out = match digest {
        Digest::Sha1 => sha1::Sha1::digest(data).to_vec(),
        Digest::Sha224 => sha2::Sha224::digest(data).to_vec(),
        Digest::Sha256 => sha2::Sha256::digest(data).to_vec(),
        Digest::Sha384 => sha2::Sha384::digest(data).to_vec(),
        Digest::Sha512 => sha2::Sha512::digest(data).to_vec(),
        d => return Err(km_err!(UnsupportedDigest, "unsupported digest {:?}", d)),
    };
    Ok(out)
}

/// ECDSA 的输入是 `bits2int(摘要)`：取最左边「群阶位数」那几位，多出来的低位右移掉，
/// 不足的左边补 0。
///
/// P-256/P-384 的域宽正好等于阶位数（32/48 字节），这条看不出来；**P-521 的域是 528 位、
/// 阶只有 521 位**，多出的 7 位必须右移掉。以前这里把这 66 字节原样交给 RustCrypto，
/// 它按域宽截断而不是按阶位数截断，签出来的签名只对「未做 521 位截断的那个整数」成立，
/// 用 FIPS/NONEwithECDSA 的标准验签一验就不过（真机缺口探针 E02 命中的就是这条）。
fn bits2int(msg: &[u8], curve: ec::NistCurve) -> Vec<u8> {
    let nbits = match curve {
        ec::NistCurve::P224 => 224,
        ec::NistCurve::P256 => 256,
        ec::NistCurve::P384 => 384,
        ec::NistCurve::P521 => 521,
    };
    let len = curve.coord_len();
    let mut out = vec![0u8; len];
    if msg.is_empty() {
        return out;
    }
    // 大端：先按域宽取**最左边**（高位）那几字节，比域窄的左边补 0。
    let take = msg.len().min(len);
    out[len - take..].copy_from_slice(&msg[..take]);
    // 再按「阶位数」把多出来的低位右移掉（P-521 域 528 位、阶 521 位 → 右移 7 位）。
    let bits = take * 8;
    if bits > nbits {
        shift_right_be(&mut out, bits - nbits);
    }
    out
}

/// 大端字节串整体右移 `bits` 位。
///
/// 大端下「位 0」是最高位：右移之后结果的最低位来自原串更靠后的位，所以结果第 `pos`
/// 位（从最高位数）对应原串第 `pos - bits` 位，负数补 0。别把方向搞反 —— 反了会把
/// 62 个 0xFF 右移成 0xFF 而不是 0x01FF…（我第一次就写反了）。
fn shift_right_be(buf: &mut [u8], bits: usize) {
    let total = buf.len() * 8;
    if bits == 0 {
        return;
    }
    if bits >= total {
        buf.fill(0);
        return;
    }
    let bit_at = |idx: usize| -> u8 {
        let byte = idx / 8;
        let bit = 7 - (idx % 8);
        buf.get(byte).map(|b| (b >> bit) & 1).unwrap_or(0)
    };
    let mut out = vec![0u8; buf.len()];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut byte = 0u8;
        for k in 0..8 {
            let pos = i * 8 + k;
            let src = pos.checked_sub(bits).map(bit_at).unwrap_or(0);
            byte = (byte << 1) | src;
        }
        *slot = byte;
    }
    buf.copy_from_slice(&out);
}
/// Sign a digest directly with ECDSA, returning a DER signature.
///
/// 两件事必须跟 AOSP 的 BoringSSL 一致，否则检测器一眼能看出这不是 TEE 的行为：
///
/// - 输入按 `bits2int` 处理（最左边阶位数的位），见 [`bits2int`]；
/// - **每次签名取随机 k**。RustCrypto 的 `sign_prehash`/`SigningKey::sign` 走 RFC 6979，
///   同一把钥匙同一个消息签两次字节完全一样；BoringSSL 是 `ECDSA_do_sign` 取随机 k，
///   两次不一样。真机缺口探针 E04 就是拿这个判的。
fn sign_ecdsa_prehashed(key: &Key, curve: ec::NistCurve, msg: &[u8]) -> Result<Vec<u8>, Error> {
    use ecdsa::hazmat::SignPrimitive as _;
    use elliptic_curve::ff::Field as _;
    let priv_bytes = nist_priv_bytes(key)?;
    let z = bits2int(msg, curve);
    let mut rng = rand_core::OsRng;
    let sig = match curve {
        // P-224 只有工程模式那类自检会要（`KeyAttestationTest.testEcAttestation` 用的就是
        // secp224r1）。以前这里直接回 UnsupportedEcCurve，于是工程模式的
        // `isGoogleKeyImport()` 抛异常 → 「Attestation key 失败」。
        ec::NistCurve::P224 => {
            let sk = EcdsaSigningKey::<p224::NistP224>::from_slice(&priv_bytes)
                .map_err(|e| km_err!(UnknownError, "P-224 key: {e:?}"))?;
            let field = p224::FieldBytes::clone_from_slice(&z);
            let k = p224::Scalar::random(&mut rng);
            let (s, _) = sk
                .as_nonzero_scalar()
                .try_sign_prehashed(k, &field)
                .map_err(|e| km_err!(UnknownError, "P-224 prehash sign: {e:?}"))?;
            let s: SigP224 = s;
            s.to_der().to_vec()
        }
        ec::NistCurve::P256 => {
            let sk = EcdsaSigningKey::<p256::NistP256>::from_slice(&priv_bytes)
                .map_err(|e| km_err!(UnknownError, "P-256 key: {e:?}"))?;
            let field = p256::FieldBytes::clone_from_slice(&z);
            let k = p256::Scalar::random(&mut rng);
            let (s, _) = sk
                .as_nonzero_scalar()
                .try_sign_prehashed(k, &field)
                .map_err(|e| km_err!(UnknownError, "P-256 prehash sign: {e:?}"))?;
            let s: SigP256 = s;
            s.to_der().to_vec()
        }
        ec::NistCurve::P384 => {
            let sk = EcdsaSigningKey::<p384::NistP384>::from_slice(&priv_bytes)
                .map_err(|e| km_err!(UnknownError, "P-384 key: {e:?}"))?;
            let field = p384::FieldBytes::clone_from_slice(&z);
            let k = p384::Scalar::random(&mut rng);
            let (s, _) = sk
                .as_nonzero_scalar()
                .try_sign_prehashed(k, &field)
                .map_err(|e| km_err!(UnknownError, "P-384 prehash sign: {e:?}"))?;
            let s: SigP384 = s;
            s.to_der().to_vec()
        }
        ec::NistCurve::P521 => {
            // RustCrypto 的 P-521 没给 `PrehashSigner`/`DigestPrimitive` 实现，但底层标量
            // 运算有：走 `SignPrimitive::try_sign_prehashed`，自己做 bits2int。
            let sk = EcdsaSigningKey::<p521::NistP521>::from_slice(&priv_bytes)
                .map_err(|e| km_err!(UnknownError, "P-521 key: {e:?}"))?;
            let field = p521::FieldBytes::clone_from_slice(&z);
            let k = p521::Scalar::random(&mut rng);
            let (s, _) = sk
                .as_nonzero_scalar()
                .try_sign_prehashed(k, &field)
                .map_err(|e| km_err!(UnknownError, "P-521 prehash sign: {e:?}"))?;
            s.to_der().to_vec()
        }
    };
    Ok(sig)
}

/// EdDSA signing operation for Ed25519.
pub struct OmmegaEd25519SignOperation {
    key: ed25519_dalek::SigningKey,
    pending_input: Vec<u8>,
}

impl OmmegaEd25519SignOperation {
    fn new(key: ec::Ed25519Key) -> Result<Self, Error> {
        Ok(Self {
            key: ed25519_dalek::SigningKey::from_bytes(&key.0),
            pending_input: Vec::new(),
        })
    }
}

impl crypto::AccumulatingOperation for OmmegaEd25519SignOperation {
    fn max_input_size(&self) -> Option<usize> {
        Some(ec::MAX_ED25519_MSG_SIZE)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.pending_input.try_extend_from_slice(data)?;
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        use ed25519_dalek::Signer as _;
        let sig = self.key.sign(&self.pending_input);
        Ok(sig.to_bytes().to_vec())
    }
}
#[cfg(test)]
mod signing_tests {
    use super::*;
    use ecdsa::signature::hazmat::PrehashVerifier as _;
    use sha2::Digest as _;

    fn p256_key() -> Key {
        let sk = p256::SecretKey::random(&mut rand_core::OsRng);
        Key::P256(ec::NistKey(sk.to_sec1_der().unwrap().to_vec()))
    }

    fn p256_verifier(key: &Key) -> p256::ecdsa::VerifyingKey {
        let priv_bytes = nist_priv_bytes(key).unwrap();
        let sk = EcdsaSigningKey::<p256::NistP256>::from_slice(&priv_bytes).unwrap();
        *sk.verifying_key()
    }

    /// DIGEST_NONE：输入本来就是摘要，不能再哈希一层。
    #[test]
    fn undigest_signs_the_given_digest_without_hashing_again() {
        let key = p256_key();
        let digest = [0x5au8; 32];
        let mut op = OmmegaEcUndigestSignOperation::new(
            match &key {
                Key::P256(k) => k.clone(),
                _ => unreachable!(),
            },
            ec::NistCurve::P256,
        )
        .unwrap();
        op.update(&digest).unwrap();
        let sig = Box::new(op).finish().unwrap();

        let verifier = p256_verifier(&key);
        let sig = SigP256::from_der(&sig).unwrap();
        verifier
            .verify_prehash(&digest, &sig)
            .unwrap_or_else(|e| panic!("NONEwithECDSA 验签失败（说明又哈希了一层）: {e:?}"));
    }

    /// 长摘要（比域宽）：不是错误，取最左边域宽那几字节再签（RFC 6979 bits2int）。
    #[test]
    fn undigest_truncates_input_longer_than_the_field() {
        let key = p256_key();
        let long: Vec<u8> = (0u8..128).collect();
        let mut op = OmmegaEcUndigestSignOperation::new(
            match &key {
                Key::P256(k) => k.clone(),
                _ => unreachable!(),
            },
            ec::NistCurve::P256,
        )
        .unwrap();
        op.update(&long[..64]).unwrap();
        op.update(&long[64..]).expect("128 字节不该报错");
        let sig = Box::new(op).finish().unwrap();

        let verifier = p256_verifier(&key);
        let sig = SigP256::from_der(&sig).unwrap();
        verifier
            .verify_prehash(&long[..32], &sig)
            .unwrap_or_else(|e| panic!("长摘要应当取左边 32 字节验得过: {e:?}"));
    }

    /// 短摘要（比域窄）：左边补 0 再签，不能直接报错。
    #[test]
    fn undigest_pads_a_short_digest_on_the_left() {
        let key = p256_key();
        let short = [0x11u8; 8];
        let mut op = OmmegaEcUndigestSignOperation::new(
            match &key {
                Key::P256(k) => k.clone(),
                _ => unreachable!(),
            },
            ec::NistCurve::P256,
        )
        .unwrap();
        op.update(&short).unwrap();
        let sig = Box::new(op).finish().unwrap();

        let mut padded = [0u8; 32];
        padded[24..].copy_from_slice(&short);
        let verifier = p256_verifier(&key);
        let sig = SigP256::from_der(&sig).unwrap();
        verifier
            .verify_prehash(&padded, &sig)
            .unwrap_or_else(|e| panic!("短摘要应当左补 0 后验得过: {e:?}"));
    }

    /// 带摘要的请求：算的必须是请求指定的摘要，不是曲线默认的 SHA-256。
    #[test]
    fn digest_sign_honours_the_requested_digest() {
        let key = p256_key();
        let message = b"ommega digest check";
        let mut op = OmmegaEcDigestSignOperation::new(
            match &key {
                Key::P256(k) => k.clone(),
                _ => unreachable!(),
            },
            ec::NistCurve::P256,
            Digest::Sha384,
        )
        .unwrap();
        op.update(message).unwrap();
        let sig = Box::new(op).finish().unwrap();

        let verifier = p256_verifier(&key);
        let sig = SigP256::from_der(&sig).unwrap();
        verifier
            .verify_prehash(&sha2::Sha384::digest(message), &sig)
            .unwrap_or_else(|e| panic!("SHA384withECDSA 验签失败: {e:?}"));
    }

    /// bits2int：P-521 的域是 528 位、阶只有 521 位，多出的 7 位必须右移掉。
    /// 全 0xFF 的 66 字节右移 7 位就是 `0x01` + 65 个 0xFF（521 个 1）。
    #[test]
    fn bits2int_truncates_p521_to_the_group_order() {
        let all_ones = vec![0xffu8; 66];
        let z = bits2int(&all_ones, ec::NistCurve::P521);
        assert_eq!(z.len(), 66);
        assert_eq!(z[0], 0x01);
        assert!(z[1..].iter().all(|b| *b == 0xff));
    }

    /// bits2int：比域宽的输入取最左边那几字节（P-256 拿 128 字节就是前 32 字节）。
    #[test]
    fn bits2int_keeps_the_leftmost_bytes() {
        let long: Vec<u8> = (0u8..128).collect();
        assert_eq!(bits2int(&long, ec::NistCurve::P256), long[..32].to_vec());
        assert_eq!(bits2int(&long, ec::NistCurve::P384), long[..48].to_vec());
    }

    /// bits2int：比域窄的输入左补 0。
    #[test]
    fn bits2int_pads_short_inputs_on_the_left() {
        let short = [0x11u8; 10];
        let z = bits2int(&short, ec::NistCurve::P256);
        assert_eq!(z.len(), 32);
        assert!(z[..22].iter().all(|b| *b == 0));
        assert_eq!(&z[22..], &short);
    }

    /// 同一把钥匙、同一个摘要签两次，字节必须不同（AOSP 的 BoringSSL 取随机 k）。
    /// 以前走 RFC 6979 是确定性的，两次一模一样，检测器拿这个判「不是 TEE 的 ECDSA」。
    #[test]
    fn repeated_ecdsa_signatures_differ() {
        let digest = [0x42u8; 32];
        let key = p256_key();
        let priv_bytes = nist_priv_bytes(&key).unwrap();
        let first = sign_ecdsa_prehashed(&key, ec::NistCurve::P256, &digest).unwrap();
        let second = sign_ecdsa_prehashed(&key, ec::NistCurve::P256, &digest).unwrap();
        assert_ne!(first, second, "P-256 两次签名不该相同");

        // 两份都得能验过（随机 k 不影响正确性）。
        let verifier = p256_verifier(&key);
        for der in [first, second] {
            let sig = SigP256::from_der(&der).unwrap();
            verifier
                .verify_prehash(&digest, &sig)
                .unwrap_or_else(|e| panic!("随机 k 的签名验不过: {e:?}"));
        }
        let _ = priv_bytes;
    }

    /// P-384 同样是随机 k。
    #[test]
    fn p384_signatures_are_randomized_too() {
        let sk = p384::SecretKey::random(&mut rand_core::OsRng);
        let key = Key::P384(ec::NistKey(sk.to_sec1_der().unwrap().to_vec()));
        let digest = [0x24u8; 48];
        let first = sign_ecdsa_prehashed(&key, ec::NistCurve::P384, &digest).unwrap();
        let second = sign_ecdsa_prehashed(&key, ec::NistCurve::P384, &digest).unwrap();
        assert_ne!(first, second, "P-384 两次签名不该相同");
    }

    /// P-521：66 字节的输入按 521 位截断后再签，用同一套截断去验必须过；
    /// 用「未截断的 66 字节」验则不该过（这正是探针 E02 命中的那个差别）。
    #[test]
    fn p521_signs_the_truncated_digest() {
        use ecdsa::hazmat::VerifyPrimitive as _;
        let sk = p521::SecretKey::random(&mut rand_core::OsRng);
        let key = Key::P521(ec::NistKey(sk.to_sec1_der().unwrap().to_vec()));
        let digest = [0x7fu8; 66];
        let der = sign_ecdsa_prehashed(&key, ec::NistCurve::P521, &digest).unwrap();

        let priv_bytes = nist_priv_bytes(&key).unwrap();
        let sk = EcdsaSigningKey::<p521::NistP521>::from_slice(&priv_bytes).unwrap();
        let verifying = sk.verifying_key();
        let sig = p521::ecdsa::Signature::from_der(&der).unwrap();

        let z = bits2int(&digest, ec::NistCurve::P521);
        let truncated = p521::FieldBytes::clone_from_slice(&z);
        verifying
            .as_affine()
            .verify_prehashed(&truncated, &sig)
            .unwrap_or_else(|e| panic!("按 521 位截断后应当验得过: {e:?}"));

        let raw = p521::FieldBytes::clone_from_slice(&digest);
        assert!(
            verifying.as_affine().verify_prehashed(&raw, &sig).is_err(),
            "按未截断的 528 位整数验应当不过"
        );
    }
}
