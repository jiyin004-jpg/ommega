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
//! RustCrypto `p256`/`p384`/`p521`, `ed25519-dalek`, `x25519-dalek`).
//! P-224 is not supported by RustCrypto; it returns `UnsupportedEcCurve`.

use der::Decode as _;
use der::Encode as _;
use ecdsa::signature::{SignatureEncoding as _, Signer as _};
use ecdsa::SigningKey as EcdsaSigningKey;
use kmr_common::{
    crypto,
    crypto::{ec, ec::Key, AccumulatingOperation, CurveType, OpaqueOr},
    explicit, km_err, Error, FallibleAllocExt,
};
use kmr_wire::keymint::{self, Digest, EcCurve};
use p256::ecdsa::Signature as SigP256;
use p384::ecdsa::Signature as SigP384;

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
            ec::NistCurve::P224 => return Err(km_err!(UnsupportedEcCurve, "P-224 unsupported")),
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
            ec::NistCurve::P224 => return Err(km_err!(UnsupportedEcCurve, "P-224 unsupported")),
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
        ec::NistCurve::P224 => Err(km_err!(UnsupportedEcCurve, "P-224 unsupported")),
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
                            p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), vk.as_affine());
                        shared.raw_secret_bytes().to_vec()
                    }
                    ec::NistCurve::P384 => {
                        let sk = p384::SecretKey::from_slice(&priv_bytes)
                            .map_err(|e| km_err!(InvalidArgument, "P-384 key: {e:?}"))?;
                        let vk = p384::PublicKey::from_sec1_bytes(peer_raw)
                            .map_err(|e| km_err!(InvalidArgument, "peer P-384 key: {e:?}"))?;
                        let shared =
                            p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), vk.as_affine());
                        shared.raw_secret_bytes().to_vec()
                    }
                    ec::NistCurve::P521 => {
                        let sk = p521::SecretKey::from_slice(&priv_bytes)
                            .map_err(|e| km_err!(InvalidArgument, "P-521 key: {e:?}"))?;
                        let vk = p521::PublicKey::from_sec1_bytes(peer_raw)
                            .map_err(|e| km_err!(InvalidArgument, "peer P-521 key: {e:?}"))?;
                        let shared =
                            p521::ecdh::diffie_hellman(sk.to_nonzero_scalar(), vk.as_affine());
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
        let _ = self.digest;
        sign_ecdsa(&self.key, self.curve, &self.pending_input)
    }
}

/// ECDSA signing of undigested data.
pub struct OmmegaEcUndigestSignOperation {
    key: Key,
    curve: ec::NistCurve,
    pending_input: Vec<u8>,
    max_size: usize,
}

impl OmmegaEcUndigestSignOperation {
    fn new(key: ec::NistKey, curve: ec::NistCurve) -> Result<Self, Error> {
        Ok(Self {
            key: key_from_nist(key, curve),
            curve,
            pending_input: Vec::new(),
            max_size: curve.coord_len(),
        })
    }
}

impl crypto::AccumulatingOperation for OmmegaEcUndigestSignOperation {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let max_extra_data = self.max_size.saturating_sub(self.pending_input.len());
        if max_extra_data > 0 {
            let len = core::cmp::min(max_extra_data, data.len());
            self.pending_input.try_extend_from_slice(&data[..len])?;
        }
        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        sign_ecdsa(&self.key, self.curve, &self.pending_input)
    }
}

/// Sign `msg` (already hashed or raw, per caller) with ECDSA, returning a DER signature.
fn sign_ecdsa(key: &Key, curve: ec::NistCurve, msg: &[u8]) -> Result<Vec<u8>, Error> {
    let priv_bytes = nist_priv_bytes(key)?;
    let sig = match curve {
        ec::NistCurve::P224 => return Err(km_err!(UnsupportedEcCurve, "P-224 ECDSA unsupported")),
        ec::NistCurve::P256 => {
            let sk = EcdsaSigningKey::<p256::NistP256>::from_slice(&priv_bytes)
                .map_err(|e| km_err!(UnknownError, "P-256 key: {e:?}"))?;
            let s: SigP256 = sk.sign(msg);
            s.to_der().to_vec()
        }
        ec::NistCurve::P384 => {
            let sk = EcdsaSigningKey::<p384::NistP384>::from_slice(&priv_bytes)
                .map_err(|e| km_err!(UnknownError, "P-384 key: {e:?}"))?;
            let s: SigP384 = sk.sign(msg);
            s.to_der().to_vec()
        }
        ec::NistCurve::P521 => {
            // RustCrypto's P-521 has no `DigestPrimitive`/`PrehashSigner` impl, so
            // signing is unsupported here. (P-256/P-384 cover normal usage.)
            return Err(km_err!(
                UnsupportedEcCurve,
                "P-521 ECDSA signing unsupported"
            ));
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
