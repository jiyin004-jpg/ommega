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

//! Pure-Rust implementation of AES (replaces BoringSSL; RustCrypto `aes`).
//!
//! ECB/CBC/CTR are implemented with `aes` block cipher + manual block chaining;
//! GCM uses the `aes-gcm` crate with a buffering scheme (inputs are accumulated
//! and processed at `finish`), which is correct for the (small) data sizes KeyMint
//! deals with.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as _, KeyIvInit as _, StreamCipher as _};
use aes::{Aes128, Aes192, Aes256};
use ctr::Ctr128BE;
use kmr_common::{crypto, crypto::OpaqueOr, explicit, km_err, vec_try, Error};
use std::boxed::Box;
use std::vec::Vec;

const BLOCK: usize = crypto::aes::BLOCK_SIZE;

/// [`crypto::Aes`] implementation backed by RustCrypto `aes`.
pub struct OmmegaAes;

trait BlockCipher: Send {
    fn encrypt_block(&self, block: &mut [u8; BLOCK]);
    fn decrypt_block(&self, block: &mut [u8; BLOCK]);
}

macro_rules! impl_block_cipher {
    ($t:ty) => {
        impl BlockCipher for $t {
            fn encrypt_block(&self, block: &mut [u8; BLOCK]) {
                let b = cipher::generic_array::GenericArray::from_mut_slice(block);
                BlockEncrypt::encrypt_block(self, b);
            }
            fn decrypt_block(&self, block: &mut [u8; BLOCK]) {
                let b = cipher::generic_array::GenericArray::from_mut_slice(block);
                BlockDecrypt::decrypt_block(self, b);
            }
        }
    };
}
impl_block_cipher!(Aes128);
impl_block_cipher!(Aes192);
impl_block_cipher!(Aes256);

fn block_cipher(key: &crypto::aes::Key) -> Box<dyn BlockCipher> {
    match key {
        crypto::aes::Key::Aes128(k) => Box::new(Aes128::new_from_slice(k).expect("key len")),
        crypto::aes::Key::Aes192(k) => Box::new(Aes192::new_from_slice(k).expect("key len")),
        crypto::aes::Key::Aes256(k) => Box::new(Aes256::new_from_slice(k).expect("key len")),
    }
}

fn key_bytes(key: &crypto::aes::Key) -> &[u8] {
    match key {
        crypto::aes::Key::Aes128(k) => &k[..],
        crypto::aes::Key::Aes192(k) => &k[..],
        crypto::aes::Key::Aes256(k) => &k[..],
    }
}

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad = BLOCK - data.len() % BLOCK;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, Error> {
    let &pad = data
        .last()
        .ok_or_else(|| km_err!(InvalidInputLength, "empty data"))?;
    let pad = pad as usize;
    if pad == 0 || pad > data.len() || !data.len().is_multiple_of(BLOCK) {
        return Err(km_err!(InvalidInputLength, "bad PKCS#7 padding"));
    }
    let start = data.len() - pad;
    if data[start..].iter().any(|&b| b as usize != pad) {
        return Err(km_err!(InvalidInputLength, "bad PKCS#7 padding bytes"));
    }
    Ok(data[..start].to_vec())
}

/// AES plain operation (ECB/CBC/CTR), buffering until finish.
pub struct OmmegaAesOperation {
    mode: crypto::aes::CipherMode,
    dir: crypto::SymmetricOperation,
    cipher: Box<dyn BlockCipher>,
    /// Original key bytes (for CTR re-keying).
    key: Vec<u8>,
    data: Vec<u8>,
}

impl OmmegaAesOperation {
    fn run_blocks(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match self.mode {
            crypto::aes::CipherMode::EcbNoPadding | crypto::aes::CipherMode::EcbPkcs7Padding => {
                for chunk in input.as_chunks::<16>().0 {
                    let mut blk = [0u8; BLOCK];
                    blk.copy_from_slice(chunk);
                    match self.dir {
                        crypto::SymmetricOperation::Encrypt => self.cipher.encrypt_block(&mut blk),
                        crypto::SymmetricOperation::Decrypt => self.cipher.decrypt_block(&mut blk),
                    }
                    out.extend_from_slice(&blk);
                }
            }
            crypto::aes::CipherMode::CbcNoPadding { nonce }
            | crypto::aes::CipherMode::CbcPkcs7Padding { nonce } => {
                let mut prev: [u8; BLOCK] = nonce;
                for chunk in input.as_chunks::<16>().0 {
                    let mut blk = [0u8; BLOCK];
                    blk.copy_from_slice(chunk);
                    match self.dir {
                        crypto::SymmetricOperation::Encrypt => {
                            for i in 0..BLOCK {
                                blk[i] ^= prev[i];
                            }
                            self.cipher.encrypt_block(&mut blk);
                            prev = blk;
                        }
                        crypto::SymmetricOperation::Decrypt => {
                            let orig = blk;
                            self.cipher.decrypt_block(&mut blk);
                            for i in 0..BLOCK {
                                blk[i] ^= prev[i];
                            }
                            prev = orig;
                        }
                    }
                    out.extend_from_slice(&blk);
                }
            }
            crypto::aes::CipherMode::Ctr { .. } => {
                unreachable!("CTR handled as a stream")
            }
        }
        out
    }
}

impl crypto::EmittingOperation for OmmegaAesOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.data.extend_from_slice(data);
        Ok(Vec::new())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self.mode {
            crypto::aes::CipherMode::EcbNoPadding
            | crypto::aes::CipherMode::CbcNoPadding { .. } => {
                if !self.data.is_empty() && !self.data.len().is_multiple_of(16) {
                    return Err(km_err!(
                        InvalidInputLength,
                        "input length {} not a multiple of block size",
                        self.data.len()
                    ));
                }
                out.extend_from_slice(&self.run_blocks(&self.data));
            }
            crypto::aes::CipherMode::EcbPkcs7Padding
            | crypto::aes::CipherMode::CbcPkcs7Padding { .. } => match self.dir {
                crypto::SymmetricOperation::Encrypt => {
                    let padded = pkcs7_pad(&self.data);
                    out.extend_from_slice(&self.run_blocks(&padded));
                }
                crypto::SymmetricOperation::Decrypt => {
                    let dec = self.run_blocks(&self.data);
                    out.extend_from_slice(&pkcs7_unpad(&dec)?);
                }
            },
            crypto::aes::CipherMode::Ctr { nonce } => {
                // AOSP 把 CTM nonce 的**整 16 字节**当计数器初值（末 4 字节是
                // 计数器本身，调用方给的 DEADBEEF 要原样参与运算）。以前这里只取
                // 前 12 字节、把后 4 字节清零，密文跟原生复算对不上 —— KmProbe 的
                // 「AES-256-CTR · 16 字节固定 IV」就是拿这个判的。
                out = ctr_transform_keyed_bytes(&self.key, &nonce, &self.data)?;
            }
        }
        Ok(out)
    }
}

/// CTR-transform data with the given raw key bytes and 12-byte nonce. Uses AES-128,
/// AES-192 or AES-256 based on key length.
fn ctr_transform_keyed_bytes(key: &[u8], nonce: &[u8; 16], data: &[u8]) -> Result<Vec<u8>, Error> {
    let iv = *nonce;
    let mut ks = vec_try![0; data.len()]?;
    let apply = |out: &mut [u8]| -> Result<(), Error> {
        match key.len() {
            16 => {
                let mut c = Ctr128BE::<Aes128>::new_from_slices(key, &iv)
                    .map_err(|_| km_err!(UnknownError, "invalid AES-128-CTR key"))?;
                c.apply_keystream(out);
            }
            24 => {
                let mut c = Ctr128BE::<Aes192>::new_from_slices(key, &iv)
                    .map_err(|_| km_err!(UnknownError, "invalid AES-192-CTR key"))?;
                c.apply_keystream(out);
            }
            32 => {
                let mut c = Ctr128BE::<Aes256>::new_from_slices(key, &iv)
                    .map_err(|_| km_err!(UnknownError, "invalid AES-256-CTR key"))?;
                c.apply_keystream(out);
            }
            _ => return Err(km_err!(UnknownError, "invalid CTR key length")),
        }
        Ok(())
    };
    apply(&mut ks)?;
    for (o, d) in ks.iter_mut().zip(data.iter()) {
        *o ^= d;
    }
    Ok(ks)
}

/// AES-GCM encrypt operation (buffers AAD + data, processes at finish).
pub struct OmmegaAesGcmEncryptOperation {
    tag_len: usize,
    aad: Vec<u8>,
    data: Vec<u8>,
    key: Vec<u8>,
    nonce: [u8; 12],
}

/// AES-GCM decrypt operation (buffers AAD + data, processes at finish).
pub struct OmmegaAesGcmDecryptOperation {
    tag_len: usize,
    aad: Vec<u8>,
    data: Vec<u8>,
    key: Vec<u8>,
    nonce: [u8; 12],
}

impl crypto::Aes for OmmegaAes {
    fn begin(
        &self,
        key: OpaqueOr<crypto::aes::Key>,
        mode: crypto::aes::CipherMode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::EmittingOperation>, Error> {
        let key = explicit!(key)?;
        let cipher = block_cipher(&key);
        let key_bytes = key_bytes(&key).to_vec();
        Ok(Box::new(OmmegaAesOperation {
            mode,
            dir,
            cipher,
            key: key_bytes,
            data: Vec::new(),
        }))
    }

    fn begin_aead(
        &self,
        key: OpaqueOr<crypto::aes::Key>,
        mode: crypto::aes::GcmMode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::AadOperation>, Error> {
        let key = explicit!(key)?;
        let nonce: [u8; 12] = match mode {
            crypto::aes::GcmMode::GcmTag12 { nonce }
            | crypto::aes::GcmMode::GcmTag13 { nonce }
            | crypto::aes::GcmMode::GcmTag14 { nonce }
            | crypto::aes::GcmMode::GcmTag15 { nonce }
            | crypto::aes::GcmMode::GcmTag16 { nonce } => nonce,
        };
        let tag_len = mode.tag_len();
        let key_bytes = key_bytes(&key).to_vec();
        match dir {
            crypto::SymmetricOperation::Encrypt => Ok(Box::new(OmmegaAesGcmEncryptOperation {
                tag_len,
                aad: Vec::new(),
                data: Vec::new(),
                key: key_bytes,
                nonce,
            })),
            crypto::SymmetricOperation::Decrypt => Ok(Box::new(OmmegaAesGcmDecryptOperation {
                tag_len,
                aad: Vec::new(),
                data: Vec::new(),
                key: key_bytes,
                nonce,
            })),
        }
    }
}

impl crypto::AadOperation for OmmegaAesGcmEncryptOperation {
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Error> {
        self.aad.extend_from_slice(aad);
        Ok(())
    }
}

impl crypto::EmittingOperation for OmmegaAesGcmEncryptOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.data.extend_from_slice(data);
        Ok(Vec::new())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        gcm_encrypt(&self.key, &self.nonce, &self.aad, &self.data, self.tag_len)
    }
}

impl crypto::AadOperation for OmmegaAesGcmDecryptOperation {
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Error> {
        self.aad.extend_from_slice(aad);
        Ok(())
    }
}

impl crypto::EmittingOperation for OmmegaAesGcmDecryptOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.data.extend_from_slice(data);
        Ok(Vec::new())
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>, Error> {
        // The input is ciphertext || tag (tag_len bytes at the end).
        if self.data.len() < self.tag_len {
            return Err(km_err!(InvalidTag, "ciphertext too short for tag"));
        }
        let split = self.data.len() - self.tag_len;
        let ciphertext = &self.data[..split];
        let tag = &self.data[split..];
        // 解不开时把参数形状记一笔：tag 长度对不上、AAD 没跟上、密文被截断这几类
        // 在日志里长得一模一样，不给长度就只能靠猜。
        match gcm_decrypt(&self.key, &self.nonce, &self.aad, ciphertext, tag) {
            Ok(plain) => Ok(plain),
            Err(error) => {
                log::info!(
                    "AES-GCM decrypt rejected: key={}B tag={}B ciphertext={}B aad={}B ({error:?})",
                    self.key.len(),
                    self.tag_len,
                    ciphertext.len(),
                    self.aad.len()
                );
                Err(error)
            }
        }
    }
}

fn gcm_encrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, Error> {
    gcm_encrypt_raw(key, nonce, aad, plaintext, tag_len)
}

fn gcm_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, Error> {
    gcm_decrypt_raw(key, nonce, aad, ciphertext, tag)
}

/// 按 (密钥长度, tag 长度) 分派到 `aes-gcm` 的对应实例。
///
/// ring 的 `AES_*_GCM` 只认 16 字节 tag、也没有 AES-192，所以这里整段换成
/// `aes-gcm`：tag 12/13/14/15/16 都是 AOSP 允许的（`GCMParameterSpec(96, iv)`），
/// 192 位密钥也是（AOSP 同时支持 128/192/256）。
macro_rules! gcm_dispatch {
    ($key:expr, $tag_len:expr, $op:ident, $nonce:expr, $aad:expr, $input:expr) => {{
        use aes_gcm::aead::consts::{U12, U13, U14, U15, U16};
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::aes::{Aes128, Aes192, Aes256};
        use aes_gcm::{AesGcm, Nonce};
        macro_rules! run {
            ($c:ty, $t:ty) => {{
                // AesGcm<Cipher, NonceSize, TagSize>：nonce 固定 12，tag 长度走第三格。
                let cipher = AesGcm::<$c, U12, $t>::new_from_slice($key)
                    .map_err(|_| km_err!(UnknownError, "invalid GCM key"))?;
                let nonce = Nonce::from_slice($nonce);
                let payload = Payload {
                    msg: $input,
                    aad: $aad,
                };
                cipher
                    .$op(nonce, payload)
                    .map_err(|_| km_err!(VerificationFailed, "GCM operation failed"))
            }};
        }
        match ($key.len(), $tag_len) {
            (16, 12) => run!(Aes128, U12),
            (16, 13) => run!(Aes128, U13),
            (16, 14) => run!(Aes128, U14),
            (16, 15) => run!(Aes128, U15),
            (16, 16) => run!(Aes128, U16),
            (24, 12) => run!(Aes192, U12),
            (24, 13) => run!(Aes192, U13),
            (24, 14) => run!(Aes192, U14),
            (24, 15) => run!(Aes192, U15),
            (24, 16) => run!(Aes192, U16),
            (32, 12) => run!(Aes256, U12),
            (32, 13) => run!(Aes256, U13),
            (32, 14) => run!(Aes256, U14),
            (32, 15) => run!(Aes256, U15),
            (32, 16) => run!(Aes256, U16),
            (len, tag) => Err(km_err!(
                UnsupportedKeySize,
                "AES-GCM key {len} bytes with {tag}-byte tag"
            )),
        }
    }};
}

/// Public AES-GCM encrypt helper (used by `km`). Emits `ciphertext || tag`.
pub(crate) fn gcm_encrypt_raw(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<Vec<u8>, Error> {
    gcm_dispatch!(key, tag_len, encrypt, nonce, aad, plaintext)
}

/// Public AES-GCM decrypt helper (used by `km`). `ciphertext` and `tag` are separate.
pub(crate) fn gcm_decrypt_raw(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut input = vec_try![0; ciphertext.len() + tag.len()]?;
    input[..ciphertext.len()].copy_from_slice(ciphertext);
    input[ciphertext.len()..].copy_from_slice(tag);
    gcm_dispatch!(key, tag.len(), decrypt, nonce, aad, &input)
}

/// KmProbe 的 GCM / CTR 项：192 位密钥、12~16 字节 tag、CTR 用完整 16 字节 IV。
#[cfg(test)]
mod kmprobe_regression_tests {
    use super::*;

    fn nonce() -> [u8; 12] {
        let mut n = [0u8; 12];
        for (i, b) in n.iter_mut().enumerate() {
            *b = 0xa0u8.wrapping_add(i as u8);
        }
        n
    }

    /// AOSP 同时支持 128/192/256 位 AES-GCM，192 位以前被直接拒了。
    #[test]
    fn aes192_gcm_round_trips() {
        let key = [0x11u8; 24];
        let ct = gcm_encrypt_raw(&key, &nonce(), b"aad", b"kmprobe-gcm-0123456789", 16).unwrap();
        assert_eq!(ct.len(), 22 + 16);
        let pt = gcm_decrypt_raw(&key, &nonce(), b"aad", &ct[..22], &ct[22..]).unwrap();
        assert_eq!(pt, b"kmprobe-gcm-0123456789");
    }

    /// `GCMParameterSpec(96, iv)`：tag 长度 12 字节也要能加解密，
    /// 输出 = 明文长度 + 12。
    #[test]
    fn gcm_accepts_twelve_byte_tags() {
        for tag_len in 12..=16usize {
            let key = [0x22u8; 32];
            let msg = b"kmprobe-gcm96";
            let ct = gcm_encrypt_raw(&key, &nonce(), &[], msg, tag_len).unwrap();
            assert_eq!(ct.len(), msg.len() + tag_len, "tag {tag_len}");
            let split = ct.len() - tag_len;
            let pt = gcm_decrypt_raw(&key, &nonce(), &[], &ct[..split], &ct[split..]).unwrap();
            assert_eq!(pt, msg, "tag {tag_len}");
        }
    }

    /// AES-CTR 的 16 字节 IV 要**整段**当计数器初值（末 4 字节非零也要参与），
    /// 不能像以前那样把后 4 字节清零。
    #[test]
    fn ctr_uses_the_whole_sixteen_byte_iv() {
        use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
        let key = [0x33u8; 32];
        let mut iv = [0u8; 16];
        iv[12] = 0xde;
        iv[13] = 0xad;
        iv[14] = 0xbe;
        iv[15] = 0xef;
        let mut plain = [0u8; 32];
        for (i, b) in plain.iter_mut().enumerate() {
            *b = 0x40u8.wrapping_add(i as u8);
        }

        let got = ctr_transform_keyed_bytes(&key, &iv, &plain).unwrap();

        let mut reference = plain;
        let mut cipher = Ctr128BE::<Aes256>::new_from_slices(&key, &iv).unwrap();
        cipher.apply_keystream(&mut reference);
        assert_eq!(got, reference, "必须跟「整 16 字节 IV」的复算一致");

        // 反向对照：把后 4 字节清零的复算必须**不**相等。
        let mut zeroed_iv = iv;
        zeroed_iv[12..].fill(0);
        let mut wrong = plain;
        let mut cipher = Ctr128BE::<Aes256>::new_from_slices(&key, &zeroed_iv).unwrap();
        cipher.apply_keystream(&mut wrong);
        assert_ne!(got, wrong, "不能再踩「IV 后 4 字节清零」那个坑");
    }
}
