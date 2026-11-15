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

//! Pure-Rust implementation of 3-DES (replaces BoringSSL; RustCrypto `des`).
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use des::TdesEde3;
use kmr_common::{crypto, crypto::OpaqueOr, explicit, km_err, Error};
use std::boxed::Box;
use std::vec::Vec;

/// [`crypto::Des`] implementation backed by RustCrypto `des` (3-DES/EDE).
pub struct OmmegaDes;

impl crypto::Des for OmmegaDes {
    fn begin(
        &self,
        key: OpaqueOr<crypto::des::Key>,
        mode: crypto::des::Mode,
        dir: crypto::SymmetricOperation,
    ) -> Result<Box<dyn crypto::EmittingOperation>, Error> {
        let key = explicit!(key)?;
        let cipher = TdesEde3::new_from_slice(&key.0)
            .map_err(|_| km_err!(UnknownError, "invalid 3-DES key"))?;
        Ok(Box::new(OmmegaDesOperation {
            cipher,
            mode,
            dir,
            pending: Vec::new(),
        }))
    }
}

/// DES operation backed by RustCrypto `des`.
pub struct OmmegaDesOperation {
    cipher: TdesEde3,
    mode: crypto::des::Mode,
    dir: crypto::SymmetricOperation,
    /// Buffered input awaiting a full block.
    pending: Vec<u8>,
}

const BLOCK: usize = crypto::des::BLOCK_SIZE;

fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
    let pad = block - data.len() % block;
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, Error> {
    let &pad = data
        .last()
        .ok_or_else(|| km_err!(InvalidInputLength, "empty block"))?;
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

impl OmmegaDesOperation {
    fn process_block(&mut self, block: &mut [u8; BLOCK]) {
        let key = GenericArray::from_mut_slice(block);
        match self.dir {
            crypto::SymmetricOperation::Encrypt => {
                self.cipher.encrypt_block(key);
            }
            crypto::SymmetricOperation::Decrypt => {
                self.cipher.decrypt_block(key);
            }
        }
    }

    fn run_cipher(&mut self, input: &[u8], output: &mut Vec<u8>) {
        match self.mode {
            crypto::des::Mode::EcbNoPadding | crypto::des::Mode::EcbPkcs7Padding => {
                for chunk in input.as_chunks::<8>().0 {
                    let mut blk = [0u8; BLOCK];
                    blk.copy_from_slice(chunk);
                    self.process_block(&mut blk);
                    output.extend_from_slice(&blk);
                }
            }
            crypto::des::Mode::CbcNoPadding { nonce }
            | crypto::des::Mode::CbcPkcs7Padding { nonce } => {
                let mut prev: [u8; BLOCK] = nonce;
                for chunk in input.as_chunks::<8>().0 {
                    let mut blk = [0u8; BLOCK];
                    blk.copy_from_slice(chunk);
                    match self.dir {
                        crypto::SymmetricOperation::Encrypt => {
                            for i in 0..BLOCK {
                                blk[i] ^= prev[i];
                            }
                            self.process_block(&mut blk);
                            prev = blk;
                        }
                        crypto::SymmetricOperation::Decrypt => {
                            let orig = blk;
                            self.process_block(&mut blk);
                            for i in 0..BLOCK {
                                blk[i] ^= prev[i];
                            }
                            prev = orig;
                        }
                    }
                    output.extend_from_slice(&blk);
                }
            }
        }
    }
}

impl crypto::EmittingOperation for OmmegaDesOperation {
    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        // Buffer until a full block is available.
        self.pending.extend_from_slice(data);
        let mut usable = self.pending.len() / BLOCK * BLOCK;
        // PKCS#7 解密：最后一块留到 finish 再验，update 阶段不吐。
        if self.dir == crypto::SymmetricOperation::Decrypt
            && matches!(
                self.mode,
                crypto::des::Mode::EcbPkcs7Padding | crypto::des::Mode::CbcPkcs7Padding { .. }
            )
            && usable >= BLOCK
        {
            usable -= BLOCK;
        }
        let mut out = Vec::new();
        let pending_slice = self.pending[..usable].to_vec();
        self.run_cipher(&pending_slice, &mut out);
        self.pending.drain(..usable);
        Ok(out)
    }

    fn finish(mut self: Box<Self>) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self.mode {
            crypto::des::Mode::EcbNoPadding | crypto::des::Mode::CbcNoPadding { .. } => {
                if !self.pending.is_empty() {
                    return Err(km_err!(
                        InvalidInputLength,
                        "input length {} not a multiple of block size",
                        self.pending.len()
                    ));
                }
            }
            crypto::des::Mode::EcbPkcs7Padding | crypto::des::Mode::CbcPkcs7Padding { .. } => {
                match self.dir {
                    crypto::SymmetricOperation::Encrypt => {
                        let padded = pkcs7_pad(&self.pending, BLOCK);
                        self.run_cipher(&padded, &mut out);
                    }
                    crypto::SymmetricOperation::Decrypt => {
                        // The full ciphertext (including padding block) may have
                        // arrived in one update; handle the leftover here.
                        if !self.pending.is_empty() {
                            let p = self.pending.clone();
                            self.run_cipher(&p, &mut out);
                        }
                        out = pkcs7_unpad(&out)?;
                    }
                }
            }
        }
        Ok(out)
    }
}

/// KmProbe 的 3DES 往返：`doFinal(ct)` 走的是 update(ct) + finish()，
/// 解密时最后一块要留到 finish 才能验 PKCS#7 填充。
#[cfg(test)]
mod pkcs7_decrypt_tests {
    use super::*;
    use crypto::Des as _;

    fn key() -> crypto::des::Key {
        let mut raw = [0u8; 24];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (0x11 + i) as u8;
        }
        crypto::des::Key(raw)
    }

    fn round_trip(mode: crypto::des::Mode) {
        let plain = b"kmprobe-3des";
        let ct = {
            let mut op = OmmegaDes
                .begin(key().into(), mode, crypto::SymmetricOperation::Encrypt)
                .unwrap();
            let mut ct = op.update(plain).unwrap();
            ct.extend(op.finish().unwrap());
            ct
        };
        assert!(!ct.is_empty() && ct.len() % crypto::des::BLOCK_SIZE == 0);

        let mut dec = OmmegaDes
            .begin(key().into(), mode, crypto::SymmetricOperation::Decrypt)
            .unwrap();
        let mut pt = dec.update(&ct).unwrap();
        pt.extend(dec.finish().unwrap());
        assert_eq!(pt, plain, "3DES 往返必须还原原文");
    }

    #[test]
    fn cbc_pkcs7_decrypts_in_one_update() {
        round_trip(crypto::des::Mode::CbcPkcs7Padding {
            nonce: [9, 8, 7, 6, 5, 4, 3, 2],
        });
    }

    #[test]
    fn ecb_pkcs7_decrypts_in_one_update() {
        round_trip(crypto::des::Mode::EcbPkcs7Padding);
    }
}
