//
// Copyright (C) 2022 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Software-only trait implementations using fake keys.

use kmr_common::{
    crypto,
    crypto::{Hkdf, Rng},
    Error,
};
use kmr_crypto_ommega::{hmac::OmmegaHmac, rng::OmmegaRng};
use kmr_ta::device::RetrieveKeyMaterial;
use rand::{rngs::StdRng, Rng as RandRng, SeedableRng};

/// Root key retrieval using hard-coded fake keys.
pub struct Keys {
    root_kek_seed: [u8; 32],
    kak_seed: [u8; 32],
}

impl Keys {
    /// Creates a new `Keys` instance with the given seeds.
    pub fn new(root_kek_seed: [u8; 32], kak_seed: [u8; 32]) -> Self {
        // 留一个指纹：两个进程（独立 HAL / 进程内）用的种子不一样时，root_kek 就不一样，
        // 旧 blob 一律 INVALID_KEY_BLOB(-33)。排障时靠它一眼看出是不是这个原因。
        let fp = format!(
            "root_kek={:02x}{:02x}{:02x}{:02x} kak={:02x}{:02x}{:02x}{:02x}",
            root_kek_seed[0],
            root_kek_seed[1],
            root_kek_seed[2],
            root_kek_seed[3],
            kak_seed[0],
            kak_seed[1],
            kak_seed[2],
            kak_seed[3]
        );
        let _ = SEED_FP.set(fp.clone());
        log::info!("crypto seed fingerprint: {fp} (pid {})", std::process::id());
        Self {
            root_kek_seed,
            kak_seed,
        }
    }
}

/// 种子指纹（前 4 字节 hex），给报错路径引用。
pub static SEED_FP: std::sync::OnceLock<String> = std::sync::OnceLock::new();

impl RetrieveKeyMaterial for Keys {
    fn root_kek(&self, _context: &[u8]) -> Result<crypto::OpaqueOr<crypto::hmac::Key>, Error> {
        // Matches `MASTER_KEY` in system/keymaster/key_blob_utils/software_keyblobs.cpp
        let mut rng = StdRng::from_seed(self.root_kek_seed);
        let mut key = [0; 16];
        RandRng::fill_bytes(&mut rng, &mut key);

        Ok(crypto::hmac::Key::new(key.to_vec()).into())
    }
    fn kak(&self) -> Result<crypto::OpaqueOr<crypto::aes::Key>, Error> {
        // Matches `kFakeKeyAgreementKey` in
        // system/keymaster/km_openssl/soft_keymaster_enforcement.cpp.
        let mut rng = StdRng::from_seed(self.kak_seed);
        let mut key = [0; 32];
        RandRng::fill_bytes(&mut rng, &mut key);

        Ok(crypto::aes::Key::Aes256(key).into())
    }
}

/// Implementation of key derivation using a random fake key.
pub struct Derive {
    hbk: Vec<u8>,
}

impl Default for Derive {
    fn default() -> Self {
        // Use random data as an emulation of a hardware-backed key.
        let mut hbk = vec![0; 32];
        let mut rng = OmmegaRng;
        rng.fill_bytes(&mut hbk);
        Self { hbk }
    }
}

impl crate::keymint::rpc::DeriveBytes for Derive {
    fn derive_bytes(&self, context: &[u8], output_len: usize) -> Result<Vec<u8>, Error> {
        OmmegaHmac.hkdf(&[], &self.hbk, context, output_len)
    }
}

/// RPC artifact retrieval using software fake key.
pub type RpcArtifacts = crate::keymint::rpc::Artifacts<Derive>;
