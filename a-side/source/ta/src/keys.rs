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

//! TA functionality related to key generation/import/upgrade.

use crate::{cert, device, AttestationChainInfo};
use core::{borrow::Borrow, cmp::Ordering, convert::TryFrom};
use der::{Decode, Encode, Sequence};
use kmr_common::{
    crypto::{self, aes, rsa, KeyMaterial, OpaqueOr},
    der_err, get_bool_tag_value, get_opt_tag_value, get_tag_value, keyblob, km_err, tag,
    try_to_vec, vec_try_with_capacity, Error, ErrorKind, FallibleAllocExt,
};
use kmr_wire::{
    keymint::{
        AttestationKey, Digest, EcCurve, ErrorCode, HardwareAuthenticatorType, KeyCharacteristics,
        KeyCreationResult, KeyFormat, KeyOrigin, KeyParam, KeyPurpose, SecurityLevel,
        UNDEFINED_NOT_AFTER, UNDEFINED_NOT_BEFORE,
    },
    *,
};
use log::{error, warn};
use std::{collections::btree_map::Entry, string::String, vec::Vec};
use x509_cert::ext::pkix::KeyUsages;

/// Maximum size of an attestation challenge value.
const MAX_ATTESTATION_CHALLENGE_LEN: usize = 128;

/// Contents of wrapping key data
///
/// ```asn1
/// SecureKeyWrapper ::= SEQUENCE {
///     version                   INTEGER, # Value 0
///     encryptedTransportKey     OCTET_STRING,
///     initializationVector      OCTET_STRING,
///     keyDescription            KeyDescription, # See below
///     encryptedKey              OCTET_STRING,
///     tag                       OCTET_STRING,
/// }
/// ```
#[derive(Debug, Clone, Sequence)]
pub struct SecureKeyWrapper<'a> {
    /// Version of this structure.
    pub version: i32,
    /// Encrypted transport key.
    #[asn1(type = "OCTET STRING")]
    pub encrypted_transport_key: &'a [u8],
    /// IV to use for decryption.
    #[asn1(type = "OCTET STRING")]
    pub initialization_vector: &'a [u8],
    /// Key parameters and description.
    pub key_description: KeyDescription<'a>,
    /// Ciphertext of the imported key.
    #[asn1(type = "OCTET STRING")]
    pub encrypted_key: &'a [u8],
    /// Tag value.
    #[asn1(type = "OCTET STRING")]
    pub tag: &'a [u8],
}

const SECURE_KEY_WRAPPER_VERSION: i32 = 0;

/// Contents of key description.
///
/// ```asn1
/// KeyDescription ::= SEQUENCE {
///     keyFormat    INTEGER, # Values from KeyFormat enum
///     keyParams    AuthorizationList, # See cert.rs
/// }
/// ```
#[derive(Debug, Clone, Sequence)]
pub struct KeyDescription<'a> {
    /// Format of imported key.
    pub key_format: i32,
    /// Key parameters.
    pub key_params: cert::AuthorizationList<'a>,
}

/// Indication of whether key import has a secure wrapper.
#[derive(Debug, Clone, Copy)]
pub(crate) enum KeyImport {
    Wrapped,
    NonWrapped,
}

/// Combined information needed for signing a fresh public key.
#[derive(Clone)]
pub(crate) struct SigningInfo<'a> {
    pub attestation_info: Option<(&'a [u8], &'a [u8])>, // (challenge, app_id)
    pub signing_key: KeyMaterial,
    /// ASN.1 DER encoding of subject field from first cert.
    pub issuer_subject: Vec<u8>,
    /// Cert chain starting with public key for `signing_key`.
    pub chain: Vec<keymint::Certificate>,
}

impl crate::KeyMintTa {
    pub fn clear_attestation_cache(&self) {
        self.attestation_chain_info.borrow_mut().clear();
    }

    fn build_attestation_chain_info(
        chain: &[keymint::Certificate],
        identity_digest: [u8; 32],
    ) -> Result<AttestationChainInfo, Error> {
        let issuer = cert::extract_subject(
            chain
                .first()
                .ok_or_else(|| km_err!(KeymintNotConfigured, "empty attestation chain"))?,
        )?;
        Ok(AttestationChainInfo {
            chain: chain.to_vec(),
            issuer,
            identity_digest,
        })
    }

    /// Retrieve the signing information.
    pub(crate) fn get_signing_info(
        &self,
        key_type: device::SigningKeyType,
    ) -> Result<SigningInfo<'_>, Error> {
        let sign_info = self.dev.sign_info.as_ref().ok_or_else(|| {
            km_err!(
                AttestationKeysNotProvisioned,
                "batch attestation keys not available"
            )
        })?;
        let snapshot = sign_info.signing_info(key_type)?;
        // The certificate chain is cached, but keybox rotation explicitly clears the cache and
        // the cache is also invalidated if the keybox identity digest changes.
        let mut attestation_chain_info = self.attestation_chain_info.borrow_mut();
        let chain_info = match attestation_chain_info.entry(key_type) {
            Entry::Occupied(mut entry) => {
                if entry.get().identity_digest != snapshot.identity_digest {
                    let refreshed = Self::build_attestation_chain_info(
                        &snapshot.cert_chain,
                        snapshot.identity_digest,
                    )?;
                    entry.insert(refreshed);
                }
                entry.into_mut()
            }
            Entry::Vacant(entry) => entry.insert(Self::build_attestation_chain_info(
                &snapshot.cert_chain,
                snapshot.identity_digest,
            )?),
        };

        log::info!(
            "using attestation key with subject {:?}",
            String::from_utf8_lossy(&chain_info.issuer)
        );

        Ok(SigningInfo {
            attestation_info: None,
            signing_key: snapshot.signing_key,
            issuer_subject: chain_info.issuer.clone(),
            chain: chain_info.chain.clone(),
        })
    }

    /// Generate an X.509 leaf certificate.
    pub(crate) fn generate_cert(
        &self,
        info: Option<SigningInfo>,
        spki_der: &[u8],
        params: &[KeyParam],
        chars: &[KeyCharacteristics],
    ) -> Result<keymint::Certificate, Error> {
        // Build and encode key usage extension value
        let key_usage_ext_bits = cert::key_usage_extension_bits(params);
        let key_usage_ext_val = cert::x509_der_encode(&key_usage_ext_bits).map_err(|e| {
            cert::x509_der_error(
                e,
                format_args!("failed to encode KeyUsage {:?}", key_usage_ext_bits),
            )
        })?;

        // Build and encode basic constraints extension value, based on the key usage extension
        // value
        let basic_constraints_ext_val = if (key_usage_ext_bits.0 & KeyUsages::KeyCertSign)
            .bits()
            .count_ones()
            != 0
        {
            let basic_constraints = cert::basic_constraints_ext_value(true);
            Some(cert::x509_der_encode(&basic_constraints).map_err(|e| {
                cert::x509_der_error(
                    e,
                    format_args!("failed to encode basic constraints {:?}", basic_constraints),
                )
            })?)
        } else {
            None
        };

        // Build and encode attestation extension if present
        let id_info = needs_attestation_ids(params)
            .then(|| self.get_attestation_ids())
            .flatten();
        let attest_ext_val = if let Some(SigningInfo {
            attestation_info: Some((challenge, app_id)),
            ..
        }) = &info
        {
            let unique_id = self.calculate_unique_id(app_id, params)?;
            let hashed_boot = self.boot_info_hashed_key()?;
            // When an attestation key signs this leaf and that attestation key
            // was minted remotely (B-side TEE), the leaf MUST carry the SAME
            // root-of-trust as the attestation key — not the A-side device's.
            // Otherwise sign_key and attest_key disagree on verified_boot_key /
            // hash within one chain and detectors flag the attestation key as
            // tampered.
            let remote_boot: Option<keymint::BootInfo>;
            let boot_info_ref: &keymint::BootInfo = match &info {
                Some(SigningInfo {
                    signing_key: KeyMaterial::Remote(remote),
                    ..
                }) if remote.root_of_trust.is_some() => {
                    let rot = remote.root_of_trust.as_ref().unwrap();
                    remote_boot = Some(keymint::BootInfo {
                        verified_boot_key: rot.verified_boot_key.clone(),
                        device_boot_locked: rot.device_locked,
                        verified_boot_state: keymint::VerifiedBootState::try_from(
                            rot.verified_boot_state,
                        )
                        .unwrap_or(keymint::VerifiedBootState::Unverified),
                        verified_boot_hash: rot.verified_boot_hash.clone(),
                        boot_patchlevel: hashed_boot.boot_patchlevel,
                    });
                    remote_boot.as_ref().unwrap()
                }
                _ => &hashed_boot,
            };
            // The attestation version must follow the attestation key's when a
            // remote (B-side TEE) attestation key signs this leaf: relay-minted
            // attest keys report their own KeyMint version (e.g. 300), while
            // the A-side local HAL version (e.g. 400 on Android 16) differs.
            // A chain whose sign_key and attest_key disagree on
            // attestationVersion/keymasterVersion is flagged as a tampered
            // attestation key. Fall back to the local AIDL version only when
            // no remote version was captured.
            let ext_version = match &info {
                Some(SigningInfo {
                    signing_key: KeyMaterial::Remote(remote),
                    ..
                }) if remote
                    .root_of_trust
                    .as_ref()
                    .is_some_and(|r| r.attestation_version > 0) =>
                {
                    remote.root_of_trust.as_ref().unwrap().attestation_version
                }
                _ => self.aidl_version as i32,
            };
            let attest_ext = cert::attestation_extension(
                ext_version,
                challenge,
                app_id,
                self.hw_info.security_level,
                id_info.as_ref().map(|v| v.borrow()),
                params,
                chars,
                &unique_id,
                boot_info_ref,
                &self.additional_attestation_info,
            )?;
            Some(
                cert::asn1_der_encode(&attest_ext)
                    .map_err(|e| der_err!(e, "failed to encode attestation extension"))?,
            )
        } else {
            None
        };

        let tbs_cert = cert::tbs_certificate(
            &info,
            spki_der,
            &key_usage_ext_val,
            basic_constraints_ext_val.as_deref(),
            attest_ext_val.as_deref(),
            tag::characteristics_at(chars, self.hw_info.security_level)?,
            params,
        )?;
        let tbs_data = cert::x509_der_encode(&tbs_cert)
            .map_err(|e| cert::x509_der_error(e, format_args!("failed to encode tbsCert")))?;
        // If key does not have ATTEST_KEY or SIGN purpose, the certificate has empty signature
        let sig_data = match info.as_ref() {
            Some(info) => self.sign_cert_data(info.signing_key.clone(), tbs_data.as_slice())?,
            None => Vec::new(),
        };

        let cert = cert::certificate(tbs_cert, &sig_data)?;
        let cert_data = cert::x509_der_encode(&cert)
            .map_err(|e| cert::x509_der_error(e, format_args!("failed to encode certificate")))?;
        Ok(keymint::Certificate {
            encoded_certificate: cert_data,
        })
    }

    /// Perform a complete signing operation using default modes.
    fn sign_cert_data(&self, signing_key: KeyMaterial, tbs_data: &[u8]) -> Result<Vec<u8>, Error> {
        match signing_key {
            KeyMaterial::Rsa(key) => {
                let mut op = self
                    .imp
                    .rsa
                    .begin_sign(key, rsa::SignMode::Pkcs1_1_5Padding(Digest::Sha256))?;
                op.update(tbs_data)?;
                op.finish()
            }
            KeyMaterial::Ec(curve, _, key) => {
                let digest = if curve == EcCurve::Curve25519 {
                    // Ed25519 includes an internal digest and so does not use an external digest.
                    Digest::None
                } else {
                    Digest::Sha256
                };
                let mut op = self.imp.ec.begin_sign(key, digest)?;
                op.update(tbs_data)?;
                op.finish()
            }
            KeyMaterial::MlDsa(_variant, key) => {
                let mut op = self.imp.mldsa.begin_sign(key)?;
                op.update(tbs_data)?;
                op.finish()
            }
            // ATTEST_KEY 是给原生证书生成用的，不是给 begin(SIGN) 用的。真机实测：
            // 用证明密钥 begin(SIGN) 恒被拒（-2/-3/-12），所以这里不再把 TBS 转发给
            // 远程 SIGN —— 那条路以前能跑通，只是因为 B 把 ATTEST_KEY 换成了 SIGN。
            // 旧版遗留的远程 blob 若描述的是普通签名密钥，也不能用它发证书。
            KeyMaterial::Remote(_) => Err(km_err!(
                IncompatiblePurpose,
                "remote certificate issuance is not supported by the SIGN transport"
            )),
            _ => Err(km_err!(
                IncompatibleAlgorithm,
                "unexpected cert signing key type"
            )),
        }
    }

    /// Calculate the `UNIQUE_ID` value for the parameters, if needed.
    fn calculate_unique_id(&self, app_id: &[u8], params: &[KeyParam]) -> Result<Vec<u8>, Error> {
        if !get_bool_tag_value!(params, IncludeUniqueId)? {
            return Ok(Vec::new());
        }
        let creation_datetime =
            get_tag_value!(params, CreationDatetime, ErrorCode::InvalidArgument)?;
        let rounded_datetime = creation_datetime.ms_since_epoch / 2_592_000_000i64;
        let datetime_data = rounded_datetime.to_ne_bytes();

        let mut combined_input = vec_try_with_capacity!(datetime_data.len() + app_id.len() + 1)?;
        combined_input.extend_from_slice(&datetime_data[..]);
        combined_input.extend_from_slice(app_id);
        combined_input.push(u8::from(get_bool_tag_value!(params, ResetSinceIdRotation)?));

        let hbk = self.dev.keys.unique_id_hbk(&*self.imp.ckdf)?;

        let mut hmac_op = self.imp.hmac.begin(hbk.into(), Digest::Sha256)?;
        hmac_op.update(&combined_input)?;
        let tag = hmac_op.finish()?;
        try_to_vec(&tag[..16])
    }

    pub(crate) fn generate_key(
        &mut self,
        params: &[KeyParam],
        attestation_key: Option<AttestationKey>,
    ) -> Result<KeyCreationResult, Error> {
        // Remote mode: if a remote backend is enabled and attestation is
        // requested, mint the key on the B-side real TEE instead of locally.
        //
        // 调用方自带证明密钥（App AttestKey）时也走远程：B 端真 TEE 用那把已有的
        // ATTEST_KEY 原生签发子证书（`generateKey(.., AttestationKey)`），而不是本端
        // 拿远程 SIGN 代签。真机实测（2026-10-23）：用证明密钥走 `begin(SIGN)` 恒被拒
        // （-2/-3/-12）—— 那条路以前能跑通，只是因为 B 把 ATTEST_KEY 偷偷换成了 SIGN。
        //
        // STRONGBOX requests follow the SAME path as TEE: when a remote
        // backend is enabled they are forwarded to the relay, which tags the
        // attestation extension with the forwarded `attestation_security_level`
        // (= 2); otherwise they fall back to the local software keybox. The
        // requesting security level only gates which signing key is chosen and
        // how the attestation extension is tagged. Driving the device's real
        // `/strongbox` HAL here was tried but failed on devices where that HAL
        // is declared but not servable from the keystore context (Unknown error
        // -1000), so it is not wired in.
        // 调用方自带的证明密钥（App AttestKey 委派）：只有当它在本端是 `Remote`
        // （私钥在 B 端真 TEE）时，才改由 B 的原生 KeyMint 用它签发子证书；
        // 如果那是一把本地签发密钥（私钥在本机），仍旧走本地路径。
        let wants_attest_challenge = get_opt_tag_value!(params, AttestationChallenge)?.is_some();
        let remote_issuer = match attestation_key.as_ref() {
            Some(info)
                if wants_attest_challenge
                    && self.dev.remote.as_ref().is_some_and(|r| r.enabled()) =>
            {
                let (blob, _) =
                    self.keyblob_parse_decrypt(&info.key_blob, &info.attest_key_params)?;
                blob.suitable_for(KeyPurpose::AttestKey, self.hw_info.security_level)?;
                if info.issuer_subject_name.is_empty() {
                    return Err(km_err!(InvalidArgument, "empty subject name"));
                }
                match blob.key_material {
                    KeyMaterial::Remote(remote) => Some(device::RemoteAttestationKey {
                        alias: remote.alias,
                        public_key: remote.public_key,
                        issuer_subject_name: info.issuer_subject_name.clone(),
                    }),
                    _ => None,
                }
            }
            _ => None,
        };
        // 认证绑定的 key 仍旧本地生成：B 端拿不到 A 的 auth token，远端铸出来也签不了
        // （begin(SIGN) 必然 -26），而丢掉 504/505 又会让叶子与请求对不上。
        // 认证密钥（PURPOSE_ATTEST_KEY）则改走远端：B 用调用方那把 ATTEST_KEY
        // 原生签发子证书，不再需要本机拿它的私钥签 TBS（真机实测：独占 ATTEST_KEY
        // 可铸，用它 begin(SIGN) 恒被拒）。
        let remote_attest = wants_attest_challenge
            && !requests_user_auth(params)
            && !agrees_only(params)
            && self.dev.remote.as_ref().is_some_and(|r| r.enabled())
            && (attestation_key.is_none() || remote_issuer.is_some());
        if remote_attest {
            // `Ok(None)` from the remote backend means it was unavailable; fall
            // back to the local software keybox when `fallback_local` allows.
            if let Some(result) = self.generate_key_remote(params, remote_issuer.as_ref())? {
                return Ok(result);
            }
            // 显式委派不能回退：本地软件 keybox 签出来的子证书与调用方那把证明
            // 密钥没有任何关系，回落等于交出一张无关的链。
            if remote_issuer.is_some()
                || !self.dev.remote.as_ref().is_some_and(|r| r.fallback_local())
            {
                return Err(km_err!(
                    UnknownError,
                    "remote attest unavailable and fallback disabled"
                ));
            }
        }
        let (key_material, chars) = self.generate_key_material(params)?;
        self.finish_keyblob_creation(
            params,
            attestation_key,
            chars,
            key_material,
            keyblob::SlotPurpose::KeyGeneration,
        )
    }

    /// Remote-mode key generation: the B-side TEE mints the attestation chain.
    ///
    /// Returns `Ok(None)` when the remote backend is unavailable (so the caller
    /// may fall back to the local software keybox), and a hard `Err` only for
    /// genuine protocol failures that must not be masked.
    fn generate_key_remote(
        &mut self,
        params: &[KeyParam],
        attestation_key: Option<&device::RemoteAttestationKey>,
    ) -> Result<Option<KeyCreationResult>, Error> {
        let challenge = get_opt_tag_value!(params, AttestationChallenge)?
            .ok_or_else(|| km_err!(AttestationChallengeMissing, "remote attest needs challenge"))?;
        // Enforce the same challenge-length bound as the local path so the
        // A-side software keymint rejects oversized challenges up front rather
        // than forwarding them and relying on the relay/B-side to refuse.
        if challenge.len() > MAX_ATTESTATION_CHALLENGE_LEN {
            return Err(km_err!(
                InvalidInputLength,
                "attestation challenge too large: {} bytes",
                challenge.len()
            ));
        }
        let app_id = get_opt_tag_value!(params, AttestationApplicationId)?
            .ok_or_else(|| km_err!(AttestationApplicationIdMissing, "remote attest needs appid"))?;
        let serial = get_opt_tag_value!(params, CertificateSerial)?;
        // Allocate once per logical key creation, even for identical params.
        // Remote transport retries reuse this alias in the same request body.
        let alias = new_remote_alias(&mut *self.imp.rng);
        // Mirror client-a's `effectiveCertificateSerial`: forward the caller's
        // CERTIFICATE_SERIAL if present, otherwise derive a deterministic
        // positive integer from (alias, challenge) so the B-side mints a leaf
        // with a readable serial instead of a random 16-byte value.
        let derived_serial = derive_remote_serial(&alias, challenge);
        let effective_serial = match serial {
            Some(s) if !s.is_empty() => Some(s),
            _ => derived_serial.as_ref(),
        };
        let mut remote_params = extract_remote_attest_params(params);
        // 显式委派：告诉 B「用这把已有的证明密钥签发子证书」。
        remote_params.attestation_key = attestation_key.cloned();
        // Tag the relay-minted chain with the requesting security level so a
        // STRONGBOX request is not misreported as TEE by the relay's default.
        remote_params.security_level = Some(self.hw_info.security_level as i32);
        // 设备 ID 证明：调用方要了就随请求带上，值取本机那套（见
        // `remote_attestation_ids`）。不带的话中继铸出来的叶子里没有 710..717，
        // 检查方直接报「Device Properties 返回异常」。
        if needs_attestation_ids(params) {
            let ids = self
                .get_attestation_ids()
                .ok_or_else(|| km_err!(CannotAttestIds, "no attestation IDs provisioned"))?;
            remote_params.attestation_ids = remote_attestation_ids(params, &ids)?;
        }
        // MODULE_HASH（tag 724）：本机软件 keybox 路径由 HAL 在
        // `SetAdditionalAttestationInfo` 里塞进来（见 `keymint_device.rs` 的
        // `KeyParam::ModuleHash`），远程路径要原样转发同一份摘要，否则中继铸出的
        // 叶子缺 724，而 `getSupplementaryAttestationInfo(MODULE_HASH)` 仍返回本机
        // 那 1213 字节 bundle —— 校验方会报 MODULE_HASH 缺失。
        remote_params.module_hash =
            self.additional_attestation_info
                .iter()
                .find_map(|param| match param {
                    KeyParam::ModuleHash(hash) if !hash.is_empty() => Some(hash.clone()),
                    _ => None,
                });
        log::info!(
            "remote attest: forwarding module_hash={:?} (additional_attestation_info={} entries)",
            remote_params.module_hash.as_deref().map(<[u8]>::len),
            self.additional_attestation_info.len()
        );

        let remote = self
            .dev
            .remote
            .as_ref()
            .ok_or_else(|| km_err!(UnknownError, "remote backend not configured"))?;
        let t_remote = std::time::Instant::now();
        let Some(chain) = remote.attest(
            challenge,
            app_id,
            &alias,
            effective_serial.map(|v| v.as_slice()),
            &remote_params,
        )?
        else {
            return Ok(None);
        };
        log::info!(
            "remote attest returned {} certs in {:?}",
            chain.len(),
            t_remote.elapsed()
        );
        if chain.is_empty() {
            return Ok(None);
        }

        // 显式委派：B 必须真的用了调用方指定的那把证明密钥。旧版 B 会忽略这个
        // 参数、改用本机批量 key 签一张无关证书，那种链必须拒掉（不能静默接受）。
        if let Some(issuer) = attestation_key {
            crate::cert::validate_remote_delegation(&chain, issuer)?;
        }
        // 请求了 ATTEST_KEY 就核对叶子是不是真机的硬件证明密钥（不发 SIGN 冒充）。
        if params
            .iter()
            .any(|p| matches!(p, KeyParam::Purpose(KeyPurpose::AttestKey)))
        {
            crate::cert::validate_native_attestation_issuer(&chain[0])?;
        }

        // Derive the remote key's public key (SPKI) from the leaf certificate.
        let leaf_der = &chain[0];
        let leaf = x509_cert::Certificate::from_der(leaf_der)
            .map_err(|e| km_err!(UnknownError, "parse remote leaf cert: {e:?}"))?;
        let public_key = leaf
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|e| km_err!(UnknownError, "encode remote SPKI: {e:?}"))?;

        // Build characteristics (algorithm/key size from params), mirroring the
        // local path but with a Remote key material.
        let (mut chars, keygen_info) = tag::extract_key_gen_characteristics(
            self.secure_storage_available(),
            params,
            self.hw_info.security_level,
        )?;
        self.add_keymint_tags(&mut chars, KeyOrigin::Generated)?;
        let _ = keygen_info;
        let root_of_trust = crate::cert::parse_remote_root_of_trust(leaf_der)?;
        // 把 B 真机自己声明的设备身份落盘：root 侧的 `daemon` 会拿去做
        // resetprop 对齐。链是真机出的，本机属性就必须说同一台机器，
        // 否则检测器拿两边一对就报 device_properties / VBMeta 摘要不一致。
        persist_remote_identity(leaf_der);
        let remote_key = KeyMaterial::Remote(crypto::RemoteRef {
            alias,
            public_key,
            root_of_trust,
        });

        let mut certificate_chain = Vec::new();
        // 未指定签发密钥时原样返回 B 的完整链；显式委派时只返回子证书 ——
        // 调用方本来就持有自己的签发链（`setAttestKeyAlias`），它自己拼；AIDL 对
        // `generateKey(.., AttestationKey)` 的要求也是只回这一张。
        let returned_chain = if attestation_key.is_some() {
            &chain[..1]
        } else {
            &chain[..]
        };
        for der in returned_chain.iter() {
            certificate_chain.try_push(keymint::Certificate {
                encoded_certificate: der.clone(),
            })?;
        }

        // Build the keyblob (encrypted, containing the Remote reference).
        let keyblob = keyblob::PlaintextKeyBlob {
            characteristics: chars
                .iter()
                .filter(|c| c.security_level != SecurityLevel::Keystore)
                .cloned()
                .collect(),
            key_material: remote_key,
        };
        let t_encrypt = std::time::Instant::now();
        let kek_context = self.dev.keys.kek_context()?;
        let root_kek = self.root_kek(&kek_context)?;
        let hidden = tag::hidden(params, self.root_of_trust()?)?;
        let encrypted_keyblob = keyblob::encrypt(
            self.hw_info.security_level,
            match &mut self.dev.sdd_mgr {
                None => None,
                Some(mr) => Some(&mut **mr),
            },
            &*self.imp.aes,
            &*self.imp.hkdf,
            &mut *self.imp.rng,
            &root_kek,
            &kek_context,
            keyblob,
            hidden,
            keyblob::SlotPurpose::KeyGeneration,
        )?;
        let serialized_keyblob = encrypted_keyblob.into_vec()?;
        log::info!(
            "remote keyblob built ({}B) in {:?}, total remote path {:?}",
            serialized_keyblob.len(),
            t_encrypt.elapsed(),
            t_remote.elapsed()
        );

        Ok(Some(KeyCreationResult {
            key_blob: serialized_keyblob,
            key_characteristics: chars,
            certificate_chain,
        }))
    }

    pub(crate) fn generate_key_material(
        &mut self,
        params: &[KeyParam],
    ) -> Result<(KeyMaterial, Vec<KeyCharacteristics>), Error> {
        let (mut chars, keygen_info) = tag::extract_key_gen_characteristics(
            self.secure_storage_available(),
            params,
            self.hw_info.security_level,
        )?;
        self.add_keymint_tags(&mut chars, KeyOrigin::Generated)?;
        let key_material = match keygen_info {
            crypto::KeyGenInfo::Aes(variant) => {
                self.imp
                    .aes
                    .generate_key(&mut *self.imp.rng, variant, params)?
            }
            crypto::KeyGenInfo::TripleDes => {
                self.imp.des.generate_key(&mut *self.imp.rng, params)?
            }
            crypto::KeyGenInfo::Hmac(key_size) => {
                self.imp
                    .hmac
                    .generate_key(&mut *self.imp.rng, key_size, params)?
            }
            crypto::KeyGenInfo::Rsa(key_size, pub_exponent) => {
                self.imp
                    .rsa
                    .generate_key(&mut *self.imp.rng, key_size, pub_exponent, params)?
            }
            crypto::KeyGenInfo::NistEc(curve) => {
                self.imp
                    .ec
                    .generate_nist_key(&mut *self.imp.rng, curve, params)?
            }
            crypto::KeyGenInfo::Ed25519 => self
                .imp
                .ec
                .generate_ed25519_key(&mut *self.imp.rng, params)?,
            crypto::KeyGenInfo::X25519 => self
                .imp
                .ec
                .generate_x25519_key(&mut *self.imp.rng, params)?,
            crypto::KeyGenInfo::MlDsa(variant) => {
                self.imp
                    .mldsa
                    .generate_key(&mut *self.imp.rng, variant, params)?
            }
        };
        Ok((key_material, chars))
    }

    pub(crate) fn import_key(
        &mut self,
        params: &[KeyParam],
        key_format: KeyFormat,
        key_data: &[u8],
        attestation_key: Option<AttestationKey>,
        import_type: KeyImport,
    ) -> Result<KeyCreationResult, Error> {
        if !self.in_early_boot && get_bool_tag_value!(params, EarlyBootOnly)? {
            return Err(km_err!(
                EarlyBootEnded,
                "attempt to use EARLY_BOOT key after early boot"
            ));
        }

        let (mut chars, key_material) = tag::extract_key_import_characteristics(
            &self.imp,
            self.secure_storage_available(),
            params,
            self.hw_info.security_level,
            key_format,
            key_data,
        )?;
        match import_type {
            KeyImport::NonWrapped => {
                self.add_keymint_tags(&mut chars, KeyOrigin::Imported)?;
            }
            KeyImport::Wrapped => {
                self.add_keymint_tags(&mut chars, KeyOrigin::SecurelyImported)?;
            }
        }

        self.finish_keyblob_creation(
            params,
            attestation_key,
            chars,
            key_material,
            keyblob::SlotPurpose::KeyImport,
        )
    }

    /// Perform common processing for keyblob creation (for both generation and import).
    pub fn finish_keyblob_creation(
        &mut self,
        params: &[KeyParam],
        attestation_key: Option<AttestationKey>,
        chars: Vec<KeyCharacteristics>,
        key_material: KeyMaterial,
        purpose: keyblob::SlotPurpose,
    ) -> Result<KeyCreationResult, Error> {
        let keyblob = keyblob::PlaintextKeyBlob {
            // Don't include any `SecurityLevel::Keystore` characteristics in the set that is bound
            // to the key.
            characteristics: chars
                .iter()
                .filter(|c| c.security_level != SecurityLevel::Keystore)
                .cloned()
                .collect(),
            key_material: key_material.clone(),
        };
        let attest_keyblob;
        let mut certificate_chain = Vec::new();
        if let Some(spki) = keyblob.key_material.subject_public_key_info(
            &mut Vec::<u8>::new(),
            &*self.imp.ec,
            &*self.imp.rsa,
            &*self.imp.mldsa,
        )? {
            // Asymmetric keys return the public key inside an X.509 certificate.
            // Need to determine:
            // - a key to sign the cert with (may be absent), together with any associated
            //   cert chain to append
            // - whether to include an attestation extension
            let attest_challenge = get_opt_tag_value!(params, AttestationChallenge)?;

            let signing_info = if let Some(attest_challenge) = attest_challenge {
                // Attestation requested.
                if attest_challenge.len() > MAX_ATTESTATION_CHALLENGE_LEN {
                    return Err(km_err!(
                        InvalidInputLength,
                        "attestation challenge too large: {} bytes",
                        attest_challenge.len()
                    ));
                }
                let attest_app_id = get_opt_tag_value!(params, AttestationApplicationId)?
                    .ok_or_else(|| {
                        km_err!(AttestationApplicationIdMissing, "attestation requested")
                    })?;
                let attestation_info: Option<(&[u8], &[u8])> =
                    Some((attest_challenge, attest_app_id));

                if let Some(attest_keyinfo) = attestation_key.as_ref() {
                    // User-specified attestation key provided.
                    (attest_keyblob, _) = self.keyblob_parse_decrypt(
                        &attest_keyinfo.key_blob,
                        &attest_keyinfo.attest_key_params,
                    )?;
                    attest_keyblob
                        .suitable_for(KeyPurpose::AttestKey, self.hw_info.security_level)?;
                    if attest_keyinfo.issuer_subject_name.is_empty() {
                        return Err(km_err!(InvalidArgument, "empty subject name"));
                    }
                    Some(SigningInfo {
                        attestation_info,
                        signing_key: attest_keyblob.key_material,
                        issuer_subject: attest_keyinfo.issuer_subject_name.clone(),
                        chain: Vec::new(),
                    })
                } else {
                    // Need to use a device key for attestation. Look up the relevant device key and
                    // chain.
                    let which_key = match (
                        get_bool_tag_value!(params, DeviceUniqueAttestation)?,
                        self.is_strongbox(),
                    ) {
                        (false, _) => device::SigningKey::Batch,
                        (true, true) => device::SigningKey::DeviceUnique,
                        (true, false) => {
                            return Err(km_err!(
                                InvalidArgument,
                                "device unique attestation supported only by Strongbox TA"
                            ))
                        }
                    };
                    // Depending on what's going to be signed, allow the implementation to switch
                    // between EC and RSA signing keys if it so chooses.
                    let algo_hint = match &keyblob.key_material {
                        crypto::KeyMaterial::Rsa(_) => device::SigningAlgorithm::Rsa,
                        crypto::KeyMaterial::Ec(_, _, _) => device::SigningAlgorithm::Ec,
                        crypto::KeyMaterial::MlDsa(_, _) => device::SigningAlgorithm::Ec,
                        _ => return Err(km_err!(InvalidArgument, "unexpected key type!")),
                    };

                    let mut info = self.get_signing_info(device::SigningKeyType {
                        which: which_key,
                        algo_hint,
                    })?;
                    info.attestation_info = attestation_info;
                    Some(info)
                }
            } else {
                // No attestation challenge, so no attestation.
                if attestation_key.is_some() {
                    return Err(km_err!(
                        AttestationChallengeMissing,
                        "got attestation key but no challenge"
                    ));
                }

                // See if the generated key can self-sign.
                let is_signing_key = params.iter().any(|param| {
                    matches!(
                        param,
                        KeyParam::Purpose(KeyPurpose::Sign)
                            | KeyParam::Purpose(KeyPurpose::AttestKey)
                    )
                });
                if is_signing_key {
                    Some(SigningInfo {
                        attestation_info: None,
                        signing_key: key_material,
                        issuer_subject: try_to_vec(tag::get_cert_subject(params)?)?,
                        chain: Vec::new(),
                    })
                } else {
                    None
                }
            };

            // Build the X.509 leaf certificate.
            let spki_der = cert::asn1_der_encode(&spki)
                .map_err(|e| der_err!(e, "failed to encode SubjectPublicKeyInfo"))?;
            let leaf_cert = self.generate_cert(signing_info.clone(), &spki_der, params, &chars)?;
            certificate_chain.try_push(leaf_cert)?;

            // Append the rest of the chain.
            if let Some(info) = signing_info {
                for cert in info.chain {
                    certificate_chain.try_push(cert)?;
                }
            }
        }

        // Now build the keyblob.
        let kek_context = self.dev.keys.kek_context()?;
        let root_kek = self.root_kek(&kek_context)?;
        let hidden = tag::hidden(params, self.root_of_trust()?)?;
        let encrypted_keyblob = keyblob::encrypt(
            self.hw_info.security_level,
            match &mut self.dev.sdd_mgr {
                None => None,
                Some(mr) => Some(&mut **mr),
            },
            &*self.imp.aes,
            &*self.imp.hkdf,
            &mut *self.imp.rng,
            &root_kek,
            &kek_context,
            keyblob,
            hidden,
            purpose,
        )?;
        let serialized_keyblob = encrypted_keyblob.into_vec()?;

        Ok(KeyCreationResult {
            key_blob: serialized_keyblob,
            key_characteristics: chars,
            certificate_chain,
        })
    }

    pub(crate) fn import_wrapped_key(
        &mut self,
        wrapped_key_data: &[u8],
        wrapping_key_blob: &[u8],
        masking_key: &[u8],
        unwrapping_params: &[KeyParam],
        password_sid: i64,
        biometric_sid: i64,
    ) -> Result<KeyCreationResult, Error> {
        // Decrypt the wrapping key blob
        let (wrapping_key, _) = self.keyblob_parse_decrypt(wrapping_key_blob, unwrapping_params)?;
        let keyblob::PlaintextKeyBlob {
            characteristics,
            key_material,
        } = wrapping_key;

        // Decode the ASN.1 DER encoded `SecureKeyWrapper`.
        let mut secure_key_wrapper = SecureKeyWrapper::from_der(wrapped_key_data)
            .map_err(|e| der_err!(e, "failed to parse SecureKeyWrapper"))?;

        if secure_key_wrapper.version != SECURE_KEY_WRAPPER_VERSION {
            return Err(km_err!(
                InvalidArgument,
                "invalid version in Secure Key Wrapper."
            ));
        }

        // Decrypt the masked transport key, using an RSA key. (Only RSA wrapping keys are supported
        // by the spec, as RSA is the only algorithm supporting asymmetric decryption.)
        let masked_transport_key = match key_material {
            KeyMaterial::Rsa(key) => {
                // Check the requirements on the wrapping key characterisitcs
                let decrypt_mode = tag::check_rsa_wrapping_key_params(
                    tag::characteristics_at(&characteristics, self.hw_info.security_level)?,
                    unwrapping_params,
                )?;

                // Decrypt the masked and encrypted transport key
                let mut crypto_op = self.imp.rsa.begin_decrypt(key, decrypt_mode)?;
                crypto_op
                    .as_mut()
                    .update(secure_key_wrapper.encrypted_transport_key)?;
                crypto_op.finish()?
            }
            _ => {
                return Err(km_err!(
                    InvalidArgument,
                    "invalid key algorithm for transport key"
                ));
            }
        };

        if masked_transport_key.len() != masking_key.len() {
            return Err(km_err!(
                InvalidArgument,
                "masked transport key is {} bytes, but masking key is {} bytes",
                masked_transport_key.len(),
                masking_key.len()
            ));
        }

        let unmasked_transport_key: Vec<u8> = masked_transport_key
            .iter()
            .zip(masking_key)
            .map(|(x, y)| x ^ y)
            .collect();

        let aes_transport_key =
            aes::Key::Aes256(unmasked_transport_key.try_into().map_err(|_e| {
                km_err!(
                    InvalidArgument,
                    "transport key len {} not correct for AES-256 key",
                    masked_transport_key.len()
                )
            })?);

        // Validate the size of the IV and match the `aes::GcmMode` based on the tag size.
        let iv_len = secure_key_wrapper.initialization_vector.len();
        if iv_len != aes::GCM_NONCE_SIZE {
            return Err(km_err!(
                InvalidArgument,
                "IV length is of {} bytes, which should be of {} bytes",
                iv_len,
                aes::GCM_NONCE_SIZE
            ));
        }
        let tag_len = secure_key_wrapper.tag.len();
        let gcm_mode = match tag_len {
            12 => crypto::aes::GcmMode::GcmTag12 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            13 => crypto::aes::GcmMode::GcmTag13 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            14 => crypto::aes::GcmMode::GcmTag14 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            15 => crypto::aes::GcmMode::GcmTag15 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            16 => crypto::aes::GcmMode::GcmTag16 {
                nonce: secure_key_wrapper.initialization_vector.try_into()
                .unwrap(/* safe: len checked */),
            },
            v => {
                return Err(km_err!(
                    InvalidMacLength,
                    "want 12-16 byte tag for AES-GCM not {} bytes",
                    v
                ))
            }
        };

        // Decrypt the encrypted key to be imported, using the ASN.1 DER (re-)encoding of the key
        // description as the AAD.
        let mut op = self.imp.aes.begin_aead(
            OpaqueOr::Explicit(aes_transport_key),
            gcm_mode,
            crypto::SymmetricOperation::Decrypt,
        )?;
        op.update_aad(
            &cert::asn1_der_encode(&secure_key_wrapper.key_description)
                .map_err(|e| der_err!(e, "failed to re-encode SecureKeyWrapper"))?,
        )?;

        let mut imported_key_data = op.update(secure_key_wrapper.encrypted_key)?;
        imported_key_data.try_extend_from_slice(&op.update(secure_key_wrapper.tag)?)?;
        imported_key_data.try_extend_from_slice(&op.finish()?)?;

        // The `Cow::to_mut()` call will not clone, because `from_der()` invokes
        // `AuthorizationList::decode_value()` which creates the owned variant.
        let imported_key_params: &mut Vec<KeyParam> =
            secure_key_wrapper.key_description.key_params.auths.to_mut();
        if let Some(secure_id) = get_opt_tag_value!(&*imported_key_params, UserSecureId)? {
            let secure_id = *secure_id;
            // If both the Password and Fingerprint bits are set in UserSecureId, the password SID
            // should be used, because biometric auth tokens contain both password and fingerprint
            // SIDs, but password auth tokens only contain the password SID.
            if (secure_id & (HardwareAuthenticatorType::Password as u64)
                == (HardwareAuthenticatorType::Password as u64))
                && (secure_id & (HardwareAuthenticatorType::Fingerprint as u64)
                    == (HardwareAuthenticatorType::Fingerprint as u64))
            {
                imported_key_params
                    .retain(|key_param| !matches!(key_param, KeyParam::UserSecureId(_)));
                imported_key_params.try_push(KeyParam::UserSecureId(password_sid as u64))?;
            } else if secure_id & (HardwareAuthenticatorType::Password as u64)
                == (HardwareAuthenticatorType::Password as u64)
            {
                imported_key_params
                    .retain(|key_param| !matches!(key_param, KeyParam::UserSecureId(_)));
                imported_key_params.try_push(KeyParam::UserSecureId(password_sid as u64))?;
            } else if secure_id & (HardwareAuthenticatorType::Fingerprint as u64)
                == (HardwareAuthenticatorType::Fingerprint as u64)
            {
                imported_key_params
                    .retain(|key_param| !matches!(key_param, KeyParam::UserSecureId(_)));
                imported_key_params.try_push(KeyParam::UserSecureId(biometric_sid as u64))?;
            }
        };

        // There is no way for clients to pass CERTIFICATE_NOT_BEFORE and CERTIFICATE_NOT_AFTER.
        // importWrappedKey must use validity with no well-defined expiration date.
        imported_key_params.try_push(KeyParam::CertificateNotBefore(UNDEFINED_NOT_BEFORE))?;
        imported_key_params.try_push(KeyParam::CertificateNotAfter(UNDEFINED_NOT_AFTER))?;

        self.import_key(
            imported_key_params,
            KeyFormat::try_from(secure_key_wrapper.key_description.key_format).map_err(|_e| {
                km_err!(
                    UnsupportedKeyFormat,
                    "could not convert the provided keyformat {}",
                    secure_key_wrapper.key_description.key_format
                )
            })?,
            &imported_key_data,
            None,
            KeyImport::Wrapped,
        )
    }

    pub(crate) fn upgrade_key(
        &mut self,
        keyblob_to_upgrade: &[u8],
        upgrade_params: Vec<KeyParam>,
    ) -> Result<Vec<u8>, Error> {
        let (mut keyblob, mut modified) =
            match self.keyblob_parse_decrypt_backlevel(keyblob_to_upgrade, &upgrade_params) {
                Ok(result) => (result.keyblob, result.kek_context_is_outdated),
                Err(e) => match e.kind() {
                    ErrorKind::Hal(ErrorCode::KeyRequiresUpgrade, _) => {
                        // Because `keyblob_parse_decrypt_backlevel` explicitly allows back-level
                        // versioned keys, a `KeyRequiresUpgrade` error indicates that the keyblob
                        // looks to be in legacy format.  Try to convert it.
                        let legacy_handler = self.dev.legacy_key.as_mut().ok_or_else(|| {
                            km_err!(KeymintNotConfigured, "no legacy key handler")
                        })?;
                        (
                            legacy_handler.convert_legacy_key(
                                keyblob_to_upgrade,
                                &upgrade_params,
                                self.boot_info.as_ref().ok_or_else(|| {
                                    km_err!(HardwareNotYetAvailable, "no boot info")
                                })?,
                                self.hw_info.security_level,
                            )?,
                            // Force the emission of a new keyblob even if versions are the same.
                            true,
                        )
                    }
                    _ => return Err(e),
                },
            };

        fn upgrade(v: &mut u32, curr: u32, _name: &str) -> Result<bool, Error> {
            match (*v).cmp(&curr) {
                Ordering::Less => {
                    *v = curr;
                    Ok(true)
                }
                Ordering::Equal => Ok(false),
                Ordering::Greater => {
                    // We allow patchlevel downgrades.
                    // error!("refusing to downgrade {name} from {v} to {curr}");
                    // Err(km_err!(
                    //     InvalidArgument,
                    //     "keyblob with future {} {} (current {})",
                    //     name,
                    //     v,
                    //     curr
                    // ))
                    *v = curr;
                    Ok(true)
                }
            }
        }

        for chars in &mut keyblob.characteristics {
            if chars.security_level != self.hw_info.security_level {
                continue;
            }
            for param in &mut chars.authorizations {
                match param {
                    KeyParam::OsVersion(v) => {
                        if let Some(hal_info) = &self.hal_info {
                            if hal_info.os_version == 0 {
                                // Special case: upgrades to OS version zero are always allowed.
                                warn!("forcing upgrade to OS version 0");
                                modified |= *v != 0;
                                *v = 0;
                            } else {
                                modified |= upgrade(v, hal_info.os_version, "OS version")?;
                            }
                        } else {
                            error!("OS version not available, can't upgrade from {v}");
                        }
                    }
                    KeyParam::OsPatchlevel(v) => {
                        if let Some(hal_info) = &self.hal_info {
                            modified |= upgrade(v, hal_info.os_patchlevel, "OS patchlevel")?;
                        } else {
                            error!("OS patchlevel not available, can't upgrade from {v}");
                        }
                    }
                    KeyParam::VendorPatchlevel(v) => {
                        if let Some(hal_info) = &self.hal_info {
                            modified |=
                                upgrade(v, hal_info.vendor_patchlevel, "vendor patchlevel")?;
                        } else {
                            error!("vendor patchlevel not available, can't upgrade from {v}");
                        }
                    }
                    KeyParam::BootPatchlevel(v) => {
                        if let Some(boot_info) = &self.boot_info {
                            modified |= upgrade(v, boot_info.boot_patchlevel, "boot patchlevel")?;
                        } else {
                            error!("boot patchlevel not available, can't upgrade from {v}");
                        }
                    }
                    _ => {}
                }
            }
        }

        if !modified {
            // No upgrade needed, return empty data to indicate existing keyblob can still be used.
            return Ok(Vec::new());
        }

        // Now re-build the keyblob. Use a potentially fresh key encryption key and context, and
        // potentially a new secure deletion secret slot. (The old slot will be released when
        // Keystore performs the corresponding `deleteKey` operation on the old keyblob.)
        let kek_context = self.dev.keys.kek_context()?;
        let root_kek = self.root_kek(&kek_context)?;
        let hidden = tag::hidden(&upgrade_params, self.root_of_trust()?)?;
        let encrypted_keyblob = keyblob::encrypt(
            self.hw_info.security_level,
            match &mut self.dev.sdd_mgr {
                None => None,
                Some(mr) => Some(&mut **mr),
            },
            &*self.imp.aes,
            &*self.imp.hkdf,
            &mut *self.imp.rng,
            &root_kek,
            &kek_context,
            keyblob,
            hidden,
            keyblob::SlotPurpose::KeyUpgrade,
        )?;
        Ok(encrypted_keyblob.into_vec()?)
    }
}

fn needs_attestation_ids(params: &[KeyParam]) -> bool {
    params.iter().any(|param| {
        matches!(
            param,
            KeyParam::AttestationIdBrand(_)
                | KeyParam::AttestationIdDevice(_)
                | KeyParam::AttestationIdProduct(_)
                | KeyParam::AttestationIdSerial(_)
                | KeyParam::AttestationIdImei(_)
                | KeyParam::AttestationIdSecondImei(_)
                | KeyParam::AttestationIdMeid(_)
                | KeyParam::AttestationIdManufacturer(_)
                | KeyParam::AttestationIdModel(_)
        )
    })
}

/// Allocate an independent 128-bit random identity for a remote key.
fn new_remote_alias(rng: &mut dyn crypto::Rng) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    format!("ommega-remote-{:032x}", u128::from_be_bytes(bytes))
}

/// Derives a deterministic positive certificate serial from `(alias, challenge)`,
/// mirroring client-a's `effectiveCertificateSerial`.  The first 8 bytes of
/// SHA-256(alias || base64(challenge)) are treated as a positive big-endian
/// integer.  This gives the B-side a readable decimal serial instead of a random
/// 16-byte TEE value (which renders as garbage in attestation viewers).
fn derive_remote_serial(alias: &str, challenge: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;
    if alias.is_empty() {
        return None;
    }
    let mut seed = alias.as_bytes().to_vec();
    seed.extend_from_slice(
        base64::engine::general_purpose::STANDARD
            .encode(challenge)
            .as_bytes(),
    );
    let digest = self_hash_sha256(&seed);
    if digest.is_empty() {
        return None;
    }
    // Take the first 8 bytes as a positive integer.
    let mut n = 0u64;
    for &b in digest.iter().take(8) {
        n = (n << 8) | u64::from(b);
    }
    if n == 0 {
        Some(vec![1])
    } else {
        let bytes = n.to_be_bytes();
        // Trim leading zeros, keep at least one byte.
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        Some(bytes[start..].to_vec())
    }
}

/// SHA-256 digest via the `sha2` crate.
fn self_hash_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// 把远端叶子里的设备身份写到 state 文件，内容没变就不重写（避免触发重启循环）。
///
/// TA 跑在 keystore2 进程里（uid 1017），只能写 keystore 状态目录；
/// 真正 resetprop + 重启 zygote 的是 root 侧的 `template/daemon`。
fn persist_remote_identity(leaf_der: &[u8]) {
    const PATH: &str = "/data/misc/keystore/ommega/remote_identity";
    let Some(identity) = crate::cert::parse_remote_device_identity(leaf_der) else {
        return;
    };
    let mut out = String::new();
    for (key, value) in [
        ("brand", identity.brand),
        ("device", identity.device),
        ("product", identity.product),
        ("manufacturer", identity.manufacturer),
        ("model", identity.model),
        ("serial", identity.serial),
    ] {
        let Some(value) = value else { continue };
        let Ok(text) = core::str::from_utf8(&value) else {
            continue;
        };
        if text.is_empty() || text.contains('\n') {
            continue;
        }
        out.push_str(key);
        out.push('=');
        out.push_str(text);
        out.push('\n');
    }
    if let Some(hash) = identity.verified_boot_hash {
        if !hash.is_empty() {
            out.push_str("vbmeta_digest=");
            for byte in hash {
                out.push_str(&format!("{byte:02x}"));
            }
            out.push('\n');
        }
    }
    // boot 锁定状态：走远程时证书里的 RootOfTrust 是 B 端真机的（多半 unlocked/orange），
    // 本机那套 green/locked 跟它一对就不一致（A09 命中），所以把 B 的说法也写下来，
    // 由 post-fs-data / daemon 拿它去 resetprop。
    if let Some(locked) = identity.device_locked {
        out.push_str(if locked {
            "device_locked=1\n"
        } else {
            "device_locked=0\n"
        });
    }
    if let Some(state) = identity.verified_boot_state {
        out.push_str(&format!("verified_boot_state={state}\n"));
    }
    if let Some(patch) = identity.boot_patchlevel {
        out.push_str(&format!("boot_patchlevel={patch}\n"));
    }
    if out.is_empty() {
        return;
    }
    if std::fs::read_to_string(PATH).ok().as_deref() == Some(out.as_str()) {
        return;
    }
    match std::fs::write(PATH, out.as_bytes()) {
        Ok(()) => log::info!("remote device identity updated ({} bytes)", out.len()),
        Err(e) => log::warn!("write {PATH} failed: {e}"),
    }
}

/// Extracts the A-side key-generation parameters from `params` into a
/// [`device::RemoteAttestParams`] so the B-side TEE mints a key matching what
/// the app requested (not a fixed EC-P256 default).  Mirrors the fields
/// client-a forwards inside `device_attest_context`.
fn extract_remote_attest_params(params: &[KeyParam]) -> device::RemoteAttestParams {
    let mut out = device::RemoteAttestParams::default();
    for p in params {
        match p {
            KeyParam::Algorithm(kmr_wire::keymint::Algorithm::Rsa) => out.key_algorithm = Some(1),
            KeyParam::Algorithm(kmr_wire::keymint::Algorithm::Ec) => out.key_algorithm = Some(3),
            KeyParam::KeySize(KeySizeInBits(bits)) => out.key_size = Some(*bits as i32),
            KeyParam::EcCurve(curve) => out.ec_curve = Some(*curve as i32),
            KeyParam::Purpose(purpose) => out.purpose.push(*purpose as i32),
            KeyParam::Digest(digest) => out.digest.push(*digest as i32),
            KeyParam::RsaOaepMgfDigest(digest) => out.mgf_digest = Some(*digest as i32),
            KeyParam::Padding(padding) => out.padding.push(*padding as i32),
            KeyParam::RsaPublicExponent(exponent) => out.rsa_public_exponent = Some(exponent.0),
            KeyParam::CertificateSubject(subject) => {
                out.certificate_subject = Some(subject.clone())
            }
            KeyParam::CertificateNotBefore(date) => {
                out.certificate_not_before_ms = Some(date.ms_since_epoch)
            }
            KeyParam::CertificateNotAfter(date) => {
                out.certificate_not_after_ms = Some(date.ms_since_epoch)
            }
            // User-authentication / authorization-list tags. These are copy-only
            // in the leaf: the local software path enforces the policy from the
            // key blob and derives the AuthorizationList from the *key params*
            // (`cert::AuthorizationList::new`), so the remote path has to carry
            // them too — otherwise a remotely minted leaf claims
            // `NO_AUTH_REQUIRED` for an auth-bound key (TrustAttestor:
            // `hardware.attestation.user_auth_metadata` /
            // `hardware.attestation.user_auth_policy`).
            //
            // `UserSecureId` (502) *is* forwarded: the B-side real TEE needs it
            // to bind the key to a user, and it is the only auth tag the server
            // keybox layer deliberately skips when writing the leaf (AOSP emits
            // the SID for `importWrappedKey()` only).
            KeyParam::UserSecureId(sid) => out.user_auth.push((502, *sid as i64)),
            KeyParam::NoAuthRequired => out.user_auth.push((503, 1)),
            KeyParam::UserAuthType(v) => out.user_auth.push((504, i64::from(*v))),
            KeyParam::AuthTimeout(v) => out.user_auth.push((505, i64::from(*v))),
            KeyParam::AllowWhileOnBody => out.user_auth.push((506, 1)),
            KeyParam::TrustedUserPresenceRequired => out.user_auth.push((507, 1)),
            KeyParam::TrustedConfirmationRequired => out.user_auth.push((508, 1)),
            KeyParam::UnlockedDeviceRequired => out.user_auth.push((509, 1)),
            _ => {}
        }
    }
    out
}

/// 调用方要求做设备 ID 证明时，算出要随请求带给中继的 `(tag, 值)` 列表。
///
/// 值一律取**本机那套**（`config [device]` / `AttestationIdInfo`），和 AOSP 的
/// `AttestationIds::check_match` 一个口径：调用方上报的值对不上本机真值就回
/// `CannotAttestIds`，绝不把调用方报的原值写进叶子 —— 拿一个投递的假值去问、
/// 叶子把假值原样吐回来，是「软件代铸」最明显的特征。
fn remote_attestation_ids(
    params: &[KeyParam],
    ids: &crate::AttestationIdInfo,
) -> Result<Vec<(u32, Vec<u8>)>, Error> {
    let requested = cert::AttestationIds::new_from_key_params(params)?;
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    requested.check_match(ids)?;
    let mut out = Vec::new();
    for p in params {
        // 中继/服务端认识的就是 710..717 与 723（第二个 IMEI）这套编号。
        let (tag, value) = match p {
            KeyParam::AttestationIdBrand(_) => (710, ids.brand.as_slice()),
            KeyParam::AttestationIdDevice(_) => (711, ids.device.as_slice()),
            KeyParam::AttestationIdProduct(_) => (712, ids.product.as_slice()),
            KeyParam::AttestationIdSerial(_) => (713, ids.serial.as_slice()),
            KeyParam::AttestationIdImei(_) => (714, ids.imei.as_slice()),
            KeyParam::AttestationIdMeid(_) => (715, ids.meid.as_slice()),
            KeyParam::AttestationIdManufacturer(_) => (716, ids.manufacturer.as_slice()),
            KeyParam::AttestationIdModel(_) => (717, ids.model.as_slice()),
            KeyParam::AttestationIdSecondImei(_) => (723, ids.imei2.as_slice()),
            _ => continue,
        };
        if value.is_empty() {
            // 本机没这项真值（比如没读到 IMEI）：那是「签不了这一项」，不是空字符串。
            return Err(km_err!(
                CannotAttestIds,
                "no local value for attestation ID tag {}",
                tag
            ));
        }
        out.try_push((tag, value.to_vec()))?;
    }
    Ok(out)
}

/// 这次 generateKey 是不是在要一把「必须用户认证才能用」的 key。
///
/// 这类 key 交给远端铸是两头堵：B 端真 TEE 每次 begin(SIGN) 都要 auth token，而
/// relay 在 B 侧拿不到 token（TEE 用硬件密钥签的 HMAC，伪造不了），签名必然 -26；
/// 反过来把 504/505 丢掉，叶子又变成「不需要认证」，跟 app 的请求对不上 ——
/// TrustAttestor 的 `hardware.attestation.user_auth_metadata` 就是这么判红的。
/// 认证策略本来就是本机的事（指纹/锁屏由本机 Keystore2 管），所以这类 key 统一
/// 本地生成，链走本地 keybox，授权列表完整。
fn requests_user_auth(params: &[KeyParam]) -> bool {
    params
        .iter()
        .any(|p| matches!(p, KeyParam::UserAuthType(_) | KeyParam::AuthTimeout(_)))
}

/// 只拿来跑 ECDH 的 key（`PURPOSE_AGREE_KEY`，而且没有签名/解密用途）。
///
/// 这类 key 不该走远程：私钥在 B 那边，每次 ECDH 都得把请求打到 B 的 TEE 上，
/// 而 B 的 `AGREE_KEY` 在实测里会把 TEE 打进 `-49` 的坏状态（之后连签名都 -1000），
/// 等于用一个探针把整条链拖死。本地软件 keybox 生成一把、本地算 ECDH 就够了 ——
/// 这类探针只看协商出的 secret 是否一致，不验证书链。
fn agrees_only(params: &[KeyParam]) -> bool {
    let mut purposes = params.iter().filter_map(|p| match p {
        KeyParam::Purpose(purpose) => Some(*purpose),
        _ => None,
    });
    let mut only_agree = false;
    for purpose in purposes.by_ref() {
        match purpose {
            keymint::KeyPurpose::AgreeKey => only_agree = true,
            _ => return false,
        }
    }
    only_agree
}

#[cfg(test)]
mod remote_alias_tests {
    use super::*;

    struct CountingRng(u8);

    impl crypto::Rng for CountingRng {
        fn add_entropy(&mut self, _data: &[u8]) {}

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0 += 1;
            dest.fill(self.0);
        }
    }

    #[test]
    fn each_key_creation_allocates_one_random_alias() {
        let mut rng = CountingRng(0);
        let first = new_remote_alias(&mut rng);
        let second = new_remote_alias(&mut rng);
        assert_ne!(first, second);
        assert_eq!(first, "ommega-remote-01010101010101010101010101010101");
        assert_eq!(second, "ommega-remote-02020202020202020202020202020202");
        assert_eq!(rng.0, 2);
        // Reusing the allocated identity also preserves the derived serial.
        let serial = derive_remote_serial(&first, b"same challenge");
        assert_eq!(serial, derive_remote_serial(&first, b"same challenge"));
        assert_ne!(serial, derive_remote_serial(&second, b"same challenge"));
    }
}
