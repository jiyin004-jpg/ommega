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

//! TA functionality related to in-progress crypto operations.

use kmr_common::{
    crypto::{AadOperation, AccumulatingOperation, EmittingOperation},
    keyblob, km_err, Error, FallibleAllocExt,
};
use kmr_wire::{
    keymint::{HardwareAuthToken, KeyParam},
    secureclock::{TimeStampToken, Timestamp},
};
use log::{error, warn};
use std::{boxed::Box, vec::Vec};

mod begin;

/// A trusted confirmation token should be the size of HMAC-SHA256 output.
const CONFIRMATION_TOKEN_SIZE: usize = 32;

/// Trusted confirmation data prefix, from IConfirmationResultCallback.hal.
const CONFIRMATION_DATA_PREFIX: &[u8] = b"confirmation token";

/// Maximum size of messages with `Tag::TrustedConfirmationRequired` set.
/// See <https://source.android.com/security/protected-confirmation/implementation>
const CONFIRMATION_MESSAGE_MAX_LEN: usize = 6144;

/// 大端无符号比较：`a >= b`（忽略前导零）。只用于 NoPadding 解密的 c < n 检查，
/// 不值得为此拉一个大数库进来。
fn be_ge(a: &[u8], b: &[u8]) -> bool {
    fn trim(v: &[u8]) -> &[u8] {
        let mut i = 0;
        while i + 1 < v.len() && v[i] == 0 {
            i += 1;
        }
        &v[i..]
    }
    let (a, b) = (trim(a), trim(b));
    a.len() > b.len() || (a.len() == b.len() && a >= b)
}

/// Union holder for in-progress cryptographic operations, each of which is an instance
/// of the relevant trait.
pub(crate) enum CryptoOperation {
    Aes(Box<dyn EmittingOperation>),
    AesGcm(Box<dyn AadOperation>),
    Des(Box<dyn EmittingOperation>),
    HmacSign(Box<dyn AccumulatingOperation>, usize), // tag length
    HmacVerify(Box<dyn AccumulatingOperation>, core::ops::Range<usize>),
    RsaDecrypt(Box<dyn AccumulatingOperation>),
    RsaSign(Box<dyn AccumulatingOperation>),
    EcAgree(Box<dyn AccumulatingOperation>),
    EcSign(Box<dyn AccumulatingOperation>),
    MlDsaSign(Box<dyn AccumulatingOperation>),
    /// Remote (B-side TEE) signing operation: data is accumulated locally and
    /// forwarded to the relay server at `finish`.
    RemoteSign {
        alias: String,
        algorithm: String,
        data: Vec<u8>,
        /// `NONEwithECDSA` 时要的域宽：真 TEE 对输入长度很挑，太短太长都可能拒；
        /// 本地软件 TA 是 pad/truncate 处理，两边不统一就会出现「本地能签、远程报错」。
        raw_digest_len: Option<usize>,
    },
    /// Remote (B-side TEE) decryption operation.
    RemoteDecrypt {
        alias: String,
        algorithm: String,
        data: Vec<u8>,
        /// RSA 的模长（字节）。真 TEE 收到长度不对的密文会回自己的错误码（QTI 上是
        /// `-33 INVALID_KEY_BLOB`），本地软件 TA 回 `-30 VERIFICATION_FAILED` ——
        /// 同一台机上本地/远程两边不一致就是检测器能看到的差异。所以在这里先按模长
        /// 拦一道，行为以本地为准。
        expected_len: Option<usize>,
        /// RSA 的模数 n（大端）。NoPadding 解密要先比一下 c < n（远程私钥在 B 端，
        /// 真机 KeyMint（含 AOSP 原版）不查这一点，得在转发前拦）。
        modulus: Vec<u8>,
    },
}

/// Current state of an operation.
pub(crate) struct Operation {
    /// Random handle used to identify the operation, also used as a challenge.
    pub handle: OpHandle,

    /// Whether update_aad() is allowed (only ever true for AEADs before data has arrived).
    pub aad_allowed: bool,

    /// Secure deletion slot to delete on successful completion of the operation.
    pub slot_to_delete: Option<keyblob::SecureDeletionSlot>,

    /// Buffer to accumulate data being signed that must have a trusted confirmation. This
    /// data matches what was been fed into `crypto_op`'s `update` method (but has a size
    /// limit so will not grow unboundedly).
    pub trusted_conf_data: Option<Vec<u8>>,

    /// Authentication data to check.
    pub auth_info: Option<AuthInfo>,

    pub crypto_op: CryptoOperation,

    /// Accumulated input size.
    pub input_size: usize,
}

impl Operation {
    /// Upper bound for buffered input to a remote (B-side forwarded) sign or
    /// decrypt operation. The bytes are only buffered until the final
    /// begin/finish forward, so a generous cap (1 MiB) is plenty for any
    /// realistic challenge / TBS / ciphertext while preventing unbounded
    /// growth from an abusive client.
    const REMOTE_OP_MAX_INPUT: usize = 1 << 20;

    /// Check whether `len` additional bytes of data can be accommodated by the `Operation`.
    fn check_size(&mut self, len: usize) -> Result<(), Error> {
        self.input_size += len;
        let max_size = match &self.crypto_op {
            CryptoOperation::HmacSign(op, _)
            | CryptoOperation::HmacVerify(op, _)
            | CryptoOperation::RsaDecrypt(op)
            | CryptoOperation::RsaSign(op)
            | CryptoOperation::EcAgree(op)
            | CryptoOperation::EcSign(op) => op.max_input_size(),
            CryptoOperation::RemoteSign { .. } | CryptoOperation::RemoteDecrypt { .. } => {
                Some(Self::REMOTE_OP_MAX_INPUT)
            }
            _ => None,
        };
        if let Some(max_size) = max_size {
            if self.input_size > max_size {
                return Err(km_err!(
                    InvalidInputLength,
                    "too much input accumulated for operation"
                ));
            }
        }
        Ok(())
    }
}

/// Newtype for operation handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpHandle(pub i64);

/// Authentication requirements associated with an operation.
pub(crate) struct AuthInfo {
    secure_ids: Vec<u64>,
    auth_type: u32,
    timeout_secs: Option<u32>,
}

impl AuthInfo {
    /// Optionally build an `AuthInfo` from key characteristics. If no authentication is needed on
    /// `update()`/`update_aad()`/`finish()`, return `None`.
    fn new(key_chars: &[KeyParam]) -> Result<Option<AuthInfo>, Error> {
        let mut secure_ids = Vec::new();
        let mut auth_type = None;
        let mut timeout_secs = None;
        let mut no_auth_required = false;

        for param in key_chars {
            match param {
                KeyParam::UserSecureId(sid) => secure_ids.try_push(*sid)?,
                KeyParam::UserAuthType(atype) => {
                    if auth_type.is_none() {
                        auth_type = Some(*atype);
                    } else {
                        return Err(km_err!(InvalidKeyBlob, "duplicate UserAuthType tag found"));
                    }
                }
                KeyParam::AuthTimeout(secs) => {
                    if timeout_secs.is_none() {
                        timeout_secs = Some(*secs)
                    } else {
                        return Err(km_err!(InvalidKeyBlob, "duplicate AuthTimeout tag found"));
                    }
                }
                KeyParam::NoAuthRequired => no_auth_required = true,
                _ => {}
            }
        }

        if secure_ids.is_empty() {
            Ok(None)
        } else if let Some(auth_type) = auth_type {
            if no_auth_required {
                Err(km_err!(
                    InvalidKeyBlob,
                    "found both NO_AUTH_REQUIRED and USER_SECURE_ID"
                ))
            } else {
                Ok(Some(AuthInfo {
                    secure_ids,
                    auth_type,
                    timeout_secs,
                }))
            }
        } else {
            Err(km_err!(
                KeyUserNotAuthenticated,
                "found USER_SECURE_ID but no USER_AUTH_TYPE"
            ))
        }
    }
}

impl crate::KeyMintTa {
    pub(crate) fn op_update_aad(
        &mut self,
        op_handle: OpHandle,
        data: &[u8],
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
    ) -> Result<(), Error> {
        self.with_authed_operation(op_handle, auth_token, timestamp_token, |op| {
            if !op.aad_allowed {
                return Err(km_err!(InvalidTag, "update-aad not allowed"));
            }
            match &mut op.crypto_op {
                CryptoOperation::AesGcm(op) => op.update_aad(data),
                _ => Err(km_err!(
                    InvalidOperation,
                    "operation does not support update_aad"
                )),
            }
        })
    }

    pub(crate) fn op_update(
        &mut self,
        op_handle: OpHandle,
        data: &[u8],
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
    ) -> Result<Vec<u8>, Error> {
        let check_presence = if self.presence_required_op == Some(op_handle) {
            self.presence_required_op = None;
            true
        } else {
            false
        };
        let tup_available = self.dev.tup.available();
        self.with_authed_operation(op_handle, auth_token, timestamp_token, |op| {
            if check_presence && !tup_available {
                return Err(km_err!(
                    ProofOfPresenceRequired,
                    "trusted proof of presence required but not available"
                ));
            }
            if let Some(trusted_conf_data) = &mut op.trusted_conf_data {
                if trusted_conf_data.len() + data.len()
                    > CONFIRMATION_DATA_PREFIX.len() + CONFIRMATION_MESSAGE_MAX_LEN
                {
                    return Err(km_err!(
                        InvalidArgument,
                        "trusted confirmation data of size {} + {} too big",
                        trusted_conf_data.len(),
                        data.len()
                    ));
                }
                trusted_conf_data.try_extend_from_slice(data)?;
            }
            op.aad_allowed = false;
            op.check_size(data.len())?;
            match &mut op.crypto_op {
                CryptoOperation::Aes(op) => op.update(data),
                CryptoOperation::AesGcm(op) => op.update(data),
                CryptoOperation::Des(op) => op.update(data),
                CryptoOperation::HmacSign(op, _) | CryptoOperation::HmacVerify(op, _) => {
                    op.update(data)?;
                    Ok(Vec::new())
                }
                CryptoOperation::RsaDecrypt(op) => {
                    op.update(data)?;
                    Ok(Vec::new())
                }
                CryptoOperation::RsaSign(op) => {
                    op.update(data)?;
                    Ok(Vec::new())
                }
                CryptoOperation::EcAgree(op) => {
                    op.update(data)?;
                    Ok(Vec::new())
                }
                CryptoOperation::EcSign(op) => {
                    op.update(data)?;
                    Ok(Vec::new())
                }
                CryptoOperation::MlDsaSign(op) => {
                    op.update(data)?;
                    Ok(Vec::new())
                }
                CryptoOperation::RemoteSign { data: buf, .. } => {
                    buf.try_extend_from_slice(data)?;
                    Ok(Vec::new())
                }
                CryptoOperation::RemoteDecrypt { data: buf, .. } => {
                    buf.try_extend_from_slice(data)?;
                    Ok(Vec::new())
                }
            }
        })
    }

    pub(crate) fn op_finish(
        &mut self,
        op_handle: OpHandle,
        data: Option<&[u8]>,
        signature: Option<&[u8]>,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
        confirmation_token: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut op = self.take_operation(op_handle)?;
        self.check_subsequent_auth(&op, auth_token, timestamp_token)?;
        // Keep the finish-argument data around for the remote-forwarding branches
        // (the `data` name is shadowed inside the crypto_op match arms).
        let finish_data = data;

        if self.presence_required_op == Some(op_handle) {
            self.presence_required_op = None;
            if !self.dev.tup.available() {
                return Err(km_err!(
                    ProofOfPresenceRequired,
                    "trusted proof of presence required but not available"
                ));
            }
        }
        if let (Some(trusted_conf_data), Some(data)) = (&mut op.trusted_conf_data, data) {
            if trusted_conf_data.len() + data.len()
                > CONFIRMATION_DATA_PREFIX.len() + CONFIRMATION_MESSAGE_MAX_LEN
            {
                return Err(km_err!(
                    InvalidArgument,
                    "data of size {} + {} too big",
                    trusted_conf_data.len(),
                    data.len()
                ));
            }
            trusted_conf_data.try_extend_from_slice(data)?;
        }

        op.check_size(data.map_or(0, |v| v.len()))?;
        let result = match op.crypto_op {
            CryptoOperation::Aes(mut op) => {
                let mut result = if let Some(data) = data {
                    op.update(data)?
                } else {
                    Vec::new()
                };
                result.try_extend_from_slice(&op.finish()?)?;
                Ok(result)
            }
            CryptoOperation::AesGcm(mut op) => {
                let mut result = if let Some(data) = data {
                    op.update(data)?
                } else {
                    Vec::new()
                };
                result.try_extend_from_slice(&op.finish()?)?;
                Ok(result)
            }
            CryptoOperation::Des(mut op) => {
                let mut result = if let Some(data) = data {
                    op.update(data)?
                } else {
                    Vec::new()
                };
                result.try_extend_from_slice(&op.finish()?)?;
                Ok(result)
            }
            CryptoOperation::HmacSign(mut op, tag_len) => {
                if let Some(data) = data {
                    op.update(data)?;
                };
                let mut tag = op.finish()?;
                tag.truncate(tag_len);
                Ok(tag)
            }
            CryptoOperation::HmacVerify(mut op, tag_len_range) => {
                let sig = signature
                    .ok_or_else(|| km_err!(InvalidArgument, "signature missing for HMAC verify"))?;
                if !tag_len_range.contains(&sig.len()) {
                    return Err(km_err!(
                        InvalidArgument,
                        "signature length invalid: {} not in {tag_len_range:?}",
                        sig.len(),
                    ));
                }

                if let Some(data) = data {
                    op.update(data)?;
                };
                let got = op.finish()?;

                if self.imp.compare.eq(&got[..sig.len()], sig) {
                    Ok(Vec::new())
                } else {
                    Err(km_err!(VerificationFailed, "HMAC verify failed"))
                }
            }
            CryptoOperation::RsaDecrypt(mut op) => {
                if let Some(data) = data {
                    op.update(data)?;
                };
                op.finish()
            }
            CryptoOperation::RsaSign(mut op) => {
                if let Some(data) = data {
                    op.update(data)?;
                };
                op.finish()
            }
            CryptoOperation::EcAgree(mut op) => {
                if let Some(data) = data {
                    op.update(data)?;
                };
                op.finish()
            }
            CryptoOperation::EcSign(mut op) => {
                if let Some(data) = data {
                    op.update(data)?;
                };
                op.finish()
            }
            CryptoOperation::MlDsaSign(mut op) => {
                if let Some(data) = data {
                    op.update(data)?;
                };
                op.finish()
            }
            CryptoOperation::RemoteSign {
                alias,
                algorithm,
                mut data,
                raw_digest_len,
            } => {
                if let Some(input) = finish_data {
                    data.try_extend_from_slice(input).map_err(|_| {
                        km_err!(MemoryAllocationFailed, "remote sign buffer overflow")
                    })?;
                }
                let raw_len = data.len();
                let data = match raw_digest_len {
                    Some(len) => raw_digest_fitted(&data, len),
                    None => data,
                };
                let sent = data.len();
                let remote = self.dev.remote.as_ref().ok_or_else(|| {
                    km_err!(
                        UnknownError,
                        "remote key used but no remote backend configured"
                    )
                })?;
                if !remote.enabled() {
                    return Err(km_err!(UnknownError, "remote backend disabled"));
                }
                let signed = remote.sign(&alias, &data, &algorithm);
                if let Err(error) = &signed {
                    error!(
                        "remote_sign failed alias={alias} algorithm={algorithm} raw={raw_len} sent={sent} fitted={raw_digest_len:?}: {error:?}"
                    );
                }
                signed?.ok_or_else(|| km_err!(UnknownError, "remote sign failed"))
            }
            CryptoOperation::RemoteDecrypt {
                alias,
                algorithm,
                mut data,
                expected_len,
                modulus,
            } => {
                if let Some(input) = finish_data {
                    data.try_extend_from_slice(input).map_err(|_| {
                        km_err!(MemoryAllocationFailed, "remote decrypt buffer overflow")
                    })?;
                }
                let in_len = data.len();
                if let Some(expected) = expected_len {
                    if in_len != expected {
                        // 本地那条路是 update 阶段按最大输入长度拦的，回
                        // `INVALID_INPUT_LENGTH`（测出来的 -21）；这里跟着它走，
                        // 否则同一个请求本地/远程两边错误类别不一样。
                        error!(
                            "remote_decrypt rejected alias={alias} algorithm={algorithm} in={in_len} expected={expected}"
                        );
                        return Err(km_err!(
                            InvalidInputLength,
                            "RSA ciphertext is {in_len} bytes, expected {expected}"
                        ));
                    }
                }
                // NoPadding 解密：c 必须严格小于模数 n。远程私钥在 B 端，真机
                // KeyMint（包括 AOSP 原版）对这一点不检查，得在这里拦（aprobe C09）。
                if algorithm == "RSA/ECB/NoPadding" && !modulus.is_empty() && be_ge(&data, &modulus)
                {
                    error!("remote_decrypt rejected alias={alias}: c >= n");
                    return Err(km_err!(
                        InvalidArgument,
                        "ciphertext representative out of range"
                    ));
                }
                let remote = self.dev.remote.as_ref().ok_or_else(|| {
                    km_err!(
                        UnknownError,
                        "remote key used but no remote backend configured"
                    )
                })?;
                if !remote.enabled() {
                    return Err(km_err!(UnknownError, "remote backend disabled"));
                }
                let plain = remote.decrypt(&alias, &data, &algorithm);
                if let Err(error) = &plain {
                    error!(
                        "remote_decrypt failed alias={alias} algorithm={algorithm} in={in_len} expected={expected_len:?}: {error:?}"
                    );
                }
                plain?.ok_or_else(|| km_err!(UnknownError, "remote decrypt failed"))
            }
        };
        if result.is_ok() {
            if let Some(trusted_conf_data) = op.trusted_conf_data {
                // Accumulated input must be checked against the trusted confirmation token.
                self.verify_confirmation_token(&trusted_conf_data, confirmation_token)?;
            }
            if let (Some(slot), Some(sdd_mgr)) = (op.slot_to_delete, &mut self.dev.sdd_mgr) {
                // A successful use of a key with UsageCountLimit(1) triggers deletion.
                warn!("Deleting single-use key after use");
                if let Err(e) = sdd_mgr.delete_secret(slot) {
                    error!("Failed to delete single-use key after use: {e:?}");
                }
            }
        }
        result
    }

    pub(crate) fn op_abort(&mut self, op_handle: OpHandle) -> Result<(), Error> {
        if self.presence_required_op == Some(op_handle) {
            self.presence_required_op = None;
        }
        let _op = self.take_operation(op_handle)?;
        Ok(())
    }

    /// Validate a `[keymint::HardwareAuthToken`].
    fn check_auth_token(
        &self,
        auth_token: HardwareAuthToken,
        auth_info: &AuthInfo,
        now: Option<Timestamp>,
        timeout_secs: Option<u32>,
        challenge: Option<i64>,
    ) -> Result<(), Error> {
        // Common check: confirm the HMAC tag in the token is valid.
        let mac_input = crate::hardware_auth_token_mac_input(&auth_token)?;
        if !self.verify_device_hmac(&mac_input, &auth_token.mac)? {
            return Err(km_err!(
                KeyUserNotAuthenticated,
                "failed to authenticate auth_token"
            ));
        }
        // Common check: token's auth type should match key's USER_AUTH_TYPE.
        if (auth_token.authenticator_type as u32 & auth_info.auth_type) == 0 {
            return Err(km_err!(
                KeyUserNotAuthenticated,
                "token auth type {:?} doesn't overlap with key auth type {:?}",
                auth_token.authenticator_type,
                auth_info.auth_type,
            ));
        }

        // Common check: token's authenticator or user ID should match key's USER_SECURE_ID.
        if !auth_info.secure_ids.iter().any(|sid| {
            auth_token.user_id == *sid as i64 || auth_token.authenticator_id == *sid as i64
        }) {
            return Err(km_err!(
                KeyUserNotAuthenticated,
                "neither user id {:?} nor authenticator id {:?} matches key",
                auth_token.user_id,
                auth_token.authenticator_id
            ));
        }

        // Optional check: token is in time range.
        if let (Some(now), Some(timeout_secs)) = (now, timeout_secs) {
            if now.milliseconds > auth_token.timestamp.milliseconds + 1000 * timeout_secs as i64 {
                return Err(km_err!(
                    KeyUserNotAuthenticated,
                    "now {now:?} is later than auth token time {:?} + {timeout_secs} seconds",
                    auth_token.timestamp,
                ));
            }
        }

        // Optional check: challenge matches.
        if let Some(challenge) = challenge {
            if auth_token.challenge != challenge {
                return Err(km_err!(KeyUserNotAuthenticated, "challenge mismatch"));
            }
        }
        Ok(())
    }

    /// Verify that an optional confirmation token matches the provided `data`.
    fn verify_confirmation_token(&self, data: &[u8], token: Option<&[u8]>) -> Result<(), Error> {
        if let Some(token) = token {
            if token.len() != CONFIRMATION_TOKEN_SIZE {
                return Err(km_err!(
                    InvalidArgument,
                    "confirmation token wrong length {}",
                    token.len()
                ));
            }
            if self.verify_device_hmac(data, token).map_err(|e| {
                km_err!(
                    VerificationFailed,
                    "failed to perform HMAC on confirmation token: {e:?}"
                )
            })? {
                Ok(())
            } else {
                Err(km_err!(
                    NoUserConfirmation,
                    "trusted confirmation token did not match"
                ))
            }
        } else {
            Err(km_err!(
                NoUserConfirmation,
                "no trusted confirmation token provided"
            ))
        }
    }

    /// Return the index of a free slot in the operations table.
    fn new_operation_index(&mut self) -> Result<usize, Error> {
        self.operations
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                km_err!(
                    TooManyOperations,
                    "current op count {} >= limit",
                    self.operations.len()
                )
            })
    }

    /// Return a new operation handle value that is not currently in use in the
    /// operations table.
    fn new_op_handle(&mut self) -> OpHandle {
        loop {
            let op_handle = OpHandle(self.imp.rng.next_u64() as i64);
            if self.op_index(op_handle).is_err() {
                return op_handle;
            }
            // op_handle already in use, go around again.
        }
    }

    /// Return the index into the operations table of an operation identified by `op_handle`.
    fn op_index(&self, op_handle: OpHandle) -> Result<usize, Error> {
        self.operations
            .iter()
            .position(|op| match op {
                Some(op) if op.handle == op_handle => true,
                Some(_op) => false,
                None => false,
            })
            .ok_or_else(|| km_err!(InvalidOperation, "operation handle {op_handle:?} not found"))
    }

    /// Execute the provided lambda over the associated [`Operation`], handling
    /// errors.
    fn with_authed_operation<F, T>(
        &mut self,
        op_handle: OpHandle,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
        f: F,
    ) -> Result<T, Error>
    where
        F: FnOnce(&mut Operation) -> Result<T, Error>,
    {
        let op_idx = self.op_index(op_handle)?;
        let check_again = self.check_subsequent_auth(
            self.operations[op_idx].as_ref().unwrap(/* safe: op_index() checks */ ),
            auth_token,
            timestamp_token,
        )?;
        let op = self.operations[op_idx].as_mut().unwrap(/* safe: op_index() checks */);
        if !check_again {
            op.auth_info = None;
        }
        let result = f(op);
        if result.is_err() {
            // A failure destroys the operation.
            if self.presence_required_op == Some(op_handle) {
                self.presence_required_op = None;
            }
            self.operations[op_idx] = None;
        }
        result
    }

    /// Return the associated [`Operation`], removing it.
    /// 如果这单是远程 key 的 finish，把要转发的数据取出来并结束 operation；不是远程就
    /// 原样放回去返回 None，调用方照旧走 `finish()`。
    ///
    /// 为什么要多这一道：远端签名是百毫秒级的网络请求，而 `KeyMintTa` 被
    /// `KeyMintDevice` 的全局 Mutex 包着。在锁内做网络会把别人的 begin 一起堵住，
    /// 检测器（TrustAttestor keystore_timing）量的就是“忙时 begin 慢不慢”。
    ///
    /// 返回 `(is_sign, alias, algorithm, data)`，由调用方在锁外完成请求。
    #[allow(clippy::type_complexity)]
    pub fn take_remote_finish(
        &mut self,
        op_handle: i64,
        data: Option<&[u8]>,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
    ) -> Result<Option<(bool, String, String, Vec<u8>)>, Error> {
        let op_idx = self.op_index(OpHandle(op_handle))?;
        let mut op = self.operations[op_idx]
            .take()
            .unwrap(/* safe: op_index() checks */);
        let remote = match &op.crypto_op {
            CryptoOperation::RemoteSign {
                alias,
                algorithm,
                raw_digest_len,
                ..
            } => Some((
                true,
                alias.clone(),
                algorithm.clone(),
                *raw_digest_len,
                None,
                None,
            )),
            CryptoOperation::RemoteDecrypt {
                alias,
                algorithm,
                expected_len,
                modulus,
                ..
            } => Some((
                false,
                alias.clone(),
                algorithm.clone(),
                None,
                *expected_len,
                Some(modulus.clone()),
            )),
            _ => None,
        };
        let Some((is_sign, alias, algorithm, raw_digest_len, expected_len, modulus)) = remote
        else {
            // 不是远程 key：放回去，让正常 finish 路径处理。
            self.operations[op_idx] = Some(op);
            return Ok(None);
        };
        // 和 finish() 一致的前置校验，失败时 operation 已经摘掉（跟原行为一样）。
        self.check_subsequent_auth(&op, auth_token, timestamp_token)?;
        op.check_size(data.map_or(0, |v| v.len()))?;
        let mut buf = match &op.crypto_op {
            CryptoOperation::RemoteSign { data, .. } => data.clone(),
            CryptoOperation::RemoteDecrypt { data, .. } => data.clone(),
            _ => Vec::new(),
        };
        if let Some(input) = data {
            buf.try_extend_from_slice(input)
                .map_err(|_| km_err!(MemoryAllocationFailed, "remote finish buffer overflow"))?;
        }
        if is_sign {
            if let Some(len) = raw_digest_len {
                buf = raw_digest_fitted(&buf, len);
            }
        } else if let Some(expected) = expected_len {
            if buf.len() != expected {
                return Err(km_err!(
                    InvalidInputLength,
                    "RSA ciphertext is {} bytes, expected {expected}",
                    buf.len()
                ));
            }
        }
        // NoPadding 解密：c 必须严格小于模数 n（真机 KeyMint 不查这个）。
        if !is_sign && algorithm == "RSA/ECB/NoPadding" {
            if let Some(n) = modulus.as_deref() {
                if !n.is_empty() && be_ge(&buf, n) {
                    error!("remote finish rejected alias={alias}: c >= n");
                    return Err(km_err!(
                        InvalidArgument,
                        "ciphertext representative out of range"
                    ));
                }
            }
        }
        Ok(Some((is_sign, alias, algorithm, buf)))
    }

    fn take_operation(&mut self, op_handle: OpHandle) -> Result<Operation, Error> {
        let op_idx = self.op_index(op_handle)?;
        Ok(self.operations[op_idx].take().unwrap(/* safe: op_index() checks */))
    }

    /// Check authentication for an operation that has already begun. Returns an indication as to
    /// whether future invocations also need to check authentication.
    fn check_subsequent_auth(
        &self,
        op: &Operation,
        auth_token: Option<HardwareAuthToken>,
        timestamp_token: Option<TimeStampToken>,
    ) -> Result<bool, Error> {
        if let Some(auth_info) = &op.auth_info {
            let auth_token = auth_token.ok_or_else(|| {
                km_err!(KeyUserNotAuthenticated, "no auth token on subsequent op")
            })?;

            // Most auth checks happen on begin(), but there are two exceptions.
            // a) There is no AUTH_TIMEOUT: there should be a valid auth token on every invocation.
            // b) There is an AUTH_TIMEOUT but we have no clock: the first invocation on the
            //    operation (after `begin()`) should check the timeout, based on a provided
            //    timestamp token.
            if let Some(timeout_secs) = auth_info.timeout_secs {
                if self.imp.clock.is_some() {
                    return Err(km_err!(
                        InvalidAuthorizationTimeout,
                        "attempt to check auth timeout after begin() on device with clock!"
                    ));
                }

                // Check that the timestamp token is valid.
                let timestamp_token = timestamp_token
                    .ok_or_else(|| km_err!(InvalidArgument, "no timestamp token provided"))?;
                if timestamp_token.challenge != op.handle.0 {
                    return Err(km_err!(InvalidArgument, "timestamp challenge mismatch"));
                }
                let mac_input = crate::clock::timestamp_token_mac_input(&timestamp_token)?;
                if !self.verify_device_hmac(&mac_input, &timestamp_token.mac)? {
                    return Err(km_err!(InvalidArgument, "timestamp MAC not verified"));
                }

                self.check_auth_token(
                    auth_token,
                    auth_info,
                    Some(timestamp_token.timestamp),
                    Some(timeout_secs),
                    Some(op.handle.0),
                )?;

                // No need to check again.
                Ok(false)
            } else {
                self.check_auth_token(auth_token, auth_info, None, None, Some(op.handle.0))?;
                // Check on every invocation
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }
}

/// 把 `NONEwithECDSA` 的输入整理成正好一个域宽。
///
/// ECDSA 把输入当大整数：短的左边补 0、长的取最左边 `len` 字节（RFC 6979 的 bits2int）。
/// 本地软件 TA 本来就是这个规则，但远程那条路是把原始字节直接交给 B 的真 TEE，各家的
/// HAL 对「不是域宽」的输入表现不一致（有的直接拒），于是同一个请求本地能签、远程报错。
/// 所以在转发前统一成域宽，两条路的语义才一致。
fn raw_digest_fitted(data: &[u8], len: usize) -> Vec<u8> {
    if data.len() == len {
        return data.to_vec();
    }
    if data.len() > len {
        return data[..len].to_vec();
    }
    let mut out = vec![0u8; len];
    out[len - data.len()..].copy_from_slice(data);
    out
}
#[cfg(test)]
mod tests {
    use super::raw_digest_fitted;

    /// 远程的 `NONEwithECDSA` 也得跟本地一样：短的左补 0、长的取左边域宽、正好就不动。
    #[test]
    fn raw_digest_is_fitted_to_the_field_width() {
        let short = [0x11u8, 0x22, 0x33, 0x44];
        assert_eq!(
            raw_digest_fitted(&short, 8),
            vec![0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44]
        );

        let long: Vec<u8> = (0u8..40).collect();
        assert_eq!(raw_digest_fitted(&long, 32), long[..32].to_vec());

        let exact = [7u8; 32];
        assert_eq!(raw_digest_fitted(&exact, 32), exact.to_vec());
    }
}
