//! Android EAT（CBOR）attestation extension 的解析。
//!
//! KeyMint 4.0 起可以把 attestation extension 写成 CBOR（EAT，OID
//! 1.3.6.1.4.1.11129.2.1.25）。按 DER（OID 2.1.17）那套读不了它，而
//! HAL 侧（`src/plat/attestation.rs`）和 TA 侧（`ta/src/cert.rs`）都要
//! 从远端链里读同一批 claim，解析器就放这儿两边共用，省得各写一份。
//!
//! claim 编号照 AOSP 的 `EatClaim` 抄：KeyMint tag 那一档是
//! `-80000 - tag`，非 KeyMint 的一档是 `NON_KM_BASE = -82000` 往下数。

use crate::crypto::RemoteRootOfTrust;
use anyhow::{anyhow, bail, Result};
use std::vec::Vec;

/// EAT attestation extension 的 OID：1.3.6.1.4.1.11129.2.1.25。
pub const EAT_OID: [u64; 10] = [1, 3, 6, 1, 4, 1, 11129, 2, 1, 25];

/// `EatClaim` 里我们用得上的几个编号。
pub mod claim {
    /// `EatClaim.NONCE`：调用方塞进来的 attestationChallenge。
    pub const NONCE: i64 = -75_008;
    /// `EatClaim.VERIFIED_BOOT_KEY`（`NON_KM_BASE - 1`）。
    pub const VERIFIED_BOOT_KEY: i64 = -82_001;
    /// `EatClaim.DEVICE_LOCKED`（`NON_KM_BASE - 2`）。
    pub const DEVICE_LOCKED: i64 = -82_002;
    /// `EatClaim.VERIFIED_BOOT_HASH`（`NON_KM_BASE - 3`）。
    pub const VERIFIED_BOOT_HASH: i64 = -82_003;
    /// `EatClaim.ATTESTATION_VERSION`（`NON_KM_BASE - 4`）。
    pub const ATTESTATION_VERSION: i64 = -82_004;
    /// `EatClaim.KEYMASTER_VERSION`（`NON_KM_BASE - 5`）。
    pub const KEYMASTER_VERSION: i64 = -82_005;
    /// `EatClaim.OFFICIAL_BUILD`（`NON_KM_BASE - 6`）。
    pub const OFFICIAL_BUILD: i64 = -82_006;
}

/// 递归深度上限，防止手工构造的链把栈撑爆。
const MAX_DEPTH: usize = 16;

/// 解出来的 CBOR 值。只保留 claim 用得到的形状，别的都归 `Other`。
#[derive(Clone, Debug)]
pub enum Cbor<'a> {
    Uint(u64),
    /// CBOR 的负数编码是 `-1 - n`，这里存的就是那个 `n`。
    Negint(u64),
    Bytes(&'a [u8]),
    Bool(bool),
    Map(Vec<(Cbor<'a>, Cbor<'a>)>),
    Other,
}

impl Cbor<'_> {
    /// 整数（含负数）。
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Cbor::Uint(v) => i64::try_from(*v).ok(),
            Cbor::Negint(v) => Some(-1 - i64::try_from(*v).ok()?),
            _ => None,
        }
    }

    /// 字节串。
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(v) => Some(v),
            _ => None,
        }
    }

    /// 布尔。
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Cbor::Bool(v) => Some(*v),
            _ => None,
        }
    }
}

/// 载荷首字节不是 `0x30`（DER SEQUENCE）就当 CBOR。DER 的
/// `KeyDescription` 恒以 `0x30` 开头，CBOR map 是 `0xa0`-`0xbf`，
/// 两个区间不重叠，所以这么区分是稳的。
pub fn is_cbor_attestation_extension(bytes: &[u8]) -> bool {
    bytes.first().map(|b| *b != 0x30).unwrap_or(false)
}

/// 解出顶层 CBOR map 的 claim 列表。
pub fn parse_claims(bytes: &[u8]) -> Result<Vec<(Cbor<'_>, Cbor<'_>)>> {
    let mut pos = 0;
    let Cbor::Map(claims) = value(bytes, &mut pos, 0)? else {
        bail!("EAT attestation extension is not a CBOR map");
    };
    // 顶层 map 之后不允许有尾随数据，和 DER 路径的宽严保持一致。
    if pos != bytes.len() {
        bail!("EAT extension has trailing data after the top-level map");
    }
    Ok(claims)
}

/// 按 claim 编号取值。
pub fn get<'a>(claims: &'a [(Cbor<'a>, Cbor<'a>)], claim: i64) -> Option<&'a Cbor<'a>> {
    claims
        .iter()
        .find(|(key, _)| key.as_int() == Some(claim))
        .map(|(_, value)| value)
}

/// 读 attestationChallenge。
pub fn challenge(bytes: &[u8]) -> Result<Vec<u8>> {
    let claims = parse_claims(bytes)?;
    match get(&claims, claim::NONCE) {
        Some(Cbor::Bytes(nonce)) => Ok(nonce.to_vec()),
        Some(_) => bail!("EAT nonce claim is not a byte string"),
        None => bail!("EAT extension has no nonce claim"),
    }
}

/// 读 verifiedBootHash。
pub fn verified_boot_hash(bytes: &[u8]) -> Result<[u8; 32]> {
    let claims = parse_claims(bytes)?;
    let Some(Cbor::Bytes(hash)) = get(&claims, claim::VERIFIED_BOOT_HASH) else {
        bail!("EAT extension has no verified-boot-hash claim");
    };
    if hash.len() != 32 {
        bail!("verifiedBootHash must be 32 bytes, got {}", hash.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hash);
    Ok(out)
}

/// 从 EAT 里拼出远端链的 root-of-trust。
///
/// 返回 `Ok(None)` 表示这条链根本没带 ROT 相关的 claim（不是错误，调用方
/// 照旧退回本地值）。EAT 里没有 DER `RootOfTrust` 的 `verifiedBootState`
/// 字段，从 `DEVICE_LOCKED` 推：锁着=Verified(0)，没锁=Unverified(2)。
pub fn root_of_trust(bytes: &[u8]) -> Result<Option<RemoteRootOfTrust>> {
    let claims = parse_claims(bytes)?;
    let Some(Cbor::Bytes(verified_boot_key)) = get(&claims, claim::VERIFIED_BOOT_KEY) else {
        return Ok(None);
    };
    let device_locked = get(&claims, claim::DEVICE_LOCKED)
        .and_then(Cbor::as_bool)
        .unwrap_or(false);
    let verified_boot_hash = get(&claims, claim::VERIFIED_BOOT_HASH)
        .and_then(Cbor::as_bytes)
        .unwrap_or_default()
        .to_vec();
    let attestation_version = get(&claims, claim::ATTESTATION_VERSION)
        .and_then(Cbor::as_int)
        .unwrap_or(0) as i32;
    let keymaster_version = get(&claims, claim::KEYMASTER_VERSION)
        .and_then(Cbor::as_int)
        .unwrap_or(0) as i32;
    Ok(Some(RemoteRootOfTrust {
        verified_boot_key: verified_boot_key.to_vec(),
        device_locked,
        verified_boot_state: if device_locked { 0 } else { 2 },
        verified_boot_hash,
        attestation_version,
        keymaster_version,
    }))
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
        3 => {
            take(buf, pos, arg)?;
            Ok(Cbor::Other)
        }
        4 => {
            for _ in 0..as_count(arg)? {
                value(buf, pos, depth + 1)?;
            }
            Ok(Cbor::Other)
        }
        5 => {
            let mut claims = Vec::new();
            for _ in 0..as_count(arg)? {
                let key = value(buf, pos, depth + 1)?;
                let claim = value(buf, pos, depth + 1)?;
                claims.push((key, claim));
            }
            Ok(Cbor::Map(claims))
        }
        6 => {
            value(buf, pos, depth + 1)?;
            Ok(Cbor::Other)
        }
        7 => match arg {
            20 => Ok(Cbor::Bool(false)),
            21 => Ok(Cbor::Bool(true)),
            // Floats 和别的 simple value，KeyDescription 里用不到。
            _ => Ok(Cbor::Other),
        },
        _ => Ok(Cbor::Other),
    }
}

/// 一个 CBOR item 的 major type 和参数。不定长的保留形式直接拒掉：
/// KeyMint 写的都是定长。
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

#[cfg(test)]
mod tests {
    use super::*;

    fn enc_head(out: &mut Vec<u8>, major: u8, arg: u64) {
        match arg {
            0..=23 => out.push((major << 5) | arg as u8),
            24..=0xff => {
                out.push((major << 5) | 24);
                out.push(arg as u8);
            }
            0x100..=0xffff => {
                out.push((major << 5) | 25);
                out.extend_from_slice(&(arg as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push((major << 5) | 26);
                out.extend_from_slice(&(arg as u32).to_be_bytes());
            }
            _ => {
                out.push((major << 5) | 27);
                out.extend_from_slice(&arg.to_be_bytes());
            }
        }
    }

    /// CBOR 的负数是 `-1 - n`。
    fn enc_int(out: &mut Vec<u8>, value: i64) {
        if value >= 0 {
            enc_head(out, 0, value as u64);
        } else {
            enc_head(out, 1, (-1 - value) as u64);
        }
    }

    fn enc_bytes(out: &mut Vec<u8>, value: &[u8]) {
        enc_head(out, 2, value.len() as u64);
        out.extend_from_slice(value);
    }

    fn enc_bool(out: &mut Vec<u8>, value: bool) {
        out.push(if value { 0xf5 } else { 0xf4 });
    }

    fn enc_root_of_trust(locked: bool, with_hash: bool) -> Vec<u8> {
        let mut out = Vec::new();
        enc_head(&mut out, 5, if with_hash { 3 } else { 2 });
        enc_int(&mut out, claim::VERIFIED_BOOT_KEY);
        enc_bytes(&mut out, &[0xaa; 32]);
        enc_int(&mut out, claim::DEVICE_LOCKED);
        enc_bool(&mut out, locked);
        if with_hash {
            enc_int(&mut out, claim::VERIFIED_BOOT_HASH);
            enc_bytes(&mut out, &[0xbb; 32]);
        }
        out
    }

    #[test]
    fn reads_root_of_trust_out_of_eat() {
        let bytes = enc_root_of_trust(true, true);
        assert!(is_cbor_attestation_extension(&bytes));
        let rot = root_of_trust(&bytes).unwrap().expect("ROT present");
        assert_eq!(rot.verified_boot_key, vec![0xaa; 32]);
        assert!(rot.device_locked);
        // EAT 里没有 verifiedBootState，锁着按 Verified 算。
        assert_eq!(rot.verified_boot_state, 0);
        assert_eq!(rot.verified_boot_hash, vec![0xbb; 32]);
    }

    #[test]
    fn unlocked_root_of_trust_is_unverified() {
        let bytes = enc_root_of_trust(false, true);
        let rot = root_of_trust(&bytes).unwrap().expect("ROT present");
        assert!(!rot.device_locked);
        assert_eq!(rot.verified_boot_state, 2);
    }

    #[test]
    fn missing_hash_claim_is_survivable() {
        let bytes = enc_root_of_trust(true, false);
        let rot = root_of_trust(&bytes).unwrap().expect("ROT present");
        assert!(rot.verified_boot_hash.is_empty());
    }

    #[test]
    fn no_root_of_trust_claims_means_none() {
        let mut out = Vec::new();
        enc_head(&mut out, 5, 1);
        enc_int(&mut out, claim::NONCE);
        enc_bytes(&mut out, b"nonce");
        assert!(root_of_trust(&out).unwrap().is_none());
    }

    #[test]
    fn reads_challenge() {
        let mut out = Vec::new();
        enc_head(&mut out, 5, 1);
        enc_int(&mut out, claim::NONCE);
        enc_bytes(&mut out, b"blind-probe");
        assert_eq!(challenge(&out).unwrap(), b"blind-probe".to_vec());
    }

    #[test]
    fn reads_verified_boot_hash() {
        let bytes = enc_root_of_trust(true, true);
        assert_eq!(verified_boot_hash(&bytes).unwrap(), [0xbb; 32]);
    }

    #[test]
    fn rejects_trailing_data() {
        let mut bytes = enc_root_of_trust(true, true);
        bytes.push(0x00);
        assert!(root_of_trust(&bytes).is_err());
    }

    #[test]
    fn rejects_deep_nesting() {
        // MAX_DEPTH 层数组套下来，里层才放值，应该在爆栈前先被拒。
        let mut out = Vec::new();
        for _ in 0..(MAX_DEPTH + 2) {
            enc_head(&mut out, 4, 1);
        }
        enc_head(&mut out, 0, 0);
        assert!(root_of_trust(&out).is_err());
    }

    #[test]
    fn rejects_indefinite_length() {
        // 0xbf 是不定长 map，KeyMint 不会写这个，直接拒。
        let bytes = [0xbf, 0xff];
        assert!(root_of_trust(&bytes).is_err());
    }

    #[test]
    fn der_starts_with_sequence_byte() {
        assert!(!is_cbor_attestation_extension(&[0x30, 0x82]));
        assert!(is_cbor_attestation_extension(&[0xa1, 0x00]));
        assert!(!is_cbor_attestation_extension(&[]));
    }
}
