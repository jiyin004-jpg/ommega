//! Captured SOTER HAL replies, plus a decoder self-test.
//!
//! Every constant below is the raw reply parcel of one SOTER transaction, as
//! dumped by the platform `service call` tool on a live OPPO PLC110 (Android
//! 16, Trustonic SOTER HAL V1).  They are what makes the hand-written decoder
//! in [`super::hal`] verifiable: [`selftest`] decodes all of them and reports
//! what it found, so the forwarding path can be checked on a device (via the
//! `selftest` op) or in a unit test without touching the HAL again.
//!
//! They also document the payload conventions of the data-carrying methods:
//!
//! * `getDeviceId`   -> 32 hex characters + NUL
//! * `exportAttkPublicKey` -> a PEM `PUBLIC KEY` block
//! * `exportAskPublicKey`  -> `[i32 json length][json][TEE signature]`

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::Parcel;
use serde_json::{json, Value};

use super::hal::{read_soter_data, read_status, Backend, SoterData};

/// Device id contained in the captures (also the value `getDeviceId` returns).
pub const DEVICE_ID: &str = "090000005171734c42866bea148b21f5";

/// Reply of `getDeviceId()` (60 bytes).
pub const DEVICE_ID_REPLY: &str = concat!(
    "000000000100000034000000000000002100000030393030303030303531373137333463343238363662656131343862",
    "323166350000000021000000"
);

/// Reply of `exportAttkPublicKey()` (476 bytes: RSA-2048 PEM, 450 payload bytes).
pub const ATTK_REPLY: &str = concat!(
    "0000000001000000d401000000000000c20100002d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d",
    "494942496a414e42676b71686b6947397730424151454641414f43415138414d49494243674b43415145417579763879",
    "48387a58656e5848356669587253300a3572766a34796e3667716e504535634658467136587550306c6d495463474369",
    "456832683164363973563665313341484d4c30774d3348525531734a3378444f0a44414a345631424c37705772626f59",
    "556c6436595041314f516455796f55544d3339742f326b304d6c4a647739667a3578305531314474336d334b75344c57",
    "510a6535382f46766a733458546a6e755473426c44426e30597272696558505a5a494e354a7a5a5574385357416f5673",
    "3750616f554f2f413378735a77766c4a46340a576756743869556d33466374386b7458736e635453626958564a2f6b2b",
    "6d55692b37595638736c46717570323965554132795a746d4d497a576e7769374169390a4859355756446445692b2b71",
    "61744a72574452774e4651594d7744626844534b55444f6b61357533634438335670694e6f6964414a622b5238534b4c",
    "624d62520a31514944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0000c2010000"
);

/// Reply of `exportAskPublicKey(10373)` (852 bytes: 826 payload bytes, made of a
/// 566-byte JSON document followed by a 256-byte TEE signature).
pub const ASK_REPLY: &str = concat!(
    "00000000010000004c030000000000003a030000360200007b227075625f6b6579223a222d2d2d2d2d424547494e2050",
    "55424c4943204b45592d2d2d2d2d5c6e4d494942496a414e42676b71686b6947397730424151454641414f4341513841",
    "4d49494243674b4341514541736a73634a794634464c365565637874347735585c6e6d766f6a6f634f436a682b594257",
    "6844645938537a794641344b6e6d4c41534436697068477038554b594a6330624d52384f585358594b41444c6a734d36",
    "74765c6e575133633862346573576b446535694164502b365a6a49463445504762314c5555646a325a3148646e365867",
    "65743048615530525254514261714d50463654395c6e554a55744f576a4a2f377862314b4d6350386130327a7231644f",
    "33364b6e696c61666843394f57477335584d2b455836396f653172366b484d704f733474345a5c6e6b672b50642f4570",
    "7859586555434d71386761745a716a61494e75773666554a6e64657a7a71464e536a76336e68596e6d486c4f414b4e4d",
    "53354369785035715c6e7142686c5745692f7674734f4e54585164526972556766317465495542497754542f5870444e",
    "646f656c652f6a566642535439446b6c4574526e736d4d395a6b5c6e4f774944415141425c6e2d2d2d2d2d454e442050",
    "55424c4943204b45592d2d2d2d2d222c226370755f6964223a2230393030303030303531373137333463343238363662",
    "65613134386232316635222c22636f756e746572223a373339302c22756964223a223130333733222c227273615f7073",
    "735f73616c746c656e223a33327d5d26ca65ede6ad86ff06bc44bef37d6acd1ee42f14b484f448d718583a0f14063925",
    "87d358d75b758f8c5604a31d8fdd37bbcc54cc28b1275e9ce0b177f1f5448b40db036f0e3e047f9e85e6c7b3e91eb721",
    "c999377007c70d20b4cdb4683f932fefc59769be71c73e33b9eed3ee24ff7b0a45900e835319c3d07e163856e7dcd391",
    "568fcfe37bb9f7a4814c46063fba9d2cf7d5928d0af09f9b80f438932a93bf9594164ec4fdbf280d1412bf7ab86b55f7",
    "e0436369c1cbf7fe0b7f608e5e6963682cd86e051e133f1f1d3b732fbd537543d95af31454b2c06df2530ccbf676a29d",
    "2c838869b53d31b993eb00d6ae287410d08c19b29d7c02afe05a7184069200003a030000"
);

/// Decode a `SoterData` reply captured as hex.
pub fn decode_soter_data_reply(hex: &str) -> Result<SoterData> {
    decode_soter_data_reply_as(hex, Backend::Trustonic)
}

/// Same, for a given vendor backend (the outer framing differs, see [`super::hal`]).
pub fn decode_soter_data_reply_as(hex: &str, backend: Backend) -> Result<SoterData> {
    let mut parcel = Parcel::from_vec(hex_decode(hex)?);
    read_status(&mut parcel)?;
    read_soter_data(&mut parcel, backend)
}

/// Decode hex, rejecting anything that is not a whole number of bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        bail!("hex string has an odd length ({})", hex.len());
    }
    let src = hex.as_bytes();
    let mut out = Vec::with_capacity(src.len() / 2);
    let mut i = 0;
    while i < src.len() {
        out.push((hex_nibble(src[i])? << 4) | hex_nibble(src[i + 1])?);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        other => bail!("not a hex digit: {:?}", other as char),
    }
}

/// Run the decoder over every captured reply.
///
/// Returns `{"ok": bool, "checks": [...]}`; a failing check carries the reason
/// instead of aborting, so one bad fixture does not hide the others.
pub fn selftest() -> Value {
    let checks = vec![
        check_device_id(),
        check_attk(),
        check_ask(),
        check_qti_framing(),
    ];
    let ok = checks.iter().all(|c| c.get("ok") == Some(&json!(true)));
    json!({ "ok": ok, "checks": checks })
}

fn check(name: &str, run: impl FnOnce() -> Result<Value>) -> Value {
    match run() {
        Ok(detail) => json!({ "name": name, "ok": true, "detail": detail }),
        Err(e) => json!({ "name": name, "ok": false, "error": format!("{e:#}") }),
    }
}

fn check_device_id() -> Value {
    check("getDeviceId reply", || {
        let data = decode_soter_data_reply(DEVICE_ID_REPLY)?;
        if data.error_code != 0 {
            bail!("error code {} (expected 0)", data.error_code);
        }
        let text = data.text().ok_or_else(|| anyhow!("payload is not UTF-8"))?;
        if text != DEVICE_ID {
            bail!("device id {text:?} does not match {DEVICE_ID:?}");
        }
        if data.length != 33 {
            bail!("length field {} (expected 33)", data.length);
        }
        Ok(json!({ "error_code": data.error_code, "length": data.length, "device_id": text }))
    })
}

fn check_attk() -> Value {
    check("exportAttkPublicKey reply", || {
        let data = decode_soter_data_reply(ATTK_REPLY)?;
        if data.error_code != 0 {
            bail!("error code {} (expected 0)", data.error_code);
        }
        let text = data.text().ok_or_else(|| anyhow!("payload is not UTF-8"))?;
        if !text.starts_with("-----BEGIN PUBLIC KEY-----")
            || !text.trim_end().ends_with("-----END PUBLIC KEY-----")
        {
            bail!("payload does not look like a PEM public key");
        }
        if data.length != 450 {
            bail!("length field {} (expected 450)", data.length);
        }
        Ok(
            json!({ "error_code": data.error_code, "length": data.length, "pem_bytes": data.data.len() }),
        )
    })
}

fn check_ask() -> Value {
    check("exportAskPublicKey reply", || {
        let data = decode_soter_data_reply(ASK_REPLY)?;
        if data.error_code != 0 {
            bail!("error code {} (expected 0)", data.error_code);
        }
        if data.length != 826 {
            bail!("length field {} (expected 826)", data.length);
        }
        let json_len = json_length(&data.data)?;
        let json_bytes = &data.data[4..4 + json_len];
        let doc: Value = serde_json::from_slice(json_bytes).context("parse the inner JSON")?;
        let cpu_id = doc
            .get("cpu_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if cpu_id != DEVICE_ID {
            bail!("inner cpu_id {cpu_id:?} does not match {DEVICE_ID:?}");
        }
        let signature_bytes = data.data.len() - 4 - json_len;
        Ok(json!({
            "error_code": data.error_code,
            "length": data.length,
            "json_bytes": json_len,
            "signature_bytes": signature_bytes,
            "uid": doc.get("uid").cloned().unwrap_or(Value::Null),
            "counter": doc.get("counter").cloned().unwrap_or(Value::Null),
        }))
    })
}

/// The Qualcomm framing: `[status][returnCode][notNull][totalSize][byte[]][length]`.
///
/// Not a device capture — the bytes are hand-built from the SOTER host APK's own
/// parcelable (`b.b`: size header, `byte[]`, length), which is exactly what a
/// Qualcomm HAL has to be writing for that host to read it back.  Keeps
/// `read_soter_data` pinned to that layout, and checks that the Trustonic framing
/// refuses the same bytes (it is one leading value and four bytes of totalSize
/// away, so a silent mix-up would otherwise decode into plausible nonsense).
fn check_qti_framing() -> Value {
    check("qti SoterData framing", || {
        const ID: &str = "0123456789abcdef0123456789abcdef";
        let mut bytes: Vec<u8> = Vec::new();
        for field in [0i32, 0, 1, 48, 33] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        bytes.extend_from_slice(ID.as_bytes());
        bytes.extend_from_slice(&[0u8; 4]); // NUL terminator plus padding to 36
        bytes.extend_from_slice(&33i32.to_le_bytes());
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

        let data = decode_soter_data_reply_as(&hex, Backend::Qti)?;
        if data.error_code != 0 {
            bail!("error code {} (expected 0)", data.error_code);
        }
        if data.length != 33 {
            bail!("length field {} (expected 33)", data.length);
        }
        let text = data.text().ok_or_else(|| anyhow!("payload is not UTF-8"))?;
        if text != ID {
            bail!("device id {text:?} does not match {ID:?}");
        }
        if decode_soter_data_reply(&hex).is_ok() {
            bail!("the Trustonic framing accepted a qti reply");
        }
        Ok(json!({ "error_code": data.error_code, "length": data.length, "device_id": text }))
    })
}

/// Split `[i32 json length][json][signature]` and return the JSON length.
fn json_length(data: &[u8]) -> Result<usize> {
    if data.len() < 4 {
        bail!("payload is too short to hold a JSON length prefix");
    }
    let len = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if len <= 0 || 4 + len as usize > data.len() {
        bail!("inner JSON length {len} does not fit the payload");
    }
    Ok(len as usize)
}

/// Split an `exportAskPublicKey` payload into its JSON document and signature.
pub fn split_ask_payload(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let json_len = json_length(data)?;
    Ok((&data[4..4 + json_len], &data[4 + json_len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_reply_decodes() {
        let data = decode_soter_data_reply(DEVICE_ID_REPLY).expect("decode device id reply");
        assert_eq!(data.error_code, 0);
        assert_eq!(data.length, 33);
        assert_eq!(data.data.len(), 33);
        assert_eq!(data.text(), Some(DEVICE_ID));
    }

    #[test]
    fn attk_reply_decodes() {
        let data = decode_soter_data_reply(ATTK_REPLY).expect("decode attk reply");
        assert_eq!(data.error_code, 0);
        assert_eq!(data.length, 450);
        assert_eq!(data.data.len(), 450);
        assert!(data
            .text()
            .expect("utf-8")
            .starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn ask_reply_decodes() {
        let data = decode_soter_data_reply(ASK_REPLY).expect("decode ask reply");
        assert_eq!(data.error_code, 0);
        assert_eq!(data.length, 826);
        let (doc_bytes, signature) = split_ask_payload(&data.data).expect("split ask payload");
        assert_eq!(doc_bytes.len(), 566);
        assert_eq!(signature.len(), 256);
        let doc: Value = serde_json::from_slice(doc_bytes).expect("parse ask json");
        assert_eq!(doc["cpu_id"].as_str(), Some(DEVICE_ID));
        assert_eq!(doc["uid"].as_str(), Some("10373"));
    }

    #[test]
    fn selftest_passes_on_captured_replies() {
        let report = selftest();
        assert_eq!(report["ok"], json!(true), "selftest report: {report}");
    }
}
