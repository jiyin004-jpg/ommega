//! 绕过服务端/钉子，直接对着设备上的 SOTER HAL 问一遍完整流程。
//!
//! 用来回答一个问题：某个 uid 的 `finish_sign` 拿到某个错误码，到底是不是
//! 「TA 这边的状态不对」，还是被服务端换层后的结果。
//!
//! ```text
//! adb push target/aarch64-linux-android/release/examples/soter_direct /data/local/tmp/
//! adb shell su -c /data/local/tmp/soter_direct [uid]
//! ```

use anyhow::Result;

use ommegaclient_b::soter::hal::Soter;

const DEFAULT_ALIAS: &str = "SoterAuthKeyV2_saltc2e99f57_scene1";
const CHALLENGE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// 一段数据的短指纹（FNV-1a 64）。用来比「两次铸造是不是同一把钥匙」：
/// 只看头几个字节会被 JSON/PEM 包装骗到，看签名又带随机数。
fn fingerprint(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn main() -> Result<()> {
    // 跟 relay 的 main 一样先起 binder 的 ProcessState：`Soter::open()` 会先试 AIDL
    // 那条后端，rsbinder 没初始化就直接 panic（HIDL 那家不需要）。
    let _ = rsbinder::ProcessState::init_default();

    let uid: i32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10503);
    // 第二个参数是 alias：换 uid 时得跟着换，比如设备本地 App 自己用的那份。
    let alias = std::env::args()
        .nth(2)
        .unwrap_or_else(|| DEFAULT_ALIAS.to_string());
    // 第三个参数是模式：`gen` 先现造一份材料再看能不能签，`rm` 收尾把这个 uid 的钥匙清掉。
    let mode = std::env::args().nth(3).unwrap_or_default();

    let Some(soter) = Soter::open()? else {
        println!("[direct] uid={uid}: no SOTER service on this device");
        return Ok(());
    };
    println!(
        "[direct] uid={uid} alias={alias} mode={}",
        if mode.is_empty() { "probe" } else { &mode }
    );

    // 真机自己报的设备号：鸭子那条「known relay cpu_id」看的就是它。
    // 先把这一条打出来，才好跟文档里的 `cpu_id` 对齐。
    let device_id = soter.get_device_id()?;
    println!(
        "[direct] get_device_id        -> {} text={:?} bytes={}",
        device_id.error_code,
        device_id.text(),
        device_id.data.len()
    );

    if mode == "gen" {
        let ask = soter.generate_ask_key_pair(uid)?;
        println!("[direct] generate_ask_key_pair -> {ask}");
        let auth = soter.generate_auth_key_pair(uid, &alias)?;
        println!("[direct] generate_auth_key_pair-> {auth}");
        let ask_pub = soter.export_ask_public_key(uid)?;
        println!(
            "[direct] export_ask_public_key   -> {} ({} bytes) fp={}",
            ask_pub.error_code,
            ask_pub.data.len(),
            fingerprint(&ask_pub.data)
        );
    }

    let ask = soter.has_ask_already(uid)?;
    println!("[direct] has_ask_already      -> {ask}");

    let has = soter.has_auth_key(uid, &alias)?;
    println!("[direct] has_auth_key         -> {has}");

    let pub_key = soter.export_auth_key_public_key(uid, &alias)?;
    println!(
        "[direct] export_auth_key_pub  -> {} ({} bytes)",
        pub_key.error_code,
        pub_key.data.len()
    );
    // 公钥的指纹：同一个 (uid, alias) 重铸之后是不是同一把钥匙，只能靠它判定
    // （前几十字节是 JSON/PEM 包装，谁铸都一样；签名还带随机数，也比不了）。
    if !pub_key.data.is_empty() {
        println!("[direct]   pub_key fp: {}", fingerprint(&pub_key.data));
    }

    let session = soter.init_sign(uid, &alias, CHALLENGE)?;
    println!(
        "[direct] init_sign            -> {} session={}",
        session.error_code, session.session
    );

    if session.error_code == 0 && session.session != 0 {
        let signed = soter.finish_sign(session.session)?;
        println!(
            "[direct] finish_sign          -> {} ({} bytes)",
            signed.error_code,
            signed.data.len()
        );
        if signed.data.len() > 24 {
            let head: Vec<String> = signed.data[..24]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            println!("[direct]   head: {}", head.join(" "));
        }
    } else {
        println!("[direct] finish_sign          -> skipped (no session)");
    }

    let again = soter.has_auth_key(uid, &alias)?;
    println!("[direct] has_auth_key (again) -> {again}");

    if mode == "rm" {
        let removed = soter.remove_all_uid_key(uid)?;
        println!("[direct] remove_all_uid_key    -> {removed}");
    }
    Ok(())
}
