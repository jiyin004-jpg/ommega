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

const ALIAS: &str = "SoterAuthKeyV2_saltc2e99f57_scene1";
const CHALLENGE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn main() -> Result<()> {
    // 跟 relay 的 main 一样先起 binder 的 ProcessState：`Soter::open()` 会先试 AIDL
    // 那条后端，rsbinder 没初始化就直接 panic（HIDL 那家不需要）。
    let _ = rsbinder::ProcessState::init_default();

    let uid: i32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10503);

    let Some(soter) = Soter::open()? else {
        println!("[direct] uid={uid}: no SOTER service on this device");
        return Ok(());
    };
    println!("[direct] uid={uid} alias={ALIAS}");

    let ask = soter.has_ask_already(uid)?;
    println!("[direct] has_ask_already      -> {ask}");

    let has = soter.has_auth_key(uid, ALIAS)?;
    println!("[direct] has_auth_key         -> {has}");

    let pub_key = soter.export_auth_key_public_key(uid, ALIAS)?;
    println!(
        "[direct] export_auth_key_pub  -> {} ({} bytes)",
        pub_key.error_code,
        pub_key.data.len()
    );

    let session = soter.init_sign(uid, ALIAS, CHALLENGE)?;
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
            let head: Vec<String> = signed.data[..24].iter().map(|b| format!("{b:02x}")).collect();
            println!("[direct]   head: {}", head.join(" "));
        }
    } else {
        println!("[direct] finish_sign          -> skipped (no session)");
    }

    let again = soter.has_auth_key(uid, ALIAS)?;
    println!("[direct] has_auth_key (again) -> {again}");
    Ok(())
}
