//! Fire one real SOTER request at the Qualcomm HAL, to give the observer something to see.
//!
//! Why this exists: the A-side SOTER host is a bind-only Java service, so nothing outside an
//! app can drive it, and `service call` cannot reach a vendor AIDL interface either. When the
//! question is "does `event=soter` come out at all", the only way to answer it without waiting
//! for an app to do something is to call the HAL directly -- which the hook sees when it is
//! injected into the HAL process rather than into the host.
//!
//! Only non-mutating transactions are sent by default: `getDeviceId` (8) and `hasAskAlready`
//! (9). `exportAuthKeyPublicKey` (3) is a read, but the HAL re-signs its answer, so it walks
//! the device's TEE signature counter -- it needs an explicit `--export` to be sent at all.
//! Nothing here generates or deletes a key.
//!
//! ```text
//! cargo build --target aarch64-linux-android --example soter_hal_probe
//! adb push target/aarch64-linux-android/release/examples/soter_hal_probe /data/local/tmp/
//! adb shell su -c '/data/local/tmp/soter_hal_probe [--uid N] [--alias A] [--repeat N]'
//! ```
//!
//! `--repeat` exists for the observer's sake: this process can be injected like any other
//! target, and the injector needs requests to keep arriving while it attaches.

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use anyhow::{Context, Result};
use rsbinder::{FromIBinder, Strong};
use vendor::qti::hardware::soter::ISoter::ISoter;

/// The vendor AIDL instance the SOTER host itself talks to.
const SERVICE: &str = "vendor.qti.hardware.soter.ISoter/default";
/// WeChat on this device; a uid that already owns SOTER keys, so the answers are interesting.
const DEFAULT_UID: i32 = 10490;
const DEFAULT_ALIAS: &str = "ommega-probe";

fn main() -> Result<()> {
    let mut service = SERVICE.to_string();
    let mut uid = DEFAULT_UID;
    let mut alias = DEFAULT_ALIAS.to_string();
    let mut export = false;
    let mut repeat = 1u32;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Aim the same SOTER-shaped request at a different process. Pointing it at
            // `android.system.keystore2.IKeystoreService/default` is how the observer's
            // *incoming* path gets exercised without an app: the payload is already inside
            // keystore2, it just sees a transaction it has no idea what to do with.
            "--service" => service = args.next().context("--service wants a value")?,
            "--uid" => {
                uid = args
                    .next()
                    .context("--uid wants a value")?
                    .parse()
                    .context("--uid wants an integer")?;
            }
            "--alias" => alias = args.next().context("--alias wants a value")?,
            "--export" => export = true,
            "--repeat" => {
                repeat = args
                    .next()
                    .context("--repeat wants a value")?
                    .parse()
                    .context("--repeat wants an integer")?;
            }
            other => println!("ignoring unknown argument {other}"),
        }
    }

    // A binder process state has to exist before any transaction is possible.
    let _ = rsbinder::ProcessState::init_default();

    let binder = rsbinder::hub::check_service(&service)
        .with_context(|| format!("{service} is not registered"))?;
    let soter: Strong<dyn ISoter> = <dyn ISoter as FromIBinder>::try_from(binder)
        .with_context(|| format!("{service} does not answer as ISoter"))?;

    // Answers are deliberately not read: the AIDL here declares everything as void, so the
    // reply is dropped by the framework. The point is the request that leaves this process.
    for round in 1..=repeat {
        println!("round {round}/{repeat}");
        println!("sending code=8 getDeviceId to {service}");
        soter.getDeviceId().context("getDeviceId failed")?;
        println!("sending code=9 hasAskAlready uid={uid}");
        soter.hasAskAlready(uid).context("hasAskAlready failed")?;
        if export {
            println!("sending code=3 exportAuthKeyPublicKey uid={uid} alias={alias} (advances the TEE counter)");
            soter
                .exportAuthKeyPublicKey(uid, &alias)
                .context("exportAuthKeyPublicKey failed")?;
        } else if round == 1 {
            println!("skipping code=3 exportAuthKeyPublicKey (pass --export to send it)");
        }
        if round != repeat {
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }
    println!("done");
    Ok(())
}
