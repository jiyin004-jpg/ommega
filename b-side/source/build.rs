use std::{fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=aidl");
    println!("cargo:rerun-if-changed=aidl/vendor/trustonic/hardware/soter");
    println!("cargo:rerun-if-changed=build.rs");

    // The relay / real-TEE forwarding path only needs the keymint HAL types
    // (plus the secureclock *data* types they reference: Timestamp and
    // TimeStampToken). ISecureClock is an async service interface we don't
    // use, and generating it would pull in dyn-compatibility problems on
    // nightly, so it is deliberately not sourced.
    let mut aidl = rsbinder_aidl::Builder::new()
        .include_dir(PathBuf::from("aidl/android/hardware/security/keymint"))
        .include_dir(PathBuf::from("aidl/android/hardware/security/secureclock"))
        // Vendor SOTER HAL: needed for the service lookup (rsbinder stamps the
        // interface descriptor onto the proxy); the traffic itself is
        // marshalled by hand in `src/soter/`.
        .include_dir(PathBuf::from("aidl/vendor/trustonic/hardware/soter"))
        .output(PathBuf::from("aidl.rs"));

    let keymint_dir = "aidl/android/hardware/security/keymint";
    for entry in fs::read_dir(keymint_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) == Some("aidl") {
            aidl = aidl.source(path);
        }
    }

    // Only the data types, not the ISecureClock async service.
    for name in ["Timestamp.aidl", "TimeStampToken.aidl"] {
        let path = PathBuf::from("aidl/android/hardware/security/secureclock").join(name);
        aidl = aidl.source(path);
    }

    let soter_dir = "aidl/vendor/trustonic/hardware/soter";
    for entry in fs::read_dir(soter_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) == Some("aidl") {
            aidl = aidl.source(path);
        }
    }

    aidl.generate().unwrap();

    let generated_path = PathBuf::from(format!("{}/aidl.rs", std::env::var("OUT_DIR").unwrap()));
    let content = fs::read_to_string(&generated_path).unwrap();
    fs::write(&generated_path, &content).unwrap();

    // Best-effort rustfmt on the generated file.
    let _ = Command::new("rustfmt")
        .args([&generated_path.as_os_str().to_string_lossy().to_string()])
        .status();

    // rsbinder-aidl emits a single `#[allow(clippy::all)]` on the *first*
    // top-level module only, so any further package tree it generates (for us:
    // `vendor`) would trip `clippy -- -D warnings` on code we do not own.
    // Give every top-level module the same allow.  The file has just been
    // rustfmt'd, so nested modules are indented and only top-level
    // declarations match here; this never touches a hand-written source.
    if let Ok(content) = fs::read_to_string(&generated_path) {
        let mut patched = String::with_capacity(content.len());
        let mut previous_line_allowed = false;
        for line in content.lines() {
            if line.starts_with("pub mod ") && !previous_line_allowed {
                patched.push_str("#[allow(clippy::all)]\n");
            }
            patched.push_str(line);
            patched.push('\n');
            previous_line_allowed = line == "#[allow(clippy::all)]";
        }
        if patched != content {
            fs::write(&generated_path, patched).unwrap();
        }
    }
}
