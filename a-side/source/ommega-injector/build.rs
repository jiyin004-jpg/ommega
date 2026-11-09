use std::{fs, path::PathBuf, process::Command};

fn ensure_soter_attk() {
    let path = PathBuf::from("assets/soter_attk.pem");
    println!("cargo:rerun-if-changed={}", path.display());
    if path.exists() {
        return;
    }
    // 发版时由 build.py 用当时时间现生成一把；这里只给直接 cargo build/clippy/test
    // （CI 的 gate 那种）兜底，免得 include_bytes! 找不到文件。
    fs::create_dir_all("assets").ok();
    let status = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
        ])
        .arg(&path)
        .status();
    match status {
        Ok(status) if status.success() => {
            println!("cargo:warning=generated a local ATTK at {}", path.display());
        }
        _ => panic!(
            "assets/soter_attk.pem is missing and openssl could not create one; install openssl or run a-side/source/build.py"
        ),
    }
}

fn main() {
    ensure_soter_attk();
    println!("cargo:rerun-if-changed=../aidl");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rustc-link-arg-bin=ommega-inject=-Wl,--export-dynamic-symbol=entry");

    let build_target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
    let package_version =
        std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown-version".to_string());
    let git_sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-git".to_string());
    let build_id = format!("{package_version}-{git_sha}-{build_target}");

    println!("cargo:rustc-env=INJECTOR_BUILD_TARGET={build_target}");
    println!("cargo:rustc-env=INJECTOR_BUILD_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=INJECTOR_BUILD_ID={build_id}");

    // AIDL 绑定统一在 ommega-aidl 里生成一次，见该 crate 的 build.rs。
}
