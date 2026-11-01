use std::{fs, path::PathBuf, process::Command};

fn add_all_aidl_sources(builder: rsbinder_aidl::Builder, dir: &str) -> rsbinder_aidl::Builder {
    let mut builder = builder;
    let entries = fs::read_dir(dir).unwrap();
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) == Some("aidl") {
            builder = builder.source(path);
        }
    }
    builder
}

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

    let aidl_dirs = [
        "../aidl/android/system/keystore2",
        "../aidl/android/hardware/security/keymint",
        "../aidl/android/hardware/security/secureclock",
        "../aidl/android/security/authorization",
        "../aidl/android/security/maintenance",
        "../aidl/android/security/keystore",
        "../aidl/top/jiyin004/ommega",
        "../aidl/vendor/qti/hardware/soter",
    ];
    let mut aidl = rsbinder_aidl::Builder::new();
    for dir in aidl_dirs {
        aidl = aidl.include_dir(PathBuf::from(dir));
    }
    let mut aidl = aidl.output(PathBuf::from("aidl.rs"));
    for dir in aidl_dirs {
        aidl = add_all_aidl_sources(aidl, dir);
    }

    aidl.generate().unwrap();

    let generated_path = PathBuf::from(format!("{}/aidl.rs", std::env::var("OUT_DIR").unwrap()));
    let content = fs::read_to_string(&generated_path).unwrap();
    // rsbinder-aidl only puts `#[allow(clippy::all)]` on the first package tree it
    // emits, so the later ones (`top`, `vendor`) trip `clippy -- -D warnings` on
    // generated code we do not own (`identity_op` on `FIRST_CALL_TRANSACTION + 0`
    // for the first method of an interface, for one).  Give each of them the same
    // allow; this only ever rewrites the freshly generated file.
    let mut patched_content = content;
    for module in ["android", "top", "vendor"] {
        patched_content = patched_content.replace(
            &format!("\npub mod {module} {{"),
            &format!("\n#[allow(clippy::all)]\n#[allow(unused_imports)]\npub mod {module} {{"),
        );
    }
    let patched_content = patched_content.replace(
        "fn build_parcel_getNumberOfEntries(&self, _arg_domain: super::Domain::Domain, _arg_nspace: i64) -> rsbinder::Result<rsbinder::Parcel>",
        "pub(crate) fn build_parcel_getNumberOfEntries(&self, _arg_domain: super::Domain::Domain, _arg_nspace: i64) -> rsbinder::Result<rsbinder::Parcel>",
    );

    fs::write(&generated_path, &patched_content).unwrap();
}
