use std::{fs, path::PathBuf, vec};

fn main() {
    println!("cargo:rerun-if-changed=aidl");
    println!("cargo:rerun-if-changed=src/proto");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = "src/proto";

    fs::create_dir_all(out_dir).unwrap();

    prost_build::Config::new()
        .out_dir(out_dir)
        .compile_protos(&["proto/storage.proto"], &["proto/"])
        .expect("Failed to compile .proto files");

    let mod_file = format!("{}/mod.rs", out_dir);
    let mod_content = ["storage.rs"]
        .iter()
        .map(|file| format!("pub mod {};", file.trim_end_matches(".rs")))
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&mod_file, mod_content).unwrap();
    let _ = std::process::Command::new("rustfmt")
        .args([&mod_file, &format!("{}/storage.rs", out_dir)])
        .status();

    // AIDL 绑定生成在 ommega lib 里，注入进 keystore2 的 payload 通过
    // `ommega::{android, top, vendor}` 复用同一份类型 —— 进程内那个本地对象
    // 要靠类型对得上来 downcast。
    let mut aidl = rsbinder_aidl::Builder::new()
        .include_dir(PathBuf::from("aidl/android/system/keystore2"))
        .include_dir(PathBuf::from("aidl/android/hardware/security/keymint"))
        .include_dir(PathBuf::from("aidl/android/hardware/security/secureclock"))
        .include_dir(PathBuf::from("aidl/android/security/authorization"))
        .include_dir(PathBuf::from("aidl/android/security/maintenance"))
        .include_dir(PathBuf::from("aidl/android/security/metrics"))
        .include_dir(PathBuf::from("aidl/android/security/keystore"))
        .include_dir(PathBuf::from("aidl/android/apex"))
        .include_dir(PathBuf::from("aidl/android/content/pm"))
        .include_dir(PathBuf::from("aidl/android/os"))
        .include_dir(PathBuf::from("aidl/top/jiyin004/ommega"))
        .include_dir(PathBuf::from("aidl/vendor/qti/hardware/soter"))
        .output(PathBuf::from("aidl.rs"));

    let dirs = vec![
        "aidl/android/system/keystore2",
        "aidl/android/hardware/security/keymint",
        "aidl/android/hardware/security/secureclock",
        "aidl/android/security/authorization",
        "aidl/android/security/maintenance",
        "aidl/android/security/metrics",
        "aidl/android/security/keystore",
        "aidl/android/apex",
        "aidl/android/content/pm",
        "aidl/android/os",
        "aidl/top/jiyin004/ommega",
        "aidl/vendor/qti/hardware/soter",
    ];
    for dir in dirs {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) == Some("aidl") {
                aidl = aidl.source(path);
            }
        }
    }
    aidl.generate().unwrap();

    let generated_path = PathBuf::from(format!("{}/aidl.rs", std::env::var("OUT_DIR").unwrap()));
    let content = fs::read_to_string(&generated_path).unwrap();

    let mut patched_content = content;
    for module in ["android", "top", "vendor"] {
        patched_content = patched_content.replace(
            &format!("\npub mod {module} {{"),
            &format!("\n#[allow(clippy::all)]\n#[allow(unused_imports)]\npub mod {module} {{"),
        );
    }
    // 绑定住在 lib 里，注入进 keystore2 的 payload 要靠这些 transaction code
    // 认拦截到的是哪个方法，所以生成的条目得跨 crate 可见。
    patched_content = patched_content.replace("pub(crate) ", "pub ");

    println!("Generated AIDL content:\n{}", generated_path.display());

    fs::write(&generated_path, &patched_content).unwrap();
}
