//! 量一下 status 页那条"解析证书链"的活儿到底多贵。
//!
//! `TaskStore::complete_task` 在唤醒等待中的 A 端之前，会拿结果里的 leaf 证书
//! 走一遍 `cert::device_boot_info_from_chain` + `attestation_application_id_from_chain`，
//! 而这两步是在 `inner` 锁里同步做的。这脚本拿真机链跑同一对函数，给出单次耗时，
//! 好判断"先解析再通知"这笔账值不值。
//!
//! 用法：cargo run --example bench_boot_parse -- <leaf.der> [iters]

use base64::Engine as _;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: bench_boot_parse <leaf.der|leaf.pem|leaf_b64.txt> [iters]");
        std::process::exit(2);
    });
    let iters: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(20_000);

    // 接受三种喂法：原始 DER、PEM、已经是 base64 的文本 —— 哪个顺手给哪个。
    let raw = std::fs::read(&path).expect("read leaf");
    let b64 = if raw.starts_with(b"-----BEGIN") {
        let pem = String::from_utf8_lossy(&raw);
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .map(|der| base64::engine::general_purpose::STANDARD.encode(&der))
            .expect("pem body")
    } else if raw.starts_with(b"{") || raw.starts_with(b"\x30") {
        base64::engine::general_purpose::STANDARD.encode(&raw)
    } else {
        String::from_utf8(raw).expect("utf8 base64")
    };
    println!("source={path}");
    println!("leaf_b64_len={} (der~{})", b64.len(), b64.len() * 3 / 4);

    // 先暖一遍，把 lazy 初始化和页错误甩掉，再计时。
    for _ in 0..500 {
        std::hint::black_box(relay_rs::cert::device_boot_info_from_chain(&b64));
        std::hint::black_box(relay_rs::cert::attestation_application_id_from_chain(&b64));
    }

    let t0 = std::time::Instant::now();
    let mut with_boot = 0u32;
    let mut with_aaid = 0u32;
    let mut first_info: Option<relay_rs::cert::DeviceBootInfo> = None;
    for _ in 0..iters {
        let info = relay_rs::cert::device_boot_info_from_chain(&b64);
        let aaid = relay_rs::cert::attestation_application_id_from_chain(&b64);
        if info.is_some() {
            with_boot += 1;
            if first_info.is_none() {
                first_info = info.clone();
            }
        }
        if aaid.is_some() {
            with_aaid += 1;
        }
        std::hint::black_box(info);
        std::hint::black_box(aaid);
    }
    let total = t0.elapsed();
    let per = total.as_secs_f64() * 1e6 / iters as f64;
    println!(
        "{iters} iters in {total:?} -> {per:.2} us/iter (pair of parses, both on the same leaf)"
    );
    println!("boot_info=Some {with_boot}/{iters}, aaid=Some {with_aaid}/{iters}");
    if let Some(info) = first_info {
        println!(
            "sample: locked={:?} verified_boot_state={:?} aaid={:?} knox={} sec_level={:?}",
            info.device_locked,
            info.verified_boot_state,
            info.aaid,
            info.knox.is_some(),
            info.security_level
        );
    }
}
