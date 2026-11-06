//! 自己跑一遍微信「指纹支付开通」的流程，跟它每一步对齐。
//!
//! 默认走本机真实 HAL；给 `--relay` 就走服务端 `/api/soter/`（跟 A 端 daemon 转发
//! 同一条路，能同时把服务端和 B 端那一串也算进去）。
//!
//! ```text
//! # 本机 HAL：先看现状（不建料）
//! soter_enable_flow --uid 10489 --salt 11d8ba34 --read-only
//!
//! # 真走一遍开通（会建料；别在别人的槽位上乱来）
//! soter_enable_flow --uid 10489 --salt 11d8ba34 --scene 1
//!
//! # 走 relay：服务端 + B 端那条链
//! soter_enable_flow --relay https://server.example:8443 --token <A 端 token> \
//!     --caller-pkg com.tencent.mm --device-id <A 的 device_id> --uid 10496 --salt 11d8ba34
//!
//! # 跑完把材料落盘，拿去 PC 上用 openssl 验链
//! soter_enable_flow --uid 10489 --salt 11d8ba34 --dump /data/local/tmp/soter-flow
//! ```
//!
//! 参数：
//!
//! - `--uid`      宿主应用（微信）的 uid。`am` / `dumpsys package com.tencent.mm` 里能拿到。
//! - `--salt`     账号盐。微信是 `md5(登录 uin)` 十六进制前 8 位；同一台手机换号会变。
//! - `--scene`    场景号，微信注册的是 1 / 2 / 920 / 3。
//! - `--challenge` 十六进制挑战值，不给自己掷。
//! - `--regen`    强制作废现有 AuthKey 再建（微信里的 forceRegen）。
//! - `--reset`    跑之前先把整个 uid 的槽位清掉（微信自救用的 removeAllUidKey，会连坐）。
//! - `--read-only` 只看现状，不建料不删料。
//! - `--no-sign`   只看料，不开签名会话（不占用设备上那张会话）。
//! - `--dump <dir>` 把 ASK / AuthKey / 签名现场落盘（用完记得删）。
//!
//! 验链（在 PC 上，材料从 `--dump` 那个目录拉回来）：
//!
//! ```text
//! openssl dgst -sha256 -verify attk.pem -signature ask.sig \
//!     -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 ask.json
//! openssl dgst -sha256 -verify ask_pub.pem -signature auth.sig \
//!     -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 auth.json
//! openssl dgst -sha256 -verify auth_pub.pem -signature sign.sig \
//!     -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 sign.json
//! ```
//!
//! 三跳都 `Verified OK` 才算这条链自洽（ASK ← ATTK、AuthKey ← ASK、签名 ← AuthKey）。

use anyhow::{anyhow, bail, Context, Result};
use ommegaclient_b::soter::{flow, handle};
use serde_json::{json, Value};
use std::path::Path;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut opts = flow::Options {
        uid: 0,
        ..flow::Options::default()
    };
    let mut relay: Option<String> = None;
    let mut token = String::new();
    let mut device_id = String::new();
    let mut dump: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--uid" => {
                opts.uid = take(&args, &mut i)?.parse().context("--uid 要是数字")?;
            }
            "--salt" => opts.salt = take(&args, &mut i)?,
            "--scene" => {
                opts.scene = take(&args, &mut i)?.parse().context("--scene 要是数字")?;
            }
            "--challenge" => opts.challenge = take(&args, &mut i)?,
            "--regen" => opts.force_regen = true,
            "--reset" => opts.reset = true,
            "--read-only" => opts.allow_mutation = false,
            "--no-sign" => opts.skip_sign = true,
            "--relay" => relay = Some(take(&args, &mut i)?),
            "--caller-pkg" => opts.caller_pkg = Some(take(&args, &mut i)?),
            "--token" => token = take(&args, &mut i)?,
            "--device-id" => device_id = take(&args, &mut i)?,
            "--dump" => dump = Some(take(&args, &mut i)?),
            "-h" | "--help" => {
                println!("用法见文件头注释（examples/soter_enable_flow.rs）");
                return Ok(());
            }
            other => bail!("认不出来的参数 {other}（--help 看用法）"),
        }
        i += 1;
    }
    if opts.uid <= 0 {
        bail!("--uid 必填：微信的 uid（dumpsys package com.tencent.mm | grep userId）");
    }
    token = std::env::var("OMMEGA_RELAY_TOKEN").unwrap_or(token);
    device_id = std::env::var("OMMEGA_RELAY_DEVICE_ID").unwrap_or(device_id);

    println!(
        "目标：uid={} 场景={} 别名={} 建料={} 调用方={}",
        opts.uid,
        opts.scene,
        opts.auth_key_name(),
        if opts.allow_mutation {
            "允许"
        } else {
            "只看"
        },
        opts.caller_pkg.as_deref().unwrap_or("（未声明）")
    );

    let report = match relay.as_deref() {
        None => {
            // HAL 那条路必须先有 binder 进程态，否则 rsbinder 直接 panic。
            let _ = rsbinder::ProcessState::init_default();
            let dump_attk = dump.clone();
            let report = flow::run(|payload| handle(&payload, opts.allow_mutation, 2), &opts)?;
            if let Some(dir) = dump_attk {
                dump_material(&dir, &report, || {
                    handle(&json!({ "op": "export_attk_public_key" }), false, 2)
                })?;
            }
            report
        }
        Some(base) => {
            if token.is_empty() {
                bail!("走 relay 要给 --token（或者 OMMEGA_RELAY_TOKEN）");
            }
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .context("建 HTTP 客户端失败")?;
            let url = format!("{}/api/soter/", base.trim_end_matches('/'));
            let send = |mut payload: Value| -> Result<Value> {
                if let Some(map) = payload.as_object_mut() {
                    if !device_id.is_empty() {
                        map.insert("device_id".to_string(), json!(device_id));
                    }
                }
                let reply = client
                    .post(&url)
                    .header("X-Relay-Token", &token)
                    .json(&payload)
                    .send()
                    .with_context(|| format!("POST {url} 失败"))?;
                let status = reply.status();
                let text = reply.text().unwrap_or_default();
                if !status.is_success() {
                    bail!("relay 回了 {status}：{}", text.trim());
                }
                serde_json::from_str(&text).with_context(|| format!("relay 回的不是 JSON：{text}"))
            };
            let report = flow::run(send, &opts)?;
            if let Some(dir) = dump {
                // relay 这条路上 attk 也走服务端，拿回来一样能验。
                dump_material(&dir, &report, || {
                    let reply = reqwest::blocking::Client::new()
                        .post(&url)
                        .header("X-Relay-Token", &token)
                        .json(&json!({ "op": "export_attk_public_key", "device_id": device_id }))
                        .send()
                        .with_context(|| format!("POST {url} 失败"))?;
                    let text = reply.text().unwrap_or_default();
                    serde_json::from_str(&text)
                        .with_context(|| format!("relay 回的不是 JSON：{text}"))
                })?;
            }
            report
        }
    };

    print!("{}", report.render());
    if report.passed() {
        println!("\n这一轮走通了：建料 → 开签名会话 → 出签名。");
    } else if report.material_ok() {
        println!("\n材料是齐的，卡在签名那一步（看上面 init_sign / finish_sign 那两行）。");
    } else {
        println!("\n材料这一步就没过：微信会删掉重来，也就看不到后面的签名。");
    }
    Ok(())
}

fn take(args: &[String], i: &mut usize) -> Result<String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| anyhow!("{} 后面缺参数", args[*i - 1]))
}

/// 把这一轮的材料落盘：整块 bin、拆开的 json/sig、还有三把公钥。
fn dump_material<F>(dir: &str, report: &flow::Report, attk: F) -> Result<()>
where
    F: FnOnce() -> Result<Value>,
{
    let dir = Path::new(dir);
    std::fs::create_dir_all(dir).with_context(|| format!("建目录 {} 失败", dir.display()))?;

    for (tag, bytes) in &report.artifacts {
        let parsed = flow::parse_envelope(bytes)
            .map_err(|why| anyhow!("{tag} 落盘失败：信封解析不了（{why}）"))?;
        // 签名盖的是原来那一串 JSON 字节，重排/美化之后就对不上了 —— 写成原样切片。
        let json_len = bytes.len() - 4 - parsed.signature_len;
        let sig_at = bytes.len() - parsed.signature_len;
        std::fs::write(dir.join(format!("{tag}.json")), &bytes[4..4 + json_len])?;
        std::fs::write(dir.join(format!("{tag}.sig")), &bytes[sig_at..])?;
        std::fs::write(dir.join(format!("{tag}.bin")), bytes)?;
        if let Some(pub_key) = parsed.doc.get("pub_key").and_then(Value::as_str) {
            std::fs::write(dir.join(format!("{tag}_pub.pem")), pub_key.as_bytes())?;
        }
        println!(
            "落盘：{} 的 json/sig/bin（{} 字节）",
            dir.join(format!("{tag}.bin")).display(),
            bytes.len()
        );
    }

    match attk() {
        Ok(reply) => {
            let text = reply
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    reply.get("data").and_then(Value::as_str).and_then(|b64| {
                        base64_decode(b64)
                            .ok()
                            .and_then(|bytes| String::from_utf8(bytes).ok())
                    })
                });
            match text {
                Some(pem) if pem.contains("BEGIN PUBLIC KEY") => {
                    let path = dir.join("attk.pem");
                    std::fs::write(&path, pem.trim().as_bytes())?;
                    println!("落盘：{}（ATTK 公钥）", path.display());
                }
                _ => println!("ATTK 公钥没拿到，逃过第一跳的验签就先跳过"),
            }
        }
        Err(e) => println!("ATTK 公钥取失败（{e}），跳过第一跳的验签"),
    }

    println!(
        "验链提示：\n\
         openssl dgst -sha256 -verify {0}/attk.pem -signature {0}/ask.sig \\\n\
         \x20   -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 {0}/ask.json",
        dir.display()
    );
    println!("（AuthKey、签名现场同理：换成 ask_pub.pem / auth_pub.pem 那两把公钥）");
    Ok(())
}

fn base64_decode(text: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.decode(text.trim())?)
}
