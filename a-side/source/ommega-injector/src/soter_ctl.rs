//! 排查模式：`ommega-inject soter-ctl <code> [i32:值] [i64:值] s16:字符串 …`
//!
//! 为什么塞在载荷二进制里而不是单开一个 bin：这个包没有 lib target，单开的 bin
//! 拿不到 crate 里的模块；挂在载荷上还能顺带用同一套参数布局/号码表。
//!
//! 走的是 `hook::soter_ndk`（libbinder_ndk 的真 AIDL 布局）—— `service call`
//! 那个命令行工具一带字符串参数就抛 `0x80000008`，不能用。

use crate::hook::soter_ndk::{transact_with_args, Arg};

/// HAL 注册在 servicemanager 里的名字。
const HAL_SERVICE: &str = "vendor.qti.hardware.soter.ISoter/default";
/// AIDL 的 interface token。
const HAL_INTERFACE: &str = "vendor.qti.hardware.soter.ISoter";

/// 触发文件放的目录。不能放 /data/local/tmp：那条目录是 shell 的 0771，宿主（uid 1000）
/// 连遍历都做不到，读不到也写不进，第一次试就是这么静默失败的。
const TRIGGER_DIR: &str = "/data/misc/ommega";
/// 结果写哪儿。按进程分文件，宿主和 HAL 各写各的，不会互相盖掉 —— 上回两个进程写同一个
/// 文件，谁的结果被后写的顶掉完全看不出来。
const OUT_DIR: &str = "/data/misc/ommega/logs";

/// 这条进程是 SOTER 链条上的哪一环。
///
/// 非分不可，因为两边结果根本不一样：宿主（`com.tencent.soter.soterserver`）发往 HAL 的
/// 事务是**跨进程**的，才会穿过我们挂在 libbinder*.so 上的 ioctl 钩子；HAL 自己调自己
/// （`vendor.qti.hardware.soter-service` 里那个就是本地对象）压根不碰 binder 驱动，钩子
/// 一条都看不见，回来的全是真 HAL 的 `-20 / -5`。所以要看拦截有没有生效、要拿签名，
/// 就得看 host 那一侧的记录。
fn process_role() -> &'static str {
    let cmdline = std::fs::read("/proc/self/cmdline").unwrap_or_default();
    let name: Vec<u8> = cmdline.into_iter().take_while(|byte| *byte != 0).collect();
    let name = String::from_utf8_lossy(&name);
    if name == "com.tencent.soter.soterserver" {
        "host"
    } else if name.contains("soter") {
        "hal"
    } else {
        "other"
    }
}

/// 这次该跑哪个触发文件：先找按进程区分的那份（`soter-sign.host.txt` / `soter-sign.hal.txt`），
/// 再退回通用的 `soter-sign.txt`（那份任何进程都会跑）。都没有就是 `None`。
fn read_trigger(role: &str) -> Option<(String, String)> {
    for path in [
        format!("{TRIGGER_DIR}/soter-sign.{role}.txt"),
        format!("{TRIGGER_DIR}/soter-sign.txt"),
    ] {
        if let Ok(text) = std::fs::read_to_string(&path) {
            return Some((path, text));
        }
    }
    None
}

/// 排查模式：有触发文件就按 SOTER 的流程自己签一遍，一行 `uid alias challenge`。
///
/// 结果写 `{OUT_DIR}/selfsign.{role}.out`。为什么要放在载荷进程里跑：ASK / 授权钥匙那几笔
/// 只有从**宿主**这边发出去，才走得到我们钩子的出站那条路（拿 uid、包名、以及服务端的
/// 真机料），单跑命令行是另一条路。
///
/// 调用点也得跟着讲究：必须在 `hook::init_hook()` 之后（见 `main.rs` 里的 `spawn_self_sign`）。
/// 上回就是放在装钩子之前跑的，宿主那几笔照样打在真 HAL 上 —— 跨进程是跨进程了，可那时
/// GOT 还没改，等于白发。
pub fn maybe_self_sign() {
    let role = process_role();
    let Some((trigger, text)) = read_trigger(role) else {
        log::info!("event=selfsign role={role} 没看到触发文件（这条只在排查时有用）");
        return;
    };
    log::info!(
        "event=selfsign role={role} 看到触发文件 {trigger}，开始跑：{}",
        text.trim()
    );
    let mut fields = text.split_whitespace();
    let uid: i32 = fields
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let alias = fields.next().unwrap_or("probe_selfsign_scene1").to_string();
    let challenge = fields
        .next()
        .unwrap_or("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .to_string();

    let out_path = format!("{OUT_DIR}/selfsign.{role}.out");
    let mut out = String::new();
    out.push_str(&format!(
        "self-sign role={role} pid={} exe={} trigger={trigger}\nuid={uid} alias={alias} challenge={challenge}\n",
        std::process::id(),
        crate::utils::current_exe_path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
    ));
    let step = |out: &mut String, code: u32, args: Vec<Arg<'_>>, label: &str| -> Vec<i32> {
        match transact_with_args(HAL_SERVICE, HAL_INTERFACE, code, &args) {
            Ok((error_code, words)) => {
                let hex: Vec<String> = words
                    .iter()
                    .map(|word| format!("{:08x}", *word as u32))
                    .collect();
                out.push_str(&format!(
                    "{label}(code={code}) error_code={error_code} words=[{}]\n",
                    hex.join(" ")
                ));
                words
            }
            Err(error) => {
                out.push_str(&format!("{label}(code={code}) 调用失败: {error}\n"));
                Vec::new()
            }
        }
    };
    // 5 = generateAskKeyPair：ASK 不在就建一把（上面那四笔全 -5 就是差它）。
    step(&mut out, 5, vec![Arg::I32(uid)], "generateAskKeyPair");
    step(&mut out, 9, vec![Arg::I32(uid)], "hasAskAlready");
    step(
        &mut out,
        7,
        vec![Arg::I32(uid), Arg::Str(&alias)],
        "generateAuthKeyPair",
    );
    step(
        &mut out,
        10,
        vec![Arg::I32(uid), Arg::Str(&alias)],
        "hasAuthKey",
    );
    let words = step(
        &mut out,
        11,
        vec![Arg::I32(uid), Arg::Str(&alias), Arg::Str(&challenge)],
        "initSign",
    );
    // initSign 的答复：第一个字是真错误码，后面是 session（高 32 位在前）。
    let real_code = words.first().copied().unwrap_or(i32::MIN);
    if real_code == 0 && words.len() >= 3 {
        let session = ((words[1] as u32 as u64) << 32 | (words[2] as u32 as u64)) as i64;
        out.push_str(&format!("session={session}\n"));
        step(&mut out, 4, vec![Arg::I64(session)], "finishSign");
    } else {
        out.push_str(&format!(
            "initSign 没成功（真码 {real_code}），不调 finishSign\n"
        ));
    }
    step(
        &mut out,
        3,
        vec![Arg::I32(uid), Arg::Str(&alias)],
        "exportAuthKeyPublicKey",
    );
    let _ = std::fs::write(&out_path, &out);
    log::info!("event=selfsign role={role} 跑完了，结果写到 {out_path}：{out}");
}

/// 返回进程退出码。
pub fn run(args: &[String]) -> i32 {
    let Some(code) = args.first().and_then(|value| value.parse::<u32>().ok()) else {
        eprintln!("用法: soter-ctl <code> [i32:值] [i64:值] s16:字符串 …");
        return 2;
    };
    let mut parsed: Vec<Arg<'_>> = Vec::new();
    for spec in args.iter().skip(1) {
        let mut parts = spec.splitn(2, ':');
        let kind = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        match kind {
            "i32" => match value.parse::<i32>() {
                Ok(v) => parsed.push(Arg::I32(v)),
                Err(error) => {
                    eprintln!("{spec}: {error}");
                    return 2;
                }
            },
            "i64" => match value.parse::<i64>() {
                Ok(v) => parsed.push(Arg::I64(v)),
                Err(error) => {
                    eprintln!("{spec}: {error}");
                    return 2;
                }
            },
            "s16" => parsed.push(Arg::Str(value)),
            other => {
                eprintln!("不认识的参数类型 {other}");
                return 2;
            }
        }
    }
    match transact_with_args(HAL_SERVICE, HAL_INTERFACE, code, &parsed) {
        Ok((error_code, words)) => {
            let hex: Vec<String> = words
                .iter()
                .map(|word| format!("{:08x}", *word as u32))
                .collect();
            println!(
                "code={code} error_code={error_code} words=[{}]",
                hex.join(" ")
            );
            if error_code == 0 {
                println!("OK: 这一笔 HAL 认了");
            }
            0
        }
        Err(error) => {
            eprintln!("code={code} 调用失败: {error}");
            1
        }
    }
}
