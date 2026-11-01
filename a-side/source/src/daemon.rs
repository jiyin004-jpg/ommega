//! keymint 守护进程（`keymint --daemon`）。
//!
//! 替代原来的 `template/daemon` shell 脚本。那版每 10 秒要跑十几次 fork
//! （`grep` 读配置、若干次 `sed` 读身份文件、`getprop` 读属性、必要时 `resetprop`
//! 写），实测光这一个 shell 就吃 4.9% CPU。这里全部改成直接读文件 + 直接比较，
//! 只有真的要写属性时才 exec 一次。
//!
//! 职责和 shell 版一一对应：
//!   - 单实例（`run/keymint-daemon.lock`，带 pid 归属校验，防 PID 复用误判）；
//!   - 定位 keymint 二进制（`bin/` → 模块根 → `libs/<abi>/`）；
//!   - 干掉残留实例、导出出证要用的几个属性、拉起 keymint、盯着它；
//!   - 每 10 秒把 `remote_identity` 里的身份/哈希/boot 补丁同步到本机属性（幂等）；
//!   - `run/restart.keymint` 出现就重启 keymint（面板操作 / watchdog 触发）。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use crate::plat::resetprop;

const STATE_DIR: &str = "/data/adb/ommega";
const RUN_DIR: &str = "/data/adb/ommega/run";
const MODDIR: &str = "/data/adb/modules/ommega";

const CONF_PATH: &str = "/data/misc/ommega/config";
const LOG_FILE: &str = "/data/misc/ommega/logs/daemon.log";
const REMOTE_IDENTITY: &str = "/data/misc/ommega/remote_identity";
const REMOTE_IDENTITY_APPLIED: &str = "/data/adb/ommega/conf/remote_identity.applied";
const REMOTE_IDENTITY_UPDATED: &str = "/data/adb/ommega/conf/remote_identity.updated";
const PROPS_CONF: &str = "/data/adb/ommega/conf/props.conf";

const RESTART_FILE: &str = "/data/adb/ommega/run/restart.keymint";
const PEER_RESTART_FILE: &str = "/data/adb/ommega/run/restart.injector";
const RESTART_ALL_FILE: &str = "/data/adb/ommega/run/restart.all";
const LOCK_DIR: &str = "/data/adb/ommega/run/keymint-daemon.lock";

/// 身份同步周期。同步的是「链里声明的身份」，只在远程出证时才变一次，
/// 10 秒足够快，也不至于把 CPU 耗在这上面。
const SYNC_INTERVAL: Duration = Duration::from_secs(10);
/// 子进程存活检查周期（比同步密，重启请求能尽快生效）。
const TICK: Duration = Duration::from_secs(1);

const KEYMINT_ENV: [&str; 5] = [
    "ro.boot.vbmeta.digest",
    "ro.boot.vbmeta.public_key_digest",
    "ro.build.version.security_patch",
    "ro.vendor.build.security_patch",
    "ro.boot.build.security_patch",
];

/// 守护进程入口。`extra` 是原始参数里除 `--daemon` 以外的部分，原样交给 keymint。
pub fn run(extra: Vec<String>) -> ! {
    if !acquire_singleton() {
        log("another instance is running; exiting");
        std::process::exit(0);
    }
    log("keymint daemon started");

    loop {
        let Some(target) = find_keymint() else {
            log("keymint binary not found");
            sleep(Duration::from_secs(5));
            continue;
        };
        stop_stale_instances(&target);

        let mut child = match spawn_keymint(&target, &extra) {
            Ok(child) => child,
            Err(error) => {
                log(&format!("failed to start {}: {error}", target.display()));
                sleep(Duration::from_secs(5));
                continue;
            }
        };
        log(&format!("keymint started (pid {})", child.id()));

        let mut last_sync = std::time::Instant::now();
        loop {
            if take_restart_request() {
                log("restart requested");
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            if last_sync.elapsed() >= SYNC_INTERVAL {
                last_sync = std::time::Instant::now();
                sync_remote_identity();
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    log(&format!("keymint exited ({status})"));
                    break;
                }
                Ok(None) => sleep(TICK),
                Err(error) => {
                    log(&format!("wait failed: {error}"));
                    break;
                }
            }
        }
        sleep(Duration::from_secs(2));
    }
}

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------

/// 只在面板开了「调试日志」时才落文件 —— 开关每轮现读，跟 shell 版一致。
fn log(message: &str) {
    if !debug_logging() {
        return;
    }
    if let Some(parent) = Path::new(LOG_FILE).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stamp = utc_stamp(secs);
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)
    {
        use std::io::Write;
        let _ = writeln!(file, "{stamp} [INFO] {message}");
    }
}

fn utc_stamp(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    let secs = epoch % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Howard Hinnant 的 `civil_from_days`（`days_from_civil` 的反向）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

fn debug_logging() -> bool {
    let Ok(text) = fs::read_to_string(CONF_PATH) else {
        return false;
    };
    config_value(&text, "debug_logging").is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// 平铺配置里 `key: value` 的第一个值。
fn config_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        (k.trim() == key).then(|| v.trim())
    })
}

// ---------------------------------------------------------------------------
// 单实例
// ---------------------------------------------------------------------------

fn acquire_singleton() -> bool {
    let _ = fs::create_dir_all(STATE_DIR);
    let _ = fs::create_dir_all(RUN_DIR);
    let lock = Path::new(LOCK_DIR);

    if fs::create_dir(lock).is_err() {
        let holder = fs::read_to_string(lock.join("pid"))
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());
        if holder.is_some_and(holder_is_daemon) {
            return false;
        }
        // 陈锁（进程没了，或那个 pid 早被别的进程复用）：清掉重抢。
        let _ = fs::remove_dir_all(lock);
        if fs::create_dir(lock).is_err() {
            return false;
        }
    }
    let _ = fs::write(lock.join("pid"), format!("{}", std::process::id()));
    // 抢锁有竞态：两个实例同时认定「这是陈锁」时，先清后建的那份会把对方刚建的
    // 删掉。拿到之后隔一秒再核一次归属，确认还是自己才算数。
    sleep(Duration::from_secs(1));
    fs::read_to_string(lock.join("pid"))
        .ok()
        .is_some_and(|text| text.trim() == std::process::id().to_string())
}

/// 锁里记的 pid 现在跑的确实是本守护（而不是内核线程或别的程序复用了这个号）。
fn holder_is_daemon(pid: u32) -> bool {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    if cmdline.is_empty() {
        return false;
    }
    let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    args.iter().any(|arg| *arg == b"--daemon")
}

// ---------------------------------------------------------------------------
// keymint 生命周期
// ---------------------------------------------------------------------------

/// keymint 的位置：`bin/`（热更新过）→ 模块根 → `libs/<abi>/`。
///
/// 刚安装完时 `customize.sh` 会清掉 `bin/` 里的旧二进制，运行用的是模块内那份；
/// 热更新过就优先用 `bin/`。两种都是正常布局，不是兼容旧版。
fn find_keymint() -> Option<PathBuf> {
    // 唯一位置：模块内的 `libs/<abi>/keymint`。ELF 只要能 execute（ksu 域有），
    // 不需要 read；`bin/` 那套热更新布局已废弃。ABI 用编译期常量，不读属性。
    let abi_dir = if cfg!(target_arch = "aarch64") {
        "arm64-v8a"
    } else if cfg!(target_arch = "arm") {
        "armeabi-v7a"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "x86"
    };
    let path = PathBuf::from(format!("{MODDIR}/libs/{abi_dir}/keymint"));
    path.is_file().then_some(path)
}

/// 杀掉所有跑着 `target` 的残留实例（只匹配这个确切路径，不碰系统 HAL）。
fn stop_stale_instances(target: &Path) {
    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    let target = target.to_string_lossy().to_string();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        let cmdline = fs::read(entry.path().join("cmdline")).unwrap_or_default();
        if cmdline.is_empty() {
            continue;
        }
        let first = cmdline.split(|b| *b == 0).next().unwrap_or_default();
        if first == target.as_bytes() {
            let _ = Command::new("/system/bin/kill")
                .args(["-KILL", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
    sleep(Duration::from_secs(1));
}

fn spawn_keymint(target: &Path, extra: &[String]) -> std::io::Result<Child> {
    let mut command = Command::new(target);
    command.args(extra);
    // 出证要用的几个属性：daemon 读好经环境变量交给 keymint，省掉它自己去读
    // （`rsproperties` 在静态进程里拿不到属性区，兜底要 fork 一次 resetprop）。
    for name in KEYMINT_ENV {
        if let Some(value) = resetprop::read_string_property(name) {
            let env_name = env_name_for(name);
            command.env(env_name, value);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn env_name_for(prop: &str) -> &'static str {
    match prop {
        "ro.boot.vbmeta.digest" => "OMMEGA_BOOT_HASH",
        "ro.boot.vbmeta.public_key_digest" => "OMMEGA_BOOT_KEY",
        "ro.build.version.security_patch" => "OMMEGA_PATCH_SECURITY",
        "ro.vendor.build.security_patch" => "OMMEGA_PATCH_VENDOR",
        _ => "OMMEGA_PATCH_BOOT",
    }
}

/// `run/restart.all` 是「两个都重启」的快捷方式，先展开成各自的一份。
fn take_restart_request() -> bool {
    if Path::new(RESTART_ALL_FILE).exists() {
        let _ = fs::write(RESTART_FILE, b"");
        let _ = fs::write(PEER_RESTART_FILE, b"");
        let _ = fs::remove_file(RESTART_ALL_FILE);
    }
    if Path::new(RESTART_FILE).exists() {
        let _ = fs::remove_file(RESTART_FILE);
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// 身份同步
// ---------------------------------------------------------------------------

fn set_prop(name: &str, value: &str) {
    if name.is_empty() || value.is_empty() {
        return;
    }
    // 值一样就不写（这个函数每 10 秒跑一次，不幂等会一直在改属性）。
    if resetprop::read_string_property(name).as_deref() == Some(value) {
        return;
    }
    let _ = resetprop::direct_write_and_verify_property(name, value);
}

/// 把链里声明的身份对齐到本机属性。
///
/// 来源是 `remote_identity`（TA 每次收到链都写）：服务端 keybox 出链时里面的哈希
/// 就是本机属性，值相同不会写；真机 B 出链时是 B 的说法，同步一次之后每次都比得上；
/// 本地模式下这个文件不更新，走不到这里。
fn sync_remote_identity() {
    let remote_mode = fs::read_to_string(CONF_PATH)
        .ok()
        .and_then(|text| config_value(&text, "remote").map(|value| value.trim().to_string()))
        .is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        });

    if !remote_mode {
        // 本地模式：把上次远程留下的 boot 状态改回「已锁定 + 已验证」，
        // 跟证书那侧的口径保持一致。
        lock_down_boot_state();
        return;
    }

    let Ok(identity) = fs::read_to_string(REMOTE_IDENTITY) else {
        return;
    };
    // 面板「伪装参数」里手写过身份就以面板为准。
    if fs::read_to_string(PROPS_CONF)
        .ok()
        .is_some_and(|text| config_value(&text, "ro.product.model").is_some())
    {
        lock_down_boot_state();
        return;
    }

    let applied_text = fs::read_to_string(REMOTE_IDENTITY_APPLIED).unwrap_or_default();
    let mut applied: Vec<(String, String)> = applied_text
        .lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    let mut changed = false;
    for key in [
        "brand",
        "device",
        "product",
        "manufacturer",
        "model",
        "serial",
        "vbmeta_digest",
    ] {
        let Some(value) = identity_value(&identity, key) else {
            continue;
        };
        if applied.iter().any(|(k, v)| k == key && v == value) {
            continue;
        }
        if let Some(prop) = identity_prop(key) {
            set_prop(prop, value);
        }
        applied.retain(|(k, _)| k != key);
        applied.push((key.to_string(), value.to_string()));
        changed = true;
    }

    if changed {
        let mut text = String::new();
        for (key, value) in &applied {
            text.push_str(&format!("{key}={value}\n"));
        }
        let _ = fs::write(REMOTE_IDENTITY_APPLIED, text);
    }

    // boot 补丁日期：链里是 YYYYMMDD（tag 708），和面板那套属性对齐。
    if let Some(boot) = identity_value(&identity, "boot_patchlevel") {
        if boot.len() == 8 && boot.chars().all(|c| c.is_ascii_digit()) {
            let (y, m, d) = (&boot[0..4], &boot[4..6], &boot[6..8]);
            let text = format!("{y}-{m}-{d}");
            for prop in [
                "ro.vendor.boot_security_patch",
                "ro.boot.build.security_patch",
                "ro.boot.image.build.security_patch",
            ] {
                set_prop(prop, &text);
            }
            if let Some(epoch) = epoch_from_ymd(y, m, d) {
                set_prop("ro.bootimage.build.date.utc", &epoch.to_string());
            }
        }
    }

    lock_down_boot_state();

    if changed {
        let brand = applied_value(&applied, "brand").unwrap_or_default();
        let model = applied_value(&applied, "model").unwrap_or_default();
        log(&format!("remote identity applied: {brand}/{model}"));
        // 只落标记，**绝不自动重启 zygote**：身份文件是 TA 每次出链都写的，
        // 自动重启会变成「重启 → App 重启 → 又认证 → 又写文件 → 又重启」的死循环。
        let _ = fs::write(REMOTE_IDENTITY_UPDATED, format!("{brand}/{model}\n"));
    }
}

/// 证书那边固定声明「已锁定 + 已验证」，属性必须同一口径 —— 不看 B 自报的状态。
fn lock_down_boot_state() {
    set_prop("ro.boot.vbmeta.device_state", "locked");
    set_prop("ro.boot.flash.locked", "1");
    set_prop("ro.boot.verifiedbootstate", "green");
}

fn identity_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        let v = v.trim();
        (k.trim() == key && !v.is_empty()).then_some(v)
    })
}

fn applied_value<'a>(applied: &'a [(String, String)], key: &str) -> Option<&'a str> {
    applied
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn identity_prop(key: &str) -> Option<&'static str> {
    Some(match key {
        "brand" => "ro.product.brand",
        "device" => "ro.product.device",
        "product" => "ro.product.name",
        "manufacturer" => "ro.product.manufacturer",
        "model" => "ro.product.model",
        "serial" => "ro.serialno",
        "vbmeta_digest" => "ro.boot.vbmeta.digest",
        _ => return None,
    })
}

/// `YYYY-MM-DD` → Unix 时间戳（UTC 零点）。
fn epoch_from_ymd(year: &str, month: &str, day: &str) -> Option<i64> {
    let year: i64 = year.parse().ok()?;
    let month: i64 = month.parse().ok()?;
    let day: i64 = day.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400)
}

/// Howard Hinnant 的 `days_from_civil`。
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_value_reads_first_match() {
        let text = "# 注释\ndebug_logging: 1\nremote: true\n";
        assert_eq!(config_value(text, "debug_logging"), Some("1"));
        assert_eq!(config_value(text, "remote"), Some("true"));
        assert_eq!(config_value(text, "missing"), None);
    }

    #[test]
    fn identity_value_skips_empty() {
        let text = "brand=OnePlus\nmodel=\nserial=ABC\n";
        assert_eq!(identity_value(text, "brand"), Some("OnePlus"));
        assert_eq!(identity_value(text, "model"), None);
        assert_eq!(identity_value(text, "serial"), Some("ABC"));
    }

    #[test]
    fn epoch_matches_known_dates() {
        assert_eq!(epoch_from_ymd("1970", "01", "01"), Some(0));
        assert_eq!(epoch_from_ymd("2025", "08", "01"), Some(1_754_006_400));
        assert_eq!(epoch_from_ymd("2025", "13", "01"), None);
    }

    #[test]
    fn utc_stamp_formats_epoch_zero() {
        assert_eq!(utc_stamp(0), "1970-01-01 00:00:00");
    }
}
