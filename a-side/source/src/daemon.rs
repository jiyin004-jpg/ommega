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
use std::os::unix::fs::PermissionsExt;
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
/// 系统自己的 uid→包名 表，只有 root（本守护）读得到。
const PACKAGES_LIST: &str = "/data/system/packages.list";
/// 抄给 keystore 域看的 AAID 表：我们被注入进 keystore2 之后在那儿跑，
/// `packages.list` 是 `0640 system:package_info` + `packages_list_file`，两头都拦。
const AAID_TABLE: &str = "/data/misc/ommega/aaid_table";
const REMOTE_IDENTITY: &str = "/data/misc/ommega/remote_identity";
const CONFIG_TOML: &str = "/data/misc/ommega/config.toml";
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
/// AAID 表的巡检周期：只 stat `packages.list`，变了才重抄（装/卸包才会变）。
const AAID_CHECK_INTERVAL: Duration = Duration::from_secs(30);

const KEYMINT_ENV: [&str; 6] = [
    "ro.boot.vbmeta.digest",
    "ro.boot.vbmeta.public_key_digest",
    "ro.build.version.security_patch",
    "ro.vendor.build.security_patch",
    "ro.boot.build.security_patch",
    // AProbe 的 A13 拿这个名字当期望值；后面设置会覆盖前面的同名环境变量，
    // 所以它在最前面被读到、最后写进 OMMEGA_PATCH_BOOT，优先生效。
    "ro.boot.image.build.security_patch",
];

/// 守护进程入口。`extra` 是原始参数里除 `--daemon` 以外的部分，原样交给 keymint。
pub fn run(extra: Vec<String>) -> ! {
    // 单实例靠内核锁（flock）：锁在我手上就到死不放，进程一死内核自动释放。
    // 以前那套「mkdir 锁目录 + pid/starttime 校验」有两个实例同时认领陈锁的竞态，
    // 实测会真的起两份守护 —— 两边每轮都把对方的 HAL 当残留杀掉，现象是 HAL 每两秒
    // 被 SIGKILL 一次，证书全失败。
    let singleton = acquire_flock();
    if singleton.is_none() || !acquire_singleton() {
        log("another instance is running; exiting");
        std::process::exit(0);
    }
    // 锁也会失效（锁目录被清、两轮自己的 pid 对不上时双方都以为自己抢到了）。
    // 同名守护就是两份内存态：两边每轮都会把对方的 HAL 当残留杀掉，实际现象是
    // HAL 每两秒被 SIGKILL 一次、证书请求全失败。这里按「名字 + memfd + pid 更小」
    // 再兜一道：只要看到比自己早起的同名实例就退。
    if let Some(name) = crate::stealth::cached_name("daemon") {
        if let Some(old) = older_same_name(&name) {
            log(&format!("older daemon pid {old} is alive; exiting"));
            std::process::exit(0);
        }
    }
    // pidfile 由守护自己写：自举（memfd 重生）会把 cmdline 换掉，shell 那边
    // 拿 `$!` 记的 pid 也可能是 setsid 的中间进程，靠它判断死活不再可靠。
    // 格式是 `pid starttime`，判活就比 starttime —— pid 被复用了也对不上。
    write_pidfile();
    log("keymint daemon started");
    // 伪装参数只在开机（或本守护重启）时算一次：面板保存只写 props.conf，
    // 不会即时改运行时；这样属性和证书永远是同一份，不会一边新一边旧。
    normalize_all();
    // AAID 兜底表：悄悄跑着，不让它拖住主循环（里面会 fork 一次 `pm`）。
    std::thread::spawn(aaid_sync_loop);
    // 看护线程：注入器和 adbr 以前是 service.sh 里那个 `while true; sleep 5`
    // （一个常驻的 busybox sh，进程列表里一眼就是「模块自带的脚本」）。
    // 搬到守护里之后，那一层就彻底没有了。
    std::thread::spawn(supervisor_loop);

    loop {
        let Some(target) = find_keymint() else {
            log("keymint binary not found");
            sleep(Duration::from_secs(5));
            continue;
        };
        stop_stale_instances(&target);

        // 出证要用的几个属性提前落成文件（而不是塞环境变量）：进程 environ 是
        // root 一条命令就能看的东西，`OMMEGA_BOOT_HASH` 那种名字太直白。
        write_env_file(&target);

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
// AAID 兜底表
// ---------------------------------------------------------------------------
//
// 为什么要有这张表：出证要往证书里塞 `attestationApplicationId`（tag 709），
// 系统只给 Keystore/Credstore 的 uid 提供，而我们的 TA 被注入进 keystore2 之后
// 拿不到那个服务；自己读 `/data/system/packages.list` 也不行（`0640 system:package_info`
// + `packages_list_file`，DAC 和 SELinux 两头都拦）。本守护一直是 root，读得到，
// 那就抄一份到数据根，TA 从那里拿。
//
// 表里行格式：`uid 包名 版本号 签名摘要`（`#` 开头是注释；摘要拿不到写 `-`）。
// 版本号和 APK 路径从 `pm list packages -f --show-versioncode` 拿，
// 签名摘要是 APK 签名证书的 SHA-256 —— 就是 AAID（709）里那个 signatureDigests。
// 只 stat `packages.list`，装/卸载才会变，变了才重抄 —— 常驻零开销。
fn aaid_sync_loop() {
    let mut last_stamp: Option<(u64, u64)> = None;
    loop {
        let stamp = fs::metadata(PACKAGES_LIST).ok().map(|meta| {
            let secs = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|delta| delta.as_secs())
                .unwrap_or(0);
            (secs, meta.len())
        });
        if stamp != last_stamp {
            let written = sync_aaid_table();
            if written {
                last_stamp = stamp;
            }
        }
        sleep(AAID_CHECK_INTERVAL);
    }
}

/// 抄一遍。返回是否已经把表写成（写失败就下轮再来，不丢状态）。
fn sync_aaid_table() -> bool {
    let Ok(list) = fs::read_to_string(PACKAGES_LIST) else {
        log("aaid table: cannot read packages.list");
        return false;
    };
    let entries = package_entries();
    let mut body =
        String::from("# uid package versionCode sigDigest  (from packages.list + APK)\n");
    let mut count = 0usize;
    for line in list.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(uid) = fields
            .next()
            .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        let entry = entries.iter().find(|entry| entry.package == name);
        let version = entry.map(|entry| entry.version).unwrap_or(1);
        let digest = entry
            .and_then(|entry| signing_cert_digest(&entry.apk))
            .map(hex::encode)
            .unwrap_or_else(|| "-".to_string());
        body.push_str(&format!("{uid} {name} {version} {digest}\n"));
        count += 1;
    }
    if count == 0 {
        log("aaid table: packages.list had no entries");
        return false;
    }
    if fs::read_to_string(AAID_TABLE).ok().as_deref() == Some(body.as_str()) {
        return true;
    }
    // 先落临时文件再 rename：TA 那边随时可能来读，不能读到半张表。
    let tmp = format!("{AAID_TABLE}.tmp");
    if let Err(error) = fs::write(&tmp, body.as_bytes()) {
        log(&format!("aaid table: cannot write {tmp}: {error}"));
        return false;
    }
    // 0644：TA 跑在 keystore 域，跟本守护不是一个 uid。
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644));
    if let Err(error) = fs::rename(&tmp, AAID_TABLE) {
        log(&format!("aaid table: cannot rename into place: {error}"));
        let _ = fs::remove_file(&tmp);
        return false;
    }
    log(&format!("aaid table: {count} packages"));
    true
}

struct PackageEntry {
    package: String,
    version: i64,
    apk: PathBuf,
}

/// `pm list packages -f --show-versioncode` 一趟拿全：
/// `package:/data/app/~~xxxx/base.apk=com.foo versionCode:123`。
/// 带 `-f` 才有 APK 路径，不然得去猜 `/data/app` 下那串目录名。
fn package_entries() -> Vec<PackageEntry> {
    let output = match Command::new("/system/bin/pm")
        .args(["list", "packages", "-f", "--show-versioncode"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("package:") else {
            continue;
        };
        // 路径里带着 `~~xxxx==` 这种哈希，里面就有 `=`；包名一定是最后一个 `=` 后面那段。
        let Some((apk, tail)) = rest.rsplit_once('=') else {
            continue;
        };
        let mut fields = tail.split_whitespace();
        let Some(package) = fields.next() else {
            continue;
        };
        let version = fields
            .next()
            .and_then(|value| value.strip_prefix("versionCode:"))
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(1);
        entries.push(PackageEntry {
            package: package.to_string(),
            version,
            apk: PathBuf::from(apk),
        });
    }
    entries
}

// APK 签名块里的 scheme id（v2 / v3），跟 AOSP apksig 里的常量一致。
const APK_SIG_SCHEME_V2: u32 = 0x7109_871a;
const APK_SIG_SCHEME_V3: u32 = 0xf053_68c0;
const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// APK 签名证书的 SHA-256 —— AAID（tag 709）里 `signatureDigests` 就是这个值。
/// 拿不到就 None（表里写 `-`）：宁可空着，也不能塞个假摘要。
fn signing_cert_digest(apk: &Path) -> Option<Vec<u8>> {
    use kmr_common::crypto::Sha256;
    let cert = apk_signing_cert(apk)?;
    kmr_crypto_ommega::sha256::OmmegaSha256 {}
        .hash(&cert)
        .ok()
        .map(|digest| digest.to_vec())
}

/// 先 v3 再 v2（跟 apksig 一样优先新方案）。
/// 从 EOCD 拿中央目录偏移，中央目录紧前面就是签名块，块里取
/// `signed_data.certificates` 的第一张证书。
fn apk_signing_cert(apk: &Path) -> Option<Vec<u8>> {
    match apk_signing_cert_inner(apk) {
        Ok(cert) => Some(cert),
        Err(stage) => {
            log(&format!("aaid: {} failed at {stage}", apk.display()));
            None
        }
    }
}

fn apk_signing_cert_inner(apk: &Path) -> Result<Vec<u8>, &'static str> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = fs::File::open(apk).map_err(|_| "open")?;
    let len = file.metadata().map_err(|_| "stat")?.len();
    if len < 64 {
        return Err("too-small");
    }

    // EOCD 从文件尾 22 字节起，前面最多还有 64KiB 的注释。
    let tail_len = std::cmp::min(len, 64 * 1024 + 22) as usize;
    let mut tail = vec![0u8; tail_len];
    file.seek(SeekFrom::Start(len - tail_len as u64))
        .map_err(|_| "seek-tail")?;
    file.read_exact(&mut tail).map_err(|_| "read-tail")?;
    let mut eocd = None;
    for i in (0..tail.len().saturating_sub(21)).rev() {
        if tail[i..i + 4] == [b'P', b'K', 5, 6] {
            eocd = Some(i);
            break;
        }
    }
    let eocd = eocd.ok_or("no-eocd")?;
    let cd_offset = le_u32(&tail, eocd + 16).ok_or("no-cd-offset")? as u64;
    if cd_offset < 32 || cd_offset > len {
        return Err("bad-cd-offset");
    }

    // 中央目录前面 24 字节：块长(8) + magic(16)。
    let mut footer = [0u8; 24];
    file.seek(SeekFrom::Start(cd_offset - 24))
        .map_err(|_| "seek-footer")?;
    file.read_exact(&mut footer).map_err(|_| "read-footer")?;
    if &footer[8..24] != APK_SIG_BLOCK_MAGIC {
        return Err("no-block-magic");
    }
    let block_size = u64::from_le_bytes(footer[0..8].try_into().map_err(|_| "footer-size")?);
    if block_size + 8 > cd_offset {
        return Err("block-too-big");
    }
    let block_start = cd_offset - block_size - 8;
    let mut block = vec![0u8; (block_size + 8) as usize];
    file.seek(SeekFrom::Start(block_start))
        .map_err(|_| "seek-block")?;
    file.read_exact(&mut block).map_err(|_| "read-block")?;

    // 布局：size(8) + (len(8)+id(4)+value)* + size(8) + magic(16)
    let pairs_end = block.len().checked_sub(24).ok_or("short-block")?;
    let mut pos = 8usize;
    let mut v2 = None;
    let mut v3 = None;
    while pos + 12 <= pairs_end {
        let pair_len = u64::from_le_bytes(
            block
                .get(pos..pos + 8)
                .and_then(|raw| raw.try_into().ok())
                .ok_or("pair-len")?,
        ) as usize;
        pos += 8;
        if pair_len < 4 || pos + pair_len > block.len() {
            break;
        }
        let id = u32::from_le_bytes(block[pos..pos + 4].try_into().map_err(|_| "pair-id")?);
        let value = &block[pos + 4..pos + pair_len];
        match id {
            APK_SIG_SCHEME_V3 => v3 = Some(value),
            APK_SIG_SCHEME_V2 => v2 = Some(value),
            _ => {}
        }
        pos += pair_len;
    }

    let value = v3.or(v2).ok_or("no-v2-v3")?;
    first_signer_cert(value)
        .map(<[u8]>::to_vec)
        .ok_or("no-cert")
}

/// 长度前缀（u32 小端）切一段，返回 (这一段, 剩下)。
fn lp32(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(buf[0..4].try_into().ok()?) as usize;
    let body = buf.get(4..4 + len)?;
    Some((body, &buf[4 + len..]))
}

/// v2/v3 的值：signers → 第一个 signer → signed_data → (digests, certificates) → 第一张证书。
/// 注意层级：`certificates` 已经是「证书序列」那个 blob 了，里面第一段就是第一张证书的
/// 长度前缀 + DER，不要再往下一层。
fn first_signer_cert(value: &[u8]) -> Option<&[u8]> {
    let (signers, _) = lp32(value)?;
    let (signer, _) = lp32(signers)?;
    let (signed_data, _) = lp32(signer)?;
    let (_digests, rest) = lp32(signed_data)?;
    let (certificates, _) = lp32(rest)?;
    let (cert, _) = lp32(certificates)?;
    (!cert.is_empty()).then_some(cert)
}

fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

// ---------------------------------------------------------------------------
// 单实例
// ---------------------------------------------------------------------------

/// 内核级排他锁。返回的 File 要活到进程结束（drop 就释放锁）。
fn acquire_flock() -> Option<fs::File> {
    use std::os::unix::io::AsRawFd;
    let dir = Path::new(RUN_DIR);
    fs::create_dir_all(dir).ok()?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("keymint-daemon.flock"))
        .ok()?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return None;
    }
    Some(file)
}

fn acquire_singleton() -> bool {
    let _ = fs::create_dir_all(STATE_DIR);
    let _ = fs::create_dir_all(STATE_DIR);
    let _ = fs::create_dir_all(RUN_DIR);
    let lock = Path::new(LOCK_DIR);

    if fs::create_dir(lock).is_err() {
        if lock_holder().is_some_and(|(pid, start)| holder_is_daemon(pid, start)) {
            return false;
        }
        // 陈锁（进程没了，或那个 pid 早被别的进程复用）：清掉重抢。
        let _ = fs::remove_dir_all(lock);
        if fs::create_dir(lock).is_err() {
            return false;
        }
    }
    let me = owner_stamp();
    let _ = fs::write(lock.join("pid"), &me);
    // 抢锁有竞态：两个实例同时认定「这是陈锁」时，先清后建的那份会把对方刚建的
    // 删掉。拿到之后隔一秒再核一次归属，确认还是自己才算数。
    sleep(Duration::from_secs(1));
    fs::read_to_string(lock.join("pid"))
        .ok()
        .is_some_and(|text| text.trim() == me)
}

/// 锁里记的身份：`pid starttime`。
fn owner_stamp() -> String {
    let pid = std::process::id();
    format!("{pid} {}", start_time(pid).unwrap_or(0))
}

/// `/proc/<pid>/stat` 第 22 个字段（进程启动时刻，单位 jiffies）。
fn start_time(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm 里可能带空格和括号，按最后一个 ')' 切才不会错位。
    let rest = &text[text.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn write_pidfile() {
    let _ = fs::create_dir_all(RUN_DIR);
    let _ = fs::write(format!("{RUN_DIR}/keymint-daemon.pid"), owner_stamp());
}

/// 有没有比自己早起的同名守护（comm 就是这个伪装名的前 15 字节、exe 在 memfd 里）。
fn older_same_name(name: &str) -> Option<u32> {
    let me = std::process::id();
    let want = comm_prefix(name);
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        if pid >= me {
            continue;
        }
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim() != want {
            continue;
        }
        let hid = matches!(fs::read_link(entry.path().join("exe")), Ok(exe) if exe.to_string_lossy().starts_with("/memfd:"));
        if hid {
            return Some(pid);
        }
    }
    None
}

fn lock_holder() -> Option<(u32, u64)> {
    let text = fs::read_to_string(Path::new(LOCK_DIR).join("pid")).ok()?;
    let mut parts = text.split_whitespace();
    let pid = parts.next()?.parse().ok()?;
    let start = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    Some((pid, start))
}

/// 锁里记的 pid 现在跑的确实是本守护（而不是内核线程或别的程序复用了这个号）。
fn holder_is_daemon(pid: u32, start: u64) -> bool {
    let Some(now) = start_time(pid) else {
        return false;
    };
    // 老格式的锁没记 starttime，那时候只能看进程还在不在了。
    if start == 0 {
        return true;
    }
    now == start
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

/// 杀掉跑着 HAL 名字的残留实例。
///
/// 按 **comm** 认人，不读 cmdline：读一个卡在 D 状态的进程的 `/proc/pid/cmdline`
/// 会把调用方一起卡住（实测设备 load 被三个这样的 tr 拉到 12，每个吃 100% CPU
/// 跑了几十分钟）。comm 存在 task_struct 里，读它不会阻塞；而我们的伪装名本来就
/// 是按 comm 前缀去重挑的，拿它认人够用。
fn stop_stale_instances(target: &Path) {
    let me = std::process::id();
    let mut wanted: Vec<String> = Vec::new();
    if let Some(hal) = crate::stealth::cached_name("hal") {
        wanted.push(comm_prefix(&hal));
    }
    // 没自举成功的老进程 comm 就还是 keymint。
    wanted.push("keymint".to_string());

    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == me {
            continue;
        }
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        let comm = comm.trim();
        if !wanted.iter().any(|name| name == comm) {
            continue;
        }
        // 只杀自己人：exe 是 memfd，或者就是模块里那个二进制。
        let exe = fs::read_link(entry.path().join("exe"))
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let ours = exe.starts_with("/memfd:") || Path::new(&exe) == target;
        if !ours {
            continue;
        }
        let _ = Command::new("/system/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    sleep(Duration::from_secs(1));
}

/// 伪装路径的 comm（basename 前 15 字节，跟内核一致）。
fn comm_prefix(path: &str) -> String {
    let base = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let bytes = base.as_bytes();
    String::from_utf8_lossy(&bytes[..bytes.len().min(15)]).into_owned()
}

fn spawn_keymint(target: &Path, extra: &[String]) -> std::io::Result<Child> {
    // 没有（table 没挑出来）就老样子直接从模块目录 exec —— 难看但能跑。
    let fake = crate::stealth::cached_name("hal").unwrap_or_default();
    let mut memfd = None;
    let mut command = if fake.starts_with('/') {
        let base = fake.rsplit('/').next().unwrap_or("hal").to_string();
        match crate::stealth::memfd_from(target, &base) {
            Some(fd) => {
                memfd = Some(fd);
                crate::stealth::command_from_memfd(fd, &fake)
            }
            None => Command::new(target),
        }
    } else {
        Command::new(target)
    };
    // 出证要用的属性不走环境变量了（见 write_env_file）。
    command
        .args(extra)
        // 守护自己的模式标记不能传给 HAL：子进程继承之后会以为自己是第二个守护。
        .env_remove("DAEMON_MODE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .inspect(|_| {
            // 子进程已经拿到自己那份 fd，父进程这份要关掉，不然每轮重启漏一个。
            if let Some(fd) = memfd {
                unsafe { libc::close(fd) };
            }
        })
}

// ---------------------------------------------------------------------------
// 看护（以前在 service.sh 的 keep-alive 循环里）
// ---------------------------------------------------------------------------

/// 每 5 秒看一眼：注入器和 adbr 的监管脚本还在不在？不在就用「memfd + 伪装名」
/// 那个启动方式（`sh -s`，脚本从标准输入读）重新拉起来。
fn supervisor_loop() {
    let mut last_soterta = std::time::Instant::now();
    loop {
        sleep(Duration::from_secs(5));
        // 先把 pidfile 刷一遍：它可能被清理脚本删了（旧版本只在启动时写一次），
        // 而看护/注入器/面板都拿它判断死活。文件不在就会被当成「守护挂了」，
        // 每 5 秒重拉一个（每个都要把 8MB 二进制读进 memfd），白白烧 CPU。
        write_pidfile();
        ensure_script("injector", &format!("{MODDIR}/daemon-injector"), &[]);
        let adbr = format!("{MODDIR}/adbr-daemon.sh");
        // 关着的时候不要去拉：adbr-daemon.sh 启动后发现自己被关会立即退出，
        // 每 5 秒拉一次就是每 5 秒一个短命进程，白白多出一串痕迹。
        if Path::new(&adbr).is_file() && config_flag("adbr") {
            ensure_script("adbr", &adbr, &["--a"]);
        }
        // SOTER 接管状态每 30 秒收敛一次（这个脚本跑一两秒就退）。
        if last_soterta.elapsed() >= Duration::from_secs(30) {
            last_soterta = std::time::Instant::now();
            let script = format!("{MODDIR}/soterta.sh");
            if Path::new(&script).is_file() {
                reap_later(spawn_script("soterta", &script, &[]));
            }
        }
    }
}

/// 拉起来的子进程必须有人 wait，否则退出后会留一堆僵尸 —— 而这个线程不 wait，
/// 所以每个子进程配一个等待线程（它退出后线程自然结束）。
fn reap_later(child: std::io::Result<Child>) {
    match child {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(error) => log(&format!("spawn failed: {error}")),
    }
}

/// 平铺 config 里的开关（`key: 1/true/on`）。读不到就当关。
fn config_flag(key: &str) -> bool {
    let Ok(text) = fs::read_to_string(CONF_PATH) else {
        return false;
    };
    for line in text.lines() {
        let Some((left, right)) = line.split_once(':') else {
            continue;
        };
        if !left.trim().eq_ignore_ascii_case(key) {
            continue;
        }
        let value = right.trim().to_ascii_lowercase();
        return matches!(value.as_str(), "1" | "true" | "yes" | "on");
    }
    false
}

fn ensure_script(role: &str, script: &str, args: &[&str]) {
    // 先按 comm 认人：脚本启动后会把 comm 改成伪装名，比 pidfile 可靠（
    // pidfile 会被清理/被上一次运行时覆盖，判错就会每 5 秒重拉一个）。
    if let Some(name) = crate::stealth::cached_name(role) {
        if comm_running(&comm_prefix(&name)) {
            return;
        }
    }
    let pidfile = match role {
        "injector" => format!("{RUN_DIR}/injector-daemon.pid"),
        _ => format!("{RUN_DIR}/adbr-daemon.lock/pid"),
    };
    if pidfile_stamp_alive(&pidfile) {
        return;
    }
    log(&format!("{role} not running; respawning"));
    reap_later(spawn_script(role, script, args));
}

/// 有没有进程的 comm 就是这个名字（comm 读取不会阻塞）。
fn comm_running(want: &str) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        if let Ok(comm) = fs::read_to_string(entry.path().join("comm")) {
            if comm.trim() == want {
                return true;
            }
        }
    }
    false
}

/// pidfile 里是 `pid starttime`；两列都对得上才算活着。
fn pidfile_stamp_alive(path: &str) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let mut parts = text.split_whitespace();
    let Some(pid) = parts.next().and_then(|v| v.parse::<u32>().ok()) else {
        return false;
    };
    let stamp = parts
        .next()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    if unsafe { libc::kill(pid as i32, 0) } != 0 {
        return false;
    }
    if stamp == 0 {
        return true;
    }
    start_time(pid) == Some(stamp)
}

/// 脚本也走 memfd：内容读进内存，`sh -s` 从标准输入读，cmdline 里就只剩一个
/// 伪装过的系统服务名。
fn spawn_script(role: &str, script: &str, args: &[&str]) -> std::io::Result<Child> {
    use std::os::unix::io::FromRawFd;
    use std::os::unix::process::CommandExt;

    let fake = crate::stealth::cached_name(role).unwrap_or_default();
    let base = fake.rsplit('/').next().unwrap_or("hal").to_string();
    let fd = crate::stealth::memfd_from(Path::new(script), &base)
        .ok_or_else(|| std::io::Error::other("memfd failed"))?;
    let stdin = unsafe { fs::File::from_raw_fd(fd) };
    let mut command = Command::new("/system/bin/sh");
    command
        .arg0(&fake)
        .arg("-s")
        // `--` 后面才是脚本自己的参数（adbr-daemon.sh 收 `--a`），
        // 不加的话 sh 会把它当自己的选项。
        .arg("--")
        .args(args)
        // 环境里不带我们的名字（脚本自己知道模块在哪里）。
        .env_remove("DAEMON_MODE")
        .env_remove("OMMEGA_MODDIR")
        .env_remove("OMMEGA_STEALTH")
        .env_remove("OMMEGA_SELF_PATH")
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn()
}

/// 把出证要用的几个属性写进 `run/keymint.env`，HAL 启动时自己读。
///
/// 不用环境变量：`/proc/<pid>/environ` 是 root 一句 `tr` 就能看的东西，
/// 里面出现 `OMMEGA_BOOT_HASH` 这种名字等于把菜单贴在门上。
fn write_env_file(_target: &Path) {
    let mut text = String::new();
    for name in KEYMINT_ENV {
        if let Some(value) = resetprop::read_string_property(name) {
            text.push_str(env_name_for(name));
            text.push('=');
            text.push_str(&value);
            text.push('\n');
        }
    }
    let path = format!("{RUN_DIR}/keymint.env");
    if fs::write(&path, text).is_ok() {
        let _ = fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
    }
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

fn set_prop(name: &str, value: &str) -> bool {
    if name.is_empty() || value.is_empty() {
        return true;
    }
    // 值一样就不写（这个函数每 10 秒跑一次，不幂等会一直在改属性）。
    if resetprop::read_string_property(name).as_deref() == Some(value) {
        return true;
    }
    match resetprop::direct_write_and_verify_property(name, value) {
        Ok(()) => true,
        Err(error) => {
            // 写不进去只记一条。**不要**让调用方因此不记账：`ro.product.*` 这类
            // 属性本来大多只读，写失败是常态，不记账就会变成每 10 秒一轮 resetprop
            // （每轮还会挨个试候选二进制），日志也会被刷满。
            log(&format!("failed to set {name}={value}: {error:#}"));
            false
        }
    }
}

/// 把链里声明的身份对齐到本机属性。
///
/// 来源是 `remote_identity`（TA 每次收到链都写）：服务端 keybox 出链时里面的哈希
/// 就是本机属性，值相同不会写；真机 B 出链时是 B 的说法，同步一次之后每次都比得上；
/// 本地模式下这个文件不更新，走不到这里。
/// boot 补丁的三个属性变体，第一个是权威名（AProbe 的 A13 与 bootloader 都用它）。
const BOOT_PATCH_PROPS: [&str; 3] = [
    "ro.boot.image.build.security_patch",
    "ro.boot.build.security_patch",
    "ro.vendor.boot_security_patch",
];

/// 开机把三个 boot 补丁属性统一到 boot 分区的真值上。
///
/// 为什么要有这一步：属性是 bootloader 的快照，厂商不跟着 OTA 刷 bootloader 就会停在
/// 旧日期（实测属性 2025-03-01，而 boot 分区里写的是 2026-08-01）。以前出链是属性优先，
/// 属性又会被 `remote_identity` 反写回来，旧日期就永远出不去。现在开机对齐一次，之后
/// 出链、面板、检测器读的都是同一个值，也省得每次去解析分区。
fn normalize_all() {
    normalize_boot_patch();
    normalize_vbmeta_digest();
    normalize_vbmeta_public_key();
    normalize_patch_props();
    normalize_identity_props();
}

/// 伪装清掉后，机型/指纹/系统版本这些属性也得回 build.prop 的真值。
///
/// 分区级那份（ro.product.system.* 等）不在 build.prop 明文里，读不到就不动 —— 宁可不改也比
/// 写一个错值强。
fn normalize_identity_props() {
    for prop in [
        "ro.product.brand",
        "ro.product.device",
        "ro.product.name",
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.build.fingerprint",
        "ro.build.version.release",
    ] {
        if props_conf_value(prop).is_some() {
            continue;
        }
        let Some(truth) = crate::plat::vbmeta::build_prop_value(prop) else {
            continue;
        };
        let current = resetprop::read_string_property(prop).unwrap_or_default();
        if current == truth {
            continue;
        }
        set_prop(prop, &truth);
        log(&format!(
            "identity: {prop} was {current}, restored to {truth} (build.prop)"
        ));
    }
}

/// os / vendor 补丁清掉伪装后回 build.prop 的真值。
///
/// 这两个没有分区级别的“真值”概念，伪装写的就是属性；用户把伪装清掉时，props.conf
/// 里那行没了，但属性还停在旧值上，没人拉得回去。这里每次归一都跟 build.prop 对一遍。
fn normalize_patch_props() {
    for prop in [
        "ro.build.version.security_patch",
        "ro.vendor.build.security_patch",
    ] {
        if props_conf_value(prop).is_some() {
            continue;
        }
        let Some(truth) = crate::plat::vbmeta::build_prop_value(prop) else {
            continue;
        };
        let current = resetprop::read_string_property(prop).unwrap_or_default();
        if current == truth {
            continue;
        }
        set_prop(prop, &truth);
        log(&format!(
            "patch level: {prop} was {current}, restored to {truth} (build.prop)"
        ));
    }
}

fn normalize_boot_patch() {
    // 优先级：props.conf 里的伪装 > config.toml 的显式值 > boot 分区真值。
    // 伪装不只需要跳过归一，还得把三个变体都刷成伪装值 —— 面板保存时那次 resetprop
    // 不一定每条都写成（实测 ro.vendor.boot_security_patch 会漏）。
    let (value, source) = match props_conf_explicit_boot_patch() {
        Some(value) => (value, "props.conf"),
        None => match declared_boot_patchlevel() {
            Some(value) => (value, "config.toml"),
            None => match crate::plat::vbmeta::boot_image_patchlevel_date() {
                Ok(value) => (value, "boot image"),
                Err(error) => {
                    // AVB 读不到就退 vendor，跟出链侧的兜底一致；bootloader 那份
                    // boot 属性不随 OTA 更新，不作为来源。
                    match resetprop::read_string_property("ro.vendor.build.security_patch") {
                        Some(v) if !v.trim().is_empty() => (v.trim().to_string(), "vendor"),
                        _ => {
                            log(&format!(
                                "boot patch: cannot read boot image metadata: {error:#}"
                            ));
                            return;
                        }
                    }
                }
            },
        },
    };
    write_patch_state(&value, source);
    let mut changed = false;
    for prop in BOOT_PATCH_PROPS {
        if resetprop::read_string_property(prop).as_deref() == Some(value.as_str()) {
            continue;
        }
        if set_prop(prop, &value) {
            changed = true;
        }
    }
    if changed {
        log(&format!("boot patch: properties set to {value} ({source})"));
    }
}

/// props.conf 里手写的 boot 补丁（伪装参数那页）。三个变体任一有值即算。
fn props_conf_explicit_boot_patch() -> Option<String> {
    BOOT_PATCH_PROPS
        .iter()
        .find_map(|key| props_conf_value(key))
}

/// 把最终值告诉 keymint：`/data/misc/ommega/patch.state`。
fn write_patch_state(value: &str, source: &str) {
    let body = format!("boot_patchlevel={value}\nsource={source}\n");
    let path = "/data/misc/ommega/patch.state";
    if fs::read_to_string(path).ok().as_deref() == Some(body.as_str()) {
        return;
    }
    if let Err(error) = fs::write(path, body.as_bytes()) {
        log(&format!("boot patch: cannot write {path}: {error}"));
    }
}

/// config.toml `[trust] boot_patchlevel` 里手写的值（auto/latest 不算）。
fn declared_boot_patchlevel() -> Option<String> {
    let text = fs::read_to_string(CONFIG_TOML).ok()?;
    let value = text.lines().find_map(|line| {
        let line = line.trim();
        let (key, value) = line.split_once('=')?;
        (key.trim() == "boot_patchlevel").then(|| {
            value
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string()
        })
    })?;
    (!value.is_empty() && !matches!(value.as_str(), "auto" | "latest")).then_some(value)
}

/// 链上的 `verifiedBootKey` 是 SHA256(vbmeta 公钥)。bootloader 只在 bootconfig 里给
/// digest（那就是 verifiedBootHash），不给公钥摘要 —— 原生 HAL 自己读分区算。
/// 不算这一份就只能发全零或者自己派生的假值，两个都是明显指纹。
fn normalize_vbmeta_public_key() {
    // 伪装优先：props.conf 里写了就用写的，没写才按 vbmeta 公钥算真值。
    if let Some(value) = props_conf_value("ro.boot.vbmeta.public_key_digest") {
        let current =
            resetprop::read_string_property("ro.boot.vbmeta.public_key_digest").unwrap_or_default();
        if !current.eq_ignore_ascii_case(&value) {
            set_prop("ro.boot.vbmeta.public_key_digest", &value);
            log("vbmeta key: property set from props.conf override");
        }
        return;
    }
    let current =
        resetprop::read_string_property("ro.boot.vbmeta.public_key_digest").unwrap_or_default();
    if !current.is_empty() && current.chars().any(|c| c != '0') {
        return;
    }
    match crate::plat::vbmeta::boot_image_public_key_digest() {
        Ok(value) => {
            set_prop("ro.boot.vbmeta.public_key_digest", &value);
            log(&format!(
                "vbmeta key: property set to {value} (from vbmeta public key)"
            ));
        }
        Err(error) => log(&format!("vbmeta key: cannot read vbmeta: {error:#}")),
    }
}

/// vbmeta 摘要（链上的 `verifiedBootHash`）对齐到 bootloader 的真值。
///
/// 本机实测过：属性里能是 `8a7aa2b9…`，而 `/proc/bootconfig` 里 bootloader 写的是
/// `a2a08ff43…`——属性被改过后就再也回不去。bootconfig 只读，拿它当准。
fn normalize_vbmeta_digest() {
    // 伪装优先：写了就用写的（并保证属性也真是它），没写才用 bootloader 的真值。
    let truth = props_conf_value("ro.boot.vbmeta.digest")
        .or_else(crate::plat::vbmeta::bootloader_vbmeta_digest);
    let Some(truth) = truth else {
        return;
    };
    let current = resetprop::read_string_property("ro.boot.vbmeta.digest").unwrap_or_default();
    if current.eq_ignore_ascii_case(&truth) {
        return;
    }
    set_prop("ro.boot.vbmeta.digest", &truth);
    log(&format!(
        "vbmeta digest: property was {current}, set to {truth}"
    ));
}

fn props_conf_value(key: &str) -> Option<String> {
    let text = fs::read_to_string(PROPS_CONF).ok()?;
    config_value(&text, key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn sync_remote_identity() {
    let configured = fs::read_to_string(CONF_PATH).unwrap_or_default();
    let remote_mode = config_value(&configured, "remote").is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    });

    if !remote_mode {
        // 本地模式：把上次远程留下的 boot 状态改回「已锁定 + 已验证」，
        // 跟证书那侧的口径保持一致。
        lock_down_boot_state();
        return;
    }

    // 只有真连得上远端 B 才拿 identity 刷属性。以前只看 remote 开关：面板勾了远端
    // 而 device_id/token 没填时，链其实是本地出的，属性却被 B（或上一次）的旧值
    // 刷回去 —— boot 补丁就此锁死，本机就是这么锁在 2025-03-01 的。
    let remote_ready = ["device_id", "token"]
        .iter()
        .all(|key| config_value(&configured, key).is_some_and(|v| !v.trim().is_empty()));
    if !remote_ready {
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
            // 写失败也照样记账：`ro.product.*` 这种属性本来就未必写得进去，
            // 不记账就会每 10 秒重试一轮。身份值真的变了（B 换机器）时这里的
            // 比对不命中，自然还会再写一次。
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
            for prop in BOOT_PATCH_PROPS {
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
