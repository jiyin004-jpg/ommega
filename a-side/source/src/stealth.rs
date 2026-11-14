//! 进程隐身。
//!
//! 目标：`ps` / `/proc` 里翻出来，看到的是一台正常 Android 机器该有的东西，
//! 而不是 `/data/adb/modules/ommega/libs/arm64-v8a/keymint` 这种一眼就认出来的路径。
//!
//! 两个动作：
//!
//! 1. **memfd 自举重启**：把自己读进内存文件再 `fexecve`，进程从此没有磁盘上的
//!    exe 了（`/proc/pid/exe` 只剩 `/memfd:xxx (deleted)`，只有 root 看得到）。
//!    系统里那些 HAL 全是 `/vendor/bin/hw/...` 起的，我们不做这一步，路径就是铁证。
//!
//! 2. **换个名字**：exec 时把 argv[0] 换成「本机确实有这个文件、但当前没有进程在跑」
//!    的系统二进制路径。comm 是 argv[0] 的 basename（截 15 字节），所以进程名也跟着
//!    变成那个 HAL 的名字。动态挑是为了跨机型：写死的话在别的机器上就成了「一个
//!    根本不存在的服务」或者「两个同名服务」，都比不藏更扎眼。
//!
//! 名字表落在 `conf/stealth.names`：daemon 先起、先挑一组写进去，后起的
//! soterta / injector 读同一份，保证同一台机器上不会两个进程抢同一个名字。
//!
//! 失败一律静默降级（只改 comm，或者什么都不改）—— 藏不住是次要的，起不来才是大事。

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

/// 名字表：`role=路径`，一行一个。
const NAMES_FILE: &str = "/data/misc/ommega/conf/stealth.names";
/// daemon 模式标记。名字故意取得通用 —— root 看 environ 时 `OMMEGA_*` 那种前缀
/// 等于自报家门。
const DAEMON_ENV: &str = "DAEMON_MODE";

/// 按「看起来最无关紧要」排的优先级。命中越靠前越像正经厂商 HAL。
const PREFERRED: [&str; 18] = [
    "spu",
    "weaver",
    "perf",
    "demura",
    "color",
    "lights",
    "vibrator",
    "thermal",
    "memtrack",
    "alarm",
    "factory",
    "ir-service",
    "psiclient",
    "pasrknob",
    "capabilityconfigstore",
    "display",
    "sensorscalibrate",
    "servicetracker",
];

/// 候选目录：只挑厂商分区里的服务。`/system/bin` 里是一堆通用工具（perfetto、logcat…），
/// 伪装成那些反而更显眼（一台手机上 perfetto 真跑起来就撞名了）。
const VENDOR_DIRS: [&str; 3] = ["/vendor/bin/hw", "/odm/bin/hw", "/vendor/bin"];

/// 这些名字一律不碰：要么太显眼（带 keymint/soter 字样等于告诉别人看这里），
/// 要么是核心服务（伪装成 audio / wifi 这种，被追问「为什么有两份」更麻烦）。
const AVOID: [&str; 29] = [
    "keymint",
    "keymaster",
    "soter",
    "gatekeeper",
    "keystore",
    "strongbox",
    "attest",
    "zipfuse",
    "logd",
    "toybox",
    "wpa_supplicant",
    "hostapd",
    "rild",
    "netd",
    "surfaceflinger",
    "audioserver",
    "cameraserver",
    "mediaserver",
    "test",
    "tool",
    "unittest",
    "selftest",
    "factory",
    "reg",
    "_cmd",
    "setup",
    "install",
    "probe",
    "diag",
];

/// 候选名必须像个系统常驻进程。
///
/// 一开始要求“必须是 android.hardware./vendor. 开头的 HAL”，结果这台机器
/// /vendor/bin/hw 里 66 个文件几乎全在跑，没跑的几个又都在 AVOID 里 —— 一个都挑不到。
/// 放宽成「名字里有 service/daemon/hal」：qconfigservice / dppdaemon / edgnss-daemon
/// 这些放在 ps 里一模一样正常，没必要吊死在标准 HAL 命名上。
fn looks_like_service(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if name.starts_with("android.hardware.") || name.starts_with("vendor.") {
        return true;
    }
    lower.contains("service") || lower.contains("daemon") || lower.contains("hal")
}

/// 路径最后一段（comm 就是这个，截 15 字节）。
fn basename(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "hal".to_string())
}

fn debug() -> bool {
    // 不读配置：这个模块在日志系统起来之前就要用，而且藏不藏得住跟日志开关无关。
    // 只在显式设了环境变量时打一行到 stderr，排查用。
    std::env::var_os("OMMEGA_STEALTH_DEBUG").is_some()
}

fn note(msg: &str) {
    if debug() {
        eprintln!("[stealth] {msg}");
    }
    // 开机阶段 stderr 被丢掉了，排障时看不到自举到底做到哪一步。
    // 落一行到日志文件（只在 OMMEGA_STEALTH_DEBUG 下写）。
    if debug() {
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/misc/ommega/logs/stealth.log")
        {
            let _ = writeln!(file, "{msg}");
        }
    }
}

/// 这个进程是不是已经跑在 memfd 上了。
pub fn already_hidden() -> bool {
    matches!(
        fs::read_link("/proc/self/exe"),
        Ok(path) if path.to_string_lossy().starts_with("/memfd:")
    )
}

/// 真实二进制路径：环境变量优先（memfd 重生后 /proc/self/exe 就不是真身了），
/// 其次才读 /proc/self/exe。读到的还是 memfd 就返回 None —— 调用方自己看着办。
pub fn self_path() -> Option<PathBuf> {
    let path = fs::read_link("/proc/self/exe").ok()?;
    if path.to_string_lossy().starts_with("/memfd:") {
        return None;
    }
    Some(path)
}

/// 改 comm（`ps` 里那一列 15 字节的名字）。改不了就算了。
pub fn set_comm(name: &str) {
    let mut buf = [0u8; 16];
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    buf[..n].copy_from_slice(&bytes[..n]);
    unsafe {
        libc::prctl(libc::PR_SET_NAME, buf.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
}

// ---------------------------------------------------------------------------
// 名字表
// ---------------------------------------------------------------------------

/// 已经在用的名字，拿 comm 算（不读 cmdline）。
///
/// 读别人的 `/proc/pid/cmdline` 会阻塞：目标进程卡在 D 状态时，内核那边拿不到 mm 锁，
/// 调用方就一直等。实测设备上三个这种 tr 各吃 100% CPU 跑了半个多小时，load 拉到 12。
/// comm 在 task_struct 里，读它不会卡；而我们的伪装名本来就是按 comm 前缀去重的。
fn running_first_args() -> HashSet<String> {
    running_comms()
}

fn usable_name(path: &str, busy: &HashSet<String>) -> bool {
    // busy 里是 comm，不是路径。
    if busy.contains(&comm_of(path)) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    !AVOID.iter().any(|bad| lower.contains(bad))
}

/// comm 是 basename 的前 15 个字节（内核硬截）。光路径不同不够：
/// `…display.demura-service` 和 `…display.color-service` 截出来都是
/// `vendor.qti.hard` —— ps 里看还是两个同名进程。
fn comm_of(path: &str) -> String {
    let base = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let bytes = base.as_bytes();
    let take = bytes.len().min(15);
    String::from_utf8_lossy(&bytes[..take]).into_owned()
}

/// 系统里正在跑的 comm（排掉我们自己的 memfd 进程）。
fn running_comms() -> HashSet<String> {
    let mut seen = HashSet::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return seen;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if matches!(fs::read_link(path.join("exe")), Ok(exe) if exe.to_string_lossy().starts_with("/memfd:"))
        {
            continue;
        }
        if let Ok(comm) = fs::read_to_string(path.join("comm")) {
            let comm = comm.trim();
            if !comm.is_empty() {
                seen.insert(comm.to_string());
            }
        }
    }
    seen
}

/// 从厂商分区里挑 `count` 个「有文件但没人跑」的路径。
///
/// 两条约束：
///   - 每个关键词只贡献一个（以前一个关键词就把 count 填满，结果全挑到 spu 那一堆）；
///   - comm 前缀不能重复（包括跟系统里正在跑的进程）。
///
/// `busy` / `used_comm` 由调用方传：assign 里保留旧名字时得用同一份集合。
fn pick_names_with(
    busy: &HashSet<String>,
    used_comm: &mut HashSet<String>,
    count: usize,
) -> Vec<String> {
    let mut picked: Vec<String> = Vec::with_capacity(count);
    note(&format!(
        "pick start count={count} busy={} comms={}",
        busy.len(),
        used_comm.len()
    ));
    for dir in VENDOR_DIRS {
        if let Ok(entries) = fs::read_dir(dir) {
            let n = entries.count();
            note(&format!("dir {dir} entries={n}"));
        }
    }

    fn take(
        path: String,
        count: usize,
        busy: &HashSet<String>,
        picked: &mut Vec<String>,
        used_comm: &mut HashSet<String>,
    ) -> bool {
        if picked.len() >= count || picked.iter().any(|item| item == &path) {
            return false;
        }
        if !Path::new(&path).is_file() || !usable_name(&path, busy) {
            note(&format!("take skip-path {path}"));
            return false;
        }
        let name = Path::new(&path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !looks_like_service(&name) {
            note(&format!("take skip-shape {path}"));
            return false;
        }
        let comm = comm_of(&path);
        if used_comm.contains(&comm) {
            return false;
        }
        used_comm.insert(comm);
        picked.push(path);
        true
    }

    for wanted in PREFERRED {
        if picked.len() >= count {
            break;
        }
        for dir in VENDOR_DIRS {
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            let mut names: Vec<String> = entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| name.to_ascii_lowercase().contains(wanted))
                .collect();
            names.sort();
            let mut done = false;
            for name in names {
                if take(format!("{dir}/{name}"), count, busy, &mut picked, used_comm) {
                    done = true;
                    break;
                }
            }
            if done {
                break;
            }
        }
    }

    // 关键词不够用就按目录顺序补齐（不限关键词），保证每个角色都有名字 ——
    // 少一个的话那一条就从表里缺着，启动它的脚本拿不到名字，又退回暴露路径。
    for dir in VENDOR_DIRS {
        if picked.len() >= count {
            break;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        for name in names {
            if picked.len() >= count {
                break;
            }
            take(format!("{dir}/{name}"), count, busy, &mut picked, used_comm);
        }
    }

    picked
}

/// 读名字表。
fn read_names() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(text) = fs::read_to_string(NAMES_FILE) else {
        return map;
    };
    for line in text.lines() {
        let Some((role, path)) = line.split_once('=') else {
            continue;
        };
        let role = role.trim();
        let path = path.trim();
        if !role.is_empty() && !path.is_empty() {
            map.insert(role.to_string(), path.to_string());
        }
    }
    map
}

/// 写名字表。用 tmp + rename，别让别的进程读到半截。
fn write_names(map: &HashMap<String, String>) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = Path::new(NAMES_FILE).parent() {
        let _ = fs::create_dir_all(dir);
        // 降权后的进程（HAL 的 resetprop 辅助进程跑在 keystore uid）也要读得到，
        // 否则它拿不到自己的伪装名，comm 就只能跟着父进程走（两个同名进程）。
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    }
    let mut roles: Vec<&String> = map.keys().collect();
    roles.sort();
    let mut text = String::new();
    for role in roles {
        text.push_str(role);
        text.push('=');
        text.push_str(&map[role]);
        text.push('\n');
    }
    let tmp = format!("{NAMES_FILE}.tmp");
    if let Ok(mut file) = fs::File::create(&tmp) {
        if file.write_all(text.as_bytes()).is_ok() {
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644));
            let _ = fs::rename(&tmp, NAMES_FILE);
        }
    }
}

/// 为角色分配名字。
///
/// 表里的各条**优先保留** —— 名字一换，上一轮还在跑的进程就成孤儿了（清理逻辑按
/// 新名字找，找不着），实测会出现两个 SOTER TA 同时存活。只给「路径没了」或
/// 「被别的进程占了」的那几条重新挑。
fn assign(roles: &[&str]) -> HashMap<String, String> {
    let existing = read_names();
    let busy = running_first_args();
    let mut used_comm = running_comms();

    let mut map = existing.clone();
    let mut need: Vec<&str> = Vec::new();
    for role in roles {
        let keep = existing.get(*role).is_some_and(|path| {
            Path::new(path).is_file()
                && usable_name(path, &busy)
                && !used_comm.contains(&comm_of(path))
        });
        match existing.get(*role) {
            Some(path) if keep => {
                used_comm.insert(comm_of(path));
            }
            _ => need.push(role),
        }
    }
    if need.is_empty() && roles.iter().all(|role| map.contains_key(*role)) {
        return map;
    }

    // 已经用掉的名字（保留的那些）不能再分给别的角色。
    let mut busy_all = busy.clone();
    for path in map.values() {
        busy_all.insert(comm_of(path));
    }
    let picked = pick_names_with(&busy_all, &mut used_comm, need.len());
    note(&format!("assign fill roles={need:?} picked={picked:?}"));
    for (role, path) in need.iter().zip(picked.iter()) {
        map.insert((*role).to_string(), path.clone());
    }
    write_names(&map);
    map
}

/// 只读名字表，不重新分配。fork 出来的子进程（resetprop helper）用这个：
/// 那边一写文件就可能和主进程抢，读一份现成的就够。
pub fn cached_name(role: &str) -> Option<String> {
    read_names().get(role).cloned()
}

/// 取某个角色的伪装路径。`extra_roles` 是「接下来可能还要用名字」的角色，
/// 一起参与分配，免得后起的进程拿到跟自己重复的名字。
pub fn name_for(role: &str, extra_roles: &[&str]) -> Option<String> {
    let mut roles: Vec<&str> = vec![role];
    roles.extend(extra_roles.iter().copied());
    let map = assign(&roles);
    map.get(role).cloned()
}

// ---------------------------------------------------------------------------
// memfd 自举
// ---------------------------------------------------------------------------

/// 把一个文件整个读进 memfd。返回的 fd 不带 CLOEXEC，子进程能直接继承。
///
/// 用 syscall 而不是 `libc::memfd_create`：那个封装是 API 30+ 才进 bionic 的，
/// 而模块的 target API 是 26，链接时就报 undefined symbol。内核从 3.17 就有这个
/// syscall，直接调没有版本问题。
pub fn memfd_from(path: &Path, memfd_name: &str) -> Option<RawFd> {
    let mut src = fs::File::open(path).ok()?;
    let name = CString::new(memfd_name).ok()?;
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0u32) } as libc::c_int;
    if fd < 0 {
        note("memfd_create failed");
        return None;
    }
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match std::io::Read::read(&mut src, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut off = 0;
                while off < n {
                    let w = unsafe {
                        libc::write(fd, buf[off..n].as_ptr() as *const libc::c_void, n - off)
                    };
                    if w <= 0 {
                        note("write to memfd failed");
                        unsafe { libc::close(fd) };
                        return None;
                    }
                    off += w as usize;
                }
            }
            Err(_) => {
                unsafe { libc::close(fd) };
                return None;
            }
        }
    }
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    Some(fd)
}

fn exec_from(fd: RawFd, argv0: &str, extra_args: &[String], extra_env: &[(&str, String)]) -> bool {
    let mut argv: Vec<CString> = Vec::with_capacity(extra_args.len() + 1);
    let Ok(a0) = CString::new(argv0) else {
        return false;
    };
    argv.push(a0);
    for arg in extra_args {
        match CString::new(arg.as_str()) {
            Ok(value) => argv.push(value),
            Err(_) => return false,
        }
    }
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    let mut env: Vec<CString> = std::env::vars()
        // 进程环境是 root 一条命令就能看的东西（`tr '\0' '\n' < /proc/pid/environ`），
        // 里面不能出现我们的名字：`_` 是 shell 填的可执行路径，OMMEGA_* / KSU_MODULE
        // 一看就知道是什么，PWD 也可能是模块目录。要传的值走 `run/keymint.env`。
        .filter(|(key, _)| {
            !matches!(key.as_str(), "_" | "PWD" | "KSU_MODULE")
                && !key.starts_with("OMMEGA_")
                && !key.starts_with("KSU_")
                && !extra_env.iter().any(|(name, _)| name == key)
        })
        .filter_map(|(key, value)| CString::new(format!("{key}={value}")).ok())
        .collect();
    // PWD 留一个中性的：完全删掉反而比系统进程少一条，看着也不对。
    if let Ok(item) = CString::new("PWD=/") {
        env.push(item);
    }
    for (key, value) in extra_env {
        if let Ok(item) = CString::new(format!("{key}={value}")) {
            env.push(item);
        }
    }
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    // `fexecve` 同样是 API 30+ 的符号，跑 `execve` 走 `/proc/self/fd/<n>`：路径
    // 在 exec 那一刻才解析，fd 还在，效果一样；顺手把它设成 CLOEXEC，免得新映像
    // 里白白挂着这个 fd。
    let Ok(path) = CString::new(format!("/proc/self/fd/{fd}")) else {
        return false;
    };
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        // 工作目录也必须换掉：从模块脚本 fork 出来的进程 cwd 就是模块目录，
        // `/proc/<pid>/cwd` 一读就是 daemon-injector / keybox_tee.xml 那一堆，
        // 比进程名还有说服力（实测有人就是看 cwd 定位的）。
        let root = CString::new("/").unwrap();
        libc::chdir(root.as_ptr());
        libc::execve(path.as_ptr(), ptrs.as_ptr(), envp.as_ptr());
    }
    false
}

/// 把一个 ELF 从 memfd 起成伪装进程。给 shell 用（soterta / injector 这些
/// 脚本拉起来的进程，自己没法做 memfd）。
///
/// 成功不会返回；失败返回 false，调用方自己决定要不要退回普通启动。
pub fn exec_hidden(real: &str, argv0: &str, extra_args: &[String]) -> bool {
    let Some(fd) = memfd_from(Path::new(real), &basename(argv0)) else {
        return false;
    };
    if exec_from(fd, argv0, extra_args, &[]) {
        return true;
    }
    unsafe { libc::close(fd) };
    false
}

/// 把一段 shell 脚本从 memfd 起成伪装进程：`/system/bin/sh -s` 从标准输入读脚本，
/// 于是 cmdline 里只剩伪装名和 `-s`，看不到模块里的脚本路径。
///
/// `$0` 变成 "sh"，脚本里靠 `$0` 推模块目录的地方已经改成 `${OMMEGA_MODDIR:-固定路径}`，
/// 所以这里不需要再往环境里塞变量。
pub fn exec_script_hidden(script: &str, argv0: &str, extra_args: &[String], _moddir: &str) -> bool {
    let Some(fd) = memfd_from(Path::new(script), &basename(argv0)) else {
        return false;
    };
    // 脚本得在 fd 0 上，sh 才会当标准输入读
    unsafe {
        if fd != 0 {
            if libc::dup2(fd, 0) < 0 {
                libc::close(fd);
                return false;
            }
            libc::close(fd);
        }
        libc::lseek(0, 0, libc::SEEK_SET);
    }

    let mut argv: Vec<CString> = Vec::new();
    let Ok(a0) = CString::new(argv0) else {
        return false;
    };
    argv.push(a0);
    argv.push(CString::new("-s").unwrap());
    // `--` 不能省：脚本自己的参数可能以 `-` 开头（adbr-daemon.sh 收 `--a`），
    // 不加的话 sh 会把它当自己的选项，直接 `unknown option: --` 退出 ——
    // 进程起来一秒就没了，日志里只有一行看不懂的报错。
    argv.push(CString::new("--").unwrap());
    for arg in extra_args {
        match CString::new(arg.as_str()) {
            Ok(value) => argv.push(value),
            Err(_) => return false,
        }
    }
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    let env: Vec<CString> = std::env::vars()
        // 同 exec_from：环境里不保留 `_` 和 OMMEGA_* 这种一眼就认出来的东西。
        .filter(|(key, _)| key != "_" && !key.starts_with("OMMEGA_"))
        .filter_map(|(key, value)| CString::new(format!("{key}={value}")).ok())
        .collect();
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    let shell = CString::new("/system/bin/sh").unwrap();
    unsafe {
        // cwd 同理：不能把模块目录带进去。
        let root = CString::new("/").unwrap();
        libc::chdir(root.as_ptr());
        libc::execve(shell.as_ptr(), ptrs.as_ptr(), envp.as_ptr());
    }
    false
}

/// 启动时的第一件事：把自己换成「伪装名 + memfd」的版本。
///
/// 只在开机时（进程刚被 shell 拉起来）跑一次，靠环境变量和 `/proc/self/exe`
/// 两道判断防重入：HAL 是 daemon 用同一个 memfd 拉起来的，进来就已经是 memfd 了。
pub fn bootstrap(role: &str, extra_roles: &[&str]) {
    note(&format!(
        "bootstrap role={role} hidden={}",
        already_hidden()
    ));
    if already_hidden() {
        // memfd 起的进程，内核把 comm 设成了执行路径的 basename —— 而那个路径是
        // `/proc/self/fd/4`，于是一排进程的 comm 全是 "4"。自己改回来。
        if let Some(arg0) = std::env::args().next() {
            if arg0.starts_with('/') {
                set_comm(&basename(&arg0));
            }
        }
        return;
    }
    let Some(real) = self_path() else {
        return;
    };
    let Some(fake) = name_for(role, extra_roles) else {
        return;
    };

    let base = basename(&fake);
    let Some(fd) = memfd_from(&real, &base) else {
        // memfd 不成就只改 comm，至少 ps 里不再是我们的名字。
        set_comm(&base);
        return;
    };

    let mut keep: Vec<String> = Vec::new();
    let mut env: Vec<(&str, String)> = Vec::new();
    for arg in std::env::args().skip(1) {
        if arg == "--daemon" {
            env.push((DAEMON_ENV, "1".to_string()));
        } else {
            keep.push(arg);
        }
    }

    // fexecve 成功就不会回来；回来就说明失败，退回只改 comm。
    if !exec_from(fd, &fake, &keep, &env) {
        note("fexecve failed; falling back to comm rename");
        set_comm(&base);
        unsafe { libc::close(fd) };
    }
}

/// 这个进程是不是以 daemon 模式启动的（`--daemon` 已经被自举换成了环境变量）。
pub fn daemon_mode() -> bool {
    std::env::var(DAEMON_ENV).as_deref() == Ok("1")
}

/// 给 daemon 用：从已经打开的 memfd 拉起子进程，argv[0] 用伪装路径。
///
/// 走 `/proc/self/fd/<n>`：内核按 fd 指的文件跑，子进程的 cmdline 是伪装路径，
/// exe 是 memfd，`/data/adb/modules/ommega` 一个字都不出现。
pub fn command_from_memfd(fd: RawFd, argv0: &str) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(format!("/proc/self/fd/{fd}"));
    command.arg0(argv0);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avoide_names_are_rejected() {
        let busy = HashSet::new();
        assert!(!usable_name(
            "/vendor/bin/hw/android.hardware.security.keymint-service-qti",
            &busy
        ));
        assert!(usable_name(
            "/vendor/bin/hw/vendor.qti.hardware.display.color-service",
            &busy
        ));
    }

    #[test]
    fn busy_names_are_rejected() {
        let mut busy = HashSet::new();
        busy.insert(comm_of("/vendor/bin/hw/qconfigservice"));
        assert!(!usable_name("/vendor/bin/hw/qconfigservice", &busy));
    }
}
