use std::ffi::c_void;

use log::{debug, error, info, warn, LevelFilter};
use nix::unistd::Pid;

pub mod config;
pub mod filter;
pub mod forward;
pub mod hide;
pub mod hook;
pub mod identify;
pub mod inject;
pub mod ipc;
pub mod logging;
pub mod parcel;
pub mod soterta;
pub mod sys;
pub mod tracker;
pub mod utils;

// AIDL 绑定跟 keymint 主体共用一份（由 ommega lib 生成），否则进程内那个本地对象
// 对不上具体类型，FromIBinder 只能走远端代理。
pub use ommega::{android, top, vendor};

/// 主目标：KeyMint 的客户端进程，这个注不进去就算启动失败。
const KEYSTORE_PROCESS: &str = "keystore2";
/// SOTER 的宿主进程：App 的 SOTER 调用都是它转成对 HAL 的调用发出去的，
/// hook 得在它进程里才认得到那条 transaction。它是附加目标，没在跑也不影响主路。
const SOTER_HOST_PROCESS: &str = "com.tencent.soter.soterserver";
/// SOTER HAL 的进程名。宿主把 app 的 SOTER 调用转成对它的调用，所以注上它就能
/// 看见直接打到 HAL 的那条路（`service call` 绕开宿主，只有注进 HAL 才有反应）。同样是
/// 附加目标，没在跑只记一条日志。
///
/// 各家 HAL 的进程名不一样，摆一起挨个试：高通是 `vendor.qti.hardware.soter-service`，
/// 联发科走 Trustonic 那套的叫 `vendor.trustonic.soter@1.0-service`（一加 PLC110 实测，
/// 它上面根本没有高通那个进程），小米是个单独的 HIDL 服务，按 HIDL 的老规矩叫
/// `vendor.xiaomi.hardware.soterservice@1.0-service`。一个都没匹配上也不当事 ——
/// 宿主那条路（app → 宿主 → HAL）本来就在宿主进程里，这条只为了 `service call` 那种
/// 绕开宿主直接打 HAL 的流量。
const SOTER_HAL_PROCESSES: [&str; 5] = [
    "vendor.qti.hardware.soter-service",
    // 高通的 HIDL 版：进程名带 `@1.0`，跟上面那个不带版本的 AIDL 服务并存于不同
    // 平台。PGP110 / Android 15 就是这种（vendor_hal_soter_qti 域）。
    "vendor.qti.hardware.soter@1.0-service",
    "vendor.trustonic.soter@1.0-service",
    "vendor.xiaomi.hardware.soterservice@1.0-service",
    "vendor.microtrust.hardware.soter@1.0-service",
];

/// 已经注过的目标不要再注第二遍：payload 是同一个可执行文件，dlopen 第二次就是第二份
/// 代码、各自一套全局状态，两边的初始化会互相扯（实测往已经注过的 SOTER 宿主再注一次，
/// 目标进程直接 SIGABRT）。判据是目标里有没有我们自己的线程名 —— 这名字是 payload 起来
/// 之后自己起的，跟注入走的是文件还是 memfd、标识符叫什么都不相干。
const PAYLOAD_THREAD_NAMES: [&str; 3] = ["injector-config", "ommega-mirror-r", "ommega-binder-p"];

fn payload_thread_names_match(name: &str) -> bool {
    PAYLOAD_THREAD_NAMES.contains(&name)
}

fn payload_thread_present(pid: i32) -> bool {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        payload_thread_names_match(comm.trim())
    })
}

/// 自检要打的目标。宿主取 HAL 用的就是这些名字，一个接口一个实例。
///
/// 高通是 `vendor.qti.hardware.soter-service` 那个进程、服务名不带版本；联发科走
/// Trustonic 那套（一加 PLC110 实测），服务名里嵌着版本、接口描述符也不同。摆一起
/// 挨个试：在 ServiceManager 里查不到的会直接报错退出，不碍事。
const SOTER_HAL_CANDIDATES: [(&str, &str); 2] = [
    (
        "vendor.qti.hardware.soter.ISoter/default",
        "vendor.qti.hardware.soter.ISoter",
    ),
    (
        "vendor.trustonic.hardware.soter.ITrustonicSoter/default",
        "vendor.trustonic.hardware.soter.ITrustonicSoter",
    ),
];
/// ISoter.getDeviceId(out SoterBufferReturn)。挑它做自检是因为纯只读：不建密钥、
/// 不动 TEE 里的任何东西。
const SOTER_HAL_GET_DEVICE_ID: u32 = 8;

fn in_soter_host() -> bool {
    std::fs::read_to_string("/proc/self/cmdline")
        .map(|cmdline| cmdline.split('\0').next() == Some(SOTER_HOST_PROCESS))
        .unwrap_or(false)
}

/// 宿主是不是 keystore2。它的 cmdline 是 `/system/bin/keystore2`，按 basename 认。
fn in_keystore2_host() -> bool {
    std::fs::read_to_string("/proc/self/cmdline")
        .map(|cmdline| {
            cmdline
                .split('\0')
                .next()
                .map(|path| path.rsplit('/').next().unwrap_or(path) == "keystore2")
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// 进程内 KeyMint 的开关：默认开，`/data/misc/ommega/inproc` 写 `0` 才关（回到走 RPC
/// 的那套：单独一个 HAL 进程）。留这个开关是为了出事能一条命令退回去。
fn inproc_keymint_enabled() -> bool {
    match std::fs::read_to_string("/data/misc/ommega/inproc") {
        Ok(text) => text.trim() != "0",
        Err(_) => true,
    }
}

///
/// 为什么非得自己造：宿主平时根本没人喊 —— 淘宝和 QQ音乐只 bind 上、从不调用，
/// 宿主自己的 Java 日志一条都没有。没有流量，`parse_write_buffer` 里那个
/// `observe` 就等于没被跑过，后面拦截那块改起来没法验。
///
/// 起独立线程、还先睡一会儿：这条调用的 ioctl 本身就是被 hook 的，跑在 `entry`
/// 的栈上等于 hook 还没装完就自己撞自己。
fn spawn_soter_selfcheck() {
    let thread = std::thread::Builder::new()
        .name("soter-selfcheck".to_string())
        .spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(2000));
            for (service, interface) in SOTER_HAL_CANDIDATES {
                match soter_selfcheck_transact(service, interface) {
                    Ok(error_code) => info!(
                        "event=soter selfcheck {service} getDeviceId returned code={error_code}"
                    ),
                    Err(error) => warn!("event=soter selfcheck {service} failed: {error:#}"),
                }
            }
        });
    if let Err(error) = thread {
        warn!("event=soter selfcheck thread did not start: {error}");
    }
}

/// 给 write 侧那套拦截造一次真流量。
///
/// 这里**必须**走 libbinder_ndk，不能图省事用 rsbinder：rsbinder 是纯 Rust 自己
/// 实现对 /dev/binder 的 ioctl，不引用 libbinder.so，而我们 hook 打在 libbinder*
/// .so 的 ioctl GOT 上，所以 rsbinder 发出去的调用绕过了 hook。之前用 rsbinder
/// 跑出来的 code=0 是真实 HAL 回的，当成"拦截生效"是错的。
fn soter_selfcheck_transact(service: &str, interface: &str) -> anyhow::Result<i32> {
    crate::hook::soter_ndk::transact(service, interface, SOTER_HAL_GET_DEVICE_ID)
        .map_err(|error| anyhow::anyhow!(error))
}

/// 扫 `/proc` 找 SOTER HAL 进程：cmdline 里含 `soter`、但不是腾讯的宿主进程。
///
/// HAL 进程名各家不一样（`vendor.qti.hardware.soter-service`、
/// `vendor.qti.hardware.soter@1.0-service`、`vendor.trustonic.soter@1.0-service`……），
/// 靠硬编码列表总有遗漏。这里直接按实际在跑的进程认，认出来的名字拿去走
/// `inject_named_process`，跟硬编码列表里那些名字是同一套比对逻辑。
fn discover_soter_hal_processes() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return names;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let text = String::from_utf8_lossy(&raw).replace('\0', " ");
        let lower = text.to_ascii_lowercase();
        // 含 soter，但排除三类自己人：
        //   soterserver —— 腾讯那个宿主（`SOTER_HOST_PROCESS`，上面已经单独注了）
        //   soterta-serve / soterta-ta —— 我们自己的守护（cmdline 也带 soter，
        //     不排掉就会把自己当成 HAL 目标去注，实测会拦下）
        if !lower.contains("soter")
            || lower.contains("soterserver")
            || lower.contains("soterta-serve")
            || lower.contains("soterta-ta")
            || lower.contains("ommega-inject")
        {
            continue;
        }
        // 我们自己的进程现在是 memfd + 伪装成厂商 HAL 的名字（daemon / HAL / 软件 TA），
        // cmdline 和 comm 看着就是 `/vendor/...` 的服务，不排掉会把自己当目标注进去。
        // 真 HAL 的 exe 是 /vendor 下的真文件，不会指向 memfd。
        let self_memfd = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map(|path| path.to_string_lossy().starts_with("/memfd:"))
            .unwrap_or(false);
        if self_memfd {
            continue;
        }
        let Some(name) = utils::process_name(pid) else {
            continue;
        };
        // 光看名字带 soter 不够：检测器自己的包名就带（`com.andrealyz.soterchecker`
        // 实测被当成 HAL 注了）。HAL 必须真是 vendor 侧的：进程名以 `vendor.` 开头，
        // 或者可执行文件落在 /vendor /odm /system_ext 下面。
        let is_vendor_side = name.starts_with("vendor.") || {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|path| {
                    let path = path.to_string_lossy();
                    path.contains("/vendor/")
                        || path.contains("/odm/")
                        || path.contains("/system_ext/")
                })
                .unwrap_or(false)
        };
        if !is_vendor_side {
            continue;
        }
        if !names.iter().any(|seen| seen == &name) {
            debug!("discovered soter hal process: {name} (pid={pid})");
            names.push(name);
        }
    }
    names
}

/// 会直接调 `vendor.qti.hardware.soter@1.0::ISoter` 的厂商侧进程。
///
/// 一加的 `vendor.oplus.hardware.cryptoeng@1.0-service` 就是这种：工程模式那页的
/// SOTER key 走 cryptoeng → HIDL soter，进程名里根本没有 "soter"，
/// `SOTER_HAL_PROCESSES` 和那套动态发现都碰不到它。静态名单兜一档，再按「加载了
/// soter 的 HIDL 客户端库」扫一遍 hw 目录下的进程，别的机型换了名字也能认。
const SOTER_HIDL_CLIENT_PROCESSES: [&str; 1] = ["vendor.oplus.hardware.cryptoeng@1.0-service"];

/// 扫 /proc 找「加载了 soter HIDL 客户端库」的厂商进程。
///
/// 只认 `/bin/hw/` 下的可执行文件：cryptoeng 这类 HAL/产线工具都在那儿，量小，
/// 不用把满机器 app 的 maps 都读一遍。名字带 soter 的（原厂 HAL 自己）跳过 ——
/// 那是服务端，上面 HAL 那一路已经注过了。
fn discover_soter_hidl_clients() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return names;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        let exe = exe.to_string_lossy().to_ascii_lowercase();
        if !exe.contains("/bin/hw/") {
            continue;
        }
        let Some(name) = utils::process_name(pid) else {
            continue;
        };
        if name.contains("soter") || name.contains("ommega") {
            continue;
        }
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            continue;
        };
        let maps = maps.to_ascii_lowercase();
        if !maps.contains("soter@1.0.so") && !maps.contains("soter-1.0.so") {
            continue;
        }
        if !names.iter().any(|seen| seen == &name) {
            debug!("discovered soter hidl client: {name} (pid={pid})");
            names.push(name);
        }
    }
    names
}

/// 把 HIDL soter 客户端全注一遍。注不进去只记日志 —— 这一路只影响厂内工具，
/// 不能让 keystore2 那条主路受牵连。
fn inject_soter_hidl_clients() {
    let mut targets = discover_soter_hidl_clients();
    for name in SOTER_HIDL_CLIENT_PROCESSES {
        if !targets.iter().any(|seen| seen == name) {
            targets.push(name.to_string());
        }
    }
    if !targets.is_empty() {
        info!("soter hidl client targets: {targets:?}");
    }
    for name in &targets {
        match inject_named_process(name) {
            Ok(()) => info!("soter hidl client injection completed ({name})"),
            Err(e) => info!("soter hidl client injection skipped ({name}): {e:#}"),
        }
    }
}

/// 按进程名找目标、把 payload 注进去，顺带把它的身份打进日志。
///
/// 同名进程不止一个时每一个都注：多用户 / 分身会让 soterserver 起两份实例
/// （2026-10-22 魅族 20 Pro 上 u999 与 system 各一个），客户端只认自己那个 uid
/// 的实例，少注一个就是白干。
fn inject_named_process(name: &str) -> anyhow::Result<()> {
    let targets = utils::find_processes_by_name(name)?;
    let mut injected = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for (pid, target_path) in targets {
        match utils::executable_identity(&target_path) {
            Ok(identity) => info!(
                "{name} target pid={} exe={} sha256={} elf={}",
                pid,
                identity.path.display(),
                identity.sha256,
                identity.elf,
            ),
            Err(error) => error!(
                "failed to describe {name} executable {}: {:#}",
                target_path.display(),
                error
            ),
        }

        if payload_thread_present(pid) {
            info!("{name} target pid={pid} already carries the payload; skipping injection");
            injected += 1;
            continue;
        }

        match inject::inject_library(Pid::from_raw(pid)) {
            Ok(()) => {
                info!("{name} target pid={pid} injected");
                injected += 1;
            }
            Err(error) => {
                error!("{name} target pid={pid} injection failed: {error:#}");
                failures.push(format!("{pid}: {error:#}"));
            }
        }
    }
    if injected == 0 {
        anyhow::bail!("every {name} instance failed: {}", failures.join("; "));
    }
    if !failures.is_empty() {
        warn!(
            "{name}: {} instance(s) failed: {}",
            failures.len(),
            failures.join("; ")
        );
    }
    Ok(())
}

/// 诊断用：只注其中几个目标，逗号分隔（`keystore2` / `soter` / `soter-hidl`），`all` 或没设
/// 就是全都注。认不出来的名字当作进程名，额外再注一份 —— 临时目标不用为了它改代码。
fn selected_targets() -> (bool, bool, bool, Vec<String>) {
    let Ok(value) = std::env::var("OMMEGA_INJECT_TARGETS") else {
        return (true, true, true, Vec::new());
    };
    let value = value.to_ascii_lowercase();
    if value.trim() == "all" {
        return (true, true, true, Vec::new());
    }
    let mut extras = Vec::new();
    let mut keystore2 = false;
    let mut soter = false;
    let mut soter_hidl = false;
    for item in value.split(',') {
        match item.trim() {
            "" => {}
            "keystore2" => keystore2 = true,
            "soter" => soter = true,
            "soter-hidl" => soter_hidl = true,
            name => extras.push(name.to_string()),
        }
    }
    (keystore2, soter, soter_hidl, extras)
}

fn log_runtime_identity(role: &str) {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let egid = unsafe { libc::getegid() };
    info!(
        "runtime identity role={} uid={} euid={} gid={} egid={}",
        role, uid, euid, gid, egid
    );
}

fn main() {
    // 第一件事：把自己换成 memfd + 系统 HAL 名字的版本（名字表由 keymint 守护生）。
    // 成功的话这里不会返回。
    hide::hide_self("injector");

    /* 自检模式：给面板一个「加载就有的结论」—— 用当前生效的 ASK 签一段固定文本
    再验一遍。纯本地密码学（微秒级，不碰网络也不碰 TEE），所以不会挡任何签名路径。 */
    if let Some(arg) = std::env::args().find(|arg| arg.starts_with("--soterta-serve")) {
        logging::init_logger_fallback(LevelFilter::Debug);
        let driver = if arg.ends_with("=vnd") {
            "/dev/vndbinder"
        } else {
            "/dev/binder"
        };
        match soterta::serve(driver) {
            Ok(()) => std::process::exit(0),
            Err(error) => {
                eprintln!("soterta serve failed: {error:#}");
                std::process::exit(1);
            }
        }
    }
    if std::env::args().any(|arg| arg == "--soter-selftest") {
        match crate::hook::soter_local::selftest() {
            Ok(()) => {
                println!("ok");
                std::process::exit(0);
            }
            Err(error) => {
                eprintln!("selftest failed: {error:#}");
                std::process::exit(1);
            }
        }
    }
    // 只读探针：对着真实 SOTER HAL 打一次 getDeviceId，把回复的前几个字段打出来。
    // 没有工程模式页的机器（NX809J 那种）就靠它看 HAL 到底能不能用、我们回的字节对不对。
    if std::env::args().any(|arg| arg == "--soter-probe") {
        logging::init_logger_fallback(LevelFilter::Debug);
        let mut services: Vec<String> = SOTER_HAL_CANDIDATES
            .iter()
            .map(|(service, _)| service.to_string())
            .collect();
        if let Ok(extra) = std::env::var("OMMEGA_SOTER_SERVICE") {
            let extra = extra.trim().to_string();
            if !extra.is_empty() && !services.contains(&extra) {
                services.push(extra);
            }
        }
        for service in services {
            match soterta::probe(&service, SOTER_HAL_GET_DEVICE_ID) {
                Ok(text) => println!("{service} getDeviceId -> {text}"),
                Err(error) => println!("{service} getDeviceId -> failed: {error:#}"),
            }
        }
        std::process::exit(0);
    }
    logging::init_logger_fallback(LevelFilter::Debug);
    let config = config::get();
    if config::parse_level_filter(&config.main.log_level).is_none() {
        warn!(
            "injector logging unknown log level '{}', keeping debug fallback",
            config.main.log_level
        );
    }
    logging::apply_level(config.main.log_level_filter());
    log_runtime_identity("Launcher");
    match utils::current_exe_identity() {
        Ok(identity) => {
            info!(
                "injector binary build_id={} build_target={} git_sha={} runtime_arch={} exe={} sha256={} elf={}",
                utils::build_id(),
                utils::build_target(),
                utils::build_git_sha(),
                std::env::consts::ARCH,
                identity.path.display(),
                identity.sha256,
                identity.elf,
            );
        }
        Err(error) => {
            error!("failed to describe current injector binary: {:#}", error);
        }
    }

    let (inject_keystore, inject_soter, inject_soter_hidl, extra_targets) = selected_targets();

    if inject_keystore {
        match inject_named_process(KEYSTORE_PROCESS) {
            Ok(()) => {
                info!("injection completed");
                utils::update_module_status("Ommega ✅ 运行中");
            }
            Err(e) => {
                error!("injection failed: {:#}", e);
                utils::update_module_status("Ommega ❌ 启动失败");
                std::process::exit(1);
            }
        }
    } else {
        info!("keystore2 target skipped by OMMEGA_INJECT_TARGETS");
    }

    // SOTER 的宿主进程也注一份。它没在跑（或者注入失败）只记一条日志：
    // keystore2 那条主路已经成了，模块不该因为这个起不来。
    if inject_soter {
        match inject_named_process(SOTER_HOST_PROCESS) {
            Ok(()) => info!("soter host injection completed"),
            Err(e) => warn!("soter host injection skipped: {:#}", e),
        }
        // HAL 的进程名一家一个样，逐个试。谁都不在就都不注（宿主那条路照常）。
        // 先动态扫一遍：cmdline 里带 soter 但不是腾讯宿主（那个上面已经单独注了）。
        // 新厂商的 HAL 自己会认出来，不用改代码。
        let mut hal_targets = discover_soter_hal_processes();
        for hal in SOTER_HAL_PROCESSES {
            if !hal_targets.iter().any(|name| name == hal) {
                hal_targets.push(hal.to_string());
            }
        }
        if !hal_targets.is_empty() {
            info!("soter hal targets: {hal_targets:?}");
        }
        for hal in &hal_targets {
            match inject_named_process(hal) {
                Ok(()) => info!("soter hal injection completed ({hal})"),
                Err(e) => info!("soter hal injection skipped ({hal}): {:#}", e),
            }
        }
    } else {
        info!("soter host target skipped by OMMEGA_INJECT_TARGETS");
    }

    // 走 HIDL 调 SOTER 的厂商进程：它们既不是 HAL 也不叫 soter（一加的 cryptoeng 就是），
    // 上面那套发现不到。它们发出去的正是 14 号 verifyAttkKeyPair 这类只有我们能答的号 ——
    // 不注进去，工程模式那页的 SOTER 项就一直吃原厂 TA 的 -20。
    if inject_soter || inject_soter_hidl {
        inject_soter_hidl_clients();
    } else {
        info!("soter hidl client target skipped by OMMEGA_INJECT_TARGETS");
    }

    // 命令行上点名要注的额外进程（调试用）。同样只是 best-effort：少注一个不该让
    // 模块起不来。
    for name in &extra_targets {
        match inject_named_process(name) {
            Ok(()) => info!("extra target {name} injection completed"),
            Err(e) => warn!("extra target {name} injection skipped: {:#}", e),
        }
    }
}

/// 诊断用：payload 里 panic 一律 abort，消息默认去 stderr（app 进程那是 /dev/null），
/// 事后只剩一条 SIGABRT。这里把 panic 原文写进日志和两个兜底文件。
fn install_payload_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let location = info
                .location()
                .map(|l| format!("{}:{}", l.file(), l.line()))
                .unwrap_or_else(|| "<unknown>".to_string());
            let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic>".to_string()
            };
            log::error!("payload panic at {location}: {msg}");
            // 只落数据根的 logs（1777 + sticky，app 域的 payload 也写得进去）。
            // 以前另写一份 /data/local/tmp/ommega-panic.log 兜底，那是 shell 的
            // 公共目录，不再拿它当我们的落盘位置。
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/data/misc/ommega/logs/panic.log")
            {
                use std::io::Write;
                let _ = writeln!(f, "[{}] {location}: {msg}", std::process::id());
            }
        }));
    });
}

#[no_mangle]
#[allow(unused)]
pub extern "C" fn entry(handle: *const c_void) -> bool {
    // This runs inside the target process, so we must initialize logging again
    // for that process. On Android this enables both logcat and stdout logging.
    logging::init_logger_fallback(LevelFilter::Debug);
    install_payload_panic_hook();
    // 这一条必须放在最前面：下面 `config::get()` 一起手就会起一个叫
    // `injector-config` 的线程，而那正好也是我们用来认「已经注过了」的记号。
    // 放到后面查就等于自己把自己当成前一份，把 hook 跳过。
    if payload_thread_present(std::process::id() as i32) {
        warn!("payload is already loaded in this process; skipping repeated initialization");
        return true;
    }
    let config = config::get();
    if config::parse_level_filter(&config.main.log_level).is_none() {
        warn!(
            "injector logging unknown log level '{}', keeping debug fallback",
            config.main.log_level
        );
    }
    logging::apply_level(config.main.log_level_filter());
    log_runtime_identity("Payload");
    log::info!(
        "Injected library entry called! Handle: {:?}, build_id={}, build_target={}, runtime_arch={}, current_exe={}",
        handle,
        utils::build_id(),
        utils::build_target(),
        std::env::consts::ARCH,
        utils::current_exe_path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
    );
    // keystore2 里就地把 KeyMint 主体拉起来：调用改走本地对象，不再多一个进程、
    // 不多一跳 RPC。起不来就还是走原来那条路（hook 装不装不受影响）。
    if in_keystore2_host() && inproc_keymint_enabled() {
        ipc::enable_inproc_keymint();
        ommega::inproc::request_start();
    }
    // RPC 会话不通不代表 hook 没用：SOTER 那条观察路径完全不碰网络，而 KeyMint
    // 那条路每次请求本来就会在 ommega 不可用时回退到系统服务（rewrite 里有那套
    // 判断）。所以这里只记日志，照样把 hook 装上。
    if let Err(error) = ipc::install_direct_rpc_session() {
        error!("failed to initialize ommega RPC session: {error:#}; installing the hook anyway");
    }
    // 日志到底装上没有、装在哪：app 域的进程（SOTER 宿主、SOTER HAL）各自的 uid 不一样，
    // 有的机型上那个目录它们进不去，本地日志就整条哑掉。这一条顺 RPC 递给 daemon，
    // 至少能看见原因，不用再靠猜。
    crate::ipc::report_event(format!(
        "event=logging role=Payload path={} enabled={} probes=[{}] error={}",
        crate::logging::active_path(),
        crate::logging::enabled(),
        crate::logging::path_probes(),
        crate::logging::init_error(),
    ));
    // 装不上 hook 只降级，不 abort：payload 跑在别人的进程里（SOTER 宿主、SOTER HAL），
    // 一个 GOT 都改不动的时候应该少一路拦截，而不是把宿主搞崩。
    if let Err(error) = hook::init_hook() {
        log::error!("binder hook not installed in this process: {error:#}");
    }
    if in_soter_host() {
        // 宿主是「只会回 -200 的壳」时不造这种流量：它压根不发 HAL 请求，自检没有意义；
        // 而它每秒一次 `getService(vendor…soter)` 会把原厂那个懒加载 HAL 叫起来 ——
        // 那个一注册就按 VINTF 把名字从我们手里拿走，soterta.sh 再抢回来，来回打架
        // （实测：TA 起 → 名字被抢 → 重抢 → 踢宿主，5 秒一轮）。
        if hook::soter::app_serving_enabled() {
            log::info!("event=soter host is a stub; skipping the HAL selfcheck");
        } else {
            spawn_soter_selfcheck();
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soter_hal_targets_include_the_exact_microtrust_process() {
        assert!(SOTER_HAL_PROCESSES.contains(&"vendor.microtrust.hardware.soter@1.0-service"));
        assert!(!SOTER_HAL_PROCESSES.contains(&"soter-1-0"));
        assert!(
            !SOTER_HAL_PROCESSES.contains(&"vendor.microtrust.hardware.soter@1.0-service-helper")
        );
    }

    #[test]
    fn payload_thread_names_recognize_our_own_threads() {
        for name in PAYLOAD_THREAD_NAMES {
            assert!(
                payload_thread_names_match(name),
                "{name} 是 payload 自己的线程"
            );
        }
    }

    #[test]
    fn payload_thread_names_ignore_other_threads() {
        for name in ["binder:4311_1", "Signal Catcher", "oommega-mirror", ""] {
            assert!(!payload_thread_names_match(name), "{name} 不是我们的线程");
        }
    }

    #[test]
    fn payload_thread_present_handles_a_missing_process() {
        assert!(
            !payload_thread_present(-1),
            "读不到就当成没有，别把注入判死"
        );
    }

    #[test]
    fn target_selection_keeps_unknown_names_as_extra_processes() {
        // 环境变量是进程级的，两个测试分开写会互相踩，所以挤在一个里串完。
        std::env::set_var("OMMEGA_INJECT_TARGETS", "keystore2,soter_hal_probe");
        let (keystore2, soter, soter_hidl, extras) = selected_targets();
        assert!(keystore2);
        assert!(!soter);
        assert!(!soter_hidl);
        assert_eq!(extras, vec!["soter_hal_probe".to_string()]);

        std::env::set_var("OMMEGA_INJECT_TARGETS", "all");
        let (keystore2, soter, soter_hidl, extras) = selected_targets();
        assert!(keystore2 && soter && soter_hidl);
        assert!(extras.is_empty());

        std::env::set_var("OMMEGA_INJECT_TARGETS", "soter-hidl");
        let (keystore2, soter, soter_hidl, _) = selected_targets();
        assert!(
            !keystore2 && !soter && soter_hidl,
            "daemon 只叫这一路时别把别的一起注了"
        );

        std::env::remove_var("OMMEGA_INJECT_TARGETS");
        let (keystore2, soter, _, extras) = selected_targets();
        assert!(keystore2 && soter);
        assert!(extras.is_empty());
    }
}
