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
/// SOTER 的宿主进程：App 的 SOTER 调用由它转成对 HAL 的调用，hook 必须装在它进程里
/// 才能看到那条 transaction。附加目标，没在跑不影响主路。
const SOTER_HOST_PROCESS: &str = "com.tencent.soter.soterserver";
/// SOTER HAL 的进程名，逐个尝试：注上它才能看见绕过宿主直接打 HAL 的流量
/// （`service call` 不经过宿主）。附加目标，没在跑只记一条日志。
/// 各家名字不同：高通 `vendor.qti.hardware.soter-service`，联发科（Trustonic）
/// `vendor.trustonic.soter@1.0-service`，小米
/// `vendor.xiaomi.hardware.soterservice@1.0-service`。
/// 一个都没匹配上不影响宿主那条路（app → 宿主 → HAL）。
const SOTER_HAL_PROCESSES: [&str; 5] = [
    "vendor.qti.hardware.soter-service",
    // 高通的 HIDL 版：进程名带 `@1.0`，与上面不带版本的 AIDL 服务按平台二选一。
    "vendor.qti.hardware.soter@1.0-service",
    "vendor.trustonic.soter@1.0-service",
    "vendor.xiaomi.hardware.soterservice@1.0-service",
    "vendor.microtrust.hardware.soter@1.0-service",
];

/// 已注过的目标不能再注第二遍：重复 dlopen 会得到第二份代码与全局状态，初始化互相
/// 干扰并可能导致 SIGABRT。判据是目标进程里有没有下面这些 payload 自己起的线程名，
/// 与注入方式（文件或 memfd）无关。
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

/// 自检要打的目标，一个接口一个实例，与宿主取 HAL 用的名字一致。
/// 高通的服务名不带版本；联发科（Trustonic）服务名内嵌版本、接口描述符也不同。
/// 在 ServiceManager 里查不到的会直接报错，不影响其它目标。
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

/// 进程内 KeyMint 的开关：默认开，`/data/misc/ommega/inproc` 写 `0` 才关，回退到
/// 独立 HAL 进程走 RPC 的旧路径。
fn inproc_keymint_enabled() -> bool {
    match std::fs::read_to_string("/data/misc/ommega/inproc") {
        Ok(text) => text.trim() != "0",
        Err(_) => true,
    }
}

/// 自检流量必须自己造：宿主平时没有真实调用（app 只 bind 不调用），没有流量
/// `parse_write_buffer` 的 `observe` 分支就跑不到。
/// 用独立线程并先 sleep 2s：这条调用的 ioctl 本身被 hook，在 `entry` 栈上执行
/// 会在 hook 装完之前撞到自己。
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

/// 给 write 侧拦截造一次真实流量。
/// 必须走 libbinder_ndk：rsbinder 直接对 /dev/binder 做 ioctl、不引用 libbinder.so，
/// 会绕过打在 libbinder*.so ioctl GOT 上的 hook（code=0 是真实 HAL 回的响应）。
fn soter_selfcheck_transact(service: &str, interface: &str) -> anyhow::Result<i32> {
    crate::hook::soter_ndk::transact(service, interface, SOTER_HAL_GET_DEVICE_ID)
        .map_err(|error| anyhow::anyhow!(error))
}

/// 扫 `/proc` 找 SOTER HAL 进程：cmdline 含 `soter` 且不是腾讯宿主。
/// HAL 进程名各家不同（`vendor.qti.hardware.soter-service`、
/// `vendor.trustonic.soter@1.0-service` 等），硬编码列表不全，故按运行中进程动态发现。
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
        // 含 soter，但排除自己人：soterserver（腾讯宿主，已单独注入）、
        // soterta-serve / soterta-ta（自家守护）、ommega-inject（自身），
        // 否则会把自己当成 HAL 目标注进去。
        if !lower.contains("soter")
            || lower.contains("soterserver")
            || lower.contains("soterta-serve")
            || lower.contains("soterta-ta")
            || lower.contains("ommega-inject")
        {
            continue;
        }
        // 自家进程由 memfd 承载并伪装成 `/vendor/...` 服务，按 exe 指向 /memfd: 排除；
        // 真 HAL 的 exe 是 /vendor 下的真实文件。
        let self_memfd = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map(|path| path.to_string_lossy().starts_with("/memfd:"))
            .unwrap_or(false);
        if self_memfd {
            continue;
        }
        let Some(name) = utils::process_name(pid) else {
            continue;
        };
        // 名字带 soter 不够（检测器包名也带）；HAL 必须是 vendor 侧：进程名以
        // `vendor.` 开头，或 exe 位于 /vendor、/odm、/system_ext 之下。
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

/// 会直接调 `vendor.qti.hardware.soter@1.0::ISoter` 但进程名不含 "soter" 的厂商侧进程，
/// 例如 `vendor.oplus.hardware.cryptoeng@1.0-service`（工程模式页的 SOTER key 走
/// cryptoeng → HIDL soter）。静态名单兜底，另有按 HIDL 客户端库的动态发现。
const SOTER_HIDL_CLIENT_PROCESSES: [&str; 1] = ["vendor.oplus.hardware.cryptoeng@1.0-service"];

/// 扫 /proc 找加载了 soter HIDL 客户端库的厂商进程。
/// 只看 `/bin/hw/` 下的可执行文件（cryptoeng 这类工具都在此，量小）。名字带 soter
/// 的跳过：那是服务端，已由 HAL 那一路覆盖。
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

/// 按进程名找目标并注入 payload，同时把可执行文件身份写进日志。
/// 同名进程有多个时每个都要注：多用户/分身会让 soterserver 起多份实例，客户端只认
/// 自己 uid 那份，漏注等于没注。
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

    /* 自检模式：用当前生效的 ASK 签一段固定文本再验一遍，给面板一个结论。
    纯本地密码学（微秒级，不碰网络也不碰 TEE），不会挡任何签名路径。 */
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
    // 只读探针：对真实 SOTER HAL 打一次 getDeviceId 并打印回复字段，用于确认 HAL
    // 可用性与我们返回的字节。
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
        // HAL 进程名各家不同，逐个尝试；都不在就不注（宿主那条路照常）。先动态扫一遍
        // 补齐静态名单，新厂商的 HAL 也能认出来。
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

    // 走 HIDL 调 SOTER、但既不叫 soter 也不是 HAL 的厂商进程（如 cryptoeng）：其发出的
    // 14 号 verifyAttkKeyPair 等只有我们能答，不注进去工程模式页会一直拿原厂 TA 的 -20。
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

/// 诊断用：payload 里 panic 一律 abort，消息默认写 stderr（app 进程下是 /dev/null），
/// 事后只剩 SIGABRT。这里把 panic 原文写进日志和 panic.log。
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
            // 只落数据根的 logs（1777 + sticky，app 域 payload 也写得进去）；
            // 不写 /data/local/tmp 这类 shell 公共目录。
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
    // 必须放在最前面：下面的 `config::get()` 会起 `injector-config` 线程，而那正是
    // 「已经注过了」的判据，放在后面查会把自己当成前一份而跳过 hook。
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
    // RPC 会话不通不代表 hook 没用：SOTER 观察路径不碰网络，KeyMint 路径在 ommega
    // 不可用时本就会回退到系统服务。所以只记日志，照样装 hook。
    if let Err(error) = ipc::install_direct_rpc_session() {
        error!("failed to initialize ommega RPC session: {error:#}; installing the hook anyway");
    }
    // 上报日志是否装上、装在哪：app 域进程（SOTER 宿主、SOTER HAL）uid 各不相同，
    // 有的机型进不去日志目录，顺 RPC 递给 daemon 便于查因。
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
        // 宿主是「只回 -200 的壳」时不造自检流量：它不发 HAL 请求，自检无意义；且它每秒
        // 一次 `getService(vendor…soter)` 会唤醒原厂懒加载 HAL，其注册时按 VINTF 抢走名字，
        // 与我们反复争抢（约 5 秒一轮）。
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
