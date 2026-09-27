use std::ffi::c_void;

use log::{error, info, warn, LevelFilter};
use nix::unistd::Pid;

pub mod config;
pub mod filter;
pub mod forward;
pub mod hook;
pub mod identify;
pub mod inject;
pub mod ipc;
pub mod legacy;
pub mod logging;
pub mod parcel;
pub mod sys;
pub mod tracker;
pub mod utils;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

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
/// 它上面根本没有高通那个进程）。两个都没有也不当事 —— 宿主那条路照样是通的。
const SOTER_HAL_PROCESSES: [&str; 2] = [
    "vendor.qti.hardware.soter-service",
    "vendor.trustonic.soter@1.0-service",
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

/// 装完 hook 之后，自己对着 SOTER HAL 打一条只读调用，给 write 侧那条观察路径
/// 制造一次真实流量。
///
/// 为什么非得自己造：宿主平时根本没人喊 —— 淘宝和 QQ音乐只 bind 上、从不调用，
/// 宿主自己的 Java 日志一条都没有。没有流量，`parse_write_buffer` 里那个
/// `observe` 就等于没被跑过，后面拦截那块改起来没法验。
///
/// 起独立线程、还先睡一会儿：这条调用的 ioctl 本身就是被 hook 的，跑在 `entry`
/// 的栈上等于 hook 还没装完就自己撞自己。
fn spawn_soter_selfcheck() {
    let thread = std::thread::Builder::new()
        .name("ommega-soter-selfcheck".to_string())
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

/// 按进程名找一个目标、把 payload 注进去，顺带把它的身份打进日志。
fn inject_named_process(name: &str) -> anyhow::Result<()> {
    let (pid, target_path) = utils::find_process_by_name(name)?;
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
        return Ok(());
    }

    inject::inject_library(Pid::from_raw(pid))
}

/// 诊断用：只注其中几个目标，逗号分隔（`keystore2` / `soter`），`all` 或没设就是两个都注。
/// 认不出来的名字当作进程名，额外再注一份 —— 临时目标不用为了它改代码。进程名按原样
/// 用（只会拿去比对），所以这里先把整个值折成小写只是为了 keystore2 / soter 那两个词。
/// 平时不设这个变量，行为跟以前一样。
fn selected_targets() -> (bool, bool, Vec<String>) {
    let Ok(value) = std::env::var("OMMEGA_INJECT_TARGETS") else {
        return (true, true, Vec::new());
    };
    let value = value.to_ascii_lowercase();
    if value.trim() == "all" {
        return (true, true, Vec::new());
    }
    let mut extras = Vec::new();
    let mut keystore2 = false;
    let mut soter = false;
    for item in value.split(',') {
        match item.trim() {
            "" => {}
            "keystore2" => keystore2 = true,
            "soter" => soter = true,
            name => extras.push(name.to_string()),
        }
    }
    (keystore2, soter, extras)
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

    let (inject_keystore, inject_soter, extra_targets) = selected_targets();

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
        for hal in SOTER_HAL_PROCESSES {
            match inject_named_process(hal) {
                Ok(()) => info!("soter hal injection completed ({hal})"),
                Err(e) => info!("soter hal injection skipped ({hal}): {:#}", e),
            }
        }
    } else {
        info!("soter host target skipped by OMMEGA_INJECT_TARGETS");
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

#[no_mangle]
#[allow(unused)]
pub extern "C" fn entry(handle: *const c_void) -> bool {
    // This runs inside the target process, so we must initialize logging again
    // for that process. On Android this enables both logcat and stdout logging.
    logging::init_logger_fallback(LevelFilter::Debug);
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
    hook::init_hook().expect("failed to initialize binder ioctl hook");
    if in_soter_host() {
        spawn_soter_selfcheck();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (keystore2, soter, extras) = selected_targets();
        assert!(keystore2);
        assert!(!soter);
        assert_eq!(extras, vec!["soter_hal_probe".to_string()]);

        std::env::set_var("OMMEGA_INJECT_TARGETS", "all");
        let (keystore2, soter, extras) = selected_targets();
        assert!(keystore2 && soter);
        assert!(extras.is_empty());

        std::env::remove_var("OMMEGA_INJECT_TARGETS");
        let (keystore2, soter, extras) = selected_targets();
        assert!(keystore2 && soter);
        assert!(extras.is_empty());
    }
}
