use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::Result;
use log::LevelFilter;

/// 唯一的日志位置。
///
/// 必须落在 `/data/misc/ommega/logs/`：注入后的 payload 跟 SOTER 宿主（uid 1000，
/// system_app）和 HAL 进程跑在同一个地址空间里，只有这个目录的 `system_app_data_file`
/// 标签它们写得进去。`/data/adb` 是 `adb_data_file`（只有 root 能开），
/// `/data/misc/keystore` 是 0700 keystore，宿主和 HAL 都开不了。
const LOG_PATH: &str = "/data/misc/ommega/logs/injector.log";
/// 保留两个旧名字，指向同一个位置：`init_logger_inner` 的循环和
/// `loosen_app_domain_path` 的判断都还按「两个候选」写，路径一致后第一个就成、直接返回。
const DEFAULT_LOG_PATH: &str = LOG_PATH;
const APP_DOMAIN_LOG_PATH: &str = LOG_PATH;
/// 时间 | 级别 | pid/tid | 模块 | 消息。
///
/// pid/tid 是必需的：这个文件是好几个进程（注入器、SOTER 宿主、SOTER HAL）共写的，
/// 不带 pid 就只能从消息内容猜是谁写的，而「到底哪个进程没注入成功」正是要查的事。
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S)(utc)} [{h({l})}] [{P}/{T}] {M} - {m}{n}";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();
/// 实际装上 logger 的那个位置（两个候选里先成的那个）。给诊断用：用 `entry` 里
/// 那条 RPC 报给 daemon 记一笔，不然 app 域的进程只能靠猜。
static ACTIVE_PATH: Mutex<Option<String>> = Mutex::new(None);
/// 两个位置都没装上时记下的原因。同上，只为了能看见。
static INIT_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// 每个候选日志路径的自开结果（`<path>: ok` 或 `<path>: <errno>`）。
static PROBES: Mutex<Option<String>> = Mutex::new(None);

/// 装上 logger 的位置，没装上就是 `<none>`。
pub fn active_path() -> String {
    ACTIVE_PATH
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| "<none>".to_string())
}

/// 两个位置都没装上时的原因（一段文字），没失败就是空串。
pub fn init_error() -> String {
    INIT_ERROR
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default()
}

/// 两个候选路径各自开得开不开。
pub fn path_probes() -> String {
    PROBES
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_default()
}
/// The WebUI log switch, re-read by the watcher thread (see `refresh_switch`).
static ENABLED: AtomicBool = AtomicBool::new(false);
/// 配置里那个级别（`[main] log_level`）。开关只管开/关，级别记在这儿，
/// 开关从关拨回开的时候要回到这个级别，而不是回到 Debug。
static DESIRED_LEVEL: Mutex<LevelFilter> = Mutex::new(LevelFilter::Off);
/// 开关复查的间隔。SOTER 宿主重启很频繁，开关关着的时候起来的那个实例
/// 不主动回来复查，就一辈子哑着（日志那份文件就是这么停在 03:21 的）。
const SWITCH_POLL_SECS: u64 = 30;

/// True when logging is switched on (WebUI "启用调试日志").  The file appender and
/// the stderr fallbacks are both gated on this.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// 重新读一次 WebUI 的日志开关，并且把级别按新状态落下去。返回是否发生了变化。
///
/// 这里必须真去读文件：payload 落进读不到 keystore 目录的域时，开关只能从
/// daemon-injector 写下的副本里看，那个副本是会变的。
pub fn refresh_switch() -> bool {
    let now_enabled = crate::config::clienta_debug_logging().unwrap_or(false);
    if now_enabled == ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    ENABLED.store(now_enabled, Ordering::Relaxed);
    apply_level_now();
    true
}

/// Sets the runtime level.  When the WebUI switch is off the level stays Off no
/// matter what the config asks for, but the requested level is remembered so
/// turning the switch back on restores it.
pub fn apply_level(level: LevelFilter) {
    if let Ok(mut guard) = DESIRED_LEVEL.lock() {
        *guard = level;
    }
    apply_level_now();
}

fn apply_level_now() {
    let desired = DESIRED_LEVEL
        .lock()
        .map(|guard| *guard)
        .unwrap_or(LevelFilter::Off);
    let level = if enabled() { desired } else { LevelFilter::Off };
    log::set_max_level(level);
}

/// 盯着开关的后台线程。一个被注入的进程里就一个，开销是 30 秒一次 stat/open。
fn spawn_switch_watcher() {
    static WATCHER: OnceLock<()> = OnceLock::new();
    WATCHER.get_or_init(|| {
        let spawned = std::thread::Builder::new()
            .name("log-switch".to_string())
            .spawn(|| loop {
                std::thread::sleep(std::time::Duration::from_secs(SWITCH_POLL_SECS));
                refresh_switch();
            });
        if let Err(error) = spawned {
            log::warn!("failed to start the log switch watcher: {error}");
        }
    });
}

/// Fallback logger setup.  `configured_level` is the `[main] log_level` from
/// `injector.toml`; which value comes in does not matter when the WebUI log
/// switch is off — then nothing at all is written, from no process, at no level.
///
/// 开关本身走 `clienta_debug_logging()`：它先看 daemon-injector 落下的那份副本，
/// 因为这段跑在 config 之前，而且目标进程（SOTER 宿主是 uid 1000）未必进得去
/// keystore 那个目录。两处都读不到就当关着。
pub fn init_logger_fallback(level: LevelFilter) {
    let _ = LOGGER_INIT.get_or_init(|| {
        if let Ok(mut guard) = DESIRED_LEVEL.lock() {
            *guard = level;
        }
        let enabled = crate::config::clienta_debug_logging().unwrap_or(false);
        ENABLED.store(enabled, Ordering::Relaxed);
        if let Err(error) = init_logger_inner(level) {
            eprintln!("injector logging failed to initialize: {error:#}");
        }
        // 开关关着就只装 logger 不写字，但开关回头一变，这个线程能把它打开。
        spawn_switch_watcher();
    });
}

fn init_logger_inner(configured_level: LevelFilter) -> Result<()> {
    // 只落文件。不用 logcat：那条线在 app 域里本来就不可靠，而且 A 端的日志
    // 统一走文件。两个候选现在指向同一个位置（见 [`LOG_PATH`]），第一个就成了。
    //
    // 先自己开一次，只为了把 errno 记下来：appender 那边把错误咽了（只 eprintln，
    // 而注入进去的进程 stderr 根本没人看），光靠“没写出来”分不清是 DAC、SELinux
    // 还是路径本身不对。这份探针文本会顺 RPC 报给 daemon。
    let mut last_error: Option<anyhow::Error> = None;
    let mut probes: Vec<String> = Vec::new();
    // 开关关着的时候不要顺手把日志文件建出来（面板那边的契约是「关着不建 log」）。
    // 但探针得继续跑 —— 只是改成「不带 create」地开一次：文件已存在时照样能分出
    // 是 DAC、SELinux 还是路径不对，没文件就报 ENOENT，真开了开关下一轮再建。
    let switched_on = crate::config::clienta_debug_logging().unwrap_or(false);
    for (label, path) in [("keystore", DEFAULT_LOG_PATH), ("app", APP_DOMAIN_LOG_PATH)] {
        let mut probe = std::fs::OpenOptions::new();
        probe.append(true);
        if switched_on {
            probe.create(true);
        }
        match probe.open(path) {
            Ok(_) => probes.push(format!("{label}=ok")),
            Err(error) => probes.push(format!("{label}={error}")),
        }
        let (config, file_logging_ready) = match kmr_common::runtime::logging::build_file_config(
            path,
            PATTERN,
            LevelFilter::Trace,
            "injector logging",
        ) {
            Ok(value) => value,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };

        if !file_logging_ready {
            continue;
        }

        if let Err(error) = log4rs::init_config(config) {
            last_error = Some(error.into());
            continue;
        }
        apply_level_now();
        loosen_app_domain_path(path);
        if let Ok(mut guard) = ACTIVE_PATH.lock() {
            *guard = Some(path.to_string());
        }
        log::info!(
            "initialized fallback logging at {} with configured level {:?}",
            path,
            configured_level
        );
        return Ok(());
    }

    // 两个位置都写不进去：没地方落就不写，不装 logger，也不退回 logcat。
    log::set_max_level(LevelFilter::Off);
    if let Ok(mut guard) = INIT_ERROR.lock() {
        let reason = match &last_error {
            Some(error) => format!("{error:#}"),
            None => "no candidate path was writable".to_string(),
        };
        *guard = Some(format!("{reason} [{}]", probes.join(", ")));
    }
    // 没失败也记一份，看看是不是第一个位置恰好能开（那就不用管第二个）。
    if let Ok(mut guard) = PROBES.lock() {
        *guard = Some(probes.join(", "));
    }
    match last_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// app 域那份日志是好几个 uid 共用的：SOTER HAL 是 system(1000)、SOTER 宿主在某些
/// 机型上是 system、在一加 PLC110 上是 u0_a292(10292)。谁先起来谁建文件，权限按各自
/// 的 umask 来（HAL 的 umask 是 0077，建出来就是 0600），后面那个连开都开不了。
/// 建完就把它放开成 0666，目录也跟着放开 —— 只动这第二个位置，keystore 那个
/// 0660 keystore:keystore 的目录保持原样。
fn loosen_app_domain_path(path: &str) {
    if path != APP_DOMAIN_LOG_PATH {
        return;
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    if let Some(parent) = std::path::Path::new(path).parent() {
        // 目录属主是 root，payload 多半不是 —— 改不动就算了，daemon-injector
        // 那边每轮都会补一刀。
        //
        // 目录必须给 other 写（app 域 payload 要落日志），但用 sticky 位挡住
        // 删掉 / 改名别人的文件，不要把目录无保护地开成 0777。
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o1777));
    }
}
