use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Result;
use log::LevelFilter;

const DEFAULT_LOG_PATH: &str = "/data/misc/ommega/logs/keymint.log";
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} [{h({l})}] {M} - {m}{n}";
/// 开关多久看一次。面板改完开关，下一笔日志最迟这么久之后就按新值走。
const SWITCH_TICK: Duration = Duration::from_secs(5);

static LOGGER_INIT: OnceLock<()> = OnceLock::new();
/// The WebUI log switch, decided once during [`init_logger`].  Kept around so
/// the `eprintln!` fallbacks (which are not part of the `log` crate) can honour
/// the same switch instead of leaking into the root manager's service log.
static ENABLED: AtomicBool = AtomicBool::new(false);
/// appender 是否真的装过。启动时开关就是关的话不装（连日志文件都不建），
/// 之后面板把开关打开时才补装 —— `log4rs::init_config` 一辈子只能成功一次。
static APPENDER: AtomicBool = AtomicBool::new(false);

/// True when logging is switched on (WebUI "启用调试日志").  Everything that
/// writes a line — the file appender, logcat and the stderr fallbacks — is
/// gated on this.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn init_logger() {
    let _ = LOGGER_INIT.get_or_init(|| {
        // The switch is the flat A-side config's `debug_logging` key, read
        // straight from the file: this runs before the runtime config exists.
        // Off means the daemon installs no appender at all, so no log file is
        // created and the level is dropped — the file log would otherwise appear
        // even with the switch off, because the appenders themselves are built
        // at Trace and only `max_level` filtered.
        let enabled = crate::config::flat_debug_logging();
        ENABLED.store(enabled, Ordering::Relaxed);
        if !enabled {
            log::set_max_level(LevelFilter::Off);
            return;
        }
        let level = crate::config::flat_log_level();
        if let Err(error) = init_logger_inner(level) {
            eprintln!("keymint logging failed to initialize: {error:#}");
        }
    });
    spawn_switch_watcher();
}

/// 跟着面板的开关走：关掉之后 appender 还在，必须把 `max_level` 压到 Off 才真的不写。
///
/// 以前只在 `init_logger` 里读一次，于是面板关了开关也只停得住 `daemon::log()` 那条现读的路，
/// tracing / log4rs 这条一直写到进程重启。返回是否发生了变化。
pub fn refresh_switch() -> bool {
    let now = crate::config::flat_debug_logging();
    if now == ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    ENABLED.store(now, Ordering::Relaxed);
    if !now {
        log::set_max_level(LevelFilter::Off);
        return true;
    }
    let level = crate::config::flat_log_level();
    if APPENDER.load(Ordering::Relaxed) {
        // 装过了，把级别抬回来就行。
        log::set_max_level(level);
    } else if let Err(error) = init_logger_inner(level) {
        // 补装失败不能把开关留在「开」上，不然会一直以为在写日志。
        ENABLED.store(false, Ordering::Relaxed);
        eprintln!("keymint logging failed to enable: {error:#}");
    }
    true
}

/// 低频盯着开关。跟 `daemon-injector` 那边 `sync_log_flag` 一个节拍，五秒级就够。
fn spawn_switch_watcher() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("log-switch".to_string())
        .spawn(|| loop {
            std::thread::sleep(SWITCH_TICK);
            refresh_switch();
        });
    if let Err(error) = spawned {
        eprintln!("keymint logging watcher failed to start: {error}");
    }
}

fn init_logger_inner(level: LevelFilter) -> Result<()> {
    // 只落文件，不走 logcat。
    let (config, file_logging_ready) = kmr_common::runtime::logging::build_file_config(
        DEFAULT_LOG_PATH,
        PATTERN,
        level,
        "keymint logging",
    )?;
    log4rs::init_config(config)?;
    log::set_max_level(level);
    APPENDER.store(true, Ordering::Relaxed);

    if file_logging_ready {
        log::info!(
            "file logging enabled at {} with level {:?}",
            DEFAULT_LOG_PATH,
            level
        );
    }

    Ok(())
}
