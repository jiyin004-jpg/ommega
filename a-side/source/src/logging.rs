use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use anyhow::Result;
use log::LevelFilter;

const DEFAULT_LOG_PATH: &str = "/data/misc/ommega/logs/keymint.log";
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} [{h({l})}] {M} - {m}{n}";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();
/// The WebUI log switch, decided once during [`init_logger`].  Kept around so
/// the `eprintln!` fallbacks (which are not part of the `log` crate) can honour
/// the same switch instead of leaking into the root manager's service log.
static ENABLED: AtomicBool = AtomicBool::new(false);

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
        if let Err(error) = init_logger_inner() {
            eprintln!("keymint logging failed to initialize: {error:#}");
        }
    });
}

fn init_logger_inner() -> Result<()> {
    // 文件 + logcat 双写。文件是正式的，但它的 SELinux 上下文（system_app_data_file）
    // 让 adb/su 都读不到，出问题时完全没档案可查；logcat 那条 adb 能直接读，
    // 所以两个appender 都装。
    let (config, file_logging_ready) = kmr_common::runtime::logging::build_file_config(
        DEFAULT_LOG_PATH,
        PATTERN,
        LevelFilter::Trace,
        "keymint logging",
    )?;
    log4rs::init_config(config)?;
    log::set_max_level(LevelFilter::Debug);

    // logcat：一直挂上，不依赖文件是否写得成功（文件在 app 域里被挡也无所谓）。
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("ommega-keymint"),
    );

    if file_logging_ready {
        log::info!(
            "file logging enabled at {} with level {:?}",
            DEFAULT_LOG_PATH,
            LevelFilter::Debug
        );
    }

    Ok(())
}
