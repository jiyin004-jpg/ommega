use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use anyhow::Result;
use log::LevelFilter;

const DEFAULT_LOG_PATH: &str = "/data/misc/keystore/ommega/logs/injector.log";
/// payload 落进 app 域时的后备：上面那个目录属于 keystore（0770），SOTER 宿主
/// 是 uid 1000，连开都开不了。这个位置由 daemon-injector 建好、权限给到 system
/// 组，system_app 写得动。
const APP_DOMAIN_LOG_PATH: &str = "/data/misc/ommega/logs/injector.log";
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} [{h({l})}] {M} - {m}{n}";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();
/// The WebUI log switch, decided once during logger init (see `enabled`).
static ENABLED: AtomicBool = AtomicBool::new(false);

/// True when logging is switched on (WebUI "启用调试日志").  The file appender and
/// the stderr fallbacks are both gated on this.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Sets the runtime level, unless logging is switched off — in that case the
/// level has to stay Off, so a later `log::set_max_level` from a config reload
/// cannot silently turn the (absent) sinks back on.
pub fn apply_level(level: LevelFilter) {
    if ENABLED.load(Ordering::Relaxed) {
        log::set_max_level(level);
    }
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
        let enabled = crate::config::clienta_debug_logging().unwrap_or(false);
        ENABLED.store(enabled, Ordering::Relaxed);
        if !enabled {
            log::set_max_level(LevelFilter::Off);
            return;
        }
        if let Err(error) = init_logger_inner(level) {
            eprintln!("injector logging failed to initialize: {error:#}");
        }
    });
}

fn init_logger_inner(configured_level: LevelFilter) -> Result<()> {
    // 只落文件。不用 logcat：那条线在 app 域里本来就不可靠，而且 A 端的日志
    // 统一走文件。目录有两个候选，哪个先装上就用哪个。
    for path in [DEFAULT_LOG_PATH, APP_DOMAIN_LOG_PATH] {
        let (config, file_logging_ready) = kmr_common::runtime::logging::build_file_config(
            path,
            PATTERN,
            LevelFilter::Trace,
            "injector logging",
        )?;

        if !file_logging_ready {
            continue;
        }

        log4rs::init_config(config)?;
        log::set_max_level(configured_level);
        log::info!(
            "initialized fallback logging at {} with fixed level {:?}",
            path,
            configured_level
        );
        return Ok(());
    }

    // 两个位置都写不进去：没地方落就不写，不装 logger，也不退回 logcat。
    log::set_max_level(LevelFilter::Off);
    Ok(())
}
