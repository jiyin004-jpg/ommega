use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::runtime::{
    file_watch::{self, WatchTrigger},
    fs::atomic_replace_preserving_metadata,
    retry::{retry_read_race, ReadRaceErrorKind, RetryOutcome},
};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

pub const DEFAULT_CONFIG_PATH: &str = "/data/misc/keystore/ommega/injector.toml";
/// Legacy A-side (client-a) per-app interception list.  Each non-comment line is
/// a package name (optionally suffixed `!`/`?`, or a `[keybox.xml]` scope
/// header).  These packages are merged into the effective scoop so apps selected
/// in the webroot UI are intercepted exactly as under the old A-side module.
///
/// This is the single data location: the webroot UI writes it through the
/// `/data/adb/ommega/ommegadata` symlink (which points here), and the injected
/// payload (keystore2, uid 1017) reads the same file.  There is no copy.
const CLIENTA_TARGET_PATH: &str = "/data/misc/keystore/ommega/target.txt";
/// Legacy A-side flat config (same directory as `target.txt`, written by the
/// webroot UI and read by the keymint daemon).  The injector only looks at one
/// key here: `global_scope`.  Everything else in that file belongs to the
/// daemon's own parser (`crate::config` on the keymint side).
const CLIENTA_CONFIG_PATH: &str = "/data/misc/keystore/ommega/config";
/// 日志开关的副本，由 daemon-injector 按真配置写好：`log_flag: 1` / `log_flag: 0`。
///
/// 位置挑在 `/data/misc` 下面是有讲究的：SOTER 宿主是 uid 1000 的 system_app，
/// 它连 `/data/adb`（0700 root）的门都进不去，读不到就回落到「日志关」。
/// `/data/misc/ommega` 的 context 是 `system_data_file`，system_app 读得动。
const CLIENTA_LOG_FLAG_PATH: &str = "/data/misc/ommega/log_flag";
/// 同一份开关的另一个副本（root / `su` 域看这个）。曾经 daemon-injector 只写这一份、
/// payload 只读上面那一份，两边对不上：SOTER 宿主读到的是一份没人更新的旧值，
/// 于是日志在 03:21 之后一个字都不再写。现在两份都写、两份都读，先读能读到的那个。
const CLIENTA_LOG_FLAG_FALLBACK_PATH: &str = "/data/adb/ommega/log_flag";
const CURRENT_CONFIG_VERSION: u32 = 1;
const REPLACE_SAVE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const REPLACE_SAVE_RETRY_LIMIT: usize = 10;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InjectorConfig {
    pub version: u32,
    pub scoop: Vec<String>,
    pub scoop_details: BTreeMap<String, toml::Table>,
    pub main: MainConfig,
    pub filter: FilterConfig,
    pub intercept: InterceptConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct MainConfig {
    pub enabled: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    pub enabled: bool,
    pub deny_packages: Vec<String>,
    pub block_android_package: bool,
    pub allow_unknown_package: bool,
    /// Intercept every app, ignoring `scoop`/`deny_packages` and the package
    /// resolution gates ("全局作用域").  Set from the A-side WebUI; see
    /// `clienta_global_scope()`.  Local-vs-remote handling is NOT affected:
    /// this only widens which callers get handled by ommega.
    pub global_scope: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct InterceptConfig {
    pub get_security_level: bool,
    pub get_key_entry: bool,
    pub update_subcomponent: bool,
    pub list_entries: bool,
    pub delete_key: bool,
    pub grant: bool,
    pub ungrant: bool,
    pub get_number_of_entries: bool,
    pub list_entries_batched: bool,
    pub get_supplementary_attestation_info: bool,
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            scoop: default_scoop(),
            scoop_details: BTreeMap::new(),
            main: MainConfig::default(),
            filter: FilterConfig::default(),
            intercept: InterceptConfig::default(),
        }
    }
}

fn default_scoop() -> Vec<String> {
    [
        "io.github.vvb2060.keyattestation",
        "com.google.android.gsf",
        "com.google.android.gms",
        "com.android.vending",
        "com.eltavine.duckdetector",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: "debug".to_string(),
        }
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_packages: Vec::new(),
            block_android_package: true,
            allow_unknown_package: false,
            global_scope: false,
        }
    }
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            get_security_level: true,
            get_key_entry: true,
            update_subcomponent: true,
            list_entries: true,
            delete_key: true,
            grant: true,
            ungrant: true,
            get_number_of_entries: true,
            list_entries_batched: true,
            get_supplementary_attestation_info: true,
        }
    }
}

#[derive(Debug)]
enum LoadError {
    Missing(io::Error),
    Io(io::Error),
    Parse(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(error) | Self::Io(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LoadContext {
    Startup,
    Reload(WatchTrigger),
}

#[derive(Deserialize)]
struct ScoopHeaderValue {
    package: String,
}

#[derive(Deserialize)]
struct ConfigVersion {
    version: Option<toml::Spanned<i64>>,
}

#[derive(Serialize)]
struct WritableConfig<'a> {
    version: u32,
    scoop: &'a [String],
    main: &'a MainConfig,
    filter: &'a FilterConfig,
    intercept: &'a InterceptConfig,
}

static CONFIG: OnceLock<RwLock<Arc<InjectorConfig>>> = OnceLock::new();
static WATCHER_STARTED: OnceLock<()> = OnceLock::new();
static CONFIG_FILE_WRITE_LOCK: Mutex<()> = Mutex::new(());

impl LoadContext {
    fn label(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Reload(trigger) => trigger.label(),
        }
    }
}

pub fn get() -> Arc<InjectorConfig> {
    if CONFIG.get().is_none() || WATCHER_STARTED.get().is_none() {
        ensure_initialized();
    }
    let base = Arc::clone(
        &CONFIG
            .get()
            .expect("injector config should be initialized")
            .read()
            .expect("injector config lock poisoned"),
    );
    apply_clienta_overrides(base)
}

/// Applies the legacy A-side files to the effective config:
///
/// * `/data/misc/keystore/ommega/target.txt` — packages toggled in the webroot
///   UI are merged into `scoop`, so those apps are intercepted exactly as under
///   the old client-a module (only package names are added; deny/scope details
///   still come from `injector.toml`).
/// * `/data/misc/keystore/ommega/config` — its `global_scope` key switches on
///   "intercept every app" mode.
///
/// Both files are re-read on every `get()`, so toggling either one in the
/// WebUI takes effect without restarting the injector.  An absent or unreadable
/// file leaves the base config unchanged.
/// 这两个 legacy 文件（`target.txt` 和扁平 `config`）以前每笔 `get()` 都要重新
/// 读一遍、解析一遍，而 `get()` 就在每笔 binder 调用的路上。它们的改动频率和
/// 调用频率差着好几个数量级，所以最多每 200ms 重看一次，中间直接复用上次结果
/// （热路径上只剩一次锁 + 一次 `Instant::elapsed`）。
const CLIENTA_OVERRIDE_TTL: Duration = Duration::from_millis(200);

struct ClientaOverrides {
    /// `target.txt` 里的包名（已去重、已脱掉 `!`/`?` 后缀），还没跟 base 取差异。
    extras: Vec<String>,
    scope_override: Option<bool>,
}

static CLIENTA_OVERRIDE_CACHE: Mutex<Option<(Instant, Arc<ClientaOverrides>)>> = Mutex::new(None);

fn clienta_overrides() -> Arc<ClientaOverrides> {
    {
        let guard = CLIENTA_OVERRIDE_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((stamp, cached)) = guard.as_ref() {
            if stamp.elapsed() < CLIENTA_OVERRIDE_TTL {
                return Arc::clone(cached);
            }
        }
    }
    // 读文件放在锁外，别让一次慢读把别的 binder 线程堵在这把锁上。
    let fresh = Arc::new(ClientaOverrides {
        extras: read_clienta_target_extras(),
        scope_override: clienta_global_scope_override(),
    });
    let mut guard = CLIENTA_OVERRIDE_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some((Instant::now(), Arc::clone(&fresh)));
    fresh
}

fn apply_clienta_overrides(base: Arc<InjectorConfig>) -> Arc<InjectorConfig> {
    let overrides = clienta_overrides();
    // Tri-state: a `global_scope` key present in the flat config wins; when the
    // key is absent the `injector.toml` value is kept.  The WebUI always writes
    // the key, so unchecking the box there really turns the mode off.
    let scope_changed = overrides
        .scope_override
        .is_some_and(|value| value != base.filter.global_scope);
    let extras: Vec<&String> = overrides
        .extras
        .iter()
        .filter(|pkg| !base.scoop.iter().any(|s| s == *pkg))
        .collect();
    if extras.is_empty() && !scope_changed {
        return base;
    }
    let mut merged = (*base).clone();
    if let Some(value) = overrides.scope_override {
        merged.filter.global_scope = value;
    }
    merged.scoop.extend(extras.into_iter().cloned());
    Arc::new(merged)
}

/// `target.txt` 里的包名（只做内部去重，不跟 base 比）；结果由
/// `clienta_overrides` 缓存。
fn read_clienta_target_extras() -> Vec<String> {
    let Ok(contents) = fs::read_to_string(CLIENTA_TARGET_PATH) else {
        return Vec::new();
    };
    let mut extras: Vec<String> = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        // Strip the legacy `!` (force GENERATE) / `?` (force PATCH) suffixes.
        let pkg = line.trim_end_matches(['!', '?']).trim();
        if pkg.is_empty() {
            continue;
        }
        if !extras.iter().any(|s| s == pkg) {
            extras.push(pkg.to_string());
        }
    }
    extras
}

/// The flat A-side config's `global_scope` value, or `None` when the file or
/// key is absent.  Truthy spellings are `1` / `true` / `yes` / `on`
/// (case-insensitive); the webroot UI writes `true`/`false`.
fn clienta_global_scope_override() -> Option<bool> {
    clienta_config_bool(Path::new(CLIENTA_CONFIG_PATH), &["global_scope"])
}

/// The flat A-side config's log switch (`debug_logging` / `debug` / `verbose`),
/// or `None` when the file or key is absent.
///
/// Read straight from the file, not through the injector config: logging is
/// initialised before (and independently of) the config, and inside a target
/// that cannot open the flat file — the SOTER host runs as uid 1000, the file
/// lives in a 0770 keystore-owned directory — the read fails and logging falls
/// back to off.
pub fn clienta_debug_logging() -> Option<bool> {
    // 先看启动器（daemon-injector，root）读完之后写下的两份副本：`/data/misc` 那份
    // system_app 读得到（SOTER 宿主走它），`/data/adb` 那份 root/su 域读得到。
    // 两份都没有或都读不到才回落到真配置本身。
    for path in [CLIENTA_LOG_FLAG_PATH, CLIENTA_LOG_FLAG_FALLBACK_PATH] {
        if let Some(value) = clienta_config_bool(Path::new(path), &["log_flag"]) {
            return Some(value);
        }
    }
    clienta_config_bool(
        Path::new(CLIENTA_CONFIG_PATH),
        &["debug_logging", "debug", "verbose"],
    )
}

/// Reads one boolean key out of a flat `key: value` config file.  `None` when
/// the file is unreadable or the key is missing; a present key always wins, so
/// `false` has to be spelled out to turn something off.
fn clienta_config_bool(path: &Path, keys: &[&str]) -> Option<bool> {
    let contents = fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(idx) = line.find(':') else {
            continue;
        };
        let key = line[..idx].trim();
        if !keys.iter().any(|want| key.eq_ignore_ascii_case(want)) {
            continue;
        }
        return Some(matches!(
            line[idx + 1..].trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ));
    }
    None
}

fn ensure_initialized() {
    let path = config_path();
    CONFIG.get_or_init(|| {
        RwLock::new(Arc::new(
            load_or_seed(&path, LoadContext::Startup)
                .expect("startup config loading always returns a fallback"),
        ))
    });
    WATCHER_STARTED.get_or_init(|| start_watcher(path));
}

fn config_path() -> PathBuf {
    std::env::var_os("OMMEGA_INJECTOR_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn load_from_path(path: &Path, allow_migration: bool) -> Result<InjectorConfig, LoadError> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| LoadError::Io(io::Error::other("config file write lock poisoned")))?;
    let contents = fs::read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            LoadError::Missing(error)
        } else {
            LoadError::Io(error)
        }
    })?;
    let (config, migrated_contents) =
        parse_versioned_config(&contents, allow_migration).map_err(LoadError::Parse)?;
    if let Some(migrated_contents) = migrated_contents {
        let (default_uid, default_gid) = default_owner(path);
        atomic_replace_preserving_metadata(
            path,
            migrated_contents.as_bytes(),
            0o600,
            default_uid,
            default_gid,
        )
        .map_err(LoadError::Io)?;
        log::info!("migrated injector.toml to version {CURRENT_CONFIG_VERSION}");
    }
    Ok(config)
}

fn load_with_context(
    path: &Path,
    context: LoadContext,
) -> Result<RetryOutcome<InjectorConfig>, LoadError> {
    match context {
        LoadContext::Reload(trigger) if trigger.should_retry_reads() => load_with_read_race_retry(
            path,
            context,
            |path| load_from_path(path, false),
            std::thread::sleep,
        ),
        LoadContext::Startup => {
            load_from_path(path, true).map(|value| RetryOutcome { value, retries: 0 })
        }
        LoadContext::Reload(_) => {
            load_from_path(path, false).map(|value| RetryOutcome { value, retries: 0 })
        }
    }
}

fn load_or_seed(path: &Path, context: LoadContext) -> Option<InjectorConfig> {
    match load_with_context(path, context) {
        Ok(loaded) => {
            if loaded.retries > 0 {
                log::info!(
                    "{} config load from {} succeeded after {} retr{}",
                    context.label(),
                    path.display(),
                    loaded.retries,
                    if loaded.retries == 1 { "y" } else { "ies" }
                );
            }
            if matches!(context, LoadContext::Startup) {
                log::info!(
                    "loaded config from {} via {}",
                    path.display(),
                    context.label()
                );
            }
            Some(loaded.value)
        }
        Err(LoadError::Missing(error)) if matches!(context, LoadContext::Startup) => {
            log::warn!(
                "config missing at {} during startup: {}; seeding defaults",
                path.display(),
                error
            );
            let mut config = InjectorConfig::default();
            if let Err(write_error) = write_config(path, &config) {
                log::error!(
                    "failed to seed config at {}: {}; disabling injector",
                    path.display(),
                    write_error
                );
                config.main.enabled = false;
            }
            Some(config)
        }
        Err(error) => {
            log::warn!(
                "load from {} via {} failed: {}; keeping current config",
                path.display(),
                context.label(),
                error
            );
            if matches!(context, LoadContext::Startup) {
                // 启动时读不到（典型：payload 落进读不到 keystore 目录的域，
                // 比如 SOTER 宿主 uid 1000）就把注入关了——这是故意的，宁可什么都不做
                // 也别拿默认配置去拦。说清楚是“关了”，别写成“保持现有配置”让人以为
                // 还在干活。
                let mut config = current_config_snapshot();
                config.main.enabled = false;
                log::warn!(
                    "config at {} is out of reach from this domain; injector disabled here",
                    path.display()
                );
                Some(config)
            } else {
                None
            }
        }
    }
}

fn current_config_snapshot() -> InjectorConfig {
    match CONFIG.get() {
        Some(lock) => match lock.read() {
            Ok(config) => config.as_ref().clone(),
            Err(error) => {
                log::error!("current config lock poisoned while snapshotting: {}", error);
                InjectorConfig::default()
            }
        },
        None => InjectorConfig::default(),
    }
}

fn write_config(path: &Path, config: &InjectorConfig) -> io::Result<()> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| io::Error::other("config file write lock poisoned"))?;
    let contents = render_config(config)?;
    let (default_uid, default_gid) = default_owner(path);
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o600, default_uid, default_gid)?;
    log::info!("wrote config to {}", path.display());
    Ok(())
}

fn default_owner(path: &Path) -> (u32, u32) {
    if path == Path::new(DEFAULT_CONFIG_PATH) {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
}

fn render_config(config: &InjectorConfig) -> io::Result<String> {
    let mut contents = String::from(
        "# With `[filter].enabled = true`, a UID is intercepted when any package\n\
         # sharing that UID is listed in `scoop`.\n\
         # Filter deny settings still apply to every package resolved for the UID.\n\n",
    );
    let base = toml::to_string_pretty(&WritableConfig {
        version: config.version,
        scoop: &config.scoop,
        main: &config.main,
        filter: &config.filter,
        intercept: &config.intercept,
    })
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    contents.push_str(&base);

    for (package, table) in &config.scoop_details {
        contents.push('\n');
        contents.push_str("[scoop.");
        contents.push_str(package);
        contents.push_str("]\n");
        if !table.is_empty() {
            let table_body = toml::to_string_pretty(table)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            contents.push_str(&table_body);
        }
    }

    Ok(contents)
}

#[cfg(test)]
fn parse_config(contents: &str) -> Result<InjectorConfig, String> {
    parse_versioned_config(contents, true).map(|(config, _)| config)
}

fn parse_versioned_config(
    contents: &str,
    allow_migration: bool,
) -> Result<(InjectorConfig, Option<String>), String> {
    let without_bom = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let bom_len = contents.len() - without_bom.len();
    let preprocessed = preprocess_config(without_bom)?;
    let version: ConfigVersion =
        toml::from_str(&preprocessed).map_err(|error| error.to_string())?;
    let migrated = match version.version {
        None => {
            if !allow_migration {
                return Err(
                    "injector config version 0 requires an injector restart to migrate".into(),
                );
            }
            Some(insert_config_version(contents, bom_len))
        }
        Some(version) => match *version.get_ref() {
            0 if allow_migration => {
                let span = version.span();
                let mut migrated = contents.to_string();
                migrated.replace_range(span.start + bom_len..span.end + bom_len, "1");
                Some(migrated)
            }
            0 => {
                return Err(
                    "injector config version 0 requires an injector restart to migrate".into(),
                )
            }
            version if version == i64::from(CURRENT_CONFIG_VERSION) => None,
            version if version < 0 => {
                return Err(format!("config version must not be negative: {version}"))
            }
            version => {
                return Err(format!(
                "config version {version} is newer than supported version {CURRENT_CONFIG_VERSION}"
            ))
            }
        },
    };
    let candidate = migrated.as_deref().unwrap_or(contents);
    let candidate = candidate.strip_prefix('\u{feff}').unwrap_or(candidate);
    let preprocessed = preprocess_config(candidate)?;
    let parsed: InjectorConfig =
        toml::from_str(&preprocessed).map_err(|error| error.to_string())?;
    Ok((parsed.normalized(), migrated))
}

fn insert_config_version(contents: &str, bom_len: usize) -> String {
    let newline = if contents.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut migrated = String::with_capacity(contents.len() + 12);
    migrated.push_str(&contents[..bom_len]);
    migrated.push_str("version = 1");
    migrated.push_str(newline);
    migrated.push_str(&contents[bom_len..]);
    migrated
}

fn preprocess_config(contents: &str) -> Result<String, String> {
    let mut rewritten = String::with_capacity(contents.len());
    for (line_no, line) in contents.split_inclusive('\n').enumerate() {
        let (body, ending) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        rewritten.push_str(&rewrite_scoop_header(body, line_no + 1)?);
        rewritten.push_str(ending);
    }
    Ok(rewritten)
}

fn rewrite_scoop_header(line: &str, line_no: usize) -> Result<String, String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("[[") || !trimmed.starts_with("[scoop.") {
        return Ok(line.to_string());
    }

    let leading = &line[..line.len() - trimmed.len()];
    let Some(close_idx) = trimmed.find(']') else {
        return Err(format!(
            "line {line_no}: unterminated [scoop.<package>] header"
        ));
    };
    let header = &trimmed[..=close_idx];
    let trailer = &trimmed[close_idx + 1..];
    let header_body = &header[1..header.len() - 1];
    let package_fragment = header_body
        .strip_prefix("scoop.")
        .ok_or_else(|| format!("line {line_no}: invalid scoop header"))?;
    let package = decode_scoop_package_header(package_fragment.trim(), line_no)?;

    Ok(format!("{leading}[scoop_details.{package:?}]{trailer}"))
}

fn decode_scoop_package_header(fragment: &str, line_no: usize) -> Result<String, String> {
    if fragment.is_empty() {
        return Err(format!("line {line_no}: empty scoop package name"));
    }

    if (fragment.starts_with('"') && fragment.ends_with('"'))
        || (fragment.starts_with('\'') && fragment.ends_with('\''))
    {
        let wrapped = format!("package = {fragment}");
        let decoded: ScoopHeaderValue =
            toml::from_str(&wrapped).map_err(|error| format!("line {line_no}: {error}"))?;
        let package = decoded.package.trim();
        if package.is_empty() {
            return Err(format!("line {line_no}: empty scoop package name"));
        }
        return Ok(package.to_string());
    }

    Ok(fragment.to_string())
}

fn normalize_packages(packages: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for package in packages {
        let package = package.trim();
        if !package.is_empty() && seen.insert(package.to_string()) {
            normalized.push(package.to_string());
        }
    }
    normalized
}

fn normalize_scoop_details(
    details: BTreeMap<String, toml::Table>,
) -> BTreeMap<String, toml::Table> {
    let mut normalized = BTreeMap::new();
    for (package, table) in details {
        let package = package.trim();
        if !package.is_empty() {
            normalized.insert(package.to_string(), table);
        }
    }
    normalized
}

fn start_watcher(path: PathBuf) {
    let reload_path = path.clone();
    if let Err(error) =
        file_watch::spawn_path_watcher("injector-config-watch", path, move |trigger| {
            reload_runtime_config(&reload_path, trigger);
        })
    {
        log::error!("failed to start config watcher thread: {}", error);
    }
}

fn reload_runtime_config(path: &Path, trigger: WatchTrigger) {
    let Some(config) = load_or_seed(path, LoadContext::Reload(trigger)) else {
        return;
    };
    if let Some(lock) = CONFIG.get() {
        match lock.write() {
            Ok(mut guard) => {
                let level = config.main.log_level_filter();
                *guard = Arc::new(config);
                crate::logging::apply_level(level);
                log::info!(
                    "reloaded config from {} via {}",
                    path.display(),
                    trigger.label()
                );
            }
            Err(error) => {
                log::error!(
                    "failed to apply config reload from {}: {}",
                    path.display(),
                    error
                );
            }
        }
    }
}

fn load_with_read_race_retry<F, S>(
    path: &Path,
    context: LoadContext,
    mut loader: F,
    sleeper: S,
) -> Result<RetryOutcome<InjectorConfig>, LoadError>
where
    F: FnMut(&Path) -> Result<InjectorConfig, LoadError>,
    S: FnMut(Duration),
{
    retry_read_race(
        || loader(path),
        |error| match error {
            LoadError::Missing(_) | LoadError::Io(_) => ReadRaceErrorKind::Retryable,
            LoadError::Parse(_) => ReadRaceErrorKind::Fatal,
        },
        REPLACE_SAVE_RETRY_LIMIT,
        REPLACE_SAVE_RETRY_INTERVAL,
        sleeper,
        |retries, error, interval| {
            log::warn!(
                "{} config load from {} hit read-side race on retry {}/{}: {}; waiting {} ms",
                context.label(),
                path.display(),
                retries,
                REPLACE_SAVE_RETRY_LIMIT,
                error,
                interval.as_millis()
            );
        },
    )
}

pub fn parse_level_filter(value: &str) -> Option<LevelFilter> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

impl MainConfig {
    pub fn log_level_filter(&self) -> LevelFilter {
        parse_level_filter(&self.log_level).unwrap_or(LevelFilter::Debug)
    }
}

impl InjectorConfig {
    fn normalized(mut self) -> Self {
        self.scoop = normalize_packages(self.scoop);
        self.scoop_details = normalize_scoop_details(self.scoop_details);
        self
    }
}

#[cfg(test)]
mod tests;
