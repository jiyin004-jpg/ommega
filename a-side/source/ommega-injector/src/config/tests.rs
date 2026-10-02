use super::*;
use std::ops::Deref;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempConfigPath(PathBuf);

impl Deref for TempConfigPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for TempConfigPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        if let (Some(parent), Some(file_name)) = (self.0.parent(), self.0.file_name()) {
            let temp = parent.join(format!(
                ".{}.tmp-{}",
                file_name.to_string_lossy(),
                std::process::id()
            ));
            let _ = fs::remove_file(temp);
        }
    }
}

fn temp_config_path(name: &str) -> TempConfigPath {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    TempConfigPath(std::env::temp_dir().join(format!("ommega-injector-{name}-{unique}.toml")))
}

#[test]
fn scoped_test_config_is_nested_and_thread_local() {
    assert!(TEST_CONFIG.with(|slot| slot.borrow().is_none()));
    let mut disabled = InjectorConfig::default();
    disabled.main.enabled = false;
    let outer = test_config_guard(disabled);
    assert!(!get().main.enabled);
    {
        let _inner = test_config_guard(InjectorConfig::default());
        assert!(get().main.enabled);
        assert!(
            std::thread::spawn(|| TEST_CONFIG.with(|slot| slot.borrow().is_none()))
                .join()
                .unwrap()
        );
    }
    assert!(!get().main.enabled);
    drop(outer);
    assert!(TEST_CONFIG.with(|slot| slot.borrow().is_none()));
}

#[test]
fn config_defaults_and_log_levels_match_contract() {
    let config = InjectorConfig::default();
    assert!(config.main.enabled);
    assert_eq!(config.scoop, default_scoop());
    assert!(config.scoop_details.is_empty());
    assert_eq!(config.main.log_level_filter(), LevelFilter::Debug);
    assert!(config.filter.block_android_package);
    assert!(!config.filter.allow_unknown_package);
    assert!(config.intercept.get_security_level);
    assert!(config.intercept.get_key_entry);
    assert!(config.intercept.update_subcomponent);
    assert!(config.intercept.list_entries);
    assert!(config.intercept.delete_key);
    assert!(config.intercept.grant);
    assert!(config.intercept.ungrant);
    assert!(config.intercept.get_number_of_entries);
    assert!(config.intercept.list_entries_batched);
    assert!(config.intercept.get_supplementary_attestation_info);

    assert_eq!(parse_level_filter("warn"), Some(LevelFilter::Warn));
    assert_eq!(parse_level_filter("WARNING"), Some(LevelFilter::Warn));
    assert_eq!(parse_level_filter("trace"), Some(LevelFilter::Trace));
    assert_eq!(parse_level_filter("unknown"), None);
}

#[test]
fn parses_new_scoop_format_and_preserves_package_details() {
    let parsed = parse_config(
        r#"
scoop = ["com.example.app", "com.other.app", "com.example.app"]

[scoop."com.example.app"]
mode = "strict"

[main]
enabled = false
log_level = "trace"

[filter]
enabled = true
deny_packages = ["com.blocked"]
block_android_package = false
allow_unknown_package = true

[intercept]
get_security_level = false
get_key_entry = true
update_subcomponent = false
list_entries = false
delete_key = false
grant = false
ungrant = false
get_number_of_entries = false
list_entries_batched = false
get_supplementary_attestation_info = true
"#,
    )
    .expect("config should parse");

    assert_eq!(
        parsed.scoop,
        vec!["com.example.app".to_string(), "com.other.app".to_string()]
    );
    assert_eq!(parsed.main.log_level_filter(), LevelFilter::Trace);
    assert!(!parsed.main.enabled);
    assert_eq!(
        parsed
            .scoop_details
            .get("com.example.app")
            .and_then(|table| table.get("mode"))
            .and_then(toml::Value::as_str),
        Some("strict")
    );
    assert!(!parsed.intercept.get_security_level);
    assert!(parsed.intercept.get_key_entry);
    assert!(!parsed.intercept.update_subcomponent);
    assert!(!parsed.intercept.list_entries);
    assert!(!parsed.intercept.delete_key);
    assert!(!parsed.intercept.grant);
    assert!(!parsed.intercept.ungrant);
    assert!(!parsed.intercept.get_number_of_entries);
    assert!(!parsed.intercept.list_entries_batched);
    assert!(parsed.intercept.get_supplementary_attestation_info);
}

#[test]
fn legacy_config_syntax_is_rejected() {
    let error = parse_config(
        r#"
[[scope]]
package = "com.legacy.app"
"#,
    )
    .expect_err("legacy scope syntax should be rejected");
    assert!(error.contains("unknown field"));

    let error = parse_config(
        r#"
scoop = ["com.example.app"]

[filter]
allow_packages = ["com.legacy.app"]
"#,
    )
    .expect_err("legacy allow_packages should be rejected");
    assert!(error.contains("unknown field"));
}

#[test]
fn rendered_config_uses_new_scoop_format() {
    let mut config = InjectorConfig {
        scoop: vec!["com.example.app".to_string()],
        ..Default::default()
    };
    let mut table = toml::Table::new();
    table.insert("enabled".to_string(), toml::Value::Boolean(true));
    config
        .scoop_details
        .insert("com.example.app".to_string(), table);

    let rendered = render_config(&config).expect("config should render");
    assert!(rendered.contains("scoop = ["));
    assert!(rendered.contains("[scoop.com.example.app]"));
    assert!(!rendered.contains("[[scope]]"));
    let reparsed = parse_config(&rendered).expect("rendered config should parse");
    assert_eq!(reparsed.scoop_details, config.scoop_details);
}

#[test]
fn missing_config_is_seeded_but_invalid_startup_config_is_untouched() {
    let path = temp_config_path("missing");

    let loaded = load_or_seed(&path, LoadContext::Startup).unwrap();
    assert!(path.exists(), "missing config should be written to disk");
    assert_eq!(loaded.version, CURRENT_CONFIG_VERSION);

    let on_disk = fs::read_to_string(&*path).expect("written config should be readable");
    let reparsed = parse_config(&on_disk).expect("written config should parse");
    assert_eq!(reparsed.scoop, loaded.scoop);

    let path = temp_config_path("invalid");
    let invalid = "[main\nbroken";
    fs::write(&*path, invalid).expect("invalid config should be written");

    let loaded = load_or_seed(&path, LoadContext::Startup).unwrap();
    assert!(
        !loaded.main.enabled,
        "invalid startup config must disable injection"
    );
    assert_eq!(fs::read_to_string(&*path).unwrap(), invalid);
    assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
}

#[test]
fn v0_config_migrates_through_public_scoop_syntax_and_preserves_mode() {
    let path = temp_config_path("v0-migration");
    let v0 = "\u{feff}scoop = [\"com.example.app\"]\r\n\r\n\
              [scoop.com.example.app]\r\nmode = \"strict\"\r\n";
    fs::write(&*path, v0).unwrap();
    fs::set_permissions(&*path, fs::Permissions::from_mode(0o640)).unwrap();

    let loaded = load_from_path(&path, true).expect("v0 config should migrate");
    assert_eq!(loaded.version, CURRENT_CONFIG_VERSION);
    assert_eq!(
        loaded
            .scoop_details
            .get("com.example.app")
            .and_then(|table| table.get("mode"))
            .and_then(toml::Value::as_str),
        Some("strict")
    );

    let migrated = fs::read_to_string(&*path).unwrap();
    assert_eq!(
        migrated,
        v0.replacen('\u{feff}', "\u{feff}version = 1\r\n", 1)
    );
    assert_eq!(fs::metadata(&*path).unwrap().mode() & 0o777, 0o640);
}

#[test]
fn explicit_v0_migration_only_replaces_the_version_value() {
    let v0 = "# keep this comment\nversion = 0 # and this one\nscoop = [\"com.example.app\"]\n";
    let (_, migrated) = parse_versioned_config(v0, true).expect("v0 config should migrate");
    assert_eq!(
        migrated.as_deref(),
        Some("# keep this comment\nversion = 1 # and this one\nscoop = [\"com.example.app\"]\n")
    );
}

#[test]
fn reload_rejects_v0_without_rewriting() {
    let path = temp_config_path("reload-v0");
    let v0 = "scoop = [\"com.example.app\"]\n";
    fs::write(&*path, v0).unwrap();

    assert!(load_or_seed(&path, LoadContext::Reload(WatchTrigger::CloseWrite)).is_none());
    assert_eq!(fs::read_to_string(&*path).unwrap(), v0);
}

#[test]
fn unsupported_versions_are_rejected_without_rewriting() {
    for contents in ["version = -1\n", "version = 2\n", "version = \"1\"\n"] {
        assert!(parse_config(contents).is_err());
    }

    let path = temp_config_path("future-version");
    let future = "version = 2\n";
    fs::write(&*path, future).unwrap();
    let loaded = load_or_seed(&path, LoadContext::Startup).unwrap();
    assert!(!loaded.main.enabled);
    assert_eq!(fs::read_to_string(&*path).unwrap(), future);
}

#[test]
fn template_scope_matches_default_scope() {
    let template = include_str!("../../../template/injector.toml");
    let parsed = parse_config(template).expect("template injector config should parse");
    assert_eq!(parsed.scoop, default_scoop());
}

#[test]
fn replace_save_retry_only_retries_read_failures() {
    let path = temp_config_path("replace-save-retry");
    let mut attempts = 0usize;
    let mut sleeps = Vec::new();

    let loaded = load_with_read_race_retry(
        &path,
        LoadContext::Reload(WatchTrigger::ReplaceSave),
        |_path| {
            attempts += 1;
            match attempts {
                1 => Err(LoadError::Io(io::Error::from(io::ErrorKind::NotFound))),
                2 => Err(LoadError::Io(io::Error::from(
                    io::ErrorKind::PermissionDenied,
                ))),
                _ => Ok(InjectorConfig::default()),
            }
        },
        |duration| sleeps.push(duration),
    )
    .expect("replace-save retry should eventually succeed");

    assert_eq!(loaded.retries, 2);
    assert_eq!(attempts, 3);
    assert_eq!(sleeps.len(), 2);
    assert!(sleeps
        .iter()
        .all(|duration| *duration == REPLACE_SAVE_RETRY_INTERVAL));

    let path = temp_config_path("replace-save-parse");
    let mut sleeps = Vec::new();

    let error = load_with_read_race_retry(
        &path,
        LoadContext::Reload(WatchTrigger::ReplaceSave),
        |_path| Err(LoadError::Parse("broken".to_string())),
        |duration| sleeps.push(duration),
    )
    .expect_err("parse failures should bypass replace-save retries");

    assert!(matches!(error, LoadError::Parse(_)));
    assert!(sleeps.is_empty());
}

#[test]
fn flat_config_bool_reads_the_webroot_spellings() {
    let path = temp_config_path("flat-bool");
    fs::write(
        &*path,
        "# comment\nurl: http://example\ndebug_logging: on\nglobal_scope: false\n",
    )
    .expect("flat config should be writable");

    assert_eq!(
        clienta_config_bool(&path, &["debug_logging", "debug", "verbose"]),
        Some(true),
        "`on` 是开"
    );
    assert_eq!(
        clienta_config_bool(&path, &["global_scope"]),
        Some(false),
        "写了 false 就是明确的关"
    );
    assert_eq!(
        clienta_config_bool(&path, &["soter_inject"]),
        None,
        "缺键返回 None，调用处才合并得上默认值"
    );

    fs::write(&*path, "Global_Scope:  1\n").expect("flat config should be writable");
    assert_eq!(
        clienta_config_bool(&path, &["global_scope"]),
        Some(true),
        "键大小写和 1 都要认"
    );

    assert_eq!(
        clienta_config_bool(
            Path::new("/definitely/not/there/config"),
            &["debug_logging"]
        ),
        None,
        "文件读不到就是 None，由调用处决定要不要当关"
    );
}
