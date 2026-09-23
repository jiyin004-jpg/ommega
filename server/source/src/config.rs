//! Runtime configuration, mirrored from relay_server/config/settings.py + .env.
//!
//! Precedence: environment variables override `.env` file values.
//! Values are read once at startup.

use std::path::Path;

/// 版本号唯一来源 = 仓库根的 `VERSION`（A 模块 / B 模块 / b-app / 服务端 四端一致）。
///
/// `Cargo.toml` 的 version 在编译期被写进二进制，所以这里用 `env!` 读它，再由
/// `version_tests` 里的单测强制它等于 `VERSION` 文件：只改一处会在 `cargo test` 直接红。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub http_port: u16,
    pub https_port: u16,
    pub use_tls: bool,
    pub tls_cert_file: String,
    pub tls_key_file: String,
    pub relay_token: String,
    pub admin_user: String,
    pub admin_password: String,
    /// Extra admin accounts in `user:pass,user2:pass2` form (RELAY_ADMIN_EXTRA).
    pub admin_extra: String,
    /// Secret key used to derive the Fernet key for encrypting stored private
    /// keys (RELAY_SECRET_KEY). Empty => plaintext fallback.
    pub secret_key: String,
    /// Auto keybox refresh enable (KEYBOX_REFRESH_ENABLED).
    pub keybox_refresh_enabled: bool,
    /// Auto keybox refresh interval in seconds (KEYBOX_REFRESH_INTERVAL_SEC).
    pub keybox_refresh_interval_secs: u64,
    /// `physical` (default) routes A/B tasks through the queue; `server_keybox`
    /// fulfils tasks locally using the stored DeviceServerIdentity.
    pub attest_source: String,
    /// Seconds a B-side assignment may stay pending before being reclaimed.
    ///
    /// “设备接到任务后多久必须交结果”的死线，超时就把任务放回队列，免得一台卡住
    /// 的设备拖住整条请求。TEE 里做一次 keymint 调用是百毫秒量级，设备又是在长
    /// 轮询上等着拿任务，留 3s 已经很宽松。可用 `RELAY_ASSIGNMENT_TIMEOUT` 调整。
    pub assignment_timeout_secs: u64,
    /// A-side wait-for-result timeout, seconds —— layer ① 等 B 设备结果的上限。
    ///
    /// 必须小于 a 端的 HTTP 读超时（`a-side/source/src/remote.rs` 的
    /// `READ_TIMEOUT_MS = 30_000`）：超了就是“a 端已经放弃、服务端还在等”，用户
    /// 什么都拿不到。同时也必须足够短：一次 TEE 认证正常情况下是百毫秒到一两秒
    /// （实测小米 1.6s / 三星 0.5s），等几十秒说明设备已经不对劲了，此时快速失败、
    /// 让回退阶梯（服务端密钥 → 自签 → a 端本地）接手反而更快也更可靠。3s 覆盖
    /// “一次长轮询空档 + TEE 运算 + 回传”的常规耗时。可用
    /// `RELAY_WAIT_RESULT_TIMEOUT` 调整。
    ///
    /// 代价：b 端若需要重试回传（最多 4×33s + 7s 退避），这次结果可能晚于 a 端
    /// 超时，就作废了 —— 但那时 a 端已经从回退层拿到一条能用的链。
    pub wait_result_timeout_secs: u64,
    /// Long-poll default timeout, seconds.
    pub poll_timeout_secs: u64,
    /// MySQL connection URL: `mysql://user:pass@host:port/dbname`
    pub mysql_url: String,
    /// MySQL session time zone (e.g. `+08:00` for Beijing time).
    pub mysql_time_zone: String,
    /// ip2region.xdb path for offline IP-to-region lookup. Empty => disabled.
    pub geo_db_path: String,
    /// Rate limit: max valid requests per token per window.
    pub rate_limit_requests: u64,
    /// Rate limit: max invalid (failed-auth) requests per IP per window.
    pub invalid_rate_limit_requests: u64,
    pub rate_limit_window_secs: u64,
    /// 聚合支付(易支付/码支付)网关地址，例如 https://pay.example.com/submit.php
    pub pay_gateway: String,
    /// 聚合支付商户号 (pid)
    pub pay_pid: String,
    /// 聚合支付商户密钥 (key)，用于签名
    pub pay_key: String,
    /// 聚合支付异步通知地址 (notify_url)
    pub pay_notify_url: String,
    /// 聚合支付同步跳转地址 (return_url)
    pub pay_return_url: String,
    /// 商品名称前缀，例如 "OMMEGA激活卡"
    pub pay_product_name: String,
    /// 回调验签通过后可用的备用校验串（向后兼容 CARD_CALLBACK_SECRET）
    pub pay_callback_secret: String,
    /// 是否要求认证（默认 true）。设为 false 时，若未配置任何 token 则允许匿名访问。
    pub auth_required: bool,
    /// Pending 任务 TTL（秒）。超过此时间未被领取的 pending 任务会标记为失败。
    pub pending_ttl_secs: u64,
    /// 已完成/失败任务的最大保留数量（每类独立计数）。
    pub completed_max: usize,
    /// 已完成/失败任务的保留时间（秒）。
    pub completed_ttl_secs: u64,
    /// B 端一连上就替它排一次自检认证，把设备 TEE 状态（启动信息）落到状态页。
    /// 默认开；`RELAY_B_SELFCHECK=0` 关掉。
    pub b_selfcheck: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            http_port: 10886,
            https_port: 8443,
            use_tls: true,
            tls_cert_file: "data/tls/server.crt".to_string(),
            tls_key_file: "data/tls/server.key".to_string(),
            relay_token: String::new(),
            admin_user: "admin".to_string(),
            admin_password: String::new(),
            admin_extra: String::new(),
            secret_key: String::new(),
            keybox_refresh_enabled: true,
            keybox_refresh_interval_secs: 7200,
            attest_source: "physical".to_string(),
            assignment_timeout_secs: 3,
            wait_result_timeout_secs: 3,
            poll_timeout_secs: 30,
            mysql_url: String::new(),
            mysql_time_zone: "+08:00".to_string(),
            geo_db_path: "ip2region.xdb".to_string(),
            rate_limit_requests: 800,
            invalid_rate_limit_requests: 40,
            rate_limit_window_secs: 3600,
            pay_gateway: String::new(),
            pay_pid: String::new(),
            pay_key: String::new(),
            pay_notify_url: String::new(),
            pay_return_url: String::new(),
            pay_product_name: String::new(),
            pay_callback_secret: String::new(),
            auth_required: true,
            pending_ttl_secs: 300,
            completed_max: 10000,
            completed_ttl_secs: 60,
            b_selfcheck: true,
        }
    }
}

fn env_str(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn env_u64(name: &str, dflt: u64) -> u64 {
    env_str(name)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(dflt)
}

fn env_u16(name: &str, dflt: u16) -> u16 {
    env_str(name)
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(dflt)
}

fn env_bool(name: &str, dflt: bool) -> bool {
    match env_str(name).as_deref() {
        Some("1" | "true" | "yes" | "on" | "True" | "TRUE") => true,
        Some("0" | "false" | "no" | "off" | "False" | "FALSE") => false,
        Some(_) => dflt,
        None => dflt,
    }
}

/// Parse a `.env`-style file (KEY=VALUE, `#` comments) into a map.
pub fn load_dotenv(path: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let Ok(contents) = std::fs::read_to_string(path) else {
        return map;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let k = line[..eq].trim().to_string();
            let v = line[eq + 1..].trim().to_string();
            let v = v.trim_matches('"').trim_matches('\'').to_string();
            map.insert(k, v);
        }
    }
    map
}

fn env_or_dotenv(dotenv: &std::collections::HashMap<String, String>, name: &str) -> Option<String> {
    env_str(name).or_else(|| dotenv.get(name).cloned().filter(|v| !v.is_empty()))
}

impl Config {
    pub fn load() -> Self {
        // Read .env from the executable's working directory.
        let mut cfg = Config::default();
        let dotenv = if Path::new(".env").exists() {
            load_dotenv(".env")
        } else {
            std::collections::HashMap::new()
        };

        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_BIND") {
            cfg.bind_addr = v;
        }
        cfg.http_port = env_u16("RELAY_HTTP_PORT", 10886);
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_HTTP_PORT") {
            if let Ok(p) = v.parse() {
                cfg.http_port = p;
            }
        }
        cfg.https_port = env_u16("RELAY_HTTPS_PORT", 8443);
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_HTTPS_PORT") {
            if let Ok(p) = v.parse() {
                cfg.https_port = p;
            }
        }
        cfg.use_tls = env_bool("RELAY_USE_TLS", true);
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_USE_TLS") {
            cfg.use_tls = matches!(v.as_str(), "1" | "true" | "True" | "TRUE" | "yes" | "on");
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_TLS_CERTFILE") {
            cfg.tls_cert_file = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_TLS_KEYFILE") {
            cfg.tls_key_file = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_TOKEN") {
            cfg.relay_token = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_ADMIN_USER") {
            cfg.admin_user = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_ADMIN_PASSWORD") {
            cfg.admin_password = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_ADMIN_EXTRA") {
            cfg.admin_extra = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_SECRET_KEY") {
            cfg.secret_key = v;
        }
        cfg.keybox_refresh_enabled = env_bool("KEYBOX_REFRESH_ENABLED", cfg.keybox_refresh_enabled);
        cfg.keybox_refresh_interval_secs = env_u64(
            "KEYBOX_REFRESH_INTERVAL_SEC",
            cfg.keybox_refresh_interval_secs,
        );
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_ATTEST_SOURCE") {
            cfg.attest_source = v;
        }
        cfg.assignment_timeout_secs = env_u64("RELAY_ASSIGNMENT_TIMEOUT", 3);
        cfg.wait_result_timeout_secs = env_u64("RELAY_WAIT_RESULT_TIMEOUT", 3);
        cfg.poll_timeout_secs = env_u64("RELAY_POLL_TIMEOUT", 30);
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_MYSQL_URL") {
            cfg.mysql_url = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_MYSQL_TIME_ZONE") {
            cfg.mysql_time_zone = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_GEO_DB_PATH") {
            cfg.geo_db_path = v;
        }
        cfg.rate_limit_requests = env_u64("RELAY_RATE_LIMIT_REQUESTS", 800);
        cfg.invalid_rate_limit_requests = env_u64("RELAY_INVALID_RATE_LIMIT_REQUESTS", 40);
        cfg.rate_limit_window_secs = env_u64("RELAY_RATE_LIMIT_WINDOW", 3600);
        if let Some(v) = env_or_dotenv(&dotenv, "PAY_GATEWAY") {
            cfg.pay_gateway = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "PAY_PID") {
            cfg.pay_pid = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "PAY_KEY") {
            cfg.pay_key = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "PAY_NOTIFY_URL") {
            cfg.pay_notify_url = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "PAY_RETURN_URL") {
            cfg.pay_return_url = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "PAY_PRODUCT_NAME") {
            cfg.pay_product_name = v;
        }
        if let Some(v) = env_or_dotenv(&dotenv, "CARD_CALLBACK_SECRET") {
            cfg.pay_callback_secret = v;
        }
        cfg.auth_required = env_bool("RELAY_AUTH_REQUIRED", cfg.auth_required);
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_AUTH_REQUIRED") {
            cfg.auth_required = matches!(v.as_str(), "1" | "true" | "True" | "TRUE" | "yes" | "on");
        }
        cfg.pending_ttl_secs = env_u64("RELAY_PENDING_TTL", cfg.pending_ttl_secs);
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_PENDING_TTL") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.pending_ttl_secs = n;
            }
        }
        cfg.completed_ttl_secs = env_u64("RELAY_COMPLETED_TTL", cfg.completed_ttl_secs);
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_COMPLETED_TTL") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.completed_ttl_secs = n;
            }
        }
        cfg.b_selfcheck = env_bool("RELAY_B_SELFCHECK", cfg.b_selfcheck);
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_B_SELFCHECK") {
            cfg.b_selfcheck = matches!(v.as_str(), "1" | "true" | "True" | "TRUE" | "yes" | "on");
        }
        if let Ok(v) = std::env::var("RELAY_COMPLETED_MAX") {
            if let Ok(n) = v.parse::<usize>() {
                cfg.completed_max = n;
            }
        }
        if let Some(v) = env_or_dotenv(&dotenv, "RELAY_COMPLETED_MAX") {
            if let Ok(n) = v.parse::<usize>() {
                cfg.completed_max = n;
            }
        }
        cfg
    }

    pub fn server_keybox_enabled(&self) -> bool {
        self.attest_source.eq_ignore_ascii_case("server_keybox")
    }
}

#[cfg(test)]
mod version_tests {
    use super::VERSION;

    #[test]
    fn version_matches_the_repo_version_file() {
        assert_eq!(
            VERSION,
            include_str!("../../../VERSION").trim(),
            "Cargo.toml 的 version 必须等于仓库根的 VERSION（两个都要改）"
        );
    }

    /// A/B 模块与 b-app 的 versionCode 是 major*1000000+minor*1000+patch 推出来的，
    /// 版本号必须是这个三段格式，它们才算得出来。
    #[test]
    fn version_is_major_minor_patch() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "VERSION 必须是 MAJOR.MINOR.PATCH: {VERSION}"
        );
        for p in parts {
            assert!(
                p.parse::<u32>().is_ok(),
                "VERSION 的每一段都得是数字: {VERSION}"
            );
        }
    }
}
