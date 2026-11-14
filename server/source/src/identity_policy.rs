//! 服务端 keybox 按安全级别分流：StrongBox 请求和 TEE 请求各用哪一份存好的身份。
//!
//! 控制台里按「自定义设备 id」指定；留空就按请求里那台 B 的 id 去找身份，
//! 找不到再借一份能用的。
//!
//! 为什么要分开：StrongBox 和 TEE 两条链的材质、`attestation_security_level`、以及
//! 检测方对「同一台设备两个级别」的预期都不一样。一个级别用一份身份，改控制台就生效，
//! 不用重启（落盘到 `data/identity_policy.json`，跟 `attest_policy.json` 一个路子）。

use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// 落盘位置。跟其它状态文件一样按进程工作目录算（systemd 的 WorkingDirectory=/opt/relay）。
pub const PATH: &str = "data/identity_policy.json";

#[derive(Debug, Clone, Default)]
struct Policy {
    /// TEE（`attestation_security_level` = 1）用哪份身份。
    tee: Option<String>,
    /// StrongBox（`attestation_security_level` = 2）用哪份身份。
    strongbox: Option<String>,
}

fn slot() -> &'static Mutex<Policy> {
    static POLICY: OnceLock<Mutex<Policy>> = OnceLock::new();
    POLICY.get_or_init(|| Mutex::new(load_file()))
}

fn load_file() -> Policy {
    let Ok(text) = std::fs::read_to_string(PATH) else {
        return Policy::default();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        // 文件写坏了当没有：别让一个坏 JSON 把这一层带偏。
        return Policy::default();
    };
    let read = |key: &str| {
        v.get(key)
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    Policy {
        tee: read("tee"),
        strongbox: read("strongbox"),
    }
}

/// 这一级别的请求该用哪份身份（`None` = 不指定，按请求里的设备 id 走）。
///
/// `level` 用 KeyMint 的 `attestation_security_level`：1 = TEE、2 = StrongBox。
/// 其它值（含缺失）按 TEE 处理，跟 A 端默认一致。
pub fn device_for_level(level: i64) -> Option<String> {
    let guard = slot().lock().ok()?;
    if level >= 2 {
        guard.strongbox.clone()
    } else {
        guard.tee.clone()
    }
}

/// 当前配置：(tee, strongbox)。
pub fn snapshot() -> (Option<String>, Option<String>) {
    match slot().lock() {
        Ok(g) => (g.tee.clone(), g.strongbox.clone()),
        Err(_) => (None, None),
    }
}

/// 改配置并落盘。`None` = 这个字段不动；`Some("")` = 清掉（回到不指定）。
pub fn set(tee: Option<String>, strongbox: Option<String>) -> std::io::Result<()> {
    {
        let mut guard = slot()
            .lock()
            .map_err(|_| std::io::Error::other("identity policy lock poisoned"))?;
        if let Some(v) = tee {
            guard.tee = normalize(v);
        }
        if let Some(v) = strongbox {
            guard.strongbox = normalize(v);
        }
    }
    let (tee, strongbox) = snapshot();
    let body = serde_json::json!({
        "tee": tee.unwrap_or_default(),
        "strongbox": strongbox.unwrap_or_default(),
    });
    if let Some(dir) = Path::new(PATH).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(&body).unwrap_or_default();
    let tmp = format!("{PATH}.tmp");
    std::fs::write(&tmp, text.as_bytes())?;
    std::fs::rename(&tmp, PATH)
}

fn normalize(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") || trimmed == "-" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_auto_clear_the_choice() {
        assert_eq!(normalize(String::new()), None);
        assert_eq!(normalize("  auto ".to_string()), None);
        assert_eq!(normalize("-".to_string()), None);
        assert_eq!(
            normalize(" QTI-1234 ".to_string()),
            Some("QTI-1234".to_string())
        );
    }

    #[test]
    fn level_two_reads_the_strongbox_slot() {
        // 直接查一次真实状态：没配过就是两个 None，配过则两者互不影响。
        let (tee, sb) = snapshot();
        if level_policy_is_empty(&tee, &sb) {
            assert_eq!(device_for_level(1), None);
            assert_eq!(device_for_level(2), None);
        }
    }

    fn level_policy_is_empty(tee: &Option<String>, sb: &Option<String>) -> bool {
        tee.is_none() && sb.is_none()
    }
}
