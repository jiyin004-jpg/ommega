//! 「默认设备 id」：A 端留空时，服务端拿它挑 B。
//!
//! A 端远程模式默认不带 `device_id`（模块装好就是这样，面板也不占位一台设备），请求照发，
//! 由服务端决定落到哪台 B。
//!
//! 两条链路各有一个默认 id，互不影响：
//! - `keymint`：attest / sign / decrypt 这类走 KeyMint 的请求，落到 B 层时优先用这一台；
//!   物理模式下它是第一顺位。
//! - `soter`：SOTER 转发的请求（init/finish、建料、探针）。SOTER 层序永远 B 设备层打头
//!   （`handlers::run_soter_task_inner`），留空时直接落到这一台。
//!
//! 不能合并成一个值：KeyMint 那条要「补丁日期 / 链好看」的机器，SOTER 那条要「槽位上有
//! 真料、能签」的机器，共用一个默认值会互相拖累。同一个 SOTER 流程的 ASK / AuthKey /
//! 签名还必须出自同一台（见 `soter_gate`），所以默认值必须是固定一台，不能每次按负载挑。
//!
//! 请求自带非空 `device_id` 时一律按请求来。没配（空字符串）= 各层自己按负载挑在线 B。
//!
//! 唯一来源是环境变量：`RELAY_DEFAULT_KEYMINT_DEVICE_ID` / `RELAY_DEFAULT_SOTER_DEVICE_ID`
//! 各自的优先，缺了回落通用 `RELAY_DEFAULT_DEVICE_ID`。`data/default_device.json` 已废弃，
//! 只在单测里解析。

use std::sync::RwLock;

use serde_json::Value;

/// 单测用的落盘路径（运行时不读文件）。
#[cfg(test)]
pub const DEFAULT_PATH: &str = "data/default_device.json";

/// 老的通用环境变量：两条链路都拿它当初始值（兼容既有部署）。
pub const ENV_KEY: &str = "RELAY_DEFAULT_DEVICE_ID";

/// 设备 id 长度上限。`device-b-xxxxxxxx` 是 17 个字节，留足余量。
const MAX_LEN: usize = 128;

/// 两条链路，不能互换：SOTER 要能签的那台，KeyMint 要链好看的那台。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Chain {
    Keymint,
    Soter,
}

impl Chain {
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Keymint => "keymint",
            Chain::Soter => "soter",
        }
    }

    fn env_key(self) -> &'static str {
        match self {
            Chain::Keymint => "RELAY_DEFAULT_KEYMINT_DEVICE_ID",
            Chain::Soter => "RELAY_DEFAULT_SOTER_DEVICE_ID",
        }
    }

    /// 只给单测的旧文件解析用。
    #[cfg(test)]
    fn file_key(self) -> &'static str {
        match self {
            Chain::Keymint => "keymint_device_id",
            Chain::Soter => "soter_device_id",
        }
    }
}

#[derive(Clone, Default)]
struct Ids {
    keymint: String,
    soter: String,
}

static IDS: RwLock<Ids> = RwLock::new(Ids {
    keymint: String::new(),
    soter: String::new(),
});

/// 某条链路当前的默认设备 id（空字符串 = 没指定，按负载挑）。
pub fn get(chain: Chain) -> String {
    IDS.read()
        .map(|ids| match chain {
            Chain::Keymint => ids.keymint.clone(),
            Chain::Soter => ids.soter.clone(),
        })
        .unwrap_or_else(|poisoned| {
            let ids = poisoned.into_inner();
            match chain {
                Chain::Keymint => ids.keymint.clone(),
                Chain::Soter => ids.soter.clone(),
            }
        })
}

/// 当前两条链路的默认值（控制台一屏展示用）。
pub fn get_all() -> (String, String) {
    (get(Chain::Keymint), get(Chain::Soter))
}

/// 规范化一个设备 id：去两端空白；空字符串表示「不指定」。
/// 只做宽松校验（不允许内部空白、限长）：设备 id 是运营自己起的，拦的只是明显写错的
/// （粘贴带空格 / 换行、超长串）。
fn normalize(raw: &str) -> Result<String, String> {
    let id = raw.trim();
    if id.len() > MAX_LEN {
        return Err(format!("device id too long (>{MAX_LEN} bytes)"));
    }
    if id.chars().any(|c| c.is_whitespace()) {
        return Err("device id must not contain whitespace".to_string());
    }
    Ok(id.to_string())
}

/// 改某条链路的默认值，**只作用于当前进程**：持久化改 `.env` 后重启。
/// 不落盘是故意的 —— 默认设备只该有一个写入口（环境变量）。
pub fn set(chain: Chain, raw: &str) -> Result<String, String> {
    let id = normalize(raw)?;
    let current = get_all();
    let (keymint, soter) = match chain {
        Chain::Keymint => (id.clone(), current.1),
        Chain::Soter => (current.0, id.clone()),
    };
    if let Ok(mut w) = IDS.write() {
        w.keymint = keymint;
        w.soter = soter;
    }
    tracing::warn!(
        "default_device: {} 只改了内存，重启后会回到 .env 里的值",
        chain.as_str()
    );
    Ok(id)
}

/// 启动时装载一次，唯一来源是环境变量：两条链路各取自己的变量，都缺时回落
/// `RELAY_DEFAULT_DEVICE_ID`。写错的（含空白 / 超长）按未指定处理。
pub fn init() {
    let mut ids = Ids::default();
    for chain in [Chain::Keymint, Chain::Soter] {
        let from_env = std::env::var(chain.env_key())
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| std::env::var(ENV_KEY).ok())
            .and_then(|v| normalize(&v).ok())
            .unwrap_or_default();
        match chain {
            Chain::Keymint => ids.keymint = from_env,
            Chain::Soter => ids.soter = from_env,
        }
    }
    if ids.keymint.is_empty() && ids.soter.is_empty() {
        tracing::info!(
            "default_device: 两条链路都未指定\
             （RELAY_DEFAULT_KEYMINT_DEVICE_ID / RELAY_DEFAULT_SOTER_DEVICE_ID 都没设），\
             A 端留空时按负载挑在线 B"
        );
    } else {
        tracing::info!(
            "default_device: keymint={:?} soter={:?}（来自 .env）",
            ids.keymint,
            ids.soter
        );
    }
    if let Ok(mut w) = IDS.write() {
        *w = ids;
    }
}

/// 只给单测用：验证老文件格式的解析（运行时不读文件）。
#[cfg(test)]
fn read_file(file_path: &str) -> Ids {
    let Ok(text) = std::fs::read_to_string(file_path) else {
        return Ids::default();
    };
    // 格式 `{"keymint_device_id":"...","soter_device_id":"..."}`；老格式只有
    // `device_id`，那就两条都用它。解析失败当没配，不能因此起不来。
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("default_device: {file_path} 解析失败（{e}），当作未指定");
            return Ids::default();
        }
    };
    let pick = |key: &str| {
        normalize(v.get(key).and_then(|x| x.as_str()).unwrap_or("")).unwrap_or_default()
    };
    let legacy = pick("device_id");
    Ids {
        keymint: {
            let k = pick(Chain::Keymint.file_key());
            if k.is_empty() {
                legacy.clone()
            } else {
                k
            }
        },
        soter: {
            let s = pick(Chain::Soter.file_key());
            if s.is_empty() {
                legacy
            } else {
                s
            }
        },
    }
}

/// 把一个 A 端请求的 `device_id` 按链路补齐成「实际要用的那台」。
/// 语义：A 端留空 + 服务端配了这条链路的默认设备 = 完全等同于 A 端自带了那个 id。
/// 所以在入口处归一，后面 physical / serverbox 层序、StrongBox 分流、身份查找、
/// 队列派发、SOTER 槽位钉与会话路由看到的都是同一台具体设备。
/// 请求已带非空 id 则原样返回（哪怕那台离线）：那是调用方点名的机器，不能拿默认值截走。
/// 没配默认值时也原样返回，空 id 继续走各层按负载挑选。
pub fn fill_in_body(chain: Chain, body: &Value) -> Value {
    let raw = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if !raw.is_empty() {
        return body.clone();
    }
    let id = get(chain);
    if id.is_empty() {
        return body.clone();
    }
    let mut out = body.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("device_id".to_string(), Value::String(id));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    /// 这两个用例都靠 `OMMEGA_DEFAULT_DEVICE_FILE` 指路径（进程级），并行跑会互相盖，
    /// 所以串行。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// 每个用例用自己的一份文件：这些测试并行跑，共用路径会互相盖。
    fn with_file(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("ommega-dd-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("default_device.json");
        let path = file.to_str().unwrap().to_string();
        std::env::set_var("OMMEGA_DEFAULT_DEVICE_FILE", &path);
        reset_empty();
        path
    }

    fn reset_empty() {
        if let Ok(mut w) = IDS.write() {
            w.keymint.clear();
            w.soter.clear();
        }
    }

    #[test]
    fn normalize_trims_and_rejects_junk() {
        assert_eq!(normalize("  device-b-1  "), Ok("device-b-1".to_string()));
        assert_eq!(normalize(""), Ok(String::new()));
        assert!(normalize("device b-1").is_err());
        assert!(normalize(&"x".repeat(MAX_LEN + 1)).is_err());
    }

    #[test]
    fn chains_are_independent() {
        let _g = TEST_LOCK.lock().unwrap();
        let file = with_file("independent");

        assert_eq!(set(Chain::Keymint, "device-b-key").unwrap(), "device-b-key");
        assert_eq!(get(Chain::Keymint), "device-b-key");
        // 设 keymint 不动 soter。
        assert_eq!(get(Chain::Soter), "");

        assert_eq!(set(Chain::Soter, "device-b-sot").unwrap(), "device-b-sot");
        assert_eq!(get(Chain::Soter), "device-b-sot");
        // 设 soter 也不动 keymint。
        assert_eq!(get(Chain::Keymint), "device-b-key");

        // 入口归一：keymint 的请求拿 keymint 那台，soter 的拿 soter 那台。
        let empty = serde_json::json!({ "challenge": "AA", "device_id": "" });
        assert_eq!(
            fill_in_body(Chain::Keymint, &empty)["device_id"],
            "device-b-key"
        );
        assert_eq!(
            fill_in_body(Chain::Soter, &empty)["device_id"],
            "device-b-sot"
        );

        // 请求自带 id：两条链路都按请求来，不被默认值截走。
        let named = serde_json::json!({ "device_id": "device-b-own" });
        assert_eq!(
            fill_in_body(Chain::Keymint, &named)["device_id"],
            "device-b-own"
        );
        assert_eq!(
            fill_in_body(Chain::Soter, &named)["device_id"],
            "device-b-own"
        );

        // 清掉一条不影响另一条。
        assert_eq!(set(Chain::Keymint, "").unwrap(), "");
        assert_eq!(get(Chain::Keymint), "");
        assert_eq!(get(Chain::Soter), "device-b-sot");
        assert_eq!(fill_in_body(Chain::Keymint, &empty)["device_id"], "");

        // 改完只在内存里，不落盘（重启就回 .env 里那个值）。
        assert!(read_file(&file).keymint.is_empty());
    }

    #[test]
    fn legacy_single_id_applies_to_both() {
        let _g = TEST_LOCK.lock().unwrap();
        let file = with_file("legacy");
        std::fs::write(&file, br#"{"device_id":"device-b-old"}"#).unwrap();
        let ids = read_file(&file);
        assert_eq!(ids.keymint, "device-b-old");
        assert_eq!(ids.soter, "device-b-old");

        // 新格式优先，不再看 device_id。
        std::fs::write(
            &file,
            br#"{"device_id":"device-b-old","keymint_device_id":"device-b-k","soter_device_id":"device-b-s"}"#,
        )
        .unwrap();
        let ids = read_file(&file);
        assert_eq!(ids.keymint, "device-b-k");
        assert_eq!(ids.soter, "device-b-s");

        let _ = std::fs::remove_dir_all(Path::new(&file).parent().unwrap());
    }
}
