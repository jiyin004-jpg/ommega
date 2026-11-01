//! B 端接入名额限制。
//!
//! 一个 B 端设备在 `b/poll` 里连上来，就占一个名额。这里管的是"最多同时接几台
//! 真正能接活的 B"。0 表示不限制（默认，跟以前一样）。
//!
//! 名额满了之后的取舍是**质量优先**：
//!   - 「锁定 + 可信启动」的设备（`device_locked=true` 且 `verified_boot_state`
//!     是 verified / self-signed）优先级最高；
//!   - 只锁定、启动状态不明的次之；
//!   - 解锁的、还没出过证的（质量未知）最后。
//!
//! 所以新设备连进来时，如果名额已满但它的质量比在线的某一台高，就顶掉最差的那台；
//! 如果在线那批已经全是"锁定+可信"，就拒绝新设备（返回 403，B 端日志里能看到原因）。
//! 掉线的设备（超过在线窗口没 poll）自动腾出名额，不需要人工处理。
//!
//! 值存在 `data/b_limit.json`，跟 `attest_policy.json` 一个套路：运行时可改，
//! 改完立即生效，重启后按文件恢复。

use std::sync::atomic::{AtomicUsize, Ordering};

/// 0 = 不限制（默认）。
static MAX_B: AtomicUsize = AtomicUsize::new(0);
/// 上限取个够大的值即可：再高也没意义（一台机器同时接几百个 B 不现实）。
const MAX_B_CAP: usize = 512;

pub fn get() -> usize {
    MAX_B.load(Ordering::Relaxed)
}

pub fn path() -> std::path::PathBuf {
    std::env::var("RELAY_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("./data"))
        .join("b_limit.json")
}

pub fn set(max: usize) -> anyhow::Result<usize> {
    let max = max.min(MAX_B_CAP);
    MAX_B.store(max, Ordering::Relaxed);
    save_file(max)?;
    Ok(max)
}

fn save_file(max: usize) -> anyhow::Result<()> {
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let body = serde_json::json!({ "max_b_devices": max });
    std::fs::write(&p, serde_json::to_vec_pretty(&body)?)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", p.display()))
}

/// 启动时读一次。文件不在就是"不限制"。
pub fn load() {
    let p = path();
    let Ok(text) = std::fs::read_to_string(&p) else {
        return;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        tracing::warn!("ignoring invalid {}", p.display());
        return;
    };
    let max = v
        .get("max_b_devices")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    MAX_B.store(max.min(MAX_B_CAP), Ordering::Relaxed);
    if max > 0 {
        tracing::info!("B 接入名额限制：{max}");
    }
}
