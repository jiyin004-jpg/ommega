//! 认证层序的策略（运行时可变 + 落盘）。
//!
//! 层序默认跟随模式（`RELAY_ATTEST_SOURCE`）：本地出证模式 → 服务端 keybox 先，
//! 物理模式 → 真机（B）先。三态：
//! - `auto`：跟随模式，不做任何覆盖
//! - `b_first`：强制 `b → keybox → self_signed`
//! - `keybox_first`：强制 `keybox → b → self_signed`
//!
//! 两个维度：`attest_order`（普通 attest）与 `id_attest_order`（带 `attestation_ids`
//! 的设备 ID 认证，`auto` 时与普通一致）。控制台保存即生效并落盘到
//! `data/attest_policy.json`；环境变量只作初始值（`1` → `keybox_first`，其它 → `auto`）。

use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Once;

/// 落盘位置，按进程工作目录算（systemd 的 `WorkingDirectory=/opt/relay`）。
pub const PATH: &str = "data/attest_policy.json";

/// 层序策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Order {
    /// 跟随模式（默认）。
    Auto = 0,
    /// 强制真机优先。
    BFirst = 1,
    /// 强制服务端 keybox 优先。
    KeyboxFirst = 2,
}

impl Order {
    /// 控制台 / 配置里用的机器 token。
    pub fn as_str(self) -> &'static str {
        match self {
            Order::Auto => "auto",
            Order::BFirst => "b_first",
            Order::KeyboxFirst => "keybox_first",
        }
    }

    fn from_u8(v: u8) -> Order {
        match v {
            1 => Order::BFirst,
            2 => Order::KeyboxFirst,
            _ => Order::Auto,
        }
    }
}

impl std::str::FromStr for Order {
    type Err = ();

    fn from_str(s: &str) -> Result<Order, ()> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Ok(Order::Auto),
            "b" | "b_first" | "b-first" | "device" | "b_side" => Ok(Order::BFirst),
            "keybox" | "keybox_first" | "keybox-first" | "server" => Ok(Order::KeyboxFirst),
            _ => Err(()),
        }
    }
}

static ATTEST_ORDER: AtomicU8 = AtomicU8::new(Order::Auto as u8);
static ID_ATTEST_ORDER: AtomicU8 = AtomicU8::new(Order::Auto as u8);
static ATTEST_KEY_ORDER: AtomicU8 = AtomicU8::new(AttestKeyOrder::Smart as u8);
static LOADED: Once = Once::new();

/// 证明密钥（`PURPOSE_ATTEST_KEY`）出证时走哪层。
/// 真机上证明密钥与普通密钥同一套 keybox，链根相同；物理模式下普通认证走 B、
/// 证明密钥留在本地，两边链根会分叉，所以这个开关决定要不要把证明密钥送出去。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttestKeyOrder {
    /// 智能模式（默认）：证明密钥也走服务端 keybox，物理模式下不占用 B。
    /// 链来自服务端身份，稳定快，但跟 B 那条链根不同。
    Smart = 0,
    /// 跟随模式：跟普通认证一条路，物理模式下交给 B 真机。
    /// 链根与普通认证一致（都是 B 的），代价是依赖 B 在线。
    Follow = 1,
}

impl AttestKeyOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            AttestKeyOrder::Smart => "smart",
            AttestKeyOrder::Follow => "follow",
        }
    }

    fn from_u8(v: u8) -> AttestKeyOrder {
        match v {
            1 => AttestKeyOrder::Follow,
            _ => AttestKeyOrder::Smart,
        }
    }
}

impl std::str::FromStr for AttestKeyOrder {
    type Err = ();

    fn from_str(s: &str) -> Result<AttestKeyOrder, ()> {
        match s.trim().to_ascii_lowercase().as_str() {
            "smart" | "" | "auto" => Ok(AttestKeyOrder::Smart),
            "follow" | "b" | "b_first" => Ok(AttestKeyOrder::Follow),
            _ => Err(()),
        }
    }
}

fn env_keybox_first(key: &str) -> Order {
    match std::env::var(key)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        // 老开关只有「开 = keybox 优先」有意义；关就是跟随模式，不能当成「强制真机」。
        "1" | "true" | "yes" | "on" => Order::KeyboxFirst,
        _ => Order::Auto,
    }
}

/// 启动时调一次：先用环境变量当初始值（兼容老部署），再用落盘值覆盖。
pub fn init() {
    LOADED.call_once(|| {
        ATTEST_ORDER.store(
            env_keybox_first("RELAY_ATTEST_KEYBOX_FIRST") as u8,
            Ordering::Relaxed,
        );
        ID_ATTEST_ORDER.store(
            env_keybox_first("RELAY_ID_ATTEST_SERVER_SIDE") as u8,
            Ordering::Relaxed,
        );
        load_file();
    });
}

fn load_file() {
    let Ok(text) = std::fs::read_to_string(PATH) else {
        return;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        // 坏 JSON 当作没有，不能让它把服务拖起来。
        return;
    };
    let read_order = |key: &str| {
        v.get(key)
            .and_then(|x| x.as_str())
            .and_then(|s| s.parse::<Order>().ok())
    };
    if let Some(o) = read_order("attest_order") {
        ATTEST_ORDER.store(o as u8, Ordering::Relaxed);
    }
    if let Some(o) = read_order("id_attest_order") {
        ID_ATTEST_ORDER.store(o as u8, Ordering::Relaxed);
    }
    if let Some(o) = v
        .get("attest_key_order")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<AttestKeyOrder>().ok())
    {
        ATTEST_KEY_ORDER.store(o as u8, Ordering::Relaxed);
    }
    // 旧格式（bool 版 keybox_first）还能读：true 当强制服务端，false 当跟随模式。
    if v.get("attest_order").is_none() {
        if let Some(b) = v.get("keybox_first").and_then(|x| x.as_bool()) {
            ATTEST_ORDER.store(
                (if b { Order::KeyboxFirst } else { Order::Auto }) as u8,
                Ordering::Relaxed,
            );
        }
    }
    if v.get("id_attest_order").is_none() {
        if let Some(b) = v.get("id_attest_server_side").and_then(|x| x.as_bool()) {
            ID_ATTEST_ORDER.store(
                (if b { Order::KeyboxFirst } else { Order::Auto }) as u8,
                Ordering::Relaxed,
            );
        }
    }
}

/// 普通 attest 的层序策略。
pub fn attest_order() -> Order {
    init();
    Order::from_u8(ATTEST_ORDER.load(Ordering::Relaxed))
}

/// 带设备 ID 的 attest 的层序策略（`auto` 时与 [`attest_order`] 同一套）。
pub fn id_attest_order() -> Order {
    init();
    Order::from_u8(ID_ATTEST_ORDER.load(Ordering::Relaxed))
}

/// 证明密钥（`PURPOSE_ATTEST_KEY`）的层序策略。
pub fn attest_key_order() -> AttestKeyOrder {
    init();
    AttestKeyOrder::from_u8(ATTEST_KEY_ORDER.load(Ordering::Relaxed))
}

/// 当前三个策略。
pub fn snapshot() -> (Order, Order, AttestKeyOrder) {
    init();
    (attest_order(), id_attest_order(), attest_key_order())
}

/// 改策略并落盘。`None` = 这个字段不动。
pub fn set(
    attest: Option<Order>,
    id_attest: Option<Order>,
    attest_key: Option<AttestKeyOrder>,
) -> std::io::Result<()> {
    init();
    if let Some(o) = attest {
        ATTEST_ORDER.store(o as u8, Ordering::Relaxed);
    }
    if let Some(o) = id_attest {
        ID_ATTEST_ORDER.store(o as u8, Ordering::Relaxed);
    }
    if let Some(o) = attest_key {
        ATTEST_KEY_ORDER.store(o as u8, Ordering::Relaxed);
    }
    let (a, i, k) = snapshot();
    let body = serde_json::json!({
        "attest_order": a.as_str(),
        "id_attest_order": i.as_str(),
        "attest_key_order": k.as_str(),
    });
    if let Some(dir) = Path::new(PATH).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(&body).unwrap_or_default();
    let tmp = format!("{PATH}.tmp");
    std::fs::write(&tmp, text.as_bytes())?;
    std::fs::rename(&tmp, PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrip() {
        for o in [Order::Auto, Order::BFirst, Order::KeyboxFirst] {
            assert_eq!(o.as_str().parse::<Order>(), Ok(o));
        }
        assert_eq!("".parse::<Order>(), Ok(Order::Auto));
        assert_eq!("KEYBOX".parse::<Order>(), Ok(Order::KeyboxFirst));
        assert_eq!("b-first".parse::<Order>(), Ok(Order::BFirst));
        assert_eq!("bogus".parse::<Order>(), Err(()));
    }

    #[test]
    fn env_flag_maps_to_auto_not_b_first() {
        // 老开关关着必须等价于「跟随模式」，不能被解释成「强制真机」。
        std::env::remove_var("__OMMEGA_NEVER_SET_THIS__");
        assert_eq!(env_keybox_first("__OMMEGA_NEVER_SET_THIS__"), Order::Auto);
    }

    #[test]
    fn set_and_snapshot_roundtrip() {
        init();
        ATTEST_ORDER.store(Order::BFirst as u8, Ordering::Relaxed);
        ID_ATTEST_ORDER.store(Order::KeyboxFirst as u8, Ordering::Relaxed);
        ATTEST_KEY_ORDER.store(AttestKeyOrder::Follow as u8, Ordering::Relaxed);
        assert_eq!(
            snapshot(),
            (Order::BFirst, Order::KeyboxFirst, AttestKeyOrder::Follow)
        );
        ATTEST_ORDER.store(Order::Auto as u8, Ordering::Relaxed);
        ID_ATTEST_ORDER.store(Order::Auto as u8, Ordering::Relaxed);
        ATTEST_KEY_ORDER.store(AttestKeyOrder::Smart as u8, Ordering::Relaxed);
        assert_eq!(
            snapshot(),
            (Order::Auto, Order::Auto, AttestKeyOrder::Smart)
        );
    }

    #[test]
    fn attest_key_order_tokens() {
        assert_eq!("".parse::<AttestKeyOrder>(), Ok(AttestKeyOrder::Smart));
        assert_eq!(
            "FOLLOW".parse::<AttestKeyOrder>(),
            Ok(AttestKeyOrder::Follow)
        );
        assert_eq!("smart".parse::<AttestKeyOrder>(), Ok(AttestKeyOrder::Smart));
        assert_eq!("bogus".parse::<AttestKeyOrder>(), Err(()));
    }
}
