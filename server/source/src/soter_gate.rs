//! SOTER 请求的短 TTL 合并（削峰用）。
//!
//! 背景：2026-09-30 实测，A 端 App 的 SOTER 初始化循环在失败后会「自删自重试」——
//! 同一份只读查询（`has_auth_key` / `has_ask_already` / `export_ask_public_key`）
//! 一秒内能问好几遍，重建类 op（`generate_*` / `remove_*`）也被反复重放，量级
//! 200~400 次/分钟，把 B 端那条单线程 relay 的队列占满，真正的 `init_sign` 反倒
//! 排队排到超时，服务端只好落 keybox 顶替 —— App 又拿到假签名，继续重试。
//!
//! 这一层只做一件事：同一台设备上、同一份请求，在很短的时间窗里直接复用上一次
//! **设备自己答出来**的结果。
//!
//! 两条不越界的规矩：
//! - 只有 `layer=b`（真设备答的）才进缓存。keybox / self_signed 顶替出来的答案
//!   不进，免得把「这台设备现在不行」也一起缓存住，下一笔连试都不试了。
//! - `init_sign` / `finish_sign` 一律不缓存：那里面有会话句柄和「这一刻有没有
//!   新鲜指纹」的状态，复用会把语义搞坏。
//!
//! 重建类 op 走的是「去重窗」：同一个 (设备, uid, 别名, op) 在窗口内重复打进来，
//! 直接把上一次的结果还回去；同时把该 uid 名下所有只读缓存清掉 —— 设备状态变了，
//! 之前量出来的「有没有料」就不能再用了。
//!
//! 2026-10-01 补的一条：**同一个写 op 记进来时，要把同 uid 上别的写记录丢掉**。
//! 去重窗只认 (设备, op, uid, 别名)，认不出中间夹了一次 `remove`；实测 App 的循环
//! 是 `remove` → `generate` → `has_auth_key`，那次 generate 落在前一笔 generate 的
//! 窗里被原样回放（同一个 task_id、33ms、根本没到设备），App 收到「建成功」，紧接着
//! 查还是删后那份 -8，去签名又 -65528，于是自删自重试 —— 请求量就是这么堆起来的。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

/// 只读、同一台设备上答案稳定的 op：短 TTL 合并的主力（实测占请求量的七成）。
const READ_OPS: &[&str] = &[
    "has_auth_key",
    "has_ask_already",
    "export_ask_public_key",
    "export_auth_key_public_key",
    "export_attk_public_key",
    "get_device_id",
    "verify_attk_key_pair",
];

/// 会改设备状态的 op：只做窗口内去重，并把只读缓存清掉。
///
/// `remove_all_uid_key` 是 uid 级的，`remove_auth_key` 是 (uid, 别名) 级的 ——
/// 清理的时候一律按 uid 清，宁可多清一点。
const WRITE_OPS: &[&str] = &[
    "generate_ask_key_pair",
    "generate_auth_key_pair",
    "generate_attk_key_pair",
    "remove_auth_key",
    "remove_all_uid_key",
];

/// 默认 5 秒：够短，设备一恢复下一笔就问得着；也够长，能把一轮初始化里的重复问
/// 全部吃掉。
const DEFAULT_READ_TTL_MS: u64 = 5_000;
/// 默认 2 秒：App 的重放间隔就在几百毫秒量级。
const DEFAULT_WRITE_WINDOW_MS: u64 = 2_000;

enum Kind {
    Read,
    Write,
    /// 不合并的 op（`init_sign` / `finish_sign` / `probe` / `selftest` / 未知）。
    None,
}

fn kind_of(op: &str) -> Kind {
    if READ_OPS.contains(&op) {
        Kind::Read
    } else if WRITE_OPS.contains(&op) {
        Kind::Write
    } else {
        Kind::None
    }
}

/// 缓存键：`设备|uid|op|别名`。只读缓存和写去重窗共用这一套布局 ——
/// 两边都按 `设备|uid|` 前缀清理，布局不一样就筛不干净。
/// uid 和别名都可能没有（uid 级 op 就没有别名）。
fn slot(device: &str, op: &str, uid: Option<i32>, alias: Option<&str>) -> String {
    let uid = uid
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let alias = alias.unwrap_or("-");
    format!("{device}|{uid}|{op}|{alias}")
}

/// 清只读缓存用的前缀：这台设备 + 这个 uid 名下的全部别名。
fn uid_prefix(device: &str, uid: Option<i32>) -> String {
    let uid = uid
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!("{device}|{uid}|")
}

pub struct SoterGate {
    read_ttl: Duration,
    write_window: Duration,
    reads: Mutex<HashMap<String, (Value, Instant)>>,
    writes: Mutex<HashMap<String, (Value, Instant)>>,
    hits: AtomicU64,
    stores: AtomicU64,
    writes_invalidated: AtomicU64,
}

impl SoterGate {
    pub fn new() -> Self {
        let read_ttl = std::env::var("OMMEGA_SOTER_READ_TTL_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_READ_TTL_MS);
        let write_window = std::env::var("OMMEGA_SOTER_WRITE_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_WRITE_WINDOW_MS);
        Self::with_windows(
            Duration::from_millis(read_ttl),
            Duration::from_millis(write_window),
        )
    }

    pub fn with_windows(read_ttl: Duration, write_window: Duration) -> Self {
        Self {
            read_ttl,
            write_window,
            reads: Mutex::new(HashMap::new()),
            writes: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            stores: AtomicU64::new(0),
            writes_invalidated: AtomicU64::new(0),
        }
    }

    /// 命中就直接把上一次的答复还回去（`init_sign` / `finish_sign` 永远不命中）。
    pub fn lookup(
        &self,
        device: &str,
        op: &str,
        uid: Option<i32>,
        alias: Option<&str>,
    ) -> Option<Value> {
        let (map, ttl, k) = match kind_of(op) {
            Kind::Read => (&self.reads, self.read_ttl, slot(device, op, uid, alias)),
            Kind::Write => (
                &self.writes,
                self.write_window,
                slot(device, op, uid, alias),
            ),
            Kind::None => return None,
        };
        let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let hit = guard.get(&k).cloned();
        match hit {
            Some((value, at)) if at.elapsed() <= ttl => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(value)
            }
            Some(_) => {
                guard.remove(&k);
                None
            }
            None => None,
        }
    }

    /// 记一次执行结果。
    ///
    /// `from_device` = 这笔答复是真由点名的那台 B 答出来的；只有它为真才进缓存。
    /// 重建类 op 无论谁答的，都把该 uid 的只读缓存清掉（设备状态可能已经变了）。
    pub fn record(
        &self,
        device: &str,
        op: &str,
        uid: Option<i32>,
        alias: Option<&str>,
        from_device: bool,
        value: &Value,
    ) {
        match kind_of(op) {
            Kind::Write => {
                self.invalidate_reads(device, uid);
                self.invalidate_sibling_writes(device, uid, op);
                if from_device {
                    let k = slot(device, op, uid, alias);
                    let ttl = self.write_window;
                    let mut guard = self
                        .writes
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    guard.retain(|_, (_, at)| at.elapsed() <= ttl);
                    guard.insert(k, (value.clone(), Instant::now()));
                    self.stores.fetch_add(1, Ordering::Relaxed);
                }
            }
            Kind::Read => {
                if from_device {
                    let k = slot(device, op, uid, alias);
                    let ttl = self.read_ttl;
                    let mut guard = self
                        .reads
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    guard.retain(|_, (_, at)| at.elapsed() <= ttl);
                    guard.insert(k, (value.clone(), Instant::now()));
                    self.stores.fetch_add(1, Ordering::Relaxed);
                }
            }
            Kind::None => {}
        }
    }

    /// 记下一笔写操作时，把同一 uid 上**别的**写去重记录丢掉：那些答案是「上一种
    /// 状态」下的，中间已经夹了这次改动，回放出去就是骗人。
    ///
    /// 同 op 的记录留着（App 重复重放同一笔还是该走窗，这是这层的本意）；
    /// `remove_all_uid_key` 是 uid 级的，把这个 uid 的写记录全清。
    fn invalidate_sibling_writes(&self, device: &str, uid: Option<i32>, op: &str) {
        let prefix = uid_prefix(device, uid);
        let mut guard = self
            .writes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = guard.len();
        guard.retain(|k, _| {
            if !k.starts_with(&prefix) {
                return true;
            }
            if op == "remove_all_uid_key" {
                return false;
            }
            let other = k[prefix.len()..].split('|').next().unwrap_or("");
            other == op
        });
        let dropped = before - guard.len();
        if dropped > 0 {
            self.writes_invalidated
                .fetch_add(dropped as u64, Ordering::Relaxed);
        }
    }

    fn invalidate_reads(&self, device: &str, uid: Option<i32>) {
        let prefix = uid_prefix(device, uid);
        let mut guard = self
            .reads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = guard.len();
        guard.retain(|k, _| !k.starts_with(&prefix));
        let dropped = before - guard.len();
        if dropped > 0 {
            self.writes_invalidated
                .fetch_add(dropped as u64, Ordering::Relaxed);
        }
    }

    /// (命中次数, 入缓存次数, 因重建而清掉的条数) —— 给状态页和日志看。
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.stores.load(Ordering::Relaxed),
            self.writes_invalidated.load(Ordering::Relaxed),
        )
    }

    /// 缓存里现存的条数（测试和状态页用）。
    pub fn len(&self) -> (usize, usize) {
        let reads = self.reads.lock().unwrap_or_else(|p| p.into_inner()).len();
        let writes = self.writes.lock().unwrap_or_else(|p| p.into_inner()).len();
        (reads, writes)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == (0, 0)
    }
}

impl Default for SoterGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gate() -> SoterGate {
        SoterGate::with_windows(Duration::from_millis(120), Duration::from_millis(120))
    }

    #[test]
    fn a_device_read_is_reused_inside_the_window() {
        let gate = gate();
        let value = json!({ "op": "has_auth_key", "error_code": 0 });
        assert!(gate
            .lookup("dev", "has_auth_key", Some(10408), Some("A"))
            .is_none());
        gate.record("dev", "has_auth_key", Some(10408), Some("A"), true, &value);
        assert_eq!(
            gate.lookup("dev", "has_auth_key", Some(10408), Some("A")),
            Some(value)
        );
    }

    #[test]
    fn a_read_that_keybox_answered_is_not_cached() {
        // 服务端那两层顶替出来的答复不许进缓存：下一笔还得先问设备。
        let gate = gate();
        gate.record(
            "dev",
            "has_auth_key",
            Some(10408),
            Some("A"),
            false,
            &json!({ "op": "has_auth_key", "error_code": 0 }),
        );
        assert!(gate
            .lookup("dev", "has_auth_key", Some(10408), Some("A"))
            .is_none());
    }

    #[test]
    fn a_read_expires_and_is_asked_again() {
        let gate = gate();
        gate.record(
            "dev",
            "export_ask_public_key",
            Some(10408),
            None,
            true,
            &json!({ "op": "export_ask_public_key", "error_code": 0 }),
        );
        assert!(gate
            .lookup("dev", "export_ask_public_key", Some(10408), None)
            .is_some());
        std::thread::sleep(Duration::from_millis(160));
        assert!(gate
            .lookup("dev", "export_ask_public_key", Some(10408), None)
            .is_none());
    }

    #[test]
    fn sign_sessions_are_never_reused() {
        // init_sign 里有会话句柄、还牵着「这一刻有没有新鲜指纹」，复用等于把语义搞坏。
        let gate = gate();
        for op in ["init_sign", "finish_sign", "probe", "selftest"] {
            gate.record(
                "dev",
                op,
                Some(10408),
                Some("A"),
                true,
                &json!({ "op": op }),
            );
            assert!(
                gate.lookup("dev", op, Some(10408), Some("A")).is_none(),
                "{op}"
            );
        }
    }

    #[test]
    fn a_rebuild_replay_is_answered_from_the_window() {
        let gate = gate();
        let first = json!({ "op": "generate_auth_key_pair", "error_code": 0 });
        gate.record(
            "dev",
            "generate_auth_key_pair",
            Some(10408),
            Some("A"),
            true,
            &first,
        );
        assert_eq!(
            gate.lookup("dev", "generate_auth_key_pair", Some(10408), Some("A")),
            Some(first)
        );
    }

    #[test]
    fn a_remove_kills_the_earlier_generate_replay() {
        // 2026-10-01 实测的循环：remove → generate → has_auth_key。
        // 那次 generate 曾经被前一笔 generate 的结果回放（同一个 task_id、33ms、
        // 根本没到设备），App 收到「建成功」再查却还是没有，只能自删自重试。
        let gate = gate();
        gate.record(
            "dev",
            "generate_auth_key_pair",
            Some(10408),
            Some("A"),
            true,
            &json!({ "error_code": 0 }),
        );
        assert!(gate
            .lookup("dev", "generate_auth_key_pair", Some(10408), Some("A"))
            .is_some());
        gate.record(
            "dev",
            "remove_auth_key",
            Some(10408),
            Some("A"),
            true,
            &json!({ "error_code": 0 }),
        );
        assert!(gate
            .lookup("dev", "generate_auth_key_pair", Some(10408), Some("A"))
            .is_none());
        // 刚记下这笔 remove 自己的答案还在（同 op 的重复重放照旧走窗）。
        assert!(gate
            .lookup("dev", "remove_auth_key", Some(10408), Some("A"))
            .is_some());
    }

    #[test]
    fn a_generate_for_another_alias_leaves_the_replay_alone() {
        let gate = gate();
        gate.record(
            "dev",
            "generate_auth_key_pair",
            Some(10408),
            Some("A"),
            true,
            &json!({}),
        );
        gate.record(
            "dev",
            "generate_auth_key_pair",
            Some(10408),
            Some("B"),
            true,
            &json!({}),
        );
        assert!(gate
            .lookup("dev", "generate_auth_key_pair", Some(10408), Some("A"))
            .is_some());
        assert!(gate
            .lookup("dev", "generate_auth_key_pair", Some(10408), Some("B"))
            .is_some());
    }

    #[test]
    fn remove_all_clears_every_write_of_that_uid() {
        let gate = gate();
        gate.record(
            "dev",
            "generate_auth_key_pair",
            Some(10408),
            Some("A"),
            true,
            &json!({}),
        );
        gate.record(
            "dev",
            "remove_auth_key",
            Some(10408),
            Some("B"),
            true,
            &json!({}),
        );
        gate.record(
            "dev",
            "remove_all_uid_key",
            Some(10408),
            None,
            true,
            &json!({}),
        );
        assert!(gate
            .lookup("dev", "generate_auth_key_pair", Some(10408), Some("A"))
            .is_none());
        assert!(gate
            .lookup("dev", "remove_auth_key", Some(10408), Some("B"))
            .is_none());
        assert!(gate
            .lookup("dev", "remove_all_uid_key", Some(10408), None)
            .is_some());
    }

    #[test]
    fn a_rebuild_drops_the_reads_of_that_uid_only() {
        let gate = gate();
        for uid in [10408, 10446] {
            gate.record(
                "dev",
                "has_auth_key",
                Some(uid),
                Some("A"),
                true,
                &json!({ "op": "has_auth_key", "error_code": 0, "uid": uid }),
            );
        }
        // 别的设备、别的 uid 都还在
        gate.record(
            "other",
            "has_auth_key",
            Some(10408),
            Some("A"),
            true,
            &json!({ "op": "has_auth_key", "error_code": 0 }),
        );
        gate.record(
            "dev",
            "remove_auth_key",
            Some(10408),
            Some("A"),
            true,
            &json!({}),
        );

        assert!(gate
            .lookup("dev", "has_auth_key", Some(10408), Some("A"))
            .is_none());
        assert!(gate
            .lookup("dev", "has_auth_key", Some(10446), Some("A"))
            .is_some());
        assert!(gate
            .lookup("other", "has_auth_key", Some(10408), Some("A"))
            .is_some());
    }

    #[test]
    fn a_rebuild_replay_from_a_substituted_layer_is_not_cached() {
        let gate = gate();
        gate.record(
            "dev",
            "remove_all_uid_key",
            Some(10408),
            None,
            false,
            &json!({ "op": "remove_all_uid_key", "error_code": 0 }),
        );
        assert!(gate
            .lookup("dev", "remove_all_uid_key", Some(10408), None)
            .is_none());
    }

    #[test]
    fn stats_count_what_happened() {
        let gate = gate();
        gate.record(
            "dev",
            "has_auth_key",
            Some(1),
            Some("A"),
            true,
            &json!({ "error_code": 0 }),
        );
        assert!(gate
            .lookup("dev", "has_auth_key", Some(1), Some("A"))
            .is_some());
        gate.record("dev", "remove_all_uid_key", Some(1), None, true, &json!({}));
        let (hits, stores, invalidated) = gate.stats();
        assert_eq!(hits, 1);
        assert_eq!(stores, 2);
        assert_eq!(invalidated, 1);
        assert!(!gate.is_empty() || gate.len() == (0, 1));
    }
}
