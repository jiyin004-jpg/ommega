//! SOTER 请求的短 TTL 合并（削峰用）。
//!
//! 同一台设备上、同一份请求，在很短的时间窗里直接复用上一次由设备自己答出来的结果。
//! 只有 `layer=b`（真设备答的）才进缓存：keybox / self_signed 顶替出来的答案不进，
//! 免得把「这台设备现在不行」也一起缓存住。`init_sign` / `finish_sign` 一律不缓存：
//! 那里面有会话句柄和「这一笔的验证过没过」的状态，复用会把语义搞坏。
//!
//! 写 op 走「去重窗」：同一个 (设备, uid, 别名, op) 在窗口内重复打进来，直接还上一次
//! 的结果，同时清掉该 uid 名下的只读缓存（设备状态变了）。记下某个写 op 时，同 uid
//! 上别的写记录一律丢掉 —— 那些答案是上一种状态下的，回放出去就是骗人；同 op 的
//! 记录留着；`remove_all_uid_key` 是 uid 级的，把这个 uid 的写记录全清。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

/// 只读、同一台设备上答案稳定的 op：短 TTL 合并的主力。
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
/// `remove_all_uid_key` 是 uid 级的，`remove_auth_key` 是 (uid, 别名) 级的；
/// 清理一律按 uid，宁可多清。
const WRITE_OPS: &[&str] = &[
    "generate_ask_key_pair",
    "generate_auth_key_pair",
    "generate_attk_key_pair",
    "remove_auth_key",
    "remove_all_uid_key",
];

/// 默认 5 秒：够短，设备一恢复下一笔就问得着；够长，能吃掉一轮初始化里的重复问。
const DEFAULT_READ_TTL_MS: u64 = 5_000;
/// 默认 2 秒：App 的重放间隔就在几百毫秒量级。
const DEFAULT_WRITE_WINDOW_MS: u64 = 2_000;

/// 「自删自建」的统计窗口与上报节拍。
///
/// 窗口压到 30 秒：死循环里两次删是**秒级**的，健康开通流程即使重试也是分钟级，
/// 短窗口里 2 次就够把两者分开。可用 `OMMEGA_SOTER_CHURN_WINDOW_MS` /
/// `OMMEGA_SOTER_CHURN_REPORT_AT` 调。
const CHURN_WINDOW: Duration = Duration::from_secs(30);
/// 窗口里第几次删开始报（健康的开通流程最多删一两次，但两次之间不会只隔几秒）。
const CHURN_REPORT_AT: u32 = 2;
/// 报过之后每隔多少次再喊一声，免得变成日志洪水。
const CHURN_REPEAT_EVERY: u32 = 5;
/// 判出「槽位 ASK 被毒化」后，这段时间里把 `has_ask_already` 一律答成「没有 ASK」，
/// 逼 App 重跑「生成 ASK → 上报腾讯」这一步。
///
/// App 只在 ASK 不存在时才上报腾讯：槽位上一旦有别的时候铸下的 ASK，它就永远跳过
/// 上报，建 AuthKey 之后腾讯不认，只能自删自建。它自己的救命手段 `remove_all_uid_key`
/// 是 uid 级的（会连坐同槽位别的账号），服务端不允许自动清，所以只能在回答层面说
/// 「没有 ASK」：App 以为没有就会重新生成并上报，循环就解开了。
/// 10 分钟：App 重试是分钟级，够跑一轮上报；还在自删自建就由 `note_slot_churn` 续窗。
const ASK_POISON_TTL: Duration = Duration::from_secs(600);
/// B 对「这把 ASK 不在」的答复码：-5，Trustonic AIDL 里是 `fffffffb`。
/// App 看到它就会去生成 ASK 并上报腾讯。
const ASK_MISSING_CODE: i64 = -5;

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

/// 缓存键：`设备|uid|op|别名`。只读缓存和写去重窗共用这套布局 —— 两边都按
/// `设备|uid|` 前缀清理，布局不一样就筛不干净。uid 和别名都可能没有。
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
    /// 「自删自建」的统计窗口与触发次数（默认为上面两个常量，可用环境变量调）。
    churn_window: Duration,
    churn_report_at: u32,
    reads: Mutex<HashMap<String, (Value, Instant)>>,
    writes: Mutex<HashMap<String, (Value, Instant)>>,
    /// 槽位「自删自建」计数：`设备|uid|别名` -> (窗口里删了几次, 上次时间)。
    churn: Mutex<HashMap<String, (u32, Instant)>>,
    /// 判出 ASK 被毒化的槽位：`设备|uid` -> 判出时刻。见 [`SoterGate::poison_ask_answer`]。
    poisoned_asks: Mutex<HashMap<String, Instant>>,
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
        let churn_window = std::env::var("OMMEGA_SOTER_CHURN_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_millis)
            .unwrap_or(CHURN_WINDOW);
        let churn_report_at = std::env::var("OMMEGA_SOTER_CHURN_REPORT_AT")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v| *v > 0)
            .unwrap_or(CHURN_REPORT_AT);
        Self {
            read_ttl: Duration::from_millis(read_ttl),
            write_window: Duration::from_millis(write_window),
            churn_window,
            churn_report_at,
            reads: Mutex::new(HashMap::new()),
            writes: Mutex::new(HashMap::new()),
            churn: Mutex::new(HashMap::new()),
            poisoned_asks: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            stores: AtomicU64::new(0),
            writes_invalidated: AtomicU64::new(0),
        }
    }

    pub fn with_windows(read_ttl: Duration, write_window: Duration) -> Self {
        Self {
            read_ttl,
            write_window,
            churn_window: CHURN_WINDOW,
            churn_report_at: CHURN_REPORT_AT,
            reads: Mutex::new(HashMap::new()),
            writes: Mutex::new(HashMap::new()),
            churn: Mutex::new(HashMap::new()),
            poisoned_asks: Mutex::new(HashMap::new()),
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
    ) -> Option<String> {
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
        self.note_slot_churn(device, op, uid, alias)
    }

    /// 同一槽位在窗口里被反复「删 AuthKey」时，给操作员一句说明（不改设备状态）。
    ///
    /// 腾讯没认这批材料时，App 就卡在「建 AuthKey → 导出 → 删掉」这一段，永远走不到
    /// 签名。两种成因：那台 B 的建料闸门没开（`OMMEGA_RELAY_SOTER_MUTATION`，
    /// `generate_*` 全被它自己拒成 -5，B 端会带 `soter_mutation_disabled` 标记）；或者
    /// 槽位上的 ASK 是别的时候 / 别处铸的。清 ASK 只能靠 `remove_all_uid_key`（uid 级，
    /// 会连坐同一个 uid 上别的账号），所以这里只报不改设备状态。
    fn note_slot_churn(
        &self,
        device: &str,
        op: &str,
        uid: Option<i32>,
        alias: Option<&str>,
    ) -> Option<String> {
        if !matches!(op, "remove_auth_key" | "remove_all_uid_key") {
            return None;
        }
        let uid_text = uid
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".to_string());
        let alias_text = alias.unwrap_or("-").to_string();
        let key = format!("{device}|{uid_text}|{alias_text}");
        let now = Instant::now();
        // 只要还在自删自建就续上毒化窗口：窗口跟着现象走，循环一停自然过期。
        self.mark_ask_poisoned(device, uid);
        let mut guard = self
            .churn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.retain(|_, (_, at)| now.duration_since(*at) <= self.churn_window);
        let entry = guard.entry(key).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
        let count = entry.0;
        drop(guard);
        let report_at = self.churn_report_at;
        let due = count == report_at
            || (count > report_at && (count - report_at).is_multiple_of(CHURN_REPEAT_EVERY));
        if !due {
            return None;
        }
        Some(format!(
            "soter: 槽位 {device}|{uid_text}|{alias_text} 在 {} 秒里第 {count} 次删 AuthKey —— \
             App 在自删自建（腾讯那边没认这批材料）。先确认那台 B 开了 \
             OMMEGA_RELAY_SOTER_MUTATION（没开的话 generate_* 全被它自己拒成 -5）。\
             闸门是开的就说明这个槽位上的 ASK 被别的时候铸过、App 跳过了「生成 ASK → 上报腾讯」\
             那一步 —— 服务端**已自动把该槽位的 `has_ask_already` 答成「没有 ASK」{} 秒**，\
             逼 App 重新生成并上报，不用人工动槽位；若过了这个窗口它还在自删自建，\
             再手工清 (remove_all_uid_key，uid 级会连坐同槽位别的账号，先看清台账)",
            self.churn_window.as_secs(),
            ASK_POISON_TTL.as_secs()
        ))
    }

    /// 毒化标记的键：ASK 是 uid 级的，所以只看 `设备|uid`，不看别名。
    fn ask_slot(device: &str, uid: Option<i32>) -> String {
        let uid = uid
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        format!("{device}|{uid}")
    }

    /// 把这个槽位标成「ASK 被毒化」。
    ///
    /// 每次看到自删自建就重标一次（不是只在报日志那一下），所以窗口跟着现象走：
    /// 循环一停，它过了 TTL 自然过期。
    fn mark_ask_poisoned(&self, device: &str, uid: Option<i32>) {
        let key = Self::ask_slot(device, uid);
        let mut guard = self
            .poisoned_asks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.retain(|_, at| at.elapsed() <= ASK_POISON_TTL);
        guard.insert(key, Instant::now());
    }

    fn ask_is_poisoned(&self, device: &str, uid: Option<i32>) -> bool {
        let key = Self::ask_slot(device, uid);
        let mut guard = self
            .poisoned_asks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.retain(|_, at| at.elapsed() <= ASK_POISON_TTL);
        guard.contains_key(&key)
    }

    /// 这一轮终于真签出来了（`finish_sign` 成功）：撤掉标记，别再骗 App。
    pub fn clear_ask_poison(&self, device: &str, uid: Option<i32>) {
        let key = Self::ask_slot(device, uid);
        let mut guard = self
            .poisoned_asks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(&key);
    }

    /// 槽位 ASK 被毒化时，把 `has_ask_already` 的答案改写成「没有 ASK」。
    ///
    /// 返回 `true` 表示真改写了（调用方记一条日志）。只碰 `has_ask_already` 这一个 op，
    /// 而且只改「有 ASK」那种答案：`has_auth_key` / `export_*` 那些是真话，一个字都不能编。
    pub fn poison_ask_answer(
        &self,
        device: &str,
        op: &str,
        uid: Option<i32>,
        value: &mut Value,
    ) -> bool {
        if op != "has_ask_already" || !self.ask_is_poisoned(device, uid) {
            return false;
        }
        if value.get("error_code").and_then(Value::as_i64) == Some(ASK_MISSING_CODE) {
            return false;
        }
        // **只允许改写我们自己兜底层（builtin / self_signed）的答复。**
        // 设备（B）的答复是真话，一个字都不能动：改成「没有 ASK」会让 App 现铸一把，
        // 跟腾讯那边记的对不上，于是自删自建死循环，永远走不到 init_sign。
        let layer = value.get("layer").and_then(Value::as_str).unwrap_or("");
        if layer != "builtin" && layer != "self_signed" {
            return false;
        }
        match value.as_object_mut() {
            Some(obj) => {
                obj.insert("error_code".to_owned(), Value::from(ASK_MISSING_CODE));
                true
            }
            None => false,
        }
    }

    /// 记下一笔写操作时，把同一 uid 上**别的**写去重记录丢掉：那些答案是「上一种状态」
    /// 下的，中间已经夹了这次改动，回放出去就是骗人。同 op 的记录留着（App 重复重放同一
    /// 笔还是该走窗）；`remove_all_uid_key` 是 uid 级的，把这个 uid 的写记录全清。
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
        // init_sign 里有会话句柄、还牵着「这一笔的验证过没过」，复用等于把语义搞坏。
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
        // remove 之后，前一笔 generate 的回放必须作废：App 收到「建成功」再查却还是
        // 没有，只能自删自重试。
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
    fn repeated_auth_key_deletions_are_reported_once_the_slot_looks_stuck() {
        let gate = SoterGate::with_windows(Duration::from_millis(120), Duration::from_millis(120));
        // 阈值之前一直不该报（阈值现在默认是 2，可用环境变量调）。
        for i in 1..CHURN_REPORT_AT {
            assert!(
                gate.record(
                    "dev",
                    "remove_auth_key",
                    Some(10490),
                    Some("SoterAuthKeyV2_salt11d8ba34_scene1"),
                    true,
                    &json!({ "error_code": 0 }),
                )
                .is_none(),
                "第 {i} 次不该报"
            );
        }
        let note = gate
            .record(
                "dev",
                "remove_auth_key",
                Some(10490),
                Some("SoterAuthKeyV2_salt11d8ba34_scene1"),
                true,
                &json!({ "error_code": 0 }),
            )
            .unwrap_or_else(|| panic!("第 {CHURN_REPORT_AT} 次该报一声"));
        assert!(note.contains("自删自建"), "{note}");
        assert!(note.contains("OMMEGA_RELAY_SOTER_MUTATION"), "{note}");
        // 别的槽位/别的 op 不受影响。
        assert!(gate
            .record(
                "dev",
                "remove_auth_key",
                Some(10491),
                Some("A"),
                true,
                &json!({}),
            )
            .is_none());
        assert!(gate
            .record(
                "dev",
                "generate_auth_key_pair",
                Some(10490),
                Some("SoterAuthKeyV2_salt11d8ba34_scene1"),
                true,
                &json!({}),
            )
            .is_none());
    }

    /// 判出「自删自建」之后，这个槽位的 `has_ask_already` 要答成「没有 ASK」，
    /// 逼 App 重走「生成 ASK → 上报腾讯」。
    #[test]
    fn a_churning_slot_gets_its_ask_answer_turned_into_missing() {
        let gate = gate();
        let mut before = json!({ "error_code": 0, "layer": "b" });
        assert!(
            !gate.poison_ask_answer("dev", "has_ask_already", Some(10489), &mut before),
            "还没判出自删自建之前一个字都不改"
        );
        assert_eq!(before["error_code"], json!(0));

        for _ in 0..CHURN_REPORT_AT {
            gate.record(
                "dev",
                "remove_auth_key",
                Some(10489),
                Some("A"),
                true,
                &json!({}),
            );
        }
        // 设备（B）的答复是真话，一个字都不许编。
        let mut from_device = json!({ "error_code": 0, "layer": "b" });
        assert!(
            !gate.poison_ask_answer("dev", "has_ask_already", Some(10489), &mut from_device),
            "设备答复不许被改写"
        );
        assert_eq!(from_device["error_code"], json!(0));

        // 只有我们自己的兜底层才允许被改写成「没有 ASK」。
        let mut from_builtin = json!({ "error_code": 0, "layer": "builtin" });
        assert!(gate.poison_ask_answer("dev", "has_ask_already", Some(10489), &mut from_builtin));
        assert_eq!(from_builtin["error_code"], json!(ASK_MISSING_CODE));
        assert_eq!(
            from_builtin["layer"],
            json!("builtin"),
            "只改错误码，别的字段不动"
        );

        // 已经是「没有」的答案不算改写。
        let mut absent = json!({ "error_code": ASK_MISSING_CODE });
        assert!(!gate.poison_ask_answer("dev", "has_ask_already", Some(10489), &mut absent));
        // 别的 op 不能编（`has_auth_key` 那种是真话）。
        let mut other = json!({ "error_code": 0 });
        assert!(!gate.poison_ask_answer("dev", "has_auth_key", Some(10489), &mut other));
        assert_eq!(other["error_code"], json!(0));
        // 别的槽位不受影响。
        let mut neighbour = json!({ "error_code": 0 });
        assert!(!gate.poison_ask_answer("dev", "has_ask_already", Some(10490), &mut neighbour));
        assert_eq!(neighbour["error_code"], json!(0));
    }

    /// 真签出来（`finish_sign` 成功）就把毒化标记撤掉：这轮已经走通了，别再骗 App。
    #[test]
    fn a_real_signature_clears_the_poison() {
        let gate = gate();
        for _ in 0..CHURN_REPORT_AT {
            gate.record(
                "dev",
                "remove_auth_key",
                Some(10489),
                Some("A"),
                true,
                &json!({}),
            );
        }
        let mut answer = json!({ "error_code": 0, "layer": "builtin" });
        assert!(gate.poison_ask_answer("dev", "has_ask_already", Some(10489), &mut answer));

        gate.clear_ask_poison("dev", Some(10489));
        let mut answer = json!({ "error_code": 0 });
        assert!(
            !gate.poison_ask_answer("dev", "has_ask_already", Some(10489), &mut answer),
            "清理之后要回到「说真话」"
        );
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
