//! SOTER 签名会话的登记表 —— `finish_sign` 回 -204 时补救的依据。
//!
//! 背景（2026-10-01 实测）：设备上的 SOTER TA **一台设备同时只保留一个有效签名会话**。
//! 后开的那张会把前一张顶掉，跟槽位（uid + 别名）没关系：uid 10043 与 uid 10373、
//! 别名也各不同，各 init 一次，回头按顺序 finish —— 先 init 的那笔必回 -204
//! （`SOTER_ERROR_OPERATEID_NULL`），4 轮 4 次都是如此。B 端的 relay 只是把句柄透传给
//! HAL / TA，自己根本没有会话表，这个「一个」改不动。
//!
//! 生产日志里 `finish_sign -204` 一直占收尾的一成上下。拦是拦不住的（谁先谁后全看 App
//! 的时序），所以这一层不拦、只留证据：`init_sign` 拿到会话的时候把 (uid, 别名,
//! challenge) 记下来，等这笔 `finish_sign` 真回 -204 了，`handlers` 拿它重开一张会话、
//! 把同一个 challenge 再签一遍 —— 同一把钥匙、同一个挑战，签名值是等价的，App 那边看到
//! 的就是一次正常成功。
//!
//! 这里没有任何阻塞，所以也不会再回 -9（`IS_AUTHING`）去让 App 重试。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 一笔会话记多久。App 的 init->finish 正常是秒级，慢的时候是在等用户按指纹（几十秒
/// 量级）。生产里能看到隔几分钟才收尾的（App 自己缓着 session 不急着签），所以给到
/// 15 分钟；过期只是不再补救，没别的副作用，内存也被 [`MAX_ENTRIES`] 卡着。
const STASH_TTL: Duration = Duration::from_secs(900);

/// 最多记多少条，挡住异常增长（正常随 `finish_sign` 清掉）。
const MAX_ENTRIES: usize = 8192;

/// 补救需要的东西：重开一张会话得用同样的 uid、别名和挑战。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotSpec {
    pub uid: i64,
    pub alias: Option<String>,
    pub challenge: Option<String>,
}

/// 补救完整可用的槽位信息（缺 alias 或 challenge 就补不了）。
impl SlotSpec {
    pub fn usable(&self) -> bool {
        self.alias.as_deref().is_some_and(|a| !a.is_empty())
            && self.challenge.as_deref().is_some_and(|c| !c.is_empty())
    }
}

struct Entry {
    requested: Option<String>,
    spec: SlotSpec,
    at: Instant,
}

pub struct SignSessions {
    ttl: Duration,
    inner: Mutex<HashMap<(String, i64), Entry>>,
}

impl SignSessions {
    pub fn new() -> Self {
        Self::with_ttl(STASH_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// `init_sign` 拿到会话时登记。uid / 别名 / 挑战缺一不可，缺了就不记 ——
    /// 记下来也补不了，白占内存。
    pub fn record(
        &self,
        device: &str,
        requested: &str,
        session: i64,
        uid: Option<i64>,
        alias: Option<&str>,
        challenge: Option<&str>,
    ) {
        if device.is_empty() {
            return;
        }
        let Some(uid) = uid else { return };
        let spec = SlotSpec {
            uid,
            alias: alias.map(str::to_string),
            challenge: challenge.map(str::to_string),
        };
        if !spec.usable() {
            return;
        }
        let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        g.retain(|_, e| now.saturating_duration_since(e.at) <= self.ttl);
        if g.len() >= MAX_ENTRIES {
            // 满了先扔一半最老的，别让它无限涨。
            let mut ages: Vec<((String, i64), Instant)> =
                g.iter().map(|(s, e)| (s.clone(), e.at)).collect();
            ages.sort_by_key(|(_, at)| *at);
            for (s, _) in ages.into_iter().take(g.len() / 2) {
                g.remove(&s);
            }
        }
        let key = (device.to_string(), session);
        // The wire handle cannot distinguish two callers reusing a handle on
        // one device. Keep it unrepairable rather than signing the wrong challenge.
        let requested = match g.get(&key) {
            Some(e) if e.requested.as_deref() != Some(requested) || e.spec != spec => None,
            _ => Some(requested.to_string()),
        };
        g.insert(
            key,
            Entry {
                requested,
                spec,
                at: now,
            },
        );
    }

    /// 查这张会话是哪个槽位开的（顺手清掉过期的）。
    pub fn lookup(&self, device: &str, session: i64) -> Option<SlotSpec> {
        let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        g.retain(|_, e| now.saturating_duration_since(e.at) <= self.ttl);
        g.get(&(device.to_string(), session))
            .map(|e| e.spec.clone())
    }

    /// 在同一把锁内确认唯一路由并取出槽位信息。
    ///
    /// 不要把这个检查拆成 `belongs_to` + `lookup`：两次加锁之间登记可能被
    /// 同号句柄的新请求覆盖，随后就会拿错 challenge。若同一请求+句柄落在
    /// 多台设备上，也一律拒绝猜测。
    pub fn lookup_for(&self, device: &str, requested: &str, session: i64) -> Option<SlotSpec> {
        let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        g.retain(|_, e| now.saturating_duration_since(e.at) <= self.ttl);
        let mut matches = g.iter().filter(|((_, handle), e)| {
            *handle == session && e.requested.as_deref() == Some(requested)
        });
        let ((matched_device, _), entry) = matches.next()?;
        if matched_device != device || matches.next().is_some() {
            return None;
        }
        Some(entry.spec.clone())
    }

    /// 在同一把锁内确认唯一路由后删除登记。
    pub fn forget_for(&self, device: &str, requested: &str, session: i64) -> bool {
        let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        g.retain(|_, e| now.saturating_duration_since(e.at) <= self.ttl);
        let mut matches = g.iter().filter(|((_, handle), e)| {
            *handle == session && e.requested.as_deref() == Some(requested)
        });
        let Some(((matched_device, _), _)) = matches.next() else {
            return false;
        };
        if matched_device != device || matches.next().is_some() {
            return false;
        }
        g.remove(&(device.to_string(), session)).is_some()
    }

    /// 防止本次路由碰巧落到另一请求的同号会话上。
    pub fn belongs_to(&self, device: &str, requested: &str, session: i64) -> bool {
        self.lookup_for(device, requested, session).is_some()
    }

    /// 原请求路由的会话归属；同请求+句柄有多个设备时不猜测。
    pub fn route(&self, requested: &str, session: i64) -> Option<String> {
        let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        g.retain(|_, e| now.saturating_duration_since(e.at) <= self.ttl);
        let mut devices = g
            .iter()
            .filter(|((_, handle), e)| {
                *handle == session && e.requested.as_deref() == Some(requested)
            })
            .map(|((device, _), _)| device.clone());
        let first = devices.next()?;
        if devices.next().is_some() {
            None
        } else {
            Some(first)
        }
    }

    /// 这一笔自己收尾了（或者补签完了），登记撤掉。
    pub fn forget(&self, device: &str, session: i64) {
        self.hold()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&(device.to_string(), session));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.hold().lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    fn hold(&self) -> &Mutex<HashMap<(String, i64), Entry>> {
        &self.inner
    }
}

impl Default for SignSessions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions() -> SignSessions {
        SignSessions::with_ttl(Duration::from_millis(150))
    }

    #[test]
    fn a_recorded_session_can_be_looked_up() {
        let s = sessions();
        s.record("a", "a", 42, Some(10043), Some("slot_a"), Some("aabb"));
        let spec = s.lookup("a", 42).expect("刚记下的会话应该查得到");
        assert_eq!(spec.uid, 10043);
        assert_eq!(spec.alias.as_deref(), Some("slot_a"));
        assert_eq!(spec.challenge.as_deref(), Some("aabb"));
        assert!(spec.usable());
    }

    #[test]
    fn a_record_without_alias_or_challenge_is_not_kept() {
        // 补救得重开一张会话，缺别名或挑战就补不了，记下来也没用。
        let s = sessions();
        s.record("a", "a", 1, Some(10043), None, Some("aabb"));
        s.record("a", "a", 2, Some(10043), Some("slot_a"), None);
        s.record("a", "a", 3, Some(10043), Some(""), Some("aabb"));
        s.record("a", "a", 4, None, Some("slot_a"), Some("aabb"));
        assert_eq!(s.len(), 0);
        assert!(s.lookup("a", 1).is_none());
    }

    #[test]
    fn a_finished_session_is_dropped() {
        let s = sessions();
        s.record("a", "a", 7, Some(10043), Some("slot_a"), Some("aabb"));
        s.forget("a", 7);
        assert!(s.lookup("a", 7).is_none());
    }

    #[test]
    fn identical_handles_on_different_devices_are_independent() {
        let s = sessions();
        s.record(
            "a",
            "offline-a",
            42,
            Some(10043),
            Some("slot_a"),
            Some("aa"),
        );
        s.record(
            "b",
            "offline-b",
            42,
            Some(10373),
            Some("slot_b"),
            Some("bb"),
        );
        assert_eq!(s.lookup("a", 42).unwrap().challenge.as_deref(), Some("aa"));
        assert_eq!(s.lookup("b", 42).unwrap().uid, 10373);
        assert!(s.lookup("c", 42).is_none());
        assert_eq!(s.route("offline-a", 42).as_deref(), Some("a"));
        assert_eq!(s.route("offline-b", 42).as_deref(), Some("b"));
        assert!(s.route("unknown", 42).is_none());
        assert_eq!(
            s.lookup_for("a", "offline-a", 42)
                .unwrap()
                .challenge
                .as_deref(),
            Some("aa")
        );
        assert!(!s.forget_for("b", "offline-a", 42));
        assert!(s.lookup_for("a", "offline-a", 42).is_some());
        assert!(s.belongs_to("a", "offline-a", 42));
        assert!(!s.belongs_to("b", "offline-a", 42));
        assert!(s.forget_for("a", "offline-a", 42));
        assert!(s.lookup("a", 42).is_none());
        assert_eq!(s.lookup("b", 42).unwrap().challenge.as_deref(), Some("bb"));
    }

    #[test]
    fn multiple_callers_reusing_one_device_handle_cannot_be_repaired() {
        let s = sessions();
        s.record("a", "caller-1", 42, Some(1), Some("x"), Some("aa"));
        s.record("a", "caller-2", 42, Some(2), Some("y"), Some("bb"));
        assert!(s.route("caller-1", 42).is_none());
        assert!(s.route("caller-2", 42).is_none());
        assert!(!s.belongs_to("a", "caller-1", 42));
        assert!(!s.belongs_to("a", "caller-2", 42));
        assert!(s.lookup_for("a", "caller-1", 42).is_none());
        assert!(!s.forget_for("a", "caller-1", 42));
    }

    #[test]
    fn one_request_with_two_device_handles_is_ambiguous() {
        let s = sessions();
        s.record("a", "offline", 42, Some(1), Some("x"), Some("aa"));
        s.record("b", "offline", 42, Some(2), Some("y"), Some("bb"));
        assert!(s.route("offline", 42).is_none());
        assert!(s.lookup_for("a", "offline", 42).is_none());
        assert!(!s.forget_for("a", "offline", 42));
        assert!(!s.belongs_to("a", "offline", 42));
        assert!(!s.belongs_to("b", "offline", 42));
    }

    #[test]
    fn an_old_session_is_not_used_for_repair() {
        let s = sessions();
        s.record("a", "a", 9, Some(10043), Some("slot_a"), Some("aabb"));
        std::thread::sleep(Duration::from_millis(200));
        assert!(s.lookup("a", 9).is_none(), "过期的登记不该再拿去补签");
    }
}
