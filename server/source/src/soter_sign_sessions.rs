//! SOTER 签名会话的登记表 —— `finish_sign` 回 -204 时补救的依据。
//!
//! 背景（2026-10-01 实测）：设备上的 SOTER TA **一台设备同时只保留一个有效签名会话**。
//! 后开的那张会把前一张顶掉，跟槽位（uid + 别名）没关系：uid 10043 与 uid 10373、
//! 别名也各不同，各 init 一次，回头按顺序 finish —— 先 init 的那笔必回 -204
//! （`SOTER_ERROR_OPERATEID_NULL`），4 轮 4 次都是如此。B 端的 relay 只是把句柄透传给
//! HAL / TA，自己根本没有会话表，这个「一个」改不动。
//!
//! 2026-10-06 又实测到一条，对「谁该去收尾」很关键：这张会话还认**开它的那个
//! 调用者**。走 B 端 relay（一个常驻进程）`init_sign` + `finish_sign` 一次就成；
//! 而拿 shell 拆成两个 `service call` 进程发（同一把 uid/别名/challenge、中间没人
//! 插队）恒回 `-204`。所以 relay 必须自己开会话、自己收尾，别把这两步拆到不同
//! 连接/不同调用者上去。
//!
//! `init_sign` 拿到会话时保存 (uid, 别名, challenge)，finish 回 -204 时可在同一次
//! 设备占用内重开会话，签同一个 challenge。租约外的过期 finish 不再补签，以免顶掉
//! 新流程；成功补签与原流程使用同一把钥匙、同一个挑战。
//!
//! 实际设备由租约串行化：init 前占位，成功后 session TTL 60 秒；finish 原子消费
//! requested+session，并在同一 guard 下补签。未知已派发结果隔离 60 秒；活跃 await
//! 的 guard 不因 TTL 被替换。HTTP 取消不能撤回已经进入 HAL 的操作。
//!
//! 租约只在「HAL 上有操作在飞」或者「正在收尾」的时候真挡人；`init_sign` 成功之后
//! 搁着等 `finish_sign` 的那种，下一笔可以直接接管。2026-10-02 的线上回归就出在这里：
//! 只 init 不 finish 的流程（B 端自检、第三方的能力探针）把租约空挂满 60 秒，真实用户
//! `init_sign` 等 3 秒抢不到就吃到 -9（`IS_AUTHING`），A 端连指纹圈都弹不出来。
//! 现在抢不到不再硬拒，退成不带租约执行，被顶掉的会话仍走 -204 补救 —— 也就是 1.6.3
//! 的性质，把租约只当成优化。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 一笔会话记多久。App 的 init->finish 正常是秒级，慢的时候是在等用户那一步
/// （指纹/人脸，几十秒量级）。生产里能看到隔几分钟才收尾的（App 自己缓着 session
/// 不急着签），所以给到 15 分钟；它保留路由/补救材料，不延长下面独立的 60 秒租约。
/// 内存被 [`MAX_ENTRIES`] 卡着。
const STASH_TTL: Duration = Duration::from_secs(900);

/// 最多记多少条，挡住异常增长（正常随 `finish_sign` 清掉）。
const MAX_ENTRIES: usize = 8192;

/// 抢设备租约最多等多久。还要被调用方自己的网络 deadline 卡着，取小的那个。
const ACQUIRE_WAIT: Duration = Duration::from_secs(3);

/// `init_sign` 成功之后，租约替这笔流程把会话留多久等 `finish_sign`。等用户那一步是
/// 几十秒量级，所以留够。它是上限而不是保守期限：停在这儿等 finish 的租约下一笔 init
/// 可以直接接管（见 [`SignSessions::acquire`]）。
const LEASE_HOLD: Duration = Duration::from_secs(60);

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
    leases: Mutex<HashMap<String, Lease>>,
}

struct Lease {
    id: uuid::Uuid,
    deadline: tokio::time::Instant,
    requested: String,
    session: Option<i64>,
    finishing: bool,
    inflight: bool,
}

/// HTTP future owns this guard until successful init transfers ownership to TTL.
/// Drop only removes its own generation, never a replacement lease.
pub struct SignLease {
    owner: Arc<SignSessions>,
    device: String,
    id: uuid::Uuid,
    pub deadline: tokio::time::Instant,
    retained: bool,
    dispatched: bool,
}

/// 收尾时没拿到租约的原因。调用方靠它决定是硬拒还是退成不带租约执行。
#[derive(Debug, PartialEq, Eq)]
pub enum LeaseMiss {
    /// 租约不是这一笔的：会话被顶掉、被接管，或者早就过期了。不该硬拒 ——
    /// 送设备去让它自己回 -204，补救路径能接住。
    NotOurs,
    /// 同一笔 finish 已经在收尾了。这种才是真该拒的，免得同一张会话签两遍。
    Busy,
}

impl SignLease {
    pub fn dispatch(&mut self) {
        self.dispatched = true;
    }
    pub fn completed(&mut self) {
        self.dispatched = false;
    }
    pub fn retain_session(&mut self, session: i64) -> bool {
        let mut leases = self.owner.leases.lock().unwrap_or_else(|p| p.into_inner());
        let Some(lease) = leases.get_mut(&self.device) else {
            return false;
        };
        if lease.id != self.id || tokio::time::Instant::now() >= lease.deadline {
            return false;
        }
        lease.session = Some(session);
        lease.inflight = false;
        lease.deadline = tokio::time::Instant::now() + LEASE_HOLD;
        self.retained = true;
        true
    }
}

impl Drop for SignLease {
    fn drop(&mut self) {
        if self.retained {
            return;
        }
        let mut leases = self.owner.leases.lock().unwrap_or_else(|p| p.into_inner());
        if leases.get(&self.device).is_some_and(|l| l.id == self.id) {
            if self.dispatched {
                // Unknown dispatched HAL result: quarantine rather than pretend
                // HTTP cancellation recalled the operation. No session can finish it.
                let lease = leases.get_mut(&self.device).unwrap();
                lease.inflight = false;
                lease.session = None;
                lease.deadline = tokio::time::Instant::now() + LEASE_HOLD;
            } else {
                leases.remove(&self.device);
            }
        }
    }
}

impl SignSessions {
    pub fn new() -> Self {
        Self::with_ttl(STASH_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
            leases: Mutex::new(HashMap::new()),
        }
    }

    /// 占住已经解析好的那台物理设备。
    ///
    /// 空位直接占；`init_sign` 成功、搁在那儿等 `finish_sign` 的租约也可以接管 ——
    /// 只 init 不 finish 的流程本来就不会来收尾，让它把设备空挂满 [`LEASE_HOLD`] 正是
    /// 2026-10-02 那次线上回归的直接原因。被接管的那一笔如果之后真来 finish，会走
    /// [`LeaseMiss::NotOurs`] 退成不带租约执行，再靠 -204 补救。
    ///
    /// 派发过但结果不明的那种（quarantine，`session` 已经清掉）不碰：设备上可能真的
    /// 还有一笔在跑。等待是异步的，同时被 [`ACQUIRE_WAIT`] 和调用方原来的网络 deadline
    /// 卡着。
    pub async fn acquire(
        self: &Arc<Self>,
        device: &str,
        requested: &str,
        deadline: tokio::time::Instant,
    ) -> Option<SignLease> {
        let wait_until = deadline.min(tokio::time::Instant::now() + ACQUIRE_WAIT);
        loop {
            {
                let mut leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
                let now = tokio::time::Instant::now();
                leases.retain(|_, l| l.inflight || l.deadline > now);
                let free = match leases.get(device) {
                    None => true,
                    Some(l) if l.session.is_some() && !l.inflight && !l.finishing => {
                        tracing::warn!(
                            "soter: {} 上的签名租约空挂等 finish（session={:?}，原请求 {}），交给 {} 接管",
                            device,
                            l.session,
                            l.requested,
                            requested
                        );
                        true
                    }
                    Some(_) => false,
                };
                if free && now < deadline {
                    let id = uuid::Uuid::new_v4();
                    let expires = now + LEASE_HOLD;
                    leases.insert(
                        device.to_owned(),
                        Lease {
                            id,
                            deadline: expires,
                            requested: requested.to_owned(),
                            session: None,
                            finishing: false,
                            inflight: true,
                        },
                    );
                    return Some(SignLease {
                        owner: self.clone(),
                        device: device.to_owned(),
                        id,
                        deadline: expires,
                        retained: false,
                        dispatched: false,
                    });
                }
            }
            if tokio::time::Instant::now() >= wait_until {
                return None;
            }
            tokio::time::sleep_until(
                wait_until.min(tokio::time::Instant::now() + Duration::from_millis(10)),
            )
            .await;
        }
    }

    /// 原子消费这一笔；重复或者过期的 finish 不该真下发 HAL 工作。
    ///
    /// 没拿到的原因分两种（见 [`LeaseMiss`]）：同一笔正在收尾才是真拒，租约不是这一笔
    /// 的退成不带租约执行，别把用户挡在门外。
    pub fn finish(
        self: &Arc<Self>,
        device: &str,
        requested: &str,
        session: i64,
        deadline: tokio::time::Instant,
    ) -> Result<SignLease, LeaseMiss> {
        let mut leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        let now = tokio::time::Instant::now();
        let Some(lease) = leases.get_mut(device) else {
            return Err(LeaseMiss::NotOurs);
        };
        if lease.finishing {
            return Err(LeaseMiss::Busy);
        }
        if lease.deadline <= now
            || deadline <= now
            || lease.requested != requested
            || lease.session != Some(session)
        {
            return Err(LeaseMiss::NotOurs);
        }
        lease.finishing = true;
        lease.inflight = true;
        Ok(SignLease {
            owner: self.clone(),
            device: device.to_owned(),
            id: lease.id,
            // TTL gates admission only; inflight now prevents replacement.
            deadline,
            retained: false,
            dispatched: false,
        })
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
        let first = match devices.next() {
            Some(device) => device,
            None => {
                let leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
                let mut matches = leases.iter().filter(|(_, l)| {
                    l.requested == requested
                        && l.session == Some(session)
                        && l.deadline > tokio::time::Instant::now()
                });
                let (device, _) = matches.next()?;
                return if matches.next().is_none() {
                    Some(device.clone())
                } else {
                    None
                };
            }
        };
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

    #[tokio::test(start_paused = true)]
    async fn leases_interleave_finish_repair_and_devices() {
        let s = Arc::new(SignSessions::new());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut first = s.acquire("a", "caller", deadline).await.unwrap();
        first.dispatch();
        first.completed();
        assert!(first.retain_session(42));
        drop(first);
        let other = s.acquire("b", "caller", deadline).await.unwrap();
        // 原来这一笔停在「等 finish」上，谁也别想进来；现在可以接管 —— 只 init
        // 不 finish 的探针流程就卡在这个状态，不能让它把设备空挂满。
        let mut takeover = s.acquire("a", "second", deadline).await.unwrap();
        takeover.dispatch();
        assert!(takeover.retain_session(42));
        // 被接管的那一笔来收尾：租约不是它的了，退成不带租约执行，不硬拒。
        assert!(matches!(
            s.finish("a", "wrong", 42, deadline),
            Err(LeaseMiss::NotOurs)
        ));
        assert!(matches!(
            s.finish("a", "caller", 42, deadline),
            Err(LeaseMiss::NotOurs)
        ));
        let mut finish = s.finish("a", "second", 42, deadline).unwrap();
        // 同一笔重复收尾才是真该拒的。
        assert!(matches!(
            s.finish("a", "second", 42, deadline),
            Err(LeaseMiss::Busy)
        ));
        let waiting = {
            let s = s.clone();
            tokio::spawn(async move { s.acquire("a", "third", deadline).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished()); // 收尾在飞，别人得等
        finish.dispatch(); // original finish + repair init/finish share this guard
        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(waiting.await.unwrap().is_none());
        finish.completed();
        drop(finish);
        drop(takeover);
        let next = s
            .acquire(
                "a",
                "third",
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(matches!(
            s.finish("a", "caller", 42, deadline),
            Err(LeaseMiss::NotOurs)
        ));
        drop(next);
        drop(other);
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_drop_and_unknown_dispatch_quarantine() {
        let s = Arc::new(SignSessions::new());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(200);
        let guard = s.acquire("a", "one", deadline).await.unwrap();
        drop(guard); // before dispatch frees immediately
        let mut guard = s.acquire("a", "one", deadline).await.unwrap();
        guard.dispatch();
        tokio::time::advance(Duration::from_secs(61)).await;
        assert!(s.acquire("a", "two", deadline).await.is_none()); // inflight cannot expire
        drop(guard); // unknown remote operation, quarantine
        assert!(s.acquire("a", "two", deadline).await.is_none());
        tokio::time::advance(Duration::from_secs(60)).await;
        let mut guard = s.acquire("a", "two", deadline).await.unwrap();
        assert!(guard.retain_session(43));
        drop(guard);
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(s.finish("a", "two", 43, deadline).is_err());
        assert!(s.acquire("a", "three", deadline).await.is_some());
    }

    /// 停在原地等 finish 的租约不挡人；真有一笔在飞的时候才挡。
    ///
    /// 2026-10-02 的线上回归就出在前半句：探针只 init 不 finish，把这个状态空挂了
    /// 60 秒，真实用户的 init 抢不到租约、A 端连指纹圈都弹不出来。
    #[tokio::test(start_paused = true)]
    async fn only_inflight_work_holds_the_device() {
        let s = Arc::new(SignSessions::new());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut init = s.acquire("a", "first", deadline).await.unwrap();
        assert!(init.retain_session(7));
        drop(init);
        // 等 finish 的租约可以接管。
        let mut next = s.acquire("a", "second", deadline).await.unwrap();
        next.dispatch();
        assert!(next.retain_session(7));
        // 被接管的那一笔来收尾，租约已经不是它的了。
        assert!(matches!(
            s.finish("a", "first", 7, deadline),
            Err(LeaseMiss::NotOurs)
        ));
        // 接管者自己收尾配得上；收尾期间别人得等。
        let mut finish = s.finish("a", "second", 7, deadline).unwrap();
        let waiter = {
            let s = s.clone();
            tokio::spawn(async move { s.acquire("a", "third", deadline).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(waiter.await.unwrap().is_none());
        finish.dispatch();
        finish.completed();
        drop(finish);
        drop(next);
        assert!(s
            .acquire(
                "a",
                "third",
                tokio::time::Instant::now() + Duration::from_secs(1)
            )
            .await
            .is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn inflight_finish_cannot_be_evicted_at_session_deadline() {
        let s = Arc::new(SignSessions::new());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(200);
        let mut init = s.acquire("a", "first", deadline).await.unwrap();
        assert!(init.retain_session(7));
        drop(init);
        tokio::time::advance(Duration::from_secs(59)).await;
        let request_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut finish = s.finish("a", "first", 7, request_deadline).unwrap();
        assert_eq!(finish.deadline, request_deadline);
        finish.dispatch();
        tokio::time::advance(Duration::from_secs(2)).await;
        // The old session TTL has elapsed, but this finish still has budget
        // for the HAL response and same-owner repair.
        assert!(tokio::time::Instant::now() < finish.deadline);
        assert!(s.acquire("a", "second", deadline).await.is_none());
        assert!(tokio::time::Instant::now() < finish.deadline);
        finish.completed();
        drop(finish);
        assert!(s.acquire("a", "second", deadline).await.is_some());
        assert!(s
            .acquire("b", "expired", tokio::time::Instant::now())
            .await
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_request_does_not_consume_live_session() {
        let s = Arc::new(SignSessions::new());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut init = s.acquire("a", "first", deadline).await.unwrap();
        assert!(init.retain_session(7));
        drop(init);
        assert!(s
            .finish("a", "first", 7, tokio::time::Instant::now())
            .is_err());
        assert!(s.finish("a", "first", 7, deadline).is_ok());
    }

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
