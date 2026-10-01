//! SOTER 签名会话的设备级排队。
//!
//! 背景（2026-10-01 实测）：设备上的 SOTER TA **一台设备同时只保留一个有效签名会话**。
//! 在一个槽位（uid + 别名）上连开 12 个 `init_sign`，回头按顺序 `finish_sign`，前 11 个
//! 全是 `-204`（`SOTER_ERROR_OPERATEID_NULL`），只有最后一个成。更宽的是：uid A 拿到
//! 会话之后，另一笔 **uid 不同、别名也不同** 的 `init_sign` 一打，A 那笔的 `finish_sign`
//! 照样 -204 —— 这个「一个」是整台设备（TA）级别的，不是槽位级的。B 端的 relay 只是把
//! 句柄透传给 HAL / TA，自己根本没有会话表，所以这个脾气改不动。
//!
//! 后果：B 是所有 A 设备共用的，谁先用上、谁手上那笔就可能被后来的顶掉，只能重试。
//! 生产日志 18 小时里 `finish_sign -204` 有 267 次（其中还有一部分是 B 端自己的能力探针
//! 干的，那个已经在 B 端加了空闲门）。
//!
//! 这一层做的事很小：`init_sign` 到它的 `finish_sign` 之间按**设备**排队。后来的那笔先等
//! 前一笔收尾（最多 [`SIGN_DEVICE_WAIT`]），等不到就回 `-9`（`SOTER_ERROR_IS_AUTHING`，
//! 「这会儿正在认证」）—— App 认识这个码，会自己退让重试，比会话被悄悄顶掉强。一笔真
//! 流程只要百来毫秒，正常排队基本等不到 -9。
//!
//! 租约不是永久的：`LEASE_TTL` 之内没人来收尾（App 崩了、网断了）就自己松掉，不能让一台
//! 设备被永久卡死。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

/// 一笔 `init_sign` 最多占住设备多久。正常 `finish_sign` 百毫秒级就来了（最慢的
/// 也就是重试一次 429 退避，一点儿秒），这里只是兜底：没人来收尾就自己过期，不能
/// 把设备卡住。不能拖得太久 —— 一笔被抛弃的租约会把它后面的兄弟全堵成 -9。
const LEASE_TTL: Duration = Duration::from_secs(3);

/// 后来者最多等前一笔收尾多久。超了就不再等，回 -9 让 App 退让重试。
///
/// 上限卡在 3 秒：一是真流程百来毫秒就完了，二是“等”本身也是给 A 端看的耗时，
/// 不能把 TEE 那条路拖到几十秒去。
pub const SIGN_DEVICE_WAIT: Duration = Duration::from_secs(3);

/// 设备被占着的时候给调用方的码：`SOTER_ERROR_IS_AUTHING`。
pub const BUSY_CODE: i64 = -9;

/// 会话登记表最多记多少条。正常随 `finish_sign` 清掉，这里只是挡住异常增长。
const MAX_SESSIONS: usize = 4096;

#[derive(Default)]
struct Lease {
    /// 占用到期时刻；`None` = 空闲。
    until: Option<Instant>,
    /// 在门口排队的后来者，收尾时一起叫醒（他们会自己再抢一次）。
    waiters: Vec<oneshot::Sender<()>>,
}

#[derive(Default)]
struct Inner {
    leases: HashMap<String, Lease>,
    /// 会话 -> 它占的设备。`init_sign` 拿到 session 时登记，`finish_sign` 用它解锁。
    sessions: HashMap<i64, (String, Instant)>,
}

pub struct SignGate {
    ttl: Duration,
    inner: Mutex<Inner>,
}

impl SignGate {
    pub fn new() -> Self {
        Self::with_ttl(LEASE_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// 占住设备。占到了返回 true；等满 `wait` 还没轮到返回 false（调用方回 -9）。
    ///
    /// 占住之后**必须**有归宿：拿到 session 就 [`bind_session`](Self::bind_session)，
    /// 拿不到就 [`release`](Self::release)。
    pub async fn acquire(&self, device: &str, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            let rx = {
                let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
                if g.leases
                    .get(device)
                    .and_then(|l| l.until)
                    .is_some_and(|t| t > Instant::now())
                {
                    let (tx, rx) = oneshot::channel();
                    g.leases
                        .entry(device.to_string())
                        .or_default()
                        .waiters
                        .push(tx);
                    Some(rx)
                } else {
                    g.leases.entry(device.to_string()).or_default().until =
                        Some(Instant::now() + self.ttl);
                    None
                }
            };
            let Some(rx) = rx else { return true };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            if tokio::time::timeout(left, rx).await.is_err() {
                return false;
            }
            // 被叫醒：回去再抢一次（可能被别人抢走，那就接着排）。
        }
    }

    /// 释放设备，把排队的叫醒。
    pub fn release(&self, device: &str) {
        let waiters = {
            let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
            match g.leases.get_mut(device) {
                Some(lease) => {
                    lease.until = None;
                    std::mem::take(&mut lease.waiters)
                }
                None => Vec::new(),
            }
        };
        for w in waiters {
            let _ = w.send(());
        }
    }

    /// 这一笔的会话是在哪台设备上签的 —— 记下来，好让它的 `finish_sign` 来解锁。
    pub fn bind_session(&self, session: i64, device: &str) {
        let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        g.sessions
            .retain(|_, (_, at)| now.saturating_duration_since(*at) <= self.ttl);
        if g.sessions.len() >= MAX_SESSIONS {
            let mut ages: Vec<(i64, Instant)> =
                g.sessions.iter().map(|(s, (_, at))| (*s, *at)).collect();
            ages.sort_by_key(|(_, at)| *at);
            for (s, _) in ages.into_iter().take(g.sessions.len() / 2) {
                g.sessions.remove(&s);
            }
        }
        g.sessions.insert(session, (device.to_string(), now));
    }

    /// `finish_sign` 用会话换回它占的设备并释放。没登记过的会话返回 `None`（那就不管）。
    pub fn take_session(&self, session: i64) -> Option<String> {
        let device = {
            let mut g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
            g.sessions.remove(&session).map(|(d, _)| d)
        };
        if let Some(d) = device.as_deref() {
            self.release(d);
        }
        device
    }

    #[cfg(test)]
    fn busy(&self, device: &str) -> bool {
        let g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
        g.leases
            .get(device)
            .and_then(|l| l.until)
            .is_some_and(|t| t > Instant::now())
    }

    #[cfg(test)]
    fn waiting(&self, device: &str) -> usize {
        let g = self.hold().lock().unwrap_or_else(|p| p.into_inner());
        g.leases.get(device).map(|l| l.waiters.len()).unwrap_or(0)
    }

    fn hold(&self) -> &Mutex<Inner> {
        &self.inner
    }
}

impl Default for SignGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> SignGate {
        SignGate::with_ttl(Duration::from_millis(150))
    }

    #[test]
    fn the_lease_outlives_a_normal_flow_but_not_a_stuck_one() {
        // 真流程 init->finish 实测 46~336ms（见 2026-10-01 的 sg3 验证），租约得比
        // 它长；但又不能长到把后面排队的人全耗死。
        assert!(LEASE_TTL >= Duration::from_secs(1));
        assert!(LEASE_TTL <= Duration::from_secs(5));
        // 等待预算不短于租约：租约过期后排队的那位应该还来得及抢到，而不是白等。
        assert!(SIGN_DEVICE_WAIT >= LEASE_TTL);
        // 给 A 端看的等待不能拖到秒级以上。
        assert!(SIGN_DEVICE_WAIT <= Duration::from_secs(3));
    }

    #[tokio::test]
    async fn the_first_one_gets_the_device() {
        let g = gate();
        assert!(g.acquire("dev-a", Duration::from_millis(50)).await);
        assert!(g.busy("dev-a"));
    }

    #[tokio::test]
    async fn the_second_one_waits_until_the_first_finishes() {
        let g = std::sync::Arc::new(gate());
        assert!(g.acquire("dev-a", Duration::from_millis(50)).await);
        g.bind_session(111, "dev-a");

        let g2 = g.clone();
        let waiter = tokio::spawn(async move {
            let got = g2.acquire("dev-a", Duration::from_secs(2)).await;
            (got, Instant::now())
        });
        // 让后来者进到排队状态，再收尾。
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(g.waiting("dev-a"), 1, "后来者应该排在门口");
        let t0 = Instant::now();
        assert_eq!(g.take_session(111).as_deref(), Some("dev-a"));
        let (got, at) = waiter.await.expect("waiter 不该 panic");
        assert!(got, "前一笔收尾后，后来者应该拿到设备");
        assert!(at.duration_since(t0) < Duration::from_millis(120));
    }

    #[tokio::test]
    async fn a_waiter_gives_up_after_its_budget() {
        let g = gate();
        assert!(g.acquire("dev-a", Duration::from_millis(50)).await);
        let t0 = Instant::now();
        assert!(
            !g.acquire("dev-a", Duration::from_millis(120)).await,
            "前面那笔一直不收尾，后来者应该放弃（调用方回 -9）"
        );
        assert!(t0.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn an_abandoned_lease_expires() {
        let g = gate();
        assert!(g.acquire("dev-a", Duration::from_millis(50)).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!g.busy("dev-a"), "没人收尾的话租约自己过期");
        assert!(g.acquire("dev-a", Duration::from_millis(50)).await);
    }

    #[tokio::test]
    async fn a_finish_releases_only_its_own_device() {
        let g = gate();
        assert!(g.acquire("dev-a", Duration::from_millis(50)).await);
        assert!(g.acquire("dev-b", Duration::from_millis(50)).await);
        g.bind_session(1, "dev-a");
        g.bind_session(2, "dev-b");

        assert_eq!(g.take_session(1).as_deref(), Some("dev-a"));
        assert!(!g.busy("dev-a"));
        assert!(g.busy("dev-b"), "别把另一台设备一起放了");
    }

    #[tokio::test]
    async fn an_unknown_session_releases_nothing() {
        let g = gate();
        assert!(g.acquire("dev-a", Duration::from_millis(50)).await);
        assert_eq!(g.take_session(999), None);
        assert!(g.busy("dev-a"));
    }
}
