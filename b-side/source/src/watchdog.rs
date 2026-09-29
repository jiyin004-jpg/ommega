//! 跨 suspend 的看门狗：长轮询卡死之后别让 relay 就这么挂着。
//!
//! 要解决的是线上那几次几小时的静默 gap。`poll_tasks` 停在 reqwest 的 read 上，
//! 那一路的超时全是 `Instant`，也就是 `CLOCK_MONOTONIC`。设备一进 suspend 这个
//! 钟就不走了，超时永远不到，进程就一直挂在原地 —— `service.sh` 的 `wait` 也
//! 一起等着，重启逻辑根本没机会跑。进程还活着，只是再也不发轮询，服务端过
//! 120s 把它判离线，于是前端看到的就是「B 端不转发了」。
//!
//! 这里把判据换成 `CLOCK_BOOTTIME`（含 suspend 时长），一超过本轮允许的墙钟
//! 上限就让进程退出，交给 `service.sh` 重新拉起来。
//!
//! 只在设备醒着的时候干活：内部 `sleep` 用的还是单调钟，suspend 期间同样不走，
//! 所以既不会把设备唤醒、也不产生额外耗电；等设备因为任何原因醒过来（用户解锁、
//! WoWLAN、系统自己的闹钟），最多一个 tick 就能发现超时。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// 生产用的检查周期。设备醒来到进程重启也就晚一秒，再调大换不来什么。
pub const DEFAULT_TICK: Duration = Duration::from_secs(1);

type Clock = Box<dyn Fn() -> Option<u64> + Send + Sync>;
type OnExpire = Box<dyn Fn(u64) + Send + Sync>;

pub struct SuspendWatchdog {
    /// 0 表示当前没有在等的东西；否则是这一轮的绝对截止时刻（开机至今毫秒）。
    deadline_ms: AtomicU64,
    clock: Clock,
    on_expire: OnExpire,
}

impl SuspendWatchdog {
    /// 起一个后台线程盯着。`on_expire` 拿到的是超时了多少毫秒 —— 用开机时长算，
    /// 所以设备中途 suspend 多久都算在里面。
    pub fn spawn(tick: Duration, on_expire: impl Fn(u64) + Send + Sync + 'static) -> Arc<Self> {
        Self::spawn_with_clock(tick, boottime_ms, on_expire)
    }

    /// 同上，但时间源自己给。测试里用不着去读 `/proc/uptime`。
    pub fn spawn_with_clock(
        tick: Duration,
        clock: impl Fn() -> Option<u64> + Send + Sync + 'static,
        on_expire: impl Fn(u64) + Send + Sync + 'static,
    ) -> Arc<Self> {
        let watchdog = Arc::new(SuspendWatchdog {
            deadline_ms: AtomicU64::new(0),
            clock: Box::new(clock),
            on_expire: Box::new(on_expire),
        });
        let worker = Arc::clone(&watchdog);
        let spawned = std::thread::Builder::new()
            .name("suspend-watchdog".to_string())
            .spawn(move || worker.run(tick));
        if let Err(e) = spawned {
            // 线程起不来就退回改动前的行为（会卡），至少日志里留个痕。
            log::error!("suspend watchdog 线程起不来：{e}；长轮询卡死将不再被兜住");
        }
        watchdog
    }

    /// 开始一轮等待，`limit` 是这一轮允许的最大墙钟时间。
    pub fn arm(&self, limit: Duration) {
        let limit_ms = limit.as_millis().min(u64::MAX as u128) as u64;
        // 时间源读不到就别武装：宁可漏掉一次兜底，也不能拿个假时间把进程杀掉。
        let deadline = match (self.clock)() {
            Some(base) => base.saturating_add(limit_ms),
            None => 0,
        };
        self.deadline_ms.store(deadline, Ordering::Release);
    }

    /// 这一轮收工了。
    pub fn disarm(&self) {
        self.deadline_ms.store(0, Ordering::Release);
    }

    /// 当前有没有在等的东西。
    pub fn armed(&self) -> bool {
        self.deadline_ms.load(Ordering::Acquire) != 0
    }

    fn run(&self, tick: Duration) {
        loop {
            std::thread::sleep(tick);
            let deadline = self.deadline_ms.load(Ordering::Acquire);
            if deadline == 0 {
                continue;
            }
            let Some(now) = (self.clock)() else {
                continue;
            };
            if let Some(over_ms) = overdue(deadline, now) {
                // 认领这一轮。主线程要是刚好收工、或者已经开了下一轮，CAS 会失败，
                // 说明这次超时已经不作数了，那就什么都别做。
                if self
                    .deadline_ms
                    .compare_exchange(deadline, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    (self.on_expire)(over_ms);
                }
            }
        }
    }
}

/// 还没到返回 `None`，到了返回超过了多少毫秒。`deadline` 为 0 表示没在等。
fn overdue(deadline_ms: u64, now_ms: u64) -> Option<u64> {
    if deadline_ms == 0 || now_ms < deadline_ms {
        None
    } else {
        Some(now_ms - deadline_ms)
    }
}

/// 开机至今的毫秒数，**含 suspend 时间** —— 就是内核的 `CLOCK_BOOTTIME`。
///
/// 特意不去用 `Instant`（那是 `CLOCK_MONOTONIC`，suspend 期间停走），正是这个
/// 差别让 reqwest 那套超时在灭屏之后失效。`/proc/uptime` 的第一列就是它。
fn boottime_ms() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = raw.split_whitespace().next()?.parse().ok()?;
    if !secs.is_finite() || secs < 0.0 {
        return None;
    }
    Some((secs * 1000.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;

    /// 测试用的时间源：从建它的那一刻起算，host 上也能跑（不碰 /proc）。
    fn fake_clock() -> impl Fn() -> Option<u64> + Send + Sync + 'static {
        let start = Instant::now();
        move || Some(start.elapsed().as_millis() as u64)
    }

    fn recorder() -> (Arc<Mutex<Vec<u64>>>, impl Fn(u64) + Send + Sync + 'static) {
        let hits = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&hits);
        (hits, move |over_ms| sink.lock().unwrap().push(over_ms))
    }

    fn wait_until(mut cond: impl FnMut() -> bool, within: Duration) -> bool {
        let limit = Instant::now() + within;
        while Instant::now() < limit {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    #[test]
    fn overdue_only_after_deadline() {
        assert_eq!(overdue(0, 9_999), None, "没在等的时候不该报超时");
        assert_eq!(overdue(1_000, 999), None);
        assert_eq!(overdue(1_000, 1_000), Some(0), "正好到点也算到了");
        assert_eq!(overdue(1_000, 5_000), Some(4_000));
    }

    #[test]
    fn arm_and_disarm_toggle_state() {
        let (_hits, on_expire) = recorder();
        let wd =
            SuspendWatchdog::spawn_with_clock(Duration::from_millis(10), fake_clock(), on_expire);
        assert!(!wd.armed());
        wd.arm(Duration::from_secs(60));
        assert!(wd.armed());
        wd.disarm();
        assert!(!wd.armed());
    }

    #[test]
    fn fires_once_after_limit_passed() {
        let (hits, on_expire) = recorder();
        let wd =
            SuspendWatchdog::spawn_with_clock(Duration::from_millis(10), fake_clock(), on_expire);
        wd.arm(Duration::from_millis(40));
        assert!(
            wait_until(|| !hits.lock().unwrap().is_empty(), Duration::from_secs(5)),
            "看门狗没在 5 秒内触发"
        );
        let over_ms = hits.lock().unwrap()[0];
        // 报的是「超过截止点多久」，不是设定的 limit。检查间隔才 10ms，所以
        // 一到点就被抓住，这个值应该是零头。
        assert!(over_ms < 200, "报上来的超出量 {over_ms}ms 不合常理");
        assert!(!wd.armed(), "触发过就该解除武装");
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(hits.lock().unwrap().len(), 1, "同一轮只该触发一次");
    }

    #[test]
    fn disarm_in_time_prevents_fire() {
        let (hits, on_expire) = recorder();
        let wd =
            SuspendWatchdog::spawn_with_clock(Duration::from_millis(10), fake_clock(), on_expire);
        wd.arm(Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(100));
        wd.disarm();
        std::thread::sleep(Duration::from_millis(1200));
        assert!(hits.lock().unwrap().is_empty(), "收工之后不该再触发");
    }

    #[test]
    fn unreadable_clock_means_no_arm() {
        let (hits, on_expire) = recorder();
        let wd = SuspendWatchdog::spawn_with_clock(Duration::from_millis(10), || None, on_expire);
        wd.arm(Duration::from_millis(10));
        assert!(!wd.armed(), "时间源读不到就不该武装");
        std::thread::sleep(Duration::from_millis(100));
        assert!(hits.lock().unwrap().is_empty());
    }
}
