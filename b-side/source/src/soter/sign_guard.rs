//! In-memory signing lease and probe exclusion. Hold the mutex only across HAL
//! calls, never across the init -> finish wait. A lost finish (or HAL restart) expires.

use std::time::{Duration, Instant};

pub(super) const LEASE: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(super) struct SignGuard {
    last_activity: Option<Instant>,
    active: Option<(i64, Instant)>,
}

impl SignGuard {
    pub(super) const fn new() -> Self {
        Self {
            last_activity: None,
            active: None,
        }
    }

    pub(super) fn activity(&mut self, now: Instant) {
        self.last_activity = Some(now);
    }

    pub(super) fn init_succeeded(&mut self, session: i64, now: Instant) {
        self.activity(now);
        self.active = Some((session, now));
    }

    pub(super) fn finish_ended(&mut self, session: i64, now: Instant) {
        self.activity(now);
        if self.active.is_some_and(|(active, _)| active == session) {
            self.active = None;
        }
    }

    fn expire(&mut self, now: Instant) {
        if self
            .active
            .is_some_and(|(_, at)| now.duration_since(at) >= LEASE)
        {
            self.active = None;
        }
    }

    pub(super) fn init_allowed(&mut self, now: Instant) -> bool {
        self.expire(now);
        self.active.is_none()
    }

    pub(super) fn finish_allowed(&mut self, session: i64, now: Instant) -> bool {
        self.expire(now);
        // No local lease may mean a session established before this process started.
        self.active.is_none_or(|(active, _)| active == session)
    }

    pub(super) fn probe_allowed(&mut self, now: Instant) -> bool {
        self.expire(now);
        self.active.is_none()
            && !self
                .last_activity
                .is_some_and(|at| now.duration_since(at) < LEASE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_busy_until_the_active_lease_expires() {
        let now = Instant::now();
        let mut guard = SignGuard::new();
        assert!(guard.init_allowed(now));
        guard.init_succeeded(1, now);
        let before_expiry = now + LEASE - Duration::from_nanos(1);
        assert!(!guard.init_allowed(before_expiry));
        assert_eq!(guard.active, Some((1, now)));
        assert!(guard.init_allowed(now + LEASE));
        assert!(guard.active.is_none());
    }

    #[test]
    fn init_after_finish_ignores_recent_activity() {
        let now = Instant::now();
        let mut guard = SignGuard::new();
        guard.activity(now);
        assert!(guard.init_allowed(now));
        guard.init_succeeded(1, now);
        guard.finish_ended(1, now);
        assert!(guard.init_allowed(now));
        assert!(!guard.probe_allowed(now));
    }

    #[test]
    fn stale_finish_is_rejected_without_changing_the_active_lease() {
        let now = Instant::now();
        let mut guard = SignGuard::new();
        guard.init_succeeded(1, now);
        assert!(guard.init_allowed(now + LEASE));
        guard.init_succeeded(2, now + LEASE);
        assert!(!guard.finish_allowed(1, now + LEASE));
        assert_eq!(guard.active, Some((2, now + LEASE)));
        assert_eq!(guard.last_activity, Some(now + LEASE));
        assert!(guard.finish_allowed(2, now + LEASE));
        assert!(!guard.init_allowed(now + LEASE));
    }

    #[test]
    fn finish_without_a_live_local_lease_is_allowed() {
        let now = Instant::now();
        let mut guard = SignGuard::new();
        assert!(guard.finish_allowed(99, now));
        guard.init_succeeded(1, now);
        assert!(!guard.finish_allowed(99, now + LEASE - Duration::from_nanos(1)));
        assert!(guard.finish_allowed(99, now + LEASE));
        assert!(guard.active.is_none());
    }

    #[test]
    fn successful_init_has_its_own_lease() {
        let now = Instant::now();
        let mut guard = SignGuard::new();
        guard.activity(now);
        guard.init_succeeded(1, now + Duration::from_secs(10));
        assert!(!guard.probe_allowed(now + LEASE));
        assert!(guard.probe_allowed(now + LEASE + Duration::from_secs(10)));
    }

    #[test]
    fn old_finish_cannot_clear_replacement_session() {
        let now = Instant::now();
        let mut guard = SignGuard::new();
        guard.init_succeeded(1, now);
        guard.init_succeeded(2, now);
        guard.finish_ended(1, now);
        assert_eq!(guard.active.map(|(session, _)| session), Some(2));
        guard.finish_ended(2, now);
        assert!(guard.active.is_none());
        assert!(!guard.probe_allowed(now));
        assert!(guard.probe_allowed(now + LEASE));
    }

    #[test]
    fn failed_init_or_hal_error_does_not_erase_an_existing_lease() {
        let now = Instant::now();
        let mut guard = SignGuard::new();
        guard.init_succeeded(1, now);
        // Failed init/open only records activity, not a successful session.
        guard.activity(now + Duration::from_secs(5));
        assert_eq!(guard.active.map(|(session, _)| session), Some(1));
        assert!(!guard.probe_allowed(now + LEASE));
        assert!(guard.probe_allowed(now + LEASE + Duration::from_secs(5)));
    }

    #[test]
    fn abandoned_session_expires_and_process_restart_has_no_lease() {
        let now = Instant::now();
        let mut guard = SignGuard::new();
        assert!(guard.probe_allowed(now));
        guard.init_succeeded(1, now);
        assert!(!guard.probe_allowed(now + LEASE - Duration::from_nanos(1)));
        assert!(guard.probe_allowed(now + LEASE));
        assert!(guard.active.is_none());
        assert!(SignGuard::new().probe_allowed(now));
    }

    #[test]
    fn check_and_reservation_share_the_hal_mutex() {
        use std::sync::{Arc, Mutex, TryLockError};
        let gate = Arc::new(Mutex::new(SignGuard::new()));
        let mut probe = gate.lock().unwrap();
        assert!(probe.probe_allowed(Instant::now()));
        let other = Arc::clone(&gate);
        std::thread::spawn(move || {
            assert!(matches!(other.try_lock(), Err(TryLockError::WouldBlock)));
        })
        .join()
        .unwrap();
        drop(probe);
        gate.lock().unwrap().init_succeeded(1, Instant::now());
        assert!(!gate.lock().unwrap().probe_allowed(Instant::now()));
    }
}
