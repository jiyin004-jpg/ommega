//! In-memory task queue mirroring `relay_server/apps/relay_core/store.py`.
//!
//! A-side endpoints create tasks, wait for a B-side device to claim them
//! (`pop_for_b`), process them and report the result back (`complete_task`).
//! Timed-out assignments are reclaimed so they are not lost forever.

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Notify};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    Pending,
    Assigned,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub task_id: String,
    pub task_type: String,
    pub payload: Value,
    pub target_device_id: String,
    pub assigned_device_id: Option<String>,
    pub assigned_at_ms: u64,
    pub result: Option<Value>,
    pub created_at_ms: u64,
    pub completed_at_ms: u64,
    pub status: TaskStatus,
}

impl Task {
    pub fn status_str(&self) -> &'static str {
        match self.status {
            TaskStatus::Pending => "pending",
            TaskStatus::Assigned => "assigned",
            TaskStatus::Completed => "completed",
            TaskStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceEntry {
    pub device_id: String,
    pub machine_id: String,
    pub last_seen_ms: u64,
    pub connected: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TaskCounts {
    pub pending: usize,
    pub assigned: usize,
    pub completed: usize,
    pub failed: usize,
}

#[derive(Default)]
struct Inner {
    tasks: HashMap<String, Task>,
    /// Per-device pending queues: device_id -> FIFO of task_ids targeting it.
    pending_by_device: HashMap<String, VecDeque<String>>,
    /// Pending tasks with no target device (any device can claim them).
    pending_any: VecDeque<String>,
    /// Completed tasks ordered by completion time: (completed_at_ms, task_id).
    completed_queue: VecDeque<(u64, String)>,
    /// Failed tasks ordered by completion time: (failed_at_ms, task_id).
    failed_queue: VecDeque<(u64, String)>,
    devices: HashMap<String, DeviceEntry>,
    /// device_id -> (machine_id, last_seen_ms) that most recently served it (for concurrency check).
    active_machine: HashMap<String, (String, u64)>,
    /// per-device recent activity for load estimation: (timestamp_ms, weight).
    device_events: HashMap<String, VecDeque<(u64, u64)>>,
    /// Rotating index used to break load ties round-robin so the balancer
    /// doesn't always pick the same (first) device when several are idle.
    load_balance_index: usize,
}

pub struct TaskStore {
    inner: Mutex<Inner>,
    /// Woken whenever a new pending task appears (long-poll support).
    notify: Notify,
    /// Sync snapshot of recently-polling device ids (seen within the online
    /// window) so blocking threads (e.g. the auto-keybox loop) can read "who is
    /// online" without taking the async `inner` lock.
    online_seen: std::sync::RwLock<HashMap<String, u64>>,
    assignment_timeout: Duration,
    /// How long a pending task may wait before being marked as failed (timeout).
    pending_ttl: Duration,
    /// Maximum number of completed/failed tasks to retain (each category independently).
    completed_max: usize,
    /// How long completed/failed tasks are kept before being purged.
    completed_ttl: Duration,
}

impl TaskStore {
    pub fn new(
        assignment_timeout_secs: u64,
        pending_ttl_secs: u64,
        completed_max: usize,
        completed_ttl_secs: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            notify: Notify::new(),
            online_seen: std::sync::RwLock::new(HashMap::new()),
            assignment_timeout: Duration::from_secs(assignment_timeout_secs),
            pending_ttl: Duration::from_secs(pending_ttl_secs),
            completed_max,
            completed_ttl: Duration::from_secs(completed_ttl_secs),
        })
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Create a task and enqueue it. Returns the task_id.
    pub async fn create_task(
        &self,
        task_type: &str,
        payload: Value,
        target_device_id: &str,
    ) -> String {
        let task_id = uuid::Uuid::new_v4().to_string();
        let now = Self::now_ms();
        let mut inner = self.inner.lock().await;
        inner.tasks.insert(
            task_id.clone(),
            Task {
                task_id: task_id.clone(),
                task_type: task_type.to_string(),
                payload,
                target_device_id: target_device_id.to_string(),
                assigned_device_id: None,
                assigned_at_ms: 0,
                result: None,
                created_at_ms: now,
                completed_at_ms: 0,
                status: TaskStatus::Pending,
            },
        );
        // Enqueue into the per-device bucket or the wildcard queue.
        if target_device_id.is_empty() {
            inner.pending_any.push_back(task_id.clone());
        } else {
            inner
                .pending_by_device
                .entry(target_device_id.to_string())
                .or_default()
                .push_back(task_id.clone());
        }
        drop(inner);
        self.notify.notify_waiters();
        task_id
    }

    /// Record a device event (must be called while holding `inner`).
    fn record_event_locked(inner: &mut Inner, device_id: &str, weight: u64) {
        let now = Self::now_ms();
        let q = inner.device_events.entry(device_id.to_string()).or_default();
        q.push_back((now, weight));
        while let Some((ts, _)) = q.front() {
            if now.saturating_sub(*ts) > 60_000 {
                q.pop_front();
            } else {
                break;
            }
        }
    }

    /// Pop the next pending task matching this device, with long-poll semantics.
    /// Returns None after `timeout` elapsed with no match.
    pub async fn pop_for_b(
        &self,
        device_id: &str,
        machine_id: &str,
        timeout: Duration,
    ) -> Option<Task> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let mut inner = self.inner.lock().await;
                // Register the device as connected.
                let hb_now = Self::now_ms();
                inner.devices.insert(
                    device_id.to_string(),
                    DeviceEntry {
                        device_id: device_id.to_string(),
                        machine_id: machine_id.to_string(),
                        last_seen_ms: hb_now,
                        connected: true,
                    },
                );
                self.mark_online_sync(device_id, hb_now);
                if !machine_id.is_empty() {
                    inner.active_machine.insert(
                        device_id.to_string(),
                        (machine_id.to_string(), hb_now),
                    );
                }
                // Reclaim timed-out assignments first.
                self.reclaim_locked(&mut inner);
                // Expire stale pending tasks and prune old completed/failed.
                self.expire_locked(&mut inner);

                if let Some(task) = self.dequeue_locked(&mut inner, device_id) {
                    Self::record_event_locked(&mut inner, device_id, 1);
                    return Some(task);
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            // Wait for a new task or the timeout (short fallback poll prevents
            // a lost `notify_waiters` from stalling until the full timeout).
            let poll_interval = remaining.min(Duration::from_millis(250));
            tokio::select! {
                _ = self.notify.notified() => {},
                _ = tokio::time::sleep(poll_interval) => {},
            }
        }
    }

    /// Try to dequeue a task matching this device from the FIFO.
    /// O(1): checks per-device queue first, then the wildcard queue.
    fn dequeue_locked(&self, inner: &mut Inner, device_id: &str) -> Option<Task> {
        // 1) Try device-specific queue first.
        if let Some(q) = inner.pending_by_device.get_mut(device_id) {
            while let Some(candidate_id) = q.pop_front() {
                if let Some(t) = inner.tasks.get_mut(&candidate_id) {
                    t.assigned_device_id = Some(device_id.to_string());
                    t.assigned_at_ms = Self::now_ms();
                    t.status = TaskStatus::Assigned;
                    return Some(t.clone());
                }
                // Stale id (task no longer exists) — drop it.
            }
            // Queue is empty now — remove the entry to save memory.
            inner.pending_by_device.remove(device_id);
        }

        // 2) Try wildcard (any-device) queue.
        while let Some(candidate_id) = inner.pending_any.pop_front() {
            if let Some(t) = inner.tasks.get_mut(&candidate_id) {
                t.assigned_device_id = Some(device_id.to_string());
                t.assigned_at_ms = Self::now_ms();
                t.status = TaskStatus::Assigned;
                return Some(t.clone());
            }
            // Stale id (task no longer exists) — drop it.
        }

        None
    }

    /// Expire stale pending tasks and prune old completed/failed tasks.
    /// Must be called while holding `inner` lock.
    fn expire_locked(&self, inner: &mut Inner) {
        let now = Self::now_ms();
        let pending_ttl_ms = self.pending_ttl.as_millis() as u64;
        let completed_ttl_ms = self.completed_ttl.as_millis() as u64;

        // 1) Expire pending tasks older than pending_ttl → mark as Failed.
        let expired_pending: Vec<String> = inner
            .tasks
            .iter()
            .filter(|(_, t)| {
                t.status == TaskStatus::Pending
                    && now.saturating_sub(t.created_at_ms) > pending_ttl_ms
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired_pending {
            if let Some(t) = inner.tasks.get_mut(id) {
                t.status = TaskStatus::Failed;
                t.result = Some(serde_json::json!({
                    "error": "task expired: pending TTL exceeded"
                }));
                t.completed_at_ms = now;
                inner.failed_queue.push_back((now, id.clone()));
            }
        }
        // Remove expired tasks from per-device and wildcard queues.
        if !expired_pending.is_empty() {
            let expired_set: std::collections::HashSet<&String> = expired_pending.iter().collect();
            for queue in inner.pending_by_device.values_mut() {
                queue.retain(|id| !expired_set.contains(id));
            }
            inner.pending_any.retain(|id| !expired_set.contains(id));
            // Clean up empty per-device queues.
            inner.pending_by_device.retain(|_, q| !q.is_empty());
        }

        // 2) Prune completed tasks by TTL (front of queue = oldest).
        while let Some(&(ts, _)) = inner.completed_queue.front() {
            if now.saturating_sub(ts) > completed_ttl_ms {
                if let Some((_, id)) = inner.completed_queue.pop_front() {
                    inner.tasks.remove(&id);
                }
            } else {
                break;
            }
        }

        // 3) Prune failed tasks by TTL.
        while let Some(&(ts, _)) = inner.failed_queue.front() {
            if now.saturating_sub(ts) > completed_ttl_ms {
                if let Some((_, id)) = inner.failed_queue.pop_front() {
                    inner.tasks.remove(&id);
                }
            } else {
                break;
            }
        }

        // 4) Prune completed tasks by max count.
        while inner.completed_queue.len() > self.completed_max {
            if let Some((_, id)) = inner.completed_queue.pop_front() {
                inner.tasks.remove(&id);
            }
        }

        // 5) Prune failed tasks by max count.
        while inner.failed_queue.len() > self.completed_max {
            if let Some((_, id)) = inner.failed_queue.pop_front() {
                inner.tasks.remove(&id);
            }
        }
    }

    /// Reclaim tasks assigned to devices that never returned a result in time.
    fn reclaim_locked(&self, inner: &mut Inner) {
        let now = Self::now_ms();
        let timeout_ms = self.assignment_timeout.as_millis() as u64;
        let stale: Vec<String> = inner
            .tasks
            .iter()
            .filter(|(_, t)| {
                t.status == TaskStatus::Assigned && now.saturating_sub(t.assigned_at_ms) > timeout_ms
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(t) = inner.tasks.get_mut(&id) {
                t.status = TaskStatus::Pending;
                t.assigned_device_id = None;
                // Put back into the appropriate bucket.
                if t.target_device_id.is_empty() {
                    inner.pending_any.push_back(id.clone());
                } else {
                    inner
                        .pending_by_device
                        .entry(t.target_device_id.clone())
                        .or_default()
                        .push_back(id.clone());
                }
            }
        }
    }

    /// Complete a task with a result reported by the B-side.
    /// Returns Ok(()) if the task existed, Err(msg) otherwise.
    pub async fn complete_task(
        &self,
        task_id: &str,
        result: Value,
        device_id: &str,
    ) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        let Some(task) = inner.tasks.get_mut(task_id) else {
            return Err("task not found".to_string());
        };
        let now = Self::now_ms();
        let is_err = result.get("error").is_some();
        task.result = Some(result);
        task.status = if is_err { TaskStatus::Failed } else { TaskStatus::Completed };
        task.assigned_device_id = Some(device_id.to_string());
        task.completed_at_ms = now;
        // Track in the appropriate ordered queue for later TTL / capacity pruning.
        if is_err {
            inner.failed_queue.push_back((now, task_id.to_string()));
        } else {
            inner.completed_queue.push_back((now, task_id.to_string()));
        }
        Self::record_event_locked(&mut inner, device_id, 1);
        // Prune completed/failed tasks to stay within capacity/TTL limits.
        self.expire_locked(&mut inner);
        drop(inner);
        self.notify.notify_waiters();
        Ok(())
    }

    /// Wait for a task result, polling internally. Returns the result or None on timeout.
    pub async fn wait_for_result(
        &self,
        task_id: &str,
        timeout: Duration,
    ) -> Option<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let inner = self.inner.lock().await;
                if let Some(t) = inner.tasks.get(task_id) {
                    if t.status == TaskStatus::Completed || t.status == TaskStatus::Failed {
                        return t.result.clone();
                    }
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            // Poll with a short fallback interval: `notify_waiters` only wakes
            // waiters currently registered, so a notify that lands while this
            // future is not registered would otherwise be lost.
            let poll_interval = remaining.min(Duration::from_millis(250));
            tokio::select! {
                _ = self.notify.notified() => {},
                _ = tokio::time::sleep(poll_interval) => {},
            }
        }
    }

    pub async fn list_tasks(&self, limit: usize) -> Vec<Task> {
        let inner = self.inner.lock().await;
        let mut v: Vec<Task> = inner.tasks.values().cloned().collect();
        v.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        v.truncate(limit);
        v
    }

    pub async fn counts(&self) -> TaskCounts {
        let inner = self.inner.lock().await;
        let mut c = TaskCounts::default();
        for t in inner.tasks.values() {
            match t.status {
                TaskStatus::Pending => c.pending += 1,
                TaskStatus::Assigned => c.assigned += 1,
                TaskStatus::Completed => c.completed += 1,
                TaskStatus::Failed => c.failed += 1,
            }
        }
        c
    }

    pub async fn cancel_task(&self, task_id: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        if inner.tasks.remove(task_id).is_some() {
            // Remove from all pending queues.
            for queue in inner.pending_by_device.values_mut() {
                queue.retain(|id| id != task_id);
            }
            inner.pending_by_device.retain(|_, q| !q.is_empty());
            inner.pending_any.retain(|id| id != task_id);
            inner.completed_queue.retain(|(_, id)| id != task_id);
            inner.failed_queue.retain(|(_, id)| id != task_id);
            Ok(())
        } else {
            Err("task not found".to_string())
        }
    }

    pub async fn get_active_machine_id(&self, device_id: &str) -> Option<String> {
        let inner = self.inner.lock().await;
        let now = Self::now_ms();
        inner
            .active_machine
            .get(device_id)
            .filter(|(_, ts)| now.saturating_sub(*ts) < 30_000)
            .map(|(m, _)| m.clone())
    }

    pub async fn get_connected_devices(&self) -> Vec<DeviceEntry> {
        let inner = self.inner.lock().await;
        let now = Self::now_ms();
        inner
            .devices
            .values()
            .filter(|d| now.saturating_sub(d.last_seen_ms) < 120_000)
            .cloned()
            .collect()
    }

    /// Record a B-side heartbeat in the synchronous online snapshot. Called from
    /// `pop_for_b` (the B long-poll heartbeat), never from an async lock scope.
    fn mark_online_sync(&self, device_id: &str, now_ms: u64) {
        if let Ok(mut m) = self.online_seen.write() {
            m.insert(device_id.to_string(), now_ms);
        }
    }

    /// Unique device ids whose B side polled within the online window (120 s),
    /// readable from blocking threads (no async lock). Stale entries are evicted
    /// on read; mirrors the 120 s window of `get_connected_devices`.
    pub fn connected_device_ids_sync(&self) -> Vec<String> {
        let now = Self::now_ms();
        let mut guard = match self.online_seen.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.retain(|_, ts| now.saturating_sub(*ts) < 120_000);
        guard.keys().cloned().collect()
    }

    pub async fn get_device_load(&self, device_id: &str) -> u64 {
        let inner = self.inner.lock().await;
        inner
            .device_events
            .get(device_id)
            .map(|q| q.iter().map(|(_, w)| *w).sum())
            .unwrap_or(0)
    }

    /// Resolve the target device_id for a new task, with load-balancing
    /// fallback when the requested device is not online.
    ///
    /// - If `requested_did` is non-empty and online → return it directly.
    /// - If `requested_did` is not online but other devices are → return the
    ///   device with the fewest active (pending/assigned) tasks.
    /// - If no devices are online → return `requested_did` unchanged.
    ///
    /// Mirrors `relay_server/apps/relay_core/store.py::resolve_online_target`.
    pub async fn resolve_online_target(&self, requested_did: &str) -> String {
        let mut inner = self.inner.lock().await;
        let now = Self::now_ms();

        // Collect online device IDs (seen within the last 120 s).
        let online_ids: Vec<String> = inner
            .devices
            .values()
            .filter(|d| now.saturating_sub(d.last_seen_ms) < 120_000)
            .map(|d| d.device_id.clone())
            .collect();

        if online_ids.is_empty() {
            return requested_did.to_string();
        }

        if !requested_did.is_empty() && online_ids.iter().any(|id| id == requested_did) {
            return requested_did.to_string();
        }

        // Load-balance: primary load = recent task activity within the last
        // 60 s (`device_events`), the SAME metric the admin UI displays via
        // `get_device_load`. Secondary = currently active (pending/assigned)
        // tasks targeting or claimed by the device. Exact ties are broken
        // round-robin so one device isn't always picked when several are idle.
        let mut candidates: Vec<(String, u64, usize)> = online_ids
            .iter()
            .map(|id| {
                let events: u64 = inner
                    .device_events
                    .get(id)
                    .map(|q| q.iter().map(|(_, w)| *w).sum())
                    .unwrap_or(0);
                let active = inner
                    .tasks
                    .values()
                    .filter(|t| {
                        t.assigned_device_id.as_deref() == Some(id)
                            || t.target_device_id == *id
                    })
                    .filter(|t| matches!(t.status, TaskStatus::Pending | TaskStatus::Assigned))
                    .count();
                (id.clone(), events, active)
            })
            .collect();

        candidates.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));

        let min = (candidates[0].1, candidates[0].2);
        let tied: Vec<&(String, u64, usize)> = candidates
            .iter()
            .filter(|c| (c.1, c.2) == min)
            .collect();
        if tied.len() > 1 {
            let i = inner.load_balance_index % tied.len();
            inner.load_balance_index = inner.load_balance_index.wrapping_add(1);
            return tied[i].0.clone();
        }
        candidates[0].0.clone()
    }
}

#[cfg(test)]
mod online_snapshot_tests {
    use super::*;

    #[test]
    fn connected_device_ids_sync_evicts_stale() {
        let store = TaskStore::new(30, 60, 100, 60);
        let now = TaskStore::now_ms();
        store.mark_online_sync("fresh", now);
        store.mark_online_sync("stale", now.saturating_sub(200_000));

        let ids = store.connected_device_ids_sync();
        assert_eq!(ids.len(), 1, "stale device must be evicted on read");
        assert_eq!(ids[0], "fresh");
    }
}
