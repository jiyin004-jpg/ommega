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

/// 一个任务最多被重新派发多少次。没这个上限的话，B 端反复领取又超时
/// （拿了一直不 complete，或者领完就挂）会让任务在 Pending 里无限打转：
/// reclaim_locked 每次回收都把 created_at_ms 重置成 now，expire_locked
/// 就永远等不到 pending TTL。
const MAX_ASSIGN_ATTEMPTS: u32 = 5;

/// 自检的结果回来之前，隔多久才允许重新排一次（毫秒）。设备刚连上时会立刻排
/// 一次，正常情况下一个来回就出结论（`tee_error` 或 `boot`），不会再排。
const SELFCHECK_RETRY_MS: u64 = 120_000;

/// 自检失败原因写进状态页前的截断长度（B 端错误文本可能很长）。
const SELFCHECK_ERROR_MAX_CHARS: usize = 300;

/// 自检请求用的 alias。跟 A 端的 `ommega-remote-*` 分开，互不干扰。
const SELFCHECK_ALIAS: &str = "ommega-selfcheck";

#[derive(Debug, Clone)]
pub struct Task {
    pub task_id: String,
    pub task_type: String,
    pub payload: Value,
    pub target_device_id: String,
    pub assigned_device_id: Option<String>,
    pub assigned_at_ms: u64,
    /// 被派发出去的次数（含第一次）。回收重排时递增，到
    /// [`MAX_ASSIGN_ATTEMPTS`] 就判死，不再重派。
    pub attempts: u32,
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
    /// Boot state parsed from the last attestation this device produced (see
    /// `cert::device_boot_info_from_chain`).  Carried across poll upserts.
    pub boot: Option<crate::cert::DeviceBootInfo>,
    /// 自检（连上后替它排的那次认证）失败的原因。成功或还没自检时是 None，
    /// 状态页用它解释"这台为什么没有启动信息"。
    pub tee_error: Option<String>,
    /// 上次替这台设备排自检的时间戳（毫秒，0 = 从没排过）。只用来限流。
    pub tee_probe_at_ms: u64,
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
    /// B 端连上后是否替它排一次自检认证（见 `pop_for_b`）。
    b_selfcheck: bool,
}

/// 单字节长度的 DER 封装（自检用的 AAID 长度远小于 128）。
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    debug_assert!(content.len() < 128);
    let mut out = vec![tag, content.len() as u8];
    out.extend_from_slice(content);
    out
}

/// 自检请求用的 `AttestationApplicationId`（DER）：
/// `SEQUENCE { SET { SEQUENCE { OCTET STRING "org.ommega.selfcheck", INTEGER 1 } },
/// SET {} }`。自检没有真实调用方，用这个占位包名；做成合法 DER 是因为 b 端
/// 会先 `check_app_id_der` 再交给 TEE。
fn selfcheck_app_id_der() -> Vec<u8> {
    let name = b"org.ommega.selfcheck";
    // PackageInfoRecord ::= SEQUENCE { packageName OCTET STRING, version INTEGER }
    let mut info = vec![0x04, name.len() as u8];
    info.extend_from_slice(name);
    info.extend_from_slice(&[0x02, 0x01, 0x01]); // version = 1
    let record = der_wrap(0x30, &info);
    // packageInfos ::= SET OF <record>
    let mut body = der_wrap(0x31, &record);
    // signatureDigests ::= SET OF <空>
    body.extend_from_slice(&[0x31, 0x00]);
    der_wrap(0x30, &body)
}

/// 截断上报文本（错误信息可能很长，状态页只留前面一段）。
fn truncate_text(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}…")
}

impl TaskStore {
    pub fn new(
        assignment_timeout_secs: u64,
        pending_ttl_secs: u64,
        completed_max: usize,
        completed_ttl_secs: u64,
        b_selfcheck: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner::default()),
            notify: Notify::new(),
            online_seen: std::sync::RwLock::new(HashMap::new()),
            assignment_timeout: Duration::from_secs(assignment_timeout_secs),
            pending_ttl: Duration::from_secs(pending_ttl_secs),
            completed_max,
            completed_ttl: Duration::from_secs(completed_ttl_secs),
            b_selfcheck,
        })
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// 自检任务的 payload：跟 A 端请求同形，参数走 b 端默认值，且只有目标设备能领。
    fn selfcheck_payload(device_id: &str) -> Value {
        use base64::Engine as _;
        let app_id = base64::engine::general_purpose::STANDARD.encode(selfcheck_app_id_der());
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
        let challenge = base64::engine::general_purpose::STANDARD.encode(nonce);
        serde_json::json!({
            // 自检标记：`complete_task` 只对带这个标记的任务写 `tee_error`，
            // 免得 A 端某次参数不对的失败被记成"这台设备 TEE 坏了"。
            "selfcheck": true,
            "device_id": device_id,
            "alias": SELFCHECK_ALIAS,
            "challenge": challenge,
            // 跟 A 端真实请求同形。b 端除了 `challenge` 和 AAID 之外都有默认值，
            // 这里还是把常用参数显式写出来，让它跟一次真实认证走同一条路径。
            "device_attest_context": {
                "attestation_application_id": app_id,
                "attestation_security_level": 1,
                "key_algorithm": 3,
                "ec_curve": 1,
                "key_size": 256,
                "purpose": [2, 3],
                "digest": [4],
            },
        })
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
                attempts: 0,
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
        let q = inner
            .device_events
            .entry(device_id.to_string())
            .or_default();
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
                // Register the device as connected.  Carrying the previous
                // boot/tee state forward keeps what the status page already
                // knows about this device across the poll upsert.
                let hb_now = Self::now_ms();
                let (known_boot, known_tee_error, known_probe_at) =
                    match inner.devices.get(device_id) {
                        Some(d) => (d.boot.clone(), d.tee_error.clone(), d.tee_probe_at_ms),
                        None => (None, None, 0),
                    };
                let has_tee_verdict = known_boot.is_some() || known_tee_error.is_some();
                inner.devices.insert(
                    device_id.to_string(),
                    DeviceEntry {
                        device_id: device_id.to_string(),
                        machine_id: machine_id.to_string(),
                        last_seen_ms: hb_now,
                        connected: true,
                        boot: known_boot,
                        tee_error: known_tee_error,
                        tee_probe_at_ms: known_probe_at,
                    },
                );
                self.mark_online_sync(device_id, hb_now);
                if !machine_id.is_empty() {
                    inner
                        .active_machine
                        .insert(device_id.to_string(), (machine_id.to_string(), hb_now));
                }
                // 自检：设备一连上就替它排一次认证，把 TEE 状态（启动信息）落到
                // 状态页 —— 否则得等它恰好接到一次 A 端请求才有人认识它，服务端
                // 重启后这段空白期更长，而那些从来没接到过请求的设备（比如 TEE
                // 出问题、认证一直失败的那台）在页面上永远是一片空白。已经有结论
                // 就不再排（成功解析出启动信息、或已经失败并记了原因），结论还没
                // 回来之前的重排由 `SELFCHECK_RETRY_MS` 限流。
                if self.b_selfcheck
                    && !has_tee_verdict
                    && hb_now.saturating_sub(known_probe_at) > SELFCHECK_RETRY_MS
                {
                    let task_id = uuid::Uuid::new_v4().to_string();
                    inner.tasks.insert(
                        task_id.clone(),
                        Task {
                            task_id: task_id.clone(),
                            task_type: "attest".to_string(),
                            payload: Self::selfcheck_payload(device_id),
                            target_device_id: device_id.to_string(),
                            assigned_device_id: None,
                            assigned_at_ms: 0,
                            attempts: 0,
                            result: None,
                            created_at_ms: hb_now,
                            completed_at_ms: 0,
                            status: TaskStatus::Pending,
                        },
                    );
                    inner
                        .pending_by_device
                        .entry(device_id.to_string())
                        .or_default()
                        .push_back(task_id.clone());
                    if let Some(entry) = inner.devices.get_mut(device_id) {
                        entry.tee_probe_at_ms = hb_now;
                    }
                    tracing::info!(
                        "b_selfcheck: enqueued TEE self-check {task_id} for {device_id}"
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
                t.status == TaskStatus::Assigned
                    && now.saturating_sub(t.assigned_at_ms) > timeout_ms
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(t) = inner.tasks.get_mut(&id) {
                t.assigned_device_id = None;
                t.attempts = t.attempts.saturating_add(1);
                if t.attempts >= MAX_ASSIGN_ATTEMPTS {
                    // 派发次数用完了，判死，不再重派。
                    t.status = TaskStatus::Failed;
                    t.result = Some(serde_json::json!({
                        "error": "task expired: too many delivery attempts"
                    }));
                    t.completed_at_ms = now;
                    inner.failed_queue.push_back((now, id.clone()));
                    continue;
                }
                t.status = TaskStatus::Pending;
                // 重置创建时间：expire_locked 按创建时长判 pending TTL，
                // 不重置的话刚被回收重试的任务会立刻被判定超时失败，
                // 重试机制形同虚设。次数上界由 attempts 兜住。
                t.created_at_ms = now;
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
    /// Returns Ok(()) if the task existed and was still open, Err(msg) otherwise.
    ///
    /// 守卫（2026-09-21 加固）：只有 Assigned / Pending 状态可以被回传终结，
    /// 已 Completed / Failed 的任务直接拒绝；认领过的任务只接受
    /// assigned_device_id 那台设备的结果。
    pub async fn complete_task(
        &self,
        task_id: &str,
        result: Value,
        device_id: &str,
    ) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        // Collect what the boot-info parse needs before taking the task borrow:
        // an attestation result carries the device's own record, and its boot
        // state (boot key / lock state / boot hash / patch levels) is kept per
        // device for the status page.  Parsed outside the borrow, no logging -
        // the outcome is visible on the page.
        let task_type = inner.tasks.get(task_id).map(|t| t.task_type.clone());
        let Some(task_type) = task_type else {
            return Err("task not found".to_string());
        };
        // 自检任务（`payload.selfcheck == true`）的结论要单独写回设备状态。
        let is_selfcheck = inner
            .tasks
            .get(task_id)
            .and_then(|t| t.payload.get("selfcheck"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let boot =
            if task_type == "attest" && result.get("error").is_none() && !device_id.is_empty() {
                result
                    .get("cert_chain")
                    .and_then(Value::as_array)
                    .and_then(|chain| chain.first())
                    .and_then(Value::as_str)
                    .and_then(crate::cert::device_boot_info_from_chain)
            } else {
                None
            };
        // 只允许"在飞"的任务被回传终结：已经完结的任务再来一次（b 端最多
        // 重试 4 次、最坏 139s，同一个结果可能重复到达）不能覆盖已有结果，
        // 也不能把同一条任务二次塞进 completed_queue —— 那会让队列长度
        // 虚高，并让结果被取两次。Pending 仍然放行：分配超时（默认 60s）
        // 把任务回收成 Pending 后，原设备的晚到结果依旧是有效结果，此时
        // assigned_device_id 已被清空，下面的归属校验自然跳过。
        {
            let task = inner.tasks.get(task_id).expect("checked above");
            match task.status {
                TaskStatus::Assigned | TaskStatus::Pending => {}
                // 重复回传当幂等处理：结果已经在里面了，不动它，也不报错 ——
                // b 端 post_result 只在收到 2xx 时停止重试，回 4xx 只会让它的
                // 日志多一条"被拒绝"。真正的重复在这里被吃掉。
                TaskStatus::Completed | TaskStatus::Failed => {
                    tracing::debug!(
                        "complete_task: duplicate report for {task_id} from {device_id} ignored"
                    );
                    return Ok(());
                }
            }
            // 归属校验：认领过设备 id 的任务，只认那个设备报上来的结果，
            // 免得共享 B token 下另一台设备把结果顶掉。任一侧为空
            // （尚未认领 / 老客户端不带 device_id）时不拦。
            if let Some(assigned) = task.assigned_device_id.as_deref() {
                if !assigned.is_empty() && !device_id.is_empty() && assigned != device_id {
                    return Err("device mismatch".to_string());
                }
            }
        }
        let Some(task) = inner.tasks.get_mut(task_id) else {
            return Err("task not found".to_string());
        };
        let now = Self::now_ms();
        let is_err = result.get("error").is_some();
        // 自检的失败原因下面要写回设备，而 `result` 马上会被移进 task，先抄出来。
        let selfcheck_error = if is_err {
            result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_string()
        } else {
            String::new()
        };
        task.result = Some(result);
        task.status = if is_err {
            TaskStatus::Failed
        } else {
            TaskStatus::Completed
        };
        // 空 device_id 不覆盖已记录的归属，否则归属信息会被抹掉。
        if !device_id.is_empty() {
            task.assigned_device_id = Some(device_id.to_string());
        }
        task.completed_at_ms = now;
        // Track in the appropriate ordered queue for later TTL / capacity pruning.
        if is_err {
            inner.failed_queue.push_back((now, task_id.to_string()));
        } else {
            inner.completed_queue.push_back((now, task_id.to_string()));
        }
        if let Some(info) = boot {
            if let Some(entry) = inner.devices.get_mut(device_id) {
                entry.boot = Some(info);
                // 认证成功就说明 TEE 是好用的，清掉自检可能留下的失败记录。
                entry.tee_error = None;
            }
        }
        // 自检的失败原因要落到状态页上：这台设备之后可能再没人给它发任务，光有
        // 一个空的 boot 看不出到底是"还没自检"还是"TEE 报错了"。
        if is_selfcheck && !device_id.is_empty() {
            let verdict = if is_err {
                Some(truncate_text(&selfcheck_error, SELFCHECK_ERROR_MAX_CHARS))
            } else if inner
                .devices
                .get(device_id)
                .and_then(|d| d.boot.as_ref())
                .is_none()
            {
                // 认证成功、链也回来了，但链里没有可解析的启动信息。
                Some("认证链里没有可解析的启动信息".to_string())
            } else {
                None
            };
            if let Some(msg) = verdict {
                tracing::info!("b_selfcheck: {device_id} TEE self-check failed: {msg}");
                if let Some(entry) = inner.devices.get_mut(device_id) {
                    entry.tee_error = Some(msg);
                }
            }
        }
        Self::record_event_locked(&mut inner, device_id, 1);
        // Prune completed/failed tasks to stay within capacity/TTL limits.
        self.expire_locked(&mut inner);
        drop(inner);
        self.notify.notify_waiters();
        Ok(())
    }

    /// Wait for a task result, polling internally. Returns the result or None on timeout.
    pub async fn wait_for_result(&self, task_id: &str, timeout: Duration) -> Option<Value> {
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
        v.sort_by_key(|t| std::cmp::Reverse(t.created_at_ms));
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
    ///   least-loaded online device (the real-device layer may be served by
    ///   another B端 when the named one is down — this is intended).
    /// - If no devices are online → return `requested_did` unchanged.
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
                        t.assigned_device_id.as_deref() == Some(id) || t.target_device_id == *id
                    })
                    .filter(|t| matches!(t.status, TaskStatus::Pending | TaskStatus::Assigned))
                    .count();
                (id.clone(), events, active)
            })
            .collect();

        candidates.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));

        let min = (candidates[0].1, candidates[0].2);
        let tied: Vec<&(String, u64, usize)> =
            candidates.iter().filter(|c| (c.1, c.2) == min).collect();
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
        let store = TaskStore::new(30, 60, 100, 60, false);
        let now = TaskStore::now_ms();
        store.mark_online_sync("fresh", now);
        store.mark_online_sync("stale", now.saturating_sub(200_000));

        let ids = store.connected_device_ids_sync();
        assert_eq!(ids.len(), 1, "stale device must be evicted on read");
        assert_eq!(ids[0], "fresh");
    }
}

#[cfg(test)]
mod selfcheck_tests {
    use super::*;
    use base64::Engine as _;

    /// 自检用的 AAID 必须是 b 端 `check_app_id_der` 能解出的形状，所以把编码
    /// 逐字节钉住：`SEQUENCE { SET { SEQUENCE { OCTET STRING "org.ommega.selfcheck",
    /// INTEGER 1 } }, SET {} }`。
    #[test]
    fn selfcheck_app_id_is_the_expected_der() {
        let der = selfcheck_app_id_der();
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1] as usize, der.len() - 2, "外层 SEQUENCE 长度不对");
        assert_eq!(der[2], 0x31, "packageInfos 应该是 SET OF");
        // 外层 SEQUENCE 的内容 = packageInfos SET（der[2..31]）+ 空的
        // signatureDigests SET（der[31..33] 两字节），所以这里要减 6 而不是 4。
        assert_eq!(der[3] as usize, der.len() - 6);
        assert_eq!(der[4], 0x30, "PackageInfoRecord 应该是 SEQUENCE");
        assert_eq!(der[5], 0x19);
        assert_eq!(
            &der[6..8],
            &[0x04, 0x14],
            "包名应该是 20 字节的 OCTET STRING"
        );
        assert_eq!(&der[8..28], b"org.ommega.selfcheck");
        assert_eq!(&der[28..31], &[0x02, 0x01, 0x01], "version 应该是 1");
        assert_eq!(&der[31..33], &[0x31, 0x00], "signatureDigests 应该是空 SET");
        assert_eq!(der.len(), 33);
    }

    /// 设备一连上就替它排一次自检，而且只排一次；失败原因要落到设备状态上。
    #[tokio::test]
    async fn selfcheck_enqueued_once_and_records_failure() {
        let store = TaskStore::new(30, 60, 100, 60, true);

        // 第一次轮询：注册设备的同时排进自检，同一轮就能领到。
        let task = store
            .pop_for_b("device-b-self", "TEST-1", Duration::from_millis(50))
            .await
            .expect("连上后应该拿到一条自检任务");
        assert_eq!(task.task_type, "attest");
        assert_eq!(task.payload["selfcheck"], Value::Bool(true));
        assert_eq!(task.payload["alias"], SELFCHECK_ALIAS);
        assert_eq!(task.target_device_id, "device-b-self");
        let ctx = &task.payload["device_attest_context"];
        assert_eq!(ctx["attestation_security_level"], Value::from(1));
        assert_eq!(
            ctx["attestation_application_id"].as_str(),
            Some(
                base64::engine::general_purpose::STANDARD
                    .encode(selfcheck_app_id_der())
                    .as_str()
            )
        );
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(task.payload["challenge"].as_str().unwrap())
            .expect("challenge 必须是 base64");
        assert_eq!(nonce.len(), 32, "challenge 应该是 32 字节随机数");

        // 模拟 b 端回传失败（比如三星那种"成功但空链"最终被拦下的情况）。
        store
            .complete_task(
                &task.task_id,
                serde_json::json!({ "error": "empty cert chain" }),
                "device-b-self",
            )
            .await
            .expect("回传应该被接收");
        let dev = store
            .get_connected_devices()
            .await
            .into_iter()
            .find(|d| d.device_id == "device-b-self")
            .expect("设备应该还在线");
        assert_eq!(dev.tee_error.as_deref(), Some("empty cert chain"));
        assert!(dev.boot.is_none());

        // 已经有结论（失败）了，不再重排。
        assert!(
            store
                .pop_for_b("device-b-self", "TEST-1", Duration::from_millis(50))
                .await
                .is_none(),
            "已经有自检结论的设备不该再被自检"
        );
    }

    /// 自检"成功"、但链里没有可解析的启动信息时也要给出原因，不能留空。
    #[tokio::test]
    async fn selfcheck_unparsable_chain_reports_a_reason() {
        let store = TaskStore::new(30, 60, 100, 60, true);
        let task = store
            .pop_for_b("device-b-blank", "TEST-1", Duration::from_millis(50))
            .await
            .expect("自检任务");
        store
            .complete_task(
                &task.task_id,
                serde_json::json!({ "cert_chain": [] }),
                "device-b-blank",
            )
            .await
            .expect("回传");
        let dev = store
            .get_connected_devices()
            .await
            .into_iter()
            .find(|d| d.device_id == "device-b-blank")
            .expect("设备在线");
        assert!(
            dev.tee_error
                .as_deref()
                .is_some_and(|e| e.contains("没有可解析的启动信息")),
            "空链要给出可读原因，实际是 {:?}",
            dev.tee_error
        );
    }

    /// 关掉开关就完全不排自检。
    #[tokio::test]
    async fn selfcheck_disabled_enqueues_nothing() {
        let store = TaskStore::new(30, 60, 100, 60, false);
        assert!(
            store
                .pop_for_b("device-b-off", "TEST-1", Duration::from_millis(50))
                .await
                .is_none(),
            "关掉自检后不该有任何任务"
        );
    }
}
