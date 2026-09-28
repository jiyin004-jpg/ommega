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

/// 两次「清理」之间至少隔多久（毫秒）。`reclaim_locked` / `expire_locked` 都是
/// 对 `tasks` 的全表扫描，而 `pop_for_b` 的长轮询里每 250 ms 就回退醒一次
/// —— 一次 30 秒的 poll 光清理就扫上百遍，且全程占着同一把全局锁。这些
/// TTL 都是秒到分钟级的，按这个间隔节流既不妨碍判定超时，又能把扫描次数
/// 压到几十次以内。
const SWEEP_INTERVAL_MS: u64 = 1_000;

/// 自检失败原因写进状态页前的截断长度（B 端错误文本可能很长）。
const SELFCHECK_ERROR_MAX_CHARS: usize = 300;

/// 自检请求用的 alias。跟 A 端的 `ommega-remote-*` 分开，互不干扰。
const SELFCHECK_ALIAS: &str = "ommega-selfcheck";

/// 负载估算看的活动窗口（毫秒）。`device_events` 里每台设备一个小队列，
/// 记的是 (时间戳, 权重)；只有落在窗口里的事件才算进负载。
const ACTIVITY_WINDOW_MS: u64 = 60_000;

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
    /// `ATTESTATION_APPLICATION_ID` from the last chain this device produced —
    /// the package identity the key was minted for, parsed by
    /// `cert::attestation_application_id_from_chain`.  This is the one field
    /// that tells a chain minted by the device's *app* (`org.ommega.deviceb`)
    /// apart from one the module minted while relaying someone else's request
    /// (the requesting package).  Carried across poll upserts like `boot`.
    pub last_aaid: Option<String>,
    /// 自检（连上后替它排的那次认证）失败的原因。成功或还没自检时是 None，
    /// 状态页用它解释"这台为什么没有启动信息"。
    pub tee_error: Option<String>,
    /// 上次替这台设备排自检的时间戳（毫秒，0 = 从没排过）。只用来限流。
    pub tee_probe_at_ms: u64,
    /// 心跳里上报“这台能不能做 SOTER”。`Some(false)` 是设备明确说了没有，
    /// `None` 是没上报过（老版本 relay），两者对路由的意义不同：说过没有的
    /// 设备不会再被派 SOTER 任务。
    pub supports_soter: Option<bool>,
    /// 心跳里上报“签名真签出来过”（`soter_sign`）。`Some(true)` 是设备拿现成
    /// 槽位真签过一次，才敢报的；`None` 是没上报，不代表签不了。状态页拿它
    /// 区分“量过，行”和“没量过，还能试”。
    pub soter_sign: Option<bool>,
    /// 心跳里上报“这台签名行不行”。`Some(true)` 是设备自己说签不了
    /// （`soter_nosign`），签名类 op 不再派给它；`None` 是没上报（老版本 relay），
    /// 还能试。
    pub soter_nosign: Option<bool>,
    /// 心跳里上报的 StrongBox 能力（有没有那个 HAL 实例）。只看展示，
    /// StrongBox 出证走的是 strongbox 模式那套逻辑。
    pub supports_strongbox: Option<bool>,
}

/// B 端心跳里带的能力声明。
///
/// `None` = 这台设备没上报这个能力（老版本 relay 不会带 `caps`），跟
/// "上报了但没有"是两回事：路由时前者可以试，后者直接跳过。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceCaps {
    pub soter: Option<bool>,
    /// 设备真签出来过一次（`soter_sign`）：签名那两个 op 派过去能做完。
    pub soter_sign: Option<bool>,
    /// 设备明说“签名这步做不了”（`soter_nosign`）：HAL 能答话，但签名要现场指纹，
    /// 无人值守的 B 端给不了。跟 `soter = Some(false)`（压根没 HAL）分开记，因为它
    /// 仍然能做身份/导出那些 op，只是签名不行。
    ///
    /// 老版本 relay 不会报这个名字 —— 那是“没说”，不是“做不到”，签名还能试。
    pub soter_nosign: Option<bool>,
    pub strongbox: Option<bool>,
}

/// 这一步得由 TEE 现场签（要新鲜指纹）：`init_sign` 开会话、`finish_sign` 出签名。
/// 其余的 op（身份、公钥导出、建/删）设备自己就能答。
fn soter_op_needs_sign(op: &str) -> bool {
    matches!(op, "init_sign" | "finish_sign")
}

fn task_needs_soter_sign(task: &Task) -> bool {
    task.payload
        .get("op")
        .and_then(Value::as_str)
        .map(soter_op_needs_sign)
        .unwrap_or(false)
}

impl DeviceCaps {
    /// 解析心跳的 `caps` 字段：逗号分隔的能力名，例如 `soter,strongbox`。
    ///
    /// - 字段缺失（`None`）→ 没有上报，沿用上一次的结论；
    /// - 空串（`Some("")`）→ 明确上报"一个都没有"。
    pub fn parse(raw: Option<&str>) -> Self {
        match raw {
            None => DeviceCaps::default(),
            Some(raw) => {
                let has = |name: &str| raw.split(',').any(|t| t.trim().eq_ignore_ascii_case(name));
                DeviceCaps {
                    soter: Some(has("soter")),
                    // 只有真签出来过的设备才会报这个名字；没报 = 没量过（或者量不
                    // 出来），那是“还能试”，不是“不行”。
                    soter_sign: Some(has("soter_sign")),
                    soter_nosign: Some(has("soter_nosign")),
                    strongbox: Some(has("strongbox")),
                }
            }
        }
    }
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
    /// 上次跑 `sweep_locked` 的时间戳（毫秒，0 = 还没跑过）。见 `SWEEP_INTERVAL_MS`。
    last_sweep_ms: u64,
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
            if now.saturating_sub(*ts) > ACTIVITY_WINDOW_MS {
                q.pop_front();
            } else {
                break;
            }
        }
    }

    /// 窗口内的活动量 —— 调度和状态页共用的那个“负载”。
    ///
    /// 队列只在 `record_event_locked` 里修剪，而那只有在该设备又冒出新事件时
    /// 才会跑：设备一安静，队列就停在那里，里面的旧事件永远不会过期。所以求和
    /// 时得自己按窗口筛一遍，不能信队列里的残留 —— 否则“曾经忙、现在闲着”的
    /// 机器负载一直挂在高位，被排在负载 0 的新机器后面，越闲越派不到活。
    fn window_activity_locked(inner: &Inner, device_id: &str) -> u64 {
        let now = Self::now_ms();
        inner
            .device_events
            .get(device_id)
            .map(|q| {
                q.iter()
                    .filter(|(ts, _)| now.saturating_sub(*ts) <= ACTIVITY_WINDOW_MS)
                    .map(|(_, w)| *w)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Pop the next pending task matching this device, with long-poll semantics.
    /// Returns None after `timeout` elapsed with no match.
    pub async fn pop_for_b(
        &self,
        device_id: &str,
        machine_id: &str,
        caps: DeviceCaps,
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
                let (
                    known_boot,
                    known_aaid,
                    known_tee_error,
                    known_probe_at,
                    known_supports_soter,
                    known_soter_sign,
                    known_soter_nosign,
                    known_supports_strongbox,
                ) = match inner.devices.get(device_id) {
                    Some(d) => (
                        d.boot.clone(),
                        d.last_aaid.clone(),
                        d.tee_error.clone(),
                        d.tee_probe_at_ms,
                        d.supports_soter,
                        d.soter_sign,
                        d.soter_nosign,
                        d.supports_strongbox,
                    ),
                    None => (None, None, None, 0, None, None, None, None),
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
                        last_aaid: known_aaid,
                        tee_error: known_tee_error,
                        tee_probe_at_ms: known_probe_at,
                        // 这次心跳没提的能力保留上次的结论，提了就按最新的算。
                        supports_soter: caps.soter.or(known_supports_soter),
                        soter_sign: caps.soter_sign.or(known_soter_sign),
                        soter_nosign: caps.soter_nosign.or(known_soter_nosign),
                        supports_strongbox: caps.strongbox.or(known_supports_strongbox),
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
                // 回收超时派发 + 过期/超量剪枝。两个都是全表扫描，按
                // `SWEEP_INTERVAL_MS` 节流（见常量注释）。
                self.sweep_locked(&mut inner);

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
        // 说过不支持的设备不该拿到 SOTER 任务：正常路径上 `resolve_soter_target`
        // 已经把它排除了，这里是兜底（比如设备在上报之后能力又变了）。
        // 两道门槛：`soter_ok` 是“这层能不能接 SOTER”（没 HAL 就整类不接），
        // `soter_sign_ok` 是“签名那两步行不行”（HAL 能答话但签不了的话，只有
        // 签名 op 不该派过来）。
        let (soter_ok, soter_sign_ok) = inner
            .devices
            .get(device_id)
            .map(|d| {
                (
                    d.supports_soter != Some(false),
                    d.soter_nosign != Some(true),
                )
            })
            .unwrap_or((true, true));
        // 1) Try device-specific queue first.
        //
        // 扫描上限设成本轮开始的长度：做不了的 SOTER 任务会被推到队尾，
        // 不设上限就会在“弹出→推回→再弹出”里转不出去。
        let mut picked: Option<Task> = None;
        let mut deferred: Vec<String> = Vec::new();
        if let Some(q) = inner.pending_by_device.get_mut(device_id) {
            let mut budget = q.len();
            while budget > 0 {
                budget -= 1;
                let Some(candidate_id) = q.pop_front() else {
                    break;
                };
                let Some(t) = inner.tasks.get_mut(&candidate_id) else {
                    // Stale id (task no longer exists) — drop it.
                    continue;
                };
                let cannot_sign = !soter_sign_ok && task_needs_soter_sign(t);
                if t.task_type == "soter" && (!soter_ok || cannot_sign) {
                    // 这台说它做不了 SOTER（或者只做不了签名那两步）。任务本身还等着人做，不能就这么
                    // 从队列里没了（那就只剩 TTL 扫到才被标失败），先收着。
                    deferred.push(candidate_id);
                    continue;
                }
                t.assigned_device_id = Some(device_id.to_string());
                t.assigned_at_ms = Self::now_ms();
                t.status = TaskStatus::Assigned;
                picked = Some(t.clone());
                break;
            }
            // Queue drained and nothing matched — drop the entry to save memory.
            if picked.is_none() && q.is_empty() {
                inner.pending_by_device.remove(device_id);
            }
        }
        // 做不了的那些交给通配队列：换台做得了的设备领走，别压在原地。
        for id in deferred {
            inner.pending_any.push_back(id);
        }
        if picked.is_some() {
            return picked;
        }

        // 2) Try wildcard (any-device) queue.
        let mut budget = inner.pending_any.len();
        while budget > 0 {
            budget -= 1;
            let Some(candidate_id) = inner.pending_any.pop_front() else {
                break;
            };
            let Some(t) = inner.tasks.get_mut(&candidate_id) else {
                // Stale id (task no longer exists) — drop it.
                continue;
            };
            let cannot_sign = !soter_sign_ok && task_needs_soter_sign(t);
            if t.task_type == "soter" && (!soter_ok || cannot_sign) {
                // 同上：放回队尾，留给做得了的设备。
                inner.pending_any.push_back(candidate_id);
                continue;
            }
            t.assigned_device_id = Some(device_id.to_string());
            t.assigned_at_ms = Self::now_ms();
            t.status = TaskStatus::Assigned;
            return Some(t.clone());
        }

        None
    }

    /// 一次清理：先回收超时没回的派发，再剪掉过期/超量的任务。
    ///
    /// 两步都是 `tasks` 全表扫描，调用点（长轮询回退、每笔结果结算）又都很密，
    /// 所以这里按 `SWEEP_INTERVAL_MS` 节流。TTL 判定最坏晚一个间隔，实际影响
    /// 可以忽略 —— 而省下的是全程持锁的全表扫描。
    fn sweep_locked(&self, inner: &mut Inner) {
        let now = Self::now_ms();
        if now.saturating_sub(inner.last_sweep_ms) < SWEEP_INTERVAL_MS {
            return;
        }
        inner.last_sweep_ms = now;
        self.reclaim_locked(inner);
        self.expire_locked(inner);
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
        // 同一条叶子证书上再取一次 AAID：启动信息只说明"设备处于什么状态"，
        // AAID 才说明"这条链是谁的身份出的"，两个都要落到状态页上。
        //
        // 这里**只把 leaf 抄出来，不当场解析**。解析是两次纯 CPU 的 DER/CBOR
        // 遍历，而这段还在 `inner` 锁里 —— 解析完才轮到下面的任务落库，才轮到
        // 末尾的 notify_waiters，也就是说等这条结果的 A 端请求要陪着一起等。
        // 状态页那份设备记录晚几十微秒更新没有任何人受影响，A 端的响应延迟却是
        // 整条链路的关键路径。所以顺序反过来：先把结果放给 A 端，再解析、再落表。
        let leaf =
            if task_type == "attest" && result.get("error").is_none() && !device_id.is_empty() {
                result
                    .get("cert_chain")
                    .and_then(Value::as_array)
                    .and_then(|chain| chain.first())
                    .and_then(Value::as_str)
                    .map(str::to_owned)
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
        // 任务本身（结果 + 状态 + 归属 + 队列）到这里已经全部落定，先把锁放掉：
        // A 端的 wait_for_result 只认 status，所以 notify 一响它立刻就能取走结果。
        // 下面那串"状态页的活儿"不该再挡在它前面。
        drop(inner);
        self.notify.notify_waiters();

        // 锁外解析：两次纯 CPU 的 DER/CBOR 遍历，不碰任何共享状态，也不用排队。
        let (boot, chain_aaid) = match leaf {
            Some(ref leaf) => (
                crate::cert::device_boot_info_from_chain(leaf),
                crate::cert::attestation_application_id_from_chain(leaf),
            ),
            None => (None, None),
        };

        // 再拿一次锁补设备记录。这一步纯粹是状态页展示用的，晚几十微秒没有任何
        // 代价；万一这段时间设备下线、条目被清掉了，就当这次没解析过，不重建条目。
        let mut inner = self.inner.lock().await;
        if boot.is_some() || chain_aaid.is_some() {
            if let Some(entry) = inner.devices.get_mut(device_id) {
                if let Some(info) = boot {
                    entry.boot = Some(info);
                    // 认证成功就说明 TEE 是好用的，清掉自检可能留下的失败记录。
                    entry.tee_error = None;
                }
                if let Some(aaid) = chain_aaid {
                    entry.last_aaid = Some(aaid);
                }
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
        self.sweep_locked(&mut inner);
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
        Self::window_activity_locked(&inner, device_id)
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
                let events = Self::window_activity_locked(&inner, id);
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

    /// Resolve the target for a SOTER task.
    ///
    /// SOTER 的答案是在目标设备的 TEE 里签的，换台设备就换了身份，所以它跟认证
    /// 不一样，没有 keybox / self_signed 兜底，只能挑一台真能做的设备：
    ///
    /// 1. 指定的设备在线、且上报了支持 SOTER → 就用它；
    /// 2. 否则在"上报了支持"的在线设备里按负载挑一台；
    /// 3. 再否则（没有设备上报过能力，比如老版本 relay）在"没上报"的设备里按负载挑；
    /// 4. 都没有 → `None`，调用方自己降级。
    ///
    /// 明确上报"不支持"的设备在第 1~3 步都不参与。
    pub async fn resolve_soter_target(
        &self,
        requested_did: &str,
        needs_sign: bool,
    ) -> Option<String> {
        let mut inner = self.inner.lock().await;
        let now = Self::now_ms();
        // 先把手上的设备快照出来（只取判路由要的字段），免得后面算负载时
        // 和 `load_balance_index` 的写操作撞借用。
        let online: Vec<(String, Option<bool>)> = inner
            .devices
            .values()
            .filter(|d| now.saturating_sub(d.last_seen_ms) < 120_000)
            // 签名 op 不能落到“明说签不了”的设备上：它接下去只会白跑一趟 -26。
            .filter(|d| !(needs_sign && d.soter_nosign == Some(true)))
            .map(|d| (d.device_id.clone(), d.supports_soter))
            .collect();
        if online.is_empty() {
            return None;
        }

        // 1) 指定的设备只要能做就直接用它 —— 这是调用方点名要的设备。
        if !requested_did.is_empty()
            && online
                .iter()
                .any(|(id, cap)| id == requested_did && *cap == Some(true))
        {
            return Some(requested_did.to_string());
        }

        // 2/3) 负载均衡。先只有"上报支持"的一档，再退到"没上报"的一档。
        // 负载口径跟认证那条路一致（近 60 s 的活动量 + 在跑的任务数）。
        for tier in [Some(true), None] {
            let mut candidates: Vec<(String, u64, usize)> = online
                .iter()
                .filter(|(_, cap)| *cap == tier)
                .map(|(id, _)| {
                    let events = Self::window_activity_locked(&inner, id);
                    let active = inner
                        .tasks
                        .values()
                        .filter(|t| {
                            t.assigned_device_id.as_deref() == Some(id.as_str())
                                || t.target_device_id == *id
                        })
                        .filter(|t| matches!(t.status, TaskStatus::Pending | TaskStatus::Assigned))
                        .count();
                    (id.clone(), events, active)
                })
                .collect();
            if candidates.is_empty() {
                continue;
            }
            candidates.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
            let min = (candidates[0].1, candidates[0].2);
            let tied: Vec<&(String, u64, usize)> =
                candidates.iter().filter(|c| (c.1, c.2) == min).collect();
            if tied.len() > 1 {
                let i = inner.load_balance_index % tied.len();
                inner.load_balance_index = inner.load_balance_index.wrapping_add(1);
                return Some(tied[i].0.clone());
            }
            return Some(candidates[0].0.clone());
        }

        None
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
            .pop_for_b(
                "device-b-self",
                "TEST-1",
                DeviceCaps::default(),
                Duration::from_millis(50),
            )
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
                .pop_for_b(
                    "device-b-self",
                    "TEST-1",
                    DeviceCaps::default(),
                    Duration::from_millis(50)
                )
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
            .pop_for_b(
                "device-b-blank",
                "TEST-1",
                DeviceCaps::default(),
                Duration::from_millis(50),
            )
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
                .pop_for_b(
                    "device-b-off",
                    "TEST-1",
                    DeviceCaps::default(),
                    Duration::from_millis(50)
                )
                .await
                .is_none(),
            "关掉自检后不该有任何任务"
        );
    }

    /// `caps` 解析：字段缺失 = 没上报，空串 = 明确上报"一个都没有"，两者不是一回事。
    #[test]
    fn device_caps_parse_distinguishes_absent_from_empty() {
        let absent = DeviceCaps::parse(None);
        assert_eq!(absent.soter, None);
        assert_eq!(absent.strongbox, None);

        let none = DeviceCaps::parse(Some(""));
        assert_eq!(none.soter, Some(false));
        assert_eq!(none.strongbox, Some(false));

        let both = DeviceCaps::parse(Some("soter,strongbox"));
        assert_eq!(both.soter, Some(true));
        assert_eq!(both.strongbox, Some(true));

        // 大小写/空格无所谓，不认识的名字不该被当成支持。
        let mixed = DeviceCaps::parse(Some(" SOTER , fingerprint "));
        assert_eq!(mixed.soter, Some(true));
        assert_eq!(mixed.soter_nosign, Some(false));
        assert_eq!(mixed.strongbox, Some(false));

        // `soter_nosign`（HAL 在、签名不行）跟 `soter` 各记各的。
        let nosign = DeviceCaps::parse(Some("soter,soter_nosign"));
        assert_eq!(nosign.soter, Some(true));
        assert_eq!(nosign.soter_nosign, Some(true));
        // `soter_sign`（真拿现成槽位签出来过）是第三条，独立于上面两条：报告里
        // 没有它就是“没量过”（还能试），不是“签不了”。
        let signed = DeviceCaps::parse(Some("soter,soter_sign"));
        assert_eq!(signed.soter, Some(true));
        assert_eq!(signed.soter_sign, Some(true));
        assert_eq!(signed.soter_nosign, Some(false));
        // 老版本 relay 只报 `soter`：那是“没说”，签名还能试（路由只看 != true）。
        let old = DeviceCaps::parse(Some("soter"));
        assert_eq!(old.soter_nosign, Some(false));
        assert_eq!(old.soter_sign, Some(false));
    }

    /// 上报 `soter_nosign` 的设备（HAL 能答话、签名要现场指纹）：身份/导出还能领，
    /// `init_sign`/`finish_sign` 不许派过来 —— 那两步远程一定回 -26，白跑一趟。
    #[tokio::test]
    async fn sign_ops_skip_a_device_that_reported_soter_nosign() {
        let store = TaskStore::new(30, 60, 100, 60, false);
        let nosign = DeviceCaps {
            soter_sign: None,
            soter: Some(true),
            soter_nosign: Some(true),
            strongbox: None,
        };
        assert!(store
            .pop_for_b("dev", "TEST-1", nosign, Duration::from_millis(10))
            .await
            .is_none());

        let identity = store
            .create_task("soter", serde_json::json!({ "op": "get_device_id" }), "dev")
            .await;
        store
            .create_task("soter", serde_json::json!({ "op": "finish_sign" }), "dev")
            .await;

        // 身份那个照旧领得到（它在队首，签名那个被挡在后面）。
        let popped = store
            .pop_for_b("dev", "TEST-1", nosign, Duration::from_millis(50))
            .await
            .expect("身份/导出的 op 应该还领得到");
        assert_eq!(popped.task_id, identity);
        // 只剩签名那个：同一台设备再问两次也不给，别的设备（说没 HAL）也拿不到。
        assert!(store
            .pop_for_b("dev", "TEST-1", nosign, Duration::from_millis(50))
            .await
            .is_none());
        let none = DeviceCaps {
            soter_sign: None,
            soter: Some(false),
            soter_nosign: None,
            strongbox: None,
        };
        assert!(store
            .pop_for_b("dev2", "TEST-1", none, Duration::from_millis(10))
            .await
            .is_none());

        // 路由也一样：点名要签名时跳过它，身份 op 照样用它。
        assert_eq!(store.resolve_soter_target("dev", true).await, None);
        assert_eq!(
            store.resolve_soter_target("dev", false).await.as_deref(),
            Some("dev")
        );
        // 没上报过的（老版本 relay）签名还是能试。
        let unknown = TaskStore::new(30, 60, 100, 60, false);
        assert!(unknown
            .pop_for_b(
                "dev",
                "TEST-1",
                DeviceCaps::default(),
                Duration::from_millis(10)
            )
            .await
            .is_none());
        assert_eq!(
            unknown.resolve_soter_target("", true).await.as_deref(),
            Some("dev")
        );
    }

    /// SOTER 路由：点名的设备支持就用它；不支持/没上报/不认识就落到支持的设备上。
    #[tokio::test]
    async fn soter_target_prefers_a_device_that_reported_support() {
        let store = TaskStore::new(30, 60, 100, 60, false);
        let none = DeviceCaps {
            soter_sign: None,
            soter: Some(false),
            soter_nosign: None,
            strongbox: Some(false),
        };
        let unknown = DeviceCaps::default();
        let yes = DeviceCaps {
            soter_sign: None,
            soter: Some(true),
            soter_nosign: None,
            strongbox: Some(true),
        };
        for (id, caps) in [
            ("dev-none", none),
            ("dev-unknown", unknown),
            ("dev-yes", yes),
        ] {
            assert!(store
                .pop_for_b(id, "TEST-1", caps, Duration::from_millis(10))
                .await
                .is_none());
        }

        assert_eq!(
            store
                .resolve_soter_target("dev-yes", false)
                .await
                .as_deref(),
            Some("dev-yes"),
            "点名的设备支持就应该用它"
        );
        for requested in ["dev-none", "dev-unknown", "dev-absent", ""] {
            assert_eq!(
                store
                    .resolve_soter_target(requested, false)
                    .await
                    .as_deref(),
                Some("dev-yes"),
                "requested={requested} 时应该落到唯一支持的设备"
            );
        }
    }

    /// 只有"没上报"的设备在线时也能用（老版本 relay）；但只剩"明确不支持"时不给结果。
    #[tokio::test]
    async fn soter_target_never_lands_on_a_device_that_said_no() {
        let store = TaskStore::new(30, 60, 100, 60, false);
        let none = DeviceCaps {
            soter_sign: None,
            soter: Some(false),
            soter_nosign: None,
            strongbox: None,
        };
        assert!(store
            .pop_for_b(
                "dev-unknown",
                "TEST-1",
                DeviceCaps::default(),
                Duration::from_millis(10)
            )
            .await
            .is_none());
        assert!(store
            .pop_for_b("dev-none", "TEST-1", none, Duration::from_millis(10))
            .await
            .is_none());
        assert_eq!(
            store.resolve_soter_target("", false).await.as_deref(),
            Some("dev-unknown"),
            "没上报的设备还能试"
        );

        let only_no = TaskStore::new(30, 60, 100, 60, false);
        assert!(only_no
            .pop_for_b("dev-none", "TEST-1", none, Duration::from_millis(10))
            .await
            .is_none());
        assert_eq!(only_no.resolve_soter_target("", false).await, None);
    }

    /// 兜底：设备上报"不支持"后不会领到 SOTER 任务，其他任务照常。
    #[tokio::test]
    async fn unsupported_device_never_dequeues_a_soter_task() {
        let store = TaskStore::new(30, 60, 100, 60, false);
        let yes = DeviceCaps {
            soter_sign: None,
            soter: Some(true),
            soter_nosign: None,
            strongbox: None,
        };
        assert!(store
            .pop_for_b("dev", "TEST-1", yes, Duration::from_millis(10))
            .await
            .is_none());
        let soter_task = store
            .create_task("soter", serde_json::json!({ "op": "probe" }), "dev")
            .await;

        // 改口：明确说不支持了。
        let no = DeviceCaps {
            soter_sign: None,
            soter: Some(false),
            soter_nosign: None,
            strongbox: None,
        };
        assert!(
            store
                .pop_for_b("dev", "TEST-1", no, Duration::from_millis(50))
                .await
                .is_none(),
            "说过不支持的设备不该领到 SOTER 任务"
        );

        // 认证任务不受影响。
        let attest_task = store
            .create_task("attest", serde_json::json!({}), "dev")
            .await;
        let popped = store
            .pop_for_b("dev", "TEST-1", no, Duration::from_millis(50))
            .await
            .expect("认证任务应该领得到");
        assert_eq!(popped.task_id, attest_task);

        // SOTER 任务还在待办里，没被谁吃掉。
        let still_pending = store
            .list_tasks(10)
            .await
            .into_iter()
            .find(|t| t.task_id == soter_task)
            .expect("任务应该还在");
        assert_eq!(still_pending.status, TaskStatus::Pending);
    }
}

#[cfg(test)]
mod device_load_window_tests {
    use super::*;

    /// 设备安静下来之后，窗口外的旧事件不能再算进负载。
    #[tokio::test]
    async fn load_forgets_events_outside_the_window() {
        let now = TaskStore::now_ms();
        let store = TaskStore::new(30, 60, 100, 60, false);
        {
            let mut inner = store.inner.lock().await;
            inner.device_events.insert(
                "dev".into(),
                [
                    (now.saturating_sub(300_000), 40), // 5 分钟前，早该忘掉
                    (now.saturating_sub(90_000), 18),  // 90 秒前，也在窗外
                    (now.saturating_sub(5_000), 3),    // 5 秒前，还算
                ]
                .into_iter()
                .collect(),
            );
        }
        assert_eq!(
            store.get_device_load("dev").await,
            3,
            "只有窗口内那 3 该算进来"
        );
    }

    /// 边界：正好落在窗口边上（60 s）的还算，刚过一秒的就不算。
    #[tokio::test]
    async fn window_edge_is_inclusive() {
        let now = TaskStore::now_ms();
        let store = TaskStore::new(30, 60, 100, 60, false);
        {
            let mut inner = store.inner.lock().await;
            inner.device_events.insert(
                "dev".into(),
                [
                    (now.saturating_sub(60_000), 4),
                    (now.saturating_sub(60_001), 9),
                ]
                .into_iter()
                .collect(),
            );
        }
        assert_eq!(store.get_device_load("dev").await, 4);
    }

    /// 派活的口径得跟 `get_device_load` 一样：很久没动静的机器不能因为历史
    /// 负载高就永远排在后面 —— 那正是“越闲越派不到活”的那个坑。
    #[tokio::test]
    async fn balancing_uses_the_same_fresh_window() {
        let now = TaskStore::now_ms();
        let store = TaskStore::new(30, 60, 100, 60, false);
        for id in ["dev-busy", "dev-idle"] {
            assert!(store
                .pop_for_b(
                    id,
                    "TEST-1",
                    DeviceCaps::default(),
                    Duration::from_millis(10)
                )
                .await
                .is_none());
        }
        {
            let mut inner = store.inner.lock().await;
            // dev-busy 曾经很忙，但那些事件早出了窗口；dev-idle 刚干了点活。
            inner.device_events.insert(
                "dev-busy".into(),
                [(now.saturating_sub(600_000), 99)].into_iter().collect(),
            );
            inner.device_events.insert(
                "dev-idle".into(),
                [(now.saturating_sub(1_000), 1)].into_iter().collect(),
            );
        }
        // 点名一台不在线的，逼它走负载均衡那条路。
        assert_eq!(
            store.resolve_online_target("dev-absent").await,
            "dev-busy",
            "过期负载不该再压着它"
        );
    }
}
