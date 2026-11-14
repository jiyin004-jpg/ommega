//! SOTER forwarding for the B-side relay agent.
//!
//! 任务载荷：
//!
//! ```json
//! { "op": "export_attk_public_key" }
//! { "op": "export_ask_public_key", "uid": 10373 }
//! { "op": "init_sign", "uid": 10373, "alias": "SoterAuthKey", "challenge": "..." }
//! ```
//!
//! `op` 缺省是 `probe`，只报这台设备能不能做 SOTER；HAL 不在时其它 op 都返回描述性错误。
//! 会改设备状态的 op（建 / 删钥匙）需要 `OMMEGA_RELAY_SOTER_MUTATION=1` 才放行。
//!
//! The wire format lives in [`hal`]: hand-marshalled, checked against captured
//! replies (see [`fixtures`]).
//!
//! 后端按 [`hal::Backend::ALL`] 的顺序逐个尝试，AIDL / HIDL 两套并存；`probe` 回包里的
//! `backend` / `service` / `interface` 就是实际选中的那一个。

pub mod fixtures;
pub mod flow;
pub mod hal;
pub mod hal_restart;
pub mod hidl;
pub mod hwbinder;
mod sign_guard;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde_json::{json, Value};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use hal::{Soter, SoterData, SoterSession};

/// Ops that create or delete keys on the device.
const MUTATING_OPS: &[&str] = &[
    "generate_ask_key_pair",
    "generate_attk_key_pair",
    "generate_auth_key_pair",
    "remove_all_uid_key",
    "remove_auth_key",
];

/// Every op this module accepts.
const KNOWN_OPS: &[&str] = &[
    "probe",
    "selftest",
    "get_device_id",
    "export_attk_public_key",
    "export_ask_public_key",
    "export_auth_key_public_key",
    "init_sign",
    "finish_sign",
    "has_ask_already",
    "has_auth_key",
    "verify_attk_key_pair",
    "generate_ask_key_pair",
    "generate_attk_key_pair",
    "generate_auth_key_pair",
    "remove_all_uid_key",
    "remove_auth_key",
];

/// 这些 op 换掉了槽位的材料：之后「这批材料能不能签」必须重新量一次。
const SLOT_REBUILD_OPS: &[&str] = &[
    "generate_ask_key_pair",
    "remove_all_uid_key",
    "remove_auth_key",
];

/// SOTER_ERROR_VERIFICATION_FAILED（-26）：这一笔的验证没过去，不是「还没建好」。
const SOTER_VERIFICATION_FAILED: i64 = -26;

/// SOTER_ASK_NOT_READY / SOTER_AUTH_KEY_NOT_READY：这个槽位上还没有对应材料。
const SOTER_ASK_NOT_READY: i64 = -5;
const SOTER_AUTH_KEY_NOT_READY: i64 = -6;

/// SOTER 结构性不可用：没开（-12）、ATTK 没配（-13）、安全通道不通（-18）、
/// TA 拿不到（-20）。这些是「这台现在真做不了」，跟「这次没签成」不是一回事。
const SOTER_NOT_ENABLED: i64 = -12;
const SOTER_ATTK_NOT_PROVISIONED: i64 = -13;
const SOTER_SECURE_HW_FAILED: i64 = -18;
const SOTER_TA_UNAVAILABLE: i64 = -20;

/// 能力探针量出来的结论。
///
/// 只有 [`SignVerdict::Unavailable`] 是「这台现在签不了」的硬证据（SOTER 没开 / ATTK
/// 没配 / 安全通道不通这类结构性毛病）。
///
/// `-26`（`SOTER_ERROR_VERIFICATION_FAILED`）不能拿来下结论：它说的是这一笔的验证没
/// 过去（真应用那条路上就是 App 自己那步生物认证没成），换一笔就可能成。把它当
/// 「TA 要新鲜指纹」上报 `soter_nosign`，服务端会把能签的机器从签名链路上踢掉。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignVerdict {
    /// 真签出来了一次。
    Signed,
    /// TA 回 -26：这一笔的验证没过去（真应用就是 App 那步生物认证没成）。
    BiometricRequired,
    /// 这个槽位上没材料（-5 / -6），探不出签名能力。
    NoMaterial,
    /// SOTER 本身不可用（没开 / ATTK 没配 / 安全通道不通 / host 拿不到 TA）。
    Unavailable,
    /// HAL 没答话、答了个没见过的码、或者压根没目标可探。
    Unknown,
}

impl SignVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            SignVerdict::Signed => "signed",
            SignVerdict::BiometricRequired => "biometric_required",
            SignVerdict::NoMaterial => "no_material",
            SignVerdict::Unavailable => "unavailable",
            SignVerdict::Unknown => "unknown",
        }
    }

    pub fn from_probe(probe: &Value) -> Self {
        match probe.get("verdict").and_then(Value::as_str) {
            Some("signed") => SignVerdict::Signed,
            Some("biometric_required") => SignVerdict::BiometricRequired,
            Some("no_material") => SignVerdict::NoMaterial,
            Some("unavailable") => SignVerdict::Unavailable,
            _ => SignVerdict::Unknown,
        }
    }

    /// `init_sign` / `finish_sign` 回的那个码说明什么。
    fn from_code(code: i64) -> Self {
        match code {
            0 => SignVerdict::Signed,
            SOTER_VERIFICATION_FAILED => SignVerdict::BiometricRequired,
            SOTER_ASK_NOT_READY | SOTER_AUTH_KEY_NOT_READY => SignVerdict::NoMaterial,
            SOTER_NOT_ENABLED
            | SOTER_ATTK_NOT_PROVISIONED
            | SOTER_SECURE_HW_FAILED
            | SOTER_TA_UNAVAILABLE => SignVerdict::Unavailable,
            _ => SignVerdict::Unknown,
        }
    }
}

impl std::fmt::Display for SignVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 最近一次真发起签名的 (uid, alias)，给能力探针当目标用。
///
/// 只放内存：重启后重新学一次就够了，没上报能力的设备服务端照样会派活。
static LEARNED_PROBE_TARGET: Mutex<Option<(i32, String)>> = Mutex::new(None);

/// Serializes real signing HAL calls with the entire probe. The same mutex
/// atomically checks/reserves probe access and protects the in-memory lease.
/// Never held while waiting for a caller's finish or during HAL restart.
static SIGN_GUARD: Mutex<sign_guard::SignGuard> = Mutex::new(sign_guard::SignGuard::new());

/// SOTER 进 HAL 的排队：全局有上限 + 同一个 uid 串行。
///
/// RPMB 会话是独占资源：TA 漏释放后 `export_*` / `generate_*` 全部回 -5，只有重启能松开。
/// 所以是有上限的并行：
///   1. 全局同时在飞不超过 `max`（`relay.conf` 的 `soter_concurrency`，默认 2），留出
///      空位给系统自己那条路；
///   2. 同一个 uid 严格串行，不同 uid 之间并行。
///
/// 卡死的 TA 由 `hal_restart` 的「连续 258 → 自动重启」兜底；KeyMint / attest 不走这里。
const SOTER_CONCURRENCY_MIN: u32 = 1;
const SOTER_CONCURRENCY_MAX: u32 = 4;
/// 默认上限（`DEFAULT_SOTER_CONCURRENCY` 的库内镜像，见 `bin/relay.rs`）。
const SOTER_CONCURRENCY_DEFAULT: u32 = 2;
/// 当前上限。跑着的 relay 改 `relay.conf` 就热更新这个值，不用重刷模块。
static SOTER_MAX_CONCURRENT: AtomicU32 = AtomicU32::new(SOTER_CONCURRENCY_DEFAULT);

/// 由 relay 的配置层调（配置一读/一改就调一次）。
pub fn set_max_concurrency(n: u32) {
    SOTER_MAX_CONCURRENT.store(n, AtomicOrdering::Relaxed);
}

fn max_concurrency() -> u32 {
    SOTER_MAX_CONCURRENT
        .load(AtomicOrdering::Relaxed)
        .clamp(SOTER_CONCURRENCY_MIN, SOTER_CONCURRENCY_MAX)
}
/// 排队超过这么久就记一条 WARN。
const SOTER_WAIT_LOG_MS: u128 = 1000;

struct HalQueue {
    state: Mutex<HalQueueState>,
    cv: Condvar,
}

#[derive(Default)]
struct HalQueueState {
    /// 这一轮的上限，每次进门前刷新（改 relay.conf 不用重启）。
    max: u32,
    /// 所有 uid 加起来在飞几笔。
    total: u32,
    /// 每个 uid 在飞几笔。
    per_uid: HashMap<i32, u32>,
}

impl HalQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(HalQueueState::default()),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HalQueueState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 拿一个名额。
    ///
    /// `uid` 为 `None` 只是「这笔没指名 uid」（探针那种），照旧要占全局名额；
    /// 同线程重入（`handle()` 里会调到 `probe()`）不占名额。
    fn enter(&'static self, uid: Option<i32>, max: Option<u32>) -> SoterHalGate {
        let depth = SOTER_HAL_DEPTH.with(|d| d.get());
        if depth > 0 {
            // 名额已经在外层拿着了，这次只记深度、不占名额。
            SOTER_HAL_DEPTH.with(|d| d.set(depth + 1));
            return SoterHalGate {
                queue: None,
                uid: None,
            };
        }
        let max = max
            .unwrap_or_else(max_concurrency)
            .clamp(SOTER_CONCURRENCY_MIN, SOTER_CONCURRENCY_MAX);
        let started = Instant::now();
        {
            let mut st = self.lock();
            st.max = max;
            while st.total >= max
                || uid.is_some_and(|u| st.per_uid.get(&u).copied().unwrap_or(0) > 0)
            {
                st = self
                    .cv
                    .wait(st)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            st.total += 1;
            if let Some(u) = uid {
                *st.per_uid.entry(u).or_insert(0) += 1;
            }
        }
        let waited_ms = started.elapsed().as_millis();
        if waited_ms >= SOTER_WAIT_LOG_MS {
            log::warn!("soter: 排队等了 {waited_ms}ms 才轮到（上限 {max}，uid {uid:?}）");
        }
        SOTER_HAL_DEPTH.with(|d| d.set(1));
        SoterHalGate {
            queue: Some(self),
            uid,
        }
    }
}

static SOTER_HAL_QUEUE: OnceLock<HalQueue> = OnceLock::new();

fn hal_queue() -> &'static HalQueue {
    SOTER_HAL_QUEUE.get_or_init(HalQueue::new)
}

thread_local! {
    /// 本线程已经进过这道门几次。`handle()` 里会调到 `probe()`，所以必须能重入
    /// —— 带名额的门直接重入会自己把自己堵死。
    static SOTER_HAL_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// 一次 SOTER HAL 准入；出作用域自动还。
struct SoterHalGate {
    /// 占了名额的是哪张队列；重入那次是 `None`（名额记在最外层那笔上）。
    /// Drop 只看这个字段决定还不还名额。
    queue: Option<&'static HalQueue>,
    uid: Option<i32>,
}

impl SoterHalGate {
    /// `uid` 为 `None` 表示这笔请求没指名 uid（探针那种），只吃全局名额；
    /// `max` 为 `None` 就读全局配置值。
    fn enter(uid: Option<i32>, max: Option<u32>) -> Self {
        hal_queue().enter(uid, max)
    }
}

impl Drop for SoterHalGate {
    fn drop(&mut self) {
        let depth = SOTER_HAL_DEPTH.with(|d| d.get());
        if depth > 1 {
            SOTER_HAL_DEPTH.with(|d| d.set(depth - 1));
            return;
        }
        SOTER_HAL_DEPTH.with(|d| d.set(0));
        let Some(queue) = self.queue else {
            return; // 重入进来的那次没占名额
        };
        let mut st = queue.lock();
        st.total = st.total.saturating_sub(1);
        if let Some(uid) = self.uid {
            if let Some(n) = st.per_uid.get_mut(&uid) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    st.per_uid.remove(&uid);
                }
            }
        }
        drop(st);
        queue.cv.notify_all();
    }
}

/// 探针要试的那个槽位；没配 OMMEGA_RELAY_SOTER_PROBE_* 的时候就用这里学到的。
pub fn learned_probe_target() -> Option<(i32, String)> {
    LEARNED_PROBE_TARGET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// 这台机器签名到底行不行。只有两档：真签出来过，或者还没量出来。
///
/// **没有「签不了」这一档。** 失败码全是「这一笔没成」：`-26` 是这一笔的验证没过去
/// （真应用那条路上就是 App 那步生物认证）、`-204` 是会话被别人顶掉、超时是没等到
/// —— 换一笔就可能成，推不出「设备能力」。报 `soter_nosign` 会让服务端把签名 op 从
/// 这台机器上挪走，甚至把槽位钉到服务端自签那两层（App 手里的真料换成假料）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignState {
    /// 真签出来过（真实 op 或探针）：报 `soter_sign`。
    Proven,
    /// 还没量出来：什么都不报，服务端照旧会试。
    Unknown,
}

static SIGN_STATE: Mutex<SignState> = Mutex::new(SignState::Unknown);

pub fn sign_state() -> SignState {
    *SIGN_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn mark_sign_proven() {
    let mut state = SIGN_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *state != SignState::Proven {
        log::info!("soter: signed once, this device can sign (keeping the verdict)");
        *state = SignState::Proven;
    }
}

/// 一个真签名 op 的结果：只有「真签出来」算证据。
///
/// 失败码一律不参与结论（`-26` 这一笔没验过、`-204` 会话被顶掉、超时没等到）：那都是
/// 「这笔没成」，换一笔就可能成，推不出「这台签不了」。
fn note_sign_result(error_code: i64) {
    if error_code == 0 {
        mark_sign_proven();
    }
}

/// 槽位被重建 / 删掉：之前那条结论跟着作废（材料换了，重新量一次更保险；
/// 量不出来时不会瞎说不支持）。
pub fn clear_sign_state() {
    let mut state = SIGN_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *state = SignState::Unknown;
}

/// `init_sign` 回了 0 说明这个槽位真有材料，记下来给探针用（探针只用现成材料，
/// 不建不删）。没配探针目标的机器只能靠这里学到目标。
fn remember_probe_target(uid: i32, alias: &str) {
    if alias.is_empty() {
        return;
    }
    let mut slot = LEARNED_PROBE_TARGET
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.as_ref().map(|(u, a)| (*u, a.as_str())) != Some((uid, alias)) {
        log::info!(
            "soter: slot uid={uid} alias={alias} can be signed on, using it for the sign probe"
        );
        *slot = Some((uid, alias.to_string()));
    }
}

/// 恒 `false`：本机不替服务端判「这份材料签不了」。
///
/// `-26` 只是这一笔没签成（这一笔的验证没过去，真应用就是 App 那步生物认证没成），
/// 材料本身没毛病。拒服务这个槽位只会把 App 推向服务端那两层自签的假料；TA 的答复
/// 原样递上去，要不要换层由服务端按错误码性质决定。
fn is_hard_slot_failure(op: &str, result: &Value) -> bool {
    let _ = (op, result);
    false
}

/// `-5` / `-6`：TA 说这个槽位上的 ASK / AuthKey 没就绪 —— 这两码才值得原地重建。
/// 别的非零码（-18 安全通道、-8、-26 验证没过）动设备状态只会更糟。
///
/// `-65528`（`TEE_ERROR_ITEM_NOT_FOUND`）：这台机器上没有这号材料，和 -5/-6 同属缺料，
/// 一样该就地补齐再试。
const SOTER_ASK_NOT_READY_CODE: i32 = -5;
const SOTER_AUTH_KEY_NOT_READY_CODE: i32 = -6;
const SOTER_ITEM_NOT_FOUND_CODE: i32 = -65528;

/// 「B 端手上没这批材料」就地补齐再重试签名。
///
/// 只在 mutation 开关打开时调用。先问 HAL 缺哪一样（ASK / AuthKey），缺什么铸什么，
/// 然后重新建一次签名会话；补齐失败就把原始错误原样递上去，绝不假装签成功。
fn rebuild_material_then_sign(
    soter: &Soter,
    uid: i32,
    alias: &str,
    challenge: &str,
    original: SoterSession,
) -> SoterSession {
    // 只有「这个槽位确实没有」的码才算缺：-5 ASK 没好、-6 AuthKey 没好、-65528。
    // 别把「非 0」都当缺：-26（这一笔验证没过）、-204（会话被顶掉）、-18/-20（TA 坏了）
    // 都是「有料，但这次没成」。当它们缺会去 generate_* 覆盖掉 App 已经和腾讯/支付宝
    // 注册过的真材料，服务端存档从此对不上且无法恢复。探不动（HAL 报错）同样当「不缺」。
    let ask_missing = matches!(
        soter.has_ask_already(uid),
        Ok(SOTER_ASK_NOT_READY_CODE) | Ok(SOTER_ITEM_NOT_FOUND_CODE)
    );
    let auth_missing = matches!(
        soter.has_auth_key(uid, alias),
        Ok(SOTER_AUTH_KEY_NOT_READY_CODE) | Ok(SOTER_ITEM_NOT_FOUND_CODE)
    );
    if !ask_missing && !auth_missing {
        log::warn!(
            "soter: init_sign uid={uid} alias={alias} returned {} but the slot has material; \
             not touching device state",
            original.error_code
        );
        return original;
    }
    log::info!(
        "soter: init_sign uid={uid} alias={alias} returned {}; rebuilding the slot \
         (ask_missing={ask_missing} auth_missing={auth_missing})",
        original.error_code
    );
    if ask_missing {
        match soter.generate_ask_key_pair(uid) {
            Ok(0) => {}
            Ok(code) => {
                log::warn!(
                    "soter: rebuild ASK for uid={uid} returned {code}; keeping the original error"
                );
                return original;
            }
            Err(e) => {
                log::warn!(
                    "soter: rebuild ASK for uid={uid} failed: {e:#}; keeping the original error"
                );
                return original;
            }
        }
    }
    if auth_missing {
        match soter.generate_auth_key_pair(uid, alias) {
            Ok(0) => {}
            Ok(code) => {
                log::warn!(
                    "soter: rebuild AuthKey uid={uid} alias={alias} returned {code}; keeping the original error"
                );
                return original;
            }
            Err(e) => {
                log::warn!(
                    "soter: rebuild AuthKey uid={uid} alias={alias} failed: {e:#}; keeping the original error"
                );
                return original;
            }
        }
    }
    match soter.init_sign(uid, alias, challenge) {
        Ok(session) => {
            log::info!(
                "soter: rebuilt slot uid={uid} alias={alias}; init_sign now returns {}",
                session.error_code
            );
            session
        }
        Err(e) => {
            log::warn!("soter: init_sign retry after rebuild failed: {e:#}");
            original
        }
    }
}

/// Handle one `soter` task payload.
///
/// `allow_mutation` comes from the relay config; it gates the ops that create
/// or delete keys. `max_concurrent` likewise comes from the live config and is
/// the ceiling on how many SOTER HAL calls may be in flight at once (see
/// [`SOTER_HAL_QUEUE`]); the same uid is always serialised.
pub fn handle(payload: &Value, allow_mutation: bool, max_concurrent: u32) -> Result<Value> {
    let op = payload
        .get("op")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("probe");
    if !KNOWN_OPS.contains(&op) {
        bail!("unknown soter op: {op}");
    }
    if MUTATING_OPS.contains(&op) && !allow_mutation {
        // 别 `bail`：任务失败在链路上会被当成「这台设备没这把钥匙」（外层只看到 -5）。
        // 按正常答复递一个 -5（跟真缺料同码，A 端行为不变），另加一个只有服务端看得懂的
        // 标记，让它能和真缺料区分开；本机也留一条 WARN。
        log::warn!(
            "soter: op '{op}' 被建料闸门拦下（relay.conf 里没开 \
             OMMEGA_RELAY_SOTER_MUTATION）：这台接不了建料/删料，A 端会一直拿到\
             「没料」的 -5 在原地重建"
        );
        return Ok(json!({
            "op": op,
            "error_code": SOTER_ASK_NOT_READY_CODE,
            "soter_mutation_disabled": true,
        }));
    }
    if op == "selftest" {
        // 自检不碰 HAL，不占名额。
        return Ok(fixtures::selftest());
    }
    // 有上限地并行：全局不超过 max，同一个 uid 串行；uid 没给就只吃全局名额。
    // 这里的 uid 只用于排队，各 arm 里还会再解析一次（坏 payload 该报错就报错）。
    let _gate = SoterHalGate::enter(uid_of(payload).ok(), Some(max_concurrent));
    if op == "probe" {
        return Ok(probe());
    }

    // 材料重建的几个 op 顺手把「这批材料能签吗」重新量一次。
    if let Ok(uid) = uid_of(payload) {
        let _ = uid;
        if SLOT_REBUILD_OPS.contains(&op) {
            clear_sign_state();
        }
    }

    // 参数先取、HAL 后开：请求本身缺参数的话就别去碰 HAL。不然「服务没起」或者
    // SELinux 拦下来这种错误会盖掉「你 uid 没给」这种更该先说的话。
    let result: Result<Value> = match op {
        "get_device_id" => Ok(data_result(op, open_soter(op)?.get_device_id()?)),
        "export_attk_public_key" => Ok(data_result(op, open_soter(op)?.export_attk_public_key()?)),
        "export_ask_public_key" => {
            let uid = uid_of(payload)?;
            Ok(ask_result(op, open_soter(op)?.export_ask_public_key(uid)?))
        }
        "export_auth_key_public_key" => {
            let (uid, alias) = (uid_of(payload)?, alias_of(payload)?);
            Ok(data_result(
                op,
                open_soter(op)?.export_auth_key_public_key(uid, &alias)?,
            ))
        }
        "finish_sign" => {
            let session = session_of(payload)?;
            let mut guard = SIGN_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            if !guard.finish_allowed(session, now) {
                return Ok(code_result(op, -204));
            }
            guard.activity(now);
            // End the matching lease even on transport/open failure. A stale
            // finish must never clear a newer session's lease.
            let data = open_soter(op).and_then(|soter| soter.finish_sign(session));
            guard.finish_ended(session, Instant::now());
            let data = data?;
            // 真替上层签出来是「这台能签」的唯一硬证据；别的码（-26 这一笔没验过、
            // -204 会话被顶掉）都是「这笔没成」，不参与能力结论。
            note_sign_result(data.error_code as i64);
            Ok(data_result(op, data))
        }
        "init_sign" => {
            let (uid, alias, challenge) = (
                uid_of(payload)?,
                alias_of(payload)?,
                string_arg(payload, "challenge")?,
            );
            let mut guard = SIGN_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            // 抢不到租约不拒：回 -9 会让 App 连指纹圈都弹不出来。让它去顶掉旧会话，
            // 被顶掉的那笔在 finish 上吃 -204，由服务端补签收尾；租约只用来挡探针
            // （`probe_allowed`）。
            guard.activity(now);
            let soter = open_soter(op)?;
            let mut session = soter.init_sign(uid, &alias, &challenge)?;
            // 这台机器上没有这批材料：原地补齐再签一次。只对「没料」的三个码重建：
            // -5（ASK 未就绪）/ -6（AuthKey 未就绪）/ -65528。-18（安全通道不通）、
            // -8 这类是 TA 的结构性问题，重建没用，还会把真钥匙重铸掉。
            if matches!(
                session.error_code,
                SOTER_ASK_NOT_READY_CODE
                    | SOTER_AUTH_KEY_NOT_READY_CODE
                    | SOTER_ITEM_NOT_FOUND_CODE
            ) && allow_mutation
            {
                session = rebuild_material_then_sign(&soter, uid, &alias, &challenge, session);
            }
            if session.error_code == 0 {
                guard.init_succeeded(session.session, Instant::now());
                // 只是建了会话，还没签出东西来：能签的证据不在这；不过槽位记住了，
                // 探针以后可以拿它去试签。
                remember_probe_target(uid, &alias);
            } else {
                // TA 连会话都不给建（-26 = 这一笔的验证没过去）：记一笔，但不参与结论。
                note_sign_result(session.error_code as i64);
            }
            Ok(json!({
                "op": op,
                "error_code": session.error_code,
                "session": session.session,
            }))
        }
        "has_ask_already" => {
            let uid = uid_of(payload)?;
            Ok(code_result(op, open_soter(op)?.has_ask_already(uid)?))
        }
        "has_auth_key" => {
            let (uid, alias) = (uid_of(payload)?, alias_of(payload)?);
            let result = code_result(op, open_soter(op)?.has_auth_key(uid, &alias)?);
            // 0 = 这个槽位有材料：除了 init_sign，这里也能学到一个能拿去试签的槽位。
            if result.get("error_code").and_then(Value::as_i64) == Some(0) {
                remember_probe_target(uid, &alias);
            }
            Ok(result)
        }
        "verify_attk_key_pair" => Ok(code_result(op, open_soter(op)?.verify_attk_key_pair()?)),
        "generate_ask_key_pair" => {
            let uid = uid_of(payload)?;
            Ok(code_result(op, open_soter(op)?.generate_ask_key_pair(uid)?))
        }
        "generate_attk_key_pair" => {
            let user_id = user_id_of(payload)?;
            Ok(code_result(
                op,
                open_soter(op)?.generate_attk_key_pair(user_id)?,
            ))
        }
        "generate_auth_key_pair" => {
            let (uid, alias) = (uid_of(payload)?, alias_of(payload)?);
            Ok(code_result(
                op,
                open_soter(op)?.generate_auth_key_pair(uid, &alias)?,
            ))
        }
        "remove_all_uid_key" => {
            let uid = uid_of(payload)?;
            Ok(code_result(op, open_soter(op)?.remove_all_uid_key(uid)?))
        }
        "remove_auth_key" => {
            let (uid, alias) = (uid_of(payload)?, alias_of(payload)?);
            Ok(code_result(
                op,
                open_soter(op)?.remove_auth_key(uid, &alias)?,
            ))
        }
        other => bail!("unknown soter op: {other}"),
    };
    let result = result?;

    // 设备层不替服务端下结论：`-26` 是 TA 对「这一笔」的答复，原样递上去。换不换层、
    // 要不要把某个槽位钉到服务端自签那两层，由服务端看错误码性质定（见
    // `is_hard_slot_failure`）。
    let _ = is_hard_slot_failure(op, &result);

    // 顺手把这笔的结果喂给 HAL 自愈：连着两笔真失败（-5/-6/-26 这几个正常答复除外）
    // 就重启一次那个服务，否则卡成「建料类 op 全正常、只有签名恒 -18」时，服务端会把
    // 它当「结构性做不了」把槽位换到自签那两层。见 `hal_restart`。
    hal_restart::note(
        op,
        result
            .get("error_code")
            .and_then(Value::as_i64)
            .unwrap_or(0),
    );

    Ok(result)
}

/// 打开 SOTER HAL；这台机器没有就明确说没有。
fn open_soter(op: &str) -> Result<Soter> {
    Soter::open()?.ok_or_else(|| {
        anyhow!(
            "this device has no SOTER HAL ({} / {}), cannot forward '{op}'",
            hal::SERVICE,
            hal::QTI_SERVICE
        )
    })
}

/// 探针签名用的挑战值（十六进制字符串，跟 A 端传下来的形状一样）。
const PROBE_CHALLENGE: &str = "00112233445566778899aabbccddeeff";

/// 真去签一次：拿一个现成的槽位走 `init_sign` + `finish_sign`，能力上报用。
///
/// `getDeviceId` 只能证明 HAL 活着，失败码也证明不了「不肯签」（-26 是这一笔没验过），
/// 所以「能不能签」只能真签一次量出来，而且只有签出来这一种结论。只用槽位上现成的
/// 材料，不建不删：槽位没材料（-5 / -6）时结论是「没量出来」，不能当「签不了」上报。
///
/// 结论写在 `verdict` 里（见 [`SignVerdict`]），`signed` 只为看日志方便。
/// 不走 Err：探针失败也得把原因带回去写进日志。
pub fn sign_probe(uid: i32, alias: &str) -> Value {
    // 探针也是真的去 init/finish，跟派下来的活一样得排队（上限走全局那个值）。
    let _gate = SoterHalGate::enter(Some(uid), None);
    let mut out = json!({ "op": "sign_probe", "uid": uid, "alias": alias });
    // Check and reserve under the real signing lock; callers cannot init
    // between this check and the probe's finish. Do not call handle() here:
    // it takes the same non-reentrant mutex.
    let mut guard = SIGN_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    if !guard.probe_allowed(Instant::now()) {
        out["skipped"] = json!(true);
        out["reason"] = json!("active signing session or recent signing activity");
        out["verdict"] = json!(SignVerdict::Unknown.as_str());
        out["signed"] = json!(false);
        return out;
    }
    let soter = match Soter::open() {
        Ok(Some(soter)) => soter,
        Ok(None) => {
            out["error"] = json!("this device has no SOTER HAL");
            out["verdict"] = json!(SignVerdict::Unknown.as_str());
            out["signed"] = json!(false);
            return out;
        }
        Err(e) => {
            out["error"] = json!(format!("{e:#}"));
            out["verdict"] = json!(SignVerdict::Unknown.as_str());
            out["signed"] = json!(false);
            return out;
        }
    };
    let session = match soter.init_sign(uid, alias, PROBE_CHALLENGE) {
        Ok(session) => session,
        Err(e) => {
            out["error"] = json!(format!("{e:#}"));
            out["verdict"] = json!(SignVerdict::Unknown.as_str());
            out["signed"] = json!(false);
            return out;
        }
    };
    out["init_sign"] = json!(session.error_code);
    if session.error_code != 0 {
        // -5 / -6：槽位上没有 ASK / AuthKey。-26：TA 连签名会话都不给建。
        let verdict = SignVerdict::from_code(session.error_code as i64);
        out["verdict"] = json!(verdict.as_str());
        out["signed"] = json!(false);
        return out;
    }
    match soter.finish_sign(session.session) {
        Ok(data) => {
            out["finish_sign"] = json!(data.error_code);
            let verdict = SignVerdict::from_code(data.error_code as i64);
            if verdict == SignVerdict::Signed {
                mark_sign_proven();
            }
            out["verdict"] = json!(verdict.as_str());
            out["signed"] = json!(data.error_code == 0);
        }
        Err(e) => {
            out["error"] = json!(format!("{e:#}"));
            out["verdict"] = json!(SignVerdict::Unknown.as_str());
            out["signed"] = json!(false);
        }
    }
    out
}

/// 这台机器有没有 SOTER HAL —— 心跳能力上报用的。
///
/// 与 [`probe`] 的区别：`probe` 会真的调一次 HAL（能证明它确实能用，但有开销），
/// 这里只问 servicemanager，适合每 20 秒一次的心跳。
pub fn service_present() -> bool {
    hal::Soter::service_present()
}

/// Capability probe: can this device serve SOTER at all?
///
/// Unlike the other ops this never fails: `supported` is `false` when the HAL
/// is missing or cannot answer, with the reason attached.
pub fn probe() -> Value {
    // 能力探针也走一遍排队（上限走全局那个值）。
    let _gate = SoterHalGate::enter(None, None);
    match Soter::open() {
        Ok(Some(soter)) => {
            let mut out = json!({
                "op": "probe",
                "backend": soter.backend().label(),
                "service": soter.backend().service(),
                "interface": soter.backend().interface(),
                "version": soter.interface_version().ok(),
            });
            // A device id read proves the HAL actually serves requests; a
            // registered-but-broken service must not be advertised as usable.
            match soter.get_device_id() {
                Ok(device) if device.error_code == 0 => {
                    out["supported"] = json!(true);
                    out["error_code"] = json!(device.error_code);
                    out["device_id"] = json!(device.text().unwrap_or_default());
                }
                Ok(device) => {
                    out["supported"] = json!(false);
                    out["error_code"] = json!(device.error_code);
                    out["reason"] = json!("getDeviceId returned a SOTER error code");
                }
                Err(e) => {
                    out["supported"] = json!(false);
                    out["reason"] = json!(format!("{e:#}"));
                }
            }
            out
        }
        Ok(None) => json!({
            "op": "probe",
            "supported": false,
            "service": hal::SERVICE,
            "reason": "service is not registered with the service manager",
        }),
        Err(e) => json!({
            "op": "probe",
            "supported": false,
            "service": hal::SERVICE,
            "reason": format!("{e:#}"),
        }),
    }
}

// ---------------------------------------------------------------------------
// Result shaping.
// ---------------------------------------------------------------------------

/// Base shape for the data-carrying ops: error code, payload, and the payload
/// as text when it is printable (PEM / device id), since callers usually want
/// that directly.
fn data_result(op: &str, data: SoterData) -> Value {
    let mut out = json!({
        "op": op,
        "error_code": data.error_code,
        "length": data.length,
        "data": base64::engine::general_purpose::STANDARD.encode(&data.data),
    });
    if let Some(text) = data.text() {
        out["text"] = json!(text);
    }
    out
}

/// `exportAskPublicKey` answers with `[i32 json length][json][TEE signature]`;
/// split it so callers do not have to know that.
fn ask_result(op: &str, data: SoterData) -> Value {
    let mut out = data_result(op, data.clone());
    if data.error_code == 0 {
        if let Ok((doc, signature)) = fixtures::split_ask_payload(&data.data) {
            out["json_bytes"] = json!(doc.len());
            out["signature"] = json!(base64::engine::general_purpose::STANDARD.encode(signature));
            if let Ok(parsed) = serde_json::from_slice::<Value>(doc) {
                out["payload"] = parsed;
            }
        }
    }
    out
}

/// Shape for the ops that return a bare SOTER error code (0 = success; for the
/// `has_*` ops 0 means "present", -5 means "absent").
fn code_result(op: &str, error_code: i32) -> Value {
    json!({ "op": op, "error_code": error_code })
}

// ---------------------------------------------------------------------------
// Payload arguments.
// ---------------------------------------------------------------------------

fn uid_of(payload: &Value) -> Result<i32> {
    int_arg(payload, "uid").context("soter payload needs the owning Android app uid")
}

fn user_id_of(payload: &Value) -> Result<i8> {
    let value = int_arg(payload, "user_id")?;
    i8::try_from(value).map_err(|_| anyhow!("'user_id' must fit in a signed byte, got {value}"))
}

fn session_of(payload: &Value) -> Result<i64> {
    long_arg(payload, "session").context("soter payload needs the session handle from init_sign")
}

fn alias_of(payload: &Value) -> Result<String> {
    string_arg(payload, "alias").context("soter payload needs the key 'alias'")
}

/// Accept an integer or a numeric string (the A-side stores uids as strings).
fn int_arg(payload: &Value, key: &str) -> Result<i32> {
    let value = payload.get(key).ok_or_else(|| anyhow!("missing '{key}'"))?;
    if let Some(number) = value.as_i64() {
        return i32::try_from(number).map_err(|_| anyhow!("'{key}' is out of range: {number}"));
    }
    if let Some(text) = value.as_str() {
        return text
            .trim()
            .parse::<i32>()
            .map_err(|_| anyhow!("'{key}' is not an integer: {text:?}"));
    }
    bail!("'{key}' must be an integer or a numeric string")
}

fn long_arg(payload: &Value, key: &str) -> Result<i64> {
    let value = payload.get(key).ok_or_else(|| anyhow!("missing '{key}'"))?;
    if let Some(number) = value.as_i64() {
        return Ok(number);
    }
    if let Some(text) = value.as_str() {
        return text
            .trim()
            .parse::<i64>()
            .map_err(|_| anyhow!("'{key}' is not an integer: {text:?}"));
    }
    bail!("'{key}' must be an integer or a numeric string")
}

fn string_arg(payload: &Value, key: &str) -> Result<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("missing string '{key}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_op_is_rejected() {
        let err = handle(&json!({ "op": "nope" }), true, 2).expect_err("must reject");
        assert!(format!("{err:#}").contains("unknown soter op"));
    }

    /// 建料闸门关着时不能报错退出（那会被当成「这台没料」的 -5 混进链路），
    /// 要按正常答复递一个带标记的 -5，让服务端能把这笔和真缺料区分开；
    /// 而且一个字节的 HAL 都不许碰（uid 故意给个不存在的也无所谓）。
    #[test]
    fn mutating_ops_need_the_opt_in() {
        let payload = json!({ "op": "generate_ask_key_pair", "uid": 10373 });
        let reply = handle(&payload, false, 2).expect("闸门关着也要给答复，不是报错");
        assert_eq!(reply["error_code"], json!(-5));
        assert_eq!(reply["soter_mutation_disabled"], json!(true));
        assert_eq!(reply["op"], json!("generate_ask_key_pair"));
    }

    #[test]
    fn missing_uid_is_reported_before_any_hal_call() {
        crate::init_binder();
        let err =
            handle(&json!({ "op": "export_ask_public_key" }), false, 2).expect_err("must fail");
        assert!(format!("{err:#}").contains("uid"), "err: {err:#}");
    }

    #[test]
    fn numeric_strings_are_accepted_for_uids() {
        assert_eq!(int_arg(&json!({ "uid": "10373" }), "uid").unwrap(), 10373);
        assert_eq!(int_arg(&json!({ "uid": 10373 }), "uid").unwrap(), 10373);
    }

    #[test]
    fn user_id_must_fit_in_a_byte() {
        assert_eq!(user_id_of(&json!({ "user_id": 1 })).unwrap(), 1);
        assert!(user_id_of(&json!({ "user_id": 300 })).is_err());
    }

    #[test]
    fn a_sign_failure_does_not_take_the_slot_off_this_device() {
        // 回包必须是 TA 自己的答复，不能带我们编的 error；真有 HAL 的机器上要先进 binder，
        // 不然 rsbinder 会 panic（`ProcessState is not initialized!`）。
        crate::init_binder();
        let uid = 900001;
        let payload = json!({ "op": "has_auth_key", "uid": uid, "alias": "whatever" });
        let text = match handle(&payload, true, 2) {
            Err(e) => format!("{e:#}"),
            Ok(v) => {
                assert!(
                    v.get("error_code").is_some(),
                    "HAL 在的时候回包要带上它自己的 error_code: {v}"
                );
                String::new()
            }
        };
        assert!(!text.contains("not served by this device"), "err: {text}");
    }

    #[test]
    fn a_verification_failure_is_never_a_hard_sign_failure() {
        // -26 只是「这笔没签成」，材料没毛病：本机不替服务端判「这层做不了」。
        for op in ["finish_sign", "init_sign", "has_auth_key", "get_device_id"] {
            for code in [-26, 0, -5, -6, -7, -9, -1000] {
                assert!(
                    !is_hard_slot_failure(op, &json!({ "error_code": code })),
                    "{op} {code} must stay the device's own answer"
                );
            }
        }
    }

    /// 只有「真签出来」算证据：失败码再多也不许变成「这台签不了」。
    ///
    /// `-26`（这一笔没验过）、`-204`（会话被顶掉）、超时都只是「这笔没成」。
    #[test]
    fn only_a_real_signature_is_capability_evidence() {
        clear_sign_state();
        assert_eq!(sign_state(), SignState::Unknown);

        for code in [-26i64, -26, -26, -26, -26] {
            note_sign_result(code);
            assert_eq!(sign_state(), SignState::Unknown, "{code} 不该当证据");
        }
        for code in [-5i64, -6, -7, -9, -204, -1000] {
            note_sign_result(code);
            assert_eq!(sign_state(), SignState::Unknown, "{code} 不该当证据");
        }

        // 真签出来过一次就是结论，之后再怎么失败也不翻。
        note_sign_result(0);
        assert_eq!(sign_state(), SignState::Proven);
        for _ in 0..5 {
            note_sign_result(-26);
        }
        assert_eq!(sign_state(), SignState::Proven);
        clear_sign_state();
    }

    #[test]
    fn rebuilding_the_slot_clears_the_verdict() {
        for op in SLOT_REBUILD_OPS {
            assert!(
                MUTATING_OPS.contains(op),
                "{op} must stay behind the opt-in"
            );
        }
        // 重建之后「能不能签」重新量：先把结论做成 Proven，再清。
        note_sign_result(0);
        assert_eq!(sign_state(), SignState::Proven);
        clear_sign_state();
        assert_eq!(sign_state(), SignState::Unknown);
    }

    #[test]
    fn selftest_op_does_not_touch_the_device() {
        let report = handle(&json!({ "op": "selftest" }), false, 2).expect("selftest must run");
        assert_eq!(report["ok"], json!(true), "report: {report}");
    }

    // ---- SOTER 进 HAL 的排队：全局有上限 + 同 uid 串行（见 `HalQueue`）----

    /// 一条用例一张自己的队列：测试是并行跑的，共用全局那张的话 `total` 互相打架，
    /// 断言就变成碰运气了。
    fn fresh_queue() -> &'static HalQueue {
        Box::leak(Box::new(HalQueue::new()))
    }

    #[test]
    fn a_gate_takes_exactly_one_slot_and_gives_it_back() {
        let q = fresh_queue();
        let uid = 40021;
        {
            let _g = q.enter(Some(uid), Some(4));
            let st = q.lock();
            assert_eq!(st.per_uid.get(&uid).copied(), Some(1), "本线程占 1 个名额");
            assert_eq!(st.total, 1);
        }
        let st = q.lock();
        assert_eq!(st.per_uid.get(&uid), None, "出作用域要还回去");
        assert_eq!(st.total, 0, "全局名额也要还");
    }

    #[test]
    fn a_gate_without_a_uid_still_gives_the_slot_back() {
        // 探针那条路不指名 uid。这种门也必须还名额：漏够 max 个之后所有 SOTER
        // 操作全都卡在等名额上，真机上的表现就是「卡死」而不是报错。
        let q = fresh_queue();
        {
            let _g = q.enter(None, Some(1));
            assert_eq!(q.lock().total, 1, "没 uid 也要占全局名额");
        }
        assert_eq!(q.lock().total, 0, "没 uid 的名额也得还");
        // 而且第二笔还得能进去（漏名额的话这里超时失败，不是挂死）
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _g = q.enter(None, Some(1));
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("名额还回来了就该能再进");
    }

    #[test]
    fn nested_enters_are_free_and_only_the_outermost_releases() {
        let q = fresh_queue();
        let outer = q.enter(Some(40001), Some(4));
        // `handle()` 里会调 `probe()`：同线程重入时不能再去要一个名额，否则
        // 一个 uid 一笔就把自己堵死。重入那次连名额都不记（算在外层头上）。
        let inner_a = q.enter(Some(40002), Some(4));
        let inner_b = q.enter(Some(40002), Some(4));
        {
            let st = q.lock();
            assert_eq!(st.per_uid.get(&40001).copied(), Some(1));
            assert_eq!(st.per_uid.get(&40002), None, "重入不该占名额");
            assert_eq!(st.total, 1, "重入也不该多占全局名额");
        }
        drop(inner_a);
        drop(inner_b);
        {
            let st = q.lock();
            assert_eq!(
                st.per_uid.get(&40001).copied(),
                Some(1),
                "内层退出不该把外层还掉"
            );
        }
        drop(outer);
        assert_eq!(q.lock().per_uid.get(&40001), None);
        assert_eq!(q.lock().total, 0);
    }

    #[test]
    fn another_thread_on_the_same_uid_waits_for_the_slot() {
        // 用 recv_timeout 而不是 join：万一以后真的写坏了，这里是失败而不是挂死。
        let q = fresh_queue();
        let uid = 40011;
        let held = q.enter(Some(uid), Some(4));
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let _g = q.enter(Some(uid), Some(4));
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "同一个 uid 上第二笔得等第一笔走完"
        );
        drop(held);
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("名额放掉之后第二笔要能进");
        t.join().unwrap();
        assert_eq!(q.lock().total, 0, "两笔都出完要归零");
    }

    #[test]
    fn a_different_uid_does_not_wait_for_the_one_held() {
        let q = fresh_queue();
        let held = q.enter(Some(40031), Some(2));
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            // 上限 2：另一个 uid 该直接进。
            let _g = q.enter(Some(40032), Some(2));
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("另一个 uid 不该被挡住");
        drop(held);
        t.join().unwrap();
    }
}
