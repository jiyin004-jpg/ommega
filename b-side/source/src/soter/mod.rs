//! SOTER forwarding for the B-side relay agent.
//!
//! SOTER is the Trustonic "secure keystore" HAL that Tencent (WeChat / QQ)
//! and Alipay use for app signing keys: the private keys live in the TEE and
//! the HAL exposes "create / export public key / sign / delete" operations for
//! them.  The A-side asks the relay for an operation with a task payload, we
//! run it against the *real* HAL on the B-side phone, and the answer goes back
//! as JSON — the same shape as the existing `attest` / `sign` / `decrypt`
//! forwarding.
//!
//! Task payload:
//!
//! ```json
//! { "op": "export_attk_public_key" }
//! { "op": "export_ask_public_key", "uid": 10373 }
//! { "op": "init_sign", "uid": 10373, "alias": "SoterAuthKey", "challenge": "..." }
//! ```
//!
//! `op` defaults to `probe`, which only reports whether this device can serve
//! SOTER at all (so the caller can decide to fall back).  Every other op fails
//! with a descriptive error when the HAL is missing, which is how the existing
//! forwarding path signals "this backing device cannot do that".
//!
//! The ops that create or remove keys change real device state (they touch the
//! payment-key store), so they stay disabled unless the operator opts in via
//! `OMMEGA_RELAY_SOTER_MUTATION=1` in `relay.conf`.
//!
//! See [`hal`] for the wire format (it is hand-marshalled and verified against
//! captured replies, see [`fixtures`]).

pub mod fixtures;
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

/// 这些 op 把槽位的材料换掉了，之后「这批材料能不能签」得重新量（服务端那边
/// ASK 重建也会把槽位的层钉清掉，这里对齐）。
const SLOT_REBUILD_OPS: &[&str] = &[
    "generate_ask_key_pair",
    "remove_all_uid_key",
    "remove_auth_key",
];

/// SOTER_ERROR_VERIFICATION_FAILED。TA 说这份材料验不过 —— 不是「还没建好」。
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
/// 只有 [`SignVerdict::Unavailable`] 算「这台现在签不了」的硬证据（SOTER 没开、
/// ATTK 没配、安全通道不通这类结构性毛病）。`-26` 不算：那是「这一刻没人按指纹」，
/// 不是「这台签不了」—— 自己人的手机上量到过同一台设备指纹窗口开着时签得出来、
/// 关着时回 -26。把 -26 当成签不了上报，服务端会把一台明明能签的机器从签名链路
/// 上踢掉（之前那个假阴性就是这么来的）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignVerdict {
    /// 真签出来了一次。
    Signed,
    /// 槽位有料，TA 说必须刚匹配过指纹（-26）：这次没签成，但这台能不能签还得再看。
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

/// 最近一次「真拿这个槽位发起了签名」的 (uid, alias)，给能力探针当目标用。
///
/// 只放内存：要落盘得先问用户，而重启后重新学一次就够了 —— 没上报能力的设备
/// 服务端照样会派活。
static LEARNED_PROBE_TARGET: Mutex<Option<(i32, String)>> = Mutex::new(None);

/// Serializes real signing HAL calls with the entire probe. The same mutex
/// atomically checks/reserves probe access and protects the in-memory lease.
/// Never held while waiting for a caller's finish or during HAL restart.
static SIGN_GUARD: Mutex<sign_guard::SignGuard> = Mutex::new(sign_guard::SignGuard::new());

/// SOTER 进 HAL 的排队：全局有上限 + 同一个 uid 串行。
///
/// 2026-10-03 在 PLC110 上实测：Trustonic 的 `tlTeeSOTER`（TA 镜像
/// `/odm/vendor/app/mcRegistry/070f0000000000000000000000000a0a.tlbin`）把 RPMB
/// session 3 打开之后不释放，之后每一次 `EXPORT_PUB_KEY` 都开不了会话 —— 驱动
/// 日志 `rpmb session 3 is already opened by 070f0000-...-a0a0` 449/449 全是它
/// 自己，`Open session failed crSession = 0xffffffff` 452 次，
/// `read counter failed (258)` 451 次。TA 从此读不到自己的持久存储，于是
/// `export_*` / `generate_*` 一律回 -5，而 `has_*` 照旧回 0（它不走 RPMB）——
/// 对外就是「说存在、却导不出来、也建不了」。踢 Android 侧的 HAL 服务没用
/// （持有者在 TEE 里），只有重启整机能松开。
///
/// 所以这里不是「放开并发」，是**有上限的并行**，两条规矩：
///
///   1. 全局同时在飞不超过 `max`（`relay.conf` 的 `soter_concurrency`，默认 2）。
///      RPMB 会话是独占资源，我们自己占得越少，机器自己那条路（系统 / 微信在真机上
///      直接调 TA）就越有空位 —— 留出来的那点空间是给它的，不是给我们堆吞吐的。
///   2. 同一个 uid 严格串行。一个 uid 上的 export / rebuild / 签名 互相插队，正是把
///      槽位搅成半成品、再喂给 TA 一堆 -5 的来路；不同 uid 之间才并行。
///
/// 真撞上那个楔子也不慌：`hal_restart` 里有「连续 258 → 自动重启」兜底。
/// KeyMint / attest 那条路不经过这里，照旧并发。
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
/// 排队超过这么久就记一笔（线上 `wait` 的 p99 就是这么数出来的）。
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
    /// 占了名额的那个 uid。重入进来的那次是 None（名额记在最外层那笔上）。
    uid: Option<i32>,
}

impl SoterHalGate {
    /// `uid` 为 `None` 表示这笔请求没指名 uid（探针那种），只吃全局名额。
    /// `max` 为 `None` 就读全局那个（探针那条路），传值的是手里有实时配置的那条路。
    fn enter(uid: Option<i32>, max: Option<u32>) -> Self {
        let depth = SOTER_HAL_DEPTH.with(|d| d.get());
        if depth > 0 {
            // 同线程重入：名额已经在外层拿着了，这里只记深度。
            SOTER_HAL_DEPTH.with(|d| d.set(depth + 1));
            return Self { uid: None };
        }
        let queue = hal_queue();
        let max = max
            .unwrap_or_else(max_concurrency)
            .clamp(SOTER_CONCURRENCY_MIN, SOTER_CONCURRENCY_MAX);
        let started = Instant::now();
        {
            let mut st = queue.lock();
            st.max = max;
            while st.total >= max
                || uid.is_some_and(|u| st.per_uid.get(&u).copied().unwrap_or(0) > 0)
            {
                st = queue
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
        Self { uid }
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
        let Some(uid) = self.uid else {
            return;
        };
        let queue = hal_queue();
        let mut st = queue.lock();
        st.total = st.total.saturating_sub(1);
        if let Some(n) = st.per_uid.get_mut(&uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.per_uid.remove(&uid);
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

/// 连续几次真派下来的签名 op 都被 -26 顶回来（TA 说“没有新鲜指纹”），就认这台
/// 不接签名。只用**真活**计数，不用探针：探针撞上指纹窗口关着只是「这次没量
/// 出来」，拿它当证据会把一台明明能签的机器踢出签名链路（PLC110 上真踩过）。
const SIGN_REFUSAL_LIMIT: u32 = 3;

/// 这台机器签名到底行不行。三个值对应上报给服务端的三件事。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignState {
    /// 真签出来过（真实 op 或探针）：报 `soter_sign`。
    Proven,
    /// 连续几次真签名 op 都被 -26 顶回来：报 `soter_nosign`，服务端不再把签名
    /// op 派过来。材料重建后会清掉，重新学。
    Refused,
    /// 还没量出来：什么都不报，服务端照旧会试。
    Unknown,
}

static SIGN_STATE: Mutex<SignState> = Mutex::new(SignState::Unknown);
/// 连续 -26 次数（碰上一次成功就清零）。
static SIGN_REFUSALS: Mutex<u32> = Mutex::new(0);

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
    *SIGN_REFUSALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = 0;
}

/// 一个真签名 op 的结果。`-26` 累加，够了就改口说签不了；成功就把之前那条
/// 否定的结论推翻（真签出来过比什么都硬）。
fn note_sign_result(error_code: i64) {
    if error_code == 0 {
        mark_sign_proven();
        return;
    }
    if error_code != SOTER_VERIFICATION_FAILED {
        return;
    }
    // 已经签出来过的机器，不会因为「这会儿没人按指纹」被改口 —— 它明明能签，
    // 服务端该继续把签名 op 派过来，人回来按一下就成。
    if sign_state() == SignState::Proven {
        return;
    }
    let mut refusals = SIGN_REFUSALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *refusals += 1;
    let count = *refusals;
    drop(refusals);
    if count < SIGN_REFUSAL_LIMIT {
        return;
    }
    let mut state = SIGN_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *state != SignState::Refused {
        log::warn!(
            "soter: {count} sign ops in a row came back -26 (no fresh fingerprint); \
             reporting this device as unable to sign"
        );
        *state = SignState::Refused;
    }
}

/// 槽位被重建 / 删掉：之前那条结论跟着作废（材料换了，能不能签得重新量）。
pub fn clear_sign_state() {
    let mut state = SIGN_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *state = SignState::Unknown;
    *SIGN_REFUSALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = 0;
}

/// `init_sign` 回了 0 说明这个槽位真有材料，记下来给探针用（探针只用现成材料，
/// 不建不删）。没这一步，没配探针目标的机器只能一直“量不出来”。
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

/// -26 落在签名步骤上，是「这一笔没签成」——TA 要的是当下那一刻的新鲜指纹。
///
/// 以前这里把它当「这份材料签不了」，记下 uid、24 小时内不再服务这个槽位。那是个
/// 误判：指纹随时可以按，材料本身没毛病，而“拒绝服务”只能把 App 推给服务端那两层
/// 自签的假料（PLC110 上就这么让一轮支付流程拿了一整套假材料）。现在一律把 TA 的
/// 答复原样递上去（`-26` 也就是 App 自己那套 `SOTER_ERR_NO_FINGERPRINT`），要不要
/// 换层由服务端按错误码的性质决定，本机不再替它下结论。
fn is_hard_slot_failure(op: &str, result: &Value) -> bool {
    let _ = (op, result);
    false
}

/// `-5` / `-6`：TA 说这个槽位上的 ASK / AuthKey 没就绪 —— 这两码才值得原地重建。
/// 别的非零码（-18 安全通道、-8、-26 没指纹）都是另一回事，动设备状态只会更糟。
///
/// `-65528`（`TEE_ERROR_ITEM_NOT_FOUND`）2026-10-02 补进来：在 PLC110 上拿一个
/// 全新 alias 打 `init_sign` 就是这个码，意思是「这台机器上没有这号材料」，
/// 和 -5/-6 同一种缺料，一样该就地补齐再试。
const SOTER_ASK_NOT_READY_CODE: i32 = -5;
const SOTER_AUTH_KEY_NOT_READY_CODE: i32 = -6;
const SOTER_ITEM_NOT_FOUND_CODE: i32 = -65528;

/// 「B 端手上没这批材料」就地补齐再重试签名。
///
/// 只在 mutation 开关打开时调用。先问 HAL 到底缺哪一样（ASK / AuthKey），缺什么铸
/// 什么，然后重新建一次签名会话；补齐失败就把原始错误原样递上去 —— 宁可让上层
/// 看到「这台真没有」，也绝不假装签成功。
fn rebuild_material_then_sign(
    soter: &Soter,
    uid: i32,
    alias: &str,
    challenge: &str,
    original: SoterSession,
) -> SoterSession {
    // 探 HAL 的返回码：0 = 有材料，非 0（-5 / -6）= 缺。探不动（HAL 报错）就当
    // "不缺"，免得在别的问题上乱改设备状态。
    let ask_missing = soter.has_ask_already(uid).map(|c| c != 0).unwrap_or(false);
    let auth_missing = soter
        .has_auth_key(uid, alias)
        .map(|c| c != 0)
        .unwrap_or(false);
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
        bail!(
            "soter op '{op}' creates or removes keys on the device and is disabled; \
             set OMMEGA_RELAY_SOTER_MUTATION=1 in relay.conf to allow it"
        );
    }
    if op == "selftest" {
        // 自检不碰 HAL，不占名额。
        return Ok(fixtures::selftest());
    }
    // 有上限地并行：全局不超过 max，同一个 uid 串行。uid 没给（探针那种）就只吃
    // 全局名额。注：这个 `uid` 只是拿来排队的，真正要用的那两处 arm 里各自还会
    // 再解析一次（坏 payload 该报错就报错，不在这里默默当没给）。
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
            // 真替上层签出来就是一整条链路的成功证据；回 -26 就是「没人按指纹」的
            // 一次实测，都交给同一个判定函数累。
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
            if !guard.init_allowed(now) {
                return Ok(code_result(op, -9));
            }
            guard.activity(now);
            let soter = open_soter(op)?;
            let mut session = soter.init_sign(uid, &alias, &challenge)?;
            // 这台机器上没有这批材料：就地在原地补齐再签一次。
            //
            // 背景（PLC110 2026-09-30 实测）：A 端 App 的 AuthKey/SoterAuthKey 是
            // 在 A 端本地建的，B 端手上不一定有，TA 会回 -5（ASK 没就绪）/ -6
            // （AuthKey 没就绪）。以前这里原样递上去，服务端只能拿自签的假料顶上，
            // App 一验不过，整个 SOTER 支付流程就炸。
            // 用户规矩：指定的那台 B 说没有，就在原地重建，不换机器、也不退回自签。
            //
            // 只认「没料」这三个码（-5 / -6 / -65528）：-18（安全通道不通）、-8 这些是 TA
            // 自己的结构性毛病，材料没问题，重建既没用、还会把人家真钥匙重铸掉。
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
                // TA 连会话都不给建（-26 = 要新鲜指纹）：也是一次实测。
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
            // 0 = 这个槽位有材料。除了 init_sign，从这里也能学到一个能拿去试签的
            // 槽位 —— 学到的机会多一点，能力上报就能早点变准。
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

    // 设备层不再替服务端下结论：`-26` 是 TA 的答复（这会儿没人按指纹），原样递上去。
    // 换不换层、要不要把某个槽位钉到服务端自签那两层，由服务端看错误码的性质定 ——
    // 在设备这边把它改成「这层做不了」就等于替 App 做了决定，还会把一台好机器从
    // 签名链路上踢掉（见 `is_hard_slot_failure`）。
    let _ = is_hard_slot_failure(op, &result);

    // 顺手把这笔的结果喂给 HAL 自愈：连着两笔真失败（-5/-6/-26 这几个正常答复除外）
    // 就重启一次那个服务。这台机器会卡成「建料类 op 全正常、只有签名恒 -18」的半死状态，
    // 不收拾的话服务端会把它当「结构性做不了」，把槽位换到自签那两层 —— App 拿到假料
    // 和一个误导性的 -5（2026-09-30 Duck Detector 那轮就是这么来的）。见 `hal_restart`。
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

/// 真去签一次：拿一个现成的槽位走 `init_sign` + `finish_sign`。
///
/// 这是能力上报用的。`getDeviceId` 只能证明 HAL 活着，证明不了它肯签 —— 一加 11
/// （PHB110）这类机器的 AuthKey 锁在「刚匹配过指纹」后面，没人按指纹时
/// `finish_sign` 一律回 -26（TA 给的原话就是「没有新鲜指纹」）。所以「能不能签」
/// 只能靠真签一次来量，别猜。
///
/// 只用槽位上现成的材料，不建不删（改设备密钥状态得先问操作者）：槽位上没材料
/// （-5 / -6）时结论是「没量出来」，不是「签不了」。这点很要紧 —— 把量不出来
/// 当成签不了上报，服务端会把一台其实能签的机器从签名链路上踢掉。
///
/// 结论写在 `verdict` 里（见 [`SignVerdict`]），`signed` 只为看日志方便。
/// 不走 Err：这是探针，HAL 不给面子也得把原因带回去写进日志。
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

    #[test]
    fn mutating_ops_need_the_opt_in() {
        let payload = json!({ "op": "generate_ask_key_pair", "uid": 10373 });
        let err = handle(&payload, false, 2).expect_err("must be gated");
        assert!(format!("{err:#}").contains("OMMEGA_RELAY_SOTER_MUTATION"));
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
        // 以前这里会记下 uid、24 小时不服务这个槽位。现在没有了：`handle()` 里
        // 对 `has_auth_key` 这种 op 的回包必须是 TA 自己的答复，不是我们编的。
        //
        // 真机（有 SOTER HAL）上跑也成立：那时候 HAL 自己会回一个 `error_code`，
        // 同样不能带我们编的那句。原来这里写死 `expect_err`（默认跑测试的机器没
        // 有 HAL），在一台真有 HAL 的机器上就变成必红，跟代码对错无关。
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
        // -26 只是「这笔没签成」，材料没毛病；本机不再替服务端判「这层做不了」——
        // 以前这么判过，结果是 App 被推去拿服务端自签的假料。
        for op in ["finish_sign", "init_sign", "has_auth_key", "get_device_id"] {
            for code in [-26, 0, -5, -6, -7, -9, -1000] {
                assert!(
                    !is_hard_slot_failure(op, &json!({ "error_code": code })),
                    "{op} {code} must stay the device's own answer"
                );
            }
        }
    }

    /// 签出来过一次就咬死；之后 -26 再多也不翻。反过来，连续几次真活都回 -26
    /// 才会改口说签不了，而且再来一次成功就推翻。
    #[test]
    fn a_signature_is_proof_and_three_refusals_are_the_opposite() {
        clear_sign_state();
        assert_eq!(sign_state(), SignState::Unknown);

        // 两次 -26 还不够：等指纹按下去的时候同台机器是签得出来的。
        note_sign_result(-26);
        note_sign_result(-26);
        assert_eq!(sign_state(), SignState::Unknown);

        // 第三次真活又被顶回来：这台就不接签名了。
        note_sign_result(-26);
        assert_eq!(sign_state(), SignState::Refused);

        // 真签出来一次比什么都硬，否定结论直接丢。
        note_sign_result(0);
        assert_eq!(sign_state(), SignState::Proven);

        // 已经证明能签了，后面几次 -26（指纹窗口关着）不该把结论抽回去。
        for _ in 0..5 {
            note_sign_result(-26);
        }
        assert_eq!(sign_state(), SignState::Proven);

        // 只有别的错误码（没建好 / 会话过期）不算数。
        clear_sign_state();
        for code in [-5, -6, -7, -9, -1000] {
            note_sign_result(code);
        }
        assert_eq!(sign_state(), SignState::Unknown);
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

    #[test]
    fn a_gate_takes_exactly_one_slot_and_gives_it_back() {
        let uid = 40021;
        {
            let _g = SoterHalGate::enter(Some(uid), Some(4));
            let st = hal_queue().lock();
            assert_eq!(st.per_uid.get(&uid).copied(), Some(1), "本线程占 1 个名额");
            assert!(st.total >= 1);
        }
        let st = hal_queue().lock();
        assert_eq!(st.per_uid.get(&uid), None, "出作用域要还回去");
    }

    #[test]
    fn nested_enters_are_free_and_only_the_outermost_releases() {
        let outer = SoterHalGate::enter(Some(40001), Some(4));
        // `handle()` 里会调 `probe()`：同线程重入时不能再去要一个名额，否则
        // 一个 uid 一笔就把自己堵死。重入那次连 uid 都不记（算在外层头上）。
        let inner_a = SoterHalGate::enter(Some(40002), Some(4));
        let inner_b = SoterHalGate::enter(Some(40002), Some(4));
        {
            let st = hal_queue().lock();
            assert_eq!(st.per_uid.get(&40001).copied(), Some(1));
            assert_eq!(st.per_uid.get(&40002), None, "重入不该占名额");
        }
        drop(inner_a);
        drop(inner_b);
        {
            let st = hal_queue().lock();
            assert_eq!(
                st.per_uid.get(&40001).copied(),
                Some(1),
                "内层退出不该把外层还掉"
            );
        }
        drop(outer);
        assert_eq!(hal_queue().lock().per_uid.get(&40001), None);
    }

    #[test]
    fn another_thread_on_the_same_uid_waits_for_the_slot() {
        // 用 recv_timeout 而不是 join：万一以后真的写坏了，这里是失败而不是挂死。
        let uid = 40011;
        let held = SoterHalGate::enter(Some(uid), Some(4));
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let _g = SoterHalGate::enter(Some(uid), Some(4));
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
    }

    #[test]
    fn a_different_uid_does_not_wait_for_the_one_held() {
        let held = SoterHalGate::enter(Some(40031), Some(2));
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            // 上限 2：另一个 uid 该直接进（这就是从「全局串行」换来的那点并行）
            let _g = SoterHalGate::enter(Some(40032), Some(2));
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("另一个 uid 不该被挡住");
        drop(held);
        t.join().unwrap();
    }
}
