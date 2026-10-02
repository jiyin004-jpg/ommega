//! HTTP handlers for all relay endpoints.
//!
//! Mirrors `relay_server/apps/relay_api/views.py`. Two fulfilment modes:
//!   - physical (default): A-side creates a task, B-side polls & returns result
//!   - server_keybox:      A-side requests are intercepted and fulfilled locally

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

use crate::auth::AuthState;
use crate::config::Config;
use crate::db::Db;
use crate::fulfill::Fulfill;
use crate::queue::TaskStore;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub auth: Arc<AuthState>,
    pub store: Arc<TaskStore>,
    pub fulfill: Arc<Fulfill>,
    pub db: Option<Arc<Db>>,
    pub geo: Option<Arc<crate::geo::Ip2Region>>,
    /// SOTER 短 TTL 合并（削峰用），见 `crate::soter_gate`。
    pub soter_gate: Arc<crate::soter_gate::SoterGate>,
    /// SOTER 签名会话登记表：`init_sign` 记下槽位，`finish_sign` 回 -204 时拿它补签，
    /// 见 `crate::soter_sign_sessions`。
    pub sign_sessions: Arc<crate::soter_sign_sessions::SignSessions>,
}

fn token_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-relay-token")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("x-api-token").and_then(|v| v.to_str().ok()))
}

pub(crate) fn client_ip(headers: &HeaderMap) -> String {
    // Prefer X-Real-IP injected by the inject_client_ip middleware, which is the
    // actual TCP socket address. X-Forwarded-For is client-supplied and trivially
    // spoofable, so it must never take precedence — otherwise anyone can claim a
    // whitelisted IP and bypass the IP allow/deny filter. It is kept only as a
    // fallback for reverse-proxy deployments that do not propagate X-Real-IP.
    if let Some(v) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return v;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn json_err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn auth_fail() -> Response {
    json_err(
        StatusCode::UNAUTHORIZED,
        "unauthorized: missing or invalid X-Relay-Token",
    )
}

/// Authenticate + rate-limit a request. Returns Ok(token) or an error response.
///
/// `role`: `Some("a")` for A-side endpoints, `Some("b")` for B-side, `None` for
/// role-agnostic endpoints (ping/health/admin status).
async fn check_auth(
    state: &AppState,
    headers: &HeaderMap,
    role: Option<&str>,
) -> Result<String, Box<Response>> {
    let token = token_from_headers(headers).unwrap_or("").to_string();
    let ip = client_ip(headers);

    // IP allow/deny filter (A/B-side only; admin uses its own session auth).
    if !state.auth.ip_allowed(&ip) {
        return Err(Box::new(json_err(
            StatusCode::FORBIDDEN,
            "access denied by IP filter",
        )));
    }

    // Authenticate first. Failed auth counts against the (much tighter)
    // invalid-request limit, keyed by client IP.
    let authorized = if state.auth.check_static_token(Some(&token)) {
        true
    } else {
        let auth = state.auth.clone();
        let token = token.clone();
        let ip = ip.clone();
        let role = role.map(str::to_string);
        tokio::task::spawn_blocking(move || auth.check_token(Some(&token), role.as_deref(), &ip))
            .await
            .unwrap_or(false)
    };
    if !authorized {
        if !state.auth.allow_invalid(&ip) {
            return Err(Box::new(json_err(
                StatusCode::TOO_MANY_REQUESTS,
                "too many invalid requests",
            )));
        }
        return Err(Box::new(auth_fail()));
    }

    // 限流按客户端 IP 算，不按 token 算。
    //
    // 为什么换成 IP：B 端是长轮询（poll + result 一轮两个请求），单台跑到 7 次/秒
    // 很正常。按 token 限的时候，这一台自己的额度先被自己的轮询吃满，超了就 429；
    // B 收到 429 会退避 1 秒，这一秒没人领任务，任务在服务端干等 —— Duck Detector
    // 上那 1~3 秒的 rkp 等待就是这么来的。改成按 IP 之后，同一台设备不管拿哪个
    // token 都算同一份额度，正常轮询永远吃不满。
    if !state.auth.allow(&ip) {
        // 这行以前没有，429 打进日志 0 条，查了半天才发现是自己在限流。
        tracing::warn!(
            "rate limit hit ip={ip} role={} window={}s limit={}",
            role.unwrap_or("-"),
            state.auth.rate_limit_window.as_secs(),
            state.auth.rate_limit_requests
        );
        return Err(Box::new(json_err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        )));
    }
    Ok(token)
}

/// Enqueue a task for an already-resolved target and wait for the B-side
/// result.  Shared by the layer helper and the SOTER path (which resolves its
/// target by capability instead of by load only).
/// 入队并等 B 端结果。`timeout_secs` 由调用方给：认证（attest）要快速失败好让回退
/// 阶梯接手，SOTER 反而要宽一点 —— 早一步换层等于给同一个槽位换了身份。
async fn enqueue_and_wait(
    state: &AppState,
    task_type: &str,
    body: &Value,
    target: &str,
    timeout_secs: u64,
) -> Value {
    let task_id = state
        .store
        .create_task(task_type, body.clone(), target)
        .await;
    // Dropping an HTTP future must also remove its queued SOTER work so it
    // cannot be reclaimed/dispatched after the device lease was released.
    let mut cancel = (task_type == "soter").then(|| CancelSoterTask {
        store: state.store.clone(),
        task_id: task_id.clone(),
        armed: true,
    });
    let timeout = Duration::from_secs(timeout_secs);
    match state.store.wait_for_result(&task_id, timeout).await {
        Some(mut result) => {
            if let Some(cancel) = cancel.as_mut() {
                cancel.armed = false;
            }
            if let Some(obj) = result.as_object_mut() {
                obj.insert("task_id".to_string(), json!(task_id));
            }
            result
        }
        None => json!({
            "error": "task timeout: no B-side result",
            "task_id": task_id,
        }),
    }
}

struct CancelSoterTask {
    store: Arc<TaskStore>,
    task_id: String,
    armed: bool,
}

impl Drop for CancelSoterTask {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let store = self.store.clone();
        let task_id = self.task_id.clone();
        tokio::spawn(async move {
            let _ = store.cancel_task(&task_id).await;
        });
    }
}

/// Layer ① — B-device fulfilment: enqueue a task for the resolved target and
/// wait for the result. Fails fast when no B device is online so the next layer
/// can run without waiting. When the requested device is offline the balancer
/// hands the task to another live B端 (intended: the real-device layer stays
/// real hardware); the log line records requested vs. actual.
async fn try_b_device_layer(
    state: &AppState,
    task_type: &str,
    body: &Value,
    device_id: &str,
    any_b_online: bool,
) -> Option<Value> {
    if !any_b_online {
        return Some(json!({ "error": "no B-side device online" }));
    }
    let target = state.store.resolve_online_target(device_id).await;
    // Trace line: the requested device and the device that will actually serve
    // the task. They differ exactly when the requested one is not online and
    // the balancer picked another live B端 — the chain will then come from that
    // other device, which is intended but must be visible in the log.
    if !device_id.is_empty() && target != device_id {
        tracing::warn!(
            "b_layer: requested device {device_id} is not online; task served by {target} instead"
        );
    } else {
        tracing::info!(
            "b_layer: type={task_type} requested={} target={target} enqueued",
            if device_id.is_empty() {
                "<any>"
            } else {
                device_id
            }
        );
    }
    Some(
        enqueue_and_wait(
            state,
            task_type,
            body,
            &target,
            state.cfg.wait_result_timeout_secs,
        )
        .await,
    )
}

/// Whether the A-side request explicitly asked for StrongBox (security_level=2).
fn is_strongbox_request(body: &Value) -> bool {
    body.get("device_attest_context")
        .and_then(|c| c.get("attestation_security_level"))
        .and_then(Value::as_i64)
        .or_else(|| {
            body.get("attestation_security_level")
                .and_then(Value::as_i64)
        })
        .unwrap_or(1)
        == 2
}

/// Rewrite the request's security level to a plain TEE request (level 1).
/// Both the `device_attest_context` entry and a top-level entry are rewritten
/// (b-app reads either), so every B-side relay interprets the downgrade.
fn demote_to_tee(body: &Value) -> Value {
    let mut b = body.clone();
    if let Some(ctx) = b.get_mut("device_attest_context") {
        if ctx.get("attestation_security_level").is_some() {
            ctx["attestation_security_level"] = json!(1);
        }
    }
    if b.get("attestation_security_level").is_some() {
        b["attestation_security_level"] = json!(1);
    }
    b
}

/// An attest result without a usable cert chain is treated as a failure so the
/// robustness demotion (or the next layer) gets a chance instead of forwarding
/// an empty chain to the A-side (which would silently fall back locally).
fn attest_chain_empty(task_type: &str, v: &Value) -> bool {
    if task_type != "attest" {
        return false;
    }
    match v.get("cert_chain") {
        None => true,
        Some(Value::Array(a)) => a.is_empty(),
        Some(_) => true,
    }
}

/// 这一层失败的原因（日志 + 最终返回给 A 端的错误都用它）。
///
/// 各层回的东西有两个来源：`error`（B 端跑挂了、任务超时、keybox 层没这个
/// 设备的身份）和一条空链（跑通了但没链）。以前先看空链 —— 于是 B 端明明回了
/// `real keymint ... generateKey failed [km_error=-49]`，日志里照样写成
/// "empty cert chain from B device"，真正的原因全被吞掉：分不清是 HAL 报错、
/// 超时，还是真交了一条空链。现在 `error` 优先，只有它没给原因才说空链。
///
/// 注意跟成功判定分开：那边必须是 `error` 为空 **且** 链非空才算这一层过了，
/// 这里只管失败时怎么描述。
fn layer_failure_msg(task_type: &str, layer: &str, v: &Value) -> String {
    if let Some(e) = v
        .get("error")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return e.to_string();
    }
    if attest_chain_empty(task_type, v) {
        return if layer == "b" {
            "empty cert chain from B device".to_string()
        } else {
            format!("empty cert chain from layer '{layer}'")
        };
    }
    "unknown error".to_string()
}

/// Layer ② — server keybox (stored identity) local fulfilment.
/// Synchronous version that takes &Fulfill directly, for use inside spawn_blocking.
fn try_keybox_layer_sync(
    fulfill: &crate::fulfill::Fulfill,
    task_type: &str,
    body: &Value,
    device_id: &str,
) -> Option<Value> {
    match task_type {
        "attest" => fulfill.try_handle_attest(device_id, body),
        "sign" => fulfill.try_handle_sign(device_id, body),
        "decrypt" => fulfill.try_handle_decrypt(device_id, body),
        _ => None,
    }
}

/// Layer ③ — server self-signed identity (extreme-case fallback, attest only).
/// Synchronous version that takes &Fulfill directly, for use inside spawn_blocking.
fn try_self_signed_layer_sync(
    fulfill: &crate::fulfill::Fulfill,
    task_type: &str,
    body: &Value,
    device_id: &str,
) -> Option<Value> {
    if task_type == "attest" {
        return fulfill.try_handle_attest_self_signed(device_id, body);
    }
    None
}

/// Layer ② (server keybox / stored identity) as an async step, wrapped in
/// spawn_blocking so the expensive crypto runs off the async runtime.
async fn run_layer_keybox(
    state: &AppState,
    task_type: &str,
    body: &Value,
    device_id: &str,
) -> Option<Value> {
    let fulfill = state.fulfill.clone();
    let tt = task_type.to_string();
    let b = body.clone();
    let did = device_id.to_string();
    match tokio::task::spawn_blocking(move || try_keybox_layer_sync(&fulfill, &tt, &b, &did)).await
    {
        Ok(v) => v,
        Err(e) => Some(json!({ "error": format!("spawn_blocking join error: {e}") })),
    }
}

/// Layer ③ (server self-signed identity, attest only) as an async step,
/// wrapped in spawn_blocking.
async fn run_layer_self_signed(
    state: &AppState,
    task_type: &str,
    body: &Value,
    device_id: &str,
) -> Option<Value> {
    let fulfill = state.fulfill.clone();
    let tt = task_type.to_string();
    let b = body.clone();
    let did = device_id.to_string();
    match tokio::task::spawn_blocking(move || try_self_signed_layer_sync(&fulfill, &tt, &b, &did))
        .await
    {
        Ok(v) => v,
        Err(e) => Some(json!({ "error": format!("spawn_blocking join error: {e}") })),
    }
}

/// KeyMint security level (0 = software, 1 = TEE, 2 = StrongBox) of the leaf a
/// relay minted, parsed out of the base64 DER chain.  Smart mode uses it to tell
/// a real StrongBox chain from one the B side silently demoted to TEE.  `None`
/// when the chain is missing, unreadable, or carries no attestation extension.
fn chain_attestation_security_level(v: &Value) -> Option<i64> {
    let leaf = v.get("cert_chain")?.as_array()?.first()?.as_str()?;
    crate::cert::attestation_security_level_from_chain(leaf)
}

/// Whether a failed B-side attest result carries a "the device HAS a StrongBox
/// HAL but it is not usable" verdict that Smart mode must surface to the
/// A-side app rather than mask. Matches the fixed wording emitted by the
/// b-side binary relay (`b-side/source/src/bin/relay.rs`) for km errors -74
/// (AttestationKeysNotProvisioned) and -68 (HardwareTypeUnavailable). Any
/// other failure (HAL absent, timeout, empty chain, foreign error text) is not
/// a definitive StrongBox-HAL verdict and returns `None` so the caller falls
/// back to the server keybox / A-side local keybox.
fn strongbox_b_kind(v: &Value) -> Option<&'static str> {
    let s = v.get("error").and_then(Value::as_str)?;
    if s.contains("attestation keys not provisioned") {
        return Some("strongbox_unprovisioned");
    }
    if s.contains("hardware type unavailable") {
        return Some("strongbox_unavailable");
    }
    None
}

/// Smart (middle) StrongBox mode: serve a StrongBox attestation from the
/// strongest honest source available.
///
///   1. server_keybox mode mints from the stored per-device identity first
///      (an uploaded identity means the operator wants local server out-证 to
///      win when it can).
///   2. Otherwise ask the B device for its real StrongBox:
///        - success (real StrongBox chain)         -> return as-is (branch 3);
///        - present-but-broken StrongBox (attestation keys not provisioned /
///          hardware type unavailable)             -> return the B error verbatim
///          with a `relay_error_kind` marker so the A-side surfaces it to the
///          calling app (branch 2);
///        - anything else (no StrongBox HAL / timeout / empty chain / foreign
///          error text)                            -> continue to the keybox step.
///   3. In physical mode, fall back to the stored per-device keybox identity,
///      which mints a StrongBox-tagged chain (branch 1).
///   4. Nothing left -> error so the A-side's local software keybox generates a
///      StrongBox-level chain itself (branch 4). `self_signed` is deliberately
///      never used for a StrongBox request.
async fn run_smart_strongbox_attest(
    state: &AppState,
    device_id: &str,
    body: &Value,
    any_b_online: bool,
) -> Response {
    let serverbox = state.fulfill.is_enabled();
    let task_type = "attest";

    if serverbox {
        if let Some(v) = run_layer_keybox(state, task_type, body, device_id).await {
            if v.get("error").is_none() && !attest_chain_empty(task_type, &v) {
                tracing::info!(
                    "run_smart_strongbox: server keybox layer fulfilled StrongBox attest for device {device_id}"
                );
                return Json(v).into_response();
            }
        }
    }

    if any_b_online {
        if let Some(v) = try_b_device_layer(state, task_type, body, device_id, true).await {
            if v.get("error").is_none() && !attest_chain_empty(task_type, &v) {
                // Only a chain that is itself StrongBox-tagged counts as the B
                // device fulfilling the StrongBox request.  The b-app relay goes
                // through the Android Keystore API, where `setIsStrongBoxBacked`
                // silently degrades to TEE on a device without a StrongBox, so
                // its chain comes back honestly tagged TEE.  Accepting that here
                // would stop the fallback short of the server keybox — which can
                // mint a properly StrongBox-tagged chain — and the calling app
                // would end up with a TEE attestation after asking for StrongBox.
                let level = chain_attestation_security_level(&v);
                if level == Some(2) {
                    tracing::info!(
                        "run_smart_strongbox: B real StrongBox fulfilled attest for device {device_id}"
                    );
                    return Json(v).into_response();
                }
                // Unreadable chains (`None`) take the same path: the next layer
                // either succeeds or the A-side local keybox does, and both
                // produce a StrongBox-tagged chain.
                tracing::info!(
                    "run_smart_strongbox: B returned a non-StrongBox chain (attestation_security_level={level:?}) for device {device_id} -> continuing fallback"
                );
            }
            if let Some(kind) = strongbox_b_kind(&v) {
                let msg = v
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("strongbox attestation refused by B device")
                    .to_string();
                tracing::info!(
                    "run_smart_strongbox: B StrongBox present but not usable (kind={kind}) -> surfaced to A: {msg}"
                );
                // HTTP 200: the A-side only inspects 2xx bodies, so the
                // `relay_error_kind` marker must ride a success-status response.
                return Json(json!({
                    "error": msg,
                    "relay_error_kind": kind,
                }))
                .into_response();
            }
            // No usable StrongBox verdict (HAL absent / timeout / empty chain /
            // foreign error text): fall through to the stored keybox below.
            tracing::info!(
                "run_smart_strongbox: B gave no usable StrongBox result for device {device_id}"
            );
        }
    }

    if !serverbox {
        if let Some(v) = run_layer_keybox(state, task_type, body, device_id).await {
            if v.get("error").is_none() && !attest_chain_empty(task_type, &v) {
                tracing::info!(
                    "run_smart_strongbox: server keybox fallback fulfilled StrongBox attest for device {device_id}"
                );
                return Json(v).into_response();
            }
        }
    }

    // Branch 4: the server cannot help — error so the A-side's local software
    // keybox generates a StrongBox-level chain itself (never a self-signed one).
    tracing::info!(
        "run_smart_strongbox: no StrongBox-capable fulfilment for device {device_id}; handing back to A-side local keybox"
    );
    json_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!(
            "all strongbox fulfilment layers failed for device {device_id}: B StrongBox unavailable and no stored server keybox identity"
        ),
    )
}

/// Refuse mode: answer a StrongBox request only with the B device's real
/// StrongBox, and refuse honestly otherwise.
///
/// Nothing is minted on this path — no stored server keybox, no self-signed
/// chain, and no silent hand-back to the A-side local software keybox (which
/// would fabricate a StrongBox-tagged chain). The A side turns the
/// `relay_error_kind` marker into the matching KeyMint error, so the calling app
/// sees what AOSP shows on a device that advertises StrongBox but has no
/// provisioned keys.
async fn run_refuse_strongbox_attest(
    state: &AppState,
    device_id: &str,
    body: &Value,
    any_b_online: bool,
) -> Response {
    let task_type = "attest";

    // Only the B device's own StrongBox can answer in this mode.
    if let Some(v) = try_b_device_layer(state, task_type, body, device_id, any_b_online).await {
        if v.get("error").is_none() && !attest_chain_empty(task_type, &v) {
            let level = chain_attestation_security_level(&v);
            if level == Some(2) {
                tracing::info!(
                    "run_refuse_strongbox: B real StrongBox fulfilled attest for device {device_id}"
                );
                return Json(v).into_response();
            }
            // A chain did come back but it is not StrongBox-tagged: the B side
            // demoted the request to TEE. Refusing is the whole point of this
            // mode, so say so instead of handing the app a TEE chain it did not
            // ask for.
            tracing::info!(
                "run_refuse_strongbox: B returned a non-StrongBox chain (attestation_security_level={level:?}) for device {device_id} -> refusing"
            );
            return refuse_strongbox_body(
                "strongbox_unprovisioned",
                "strongbox not supported: serving device demoted the request to TEE",
            );
        }

        // Keep the B side's own verdict when it named one; otherwise fall through
        // to the AOSP "keys not provisioned" wording (KeyMint -74 on the A side).
        if let Some(kind) = strongbox_b_kind(&v) {
            let msg = v
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("strongbox attestation refused by B device")
                .to_string();
            tracing::info!(
                "run_refuse_strongbox: B StrongBox present but not usable (kind={kind}) -> refusing: {msg}"
            );
            return refuse_strongbox_body(kind, &msg);
        }
    }

    tracing::info!(
        "run_refuse_strongbox: no real B StrongBox for device {device_id} -> refusing (nothing minted server-side or A-side)"
    );
    refuse_strongbox_body(
        "strongbox_unprovisioned",
        "strongbox not supported: no usable StrongBox on the serving device (attestation keys not provisioned)",
    )
}

/// Error body carrying the `relay_error_kind` marker. HTTP 200 on purpose: the A
/// side only inspects 2xx bodies, and this is the shape it converts into a real
/// KeyMint error (AttestationKeysNotProvisioned / HardwareTypeUnavailable).
fn refuse_strongbox_json(kind: &str, msg: &str) -> Value {
    json!({
        "error": msg,
        "relay_error_kind": kind,
    })
}

fn refuse_strongbox_body(kind: &str, msg: &str) -> Response {
    Json(refuse_strongbox_json(kind, msg)).into_response()
}

/// Shared logic for A-side task endpoints.
///
/// Three-layer fallback, with the order set by the active mode:
///   physical:  ① B device -> ② stored keybox -> ③ self-signed
///   serverbox: ② stored keybox -> ① B device -> ③ self-signed
/// A layer "succeeds" when it returns a result without an `error` field;
/// otherwise the next layer is tried, and only when every layer fails is an
/// error returned.
async fn run_a_side_task(state: &AppState, task_type: &str, body: &Value) -> Response {
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if device_id.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "device_id required");
    }
    let ctx = body
        .get("device_attest_context")
        .cloned()
        .unwrap_or(Value::Null);
    let ctx_short = match &ctx {
        Value::Object(m) => {
            let mut s = String::new();
            for (k, v) in m {
                if k == "attestation_application_id" {
                    s.push_str(&format!(
                        "{k}=<appid-len:{}> ",
                        v.as_str().map(|x| x.len()).unwrap_or(0)
                    ));
                } else if k == "certificate_subject" {
                    s.push_str(&format!(
                        "{k}=<b64-len:{}> ",
                        v.as_str().map(|x| x.len()).unwrap_or(0)
                    ));
                } else {
                    s.push_str(&format!("{k}={v} "));
                }
            }
            s
        }
        _ => format!("{ctx}"),
    };
    tracing::info!(
        "run_a_side_task: type={task_type} device={device_id} alias={} ctx=[{ctx_short}]",
        body.get("alias").and_then(|v| v.as_str()).unwrap_or("")
    );

    let connected = state.store.get_connected_devices().await;
    let any_b_online = !connected.is_empty();

    // Smart (middle) mode: StrongBox attestations are served by the strongest
    // honest source available (real B StrongBox -> stored per-device keybox ->
    // A-side local keybox). A present-but-broken B StrongBox is surfaced to the
    // app rather than masked; self_signed never substitutes a StrongBox request.
    if task_type == "attest"
        && crate::strongbox::mode() == crate::strongbox::StrongboxMode::Smart
        && is_strongbox_request(body)
    {
        return run_smart_strongbox_attest(state, &device_id, body, any_b_online).await;
    }

    // Refuse mode: a StrongBox request gets the serving device's real StrongBox
    // or a real KeyMint error. Nothing is minted — not by the server keybox, not
    // by the self-signed layer, and not by the A-side local software keybox.
    if task_type == "attest"
        && crate::strongbox::mode() == crate::strongbox::StrongboxMode::Refuse
        && is_strongbox_request(body)
    {
        return run_refuse_strongbox_attest(state, &device_id, body, any_b_online).await;
    }

    let serverbox = state.fulfill.is_enabled();

    // StrongBox (security_level=2) requests follow the SAME layer order as TEE.
    // Each layer handles them according to its own capability:
    //   - server keybox layer: tags the attestation StrongBox using the
    //     forwarded `attestation_security_level` and mints with the stored keybox.
    //   - B-side layer: tries the B-side device's real StrongBox HAL; if that
    //     device has none it returns an error and the next layer is attempted.
    // Only when every layer fails does the request error, letting the A-side
    // fall back to its local software keybox.
    let order: &[&str] = if serverbox {
        &["keybox", "b", "self_signed"]
    } else {
        &["b", "keybox", "self_signed"]
    };

    let mut last_error: Option<String> = None;
    // 第一处「这台设备根本没有这个 alias 的私钥」的原因，原样带到最终错误里。
    // A 端靠这段文本（或 error_kind=no_such_key）判断「不是网络/时序问题，而是 key 不在这」，
    // 从而决定在原地重建或回确定错误码；只在 self_signed 那层含糊地写一句
    // 「produced no result」会把原因丢掉，A 端就只能当普通失败无限重试。
    let mut key_missing: Option<String> = None;
    for &layer in order {
        let result = match layer {
            "b" => try_b_device_layer(state, task_type, body, &device_id, any_b_online).await,
            "keybox" => run_layer_keybox(state, task_type, body, &device_id).await,
            "self_signed" => run_layer_self_signed(state, task_type, body, &device_id).await,
            _ => None,
        };
        match result {
            Some(v) if v.get("error").is_none() && !attest_chain_empty(task_type, &v) => {
                tracing::info!(
                    "run_a_side_task: type={task_type} layer={layer} result_keys={:?} has_cert_chain={}",
                    v.as_object().map(|m| m.keys().cloned().collect::<Vec<String>>()),
                    v.get("cert_chain").is_some(),
                );
                return Json(v).into_response();
            }
            Some(v) => {
                // 失败原因交给 `layer_failure_msg`：各层回的 `error` 优先，只有它
                // 没给原因时才说空链。`device` 是 *请求的* 设备 —— 正上方的
                // `b_poll` 行会显示实际接管的是哪一台。
                let msg = layer_failure_msg(task_type, layer, &v);
                tracing::info!(
                    "run_a_side_task: type={task_type} layer={layer} device={device_id} failed: {msg}"
                );
                // StrongBox robustness mode: a StrongBox attest that the B
                // device cannot fulfil (capability error — not supported /
                // keys not provisioned / HAL absent — or no cert chain at
                // all) is transparently retried as a TEE request on the B
                // side — the Android-standard silent fallback. The B side
                // tags the downgraded chain TRUSTED_ENVIRONMENT, so this is
                // an honest degradation, never a mislabelled StrongBox.
                // When the mode is off, the failure propagates to the next
                // layer exactly as before (strict native semantics).
                if layer == "b"
                    && task_type == "attest"
                    && crate::strongbox::mode() == crate::strongbox::StrongboxMode::Robust
                    && is_strongbox_request(body)
                {
                    let demoted = demote_to_tee(body);
                    if let Some(dv) =
                        try_b_device_layer(state, task_type, &demoted, &device_id, any_b_online)
                            .await
                    {
                        if dv.get("error").is_none() && !attest_chain_empty(task_type, &dv) {
                            tracing::info!(
                                "run_a_side_task: type={task_type} layer=b strongbox-robust demoted to TEE ok"
                            );
                            return Json(dv).into_response();
                        }
                        let dmsg = layer_failure_msg(task_type, layer, &dv);
                        tracing::info!(
                            "run_a_side_task: type={task_type} layer=b strongbox demotion retry failed: {dmsg}"
                        );
                    }
                }
                if key_missing.is_none()
                    && (msg.contains("no key for alias")
                        || msg.contains("no server_keybox session"))
                {
                    key_missing = Some(msg.clone());
                }
                // 设备自己说「这个 alias 的私钥不在我这」时，后面的顶替层
                // （keybox / self_signed）一律不许接手：它们手里的钥匙跟 App
                // 那把不是一对，签出来的东西 App 一验就废，只会原地无限重试
                // （线上 `ommega-remote-80a3ffcdf5153abf` 就这么刷了 9 万条
                // 日志，把 B 那条单线程队列占满，顺带拖慢所有远端 op）。
                // 把原因原样交回 A 端，让它在那台设备上原地重建。
                if b_said_key_missing(layer, &msg) {
                    tracing::info!(
                        "run_a_side_task: type={task_type} layer=b reported missing key; \
                         skipping keybox/self_signed substitution for {device_id}"
                    );
                    last_error = Some(msg.clone());
                    break;
                }
                last_error = Some(msg);
            }
            None => {
                tracing::info!("run_a_side_task: type={task_type} layer={layer} not applicable");
                last_error = Some(format!("layer {layer} produced no result"));
            }
        }
    }

    json_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        &format!(
            "all fulfilment layers failed for device {device_id}: {}{}",
            key_missing
                .as_deref()
                .map(|m| format!("{m}; "))
                .unwrap_or_default(),
            last_error.unwrap_or_else(|| "unknown".to_string())
        ),
    )
}

// ---------------------------------------------------------------------------
// Basic endpoints
// ---------------------------------------------------------------------------

/// 设备层（`layer == "b"`）是否明确回了「这个 alias 没私钥」。
///
/// 只认这一种措辞，因为它是「不是网络、不是时序，而是 key 真不在这」的意思：
/// 真机说了这句之后，再把服务端自己那把 keybox 的签名顶上去就是另一把钥匙，
/// 拿不回原样。
fn b_said_key_missing(layer: &str, msg: &str) -> bool {
    layer == "b" && msg.contains("no key for alias")
}

pub async fn ping() -> &'static str {
    "pong"
}

pub async fn health(State(state): State<AppState>) -> Response {
    let counts = state.store.counts().await;
    let devices = state.store.get_connected_devices().await;
    // `machine_id` is deliberately omitted (same as the public status page):
    // health is unauthenticated and machine ids are not meant to be public.
    let device_list: Vec<Value> = devices
        .iter()
        .map(|d| {
            json!({
                "device_id": d.device_id,
                "last_seen_ms": d.last_seen_ms,
            })
        })
        .collect();
    Json(json!({
        "status": "ok",
        "mode": if state.fulfill.is_enabled() { "server_keybox" } else { "physical" },
        "tasks": {
            "pending": counts.pending,
            "assigned": counts.assigned,
            "completed": counts.completed,
            "failed": counts.failed,
        },
        "connected_devices": device_list,
        "server_time_ms": chrono::Utc::now().timestamp_millis(),
    }))
    .into_response()
}

pub async fn cert_chain_dump(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Diagnostic: dump stored server identity chain (admin diagnostic). Requires
    // a valid A/B token so the keybox identity is not exposed to unauthenticated
    // callers.
    if let Err(r) = check_auth(&state, &headers, None).await {
        return *r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let result = tokio::task::spawn_blocking(move || db.get_active_device_identity()).await;
    match result {
        Ok(Ok(Some(id))) => Json(json!({
            "device_id": id.device_id,
            "algorithm": id.algorithm,
            "active": id.active,
            // 链的形状：真机出链是 `device-like`，老公开 keybox 是
            // `legacy-keybox`（客户端的形状检查能一眼认出来）。
            "rdn_shape": crate::cert::chain_rdn_shape(&id.certificate_chain_pem).as_str(),
            "certificate_chain_pem": id.certificate_chain_pem,
        }))
        .into_response(),
        Ok(Ok(None)) => json_err(StatusCode::NOT_FOUND, "no active server identity"),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("join error: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// A-side task endpoints
// ---------------------------------------------------------------------------

pub async fn attest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")).await {
        return *r;
    }
    run_a_side_task(&state, "attest", &body).await
}

pub async fn sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")).await {
        return *r;
    }
    run_a_side_task(&state, "sign", &body).await
}

pub async fn decrypt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")).await {
        return *r;
    }
    run_a_side_task(&state, "decrypt", &body).await
}

/// POST /api/soter/ — SOTER 转发的入口，鉴权后交给 `run_soter_task`。
pub async fn soter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")).await {
        return *r;
    }
    run_soter_task(&state, &body).await
}

/// SOTER 入口；设备会话在 inner 的设备层补签之后按实际设备清理。
/// 服务端回退层不消费其他设备的同号会话。
async fn run_soter_task(state: &AppState, body: &Value) -> Response {
    run_soter_task_inner(state, body).await
}

/// 补签最多试几次。第二次是给「设备层那一瞬没答出来」准备的 —— 那种是瞬时的。
const REPAIR_ATTEMPTS: u32 = 2;

/// 两次补签之间等多久。
const REPAIR_RETRY_GAP: Duration = Duration::from_millis(150);

/// `finish_sign` 回 -204 时的补救：拿 init 时缓存的参数重开一张会话，再签一次。
///
/// -204（`SOTER_ERROR_OPERATEID_NULL`）在设备上就一个意思：这张会话被后来的一笔
/// `init_sign` 顶掉了 —— TA 一台设备只保留一个会话，跟槽位是谁的无关（2026-10-01 实测
/// 见 `soter_sign_sessions` 的模块注释）。App 手上只有它自己那一张 session，没牌可打，
/// 所以服务端替它重开：用同一个 uid / 别名 / challenge 再 `init_sign` 一次，拿新会话把
/// 同一个 challenge 签了。同一把钥匙、同一个挑战 —— 签名值是等价的，App 那边就是一次
/// 正常成功。
///
/// 只试 [`REPAIR_ATTEMPTS`] 次（中间隔 [`REPAIR_RETRY_GAP`]）；试不出来（拿不到新会话、
/// 或者补签本身也失败）就返回 `None`，外面照旧把原来的 -204 还回去。
///
/// 为什么要试第二次：失败那几次看下来多半不是「会话抢不到」，而是设备层那一瞬答不出来
/// （没有在线的 B、转发超时）。这种是瞬时的，隔一百多毫秒再来一次就够了；第一次已经
/// 拿到签名就直接回，正常路径不因为重试多花一点时间。
async fn repair_clobbered_finish(
    state: &AppState,
    body: &Value,
    requested: &str,
    target: Option<&str>,
) -> Result<Option<Value>, ()> {
    let Some(session) = body.get("session").and_then(Value::as_i64) else {
        return Ok(None);
    };
    let Some(device) = target else {
        return Ok(None);
    };
    let spec = match state.sign_sessions.lookup_for(device, requested, session) {
        Some(spec) => spec,
        None => {
            // 这张会话没登记（init 不是设备层答的）或者登记已经过期 —— 补不了，只能把
            // 原来的 -204 还回去。留一行日志，好知道到底哪种情况多。
            tracing::warn!("soter: 会话 {session} 没在登记表里（没记上或已过期），补不了");
            return Ok(None);
        }
    };
    let Some(alias) = spec.alias.as_deref() else {
        return Ok(None);
    };
    tracing::info!(
        "soter: 会话 {session} 被顶掉了，拿缓存的参数重开一张再签（uid={} alias={alias}）",
        spec.uid
    );
    for attempt in 1..=REPAIR_ATTEMPTS {
        if attempt > 1 {
            tracing::info!("soter: 补签第 {attempt} 次重试（会话 {session}）");
            tokio::time::sleep(REPAIR_RETRY_GAP).await;
        }
        if let Some(done) = repair_once(state, body, requested, target, session, &spec).await? {
            return Ok(Some(done));
        }
    }
    Ok(None)
}

/// 补签的实际动作：重开一张会话、把同一个 challenge 签出来。
async fn repair_once(
    state: &AppState,
    body: &Value,
    requested: &str,
    target: Option<&str>,
    session: i64,
    spec: &crate::soter_sign_sessions::SlotSpec,
) -> Result<Option<Value>, ()> {
    let (Some(alias), Some(challenge)) = (spec.alias.as_deref(), spec.challenge.as_deref()) else {
        return Ok(None);
    };
    let init_body = repair_init_body(body, spec.uid, alias, challenge);
    let init = try_b_soter_layer(state, &init_body, requested, target)
        .await
        .ok_or(())?;
    repair_reply_known(&init.value, init.device.as_deref(), target)?;
    let init_code = init.value.get("error_code").and_then(Value::as_i64);
    if init_code != Some(0) {
        return Ok(None);
    }
    let Some(new_session) = init
        .value
        .get("session")
        .and_then(Value::as_i64)
        .filter(|s| *s != 0)
    else {
        tracing::info!("soter: 补签没拿到新会话（init error_code={init_code:?}）");
        return Err(());
    };
    let mut fin_body = body.clone();
    if let Some(obj) = fin_body.as_object_mut() {
        obj.insert("session".to_string(), json!(new_session));
    }
    // The new handle belongs to the device that actually answered init, not the request.
    let done = try_b_soter_layer(state, &fin_body, requested, init.device.as_deref())
        .await
        .ok_or(())?;
    repair_reply_known(&done.value, done.device.as_deref(), init.device.as_deref())?;
    let code = done.value.get("error_code").and_then(Value::as_i64);
    if code != Some(0) || done.device != init.device {
        tracing::warn!("soter: 补签的 finish 也失败了（error_code={code:?}）");
        return Ok(None);
    }
    tracing::info!(
        "soter: 补签成功，会话 {session} 的那个 challenge 由新会话 {new_session} 签出来了"
    );
    Ok(Some(done.value))
}

fn finish_owner_layer<'a>(
    remembered: Option<&str>,
    server_owner: Option<&'a str>,
) -> Option<&'a str> {
    if remembered.is_some() {
        Some("b")
    } else {
        server_owner
    }
}

// A dispatched repair without a definite reply must stop the retry loop and
// leave the outer dispatched guard incomplete (quarantined on drop).
#[cfg(test)]
mod repair_outcome_tests {
    use super::*;

    #[test]
    fn finish_routes_only_to_its_owner_in_either_mode() {
        assert_eq!(
            finish_owner_layer(None, Some("self_signed")),
            Some("self_signed")
        );
        assert_eq!(finish_owner_layer(None, Some("keybox")), Some("keybox"));
        assert_eq!(finish_owner_layer(None, None), None);
        assert_eq!(
            finish_owner_layer(Some("actual-b"), Some("keybox")),
            Some("b")
        );
        assert_eq!(finish_owner_layer(Some("offline-b"), None), Some("b"));
    }

    #[test]
    fn uncertain_repair_stops_instead_of_releasing_as_original_failure() {
        assert_eq!(
            repair_reply_known(&json!({"error": "timeout"}), Some("b"), Some("b")),
            Err(())
        );
        assert_eq!(
            repair_reply_known(&json!({"error_code": 0}), Some("other"), Some("b")),
            Err(())
        );
        assert_eq!(
            repair_reply_known(&json!({}), Some("b"), Some("b")),
            Err(())
        );
        assert_eq!(
            repair_reply_known(&json!({"error_code": -204}), Some("b"), Some("b")),
            Ok(())
        );
        assert_eq!(
            repair_reply_known(&json!({"error_code": -9}), Some("b"), Some("b")),
            Ok(())
        );
        assert_eq!(
            repair_reply_known(&json!({"error_code": 0}), Some("b"), Some("b")),
            Ok(())
        );
    }
}

fn repair_reply_known(reply: &Value, actual: Option<&str>, target: Option<&str>) -> Result<(), ()> {
    if reply.get("error").is_some()
        || actual != target
        || reply.get("error_code").and_then(Value::as_i64).is_none()
    {
        Err(())
    } else {
        Ok(())
    }
}

/// 把一笔 `finish_sign` 请求改写成「重开同一张槽位」的 `init_sign`：补签要的三个参数
/// 全带上（App 的 finish 请求里只有 session，别的什么都没有）。
fn repair_init_body(body: &Value, uid: i64, alias: &str, challenge: &str) -> Value {
    let mut out = body.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("op".to_string(), json!("init_sign"));
        obj.insert("uid".to_string(), json!(uid));
        obj.insert("alias".to_string(), json!(alias));
        obj.insert("challenge".to_string(), json!(challenge));
        obj.remove("session");
    }
    out
}

/// SOTER 转发：跟认证共用同一套三层链，差别只在三层的实现。
///
/// 层序（`physical` / `serverbox` 两种模式只差优先级）：
///   physical:   B 端设备层 -> 服务端密钥层(keybox) -> 服务端自签层
///   serverbox:  服务端密钥层 -> B 端设备层 -> 服务端自签层
/// 哪一层没做成（没物料、没能力、请求失败）就回退下一层，三层都不行才把错误回
/// 给 A 端；A 端据此用本地密钥，本地也不行就透原生。
///
/// B 端层在线点名时不换设备；离线点名且没有已登记的签名会话路由时才按能力
/// 和负载选设备。finish 保留 init 的实际设备，无法使用原设备时走原来的回退层，
/// 不在另一台设备上拿同号句柄补签。
///
/// 服务端两层（见 `soter_mint`）用服务端自己的 RSA 物料现造一份自洽的 ASK，让
/// A 端本地流程先闭环；腾讯那边的根谁也拿不到，这两层不假装自己是腾讯认得的东西。
async fn run_soter_task_inner(state: &AppState, body: &Value) -> Response {
    if !body.is_object() {
        return json_err(StatusCode::BAD_REQUEST, "json object body required");
    }
    let requested = body.get("device_id").and_then(Value::as_str).unwrap_or("");
    let op = body.get("op").and_then(Value::as_str).unwrap_or("probe");
    let probe_uid = body
        .get("uid")
        .and_then(Value::as_i64)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string());
    let probe_alias = body
        .get("alias")
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_string();
    tracing::info!(
        "soter: op={op} uid={probe_uid} alias={probe_alias} requested={}",
        if requested.is_empty() {
            "<any>"
        } else {
            requested
        }
    );

    let gate_uid = body.get("uid").and_then(Value::as_i64).map(|v| v as i32);
    let alias_arg = body.get("alias").and_then(Value::as_str);
    // 削峰：同一台设备上同一份只读 op（`has_auth_key` / `has_ask_already` / `export_*`）
    // 会被 App 的 SOTER 初始化循环反复问，几秒内答案不会变；重建类 op 也会被反复重放。
    // 命中的前提是上一次**真由这台设备答出来**（见 `soter_gate`），而且窗口极短，
    // 设备一旦恢复下一笔就问得着。
    if let Some(hit) = state.soter_gate.lookup(requested, op, gate_uid, alias_arg) {
        tracing::info!(
            "soter: op={op} uid={probe_uid} alias={} coalesced (short-TTL window)",
            alias_arg.unwrap_or("-")
        );
        return Json(hit).into_response();
    }

    let serverbox = state.fulfill.is_enabled();
    let order: &[&str] = if serverbox {
        &["keybox", "b", "self_signed"]
    } else {
        &["b", "keybox", "self_signed"]
    };

    let request_deadline =
        tokio::time::Instant::now() + Duration::from_secs(state.cfg.soter_wait_result_timeout_secs);
    let mut last_error: Option<String> = None;

    // B 端这一层有没有能接活的设备，先问一次：没有就是「这层结构性地做不了」，
    // 顺带让下面不用再解析一遍。
    let needs_sign = matches!(op, "init_sign" | "finish_sign");
    let connected = state.store.get_connected_devices().await;
    let requested_online = connected.iter().any(|d| d.device_id == requested);
    let remembered = if op == "finish_sign" {
        body.get("session")
            .and_then(Value::as_i64)
            .and_then(|s| state.sign_sessions.route(requested, s))
    } else {
        None
    };
    let session_present =
        op == "finish_sign" && body.get("session").and_then(Value::as_i64).is_some();
    // A recorded (requested device, integer session) route is authoritative.
    // Do not let a newly-online requested device override it: the same numeric
    // handle can refer to a different TA session on another B device.
    let route_request = remembered.as_deref().unwrap_or(requested);
    let resolved = if session_present {
        // If the route is unknown or ambiguous, do not guess: sending finish to
        // another B could operate an unrelated session with the same integer
        // handle. If the original B is offline, finish is terminal; neither
        // another B nor a server mint layer owns that session.
        remembered.as_deref().and_then(|actual| {
            connected
                .iter()
                .find(|d| d.device_id == actual)
                .filter(|d| {
                    d.supports_soter != Some(false) && !(needs_sign && d.soter_nosign == Some(true))
                })
                .map(|d| d.device_id.clone())
        })
    } else if requested_online {
        // Unknown capabilities may be tried on the original device, but explicit
        // negative capabilities must still go through the unchanged fallback layers.
        connected
            .iter()
            .find(|d| d.device_id == route_request)
            .filter(|d| {
                d.supports_soter != Some(false) && !(needs_sign && d.soter_nosign == Some(true))
            })
            .map(|d| d.device_id.clone())
    } else {
        state
            .store
            .resolve_soter_target(route_request, needs_sign)
            .await
    };
    let b_target = if session_present {
        resolved
    } else {
        consistent_soter_target(requested_online, requested, None, resolved)
    };

    // Physical finish must never fall through to a fabricated session or repair
    // without a live lease. Unknown/expired handles are terminal business errors.
    let server_owner = if op == "finish_sign" && remembered.is_none() {
        body.get("session")
            .and_then(Value::as_i64)
            .and_then(|s| crate::soter_mint::session_layer(requested, s))
    } else {
        None
    };
    if op == "finish_sign" && remembered.is_none() && server_owner.is_none() {
        return Json(json!({"error_code": -204, "relay_error_kind": "soter_session_expired"}))
            .into_response();
    }

    // `finish_sign` 回来 -204 时的补救在 `repair_clobbered_finish` 里：
    // 只拿 `init_sign` 时缓存的参数重开一张会话再签一次。B 端自己的能力探针也会在这台
    // 设备上跑 `init_sign`，那是另一条顶人的路子，已在 B 端给它加了空闲门
    // （`b-side/source/src/caps.rs` 的 `SIGN_PROBE_QUIET`）。

    // 这个槽位已经定过层就把它排到最前面：同一槽位的材料必须只出自一层，否则 App
    // 手里会出现一半 B 的一半 keybox 的状态（导出的公钥和签名的私钥都对不上）。
    //
    // 但钉子只在「B 端这层结构性地做不了」（一台能接的设备都没有）的时候才作数：
    // 一次超时、一次 `-26`（这会儿没人按指纹）都可能只是这一笔没答好，那种时候
    // 把槽位挪到服务端自签那两层，App 手里就换成假料了，真机再也轮不上 —— 实测
    // PLC110 的 uid 10490 就是这么被钉到 self_signed 上，之后每轮第一个 op 又把
    // 钉子续上，一轮流程都回不到真机。
    let uid = body.get("uid").and_then(Value::as_i64).map(|v| v as i32);
    let mut layers: Vec<&str> = Vec::with_capacity(order.len());
    if let (false, Some(uid)) = (requested.is_empty(), uid) {
        if let Some(pinned) = crate::soter_mint::pinned_layer(requested, uid) {
            let honour = pinned == "b" || b_target.is_none();
            if !honour {
                tracing::info!(
                    "soter: slot {requested}|{uid} is pinned to {pinned} but the B-side layer can \
                     serve it again; going back to the device first"
                );
            }
            if honour {
                if let Some(pos) = order.iter().position(|layer| *layer == pinned) {
                    layers.push(order[pos]);
                    layers.extend(
                        order
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| *i != pos)
                            .map(|(_, layer)| *layer),
                    );
                }
            }
        }
    }
    if layers.is_empty() {
        layers.extend(order.iter().copied());
    }
    if op == "finish_sign" {
        layers.clear();
        if let Some(owner) = finish_owner_layer(remembered.as_deref(), server_owner.as_deref()) {
            layers.push(owner);
        }
    }

    // B 端这层到底是不是结构性地做不了（没有设备、设备没报 SOTER、TA 结构性报错）。
    // 只有它成立，服务端那两层接上之后才允许把槽位挪过去。
    let mut b_structural = b_target.is_none();
    // 设备层那个失败答复（结构性失败也带着真错误码）。服务端两层都接不了这个槽位的时候
    // 把它原样还回去 —— 比递一个「钥匙不在这层」的 -5 准得多。
    let mut b_error_reply: Option<Value> = None;
    let mut served_device: Option<String> = None;

    for &layer in &layers {
        let result = match layer {
            "b" => {
                let mut lease = if needs_sign {
                    match b_target.as_deref() {
                        Some(device) if op == "init_sign" => {
                            match state.sign_sessions.acquire(device, requested, request_deadline).await {
                                Some(lease) => Some(lease),
                                None => return Json(json!({"error_code": -9, "relay_error_kind": "soter_busy", "retryable": true})).into_response(),
                            }
                        }
                        Some(device) => {
                            match body.get("session").and_then(Value::as_i64).and_then(|s| state.sign_sessions.finish(device, requested, s)) {
                                Some(lease) => Some(lease),
                                None => return Json(json!({"error_code": -204, "relay_error_kind": "soter_session_expired"})).into_response(),
                            }
                        }
                        None if op == "finish_sign" => return Json(json!({"error_code": -204, "relay_error_kind": "soter_session_expired"})).into_response(),
                        None => None,
                    }
                } else {
                    None
                };
                let deadline = lease
                    .as_ref()
                    .map(|l| l.deadline.min(request_deadline))
                    .unwrap_or(request_deadline);
                let work = async {
                    if let Some(guard) = lease.as_mut() {
                        guard.dispatch();
                    }
                    match try_b_soter_layer(state, body, requested, b_target.as_deref()).await {
                        Some(mut b) => {
                            if needs_sign
                                && b.device.as_deref() == b_target.as_deref()
                                && b.value.get("error_code").and_then(Value::as_i64) == Some(-9)
                            {
                                // B's local active lease rejected init without touching HAL.
                                // This is a definite result, not unknown dispatch; release
                                // only our server reservation, never the B active session.
                                if let Some(guard) = lease.as_mut() {
                                    guard.completed();
                                }
                                return Some(b.value);
                            }
                            if needs_sign
                                && b.value.get("error").is_none()
                                && b.device.as_deref() != b_target.as_deref()
                            {
                                return Some(
                                    json!({"error_code": -204, "relay_error_kind": "soter_device_mismatch"}),
                                );
                            }
                            b_structural = b.unavailable;
                            served_device = b.device.clone();
                            if let Some(reply) = b.hardware_reply.clone() {
                                b_error_reply = Some(reply);
                            }
                            // -204（`SOTER_ERROR_OPERATEID_NULL`）在这台设备上就一个意思：这张
                            // 会话被后来的一笔 `init_sign` 顶掉了（TA 一台设备只留一个会话）。
                            // 拿 init 时缓存的参数重开一张、用同一个 challenge 再签一次。
                            if op == "finish_sign"
                                && b.value.get("error_code").and_then(Value::as_i64) == Some(-204)
                            {
                                match repair_clobbered_finish(
                                    state,
                                    body,
                                    requested,
                                    b.device.as_deref(),
                                )
                                .await
                                {
                                    Ok(Some(fixed)) => b.value = fixed,
                                    Ok(None) => {}
                                    Err(()) => {
                                        return Some(
                                            json!({"error_code": -204, "relay_error_kind": "soter_dispatch_unknown", "retryable": true}),
                                        )
                                    }
                                }
                            }
                            if op == "finish_sign" {
                                if let (Some(device), Some(session)) = (
                                    b.device.as_deref(),
                                    body.get("session").and_then(Value::as_i64),
                                ) {
                                    state.sign_sessions.forget_for(device, requested, session);
                                }
                            }
                            if b.value.get("error").is_none() {
                                if let Some(guard) = lease.as_mut() {
                                    guard.completed();
                                }
                            } else if needs_sign {
                                return Some(
                                    json!({"error_code": if op == "finish_sign" { -204 } else { -9 }, "relay_error_kind": "soter_dispatch_unknown", "retryable": true}),
                                );
                            }
                            if op == "init_sign"
                                && b.value.get("error_code").and_then(Value::as_i64) == Some(0)
                            {
                                if let Some(guard) = lease.as_mut() {
                                    let kept = b
                                        .value
                                        .get("session")
                                        .and_then(Value::as_i64)
                                        .filter(|s| *s != 0)
                                        .is_some_and(|s| guard.retain_session(s));
                                    if !kept {
                                        return Some(json!({"error_code": -204}));
                                    }
                                }
                            }
                            Some(b.value)
                        }
                        None => None,
                    }
                };
                match tokio::time::timeout_at(deadline, work).await {
                    Ok(result) => result,
                    Err(_) => return Json(json!({"error_code": if op == "finish_sign" { -204 } else { -9 }, "relay_error_kind": "soter_deadline"})).into_response(),
                }
            }
            "keybox" | "self_signed" => run_layer_soter(state, layer, body, requested).await,
            _ => None,
        };
        match result {
            Some(mut v)
                if layer == "b" && v.get("error_code").and_then(Value::as_i64) == Some(-9) =>
            {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("retryable".to_owned(), json!(true));
                }
                return Json(v).into_response();
            }
            Some(v) if v.get("error").is_none() => {
                // 服务端这两层的钥匙各是各的（`soter_mint` 的 `Store::auth` 按
                // `{device}|{uid}|{alias}` 存），槽位建在 B 上的钥匙它们手里没有，于是
                // 「用已有钥匙」的 op 会回 -5/-6/-8。那不是「做成了」，是「这层没这把
                // 钥匙」；当成成功递出去，App 会以为钥匙丢了 —— 实测 Duck Detector 就是
                // 这么报 soter damaged 的。这种答复不算数，接着往下走。
                if let Some(code) = server_layer_missed_the_slot(layer, op, &v) {
                    let detail = format!(
                        "{layer}: 这层没有这个槽位的材料（{code} {}）",
                        soter_error_name(code)
                    );
                    tracing::info!("soter: op={op} layer={layer} cannot serve this slot: {detail}");
                    last_error = Some(detail);
                    continue;
                }
                let code = v.get("error_code").and_then(Value::as_i64).unwrap_or(0);
                tracing::info!("soter: op={op} layer={layer} ok error_code={code}");
                state
                    .soter_gate
                    .record(requested, op, gate_uid, alias_arg, layer == "b", &v);
                if let Some(uid) = uid {
                    if let Some(pin) = layer_to_pin(layer, b_structural) {
                        crate::soter_mint::pin_layer(requested, uid, pin);
                    }
                }
                // 设备层的会话记下来：被顶掉的时候还能用同样的参数补一次（见
                // `repair_clobbered_finish`）。
                if layer == "b" && op == "init_sign" && code == 0 && served_device.is_some() {
                    if let Some(session) =
                        v.get("session").and_then(Value::as_i64).filter(|s| *s != 0)
                    {
                        state.sign_sessions.record(
                            served_device.as_deref().unwrap(),
                            requested,
                            session,
                            body.get("uid").and_then(Value::as_i64),
                            alias_arg,
                            body.get("challenge").and_then(Value::as_str),
                        );
                        tracing::info!(
                            "soter: 记下会话 {session}（uid={probe_uid} alias={probe_alias}），被顶掉时可以重签"
                        );
                    }
                }
                return Json(v).into_response();
            }
            Some(v) => {
                let msg = v
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_string();
                tracing::info!("soter: op={op} layer={layer} failed: {msg}");
                last_error = Some(format!("{layer}: {msg}"));
            }
            None => {
                tracing::info!("soter: op={op} layer={layer} 不管这个 op");
                last_error = Some(format!("{layer}: op '{op}' not handled by this layer"));
            }
        }
    }

    // 三层都没接住（init_sign 的话就是一张会话都没拿到）。
    let detail = last_error.unwrap_or_else(|| "no layer could serve the request".to_string());
    if let Some(reply) = b_error_reply {
        // 服务端那两层接不了这笔（材料在真机上，它们手里没有），把设备层的答复还回去：
        // App 该看到的是「这台设备真实出了什么毛病」，而不是「这把钥匙不在这层」。
        //
        // 码先取出来：`tracing` 宏展开里自带一个叫 `Value` 的东西，写在宏参数里会被它抢走
        // （`error[E0782]: expected a type, found a trait`）。
        let code = reply.get("error_code").and_then(Value::as_i64).unwrap_or(0);
        tracing::warn!(
            "soter: op={op} requested={requested} 服务端两层都接不了这个槽位（{detail}），\
             把设备层的答复还回去 code={code}"
        );
        return Json(reply).into_response();
    }
    tracing::warn!("soter: op={op} requested={requested} all layers failed (last: {detail})");
    json_err(
        StatusCode::SERVICE_UNAVAILABLE,
        &format!("no layer could serve SOTER op '{op}' ({detail})"),
    )
}

/// 保留在线点名设备以及已知会话的原设备；不能接活时由原回退层处理，不能换身份。
fn consistent_soter_target(
    requested_online: bool,
    requested: &str,
    remembered: Option<&str>,
    resolved: Option<String>,
) -> Option<String> {
    let required = if requested_online {
        Some(requested)
    } else {
        remembered
    };
    match required {
        Some(device) => resolved.filter(|target| target == device),
        None => resolved,
    }
}

/// B 端设备层：只派给调用方已解析并校验过的设备。
///
/// 一台都没有不算"这层不管这个 op"，而是这层没做成，所以返回带 `error` 的对象，
/// 让上层接着试服务端那两层。
async fn try_b_soter_layer(
    state: &AppState,
    body: &Value,
    requested: &str,
    target: Option<&str>,
) -> Option<BSoterLayer> {
    let op = body.get("op").and_then(Value::as_str).unwrap_or("probe");
    let Some(target) = target else {
        return Some(BSoterLayer {
            value: json!({
                "error": "no B-side device reporting SOTER support is online",
            }),
            unavailable: true,
            device: None,
            hardware_reply: None,
        });
    };
    if !requested.is_empty() && target != requested {
        tracing::warn!(
            "soter: requested device {requested} cannot serve SOTER; task served by {target} instead"
        );
    }
    let reply = enqueue_and_wait(
        state,
        "soter",
        body,
        target,
        state.cfg.soter_wait_result_timeout_secs,
    )
    .await;
    // Result device_id can be the TA's get_device_id output; use the dispatch
    // metadata instead. Query only this task: never scan the full task table on
    // the hot SOTER completion path.
    let device = (match reply.get("task_id").and_then(Value::as_str) {
        Some(task_id) => state.store.assigned_device_for_task(task_id).await,
        None => None,
    })
    .filter(|d| !d.is_empty());
    if reply.get("error").is_none() && device.as_deref() != Some(target) {
        return Some(BSoterLayer {
            value: json!({"error": "SOTER completion device mismatch", "error_code": -204}),
            unavailable: false,
            device: None,
            hardware_reply: None,
        });
    }
    if let Some(code) = soter_device_hard_failure(op, &reply) {
        return Some(BSoterLayer {
            value: json!({
                "error": format!(
                    "B-side device {target} failed SOTER op '{op}' with error_code {code} ({})",
                    soter_error_name(code)
                ),
            }),
            unavailable: true,
            device,
            hardware_reply: Some(reply),
        });
    }
    // 这里返回的是设备自己的答复，包括 `-26`「这会儿没人按指纹」和超时 —— 那是
    // 这笔没答好，不是这层做不了，得原样递给 App 让它重试。队列定向拒绝则是
    // 明确的能力结论，和 resolve_soter_target 的在线能力拒绝保持同一回退策略。
    let unavailable = soter_relay_marks_unavailable(&reply);
    Some(BSoterLayer {
        value: reply,
        device,
        unavailable,
        hardware_reply: None,
    })
}

/// B 端这一层的结论，外加「结构性地做不了」这个标记。
///
/// 标记只影响槽位钉层：没在线设备 / 设备没报 SOTER / TA 结构性报错（没开、ATTK
/// 没配、安全通道不通）算真做不了，可以考虑把钉子挪到服务端那两层；一次超时、
/// 一次 `-26` 都不算。
struct BSoterLayer {
    value: Value,
    /// Relay device that actually completed the queued task (not the TA device_id).
    device: Option<String>,
    unavailable: bool,
    /// 结构性失败时设备层那个原始答复（带着真错误码）。服务端那两层接不了同一个
    /// 槽位的时候要把它还给 App —— 该让人看见的是「这台设备真实出了什么毛病」，
    /// 而不是「这把钥匙不在这层」的 -5。
    hardware_reply: Option<Value>,
}

/// 这一轮下来该把 `(device, uid)` 槽位钉在哪一层（`None` = 别碰钉子）。
///
/// 一句话：真机接了这个 op 就钉真机；只有真机结构性地做不了，兜底层才有资格拿到
/// 钉子。真机接了却答个错（参数不齐、超时）时，钉子必须留在 `b` 上 —— 兜底层
/// 抢走钉子等于以后每轮都拿服务端自签的假料，App 手里的身份跟着换（PLC110 的
/// uid 10490 就是这么被钉到 self_signed 上的）。
fn layer_to_pin(served_layer: &str, b_structural: bool) -> Option<&str> {
    if served_layer == "b" || b_structural {
        Some(served_layer)
    } else {
        None
    }
}

/// 设备层答复里的 `error_code` 什么时候算「这层结构性地做不了」。
///
/// 只有结构性毛病才算：SOTER 没开（-12）、ATTK 没配（-13）、安全通道不通（-18）。
/// 其余负码都是「这笔没成」，得原样递给 App，不然会误判一台好机器：
///
/// - `-26 VERIFICATION_FAILED`：TA 要新鲜指纹，人不在/没按而已，按下就能成；
/// - `-5` / `-6`：材料还没建，App 就是靠它决定要不要 generate；
/// - `-7` / `-8` / `-9`：会话过期、没有匹配的 auth key、正在验证 —— 流程状态。
///
/// 把这些当成「这层没做成」，`run_soter_task` 就会把 `(device, uid)` 槽位挪到
/// 服务端自签那两层：App 手里换成假料，真机再也轮不到（PLC110 的 uid 10490
/// 就这么被钉到 self_signed 上，之后一轮流程都回不到真机）。
/// Queue-directed relay verdicts that mean the B device cannot serve SOTER at all.
/// Timeouts and ordinary SOTER operation errors deliberately do not match.
fn soter_relay_marks_unavailable(reply: &Value) -> bool {
    matches!(
        reply.get("relay_error_kind").and_then(Value::as_str),
        Some("soter_unsupported" | "soter_nosign")
    )
}

fn soter_device_hard_failure(op: &str, reply: &Value) -> Option<i64> {
    let code = reply.get("error_code").and_then(Value::as_i64)?;
    if !matches!(
        op,
        "get_device_id"
            | "generate_ask_key_pair"
            | "generate_auth_key_pair"
            | "init_sign"
            | "finish_sign"
    ) {
        return None;
    }
    matches!(
        code,
        SOTER_NOT_ENABLED | SOTER_ATTK_NOT_PROVISIONED | SOTER_SECURE_HW_FAILED
    )
    .then_some(code)
}

/// 结构性错误码：这几种换下一层不算亏，设备这会儿真的做不了。
const SOTER_NOT_ENABLED: i64 = -12;
const SOTER_ATTK_NOT_PROVISIONED: i64 = -13;
const SOTER_SECURE_HW_FAILED: i64 = -18;

/// SOTER 错误码的名字（腾讯 `SoterErrorCode`），只为日志好读。只列跟换层判断有关的。
fn soter_error_name(code: i64) -> &'static str {
    match code {
        0 => "SOTER_ERROR_OK",
        -5 => "SOTER_ERROR_ASK_NOT_READY",
        -6 => "SOTER_ERROR_AUTH_KEY_NOT_READY",
        -7 => "SOTER_ERROR_SESSION_OUT_OF_TIME",
        -8 => "SOTER_ERROR_NO_AUTH_KEY_MATCHED",
        -9 => "SOTER_ERROR_IS_AUTHING",
        -12 => "SOTER_ERROR_SOTER_NOT_ENABLED",
        -13 => "SOTER_ERROR_ATTK_NOT_PROVISIONED",
        -18 => "SOTER_ERROR_SECURE_HW_COMMUNICATION_FAILED",
        -20 => "SOTER_ERROR_ATTK_ALREADY_PROVISIONED",
        -25 => "SOTER_ERROR_INVALID_KEY_BLOB",
        -26 => "SOTER_ERROR_VERIFICATION_FAILED",
        -29 => "SOTER_ERROR_UNEXPECTED_NULL_POINTER",
        -201 => "SOTER_ERROR_UID_NULL",
        -204 => "SOTER_ERROR_OPERATEID_NULL",
        -1000 => "SOTER_ERROR_UNKNOWN_ERROR",
        _ => "unknown SOTER error",
    }
}

/// 「用已有钥匙」的 op：槽位得在同一层里把 ASK/AuthKey 建出来过，这几笔才可能成。
///
/// `has_auth_key` / `remove_auth_key` 这类不在里面 —— 它们的 -5 是正经答案
/// （「你这把钥匙不在」），App 就是靠它决定要不要重建。
const SOTER_KEY_USING_OPS: &[&str] = &["init_sign", "finish_sign", "export_auth_key_public_key"];

/// 服务端那两层答成「这层没这个槽位的材料」时的那几个码。
const SOTER_ASK_NOT_READY: i64 = -5;
const SOTER_AUTH_KEY_NOT_READY: i64 = -6;
const SOTER_NO_AUTH_KEY_MATCHED: i64 = -8;

/// 服务端那两层（keybox / self_signed）这答复算不算「没材料、干不了这一笔」。
///
/// 这两层各自维护自己的 ASK/AuthKey，槽位在真机上建的钥匙它们手里没有，
/// `init_sign` / `finish_sign` / `export_auth_key_public_key` 就会回 -5/-6/-8。
/// 那不是说操作成功了，得当成「这层不管这一笔」继续往下试。
///
/// 设备层（`b`）不适用：那是这套流程里权威的那台，它的 -5 就是「这把钥匙不在」，
/// 必须原样递给 App（`soter_device_hard_failure` 的注释里说的是同一件事）。
fn server_layer_missed_the_slot(layer: &str, op: &str, reply: &Value) -> Option<i64> {
    if layer == "b" || !SOTER_KEY_USING_OPS.contains(&op) {
        return None;
    }
    let code = reply.get("error_code").and_then(Value::as_i64)?;
    matches!(
        code,
        SOTER_ASK_NOT_READY | SOTER_AUTH_KEY_NOT_READY | SOTER_NO_AUTH_KEY_MATCHED
    )
    .then_some(code)
}

/// 服务端那两层：`keybox` 层得先从库里把这台设备名下的服务端身份私钥拿出来
/// （只有 RSA 才签得动 SOTER），拿不到就让下一层试。
async fn run_layer_soter(
    state: &AppState,
    layer: &str,
    body: &Value,
    device_id: &str,
) -> Option<Value> {
    let db = state.db.clone();
    let layer = layer.to_string();
    let body = body.clone();
    let device_id = device_id.to_string();
    let result = tokio::task::spawn_blocking(move || {
        let key_pem = if layer == "keybox" {
            // keybox 层只认 RSA：EC 身份签不动 SOTER，那就是这层没物料。
            db.and_then(|db| match db.get_device_identity_by_id(&device_id, "rsa") {
                Ok(Some(identity)) => Some(identity.private_key_pem_cipher),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(
                        "soter: keybox layer could not load the server identity for {device_id}: {e:#}"
                    );
                    None
                }
            })
        } else {
            None
        };
        crate::soter_mint::run(&layer, &device_id, &body, key_pem.as_deref())
    })
    .await;
    match result {
        Ok(v) => v,
        Err(e) => Some(json!({ "error": format!("spawn_blocking join error: {e}") })),
    }
}

// ---------------------------------------------------------------------------
// Client report (A-side diagnostics)
// ---------------------------------------------------------------------------

pub async fn client_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")).await {
        return *r;
    }
    let Some(db) = state.db.clone() else {
        return Json(json!({ "status": "ok", "stored": false })).into_response();
    };
    let row = crate::db::ClientReportRow {
        device_id: body
            .get("device_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        level: body
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("info")
            .to_string(),
        code: body
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        message: body
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        detail_json: body
            .get("detail")
            .map(|d| d.to_string())
            .unwrap_or_else(|| "{}".to_string()),
        client_ip: client_ip(&headers),
        user_agent: headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let result = tokio::task::spawn_blocking(move || db.insert_client_report(&row)).await;
    match result {
        Ok(Ok(())) => Json(json!({ "status": "ok" })).into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("join error: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// B-side endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PollQuery {
    pub device_id: String,
    pub machine_id: Option<String>,
    pub timeout: Option<u64>,
    /// 设备能力声明（逗号分隔，例如 `soter,strongbox`）。缺失 = 没上报，
    /// 空串 = 上报了一个都没有。见 `queue::DeviceCaps::parse`。
    pub caps: Option<String>,
}

pub async fn b_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PollQuery>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("b")).await {
        return *r;
    }
    if q.device_id.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "device_id required");
    }
    let machine_id = q.machine_id.unwrap_or_default();

    // Concurrency guard: reject if another machine is actively serving this device.
    if let Some(active) = state.store.get_active_machine_id(&q.device_id).await {
        if !machine_id.is_empty() && active != machine_id {
            return json_err(
                StatusCode::CONFLICT,
                "another machine is already serving this device",
            );
        }
    }

    let timeout_secs = q.timeout.unwrap_or(state.cfg.poll_timeout_secs);
    let timeout = Duration::from_secs(timeout_secs.min(120));

    match state
        .store
        .pop_for_b(
            &q.device_id,
            &machine_id,
            crate::queue::DeviceCaps::parse(q.caps.as_deref()),
            timeout,
        )
        .await
    {
        Some(task) => {
            // Which device actually took the task — the counterpart of the
            // `b_layer` log line, so a mismatch is visible from the log alone.
            tracing::info!(
                "b_poll: device={} machine={} claimed task={} type={} requested={}",
                q.device_id,
                if machine_id.is_empty() {
                    "<none>"
                } else {
                    machine_id.as_str()
                },
                task.task_id,
                task.task_type,
                // NB: inside tracing's macro `Value` resolves to tracing's own
                // Value trait, so go through a closure instead of Value::as_str.
                task.payload
                    .get("device_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            );
            Json(json!({
                "task_id": task.task_id,
                "task_type": task.task_type,
                "payload": task.payload,
                "target_device_id": task.target_device_id,
            }))
            .into_response()
        }
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

pub async fn b_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("b")).await {
        return *r;
    }
    let task_id = body
        .get("task_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let result = body.get("result").cloned().unwrap_or(Value::Null);
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if task_id.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "task_id required");
    }
    match state
        .store
        .complete_task(&task_id, result, &device_id)
        .await
    {
        Ok(()) => Json(json!({ "status": "ok" })).into_response(),
        Err(_) => json_err(StatusCode::NOT_FOUND, "task not found"),
    }
}

pub async fn b_upload_keybox_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("b")).await {
        return *r;
    }
    let fulfill = state.fulfill.clone();
    let b = body.clone();
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let result = tokio::task::spawn_blocking(move || {
        fulfill.try_handle_b_upload_keybox_identity(&device_id, &b)
    })
    .await;
    match result {
        Ok(Some(v)) => {
            // Validation / parse failures are client errors: surface them as
            // 400 (with the specific reason) instead of a 200-with-error body.
            if let Some(err) = v.get("error").and_then(Value::as_str) {
                json_err(StatusCode::BAD_REQUEST, err)
            } else {
                Json(v).into_response()
            }
        }
        Ok(None) => json_err(
            StatusCode::BAD_REQUEST,
            "server_keybox mode required for identity upload",
        ),
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("join error: {e}"),
        ),
    }
}

pub async fn b_revoke_server_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("b")).await {
        return *r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let device_id = body
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let result =
        tokio::task::spawn_blocking(move || db.set_device_identity_active(&device_id, false)).await;
    match result {
        Ok(Ok(())) => Json(json!({ "status": "ok" })).into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("join error: {e}"),
        ),
    }
}

pub async fn admin_cancel_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // This is an admin operation: require a valid admin session (X-Relay-Session),
    // not just any A/B token.
    let sid = headers
        .get("x-relay-session")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !state.auth.check_session(&sid) {
        return json_err(
            StatusCode::UNAUTHORIZED,
            "unauthorized: missing or invalid session",
        );
    }
    let task_id = body
        .get("task_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if task_id.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "task_id required");
    }
    match state.store.cancel_task(&task_id).await {
        Ok(()) => Json(json!({ "status": "ok" })).into_response(),
        Err(_) => json_err(StatusCode::NOT_FOUND, "task not found"),
    }
}

/// GET /api/keybox/public/ — 把服务端池子里的公开 keybox 发给 A 端。
///
/// A 端那边是用 curl 取下来再 atob 的，所以这里直接回 base64 文本，不是 JSON。
/// 匿名可取：里面的东西本来就是从公开仓库采的，没什么可保护的。
pub async fn public_keybox(State(state): State<AppState>) -> Response {
    let Some(db) = state.db.as_ref() else {
        return json_err(StatusCode::SERVICE_UNAVAILABLE, "no database");
    };
    // EC 和 RSA 各捞一份 —— 以前是「EC 优先，拿到就停」，A 端因此永远只拿到半套
    // 材料，请求落到缺的那种算法上就只能报错。同一份 keybox 文件里的 EC/RSA 两段
    // 入库时本就是分开的两行，这里按算法各扫一遍；只凑得到一种就发一种（A 端会用
    // 自己内置的自签材料补缺）。采到的身份可能挂在主 device_id 上，也可能挂在
    // -1/-2 这样的后缀上 —— 后缀范围跟着采集端的上限走，两边写死后加了一边另一边
    // 就白搭。
    let base = crate::autokeybox::device_id_for("public");
    let mut candidates = vec![base.clone()];
    for n in 1..crate::autokeybox::PUBLIC_MAX_IDENTITIES {
        candidates.push(format!("{base}-{n}"));
    }
    let mut picked: Vec<(String, crate::db::DeviceIdentity)> = Vec::new();
    for algo in ["ec", "rsa"] {
        'scan: for device_id in &candidates {
            match db.get_device_identity_by_id(device_id, algo) {
                Ok(Some(id)) => {
                    // 只认采集器写进去的那些。device-b-2 这类名字是自动源专用槽位，
                    // 但有台真设备恰好叫这个名字的话，它的私钥不能就这么匿名发出去。
                    let mid = id.machine_id.as_str();
                    if mid != "auto:public" && mid != "auto-cover:public" {
                        tracing::warn!(
                            "public_keybox device_id={device_id} 是 {} 写的，不是公开源，跳过",
                            mid
                        );
                        continue;
                    }
                    // 发出去之前再看一眼吊销名单：万一这份是名单更新之前采进来的，
                    // 发过去就是让对面白跑一次，顺手把这行删了等下一轮采集重填。
                    if let Some((serial, status)) =
                        crate::attstatus::revoked_reason(&id.certificate_chain_pem)
                    {
                        tracing::warn!(
                            "public_keybox device_id={device_id} 已吊销（serial={serial} {status}），删掉换下一个"
                        );
                        if let Err(e) = db.delete_device_identity(device_id) {
                            tracing::warn!("public_keybox 删 {device_id} 失败: {e}");
                        }
                        continue;
                    }
                    picked.push((device_id.clone(), id));
                    break 'scan;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("public_keybox lookup failed device_id={device_id} err={e}")
                }
            }
        }
    }
    if picked.is_empty() {
        // 池子里一个能用的都没有：要么还没采到，要么采到的全进了吊销名单。
        // 这里特意回「404 + 空 body」而不是 JSON 错误体 —— A 端拿 curl 取完只判断
        // 「有没有输出」，输出为空它就弹自己那句「未找到有效密钥箱」；回 JSON 的话
        // 对面 atob 会抛异常，弹出来的是「设置失败」，看着像服务端坏了。
        tracing::warn!("public_keybox 池子里没有可用身份（未采到或全被吊销），回 404 空 body");
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain; charset=utf-8")],
            "",
        )
            .into_response();
    }
    // 两种算法可能落在不同槽位上，XML 上挂哪个 device_id 都无所谓，A 端只认材料。
    let xml_device_id = picked[0].0.clone();
    let keys: Vec<(String, String, String)> = picked
        .iter()
        .map(|(_, id)| {
            (
                id.algorithm.clone(),
                id.private_key_pem_cipher.clone(),
                id.certificate_chain_pem.clone(),
            )
        })
        .collect();
    let xml = crate::keybox::build_keybox_xml_with_keys(&xml_device_id, &keys);
    tracing::info!(
        "public_keybox served device_id={} algorithms={:?} xml_bytes={}",
        xml_device_id,
        keys.iter()
            .map(|(algo, _, _)| algo.as_str())
            .collect::<Vec<_>>(),
        xml.len()
    );
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        b64,
    )
        .into_response()
}

#[cfg(test)]
mod soter_device_layer_tests {
    use super::{soter_device_hard_failure, soter_error_name, soter_relay_marks_unavailable};
    use serde_json::json;

    #[test]
    fn queue_relay_capability_markers_are_unavailable_but_timeout_is_not() {
        assert!(soter_relay_marks_unavailable(&json!({
            "error": "SOTER unsupported",
            "relay_error_kind": "soter_unsupported",
        })));
        assert!(soter_relay_marks_unavailable(&json!({
            "error": "SOTER signing disabled",
            "relay_error_kind": "soter_nosign",
        })));
        assert!(!soter_relay_marks_unavailable(&json!({
            "error": "task timeout",
            "relay_error_kind": "timeout",
        })));
        assert!(!soter_relay_marks_unavailable(&json!({
            "error": "task timeout",
        })));
    }

    #[test]
    fn only_structural_device_errors_are_a_layer_failure() {
        // 设备真的做不了：没开 SOTER、ATTK 没配、安全通道不通。
        assert_eq!(
            soter_device_hard_failure("generate_auth_key_pair", &json!({ "error_code": -13 })),
            Some(-13)
        );
        assert_eq!(
            soter_device_hard_failure("init_sign", &json!({ "error_code": -12 })),
            Some(-12)
        );
        assert_eq!(
            soter_device_hard_failure("finish_sign", &json!({ "error_code": -18 })),
            Some(-18)
        );
    }

    #[test]
    fn a_sign_failure_that_is_not_structural_stays_an_answer() {
        // 实测的两种误判，都把一个好好的机器弄瘸过：
        // - 一加 11 的 `finish_sign` 回 -26：TA 要新鲜指纹，人不在而已，按下就能签；
        // - PLC110 的 op 被 15s 超时打断，槽位从此挪到 self_signed。
        for op in ["init_sign", "finish_sign", "generate_auth_key_pair"] {
            for code in [-26, -25, -5, -6, -7, -8, -9, -20, -1000] {
                assert_eq!(
                    soter_device_hard_failure(op, &json!({ "error_code": code })),
                    None,
                    "{op} {code}"
                );
            }
        }
    }

    #[test]
    fn a_lookup_answer_stays_an_answer() {
        // “还没建”是 App 要看的正常回答，不能当失败。
        for op in [
            "has_ask_already",
            "has_auth_key",
            "export_ask_public_key",
            "export_auth_key_public_key",
            "remove_auth_key",
            "remove_all_uid_key",
        ] {
            assert_eq!(
                soter_device_hard_failure(op, &json!({ "error_code": -5 })),
                None,
                "{op}"
            );
            assert_eq!(
                soter_device_hard_failure(op, &json!({ "error_code": -6 })),
                None,
                "{op}"
            );
        }
        // 成功、以及 relay 自己报的失败（没有 error_code），都轮不到这条判断。
        assert_eq!(
            soter_device_hard_failure("finish_sign", &json!({ "error_code": 0 })),
            None
        );
        assert_eq!(
            soter_device_hard_failure("finish_sign", &json!({ "error": "task timeout" })),
            None
        );
    }

    #[test]
    fn a_real_device_keeps_the_slot_pin() {
        use super::layer_to_pin;
        // 真机答上了：钉它。
        assert_eq!(layer_to_pin("b", false), Some("b"));
        // 真机没接住（参数不齐 / 超时 / -26），兜底层接上了也不能留钉子。
        assert_eq!(layer_to_pin("self_signed", false), None);
        assert_eq!(layer_to_pin("keybox", false), None);
        // 真机结构性地做不了（一台能接的设备都没有），兜底层把流程接上就该钉住，
        // 下一轮别再拿同一份请求去碰一台做不了的机器。
        assert_eq!(layer_to_pin("self_signed", true), Some("self_signed"));
        assert_eq!(layer_to_pin("keybox", true), Some("keybox"));
        assert_eq!(layer_to_pin("b", true), Some("b"));
    }

    #[test]
    fn finish_route_does_not_follow_a_new_balancer_choice() {
        use super::consistent_soter_target;
        assert_eq!(
            consistent_soter_target(false, "offline", Some("a"), Some("a".into())),
            Some("a".into())
        );
        assert_eq!(
            consistent_soter_target(false, "offline", Some("a"), Some("b".into())),
            None
        );
        assert_eq!(
            consistent_soter_target(true, "b", Some("a"), Some("b".into())),
            Some("b".into())
        );
        assert_eq!(
            consistent_soter_target(true, "b", None, Some("a".into())),
            None
        );
        assert_eq!(
            consistent_soter_target(false, "offline", None, Some("a".into())),
            Some("a".into())
        );
    }

    #[test]
    fn known_codes_are_named_for_the_log() {
        assert_eq!(soter_error_name(-26), "SOTER_ERROR_VERIFICATION_FAILED");
        assert_eq!(soter_error_name(-8), "SOTER_ERROR_NO_AUTH_KEY_MATCHED");
        assert_eq!(soter_error_name(-3), "unknown SOTER error");
    }
}

#[cfg(test)]
mod strongbox_smart_tests {
    use super::{chain_attestation_security_level, refuse_strongbox_json, strongbox_b_kind};
    use serde_json::json;

    #[test]
    fn refuse_body_uses_aosp_kinds() {
        // 拒绝模式回给 A 端的形状：error + relay_error_kind。A 端按 kind 翻成
        // KeyMint -74 / -68，也就是 AOSP 的「支持但没预制密钥 / 硬件类型不可用」。
        let v = refuse_strongbox_json(
            "strongbox_unprovisioned",
            "strongbox not supported: no usable StrongBox on the serving device",
        );
        assert_eq!(
            v.get("relay_error_kind").and_then(|x| x.as_str()),
            Some("strongbox_unprovisioned")
        );
        assert!(v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap()
            .contains("no usable StrongBox"));

        // B 端自己报了 verdict 时原样带上（比如硬件类型不可用）。
        let named = refuse_strongbox_json("strongbox_unavailable", "hardware type unavailable");
        assert_eq!(
            named.get("relay_error_kind").and_then(|x| x.as_str()),
            Some("strongbox_unavailable")
        );
    }

    #[test]
    fn classifies_relay_strongbox_errors() {
        // Present-but-broken StrongBox verdicts -> surfaced to the app.
        assert_eq!(
            strongbox_b_kind(&json!({
                "error": "strongbox not supported: HAL exists but attestation keys not provisioned (factory provisioning issue)"
            })),
            Some("strongbox_unprovisioned")
        );
        assert_eq!(
            strongbox_b_kind(&json!({
                "error": "strongbox not supported: HAL exists but hardware type unavailable"
            })),
            Some("strongbox_unavailable")
        );

        // Not a StrongBox-HAL verdict -> server keybox / A-side local fallback.
        assert_eq!(
            strongbox_b_kind(&json!({
                "error": "strongbox not supported: StrongBox HAL service not present on this device"
            })),
            None
        );
        assert_eq!(
            strongbox_b_kind(&json!({ "error": "task timeout: no B-side result" })),
            None
        );
        assert_eq!(
            strongbox_b_kind(
                &json!({ "error": "strongbox not supported: strongbox generateKey failed" })
            ),
            None
        );
        assert_eq!(
            strongbox_b_kind(&json!({ "error": "some native ROM exception message" })),
            None
        );
        assert_eq!(strongbox_b_kind(&json!({ "cert_chain": [] })), None);
        assert_eq!(strongbox_b_kind(&json!({ "cert_chain": ["Zm9v"] })), None);
    }

    /// Smart mode only accepts a chain that is itself StrongBox-tagged, so a
    /// chain it cannot read has to come back `None` — that is what lets the
    /// fallback continue to the server keybox instead of handing a
    /// possibly-demoted chain to the app.  (Reading a real chain is covered by
    /// the cert tests; what matters here is the unreadable case.)
    #[test]
    fn unreadable_chains_have_no_security_level() {
        assert_eq!(chain_attestation_security_level(&json!({})), None);
        assert_eq!(
            chain_attestation_security_level(&json!({ "cert_chain": [] })),
            None
        );
        assert_eq!(
            chain_attestation_security_level(&json!({ "cert_chain": "not-an-array" })),
            None
        );
        assert_eq!(
            chain_attestation_security_level(&json!({ "cert_chain": ["bm90IGRlcg=="] })),
            None
        );
    }
}

#[cfg(test)]
mod key_missing_substitution_tests {
    use super::*;

    /// 真机说了「没这个 key」⇒ 后面的层不许顶替。
    #[test]
    fn device_layer_missing_key_blocks_substitution() {
        assert!(b_said_key_missing(
            "b",
            "no key for alias 'ommega-remote-80a3ffcdf5153abf' (call attest first)"
        ));
    }

    /// 别的层的同类措辞不算：keybox 自己说没 session 是另一回事。
    #[test]
    fn other_layers_do_not_block() {
        assert!(!b_said_key_missing("keybox", "no key for alias 'x'"));
        assert!(!b_said_key_missing("self_signed", "no key for alias 'x'"));
    }

    /// 超时 / 没设备在线这类不是「key 不在这」，该走回退阶梯。
    #[test]
    fn timeouts_are_not_key_missing() {
        assert!(!b_said_key_missing("b", "task timeout: no B-side result"));
        assert!(!b_said_key_missing("b", "no B-side device online"));
        assert!(!b_said_key_missing("b", "empty cert chain from B device"));
    }
}

#[cfg(test)]
mod layer_failure_msg_tests {
    use super::*;
    use serde_json::json;

    /// 关键回归：B 端回了真实错误、且没交链 —— 报的必须是那个错误本身，
    /// 不能再被吞成 "empty cert chain from B device"。
    #[test]
    fn error_wins_over_missing_chain() {
        let v = json!({
            "error": "real keymint android.hardware.security.keymint.IKeyMintDevice/default \
                      generateKey failed [km_error=-49]: ServiceSpecific"
        });
        let msg = layer_failure_msg("attest", "b", &v);
        assert!(msg.contains("km_error=-49"), "got: {msg}");
        assert!(!msg.contains("empty cert chain"), "got: {msg}");
    }

    /// 任务超时也是 `error`，同样不能被说成空链。
    #[test]
    fn timeout_error_is_reported() {
        let v = json!({ "error": "task timeout: no B-side result" });
        assert_eq!(
            layer_failure_msg("attest", "b", &v),
            "task timeout: no B-side result"
        );
    }

    /// keybox 层“没这个设备的身份”也该说人话地透出来。
    #[test]
    fn layer_error_is_reported() {
        let v = json!({ "error": "no stored identity for device-b-xxxx" });
        assert_eq!(
            layer_failure_msg("attest", "keybox", &v),
            "no stored identity for device-b-xxxx"
        );
    }

    /// 真的只给了空链（没有 error）时才说空链，并且要指明是哪一层。
    #[test]
    fn empty_chain_is_reported_per_layer() {
        let v = json!({ "cert_chain": [] });
        assert_eq!(
            layer_failure_msg("attest", "b", &v),
            "empty cert chain from B device"
        );
        assert_eq!(
            layer_failure_msg("attest", "keybox", &v),
            "empty cert chain from layer 'keybox'"
        );
        // 链字段干脆没有，对 attest 来说同样是空链。
        assert_eq!(
            layer_failure_msg("attest", "b", &json!({})),
            "empty cert chain from B device"
        );
    }

    /// sign/decrypt 不涉及链：没 error 就是 unknown error，不会被说成空链。
    #[test]
    fn non_attest_without_error_is_unknown() {
        assert_eq!(layer_failure_msg("sign", "b", &json!({})), "unknown error");
        assert_eq!(
            layer_failure_msg("decrypt", "b", &json!({})),
            "unknown error"
        );
    }

    /// 空白 error 不算“给了原因”，退回空链判定。
    #[test]
    fn blank_error_is_not_a_reason() {
        let v = json!({ "error": "   ", "cert_chain": [] });
        assert_eq!(
            layer_failure_msg("attest", "b", &v),
            "empty cert chain from B device"
        );
    }
}

#[cfg(test)]
mod soter_slot_miss_tests {
    use super::*;
    use serde_json::json;

    /// 补签的请求体：op 换成 init_sign，参数用缓存的那三个，session 拿掉。
    #[test]
    fn a_repair_request_turns_a_finish_into_an_init() {
        let body = json!({
            "op": "finish_sign",
            "session": 123,
            "device_id": "device-b-c3f204aa",
            "machine_id": "PLC110",
        });
        let out = repair_init_body(&body, 10043, "slot_a", "aabbcc");
        assert_eq!(out.get("op").and_then(Value::as_str), Some("init_sign"));
        assert_eq!(out.get("uid").and_then(Value::as_i64), Some(10043));
        assert_eq!(out.get("alias").and_then(Value::as_str), Some("slot_a"));
        assert_eq!(out.get("challenge").and_then(Value::as_str), Some("aabbcc"));
        assert!(out.get("session").is_none(), "init_sign 不该带着旧会话");
        // 设备/机器的路由信息得留着，不然这层不知道该找谁。
        assert_eq!(
            out.get("device_id").and_then(Value::as_str),
            Some("device-b-c3f204aa")
        );
    }

    /// 回归（2026-09-30，Duck Detector 那个 -5）：槽位的钥匙建在真机上，keybox 层
    /// 手里没有，`init_sign` 回 -5 —— 这不是「签好了」，得接着往下试。
    #[test]
    fn a_server_layer_without_the_slot_material_is_not_a_success() {
        for layer in ["keybox", "self_signed"] {
            let reply = json!({ "op": "init_sign", "error_code": -5 });
            assert_eq!(
                server_layer_missed_the_slot(layer, "init_sign", &reply),
                Some(-5),
                "{layer} 回 -5 不该被当成成功"
            );
        }
        for (op, code) in [
            ("finish_sign", -5),
            ("finish_sign", -6),
            ("export_auth_key_public_key", -8),
        ] {
            let reply = json!({ "op": op, "error_code": code });
            assert_eq!(
                server_layer_missed_the_slot("keybox", op, &reply),
                Some(code)
            );
        }
    }

    /// 真机是权威：它回什么就是什么，不能因为 -5 就把这台设备的话丢掉。
    #[test]
    fn the_device_layer_keeps_its_own_verdict() {
        let reply = json!({ "op": "init_sign", "error_code": -5 });
        assert_eq!(server_layer_missed_the_slot("b", "init_sign", &reply), None);
    }

    /// `has_auth_key` / `remove_auth_key` 这类 op 的 -5 是正经答案（「你没这把钥匙」），
    /// App 就是靠它决定重建，不能被当成层失败。
    #[test]
    fn a_probe_op_keeps_its_not_found_answer() {
        let reply = json!({ "op": "has_auth_key", "error_code": -5 });
        assert_eq!(
            server_layer_missed_the_slot("keybox", "has_auth_key", &reply),
            None
        );
        let reply = json!({ "op": "remove_auth_key", "error_code": -6 });
        assert_eq!(
            server_layer_missed_the_slot("keybox", "remove_auth_key", &reply),
            None
        );
    }

    /// 真做成的答复照旧算成功。
    #[test]
    fn a_real_answer_is_still_a_success() {
        let reply = json!({ "op": "init_sign", "error_code": 0, "session": 42 });
        assert_eq!(
            server_layer_missed_the_slot("keybox", "init_sign", &reply),
            None
        );
    }

    /// 别的码（比如 -26 没指纹）也不该被吃掉：那是 App 自己那套错误码。
    #[test]
    fn other_codes_are_left_alone() {
        let reply = json!({ "op": "init_sign", "error_code": -26 });
        assert_eq!(
            server_layer_missed_the_slot("keybox", "init_sign", &reply),
            None
        );
        assert_eq!(
            server_layer_missed_the_slot("keybox", "init_sign", &json!({ "op": "init_sign" })),
            None
        );
    }
}
