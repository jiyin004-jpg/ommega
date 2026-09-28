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
fn check_auth(
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
    if !state.auth.check_token(Some(&token), role, &ip) {
        if !state.auth.allow_invalid(&ip) {
            return Err(Box::new(json_err(
                StatusCode::TOO_MANY_REQUESTS,
                "too many invalid requests",
            )));
        }
        return Err(Box::new(auth_fail()));
    }

    // Valid auth: rate limit by token (or IP when no token).
    let rl_key = if token.is_empty() { ip } else { token.clone() };
    if !state.auth.allow(&rl_key) {
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
    let timeout = Duration::from_secs(timeout_secs);
    match state.store.wait_for_result(&task_id, timeout).await {
        Some(mut result) => {
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
                // The empty-chain text must name the layer that produced it: the
                // keybox/self_signed layers return the same shape, so the old
                // wording ("from B device") sent operators looking at the wrong
                // side. `device` is the *requested* device — the `b_poll` line
                // right above shows which device actually served a substitution.
                let msg = if attest_chain_empty(task_type, &v) {
                    if layer == "b" {
                        "empty cert chain from B device".to_string()
                    } else {
                        format!("empty cert chain from layer '{layer}'")
                    }
                } else {
                    v.get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error")
                        .to_string()
                };
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
                        let dmsg = if attest_chain_empty(task_type, &dv) {
                            "empty cert chain".to_string()
                        } else {
                            dv.get("error")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown error")
                                .to_string()
                        };
                        tracing::info!(
                            "run_a_side_task: type={task_type} layer=b strongbox demotion retry failed: {dmsg}"
                        );
                    }
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
            "all fulfilment layers failed for device {device_id}: {}",
            last_error.unwrap_or_else(|| "unknown".to_string())
        ),
    )
}

// ---------------------------------------------------------------------------
// Basic endpoints
// ---------------------------------------------------------------------------

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
    if let Err(r) = check_auth(&state, &headers, None) {
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
    if let Err(r) = check_auth(&state, &headers, Some("a")) {
        return *r;
    }
    run_a_side_task(&state, "attest", &body).await
}

pub async fn sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")) {
        return *r;
    }
    run_a_side_task(&state, "sign", &body).await
}

pub async fn decrypt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")) {
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
    if let Err(r) = check_auth(&state, &headers, Some("a")) {
        return *r;
    }
    run_soter_task(&state, &body).await
}

/// SOTER 转发：跟认证共用同一套三层链，差别只在三层的实现。
///
/// 层序（`physical` / `serverbox` 两种模式只差优先级）：
///   physical:   B 端设备层 -> 服务端密钥层(keybox) -> 服务端自签层
///   serverbox:  服务端密钥层 -> B 端设备层 -> 服务端自签层
/// 哪一层没做成（没物料、没能力、请求失败）就回退下一层，三层都不行才把错误回
/// 给 A 端；A 端据此用本地密钥，本地也不行就透原生。
///
/// B 端层的路由规则跟认证一样（见 `queue::resolve_soter_target`）：点名的设备
/// 支持 SOTER 就用它，否则按负载在报过支持的设备里挑一台；一台都没有就是这层
/// 没做成。SOTER 的答案本来是目标设备 TEE 里签的，换台设备就换了身份，所以这
/// 一层没有"拿别的设备的密钥顶一下"这回事，只能换设备。
///
/// 服务端两层（见 `soter_mint`）用服务端自己的 RSA 物料现造一份自洽的 ASK，让
/// A 端本地流程先闭环；腾讯那边的根谁也拿不到，这两层不假装自己是腾讯认得的东西。
async fn run_soter_task(state: &AppState, body: &Value) -> Response {
    if !body.is_object() {
        return json_err(StatusCode::BAD_REQUEST, "json object body required");
    }
    let requested = body.get("device_id").and_then(Value::as_str).unwrap_or("");
    let op = body.get("op").and_then(Value::as_str).unwrap_or("probe");
    tracing::info!(
        "soter: op={op} requested={}",
        if requested.is_empty() {
            "<any>"
        } else {
            requested
        }
    );

    let serverbox = state.fulfill.is_enabled();
    let order: &[&str] = if serverbox {
        &["keybox", "b", "self_signed"]
    } else {
        &["b", "keybox", "self_signed"]
    };

    let mut last_error: Option<String> = None;

    // 这个槽位已经定过层就把它排到最前面：同一槽位的材料必须只出自一层，否则 App
    // 手里会出现一半 B 的一半 keybox 的状态（导出的公钥和签名的私钥都对不上）。
    // 它这会儿不灵就照旧往下换 —— 换层是策略，只是换成了钉子跟着挪。
    let uid = body.get("uid").and_then(Value::as_i64).map(|v| v as i32);
    let mut layers: Vec<&str> = Vec::with_capacity(order.len());
    if let (false, Some(uid)) = (requested.is_empty(), uid) {
        if let Some(pinned) = crate::soter_mint::pinned_layer(requested, uid) {
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
    if layers.is_empty() {
        layers.extend(order.iter().copied());
    }

    for &layer in &layers {
        let result = match layer {
            "b" => try_b_soter_layer(state, body, requested).await,
            "keybox" | "self_signed" => run_layer_soter(state, layer, body, requested).await,
            _ => None,
        };
        match result {
            Some(v) if v.get("error").is_none() => {
                tracing::info!("soter: op={op} layer={layer} ok");
                // 谁服务了这个槽位就把它钉在谁身上，下次先问它。
                if let Some(uid) = uid {
                    crate::soter_mint::pin_layer(requested, uid, layer);
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

    let detail = last_error.unwrap_or_else(|| "no layer could serve the request".to_string());
    tracing::warn!("soter: op={op} requested={requested} all layers failed (last: {detail})");
    json_err(
        StatusCode::SERVICE_UNAVAILABLE,
        &format!("no layer could serve SOTER op '{op}' ({detail})"),
    )
}

/// B 端设备层：优先点名的设备，它做不了就按负载换一台报过支持的。
///
/// 一台都没有不算"这层不管这个 op"，而是这层没做成，所以返回带 `error` 的对象，
/// 让上层接着试服务端那两层。
async fn try_b_soter_layer(state: &AppState, body: &Value, requested: &str) -> Option<Value> {
    // 先看这一步要不要真签名：签名只能由“真能现场签”的设备做。远端那台一加 11
    // 的 TA 非要新鲜指纹（回 -26），它自己已经上报 `soter_nosign` 了，这里就别
    // 再把签名任务排给它白跑一趟。
    let op = body.get("op").and_then(Value::as_str).unwrap_or("probe");
    let needs_sign = matches!(op, "init_sign" | "finish_sign");
    let Some(target) = state
        .store
        .resolve_soter_target(requested, needs_sign)
        .await
    else {
        return Some(json!({
            "error": "no B-side device reporting SOTER support is online",
        }));
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
        &target,
        state.cfg.soter_wait_result_timeout_secs,
    )
    .await;
    if let Some(code) = soter_device_hard_failure(op, &reply) {
        return Some(json!({
            "error": format!(
                "B-side device {target} failed SOTER op '{op}' with error_code {code} ({})",
                soter_error_name(code)
            ),
        }));
    }
    Some(reply)
}

/// 设备层答复里的 `error_code` 非 0 时，算不算“这轮流程做不成了”。
///
/// 设备层的答复是 B 端 relay 把 SOTER HAL 的结果原样带回来的，`error_code` 是腾讯
/// 那套 `SoterErrorCode`（TEE 那边给的）。查询类 op（`has_*` / `export_*`）的负码是
/// “这东西还没建”的正常回答，App 就是靠它决定要不要 generate，必须原样递上去 ——
/// 当成失败会让槽位在两层之间来回跳，App 手里就会出现一半 B 一半 keybox 的材料。
///
/// 建和签这几类不一样：`generate_*` / `init_sign` / `finish_sign` 一失败，这轮流程
/// 就死在这台设备上了。这种答复再往上递，App 只会白报一次失败；更要命的是
/// `run_soter_task` 会把答复当成“这层做成了”，顺手把 `(device, uid)` 槽位钉在这台
/// 设备上（30 分钟，而下一轮流程的 *第一个 op* 又会把它续上）—— 于是这轮之后每轮
/// 都还来问它，永远好不了。实测一加 11（PHB110）上 WeChat 的 `finish_sign` 一直是
/// `-26 SOTER_ERROR_VERIFICATION_FAILED`，就是被这么钉死的。这类失败要明说成
/// “这层没做成”，让服务端那两层接上，钉子也跟着挪过去。
fn soter_device_hard_failure(op: &str, reply: &Value) -> Option<i64> {
    let code = reply.get("error_code").and_then(Value::as_i64)?;
    if code == 0 {
        return None;
    }
    matches!(
        op,
        "get_device_id"
            | "generate_ask_key_pair"
            | "generate_auth_key_pair"
            | "init_sign"
            | "finish_sign"
    )
    .then_some(code)
}

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
    if let Err(r) = check_auth(&state, &headers, Some("a")) {
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
    if let Err(r) = check_auth(&state, &headers, Some("b")) {
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
    if let Err(r) = check_auth(&state, &headers, Some("b")) {
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
    if let Err(r) = check_auth(&state, &headers, Some("b")) {
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
    if let Err(r) = check_auth(&state, &headers, Some("b")) {
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
    // EC 优先（体积小，A 端拿它铸 leaf 也快），取不到再退 RSA。采到的身份可能挂在
    // 主 device_id 上，也可能挂在 -1/-2 这样的后缀上 —— 后缀范围跟着采集端的上限走，
    // 两边写死后加了一边另一边就白搭。
    let base = crate::autokeybox::device_id_for("public");
    let mut candidates = vec![base.clone()];
    for n in 1..crate::autokeybox::PUBLIC_MAX_IDENTITIES {
        candidates.push(format!("{base}-{n}"));
    }
    let mut picked: Option<(String, crate::db::DeviceIdentity)> = None;
    'scan: for algo in ["ec", "rsa"] {
        for device_id in &candidates {
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
                    picked = Some((device_id.clone(), id));
                    break 'scan;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("public_keybox lookup failed device_id={device_id} err={e}")
                }
            }
        }
    }
    let Some((device_id, id)) = picked else {
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
    };
    let xml = crate::keybox::build_keybox_xml(
        &device_id,
        &id.algorithm,
        &id.private_key_pem_cipher,
        &id.certificate_chain_pem,
    );
    tracing::info!(
        "public_keybox served device_id={} algorithm={} xml_bytes={}",
        device_id,
        id.algorithm,
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
    use super::{soter_device_hard_failure, soter_error_name};
    use serde_json::json;

    #[test]
    fn a_device_sign_failure_is_a_layer_failure() {
        // 实测一加 11：会话是真的（编解码没问题），TEE 就是不给签。
        assert_eq!(
            soter_device_hard_failure("finish_sign", &json!({ "error_code": -26 })),
            Some(-26)
        );
        assert_eq!(
            soter_device_hard_failure("init_sign", &json!({ "error_code": -6 })),
            Some(-6)
        );
        assert_eq!(
            soter_device_hard_failure("generate_auth_key_pair", &json!({ "error_code": -13 })),
            Some(-13)
        );
        assert_eq!(
            soter_device_hard_failure("get_device_id", &json!({ "error_code": -1000 })),
            Some(-1000)
        );
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
