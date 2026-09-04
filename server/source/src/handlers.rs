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
        .or_else(|| {
            headers
                .get("x-api-token")
                .and_then(|v| v.to_str().ok())
        })
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
    json_err(StatusCode::UNAUTHORIZED, "unauthorized: missing or invalid X-Relay-Token")
}

/// Authenticate + rate-limit a request. Returns Ok(token) or an error response.
///
/// `role`: `Some("a")` for A-side endpoints, `Some("b")` for B-side, `None` for
/// role-agnostic endpoints (ping/health/admin status).
fn check_auth(state: &AppState, headers: &HeaderMap, role: Option<&str>) -> Result<String, Response> {
    let token = token_from_headers(headers).unwrap_or("").to_string();
    let ip = client_ip(headers);

    // IP allow/deny filter (A/B-side only; admin uses its own session auth).
    if !state.auth.ip_allowed(&ip) {
        return Err(json_err(
            StatusCode::FORBIDDEN,
            "access denied by IP filter",
        ));
    }

    // Authenticate first. Failed auth counts against the (much tighter)
    // invalid-request limit, keyed by client IP.
    if !state.auth.check_token(Some(&token), role, &ip) {
        if !state.auth.allow_invalid(&ip) {
            return Err(json_err(
                StatusCode::TOO_MANY_REQUESTS,
                "too many invalid requests",
            ));
        }
        return Err(auth_fail());
    }

    // Valid auth: rate limit by token (or IP when no token).
    let rl_key = if token.is_empty() { ip } else { token.clone() };
    if !state.auth.allow(&rl_key) {
        return Err(json_err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded",
        ));
    }
    Ok(token)
}

/// Layer ① — B-device fulfilment: enqueue a task for the (load-balanced)
/// target and wait for the result. Fails fast when no B device is online so
/// the next layer can run without waiting.
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
    let task_id = state
        .store
        .create_task(task_type, body.clone(), &target)
        .await;
    let timeout = Duration::from_secs(state.cfg.wait_result_timeout_secs);
    match state.store.wait_for_result(&task_id, timeout).await {
        Some(mut result) => {
            if let Some(obj) = result.as_object_mut() {
                obj.insert("task_id".to_string(), json!(task_id));
            }
            Some(result)
        }
        None => Some(json!({
            "error": "task timeout: no B-side result",
            "task_id": task_id,
        })),
    }
}

/// Whether the A-side request explicitly asked for StrongBox (security_level=2).
fn is_strongbox_request(body: &Value) -> bool {
    body.get("device_attest_context")
        .and_then(|c| c.get("attestation_security_level"))
        .and_then(Value::as_i64)
        .or_else(|| body.get("attestation_security_level").and_then(Value::as_i64))
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
    match tokio::task::spawn_blocking(move || {
        try_keybox_layer_sync(&fulfill, &tt, &b, &did)
    })
    .await
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
    match tokio::task::spawn_blocking(move || {
        try_self_signed_layer_sync(&fulfill, &tt, &b, &did)
    })
    .await
    {
        Ok(v) => v,
        Err(e) => Some(json!({ "error": format!("spawn_blocking join error: {e}") })),
    }
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
                tracing::info!(
                    "run_smart_strongbox: B real StrongBox fulfilled attest for device {device_id}"
                );
                return Json(v).into_response();
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

/// Shared logic for A-side task endpoints.
///
/// Three-layer fallback, with the order set by the active mode:
///   physical:  ① B device -> ② stored keybox -> ③ self-signed
///   serverbox: ② stored keybox -> ① B device -> ③ self-signed
/// A layer "succeeds" when it returns a result without an `error` field;
/// otherwise the next layer is tried, and only when every layer fails is an
/// error returned.
async fn run_a_side_task(
    state: &AppState,
    task_type: &str,
    body: &Value,
) -> Response {
    let device_id = body.get("device_id").and_then(Value::as_str).unwrap_or("").to_string();
    if device_id.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "device_id required");
    }
    let ctx = body.get("device_attest_context").cloned().unwrap_or(Value::Null);
    let ctx_short = match &ctx {
        Value::Object(m) => {
            let mut s = String::new();
            for (k, v) in m {
                if k == "attestation_application_id" {
                    s.push_str(&format!("{k}=<appid-len:{}> ", v.as_str().map(|x| x.len()).unwrap_or(0)));
                } else if k == "certificate_subject" {
                    s.push_str(&format!("{k}=<b64-len:{}> ", v.as_str().map(|x| x.len()).unwrap_or(0)));
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
            Some(v)
                if v.get("error").is_none() && !attest_chain_empty(task_type, &v) => {
                tracing::info!(
                    "run_a_side_task: type={task_type} layer={layer} result_keys={:?} has_cert_chain={}",
                    v.as_object().map(|m| m.keys().cloned().collect::<Vec<String>>()),
                    v.get("cert_chain").is_some(),
                );
                return Json(v).into_response();
            }
            Some(v) => {
                let msg = if attest_chain_empty(task_type, &v) {
                    "empty cert chain from B device".to_string()
                } else {
                    v.get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error")
                        .to_string()
                };
                tracing::info!("run_a_side_task: type={task_type} layer={layer} failed: {msg}");
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
                    if let Some(dv) = try_b_device_layer(
                        state,
                        task_type,
                        &demoted,
                        &device_id,
                        any_b_online,
                    )
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
        return r;
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
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
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
        return r;
    }
    run_a_side_task(&state, "attest", &body).await
}

pub async fn sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")) {
        return r;
    }
    run_a_side_task(&state, "sign", &body).await
}

pub async fn decrypt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("a")) {
        return r;
    }
    run_a_side_task(&state, "decrypt", &body).await
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
        return r;
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
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
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
}

pub async fn b_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PollQuery>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("b")) {
        return r;
    }
    if q.device_id.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "device_id required");
    }
    let machine_id = q.machine_id.unwrap_or_default();

    // Concurrency guard: reject if another machine is actively serving this device.
    if let Some(active) = state.store.get_active_machine_id(&q.device_id).await {
        if !machine_id.is_empty() && active != machine_id {
            return json_err(StatusCode::CONFLICT, "another machine is already serving this device");
        }
    }

    let timeout_secs = q.timeout.unwrap_or(state.cfg.poll_timeout_secs);
    let timeout = Duration::from_secs(timeout_secs.min(120));

    match state
        .store
        .pop_for_b(&q.device_id, &machine_id, timeout)
        .await
    {
        Some(task) => Json(json!({
            "task_id": task.task_id,
            "task_type": task.task_type,
            "payload": task.payload,
            "target_device_id": task.target_device_id,
        }))
        .into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

pub async fn b_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers, Some("b")) {
        return r;
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
    match state.store.complete_task(&task_id, result, &device_id).await {
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
        return r;
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
        return r;
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
        tokio::task::spawn_blocking(move || db.set_device_identity_active(&device_id, false))
            .await;
    match result {
        Ok(Ok(())) => Json(json!({ "status": "ok" })).into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
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

#[cfg(test)]
mod strongbox_smart_tests {
    use super::strongbox_b_kind;
    use serde_json::json;

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
            strongbox_b_kind(&json!({ "error": "strongbox not supported: strongbox generateKey failed" })),
            None
        );
        assert_eq!(
            strongbox_b_kind(&json!({ "error": "some native ROM exception message" })),
            None
        );
        assert_eq!(strongbox_b_kind(&json!({ "cert_chain": [] })), None);
        assert_eq!(strongbox_b_kind(&json!({ "cert_chain": ["Zm9v"] })), None);
    }
}
