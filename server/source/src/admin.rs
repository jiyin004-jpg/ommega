//! Admin web console: a single-page management UI served by the relay.
//!
//! Routes (all under `/admin/`):
//!   GET  /admin/                     -> the web console (login page if no session)
//!   POST /api/admin/login/           -> username+password -> session id
//!   POST /api/admin/logout/          -> invalidate session
//!   GET  /api/admin/session/         -> check session validity
//!   GET  /api/admin/overview/        -> server mode, counts, identity summary
//!   GET  /api/admin/devices/         -> stored server identities + connected B devices
//!   GET  /api/admin/tasks/           -> task list
//!   GET  /api/admin/reports/         -> client reports
//!   POST /api/admin/keybox/          -> upload a single keybox.xml (raw XML body)
//!   POST /api/admin/mode/            -> enable/disable server_keybox mode
//!   POST /api/admin/devices/{id}/active/  -> activate/deactivate a stored identity
//!   DELETE /api/admin/devices/{id}/  -> delete a stored identity
//!
//! Admin endpoints require a valid session (issued by `/api/admin/login/`) via
//! the `X-Relay-Session` header. This is fully separate from the A/B-side
//! `X-Relay-Token`, mirroring Django's independent admin account/session model.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::db::DeviceIdentity;
use crate::handlers::AppState;
use crate::keybox;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn json_err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn auth_fail() -> Response {
    json_err(
        StatusCode::UNAUTHORIZED,
        "unauthorized: missing or invalid session",
    )
}

/// Extract the session id from the `X-Relay-Session` header.
fn session_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-relay-session")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Require a valid admin session.
fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let sid = session_from_headers(headers);
    if state.auth.check_session(&sid) {
        Ok(())
    } else {
        Err(auth_fail())
    }
}

// ---------------------------------------------------------------------------
// Login / logout / session
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

/// POST /api/admin/login/ — verify credentials and issue a session id.
pub async fn admin_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    // Use the real client IP (X-Real-IP injected from the TCP socket, never
    // client-supplied X-Forwarded-For) so the login rate limit cannot be
    // bypassed by spoofing the header.
    let ip = crate::handlers::client_ip(&headers);
    let key = format!("{ip}:{}", body.username);
    // Rate-limit login attempts (5/min per username+IP) to prevent brute force.
    if !state.auth.allow_login_attempt(&key) {
        return json_err(StatusCode::TOO_MANY_REQUESTS, "too many login attempts, try again later");
    }
    if !state.auth.verify_admin(&body.username, &body.password) {
        return json_err(StatusCode::UNAUTHORIZED, "invalid username or password");
    }
    let sid = state.auth.create_session();
    Json(json!({ "status": "ok", "session": sid, "username": body.username })).into_response()
}

/// POST /api/admin/logout/ — invalidate the current session.
pub async fn admin_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let sid = session_from_headers(&headers);
    state.auth.drop_session(&sid);
    Json(json!({ "status": "ok" })).into_response()
}

/// GET /api/admin/session/ — report whether the current session is valid.
pub async fn admin_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let valid = state.auth.check_session(&session_from_headers(&headers));
    Json(json!({ "valid": valid })).into_response()
}

// ---------------------------------------------------------------------------
// Static console page
// ---------------------------------------------------------------------------

pub async fn admin_page() -> impl IntoResponse {
    Html(include_str!("admin_ui.html"))
}

/// Login page (username + password).
pub async fn login_page() -> impl IntoResponse {
    Html(include_str!("login_ui.html"))
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

pub async fn admin_overview(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let counts = state.store.counts().await;
    let connected = state.store.get_connected_devices().await;

    // Stored identities from DB (server_keybox mode).  Skips private key
    // decryption — only metadata fields are needed for the overview page.
    let identities = match state.db.clone() {
        Some(db) => {
            match tokio::task::spawn_blocking(move || db.list_device_identities_meta()).await {
                Ok(Ok(v)) => v,
                Ok(Err(_)) => Vec::new(),
                Err(_) => Vec::new(),
            }
        }
        None => Vec::new(),
    };
    let active_identity = identities.iter().find(|d| d.active).cloned();

    Json(json!({
        "status": "ok",
        "mode": if state.fulfill.is_enabled() { "server_keybox" } else { "physical" },
        "server_keybox_enabled": state.fulfill.is_enabled(),
        "db": state.db.is_some(),
        "counts": {
            "pending": counts.pending,
            "assigned": counts.assigned,
            "completed": counts.completed,
            "failed": counts.failed,
        },
        "connected_b_devices": connected.len(),
        "stored_identities": identities.len(),
        "active_identity": active_identity.map(|d| json!({
            "device_id": d.device_id,
            "algorithm": d.algorithm,
            "cert_count": crate::keybox::cert_count(&d.certificate_chain_pem),
        })),
        "server_time_ms": chrono::Utc::now().timestamp_millis(),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

pub async fn admin_devices(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    // Stored server identities (deduplicated per device_id, with their
    // algorithms listed). These represent "devices that have an uploaded
    // keybox certificate".
    let identities: Vec<Value> = match state.db.clone() {
        Some(db) => {
            let result =
                tokio::task::spawn_blocking(move || db.list_device_identities_meta()).await;
            let mut rows = match result {
                Ok(Ok(v)) => v,
                _ => Vec::new(),
            };
            rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
            let mut grouped: Vec<Value> = Vec::new();
            for d in &rows {
                if let Some(last) = grouped.last_mut().and_then(|v| v.as_object_mut()) {
                    if last.get("device_id").and_then(Value::as_str) == Some(d.device_id.as_str())
                    {
                        // Append algorithm to an existing device entry.
                        if let Some(arr) = last.get_mut("algorithms").and_then(Value::as_array_mut) {
                            arr.push(json!(d.algorithm));
                        }
                        continue;
                    }
                }
                grouped.push(json!({
                    "device_id": d.device_id,
                    "algorithms": [d.algorithm],
                    "cert_count": crate::keybox::cert_count(&d.certificate_chain_pem),
                    "active": d.active,
                    "created_at": d.created_at,
                    "has_private_key": !d.private_key_pem_cipher.is_empty(),
                }));
            }
            grouped
        }
        None => Vec::new(),
    };

    // Connected B-side devices, ordered by load (ascending: least loaded first).
    let mut connected_raw = state.store.get_connected_devices().await;
    let mut connected: Vec<(Value, u64)> = Vec::new();
    for d in connected_raw.drain(..) {
        let load = state.store.get_device_load(&d.device_id).await;
        connected.push((
            json!({
                "device_id": d.device_id,
                "machine_id": d.machine_id,
                "last_seen_ms": d.last_seen_ms,
                "connected": d.connected,
                "load": load,
            }),
            load,
        ));
    }
    connected.sort_by(|a, b| a.1.cmp(&b.1).then(a.0["device_id"].as_str().cmp(&b.0["device_id"].as_str())));
    let connected: Vec<Value> = connected.into_iter().map(|(v, _)| v).collect();

    Json(json!({
        "status": "ok",
        "identities": identities,
        "connected_b_devices": connected,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Tasks & reports
// ---------------------------------------------------------------------------

pub async fn admin_tasks(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let tasks: Vec<Value> = state
        .store
        .list_tasks(100)
        .await
        .iter()
        .map(|t| {
            json!({
                "task_id": t.task_id,
                "task_type": t.task_type,
                "requested_device_id": t
                    .payload
                    .get("device_id")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                "target_device_id": t.target_device_id,
                "assigned_device_id": t.assigned_device_id,
                "status": t.status_str(),
                "created_at_ms": t.created_at_ms,
            })
        })
        .collect();
    Json(json!({ "status": "ok", "tasks": tasks })).into_response()
}

pub async fn admin_reports(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let reports: Vec<Value> = match state.db.clone() {
        Some(db) => {
            match tokio::task::spawn_blocking(move || db.list_client_reports(100)).await {
                Ok(Ok(rows)) => rows
                    .iter()
                    .map(|r| {
                        json!({
                            "device_id": r.device_id,
                            "level": r.level,
                            "code": r.code,
                            "message": r.message,
                            "created_at": r.created_at,
                        })
                    })
                    .collect(),
                _ => Vec::new(),
            }
        }
        None => Vec::new(),
    };
    Json(json!({ "status": "ok", "reports": reports })).into_response()
}

// ---------------------------------------------------------------------------
// keybox.xml single-file upload
// ---------------------------------------------------------------------------

/// POST /api/admin/keybox/ — body is the raw contents of keybox.xml.
/// Parses it, stores the identity in the DB and auto-enables server_keybox mode.
pub async fn admin_upload_keybox(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = &state.db else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "DB not enabled (RELAY_DB_PATH is empty) — cannot store a keybox",
        );
    };

    let xml = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "body is not valid UTF-8"),
    };

    // A keybox.xml may contain several `<Key>` entries (RSA + EC). Parse all of
    // them and persist each as a distinct (device_id, algorithm) identity so the
    // fulfil layer can serve whichever algorithm the A-side requests.
    let keyboxes = match keybox::parse_keybox_xml_all(xml) {
        Ok(kb) => kb,
        Err(e) => {
            return json_err(
                StatusCode::BAD_REQUEST,
                &format!("invalid keybox.xml: {e}"),
            )
        }
    };

    if keyboxes.is_empty() {
        return json_err(
            StatusCode::BAD_REQUEST,
            "keybox.xml did not contain any valid keybox entries",
        );
    }
    let device_id = if keyboxes[0].device_id.is_empty() {
        "server_keybox".to_string()
    } else {
        keyboxes[0].device_id.clone()
    };

    let mut imported = Vec::new();
    for kb in &keyboxes {
        // Validate the private key parses AND matches the chain leaf before
        // persisting this entry (mirrors the B-side upload path), so a
        // mismatched keybox cannot mint an unverifiable attestation chain.
        if let Some(err) = crate::cert::validate_identity_pem(
            &kb.private_key_pem,
            &kb.certificate_chain_pem,
        ) {
            return json_err(
                StatusCode::BAD_REQUEST,
                &format!(
                    "keybox.xml entry (algorithm {}) is unusable: {err}",
                    kb.algorithm
                ),
            );
        }
        let identity = DeviceIdentity {
            device_id: device_id.clone(),
            algorithm: kb.algorithm.clone(),
            certificate_chain_pem: kb.certificate_chain_pem.clone(),
            private_key_pem_cipher: kb.private_key_pem.clone(),
            active: true,
            machine_id: "admin-upload".to_string(),
            created_at: String::new(),
        };
        let db_clone = db.clone();
        let id_clone = identity.clone();
        let upsert_result =
            tokio::task::spawn_blocking(move || db_clone.upsert_device_identity(&id_clone)).await;
        match upsert_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}"))
            }
            Err(e) => {
                return json_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("join error: {e}"),
                )
            }
        }
        imported.push(json!({
            "algorithm": kb.algorithm,
            "cert_count": kb.cert_count,
        }));
    }

    // A freshly uploaded keybox is meant to be used: switch to local mode.
    state.fulfill.set_enabled(true);

    Json(json!({
        "status": "ok",
        "device_id": device_id,
        "imported": imported,
        "server_keybox_enabled": true,
        "message": "keybox.xml imported; server_keybox mode enabled",
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Mode switch (runtime)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ModeBody {
    pub enabled: bool,
}

/// POST /api/admin/mode/  {"enabled": true|false}
pub async fn admin_set_mode(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ModeBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    state.fulfill.set_enabled(body.enabled);
    Json(json!({
        "status": "ok",
        "server_keybox_enabled": state.fulfill.is_enabled(),
        "mode": if state.fulfill.is_enabled() { "server_keybox" } else { "physical" },
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Device identity management
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ActiveBody {
    pub active: bool,
}

pub async fn admin_set_device_active(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(body): Json<ActiveBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let active = body.active;
    let device_id_clone = device_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        db.set_device_identity_active(&device_id_clone, active)
    })
    .await;
    match result {
        Ok(Ok(())) => Json(json!({ "status": "ok", "device_id": device_id, "active": body.active }))
            .into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
    }
}

pub async fn admin_delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let device_id_clone = device_id.clone();
    let result =
        tokio::task::spawn_blocking(move || db.delete_device_identity(&device_id_clone)).await;
    match result {
        Ok(Ok(())) => Json(json!({ "status": "ok", "device_id": device_id })).into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
    }
}

// ---------------------------------------------------------------------------
// API token management (mirrors Django ApiToken: generate / list / enable /
// disable / delete). Tokens are "card"-style: activated on first use, expire
// after `duration_seconds` from activation.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct TokenGenBody {
    pub role: String, // "a" | "b"
    pub duration_seconds: i64,
    pub note: Option<String>,
}

/// GET /api/admin/tokens/ — list all API tokens.
pub async fn admin_tokens(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let result = tokio::task::spawn_blocking(move || db.list_api_tokens()).await;
    let tokens: Vec<Value> = match result {
        Ok(Ok(rows)) => rows
            .iter()
            .map(|t| {
                json!({
                    "id": t.id,
                    "token": t.token,
                    "role": t.role,
                    "duration_seconds": t.duration_seconds,
                    "note": t.note,
                    "enabled": t.enabled,
                    "activated_at": t.activated_at,
                    "created_at": t.created_at,
                    "last_ip": t.last_ip,
                    "last_used_at": t.last_used_at,
                })
            })
            .collect(),
        Ok(Err(e)) => {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}"))
        }
        Err(e) => {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}"))
        }
    };
    Json(json!({ "status": "ok", "tokens": tokens })).into_response()
}

/// POST /api/admin/tokens/ — generate a new API token.
pub async fn admin_generate_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TokenGenBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    if body.role != "a" && body.role != "b" {
        return json_err(StatusCode::BAD_REQUEST, "role must be 'a' or 'b'");
    }
    if body.duration_seconds <= 0 {
        return json_err(StatusCode::BAD_REQUEST, "duration_seconds must be positive");
    }
    let token = crate::util::generate_token_string();
    let token_clone = token.clone();
    let note = body.note.clone().unwrap_or_default();
    let role = body.role.clone();
    let duration = body.duration_seconds;
    let result = tokio::task::spawn_blocking(move || {
        db.insert_api_token(&token_clone, &role, duration, &note)
    })
    .await;
    match result {
        Ok(Ok(())) => Json(json!({
            "status": "ok",
            "token": token,
            "role": body.role,
            "duration_seconds": body.duration_seconds,
        }))
        .into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
    }
}

#[derive(serde::Deserialize)]
pub struct TokenToggleBody {
    pub enabled: bool,
}

/// POST /api/admin/tokens/:id/ — enable/disable a token.
pub async fn admin_toggle_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<TokenToggleBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let enabled = body.enabled;
    let result =
        tokio::task::spawn_blocking(move || db.set_token_enabled(id, enabled)).await;
    match result {
        Ok(Ok(())) => Json(json!({ "status": "ok", "id": id, "enabled": body.enabled })).into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
    }
}

/// DELETE /api/admin/tokens/:id/ — delete a token.
pub async fn admin_delete_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let result = tokio::task::spawn_blocking(move || db.delete_token(id)).await;
    match result {
        Ok(Ok(())) => Json(json!({ "status": "ok", "id": id })).into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
    }
}

/// GET /api/admin/tokens/:token/ips/ — historical IPs used by a token, with
/// region info resolved from the offline ip2region database.
pub async fn admin_token_ips(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let rows = match tokio::task::spawn_blocking(move || db.token_usage_ips(&token)).await {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
    };
    // Attach region info for each IP.
    let geo = state.geo.as_ref();
    let ips: Vec<Value> = rows
        .iter()
        .map(|r| {
            let ip = r.get("ip").and_then(Value::as_str).unwrap_or("").to_string();
            let region = geo
                .and_then(|g| g.search(&ip))
                .unwrap_or_default();
            let (country, province, city, isp) = split_region(&region);
            json!({
                "ip": ip,
                "region": region,
                "country": country,
                "province": province,
                "city": city,
                "isp": isp,
                "first_used_at": r.get("first_used_at").cloned().unwrap_or(Value::Null),
                "last_used_at": r.get("last_used_at").cloned().unwrap_or(Value::Null),
                "count": r.get("count").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    Json(json!({ "status": "ok", "ips": ips })).into_response()
}

/// Split an ip2region region string `国家|区域|省份|城市|ISP` into its parts.
fn split_region(region: &str) -> (String, String, String, String) {
    let parts: Vec<&str> = region.split('|').collect();
    let get = |i: usize| parts.get(i).map(|s| s.to_string()).unwrap_or_default();
    (get(0), get(2), get(3), get(4))
}

// ---------------------------------------------------------------------------
// Auto keybox management.
// ---------------------------------------------------------------------------

/// GET /api/admin/autokeybox/ — current state + configured sources.
pub async fn admin_autokeybox_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let sources: Vec<Value> = crate::autokeybox::configured_sources()
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "device_id": s.device_id,
                "url_primary": s.url_primary,
                "url_mirror": s.url_mirror,
                "decode_hex": s.decode_hex,
            })
        })
        .collect();
    Json(json!({
        "status": "ok",
        "enabled": crate::autokeybox::is_enabled(),
        "cover_enabled": crate::autokeybox::cover_enabled(),
        "cover_source": crate::autokeybox::cover_source(),
        "interval_secs": state.cfg.keybox_refresh_interval_secs,
        "sources": sources,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct AutoKeyboxToggleBody {
    pub enabled: bool,
}

/// POST /api/admin/autokeybox/ — enable/disable the auto-refresh loop.
pub async fn admin_autokeybox_toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AutoKeyboxToggleBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    crate::autokeybox::set_enabled(body.enabled);
    Json(json!({ "status": "ok", "enabled": body.enabled })).into_response()
}

/// POST /api/admin/autokeybox/refresh/ — trigger an immediate refresh (async).
pub async fn admin_autokeybox_refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let store = state.store.clone();
    // Run in a detached thread to avoid blocking the request.
    std::thread::spawn(move || {
        crate::autokeybox::refresh_all(&db, Some(store.as_ref()));
    });
    Json(json!({ "status": "ok", "message": "refresh triggered" })).into_response()
}

#[derive(serde::Deserialize)]
pub struct AutoKeyboxCoverBody {
    pub enabled: bool,
}

/// POST /api/admin/autokeybox/cover/ — enable/disable the auto-cover mode.
///
/// Enabling sets the flag and triggers an immediate refresh+cover (fetch keys,
/// then write them into every online B device id's server identity). Disabling
/// clears the flag and deletes the rows auto-cover wrote (`machine_id
/// auto-cover:*`) so the affected devices fall back to pure A/B forwarding.
pub async fn admin_autokeybox_cover_toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AutoKeyboxCoverBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(
            StatusCode::BAD_REQUEST,
            "DB not enabled (RELAY_DB_PATH is empty) — cannot manage auto-cover identities",
        );
    };
    if body.enabled {
        crate::autokeybox::set_cover_enabled(true);
        let store = state.store.clone();
        std::thread::spawn(move || {
            crate::autokeybox::refresh_all(&db, Some(store.as_ref()));
        });
        Json(json!({
            "status": "ok",
            "cover_enabled": true,
            "message": "auto-cover enabled; immediate refresh+cover triggered",
        }))
        .into_response()
    } else {
        crate::autokeybox::set_cover_enabled(false);
        let result = tokio::task::spawn_blocking(move || crate::autokeybox::clear_auto_cover(&db))
            .await;
        match result {
            Ok(Ok(cleared)) => Json(json!({
                "status": "ok",
                "cover_enabled": false,
                "cleared": cleared,
            }))
            .into_response(),
            Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
        }
    }
}

/// POST /api/admin/autokeybox/cover/clear/ — manually delete the identities the
/// auto-cover mode wrote (`machine_id auto-cover:*`), regardless of the flag.
pub async fn admin_autokeybox_cover_clear(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let result = tokio::task::spawn_blocking(move || crate::autokeybox::clear_auto_cover(&db)).await;
    match result {
        Ok(Ok(cleared)) => Json(json!({ "status": "ok", "cleared": cleared })).into_response(),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}")),
    }
}

#[derive(serde::Deserialize)]
pub struct AutoKeyboxDeviceBody {
    pub name: String,
    pub device_id: String,
}

#[derive(serde::Deserialize)]
pub struct AutoKeyboxCoverSourceBody {
    pub source: String,
}

/// POST /api/admin/autokeybox/cover/source/ — choose which Auto Keybox source
/// feeds the auto-cover step: `"auto"` (all sources, later wins per algorithm)
/// or a configured source name such as `"yurikey"` / `"kow"`.
pub async fn admin_autokeybox_cover_source(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AutoKeyboxCoverSourceBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    if !crate::autokeybox::set_cover_source(&body.source) {
        let names: Vec<String> = crate::autokeybox::configured_sources()
            .iter()
            .map(|s| s.name.clone())
            .collect();
        return json_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "invalid cover source {:?}: expected \"auto\" or one of {:?}",
                body.source, names
            ),
        );
    }
    Json(json!({
        "status": "ok",
        "cover_source": crate::autokeybox::cover_source(),
    }))
    .into_response()
}

/// POST /api/admin/autokeybox/device/ — override a source's target device_id.
pub async fn admin_autokeybox_set_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AutoKeyboxDeviceBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    if body.device_id.trim().is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "device_id must not be empty");
    }
    crate::autokeybox::set_device_id(&body.name, &body.device_id);
    Json(json!({
        "status": "ok",
        "name": body.name,
        "device_id": crate::autokeybox::device_id_for(&body.name),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Card order management.
// ---------------------------------------------------------------------------

/// GET /api/admin/cards/ — list all card orders.
pub async fn admin_card_orders(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let Some(db) = state.db.clone() else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let result = tokio::task::spawn_blocking(move || db.list_card_orders()).await;
    let orders: Vec<Value> = match result {
        Ok(Ok(rows)) => rows
            .iter()
            .map(|o| {
                json!({
                    "id": o.id,
                    "order_id": o.order_id,
                    "card_type": o.card_type,
                    "role": o.role,
                    "price_cents": o.price_cents,
                    "status": o.status,
                    "bonus_draws": o.bonus_draws,
                    "contact": o.contact,
                    "token_id": o.token_id,
                    "created_at": o.created_at,
                    "paid_at": o.paid_at,
                    "pay_type": o.pay_type,
                    "trade_no": o.trade_no,
                })
            })
            .collect(),
        Ok(Err(e)) => {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}"))
        }
        Err(e) => {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("join error: {e}"))
        }
    };
    Json(json!({ "status": "ok", "orders": orders })).into_response()
}

// ---------------------------------------------------------------------------
// A/B-side IP allow/deny list management.
// ---------------------------------------------------------------------------

/// GET /api/admin/ipfilter/ — current state + list.
pub async fn admin_ipfilter_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    Json(json!({
        "status": "ok",
        "enabled": state.auth.ip_filter_enabled(),
        "whitelist": state.auth.ip_filter_is_whitelist(),
        "ips": state.auth.ip_filter_list(),
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct IpFilterConfigBody {
    pub enabled: bool,
    #[serde(default)]
    pub whitelist: bool,
}

/// POST /api/admin/ipfilter/config/ — enable/disable + switch mode.
pub async fn admin_ipfilter_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<IpFilterConfigBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    state.auth.set_ip_filter_enabled(body.enabled);
    state.auth.set_ip_filter_whitelist(body.whitelist);
    Json(json!({
        "status": "ok",
        "enabled": body.enabled,
        "whitelist": body.whitelist,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct IpFilterIpBody {
    pub ip: String,
}

/// POST /api/admin/ipfilter/add/ — add an IP to the list.
pub async fn admin_ipfilter_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<IpFilterIpBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    state.auth.add_ip(&body.ip);
    Json(json!({ "status": "ok", "ips": state.auth.ip_filter_list() })).into_response()
}

/// POST /api/admin/ipfilter/remove/ — remove an IP from the list.
pub async fn admin_ipfilter_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<IpFilterIpBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    state.auth.remove_ip(&body.ip);
    Json(json!({ "status": "ok", "ips": state.auth.ip_filter_list() })).into_response()
}

// ---------------------------------------------------------------------------
// StrongBox handling mode (three-state: off | smart | robust).
// ---------------------------------------------------------------------------

/// GET /api/admin/strongbox/ — current StrongBox handling-mode switch state.
///
/// `mode` is the three-state token (`"off" | "smart" | "robust"`); `enabled`
/// is kept for backwards compatibility and reports only whether the Robust
/// (original "强健/降级") mode is active.
pub async fn admin_strongbox_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let m = crate::strongbox::mode();
    Json(json!({
        "status": "ok",
        "mode": m.as_str(),
        "enabled": m == crate::strongbox::StrongboxMode::Robust,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct StrongboxToggleBody {
    /// Three-state mode token: `"off" | "smart" | "robust"`. Preferred field.
    pub mode: Option<String>,
    /// Legacy boolean switch (robustness on/off). Honoured only when `mode`
    /// is absent: `true` → `"robust"`, `false` → `"off"`.
    pub enabled: Option<bool>,
}

/// POST /api/admin/strongbox/ — set the StrongBox handling mode.
///
/// Modes:
///   - off (default): strict native semantics — StrongBox errors propagate to
///     the next fulfilment layer exactly as before.
///   - smart: StrongBox-fidelity orchestration — serve from the B device's real
///     StrongBox when it works; surface a present-but-broken StrongBox
///     (keys not provisioned / hardware type unavailable) verbatim to the A-side
///     app; fall back to the stored per-device keybox identity when the B device
///     has no StrongBox; otherwise hand back to the A-side local keybox.
///   - robust: Android-standard silent fallback — a B-side StrongBox capability
///     error is transparently retried as a TEE request on the same B device.
pub async fn admin_strongbox_toggle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<StrongboxToggleBody>,
) -> Response {
    if let Err(r) = check_auth(&state, &headers) {
        return r;
    }
    let next = if let Some(tok) = body.mode.as_deref() {
        match crate::strongbox::StrongboxMode::from_str(tok) {
            Some(m) => m,
            None => {
                return json_err(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid mode {tok:?}: expected \"off\" | \"smart\" | \"robust\""),
                );
            }
        }
    } else if body.enabled == Some(true) {
        crate::strongbox::StrongboxMode::Robust
    } else {
        crate::strongbox::StrongboxMode::Off
    };
    crate::strongbox::set_mode(next);
    Json(json!({
        "status": "ok",
        "mode": next.as_str(),
        "enabled": next == crate::strongbox::StrongboxMode::Robust,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Public status page (no auth) — mirrors Django's `device_status`.
// ---------------------------------------------------------------------------

/// Public status page (read-only, no sensitive data).
pub async fn status_page() -> impl IntoResponse {
    Html(include_str!("status_ui.html"))
}

/// GET /api/status/ — public read-only device status: online B devices (load
/// sorted) + stored-cert device IDs. Never exposes keys/certs/tokens.
pub async fn public_status(State(state): State<AppState>) -> Response {
    // Online B devices, ordered by load ascending (least loaded first).
    let mut connected_raw = state.store.get_connected_devices().await;
    let mut connected: Vec<(Value, u64)> = Vec::new();
    for d in connected_raw.drain(..) {
        let load = state.store.get_device_load(&d.device_id).await;
        connected.push((
            json!({
                "device_id": d.device_id,
                "machine_id": d.machine_id,
                "load": load,
                "last_seen_ms": d.last_seen_ms,
            }),
            load,
        ));
    }
    connected.sort_by(|a, b| a.1.cmp(&b.1).then(a.0["device_id"].as_str().cmp(&b.0["device_id"].as_str())));
    let connected: Vec<Value> = connected.into_iter().map(|(v, _)| v).collect();

    // Stored-cert device IDs (deduplicated, no key/cert material).
    let cert_devices: Vec<Value> = match state.db.clone() {
        Some(db) => {
            let result =
                tokio::task::spawn_blocking(move || db.list_device_identities_meta()).await;
            let mut rows = match result {
                Ok(Ok(v)) => v,
                _ => Vec::new(),
            };
            rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
            let mut grouped: Vec<Value> = Vec::new();
            for d in &rows {
                if let Some(last) = grouped.last_mut().and_then(|v| v.as_object_mut()) {
                    if last.get("device_id").and_then(Value::as_str) == Some(d.device_id.as_str()) {
                        if let Some(arr) = last.get_mut("algorithms").and_then(Value::as_array_mut) {
                            arr.push(json!(d.algorithm));
                        }
                        continue;
                    }
                }
                grouped.push(json!({
                    "device_id": d.device_id,
                    "algorithms": [d.algorithm],
                    "active": d.active,
                }));
            }
            grouped
        }
        None => Vec::new(),
    };

    Json(json!({
        "status": "ok",
        "mode": if state.fulfill.is_enabled() { "serverbox" } else { "physical" },
        "online_b_devices": connected,
        "cert_devices": cert_devices,
        "server_time_ms": chrono::Utc::now().timestamp_millis(),
    }))
    .into_response()
}
