//! Card sales: yearly/monthly API-token cards, lottery, and a payment callback.
//!
//! - `POST /api/card/order/`   — create a pending order (year card, role a/b).
//! - `POST /api/card/lottery/` — daily lottery (1 free draw/day; buying a year
//!   card grants bonus draws).
//! - `POST /api/card/pay_callback/` — payment callback (called by your payment
//!   / card platform) to mark an order paid and issue the API token.
//!
//! A "card" is just an existing API token (role a/b, duration year/month), so
//! the purchased credential plugs straight into the A/B-side auth.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::handlers::AppState;

const YEAR_PRICE_CENTS: i64 = 500; // 5.00 CNY

fn json_err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn client_ip(headers: &HeaderMap) -> String {
    crate::handlers::client_ip(headers)
}

fn today_str() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn generate_order_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("ord{}", hex_encode(&bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Order creation
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct OrderBody {
    pub card_type: String, // "year"
    pub role: String,      // "a" | "b"
    #[serde(default)]
    pub contact: String, // buyer contact (used to query the card later)
    #[serde(default)]
    pub pay_type: String, // "alipay" | "wxpay"
}

/// POST /api/card/order/ — create a pending year-card order.
pub async fn card_order(State(state): State<AppState>, Json(body): Json<OrderBody>) -> Response {
    if body.card_type != "year" {
        return json_err(StatusCode::BAD_REQUEST, "only yearly cards are sold");
    }
    if body.role != "a" && body.role != "b" {
        return json_err(StatusCode::BAD_REQUEST, "role must be 'a' or 'b'");
    }
    if body.contact.trim().is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "contact is required");
    }
    let pay_type = if body.pay_type == "wxpay" {
        "wxpay"
    } else {
        "alipay"
    };
    let Some(db) = &state.db else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let order_id = generate_order_id();
    // Buying a year card grants 1 bonus lottery draw.
    if let Err(e) = db.create_card_order(crate::db::NewCardOrder {
        order_id: &order_id,
        card_type: "year",
        role: &body.role,
        price_cents: YEAR_PRICE_CENTS,
        bonus_draws: 1,
        contact: body.contact.trim(),
        pay_type,
    }) {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}"));
    }

    let mut resp = json!({
        "status": "ok",
        "order_id": order_id,
        "card_type": "year",
        "role": body.role,
        "price_cents": YEAR_PRICE_CENTS,
        "pay_type": pay_type,
        "contact": body.contact.trim(),
        "message": "order created; awaiting payment",
    });

    // If an aggregate-payment gateway is configured, submit the order and
    // return the QR code / cashier URL so the buyer can pay right away.
    let cfg = &state.cfg;
    if !cfg.pay_gateway.is_empty() && !cfg.pay_pid.is_empty() && !cfg.pay_key.is_empty() {
        let money = format!("{:.2}", YEAR_PRICE_CENTS as f64 / 100.0);
        let name = if cfg.pay_product_name.is_empty() {
            format!(
                "OMMEGA 年卡({}端)",
                if body.role == "a" { "A" } else { "B" }
            )
        } else {
            cfg.pay_product_name.clone()
        };
        let gw = crate::pay::Gateway {
            url: &cfg.pay_gateway,
            pid: &cfg.pay_pid,
            key: &cfg.pay_key,
            notify_url: &cfg.pay_notify_url,
            return_url: &cfg.pay_return_url,
        };
        let order = crate::pay::OrderReq {
            pay_type,
            out_trade_no: &order_id,
            name: &name,
            money: &money,
        };
        match crate::pay::submit_order(gw, order).await {
            Ok(pay_resp) => {
                let _ = db.set_order_trade_no(&order_id, &pay_resp.trade_no);
                let pay_url = if !pay_resp.url.is_empty() {
                    pay_resp.url
                } else {
                    pay_resp.cashier_url.clone()
                };
                resp["pay_trade_no"] = json!(pay_resp.trade_no);
                resp["pay_qrcode"] = json!(pay_resp.qrcode);
                resp["pay_url"] = json!(pay_url);
                resp["pay_cashier"] = json!(pay_resp.cashier_url);
                // Pre-render the QR code as an inline SVG data URI for instant display.
                if !pay_resp.qrcode.is_empty() {
                    if let Some(svg) = crate::pay::qrcode_svg_data_uri(&pay_resp.qrcode) {
                        resp["pay_qr_svg"] = json!(svg);
                    }
                }
                resp["message"] = json!("order created; scan the QR code to complete payment");
            }
            Err(e) => {
                tracing::warn!("pay gateway submit failed: {e}");
                resp["pay_error"] = json!(e);
                resp["message"] =
                    json!("order created; payment gateway unavailable, contact admin");
            }
        }
    } else {
        resp["message"] = json!("order created; payment gateway not configured");
    }

    Json(resp).into_response()
}

// ---------------------------------------------------------------------------
// Lottery
// ---------------------------------------------------------------------------

/// POST /api/card/lottery/ — three free draws per day; bonus draws from purchases.
pub async fn card_lottery(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(db) = &state.db else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let ip = client_ip(&headers);
    let today = today_str();
    let client_key = format!("ip:{ip}");

    // Strict daily limit: at most 3 draws per client per day.
    match db.lottery_draws_today(&client_key, &today) {
        Ok(n) if n >= 3 => {
            return json_err(
                StatusCode::TOO_MANY_REQUESTS,
                "daily draw limit reached (3/day)",
            );
        }
        Ok(_) => {}
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
    }

    // Draw: 10% chance to win a 7-day A-side card.
    let won = draw_won();
    let card_type = if won { "week" } else { "none" };

    if let Err(e) = db.insert_lottery_record(&client_key, &today, won, card_type) {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}"));
    }

    if won {
        let token = crate::util::generate_token_string();
        if let Err(e) = db.insert_api_token(&token, "a", crate::db::WEEK_SECS, "card:week") {
            return json_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("issue failed: {e}"),
            );
        }
        return Json(json!({
            "status": "ok",
            "won": true,
            "card_type": "week",
            "role": "a",
            "token": token,
            "message": "congratulations! you won a 7-day A-side card",
        }))
        .into_response();
    }

    Json(json!({
        "status": "ok",
        "won": false,
        "message": "better luck next time",
    }))
    .into_response()
}

fn draw_won() -> bool {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    rng.gen_bool(0.1)
}

// ---------------------------------------------------------------------------
// Payment callback (aggregate payment / card platform integration)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct PayCallbackBody {
    pub order_id: String,
    #[serde(default)]
    pub secret: String,
}

/// POST/GET /api/card/pay_callback/ — entry point for both the aggregate
/// payment async notification (URL-encoded form POST or GET query) and the
/// legacy secret callback (JSON POST).
pub async fn card_pay_callback(
    State(state): State<AppState>,
    query: axum::extract::RawQuery,
    body: axum::body::Bytes,
) -> Response {
    let text = match std::str::from_utf8(&body) {
        Ok(t) => t,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "bad body"),
    };
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        // Legacy JSON callback with secret.
        let parsed: serde_json::Result<PayCallbackBody> = serde_json::from_str(trimmed);
        let body = match parsed {
            Ok(b) => b,
            Err(_) => return json_err(StatusCode::BAD_REQUEST, "invalid JSON"),
        };
        return legacy_pay_callback(state, body).await;
    }
    // Aggregate payment async notification: parameters may arrive in the
    // query string (GET) and/or the form body (POST). Merge both.
    let mut params = crate::pay::parse_form(trimmed);
    if let Some(q) = query.0 {
        for (k, v) in crate::pay::parse_form(&q) {
            params.entry(k).or_insert(v);
        }
    }
    aggregate_pay_notify(state, params).await
}

/// Mark an order paid and deliver the card token. Idempotent for paid/delivered.
fn pay_and_deliver(db: &crate::db::Db, order_id: &str) -> Result<Option<String>, String> {
    let order = match db.get_card_order(order_id) {
        Ok(Some(o)) => o,
        Ok(None) => return Err("order not found".into()),
        Err(e) => return Err(format!("db error: {e}")),
    };
    // Atomic claim+deliver: concurrent callbacks serialize, exactly one token
    // is minted, and a claimed-but-undelivered order is recovered.
    db.deliver_order_with_token(order_id, &order.role, &order.card_type)
        .map_err(|e| format!("deliver failed: {e}"))
}

/// Aggregate payment async notification: verify `sign`, then mark paid & deliver.
/// Responds with plain-text `success` (the ack token platforms expect), or
/// `fail` so the platform retries.
async fn aggregate_pay_notify(
    state: AppState,
    params: std::collections::BTreeMap<String, String>,
) -> Response {
    let Some(db) = &state.db else {
        return "fail".into_response();
    };
    let cfg = &state.cfg;
    if cfg.pay_key.is_empty() {
        return "fail".into_response();
    }
    // Verify signature.
    if !crate::pay::verify_sign(&params, &cfg.pay_key) {
        tracing::warn!(
            "pay callback: bad signature {:?}",
            params.get("out_trade_no")
        );
        return "fail".into_response();
    }
    // Check pid matches ours (if provided).
    if let Some(pid) = params.get("pid") {
        if !cfg.pay_pid.is_empty() && pid != &cfg.pay_pid {
            tracing::warn!("pay callback: pid mismatch");
            return "fail".into_response();
        }
    }
    // Only TRADE_SUCCESS means paid.
    if params.get("trade_status").map(|s| s.as_str()) != Some("TRADE_SUCCESS") {
        return "success".into_response(); // acknowledged, nothing to do
    }
    let Some(order_id) = params.get("out_trade_no") else {
        return "fail".into_response();
    };
    // Cross-check amount (optional but recommended): money in CNY string.
    if let Some(money) = params.get("money") {
        if let Ok(amt) = money.parse::<f64>() {
            let cents = (amt * 100.0).round() as i64;
            if let Ok(Some(order)) = db.get_card_order(order_id) {
                if order.price_cents > 0 && cents != order.price_cents {
                    tracing::warn!(
                        "pay callback: amount mismatch order={order_id} expect={} got={cents}",
                        order.price_cents
                    );
                    return "fail".into_response();
                }
            }
        }
    }
    if let Some(trade_no) = params.get("trade_no") {
        let _ = db.set_order_trade_no(order_id, trade_no);
    }
    match pay_and_deliver(db, order_id) {
        Ok(_) => "success".into_response(),
        Err(e) => {
            tracing::error!("pay callback deliver failed: {e}");
            "fail".into_response()
        }
    }
}

/// Legacy JSON callback authenticated with `CARD_CALLBACK_SECRET`.
async fn legacy_pay_callback(state: AppState, body: PayCallbackBody) -> Response {
    // Verify the callback secret (must match CARD_CALLBACK_SECRET).
    let expected = state.cfg.pay_callback_secret.clone();
    if expected.is_empty() || body.secret != expected {
        return json_err(StatusCode::UNAUTHORIZED, "invalid callback secret");
    }
    let Some(db) = &state.db else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    match pay_and_deliver(db, &body.order_id) {
        Ok(Some(token)) => Json(json!({
            "status": "ok",
            "order_id": body.order_id,
            "token": token,
        }))
        .into_response(),
        Ok(None) => {
            // Already paid/delivered or still processing.
            let order = db.get_card_order(&body.order_id).ok().flatten();
            let status = order.map(|o| o.status).unwrap_or_default();
            Json(json!({
                "status": "already",
                "order_id": body.order_id,
                "order_status": status,
            }))
            .into_response()
        }
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("deliver failed: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Order status query (front-end polls after paying)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct OrderStatusBody {
    pub order_id: String,
}

/// POST /api/card/order/status/ — query an order; when delivered, includes the token.
pub async fn card_order_status(
    State(state): State<AppState>,
    Json(body): Json<OrderStatusBody>,
) -> Response {
    let Some(db) = &state.db else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let order = match db.get_card_order(&body.order_id) {
        Ok(Some(o)) => o,
        Ok(None) => return json_err(StatusCode::NOT_FOUND, "order not found"),
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
    };
    let token = order
        .token_id
        .and_then(|id| db.get_token_by_id(id).ok().flatten())
        .map(|t| t.token)
        .unwrap_or_default();
    Json(json!({
        "status": "ok",
        "order_id": order.order_id,
        "order_status": order.status,
        "role": order.role,
        "card_type": order.card_type,
        "pay_type": order.pay_type,
        "price_cents": order.price_cents,
        "token": if order.status == "delivered" { token } else { String::new() },
        "paid_at": order.paid_at,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Query card by contact
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct QueryCardBody {
    pub contact: String,
}

/// POST /api/card/query/ — query delivered card(s) by exact contact match.
/// Returns the card token(s) for any delivered order matching the contact.
/// Rate-limited by client IP so contacts cannot be trivially enumerated.
pub async fn card_query_by_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<QueryCardBody>,
) -> Response {
    let ip = crate::handlers::client_ip(&headers);
    if !state.auth.allow(&ip) {
        return json_err(
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded, try again later",
        );
    }
    let contact = body.contact.trim();
    if contact.is_empty() {
        return json_err(StatusCode::BAD_REQUEST, "contact is required");
    }
    let Some(db) = &state.db else {
        return json_err(StatusCode::NOT_FOUND, "no db");
    };
    let orders = match db.find_orders_by_contact(contact) {
        Ok(o) => o,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("db error: {e}")),
    };
    if orders.is_empty() {
        return Json(json!({ "status": "ok", "cards": [] })).into_response();
    }
    // Resolve each order's token (if delivered).
    let mut cards: Vec<Value> = Vec::new();
    for o in &orders {
        let token = o
            .token_id
            .and_then(|id| db.get_token_by_id(id).ok().flatten())
            .map(|t| t.token)
            .unwrap_or_default();
        cards.push(json!({
            "order_id": o.order_id,
            "role": o.role,
            "card_type": o.card_type,
            "token": token,
            "paid_at": o.paid_at,
        }));
    }
    Json(json!({ "status": "ok", "cards": cards })).into_response()
}
