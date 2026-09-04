//! relay_rs — Rust port of the ommega relay_server.
//!
//! Endpoints (parity with relay_server):
//!   A-side  : GET  /api/ping/ , GET /api/health/ , POST /api/attest/,
//!             POST /api/sign/, POST /api/decrypt/, POST /api/client_report/
//!   B-side  : GET  /api/b/poll/?device_id=..&machine_id=..&timeout=N
//!             POST /api/b/result/
//!             POST /api/b/upload_keybox_identity/, POST /api/b/revoke_server_identity/
//!   Admin   : GET /api/status/, POST /api/admin/cancel_task/
//!
//! Auth: `X-Relay-Token` header must match RELAY_TOKEN.

mod admin;
mod auth;
mod autokeybox;
mod card;
mod cert;
mod config;
mod crypto;
mod db;
mod fulfill;
mod geo;
mod handlers;
mod keybox;
mod pay;
mod queue;
mod strongbox;
mod util;

use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::middleware;
use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::db::Db;
use crate::fulfill::Fulfill;
use crate::queue::TaskStore;

/// Serve the embedded background image (compiled into the binary).
async fn serve_bg() -> impl axum::response::IntoResponse {
    let bytes: &[u8] = include_bytes!("static/bg.png");
    (
        [(axum::http::header::CONTENT_TYPE, "image/png")],
        bytes.to_vec(),
    )
}

/// Card purchase page (public).
async fn card_page() -> impl axum::response::IntoResponse {
    axum::response::Html(include_str!("card_ui.html"))
}

/// Middleware: inject the real client IP as `X-Real-IP` header from the TCP
/// socket address, so downstream handlers can log it even when no proxy is
/// present (e.g. B-side devices connecting directly).
async fn inject_client_ip(
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl axum::response::IntoResponse {
    // The ConnectInfo is injected by into_make_service_with_connect_info.
    if let Some(connect_info) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip = connect_info.0.ip().to_string();
        if let Ok(val) = ip.parse() {
            req.headers_mut().insert("X-Real-IP", val);
        }
    }
    next.run(req).await
}

fn build_router(cfg: &Arc<Config>) -> Router {
    let store = TaskStore::new(
        cfg.assignment_timeout_secs,
        cfg.pending_ttl_secs,
        cfg.completed_max,
        cfg.completed_ttl_secs,
    );
    // Initialize the Fernet cipher used to encrypt stored private keys.
    crate::crypto::init_fernet(&cfg.secret_key);
    let db = if cfg.mysql_url.is_empty() {
        None
    } else {
        match Db::open(&cfg.mysql_url) {
            Ok(d) => Some(Arc::new(d)),
            Err(e) => {
                tracing::warn!("DB open failed ({e}); running without persistence");
                None
            }
        }
    };
    let auth = Arc::new(
        crate::auth::AuthState::new(
            cfg.relay_token.clone(),
            cfg.rate_limit_requests,
            cfg.rate_limit_window_secs,
            cfg.auth_required,
        )
        .with_db(db.clone())
        .with_invalid_rate_limit(cfg.invalid_rate_limit_requests)
        .with_admin_credentials(&cfg.admin_user, &cfg.admin_password, &cfg.admin_extra),
    );
    let fulfill = Fulfill::new(cfg.server_keybox_enabled(), db.clone());

    // Load the offline IP-to-region database (non-fatal if missing).
    let geo = crate::geo::Ip2Region::load(&cfg.geo_db_path).map(Arc::new);
    if geo.is_none() {
        tracing::warn!(
            "ip2region database not found at '{}'; IP region lookup disabled",
            cfg.geo_db_path
        );
    }

    // Start the auto keybox refresh loop (background thread) when enabled.
    // `store` is passed so the auto-cover step can snapshot online B device ids.
    if cfg.keybox_refresh_enabled {
        if let Some(db_ref) = db.clone() {
            crate::autokeybox::set_enabled(true);
            crate::autokeybox::start_background(
                db_ref,
                store.clone(),
                std::time::Duration::from_secs(cfg.keybox_refresh_interval_secs),
            );
        }
    }

    let state = handlers::AppState {
        cfg: cfg.clone(),
        auth,
        store,
        fulfill,
        db,
        geo,
    };

    Router::new()
        .route("/api/ping/", get(handlers::ping))
        .route("/api/health/", get(handlers::health))
        .route("/api/status/", get(admin::public_status))
        .route("/status/", get(admin::status_page))
        .route("/status", get(admin::status_page))
        // Card sales (public)
        .route("/card/", get(card_page))
        .route("/card", get(card_page))
        .route("/api/card/order/", post(card::card_order))
        .route("/api/card/lottery/", post(card::card_lottery))
        .route(
            "/api/card/pay_callback/",
            get(card::card_pay_callback).post(card::card_pay_callback),
        )
        .route("/api/card/order/status/", post(card::card_order_status))
        .route("/api/card/query/", post(card::card_query_by_contact))
        .route("/api/cert_chain_dump/", get(handlers::cert_chain_dump))
        .route("/api/attest/", post(handlers::attest))
        .route("/api/sign/", post(handlers::sign))
        .route("/api/decrypt/", post(handlers::decrypt))
        .route("/api/client_report/", post(handlers::client_report))
        .route("/api/b/poll/", get(handlers::b_poll))
        .route("/api/b/result/", post(handlers::b_result))
        .route(
            "/api/b/upload_keybox_identity/",
            post(handlers::b_upload_keybox_identity),
        )
        .route(
            "/api/b/revoke_server_identity/",
            post(handlers::b_revoke_server_identity),
        )
        .route("/api/admin/cancel_task/", post(handlers::admin_cancel_task))
        // Admin web console (hidden path, not /admin/)
        .route("/jiyin004/", get(admin::admin_page))
        .route("/jiyin004", get(admin::admin_page))
        .route("/login/", get(admin::login_page))
        // Static background image (compiled into the binary)
        .route("/static/bg.png", get(serve_bg))
        .route("/api/admin/login/", post(admin::admin_login))
        .route("/api/admin/logout/", post(admin::admin_logout))
        .route("/api/admin/session/", get(admin::admin_session))
        .route("/api/admin/overview/", get(admin::admin_overview))
        .route("/api/admin/devices/", get(admin::admin_devices))
        .route("/api/admin/tasks/", get(admin::admin_tasks))
        .route("/api/admin/reports/", get(admin::admin_reports))
        .route("/api/admin/keybox/", post(admin::admin_upload_keybox))
        .route("/api/admin/mode/", post(admin::admin_set_mode))
        .route("/api/admin/tokens/", get(admin::admin_tokens))
        .route("/api/admin/tokens/", post(admin::admin_generate_token))
        .route(
            "/api/admin/autokeybox/",
            get(admin::admin_autokeybox_status),
        )
        .route(
            "/api/admin/autokeybox/",
            post(admin::admin_autokeybox_toggle),
        )
        .route(
            "/api/admin/autokeybox/refresh/",
            post(admin::admin_autokeybox_refresh),
        )
        .route(
            "/api/admin/autokeybox/device/",
            post(admin::admin_autokeybox_set_device),
        )
        .route(
            "/api/admin/autokeybox/cover/",
            post(admin::admin_autokeybox_cover_toggle),
        )
        .route(
            "/api/admin/autokeybox/cover/clear/",
            post(admin::admin_autokeybox_cover_clear),
        )
        .route(
            "/api/admin/autokeybox/cover/source/",
            post(admin::admin_autokeybox_cover_source),
        )
        .route("/api/admin/cards/", get(admin::admin_card_orders))
        .route("/api/admin/ipfilter/", get(admin::admin_ipfilter_status))
        .route(
            "/api/admin/ipfilter/config/",
            post(admin::admin_ipfilter_config),
        )
        .route(
            "/api/admin/ipfilter/add/",
            post(admin::admin_ipfilter_add),
        )
        .route(
            "/api/admin/ipfilter/remove/",
            post(admin::admin_ipfilter_remove),
        )
        .route(
            "/api/admin/strongbox/",
            get(admin::admin_strongbox_status),
        )
        .route(
            "/api/admin/strongbox/",
            post(admin::admin_strongbox_toggle),
        )
        .route(
            "/api/admin/tokens/:token/ips/",
            get(admin::admin_token_ips),
        )
        .route(
            "/api/admin/tokens/:id/",
            post(admin::admin_toggle_token),
        )
        .route(
            "/api/admin/tokens/:id/",
            axum::routing::delete(admin::admin_delete_token),
        )
        .route(
            "/api/admin/devices/:device_id/active/",
            post(admin::admin_set_device_active),
        )
        .route(
            "/api/admin/devices/:device_id/",
            axum::routing::delete(admin::admin_delete_device),
        )
        .with_state(state)
        .layer(middleware::from_fn(inject_client_ip))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Explicitly select rustls crypto provider (ring) to avoid runtime panic
    // when both `ring` and `aws-lc-rs` features are enabled transitively.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(
            tracing::Level::INFO.into(),
        ))
        .init();

    let cfg = Arc::new(Config::load());
    tracing::info!(
        "relay_rs starting: mode={} bind={} http={} https={} tls={}",
        if cfg.server_keybox_enabled() { "server_keybox" } else { "physical" },
        cfg.bind_addr,
        cfg.http_port,
        cfg.https_port,
        cfg.use_tls
    );

    let app = build_router(&cfg);

    // HTTP server
    let http_addr = format!("{}:{}", cfg.bind_addr, cfg.http_port);
    let http_listener = tokio::net::TcpListener::bind(&http_addr).await?;
    tracing::info!("HTTP listening on {http_addr}");
    let http_server = axum::serve(
        http_listener,
        app.clone().into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    // HTTPS server (if TLS enabled and cert files exist)
    if cfg.use_tls {
        let cert_path = std::path::Path::new(&cfg.tls_cert_file);
        let key_path = std::path::Path::new(&cfg.tls_key_file);
        if cert_path.exists() && key_path.exists() {
            let https_addr = format!("{}:{}", cfg.bind_addr, cfg.https_port);
            tracing::info!("HTTPS listening on {https_addr}");
            let https_server = axum_server::bind_rustls(
                https_addr.parse()?,
                axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &cfg.tls_cert_file,
                    &cfg.tls_key_file,
                )
                .await?,
            )
            .serve(app.clone().into_make_service_with_connect_info::<std::net::SocketAddr>());
            // Run both servers concurrently.
            tokio::select! {
                r = http_server => { r?; }
                r = https_server => { r?; }
            }
            return Ok(());
        }
        tracing::warn!(
            "TLS enabled but cert/key missing ({} / {}); falling back to HTTP only",
            cfg.tls_cert_file,
            cfg.tls_key_file
        );
    }

    http_server.await?;
    Ok(())
}
