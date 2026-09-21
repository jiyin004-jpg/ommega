//! Token authentication and simple in-memory rate limiting.
//!
//! Mirrors Django's `_check_token` + `_db_token_valid`:
//!   1. static env token (RELAY_TOKEN) matches exactly -> allowed
//!   2. otherwise, a DB-issued "card" token (ApiToken) is checked:
//!        - role must match the endpoint's expected role (a/b), if any
//!        - activated on first use (activation-based expiry)
//!        - `expires_at = activated_at + duration_seconds`
//!   3. if neither env token nor any DB token is configured, allow (back-compat)

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::db::Db;

#[derive(Clone)]
pub struct AuthState {
    pub relay_token: String,
    pub admin_user: String,
    pub admin_password: String,
    pub admin_extra: String,
    db: Option<Arc<Db>>,
    rate: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    invalid_rate: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    login_rate: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    pub rate_limit_requests: u64,
    pub invalid_rate_limit_requests: u64,
    pub rate_limit_window: Duration,
    // IP allow/deny list (applies to A/B-side endpoints only).
    ip_filter_enabled: Arc<AtomicBool>,
    /// true = whitelist mode (only listed IPs allowed), false = blacklist mode.
    ip_filter_whitelist: Arc<AtomicBool>,
    ip_filter_list: Arc<Mutex<HashSet<String>>>,
    /// When true (default), a valid token is always required. When false,
    /// anonymous access is allowed when neither a static token nor any DB
    /// token is configured (backward-compatibility fallback).
    pub auth_required: bool,
}

/// Admin session TTL: 12 hours of inactivity.
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

impl AuthState {
    pub fn new(
        relay_token: String,
        rate_limit_requests: u64,
        rate_limit_window_secs: u64,
        auth_required: bool,
    ) -> Self {
        Self {
            relay_token,
            admin_user: String::new(),
            admin_password: String::new(),
            admin_extra: String::new(),
            db: None,
            rate: Arc::new(Mutex::new(HashMap::new())),
            invalid_rate: Arc::new(Mutex::new(HashMap::new())),
            login_rate: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            rate_limit_requests,
            // Invalid (failed-auth) requests get a much tighter limit.
            invalid_rate_limit_requests: 40,
            rate_limit_window: Duration::from_secs(rate_limit_window_secs),
            ip_filter_enabled: Arc::new(AtomicBool::new(false)),
            ip_filter_whitelist: Arc::new(AtomicBool::new(false)),
            ip_filter_list: Arc::new(Mutex::new(HashSet::new())),
            auth_required,
        }
    }

    /// Attach the DB handle (set once after `Db::open`).
    pub fn with_db(mut self, db: Option<Arc<Db>>) -> Self {
        self.db = db;
        self
    }

    /// Set admin credentials (user/password/extra accounts).
    pub fn with_admin_credentials(mut self, user: &str, password: &str, extra: &str) -> Self {
        self.admin_user = user.to_string();
        self.admin_password = password.to_string();
        self.admin_extra = extra.to_string();
        self
    }

    /// 定长比较。用 `==` 比密码的话，"前几个字符对不对"会从耗时上泄漏出去；
    /// 这里不管第几位不匹配都把循环跑完，长度不同也不提前返回。
    fn ct_eq_secret(a: &str, b: &str) -> bool {
        let (a, b) = (a.as_bytes(), b.as_bytes());
        let mut diff = if a.len() == b.len() { 0u8 } else { 1u8 };
        for i in 0..a.len().max(b.len()) {
            diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
        }
        diff == 0
    }

    /// Verify admin credentials. Returns true when user/password match either
    /// the primary account or one of the `user:pass` entries in `admin_extra`.
    pub fn verify_admin(&self, user: &str, password: &str) -> bool {
        if self.admin_user.is_empty() {
            return false;
        }
        // 未配置密码时空字符串会直接命中下面的等值比较，等于“admin+空密码”
        // 就能拿完整管理会话，所以主账号与 extra 条目都拒绝空密码。
        if !self.admin_password.is_empty()
            && user == self.admin_user
            && Self::ct_eq_secret(password, &self.admin_password)
        {
            return true;
        }
        for entry in self.admin_extra.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((u, p)) = entry.split_once(':') {
                let p = p.trim();
                if !p.is_empty() && user == u.trim() && Self::ct_eq_secret(password, p) {
                    return true;
                }
            }
        }
        false
    }

    /// Create a new admin session, returning the session id (opaque token).
    pub fn create_session(&self) -> String {
        use base64::Engine;
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let sid = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b)
            .to_string();
        let mut sessions = crate::util::mu(&self.sessions);
        // Opportunistically prune expired sessions.
        let now = Instant::now();
        sessions.retain(|_, exp| now.duration_since(*exp) < SESSION_TTL);
        sessions.insert(sid.clone(), now);
        sid
    }

    /// Check whether a session id is valid (and refresh its TTL).
    pub fn check_session(&self, sid: &str) -> bool {
        if sid.is_empty() {
            return false;
        }
        let mut sessions = crate::util::mu(&self.sessions);
        let now = Instant::now();
        sessions.retain(|_, exp| now.duration_since(*exp) < SESSION_TTL);
        match sessions.get_mut(sid) {
            Some(exp) => {
                *exp = now;
                true
            }
            None => false,
        }
    }

    /// Invalidate a session id.
    pub fn drop_session(&self, sid: &str) {
        let mut sessions = crate::util::mu(&self.sessions);
        sessions.remove(sid);
    }

    // ---- IP allow/deny list (A/B-side only) ----

    pub fn ip_filter_enabled(&self) -> bool {
        self.ip_filter_enabled.load(Ordering::Relaxed)
    }

    pub fn ip_filter_is_whitelist(&self) -> bool {
        self.ip_filter_whitelist.load(Ordering::Relaxed)
    }

    pub fn set_ip_filter_enabled(&self, v: bool) {
        self.ip_filter_enabled.store(v, Ordering::Relaxed);
    }

    pub fn set_ip_filter_whitelist(&self, v: bool) {
        self.ip_filter_whitelist.store(v, Ordering::Relaxed);
    }

    pub fn ip_filter_list(&self) -> Vec<String> {
        let mut list: Vec<String> = crate::util::mu(&self.ip_filter_list)
            .iter()
            .cloned()
            .collect();
        list.sort();
        list
    }

    pub fn add_ip(&self, ip: &str) -> bool {
        let ip = ip.trim();
        if ip.is_empty() {
            return false;
        }
        crate::util::mu(&self.ip_filter_list).insert(ip.to_string())
    }

    pub fn remove_ip(&self, ip: &str) -> bool {
        crate::util::mu(&self.ip_filter_list).remove(ip)
    }

    /// Whether the given client IP is allowed through the filter. Returns true
    /// when the filter is disabled, or when the IP passes the current mode.
    pub fn ip_allowed(&self, ip: &str) -> bool {
        if !self.ip_filter_enabled.load(Ordering::Relaxed) {
            return true;
        }
        let list = crate::util::mu(&self.ip_filter_list);
        let contained = list.contains(ip);
        if self.ip_filter_whitelist.load(Ordering::Relaxed) {
            contained // whitelist: only listed IPs allowed
        } else {
            !contained // blacklist: listed IPs denied
        }
    }

    /// Set the invalid (failed-auth) rate limit.
    pub fn with_invalid_rate_limit(mut self, limit: u64) -> Self {
        self.invalid_rate_limit_requests = limit;
        self
    }

    /// Returns true if the header value matches the configured static token.
    pub fn check_static_token(&self, header: Option<&str>) -> bool {
        if self.relay_token.is_empty() {
            return false;
        }
        match header {
            Some(v) => v == self.relay_token,
            None => false,
        }
    }

    /// Full auth check for an endpoint with an optional required role.
    ///
    /// `role`: `Some("a")` for A-side endpoints, `Some("b")` for B-side,
    /// `None` for role-agnostic endpoints (ping/health). Returns true when the
    /// request is authorized. Also activates the token on first use and records
    /// the client IP.
    pub fn check_token(&self, header: Option<&str>, role: Option<&str>, ip: &str) -> bool {
        let token = header.unwrap_or("");

        // 1) static env token (back-compat)
        if self.check_static_token(Some(token)) {
            return true;
        }

        // 2) DB card token
        if let Some(db) = &self.db {
            if !token.is_empty() {
                if let Ok(Some(row)) = db.get_api_token(token) {
                    // role check
                    if let Some(required) = role {
                        if row.role != required {
                            return false;
                        }
                    }
                    // activated / expiry (activation-based)
                    if !row.enabled {
                        return false;
                    }
                    // activate on first use
                    if row.activated_at.is_empty() {
                        let _ = db.activate_token_if_needed(token);
                    }
                    // record usage (IP + last-used)
                    if let Err(e) = db.record_token_use(token, ip) {
                        tracing::warn!(
                            "check_token: record_token_use failed token={} ip={} err={e}",
                            token,
                            ip
                        );
                    }
                    // check expiry against activation time
                    return token_is_valid(db, token, row.duration_seconds);
                }
            }
        }

        // 3) anonymous fallback: only allowed when auth_required is explicitly
        //    disabled AND no static token AND no DB token is configured.
        if !self.auth_required && self.relay_token.is_empty() {
            let has_db_token = self
                .db
                .as_ref()
                .map(|db| db.has_any_token().unwrap_or(false))
                .unwrap_or(false);
            if !has_db_token {
                return true;
            }
        }

        false
    }

    /// Sliding-window rate limit keyed by token (or client IP when no token).
    /// Returns true if the request is allowed.
    pub fn allow(&self, key: &str) -> bool {
        self.allow_with_limit(&self.rate, key, self.rate_limit_requests)
    }

    /// Sliding-window rate limit for invalid (failed-auth) requests, keyed by
    /// client IP. Uses a much tighter limit than valid requests.
    pub fn allow_invalid(&self, key: &str) -> bool {
        self.allow_with_limit(&self.invalid_rate, key, self.invalid_rate_limit_requests)
    }

    /// Sliding-window rate limit for admin login attempts, keyed by username+IP.
    /// Returns true if the attempt is allowed. Limits to 5 attempts per minute
    /// (independent of the general request rate limit).
    pub fn allow_login_attempt(&self, key: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let mut map = crate::util::mu(&self.login_rate);
        let bucket = map.entry(key.to_string()).or_default();
        bucket.retain(|t| now.duration_since(*t) < window);
        if bucket.len() as u64 >= 5 {
            false
        } else {
            bucket.push(now);
            true
        }
    }

    fn allow_with_limit(
        &self,
        rate: &Arc<Mutex<HashMap<String, Vec<Instant>>>>,
        key: &str,
        limit: u64,
    ) -> bool {
        let now = Instant::now();
        let mut map = crate::util::mu(rate);
        let bucket = map.entry(key.to_string()).or_default();
        bucket.retain(|t| now.duration_since(*t) < self.rate_limit_window);
        if bucket.len() as u64 >= limit {
            false
        } else {
            bucket.push(now);
            true
        }
    }
}

/// Check expiry of an already-activated token. Returns true if not expired.
/// A token with no `activated_at` is treated as not-yet-activated (valid).
fn token_is_valid(db: &Arc<Db>, token: &str, duration_seconds: i64) -> bool {
    match db.get_api_token(token) {
        Ok(Some(row)) => {
            if row.activated_at.is_empty() {
                return true; // not activated yet
            }
            // activated_at is stored as `YYYY-MM-DD HH:MM:SS` in Beijing time
            // (MySQL session time_zone = +08:00). Parse it and add duration_seconds.
            let act = match parse_beijing_datetime(&row.activated_at) {
                Some(t) => t,
                None => return false,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            now <= act + duration_seconds
        }
        Ok(None) => false,
        Err(_) => false,
    }
}

/// Parse `YYYY-MM-DD HH:MM:SS` (Beijing time, +08:00) into a unix timestamp
/// (seconds). MySQL DATETIME columns are stored in local Beijing time.
fn parse_beijing_datetime(s: &str) -> Option<i64> {
    // Strip fractional seconds if present (e.g. `2026-08-14 12:00:00.123456`).
    let s = s.trim();
    let s = if let Some(dot) = s.find('.') {
        &s[..dot]
    } else {
        s
    };
    let parts: Vec<&str> = s.split([' ', ':', '-']).collect();
    if parts.len() < 6 {
        return None;
    }
    use chrono::TimeZone;
    let y: i32 = parts[0].parse().ok()?;
    let mo: u32 = parts[1].parse().ok()?;
    let d: u32 = parts[2].parse().ok()?;
    let h: u32 = parts[3].parse().ok()?;
    let mi: u32 = parts[4].parse().ok()?;
    let sec: u32 = parts[5].parse().ok()?;
    let offset = chrono::FixedOffset::east_opt(8 * 3600)?;
    let dt = offset.with_ymd_and_hms(y, mo, d, h, mi, sec).single()?;
    Some(dt.timestamp())
}
