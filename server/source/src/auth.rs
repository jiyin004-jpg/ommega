//! Token authentication and simple in-memory rate limiting.
//!
//! Auth chain:
//!   1. static env token (RELAY_TOKEN) matches exactly -> allowed
//!   2. otherwise a DB-issued "card" token (ApiToken) is checked:
//!        - role must match the endpoint's expected role (a/b), if any
//!        - activated on first use (activation-based expiry)
//!        - `expires_at = activated_at + duration_seconds`
//!   3. anonymous access only when `auth_required` is off AND no static token
//!      AND no DB token is configured (back-compat)

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::db::Db;

/// Token 身份（配对 / 公开 / 老卡密），见 [`AuthState::token_meta`]。
#[derive(Debug, Clone, Default)]
pub struct TokenMeta {
    pub role: String,
    pub pair_id: String,
    pub kind: String,
}

/// 请求方带过来的设备指纹：`ro.serialno` / `ro.boot.serialno` / IMEI1。
///
/// 私卡首次成功鉴权时把这几项写进 `api_token`，之后每次请求必须跟已绑定的一致，
/// 换设备就过不去（要换机器先在 /card 页面解绑）。稳定性：`sn`
/// （`ro.boot.serialno`，bootloader 只读）与 IMEI 改不动；`serial`（`ro.serialno`）
/// 是可写属性，会被 `remote_identity` / `props.conf` 改写，只作兜底。
#[derive(Debug, Clone, Default)]
pub struct DeviceFp {
    pub serial: String,
    pub sn: String,
    /// IMEI1（`persist.radio.imei1` 一类）。硬件写死，比序列号更适合作绑定材料。
    pub imei: String,
}

impl DeviceFp {
    /// 三项都读不到（或只有 AOSP 的占位值）才算没有指纹。
    pub fn is_empty(&self) -> bool {
        AuthState::fingerprint_part(&self.serial).is_empty()
            && AuthState::fingerprint_part(&self.sn).is_empty()
            && AuthState::fingerprint_part(&self.imei).is_empty()
    }
}

impl TokenMeta {
    /// 能不能跟另一端的 token 配对互通。卡密只有两种：
    ///
    /// - **普通卡**（`kind = "public"`）：两边都是普通卡才通，公开卡不能指挥别人的私机；
    /// - **私卡**（`kind = "pair"`，含 `kind` 为空的早期记录）：`pair_id` 任一方为空 =
    ///   没约束 → 通；都有值就必须同组。
    ///
    /// `kind` 为空走私卡分支，不存在「空 kind 直接放行」的第三个分支。
    pub fn allows(&self, other: &TokenMeta) -> bool {
        let public = |m: &TokenMeta| m.kind.eq_ignore_ascii_case("public");

        // 普通卡：两边都是普通卡才放行（公开卡不能指挥别人的私机）。
        if public(self) || public(other) {
            return public(self) && public(other);
        }

        // 剩下都是私卡（含早期 kind 为空的记录）：pair_id 任一方为空 →
        // 没填就是没约束，放行；都有值就严格同组。
        if self.pair_id.is_empty() || other.pair_id.is_empty() {
            return true;
        }
        self.pair_id == other.pair_id
    }
}

/// Token 使用登记的节流：同一 token 60 秒内只写一次库。
///
/// B 端几百台设备共用一把 token、70ms 一轮 poll，每笔都 `UPDATE api_token SET last_ip…`
/// 会撞在同一行上，把 MySQL 的行锁打满。节流只降低「最后使用 IP / 时间」的精度
/// （最多晚 60 秒），鉴权与过期判断不受影响。
fn should_record_token_use(token: &str) -> bool {
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, Instant};
    const THROTTLE: Duration = Duration::from_secs(60);
    static LAST: LazyLock<Mutex<std::collections::HashMap<String, Instant>>> =
        LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
    let Ok(mut map) = LAST.lock() else {
        return true;
    };
    let now = Instant::now();
    match map.get(token) {
        Some(last) if now.duration_since(*last) < THROTTLE => false,
        _ => {
            if map.len() > 4096 {
                map.clear();
            }
            map.insert(token.to_string(), now);
            true
        }
    }
}

#[derive(Clone)]
pub struct AuthState {
    pub relay_token: String,
    pub admin_user: String,
    pub admin_password: String,
    pub admin_extra: String,
    db: Option<Arc<Db>>,
    rate: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    invalid_rate: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    login_rate: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
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
    /// 鉴权结果的短缓存：token -> (整行, 时间)。
    ///
    /// `get_api_token` 是同步 MySQL 查询，而 A 端每笔 attest/sign/decrypt、B 端每 5 秒
    /// 一次 poll 都要鉴权，全在关键路径上；卡密的 role/kind/enabled/绑定几秒内不会变，
    /// 所以值得缓存，代价是运营改卡 / 用户解绑最多晚 `TOKEN_CACHE_TTL` 生效。
    token_cache: Arc<Mutex<HashMap<String, (crate::db::ApiTokenRow, Instant)>>>,
}

/// Admin session TTL: 12 hours of inactivity.
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

/// 限流表最多留多少条 key（按 IP 记），超了就清一遍空桶。
const RATE_MAP_MAX: usize = 4096;

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
            token_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attach the DB handle (set once after `Db::open`).
    pub fn with_db(mut self, db: Option<Arc<Db>>) -> Self {
        self.db = db;
        self
    }

    /// 卡密鉴权结果的缓存时长：10 秒。
    const TOKEN_CACHE_TTL: Duration = Duration::from_secs(10);

    fn cached_token(&self, token: &str) -> Option<crate::db::ApiTokenRow> {
        let guard = self.token_cache.lock().ok()?;
        let (row, at) = guard.get(token)?;
        if at.elapsed() < Self::TOKEN_CACHE_TTL {
            Some(row.clone())
        } else {
            None
        }
    }

    fn remember_token(&self, token: &str, row: &crate::db::ApiTokenRow) {
        if let Ok(mut guard) = self.token_cache.lock() {
            // 正常不会到这个量；到了就顺手清一轮过期的，别让它无限长。
            if guard.len() > 1024 {
                guard.retain(|_, (_, at)| at.elapsed() < Self::TOKEN_CACHE_TTL);
            }
            guard.insert(token.to_string(), (row.clone(), Instant::now()));
        }
    }

    /// 拿 token 行：先看缓存，没命中再查库（查到就存进去）。
    fn lookup_token(&self, token: &str) -> Option<crate::db::ApiTokenRow> {
        if let Some(row) = self.cached_token(token) {
            return Some(row);
        }
        let db = self.db.as_ref()?;
        let row = db.get_api_token(token).ok().flatten()?;
        self.remember_token(token, &row);
        Some(row)
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
            // 定长比较，跟 admin 密码走同一套（见 ct_eq_secret）：用 `==` 会让
            // “前缀对了几位”从耗时上泄出去。
            Some(v) => Self::ct_eq_secret(v, &self.relay_token),
            None => false,
        }
    }

    /// Token 身份：配对组 + 类型，供「A/B 必须配对才能走通」的判断用。
    /// 配对规则见 [`Self::allows`]；`enabled = false` 的卡返回 `None`（等于认不出）。
    ///
    /// 静态 env token / 没配 token 时返回 `None`，调用方按历史行为放行，不进入配对判断。
    pub fn token_meta(&self, header: Option<&str>) -> Option<TokenMeta> {
        let token = header.unwrap_or("");
        if token.is_empty() || self.check_static_token(Some(token)) {
            // 静态 env token / 没有 token：不参与配对，按老行为放行。
            return None;
        }
        let db = self.db.as_ref()?;
        let _ = db;
        let row = self.lookup_token(token)?;
        if !row.enabled {
            return None;
        }
        Some(TokenMeta {
            role: row.role,
            pair_id: row.pair_id,
            kind: row.kind,
        })
    }

    /// Full auth check for an endpoint with an optional required role.
    ///
    /// `role`: `Some("a")` for A-side, `Some("b")` for B-side, `None` for
    /// role-agnostic endpoints (ping/health). On success the token is activated on
    /// first use and the client IP is recorded.
    ///
    /// `fp`: 设备指纹。显式私卡（`pair` / `private`）用它做首次绑定与后续一致性
    /// 校验，A、B 两端都绑；公开卡和 `kind` 为空的老卡不参与绑定。
    pub fn check_token(
        &self,
        header: Option<&str>,
        role: Option<&str>,
        ip: &str,
        fp: Option<&DeviceFp>,
    ) -> bool {
        let token = header.unwrap_or("");

        // 1) static env token (back-compat)
        if self.check_static_token(Some(token)) {
            return true;
        }

        // 2) DB card token
        if let Some(db) = &self.db {
            if !token.is_empty() {
                if let Some(row) = self.lookup_token(token) {
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
                    // 私卡绑定设备：首次带指纹就绑，之后每次都要对得上。
                    // A、B 两端都绑（只给 A 端绑的话 B 卡换机器照样能用）；公开卡不绑。
                    if role.is_some()
                        && Self::is_private_card(&row)
                        && !self.device_binding_ok(db, &row, fp)
                    {
                        tracing::warn!(
                            "check_token: device mismatch token={} bound=({},{},{}) got=({},{},{})",
                            token,
                            row.bound_serial,
                            row.bound_sn,
                            row.bound_imei,
                            fp.map(|f| f.serial.as_str()).unwrap_or("-"),
                            fp.map(|f| f.sn.as_str()).unwrap_or("-"),
                            fp.map(|f| f.imei.as_str()).unwrap_or("-")
                        );
                        return false;
                    }
                    // activate on first use
                    if row.activated_at.is_empty() {
                        let _ = db.activate_token_if_needed(token);
                    }
                    // record usage (IP + last-used)
                    //
                    // 节流：同一 token 60 秒内只落一次库（见 should_record_token_use）。
                    if should_record_token_use(token) {
                        if let Err(e) = db.record_token_use(token, ip) {
                            tracing::warn!(
                                "check_token: record_token_use failed token={} ip={} err={e}",
                                token,
                                ip
                            );
                        }
                    }
                    // check expiry against activation time
                    return token_is_valid(&row, row.duration_seconds);
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

    /// 这张卡要不要绑定设备：**只有显式私卡/配对卡才绑**。
    ///
    /// - `kind` 为空（老卡密、控制台默认生成的）：公开卡，谁都能用，不绑；
    /// - `public`：公开/测试卡，不绑；
    /// - `pair`（配对卡）、`private`：一卡一机，第一次用哪台就锁哪台。
    fn is_private_card(row: &crate::db::ApiTokenRow) -> bool {
        let k = row.kind.trim();
        !(k.is_empty() || k.eq_ignore_ascii_case("public"))
    }

    /// 设备指纹一致性检查：没绑就绑上，绑了就要求每次都对上。
    ///
    /// - 库里全空：只绑定不检查；不传指纹的老 A 端仍能用，但永远绑不上；
    /// - 旧库只记了其中一项：只比非空的那项。
    ///
    /// 绑定仲裁走 `bind_token_device` 的乐观锁：`Ok(false)` 说明另一台设备先绑上了，
    /// 必须回库确认库里记的确实是自己的指纹才放行；写绑定失败也按不通过处理，
    /// 别让一次数据库异常把私卡退化成不绑定。
    fn device_binding_ok(
        &self,
        db: &Arc<Db>,
        row: &crate::db::ApiTokenRow,
        fp: Option<&DeviceFp>,
    ) -> bool {
        let bound_serial = row.bound_serial.trim();
        let bound_sn = row.bound_sn.trim();
        let bound_imei = row.bound_imei.trim();

        if bound_serial.is_empty() && bound_sn.is_empty() && bound_imei.is_empty() {
            let Some(fp) = fp else { return true };
            if fp.is_empty() {
                return true;
            }
            match db.bind_token_device(&row.token, &fp.serial, &fp.sn, &fp.imei) {
                Ok(true) => {
                    // 更新缓存：本机接下来的请求不该拿旧行去撞自己的绑定。
                    let mut bound = row.clone();
                    bound.bound_serial = fp.serial.clone();
                    bound.bound_sn = fp.sn.clone();
                    bound.bound_imei = fp.imei.clone();
                    self.remember_token(&row.token, &bound);
                    true
                }
                Ok(false) => {
                    // 缓存是绑定前的行、库里已经有主：以库里最新绑定为准（绕过缓存直查）。
                    match db.get_api_token(&row.token) {
                        Ok(Some(fresh)) => {
                            let ok = Self::bounds_match(
                                &fresh.bound_serial,
                                &fresh.bound_sn,
                                &fresh.bound_imei,
                                fp,
                            );
                            if ok {
                                self.remember_token(&row.token, &fresh);
                            }
                            ok
                        }
                        Ok(None) => false,
                        Err(e) => {
                            tracing::warn!(
                                "check_token: re-read after losing bind race failed token={} err={e}",
                                row.token
                            );
                            false
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("bind_token_device failed token={} err={e}", row.token);
                    false
                }
            }
        } else {
            // 已绑定的卡却不报指纹：只能当不匹配，不然换个客户端不带 header 就绕过了。
            let Some(fp) =
                fp.filter(|fp| Self::bounds_match(bound_serial, bound_sn, bound_imei, fp))
            else {
                return false;
            };
            // 指纹对上了但上报值跟库里不完全一样：把**库里缺的那几项补上**。
            // `serial`（可写伪装串号）跟到当前值；`sn` / `imei` 是硬件项，只补空、
            // 不拿新值盖旧值（宁可保留首次绑定的那个）。
            let new_serial = if fp.serial.trim().is_empty() {
                bound_serial.to_string()
            } else {
                fp.serial.clone()
            };
            let new_sn = if bound_sn.is_empty() {
                fp.sn.clone()
            } else {
                bound_sn.to_string()
            };
            let new_imei = if bound_imei.is_empty() {
                fp.imei.clone()
            } else {
                bound_imei.to_string()
            };
            if new_serial != bound_serial || new_sn != bound_sn || new_imei != bound_imei {
                match db.refresh_token_device(&row.token, &new_serial, &new_sn, &new_imei) {
                    Ok(()) => {
                        let mut current = row.clone();
                        current.bound_serial = new_serial;
                        current.bound_sn = new_sn;
                        current.bound_imei = new_imei;
                        self.remember_token(&row.token, &current);
                        tracing::info!(
                            "check_token: refreshed device fingerprint token={} was=({},{},{}) now=({},{},{})",
                            row.token,
                            bound_serial,
                            bound_sn,
                            bound_imei,
                            current.bound_serial.trim(),
                            current.bound_sn.trim(),
                            current.bound_imei.trim()
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "check_token: refresh_token_device failed token={} err={e}",
                            row.token
                        );
                    }
                }
            }
            true
        }
    }

    /// 已绑定行与本次上报的指纹是否一致。
    ///
    /// **任一稳定项对得上就算同一台**：`sn`（`ro.boot.serialno`，只读）和 `imei`
    /// （IMEI1，硬件写死）任意一项相等就放行 —— 序列号在部分机器上会被伪装层改写，
    /// 两者互为兵备。可写的 `serial`（`ro.serialno`）只作第三顺位兜底。
    ///
    /// 只按「两边都非空的项」比，有一项相等就过。两边没有任何可比项（含全空、
    /// 或只有占位值 `unknown` / `0`）绝不命中 —— 没有指纹不能当匹配。
    fn bounds_match(bound_serial: &str, bound_sn: &str, bound_imei: &str, fp: &DeviceFp) -> bool {
        let pairs = [
            (
                Self::fingerprint_part(bound_sn),
                Self::fingerprint_part(&fp.sn),
            ),
            (
                Self::fingerprint_part(bound_imei),
                Self::fingerprint_part(&fp.imei),
            ),
            (
                Self::fingerprint_part(bound_serial),
                Self::fingerprint_part(&fp.serial),
            ),
        ];
        // 两边都非空的项里，有任意一对相等就算命中。
        pairs
            .iter()
            .any(|(bound, got)| !bound.is_empty() && !got.is_empty() && bound == got)
    }

    /// 指纹里的一项去掉空白，顺手把 AOSP 读不到序列号时给的占位值当空处理 ——
    /// 不然两台都报 `unknown` 的机器会互相命中。
    fn fingerprint_part(value: &str) -> &str {
        let value = value.trim();
        if value.eq_ignore_ascii_case("unknown") || value == "0" {
            ""
        } else {
            value
        }
    }
    /// Sliding-window rate limit，`key` 就是客户端 IP（见 check_auth）。返回是否放行。
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
        let window = Duration::from_secs(60);
        let mut map = crate::util::mu(&self.login_rate);
        let now = Instant::now();
        let bucket = map.entry(key.to_string()).or_default();
        prune_rate_bucket(bucket, now, window);
        if bucket.len() as u64 >= 5 {
            false
        } else {
            bucket.push_back(now);
            true
        }
    }

    fn allow_with_limit(
        &self,
        rate: &Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
        key: &str,
        limit: u64,
    ) -> bool {
        let mut map = crate::util::mu(rate);
        // 在锁内取时间，保证桶内时间递增，才能只弹出过期前缀。
        let now = Instant::now();
        // 桶空了不删，表只涨不消；攒到一定规模就把过期的清一遭。
        if map.len() > RATE_MAP_MAX && !map.contains_key(key) {
            map.retain(|_, v| {
                prune_rate_bucket(v, now, self.rate_limit_window);
                !v.is_empty()
            });
        }
        let bucket = map.entry(key.to_string()).or_default();
        prune_rate_bucket(bucket, now, self.rate_limit_window);
        if bucket.len() as u64 >= limit {
            false
        } else {
            bucket.push_back(now);
            true
        }
    }
}

/// 每个时间戳只入队/出队一次，热 IP 不再每次请求扫描整个窗口。
/// 保留精确滑动窗口语义：恰好位于窗口边界的请求已经过期。
fn prune_rate_bucket(bucket: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while bucket
        .front()
        .is_some_and(|t| now.duration_since(*t) >= window)
    {
        bucket.pop_front();
    }
}

/// Check expiry of an already-activated token. Returns true if not expired.
/// A token with no `activated_at` is treated as not-yet-activated (valid).
/// Callers pass the already-fetched row; this must not query the DB again.
fn token_is_valid(row: &crate::db::ApiTokenRow, duration_seconds: i64) -> bool {
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

#[cfg(test)]
mod rate_tests {
    use super::*;

    #[test]
    fn pruning_keeps_live_entries_and_expires_window_boundary() {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let live = now - Duration::from_secs(59);
        let mut bucket = VecDeque::from([now - Duration::from_secs(61), now - window, live, now]);
        prune_rate_bucket(&mut bucket, now, window);
        assert_eq!(bucket, VecDeque::from([live, now]));
        prune_rate_bucket(&mut bucket, now + window, window);
        assert!(bucket.is_empty());
    }

    #[test]
    fn limits_remain_exact_and_independent_per_ip() {
        let auth = AuthState::new(String::new(), 2, 60, true);
        assert!(auth.allow("one"));
        assert!(auth.allow("one"));
        assert!(!auth.allow("one"));
        assert!(auth.allow("two"));
        assert!(auth.allow_invalid("one"));
        for _ in 0..5 {
            assert!(auth.allow_login_attempt("one:admin"));
        }
        assert!(!auth.allow_login_attempt("one:admin"));
    }

    #[test]
    fn hot_large_map_does_not_rescan_other_buckets() {
        let auth = AuthState::new(String::new(), 2, 60, true);
        let old = Instant::now() - Duration::from_secs(61);
        {
            let mut map = crate::util::mu(&auth.rate);
            for i in 0..=RATE_MAP_MAX {
                map.insert(format!("cold-{i}"), VecDeque::from([old]));
            }
            map.insert("hot".into(), VecDeque::new());
        }
        assert!(auth.allow("hot"));
        assert!(crate::util::mu(&auth.rate).contains_key("cold-0"));
        assert!(auth.allow("new-ip"));
        assert!(!crate::util::mu(&auth.rate).contains_key("cold-0"));
    }

    #[test]
    #[ignore = "manual hot-window performance comparison"]
    fn bench_hot_window_pruning() {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let rounds = 2000;
        let mut old = vec![now; 60000];
        let start = Instant::now();
        for _ in 0..rounds {
            old.retain(|t| now.duration_since(*t) < window);
        }
        let scan = start.elapsed();
        let mut new = VecDeque::from(vec![now; 60000]);
        let start = Instant::now();
        for _ in 0..rounds {
            prune_rate_bucket(&mut new, now, window);
        }
        let prefix = start.elapsed();
        assert_eq!(old.len(), new.len());
        eprintln!("{rounds} prunes, 60000 live entries: scan={scan:?}, prefix={prefix:?}");
    }
}

#[cfg(test)]
mod allows_tests {
    use super::TokenMeta;

    fn meta(kind: &str, pair: &str) -> TokenMeta {
        TokenMeta {
            role: "a".to_string(),
            pair_id: pair.to_string(),
            kind: kind.to_string(),
        }
    }

    /// 普通卡只跟普通卡互通（任意），不渗到私卡。两个方向都要拒。
    #[test]
    fn public_cards_only_pair_with_public() {
        assert!(meta("public", "").allows(&meta("public", "")));
        // 普通卡在左
        assert!(!meta("public", "").allows(&meta("pair", "x")));
        // 普通卡在右（反过来）
        assert!(!meta("pair", "x").allows(&meta("public", "")));
        // 普通卡带 pair_id 也一样，kind 优先
        assert!(!meta("public", "y").allows(&meta("pair", "y")));
        assert!(!meta("pair", "y").allows(&meta("public", "y")));
    }

    /// 私卡之间：pair_id 没填的当无约束放行，填了就严格同组。两个方向都要试。
    #[test]
    fn private_pair_rules() {
        // 空在 A 侧
        assert!(meta("pair", "").allows(&meta("pair", "x")));
        // 空在 B 侧（反过来）
        assert!(meta("pair", "x").allows(&meta("pair", "")));
        // 都空
        assert!(meta("pair", "").allows(&meta("pair", "")));
        // 同组
        assert!(meta("pair", "x").allows(&meta("pair", "x")));
        // 不同组，两个方向都拒
        assert!(!meta("pair", "x").allows(&meta("pair", "y")));
        assert!(!meta("pair", "y").allows(&meta("pair", "x")));
    }

    /// allows 必须对称：换一下 self/other 结果不变。
    #[test]
    fn allows_is_symmetric() {
        let cases = [
            ("public", ""),
            ("public", "x"),
            ("pair", ""),
            ("pair", "x"),
            ("pair", "y"),
            ("", ""),
            ("", "x"),
        ];
        for (ka, pa) in cases {
            for (kb, pb) in cases {
                let a = meta(ka, pa);
                let b = meta(kb, pb);
                assert_eq!(
                    a.allows(&b),
                    b.allows(&a),
                    "不对称: ({ka},{pa}) vs ({kb},{pb})"
                );
            }
        }
    }

    /// kind 为空的早期记录按私卡处理，而不是单独的第三种卡。
    #[test]
    fn empty_kind_behaves_like_private() {
        // 早期卡 pair_id 一般也为空 → 无约束放行
        assert!(meta("", "").allows(&meta("pair", "x")));
        assert!(meta("pair", "x").allows(&meta("", "")));
        // 但如果它带上了 pair_id，就按私卡严格比
        assert!(!meta("", "x").allows(&meta("pair", "y")));
    }
}

#[cfg(test)]
mod binding_tests {
    use super::{AuthState, DeviceFp};

    fn fp(serial: &str, sn: &str, imei: &str) -> DeviceFp {
        DeviceFp {
            serial: serial.to_string(),
            sn: sn.to_string(),
            imei: imei.to_string(),
        }
    }

    /// 绑定后只认同一台设备：`sn` / `imei` 任意一项对得上就算同一台，
    /// 可写项（`ro.serialno`）被伪装改掉也不拦；旧行只记了一项时只比那一项。
    #[test]
    fn bound_fingerprint_matches_field_wise() {
        let current = fp("SN1", "BOOT1", "860000000000001");
        assert!(AuthState::bounds_match(
            "SN1",
            "BOOT1",
            "860000000000001",
            &current
        ));
        // 只记了可写串号：比串号
        assert!(AuthState::bounds_match("SN1", "", "", &current));
        // 只记了 boot serial：比 boot serial
        assert!(AuthState::bounds_match("", "BOOT1", "", &current));
        // 只记了 IMEI：比 IMEI（硬件项，重启/伪装都不变）
        assert!(AuthState::bounds_match("", "", "860000000000001", &current));
        // 重启后 ro.serialno 换了值，boot serial 没变：同一台机器，放行。
        assert!(AuthState::bounds_match("OLD", "BOOT1", "", &current));
        // 换了设备：没有任何一项对得上就必须拒绕。
        assert!(!AuthState::bounds_match(
            "OTHER",
            "OTHERBOOT",
            "860000000000999",
            &current
        ));
        // boot serial 变了但 IMEI 没变：还是同一台（任一稳定项对得上即可）。
        assert!(AuthState::bounds_match(
            "",
            "OTHERBOOT",
            "860000000000001",
            &current
        ));
    }

    /// 未绑定行、以及已绑定卡不带指纹的请求，都必须判为不匹配：
    /// 前者不能在这个分支里被当成命中，后者不能靠省略 header 绕过。
    #[test]
    fn empty_side_never_matches() {
        let current = fp("SN1", "BOOT1", "860000000000001");
        assert!(!AuthState::bounds_match("", "", "", &current));
        assert!(!AuthState::bounds_match(
            "SN1",
            "BOOT1",
            "860000000000001",
            &fp("", "", "")
        ));
        // AOSP 读不到序列号时的占位值不能当指纹用，否则两台都报 unknown 的
        // 机器会互相命中。
        assert!(DeviceFp::default().is_empty());
        assert!(fp("unknown", " unknown ", "0").is_empty());
        assert!(!AuthState::bounds_match(
            "unknown",
            "unknown",
            "unknown",
            &fp("unknown", "unknown", "unknown")
        ));
    }
}
