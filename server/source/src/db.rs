//! MySQL persistence mirroring `relay_server/apps/portal/models.py`.
//!
//! Tables (reuse the Django portal_* schema, but with relay_rs-specific names):
//!   - `device_server_identity`: DeviceServerIdentity (server_keybox keybox)
//!   - `api_token`: ApiToken (issued A/B tokens)
//!   - `token_usage_log`: token -> IP usage history
//!   - `card_order`: card orders
//!   - `card_lottery`: card lottery records
//!   - `client_report`: ClientReport (diagnostics from A-side)
//!
//! All DATETIME columns are stored in Beijing time (session time_zone set to
//! `+08:00` on connect), matching the relay_server / Django convention.

use mysql::prelude::*;
use mysql::{params, Column, OptsBuilder, Pool, Value};
use serde_json::Value as JsonValue;

/// Card token durations (seconds), applied when a card is delivered.
pub const YEAR_SECS: i64 = 31_536_000;
pub const MONTH_SECS: i64 = 2_592_000;
pub const WEEK_SECS: i64 = 604_800; // 7 days

/// Find the positional index of a column by name in the row's column list.
fn col_index(row: &mysql::Row, col: &str) -> Option<usize> {
    row.columns_ref().iter().position(|c: &Column| c.name_str() == col)
}

/// Safely read an optional string / datetime / numeric column from a MySQL
/// row.  The official `row.get::<Option<String>>()` panics when the driver
/// returns the value as `Value::Date(..)` (DATETIME / TIMESTAMP columns),
/// or `Value::Int(..)`.  We decode based on the actual Value variant.
fn row_str_opt(row: &mysql::Row, col: &str) -> Option<String> {
    // 1) Try the naive path first for plain VARCHAR.
    match row.get_opt::<Option<String>, _>(col) {
        Some(Ok(Some(s))) => return Some(s),
        Some(Ok(None)) => return None,
        _ => {} // fallthrough: try Value-based decoding
    }
    // 2) Fallback: inspect the raw Value.
    let idx = col_index(row, col)?;
    value_to_string(row.as_ref(idx)?.clone())
}

/// Same as `row_str_opt` but looking up by column positional index.  Useful
/// for aggregate queries (`MIN(..)`, `MAX(..)`) whose output columns are
/// anonymous.
fn row_str_opt_pos(row: &mysql::Row, idx: usize) -> Option<String> {
    value_to_string(row.as_ref(idx)?.clone())
}

/// Convert a raw MySQL `Value` into an optional display string.
fn value_to_string(v: Value) -> Option<String> {
    match v {
        Value::NULL => None,
        Value::Bytes(b) => Some(String::from_utf8_lossy(&b).into_owned()),
        Value::Int(n) => Some(n.to_string()),
        Value::UInt(n) => Some(n.to_string()),
        Value::Float(f) => Some(f.to_string()),
        Value::Double(f) => Some(f.to_string()),
        Value::Date(y, mo, d, h, mi, s, _us) => Some(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            y, mo, d, h, mi, s
        )),
        Value::Time(neg, d, h, mi, s, _us) => {
            let sign = if neg { "-" } else { "" };
            Some(format!("{sign}{d}d {h:02}:{mi:02}:{s:02}"))
        }
    }
}

/// Same as `row_str_opt` but returning empty string on NULL.
fn row_str(row: &mysql::Row, col: &str) -> String {
    row_str_opt(row, col).unwrap_or_default()
}

pub struct Db {
    pool: Pool,
}

#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub algorithm: String, // "ec" | "rsa"
    pub certificate_chain_pem: String,
    pub private_key_pem_cipher: String,
    pub active: bool,
    pub machine_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct ApiTokenRow {
    pub id: i64,
    pub token: String,
    pub role: String, // "a" | "b"
    pub duration_seconds: i64,
    pub note: String,
    pub enabled: bool,
    pub activated_at: String,
    pub created_at: String,
    pub last_ip: String,
    pub last_used_at: String,
}

#[derive(Debug, Clone)]
pub struct CardOrderRow {
    pub id: i64,
    pub order_id: String,
    pub card_type: String, // "year" | "month"
    pub role: String,      // "a" | "b"
    pub price_cents: i64,
    pub status: String, // "pending" | "paid" | "delivered"
    pub bonus_draws: i64,
    pub contact: String,
    pub token_id: Option<i64>,
    pub created_at: String,
    pub paid_at: String,
    pub pay_type: String, // "alipay" | "wxpay" | ""
    pub trade_no: String, // 支付平台流水号
}

#[derive(Debug, Clone)]
pub struct ClientReportRow {
    pub device_id: String,
    pub level: String,
    pub code: String,
    pub message: String,
    pub detail_json: String,
    pub client_ip: String,
    pub user_agent: String,
    pub created_at: String,
}

impl Db {
    /// Connect to MySQL. `url` is a MySQL connection URL such as
    /// `mysql://user:pass@host:port/dbname`. Sets the session time zone to
    /// Beijing time (`+08:00`) so all `NOW()` values are local time.
    pub fn open(url: &str) -> anyhow::Result<Self> {
        let base = mysql::Opts::from_url(url)?;
        let opts = OptsBuilder::from_opts(base)
            .init(vec![
                "SET time_zone = '+08:00'".to_string(),
                "SET NAMES utf8mb4".to_string(),
            ]);
        let pool = Pool::new(opts)?;
        // Verify connection: check out once and immediately return it.
        let _conn = pool.get_conn()?;
        Ok(Self { pool })
    }

    /// Get a connection from the pool. The `OptsBuilder::init` above ensures
    /// every new connection has the correct time_zone and charset — no need
    /// to repeat SET queries on every checkout.
    fn conn(&self) -> anyhow::Result<mysql::PooledConn> {
        Ok(self.pool.get_conn()?)
    }

    // ---- DeviceServerIdentity ----

    pub fn upsert_device_identity(&self, id: &DeviceIdentity) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        // Encrypt the private key at rest (Fernet; no-op if no secret key).
        let private_key_cipher = crate::crypto::encrypt_private_pem(&id.private_key_pem_cipher);
        conn.exec_drop(
            r#"
            INSERT INTO device_server_identity
                (device_id, algorithm, certificate_chain_pem, private_key_pem_cipher,
                 active, machine_id, created_at)
            VALUES (:device_id, :algorithm, :cert, :key, :active, :machine_id,
                    COALESCE(:created_at, NOW()))
            ON DUPLICATE KEY UPDATE
                certificate_chain_pem = VALUES(certificate_chain_pem),
                private_key_pem_cipher = VALUES(private_key_pem_cipher),
                active = VALUES(active),
                machine_id = VALUES(machine_id)
            "#,
            params! {
                "device_id" => &id.device_id,
                "algorithm" => &id.algorithm,
                "cert" => &id.certificate_chain_pem,
                "key" => &private_key_cipher,
                "active" => id.active as i64,
                "machine_id" => &id.machine_id,
                "created_at" => if id.created_at.is_empty() { None } else { Some(&id.created_at) },
            },
        )?;
        Ok(())
    }

    fn device_identity_from_row(row: mysql::Row) -> anyhow::Result<DeviceIdentity> {
        let device_id = row_str(&row, "device_id");
        let algorithm = row_str(&row, "algorithm");
        let certificate_chain_pem = row_str(&row, "certificate_chain_pem");
        let private_key_pem_cipher = row_str(&row, "private_key_pem_cipher");
        let active: i64 = row.get("active").unwrap_or(0);
        let machine_id = row_str(&row, "machine_id");
        let created_at = row_str(&row, "created_at");
        Ok(DeviceIdentity {
            device_id,
            algorithm,
            certificate_chain_pem,
            private_key_pem_cipher,
            active: active != 0,
            machine_id,
            created_at,
        })
    }

    pub fn get_active_device_identity(&self) -> anyhow::Result<Option<DeviceIdentity>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT device_id, algorithm, certificate_chain_pem, private_key_pem_cipher,
                    active, machine_id, created_at
             FROM device_server_identity WHERE active = 1 ORDER BY id DESC LIMIT 1",
            (),
        )?;
        match rows.into_iter().next() {
            Some(r) => {
                let mut d = Self::device_identity_from_row(r)?;
                d.private_key_pem_cipher =
                    crate::crypto::decrypt_private_pem(&d.private_key_pem_cipher);
                Ok(Some(d))
            }
            None => Ok(None),
        }
    }

    pub fn get_device_identity_by_id(
        &self,
        device_id: &str,
        algorithm: &str,
    ) -> anyhow::Result<Option<DeviceIdentity>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT device_id, algorithm, certificate_chain_pem, private_key_pem_cipher,
                    active, machine_id, created_at
             FROM device_server_identity WHERE device_id = :device_id AND algorithm = :algorithm AND active = 1 LIMIT 1",
            params! {
                "device_id" => device_id,
                "algorithm" => algorithm,
            },
        )?;
        match rows.into_iter().next() {
            Some(r) => {
                let mut d = Self::device_identity_from_row(r)?;
                d.private_key_pem_cipher =
                    crate::crypto::decrypt_private_pem(&d.private_key_pem_cipher);
                Ok(Some(d))
            }
            None => Ok(None),
        }
    }

    /// Fetch any active identity for a device regardless of algorithm — a
    /// targeted lookup replacing a full `list_device_identities()` scan when
    /// the exact algorithm match is missing.
    pub fn get_any_device_identity(&self, device_id: &str) -> anyhow::Result<Option<DeviceIdentity>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT device_id, algorithm, certificate_chain_pem, private_key_pem_cipher,
                    active, machine_id, created_at
             FROM device_server_identity WHERE device_id = :device_id AND active = 1 LIMIT 1",
            params! { "device_id" => device_id },
        )?;
        match rows.into_iter().next() {
            Some(r) => {
                let mut d = Self::device_identity_from_row(r)?;
                d.private_key_pem_cipher =
                    crate::crypto::decrypt_private_pem(&d.private_key_pem_cipher);
                Ok(Some(d))
            }
            None => Ok(None),
        }
    }

    /// Lists identity metadata without private-key decryption — only the
    /// display fields (device_id, algorithm, cert_count, active, etc.) are
    /// populated. Callers that only need the identity list for display should
    /// prefer this to avoid the overhead of Fernet decryption.
    pub fn list_device_identities_meta(&self) -> anyhow::Result<Vec<DeviceIdentity>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT device_id, algorithm, certificate_chain_pem, private_key_pem_cipher,
                    active, machine_id, created_at
             FROM device_server_identity ORDER BY id DESC",
            (),
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(Self::device_identity_from_row(r)?);
        }
        Ok(out)
    }

    pub fn set_device_identity_active(&self, device_id: &str, active: bool) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "UPDATE device_server_identity SET active = :active WHERE device_id = :device_id",
            params! {
                "active" => active as i64,
                "device_id" => device_id,
            },
        )?;
        Ok(())
    }

    pub fn delete_device_identity(&self, device_id: &str) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "DELETE FROM device_server_identity WHERE device_id = :device_id",
            params! {
                "device_id" => device_id,
            },
        )?;
        Ok(())
    }

    /// Delete every identity row whose `machine_id` starts with `prefix`
    /// (e.g. `"auto-cover"`), returning the number of deleted rows. Used to
    /// clear the identities that the auto-cover mode wrote, without touching
    /// manually-uploaded or ordinary auto-keybox (`auto:<source>`) rows.
    pub fn delete_device_identities_by_machine_prefix(&self, prefix: &str) -> anyhow::Result<u64> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "DELETE FROM device_server_identity WHERE machine_id LIKE CONCAT(:prefix, '%')",
            params! {
                "prefix" => prefix,
            },
        )?;
        Ok(conn.affected_rows())
    }

    // ---- ApiToken ----

    fn api_token_from_row(row: mysql::Row) -> anyhow::Result<ApiTokenRow> {
        let id: i64 = row.get("id").unwrap_or(0);
        let token = row_str(&row, "token");
        let role = row_str(&row, "role");
        let duration_seconds: i64 = row.get("duration_seconds").unwrap_or(0);
        let note = row_str(&row, "note");
        let enabled: i64 = row.get("enabled").unwrap_or(0);
        Ok(ApiTokenRow {
            id,
            token,
            role,
            duration_seconds,
            note,
            enabled: enabled != 0,
            activated_at: row_str(&row, "activated_at"),
            created_at: row_str(&row, "created_at"),
            last_ip: row_str(&row, "last_ip"),
            last_used_at: row_str(&row, "last_used_at"),
        })
    }

    pub fn insert_api_token(
        &self,
        token: &str,
        role: &str,
        duration_seconds: i64,
        note: &str,
    ) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO api_token (token, role, duration_seconds, note)
             VALUES (:token, :role, :duration_seconds, :note)",
            params! {
                "token" => token,
                "role" => role,
                "duration_seconds" => duration_seconds,
                "note" => note,
            },
        )?;
        Ok(())
    }

    pub fn list_api_tokens(&self) -> anyhow::Result<Vec<ApiTokenRow>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT id, token, role, duration_seconds, note, enabled, activated_at,
                    created_at, last_ip, last_used_at
             FROM api_token ORDER BY id DESC",
            (),
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(Self::api_token_from_row(r)?);
        }
        Ok(out)
    }

    /// Look up a token row by its token string. Used for DB-token auth.
    pub fn get_api_token(&self, token: &str) -> anyhow::Result<Option<ApiTokenRow>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT id, token, role, duration_seconds, note, enabled, activated_at,
                    created_at, last_ip, last_used_at
             FROM api_token WHERE token = :token LIMIT 1",
            params! {
                "token" => token,
            },
        )?;
        match rows.into_iter().next() {
            Some(r) => Ok(Some(Self::api_token_from_row(r)?)),
            None => Ok(None),
        }
    }

    /// Set `activated_at` on first use (activation-based expiry). Returns true
    /// if this call performed the activation.
    pub fn activate_token_if_needed(&self, token: &str) -> anyhow::Result<bool> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT activated_at FROM api_token WHERE token = :token LIMIT 1",
            params! { "token" => token },
        )?;
        let already = rows.first().and_then(|r| row_str_opt(r, "activated_at"));
        if already.is_some() {
            return Ok(false);
        }
        conn.exec_drop(
            "UPDATE api_token SET activated_at = NOW() WHERE token = :token",
            params! { "token" => token },
        )?;
        Ok(true)
    }

    /// Record the client IP and last-used time for a token, appending a row to
    /// the usage log (for historical IP listing).
    pub fn record_token_use(&self, token: &str, ip: &str) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        // BEGIN/COMMIT must use the text protocol: the mysql crate sends
        // `exec_drop` (even with empty params) through the prepared-statement
        // protocol, which MySQL rejects for BEGIN/COMMIT with ERROR 1295.
        conn.query_drop("BEGIN")?;
        conn.exec_drop(
            "UPDATE api_token SET last_ip = :ip, last_used_at = NOW() WHERE token = :token",
            params! {
                "ip" => ip,
                "token" => token,
            },
        )?;
        conn.exec_drop(
            "INSERT INTO token_usage_log (token, ip) VALUES (:token, :ip)",
            params! {
                "token" => token,
                "ip" => ip,
            },
        )?;
        conn.query_drop("COMMIT")?;
        Ok(())
    }

    /// Distinct historical IPs used by a token, with first/last use time and
    /// use count, ordered by most recent first.
    pub fn token_usage_ips(&self, token: &str) -> anyhow::Result<Vec<JsonValue>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT ip, MIN(used_at), MAX(used_at), COUNT(*)
             FROM token_usage_log WHERE token = :token
             GROUP BY ip ORDER BY MAX(used_at) DESC",
            params! { "token" => token },
        )?;
        let mut out = Vec::new();
        for r in rows {
            let ip = row_str(&r, "ip");
            // Columns returned without names via aggregate MIN/MAX; use positional lookup.
            let first = row_str_opt_pos(&r, 1).unwrap_or_default();
            let last = row_str_opt_pos(&r, 2).unwrap_or_default();
            let count: i64 = r.get(3).unwrap_or(0);
            out.push(serde_json::json!({
                "ip": ip,
                "first_used_at": first,
                "last_used_at": last,
                "count": count,
            }));
        }
        Ok(out)
    }

    /// Whether any DB token exists (used for anonymous-allow fallback parity).
    pub fn has_any_token(&self) -> anyhow::Result<bool> {
        let mut conn = self.conn()?;
        let n: Option<i64> = conn.exec_first("SELECT count(*) FROM api_token", ())?;
        Ok(n.unwrap_or(0) > 0)
    }

    pub fn set_token_enabled(&self, id: i64, enabled: bool) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "UPDATE api_token SET enabled = :enabled WHERE id = :id",
            params! {
                "enabled" => enabled as i64,
                "id" => id,
            },
        )?;
        Ok(())
    }

    pub fn delete_token(&self, id: i64) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop("DELETE FROM api_token WHERE id = :id", params! { "id" => id })?;
        Ok(())
    }

    /// Look up a token row by its numeric id.
    pub fn get_token_by_id(&self, id: i64) -> anyhow::Result<Option<ApiTokenRow>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT id, token, role, duration_seconds, note, enabled, activated_at,
                    created_at, last_ip, last_used_at
             FROM api_token WHERE id = :id LIMIT 1",
            params! { "id" => id },
        )?;
        match rows.into_iter().next() {
            Some(r) => Ok(Some(Self::api_token_from_row(r)?)),
            None => Ok(None),
        }
    }

    // ---- Card orders ----

    fn card_order_from_row(row: mysql::Row) -> anyhow::Result<CardOrderRow> {
        let id: i64 = row.get("id").unwrap_or(0);
        let order_id = row_str(&row, "order_id");
        let card_type = row_str(&row, "card_type");
        let role = row_str(&row, "role");
        let price_cents: i64 = row.get("price_cents").unwrap_or(0);
        let status = row_str(&row, "status");
        let bonus_draws: i64 = row.get("bonus_draws").unwrap_or(0);
        let contact = row_str(&row, "contact");
        let token_id: Option<i64> = row.get("token_id");
        Ok(CardOrderRow {
            id,
            order_id,
            card_type,
            role,
            price_cents,
            status,
            bonus_draws,
            contact,
            token_id,
            created_at: row_str(&row, "created_at"),
            paid_at: row_str(&row, "paid_at"),
            pay_type: row_str(&row, "pay_type"),
            trade_no: row_str(&row, "trade_no"),
        })
    }

    pub fn create_card_order(
        &self,
        order_id: &str,
        card_type: &str,
        role: &str,
        price_cents: i64,
        bonus_draws: i64,
        contact: &str,
        pay_type: &str,
    ) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO card_order (order_id, card_type, role, price_cents, bonus_draws, contact, pay_type)
             VALUES (:order_id, :card_type, :role, :price_cents, :bonus_draws, :contact, :pay_type)",
            params! {
                "order_id" => order_id,
                "card_type" => card_type,
                "role" => role,
                "price_cents" => price_cents,
                "bonus_draws" => bonus_draws,
                "contact" => contact,
                "pay_type" => pay_type,
            },
        )?;
        Ok(())
    }

    /// 保存支付平台返回的流水号。
    pub fn set_order_trade_no(&self, order_id: &str, trade_no: &str) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "UPDATE card_order SET trade_no = :trade_no WHERE order_id = :order_id",
            params! {
                "trade_no" => trade_no,
                "order_id" => order_id,
            },
        )?;
        Ok(())
    }

    pub fn get_card_order(&self, order_id: &str) -> anyhow::Result<Option<CardOrderRow>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT id, order_id, card_type, role, price_cents, status, bonus_draws,
                    contact, token_id, created_at, paid_at, pay_type, trade_no
             FROM card_order WHERE order_id = :order_id LIMIT 1",
            params! { "order_id" => order_id },
        )?;
        match rows.into_iter().next() {
            Some(r) => Ok(Some(Self::card_order_from_row(r)?)),
            None => Ok(None),
        }
    }

    pub fn list_card_orders(&self) -> anyhow::Result<Vec<CardOrderRow>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT id, order_id, card_type, role, price_cents, status, bonus_draws,
                    contact, token_id, created_at, paid_at, pay_type, trade_no
             FROM card_order ORDER BY id DESC",
            (),
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(Self::card_order_from_row(r)?);
        }
        Ok(out)
    }

    /// Find delivered orders by exact contact match, returning their card
    /// tokens (look up via token_id) for the "query card by contact" feature.
    pub fn find_orders_by_contact(&self, contact: &str) -> anyhow::Result<Vec<CardOrderRow>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT id, order_id, card_type, role, price_cents, status, bonus_draws,
                    contact, token_id, created_at, paid_at, pay_type, trade_no
             FROM card_order WHERE contact = :contact AND status = 'delivered'
             ORDER BY id DESC",
            params! { "contact" => contact },
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(Self::card_order_from_row(r)?);
        }
        Ok(out)
    }

    /// Atomically mark an order delivered and create/link its API token.
    ///
    /// Runs in a single transaction with `SELECT ... FOR UPDATE` so concurrent
    /// payment callbacks (or platform retries) serialize on the order row:
    /// exactly one token is minted per order, and a claimed-but-undelivered
    /// order (left by an interrupted attempt) is recovered instead of being
    /// stuck in `paid`.
    ///
    /// Returns `Ok(Some(token))` when the order is (or was already) delivered,
    /// `Ok(None)` if it was already delivered but no token is resolvable,
    /// `Err` for a missing order or a DB failure.
    pub fn deliver_order_with_token(
        &self,
        order_id: &str,
        role: &str,
        card_type: &str,
    ) -> anyhow::Result<Option<String>> {
        let mut conn = self.conn()?;
        conn.query_drop("BEGIN")?;
        // Serialize on the order row so two concurrent callbacks cannot both mint.
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT id, status, token_id FROM card_order WHERE order_id = :oid FOR UPDATE",
            params! { "oid" => order_id },
        )?;
        let Some(row) = rows.first() else {
            conn.query_drop("ROLLBACK")?;
            anyhow::bail!("order not found");
        };
        let status = row_str(row, "status");
        let token_id: Option<i64> = row.get("token_id");
        if status == "delivered" {
            conn.query_drop("COMMIT")?;
            let token = token_id
                .and_then(|id| self.get_token_by_id(id).ok().flatten())
                .map(|t| t.token)
                .unwrap_or_default();
            return Ok(if token.is_empty() { None } else { Some(token) });
        }
        // pending — or a `paid` row left by an interrupted attempt: mint the
        // token and deliver in the same transaction.
        let token = crate::util::generate_token_string();
        let duration = match card_type {
            "year" => YEAR_SECS,
            "week" => WEEK_SECS,
            _ => MONTH_SECS,
        };
        let note = format!("card:{card_type}");
        if let Err(e) = conn.exec_drop(
            "INSERT INTO api_token (token, role, duration_seconds, note)
             VALUES (:t, :r, :d, :n)",
            params! { "t" => &token, "r" => role, "d" => duration, "n" => &note },
        ) {
            let _ = conn.query_drop("ROLLBACK");
            return Err(e.into());
        }
        let inserted_id: Option<i64> = conn
            .exec_first(
                "SELECT id FROM api_token WHERE token = :t LIMIT 1",
                params! { "t" => &token },
            )
            .map_err(|e| {
                let _ = conn.query_drop("ROLLBACK");
                e
            })?;
        let inserted_id = inserted_id.unwrap_or(0);
        if let Err(e) = conn.exec_drop(
            "UPDATE card_order SET status='delivered', token_id=:tid,
                    paid_at=COALESCE(paid_at, NOW())
             WHERE order_id=:oid",
            params! { "tid" => inserted_id, "oid" => order_id },
        ) {
            let _ = conn.query_drop("ROLLBACK");
            return Err(e.into());
        }
        conn.query_drop("COMMIT")?;
        Ok(Some(token))
    }

    // ---- Card lottery ----

    /// Count today's lottery draws for a client key (IP/device fingerprint).
    pub fn lottery_draws_today(&self, client_key: &str, today: &str) -> anyhow::Result<i64> {
        let mut conn = self.conn()?;
        let n: Option<i64> = conn.exec_first(
            "SELECT count(*) FROM card_lottery WHERE client_key = :client_key AND draw_date = :today",
            params! {
                "client_key" => client_key,
                "today" => today,
            },
        )?;
        Ok(n.unwrap_or(0))
    }

    pub fn insert_lottery_record(
        &self,
        client_key: &str,
        today: &str,
        won: bool,
        card_type: &str,
    ) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO card_lottery (client_key, draw_date, won, card_type)
             VALUES (:client_key, :today, :won, :card_type)",
            params! {
                "client_key" => client_key,
                "today" => today,
                "won" => won as i64,
                "card_type" => card_type,
            },
        )?;
        Ok(())
    }

    // ---- ClientReport ----

    pub fn insert_client_report(&self, r: &ClientReportRow) -> anyhow::Result<()> {
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT INTO client_report
                (device_id, level, code, message, detail_json, client_ip, user_agent, created_at)
             VALUES (:device_id, :level, :code, :message, :detail_json, :client_ip, :user_agent, :created_at)",
            params! {
                "device_id" => &r.device_id,
                "level" => &r.level,
                "code" => &r.code,
                "message" => &r.message,
                "detail_json" => &r.detail_json,
                "client_ip" => &r.client_ip,
                "user_agent" => &r.user_agent,
                "created_at" => &r.created_at,
            },
        )?;
        Ok(())
    }

    pub fn list_client_reports(&self, limit: usize) -> anyhow::Result<Vec<ClientReportRow>> {
        let mut conn = self.conn()?;
        let rows: Vec<mysql::Row> = conn.exec(
            "SELECT device_id, level, code, message, detail_json, client_ip, user_agent, created_at
             FROM client_report ORDER BY id DESC LIMIT :limit",
            params! { "limit" => limit as i64 },
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(ClientReportRow {
                device_id: row_str(&r, "device_id"),
                level: row_str(&r, "level"),
                code: row_str(&r, "code"),
                message: row_str(&r, "message"),
                detail_json: row_str(&r, "detail_json"),
                client_ip: row_str(&r, "client_ip"),
                user_agent: row_str(&r, "user_agent"),
                created_at: row_str(&r, "created_at"),
            });
        }
        Ok(out)
    }
}
