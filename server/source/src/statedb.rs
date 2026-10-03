//! 服务端「要长期保留的状态」统一放一个 SQLite 文件里。
//!
//! 为什么不用原来那两套 JSON（2026-10-03 实测）：
//!
//!   - `data/sessions.json` 73.9 MB / 11714 条 / 每条 7.9 KB，**每次新出证都整份
//!     序列化重写一遍**，出证约 400 次/天 → 25~30 GB/天的写放大；进程启动还得
//!     解析这 74 MB。
//!   - `data/soter_slots.json` 178 KB，148 次/天整份重写，而且**没有 tmp+rename**
//!     （会话表有）—— 崩在写盘中间就解不开，`load_slots` 直接按空算：钉子全丢、
//!     层跟着抖。cap 抬到 512 之后这个文件还要往 MB 级长。
//!
//! SQLite 一条 INSERT/UPDATE 就把这几件事一起解决了：没有写放大、原子（WAL）、
//! 崩不坏、要删按条件删、要数按条件数。
//!
//! 表：
//!   - `sessions`           —— 原来 `data/sessions.json` 那份（keybox / 自签会话）
//!   - `soter_slots`        —— 原来 `data/soter_slots.json` 里的钉子（层 + 时间戳）
//!   - `soter_slot_owners`  —— 原来钉子记录里的 `owners`，一个账号一行
//!
//! `sessions.leaf_key_pem` 里存的**就是原来落盘的那份密文**（Fernet），迁移是把
//! 字节搬过去、不是重新加密 —— 所以拿旧文件回滚也读得回来。
//!
//! 内存里那份 map 仍然是权威（读路径一个 DB 查询都不加），这里是写穿 + 启动装载。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

/// 默认落盘位置（systemd 的 WorkingDirectory 是 /opt/relay）。`OMMEGA_STATE_DB` 可覆盖。
pub const DEFAULT_PATH: &str = "data/relay_state.db";

/// 旧的两份 JSON，只在库里是空的时候导一次；导完不动它们（留着当回滚源）。
const LEGACY_SESSIONS: &str = "data/sessions.json";
const LEGACY_SLOTS: &str = "data/soter_slots.json";

/// 一个槽位里每一族最多记几个指纹。三族分开算：一个账号在每一族最多留一个指纹，
/// 所以「同族 512 个」是上限而不是 512/3。满了不是「不收新的」，而是把这一族里
/// 最久没见到的那一条换出去（LRU，见 `add_owner`）。
pub const OWNER_FAMILY_CAP: usize = 512;

/// 会话表条数上限，跟 B 端 `SESSION_MAX_FILES` 一个口径。超了按「最久没用」淘汰。
pub const SESSION_MAX: usize = 20_000;

/// 启动时只把最近用过的这么多条会话装进内存。一条（链 + 私钥密文）实测 6~8 KB，
/// 8000 条 ≈ 50 MB；没装进来的留在库里，取用时按 alias 单查一条（有索引）。
pub const SESSION_MEMORY_HOT: usize = 8_000;

/// v2：会话表加了 `used_epoch_ms`（最后一次使用）。TTL 和 LRU 都按它算，不再看创建时间。
const SCHEMA_VERSION: i64 = 2;

/// 会话表里一行（字段跟旧的 `SessionFile` 对齐，多一个最后使用时间）。
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRow {
    pub chain_pem: String,
    pub leaf_key_pem: String,
    pub created_epoch_ms: u64,
    /// 最后一次被取用的时间。老库迁上来时先拿 `created_epoch_ms` 顶上。
    pub used_epoch_ms: u64,
}

/// 启动时把槽位表整个装进内存用的快照。
#[derive(Debug, Default, PartialEq)]
pub struct SlotsSnapshot {
    /// (slot_id, layer, at_millis)
    pub slots: Vec<(String, String, i64)>,
    /// (slot_id, family, token, last_seen_ms)
    pub owners: Vec<(String, String, String, i64)>,
}

/// 记一个账号指纹的结果。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OwnerAdd {
    /// 这一族里现在有几个指纹（等于「这个槽位上这一族见过几个账号」）。
    pub family_count: usize,
    /// 这一条是新记的还是早就有了（只有新记的才值得打日志）。
    pub inserted: bool,
}

/// 从旧 JSON 导进来的账。
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ImportReport {
    pub sessions: usize,
    pub slots: usize,
    pub owners: usize,
    pub files: Vec<String>,
}

impl ImportReport {
    pub fn is_empty(&self) -> bool {
        self.sessions == 0 && self.slots == 0 && self.owners == 0
    }
}

pub struct StateDb {
    conn: Mutex<Connection>,
    path: String,
}

impl StateDb {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(dir) = Path::new(path).parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create state db dir {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("open {path}"))?;
        let db = Self {
            conn: Mutex::new(conn),
            path: path.to_string(),
        };
        db.init()?;
        Ok(db)
    }

    /// 测试、或者落盘不可用时用（同一套代码路径，只是不持久）。
    pub fn open_in_memory() -> Result<Self> {
        let db = Self {
            conn: Mutex::new(Connection::open_in_memory().context("open :memory:")?),
            path: ":memory:".to_string(),
        };
        db.init()?;
        Ok(db)
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    fn plain(&self) -> MutexGuard<'_, Connection> {
        crate::util::mu(&self.conn)
    }

    fn init(&self) -> Result<()> {
        let conn = self.plain();
        // WAL：读写不互相堵，崩了也只剩最后一条事务没落。`:memory:` 上会返回
        // "memory"，不是错误。
        let _mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .unwrap_or_else(|_| "unknown".to_string());
        conn.execute_batch(
            "PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;
             PRAGMA foreign_keys=ON;",
        )
        .context("state db pragmas")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions(
                 alias            TEXT PRIMARY KEY,
                 chain_pem        TEXT NOT NULL,
                 leaf_key_pem     TEXT NOT NULL,
                 created_epoch_ms INTEGER NOT NULL,
                 used_epoch_ms    INTEGER NOT NULL DEFAULT 0);
             CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_epoch_ms);
             CREATE TABLE IF NOT EXISTS soter_slots(
                 slot_id   TEXT PRIMARY KEY,
                 layer     TEXT NOT NULL DEFAULT '',
                 at_millis INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS soter_slot_owners(
                 slot_id       TEXT NOT NULL,
                 family        TEXT NOT NULL,
                 token         TEXT NOT NULL,
                 first_seen_ms INTEGER NOT NULL,
                 last_seen_ms  INTEGER NOT NULL,
                 PRIMARY KEY(slot_id, family, token));
             CREATE INDEX IF NOT EXISTS idx_owners_slot ON soter_slot_owners(slot_id, family);",
        )
        .context("state db schema")?;
        // v1 -> v2：老库的会话表没有 `used_epoch_ms`。补上，并拿创建时间顶上
        // （那时候我们唯一的「最后使用」证据就是它）。
        if !Self::has_column(&conn, "sessions", "used_epoch_ms")? {
            conn.execute_batch(
                "ALTER TABLE sessions ADD COLUMN used_epoch_ms INTEGER NOT NULL DEFAULT 0;
                 UPDATE sessions SET used_epoch_ms = created_epoch_ms WHERE used_epoch_ms = 0;",
            )
            .context("state db 迁移 sessions.used_epoch_ms")?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_sessions_used ON sessions(used_epoch_ms);",
        )
        .context("state db index idx_sessions_used")?;
        // 账号指纹的「最后见到」：从旧 JSON 导进来的那批当时写的是 0（那份 JSON 里
        // 压根没有时间），0 一律按「未知」算。这行回填不能省 —— 直接挂上 TTL，0 会被
        // 当成「过期了几辈子」，第一次启动就把整张表的账号记录清光（2026-10-03 真发生
        // 过一次，5298 条剩 386 条）。拿当下顶上：我们至少知道它到这一刻还在库里。
        // 只补 0 的行，正常记录动不着；补过之后这里每次都返回 0。
        let fixed = conn
            .execute(
                "UPDATE soter_slot_owners SET first_seen_ms = ?1, last_seen_ms = ?1
                  WHERE last_seen_ms = 0",
                params![chrono::Utc::now().timestamp_millis()],
            )
            .context("state db 回填 soter_slot_owners 的时间戳")?;
        if fixed > 0 {
            tracing::info!("state db: {fixed} 条账号指纹的时间戳是 0，按现在回填");
        }
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        if version < SCHEMA_VERSION {
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)
                .context("state db user_version")?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // 会话表（原 data/sessions.json）
    // -----------------------------------------------------------------------

    /// 会话表的列，顺序跟 `session_row` 里读的一一对应。
    const SESSION_COLS: &'static str =
        "alias, chain_pem, leaf_key_pem, created_epoch_ms, used_epoch_ms";

    fn session_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(String, SessionRow)> {
        Ok((
            r.get::<_, String>(0)?,
            SessionRow {
                chain_pem: r.get(1)?,
                leaf_key_pem: r.get(2)?,
                created_epoch_ms: r.get::<_, i64>(3)? as u64,
                used_epoch_ms: r.get::<_, i64>(4)? as u64,
            },
        ))
    }

    pub fn session_count(&self) -> Result<usize> {
        let conn = self.plain();
        let n: i64 = conn.query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// 全量装载（测试/演练用；进程启动走 `load_hot_sessions`）。
    pub fn load_sessions(&self) -> Result<Vec<(String, SessionRow)>> {
        let conn = self.plain();
        let mut stmt = conn.prepare(&format!("SELECT {} FROM sessions", Self::SESSION_COLS))?;
        let rows = stmt.query_map([], |r| Self::session_row(r))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// 启动时只装「最近用过的」那批：内存当热缓存，冷的留在库里按 alias 单查。
    pub fn load_hot_sessions(&self, limit: usize) -> Result<Vec<(String, SessionRow)>> {
        let conn = self.plain();
        let mut stmt = conn.prepare(&format!(
            "SELECT {} FROM sessions ORDER BY used_epoch_ms DESC, created_epoch_ms DESC LIMIT ?1",
            Self::SESSION_COLS
        ))?;
        let rows = stmt.query_map(params![limit as i64], |r| Self::session_row(r))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// 按 alias 单查一条（内存热缓存没命中时走这里）。
    pub fn get_session_row(&self, alias: &str) -> Result<Option<SessionRow>> {
        let conn = self.plain();
        let row = conn
            .query_row(
                &format!(
                    "SELECT {} FROM sessions WHERE alias = ?1",
                    Self::SESSION_COLS
                ),
                params![alias],
                |r| Self::session_row(r),
            )
            .optional()?;
        Ok(row.map(|(_, s)| s))
    }

    /// 一条会话一行；原来这里是「整份 74 MB 重写一遍」。
    pub fn upsert_session(&self, alias: &str, row: &SessionRow) -> Result<()> {
        let conn = self.plain();
        conn.execute(
            "INSERT INTO sessions(alias, chain_pem, leaf_key_pem, created_epoch_ms, used_epoch_ms)
             VALUES(?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(alias) DO UPDATE SET
                 chain_pem = excluded.chain_pem,
                 leaf_key_pem = excluded.leaf_key_pem,
                 created_epoch_ms = excluded.created_epoch_ms,
                 used_epoch_ms = excluded.used_epoch_ms",
            params![
                alias,
                row.chain_pem,
                row.leaf_key_pem,
                row.created_epoch_ms as i64,
                row.used_epoch_ms as i64
            ],
        )?;
        Ok(())
    }

    /// 顶一下「最后使用」时间（TTL 和 LRU 都看它）。调用方有节流，别每条请求都来。
    pub fn touch_session(&self, alias: &str, used_ms: i64) -> Result<()> {
        let conn = self.plain();
        conn.execute(
            "UPDATE sessions SET used_epoch_ms = ?2 WHERE alias = ?1",
            params![alias, used_ms],
        )?;
        Ok(())
    }

    /// 过期的会话按「最后使用」删。返回删了几条。
    pub fn delete_sessions_expired_before(&self, cutoff_ms: i64) -> Result<usize> {
        let conn = self.plain();
        Ok(conn.execute(
            "DELETE FROM sessions WHERE used_epoch_ms < ?1",
            params![cutoff_ms],
        )?)
    }

    /// 会话表超过 `cap` 条就从最久没用的开始删（LRU，丢的永远是没人用的那批）。
    /// 返回删了几条。
    pub fn trim_sessions_lru(&self, cap: usize) -> Result<usize> {
        let conn = self.plain();
        Ok(conn.execute(
            "DELETE FROM sessions WHERE alias IN (
                 SELECT alias FROM sessions
                 ORDER BY used_epoch_ms ASC, created_epoch_ms ASC
                 LIMIT (SELECT max(0, count(*) - ?1) FROM sessions))",
            params![cap as i64],
        )?)
    }

    // -----------------------------------------------------------------------
    // 槽位钉子 + 账号指纹（原 data/soter_slots.json）
    // -----------------------------------------------------------------------

    pub fn slot_count(&self) -> Result<usize> {
        let conn = self.plain();
        let n: i64 = conn.query_row("SELECT count(*) FROM soter_slots", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    pub fn slots_snapshot(&self) -> Result<SlotsSnapshot> {
        let conn = self.plain();
        let mut out = SlotsSnapshot::default();
        {
            let mut stmt = conn.prepare("SELECT slot_id, layer, at_millis FROM soter_slots")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                out.slots.push(row?);
            }
        }
        {
            let mut stmt = conn.prepare(
                "SELECT slot_id, family, token, last_seen_ms FROM soter_slot_owners ORDER BY first_seen_ms",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?;
            for row in rows {
                out.owners.push(row?);
            }
        }
        Ok(out)
    }

    pub fn upsert_slot(&self, slot_id: &str, layer: &str, at_millis: i64) -> Result<()> {
        let conn = self.plain();
        conn.execute(
            "INSERT INTO soter_slots(slot_id, layer, at_millis) VALUES(?1, ?2, ?3)
             ON CONFLICT(slot_id) DO UPDATE SET layer = excluded.layer, at_millis = excluded.at_millis",
            params![slot_id, layer, at_millis],
        )?;
        Ok(())
    }

    /// 拔钉子：**只删「钉层」这一行，账号记录留着**。
    ///
    /// 账号记录是「这个槽位上还认得出几个号」的判据（连坐拦截用）。清钥匙的时候
    /// 连它一起删，等于把「这里原本有好几个号」的证据也抹掉，下一次别人问就没法答。
    pub fn delete_slot_pin(&self, slot_id: &str) -> Result<()> {
        let conn = self.plain();
        conn.execute(
            "DELETE FROM soter_slots WHERE slot_id = ?1",
            params![slot_id],
        )?;
        Ok(())
    }

    /// 丢掉太久没见到的账号记录（TTL）。每条缓存都有过期时间，不留永生的行。
    ///
    /// 时间戳 0 的不碰：那是「不知道什么时候见的」（老数据/导入的），不是「很久没见」。
    /// 把它们当过期删掉，丢的是「这个槽位上原本有几个号」的判据。
    pub fn purge_owners_expired_before(&self, cutoff_ms: i64) -> Result<usize> {
        let conn = self.plain();
        Ok(conn.execute(
            "DELETE FROM soter_slot_owners WHERE last_seen_ms < ?1 AND last_seen_ms > 0",
            params![cutoff_ms],
        )?)
    }

    /// 记一个账号指纹。
    ///
    /// 记过就只刷「最后见到」；没记过才插。这一族满了（`cap` 条）不是拒收新的，
    /// 而是把这一族里**最久没见到**的那条换出去 —— 丢的永远是最没用的那个，
    /// 正在用的号不会被新号挤掉。
    pub fn add_owner(
        &self,
        slot_id: &str,
        family: &str,
        token: &str,
        now_ms: i64,
        cap: usize,
    ) -> Result<OwnerAdd> {
        let conn = self.plain();
        let count: i64 = conn.query_row(
            "SELECT count(*) FROM soter_slot_owners WHERE slot_id = ?1 AND family = ?2",
            params![slot_id, family],
            |r| r.get(0),
        )?;
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM soter_slot_owners WHERE slot_id = ?1 AND family = ?2 AND token = ?3",
                params![slot_id, family, token],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if exists {
            conn.execute(
                "UPDATE soter_slot_owners SET last_seen_ms = ?4
                 WHERE slot_id = ?1 AND family = ?2 AND token = ?3",
                params![slot_id, family, token, now_ms],
            )?;
            return Ok(OwnerAdd {
                family_count: count as usize,
                inserted: false,
            });
        }
        if cap > 0 && count as usize >= cap {
            // LRU：把这一族最久没见到的那条换出去。（token 只是并列时的稳定排序。）
            conn.execute(
                "DELETE FROM soter_slot_owners
                 WHERE slot_id = ?1 AND family = ?2 AND token = (
                     SELECT token FROM soter_slot_owners
                     WHERE slot_id = ?1 AND family = ?2
                     ORDER BY last_seen_ms ASC, token ASC LIMIT 1)",
                params![slot_id, family],
            )?;
        }
        conn.execute(
            "INSERT INTO soter_slot_owners(slot_id, family, token, first_seen_ms, last_seen_ms)
             VALUES(?1, ?2, ?3, ?4, ?4)",
            params![slot_id, family, token, now_ms],
        )?;
        let after = if cap > 0 && count as usize >= cap {
            cap
        } else {
            (count + 1) as usize
        };
        Ok(OwnerAdd {
            family_count: after,
            inserted: true,
        })
    }

    // -----------------------------------------------------------------------
    // 旧 JSON 一次性导入
    // -----------------------------------------------------------------------

    /// 库里是空的（新库）才导；导的是字节，`INSERT OR IGNORE` 不会盖掉库里更新的行。
    pub fn import_legacy_if_empty(&self) -> Result<ImportReport> {
        if self.session_count()? > 0 || self.slot_count()? > 0 {
            return Ok(ImportReport::default());
        }
        let sessions = PathBuf::from(LEGACY_SESSIONS);
        let slots = PathBuf::from(LEGACY_SLOTS);
        let report = self.import_legacy_json(
            sessions.exists().then_some(sessions.as_path()),
            slots.exists().then_some(slots.as_path()),
        )?;
        if !report.is_empty() {
            tracing::info!(
                "state db: 从旧 JSON 导了 {} 条会话 / {} 个槽位 / {} 个账号指纹（{}）",
                report.sessions,
                report.slots,
                report.owners,
                report.files.join(", ")
            );
        }
        Ok(report)
    }

    /// 导入本身（测试和演练都走这里）。两个路径都可以是 None。
    ///
    /// 整个导入包在一个事务里：线上那份会话表一万多条，逐条 autocommit 又慢、中途断了
    /// 还会导一半（库里一半、旧 JSON 一半，而下一次启动因为「库非空」就不导了）。
    pub fn import_legacy_json(
        &self,
        sessions_json: Option<&Path>,
        slots_json: Option<&Path>,
    ) -> Result<ImportReport> {
        let mut report = ImportReport::default();
        if sessions_json.is_none() && slots_json.is_none() {
            return Ok(report);
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        let conn = self.plain();
        let tx = conn
            .unchecked_transaction()
            .context("state db import transaction")?;
        if let Some(path) = sessions_json {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            // 同一条会话可能被两台设备拥有（老布局按设备嵌套），后来的同别名忽略。
            let mut seen = std::collections::HashSet::new();
            for (alias, row) in legacy_sessions(&text)? {
                if !seen.insert(alias.clone()) {
                    continue;
                }
                if Self::insert_session_if_absent(&tx, &alias, &row)? {
                    report.sessions += 1;
                }
            }
            report.files.push(path.display().to_string());
        }
        if let Some(path) = slots_json {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            for (slot_id, pin) in legacy_slots(&text)? {
                if pin.layer.is_empty() && pin.at_millis == 0 {
                    // 只有账号记录、没钉过层的记录：不写空钉子行（读回来一样）。
                } else if Self::insert_slot_if_absent(&tx, &slot_id, &pin.layer, pin.at_millis)? {
                    report.slots += 1;
                }
                for token in pin.owners {
                    let Some((family, value)) = token.split_once(':') else {
                        continue;
                    };
                    if value.is_empty() {
                        continue;
                    }
                    if Self::insert_owner_if_absent(&tx, &slot_id, family, value, now_ms)? {
                        report.owners += 1;
                    }
                }
            }
            report.files.push(path.display().to_string());
        }
        tx.commit().context("state db import commit")?;
        Ok(report)
    }

    fn insert_session_if_absent(conn: &Connection, alias: &str, row: &SessionRow) -> Result<bool> {
        // 旧 JSON 里没有「最后使用」，拿创建时间顶上。
        let n = conn.execute(
            "INSERT OR IGNORE INTO sessions(alias, chain_pem, leaf_key_pem, created_epoch_ms, used_epoch_ms)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                alias,
                row.chain_pem,
                row.leaf_key_pem,
                row.created_epoch_ms as i64,
                row.used_epoch_ms as i64
            ],
        )?;
        Ok(n > 0)
    }

    /// 表里有没有这一列（迁移用，SQLite 没有 `ADD COLUMN IF NOT EXISTS`）。
    fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn insert_slot_if_absent(
        conn: &Connection,
        slot_id: &str,
        layer: &str,
        at_millis: i64,
    ) -> Result<bool> {
        let n = conn.execute(
            "INSERT OR IGNORE INTO soter_slots(slot_id, layer, at_millis) VALUES(?1, ?2, ?3)",
            params![slot_id, layer, at_millis],
        )?;
        Ok(n > 0)
    }

    fn insert_owner_if_absent(
        conn: &Connection,
        slot_id: &str,
        family: &str,
        token: &str,
        now_ms: i64,
    ) -> Result<bool> {
        // 旧 JSON 里没有时间，所以时间戳写「导入这一刻」而不是 0 —— 0 是「未知」，
        // 挂上 TTL 之后会被当成早就过期，一启动就把这批记录全清了。
        let n = conn.execute(
            "INSERT OR IGNORE INTO soter_slot_owners(slot_id, family, token, first_seen_ms, last_seen_ms)
             VALUES(?1, ?2, ?3, ?4, ?4)",
            params![slot_id, family, token, now_ms],
        )?;
        Ok(n > 0)
    }
}

// ---------------------------------------------------------------------------
// 旧 JSON 的形状（只在导入时用，别的地方不要碰这两个结构）
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct LegacySession {
    chain_pem: String,
    leaf_key_pem: String,
    created_epoch_ms: u64,
}

#[derive(serde::Deserialize, Default)]
struct LegacyPin {
    #[serde(default)]
    layer: String,
    #[serde(default)]
    at_millis: i64,
    #[serde(default)]
    owners: Vec<String>,
}

/// 兼容两种布局：现在这份是扁平的 `alias -> session`，更早那份按设备嵌套。
fn legacy_sessions(text: &str) -> Result<Vec<(String, SessionRow)>> {
    if let Ok(flat) = serde_json::from_str::<HashMap<String, LegacySession>>(text) {
        return Ok(flat
            .into_iter()
            .map(|(alias, s)| {
                (
                    alias,
                    SessionRow {
                        chain_pem: s.chain_pem,
                        leaf_key_pem: s.leaf_key_pem,
                        created_epoch_ms: s.created_epoch_ms,
                        used_epoch_ms: s.created_epoch_ms,
                    },
                )
            })
            .collect());
    }
    let nested = serde_json::from_str::<HashMap<String, HashMap<String, LegacySession>>>(text)
        .context("sessions json 既不是扁平也不是按设备嵌套")?;
    let mut out = Vec::new();
    for (_device, aliases) in nested {
        for (alias, s) in aliases {
            out.push((
                alias,
                SessionRow {
                    chain_pem: s.chain_pem,
                    leaf_key_pem: s.leaf_key_pem,
                    created_epoch_ms: s.created_epoch_ms,
                    used_epoch_ms: s.created_epoch_ms,
                },
            ));
        }
    }
    Ok(out)
}

fn legacy_slots(text: &str) -> Result<HashMap<String, LegacyPin>> {
    serde_json::from_str(text).context("soter_slots json 解不开")
}

// ---------------------------------------------------------------------------
// 进程内那一份
// ---------------------------------------------------------------------------

/// 进程里共用的那一个库（`fulfill` 和 `soter_mint` 用的是同一份）。
///
/// 开不起来的时候**不**退化成内存库：会话表就是 A 端那批 `KeyMaterial::Remote`
/// 的钥匙，静默丢掉等于让所有远程钥匙当场签不动（1.6.4 之前丢 `sessions.json`
/// 就是这么坏的），所以宁可起不来，让日志和 systemd 直接说。
static SHARED: OnceLock<Result<Arc<StateDb>, String>> = OnceLock::new();

fn init() -> &'static Result<Arc<StateDb>, String> {
    SHARED.get_or_init(open_for_process)
}

/// 启动时先调一次：这里拿到 Err，进程带原因退出。
pub fn open_checked() -> Result<Arc<StateDb>> {
    match init() {
        Ok(db) => Ok(db.clone()),
        Err(e) => bail!("{e}"),
    }
}

/// 读路径用（启动时已经 `open_checked` 过了）。
pub fn shared() -> Arc<StateDb> {
    match init() {
        Ok(db) => db.clone(),
        Err(e) => panic!("state db 没开起来：{e}"),
    }
}

#[cfg(test)]
fn open_for_process() -> Result<Arc<StateDb>, String> {
    // 测试里不碰仓库里的 data/：每个测试进程一份内存库。
    StateDb::open_in_memory()
        .map(Arc::new)
        .map_err(|e| format!("{e:#}"))
}

#[cfg(not(test))]
fn open_for_process() -> Result<Arc<StateDb>, String> {
    let path = std::env::var("OMMEGA_STATE_DB").unwrap_or_else(|_| DEFAULT_PATH.to_string());
    StateDb::open(&path)
        .and_then(|db| {
            db.import_legacy_if_empty()?;
            Ok(db)
        })
        .map(Arc::new)
        .map_err(|e| {
            format!(
                "state db 打不开（{path}）：{e:#} —— 会话表和槽位登记表都在这儿，\
                 起不来比静默丢会话强。查路径/权限/磁盘，或者回滚上一版二进制\
                 （回滚前把库挪走：mv {path} {path}.bak）"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db(tag: &str) -> (StateDb, PathBuf) {
        let dir = std::env::temp_dir().join(format!("ommega-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.db");
        let db = StateDb::open(path.to_str().unwrap()).unwrap();
        (db, dir)
    }

    fn row(chain: &str, leaf: &str, ms: u64) -> SessionRow {
        row_at(chain, leaf, ms, ms)
    }

    fn row_at(chain: &str, leaf: &str, created: u64, used: u64) -> SessionRow {
        SessionRow {
            chain_pem: chain.to_string(),
            leaf_key_pem: leaf.to_string(),
            created_epoch_ms: created,
            used_epoch_ms: used,
        }
    }

    #[test]
    fn sessions_survive_a_reopen_and_purge_by_time() {
        let (db, dir) = tmp_db("sessions");
        db.upsert_session("a", &row_at("chain-a", "key-a", 1_000, 1_000))
            .unwrap();
        db.upsert_session("b", &row("chain-b", "key-b", 2_000))
            .unwrap();
        // 同名再写就是覆盖，不是再来一行
        db.upsert_session("a", &row_at("chain-a2", "key-a2", 3_000, 1_000))
            .unwrap();
        assert_eq!(db.session_count().unwrap(), 2);

        let reopened = StateDb::open(db.path()).unwrap();
        let mut rows = reopened.load_sessions().unwrap();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1.chain_pem, "chain-a2");
        assert_eq!(rows[0].1.created_epoch_ms, 3_000);
        assert_eq!(rows[0].1.used_epoch_ms, 1_000);

        // 「最后使用」顶一下；TTL 看它，不看创建时间：
        // a 的创建时间更新（3000）但最后用在 1000 → 过期；
        // b 的创建时间更早（2000）但最后用在 9000 → 留着。
        reopened.touch_session("b", 9_000).unwrap();
        assert_eq!(
            reopened
                .get_session_row("b")
                .unwrap()
                .unwrap()
                .used_epoch_ms,
            9_000
        );
        assert_eq!(reopened.delete_sessions_expired_before(2_500).unwrap(), 1);
        assert_eq!(reopened.session_count().unwrap(), 1);
        assert!(reopened.get_session_row("b").unwrap().is_some());
        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hot_load_and_lru_trim_keep_the_most_recently_used() {
        let (db, dir) = tmp_db("lru");
        for i in 1..=5u64 {
            db.upsert_session(
                &format!("al{i}"),
                &row(&format!("c{i}"), &format!("l{i}"), i * 100),
            )
            .unwrap();
        }
        // 热缓存只装最近用过的两条
        let hot: Vec<String> = db
            .load_hot_sessions(2)
            .unwrap()
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        assert_eq!(hot, vec!["al5", "al4"]);

        // 上限 3：把最久没用的 al1 / al2 挤掉，留最近用的
        assert_eq!(db.trim_sessions_lru(3).unwrap(), 2);
        let mut left: Vec<String> = db
            .load_sessions()
            .unwrap()
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        left.sort();
        assert_eq!(left, vec!["al3", "al4", "al5"]);
        // 没超上限时一条不动
        assert_eq!(db.trim_sessions_lru(10).unwrap(), 0);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v1_sessions_table_migrates_to_last_used() {
        // 手搓一版 v1 的表（没有 used_epoch_ms），打开后得能迁上来：
        // 老行没有最后使用时间，拿创建时间顶上。
        let dir = std::env::temp_dir().join(format!("ommega-state-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE sessions(
                     alias            TEXT PRIMARY KEY,
                     chain_pem        TEXT NOT NULL,
                     leaf_key_pem     TEXT NOT NULL,
                     created_epoch_ms INTEGER NOT NULL);",
            )
            .unwrap();
            conn.execute("INSERT INTO sessions VALUES('old','C','L',1234)", [])
                .unwrap();
        }
        let db = StateDb::open(path.to_str().unwrap()).unwrap();
        let migrated = db.get_session_row("old").unwrap().unwrap();
        assert_eq!(migrated.created_epoch_ms, 1_234);
        assert_eq!(migrated.used_epoch_ms, 1_234);
        assert_eq!(db.session_count().unwrap(), 1);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slots_and_owners_round_trip_with_a_per_family_cap() {
        let (db, dir) = tmp_db("slots");
        db.upsert_slot("dev|1", "b", 111).unwrap();
        // 存的是同一族 3 个指纹 + 另一族 1 个
        for (family, token) in [("v2", "s1"), ("v2", "s2"), ("v2", "s3"), ("wx", "acct")] {
            let add = db
                .add_owner("dev|1", family, token, 500, OWNER_FAMILY_CAP)
                .unwrap();
            assert!(add.inserted);
        }
        let again = db
            .add_owner("dev|1", "v2", "s1", 900, OWNER_FAMILY_CAP)
            .unwrap();
        assert!(!again.inserted, "同一条指纹不该算新的");
        assert_eq!(again.family_count, 3);

        // cap 生效：这一族满了就把最久没见到的那条换出去（LRU，不是拒收新的）
        let capped = db.add_owner("dev|1", "wx", "x", 901, 1).unwrap();
        assert!(capped.inserted, "满了也得收新的，换掉最久没用的那条");
        assert_eq!(capped.family_count, 1);

        let snap = db.slots_snapshot().unwrap();
        assert_eq!(
            snap.slots,
            vec![("dev|1".to_string(), "b".to_string(), 111)]
        );
        assert_eq!(snap.owners.len(), 4);
        assert!(snap
            .owners
            .iter()
            .any(|(slot, family, token, seen)| slot == "dev|1"
                && family == "v2"
                && token == "s1"
                && *seen == 900));
        // 被换出去的是 wx 那一族里最久没见的 acct，新进来的 x 在
        assert!(snap.owners.iter().any(|(_, f, t, _)| f == "wx" && t == "x"));
        assert!(!snap
            .owners
            .iter()
            .any(|(_, f, t, _)| f == "wx" && t == "acct"));

        // 拔钉子只删「钉层」那一行，账号记录得留着（那是连坐判断的判据）
        db.delete_slot_pin("dev|1").unwrap();
        assert_eq!(db.slot_count().unwrap(), 0);
        assert_eq!(db.slots_snapshot().unwrap().owners.len(), 4);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn owner_records_expire_by_last_seen() {
        let (db, dir) = tmp_db("owner-ttl");
        db.add_owner("d|1", "v2", "fresh", 10_000, OWNER_FAMILY_CAP)
            .unwrap();
        db.add_owner("d|1", "v2", "stale", 1_000, OWNER_FAMILY_CAP)
            .unwrap();
        assert_eq!(db.purge_owners_expired_before(5_000).unwrap(), 1);
        let owners = db.slots_snapshot().unwrap().owners;
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].2, "fresh");
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 从旧 JSON 导进来的账号记录不能一挂上 TTL 就被清光。
    ///
    /// 那份 JSON 里根本没有时间，早先导的时候写的是 0 —— 而 0 在「按最后见到算过期」
    /// 下等于「过期了几辈子」，2026-10-03 上线时真把线上 5298 条清成了 386 条。
    #[test]
    fn imported_owner_records_survive_the_ttl() {
        let (db, dir) = tmp_db("import-owner-ttl");
        let slots_json = dir.join("soter_slots.json");
        std::fs::write(
            &slots_json,
            r#"{"dev|9":{"layer":"b","at_millis":333,
                 "owners":["wx:hubssh","v2:salt1"]}}"#,
        )
        .unwrap();
        let report = db.import_legacy_json(None, Some(&slots_json)).unwrap();
        assert_eq!(report.owners, 2);

        let owners = db.slots_snapshot().unwrap().owners;
        assert_eq!(owners.len(), 2);
        assert!(
            owners.iter().all(|(_, _, _, ms)| *ms > 0),
            "导入得写上「导入这一刻」，不能留 0"
        );
        // 30 天这条线上：刚导进来的，一条都不该被清
        let now = chrono::Utc::now().timestamp_millis();
        let cutoff = now - 30 * 24 * 60 * 60 * 1000;
        assert_eq!(db.purge_owners_expired_before(cutoff).unwrap(), 0);
        assert_eq!(db.slots_snapshot().unwrap().owners.len(), 2);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 时间戳是 0（「不知道什么时候见的」）的记录，再狠的 cutoff 也不清；
    /// 而且库里一旦出现 0，下一次开库得把它回填成当下（否则 TTL 永远管不了它）。
    #[test]
    fn unknown_timestamp_owner_records_are_backfilled_then_spared() {
        let (db, dir) = tmp_db("owner-zero");
        {
            let conn = db.plain();
            StateDb::insert_owner_if_absent(&conn, "d|1", "v2", "old", 0).unwrap();
        }
        assert_eq!(db.slots_snapshot().unwrap().owners[0].3, 0);
        assert_eq!(
            db.purge_owners_expired_before(i64::MAX).unwrap(),
            0,
            "0 是「不知道」，不是「早就过期」"
        );
        drop(db);

        let path = dir.join("state.db");
        let db = StateDb::open(path.to_str().unwrap()).unwrap();
        let owners = db.slots_snapshot().unwrap().owners;
        assert!(owners[0].3 > 0, "开库时该把 0 回填成当下");
        // 回填之后 TTL 才真的能管它：30 天内还在，放到永生就该过期
        let now = chrono::Utc::now().timestamp_millis();
        assert_eq!(
            db.purge_owners_expired_before(now - 30 * 24 * 60 * 60 * 1000)
                .unwrap(),
            0
        );
        assert_eq!(db.purge_owners_expired_before(i64::MAX).unwrap(), 1);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_json_import_is_byte_faithful_and_idempotent() {
        let (db, dir) = tmp_db("import");
        let sessions_json = dir.join("sessions.json");
        let slots_json = dir.join("soter_slots.json");
        let leaf = "gAAAAA-ciphertext-not-a-real-key";
        std::fs::write(
            &sessions_json,
            format!(
                r#"{{"al1":{{"chain_pem":"CHAIN","leaf_key_pem":"{leaf}","created_epoch_ms":1234}},
                    "al2":{{"chain_pem":"C2","leaf_key_pem":"L2","created_epoch_ms":5678}}}}"#
            ),
        )
        .unwrap();
        std::fs::write(
            &slots_json,
            r#"{"dev|7":{"layer":"b","at_millis":222,
                 "owners":["wx:hubssh","v2:salt1","v1:salt1","工具别名","v2:"]}}"#,
        )
        .unwrap();

        let report = db
            .import_legacy_json(Some(&sessions_json), Some(&slots_json))
            .unwrap();
        assert_eq!(report.sessions, 2);
        assert_eq!(report.slots, 1);
        // 「工具别名」「v2:」（空值）都不算账号
        assert_eq!(report.owners, 3);

        // 字节原样搬过来：密文不需要重新加密，拿旧文件回滚也读得回来
        let rows = db.load_sessions().unwrap();
        let al1 = rows.iter().find(|(a, _)| a == "al1").unwrap();
        assert_eq!(al1.1.leaf_key_pem, leaf);
        assert_eq!(al1.1.chain_pem, "CHAIN");

        // 再导一遍不翻倍
        let second = db
            .import_legacy_json(Some(&sessions_json), Some(&slots_json))
            .unwrap();
        assert!(second.is_empty(), "{second:?}");
        assert_eq!(db.session_count().unwrap(), 2);
        assert_eq!(db.slots_snapshot().unwrap().owners.len(), 3);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_nested_session_layout_still_imports() {
        let (db, dir) = tmp_db("nested");
        let path = dir.join("sessions.json");
        std::fs::write(
            &path,
            r#"{"dev-1":{"a":{"chain_pem":"C","leaf_key_pem":"L","created_epoch_ms":1}},
                "dev-2":{"a":{"chain_pem":"C2","leaf_key_pem":"L2","created_epoch_ms":2},
                         "b":{"chain_pem":"C3","leaf_key_pem":"L3","created_epoch_ms":3}}}"#,
        )
        .unwrap();
        let report = db.import_legacy_json(Some(&path), None).unwrap();
        // 老布局里同一个别名可能出现在两台设备下 —— 只留第一条
        assert_eq!(report.sessions, 2);
        let rows = db.load_sessions().unwrap();
        assert_eq!(rows.len(), 2);
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 拿线上的真文件跑一遍（不放进 CI：CI 没有那份数据）。
    ///
    /// ```text
    /// OMMEGA_DRILL_DIR=/path/to/dir cargo test -- --ignored --nocapture drill
    /// ```
    /// 目录里放 `sessions.json` 和 `soter_slots.json`。
    /// 拿线上的真库练一遍 v1→v2 迁移（不放进 CI：CI 没有那份数据）。
    ///
    /// ```text
    /// OMMEGA_DRILL_DB=/path/to/relay_state.db cargo test -- --ignored --nocapture drill_migrate
    /// ```
    /// 先拿一个副本跑（`sqlite3 真库 ".backup 副本"`），别直接对着生产文件开。
    #[test]
    #[ignore]
    fn drill_migrate_a_real_state_db() {
        let Ok(path) = std::env::var("OMMEGA_DRILL_DB") else {
            return;
        };
        let started = std::time::Instant::now();
        let (before_sessions, before_has_used) = {
            let conn = Connection::open(&path).unwrap();
            let mut stmt = conn.prepare("PRAGMA table_info(sessions)").unwrap();
            let mut rows = stmt.query([]).unwrap();
            let mut has_used = false;
            while let Some(r) = rows.next().unwrap() {
                if r.get::<_, String>(1).unwrap() == "used_epoch_ms" {
                    has_used = true;
                }
            }
            let n: i64 = conn
                .query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))
                .unwrap();
            (n, has_used)
        };
        println!("迁移前：sessions={before_sessions}，已有 used_epoch_ms={before_has_used}");

        let db = StateDb::open(&path).unwrap();
        let rows = db.load_sessions().unwrap();
        let zero_used = rows.iter().filter(|(_, s)| s.used_epoch_ms == 0).count();
        let used_eq_created = rows
            .iter()
            .filter(|(_, s)| s.used_epoch_ms == s.created_epoch_ms)
            .count();
        println!(
            "迁移后：sessions={}，used=0 的 {} 条，used==created 的 {} 条，用时 {} ms",
            rows.len(),
            zero_used,
            used_eq_created,
            started.elapsed().as_millis()
        );
        assert_eq!(rows.len() as i64, before_sessions, "条数不该变");
        assert_eq!(zero_used, 0, "老行必须都回填了最后使用");
        if !before_has_used {
            assert_eq!(
                used_eq_created,
                rows.len(),
                "第一次迁移得全部回填成创建时间"
            );
        }

        // 热装载只装上限那么多，且每一条都能按 alias 单查回来
        let hot = db.load_hot_sessions(SESSION_MEMORY_HOT).unwrap();
        println!("热装载 {} 条（上限 {SESSION_MEMORY_HOT}）", hot.len());
        assert!(hot.len() <= SESSION_MEMORY_HOT);
        if let Some((alias, _)) = hot.first() {
            assert!(db.get_session_row(alias).unwrap().is_some());
        }
        let slots = db.slots_snapshot().unwrap();
        println!(
            "槽位 {} 个 / 账号指纹 {} 条",
            slots.slots.len(),
            slots.owners.len()
        );
        // 幂等：再开一次不会又改一遍
        let reopened = StateDb::open(&path).unwrap();
        assert_eq!(reopened.session_count().unwrap(), rows.len());
        println!("迁移是幂等的，重开一次条数不变");

        // 在大表上验一遍 LRU 淘汰 SQL：压到 1000 条，留下的必须都不比删掉的老
        let before: HashMap<String, u64> = rows
            .iter()
            .map(|(a, s)| (a.clone(), s.used_epoch_ms))
            .collect();
        let removed = db.trim_sessions_lru(1_000).unwrap();
        let after = db.load_sessions().unwrap();
        let kept: HashMap<String, u64> = after
            .iter()
            .map(|(a, s)| (a.clone(), s.used_epoch_ms))
            .collect();
        assert_eq!(after.len(), 1_000);
        assert_eq!(before.len() - kept.len(), removed);
        let min_kept = kept.values().min().copied().unwrap_or(0);
        let max_gone = before
            .iter()
            .filter(|(a, _)| !kept.contains_key(*a))
            .map(|(_, u)| *u)
            .max()
            .unwrap_or(0);
        println!(
            "LRU 压到 1000：删了 {removed} 条，留下的最早 used={min_kept}，删掉的最晚 used={max_gone}"
        );
        assert!(min_kept >= max_gone, "留下的必须都不比删掉的老");
    }

    #[test]
    #[ignore]
    fn drill_against_real_production_json() {
        let Ok(dir) = std::env::var("OMMEGA_DRILL_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let sessions_json = dir.join("sessions.json");
        let slots_json = dir.join("soter_slots.json");
        let started = std::time::Instant::now();
        let (db, scratch) = tmp_db("drill");
        let report = db
            .import_legacy_json(Some(&sessions_json), Some(&slots_json))
            .unwrap();
        let import_ms = started.elapsed().as_millis();
        println!(
            "导入 {} 条会话 / {} 个槽位 / {} 个账号指纹，用时 {import_ms} ms",
            report.sessions, report.slots, report.owners
        );

        // 跟源文件逐条对一遍（字节级）
        let text = std::fs::read_to_string(&sessions_json).unwrap();
        let legacy: serde_json::Value = serde_json::from_str(&text).unwrap();
        let obj = legacy.as_object().unwrap();
        assert_eq!(obj.len(), report.sessions, "条数对不上");
        let loaded: HashMap<String, SessionRow> = db.load_sessions().unwrap().into_iter().collect();
        assert_eq!(loaded.len(), obj.len());
        let mut checked = 0;
        for (alias, sf) in obj {
            let want_chain = sf["chain_pem"].as_str().unwrap();
            let want_leaf = sf["leaf_key_pem"].as_str().unwrap();
            let got = loaded.get(alias).expect("别名丢了");
            assert_eq!(got.chain_pem, want_chain, "{alias} 的链被搬坏了");
            assert_eq!(got.leaf_key_pem, want_leaf, "{alias} 的私钥被搬坏了");
            checked += 1;
        }
        println!("逐条核对 {checked} 条，链和私钥都逐字节一致");

        // 全表校验：存进去的私钥解不解得出来、跟链配不配得上。
        // 配不上的会话发回 A 端就是「签出来的东西验不过」—— 属于库里早就有的坏行，
        // 跟搬迁无关（字段是逐字节搬的），但趁这次演练把规模量出来。
        crate::crypto::init_fernet(
            &std::env::var("OMMEGA_DRILL_FERNET").unwrap_or_else(|_| "drill".to_string()),
        );
        let mut unparsed: Vec<String> = Vec::new();
        let mut bad: Vec<(String, String, u64)> = Vec::new();
        for (alias, row) in &loaded {
            let pem = crate::crypto::decrypt_private_pem(&row.leaf_key_pem);
            if crate::cert::parse_private_key(pem.as_bytes()).is_err() {
                unparsed.push(alias.clone());
                continue;
            }
            if let Some(why) = crate::cert::validate_identity_pem(&pem, &row.chain_pem) {
                bad.push((alias.clone(), why, row.created_epoch_ms));
            }
        }
        println!(
            "全表校验 {} 条：私钥解不出来的 {} 条，跟链配对不上的 {} 条",
            loaded.len(),
            unparsed.len(),
            bad.len()
        );
        for alias in unparsed.iter().take(10) {
            println!("  [解不出] {alias}");
        }
        bad.sort_by_key(|(_, _, ms)| *ms);
        for (alias, why, ms) in bad.iter().take(15) {
            println!("  [配不上] {alias}（{ms}）：{why}");
        }

        // 槽位：钉子和账号记录都得在
        let legacy_slots: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&slots_json).unwrap()).unwrap();
        let map = legacy_slots.as_object().unwrap();
        let snap = db.slots_snapshot().unwrap();
        let pinned_in_json = map
            .values()
            .filter(|v| !v["layer"].as_str().unwrap_or("").is_empty())
            .count();
        assert_eq!(snap.slots.len(), pinned_in_json, "钉子数对不上");
        let owners_in_json: usize = map
            .values()
            .map(|v| {
                v["owners"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter(|t| {
                                let t = t.as_str().unwrap_or("");
                                match t.split_once(':') {
                                    Some((_, value)) => !value.is_empty(),
                                    None => false,
                                }
                            })
                            .count()
                    })
                    .unwrap_or(0)
            })
            .sum();
        assert_eq!(snap.owners.len(), owners_in_json, "账号指纹数对不上");
        println!(
            "槽位 {} 个（其中钉过层的 {} 个）、账号指纹 {} 条",
            map.len(),
            snap.slots.len(),
            snap.owners.len()
        );

        // 导完马上跑一遍 TTL 清理：一条都不该掉（导入写的是「导入这一刻」，不是 0）。
        // 这条正是 2026-10-03 上线时踩的坑，拿真数据再验一次。
        let cutoff = chrono::Utc::now().timestamp_millis() - 30 * 24 * 60 * 60 * 1000;
        assert_eq!(
            db.purge_owners_expired_before(cutoff).unwrap(),
            0,
            "刚导入的账号记录不能被 TTL 清掉"
        );
        assert_eq!(
            db.slots_snapshot().unwrap().owners.len(),
            owners_in_json,
            "清理之后账号指纹数不该变"
        );
        println!("导入后跑一遍 30 天 TTL：一条没掉");
        drop(db);
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
