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
use rusqlite::{params, Connection};

/// 默认落盘位置（systemd 的 WorkingDirectory 是 /opt/relay）。`OMMEGA_STATE_DB` 可覆盖。
pub const DEFAULT_PATH: &str = "data/relay_state.db";

/// 旧的两份 JSON，只在库里是空的时候导一次；导完不动它们（留着当回滚源）。
const LEGACY_SESSIONS: &str = "data/sessions.json";
const LEGACY_SLOTS: &str = "data/soter_slots.json";

/// 一个槽位里每一族最多记几个指纹。三族分开算：一个账号在每一族最多留一个指纹，
/// 所以「同族 512 个」是上限而不是 512/3。
pub const OWNER_FAMILY_CAP: usize = 512;

const SCHEMA_VERSION: i64 = 1;

/// 会话表里一行（字段跟旧的 `SessionFile` 对齐）。
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRow {
    pub chain_pem: String,
    pub leaf_key_pem: String,
    pub created_epoch_ms: u64,
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
                 created_epoch_ms INTEGER NOT NULL);
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

    pub fn session_count(&self) -> Result<usize> {
        let conn = self.plain();
        let n: i64 = conn.query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    pub fn load_sessions(&self) -> Result<Vec<(String, SessionRow)>> {
        let conn = self.plain();
        let mut stmt =
            conn.prepare("SELECT alias, chain_pem, leaf_key_pem, created_epoch_ms FROM sessions")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                SessionRow {
                    chain_pem: r.get(1)?,
                    leaf_key_pem: r.get(2)?,
                    created_epoch_ms: r.get::<_, i64>(3)? as u64,
                },
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// 一条会话一行；原来这里是「整份 74 MB 重写一遍」。
    pub fn upsert_session(&self, alias: &str, row: &SessionRow) -> Result<()> {
        let conn = self.plain();
        conn.execute(
            "INSERT INTO sessions(alias, chain_pem, leaf_key_pem, created_epoch_ms)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(alias) DO UPDATE SET
                 chain_pem = excluded.chain_pem,
                 leaf_key_pem = excluded.leaf_key_pem,
                 created_epoch_ms = excluded.created_epoch_ms",
            params![
                alias,
                row.chain_pem,
                row.leaf_key_pem,
                row.created_epoch_ms as i64
            ],
        )?;
        Ok(())
    }

    /// 过期的会话直接按条件删。返回删了几条。
    pub fn delete_sessions_expired_before(&self, cutoff_ms: i64) -> Result<usize> {
        let conn = self.plain();
        Ok(conn.execute(
            "DELETE FROM sessions WHERE created_epoch_ms < ?1",
            params![cutoff_ms],
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

    /// 拔钉子：跟内存里的语义一致（连这个槽位的账号记录一起删）。
    pub fn delete_slot(&self, slot_id: &str) -> Result<()> {
        let conn = self.plain();
        conn.execute(
            "DELETE FROM soter_slots WHERE slot_id = ?1",
            params![slot_id],
        )?;
        conn.execute(
            "DELETE FROM soter_slot_owners WHERE slot_id = ?1",
            params![slot_id],
        )?;
        Ok(())
    }

    /// 记一个账号指纹。同一族超过 `cap` 就不记了（返回现有条数，`inserted=false`）。
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
        if count as usize >= cap {
            return Ok(OwnerAdd {
                family_count: count as usize,
                inserted: false,
            });
        }
        conn.execute(
            "INSERT INTO soter_slot_owners(slot_id, family, token, first_seen_ms, last_seen_ms)
             VALUES(?1, ?2, ?3, ?4, ?4)",
            params![slot_id, family, token, now_ms],
        )?;
        Ok(OwnerAdd {
            family_count: (count + 1) as usize,
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
                    if Self::insert_owner_if_absent(&tx, &slot_id, family, value)? {
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
        let n = conn.execute(
            "INSERT OR IGNORE INTO sessions(alias, chain_pem, leaf_key_pem, created_epoch_ms)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                alias,
                row.chain_pem,
                row.leaf_key_pem,
                row.created_epoch_ms as i64
            ],
        )?;
        Ok(n > 0)
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
    ) -> Result<bool> {
        let n = conn.execute(
            "INSERT OR IGNORE INTO soter_slot_owners(slot_id, family, token, first_seen_ms, last_seen_ms)
             VALUES(?1, ?2, ?3, 0, 0)",
            params![slot_id, family, token],
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
        SessionRow {
            chain_pem: chain.to_string(),
            leaf_key_pem: leaf.to_string(),
            created_epoch_ms: ms,
        }
    }

    #[test]
    fn sessions_survive_a_reopen_and_purge_by_time() {
        let (db, dir) = tmp_db("sessions");
        db.upsert_session("a", &row("chain-a", "key-a", 1_000))
            .unwrap();
        db.upsert_session("b", &row("chain-b", "key-b", 2_000))
            .unwrap();
        // 同名再写就是覆盖，不是再来一行
        db.upsert_session("a", &row("chain-a2", "key-a2", 3_000))
            .unwrap();
        assert_eq!(db.session_count().unwrap(), 2);

        let reopened = StateDb::open(db.path()).unwrap();
        let mut rows = reopened.load_sessions().unwrap();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1.chain_pem, "chain-a2");
        assert_eq!(rows[0].1.created_epoch_ms, 3_000);

        // 过期的按条件删（原来得整份重写一遍才删得掉）
        assert_eq!(reopened.delete_sessions_expired_before(2_500).unwrap(), 1);
        assert_eq!(reopened.session_count().unwrap(), 1);
        drop(reopened);
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

        // cap 生效：同族满了就不再进
        let capped = db.add_owner("dev|1", "wx", "x", 901, 1).unwrap();
        assert!(!capped.inserted);
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

        // 拔钉子连账号记录一起删（跟内存语义一致）
        db.delete_slot("dev|1").unwrap();
        assert_eq!(db.slot_count().unwrap(), 0);
        assert!(db.slots_snapshot().unwrap().owners.is_empty());
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
        drop(db);
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
