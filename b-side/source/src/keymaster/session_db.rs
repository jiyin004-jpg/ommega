//! 会话（TEE key blob + 证书链）的落盘层：一个 SQLite 文件，取代原来「一个别名
//! 一个 JSON 文件」的目录。
//!
//! 为什么换掉目录：
//!   1. 取用一次是「拼路径 + 读整个 JSON」，别名还得先哈希成文件名（带截断，理论上
//!      会撞）；库表按 alias 主键查一行。
//!   2. 清一轮是 read_dir + 对两万个文件挨个 stat，再排序，再逐个 unlink；库里是
//!      `DELETE ... WHERE used_ms < ?` 加一条按 used_ms 排序的搬运，索引直接扫。
//!   3. 上限和 TTL 跟服务端的 sessions 表一个口径（20000 条 / 7 天，都按最后一次
//!      使用算），两边讲的是同一件事。
//!
//! 旧目录**原样不动**：刷回旧版本时那边照样读得到，等于现成的回滚源；确认没问题后
//! 手工 `rm -rf /data/adb/ommega/sessions` 就把那一百多 MB 收回来了。
//!
//! 库打不开不致命：退回纯内存会话（重启即丢，但设备还在干活），同时响亮地报一条
//! error —— 静默降级会让人回头去别处找原因。

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rusqlite::{params, Connection, OptionalExtension};

/// 库文件位置的默认值。演练/换机器时可以用 `OMMEGA_SESSIONS_DB` 指到别处。
pub const DEFAULT_DB_PATH: &str = "/data/adb/ommega/sessions.db";
/// 旧版「一个别名一个 JSON」的目录，只在库还空着的时候导入一次。
/// 跟库文件一样可以用 `OMMEGA_SESSIONS_DIR` 顶掉。
pub const DEFAULT_LEGACY_DIR: &str = "/data/adb/ommega/sessions";

pub fn db_path() -> PathBuf {
    std::env::var_os("OMMEGA_SESSIONS_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DB_PATH))
}

pub fn legacy_dir() -> PathBuf {
    std::env::var_os("OMMEGA_SESSIONS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LEGACY_DIR))
}
/// 多久没用就算过期（TTL 按最后一次使用算，不按铸造时间）。
pub const TTL_SECS: u64 = 7 * 24 * 3600;
/// 条数上限，跟服务端 `SESSION_MAX` 一个数。超了按最后使用时间从旧到新淘汰。
pub const MAX_ROWS: usize = 20_000;
/// 两次清理之间至少隔这么久。
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);

/// 一条会话。这里故意不认识 `tee_ops` 的类型：库里存的就是这几个字段，怎么解释
/// （枚举、HAL 名字）由上层决定。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub key_blob: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
    pub algorithm: String,
    pub hal_service: String,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

static DB: OnceLock<Mutex<Connection>> = OnceLock::new();

/// 开库、必要时导一遍旧目录、清一轮。启动时调一次；之后库一直是开着的那条连接。
pub fn init() {
    let db_path = db_path();
    let conn = match open_conn(&db_path) {
        Ok(conn) => conn,
        Err(err) => {
            log::error!(
                "session db {} unavailable ({err:#}); falling back to memory-only \
                 sessions for this run (they are lost on restart)",
                db_path.display()
            );
            return;
        }
    };
    let now = now_ms();
    match import_legacy_dir(&conn, &legacy_dir(), now) {
        Ok(0) => {}
        Ok(imported) => log::info!(
            "imported {imported} legacy session file(s) into {}",
            db_path.display()
        ),
        Err(err) => log::warn!("legacy session import failed: {err:#}"),
    }
    match prune_rows(&conn, now, TTL_SECS, MAX_ROWS) {
        Ok((expired, over_cap)) if expired + over_cap > 0 => log::info!(
            "session db pruned at startup: {expired} expired, {over_cap} over the {MAX_ROWS} cap"
        ),
        Ok(_) => {}
        Err(err) => log::warn!("session db prune failed: {err:#}"),
    }
    if DB.set(Mutex::new(conn)).is_err() {
        log::warn!("session db already initialised; keeping the first connection");
    }
}

/// 启动/取用时的入口，节流版清理：不管来多少任务，最多每 10 分钟清一次。
/// 清理本身只有两条 DELETE，但它在 keygen 的结果路径上，没必要每次都跑。
pub fn prune_if_due() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let due = {
        let mut guard = LAST.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let due = match guard.as_ref() {
            Some(last) => last.elapsed() >= PRUNE_INTERVAL,
            None => true,
        };
        if due {
            *guard = Some(Instant::now());
        }
        due
    };
    if !due {
        return;
    }
    let Some(lock) = DB.get() else { return };
    let conn = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match prune_rows(&conn, now_ms(), TTL_SECS, MAX_ROWS) {
        Ok((expired, over_cap)) if expired + over_cap > 0 => {
            log::info!("session db pruned: {expired} expired, {over_cap} over the {MAX_ROWS} cap")
        }
        Ok(_) => {}
        Err(err) => log::warn!("session db prune failed: {err:#}"),
    }
}

pub fn get(alias: &str) -> Option<Stored> {
    let lock = DB.get()?;
    let conn = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match get_row(&conn, alias) {
        Ok(row) => row,
        Err(err) => {
            log::warn!("session db read failed for alias '{alias}': {err:#}");
            None
        }
    }
}

/// 写入（同 alias 覆盖）。失败只记一条 warn：库坏了不该让正在出证的请求跟着失败，
/// 内存里那一份照样能用。
pub fn put(alias: &str, session: &Stored) {
    let Some(lock) = DB.get() else { return };
    let conn = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(err) = put_row(&conn, alias, session, now_ms()) {
        log::warn!("session db write failed for alias '{alias}': {err:#}");
    }
}

/// 把最后使用时间顶到当下 —— 淘汰的依据就是这个。
pub fn touch(alias: &str) {
    let Some(lock) = DB.get() else { return };
    let conn = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Err(err) = touch_row(&conn, alias, now_ms()) {
        log::warn!("session db touch failed for alias '{alias}': {err:#}");
    }
}

// ---------------------------------------------------------------------------
// 行级别实现（都拿 &Connection，方便测）
// ---------------------------------------------------------------------------

fn open_conn(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let conn =
        Connection::open(path).with_context(|| format!("open session db {}", path.display()))?;
    // WAL：写一条不用重写整表，被 pkill -9 打断也能在下次打开时自恢复（relay 每次
    // 重启都是 SIGKILL，这条是常态而不是意外）。
    let _mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .unwrap_or_else(|_| "unknown".to_string());
    conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;")
        .context("session db pragmas")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sessions(
             alias       TEXT PRIMARY KEY,
             key_blob    BLOB NOT NULL,
             cert_chain  BLOB NOT NULL,
             algorithm   TEXT NOT NULL,
             hal_service TEXT NOT NULL,
             created_ms  INTEGER NOT NULL,
             used_ms     INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_sessions_used ON sessions(used_ms);",
    )
    .context("session db schema")?;
    Ok(conn)
}

/// 证书链拼成一坨存：每条前面 4 字节大端长度。省一张子表，也不用 base64 撑大
/// 三分之一（旧格式是 JSON + base64，实测 8 KB/条）。
fn pack_chain(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(chain.iter().map(|cert| cert.len() + 4).sum());
    for cert in chain {
        out.extend_from_slice(&(cert.len() as u32).to_be_bytes());
        out.extend_from_slice(cert);
    }
    out
}

fn unpack_chain(blob: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut rest = blob;
    let mut chain = Vec::new();
    while !rest.is_empty() {
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        rest = rest.get(4..)?;
        chain.push(rest.get(..len)?.to_vec());
        rest = rest.get(len..)?;
    }
    Some(chain)
}

fn put_row(conn: &Connection, alias: &str, session: &Stored, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO sessions(alias, key_blob, cert_chain, algorithm, hal_service, created_ms, used_ms)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(alias) DO UPDATE SET
             key_blob    = excluded.key_blob,
             cert_chain  = excluded.cert_chain,
             algorithm   = excluded.algorithm,
             hal_service = excluded.hal_service,
             used_ms     = excluded.used_ms",
        params![
            alias,
            session.key_blob,
            pack_chain(&session.cert_chain),
            session.algorithm,
            session.hal_service,
            now
        ],
    )
    .with_context(|| format!("insert session '{alias}'"))?;
    Ok(())
}

fn get_row(conn: &Connection, alias: &str) -> Result<Option<Stored>> {
    let row: Option<(Vec<u8>, Vec<u8>, String, String)> = conn
        .query_row(
            "SELECT key_blob, cert_chain, algorithm, hal_service FROM sessions WHERE alias = ?1",
            params![alias],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .with_context(|| format!("select session '{alias}'"))?;
    let Some((key_blob, chain_blob, algorithm, hal_service)) = row else {
        return Ok(None);
    };
    let cert_chain = unpack_chain(&chain_blob)
        .with_context(|| format!("session '{alias}' has a corrupt cert_chain blob"))?;
    Ok(Some(Stored {
        key_blob,
        cert_chain,
        algorithm,
        hal_service,
    }))
}

fn touch_row(conn: &Connection, alias: &str, now: i64) -> Result<usize> {
    conn.execute(
        "UPDATE sessions SET used_ms = ?2 WHERE alias = ?1",
        params![alias, now],
    )
    .with_context(|| format!("touch session '{alias}'"))
}

/// 清两个口子：超 TTL 的、以及超条数上限后按最后使用时间从旧到新淘汰的。
/// 返回 (过期清掉几条, 超上限清掉几条)。
///
/// `used_ms > 0` 是跟服务端学的教训：时间戳未知（0）是「不知道」，不是「早就过期」。
/// 不过这里的行都是我们自己写的真实时间戳，0 只可能出现在旧目录里连 mtime 都读不出来
/// 的那几条。
fn prune_rows(conn: &Connection, now: i64, ttl_secs: u64, cap: usize) -> Result<(usize, usize)> {
    let cutoff = now.saturating_sub((ttl_secs as i64).saturating_mul(1000));
    let expired = conn
        .execute(
            "DELETE FROM sessions WHERE used_ms > 0 AND used_ms < ?1",
            params![cutoff],
        )
        .context("delete expired sessions")?;
    // 只留最新用过的 cap 条，其余从旧的那头开始清。
    let over_cap = conn
        .execute(
            "DELETE FROM sessions WHERE alias IN (
                 SELECT alias FROM sessions ORDER BY used_ms DESC LIMIT -1 OFFSET ?1
             )",
            params![cap as i64],
        )
        .context("trim sessions to the cap")?;
    Ok((expired, over_cap))
}

/// 旧目录导一次。别名反推不出来（文件名是哈希），所以只能逐个读 JSON；导入用的
/// 「最后使用时间」取文件的 mtime —— 老版本的 LRU 依据正是 mtime，换算过来一致。
/// 库里已经有东西就不导，免得把清过的旧记录又拽回来。
fn import_legacy_dir(conn: &Connection, dir: &Path, now: i64) -> Result<usize> {
    let existing: i64 = conn
        .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
        .context("count sessions")?;
    if existing > 0 {
        return Ok(0);
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(0);
    };
    let tx = conn.unchecked_transaction().context("begin import")?;
    let mut imported = 0usize;
    let mut skipped = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let used_ms = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|mtime| mtime.duration_since(UNIX_EPOCH).ok())
            .map(|age| age.as_millis() as i64)
            .unwrap_or(now);
        let parsed = std::fs::read_to_string(&path)
            .ok()
            .and_then(|data| parse_legacy_json(&data));
        match parsed {
            Some((alias, session)) => {
                put_row(&tx, &alias, &session, used_ms)?;
                imported += 1;
            }
            None => {
                skipped += 1;
                log::warn!("skipping unreadable legacy session {}", path.display());
            }
        }
    }
    tx.commit().context("commit import")?;
    if skipped > 0 {
        log::warn!("{skipped} legacy session file(s) could not be read and were skipped");
    }
    Ok(imported)
}

/// 老版本那条 JSON：`{"alias":..., "key_blob":b64, "cert_chain":[b64...],
/// "algorithm":"EcP256|Rsa2048", "hal_service":"tee|strongbox"}`。
/// `hal_service` 是后加的，老记录没有，按 tee 算（当时的唯一取值）。
pub(crate) fn parse_legacy_json(data: &str) -> Option<(String, Stored)> {
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    let alias = value.get("alias")?.as_str()?.to_string();
    let key_blob = B64.decode(value.get("key_blob")?.as_str()?).ok()?;
    let cert_chain = value
        .get("cert_chain")?
        .as_array()?
        .iter()
        .map(|cert| B64.decode(cert.as_str()?).ok())
        .collect::<Option<Vec<Vec<u8>>>>()?;
    let algorithm = value.get("algorithm")?.as_str()?.to_string();
    let hal_service = value
        .get("hal_service")
        .and_then(|v| v.as_str())
        .unwrap_or("tee")
        .to_string();
    Some((
        alias,
        Stored {
            key_blob,
            cert_chain,
            algorithm,
            hal_service,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(id: u8) -> Stored {
        Stored {
            key_blob: vec![id; 64],
            cert_chain: vec![vec![id, id, id], vec![0xaa, 0xbb]],
            algorithm: "EcP256".to_string(),
            hal_service: "tee".to_string(),
        }
    }

    fn open_temp(dir: &tempfile::TempDir) -> Connection {
        open_conn(&dir.path().join("sessions.db")).unwrap()
    }

    /// 存取是同一份东西，覆盖写要能改内容、保留 created_ms。
    #[test]
    fn put_get_round_trip_and_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_temp(&dir);
        assert!(get_row(&conn, "a").unwrap().is_none());
        put_row(&conn, "a", &session(1), 1_000).unwrap();
        assert_eq!(get_row(&conn, "a").unwrap().unwrap(), session(1));
        put_row(&conn, "a", &session(2), 2_000).unwrap();
        assert_eq!(
            get_row(&conn, "a").unwrap().unwrap().key_blob,
            vec![2u8; 64]
        );
        let (created, used): (i64, i64) = conn
            .query_row("SELECT created_ms, used_ms FROM sessions", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!((created, used), (1_000, 2_000), "created 不该被覆盖");
    }

    /// 证书链是拼成一坨存的，拆回来必须一模一样（含空链和多条）。
    #[test]
    fn cert_chain_survives_packing() {
        for chain in [
            vec![],
            vec![vec![1u8; 900]],
            vec![vec![], vec![2u8; 3], vec![3u8; 1200]],
        ] {
            let packed = pack_chain(&chain);
            assert_eq!(unpack_chain(&packed).unwrap(), chain);
        }
        assert!(unpack_chain(&[0, 0]).is_none(), "长度头都不够就是坏的");
        assert!(unpack_chain(&[0, 0, 0, 9, 1, 2]).is_none(), "长度比数据大");
    }

    /// TTL 按「最后一次使用」算：碰过一下就不该被当成过期的清掉。
    #[test]
    fn ttl_follows_the_last_use_not_the_creation() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_temp(&dir);
        let day = 24 * 3600 * 1000;
        let now = now_ms();
        let minted = now - 10 * day; // 十天前铸的
        put_row(&conn, "hot", &session(1), minted).unwrap();
        put_row(&conn, "cold", &session(2), minted).unwrap();
        // 只有 hot 五分钟前刚被用过。
        touch_row(&conn, "hot", now - 5 * 60 * 1000).unwrap();
        let (expired, over) = prune_rows(&conn, now, TTL_SECS, MAX_ROWS).unwrap();
        assert_eq!((expired, over), (1, 0));
        assert!(get_row(&conn, "hot").unwrap().is_some(), "刚用过的必须留着");
        assert!(get_row(&conn, "cold").unwrap().is_none());
    }

    /// 超上限淘汰最久没用的那批，最新的一批一个不动。
    #[test]
    fn over_the_cap_evicts_the_least_recently_used() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_temp(&dir);
        for id in 0..10u8 {
            put_row(&conn, &format!("k{id}"), &session(id), 1_000 + id as i64).unwrap();
        }
        // k0 最老，碰一下把它顶成最新的。
        touch_row(&conn, "k0", 9_000).unwrap();
        let (expired, over) = prune_rows(&conn, 9_000, TTL_SECS, 3).unwrap();
        assert_eq!((expired, over), (0, 7));
        let mut live: Vec<String> = conn
            .prepare("SELECT alias FROM sessions")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        live.sort();
        assert_eq!(live, vec!["k0", "k8", "k9"], "留的是最近用过的三个");
    }

    /// 时间戳未知（0）算「不知道」，不算「早就过期」—— 服务端为这条规矩栽过一次。
    #[test]
    fn unknown_timestamp_is_not_expired() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_temp(&dir);
        put_row(&conn, "nobody-knows", &session(1), 0).unwrap();
        let (expired, over) = prune_rows(&conn, 10 * 24 * 3600 * 1000, TTL_SECS, MAX_ROWS).unwrap();
        assert_eq!((expired, over), (0, 0));
        assert!(get_row(&conn, "nobody-knows").unwrap().is_some());
    }

    /// 旧目录导入：别名进库、mtime 当最后使用时间、库非空时不再导、坏文件跳过。
    #[test]
    fn legacy_json_dir_is_imported_once() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open_temp(&dir);
        let legacy = dir.path().join("sessions");
        std::fs::create_dir_all(&legacy).unwrap();
        let json = |alias: &str, hal: Option<&str>| {
            let mut value = serde_json::json!({
                "alias": alias,
                "key_blob": B64.encode([7u8; 8]),
                "cert_chain": [B64.encode([1u8; 4])],
                "algorithm": "Rsa2048",
            });
            if let Some(hal) = hal {
                value["hal_service"] = serde_json::json!(hal);
            }
            value.to_string()
        };
        std::fs::write(legacy.join("aaa_1.json"), json("alias-A", None)).unwrap();
        std::fs::write(
            legacy.join("bbb_2.json"),
            json("alias-B", Some("strongbox")),
        )
        .unwrap();
        std::fs::write(legacy.join("ccc_3.json"), "{ not json").unwrap();
        std::fs::write(legacy.join("notes.txt"), "ignore me").unwrap();

        let now = now_ms();
        assert_eq!(import_legacy_dir(&conn, &legacy, now).unwrap(), 2);
        let a = get_row(&conn, "alias-A").unwrap().unwrap();
        assert_eq!(a.key_blob, vec![7u8; 8]);
        assert_eq!(a.cert_chain, vec![vec![1u8; 4]]);
        assert_eq!(a.algorithm, "Rsa2048");
        assert_eq!(a.hal_service, "tee", "老记录没有 hal_service，按 tee 算");
        assert_eq!(
            get_row(&conn, "alias-B").unwrap().unwrap().hal_service,
            "strongbox"
        );
        // 第二次进来库里已经有东西了，一条都不再动。
        assert_eq!(import_legacy_dir(&conn, &legacy, now).unwrap(), 0);
    }

    /// 重启后（重新开库）数据还在，而且新写的覆盖得住旧的。
    #[test]
    fn reopening_the_db_keeps_the_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.db");
        {
            let conn = open_conn(&path).unwrap();
            put_row(&conn, "alias", &session(3), 5_000).unwrap();
        }
        let conn = open_conn(&path).unwrap();
        assert_eq!(get_row(&conn, "alias").unwrap().unwrap(), session(3));
    }

    /// 真机演练（默认跳过）：拿设备上真目录导一遍，看条数对不对、超 TTL 的占多少。
    /// 要用 OMMEGA_SESSIONS_DB / OMMEGA_SESSIONS_DIR 两个环境变量指路：
    ///
    /// ```text
    /// cp -r /data/adb/ommega/sessions /data/local/tmp/sessions-drill
    /// OMMEGA_SESSIONS_DB=/data/local/tmp/drill.db \
    ///   OMMEGA_SESSIONS_DIR=/data/local/tmp/sessions-drill \
    ///   ./ommega-sessdb-test --ignored drill_from_the_real_sessions_dir --nocapture
    /// ```
    #[test]
    #[ignore]
    fn drill_from_the_real_sessions_dir() {
        let dir = legacy_dir();
        let db = db_path();
        let files = std::fs::read_dir(&dir)
            .expect("真目录读不到，先看 OMMEGA_SESSIONS_DIR")
            .flatten()
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .count();
        let _ = std::fs::remove_file(&db);
        let conn = open_conn(&db).unwrap();
        let now = now_ms();
        let started = std::time::Instant::now();
        let imported = import_legacy_dir(&conn, &dir, now).unwrap();
        let elapsed = started.elapsed();
        // 逐条比对：旧 JSON 里那几条字段（key blob、证书链、算法、HAL）搬过来得一模一样，
        // 少一条或错一个字节，刷上去就是一片 `no key for alias`。比对放在清理之前，
        // 免得把「过期清掉了」误读成「没导进来」。
        let mut checked = 0usize;
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some((alias, want)) = std::fs::read_to_string(&path)
                .ok()
                .and_then(|data| parse_legacy_json(&data))
            else {
                continue;
            };
            let got = get_row(&conn, &alias)
                .unwrap()
                .unwrap_or_else(|| panic!("导入后找不到 {alias}"));
            assert_eq!(got.key_blob, want.key_blob, "{alias} 的 key blob 对不上");
            assert_eq!(got.cert_chain, want.cert_chain, "{alias} 的证书链对不上");
            assert_eq!(got.algorithm, want.algorithm, "{alias} 的算法对不上");
            assert_eq!(got.hal_service, want.hal_service, "{alias} 的 HAL 对不上");
            checked += 1;
        }
        let (expired, over_cap) = prune_rows(&conn, now, TTL_SECS, MAX_ROWS).unwrap();
        let rows: i64 = conn
            .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        let sample: Option<(String, i64, i64)> = conn
            .query_row(
                "SELECT alias, length(key_blob), length(cert_chain) FROM sessions LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .unwrap();
        println!(
            "文件 {files} 个 → 导入 {imported} 条（{elapsed:?}），逐条比对 {checked} 条一致｜过期清掉 \
             {expired}、超上限清掉 {over_cap}、留在库里 {rows}｜抽样 {sample:?}"
        );
        assert_eq!(imported, files, "每个文件都该进去一条");
        assert_eq!(checked, files, "逐条比对得把每个文件都比一遍");
        assert_eq!(rows, (imported - expired - over_cap) as i64);
    }
}
