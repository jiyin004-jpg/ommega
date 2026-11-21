//! 本地 SOTER 料库（ASK / AuthKey / 墓碑）的落盘。
//!
//! 注入在 app 域的那份 payload（SOTER 宿主是 platform_app、带 MLS 类别）读得到这份
//! 文件，但写不动：MLS 的写约束要求主体和客体的级别相等，SELinux 的类型规则放行了
//! 也没用。所以它的写顺着 `IMaintenanceService::writeSoterStore` 走到这里，由 daemon
//! 代写。
//!
//! 收进来的是整份文本（调用方自己做过读-改-写）。落盘走「临时文件 + rename」：中途
//! 掉电不会留半个 json，读的那一侧也只会看到完整的旧版或新版。

use std::sync::Mutex;

/// 跟 `hook::soter_local::ASK_STORE_PATH` 是同一个地方。
pub const STORE_PATH: &str = "/data/misc/keystore/ommega/soter_asks.json";

/// 数据根：料库和那几份小件都在这个目录里。
pub const DATA_ROOT: &str = "/data/misc/keystore/ommega";

/// 按名取数据根里的文件路径。只认单层文件名（字母数字和 `. _ -`），`/`、`..` 一律拒。
pub fn named_path(name: &str) -> Option<std::path::PathBuf> {
    if name.is_empty() || name.len() > 64 || name == "." || name == ".." {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return None;
    }
    Some(std::path::Path::new(DATA_ROOT).join(name))
}

/// 读数据根里的一份文件。不存在、读不动都是 `None`。
pub fn read_named(name: &str) -> Option<String> {
    let path = named_path(name)?;
    std::fs::read_to_string(path).ok()
}

/// 写数据根里的一份文件：临时文件 + rename，落盘统一 0666。
pub fn write_named(name: &str, text: &str) -> bool {
    match named_path(name) {
        Some(path) => write_at(&path.to_string_lossy(), text),
        None => false,
    }
}

/// 整份料库读出来；没有这个文件就是 `None`。
pub fn read() -> Option<String> {
    std::fs::read_to_string(STORE_PATH).ok()
}

/// 某个 uid 的下一个 counter。
///
/// app 域（进不去数据根）自己开不了这个文件，但 counter 必须单调递增 —— 两边都写同一份
/// 文本、都得拿同一把 flock，所以加减在这里做，注入器那边只负责把结果报给 App。
///
/// 返回 `None` = 文件开不了/锁不上，调用方应当只留内存，**不要**回写。
pub fn bump_counter(uid: i32, memory_floor: u64) -> Option<u64> {
    use kmr_common::soter_counter::{counter_for, next_counter, set_counter};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;

    let path = named_path("soter_counter")?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .ok()?;
    let _guard = WRITE_LOCK.lock().ok()?;
    let _lock = file.lock(); // 锁跟着 fd，文件关闭（drop）时自动释放
    let mut text = String::new();
    let _ = file.read_to_string(&mut text);
    let next = next_counter(counter_for(&text, uid), memory_floor);
    let updated = set_counter(&text, uid, next);
    let _ = file.seek(SeekFrom::Start(0));
    // 先写后截：反过来一旦 write_all 失败（ENOSPC/EDQUOT）文件就空了，所有 uid 的
    // 计数一起丢，下轮全部从 1 开始。
    if file.write_all(updated.as_bytes()).is_ok() {
        let _ = file.set_len(updated.len() as u64);
    }
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
    Some(next)
}

/// 读-改-写在调用方那边，这里只保证「写」是串行的。
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// 把整份文本写进料库。返回 false = 没写进去（目录没权限、磁盘满之类）。
pub fn write(text: &str) -> bool {
    let Ok(_guard) = WRITE_LOCK.lock() else {
        return false;
    };
    write_at(STORE_PATH, text)
}

fn write_at(path: &str, text: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;

    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // 这个文件由几个域一起写，落盘完统一 0666。临时名带 pid + 序号：几个域并发写同一个
    // 文件时，固定的 `.tmp` 会被下一个写者踩掉。
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = format!(
        "{path}.rpc.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let mut fail = None;
    match std::fs::write(&tmp, text.as_bytes()) {
        Ok(()) => {
            if let Err(error) =
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666))
            {
                fail = Some(format!("chmod {tmp}: {error}"));
            }
            if fail.is_none() {
                if let Err(error) = std::fs::rename(&tmp, path) {
                    fail = Some(format!("rename {tmp} -> {path}: {error}"));
                }
            }
        }
        Err(error) => fail = Some(format!("write {tmp}: {error}")),
    }
    if fail.is_none() {
        return true;
    }
    // 目录不可写（只有文件本身可写）时改回就地把内容盖掉：掉电可能留半个 json，
    // 但总比「一个字都落不下去」强。
    let _ = std::fs::remove_file(&tmp);
    match std::fs::write(path, text.as_bytes()) {
        Ok(()) => {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
            true
        }
        Err(error) => {
            log::warn!(
                "failed to write the soter ask store at {path}: {}; in-place: {error}",
                fail.unwrap_or_default()
            );
            false
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_the_text_and_leaves_the_file_writable_for_every_domain() {
        let dir = std::env::temp_dir().join(format!("ommega-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");
        std::fs::write(&path, b"{\"old\":1}").unwrap();
        // 别的写者留下的 0644 不能一直带下去，否者 uid 不同的那几家就写不动了。
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o644);
        std::fs::set_permissions(&path, permissions).unwrap();

        let path_text = path.to_str().unwrap().to_string();
        assert!(write_at(&path_text, "{\"new\":2}"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"new\":2}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o666);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_directory_is_created() {
        let dir = std::env::temp_dir().join(format!("ommega-store-new-{}", std::process::id()));
        let path = dir.join("nested").join("store.json");
        assert!(write_at(path.to_str().unwrap(), "{}"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
