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
pub const STORE_PATH: &str = "/data/misc/ommega/soter_asks.json";

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
    // 这个文件是几个域一起写的：keystore 域里的 payload、hal_soter、还有 system_app
    // 宿主。以前这里「保留原权限」，只要哪一次留下 0644，后面**不属同一 uid 的写者**
    // 就全哑了，而且 rename 会把 0644 一直带下去 —— 实测到的症状就是 ASK/AuthKey 只
    // 活在内存里、墓碑永远清不掉（导出 AuthKey 恒 -6）。所以落盘完统一 0666。
    let tmp = format!("{path}.rpc.tmp");
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
