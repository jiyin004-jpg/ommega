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
    if let Some(dir) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // 保留原来的权限：这个文件本来是 0666（几个写者都靠 other 那一档），rename 会把
    // 临时文件自己的 0644 带上去，后来者就写不动了。
    let keep_mode = std::fs::metadata(path).map(|meta| meta.permissions()).ok();
    let tmp = format!("{path}.rpc.tmp");
    let written = std::fs::write(&tmp, text.as_bytes()).is_ok();
    if written {
        if let Some(permissions) = keep_mode {
            let _ = std::fs::set_permissions(&tmp, permissions);
        }
        if std::fs::rename(&tmp, path).is_ok() {
            return true;
        }
    }
    let _ = std::fs::remove_file(&tmp);
    log::warn!("failed to write the soter ask store at {path}");
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_the_text_and_keeps_the_old_mode() {
        let dir = std::env::temp_dir().join(format!("ommega-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.json");
        std::fs::write(&path, b"{\"old\":1}").unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o666);
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
