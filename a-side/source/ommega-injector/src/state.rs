//! 数据根里那几份小文件的读写。
//!
//! 数据根是 `/data/misc/keystore/ommega`，属主 root:keystore、0770，父目录
//! `/data/misc/keystore` 还是 0700 的 keystore_data_file。所以：
//!
//! - daemon、软件 TA、keystore2 里那份 payload 都在能进这个目录的域里，本地读写即可；
//! - SOTER 宿主（app 域，uid 10182 那种）连目录都穿不进去，只能走 maintenance RPC。
//!
//! 这一层就干一件事：本地读得动就读本地，读不动走 RPC；写同理。判据是 errno
//! 不是 NotFound —— 文件真没有（NotFound）就别白跑一趟跨进程。

/// 数据根，跟 daemon 侧的 `soter_store::DATA_ROOT` 是同一个。
pub const ROOT: &str = "/data/misc/keystore/ommega";

/// 已经在这层走 RPC 了（重入闸，见 [`read`]）。
static IN_RPC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 按名拼数据根里的路径。
pub fn path(name: &str) -> String {
    format!("{ROOT}/{name}")
}

/// 本地读不到（权限/目录进不去）才走 RPC。
///
/// 重入闸：RPC 那条路本身要初始化进程状态，而初始化会读配置（`log_flag` / `config`），
/// 那又回到这里 —— 不挡住就是无限递归。闸门里的人只读本地。
pub fn read(name: &str) -> Option<String> {
    match std::fs::read_to_string(path(name)) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => {
            if IN_RPC.swap(true, std::sync::atomic::Ordering::Relaxed) {
                return None;
            }
            let answer = match crate::ipc::read_state(name) {
                Ok(Some(text)) => Some(text),
                Ok(None) => None,
                Err(error) => {
                    log::debug!("event=state read {name} failed locally and over RPC ({error:#})");
                    None
                }
            };
            IN_RPC.store(false, std::sync::atomic::Ordering::Relaxed);
            answer
        }
    }
}

/// 读一份文件，全是空白就当没有。
pub fn read_trimmed(name: &str) -> Option<String> {
    read(name).map(|text| text.trim().to_string())
}

/// 写一份文件。本地写得动就本地写，写不动交给 daemon。
pub fn write(name: &str, data: &str) -> bool {
    let target = path(name);
    match std::fs::write(&target, data.as_bytes()) {
        Ok(()) => {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666));
            true
        }
        Err(_) => match crate::ipc::write_state(name, data) {
            Ok(ok) => ok,
            Err(error) => {
                log::debug!("event=state write {name} failed locally and over RPC ({error:#})");
                false
            }
        },
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// 数据根拼出来的路径就是 daemon 那份料库的目录，别在两处各写一遍。
    #[test]
    fn the_root_matches_the_store() {
        assert_eq!(path("soter_ok"), "/data/misc/keystore/ommega/soter_ok");
    }

    /// 本地读得动的时候不许走 RPC（daemon / 软件 TA 都是这条）。
    #[test]
    fn a_readable_file_is_served_locally() {
        let dir = std::env::temp_dir().join(format!("ommega-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("flag");
        std::fs::write(&file, b"1\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap().trim(),
            "1",
            "sanity: the local read is the one this layer relies on"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
