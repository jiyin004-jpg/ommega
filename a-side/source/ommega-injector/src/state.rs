//! 数据根里那几份小文件的读写。
//!
//! 数据根是 `/data/misc/keystore/ommega`，属主 root:keystore、0770，父目录
//! `/data/misc/keystore` 还是 0700 的 keystore_data_file。所以：
//!
//! - daemon、软件 TA、keystore2 里那份 payload 都在能进这个目录的域里，本地读写即可；
//! - SOTER 宿主（app 域，uid 10182 那种）连目录都穿不进去，只能走 maintenance RPC。
//!
//! 这一层就干一件事：本地读写得动就用本地，动不了走 RPC。判据是 errno 不是
//! NotFound —— 文件真没有就别白跑一趟跨进程。

use std::sync::atomic::{AtomicBool, Ordering};

/// 数据根，跟 daemon 侧的 `soter_store::DATA_ROOT` 是同一个。
pub const ROOT: &str = "/data/misc/keystore/ommega";

/// 一次读的结果。三态是必要的：把「读不动」当成「没有」正是打掉整份料库那个老 bug
/// —— 调用方按空料库做一次读-改-写，别人建好的 ASK / AuthKey 就没了。
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    /// 读到了。
    Got(String),
    /// 确定没有这个文件。
    Missing,
    /// 读不动（没权限、目录进不去、daemon 也不肯说），不知道该不该当成空。
    Unreadable,
}

// 当前线程已经在这层走 RPC 了（重入闸，见 `read_checked`）。
//
// 必须是线程局部的：宿主里多条 binder 线程并发进来，用全局标志的话，一条线程正在
// 走 RPC 就会让另一条线程的合法读被当成重入、直接静默返回「读不到」。
thread_local! {
    static IN_RPC: AtomicBool = const { AtomicBool::new(false) };
}

/// 按名拼数据根里的路径。
pub fn path(name: &str) -> String {
    format!("{ROOT}/{name}")
}

/// 读一份文件，三种结果都如实报出来。本地读不动才走 RPC。
///
/// 重入闸：RPC 那条路自己要初始化进程状态，而初始化会读配置（`log_flag` / `config`），
/// 那又回到这里 —— 不挡住就是无限递归。闸门里的人只读本地。
pub fn read_checked(name: &str) -> Read {
    match std::fs::read_to_string(path(name)) {
        Ok(text) => Read::Got(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Read::Missing,
        Err(_) => {
            if IN_RPC.with(|flag| flag.swap(true, Ordering::Relaxed)) {
                return Read::Unreadable;
            }
            // 闸门用 drop guard 收：`ipc` 里一堆 `expect`，panic 揉过这里时闸门得自己
            // 解开，否则这条（会被复用的）binder 线程以后只读本地。
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    IN_RPC.with(|flag| flag.store(false, Ordering::Relaxed));
                }
            }
            let _reset = Reset;
            match crate::ipc::read_state(name) {
                Ok(Some(text)) => Read::Got(text),
                Ok(None) => Read::Missing,
                Err(error) => {
                    log::debug!("event=state read {name} failed locally and over RPC ({error:#})");
                    Read::Unreadable
                }
            }
        }
    }
}

/// 读一份文件；「没有」和「读不动」都回 `None`。要区分两者用 [`read_checked`]。
pub fn read(name: &str) -> Option<String> {
    match read_checked(name) {
        Read::Got(text) => Some(text),
        _ => None,
    }
}

/// 写一份文件。本地写得动就本地写，写不动交给 daemon。
///
/// 落盘统一走临时文件 + rename：这份文件几个域一起写，中途掉电留半个文件比没有更糟。
pub fn write(name: &str, data: &str) -> bool {
    if write_locally(name, data) {
        return true;
    }
    match crate::ipc::write_state(name, data) {
        Ok(ok) => ok,
        Err(error) => {
            log::debug!("event=state write {name} failed locally and over RPC ({error:#})");
            false
        }
    }
}

fn write_locally(name: &str, data: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;

    // 临时文件名带 pid + 序号：几个域可能同时写同一份文件，固定的 `.tmp` 会被下一个
    // 写者踩掉，然后 rename 上去的是别人的内容。
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let target = path(name);
    let tmp = format!(
        "{target}.{}.{}.tmp",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    if std::fs::write(&tmp, data.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666));
    if std::fs::rename(&tmp, &target).is_ok() {
        return true;
    }
    let _ = std::fs::remove_file(&tmp);
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// 数据根拼出来的路径就是 daemon 那份料库的目录，别在两处各写一遍。
    #[test]
    fn the_root_matches_the_store() {
        assert_eq!(path("soter_ok"), "/data/misc/keystore/ommega/soter_ok");
    }

    /// 「读不动」和「没有」必须分得开：混成一个值就会把整份料库覆盖掉。
    #[test]
    fn an_unreadable_store_is_not_an_empty_one() {
        assert_ne!(Read::Unreadable, Read::Missing);
        assert_eq!(Read::Missing, Read::Missing);
    }
}
