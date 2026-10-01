//! 按住系统，别让它进 suspend。
//!
//! Android 的规则是「没人持有 wakelock 就 suspend」，而 suspend 会把 relay 整个
//! 冻住：
//!
//! - reqwest 的超时（连接、读、总超时）都挂在单调钟上，睡的时候单调钟不走，
//!   所以恢复后第一次 poll 会一直挂在那里不返回；
//! - 看门狗判得对（它读的 `/proc/uptime` 是启动钟，睡的时候照走），但它自己那个
//!   `sleep` 也是单调钟，睡着的时候同样不跑 —— 只能在设备醒过来之后才收网。
//!
//! 结果就是：灭屏一会儿，服务端就收不到 poll 了（服务端 120 秒没有 poll 就把这
//! 台 B 端标成离线），A 端的请求被转给别的 B 端。醒过来之后看门狗能救，但那是
//! 「醒了之后」的事。
//!
//! 治本只有两条路：要么别让它睡，要么外面定时把它叫醒。这里做第一种 ——
//! `CONFIG_PM_WAKELOCKS=y` 的内核上，往 `/sys/power/wake_lock` 写一个名字就拿到
//! 一把全局锁，拿着锁系统不会 suspend（这台机器上实测这文件是 777，不用 root 也
//! 写得进去）。
//!
//! 一个必须记住的坑：**这把锁不跟进程绑定**。实测写完之后进程退出，锁还挂着。
//! 所以三件事都得做：
//! 1. 上线前先把同名残留解掉（上次被 `pkill -9` 打死留下的）；
//! 2. 退出时自己解（`Drop`）；
//! 3. 模块卸载脚本里再解一把。
//!
//! 漏掉哪一条，手机都会一直醒着耗电。

use std::io::{Error, ErrorKind, Write};

/// 默认锁名。别人 `cat /sys/power/wake_lock` 一眼能看出是谁按着的。
pub const DEFAULT_NAME: &str = "ommega_relay";

const LOCK_PATH: &str = "/sys/power/wake_lock";
const UNLOCK_PATH: &str = "/sys/power/wake_unlock";

/// 一把拿住的锁。`Drop` 会解掉，所以别让它提前出作用域。
pub struct WakeLock {
    name: String,
    lock_path: String,
    held: bool,
}

impl WakeLock {
    /// 拿锁。同名残留会先被解掉 —— 那个残留只会来自上一次没优雅退出的自己。
    pub fn acquire(name: &str) -> std::io::Result<Self> {
        Self::acquire_at(LOCK_PATH, UNLOCK_PATH, name)
    }

    fn acquire_at(lock: &str, unlock: &str, name: &str) -> std::io::Result<Self> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::new(ErrorKind::InvalidInput, "wakelock 名字不能是空"));
        }
        // 解残留：解不掉（比如没有 unlock 文件）不算错，接着拿就行。
        let _ = write_name(unlock, name);
        write_name(lock, name)?;
        Ok(Self {
            name: name.to_string(),
            lock_path: lock.to_string(),
            held: true,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// 内核那边现在真的记着这个锁吗。读回来确认，不看自己的状态位。
    pub fn held_now(&self) -> bool {
        held_at(&self.lock_path, &self.name)
    }

    /// 解掉。可以重复调。
    pub fn release(&mut self) {
        if !self.held {
            return;
        }
        let _ = write_name(UNLOCK_PATH, &self.name);
        self.held = false;
    }
}

impl Drop for WakeLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// 内核现在记不记得这个名字。
pub fn held(name: &str) -> bool {
    held_at(LOCK_PATH, name)
}

/// 锁不在就重新拿一下。返回内核认不认 —— 不认说明这个内核没有这个接口。
pub fn reacquire(name: &str) -> bool {
    if held(name) {
        return true;
    }
    write_name(LOCK_PATH, name).is_ok() && held(name)
}

/// 把同名残留解掉。返回「本来有一条、现在解掉了」。
///
/// 自己不开这个功能时也得调一下：上一任（或者上一次开着的时候）留下的锁没人
/// 解的话，配置里写 false 跟没写一样，系统还是睡不下去。
pub fn clear_stale(name: &str) -> bool {
    clear_stale_at(LOCK_PATH, UNLOCK_PATH, name)
}

fn clear_stale_at(lock: &str, unlock: &str, name: &str) -> bool {
    if !held_at(lock, name) {
        return false;
    }
    write_name(unlock, name).is_ok() && !held_at(lock, name)
}

/// 内核现在记不记得这个名字（路径可形参化，方便测）。
pub fn held_at(lock_path: &str, name: &str) -> bool {
    std::fs::read_to_string(lock_path)
        .map(|text| text.lines().any(|line| line.trim() == name))
        .unwrap_or(false)
}

/// 往 `wake_lock` 里写名字是「拿」，往 `wake_unlock` 里写是「放」。
fn write_name(path: &str, name: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    /// 拿两个临时文件当 lock/unlock 用，别去动真的 /sys/power。
    fn fixtures() -> (String, String, std::path::PathBuf) {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ommega-wl-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join("wake_lock");
        let unlock = dir.join("wake_unlock");
        std::fs::write(&lock, "").unwrap();
        std::fs::write(&unlock, "").unwrap();
        (
            lock.to_string_lossy().to_string(),
            unlock.to_string_lossy().to_string(),
            dir,
        )
    }

    #[test]
    fn acquiring_writes_the_name_where_the_kernel_looks() {
        let (lock, unlock, dir) = fixtures();
        let wl = WakeLock::acquire_at(&lock, &unlock, "ommega_test").unwrap();
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), "ommega_test");
        assert!(wl.held_now());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn acquiring_clears_a_stale_lock_of_the_same_name_first() {
        let (lock, unlock, dir) = fixtures();
        // 上一次被 -9 打死留下的，解锁文件里没人写它，锁还挂着
        std::fs::write(&lock, "ommega_test\n").unwrap();
        let _wl = WakeLock::acquire_at(&lock, &unlock, "ommega_test").unwrap();
        assert_eq!(std::fs::read_to_string(&unlock).unwrap(), "ommega_test");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn releasing_writes_to_the_unlock_file_and_is_idempotent() {
        let (lock, unlock, dir) = fixtures();
        let mut wl = WakeLock::acquire_at(&lock, &unlock, "ommega_test").unwrap();
        wl.release();
        assert_eq!(std::fs::read_to_string(&unlock).unwrap(), "ommega_test");
        // 第二次不该再写一遍（免得把别人的记录搅了）
        std::fs::write(&unlock, "").unwrap();
        wl.release();
        assert_eq!(std::fs::read_to_string(&unlock).unwrap(), "");
        drop(wl);
        assert_eq!(std::fs::read_to_string(&unlock).unwrap(), "");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn dropping_releases() {
        let (lock, unlock, dir) = fixtures();
        {
            let _wl = WakeLock::acquire_at(&lock, &unlock, "ommega_test").unwrap();
        }
        assert_eq!(std::fs::read_to_string(&unlock).unwrap(), "ommega_test");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn held_now_reports_what_the_kernel_says_not_what_we_think() {
        let (lock, unlock, dir) = fixtures();
        let wl = WakeLock::acquire_at(&lock, &unlock, "ommega_test").unwrap();
        assert!(wl.held_now());
        // 别人把它解了
        std::fs::write(&lock, "\n").unwrap();
        assert!(!wl.held_now());
        // 文件都没有的时候（内核没开 CONFIG_PM_WAKELOCKS）也不能崩
        assert!(!held_at("/nonexistent/ommega/wake_lock", "ommega_test"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_nameless_lock_is_refused() {
        let (lock, unlock, dir) = fixtures();
        assert!(WakeLock::acquire_at(&lock, &unlock, "   ").is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    // 「本来有一条、解掉了」那一半只能在真内核上验（测试里没有会把名字从 lock
    // 文件里抹掉的内核）。这里只管住没锁的时候不去乱写。
    #[test]
    fn clearing_a_lock_that_is_not_held_writes_nothing() {
        let (lock, unlock, dir) = fixtures();
        assert!(!clear_stale_at(&lock, &unlock, "ommega_test"));
        assert_eq!(std::fs::read_to_string(&unlock).unwrap(), "");
        std::fs::remove_dir_all(dir).ok();
    }
}
