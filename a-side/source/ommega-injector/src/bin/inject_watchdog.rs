//! 文件变化驱动的 injector 调度器。
//!
//! 以前 `daemon-injector` 自己是个「每 3~5 秒轮询一轮」的 shell 循环：每轮 `mkdir`、
//! `chown`、`chmod`、`chcon`、几次 `cat` 比对——十几二十次 fork，只为确认「什么都没
//! 变」。实测这一层稳定吃 4% CPU（改之前 8%）。
//!
//! 这里把「什么时候该跑」搬到 Rust：每秒 stat 一遍几个关键文件（`<0.01%`），只有
//! mtime 真的变了，或者距上次超过一分钟（`dumpsys` 前台采样、SOTER 自检这类不靠文件
//! 变化触发的事得靠它兜底），才叫 `daemon-injector --once` 跑一轮真正的同步 + 注入。
//!
//! 锁仍然用 shell 那套（`run/injector-daemon.lock`）：由本进程持有，调用 `--once` 时
//! 用 `OMMEGA_SKIP_LOCK=1` 告诉它别抢。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const MODDIR: &str = "/data/adb/modules/ommega";
const DATA_DIR: &str = "/data/misc/keystore/ommega";
const STATE_DIR: &str = "/data/adb/ommega";

/// stat 一遍全部被监控项要多久？极短，所以可以拍得密一点，让面板改动近乎即时生效。
const POLL: Duration = Duration::from_millis(700);
/// 兜底周期：没有文件变化也要跑一轮（前台采样 / 自检 / 把崩溃的 SOTER 宿主拉起来）。
const IDLE_TICK: Duration = Duration::from_secs(60);

fn watched() -> Vec<PathBuf> {
    let data = PathBuf::from(DATA_DIR);
    let state = PathBuf::from(STATE_DIR);
    vec![
        data.join("config"),
        data.join("config.toml"),
        data.join("target.txt"),
        data.join("injector.toml"),
        data.join("soter_attk.pem"),
        data.join("soter_cpu_id"),
        data.join("keybox_tee.xml"),
        data.join("keybox_strongbox.xml"),
        // 面板写的伪装项、能力开关都在这里；目录 mtime 变就说明有增删
        state.join("conf"),
    ]
}

fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

fn snapshot() -> Vec<Option<SystemTime>> {
    watched().iter().map(|path| mtime(path)).collect()
}

fn run_once() {
    let script = format!("{MODDIR}/daemon-injector");
    let status = Command::new("sh")
        .arg(&script)
        .arg("--once")
        .env("OMMEGA_SKIP_LOCK", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => log_line(&format!("daemon-injector --once exited with {s}")),
        Err(e) => log_line(&format!("failed to run daemon-injector: {e}")),
    }
}

fn log_line(msg: &str) {
    // 跟 shell 那层一个日志文件，方便对照
    let path = format!("{STATE_DIR}/logs/injector-watchdog.log");
    if let Some(parent) = Path::new(&path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

/// 抢 `run/injector-daemon.lock`。拿不到说明已有实例在跑（或者上次被 kill 留了残锁）。
fn acquire_lock() -> Option<PathBuf> {
    let lock = PathBuf::from(format!("{STATE_DIR}/run/injector-daemon.lock"));
    let _ = fs::create_dir_all(format!("{STATE_DIR}/run"));
    if fs::create_dir(&lock).is_ok() {
        let _ = fs::write(lock.join("pid"), format!("{}", std::process::id()));
        return Some(lock);
    }
    // 残锁：目录在但没有活着的 holder（shell 那套也这么判断）
    let holder = fs::read_to_string(lock.join("pid")).unwrap_or_default();
    let holder = holder.trim();
    let alive = if holder.is_empty() {
        false
    } else {
        Path::new(&format!("/proc/{holder}")).exists()
    };
    if alive {
        log_line(&format!(
            "another watch instance (pid {holder}) is running; exiting"
        ));
        return None;
    }
    let _ = fs::remove_dir_all(&lock);
    if fs::create_dir(&lock).is_ok() {
        let _ = fs::write(lock.join("pid"), format!("{}", std::process::id()));
        return Some(lock);
    }
    None
}

fn main() {
    let Some(_lock) = acquire_lock() else {
        return;
    };

    // 起来先跑一轮：把上次留下的状态对齐
    run_once();
    let mut last_run = Instant::now();
    let mut last = snapshot();

    loop {
        thread::sleep(POLL);
        let current = snapshot();
        let changed = current != last;
        if changed || last_run.elapsed() >= IDLE_TICK {
            if changed {
                log_line("watched file changed; running a tick");
            }
            last = current;
            last_run = Instant::now();
            run_once();
        }
    }
}
