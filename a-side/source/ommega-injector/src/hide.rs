//! 进程隐身（注入器那份）。
//!
//! keymint 有一整套（`src/stealth.rs`），这里只留最小的一半：把自己读进 memfd 再
//! `fexecve`，进程名换成名字表里挑好的系统 HAL 名。这样注入器哪怕只跑半秒，
//! `ps` 里也不会出现 `/data/adb/modules/ommega/libs/arm64-v8a/ommega-inject`。
//!
//! 名字表由 keymint 守护开机时生成（`/data/misc/ommega/conf/stealth.names`），
//! 这里只读不写 —— 注入器可能同时有好几个在跑，别去抢那个文件。
//!
//! 失败静默降级：藏不住可以，注入不了不行。

use std::ffi::CString;
use std::fs;
use std::path::Path;

const NAMES_FILE: &str = "/data/misc/ommega/conf/stealth.names";

fn name_for(role: &str) -> Option<String> {
    let text = fs::read_to_string(NAMES_FILE).ok()?;
    for line in text.lines() {
        let (key, value) = line.split_once('=')?;
        if key.trim() == role {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn already_hidden() -> bool {
    matches!(
        fs::read_link("/proc/self/exe"),
        Ok(path) if path.to_string_lossy().starts_with("/memfd:")
    )
}

/// 改 comm。memfd 起的进程内核会把它设成 `/proc/self/fd/N` 的 basename（就是 "4"），
/// 不改的话 `ps` 里一排 "4"，比不藏还显眼。
fn set_comm(name: &str) {
    let mut buf = [0u8; 16];
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    buf[..n].copy_from_slice(&bytes[..n]);
    unsafe {
        libc::prctl(libc::PR_SET_NAME, buf.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
}

/// 换成「memfd 里的自己 + 伪装名」。成功不会返回。
pub fn hide_self(role: &str) {
    if already_hidden() {
        if let Some(arg0) = std::env::args().next() {
            if let Some(base) = Path::new(&arg0).file_name() {
                set_comm(&base.to_string_lossy());
            }
        }
        return;
    }
    let Some(fake) = name_for(role) else {
        return;
    };
    let Ok(real) = fs::read_link("/proc/self/exe") else {
        return;
    };
    if !real.is_file() {
        return;
    }
    // 真身路径落文件：自举之后 `/proc/self/exe` 就是 memfd 了，而注入器还得靠
    // 这个路径把自己映射进目标进程。不用环境变量 —— environ 是 root 一句 tr 就能看的东西。
    let _ = fs::create_dir_all("/data/adb/ommega/run");
    let _ = fs::write(
        "/data/adb/ommega/run/injector.self",
        real.to_string_lossy().as_bytes(),
    );
    let base = Path::new(&fake)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "hal".to_string());
    let Ok(name) = CString::new(base) else {
        return;
    };
    // syscall 直接调：`libc::memfd_create` 是 API 30+ 的符号，target API 26 链接不上。
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0u32) } as libc::c_int;
    if fd < 0 {
        return;
    }
    if !copy_into(fd, &real) {
        unsafe { libc::close(fd) };
        return;
    }

    let Ok(a0) = CString::new(fake) else {
        unsafe { libc::close(fd) };
        return;
    };
    let mut args: Vec<CString> = vec![a0];
    for arg in std::env::args().skip(1) {
        match CString::new(arg) {
            Ok(value) => args.push(value),
            Err(_) => {
                unsafe { libc::close(fd) };
                return;
            }
        }
    }
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    let mut env: Vec<CString> = std::env::vars()
        // 环境里不留 `_`（shell 填的可执行路径）、PWD、OMMEGA_*、KSU_*。
        .filter(|(key, _)| {
            !matches!(key.as_str(), "_" | "PWD" | "KSU_MODULE")
                && !key.starts_with("OMMEGA_")
                && !key.starts_with("KSU_")
        })
        .filter_map(|(key, value)| CString::new(format!("{key}={value}")).ok())
        .collect();
    if let Ok(item) = CString::new("PWD=/") {
        env.push(item);
    }
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|s| s.as_ptr()).collect();
    envp.push(std::ptr::null());

    unsafe {
        // cwd 也得换回根：从模块脚本 fork 出来的进程 cwd 就是模块目录，
        // `/proc/<pid>/cwd` 一读就把 daemon-injector、keybox_*.xml 全露了。
        let root = CString::new("/").unwrap();
        libc::chdir(root.as_ptr());
        // `fexecve` 也是 API 30+，走 /proc/self/fd（exec 时 fd 还在，路径才解析）。
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        if let Ok(path) = CString::new(format!("/proc/self/fd/{fd}")) {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        }
        libc::close(fd);
    }
}

fn copy_into(fd: libc::c_int, path: &Path) -> bool {
    let Ok(mut src) = fs::File::open(path) else {
        return false;
    };
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match std::io::Read::read(&mut src, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut off = 0;
                while off < n {
                    let written = unsafe {
                        libc::write(fd, buf[off..n].as_ptr() as *const libc::c_void, n - off)
                    };
                    if written <= 0 {
                        return false;
                    }
                    off += written as usize;
                }
            }
            Err(_) => return false,
        }
    }
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    true
}
