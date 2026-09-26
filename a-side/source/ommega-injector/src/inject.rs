mod memfd;
pub(crate) mod payload_fd;

use std::ffi::{c_void, CString};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::{rpc, selinux};
use log::{debug, error, info, warn};
use nix::{sys::signal::Signal, unistd::Pid};
use rand::TryRng;

use memfd::{write_payload_into_remote_memfd, RemoteMemfdAddrs};
use payload_fd::{
    log_loader_abi, open_remote_payload_fd_from_path, send_fd_to_remote, RemoteFdHandoffAddrs,
};

use crate::sys::wait_pid;
use crate::{sys, utils};

const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;
const REMOTE_PAYLOAD_STATE_PATH: &str = "/data/adb/ommega/injector.payload";

/// The daemon cannot look at another uid's /proc entry (hidepid hides those), so it has no
/// way to tell what a socket peer process actually is. This is the list it checks against
/// instead: one "<pid> <identifier>" line per target this launcher has injected. It lives
/// next to the daemon's own state because that directory is the one the daemon can read
/// for sure; the launcher runs as root, so writing there is fine.
const DAEMON_PEER_STATE_PATH: &str = "/data/misc/keystore/ommega/rpc.peers";
// 30s so an injection racing keystore2/keymint (re)start after boot has time
// for keymint to (re)bind rpc.sock instead of timing out after 10s.
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const READY_RETRY_DELAY: Duration = Duration::from_millis(200);

#[repr(C)]
struct android_dlextinfo {
    flags: u64,
    reserved_addr: *mut c_void,
    reserved_size: usize,
    relro_fd: i32,
    library_fd: i32,
    library_fd_offset: i64,
    library_namespace: *mut c_void,
}

fn generate_remote_payload_identifier() -> Result<String> {
    let mut random = [0u8; 16];
    let mut rng = rand::rngs::SysRng;
    rng.try_fill_bytes(&mut random)
        .context("failed to fill payload identifier bytes from SysRng")?;
    Ok(format!("lib{}.so", utils::hex_encode(&random)))
}

fn finish_injection_result(result: Result<()>, cleanup_errors: Vec<anyhow::Error>) -> Result<()> {
    if cleanup_errors.is_empty() {
        return result;
    }

    for cleanup_error in &cleanup_errors {
        error!("injection cleanup failed: {cleanup_error:#}");
    }

    let cleanup_message = cleanup_errors
        .iter()
        .map(|error| format!("{error:#}"))
        .collect::<Vec<_>>()
        .join("; ");
    match result {
        Ok(()) => Err(anyhow!("injection cleanup failed: {cleanup_message}")),
        Err(error) => Err(error.context(format!(
            "injection failed and cleanup also failed: {cleanup_message}"
        ))),
    }
}

fn persist_remote_payload_state(pid: Pid, payload_identifier: &str) -> Result<()> {
    let path = Path::new(REMOTE_PAYLOAD_STATE_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create injector payload state directory {}",
                parent.display()
            )
        })?;
    }
    // 这个文件里可以有多行（daemon 那边按多行记录读），一个目标一行。写的时要保住别人的
    // 行：多个目标都往这里记，直接覆写会把 keystore2 那条顶掉，daemon 就会以为它没注过。
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let pid_field = pid.to_string();
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .next()
                .map(|field| field != pid_field)
                != Some(false)
        })
        .map(|line| line.to_string())
        .collect();
    lines.push(format!("{pid} {payload_identifier}"));
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(path, &body)
        .with_context(|| format!("failed to write injector payload state {}", path.display()))?;
    write_daemon_peer_state(&body);
    Ok(())
}

fn write_daemon_peer_state(body: &str) {
    let path = Path::new(DAEMON_PEER_STATE_PATH);
    match std::fs::write(path, body) {
        Ok(()) => debug!("refreshed the daemon peer state {}", path.display()),
        Err(error) => debug!(
            "cannot write the daemon peer state {} ({error}); an app-domain target of this \
             injection will not be accepted by the RPC server",
            path.display()
        ),
    }
}

fn wait_for_rpc_socket() -> Result<()> {
    let start = Instant::now();
    // Whether we already warned about the stat error, so a persistent
    // permission/traversal denial (e.g. SELinux on newer Android blocking the
    // keystore dir) is reported once instead of looking like "not ready yet".
    let mut warned = false;

    while start.elapsed() < READY_TIMEOUT {
        // The file socket is invisible to app-domain callers (0700 keystore dir), so
        // the abstract rendezvous point counts as ready too.
        if std::fs::metadata(rpc::SOCKET).is_ok() || crate::ipc::abstract_rpc_reachable() {
            return Ok(());
        }
        match std::fs::metadata(rpc::SOCKET) {
            Err(err) if !warned => {
                // Log the real reason (EACCES vs ENOENT etc.) so an Android-17
                // SELinux denial surfaces clearly instead of a bare timeout.
                warn!(
                    "waiting for ommega RPC socket {}: stat error: {err}; retrying until {}s",
                    rpc::SOCKET,
                    READY_TIMEOUT.as_secs()
                );
                warned = true;
            }
            _ => {}
        }
        thread::sleep(READY_RETRY_DELAY);
    }

    bail!(
        "ommega RPC endpoint did not become reachable in time (file={}, abstract={})",
        rpc::SOCKET,
        crate::ipc::abstract_rpc_reachable()
    );
}

pub fn inject_library(pid: Pid) -> Result<()> {
    wait_for_rpc_socket()?;

    let self_path = utils::current_exe_path()?;

    nix::sys::ptrace::attach(pid).with_context(|| format!("Failed to attach to process {pid}"))?;
    debug!("attached to process {}", pid);

    if let Err(e) = wait_pid(pid, Signal::SIGSTOP) {
        warn!("wait for process stop failed; detaching: {}", e);
        if let Err(detach_error) = nix::sys::ptrace::detach(pid, None)
            .with_context(|| format!("Failed to detach from process {pid} after wait failure"))
        {
            return Err(e.context(format!(
                "Failed to wait for process {pid} to stop; cleanup also failed: {detach_error:#}"
            )));
        }
        return Err(e.context(format!("Failed to wait for process {pid} to stop")));
    }

    let backup_regs = match sys::get_regs(pid).context("Failed to backup registers.") {
        Ok(regs) => regs,
        Err(error) => {
            if let Err(detach_error) = nix::sys::ptrace::detach(pid, None).with_context(|| {
                format!("Failed to detach from process {pid} after get_regs failure")
            }) {
                return Err(error.context(format!(
                    "cleanup after get_regs failure also failed: {detach_error:#}"
                )));
            }
            return Err(error);
        }
    };

    // Run actual injection; regardless of success/failure we MUST restore regs and detach
    let result = do_inject(pid, &self_path);

    // === CLEANUP: Always restore registers and detach ===
    debug!("restoring registers and detaching");
    let mut cleanup_errors = Vec::new();
    if let Err(e) = sys::set_regs(pid, &backup_regs) {
        cleanup_errors.push(e.context("Failed to restore registers"));
    }
    if let Err(e) = nix::sys::ptrace::detach(pid, None)
        .with_context(|| format!("Failed to detach from process {pid}"))
    {
        cleanup_errors.push(e);
    }

    finish_injection_result(result, cleanup_errors)
}

fn do_inject(pid: Pid, self_path: &std::path::Path) -> Result<()> {
    let payload_identifier =
        generate_remote_payload_identifier().context("failed to generate payload identifier")?;
    log_loader_abi();
    info!(
        "starting injection build_id={} pid={} payload={} self_path={}",
        crate::utils::build_id(),
        pid,
        payload_identifier,
        self_path.display(),
    );
    let mut regs = sys::get_regs(pid)?;

    let local_maps = lsplt_rs::MapInfo::scan("self");
    let remote_maps = lsplt_rs::MapInfo::scan(pid.as_raw().to_string().as_str());

    // Helper closure to resolve function address
    let resolve = |lib: &str, name: &str| -> Result<usize> {
        utils::resolve_func_addr(&local_maps, &remote_maps, lib, name)
            .or_else(|_| utils::resolve_func_addr(&local_maps, &remote_maps, "libc.so", name))
        // Fallback to libc for newer android
    };

    // Helper to push data to remote stack and update regs SP
    let mut push_to_remote_stack = |data: &[u8]| -> Result<usize> {
        let sp = {
            #[cfg(target_arch = "x86_64")]
            {
                regs.rsp as usize
            }
            #[cfg(target_arch = "x86")]
            {
                regs.esp as usize
            }
            #[cfg(target_arch = "aarch64")]
            {
                regs.sp as usize
            }
            #[cfg(target_arch = "arm")]
            {
                regs.uregs[13] as usize
            }
        };
        let tentative_sp = sp
            .checked_sub(data.len())
            .context("stack underflow while reserving remote storage")?;
        let new_sp = tentative_sp & !0xf;
        let write_base = new_sp
            .checked_add(data.len())
            .context("aligned remote stack write overflow")?;
        // Keep the remote scratch allocations 16-byte aligned like the reference
        // injector. Ancillary socket control buffers are sensitive to layout.
        let new_sp = sys::push_stack(pid, write_base, data)?;

        // Update local regs copy
        #[cfg(target_arch = "x86_64")]
        {
            regs.rsp = new_sp as u64;
        }
        #[cfg(target_arch = "x86")]
        {
            regs.esp = new_sp as u32;
        }
        #[cfg(target_arch = "aarch64")]
        {
            regs.sp = new_sp as u64;
        }
        #[cfg(target_arch = "arm")]
        {
            regs.uregs[13] = new_sp as u32;
        }

        // Commit SP change to remote process so subsequent remote_call works correctly
        sys::set_regs(pid, &regs)?;
        debug!(
            "remote scratch push: size={} old_sp=0x{:x} new_sp=0x{:x} align={}",
            data.len(),
            sp,
            new_sp,
            new_sp % 16
        );
        Ok(new_sp)
    };

    let libc_return_addr = utils::resolve_return_addr(&remote_maps, "libc.so")?;
    debug!("resolved libc return address=0x{:x}", libc_return_addr);

    let close_addr = resolve("libc.so", "close")?;
    let open_addr = resolve("libc.so", "open").or_else(|_| resolve("libc.so", "open64"))?;
    let socket_addr = resolve("libc.so", "socket")?;
    let setsockopt_addr = resolve("libc.so", "setsockopt")?;
    let bind_addr = resolve("libc.so", "bind")?;
    let recvmsg_addr = resolve("libc.so", "recvmsg")?;
    let errno_addr = resolve("libc.so", "__errno").ok();
    let strlen_addr = resolve("libc.so", "strlen").ok();
    let dlopen_addr = resolve("libdl.so", "android_dlopen_ext")?;
    let dlsym_addr = resolve("libdl.so", "dlsym")?;
    let dlerror_addr = resolve("libdl.so", "dlerror").ok();

    let read_remote_dlerror = || -> Result<Option<String>> {
        if let (Some(err_fn), Some(str_fn)) = (dlerror_addr, strlen_addr) {
            let err_ptr = sys::remote_call(pid, err_fn, libc_return_addr, &[])?;
            if err_ptr == 0 {
                return Ok(None);
            }

            let len = sys::remote_call(pid, str_fn, libc_return_addr, &[err_ptr])?;
            if len == 0 || len > 1024 {
                return Ok(Some(format!(
                    "remote dlerror pointer=0x{err_ptr:x} returned invalid length {len}"
                )));
            }

            let mut err_buf = vec![0u8; len];
            sys::read_stack(pid, err_ptr, &mut err_buf)?;
            return Ok(Some(String::from_utf8_lossy(&err_buf).into_owned()));
        }

        Ok(None)
    };

    let get_remote_errno = || -> Result<i32> {
        if let Some(addr) = errno_addr {
            let ptr = sys::remote_call(pid, addr, libc_return_addr, &[])?;
            let mut buf = [0u8; 4];
            sys::read_stack(pid, ptr, &mut buf)?;
            Ok(i32::from_ne_bytes(buf))
        } else {
            Ok(0)
        }
    };

    let close_remote = |fd: i32| -> Result<()> {
        let close_res = sys::remote_call(pid, close_addr, libc_return_addr, &[fd as usize])?;
        if close_res != 0 {
            let err = get_remote_errno().unwrap_or(0);
            bail!(
                "Remote close failed for fd {}: result={} errno={}",
                fd,
                close_res,
                err
            );
        }
        Ok(())
    };

    let local_lib_file = std::fs::File::open(self_path).with_context(|| {
        format!(
            "Failed to open deployed payload image {}",
            self_path.display()
        )
    })?;
    let local_lib_fd = local_lib_file.as_raw_fd();
    info!(
        "local payload file ready: fd={} path={} identifier={} sha256={}",
        local_lib_fd,
        self_path.display(),
        payload_identifier,
        utils::sha256_file(self_path).unwrap_or_else(|_| "<unavailable>".to_string())
    );
    if let Err(error) = selinux::set_sockcreate_con("u:object_r:system_file:s0") {
        warn!("sockcreate context setup failed: {error:#}");
    }

    let fd_handoff_addrs = RemoteFdHandoffAddrs {
        socket: socket_addr,
        bind: bind_addr,
        recvmsg: recvmsg_addr,
        setsockopt: setsockopt_addr,
        libc_return: libc_return_addr,
    };

    // memfd 那条路要的三个 libc 符号。缺一个就不走这条路（老机器上 memfd_create 可能
    // 根本不存在），而不是把整个注入判失败 —— 还有递 fd 和直接开文件两条回落。
    let memfd_addrs = match (
        resolve("libc.so", "memfd_create"),
        resolve("libc.so", "write"),
        resolve("libc.so", "lseek").or_else(|_| resolve("libc.so", "lseek64")),
    ) {
        (Ok(memfd_create), Ok(write), Ok(lseek)) => Some(RemoteMemfdAddrs {
            memfd_create,
            write,
            lseek,
            libc_return: libc_return_addr,
        }),
        _ => {
            warn!("memfd payload transfer unavailable: memfd_create/write/lseek not resolvable in the target");
            None
        }
    };

    // payload 镜像统一走 memfd：在目标进程里现开一块内存文件、分块写完再 dlopen 它。
    // 这条对 keystore2 和 SOTER 宿主一样有效，也不碰文件系统。以前是先跨进程递 fd
    // （只有 keystore2 那条验过）、memfd 只当兜底，两个目标各走一条路；现在从 memfd
    // 起手，递 fd 和直接开文件只留作老内核 / 权限受限时的回落，行为一致。
    let remote_lib_fd = 'handoff: {
        let memfd_note = match memfd_addrs {
            Some(addrs) => match write_payload_into_remote_memfd(
                pid,
                &payload_identifier,
                self_path,
                addrs,
                &mut push_to_remote_stack,
                &get_remote_errno,
                &close_remote,
            ) {
                Ok(fd) => break 'handoff fd,
                Err(error) => format!("memfd payload transfer failed: {error:#}"),
            },
            None => "memfd payload transfer unavailable: memfd_create/write/lseek not resolvable in the target".to_string(),
        };

        match send_fd_to_remote(
            pid,
            local_lib_fd,
            "payload image",
            fd_handoff_addrs,
            &mut push_to_remote_stack,
            &get_remote_errno,
            &close_remote,
        ) {
            Ok(fd) => break 'handoff fd,
            Err(socket_error) => {
                warn!(
                    "{memfd_note}; payload fd handoff also failed: {socket_error:#}. Trying direct fallback via {}.",
                    self_path.display()
                );
                open_remote_payload_fd_from_path(
                    pid,
                    open_addr,
                    libc_return_addr,
                    self_path,
                    &mut push_to_remote_stack,
                    &get_remote_errno,
                )
                .with_context(|| {
                    format!(
                        "failed to move the payload into the target process: {memfd_note}; fd handoff: {socket_error:#}; couldn't reopen {} directly either",
                        self_path.display()
                    )
                })?
            }
        }
    };

    let dlext_info = android_dlextinfo {
        flags: ANDROID_DLEXT_USE_LIBRARY_FD,
        reserved_addr: std::ptr::null_mut(),
        reserved_size: 0,
        relro_fd: -1,
        library_fd: remote_lib_fd,
        library_fd_offset: 0,
        library_namespace: std::ptr::null_mut(),
    };
    let info_bytes = unsafe {
        std::slice::from_raw_parts(
            &dlext_info as *const _ as *const u8,
            std::mem::size_of::<android_dlextinfo>(),
        )
    };
    let remote_info_ptr = push_to_remote_stack(info_bytes)?;

    let remote_loader_path_c = CString::new(payload_identifier.as_str())?;
    let remote_path_ptr = push_to_remote_stack(remote_loader_path_c.as_bytes_with_nul())?;

    // Register the pid before the payload runs: the daemon authorizes an app-domain client by
    // matching the pid SO_PEERCRED reports against this list, and the payload starts talking
    // to the RPC server from inside `entry`. Writing this after the call would be too late for
    // the first (and on a target that never retries, the only) connection attempt.
    if let Err(error) = persist_remote_payload_state(pid, &payload_identifier) {
        warn!(
            "failed to persist payload identifier state for pid {}: {:#}",
            pid, error
        );
    }

    // Call dlopen
    // args: filename, flags (RTLD_NOW=2), extinfo
    let handle = sys::remote_call(
        pid,
        dlopen_addr,
        libc_return_addr,
        &[remote_path_ptr, libc::RTLD_NOW as usize, remote_info_ptr],
    )?;

    debug!(
        "Remote dlopen handle: 0x{:x} using identifier={} fd={}",
        handle, payload_identifier, remote_lib_fd
    );

    if handle == 0 {
        if let Some(error_message) = read_remote_dlerror()? {
            error!("android_dlopen_ext failed: {}", error_message);
        }
        close_remote(remote_lib_fd)?;
        bail!("Remote dlopen failed");
    }

    close_remote(remote_lib_fd)?;

    if let Some(err_fn) = dlerror_addr {
        let _ = sys::remote_call(pid, err_fn, libc_return_addr, &[]);
    }
    let entry_symbol = std::ffi::CString::new("entry")?;
    let remote_entry_symbol_ptr = push_to_remote_stack(entry_symbol.as_bytes_with_nul())?;
    let injector_entry = sys::remote_call(
        pid,
        dlsym_addr,
        libc_return_addr,
        &[handle, remote_entry_symbol_ptr],
    )?;
    if injector_entry == 0 {
        if let Some(error_message) = read_remote_dlerror()? {
            error!("dlsym(entry) failed: {}", error_message);
        }
        bail!("Failed to find 'entry' symbol in injected image");
    }
    debug!(
        "resolved remote entry via dlsym address=0x{:x}",
        injector_entry
    );

    let entry_result = sys::remote_call(pid, injector_entry, libc_return_addr, &[handle])?;
    if entry_result == 0 {
        bail!("Remote entry returned false");
    }

    info!("remote entry returned successfully");
    Ok(())
}
