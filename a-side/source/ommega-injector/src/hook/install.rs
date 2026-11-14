use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};

use anyhow::{anyhow, bail, Result};
use log::{debug, info};

use super::{
    intercept, new_close, new_dup, new_dup2, new_dup3, new_fcntl, new_fdsan_close, new_ioctl,
    rewrite, HOOK_INIT, OLD_CLOSE, OLD_DUP, OLD_DUP2, OLD_DUP3, OLD_FCNTL, OLD_FDSAN_CLOSE,
    OLD_IOCTL,
};
use crate::{config, ipc};

pub(super) fn init_hook() -> Result<()> {
    let result = HOOK_INIT.get_or_init(|| install_hooks().map_err(|error| format!("{error:#}")));
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(anyhow!(error.clone())),
    }
}

/// soterserver（system_ext 的 platform_app）里 libbinder 的 GOT/RELRO 那一段是 `---p`，
/// lsplt 的 ScanHookInfo 只收 private 且可读的映射，commit 时找不到承载 GOT 的那块就
/// 整片失败，宿主直接 SIGABRT。这里在 commit 之前把 libbinder* / libhidlbase 的 `---p`
/// 段放开成只读，让它能被 lsplt 认领。
fn unlock_binder_relro() {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return;
    };
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else { continue };
        let Some(perms) = fields.next() else { continue };
        if perms != "---p" || !(line.contains("libbinder") || line.contains("libhidlbase")) {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
        ) else {
            continue;
        };
        if end <= start {
            continue;
        }
        let rc =
            unsafe { libc::mprotect(start as *mut libc::c_void, end - start, libc::PROT_READ) };
        info!(
            "binder relro {range} -> {} rc={rc}",
            if rc == 0 {
                "readable"
            } else {
                "mprotect failed"
            }
        );
    }
}

fn install_hooks() -> Result<()> {
    fn register_hooks(
        libraries: &[(String, lsplt_rs::DeviceId, lsplt_rs::Inode)],
        symbols: &'static [&'static str],
        replacement: *mut c_void,
        label: &str,
    ) -> Result<Vec<*mut c_void>> {
        let mut backups = vec![std::ptr::null_mut(); libraries.len() * symbols.len()];
        for ((path, dev, inode), backups) in libraries.iter().zip(backups.chunks_mut(symbols.len()))
        {
            for (symbol, backup) in symbols.iter().zip(backups) {
                lsplt_rs::register_hook(*dev, *inode, symbol, replacement, Some(backup)).map_err(
                    |error| {
                        anyhow!(
                            "failed to register binder {label} hook path={path} symbol={symbol}: {error}"
                        )
                    },
                )?;
                debug!("registered binder {label} hook path={path} symbol={symbol}");
            }
        }
        Ok(backups)
    }

    fn store_original(backups: &[*mut c_void], original: &AtomicPtr<c_void>) {
        if let Some(&ptr) = backups.iter().find(|ptr| !ptr.is_null()) {
            let _ = original.compare_exchange(
                std::ptr::null_mut(),
                ptr,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
        }
    }

    let _ = config::get();
    info!("initializing binder ioctl hook");
    ipc::ensure_process_state();

    let mut libraries = Vec::new();
    let mut seen = HashSet::new();

    for map in lsplt_rs::MapInfo::scan("self") {
        if let Some(path) = &map.pathname {
            let name = path.rsplit('/').next().unwrap_or(path);
            // HIDL 那套的 ipc 实现不在 libbinder 里：Android 13+ 的 `libhwbinder.so`
            // 只是个 10KB 的空壳，真正调 ioctl 的是 `libhidlbase.so`（只 hook libbinder 时，
            // cryptoeng 发往 HIDL soter 的事务一条都看不到）。
            if (name.starts_with("libbinder")
                || name == "libhwbinder.so"
                || name == "libhidlbase.so")
                && seen.insert((map.dev, map.inode))
            {
                debug!(
                    "Found binder library for ioctl hook: {} (dev={}, inode={})",
                    path, map.dev, map.inode
                );
                libraries.push((path.clone(), map.dev, map.inode));
            }
        }
    }

    if libraries.is_empty() {
        bail!("Could not find binder libraries in process maps");
    }

    let ioctl_backups = register_hooks(
        &libraries,
        &["ioctl", "__ioctl"],
        new_ioctl as *mut c_void,
        "ioctl",
    )?;
    let close_backups = register_hooks(
        &libraries,
        &["close", "__close"],
        new_close as *mut c_void,
        "close",
    )?;
    let dup_backups = register_hooks(
        &libraries,
        &["dup"],
        new_dup as *mut c_void,
        "fd duplication",
    )?;
    let fdsan_backups = register_hooks(
        &libraries,
        &["android_fdsan_close_with_tag"],
        new_fdsan_close as *mut c_void,
        "close",
    )?;
    let dup2_backups = register_hooks(
        &libraries,
        &["dup2"],
        new_dup2 as *mut c_void,
        "fd replacement",
    )?;
    let dup3_backups = register_hooks(
        &libraries,
        &["dup3"],
        new_dup3 as *mut c_void,
        "fd replacement",
    )?;
    let fcntl_backups = register_hooks(
        &libraries,
        &["fcntl"],
        new_fcntl as *mut c_void,
        "fd duplication",
    )?;

    unlock_binder_relro();
    let commit_result = lsplt_rs::commit_hook();
    info!("lsplt commit_hook -> {:?}", commit_result);
    for (label, symbols, backups) in [
        ("ioctl", &["ioctl", "__ioctl"][..], &ioctl_backups),
        ("close", &["close", "__close"][..], &close_backups),
        ("dup", &["dup"][..], &dup_backups),
        (
            "fdsan",
            &["android_fdsan_close_with_tag"][..],
            &fdsan_backups,
        ),
        ("dup2", &["dup2"][..], &dup2_backups),
        ("dup3", &["dup3"][..], &dup3_backups),
        ("fcntl", &["fcntl"][..], &fcntl_backups),
    ] {
        for (index, backup) in backups.iter().enumerate() {
            let lib = libraries
                .get(index / symbols.len())
                .map(|entry| entry.0.as_str())
                .unwrap_or("?");
            let sym = symbols.get(index % symbols.len()).copied().unwrap_or("?");
            info!(
                "lsplt backup {label} {lib} {sym} -> {} ({backup:p})",
                if backup.is_null() { "null" } else { "hooked" }
            );
        }
    }
    if let Err(error) = &commit_result {
        log::warn!(
            "binder hook not installed in this process ({error:?}); continuing without interception"
        );
    }
    let ioctl_committed = ioctl_backups.iter().filter(|ptr| !ptr.is_null()).count();
    let close_committed = close_backups
        .iter()
        .chain(fdsan_backups.iter())
        .filter(|ptr| !ptr.is_null())
        .count();
    store_original(&ioctl_backups, &OLD_IOCTL);
    store_original(&close_backups, &OLD_CLOSE);
    store_original(&fdsan_backups, &OLD_FDSAN_CLOSE);
    store_original(&dup_backups, &OLD_DUP);
    store_original(&dup2_backups, &OLD_DUP2);
    store_original(&dup3_backups, &OLD_DUP3);
    store_original(&fcntl_backups, &OLD_FCNTL);
    if ioctl_committed == 0 {
        // 不能 panic：payload 进的是别人的进程（SOTER 宿主、HAL），一个 hook 装不上
        // 只该少一路拦截，不该把宿主整个 abort 掉（一加 PKG110 上就是这么每 17 秒
        // 崩一次 soterserver 的）。这里降级返回，后续走透传。
        log::warn!(
            "no binder ioctl hook was committed in this process; running without interception"
        );
        return Ok(());
    }
    if close_committed == 0 {
        log::warn!("no binder close hook was committed in this process; fd tracking is disabled");
    }
    intercept::start_operation_publication_worker().map_err(|error| anyhow!(error))?;
    rewrite::start_mirror_recovery_worker().map_err(|error| anyhow!(error))?;
    info!(
        "committed {} binder ioctl hook(s) and {} close hook(s)",
        ioctl_committed, close_committed
    );
    Ok(())
}
