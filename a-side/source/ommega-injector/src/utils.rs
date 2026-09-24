use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::CString,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use log::debug;
use lsplt_rs::MapInfo;
use sha2::{Digest, Sha256};

const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;
const EM_386: u16 = 3;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

#[derive(Debug, Clone)]
pub struct ExecutableIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub elf: String,
}

pub fn build_id() -> &'static str {
    env!("INJECTOR_BUILD_ID")
}

pub fn build_target() -> &'static str {
    env!("INJECTOR_BUILD_TARGET")
}

pub fn build_git_sha() -> &'static str {
    env!("INJECTOR_BUILD_GIT_SHA")
}

pub fn current_exe_path() -> Result<PathBuf> {
    std::fs::read_link("/proc/self/exe").context("Failed to read link /proc/self/exe")
}

/// Locates the module root dir for a binary installed under
/// `/data/adb/modules/<id>/` (the binary lives in `libs/<abi>/`).
fn module_root_from_exe() -> Option<PathBuf> {
    let exe = current_exe_path().ok()?;
    // Look for the `/data/adb/modules/<id>` ancestor and stop there.  Works for
    // both `libs/<abi>/<bin>` and `<module>/<bin>` layouts.
    let mut dir = exe.parent()?;
    loop {
        let name = dir.file_name()?.to_str()?.to_string();
        if dir.parent().is_some_and(|p| p.ends_with("modules")) && name != "modules" {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

/// Best-effort update of the module.prop description so the KernelSU/Magisk
/// card reflects the actual injected state.  The module dir is derived from the
/// running binary's own path, so this works regardless of module id.
///
/// The write goes through [`write_atomic`] on purpose: `service.sh` kills stale
/// module processes with `kill -9` before every start, and a plain `fs::write`
/// (truncate, then write) landing in that window leaves an empty `module.prop` —
/// the manager card would then show neither name nor version.
pub fn update_module_status(status: &str) {
    let Some(module_root) = module_root_from_exe() else {
        return;
    };
    let prop_file = module_root.join("module.prop");
    let Ok(contents) = std::fs::read_to_string(&prop_file) else {
        return;
    };
    let mut out = String::new();
    let mut changed = false;
    for line in contents.lines() {
        if line.starts_with("description=") {
            out.push_str("description=");
            out.push_str(status);
            out.push('\n');
            changed = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if changed {
        let _ = write_atomic(&prop_file, out.as_bytes());
    }
}

/// Same-directory temp file, `fsync`, then `rename`: readers (and a `kill -9`
/// at the wrong moment) see either the old file or the new one, never a
/// half-written or empty one.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".module.prop.tmp.{}", std::process::id()));
    let written = File::create(&tmp).and_then(|mut file| {
        file.write_all(data)?;
        file.sync_all()
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return written;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn current_exe_identity() -> Result<ExecutableIdentity> {
    executable_identity(&current_exe_path()?)
}

pub fn executable_identity(path: &Path) -> Result<ExecutableIdentity> {
    Ok(ExecutableIdentity {
        path: path.to_path_buf(),
        sha256: sha256_file(path)?,
        elf: describe_elf(path)?,
    })
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open {} for hashing", path.display()))?;
    let mut sha256 = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("Failed to read {} for hashing", path.display()))?;
        if read == 0 {
            break;
        }
        sha256.update(&buffer[..read]);
    }

    Ok(hex_encode(&sha256.finalize()))
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub fn describe_elf(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("Failed to open ELF {}", path.display()))?;
    let mut header = [0u8; 20];
    file.read_exact(&mut header)
        .with_context(|| format!("Failed to read ELF header from {}", path.display()))?;

    if header[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(anyhow!("{} is not an ELF file", path.display()));
    }

    let class = match header[4] {
        ELF_CLASS_32 => "ELF32",
        ELF_CLASS_64 => "ELF64",
        other => return Err(anyhow!("unsupported ELF class {}", other)),
    };

    let machine = u16::from_le_bytes([header[18], header[19]]);
    let arch = match machine {
        EM_386 => "x86",
        EM_ARM => "arm",
        EM_X86_64 => "x86_64",
        EM_AARCH64 => "aarch64",
        _ => "unknown",
    };

    Ok(format!("{class} {arch} (e_machine={machine})"))
}

// Hook stuff
pub fn resolve_base_addr(info: &[MapInfo], lib_name: &str) -> Result<usize> {
    for map in info {
        if let Some(path) = &map.pathname {
            if map.offset == 0 && path.as_str().ends_with(lib_name) {
                debug!(
                    "Found library '{}' at base address: 0x{:x}",
                    lib_name, map.start
                );
                return Ok(map.start);
            }
        }
    }
    Err(anyhow!("Library '{}' not found in process maps", lib_name))
}

pub fn resolve_return_addr(info: &[MapInfo], lib_name: &str) -> Result<usize> {
    for map in info {
        if let Some(path) = &map.pathname {
            if (map.perms & libc::PROT_EXEC as u8) == 0 && path.as_str().ends_with(lib_name) {
                // Use map.start directly (not + offset). This is a non-executable
                // region that will cause SIGSEGV when the remote function "returns"
                // here, allowing us to catch the return value.
                debug!(
                    "Found return addr in library '{}' at address: 0x{:x}",
                    lib_name, map.start
                );
                return Ok(map.start);
            }
        }
    }
    Err(anyhow!("Not found in library '{}'", lib_name))
}

pub fn resolve_func_addr(
    local: &[MapInfo],
    remote: &[MapInfo],
    lib_name: &str,
    name: &str,
) -> Result<usize> {
    let lib_name_c = CString::new(lib_name).map_err(|_| anyhow!("Invalid library name"))?;
    let name_c = CString::new(name).map_err(|_| anyhow!("Invalid function name"))?;
    let lib = unsafe { libc::dlopen(lib_name_c.as_ptr(), libc::RTLD_NOW) };
    if lib.is_null() {
        return Err(anyhow!(
            "Failed to open library '{}': {}",
            lib_name,
            std::io::Error::last_os_error()
        ));
    }

    let symbol = unsafe { libc::dlsym(lib, name_c.as_ptr()) };
    let symbol_error = symbol.is_null().then(std::io::Error::last_os_error);
    unsafe {
        libc::dlclose(lib);
    }
    if let Some(error) = symbol_error {
        return Err(anyhow!(
            "Failed to find symbol '{}' in library '{}': {}",
            name,
            lib_name,
            error
        ));
    }

    let local_addr = resolve_base_addr(local, lib_name)
        .with_context(|| format!("failed to find local base for module {}", lib_name))?;
    let remote_addr = resolve_base_addr(remote, lib_name)
        .with_context(|| format!("failed to find remote base for module {}", lib_name))?;

    let offset = (symbol as usize)
        .checked_sub(local_addr)
        .ok_or_else(|| anyhow!("Invalid symbol address"))?;
    let remote_func_addr = remote_addr
        .checked_add(offset)
        .ok_or_else(|| anyhow!("Address overflow"))?;

    debug!(
        "Resolved function '{}' address: 0x{:x}",
        name, remote_func_addr
    );
    Ok(remote_func_addr)
}

pub fn find_process_by_name(target_name: &str) -> Result<(i32, PathBuf)> {
    for entry in std::fs::read_dir("/proc")?.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }

        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|name| name.parse::<i32>().ok()) else {
            continue;
        };
        let path = entry.path();

        if process_name(pid).as_deref() != Some(target_name) {
            continue;
        }

        let target = std::fs::read_link(path.join("exe"))
            .unwrap_or_else(|_| PathBuf::from(format!("/proc/{pid}/exe")));
        debug!("found target executable path={:?} pid={}", target, pid);

        return Ok((pid, target));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("Process '{}' not found", target_name),
    ))
    .context("")
}

pub fn process_name(pid: i32) -> Option<String> {
    let path = PathBuf::from(format!("/proc/{pid}"));
    std::fs::read(path.join("cmdline"))
        .ok()
        .and_then(|cmdline| {
            let first = cmdline
                .split(|byte| *byte == 0)
                .find(|part| !part.is_empty())?;
            Path::new(std::ffi::OsStr::from_bytes(first))
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(str::to_owned)
        })
        .or_else(|| {
            std::fs::read_to_string(path.join("comm"))
                .ok()
                .map(|name| name.trim().to_owned())
        })
}
