//! Unified persistent property API for Android.
//!
//! Automatically detects the storage format (protobuf vs. legacy per-file) and
//! routes operations accordingly.  Also handles SELinux label preservation when
//! writing files.

use std::ffi::CString;
use std::os::raw::c_char;
use std::path::Path;

use prop_rs::{
    check_proto, legacy_delete_prop, legacy_set_prop, PersistentPropertyFile, PersistentResult,
    ANDROID_PERSISTENT_PROP_DIR, ANDROID_PERSISTENT_PROP_FILE,
};

// ── SELinux extended attribute helpers ───────────────────────────────────────

const XATTR_SELINUX: &[u8] = b"security.selinux\0";

/// Read the SELinux label of a file.
fn get_selinux_label(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = vec![0u8; 256];
    let ret = unsafe {
        libc::lgetxattr(
            c_path.as_ptr(),
            XATTR_SELINUX.as_ptr() as *const c_char,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if ret > 0 {
        buf.truncate(ret as usize);
        Some(buf)
    } else {
        None
    }
}

/// Set the SELinux label of a file.
fn set_selinux_label(path: &Path, label: &[u8]) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
        unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                XATTR_SELINUX.as_ptr() as *const c_char,
                label.as_ptr() as *const libc::c_void,
                label.len(),
                0,
            );
        }
    }
}

// ── Unified persist API ─────────────────────────────────────────────────────

/// Set a persistent property, auto-detecting the storage format.
///
/// If the protobuf file exists, uses protobuf format.  Otherwise falls back to
/// the legacy per-file format.  SELinux labels are preserved on the protobuf
/// file.
pub fn persist_set_prop(key: &str, value: &str) -> PersistentResult<()> {
    let dir = Path::new(ANDROID_PERSISTENT_PROP_DIR);
    if check_proto(dir) {
        let path = Path::new(ANDROID_PERSISTENT_PROP_FILE);
        let original_label = get_selinux_label(path);

        let mut props = PersistentPropertyFile::load_or_default(path)?;
        props.set(key, value);
        props.write_to_path(path)?;

        if let Some(label) = original_label {
            set_selinux_label(path, &label);
        }
        Ok(())
    } else {
        legacy_set_prop(dir, key, value)
    }
}

/// Delete a persistent property, auto-detecting the storage format.
pub fn persist_delete_prop(key: &str) -> PersistentResult<()> {
    let dir = Path::new(ANDROID_PERSISTENT_PROP_DIR);
    if check_proto(dir) {
        let path = Path::new(ANDROID_PERSISTENT_PROP_FILE);
        let original_label = get_selinux_label(path);

        let mut props = PersistentPropertyFile::load_or_default(path)?;
        props.delete(key);
        props.write_to_path(path)?;

        if let Some(label) = original_label {
            set_selinux_label(path, &label);
        }
        Ok(())
    } else {
        legacy_delete_prop(dir, key)?;
        Ok(())
    }
}

/// Get all persistent properties, auto-detecting the storage format.
///
/// Returns them as `(name, value)` pairs, sorted by name.
pub fn persist_get_all_props() -> PersistentResult<Vec<(String, String)>> {
    let dir = Path::new(ANDROID_PERSISTENT_PROP_DIR);
    if check_proto(dir) {
        let path = Path::new(ANDROID_PERSISTENT_PROP_FILE);
        let props = PersistentPropertyFile::load_or_default(path)?;
        Ok(props
            .iter()
            .map(|p| (p.name.clone(), p.value.clone()))
            .collect())
    } else {
        let props = prop_rs::legacy_list_props(dir)?;
        Ok(props.into_iter().map(|p| (p.name, p.value)).collect())
    }
}

/// Get a persistent property, auto-detecting the storage format.
pub fn persist_get_prop(key: &str) -> PersistentResult<Option<String>> {
    let dir = Path::new(ANDROID_PERSISTENT_PROP_DIR);
    if check_proto(dir) {
        let path = Path::new(ANDROID_PERSISTENT_PROP_FILE);
        let props = PersistentPropertyFile::load_or_default(path)?;
        Ok(props.get(key).map(String::from))
    } else {
        prop_rs::legacy_get_prop(dir, key)
    }
}
