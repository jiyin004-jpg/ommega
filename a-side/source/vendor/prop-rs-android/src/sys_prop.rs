//! Bionic `__system_property_*` API wrapper via `dlsym` + mmap.
//!
//! This module dynamically loads Android bionic's **standard** system property
//! functions at runtime and exposes a safe Rust API.  For operations that
//! stock bionic does not support (add, update, delete, get_context), we use
//! [`crate::mmap_prop_area::MmapPropArea`] which operates directly on the
//! `MAP_SHARED` mmap files under `/dev/__properties__` with the exact atomic
//! memory-ordering semantics required by bionic's concurrent readers.
//!
//! This replaces Magisk's approach of linking against a patched bionic with
//! `__system_property_*2` symbols, making the code work on KernelSU without
//! any bionic modifications.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Cursor;
use std::io::{self};
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use memmap2::MmapOptions;
use prop_rs::{PropArea, PropAreaHoleInfo, PropertyContext, PROP_VALUE_MAX};

use crate::mmap_prop_area::{
    MmapPropArea, MmapPropAreaError, ValueSlotInspect as MmapValueSlotInspect,
};

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum SysPropError {
    /// A required bionic symbol was not found via dlsym.
    SymbolNotFound(&'static str),
    /// `__system_properties_init` returned a non-zero error code.
    InitFailed(c_int),
    /// `__system_property_set` returned a non-zero error code.
    SetFailed(c_int),
    /// A mmap prop-area operation failed.
    MmapPropArea(MmapPropAreaError),
    /// An I/O error occurred during mmap operations.
    Io(io::Error),
    /// The property key or value contains an interior NUL byte.
    InvalidCString(String),
    /// The property value is too long for a mutable system property.
    ValueTooLong {
        key: String,
        len: usize,
        max_len: usize,
    },
    /// A persistent-property I/O operation failed.
    Persistent(prop_rs::PersistentPropError),
}

impl fmt::Display for SysPropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SymbolNotFound(sym) => write!(f, "bionic symbol not found: {sym}"),
            Self::InitFailed(code) => write!(f, "__system_properties_init failed: {code}"),
            Self::SetFailed(code) => write!(f, "__system_property_set failed: {code}"),
            Self::MmapPropArea(e) => write!(f, "mmap prop area error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidCString(s) => write!(f, "invalid C string: {s}"),
            Self::ValueTooLong { key, len, max_len } => {
                write!(
                    f,
                    "property value too long for mutable property {key}: {len} >= {max_len}"
                )
            }
            Self::Persistent(e) => write!(f, "persistent property error: {e}"),
        }
    }
}

impl std::error::Error for SysPropError {}

impl From<prop_rs::PersistentPropError> for SysPropError {
    fn from(e: prop_rs::PersistentPropError) -> Self {
        Self::Persistent(e)
    }
}

impl From<MmapPropAreaError> for SysPropError {
    fn from(e: MmapPropAreaError) -> Self {
        Self::MmapPropArea(e)
    }
}

impl From<io::Error> for SysPropError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub type SysPropResult<T> = std::result::Result<T, SysPropError>;

#[derive(Debug, Clone)]
pub struct PropAreaValueInspect {
    pub context: String,
    pub path: PathBuf,
    pub is_long: bool,
    pub value_len: usize,
    pub tail_size: usize,
    pub tail_nonzero: usize,
}

#[derive(Debug, Clone)]
pub struct PropAreaScanReport {
    pub context: String,
    pub path: PathBuf,
    pub bytes_used: u32,
    pub has_dirty_backup: bool,
    pub object_count: usize,
    pub hole_count: usize,
    pub holes: Vec<PropAreaHoleInfo>,
}

// ── Opaque prop_info pointer ────────────────────────────────────────────────

/// Opaque handle to a bionic `prop_info` structure in shared memory.
#[derive(Debug, Clone, Copy)]
pub struct PropInfoPtr(*const c_void);

// Safety: prop_info lives in MAP_SHARED memory and is safe to access from any
// thread (bionic uses atomics for the serial protocol).
unsafe impl Send for PropInfoPtr {}
unsafe impl Sync for PropInfoPtr {}

impl PropInfoPtr {
    fn as_ptr(self) -> *const c_void {
        self.0
    }
}

// ── Function-pointer type aliases ───────────────────────────────────────────

type FnInit = unsafe extern "C" fn() -> c_int;
type FnFind = unsafe extern "C" fn(*const c_char) -> *const c_void;
type FnReadCallback = unsafe extern "C" fn(
    *const c_void, // pi
    Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, u32)>,
    *mut c_void, // cookie
);
type FnForEach =
    unsafe extern "C" fn(Option<unsafe extern "C" fn(*const c_void, *mut c_void)>, *mut c_void);
type FnSet = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
type FnSerial = unsafe extern "C" fn(*const c_void) -> u32;
type FnAreaSerial = unsafe extern "C" fn() -> u32;
type FnWait = unsafe extern "C" fn(
    *const c_void,         // pi (null = global)
    u32,                   // old serial
    *mut u32,              // new serial out
    *const libc::timespec, // timeout (null = infinite)
) -> bool;

// ── Loaded API singleton ────────────────────────────────────────────────────

struct BionicApi {
    // Standard bionic symbols (available on all Android versions)
    find: FnFind,
    read_callback: FnReadCallback,
    for_each: FnForEach,
    set: FnSet,
    serial: FnSerial,
    // Optional standard symbols (API 26+)
    area_serial: Option<FnAreaSerial>,
    wait: Option<FnWait>,
}

static API: OnceLock<BionicApi> = OnceLock::new();

fn load_sym<T>(name: &str) -> Option<T> {
    let cname = CString::new(name).ok()?;
    let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr()) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute_copy(&ptr) })
    }
}

fn load_sym_required<T>(name: &'static str) -> SysPropResult<T> {
    load_sym(name).ok_or(SysPropError::SymbolNotFound(name))
}

fn api() -> &'static BionicApi {
    API.get().expect("sys_prop::init() must be called first")
}

// ── MmapPropArea cache ──────────────────────────────────────────────────────

// ── PropertyContext singletons ───────────────────────────────────────────────

static PROP_CTX: OnceLock<CachedPropertyContext> = OnceLock::new();

/// Appcompat override context for Android 14+ dual-write support.
/// `None` when the appcompat_override directory does not exist.
static APPCOMPAT_CTX: OnceLock<Option<CachedPropertyContext>> = OnceLock::new();

/// Per-PropertyContext cache wrapper that opens prop area files as
/// `MAP_SHARED` mmap regions and wraps them in `MmapPropArea`.
///
/// Areas are cached lazily: first access mmaps and stores; later accesses reuse
/// the mapped region so writes do not remap every time.
struct CachedPropertyContext {
    ctx: PropertyContext,
    area_cache: Mutex<HashMap<String, MmapPropArea>>,
    serial_area: Mutex<Option<MmapPropArea>>,
}

impl CachedPropertyContext {
    fn new(ctx: PropertyContext) -> Self {
        Self {
            ctx,
            area_cache: Mutex::new(HashMap::new()),
            serial_area: Mutex::new(None),
        }
    }

    fn get_context_for_name(&self, name: &str) -> &str {
        self.ctx.get_context_for_name(name)
    }

    fn map_context_area(&self, context: &str) -> SysPropResult<MmapPropArea> {
        let path = self.ctx.context_file_path(context);
        let f = OpenOptions::new().read(true).write(true).open(&path)?;
        let map = unsafe { MmapOptions::new().map_mut(&f) }?;
        Ok(MmapPropArea::new(map)?)
    }

    fn map_serial_area(&self) -> SysPropResult<MmapPropArea> {
        let path = self.ctx.serial_prop_area_path();
        let f = OpenOptions::new().read(true).write(true).open(&path)?;
        let map = unsafe { MmapOptions::new().map_mut(&f) }?;
        Ok(MmapPropArea::new(map)?)
    }

    fn with_area_rw<T>(
        &self,
        context: &str,
        f: impl FnOnce(&mut MmapPropArea) -> SysPropResult<T>,
    ) -> SysPropResult<T> {
        let mut cache = self.area_cache.lock().map_err(|_| {
            SysPropError::Io(io::Error::new(
                io::ErrorKind::Other,
                "area cache mutex poisoned",
            ))
        })?;

        if !cache.contains_key(context) {
            let area = self.map_context_area(context)?;
            cache.insert(context.to_owned(), area);
        }

        let area = cache.get_mut(context).ok_or_else(|| {
            SysPropError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("prop area not found for context: {context}"),
            ))
        })?;
        f(area)
    }

    fn with_serial_area_rw<T>(
        &self,
        f: impl FnOnce(&mut MmapPropArea) -> SysPropResult<T>,
    ) -> SysPropResult<T> {
        let mut serial = self.serial_area.lock().map_err(|_| {
            SysPropError::Io(io::Error::new(
                io::ErrorKind::Other,
                "serial area mutex poisoned",
            ))
        })?;

        if serial.is_none() {
            *serial = Some(self.map_serial_area()?);
        }

        let area = serial.as_mut().ok_or_else(|| {
            SysPropError::Io(io::Error::new(
                io::ErrorKind::Other,
                "serial area initialization failed",
            ))
        })?;
        f(area)
    }

    fn with_area_and_serial_rw<T>(
        &self,
        context: &str,
        f: impl FnOnce(&mut MmapPropArea, &mut MmapPropArea) -> SysPropResult<T>,
    ) -> SysPropResult<T> {
        let mut cache = self.area_cache.lock().map_err(|_| {
            SysPropError::Io(io::Error::new(
                io::ErrorKind::Other,
                "area cache mutex poisoned",
            ))
        })?;
        if !cache.contains_key(context) {
            let area = self.map_context_area(context)?;
            cache.insert(context.to_owned(), area);
        }
        let area = cache.get_mut(context).ok_or_else(|| {
            SysPropError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("prop area not found for context: {context}"),
            ))
        })?;

        let mut serial = self.serial_area.lock().map_err(|_| {
            SysPropError::Io(io::Error::new(
                io::ErrorKind::Other,
                "serial area mutex poisoned",
            ))
        })?;
        if serial.is_none() {
            *serial = Some(self.map_serial_area()?);
        }
        let serial_area = serial.as_mut().ok_or_else(|| {
            SysPropError::Io(io::Error::new(
                io::ErrorKind::Other,
                "serial area initialization failed",
            ))
        })?;

        f(area, serial_area)
    }
}

const APPCOMPAT_DIR: &str = "/dev/__properties__/appcompat_override";
const APPCOMPAT_PREFIX: &str = "ro.appcompat_override.";

/// Strip the `ro.appcompat_override.` prefix if present, returning the
/// underlying property name for lookup in the appcompat area.
fn strip_appcompat_prefix(key: &str) -> &str {
    key.strip_prefix(APPCOMPAT_PREFIX).unwrap_or(key)
}

fn prop_ctx() -> SysPropResult<&'static CachedPropertyContext> {
    PROP_CTX.get().ok_or_else(|| {
        SysPropError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "PropertyContext not initialized — call sys_prop::init() first",
        ))
    })
}

fn appcompat_ctx() -> Option<&'static CachedPropertyContext> {
    APPCOMPAT_CTX.get().and_then(|opt| opt.as_ref())
}

/// Bump the global `properties_serial` area and wake waiters.
///
/// Matches bionic's Add() / Delete() pattern:
/// ```cpp
/// atomic_store_explicit(serial_pa->serial(),
///     atomic_load_explicit(serial_pa->serial(), relaxed) + 1, release);
/// __futex_wake(serial_pa->serial(), INT32_MAX);
/// ```
fn bump_and_wake_global_serial(ctx: &CachedPropertyContext) -> SysPropResult<()> {
    ctx.with_serial_area_rw(|serial_area| {
        serial_area.bump_area_serial_and_wake();
        Ok(())
    })
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Load bionic symbols, initialize `PropertyContext`, and call
/// `__system_properties_init`.
///
/// This must be called once before any other function in this module.
/// Subsequent calls are harmless no-ops.
pub fn init() -> SysPropResult<()> {
    if API.get().is_some() {
        return Ok(());
    }

    let init_fn: FnInit = load_sym_required("__system_properties_init")?;

    let bionic = BionicApi {
        find: load_sym_required("__system_property_find")?,
        read_callback: load_sym_required("__system_property_read_callback")?,
        for_each: load_sym_required("__system_property_foreach")?,
        set: load_sym_required("__system_property_set")?,
        serial: load_sym_required("__system_property_serial")?,
        area_serial: load_sym("__system_property_area_serial"),
        wait: load_sym("__system_property_wait"),
    };

    let ret = unsafe { init_fn() };
    if ret != 0 {
        return Err(SysPropError::InitFailed(ret));
    }

    let _ = API.set(bionic);

    // Initialize PropertyContext for prop-rs mmap operations.
    let _ = PROP_CTX.get_or_init(|| {
        CachedPropertyContext::new(
            PropertyContext::new(Path::new("/dev/__properties__"), Some(Path::new("/")))
                .expect("failed to load PropertyContext from /dev/__properties__"),
        )
    });

    // Initialize appcompat_override context (Android 14+).
    // Silently set to None when the directory does not exist.
    let _ = APPCOMPAT_CTX.get_or_init(|| {
        let dir = PathBuf::from(APPCOMPAT_DIR);
        if !dir.is_dir() {
            return None;
        }
        PropertyContext::new(&dir, Some(Path::new("/")))
            .ok()
            .map(CachedPropertyContext::new)
    });

    Ok(())
}

/// Find a property by name, returning an opaque handle.
pub fn find(key: &str) -> Option<PropInfoPtr> {
    let ckey = CString::new(key).ok()?;
    let pi = unsafe { (api().find)(ckey.as_ptr()) };
    if pi.is_null() {
        None
    } else {
        Some(PropInfoPtr(pi))
    }
}

/// Read the value of a property by name.
pub fn get(key: &str) -> Option<String> {
    let pi = find(key)?;
    read_value(pi)
}

/// Read the current value from a prop_info handle.
pub fn read(pi: PropInfoPtr) -> Option<(String, String)> {
    read_name_value(pi)
}

/// Get the serial number of a prop_info.
pub fn serial(pi: PropInfoPtr) -> u32 {
    unsafe { (api().serial)(pi.as_ptr()) }
}

/// Get the global area serial (if available).
pub fn area_serial() -> Option<u32> {
    api().area_serial.map(|f| unsafe { f() })
}

/// Get the SELinux context of a property by name.
///
/// Uses `prop-rs`'s `PropertyContext` to resolve the context — no patched
/// bionic required.
pub fn get_context(key: &str) -> SysPropResult<String> {
    let ctx = prop_ctx()?;
    Ok(ctx.get_context_for_name(key).to_string())
}

/// Resolve the backing prop-area file path for a property name.
pub fn area_path(key: &str) -> SysPropResult<PathBuf> {
    let ctx = prop_ctx()?;
    let context = ctx.get_context_for_name(key);
    Ok(ctx.ctx.context_file_path(context))
}

/// Inspect the current storage state of a property's value slot.
pub fn inspect_value_slot(key: &str) -> SysPropResult<Option<PropAreaValueInspect>> {
    let ctx = prop_ctx()?;
    let context = ctx.get_context_for_name(key).to_string();
    let path = ctx.ctx.context_file_path(&context);

    ctx.with_area_rw(&context, |area| {
        Ok(area.inspect_value_slot(key)?.map(|inspect| {
            let MmapValueSlotInspect {
                is_long,
                value_len,
                tail_size,
                tail_nonzero,
            } = inspect;
            PropAreaValueInspect {
                context: context.clone(),
                path: path.clone(),
                is_long,
                value_len,
                tail_size,
                tail_nonzero,
            }
        }))
    })
}

/// Scan allocations in the property's backing prop-area file.
pub fn scan_area(key: &str) -> SysPropResult<PropAreaScanReport> {
    let ctx = prop_ctx()?;
    let context = ctx.get_context_for_name(key).to_string();
    let path = ctx.ctx.context_file_path(&context);

    let file = OpenOptions::new().read(true).open(&path)?;
    let map = unsafe { MmapOptions::new().map(&file) }?;
    let cursor = Cursor::new(&map[..]);
    let mut area =
        PropArea::new(cursor).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let scan = area
        .scan_allocations()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    Ok(PropAreaScanReport {
        context,
        path,
        bytes_used: scan.bytes_used,
        has_dirty_backup: scan.has_dirty_backup,
        object_count: scan.objects.len(),
        hole_count: scan.holes.len(),
        holes: scan.holes,
    })
}

/// Iterate over all properties.
pub fn for_each(mut callback: impl FnMut(&str, &str)) {
    // We need a double indirection: for_each gives us pi, then we read_callback
    // to get name+value.
    struct Cookie<'a> {
        cb: &'a mut dyn FnMut(&str, &str),
        read_cb: FnReadCallback,
    }

    unsafe extern "C" fn iter_cb(pi: *const c_void, cookie: *mut c_void) {
        let c = &mut *(cookie as *mut Cookie);

        struct Inner {
            name: Option<String>,
            value: Option<String>,
        }
        unsafe extern "C" fn read_cb(
            ck: *mut c_void,
            name: *const c_char,
            value: *const c_char,
            _serial: u32,
        ) {
            let inner = &mut *(ck as *mut Inner);
            inner.name = Some(CStr::from_ptr(name).to_string_lossy().into_owned());
            inner.value = Some(CStr::from_ptr(value).to_string_lossy().into_owned());
        }

        let mut inner = Inner {
            name: None,
            value: None,
        };
        (c.read_cb)(pi, Some(read_cb), &mut inner as *mut _ as *mut c_void);
        if let (Some(n), Some(v)) = (inner.name, inner.value) {
            (c.cb)(&n, &v);
        }
    }

    let mut cookie = Cookie {
        cb: &mut callback,
        read_cb: api().read_callback,
    };
    unsafe {
        (api().for_each)(Some(iter_cb), &mut cookie as *mut _ as *mut c_void);
    }
}

/// Set a property value.
///
/// - For `ro.*` properties or when `skip_svc` is true: bypasses
///   `property_service` and writes directly to shared memory via
///   [`MmapPropArea`], with serial publication following bionic's exact atomic
///   ordering (see `system_properties.cpp` Update/Add).
/// - For other properties: uses `__system_property_set` which goes through
///   init's `property_service` socket.
pub fn set(key: &str, value: &str, skip_svc: bool) -> SysPropResult<bool> {
    let force_skip = skip_svc || key.starts_with("ro.");
    let mut need_rebuild = false;
    let mut need_rebuild_appcompat = false;

    if !key.starts_with("ro.") && value.len() >= PROP_VALUE_MAX {
        return Err(SysPropError::ValueTooLong {
            key: key.to_owned(),
            len: value.len(),
            max_len: PROP_VALUE_MAX,
        });
    }

    if force_skip {
        // Direct mmap write via mmap_prop_area writer protocol.
        let ctx = prop_ctx()?;
        let context = ctx.get_context_for_name(key);
        ctx.with_area_and_serial_rw(context, |area, serial_area| {
            area.upsert(key, value, serial_area, &mut need_rebuild)?;
            Ok(())
        })?;

        // Dual-write to appcompat_override area (Android 14+).
        if let Some(appcompat) = appcompat_ctx() {
            let override_key = strip_appcompat_prefix(key);
            let ctx_name = appcompat.get_context_for_name(override_key);
            let _ = appcompat.with_area_and_serial_rw(ctx_name, |ov_area, serial_area| {
                ov_area.upsert(
                    override_key,
                    value,
                    serial_area,
                    &mut need_rebuild_appcompat,
                )?;
                Ok(())
            });
        }
    } else {
        // Go through bionic's property_service socket.
        let ckey = make_cstring(key)?;
        let cval = make_cstring(value)?;
        let ret = unsafe { (api().set)(ckey.as_ptr(), cval.as_ptr()) };
        if ret != 0 {
            return Err(SysPropError::SetFailed(ret));
        }
    }

    Ok(need_rebuild || need_rebuild_appcompat)
}

/// Delete a property from shared memory.
///
/// Returns `true` if the property existed and was deleted.
///
/// This does **not** touch persistent storage — the caller is responsible
/// for calling `persist::persist_delete_prop` when appropriate.
pub fn delete(key: &str) -> SysPropResult<bool> {
    let ctx = prop_ctx()?;
    let context = ctx.get_context_for_name(key);
    let deleted = ctx.with_area_rw(context, |area| Ok(area.remove(key)?))?;

    if deleted {
        let _ = bump_and_wake_global_serial(ctx);
    }

    // Dual-delete from appcompat_override area (Android 14+).
    if let Some(appcompat) = appcompat_ctx() {
        let override_key = strip_appcompat_prefix(key);
        let ctx_name = appcompat.get_context_for_name(override_key);
        let _ = appcompat.with_area_rw(ctx_name, |ov_area| Ok(ov_area.remove(override_key)?));

        if deleted {
            let _ = bump_and_wake_global_serial(appcompat);
        }
    }

    Ok(deleted)
}

/// Wait for a property to exist or change away from a given value.
///
/// Follows Magisk resetprop semantics:
/// - `old_value = None`: wait until the property exists, then return.
/// - `old_value = Some(v)`: if the current value already differs from `v`,
///   return immediately; otherwise wait until the value changes to something
///   other than `v`.
/// - `timeout = None`: wait indefinitely.
///
/// Returns `true` if the condition was met, `false` on timeout.
pub fn wait(key: &str, old_value: Option<&str>, timeout: Option<Duration>) -> SysPropResult<bool> {
    let wait_fn = api()
        .wait
        .ok_or(SysPropError::SymbolNotFound("__system_property_wait"))?;

    let deadline = timeout.map(|d| std::time::Instant::now() + d);

    // Phase 1: wait for the property to exist.
    let info = loop {
        if let Some(dl) = deadline {
            if std::time::Instant::now() >= dl {
                return Ok(false);
            }
        }

        if let Some(pi) = find(key) {
            break pi;
        }

        // Property doesn't exist — wait for global area serial change.
        let old = area_serial().unwrap_or(0);
        let mut new_serial = 0u32;
        let ts = remaining_timespec(deadline);
        let changed = unsafe { wait_fn(std::ptr::null(), old, &mut new_serial, ts_ptr(&ts)) };
        if !changed && deadline.is_some() {
            return Ok(false);
        }
    };

    // If no old_value specified, property existence is sufficient.
    let old_value = match old_value {
        Some(v) => v,
        None => return Ok(true),
    };

    // Phase 2: wait for value != old_value.
    // Prefer waiting on global serial when available. For direct mmap writes,
    // prop serial may be restored to hide modifications, but global serial is
    // still bumped and reliably signals that some property changed.
    let use_global_wait = api().area_serial.is_some();
    loop {
        if let Some(dl) = deadline {
            if std::time::Instant::now() >= dl {
                return Ok(false);
            }
        }

        let mut curr_serial = 0u32;
        if let Some(current) = read_value_serial(info, &mut curr_serial) {
            if current != old_value {
                return Ok(true);
            }
        }

        // Current value still equals old_value — wait for serial change.
        let mut new_serial = 0u32;
        let ts = remaining_timespec(deadline);
        let changed = if use_global_wait {
            let old_global = area_serial().unwrap_or(0);
            unsafe { wait_fn(std::ptr::null(), old_global, &mut new_serial, ts_ptr(&ts)) }
        } else {
            unsafe { wait_fn(info.as_ptr(), curr_serial, &mut new_serial, ts_ptr(&ts)) }
        };
        if !changed && deadline.is_some() {
            return Ok(false);
        }
    }
}

pub fn rebuild(context: &String, check: bool, appcompat: bool) -> SysPropResult<()> {
    let mut callback = |area: &mut MmapPropArea| {
        if check {
            let mut prop_area = area.as_prop_area()?;
            let res = prop_area
                .scan_allocations()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            if !res.has_abnormal && res.holes.is_empty() {
                return Ok(());
            }
        }
        let mut anon_area = MmapPropArea::new_anon_from(area)?;
        anon_area.fill_prop_from(area)?;
        area.replace_with_area(&anon_area)?;
        Ok(())
    };

    if !appcompat {
        let ctx = prop_ctx()?;
        ctx.with_area_rw(context, &mut callback)?;
    } else if let Some(appcompat_ctx) = appcompat_ctx() {
        appcompat_ctx.with_area_rw(context, &mut callback)?;
    }

    Ok(())
}

pub fn list_contexts(appcompat: bool) -> SysPropResult<Vec<&'static str>> {
    let ctx = if !appcompat {
        prop_ctx()?
    } else {
        if let Some(ctx) = appcompat_ctx() {
            ctx
        } else {
            return Ok(Vec::<_>::new());
        }
    };
    Ok(ctx.ctx.list_all_contexts())
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn make_cstring(s: &str) -> SysPropResult<CString> {
    CString::new(s).map_err(|_| SysPropError::InvalidCString(s.to_owned()))
}

fn read_value(pi: PropInfoPtr) -> Option<String> {
    struct ValueCookie {
        value: Option<String>,
    }

    unsafe extern "C" fn cb(
        cookie: *mut c_void,
        _name: *const c_char,
        value: *const c_char,
        _serial: u32,
    ) {
        let c = &mut *(cookie as *mut ValueCookie);
        c.value = Some(CStr::from_ptr(value).to_string_lossy().into_owned());
    }

    let mut cookie = ValueCookie { value: None };
    unsafe {
        (api().read_callback)(pi.as_ptr(), Some(cb), &mut cookie as *mut _ as *mut c_void);
    }
    cookie.value
}

/// Read the value and serial of a prop_info in one callback.
fn read_value_serial(pi: PropInfoPtr, out_serial: &mut u32) -> Option<String> {
    struct Cookie {
        value: Option<String>,
        serial: u32,
    }

    unsafe extern "C" fn cb(
        cookie: *mut c_void,
        _name: *const c_char,
        value: *const c_char,
        serial: u32,
    ) {
        let c = &mut *(cookie as *mut Cookie);
        c.value = Some(CStr::from_ptr(value).to_string_lossy().into_owned());
        c.serial = serial;
    }

    let mut cookie = Cookie {
        value: None,
        serial: 0,
    };
    unsafe {
        (api().read_callback)(pi.as_ptr(), Some(cb), &mut cookie as *mut _ as *mut c_void);
    }
    *out_serial = cookie.serial;
    cookie.value
}

fn read_name_value(pi: PropInfoPtr) -> Option<(String, String)> {
    struct NVCookie {
        name: Option<String>,
        value: Option<String>,
    }

    unsafe extern "C" fn cb(
        cookie: *mut c_void,
        name: *const c_char,
        value: *const c_char,
        _serial: u32,
    ) {
        let c = &mut *(cookie as *mut NVCookie);
        c.name = Some(CStr::from_ptr(name).to_string_lossy().into_owned());
        c.value = Some(CStr::from_ptr(value).to_string_lossy().into_owned());
    }

    let mut cookie = NVCookie {
        name: None,
        value: None,
    };
    unsafe {
        (api().read_callback)(pi.as_ptr(), Some(cb), &mut cookie as *mut _ as *mut c_void);
    }
    Some((cookie.name?, cookie.value?))
}

fn remaining_timespec(deadline: Option<std::time::Instant>) -> Option<libc::timespec> {
    deadline.map(|dl| {
        let remaining = dl.saturating_duration_since(std::time::Instant::now());
        libc::timespec {
            tv_sec: remaining.as_secs() as libc::time_t,
            tv_nsec: remaining.subsec_nanos() as libc::c_long,
        }
    })
}

fn ts_ptr(ts: &Option<libc::timespec>) -> *const libc::timespec {
    match ts {
        Some(t) => t as *const _,
        None => std::ptr::null(),
    }
}
