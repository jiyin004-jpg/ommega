//! Android property context parser.
//!
//! Maps property names to SELinux context strings by reading the same files
//! that Android's `libbase` / `bionic` use, but using only plain file I/O —
//! no mmap, no ioctl, no futex.  This makes the code host-portable and
//! usable for offline analysis of Android system images.
//!
//! # Context storage types
//!
//! | Condition                                         | Mode       |
//! |---------------------------------------------------|------------|
//! | `props_dir` is a directory **and** `property_info` exists | [`Serialized`] |
//! | `props_dir` is a directory (no `property_info`)   | [`Split`]  |
//! | `props_dir` is a plain file                       | [`PreSplit`] |
//!
//! These mirror Android's `ContextsSerialized`, `ContextsSplit`, and
//! `ContextsPreSplit` respectively.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ────────────────────────────────────────────────────────────────────────────
// Binary helpers
// ────────────────────────────────────────────────────────────────────────────

#[inline]
fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let b: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_ne_bytes(b))
}

/// Read a null-terminated C string from `data` starting at `offset`.
fn read_cstr(data: &[u8], offset: usize) -> Option<&str> {
    let slice = data.get(offset..)?;
    let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..len]).ok()
}

// ────────────────────────────────────────────────────────────────────────────
// Serialized context  (`/dev/__properties__/property_info`)
// ────────────────────────────────────────────────────────────────────────────
//
// Binary format (all values native-endian u32):
//
//  PropertyInfoAreaHeader  @ offset 0  (6 × u32 = 24 bytes)
//  ┌─────────────────────────────────────────────────────────┐
//  │ current_version           │ minimum_supported_version   │
//  │ size                      │ contexts_offset              │
//  │ types_offset              │ root_offset                  │
//  └─────────────────────────────────────────────────────────┘
//
//  Context / type table  @ contexts_offset / types_offset:
//    [u32 count] [u32 str_off_0] [u32 str_off_1] …
//    (each str_off points to a null-terminated string inside `data`)
//
//  TrieNodeInternal  (7 × u32 = 28 bytes):
//    +0   property_entry      → offset to PropertyEntry
//    +4   num_child_nodes
//    +8   child_nodes         → offset to u32[] of child TrieNodeInternal offsets
//    +12  num_prefixes
//    +16  prefix_entries      → offset to u32[] of PropertyEntry offsets
//    +20  num_exact_matches
//    +24  exact_match_entries → offset to u32[] of PropertyEntry offsets
//
//  PropertyEntry  (4 × u32 = 16 bytes):
//    +0  name_offset  → offset to null-terminated name
//    +4  namelen
//    +8  context_index  (~0u if no context)
//    +12 type_index     (~0u if no type)

/// Minimum `current_version` that this parser has been tested against.
const SUPPORTED_VERSION: u32 = 2;

struct SerializedContext {
    data: Vec<u8>,
}

impl SerializedContext {
    fn load(path: &Path) -> io::Result<Self> {
        let data = fs::read(path)?;
        if data.len() < 24 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "property_info file too small",
            ));
        }
        let min_ver = read_u32(&data, 4).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "property_info header truncated")
        })?;
        if min_ver > SUPPORTED_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "property_info requires parser version >= {min_ver}, we support {SUPPORTED_VERSION}"
                ),
            ));
        }
        Ok(Self { data })
    }

    // ── Header accessors ─────────────────────────────────────────────────────

    fn current_version(&self) -> u32 {
        read_u32(&self.data, 0).unwrap_or(0)
    }
    fn _size(&self) -> usize {
        read_u32(&self.data, 8).unwrap_or(0) as usize
    }
    fn contexts_offset(&self) -> Option<usize> {
        let off = read_u32(&self.data, 12)? as usize;
        if off < self.data.len() {
            Some(off)
        } else {
            None
        }
    }
    fn types_offset(&self) -> Option<usize> {
        let off = read_u32(&self.data, 16)? as usize;
        if off < self.data.len() {
            Some(off)
        } else {
            None
        }
    }
    fn root_offset(&self) -> Option<usize> {
        let off = read_u32(&self.data, 20)? as usize;
        // root node needs at least 28 bytes (TrieNodeInternal)
        if off + 28 <= self.data.len() {
            Some(off)
        } else {
            None
        }
    }

    // ── Context / type tables ─────────────────────────────────────────────────

    pub fn num_contexts(&self) -> usize {
        self.contexts_offset()
            .and_then(|off| read_u32(&self.data, off))
            .unwrap_or(0) as usize
    }

    pub fn context(&self, index: usize) -> Option<&str> {
        let ctx_off = self.contexts_offset()?;
        let arr_off = ctx_off.checked_add(4)?;
        let str_off = read_u32(&self.data, arr_off.checked_add(index.checked_mul(4)?)?)? as usize;
        read_cstr(&self.data, str_off)
    }

    pub fn num_types(&self) -> usize {
        self.types_offset()
            .and_then(|off| read_u32(&self.data, off))
            .unwrap_or(0) as usize
    }

    pub fn type_str(&self, index: usize) -> Option<&str> {
        let typ_off = self.types_offset()?;
        let arr_off = typ_off.checked_add(4)?;
        let str_off = read_u32(&self.data, arr_off.checked_add(index.checked_mul(4)?)?)? as usize;
        read_cstr(&self.data, str_off)
    }

    // ── TrieNodeInternal accessors (by node byte offset) ─────────────────────

    fn node_pe_offset(&self, node_off: usize) -> Option<usize> {
        Some(read_u32(&self.data, node_off)? as usize)
    }

    /// Context index stored in the PropertyEntry attached to this trie node.
    fn node_context_index(&self, node_off: usize) -> Option<u32> {
        let pe = self.node_pe_offset(node_off)?;
        read_u32(&self.data, pe.checked_add(8)?)
    }

    fn node_num_children(&self, node_off: usize) -> usize {
        read_u32(&self.data, node_off + 4).unwrap_or(0) as usize
    }

    fn node_child_arr_off(&self, node_off: usize) -> Option<usize> {
        Some(read_u32(&self.data, node_off.checked_add(8)?)? as usize)
    }

    /// Byte offset of the i-th child TrieNodeInternal.
    fn node_child_offset(&self, node_off: usize, i: usize) -> Option<usize> {
        let arr = self.node_child_arr_off(node_off)?;
        Some(read_u32(&self.data, arr.checked_add(i.checked_mul(4)?)?)? as usize)
    }

    /// Name string of a child node (the trie segment, e.g. "ro", "persist").
    fn node_child_name(&self, child_off: usize) -> Option<&str> {
        let pe = self.node_pe_offset(child_off)?;
        let name_off = read_u32(&self.data, pe)? as usize;
        read_cstr(&self.data, name_off)
    }

    fn node_num_prefixes(&self, node_off: usize) -> usize {
        node_off
            .checked_add(12)
            .and_then(|off| read_u32(&self.data, off))
            .unwrap_or(0) as usize
    }

    fn node_prefix_arr_off(&self, node_off: usize) -> Option<usize> {
        Some(read_u32(&self.data, node_off.checked_add(16)?)? as usize)
    }

    fn node_num_exact_matches(&self, node_off: usize) -> usize {
        node_off
            .checked_add(20)
            .and_then(|off| read_u32(&self.data, off))
            .unwrap_or(0) as usize
    }

    fn node_exact_arr_off(&self, node_off: usize) -> Option<usize> {
        Some(read_u32(&self.data, node_off.checked_add(24)?)? as usize)
    }

    // ── Trie traversal ────────────────────────────────────────────────────────

    /// Mirrors `PropertyInfoArea::CheckPrefixMatch`.
    ///
    /// Prefixes are stored sorted longest-first; we return on the first match.
    fn check_prefix_match(&self, remaining: &str, node_off: usize, ctx_idx: &mut u32) {
        let n = self.node_num_prefixes(node_off);
        if n == 0 {
            return;
        }
        let arr_off = match self.node_prefix_arr_off(node_off) {
            Some(off) => off,
            None => return,
        };
        let rem_bytes = remaining.as_bytes();

        for i in 0..n {
            let Some(pe_off) = read_u32(&self.data, arr_off + i * 4).map(|v| v as usize) else {
                return;
            };
            let Some(name_off) = read_u32(&self.data, pe_off).map(|v| v as usize) else {
                return;
            };
            let Some(prefix_len) = read_u32(&self.data, pe_off + 4).map(|v| v as usize) else {
                return;
            };
            let Some(ctx) = read_u32(&self.data, pe_off + 8) else {
                return;
            };

            if prefix_len > rem_bytes.len() {
                continue;
            }
            let Some(prefix_bytes) = self.data.get(name_off..name_off + prefix_len) else {
                return;
            };
            if rem_bytes[..prefix_len] == *prefix_bytes {
                if ctx != !0u32 {
                    *ctx_idx = ctx;
                }
                return; // first (longest) match wins
            }
        }
    }

    /// Binary-search the child list of `node_off` for a segment equal to `piece`.
    ///
    /// Mirrors `TrieNode::FindChildForString`:
    ///   `strncmp(child_name, piece, piece.len())`, returning 1 if equal but child is longer.
    fn find_child(&self, node_off: usize, piece: &str) -> Option<usize> {
        let n = self.node_num_children(node_off);
        if n == 0 {
            return None;
        }
        let piece_bytes = piece.as_bytes();
        let plen = piece_bytes.len();

        let mut lo = 0i32;
        let mut hi = n as i32 - 1;
        while lo <= hi {
            let mid = (lo + hi) / 2;
            let child_off = self.node_child_offset(node_off, mid as usize)?;
            let child_name = self.node_child_name(child_off)?;
            let cmp = strncmp_piece(child_name.as_bytes(), piece_bytes, plen);
            match cmp {
                0 => return Some(child_off),
                x if x < 0 => lo = mid + 1,
                _ => hi = mid - 1,
            }
        }
        None
    }

    /// Mirrors `PropertyInfoArea::GetPropertyInfoIndexes` — returns context index.
    fn get_context_index(&self, name: &str) -> Option<usize> {
        let mut ctx_idx: u32 = !0u32;
        let mut remaining = name;
        let mut node_off = self.root_offset()?;

        loop {
            // Apply context provided by current trie node.
            let node_ctx = self.node_context_index(node_off).unwrap_or(!0u32);
            if node_ctx != !0u32 {
                ctx_idx = node_ctx;
            }

            // Check prefix entries at this node (checked after node context
            // because prefixes are by definition longer than the node itself).
            self.check_prefix_match(remaining, node_off, &mut ctx_idx);

            let Some(dot_pos) = remaining.find('.') else {
                break;
            };
            let piece = &remaining[..dot_pos];

            match self.find_child(node_off, piece) {
                Some(child_off) => {
                    node_off = child_off;
                    remaining = &remaining[dot_pos + 1..];
                }
                None => break,
            }
        }

        // Check exact matches at the leaf.
        let n_exact = self.node_num_exact_matches(node_off);
        if n_exact > 0 {
            let arr_off = self.node_exact_arr_off(node_off)?;
            for i in 0..n_exact {
                let pe_off = read_u32(&self.data, arr_off + i * 4)? as usize;
                let name_off = read_u32(&self.data, pe_off)? as usize;
                let exact_name = read_cstr(&self.data, name_off)?;
                if exact_name == remaining {
                    let ctx = read_u32(&self.data, pe_off + 8)?;
                    if ctx != !0u32 {
                        ctx_idx = ctx;
                    }
                    // Use whatever ctx_idx we have (might be inherited).
                    return if ctx_idx == !0u32 {
                        None
                    } else {
                        Some(ctx_idx as usize)
                    };
                }
            }
        }

        // Prefix matches not delimited by '.'.
        self.check_prefix_match(remaining, node_off, &mut ctx_idx);

        if ctx_idx == !0u32 {
            None
        } else {
            Some(ctx_idx as usize)
        }
    }

    pub fn get_context_for_name(&self, name: &str) -> &str {
        match self.get_context_index(name) {
            Some(idx) => self.context(idx).unwrap_or(DEFAULT_CONTEXT),
            _ => DEFAULT_CONTEXT,
        }
    }
}

/// Mirrors C `strncmp(a, b, n)` followed by the "longer prefix" check.
///
/// Returns:
///  - negative if `a < b` in the first `n` bytes
///  - 0        if `a[..n] == b[..n]` **and** `a.len() == n` (exact prefix match)
///  - positive if `a > b`, or if `a[..n] == b[..n]` but `a.len() > n`
fn strncmp_piece(child: &[u8], piece: &[u8], n: usize) -> i32 {
    for i in 0..n {
        let cb = child.get(i).copied().unwrap_or(0);
        let pb = piece[i];
        if cb < pb {
            return -1;
        }
        if cb > pb {
            return 1;
        }
    }
    // First `n` bytes are equal; if child is longer → return 1 (consider it greater)
    if child.len() > n {
        1
    } else {
        0
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Split context  (text `property_contexts` files)
// ────────────────────────────────────────────────────────────────────────────
//
// File format (one entry per line):
//   <prefix>   <selinux_context>   [# comment]
//
// `ctl.*` entries are skipped (init IPC properties, not written to disk).
// Entries are kept sorted longest-prefix-first; '*' is a wildcard and goes last.

struct PrefixEntry {
    prefix: String,
    context: String,
}

struct SplitContext {
    prefixes: Vec<PrefixEntry>,
}

impl SplitContext {
    /// Load from `system_root`, mirroring `ContextsSplit::InitializeProperties`.
    fn load(system_root: &Path) -> io::Result<Self> {
        let mut prefixes: Vec<PrefixEntry> = Vec::new();

        // 1. Legacy single-file at root
        let legacy = system_root.join("property_contexts");
        if legacy.exists() {
            Self::load_file(&legacy, &mut prefixes)?;
            return Ok(Self { prefixes });
        }

        // 2. Modern split: plat + vendor
        let plat = system_root.join("system/etc/selinux/plat_property_contexts");
        if plat.exists() {
            Self::load_file(&plat, &mut prefixes)?;
            let vendor = system_root.join("vendor/etc/selinux/vendor_property_contexts");
            if vendor.exists() {
                let _ = Self::load_file(&vendor, &mut prefixes);
            } else {
                let nonplat = system_root.join("vendor/etc/selinux/nonplat_property_contexts");
                let _ = Self::load_file(&nonplat, &mut prefixes);
            }
        } else {
            // 3. Older split at root
            let plat2 = system_root.join("plat_property_contexts");
            if plat2.exists() {
                Self::load_file(&plat2, &mut prefixes)?;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no property_contexts file found under system_root",
                ));
            }
            let vendor2 = system_root.join("vendor_property_contexts");
            if vendor2.exists() {
                let _ = Self::load_file(&vendor2, &mut prefixes);
            } else {
                let nonplat2 = system_root.join("nonplat_property_contexts");
                let _ = Self::load_file(&nonplat2, &mut prefixes);
            }
        }

        Ok(Self { prefixes })
    }

    /// Parse one property_contexts file and insert entries sorted longest-first.
    fn load_file(path: &Path, prefixes: &mut Vec<PrefixEntry>) -> io::Result<()> {
        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            // Strip inline comments.
            let line = match line.split_once('#') {
                Some((before, _)) => before,
                None => line,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let mut parts = line.split_whitespace();
            let Some(prefix) = parts.next() else { continue };
            let Some(context) = parts.next() else {
                continue;
            };

            // ctl.* properties are init IPC — no backing file.
            if prefix.starts_with("ctl.") {
                continue;
            }

            let plen = prefix.len();
            let entry = PrefixEntry {
                prefix: prefix.to_string(),
                context: context.to_string(),
            };
            // Insert just before the first entry with a shorter prefix,
            // keeping '*' (wildcard) at the very end.
            let pos = prefixes
                .iter()
                .position(|e| e.prefix == "*" || e.prefix.len() < plen)
                .unwrap_or(prefixes.len());
            prefixes.insert(pos, entry);
        }
        Ok(())
    }

    fn get_context_for_name(&self, name: &str) -> &str {
        for entry in &self.prefixes {
            if entry.prefix == "*" || name.starts_with(entry.prefix.as_str()) {
                return &entry.context;
            }
        }
        DEFAULT_CONTEXT
    }
}

// ────────────────────────────────────────────────────────────────────────────
// PreSplit context  (legacy single prop-area file)
// ────────────────────────────────────────────────────────────────────────────

/// Context returned for all properties in the PreSplit layout.
const PRE_SPLIT_CONTEXT: &str = "u:object_r:properties_device:s0";

/// Default fallback context when no match is found.
const DEFAULT_CONTEXT: &str = "u:object_r:default_prop:s0";

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

enum ContextStorage {
    Serialized(SerializedContext),
    Split(SplitContext),
    PreSplit,
}

/// Which storage format was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextType {
    /// Modern Android (≥ 8.0): binary trie in `property_info`.
    Serialized,
    /// Older Android (7.x): text `property_contexts` files.
    Split,
    /// Legacy Android (≤ 6.0): single prop-area file; all props share one context.
    PreSplit,
}

impl fmt::Display for ContextType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialized => write!(f, "Serialized"),
            Self::Split => write!(f, "Split"),
            Self::PreSplit => write!(f, "PreSplit"),
        }
    }
}

/// Parses Android property context metadata from plain files.
///
/// No system calls beyond `read()` are used — no `mmap`, no `ioctl`, no futex —
/// making this code fully portable to non-Android hosts for offline analysis.
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use prop_rs::PropertyContext;
///
/// let ctx = PropertyContext::new(
///     Path::new("/dev/__properties__"),
///     None, // system_root — `None` uses `/`
/// ).unwrap();
///
/// println!("{}", ctx.get_context_for_name("ro.build.fingerprint"));
/// ```
pub struct PropertyContext {
    storage: ContextStorage,
    props_dir: PathBuf,
}

impl PropertyContext {
    /// Load property context from disk.
    ///
    /// # Parameters
    /// - `props_dir` — path to `/dev/__properties__` or an offline copy of it.
    /// - `system_root` — optional system-root prefix used to locate SELinux
    ///   `property_contexts` files when the storage format is [`ContextType::Split`].
    ///   Pass `None` to default to `/` (correct when running on a live device).
    ///
    /// # Detection
    /// | `props_dir` is … | `property_info` exists? | Format |
    /// |---|---|---|
    /// | directory | yes | [`ContextType::Serialized`] |
    /// | directory | no  | [`ContextType::Split`] |
    /// | file | — | [`ContextType::PreSplit`] |
    pub fn new(props_dir: &Path, system_root: Option<&Path>) -> io::Result<Self> {
        let meta = fs::metadata(props_dir)?;
        let storage = if meta.is_dir() {
            let tree_file = props_dir.join("property_info");
            if tree_file.exists() {
                let sc = SerializedContext::load(&tree_file)?;
                ContextStorage::Serialized(sc)
            } else {
                let root = system_root.unwrap_or(Path::new("/"));
                let sc = SplitContext::load(root)?;
                ContextStorage::Split(sc)
            }
        } else {
            ContextStorage::PreSplit
        };
        Ok(Self {
            storage,
            props_dir: props_dir.to_path_buf(),
        })
    }

    /// Returns the SELinux context string for `prop_name`.
    ///
    /// Falls back to `"u:object_r:default_prop:s0"` if no context matches.
    pub fn get_context_for_name(&self, prop_name: &str) -> &str {
        match &self.storage {
            ContextStorage::Serialized(sc) => sc.get_context_for_name(prop_name),
            ContextStorage::Split(sc) => sc.get_context_for_name(prop_name),
            ContextStorage::PreSplit => PRE_SPLIT_CONTEXT,
        }
    }

    /// Returns the SELinux context string for `prop_name` as an owned [`String`].
    ///
    /// This name is kept for compatibility with older call sites.
    pub fn get_property_for_name(&self, prop_name: &str) -> String {
        self.get_context_for_name(prop_name).to_string()
    }

    /// Which storage format is in use.
    pub fn context_type(&self) -> ContextType {
        match &self.storage {
            ContextStorage::Serialized(_) => ContextType::Serialized,
            ContextStorage::Split(_) => ContextType::Split,
            ContextStorage::PreSplit => ContextType::PreSplit,
        }
    }

    /// Dump a human-readable summary of the loaded context data to stdout.
    ///
    /// Useful for debugging and offline analysis.
    pub fn dump(&self) {
        println!("PropertyContext @ {:?}", self.props_dir);
        println!("  type : {}", self.context_type());
        match &self.storage {
            ContextStorage::Serialized(sc) => {
                println!("  parser version : {}", sc.current_version());
                println!("  contexts ({}):", sc.num_contexts());
                for i in 0..sc.num_contexts() {
                    if let Some(ctx) = sc.context(i) {
                        println!("    [{:3}] {}", i, ctx);
                    }
                }
                println!("  types ({}):", sc.num_types());
                for i in 0..sc.num_types() {
                    if let Some(t) = sc.type_str(i) {
                        println!("    [{:3}] {}", i, t);
                    }
                }
            }
            ContextStorage::Split(sc) => {
                println!("  prefix entries ({}):", sc.prefixes.len());
                for e in &sc.prefixes {
                    println!("    {:<60} {}", e.prefix, e.context);
                }
            }
            ContextStorage::PreSplit => {
                println!("  context : {}", PRE_SPLIT_CONTEXT);
            }
        }
    }

    /// Convenience initialiser for a **live Android device**.
    ///
    /// Uses `/dev/__properties__` and `/` as defaults.
    #[cfg(target_os = "android")]
    pub fn for_android() -> io::Result<Self> {
        Self::new(Path::new("/dev/__properties__"), Some(Path::new("/")))
    }

    /// The path to `props_dir` passed to [`PropertyContext::new`].
    pub fn props_dir(&self) -> &Path {
        &self.props_dir
    }

    /// Return all SELinux context strings known to this property context.
    ///
    /// - **Serialized**: iterates the context table in `property_info`.
    /// - **Split**: de-duplicates context strings from the prefix list.
    /// - **PreSplit**: returns the single fixed context.
    pub fn list_all_contexts(&self) -> Vec<&str> {
        match &self.storage {
            ContextStorage::Serialized(sc) => (0..sc.num_contexts())
                .filter_map(|i| sc.context(i))
                .collect(),
            ContextStorage::Split(sc) => {
                let mut seen = std::collections::BTreeSet::new();
                let mut result = Vec::new();
                for entry in &sc.prefixes {
                    if seen.insert(entry.context.as_str()) {
                        result.push(entry.context.as_str());
                    }
                }
                result
            }
            ContextStorage::PreSplit => vec![PRE_SPLIT_CONTEXT],
        }
    }

    /// Resolve a context name to its prop-area file path.
    ///
    /// In **PreSplit** mode `props_dir` is the single file itself, so this
    /// always returns `props_dir` regardless of `context`.
    /// In directory-based modes the context name is used as the filename.
    pub fn context_file_path(&self, context: &str) -> PathBuf {
        match &self.storage {
            ContextStorage::PreSplit => self.props_dir.clone(),
            _ => self.props_dir.join(context),
        }
    }

    /// Return the path to the global `properties_serial` prop-area file.
    ///
    /// In **Serialized** and **Split** modes this is `props_dir/properties_serial`.
    /// In **PreSplit** mode the single prop-area file doubles as the serial area,
    /// mirroring bionic's `ContextsPreSplit::GetSerialPropArea`.
    pub fn serial_prop_area_path(&self) -> PathBuf {
        match &self.storage {
            ContextStorage::PreSplit => self.props_dir.clone(),
            _ => self.props_dir.join("properties_serial"),
        }
    }

    /// Enumerate prop-area files under `props_dir` as `(context_name, path)`.
    ///
    /// - **PreSplit**: single entry `(PRE_SPLIT_CONTEXT, props_dir)`.
    /// - **Serialized / Split**: builds file paths from known context names
    ///   without enumerating the directory (avoids `read_dir` permission issues
    ///   on low-privilege Android users).
    pub fn prop_area_files(&self) -> io::Result<Vec<(String, PathBuf)>> {
        match &self.storage {
            ContextStorage::PreSplit => Ok(vec![(
                PRE_SPLIT_CONTEXT.to_string(),
                self.props_dir.clone(),
            )]),
            _ => {
                let mut names: Vec<String> = self
                    .list_all_contexts()
                    .into_iter()
                    .map(|ctx| ctx.to_string())
                    .collect();
                names.sort();
                names.dedup();

                Ok(names
                    .into_iter()
                    .map(|ctx| {
                        let path = self.context_file_path(&ctx);
                        (ctx, path)
                    })
                    .collect())
            }
        }
    }
}
