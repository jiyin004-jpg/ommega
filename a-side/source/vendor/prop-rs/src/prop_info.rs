use std::mem::{offset_of, size_of};

pub const PROP_AREA_MAGIC: u32 = 0x504f_5250;
pub const PROP_AREA_VERSION: u32 = 0xfc6e_d0ab;
pub const PROP_VALUE_MAX: usize = 92;
pub const PROP_NAME_MAX: usize = 32;
pub(crate) const LONG_LEGACY_ERROR_BUFFER_SIZE: usize = 56;
pub(crate) const LONG_LEGACY_ERROR: &str = "Must use __system_property_read_callback() to read";
pub(crate) const PROP_INFO_LONG_FLAG: u32 = 1 << 16;

/// Byte offset of `serial` within `RawPropAreaHeader` (file-absolute offset).
pub const AREA_SERIAL_OFFSET: u64 = offset_of!(RawPropAreaHeader, serial) as u64;

/// Byte offset of `serial` within `RawPropInfoHeader`.
pub const PROP_INFO_SERIAL_OFFSET: u32 = offset_of!(RawPropInfoHeader, serial) as u32;

// ── repr(C) mirrors of the on-disk / in-memory C++ structs ───────────────────

/// Mirrors the fixed header of C++ `prop_area` (before the flexible `data_[]` array).
///
/// ```text
/// offset   0  bytes_used  u32
/// offset   4  serial      u32   (ignored; kept to preserve layout)
/// offset   8  magic       u32
/// offset  12  version     u32
/// offset  16  reserved    [u32; 28]  (112 bytes)
/// ──────────────────────────────
/// total: 128 bytes  →  data_[] starts here
/// ```
#[repr(C)]
pub struct RawPropAreaHeader {
    pub bytes_used: u32,
    pub serial: u32,
    pub magic: u32,
    pub version: u32,
    pub reserved: [u32; 28],
}

/// Mirrors the fixed header of C++ `prop_trie_node` (before the flexible `name[0]` array).
///
/// ```text
/// offset  0  namelen   u32
/// offset  4  prop      u32   (offset into data_[] → prop_info)
/// offset  8  left      u32
/// offset 12  right     u32
/// offset 16  children  u32
/// ─────────────────────────
/// total: 20 bytes  →  name[] starts here
/// ```
#[repr(C)]
pub struct RawTrieNodeHeader {
    pub namelen: u32,
    pub prop: u32,
    pub left: u32,
    pub right: u32,
    pub children: u32,
}

/// The `long_property` sub-struct inside the `prop_info` value union.
///
/// ```text
/// offset  0  error_message  [u8; 56]
/// offset 56  offset         u32    (relative offset from prop_info to the long string)
/// ```
#[repr(C)]
pub struct RawLongProperty {
    pub error_message: [u8; LONG_LEGACY_ERROR_BUFFER_SIZE],
    pub offset: u32,
}

/// Mirrors the fixed portion of C++ `prop_info` (before the flexible `name[0]` array).
///
/// ```text
/// offset  0  serial  u32   (ignored; kept to preserve layout)
/// offset  4  value   [u8; 92]   (overlaps with RawLongProperty when is_long)
/// ────────────────────────
/// total: 96 bytes  →  name[] starts here
/// ```
#[repr(C)]
pub struct RawPropInfoHeader {
    pub serial: u32,
    pub value: [u8; PROP_VALUE_MAX],
}

// ── Derived layout constants (never hardcoded) ────────────────────────────────

/// Size of the `prop_area` header; `data_[]` starts at this offset in the file.
pub const PROP_AREA_HEADER_SIZE: u64 = size_of::<RawPropAreaHeader>() as u64;

/// Size of the fixed part of `prop_trie_node`.
pub(crate) const PROP_TRIE_NODE_HEADER_SIZE: u32 = size_of::<RawTrieNodeHeader>() as u32;

/// Size of the fixed part of `prop_info`.
pub(crate) const PROP_INFO_SIZE: u32 = size_of::<RawPropInfoHeader>() as u32;

/// Byte offset of `long_property.offset` within a `prop_info` record.
/// = `offset_of!(RawPropInfoHeader, value)` + `offset_of!(RawLongProperty, offset)`
pub(crate) const LONG_OFFSET_IN_INFO: u32 =
    (offset_of!(RawPropInfoHeader, value) + offset_of!(RawLongProperty, offset)) as u32;

pub(crate) const DIRTY_BACKUP_SIZE: u32 = align_up(PROP_VALUE_MAX as u32, 4);
pub(crate) const INITIAL_BYTES_USED: u32 = PROP_TRIE_NODE_HEADER_SIZE + DIRTY_BACKUP_SIZE;

// ── Public API type ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyInfo {
    pub name: String,
    pub value: String,
    pub prop_offset: u32,
    pub name_offset: u32,
    pub value_offset: u32,
    pub is_long: bool,
}

// ── Utility ───────────────────────────────────────────────────────────────────

pub(crate) const fn align_up(value: u32, align: u32) -> u32 {
    if align == 0 {
        return value;
    }
    let mask = align - 1;
    (value + mask) & !mask
}
