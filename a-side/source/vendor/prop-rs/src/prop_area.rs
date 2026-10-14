use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::offset_of;
use std::ops::Add;

use crate::prop_info::{
    align_up, PropertyInfo, RawLongProperty, RawPropAreaHeader, RawPropInfoHeader,
    RawTrieNodeHeader, DIRTY_BACKUP_SIZE, INITIAL_BYTES_USED, LONG_LEGACY_ERROR,
    LONG_OFFSET_IN_INFO, PROP_AREA_HEADER_SIZE, PROP_AREA_MAGIC, PROP_AREA_VERSION,
    PROP_INFO_LONG_FLAG, PROP_INFO_SIZE, PROP_TRIE_NODE_HEADER_SIZE, PROP_VALUE_MAX,
};

// ── Offset constants derived entirely from the repr(C) structs ────────────────

const BYTES_USED_OFFSET: u64 = offset_of!(RawPropAreaHeader, bytes_used) as u64;
const MAGIC_OFFSET: u64 = offset_of!(RawPropAreaHeader, magic) as u64;
const VERSION_OFFSET: u64 = offset_of!(RawPropAreaHeader, version) as u64;

const NODE_PROP_OFFSET: u32 = offset_of!(RawTrieNodeHeader, prop) as u32;
const NODE_LEFT_OFFSET: u32 = offset_of!(RawTrieNodeHeader, left) as u32;
const NODE_RIGHT_OFFSET: u32 = offset_of!(RawTrieNodeHeader, right) as u32;
const NODE_CHILDREN_OFFSET: u32 = offset_of!(RawTrieNodeHeader, children) as u32;

const PROP_SERIAL_OFFSET: u32 = offset_of!(RawPropInfoHeader, serial) as u32;

pub type Result<T> = std::result::Result<T, PropAreaError>;

/// Information returned by [`PropArea::set_property_no_serial`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropWriteResult {
    /// Offset of the `prop_info` record within the data region.
    /// The file-absolute offset is `PROP_AREA_HEADER_SIZE + prop_offset`.
    pub prop_offset: u32,
    /// Previous prop serial for update operations; `0` when a new prop was
    /// created.
    pub serial: u32,
    /// `true` when a new property was created; `false` when an existing one
    /// was updated.
    pub created: bool,
    /// Length encoded into serial high bits (`serial >> 24`).
    /// For long properties this is the legacy inline error message length.
    pub serial_len: u32,
    /// Whether the property uses long-value layout.
    pub is_long: bool,
}

#[derive(Debug)]
pub enum PropAreaError {
    Io(io::Error),
    Utf8(std::string::FromUtf8Error),
    AreaTooSmall(u64),
    AreaTooLarge(u64),
    InvalidMagic(u32),
    InvalidVersion(u32),
    InvalidBytesUsed(u32),
    InvalidOffset(u32, String),
    InvalidKey(String),
    InPlaceUpdateTooLong {
        name: String,
        new_len: usize,
        max_len: usize,
    },
    Corrupted(&'static str),
    AreaFull {
        requested: u32,
        available: u32,
    },
}

impl fmt::Display for PropAreaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Utf8(err) => write!(f, "utf8 error: {err}"),
            Self::AreaTooSmall(size) => write!(f, "prop area too small: {size} bytes"),
            Self::AreaTooLarge(size) => write!(f, "prop area too large: {size} bytes"),
            Self::InvalidMagic(magic) => write!(f, "invalid prop area magic: 0x{magic:08x}"),
            Self::InvalidVersion(version) => {
                write!(f, "invalid prop area version: 0x{version:08x}")
            }
            Self::InvalidBytesUsed(bytes_used) => {
                write!(f, "invalid bytes_used value: {bytes_used}")
            }
            Self::InvalidOffset(offset, detail) => write!(f, "invalid data offset: {offset} ({detail})"),
            Self::InvalidKey(key) => write!(f, "invalid property key: {key}"),
            Self::InPlaceUpdateTooLong {
                name,
                new_len,
                max_len,
            } => write!(
                f,
                "cannot update property '{name}' in place: new value length {new_len} exceeds max {max_len}"
            ),
            Self::Corrupted(message) => write!(f, "corrupted prop area: {message}"),
            Self::AreaFull {
                requested,
                available,
            } => write!(
                f,
                "prop area is full: requested {requested} bytes, only {available} bytes available"
            ),
        }
    }
}

impl std::error::Error for PropAreaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Utf8(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for PropAreaError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<std::string::FromUtf8Error> for PropAreaError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        Self::Utf8(value)
    }
}

#[derive(Debug, Clone)]
struct TrieNodeRecord {
    offset: u32,
    namelen: u32,
    prop: u32,
    left: u32,
    right: u32,
    children: u32,
    name: String,
}

#[derive(Debug, Clone)]
struct PropRecord {
    name: String,
    value: String,
    prop_offset: u32,
    value_offset: u32,
    is_long: bool,
    serial: u32,
}

pub struct PropArea<M> {
    inner: M,
    area_size: u64,
    data_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PropAreaObjectKind {
    TrieNode {
        left: u32,
        right: u32,
        children: u32,
        prop: u32,
        /// This prop trie node doesn't have child or prop
        unused: bool,
        /// This prop trie node has an offset field whose value smaller than its offset
        abnormal_offset: bool,
        /// This prop trie node doesn't have children, but its prop doesn't follow it
        abnormal_prop: bool,
    },
    DirtyBackup,
    PropInfo {
        serial: u32,
        long_value_offset: Option<u32>,
        /// There are some bytes after the end of the value, is usually checked for ro props
        /// or bootloader lock related props.
        unclear_value: bool,
        /// Its long value doesn't follow it
        abnormal_long_value: bool,
        abnormal_serial: bool,
    },
    LongValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropAreaObjectInfo {
    pub kind: PropAreaObjectKind,
    pub offset: u32,
    pub size: u32,
    pub aligned_size: u32,
    pub end_offset: u32,
    pub aligned_end_offset: u32,
    pub detail: String,
    pub abnormal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropAreaHoleInfo {
    pub start_offset: u32,
    pub end_offset: u32,
    pub size: u32,
    pub aligned_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropAreaAllocationScan {
    pub bytes_used: u32,
    pub has_dirty_backup: bool,
    pub objects: Vec<PropAreaObjectInfo>,
    pub holes: Vec<PropAreaHoleInfo>,
    pub has_abnormal: bool,
}

impl<M: Read + Seek> PropArea<M> {
    pub fn new(inner: M) -> Result<Self> {
        let mut inner = inner;
        let area_size = inner.seek(SeekFrom::End(0))?;
        Self::from_inner_with_size(inner, area_size)
    }

    pub fn area_size(&self) -> u64 {
        self.area_size
    }

    pub fn data_size(&self) -> u32 {
        self.data_size
    }

    pub fn into_inner(self) -> M {
        self.inner
    }

    pub fn get_property(&mut self, key: &str) -> Result<Option<String>> {
        Ok(self
            .get_property_info(key)?
            .map(|property_info| property_info.value))
    }

    pub fn get_property_info(&mut self, key: &str) -> Result<Option<PropertyInfo>> {
        let node_offset = match self.traverse_trie(key)? {
            Some(offset) => offset,
            None => return Ok(None),
        };

        let prop_offset = self.read_u32_data(node_offset + NODE_PROP_OFFSET)?;
        if prop_offset == 0 {
            return Ok(None);
        }

        let record = self.read_prop_record(prop_offset)?;
        Ok(Some(self.to_property_info(record)))
    }

    pub fn for_each_property<F>(&mut self, mut callback: F) -> Result<()>
    where
        F: FnMut(PropertyInfo),
    {
        let mut visited = BTreeSet::new();
        self.for_each_from(0, &mut visited, &mut callback)
    }

    pub fn for_each_property_info<F>(&mut self, callback: F) -> Result<()>
    where
        F: FnMut(PropertyInfo),
    {
        self.for_each_property(callback)
    }

    pub fn scan_allocations(&mut self) -> Result<PropAreaAllocationScan> {
        let bytes_used = self.bytes_used()?;
        let has_dirty_backup = self.has_dirty_backup()?;

        let mut objects = Vec::new();
        let mut stack = BTreeSet::new();
        let mut seen_nodes = BTreeSet::new();
        let mut seen_props = BTreeSet::new();
        let mut seen_longs = BTreeSet::new();
        let mut has_abnormal = false;

        if has_dirty_backup {
            objects.push(Self::make_scan_object(
                PropAreaObjectKind::DirtyBackup,
                PROP_TRIE_NODE_HEADER_SIZE,
                DIRTY_BACKUP_SIZE,
                "<dirty-backup>".to_owned(),
                false,
            )?);
        }

        self.scan_allocations_from(
            0,
            &mut stack,
            &mut seen_nodes,
            &mut seen_props,
            &mut seen_longs,
            &mut objects,
            &mut has_abnormal,
        )?;

        objects.sort_by(|a, b| {
            a.offset
                .cmp(&b.offset)
                .then(a.kind.cmp(&b.kind))
                .then(a.aligned_end_offset.cmp(&b.aligned_end_offset))
        });

        for object in &objects {
            if object.aligned_end_offset > bytes_used {
                return Err(PropAreaError::Corrupted(
                    "allocation object extends beyond bytes_used",
                ));
            }
        }

        let mut holes = Vec::new();
        let initial_cursor = if has_dirty_backup {
            INITIAL_BYTES_USED
        } else {
            PROP_TRIE_NODE_HEADER_SIZE
        };
        let mut cursor = initial_cursor.min(bytes_used);

        for object in &objects {
            if object.offset > cursor {
                holes.push(Self::make_scan_hole(cursor, object.offset));
            }
            if object.aligned_end_offset > cursor {
                cursor = object.aligned_end_offset;
            }
        }

        if bytes_used > cursor {
            holes.push(Self::make_scan_hole(cursor, bytes_used));
        }

        Ok(PropAreaAllocationScan {
            bytes_used,
            has_dirty_backup,
            objects,
            holes,
            has_abnormal,
        })
    }

    fn has_dirty_backup(&mut self) -> Result<bool> {
        let root = self.read_node(0)?;

        if root.children != 0 && root.children == PROP_TRIE_NODE_HEADER_SIZE {
            return Ok(false);
        }

        if root.children == 0 {
            return Ok(self.bytes_used()? == INITIAL_BYTES_USED);
        }

        Ok(true)
    }

    fn from_inner_with_size(inner: M, area_size: u64) -> Result<Self> {
        if area_size < PROP_AREA_HEADER_SIZE {
            return Err(PropAreaError::AreaTooSmall(area_size));
        }

        let data_size = area_size
            .checked_sub(PROP_AREA_HEADER_SIZE)
            .ok_or(PropAreaError::AreaTooSmall(area_size))?;
        let data_size =
            u32::try_from(data_size).map_err(|_| PropAreaError::AreaTooLarge(area_size))?;

        let mut this = Self {
            inner,
            area_size,
            data_size,
        };

        let magic = this.read_u32_abs(MAGIC_OFFSET)?;
        if magic != PROP_AREA_MAGIC {
            return Err(PropAreaError::InvalidMagic(magic));
        }

        let version = this.read_u32_abs(VERSION_OFFSET)?;
        if version != PROP_AREA_VERSION {
            return Err(PropAreaError::InvalidVersion(version));
        }

        let bytes_used = this.bytes_used()?;
        if bytes_used < PROP_TRIE_NODE_HEADER_SIZE || bytes_used > this.data_size {
            return Err(PropAreaError::InvalidBytesUsed(bytes_used));
        }

        Ok(this)
    }

    fn bytes_used(&mut self) -> Result<u32> {
        self.read_u32_abs(BYTES_USED_OFFSET)
    }

    fn validate_key<'a>(&self, key: &'a str) -> Result<Vec<&'a str>> {
        if key.is_empty() {
            return Err(PropAreaError::InvalidKey(key.to_owned()));
        }

        let segments: Vec<_> = key.split('.').collect();
        if segments.iter().any(|segment| segment.is_empty()) {
            return Err(PropAreaError::InvalidKey(key.to_owned()));
        }

        Ok(segments)
    }

    fn traverse_trie(&mut self, key: &str) -> Result<Option<u32>> {
        let segments = self.validate_key(key)?;
        let mut current_offset = 0u32;

        for segment in segments {
            let current = self.read_node(current_offset)?;
            if current.children == 0 {
                return Ok(None);
            }

            let next = self.find_sibling(current.children, segment)?;
            let Some(next_offset) = next else {
                return Ok(None);
            };
            current_offset = next_offset;
        }

        Ok(Some(current_offset))
    }

    fn find_sibling(&mut self, root_offset: u32, target: &str) -> Result<Option<u32>> {
        let mut current_offset = root_offset;
        let max_steps = usize::max(
            1,
            self.data_size as usize / PROP_TRIE_NODE_HEADER_SIZE as usize,
        );

        for _ in 0..max_steps {
            let current = self.read_node(current_offset)?;
            match cmp_prop_name(target, &current.name) {
                std::cmp::Ordering::Equal => return Ok(Some(current_offset)),
                std::cmp::Ordering::Less => {
                    if current.left == 0 {
                        return Ok(None);
                    }
                    current_offset = current.left;
                }
                std::cmp::Ordering::Greater => {
                    if current.right == 0 {
                        return Ok(None);
                    }
                    current_offset = current.right;
                }
            }
        }

        Err(PropAreaError::Corrupted("possible cycle in sibling tree"))
    }

    fn read_node(&mut self, offset: u32) -> Result<TrieNodeRecord> {
        let header = self.read_data(offset, PROP_TRIE_NODE_HEADER_SIZE)?;
        let namelen = read_u32_at(&header, offset_of!(RawTrieNodeHeader, namelen));
        let prop = read_u32_at(&header, offset_of!(RawTrieNodeHeader, prop));
        let left = read_u32_at(&header, offset_of!(RawTrieNodeHeader, left));
        let right = read_u32_at(&header, offset_of!(RawTrieNodeHeader, right));
        let children = read_u32_at(&header, offset_of!(RawTrieNodeHeader, children));

        let name = if namelen == 0 {
            String::new()
        } else {
            self.read_c_string(offset + PROP_TRIE_NODE_HEADER_SIZE, Some(namelen + 1))?
        };

        Ok(TrieNodeRecord {
            offset,
            namelen,
            prop,
            left,
            right,
            children,
            name,
        })
    }

    fn read_prop_record(&mut self, prop_offset: u32) -> Result<PropRecord> {
        let header = self.read_data(prop_offset, PROP_INFO_SIZE)?;
        let name = self.read_c_string(prop_offset + PROP_INFO_SIZE, None)?;
        let is_long = self.is_long_prop(&header);
        let serial = read_u32_at(&header, offset_of!(RawPropInfoHeader, serial));

        let value_offset = if is_long {
            let long_offset = read_u32_at(
                &header,
                offset_of!(RawPropInfoHeader, value) + offset_of!(RawLongProperty, offset),
            );
            let min_long_offset = align_up(PROP_INFO_SIZE + name.len() as u32 + 1, 4);
            if long_offset < min_long_offset {
                return Err(PropAreaError::Corrupted(
                    "long property offset points into prop_info",
                ));
            }

            prop_offset
                .checked_add(long_offset)
                .ok_or(PropAreaError::InvalidOffset(
                    prop_offset,
                    format!("long offset of prop offset {prop_offset}"),
                ))?
        } else {
            prop_offset + offset_of!(RawPropInfoHeader, value) as u32
        };

        let value =
            if is_long {
                self.read_c_string(value_offset, None)?
            } else {
                let raw_value = &header[4..4 + PROP_VALUE_MAX];
                let end = raw_value.iter().position(|byte| *byte == 0).ok_or(
                    PropAreaError::Corrupted("inline property value is not null terminated"),
                )?;
                String::from_utf8(raw_value[..end].to_vec())?
            };

        Ok(PropRecord {
            name,
            value,
            prop_offset,
            value_offset,
            is_long,
            serial,
        })
    }

    fn is_long_prop(&self, header: &[u8]) -> bool {
        let serial = read_u32_at(header, offset_of!(RawPropInfoHeader, serial));
        (serial & PROP_INFO_LONG_FLAG) != 0
    }

    fn for_each_from<F>(
        &mut self,
        offset: u32,
        visited: &mut BTreeSet<u32>,
        callback: &mut F,
    ) -> Result<()>
    where
        F: FnMut(PropertyInfo),
    {
        if !visited.insert(offset) {
            return Err(PropAreaError::Corrupted(
                "cycle detected while iterating trie",
            ));
        }

        let node = self.read_node(offset)?;
        if node.left != 0 {
            self.for_each_from(node.left, visited, callback)?;
        }

        if node.prop != 0 {
            let record = self.read_prop_record(node.prop)?;
            callback(self.to_property_info(record));
        }

        if node.children != 0 {
            self.for_each_from(node.children, visited, callback)?;
        }

        if node.right != 0 {
            self.for_each_from(node.right, visited, callback)?;
        }

        visited.remove(&offset);
        Ok(())
    }

    fn scan_allocations_from(
        &mut self,
        offset: u32,
        stack: &mut BTreeSet<u32>,
        seen_nodes: &mut BTreeSet<u32>,
        seen_props: &mut BTreeSet<u32>,
        seen_longs: &mut BTreeSet<u32>,
        objects: &mut Vec<PropAreaObjectInfo>,
        has_abnormal: &mut bool,
    ) -> Result<()> {
        if seen_nodes.contains(&offset) {
            return Ok(());
        }

        if !stack.insert(offset) {
            return Err(PropAreaError::Corrupted(
                "cycle detected while scanning allocation trie",
            ));
        }

        let node = self.read_node(offset)?;
        seen_nodes.insert(offset);

        let trie_size = if node.namelen == 0 {
            PROP_TRIE_NODE_HEADER_SIZE
        } else {
            PROP_TRIE_NODE_HEADER_SIZE
                .checked_add(node.namelen)
                .and_then(|v| v.checked_add(1))
                .ok_or(PropAreaError::InvalidOffset(
                    node.offset,
                    format!(
                        "trie at offset {offset} has invalid name size {}",
                        node.namelen
                    ),
                ))?
        };

        let trie_detail = if node.namelen == 0 {
            "<root>".to_owned()
        } else {
            node.name.clone()
        };

        let unused = node.prop == 0 && node.children == 0 && offset != 0;
        let abnormal_offset = (node.left != 0 && node.left <= offset)
            || (node.right != 0 && node.right <= offset)
            || (node.children != 0 && node.children <= offset)
            || (node.prop != 0 && node.prop <= offset);
        let abnormal_prop = node.children == 0
            && node.prop != 0
            && (node.prop != offset + PROP_TRIE_NODE_HEADER_SIZE + align_up(node.namelen + 1, 4));
        let abnormal = unused || abnormal_offset || abnormal_prop;
        *has_abnormal |= abnormal;

        objects.push(Self::make_scan_object(
            PropAreaObjectKind::TrieNode {
                left: node.left,
                right: node.right,
                children: node.children,
                prop: node.prop,
                unused,
                abnormal_offset,
                abnormal_prop,
            },
            node.offset,
            trie_size,
            trie_detail,
            abnormal,
        )?);

        if node.prop != 0 && seen_props.insert(node.prop) {
            let record = self.read_prop_record(node.prop)?;

            let name_len = u32::try_from(record.name.len())
                .map_err(|_| PropAreaError::Corrupted("property name too long"))?;
            let prop_size = PROP_INFO_SIZE
                .checked_add(name_len)
                .and_then(|v| v.checked_add(1))
                .ok_or(PropAreaError::InvalidOffset(
                    record.prop_offset,
                    format!(
                        "prop at offset {} has invalid name len {name_len}",
                        node.prop
                    ),
                ))?;

            let value_len = record.value.len() as u32 + 1;
            let value_max = if record.is_long {
                align_up(value_len, 4)
            } else {
                PROP_VALUE_MAX as u32
            };
            let is_ro = record.name.starts_with("ro.");
            let unclear_value = if is_ro && value_len < value_max as u32 {
                let end = record.value_offset.add(value_len);
                self.read_data(end, value_max - value_len)?
                    .iter()
                    .any(|c| *c != 0)
            } else {
                false
            };

            let abnormal_long_value = record.is_long
                && record.value_offset != align_up(node.prop + PROP_INFO_SIZE + name_len + 1, 4);
            let abnormal_serial =
                is_ro && ((record.serial & 0x00ff_ffff & !PROP_INFO_LONG_FLAG) >> 1) != 0;
            let abnormal = unclear_value || abnormal_long_value || abnormal_serial;
            *has_abnormal |= abnormal;

            objects.push(Self::make_scan_object(
                PropAreaObjectKind::PropInfo {
                    serial: record.serial,
                    long_value_offset: if record.is_long {
                        Some(record.value_offset)
                    } else {
                        None
                    },
                    unclear_value,
                    abnormal_long_value,
                    abnormal_serial,
                },
                record.prop_offset,
                prop_size,
                record.name.clone(),
                abnormal,
            )?);

            if record.is_long && seen_longs.insert(record.value_offset) {
                let value_len = u32::try_from(record.value.len())
                    .map_err(|_| PropAreaError::Corrupted("long value too long"))?;
                let long_size = value_len
                    .checked_add(1)
                    .ok_or(PropAreaError::InvalidOffset(
                        record.value_offset,
                        format!(
                            "long prop at {} has invalid value len {value_len}",
                            node.prop
                        ),
                    ))?;

                objects.push(Self::make_scan_object(
                    PropAreaObjectKind::LongValue,
                    record.value_offset,
                    long_size,
                    record.name,
                    abnormal_long_value || unclear_value,
                )?);
            }
        }

        if node.left != 0 {
            self.scan_allocations_from(
                node.left,
                stack,
                seen_nodes,
                seen_props,
                seen_longs,
                objects,
                has_abnormal,
            )?;
        }

        if node.children != 0 {
            self.scan_allocations_from(
                node.children,
                stack,
                seen_nodes,
                seen_props,
                seen_longs,
                objects,
                has_abnormal,
            )?;
        }

        if node.right != 0 {
            self.scan_allocations_from(
                node.right,
                stack,
                seen_nodes,
                seen_props,
                seen_longs,
                objects,
                has_abnormal,
            )?;
        }

        stack.remove(&offset);
        Ok(())
    }

    fn make_scan_object(
        kind: PropAreaObjectKind,
        offset: u32,
        size: u32,
        detail: String,
        abnormal: bool,
    ) -> Result<PropAreaObjectInfo> {
        let aligned_size = align_up(size, 4);
        let end_offset = offset
            .checked_add(size)
            .ok_or(PropAreaError::InvalidOffset(
                offset,
                format!("overflow end_offset at offset {offset} size {size}"),
            ))?;
        let aligned_end_offset =
            offset
                .checked_add(aligned_size)
                .ok_or(PropAreaError::InvalidOffset(
                    offset,
                    format!("overflow aligned_end_offset at offset {offset} size {size}"),
                ))?;

        Ok(PropAreaObjectInfo {
            kind,
            offset,
            size,
            aligned_size,
            end_offset,
            aligned_end_offset,
            detail,
            abnormal,
        })
    }

    fn make_scan_hole(start_offset: u32, end_offset: u32) -> PropAreaHoleInfo {
        let size = end_offset.saturating_sub(start_offset);
        PropAreaHoleInfo {
            start_offset,
            end_offset,
            size,
            aligned_size: align_up(size, 4),
        }
    }

    fn to_property_info(&self, record: PropRecord) -> PropertyInfo {
        PropertyInfo {
            name: record.name,
            value: record.value,
            prop_offset: record.prop_offset,
            name_offset: record.prop_offset + PROP_INFO_SIZE,
            value_offset: record.value_offset,
            is_long: record.is_long,
        }
    }

    fn read_u32_abs(&mut self, absolute_offset: u64) -> Result<u32> {
        let mut bytes = [0u8; 4];
        self.inner.seek(SeekFrom::Start(absolute_offset))?;
        self.inner.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u32_data(&mut self, data_offset: u32) -> Result<u32> {
        let absolute_offset = self.check_range(data_offset, 4)?;
        self.read_u32_abs(absolute_offset)
    }

    fn read_data(&mut self, data_offset: u32, len: u32) -> Result<Vec<u8>> {
        let absolute_offset = self.check_range(data_offset, len)?;
        let mut buffer = vec![0u8; len as usize];
        self.inner.seek(SeekFrom::Start(absolute_offset))?;
        self.inner.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn read_c_string(&mut self, data_offset: u32, max_len: Option<u32>) -> Result<String> {
        let bytes = self.read_c_string_bytes(data_offset, max_len)?;
        Ok(String::from_utf8(bytes)?)
    }

    fn read_c_string_bytes(&mut self, data_offset: u32, max_len: Option<u32>) -> Result<Vec<u8>> {
        let limit = max_len.unwrap_or(self.data_size.saturating_sub(data_offset));
        if data_offset > self.data_size {
            return Err(PropAreaError::InvalidOffset(
                data_offset,
                format!("read c string at {data_offset}"),
            ));
        }

        // Read in chunks sized to cover typical property names and values in
        // one or two reads.  PROP_VALUE_MAX (92) covers most inline values;
        // names are even shorter (PROP_NAME_MAX = 32).
        const CHUNK: u32 = PROP_VALUE_MAX as u32;

        let mut bytes = Vec::new();
        let mut cursor = 0u32;
        while cursor < limit {
            let remaining = limit - cursor;
            let to_read = remaining.min(CHUNK);
            let abs = self.check_range(data_offset + cursor, to_read)?;
            let mut buf = vec![0u8; to_read as usize];
            self.inner.seek(SeekFrom::Start(abs))?;
            self.inner.read_exact(&mut buf)?;

            if let Some(nul_pos) = buf.iter().position(|&b| b == 0) {
                bytes.extend_from_slice(&buf[..nul_pos]);
                return Ok(bytes);
            }
            bytes.extend_from_slice(&buf);
            cursor += to_read;
        }

        Err(PropAreaError::Corrupted("unterminated c string"))
    }

    fn check_range(&self, data_offset: u32, len: u32) -> Result<u64> {
        let end = data_offset
            .checked_add(len)
            .ok_or(PropAreaError::InvalidOffset(
                data_offset,
                format!("check_range {data_offset} {len}"),
            ))?;
        if end > self.data_size {
            return Err(PropAreaError::InvalidOffset(
                data_offset,
                format!("check_range {data_offset} {len}"),
            ));
        }
        Ok(PROP_AREA_HEADER_SIZE + data_offset as u64)
    }
}

impl<M: Read + Write + Seek> PropArea<M> {
    pub fn create(mut inner: M, area_size: u64) -> Result<Self> {
        if area_size < PROP_AREA_HEADER_SIZE + PROP_TRIE_NODE_HEADER_SIZE as u64 {
            return Err(PropAreaError::AreaTooSmall(area_size));
        }

        zero_fill(&mut inner, area_size)?;
        inner.seek(SeekFrom::Start(BYTES_USED_OFFSET))?;
        inner.write_all(&INITIAL_BYTES_USED.to_le_bytes())?;
        inner.write_all(&0u32.to_le_bytes())?;
        inner.write_all(&PROP_AREA_MAGIC.to_le_bytes())?;
        inner.write_all(&PROP_AREA_VERSION.to_le_bytes())?;
        inner.flush()?;

        Self::from_inner_with_size(inner, area_size)
    }

    /// Set (or create) a property and write serial in non-atomic file mode.
    ///
    /// This path is for offline/non-shared edits where plain writes are
    /// acceptable. Runtime shared-memory writers should use
    /// [`PropArea::set_property_no_serial`] and publish serial with atomics in
    /// the caller.
    pub fn set_property(&mut self, key: &str, value: &str) -> Result<()> {
        let write = self.set_property_no_serial(key, value)?;
        let serial = if write.created {
            compose_initial_serial(write.serial_len, write.is_long)
        } else {
            compose_updated_serial(write.serial, write.serial_len, write.is_long)
        };
        self.write_u32_data(write.prop_offset + PROP_SERIAL_OFFSET, serial)?;
        Ok(())
    }

    /// Set (or create) a property while leaving serial publication to caller.
    ///
    /// This method updates only value bytes and layout metadata required to
    /// locate the value (including long-value offset when needed). It does not
    /// publish a new serial; caller should do it with platform-appropriate
    /// atomics/futex ordering.
    pub fn set_property_no_serial(&mut self, key: &str, value: &str) -> Result<PropWriteResult> {
        let node_offset = self.ensure_traverse_trie(key)?;
        let prop_offset = self.read_u32_data(node_offset + NODE_PROP_OFFSET)?;

        if prop_offset == 0 {
            let is_long = value.len() >= PROP_VALUE_MAX;
            let serial_len = self.serial_len_for_layout(value, is_long)?;
            let new_prop_offset = self.create_prop_info_no_serial(key, value)?;
            self.write_u32_data(node_offset + NODE_PROP_OFFSET, new_prop_offset)?;
            return Ok(PropWriteResult {
                prop_offset: new_prop_offset,
                serial: 0,
                created: true,
                serial_len,
                is_long,
            });
        }

        let record = self.read_prop_record(prop_offset)?;
        let old_serial = self.read_u32_data(prop_offset + PROP_SERIAL_OFFSET)?;
        let serial_len = self.serial_len_for_layout(value, record.is_long)?;
        let result = if record.is_long {
            self.update_long_property_no_serial(prop_offset, &record.name, value)
        } else {
            self.update_inline_property_in_place_no_serial(prop_offset, &record.name, value)
        };

        match result {
            Ok(()) => Ok(PropWriteResult {
                prop_offset,
                serial: old_serial,
                created: false,
                serial_len,
                is_long: record.is_long,
            }),
            Err(PropAreaError::InPlaceUpdateTooLong { .. }) => {
                // Value doesn't fit in the current slot (inline -> long, or
                // long value grew beyond its allocation). Delete without
                // pruning and re-create so the new allocation can accommodate
                // the larger value.
                self.write_u32_data(node_offset + NODE_PROP_OFFSET, 0)?;
                self.wipe_prop_info(prop_offset)?;
                let is_long = value.len() >= PROP_VALUE_MAX;
                let serial_len = self.serial_len_for_layout(value, is_long)?;
                let new_prop_offset = self.create_prop_info_no_serial(key, value)?;
                self.write_u32_data(node_offset + NODE_PROP_OFFSET, new_prop_offset)?;
                Ok(PropWriteResult {
                    prop_offset: new_prop_offset,
                    serial: 0,
                    created: true,
                    serial_len,
                    is_long,
                })
            }
            Err(e) => Err(e),
        }
    }

    pub fn delete_property(&mut self, key: &str) -> Result<bool> {
        self.delete_property_inner(key, true)
    }

    /// Delete a property without pruning empty trie nodes.
    ///
    /// This is useful for the delete+add pattern (e.g. when converting an
    /// inline property to a long property) where the trie node will be reused
    /// immediately after deletion.
    pub fn delete_property_no_prune(&mut self, key: &str) -> Result<bool> {
        self.delete_property_inner(key, false)
    }

    fn delete_property_inner(&mut self, key: &str, prune: bool) -> Result<bool> {
        let Some(node_offset) = self.traverse_trie(key)? else {
            return Ok(false);
        };

        let prop_offset = self.read_u32_data(node_offset + NODE_PROP_OFFSET)?;
        if prop_offset == 0 {
            return Ok(false);
        }

        self.write_u32_data(node_offset + NODE_PROP_OFFSET, 0)?;
        self.wipe_prop_info(prop_offset)?;
        if prune {
            let _ = self.prune_trie(0)?;
        }
        Ok(true)
    }

    fn ensure_traverse_trie(&mut self, key: &str) -> Result<u32> {
        let segments = self.validate_key(key)?;
        let mut current_offset = 0u32;

        for segment in segments {
            let current = self.read_node(current_offset)?;
            let child_root = if current.children != 0 {
                current.children
            } else {
                let new_offset = self.create_trie_node(segment)?;
                self.write_u32_data(current.offset + NODE_CHILDREN_OFFSET, new_offset)?;
                new_offset
            };

            current_offset = self.ensure_sibling(child_root, segment)?;
        }

        Ok(current_offset)
    }

    fn ensure_sibling(&mut self, root_offset: u32, target: &str) -> Result<u32> {
        let mut current_offset = root_offset;
        let max_steps = usize::max(
            1,
            self.data_size as usize / PROP_TRIE_NODE_HEADER_SIZE as usize,
        );

        for _ in 0..max_steps {
            let current = self.read_node(current_offset)?;
            match cmp_prop_name(target, &current.name) {
                std::cmp::Ordering::Equal => return Ok(current_offset),
                std::cmp::Ordering::Less => {
                    if current.left != 0 {
                        current_offset = current.left;
                    } else {
                        let new_offset = self.create_trie_node(target)?;
                        self.write_u32_data(current.offset + NODE_LEFT_OFFSET, new_offset)?;
                        return Ok(new_offset);
                    }
                }
                std::cmp::Ordering::Greater => {
                    if current.right != 0 {
                        current_offset = current.right;
                    } else {
                        let new_offset = self.create_trie_node(target)?;
                        self.write_u32_data(current.offset + NODE_RIGHT_OFFSET, new_offset)?;
                        return Ok(new_offset);
                    }
                }
            }
        }

        Err(PropAreaError::Corrupted(
            "possible cycle while inserting sibling node",
        ))
    }

    fn create_trie_node(&mut self, name: &str) -> Result<u32> {
        let name_len =
            u32::try_from(name.len()).map_err(|_| PropAreaError::Corrupted("name too long"))?;
        let node_size = PROP_TRIE_NODE_HEADER_SIZE + name_len + 1;
        let offset = self.allocate_obj(node_size)?;

        self.write_u32_data(offset, name_len)?;
        self.write_u32_data(offset + NODE_PROP_OFFSET, 0)?;
        self.write_u32_data(offset + NODE_LEFT_OFFSET, 0)?;
        self.write_u32_data(offset + NODE_RIGHT_OFFSET, 0)?;
        self.write_u32_data(offset + NODE_CHILDREN_OFFSET, 0)?;
        self.write_bytes_data(offset + PROP_TRIE_NODE_HEADER_SIZE, name.as_bytes())?;
        self.write_bytes_data(offset + PROP_TRIE_NODE_HEADER_SIZE + name_len, &[0])?;

        Ok(offset)
    }

    fn serial_len_for_layout(&self, value: &str, is_long: bool) -> Result<u32> {
        if is_long {
            u32::try_from(LONG_LEGACY_ERROR.len())
                .map_err(|_| PropAreaError::Corrupted("legacy error marker too long"))
        } else {
            u32::try_from(value.len())
                .map_err(|_| PropAreaError::Corrupted("value length overflow"))
        }
    }

    fn create_prop_info_no_serial(&mut self, name: &str, value: &str) -> Result<u32> {
        let name_len =
            u32::try_from(name.len()).map_err(|_| PropAreaError::Corrupted("name too long"))?;
        let prop_offset = self.allocate_obj(PROP_INFO_SIZE + name_len + 1)?;

        self.write_u32_data(prop_offset, 0)?;
        if value.len() >= PROP_VALUE_MAX {
            self.write_long_layout_no_serial(prop_offset, name_len, value)?;
        } else {
            self.initialize_inline_property_no_serial(prop_offset, value)?;
        }

        self.write_bytes_data(prop_offset + PROP_INFO_SIZE, name.as_bytes())?;
        self.write_bytes_data(prop_offset + PROP_INFO_SIZE + name_len, &[0])?;
        Ok(prop_offset)
    }

    fn write_inline_value_bytes(&mut self, prop_offset: u32, value: &str) -> Result<()> {
        if value.len() >= PROP_VALUE_MAX {
            return Err(PropAreaError::Corrupted("inline property value too large"));
        }

        self.zero_data(prop_offset + 4, PROP_VALUE_MAX as u32)?;
        self.write_bytes_data(prop_offset + 4, value.as_bytes())?;
        self.write_bytes_data(prop_offset + 4 + value.len() as u32, &[0])?;
        Ok(())
    }

    fn initialize_inline_property_no_serial(
        &mut self,
        prop_offset: u32,
        value: &str,
    ) -> Result<()> {
        if value.len() >= PROP_VALUE_MAX {
            return Err(PropAreaError::Corrupted("inline property value too large"));
        }

        self.write_inline_value_bytes(prop_offset, value)?;
        Ok(())
    }

    fn update_inline_property_in_place_no_serial(
        &mut self,
        prop_offset: u32,
        name: &str,
        value: &str,
    ) -> Result<()> {
        if value.len() >= PROP_VALUE_MAX {
            return Err(PropAreaError::InPlaceUpdateTooLong {
                name: name.to_owned(),
                new_len: value.len(),
                max_len: PROP_VALUE_MAX - 1,
            });
        }

        self.write_inline_value_bytes(prop_offset, value)?;
        Ok(())
    }

    fn update_long_property_no_serial(
        &mut self,
        prop_offset: u32,
        name: &str,
        value: &str,
    ) -> Result<()> {
        let header = self.read_data(prop_offset, PROP_INFO_SIZE)?;
        let current_rel = read_u32_at(
            &header,
            offset_of!(RawPropInfoHeader, value) + offset_of!(RawLongProperty, offset),
        );
        let current_offset =
            prop_offset
                .checked_add(current_rel)
                .ok_or(PropAreaError::InvalidOffset(
                    prop_offset,
                    format!("get long value offset {prop_offset} {current_rel}"),
                ))?;
        let current_bytes = self.read_c_string_bytes(current_offset, None)?;
        let current_len = current_bytes.len();
        if value.len() > current_len {
            return Err(PropAreaError::InPlaceUpdateTooLong {
                name: name.to_owned(),
                new_len: value.len(),
                max_len: current_len,
            });
        }
        let current_capacity = current_len as u32 + 1;

        self.zero_data(current_offset, current_capacity)?;
        self.write_bytes_data(current_offset, value.as_bytes())?;
        self.write_bytes_data(current_offset + value.len() as u32, &[0])?;
        Ok(())
    }

    fn write_long_layout_no_serial(
        &mut self,
        prop_offset: u32,
        name_len: u32,
        value: &str,
    ) -> Result<()> {
        let long_value_size = u32::try_from(value.len() + 1)
            .map_err(|_| PropAreaError::Corrupted("value too large to store"))?;
        let long_value_offset = self.allocate_obj(long_value_size)?;
        let relative_offset =
            long_value_offset
                .checked_sub(prop_offset)
                .ok_or(PropAreaError::InvalidOffset(
                    long_value_offset,
                    format!("long_value_offset {long_value_offset} - prop_offset {prop_offset}"),
                ))?;
        let min_expected = align_up(PROP_INFO_SIZE + name_len + 1, 4);
        if relative_offset < min_expected {
            return Err(PropAreaError::Corrupted("invalid long value placement"));
        }

        self.zero_data(prop_offset + 4, PROP_VALUE_MAX as u32)?;
        self.write_bytes_data(prop_offset + 4, LONG_LEGACY_ERROR.as_bytes())?;
        self.write_bytes_data(prop_offset + 4 + LONG_LEGACY_ERROR.len() as u32, &[0])?;
        self.write_u32_data(prop_offset + LONG_OFFSET_IN_INFO, relative_offset)?;

        self.write_bytes_data(long_value_offset, value.as_bytes())?;
        self.write_bytes_data(long_value_offset + value.len() as u32, &[0])?;
        Ok(())
    }

    fn wipe_prop_info(&mut self, prop_offset: u32) -> Result<()> {
        let record = self.read_prop_record(prop_offset)?;
        if record.is_long {
            let value_len = record.value.len() as u32 + 1;
            self.zero_data(record.value_offset, value_len)?;
        }

        let name_len = record.name.len() as u32 + 1;
        self.zero_data(prop_offset + PROP_INFO_SIZE, name_len)?;
        self.zero_data(prop_offset, PROP_INFO_SIZE)?;
        Ok(())
    }

    fn prune_trie(&mut self, offset: u32) -> Result<bool> {
        let node = self.read_node(offset)?;
        let mut is_leaf = true;

        if node.children != 0 {
            if self.prune_trie(node.children)? {
                self.write_u32_data(offset + NODE_CHILDREN_OFFSET, 0)?;
            } else {
                is_leaf = false;
            }
        }
        if node.left != 0 {
            if self.prune_trie(node.left)? {
                self.write_u32_data(offset + NODE_LEFT_OFFSET, 0)?;
            } else {
                is_leaf = false;
            }
        }
        if node.right != 0 {
            if self.prune_trie(node.right)? {
                self.write_u32_data(offset + NODE_RIGHT_OFFSET, 0)?;
            } else {
                is_leaf = false;
            }
        }

        let prop = self.read_u32_data(offset + NODE_PROP_OFFSET)?;
        if is_leaf && prop == 0 {
            if node.namelen != 0 {
                self.zero_data(offset + PROP_TRIE_NODE_HEADER_SIZE, node.namelen + 1)?;
            }
            self.zero_data(offset, PROP_TRIE_NODE_HEADER_SIZE)?;
            return Ok(true);
        }

        Ok(false)
    }

    fn allocate_obj(&mut self, size: u32) -> Result<u32> {
        let aligned = align_up(size, 4);
        let bytes_used = self.bytes_used()?;
        let next = bytes_used
            .checked_add(aligned)
            .ok_or(PropAreaError::AreaFull {
                requested: aligned,
                available: self.data_size.saturating_sub(bytes_used),
            })?;

        if next > self.data_size {
            return Err(PropAreaError::AreaFull {
                requested: aligned,
                available: self.data_size.saturating_sub(bytes_used),
            });
        }

        self.write_u32_abs(BYTES_USED_OFFSET, next)?;
        self.zero_data(bytes_used, aligned)?;
        Ok(bytes_used)
    }

    fn write_u32_abs(&mut self, absolute_offset: u64, value: u32) -> Result<()> {
        self.inner.seek(SeekFrom::Start(absolute_offset))?;
        self.inner.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    fn write_u32_data(&mut self, data_offset: u32, value: u32) -> Result<()> {
        let absolute_offset = self.check_range(data_offset, 4)?;
        self.write_u32_abs(absolute_offset, value)
    }

    fn write_bytes_data(&mut self, data_offset: u32, bytes: &[u8]) -> Result<()> {
        let len =
            u32::try_from(bytes.len()).map_err(|_| PropAreaError::Corrupted("buffer too large"))?;
        let absolute_offset = self.check_range(data_offset, len)?;
        self.inner.seek(SeekFrom::Start(absolute_offset))?;
        self.inner.write_all(bytes)?;
        Ok(())
    }

    fn zero_data(&mut self, data_offset: u32, len: u32) -> Result<()> {
        let absolute_offset = self.check_range(data_offset, len)?;
        self.inner.seek(SeekFrom::Start(absolute_offset))?;
        let zeros = [0u8; 256];
        let mut remaining = len as usize;
        while remaining > 0 {
            let chunk = remaining.min(zeros.len());
            self.inner.write_all(&zeros[..chunk])?;
            remaining -= chunk;
        }
        Ok(())
    }
}

fn compose_initial_serial(value_len: u32, is_long: bool) -> u32 {
    let mut serial = value_len << 24;
    if is_long {
        serial |= PROP_INFO_LONG_FLAG;
    }

    serial
}

fn compose_updated_serial(old_serial: u32, value_len: u32, is_long: bool) -> u32 {
    let mut serial = value_len << 24;
    if is_long {
        serial |= PROP_INFO_LONG_FLAG;
    }

    // Match bionic Update(): serial|=1 in local, then publish ((serial+1)&0xffffff).
    let counter = (((old_serial & 0x00ff_ffff) | 1) + 1) & 0x00ff_ffff;

    serial | counter
}

fn read_u32_at(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

fn cmp_prop_name(one: &str, two: &str) -> std::cmp::Ordering {
    match one.len().cmp(&two.len()) {
        std::cmp::Ordering::Equal => one.as_bytes().cmp(two.as_bytes()),
        ordering => ordering,
    }
}

fn zero_fill<M: Write + Seek>(inner: &mut M, area_size: u64) -> Result<()> {
    inner.seek(SeekFrom::Start(0))?;
    let zeros = [0u8; 4096];
    let mut remaining = area_size;
    while remaining > 0 {
        let chunk = usize::try_from(remaining.min(zeros.len() as u64)).unwrap();
        inner.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    inner.flush()?;
    inner.seek(SeekFrom::Start(0))?;
    Ok(())
}
