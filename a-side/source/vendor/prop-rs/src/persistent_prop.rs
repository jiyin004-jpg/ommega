use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;

pub const ANDROID_PERSISTENT_PROP_DIR: &str = "/data/property";
pub const ANDROID_PERSISTENT_PROP_FILE: &str = "/data/property/persistent_properties";

pub type PersistentResult<T> = std::result::Result<T, PersistentPropError>;

#[derive(Debug)]
pub enum PersistentPropError {
    Io(io::Error),
    Decode(prost::DecodeError),
    Encode(prost::EncodeError),
    InvalidPath(PathBuf),
}

impl fmt::Display for PersistentPropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Decode(err) => write!(f, "protobuf decode error: {err}"),
            Self::Encode(err) => write!(f, "protobuf encode error: {err}"),
            Self::InvalidPath(path) => {
                write!(
                    f,
                    "invalid persistent property file path: {}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for PersistentPropError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Decode(err) => Some(err),
            Self::Encode(err) => Some(err),
            Self::InvalidPath(_) => None,
        }
    }
}

impl From<io::Error> for PersistentPropError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<prost::DecodeError> for PersistentPropError {
    fn from(value: prost::DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl From<prost::EncodeError> for PersistentPropError {
    fn from(value: prost::EncodeError) -> Self {
        Self::Encode(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentProperty {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistentPropertyFile {
    properties: Vec<PersistentProperty>,
}

impl PersistentPropertyFile {
    pub fn from_bytes(bytes: &[u8]) -> PersistentResult<Self> {
        let proto = ProtoPersistentProperties::decode(bytes)?;

        let mut map = BTreeMap::<String, String>::new();
        for record in proto.properties {
            if let (Some(name), Some(value)) = (record.name, record.value) {
                map.insert(name, value);
            }
        }

        let properties = map
            .into_iter()
            .map(|(name, value)| PersistentProperty { name, value })
            .collect();

        Ok(Self { properties })
    }

    pub fn to_bytes(&self) -> PersistentResult<Vec<u8>> {
        let proto = ProtoPersistentProperties {
            properties: self
                .properties
                .iter()
                .map(|property| ProtoPersistentPropertyRecord {
                    name: Some(property.name.clone()),
                    value: Some(property.value.clone()),
                })
                .collect(),
        };

        let mut out = Vec::new();
        proto.encode(&mut out)?;
        Ok(out)
    }

    pub fn load(path: impl AsRef<Path>) -> PersistentResult<Self> {
        let bytes = fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    pub fn load_or_default(path: impl AsRef<Path>) -> PersistentResult<Self> {
        match fs::read(path.as_ref()) {
            Ok(bytes) => Self::from_bytes(&bytes),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn write_to_path(&self, path: impl AsRef<Path>) -> PersistentResult<()> {
        let path = path.as_ref();
        let bytes = self.to_bytes()?;
        write_bytes_atomically(path, &bytes)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        let idx = self.find_index(key).ok()?;
        Some(self.properties[idx].value.as_str())
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        let value = value.into();
        match self.find_index(&key) {
            Ok(index) => self.properties[index].value = value,
            Err(index) => self
                .properties
                .insert(index, PersistentProperty { name: key, value }),
        }
    }

    pub fn delete(&mut self, key: &str) -> bool {
        let Ok(index) = self.find_index(key) else {
            return false;
        };
        self.properties.remove(index);
        true
    }

    pub fn iter(&self) -> impl Iterator<Item = &PersistentProperty> {
        self.properties.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }

    fn find_index(&self, key: &str) -> Result<usize, usize> {
        self.properties
            .binary_search_by(|record| record.name.as_str().cmp(key))
    }
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> PersistentResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| PersistentPropError::InvalidPath(path.to_path_buf()))?;

    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)?;
    }

    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| PersistentPropError::InvalidPath(path.to_path_buf()))?;

    let pid = std::process::id();

    for attempt in 0..64u32 {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_name = format!(".{file_name}.{pid}.{ts}.{attempt}.tmp");
        let tmp_path = parent.join(tmp_name);

        let mut file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };

        if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err.into());
        }
        drop(file);

        match fs::rename(&tmp_path, path) {
            Ok(()) => return Ok(()),
            Err(err)
                if err.kind() == io::ErrorKind::AlreadyExists
                    || err.kind() == io::ErrorKind::PermissionDenied =>
            {
                if path.exists() {
                    fs::remove_file(path)?;
                    fs::rename(&tmp_path, path)?;
                    return Ok(());
                }
                let _ = fs::remove_file(&tmp_path);
                return Err(err.into());
            }
            Err(err) => {
                let _ = fs::remove_file(&tmp_path);
                return Err(err.into());
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate a temporary filename for atomic write",
    )
    .into())
}

// ── Legacy per-file format ──────────────────────────────────────────────────
//
// Older Android devices store persistent properties as individual files under
// `/data/property/` (one file per property, filename = property name, content =
// value).  This is used as a fallback when `persistent_properties` (protobuf)
// does not exist.

/// Returns `true` if the protobuf persistent properties file exists under `dir`.
pub fn check_proto(dir: &Path) -> bool {
    dir.join("persistent_properties").exists()
}

/// Validate that `key` is safe to use as a filename inside a directory.
///
/// Rejects empty keys, keys containing path separators (`/`, `\`), and keys
/// that are or contain `..` path components.
fn validate_legacy_key(key: &str) -> PersistentResult<()> {
    if key.is_empty()
        || key.contains('/')
        || key.contains('\\')
        || key == ".."
        || key.starts_with("../")
        || key.ends_with("/..")
        || key.contains("/../")
    {
        return Err(PersistentPropError::InvalidPath(PathBuf::from(key)));
    }
    Ok(())
}

/// Read a single property from the legacy per-file storage.
pub fn legacy_get_prop(dir: &Path, key: &str) -> PersistentResult<Option<String>> {
    validate_legacy_key(key)?;
    let path = dir.join(key);
    match fs::read_to_string(&path) {
        Ok(val) => Ok(Some(val)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Write a single property to the legacy per-file storage using atomic write.
pub fn legacy_set_prop(dir: &Path, key: &str, value: &str) -> PersistentResult<()> {
    validate_legacy_key(key)?;
    let path = dir.join(key);
    write_bytes_atomically(&path, value.as_bytes())
}

/// Delete a single property from the legacy per-file storage.
pub fn legacy_delete_prop(dir: &Path, key: &str) -> PersistentResult<bool> {
    validate_legacy_key(key)?;
    let path = dir.join(key);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// List all properties stored in the legacy per-file format.
pub fn legacy_list_props(dir: &Path) -> PersistentResult<Vec<PersistentProperty>> {
    let mut props = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(props),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "persistent_properties" || name.starts_with('.') {
            continue;
        }
        if let Ok(value) = fs::read_to_string(entry.path()) {
            props.push(PersistentProperty { name, value });
        }
    }
    props.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(props)
}

// ── Protobuf message types ──────────────────────────────────────────────────

#[derive(Clone, PartialEq, Message)]
struct ProtoPersistentProperties {
    #[prost(message, repeated, tag = "1")]
    properties: Vec<ProtoPersistentPropertyRecord>,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoPersistentPropertyRecord {
    #[prost(string, optional, tag = "1")]
    name: Option<String>,
    #[prost(string, optional, tag = "2")]
    value: Option<String>,
}
