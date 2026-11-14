// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::format;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt},
};
use std::path::Path;

pub fn atomic_replace_preserving_metadata(
    path: &Path,
    contents: &[u8],
    default_mode: u32,
    default_uid: u32,
    default_gid: u32,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;

    let (mode, uid, gid) = match fs::metadata(path) {
        Ok(metadata) => (metadata.mode() & 0o7777, metadata.uid(), metadata.gid()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            (default_mode, default_uid, default_gid)
        }
        Err(error) => return Err(error),
    };
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    let temp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(mode)
            .open(&temp_path)?;
        file.write_all(contents)?;
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();

    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}
