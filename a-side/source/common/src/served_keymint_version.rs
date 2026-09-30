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

//! Remembers the KeyMint HAL version stamped into the attestation chain that
//! was actually served to a client.
//!
//! The A-side HAL reports its own KeyMint version in `getHardwareInfo()` and
//! uses it to gate tags, but when attestation is relayed to a real remote
//! B-side TEE the served chain carries *that* device's version (e.g. `400` for
//! an Android 16 vendor KeyMint 4 HAL). A detector reads both the chain and the
//! A-side declaration and flags a mismatch when they disagree.
//!
//! The relay path therefore records the version observed on the served chain
//! here, and persists it under the ommega data directory. Because the A-side
//! hardware profile is resolved once per process, the learned value only
//! affects `getHardwareInfo()` / tag gating after the next process start — the
//! same lifetime as the persisted file. Only known KeyMint HAL versions
//! (`100..=500`) are accepted, so a malformed remote chain cannot poison the
//! reported version.

use core::sync::atomic::{AtomicI32, Ordering};

/// Persisted next to the other ommega runtime data. The keymint process runs as
/// uid 1017 (`keystore`) and owns `/data/misc/keystore/ommega[/data]`, so the
/// TA relay path (writer) and the HAL profile probe (reader) can both reach it.
pub const SERVED_KEYMINT_VERSION_PATH: &str =
    "/data/misc/keystore/ommega/data/served_keymint_version";

/// Cached learned version; `0` means "not learned yet".
static SERVED_KEYMINT_VERSION: AtomicI32 = AtomicI32::new(0);

/// Record the KeyMint version carried by a chain that was just served to a
/// client and persist it for the next process start. Unknown values are
/// ignored.
pub fn record_served_keymint_version(version: i32) {
    if !is_valid_keymint_version(version) {
        log::warn!("ignoring served KeyMint version {version}: not a known KeyMint HAL version");
        return;
    }
    if SERVED_KEYMINT_VERSION.swap(version, Ordering::AcqRel) == version {
        return;
    }
    if let Err(error) = write_served_keymint_version(version) {
        log::warn!("failed to persist served KeyMint version {version}: {error}");
    }
}

/// The KeyMint version to report, learned from a previously served chain.
///
/// Reads (and caches) the persisted value on first use. Returns `None` when
/// nothing has been learned yet, so the caller keeps the existing
/// VINTF/Android-derived version.
pub fn served_keymint_version() -> Option<i32> {
    let cached = SERVED_KEYMINT_VERSION.load(Ordering::Acquire);
    if is_valid_keymint_version(cached) {
        return Some(cached);
    }
    let version =
        parse_served_keymint_version(&std::fs::read_to_string(SERVED_KEYMINT_VERSION_PATH).ok()?)?;
    SERVED_KEYMINT_VERSION.store(version, Ordering::Release);
    Some(version)
}

fn is_valid_keymint_version(version: i32) -> bool {
    matches!(version, 100 | 200 | 300 | 400 | 500)
}

/// Parse a persisted version file body. Pure so it can be unit-tested without
/// touching the device's real data directory.
fn parse_served_keymint_version(contents: &str) -> Option<i32> {
    contents
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|version| is_valid_keymint_version(*version))
}

fn write_served_keymint_version(version: i32) -> Result<(), std::io::Error> {
    let path = std::path::Path::new(SERVED_KEYMINT_VERSION_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, std::format!("{version}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_keymint_versions_are_accepted() {
        for version in [100, 200, 300, 400, 500] {
            assert!(is_valid_keymint_version(version));
            assert_eq!(
                parse_served_keymint_version(&version.to_string()),
                Some(version)
            );
        }
        for version in [0, 1, 4, 99, 600, -400] {
            assert!(!is_valid_keymint_version(version));
            assert_eq!(parse_served_keymint_version(&version.to_string()), None);
        }
    }

    #[test]
    fn persisted_body_round_trips_and_tolerates_whitespace() {
        assert_eq!(parse_served_keymint_version("400\n"), Some(400));
        assert_eq!(parse_served_keymint_version("  300  \n"), Some(300));
        assert_eq!(parse_served_keymint_version(""), None);
        assert_eq!(parse_served_keymint_version("garbage"), None);
    }
}
