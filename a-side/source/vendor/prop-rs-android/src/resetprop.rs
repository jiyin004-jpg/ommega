//! Core resetprop operations — platform-independent of CLI framework.
//!
//! This module implements the business logic for Magisk-compatible property
//! operations.  The binary in `tools/resetprop` is a thin CLI wrapper around
//! this module.

use std::io;
use std::time::Duration;

use crate::persist;
use crate::sys_prop::{self, SysPropResult};

/// Configuration flags that mirror the CLI flags of `resetprop`.
pub struct ResetProp {
    /// `-n`: bypass property_service, direct mmap.
    pub skip_svc: bool,
    /// `-p`: also operate on persistent property storage.
    pub persistent: bool,
    /// `-P`: only read persistent properties from storage.
    pub persist_only: bool,
    /// `-v`: verbose output to stderr.
    pub verbose: bool,
    /// `-Z`: show SELinux context instead of value.
    pub show_context: bool,
    /// `-c`: rebuild prop area (former compact)
    pub rebuild: bool,
}

impl ResetProp {
    /// Get a single property value, or its SELinux context if `-Z`.
    ///
    /// Returns `None` when the property is not found (caller should handle
    /// the exit code).
    pub fn get(&self, name: &str) -> Option<String> {
        if self.show_context {
            return sys_prop::get_context(name).ok();
        }

        let mut val = if !self.persist_only {
            sys_prop::get(name)
        } else {
            None
        };

        if val.is_none() && (self.persistent || self.persist_only) && name.starts_with("persist.") {
            val = persist::persist_get_prop(name).ok().flatten();
        }

        val
    }

    /// Set a property, handling persistent storage according to flags.
    ///
    /// Persistent write happens only when **all** of:
    /// - `-p` flag is set
    /// - the property key starts with `persist.`
    /// - the write bypassed property_service (skip_svc or ro.*)
    ///
    /// This matches Magisk's behavior: property_service already persists
    /// `persist.*` keys by itself, so we only need to manually persist when
    /// we bypass it.
    pub fn set(&self, name: &str, value: &str) -> SysPropResult<bool> {
        let need_rebuild = sys_prop::set(name, value, self.skip_svc)?;

        let skip = self.skip_svc || name.starts_with("ro.");
        if skip && self.persistent && name.starts_with("persist.") {
            persist::persist_set_prop(name, value)?;
        }

        if self.verbose {
            eprintln!("resetprop: set {name}={value}");
        }
        Ok(need_rebuild)
    }

    /// Delete a property.
    ///
    /// Returns `true` if the property existed and was deleted.
    pub fn delete(&self, name: &str) -> SysPropResult<bool> {
        let deleted = sys_prop::delete(name)?;

        if deleted && self.persistent && name.starts_with("persist.") {
            persist::persist_delete_prop(name)?;
        }

        if self.verbose {
            if deleted {
                eprintln!("resetprop: deleted {name}");
            } else {
                eprintln!("resetprop: {name} not found");
            }
        }
        Ok(deleted)
    }

    /// Wait for a property to exist or change away from `old_value`.
    ///
    /// Follows Magisk semantics:
    /// - `old_value = None`: wait until the property exists.
    /// - `old_value = Some(v)`: wait until the property value differs from `v`.
    ///
    /// Returns `true` if the condition was met, `false` on timeout.
    pub fn wait(
        &self,
        name: &str,
        old_value: Option<&str>,
        timeout: Option<Duration>,
    ) -> SysPropResult<bool> {
        sys_prop::wait(name, old_value, timeout)
    }

    /// Collect all properties as sorted `(name, value|context)` pairs.
    ///
    /// When `-Z` is set, values are replaced with the SELinux context.
    /// When `-p`/`-P` is set, persistent properties are merged (persistent
    /// values override system values for the same key).
    pub fn list_all(&self) -> SysPropResult<Vec<(String, String)>> {
        let mut props: Vec<(String, String)> = Vec::new();

        if !self.persist_only {
            sys_prop::for_each(|name, value| {
                props.push((name.to_owned(), value.to_owned()));
            });
        }

        if self.persistent || self.persist_only {
            let persist_props = persist::persist_get_all_props()?;
            for (name, value) in persist_props {
                // Persistent props merge: only add if not already present from sys
                if !props.iter().any(|(n, _)| n == &name) {
                    props.push((name, value));
                }
            }
        }

        props.sort_by(|a, b| a.0.cmp(&b.0));

        if self.show_context {
            for entry in &mut props {
                entry.1 = sys_prop::get_context(&entry.0).unwrap_or_default();
            }
        }

        Ok(props)
    }

    /// Load and set properties from an iterator of lines.
    ///
    /// Lines starting with `#` are comments; empty lines are skipped.
    /// Key and value are separated by `=`.
    pub fn load_props(
        &self,
        lines: impl Iterator<Item = Result<String, io::Error>>,
    ) -> SysPropResult<bool> {
        let mut need_rebuild = false;
        for line in lines {
            let line =
                line.map_err(|e| sys_prop::SysPropError::InvalidCString(format!("io error: {e}")))?;
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (key, value) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue,
            };

            if key.is_empty() {
                continue;
            }

            need_rebuild |= self.set(key, value)?;
        }
        Ok(need_rebuild)
    }

    pub fn rebuild(&self, area: &String) -> SysPropResult<()> {
        sys_prop::rebuild(area, false, false)?;
        sys_prop::rebuild(area, false, true)?;
        Ok(())
    }

    pub fn rebuild_all(&self, force: bool) -> SysPropResult<bool> {
        let contexts = sys_prop::list_contexts(false)?;
        let mut all_success = true;
        for name in contexts {
            if let Err(e) = sys_prop::rebuild(&name.to_string(), !force, false) {
                log::error!("failed to rebuild area {name}: {e:?}");
                all_success = false;
            }
        }

        let contexts = sys_prop::list_contexts(true)?;
        for name in contexts {
            if let Err(e) = sys_prop::rebuild(&name.to_string(), !force, true) {
                log::error!("failed to rebuild appcompat area {name}: {e:?}");
                all_success = false;
            }
        }

        Ok(all_success)
    }
}
