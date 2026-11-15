//! Small shared helpers used across modules.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock a `std::sync::Mutex` and recover from a poisoned state.
/// If another thread panicked while holding the lock, the guard is still valid
/// (the data may be in an inconsistent state, but in practice the in-memory
/// maps/sets used here are simple enough that this is safe to continue).
pub fn mu<'a, T>(m: &'a Mutex<T>) -> MutexGuard<'a, T> {
    match m.lock() {
        Ok(g) => g,
        Err(PoisonError { .. }) => m.lock().unwrap_or_else(|e| e.into_inner()),
    }
}

/// Generate a URL-safe, 24-byte random token (32 chars, matches Django's
/// `secrets.token_urlsafe(24)`).
pub fn generate_token_string() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 北京时间 `YYYY-MM-DD HH:MM:SS` → unix 秒。库里的 DATETIME 列都是 +08:00
/// （MySQL session `time_zone = +08:00`），字符串也按这个时区解释。
///
/// 小数秒直接丢掉（`2026-08-14 12:00:00.123456`），月/日/时/分/秒不要求补零。
pub fn parse_bj_seconds(s: &str) -> Option<i64> {
    // Strip fractional seconds if present (e.g. `2026-08-14 12:00:00.123456`).
    let s = s.trim();
    let s = if let Some(dot) = s.find('.') {
        &s[..dot]
    } else {
        s
    };
    let parts: Vec<&str> = s.split([' ', ':', '-']).collect();
    if parts.len() < 6 {
        return None;
    }
    use chrono::TimeZone;
    let y: i32 = parts[0].parse().ok()?;
    let mo: u32 = parts[1].parse().ok()?;
    let d: u32 = parts[2].parse().ok()?;
    let h: u32 = parts[3].parse().ok()?;
    let mi: u32 = parts[4].parse().ok()?;
    let sec: u32 = parts[5].parse().ok()?;
    let offset = chrono::FixedOffset::east_opt(8 * 3600)?;
    let dt = offset.with_ymd_and_hms(y, mo, d, h, mi, sec).single()?;
    Some(dt.timestamp())
}
