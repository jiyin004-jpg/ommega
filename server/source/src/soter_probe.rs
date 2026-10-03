//! 探测机（春秋 / 鸭子）的 SOTER 请求：用服务端内置物料就地作答，一个字节都不落 B 端。
//!
//! 为什么要拦：这两台探测器把整套 SOTER 流程（ASK、AuthKey、签名）反复地跑，每笔都要真机
//! TEE 陪着走一遍 —— 而它们要的只是「SOTER 能不能用」，不是腾讯认得的那把钥匙。实测当前
//! 每分钟能从 B 端拿走十几到二十几笔。attest 走的是另一条路，这里一个字都不动，判据只对
//! `/api/soter/` 生效。
//!
//! 判据为什么不只看别名：探测机的 ASK 那几个 op（`has_ask_already`、`export_ask_public_key`、
//! `generate_ask_key_pair`、`remove_all_uid_key`）本来就不带别名，只看别名连一小半都拦不到。
//! 所以这里还记「槽位」—— `(点名设备, uid)` 上见过探测别名，这个槽位接下来也按探测机对待。
//! 反过来，同一个槽位只要见过一次真应用的别名（微信那种），就把它当回真应用、不再拦：
//! uid 号在不同设备上是复用的，宁可漏拦，也不能把别人的真钥匙拦成服务端造的假料。
//!
//! 判据为什么必须留在服务端：别人自己写的 A 端不会带本地兜底（A 端那份见
//! `a-side/source/src/soter_relay.rs`），这些流量只有服务端看得见。

use std::collections::HashMap;
use std::sync::Mutex;

use crate::config::Config;

/// 两台探测机的别名前缀，跟 A 端 `soter_relay::DEFAULT_LOCAL_ONLY_PREFIXES` 一个口径。
pub const DEFAULT_PREFIXES: &str = "chunqiu_soter_probe_,duckdetector_soter_probe_";

/// 一个槽位「刚跑过探测机的流程」算多久。
///
/// 一轮探测流程是秒级的，但探测器会一直循环跑；30 分钟够覆盖它跑着的那段时间，又短到不
/// 至于把一次误判留一整天。
const LEARNED_TTL_MS: i64 = 30 * 60 * 1000;

/// 槽位上见过真应用别名之后，多久不再把它当探测机。
const REAL_APP_QUIET_MS: i64 = 24 * 60 * 60 * 1000;

/// 最多记多少个槽位。满了按「最后一次见到探测别名」的时间丢一半。
const NOTE_CAP: usize = 8192;

/// 判据用的槽位备注。
#[derive(Debug, Clone, Default)]
struct SlotNote {
    /// 最后一次见到探测别名。
    probe_ms: i64,
    /// 最后一次见到真应用的别名。
    real_ms: i64,
}

/// 槽位备注表。纯逻辑，好单测：生产里就是 `NOTES` 里那张表。
#[derive(Debug, Default)]
struct Notes {
    map: HashMap<String, SlotNote>,
}

impl Notes {
    fn key(device: &str, uid: i32) -> String {
        format!("{device}|{uid}")
    }

    /// 记一笔：这个槽位上刚见到了什么。
    ///
    /// `probe` 是探测别名，`real` 是「非空、且不是探测别名」的别名（真应用自己起的名）。
    fn observe(&mut self, device: &str, uid: i32, probe: bool, real: bool, now: i64) {
        if !probe && !real {
            return;
        }
        let key = Self::key(device, uid);
        let note = self.map.entry(key).or_default();
        if probe {
            note.probe_ms = now;
        }
        if real {
            note.real_ms = now;
        }
        if self.map.len() > NOTE_CAP {
            self.trim(now);
        }
    }

    /// 超出容量：把过期的先清了；还超就按「最后见过探测别名」的时间丢一半。
    fn trim(&mut self, now: i64) {
        self.map
            .retain(|_, n| now.saturating_sub(n.probe_ms) <= LEARNED_TTL_MS);
        if self.map.len() <= NOTE_CAP {
            return;
        }
        let mut seen: Vec<(String, i64)> = self
            .map
            .iter()
            .map(|(k, n)| (k.clone(), n.probe_ms))
            .collect();
        seen.sort_by_key(|(_, at)| *at);
        for (key, _) in seen.into_iter().take(self.map.len() - NOTE_CAP / 2) {
            self.map.remove(&key);
        }
    }

    /// 这个槽位刚跑过探测机的流程，而且没露过真应用的马脚。
    fn is_learned(&self, device: &str, uid: i32, now: i64) -> bool {
        let Some(note) = self.map.get(&Self::key(device, uid)) else {
            return false;
        };
        if now.saturating_sub(note.probe_ms) > LEARNED_TTL_MS {
            return false;
        }
        note.real_ms == 0 || now.saturating_sub(note.real_ms) > REAL_APP_QUIET_MS
    }
}

static NOTES: Mutex<Option<Notes>> = Mutex::new(None);

/// 名单里的分隔符：逗号、分号、空白都算；写成 `none` / `off` / `-` 就是关掉。
fn split_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || matches!(trimmed.to_lowercase().as_str(), "none" | "off" | "-") {
        return Vec::new();
    }
    trimmed
        .split([',', ';', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// 别名有没有命中探测前缀。认的是前缀，不是「包含」——别的名字里夹着它不算。
fn prefix_hit(alias: &str, prefixes: &str) -> bool {
    !alias.is_empty()
        && split_list(prefixes)
            .iter()
            .any(|prefix| alias.starts_with(prefix.as_str()))
}

/// uid 在不在手写的名单里。写法两种：`10401`（哪台设备都算）和
/// `device-b-c3f204aa:10401`（只认这台点名设备）。
fn uid_listed(device: &str, uid: i32, list: &str) -> bool {
    split_list(list)
        .iter()
        .any(|item| match item.split_once(':') {
            Some((dev, num)) => dev.trim() == device && num.trim() == uid.to_string(),
            None => item == &uid.to_string(),
        })
}

/// 这笔要不要就地作答；要的话给出理由（拿去打日志）。
///
/// 三个条件按强弱排：别名命中（铁证）、uid 在手写名单里（人工指定）、槽位刚跑过探测流程
/// （从别名学来的）。都不命中就返回 `None`，照原来的路走。
pub fn reason(cfg: &Config, device: &str, uid: Option<i32>, alias: Option<&str>) -> Option<String> {
    let alias = alias.unwrap_or("");
    let prefixes = cfg.soter_local_only_prefixes.as_str();
    let probe = prefix_hit(alias, prefixes);
    let real = !alias.is_empty() && !probe;
    let now = chrono::Utc::now().timestamp_millis();

    let mut guard = NOTES.lock().ok()?;
    let notes = guard.get_or_insert_with(Notes::default);
    if let Some(uid) = uid {
        notes.observe(device, uid, probe, real, now);
    }
    if probe {
        return Some("别名命中本地兜底前缀".to_string());
    }
    let uid = uid?;
    if uid_listed(device, uid, cfg.soter_local_only_uids.as_str()) {
        return Some("uid 在这次会话的本地兜底名单里".to_string());
    }
    notes
        .is_learned(device, uid, now)
        .then(|| "这个槽位刚跑过探测机的流程".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = "device-b-c3f204aa";

    #[test]
    fn the_two_probe_names_are_the_default_prefixes() {
        assert!(prefix_hit(
            "chunqiu_soter_probe_1791022575713",
            DEFAULT_PREFIXES
        ));
        assert!(prefix_hit(
            "duckdetector_soter_probe_1791022480012",
            DEFAULT_PREFIXES
        ));
        // 真应用的别名一个都不能碰。
        assert!(!prefix_hit(
            "SoterAuthKeyV2_salt11d8ba34_scene1",
            DEFAULT_PREFIXES
        ));
        assert!(!prefix_hit("WechatAuthKeyPay&dx20079023", DEFAULT_PREFIXES));
        assert!(!prefix_hit("", DEFAULT_PREFIXES));
        // 认前缀不是「包含」。
        assert!(!prefix_hit("x_chunqiu_soter_probe_1", DEFAULT_PREFIXES));
    }

    #[test]
    fn the_list_can_be_switched_off() {
        for off in ["", "none", "off", "-", "  ", "NONE"] {
            assert!(!prefix_hit("chunqiu_soter_probe_1", off), "{off:?}");
            assert!(!uid_listed(DEV, 10401, off), "{off:?}");
        }
    }

    #[test]
    fn a_uid_may_be_listed_for_one_device_only() {
        assert!(uid_listed(DEV, 10401, "10401"));
        assert!(uid_listed(DEV, 10401, "10388, 10401"));
        assert!(uid_listed(DEV, 10401, &format!("{DEV}:10401")));
        assert!(!uid_listed(
            "device-b-other",
            10401,
            &format!("{DEV}:10401")
        ));
        assert!(!uid_listed(DEV, 10402, &format!("{DEV}:10401")));
        // 坏项丢掉，好的还得管用。
        assert!(uid_listed(DEV, 10401, "乱写,:,10388,10401"));
    }

    #[test]
    fn a_slot_that_ran_a_probe_is_a_probe_from_then_on() {
        let mut notes = Notes::default();
        let now = 1_000_000i64;
        // 别的人类名字：不学也不拦。
        notes.observe(DEV, 7, false, true, now);
        assert!(!notes.is_learned(DEV, 7, now));
        // 探测别名进过这个槽位，之后不带别名的 op 也按探测机对待。
        notes.observe(DEV, 10401, true, false, now);
        assert!(notes.is_learned(DEV, 10401, now + 60_000));
        // 别的槽位、别的设备不受影响。
        assert!(!notes.is_learned(DEV, 10402, now));
        assert!(!notes.is_learned("device-b-other", 10401, now));
    }

    #[test]
    fn one_real_app_alias_and_the_slot_is_left_alone() {
        let mut notes = Notes::default();
        let now = 1_000_000i64;
        notes.observe(DEV, 10401, true, false, now);
        assert!(notes.is_learned(DEV, 10401, now));
        // 同一个槽位上冒出来真应用的名字（uid 号跨设备复用），立刻不再拦。
        notes.observe(DEV, 10401, false, true, now + 1_000);
        assert!(!notes.is_learned(DEV, 10401, now + 2_000));
        // 那句「真应用」的话也会过期：一天之后探测别名再来，照样学。
        let later = now + REAL_APP_QUIET_MS + 60_000;
        notes.observe(DEV, 10401, true, false, later);
        assert!(notes.is_learned(DEV, 10401, later + 1_000));
    }

    #[test]
    fn a_stale_note_stops_diverting() {
        let mut notes = Notes::default();
        let now = 1_000_000i64;
        notes.observe(DEV, 10401, true, false, now);
        assert!(notes.is_learned(DEV, 10401, now + LEARNED_TTL_MS));
        assert!(!notes.is_learned(DEV, 10401, now + LEARNED_TTL_MS + 1));
    }

    #[test]
    fn the_note_table_does_not_grow_forever() {
        let mut notes = Notes::default();
        for i in 0..(NOTE_CAP * 2) as i32 {
            notes.observe(DEV, i, true, false, 1_000 + i as i64);
        }
        assert!(
            notes.map.len() <= NOTE_CAP,
            "备注表涨到了 {} 条",
            notes.map.len()
        );
    }
}
