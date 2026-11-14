//! SOTER 的策略（运行时可变 + 落盘）。
//!
//! 控制台一保存就生效，落盘到 `data/soter_policy.json`；环境变量只当初始默认
//! （`RELAY_SOTER_REAL_APP_PACKAGES` 那几份名单）。
//!
//! 1. **模式**（`mode`）：
//!    - `real`（真机模式，缺省）：`b → keybox → self_signed`。真应用按设备 id 交给 B，
//!      B 处理不了（离线 / 没能力 / 这一笔真做不下去）才轮服务端那两层。
//!    - `server_key`（服务端密钥模式）：`attk → self_signed`，**一次都不碰 B**。用控制台
//!      上传的 ATTK（私钥 + 对应的 cpuid）铸料，身份就是那把 ATTK 的。
//!
//! 2. **身份绑定**（`identities`）：哪一笔用哪把 ATTK。默认跟着请求的设备 id 走 ——
//!    哪台 B 的请求就用它上传的 ATTK（请求 device_id 为空的，已被控制台那个「默认
//!    SOTER 设备 id」填过）。规则按 `users`（AOSP 用户号：0 机主、10/11 工作资料、
//!    999 分身）、`uids`（完整 uid）、`app_ids`（用户内应用号）、`packages`（主包名）
//!    四种条件挑例外：同一格内是「或」，格子之间是「且」，第一条命中的算数。
//!    都不命中就按顺序退：请求设备绑定的那把 → `attk_id`（控制台显式兜底）→ ATTK 库里
//!    标了默认 / 最早启用的那把；所以 `attk_id` 是最后一级兜底，不是「只能生效那把」。
//!    四格全空的规则不算数（不许一条空规则把后面全吃了）。
//!
//! 3. **白名单覆盖**（`whitelist`）：包名 / 别名前缀 / 只许本地 / 只许真机 四份名单，
//!    非空就盖掉环境变量那套。不在真应用白名单里的调用一律打回 A 端本地作答
//!    （`local_only`），两种模式都一样 —— 差别只在「谁来铸料」。

use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, OnceLock, RwLock};

use serde::{Deserialize, Serialize};

use crate::android_uid::Uid;

/// 落盘位置。跟其它状态文件一样按进程工作目录算（systemd 的 `WorkingDirectory=/opt/relay`）。
pub const PATH: &str = "data/soter_policy.json";

// ---------------------------------------------------------------------------
// 模式
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// 真机模式：B 按设备 id 处理，处理不了才落服务端。
    #[default]
    #[serde(rename = "real")]
    Real,
    /// 服务端密钥模式：全用控制台上传的 ATTK，不碰 B。
    #[serde(rename = "server_key")]
    ServerKey,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Real => "real",
            Mode::ServerKey => "server_key",
        }
    }

    /// 这个模式的层序（`attk` 那层的物料要现从库里取，见 `handlers::run_layer_soter`）。
    pub fn layers(self) -> Vec<&'static str> {
        match self {
            Mode::Real => vec!["b", "keybox", "self_signed"],
            Mode::ServerKey => vec!["attk", "self_signed"],
        }
    }
}

impl FromStr for Mode {
    type Err = ();

    fn from_str(s: &str) -> Result<Mode, ()> {
        match s.trim().to_ascii_lowercase().as_str() {
            "real" | "device" | "b" | "b_first" | "" => Ok(Mode::Real),
            "server_key" | "server-key" | "serverkey" | "attk" | "server" => Ok(Mode::ServerKey),
            _ => Err(()),
        }
    }
}

// ---------------------------------------------------------------------------
// 身份绑定规则
// ---------------------------------------------------------------------------

/// 「这些调用用这把 ATTK」。四个条件格都可空，空的格子不参与判定。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRule {
    /// `soter_attk` 表里的行 id。
    pub attk_id: i64,
    /// AOSP 用户号（0 机主、10/11 工作资料、999 分身）。
    #[serde(default)]
    pub users: Vec<i32>,
    /// 完整 uid（`userId * 100000 + appId`）。
    #[serde(default)]
    pub uids: Vec<i32>,
    /// 用户内的应用号（各用户下同一个应用的这个号一样）。
    #[serde(default)]
    pub app_ids: Vec<i32>,
    /// 包名（主包名，`com.tencent.mm:tools` 这种进程名按主包名算）。
    #[serde(default)]
    pub packages: Vec<String>,
}

impl IdentityRule {
    /// 四格全空 = 不算规则（不许一条空规则把后面全吃了）。
    fn is_empty(&self) -> bool {
        self.users.is_empty()
            && self.uids.is_empty()
            && self.app_ids.is_empty()
            && self.packages.is_empty()
    }

    fn matches(&self, uid: Option<i32>, caller_pkg: Option<&str>) -> bool {
        if self.is_empty() {
            return false;
        }
        let parsed = uid.and_then(Uid::parse);
        if !self.uids.is_empty() {
            match uid {
                Some(raw) if self.uids.contains(&raw) => {}
                _ => return false,
            }
        }
        if !self.users.is_empty() {
            match parsed {
                Some(u) if self.users.contains(&u.user) => {}
                _ => return false,
            }
        }
        if !self.app_ids.is_empty() {
            match parsed {
                Some(u) if self.app_ids.contains(&u.app) => {}
                _ => return false,
            }
        }
        if !self.packages.is_empty() {
            let callers = split_names(caller_pkg.unwrap_or(""));
            if !callers
                .iter()
                .any(|caller| self.packages.iter().any(|listed| same_app(listed, caller)))
            {
                return false;
            }
        }
        true
    }
}

/// 两个包名算不算同一个应用（`com.tencent.mm:tools` → `com.tencent.mm`）。
fn same_app(listed: &str, caller: &str) -> bool {
    fn base(name: &str) -> &str {
        name.split(':').next().unwrap_or(name).trim()
    }
    let (a, b) = (base(listed), base(caller));
    !a.is_empty() && a == b
}

fn split_names(raw: &str) -> Vec<&str> {
    raw.split([',', ';', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// 白名单覆盖
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Whitelist {
    /// 真应用包名（逗号 / 换行分隔）。空 = 用环境变量 / 内置缺省。
    #[serde(default)]
    pub packages: String,
    /// 真应用别名前缀。空 = 用环境变量 / 内置缺省。
    #[serde(default)]
    pub prefixes: String,
    /// 「永远本地作答」的别名前缀。空 = 用环境变量。
    #[serde(default)]
    pub local_only_prefixes: String,
    /// 「永远当真应用（走真机）」的 uid 手写名单。空 = 用环境变量。
    #[serde(default)]
    pub local_only_uids: String,
}

/// 控制台保存时送来的补丁：每一项 `None` 表示「这一项不动」。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WhitelistPatch {
    pub packages: Option<String>,
    pub prefixes: Option<String>,
    pub local_only_prefixes: Option<String>,
    pub local_only_uids: Option<String>,
}

// ---------------------------------------------------------------------------
// 快照
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub mode: Mode,
    /// 服务端密钥模式的全局兜底 ATTK（`None` = 只用设备匹配 / 库里默认）。
    pub attk_id: Option<i64>,
    pub whitelist: Whitelist,
    pub identities: Vec<IdentityRule>,
}

impl Snapshot {
    /// 按层序排好的模式名字，给 handler 直接用。
    pub fn layers(&self) -> Vec<&'static str> {
        self.mode.layers()
    }

    /// 这一笔该用哪把 ATTK：先看身份绑定规则，再退回默认。
    /// 注意真实的选路是「规则 → 请求设备绑定的那把 → 默认」，设备那一步在
    /// `db::pick_soter_attk` 里；这里只管规则和全局兜底。
    pub fn attk_for(&self, uid: Option<i32>, caller_pkg: Option<&str>) -> Option<i64> {
        self.rule_attk(uid, caller_pkg).or(self.attk_id)
    }

    /// 只有身份绑定规则命中的那把（没命中回 `None`，交给设备匹配）。
    pub fn rule_attk(&self, uid: Option<i32>, caller_pkg: Option<&str>) -> Option<i64> {
        for rule in &self.identities {
            if rule.matches(uid, caller_pkg) {
                return Some(rule.attk_id);
            }
        }
        None
    }
}

static POLICY: OnceLock<RwLock<Arc<Snapshot>>> = OnceLock::new();

fn cell() -> &'static RwLock<Arc<Snapshot>> {
    POLICY.get_or_init(|| RwLock::new(Arc::new(load_file())))
}

/// 当前策略（读的时候克隆一个指针，不持有锁）。
pub fn snapshot() -> Arc<Snapshot> {
    match cell().read() {
        Ok(guard) => guard.clone(),
        Err(poison) => poison.into_inner().clone(),
    }
}

/// 层序（handler 里那句 `let order` 就是它）。
pub fn layers() -> Vec<&'static str> {
    snapshot().layers()
}

/// 这一笔用哪个 ATTK（服务端密钥模式）。规则命中就用规则那把；否则交给设备匹配。
pub fn attk_for(uid: Option<i32>, caller_pkg: Option<&str>) -> Option<i64> {
    snapshot().attk_for(uid, caller_pkg)
}

/// 只有身份绑定规则命中的那把（`None` = 没规则管，按请求设备匹配）。
pub fn rule_attk(uid: Option<i32>, caller_pkg: Option<&str>) -> Option<i64> {
    snapshot().rule_attk(uid, caller_pkg)
}

// ---------------------------------------------------------------------------
// 落盘
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Default)]
struct FileModel {
    #[serde(default)]
    mode: Mode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attk_id: Option<i64>,
    #[serde(default)]
    whitelist: Whitelist,
    #[serde(default)]
    identities: Vec<IdentityRule>,
}

fn load_file() -> Snapshot {
    let Ok(text) = std::fs::read_to_string(PATH) else {
        return Snapshot::default();
    };
    let Ok(model) = serde_json::from_str::<FileModel>(&text) else {
        // 文件写坏了就当没有：别让一个坏 JSON 把 SOTER 拖死。
        tracing::warn!("soter: {PATH} 解析不了，按缺省策略（真机模式）跑");
        return Snapshot::default();
    };
    Snapshot {
        mode: model.mode,
        attk_id: model.attk_id,
        whitelist: model.whitelist,
        identities: model.identities,
    }
}

fn persist(snap: &Snapshot) -> std::io::Result<()> {
    let model = FileModel {
        mode: snap.mode,
        attk_id: snap.attk_id,
        whitelist: snap.whitelist.clone(),
        identities: snap.identities.clone(),
    };
    let text = serde_json::to_string_pretty(&model).unwrap_or_default();
    if let Some(dir) = Path::new(PATH).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = format!("{PATH}.tmp");
    std::fs::write(&tmp, text.as_bytes())?;
    std::fs::rename(&tmp, PATH)
}

/// 控制台送来的补丁。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Patch {
    /// `real` / `server_key`。
    pub mode: Option<String>,
    /// 默认 ATTK 的行 id。
    pub attk_id: Option<i64>,
    /// 把默认 ATTK 清掉（回到「用库里标默认的那把」）。
    #[serde(default)]
    pub clear_attk: bool,
    pub whitelist: Option<WhitelistPatch>,
    /// 整份替换身份绑定规则（没送就不动）。
    pub identities: Option<Vec<IdentityRule>>,
    /// 整份恢复缺省（真机模式 + 白名单回落到环境变量 + 规则清空）。
    #[serde(default)]
    pub reset: bool,
}

/// 改策略并落盘，返回改完的快照。
pub fn set(patch: Patch) -> Result<Snapshot, String> {
    let mut snap = (*snapshot()).clone();
    if patch.reset {
        snap = Snapshot::default();
    } else {
        if let Some(raw) = patch.mode.as_deref() {
            snap.mode = raw
                .parse::<Mode>()
                .map_err(|_| format!("unknown soter mode {raw:?} (real | server_key)"))?;
        }
        if patch.clear_attk {
            snap.attk_id = None;
        } else if let Some(id) = patch.attk_id {
            snap.attk_id = Some(id);
        }
        if let Some(w) = patch.whitelist {
            if let Some(v) = w.packages {
                snap.whitelist.packages = v.trim().to_string();
            }
            if let Some(v) = w.prefixes {
                snap.whitelist.prefixes = v.trim().to_string();
            }
            if let Some(v) = w.local_only_prefixes {
                snap.whitelist.local_only_prefixes = v.trim().to_string();
            }
            if let Some(v) = w.local_only_uids {
                snap.whitelist.local_only_uids = v.trim().to_string();
            }
        }
        if let Some(mut rules) = patch.identities {
            for (i, rule) in rules.iter_mut().enumerate() {
                rule.packages = rule
                    .packages
                    .iter()
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect();
                rule.packages.dedup();
                if rule.attk_id <= 0 {
                    return Err(format!("identities[{i}]: attk_id is required"));
                }
                if rule.is_empty() {
                    return Err(format!(
                        "identities[{i}]: 至少给 users / uids / app_ids / packages 里的一项，\
                         空规则会把后面全吃了"
                    ));
                }
            }
            snap.identities = rules;
        }
    }
    persist(&snap).map_err(|e| format!("failed to persist {PATH}: {e}"))?;
    let shared = Arc::new(snap.clone());
    match cell().write() {
        Ok(mut guard) => *guard = shared,
        Err(poison) => *poison.into_inner() = shared,
    }
    Ok(snap)
}

// ---------------------------------------------------------------------------
// 白名单生效值（控制台写了就盖掉环境变量那套）
// ---------------------------------------------------------------------------

fn pick(override_value: &str, fallback: &str) -> String {
    let trimmed = override_value.trim();
    if trimmed.is_empty() {
        fallback.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

/// 真应用包名名单的生效值。
pub fn real_packages(fallback: &str) -> String {
    pick(&snapshot().whitelist.packages, fallback)
}

/// 真应用别名前缀名单的生效值。
pub fn real_prefixes(fallback: &str) -> String {
    pick(&snapshot().whitelist.prefixes, fallback)
}

/// 「永远本地」别名前缀的生效值。
pub fn local_only_prefixes(fallback: &str) -> String {
    pick(&snapshot().whitelist.local_only_prefixes, fallback)
}

/// 「永远当真机」uid 名单的生效值。
pub fn local_only_uids(fallback: &str) -> String {
    pick(&snapshot().whitelist.local_only_uids, fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(mode: Mode, attk: Option<i64>, rules: Vec<IdentityRule>) -> Snapshot {
        Snapshot {
            mode,
            attk_id: attk,
            whitelist: Whitelist::default(),
            identities: rules,
        }
    }

    #[test]
    fn mode_tokens_roundtrip() {
        assert_eq!("real".parse::<Mode>(), Ok(Mode::Real));
        assert_eq!("".parse::<Mode>(), Ok(Mode::Real));
        assert_eq!("SERVER_KEY".parse::<Mode>(), Ok(Mode::ServerKey));
        assert_eq!("attk".parse::<Mode>(), Ok(Mode::ServerKey));
        assert_eq!("bogus".parse::<Mode>(), Err(()));
    }

    #[test]
    fn layers_follow_mode() {
        assert_eq!(Mode::Real.layers(), vec!["b", "keybox", "self_signed"]);
        assert_eq!(Mode::ServerKey.layers(), vec!["attk", "self_signed"]);
    }

    #[test]
    fn rule_matches_work_profile_uid() {
        let rule = IdentityRule {
            attk_id: 7,
            users: vec![10],
            ..Default::default()
        };
        let s = snap(Mode::ServerKey, Some(1), vec![rule]);
        assert_eq!(s.attk_for(Some(1_010_490), None), Some(7));
        assert_eq!(s.attk_for(Some(10490), None), Some(1));
    }

    #[test]
    fn rule_matches_app_id_across_users() {
        // 各用户下的微信（appId 10490）都用这把，不管机主还是分身。
        let rule = IdentityRule {
            attk_id: 9,
            app_ids: vec![10490],
            ..Default::default()
        };
        let s = snap(Mode::ServerKey, None, vec![rule]);
        assert_eq!(s.attk_for(Some(10490), None), Some(9));
        assert_eq!(s.attk_for(Some(99_910_490), None), Some(9));
        assert_eq!(s.attk_for(Some(10123), None), None);
    }

    #[test]
    fn rule_matches_package_with_process_suffix() {
        let rule = IdentityRule {
            attk_id: 3,
            packages: vec!["com.tencent.mm".to_string()],
            ..Default::default()
        };
        let s = snap(Mode::ServerKey, None, vec![rule]);
        assert_eq!(s.attk_for(None, Some("com.tencent.mm:tools")), Some(3));
        assert_eq!(s.attk_for(None, Some("com.eg.android.AlipayGphone")), None);
    }

    #[test]
    fn empty_rule_never_matches() {
        let rule = IdentityRule {
            attk_id: 5,
            ..Default::default()
        };
        let s = snap(Mode::ServerKey, Some(2), vec![rule]);
        assert_eq!(s.attk_for(Some(10490), Some("com.tencent.mm")), Some(2));
    }

    #[test]
    fn uid_beats_user_rule_by_order() {
        let exact = IdentityRule {
            attk_id: 11,
            uids: vec![99_910_490],
            ..Default::default()
        };
        let by_user = IdentityRule {
            attk_id: 22,
            users: vec![999],
            ..Default::default()
        };
        let s = snap(Mode::ServerKey, None, vec![exact, by_user]);
        assert_eq!(s.attk_for(Some(99_910_490), None), Some(11));
        assert_eq!(s.attk_for(Some(99_910_491), None), Some(22));
    }

    #[test]
    fn whitelist_override_wins_only_when_set() {
        assert_eq!(pick("", "env-value"), "env-value");
        assert_eq!(pick("  ", "env-value"), "env-value");
        assert_eq!(pick(" a,b ", "env-value"), "a,b");
    }
}
