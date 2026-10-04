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

/// 真应用（支持 SOTER SDK 的那批，微信 / 支付宝 / GMS 都走这套名字）的别名前缀。
///
/// 规则是反向的：**命中这里的交给真机，其余一律用内置料就地作答**。
/// 探测机自己起的名字（`*_soter_probe_*`）不在里面，所以连它那几笔不带别名的 ASK
/// 也一并落到内置料上 —— 同一轮的 ASK / AuthKey 报同一个号，不再一个真机一个本地。
pub const DEFAULT_REAL_APP_PREFIXES: &str = "SoterAuthKey,WechatAuthKeyPay&";

/// 槽位上见过真应用别名之后，多久内它「不带别名的调用」（ASK / getDeviceId 那套）也照样
/// 交给真机。真应用的 uid 是诚实的（SDK 拿自己的 `Binder.getCallingUid()` 填），但窗口要
/// 短：一轮流程里那几笔本来就隔着几秒，6 秒够挂得住；再长只会把探测机/别的应用的
/// 不带别名调用误当成真应用的，反而把它们送到真机上去。
const REAL_SLOT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// 「这个槽位上一笔是谁答的」记多久。
///
/// ASK 与 AuthKey 必须同源 —— 内置料那把 ASK 和真机那把不是同一把，混着给 App 就验不过。
/// 所以一笔 ASK 刚在内置料上答过，紧接着同槽位的 AuthKey 不再去真机。
const STICKY_MS: i64 = 90 * 1000;

/// 最多记多少个槽位。满了按「最后一次见到探测别名」的时间丢一半。
const NOTE_CAP: usize = 8192;

/// 判据用的槽位备注。
#[derive(Debug, Clone, Default)]
struct SlotNote {
    /// 最后一次见到真应用别名。
    real_ms: i64,
    /// 最后一笔是谁答的（`true` = 真机）。
    served_real: bool,
    /// 最后一笔答的时间。
    served_ms: i64,
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

    /// 记一笔：这个槽位上刚见到了真应用别名。
    fn observe(&mut self, device: &str, uid: i32, now: i64) {
        let key = Self::key(device, uid);
        let note = self.map.entry(key).or_default();
        note.real_ms = now;
        if self.map.len() > NOTE_CAP {
            self.trim(now);
        }
    }

    /// 记一笔：这个槽位的这一笔是谁答的。
    fn served(&mut self, device: &str, uid: i32, real: bool, now: i64) {
        let key = Self::key(device, uid);
        let note = self.map.entry(key).or_default();
        note.served_real = real;
        note.served_ms = now;
    }

    /// 超出容量：把过期的先清了；还超就按「最后见过真应用别名」的时间丢一半。
    fn trim(&mut self, now: i64) {
        self.map.retain(|_, n| {
            now.saturating_sub(n.real_ms) <= REAL_SLOT_TTL_MS
                || now.saturating_sub(n.served_ms) <= STICKY_MS
        });
        if self.map.len() <= NOTE_CAP {
            return;
        }
        let mut seen: Vec<(String, i64)> = self
            .map
            .iter()
            .map(|(k, n)| (k.clone(), n.real_ms))
            .collect();
        seen.sort_by_key(|(_, at)| *at);
        for (key, _) in seen.into_iter().take(self.map.len() - NOTE_CAP / 2) {
            self.map.remove(&key);
        }
    }

    /// 这个槽位刚用过真应用别名（长期）。
    fn is_real_slot(&self, device: &str, uid: i32, now: i64) -> bool {
        let Some(note) = self.map.get(&Self::key(device, uid)) else {
            return false;
        };
        now.saturating_sub(note.real_ms) <= REAL_SLOT_TTL_MS
    }

    /// 这个槽位上上一笔是谁答的（短期，只为了把 ASK 与 AuthKey 绑到同一个源上）。
    /// `None` = 还没来得及记、或者已经过期。
    fn last_side(&self, device: &str, uid: i32, now: i64) -> Option<bool> {
        let note = self.map.get(&Self::key(device, uid))?;
        (note.served_ms != 0 && now.saturating_sub(note.served_ms) <= STICKY_MS)
            .then_some(note.served_real)
    }
}

static NOTES: Mutex<Option<Notes>> = Mutex::new(None);

/// 会话号（`init_sign` 开的）→ 这一轮是在哪一侧开的（`true` = 真机）。
///
/// `finish_sign` 那笔**不带别名也不带 uid**，只有会话号；不能拿它去重新判“这是谁”，
/// 必须送回开会话的那一侧 —— 不然真机的会话拿到内置料上去问，只会回 -5（微信就是这么失败的）。
const SESSION_SIDE_TTL_MS: i64 = 10 * 60 * 1000;
static SESSION_SIDES: Mutex<Option<HashMap<String, (bool, i64)>>> = Mutex::new(None);

/// 记一笔：这个会话是哪一侧开的。
pub fn note_session_side(device: &str, session: i64, real: bool) {
    let Ok(mut guard) = SESSION_SIDES.lock() else {
        return;
    };
    let map = guard.get_or_insert_with(HashMap::new);
    let now = chrono::Utc::now().timestamp_millis();
    map.retain(|_, (_, at)| now.saturating_sub(*at) <= SESSION_SIDE_TTL_MS);
    map.insert(format!("{device}|{session}"), (real, now));
}

/// 这个会话是哪一侧开的。`None` = 不知道（老服务端、重启后丢了）。
pub fn session_side(device: &str, session: i64) -> Option<bool> {
    let guard = SESSION_SIDES.lock().ok()?;
    let map = guard.as_ref()?;
    let (real, at) = map.get(&format!("{device}|{session}"))?;
    let now = chrono::Utc::now().timestamp_millis();
    (now.saturating_sub(*at) <= SESSION_SIDE_TTL_MS).then_some(*real)
}

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

/// `caller_pkg` 字段名：A 端把「真正调用者是谁」的包名带过来（设备本地解析，精确）。
/// 带了就按它判白名单；没带（老 A 端）就沿用下面那套别名/槽位逻辑。
pub const CALLER_PKG_FIELD: &str = "caller_pkg";

/// 真应用的包名白名单：这些才交给真机，其余一律内置料。
///
/// 为什么用包名：别名是调用方自己起的、请求里的 uid 也是自己填的，两者都不可信；
/// 包名由 A 端按内核给的真调用者 uid 在设备本地翻出来，是唯一精确的判据。
///
/// 宁可写宽：名单漏一个真应用，它拿到内置料、自己服务端验不过就直接坏；名单里多一个
/// （哪怕它根本不用 SOTER）什么也不会发生。但**探测器/测试类的包一个都不能放进来**
/// （放进来就是把真机那个 cpu_id 递出去）。要加硬就改环境变量
/// `RELAY_SOTER_REAL_APP_PACKAGES`（逗号分隔，写了就不看这份缺省）。
pub const DEFAULT_REAL_APP_PACKAGES: &str = concat!(
    // 腾讯自家那套 SOTER SDK（微信/QQ 全系）。
    "com.tencent.mm,com.tencent.mm:tools,com.tencent.mobileqq,com.tencent.mobileqqi,",
    "com.tencent.tim,com.tencent.wework,com.tencent.qqlite,",
    // 支付/金融：支付宝、云闪付、主要银行、京东金融、微众。
    "com.eg.android.AlipayGphone,com.unionpay,com.unionpay.mobilepay,",
    "com.icbc,com.chinamworld.main,com.android.bankabc,com.chinamworld.bocmbci,",
    "cmb.pb,com.bankcomm.Bankcomm,com.yitong.mbank.psbc,com.ecitic.bank.mobile,",
    "com.spdbccc.app,com.cib.cibmb,com.cebbank.mobile.cemb,com.pingan.paces.ccms,",
    "com.pingan.papay,com.webank.wemoney,com.cmbc.cc.mbank,com.cgbchina.xpt,",
    "cn.com.hsbc.hsbcchina,com.jd.jrapp,",
    // 头部电商/生活/内容类，和三家运营商。
    "com.taobao.taobao,com.taobao.idlefish,com.tmall.wireless,com.xunmeng.pinduoduo,",
    "com.sankuai.meituan,com.sankuai.meituan.takeoutnew,com.dianping.v1,",
    "com.sdu.didi.psnger,com.jingdong.app.mall,com.sinovatech.unicom.ui,",
    "com.greenpoint.android.mc10086.activity,com.ct.client,",
    "com.smile.gifmaker,",
    "tv.danmaku.bili,com.baidu.tieba,com.baidu.netdisk,com.netease.cloudmusic,",
    "ctrip.android.view,com.achievo.vipshop,",
    // GMS/Play。
    "com.google.android.gms,com.android.vending",
);

/// 这笔要不要就地作答（用内置料）；要的话给出理由（拿去打日志）。
///
/// 反向白名单：
///
/// 1. 别名命中真应用那套名字（`SoterAuthKey…` / `WechatAuthKeyPay&…`）→ `None`（交给真机），
///    同时把这个槽位标成真应用；
/// 2. 有别名但不在名单里（探测机自己起的名字、其它自定义名）→ 就地作答；
/// 3. 没别名（ASK / getDeviceId 那套）：槽位刚用过真应用别名 → 交给真机；否则就地作答。
///
/// `soter_local_only_prefixes` / `soter_local_only_uids` 两个旧名单还留着当人工口子：
/// 前者点名「永远本地」，后者点名「永远当真应用」。
pub fn reason(cfg: &Config, device: &str, uid: Option<i32>, alias: Option<&str>) -> Option<String> {
    reason_with_caller(cfg, device, uid, alias, None)
}

/// 带「真调用者包名」的版本：A 端传了 `caller_pkg` 就按包名白名单判（精确），
/// 没传就走旧的别名/槽位逻辑。
pub fn reason_with_caller(
    cfg: &Config,
    device: &str,
    uid: Option<i32>,
    alias: Option<&str>,
    caller_pkg: Option<&str>,
) -> Option<String> {
    if let Some(pkg) = caller_pkg.map(str::trim).filter(|p| !p.is_empty()) {
        let packages = if cfg.soter_real_app_packages.trim().is_empty() {
            DEFAULT_REAL_APP_PACKAGES.to_string()
        } else {
            cfg.soter_real_app_packages.clone()
        };
        let known = split_list(&packages);
        // 一个 uid 可能挂着好几个包（GMS 那种共享 uid），A 端把本机解析出来的包名
        // 逗号连起来一起报；命中任意一个就算真应用。
        let callers = split_list(pkg);
        if callers
            .iter()
            .any(|caller| known.iter().any(|name| name == caller))
        {
            // 真应用：交给真机，顺便把它的槽位标上（下一笔不带包名时不至于判错）。
            let now = chrono::Utc::now().timestamp_millis();
            if let (Some(uid), Ok(mut guard)) = (uid, NOTES.lock()) {
                let notes = guard.get_or_insert_with(Notes::default);
                notes.observe(device, uid, now);
                notes.served(device, uid, true, now);
            }
            return None;
        }
        return Some(format!("调用者包名 {pkg} 不在真应用名单里"));
    }
    reason_without_caller(cfg, device, uid, alias)
}

fn reason_without_caller(
    cfg: &Config,
    device: &str,
    uid: Option<i32>,
    alias: Option<&str>,
) -> Option<String> {
    let alias = alias.unwrap_or("").trim();
    let real_prefixes = if cfg.soter_real_app_prefixes.trim().is_empty() {
        DEFAULT_REAL_APP_PREFIXES.to_string()
    } else {
        cfg.soter_real_app_prefixes.clone()
    };
    let now = chrono::Utc::now().timestamp_millis();
    let force_real = uid
        .map(|uid| uid_listed(device, uid, cfg.soter_local_only_uids.as_str()))
        .unwrap_or(false);

    let mut guard = NOTES.lock().ok()?;
    let notes = guard.get_or_insert_with(Notes::default);
    // 上一笔是谁答的：ASK 与 AuthKey 必须同源（两把 ASK 不是同一把，混着给 App 就验不过）。
    let sticky = uid.and_then(|uid| notes.last_side(device, uid, now));

    if prefix_hit(alias, cfg.soter_local_only_prefixes.as_str()) {
        if let Some(uid) = uid {
            notes.served(device, uid, false, now);
        }
        return Some("别名命中人工指定的本地兜底前缀".to_string());
    }

    let is_real_alias = prefix_hit(alias, &real_prefixes);
    let has_alias = !alias.is_empty() && alias != "-";
    let (real, why) = if is_real_alias {
        if sticky == Some(false) {
            (
                false,
                "上一笔刚在内置料上答过，这一笔跟着内置（不拆 ASK/AuthKey）".to_string(),
            )
        } else {
            if let Some(uid) = uid {
                notes.observe(device, uid, now);
            }
            (true, "别名命中真应用名单".to_string())
        }
    } else if has_alias {
        if sticky == Some(true) {
            (true, "上一笔是真机答的，这一笔跟着给真机".to_string())
        } else {
            (false, format!("别名 {alias:?} 不在真应用名单里"))
        }
    } else if let Some(uid) = uid {
        if force_real || notes.is_real_slot(device, uid, now) || sticky == Some(true) {
            (
                true,
                format!("槽位 {device}|{uid} 用过真应用别名，交给真机"),
            )
        } else {
            (
                false,
                format!("没别名的调用，槽位 {device}|{uid} 没见过真应用别名"),
            )
        }
    } else {
        // 没别名也没 uid（`finish_sign` / `getDeviceId` 这种）：默认交给真机。
        // 这是会话类调用，它必须回到开会话的那一侧；而“那一侧是不是内置料”由
        // `soter_probe::session_side` 在外面判（handler 里）。这里不能拍板内置 ——
        // 真机的会话拿到内置料上问只会回 -5。
        (true, "没别名也没 uid 的调用，默认交给真机".to_string())
    };

    if let Some(uid) = uid {
        notes.served(device, uid, real, now);
    }
    if real {
        None
    } else {
        Some(why)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = "device-b-c3f204aa";

    /// 真应用那套名字在缺省名单里，探测机自己起的名字不在。
    #[test]
    fn the_real_app_names_are_the_default_prefixes() {
        for real in [
            "SoterAuthKeyV2_salt11d8ba34_scene1",
            "SoterAuthKey_salt0d4a5c11_scene2",
            "WechatAuthKeyPay&dx20079023",
        ] {
            assert!(prefix_hit(real, DEFAULT_REAL_APP_PREFIXES), "{real}");
        }
        for probe in [
            "chunqiu_soter_probe_1791022575713",
            "duckdetector_soter_probe_1791022480012",
        ] {
            assert!(!prefix_hit(probe, DEFAULT_REAL_APP_PREFIXES), "{probe}");
        }
        assert!(!prefix_hit("", DEFAULT_REAL_APP_PREFIXES));
        // 认前缀不是「包含」。
        assert!(!prefix_hit(
            "x_SoterAuthKeyV2_salt11d8ba34_scene1",
            DEFAULT_REAL_APP_PREFIXES
        ));
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

    /// 真应用别名进过的槽位=真应用的槽位：它的不带别名的 op（ASK 那套）也照旧给真机。
    #[test]
    fn a_slot_that_used_a_real_alias_stays_a_real_slot() {
        let mut notes = Notes::default();
        let now = 1_000_000i64;
        assert!(!notes.is_real_slot(DEV, 10401, now));
        notes.observe(DEV, 10401, now);
        assert!(notes.is_real_slot(DEV, 10401, now + 2_000));
        // 别的槽位、别的设备不受影响。
        assert!(!notes.is_real_slot(DEV, 10402, now));
        assert!(!notes.is_real_slot("device-b-other", 10401, now));
    }

    #[test]
    fn a_stale_note_stops_mattering() {
        let mut notes = Notes::default();
        let now = 1_000_000i64;
        notes.observe(DEV, 10401, now);
        assert!(notes.is_real_slot(DEV, 10401, now + REAL_SLOT_TTL_MS));
        assert!(!notes.is_real_slot(DEV, 10401, now + REAL_SLOT_TTL_MS + 1));
    }

    /// 粘性：同一槽位上一笔是谁答的，紧接着那一笔得跟着走（ASK 与 AuthKey 不能拆源）。
    #[test]
    fn the_sticky_side_holds_for_a_moment_only() {
        let mut notes = Notes::default();
        let now = 1_000_000i64;
        assert_eq!(notes.last_side(DEV, 10401, now), None);
        notes.served(DEV, 10401, false, now);
        assert_eq!(notes.last_side(DEV, 10401, now + 1_000), Some(false));
        assert_eq!(notes.last_side(DEV, 10401, now + STICKY_MS + 1), None);
        notes.served(DEV, 10401, true, now);
        assert_eq!(notes.last_side(DEV, 10401, now), Some(true));
    }

    #[test]
    fn the_note_table_does_not_grow_forever() {
        let mut notes = Notes::default();
        for i in 0..(NOTE_CAP * 2) as i32 {
            notes.observe(DEV, i, 1_000 + i as i64);
        }
        assert!(
            notes.map.len() <= NOTE_CAP,
            "备注表涨到了 {} 条",
            notes.map.len()
        );
    }

    /// 带了 `caller_pkg` 就按包名白名单判：名单里给真机，名单外一律内置。
    #[test]
    fn a_caller_package_decides_by_the_package_list() {
        let cfg = Config::default();
        for real in ["com.tencent.mm", "com.tencent.mobileqq"] {
            assert_eq!(
                reason_with_caller(&cfg, DEV, Some(10490), Some("SoterAuthKeyV2_x"), Some(real)),
                None,
                "{real} 应当给真机"
            );
        }
        for outside in ["com.duck.detector", "com.example.app"] {
            let why = reason_with_caller(&cfg, DEV, Some(10490), None, Some(outside))
                .expect("不在名单里的得判内置");
            assert!(why.contains(outside), "{why}");
        }
        // 没带包名 → 老逻辑。用一个没在别处碰过的 uid：真应用那几笔会把这个槽位
        // 记成粘性的「真机答的」，用同一个 uid 验就验不到别名那条路了。
        assert!(
            reason_with_caller(&cfg, DEV, Some(10666), Some("SomeRandomAlias"), None).is_some()
        );
    }

    /// 一个 uid 挂着好几个包时，A 端逗号连起来一起报；命中任意一个就算真应用。
    #[test]
    fn any_package_of_a_shared_uid_counts_as_a_real_app() {
        let cfg = Config::default();
        for pkg in [
            "com.tencent.mm,com.tencent.mm:tools",
            "com.google.android.gms,com.google.android.gsf",
            "a.b.c,com.eg.android.AlipayGphone",
        ] {
            assert_eq!(
                reason_with_caller(&cfg, DEV, Some(10490), None, Some(pkg)),
                None,
                "{pkg} 里有一个真应用就该给真机"
            );
        }
        // 一个都不在名单里 → 内置。
        assert!(
            reason_with_caller(&cfg, DEV, Some(10490), None, Some("com.a.one,com.b.two")).is_some()
        );
    }

    /// 缺省名单里放进来来的那几类包名不要手滑删掉（漏一个就是一台真应用被内置料顶掉），
    /// 同时把探测器/测试类的包挡在外面。
    #[test]
    fn the_default_package_list_covers_the_known_real_apps() {
        let known = split_list(DEFAULT_REAL_APP_PACKAGES);
        for pkg in [
            // 腾讯系
            "com.tencent.mm",
            "com.tencent.mobileqq",
            "com.tencent.tim",
            "com.tencent.wework",
            // 支付/银行
            "com.eg.android.AlipayGphone",
            "com.unionpay",
            "com.icbc",
            "cmb.pb",
            "com.webank.wemoney",
            "com.jd.jrapp",
            // 头部应用与运营商
            "com.taobao.taobao",
            "com.xunmeng.pinduoduo",
            "com.sankuai.meituan",
            "com.sdu.didi.psnger",
            "com.sinovatech.unicom.ui",
            // GMS/Play
            "com.google.android.gms",
            "com.android.vending",
        ] {
            assert!(
                known.iter().any(|name| name == pkg),
                "{pkg} 不在缺省真应用名单里"
            );
        }
        // 抖音（含极速版）2026-10-04 按要求移出，别再手滑加回来。
        for pulled in ["com.ss.android.ugc.aweme", "com.ss.android.ugc.aweme.lite"] {
            assert!(
                !known.iter().any(|name| name == pulled),
                "{pulled} 已按要求移出真应用名单"
            );
        }
        // 探测/测试类一个都不能在里面 —— 放进来就是把真机那个 cpu_id 递出去。
        for probe in [
            "com.eltavine.duckdetector",
            "io.github.vvb2060.keyattestation",
            "com.tsng.hidemyapplist",
            "me.weishu.kernelsu",
        ] {
            assert!(
                !known.iter().any(|name| name == probe),
                "{probe} 是探测/测试类，不该进真应用名单"
            );
        }
    }
}
