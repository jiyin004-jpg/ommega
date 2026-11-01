//! 让本机真 TEE 按 A 端声明的补丁日期出链。
//!
//! KeyMint HAL 只在进程启动那一刻读一次 `ro.build.version.security_patch` /
//! `ro.vendor.build.security_patch`（打包成 tag 705/706/718 一次性交给 TEE），之后就
//! 再也不看属性。所以「让链上的日期跟着 A 端走」必须两步：先 resetprop 改属性，再让
//! HAL 重读；只改属性链上不会变（2026-10-15 在 PLC110 / Trustonic 上实测过）。
//!
//! 默认关闭，relay.conf 里开 `OMMEGA_RELAY_PATCHLEVEL_FOLLOW_A=true`。
//! 只在请求真带了日期、且与本机当前值不一致时才动，平时一分一秒都不多花。

use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

use crate::keymaster::attest_proxy::{SYSTEM_KEYMINT_DEFAULT, SYSTEM_KEYMINT_STRONGBOX};
use crate::keymaster::relay_tee::clear_system_keymint;

/// 开关是 relay.conf 的 `OMMEGA_RELAY_PATCHLEVEL_FOLLOW_A`（由 `RelayConfig` 热重载，
/// 改完不用重启进程）。
pub const FOLLOW_KEY: &str = "OMMEGA_RELAY_PATCHLEVEL_FOLLOW_A";

/// 这些包**不**跟随（黑名单，逗号分隔，匹配 tag 709 里的包名）：碰到它们就不动
/// 属性、不重启 HAL，直接拿本机现在的值出链。
/// **留空 = 全都跟**（旧行为）。
pub const FOLLOW_PKGS_KEY: &str = "OMMEGA_RELAY_PATCHLEVEL_SKIP_PKGS";

const OS_PROP: &str = "ro.build.version.security_patch";
const VENDOR_PROP: &str = "ro.vendor.build.security_patch";

/// TEE 把 `os_version` 算成「主版本*10000 + 次版本*100」，而它读的是这几个字符串属性
/// （不同厂商的 TA 读的不是同一个，所以能读到的都同步一份）。
///
/// `ro.build.version.sdk` 故意不动：那里是 36 这种整数，拿去算会变成 360000；
/// 而且改它会让本机所有应用看到的 API 级别跟着变，影响面远超这一条链。
const RELEASE_PROPS: &[&str] = &[
    "ro.build.version.release",
    "ro.build.version.release_or_codename",
    "ro.system.build.version.release",
    "ro.system.build.version.release_or_codename",
];

/// `os_version` 160000 → `"16"`；161000 → `"16.1"`。越界返回 None。
fn release_value(v: i64) -> Option<String> {
    let major = v / 10_000;
    let minor = (v / 100) % 100;
    if !(8..=99).contains(&major) || !(0..=99).contains(&minor) {
        return None;
    }
    if minor == 0 {
        Some(format!("{major}"))
    } else {
        Some(format!("{major}.{minor}"))
    }
}

/// 开机时真机原值的落盘位置（面板恢复按钮读它）。
const BASELINE_FILE: &str = "/data/adb/ommega-b/conf/baseline.props";

/// 用户存储（CE）是否已就绪。`true` 等于「开机后至少解过一次锁」。
const CE_AVAILABLE_PROP: &str = "sys.user.0.ce_available";

/// 没解锁就不许动 TEE：keystore2 在「开机后还没解过锁」的状态下被重启，解锁流程依赖
/// 的认证绑定会失效 —— 密码输对了也解不开（2026-10-17 在 PLC110 上实测）。所以这两项
/// 是能不能切补丁日期（会连带重启 keymint HAL + keystore2）的前置条件。
fn user_storage_unlocked() -> bool {
    ce_unlocked_from_prop(getprop(CE_AVAILABLE_PROP).ok().as_deref())
}

/// 单独拆出来好写单测。
fn ce_unlocked_from_prop(value: Option<&str>) -> bool {
    matches!(value, Some("true"))
}

/// 找 resetprop：模块目录、KernelSU、APatch、Magisk 都试一遍，最后再靠 PATH。
/// 不同 root 管理器的位置就是不一样，只认一个等于「换了管理器这功能就没了」。
const RESETPROP_CANDIDATES: &[&str] = &[
    "/data/adb/ommega-b/bin/resetprop",
    "/data/adb/ksu/bin/resetprop",
    "/data/adb/ap/bin/resetprop",
    "/data/adb/magisk/resetprop",
    "/debug_ramdisk/resetprop",
];

static KNOWN_SERVICE: OnceLock<Mutex<Option<String>>> = OnceLock::new();

/// 本机原始的三个值（第一次跟着改之前记下来）。
///
/// 为什么要记：跟完之后属性会一直是 A 的值，本机所有应用看到的系统版本/补丁日期
/// 都变成别人的。所以每笔出完链必须自己回原值 —— 用这份基线，而不是「上一笔的值」：
/// 上一笔可能已经是 A 的，拿它当基线就永远回不去了。
/// 三个补丁相关属性的名字 -> 原始值。
type Baseline = Vec<(String, String)>;

static BASELINE: OnceLock<Mutex<Option<Baseline>>> = OnceLock::new();

fn baseline_slot() -> &'static Mutex<Option<Baseline>> {
    BASELINE.get_or_init(|| Mutex::new(None))
}

/// 第一次动属性前把三项的原值记下来（只记一次）。
fn remember_baseline(props: &[&str]) {
    let mut slot = match baseline_slot().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    if slot.is_some() {
        return;
    }
    let mut pairs = Vec::new();
    for prop in props {
        if let Ok(v) = getprop(prop) {
            if !v.is_empty() {
                pairs.push(((*prop).to_string(), v));
            }
        }
    }
    // 落一份到磁盘：面板的「停止模块 / 恢复并重启」要拿它把真机原值写回去，
    // 而面板是另一个进程、拿不到这里的内存。
    let mut text = String::new();
    for (k, v) in &pairs {
        text.push_str(k);
        text.push_str(": ");
        text.push_str(v);
        text.push('\n');
    }
    if !text.is_empty() {
        if let Some(dir) = std::path::Path::new(BASELINE_FILE).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if !std::path::Path::new(BASELINE_FILE).exists() {
            if let Err(e) = std::fs::write(BASELINE_FILE, text) {
                log::warn!("patchlevel: 写基线文件失败: {e:#}");
            }
        }
    }
    *slot = Some(pairs);
}

/// 对齐 + 出链之间不能被别的请求插进来，见 [`lock`]。
static ATTEST_LOCK: Mutex<()> = Mutex::new(());

/// 把「按 A 端日期对齐」和「铸钥匙」两步锁在一起。
///
/// 开了跟随开关之后每一笔 attest 都要拿这把锁：两个请求各自改了属性、各自弹了 HAL
/// 再出链，中间一交叉，铸出来的链就不是它自己声明的值了（2026-10-15 在 PLC110 上
/// 实测到过：另一台 A 的请求插进来把值翻了回去）。
pub fn lock() -> std::sync::MutexGuard<'static, ()> {
    ATTEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn getprop(key: &str) -> Result<String> {
    let out = Command::new("getprop")
        .arg(key)
        .output()
        .with_context(|| format!("run getprop {key}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn resetprop(key: &str, value: &str) -> Result<()> {
    let mut failures: Vec<String> = Vec::new();
    let mut candidates: Vec<String> = RESETPROP_CANDIDATES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    candidates.push("resetprop".to_string());
    for cand in candidates {
        // 绝对路径的先看看在不在；不在就跳过。
        if cand.starts_with('/') && !std::path::Path::new(&cand).exists() {
            continue;
        }
        match Command::new(&cand).args([key, value]).output() {
            Ok(o) if o.status.success() => return Ok(()),
            Ok(o) => failures.push(format!(
                "{cand}: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => failures.push(format!("{cand}: {e}")),
        }
    }
    if failures.is_empty() {
        failures.push("没找到可用的 resetprop".to_string());
    }
    Err(anyhow!("{}", failures.join("; ")))
}

fn ymd(year: i64, month: i64, day: i64) -> Option<String> {
    if !(2000..=2099).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(format!("{year:04}-{month:02}-{day:02}"))
}

/// A 端的 `os_patch_level` 是 YYYYMM → 属性要 "YYYY-MM-01"。
fn os_prop_value(v: i64) -> Option<String> {
    ymd(v / 100, v % 100, 1)
}

/// A 端的 `vendor_patch_level` 是 YYYYMMDD → 属性要 "YYYY-MM-DD"。
fn vendor_prop_value(v: i64) -> Option<String> {
    ymd(v / 10000, (v / 100) % 100, v % 100)
}

/// tag 709 的 DER 里含请求方的包名；列表命中才跟随。
fn payload_package(payload: &Value) -> Option<String> {
    let ctx = payload.get("device_attest_context").unwrap_or(payload);
    let raw = ctx
        .get("attestation_application_id")
        .or_else(|| payload.get("attestation_application_id"))
        .and_then(Value::as_str)?;
    let der = base64_decode(raw)?;
    Some(String::from_utf8_lossy(&der).to_string())
}

fn base64_decode(raw: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(raw.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in raw.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = T.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// 这个请求的 AAID 包名是否命中了黑名单。命中了就不跟随。
pub fn package_blocked(payload: &Value, blocked: &[String]) -> bool {
    if blocked.is_empty() {
        return false;
    }
    let Some(aaid) = payload_package(payload) else {
        return false;
    };
    blocked
        .iter()
        .any(|p| !p.is_empty() && aaid.contains(p.as_str()))
}

/// 从 1.7.0 起 A 端才会在请求里带自己的版本号。低于这个版本的（或者压根没带
/// `client_version` 的旧客户端）不跟随：它们上报的日期格式也还是旧的 YYYYMM。
const FOLLOW_MIN_VERSION: (u32, u32, u32) = (1, 7, 0);

fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.trim().split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .split(['-', '+'])
        .next()
        .unwrap_or("0")
        .parse::<u32>()
        .ok()?;
    Some((major, minor, patch))
}

/// A 端版本 ≥ 1.7.0 才跟随。
pub fn client_version_ok(payload: &Value) -> bool {
    let ctx = payload.get("device_attest_context").unwrap_or(payload);
    ctx.get("client_version")
        .or_else(|| payload.get("client_version"))
        .and_then(Value::as_str)
        .and_then(parse_version)
        .is_some_and(|v| v >= FOLLOW_MIN_VERSION)
}

/// 这个值要不要动：和**本机原值**（开机时的真实值）比，一样就不动。
///
/// 之所以要拿基线比而不是「当前属性值」：上一次搞脏了（比如还原失败）之后属性已经不
/// 是本机原值了，拿它当参照会把本该改的回合当成「已经匹配」。
fn value_matches(_prop: &str, base: &str, want: &str) -> bool {
    base.trim() == want.trim()
}

/// 把 A 端在 `device_attest_context` 里声明的版本号/补丁日期落到本机 TEE 上。
///
/// 返回 `Some(说明)` 表示这次真动了属性（并让 HAL 重读了）；`None` 表示不用动——
/// 开关没开、请求里没带、或者**跟本机原值一样**（A 端已经同步成全一致时就是这样，
/// 这时候不该为了一笔请求去折腾 HAL 和 keystore2）。
pub fn follow_a_side(payload: &Value, on: bool) -> Option<String> {
    if !on {
        return None;
    }
    // 字段可能在顶层，也可能在 `device_attest_context` 里（server 两种都发过）。
    let ctx = payload.get("device_attest_context").unwrap_or(payload);
    let want_os = ctx
        .get("os_patch_level")
        .and_then(Value::as_i64)
        .and_then(os_prop_value);
    let want_vendor = ctx
        .get("vendor_patch_level")
        .and_then(Value::as_i64)
        .and_then(vendor_prop_value);
    let want_release = ctx
        .get("os_version")
        .and_then(Value::as_i64)
        .filter(|v| (10_000..=999_999).contains(v))
        .and_then(release_value);
    if want_os.is_none() && want_vendor.is_none() && want_release.is_none() {
        return None;
    }

    // 锁屏期不动：这笔直接按本机当前值出链（跟「不带日期的老客户端」同一条降级路），
    // 等解锁后的下一笔再切。否则会出现「输对密码进不了桌面」。
    if !user_storage_unlocked() {
        log::info!("patchlevel follow: 设备还没解锁（CE 未就绪），这笔跳过、不改补丁日期");
        return None;
    }

    let mut applied: Vec<String> = Vec::new();
    let mut baseline_props: Vec<&str> = vec![OS_PROP, VENDOR_PROP];
    baseline_props.extend_from_slice(RELEASE_PROPS);
    remember_baseline(&baseline_props);

    // 这轮要落哪些属性。os_version 不直接对应某个属性：它要拆成主/次版本，写到
    // release 那一族字符串属性上；只写本机本来就有的，不凭空造新属性。
    let mut targets: Vec<(String, String)> = Vec::new();
    if let Some(want) = want_os {
        targets.push((OS_PROP.to_string(), want));
    }
    if let Some(want) = want_vendor {
        targets.push((VENDOR_PROP.to_string(), want));
    }
    if let Some(want) = want_release {
        let mut hit = false;
        for prop in RELEASE_PROPS {
            if getprop(prop).map(|v| !v.trim().is_empty()).unwrap_or(false) {
                targets.push(((*prop).to_string(), want.clone()));
                hit = true;
            }
        }
        if !hit {
            log::warn!("patchlevel follow: 本机没有 release 属性可改，os_version 跟随跳过");
        }
    }

    for (prop, want) in targets {
        let prop = prop.as_str();
        if want.is_empty() {
            continue;
        }
        let current = match getprop(prop) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("patchlevel follow: 读 {prop} 失败: {e:#}");
                continue;
            }
        };
        // 只以**当前值**为准：值一致就不动、不弹 HAL；不一致（包括从上次的 A1
        // 改回本机原值）就写回去再重读。以前这里先拿 baseline（第一次记下的本机
        // 原值）比 want，一旦 want 又回到原值就直接 continue —— 但那时 current
        // 还是上一次写进去的 A1，属性/HAL 就停在旧值上了。
        if value_matches(prop, &current, &want) {
            continue;
        }
        if let Err(e) = resetprop(prop, &want) {
            log::warn!("patchlevel follow: 写 {prop}={want} 失败: {e:#}");
            continue;
        }
        applied.push(format!("{prop}: {current} -> {want}"));
    }
    if applied.is_empty() {
        return None;
    }

    // 属性改了还不够，HAL 不重读 TEE 那边还是老值。
    let note = match restart_keymint_hal() {
        Ok(mut note) => {
            // 老句柄跟着进程一起没了，清掉缓存让下一笔重新连。
            clear_system_keymint(SYSTEM_KEYMINT_DEFAULT);
            clear_system_keymint(SYSTEM_KEYMINT_STRONGBOX);
            // keystore2 手里那个旧句柄不会自己重连，不换掉它，本机 App 的密钥操作
            // 就全废（见 restart_keystore2 的注释）。
            match restart_keystore2() {
                Ok(k) => {
                    note.push_str("; ");
                    note.push_str(&k);
                    note
                }
                Err(e) => {
                    log::warn!("patchlevel follow: keystore2 重启失败: {e:#}");
                    format!("{note}; keystore2 重启失败({e:#})")
                }
            }
        }
        Err(e) => {
            log::warn!("patchlevel follow: keymint HAL 重启失败: {e:#}");
            format!("重读失败({e:#})")
        }
    };
    Some(format!(
        "B 端版本/补丁日期跟随 A 端：{}；{note}",
        applied.join(", ")
    ))
}

/// 上一次找到的 keymint 服务名。扫描不能每次都成：上一笔刚 `ctl.restart`、现在正卡在
/// `restarting/stopped` 那一下，就扫不到了 —— 那时候只能靠记住的名字继续弹它。
fn known_service() -> Option<String> {
    KNOWN_SERVICE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|g| g.clone())
}

fn remember_service(name: &str) {
    if let Ok(mut g) = KNOWN_SERVICE.get_or_init(|| Mutex::new(None)).lock() {
        *g = Some(name.to_string());
    }
}

/// `init.svc.*` 里在跑的 keymint 服务。
fn running_keymint_services() -> Vec<String> {
    let Ok(out) = Command::new("getprop").output() else {
        return Vec::new();
    };
    let all = String::from_utf8_lossy(&out.stdout);
    let mut services: Vec<String> = Vec::new();
    for line in all.lines() {
        // 形如 `[init.svc.vendor.keymint-trustonic]: [running]`
        let Some(rest) = line.strip_prefix("[init.svc.") else {
            continue;
        };
        let Some((name, val)) = rest.split_once("]: [") else {
            continue;
        };
        if !name.contains("keymint") {
            continue;
        }
        if val.trim_end_matches(']') != "running" {
            continue;
        }
        services.push(name.to_string());
    }
    services
}

/// 重启 init 管的 keymint HAL：它启动时会重读属性、重新 `TEE_Configure`。
/// 服务名各机型不同（PLC110 是 `vendor.keymint-trustonic`，NX721J 是
/// `vendor.keymint-qti`），所以从 `init.svc.*` 里现找。
fn restart_keymint_hal() -> Result<String> {
    let mut services = running_keymint_services();
    if services.is_empty() {
        // 上一笔刚弹完，这一笔正好撞在它没起来的窗口里；等一两秒再看。
        for _ in 0..6 {
            sleep(Duration::from_millis(300));
            services = running_keymint_services();
            if !services.is_empty() {
                break;
            }
        }
    }
    if services.is_empty() {
        // 还是看不到，就用上次记住的名字继续弹（这个名字 init 认）。
        if let Some(name) = known_service() {
            services.push(name);
        }
    }
    if services.is_empty() {
        return Err(anyhow!("没找到在跑的 keymint HAL 服务"));
    }
    remember_service(&services[0]);

    let mut notes: Vec<String> = Vec::new();
    for svc in services {
        let pid_prop = format!("init.svc_debug_pid.{svc}");
        let before = getprop(&pid_prop).unwrap_or_default();
        Command::new("setprop")
            .args(["ctl.restart", &svc])
            .output()
            .with_context(|| format!("setprop ctl.restart {svc}"))?;
        let mut restarted = false;
        let mut now = before.clone();
        // 最多等 6 秒；等不到也照常出链，只是链上还是旧值。
        for _ in 0..24 {
            sleep(Duration::from_millis(250));
            now = getprop(&pid_prop).unwrap_or_default();
            if !now.is_empty() && now != before {
                restarted = true;
                break;
            }
        }
        notes.push(format!(
            "{svc} {} ({before} -> {now})",
            if restarted {
                "已重读"
            } else {
                "重启没等到"
            }
        ));
    }
    Ok(notes.join("; "))
}

/// 重启 keystore2。弹完 KeyMint HAL 必须跟着做这一步。
///
/// 为什么：HAL 被 `ctl.restart` 换掉之后，keystore2 手里那个句柄就是死的，它不会自己
/// 重连 —— 之后本机所有 App 的生成/签名都回 `SYSTEM_ERROR(4)`（keystore2 日志里是
/// `Binder exception code TRANSACTION_FAILED, 0`），密钥认证这类 App 直接报「无法认证」。
/// 2026-10-15 在 PLC110 上实测：只弹 HAL 不加这一步，之后 keygen 一直失败；把
/// keystore2 一重启立刻恢复（连测两次 GenerateKey 都成功）。
///
/// 只在本笔真改过属性、真弹过 HAL 的时候跑，平时一分一毫都不多花。
fn restart_keystore2() -> Result<String> {
    const SVC: &str = "keystore2";
    const PID_PROP: &str = "init.svc_debug_pid.keystore2";
    let before = getprop(PID_PROP).unwrap_or_default();
    Command::new("setprop")
        .args(["ctl.restart", SVC])
        .output()
        .with_context(|| format!("setprop ctl.restart {SVC}"))?;
    let mut restarted = false;
    let mut now = before.clone();
    // keystore2 起来很快，最多等 3 秒；等不到也照常出链。
    for _ in 0..12 {
        sleep(Duration::from_millis(250));
        now = getprop(PID_PROP).unwrap_or_default();
        if !now.is_empty() && now != before {
            restarted = true;
            break;
        }
    }
    Ok(format!(
        "{SVC} {} ({before} -> {now})",
        if restarted {
            "已重启"
        } else {
            "重启没等到"
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// CE 没就绪（开机后还没解锁）时绝不能往下走，否则重启 keystore2 会把解锁弄坏。
    #[test]
    fn ce_availability_gates_the_switch() {
        assert!(ce_unlocked_from_prop(Some("true")));
        assert!(!ce_unlocked_from_prop(Some("false")));
        assert!(!ce_unlocked_from_prop(Some("")));
        assert!(!ce_unlocked_from_prop(None));
    }

    #[test]
    fn maps_os_version_to_release_string() {
        assert_eq!(release_value(160000).as_deref(), Some("16"));
        assert_eq!(release_value(150000).as_deref(), Some("15"));
        assert_eq!(release_value(161000).as_deref(), Some("16.1"));
        // 越界的不采信（老客户端发 7 之类的值）。
        assert_eq!(release_value(7), None);
        assert_eq!(release_value(0), None);
    }

    #[test]
    fn formats_patch_levels() {
        assert_eq!(os_prop_value(202608).as_deref(), Some("2026-08-01"));
        assert_eq!(vendor_prop_value(20260801).as_deref(), Some("2026-08-01"));
        assert_eq!(os_prop_value(0), None);
        assert_eq!(vendor_prop_value(20261301), None);
    }

    /// 跟本机原值一样就不动（A 端已经全同步的情况），不一样才动。
    #[test]
    fn decides_by_local_original_value() {
        assert!(value_matches(OS_PROP, "2026-08-01", "2026-08-01"));
        assert!(!value_matches(OS_PROP, "2026-08-01", "2026-09-01"));
        assert!(!value_matches(OS_PROP, "2026-08-01", ""));
    }

    #[test]
    fn disabled_by_default() {
        let payload = json!({"device_attest_context": {"os_patch_level": 202608}});
        assert!(follow_a_side(&payload, false).is_none());
    }

    #[test]
    fn ignores_payloads_without_dates() {
        let payload = json!({"device_attest_context": {"key_algorithm": 3}});
        assert!(follow_a_side(&payload, true).is_none());
    }

    #[test]
    fn package_gate_needs_a_match() {
        // "com.example" 的 AttestationApplicationId
        let aaid = "MBYxEjAQBAtjb20uZXhhbXBsZQIBATEA";
        let payload = json!({"device_attest_context": {"attestation_application_id": aaid}});
        assert!(package_blocked(&payload, &["com.example".to_string()]));
        assert!(!package_blocked(&payload, &["com.other.app".to_string()]));
        // 黑名单留空 = 谁都不拦
        assert!(!package_blocked(&payload, &[]));
    }

    #[test]
    fn version_gate_matches_1_7_0() {
        let old = json!({"device_attest_context": {"client_version": "1.6.9"}});
        let missing = json!({"device_attest_context": {"key_algorithm": 3}});
        let same = json!({"device_attest_context": {"client_version": "1.7.0"}});
        let newer = json!({"device_attest_context": {"client_version": "1.10.2-3-gabc"}});
        let top = json!({"client_version": "2.0.0"});
        assert!(!client_version_ok(&old));
        assert!(!client_version_ok(&missing));
        assert!(client_version_ok(&same));
        assert!(client_version_ok(&newer));
        assert!(client_version_ok(&top));
    }
}
