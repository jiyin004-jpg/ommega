use kmr_common::consts::{AID_APP_START, AID_USER_OFFSET};

use crate::config::FilterConfig;

/// Whether `uid` may drive keystore's *global* state interfaces
/// (`IKeystoreMaintenance` / `IKeystoreAuthorization`).
///
/// Both of those interfaces are platform entry points (init, system_server, the
/// keystore updater, vold) that a third-party app cannot reach through
/// keystore2's own nodes.  The injector used to pick the maintenance /
/// authorization branch from the parcel's interface token alone, so an app
/// could dial a maintenance-token transaction into the *service* node and still
/// be handed a maintenance-shaped (and state-changing) reply, while the real
/// keystore2 answers BAD_TYPE and changes nothing.  That divergence is directly
/// observable from an app - TrustAttestor reports it as
/// `hardware.attestation.interface_token_dispatch` ("wrong interface token
/// dispatched to a Keystore maintenance transaction").
///
/// The token therefore never decides on its own: both branches additionally
/// require a non-app caller, exactly like the system-backend rule in
/// [`evaluate`].  The uid comes from the binder header (`sender_euid`), which the
/// kernel fills in, so a caller cannot forge it.
pub fn is_global_state_caller(uid: i64) -> bool {
    u32::try_from(uid).is_ok_and(|uid| uid % AID_USER_OFFSET < AID_APP_START)
}

#[derive(Debug, Clone)]
pub enum PackageResolution {
    Known(Vec<String>),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterReason {
    Disabled,
    Allowed,
    /// `filter.global_scope` is on: an ordinary app (or an explicitly listed
    /// component) is handled by ommega even though it is not in `scoop`.
    GlobalScope,
    RejectedAndroidPackage,
    RejectedByDenylist,
    RejectedNotInScope,
    RejectedUnknownPackage,
    /// Global scope is on, but the caller is a ROM system package that was not
    /// listed explicitly, so it keeps using the system backend.
    RejectedSystemPackage,
}

/// Components global scope always intercepts, listed or not: Google Play and
/// the GMS/GFS stack are what users expect to be spoofed on every device.
const GLOBAL_SCOPE_ALWAYS: &[&str] = &["com.google.", "com.android.vending"];

/// Package-name prefixes of ROM/vendor system components.  Global scope leaves
/// these on the system backend (unless listed in `scoop`): they hold keys minted
/// before ommega ran, and a ROM service losing access to them can restart the
/// whole system.
const SYSTEM_PACKAGE_PREFIXES: &[&str] = &[
    // "android" 精确匹配裸系统包；"android." 前缀不能省掉点号，否则
    // androidx.* 这类应用包也会被 starts_with("android") 误判成 ROM 组件。
    "android",
    "android.",
    "com.android.",
    "com.zte.",
    "com.qualcomm.",
    "com.mediatek.",
    "com.oplus.",
    "com.oneplus.",
    "com.coloros.",
    "com.miui.",
    "com.xiaomi.",
    "com.samsung.",
    "com.sec.",
    "com.huawei.",
    "com.hihonor.",
    "com.vivo.",
    "com.bbk.",
    "com.nubia.",
    "cn.nubia.",
    "com.meizu.",
    "com.motorola.",
    "com.transsion.",
    "com.sony.",
    "com.lge.",
    "org.codeaurora.",
];

/// Best-effort classification of a package as a system/ROM component.  Package
/// names are all the filter has (the caller's ApplicationInfo is not reachable
/// from inside keystore2), so this is a prefix heuristic; `scoop` overrides it,
/// and `GLOBAL_SCOPE_ALWAYS` wins over the heuristic.
fn is_system_package_name(package: &str) -> bool {
    if GLOBAL_SCOPE_ALWAYS
        .iter()
        .any(|prefix| package.starts_with(prefix))
    {
        return false;
    }
    SYSTEM_PACKAGE_PREFIXES.iter().any(|prefix| {
        // 带点的项才是前缀；不带点的（目前只有裸的 "android"）只能精确匹配，
        // 否则 starts_with("android") 会把 androidx.* / androidauto.* 这些
        // 应用包一起当 ROM 组件吞掉。
        if prefix.ends_with('.') {
            package.starts_with(prefix)
        } else {
            package == *prefix
        }
    })
}

#[derive(Debug, Clone)]
pub struct FilterDecision {
    pub allowed: bool,
    pub reason: FilterReason,
    pub packages: Vec<String>,
}

/// 系统 uid（< AID_APP_START）里额外放行接管的那部分调用方。
///
/// 这些进程 uid 落在 system 范围，但 SELinux 域是 `u:r:xxx_app:s0`，也就是 ROM
/// 自带的 app（一加/OPPO 的工程模式就是 `engineermode_app`），不是 system_server
/// / init / keystore 那种平台进程——接管它们的 keystore 流量不会把系统拖进 boot
/// loop。默认只放 `engineermode`（它现场建 test_key 用完就删，不依赖旧 blob）；
/// 别的 ROM 组件要接管，往 config 的 `allow_system_sids` 里加域前缀。
fn sid_allows_system_uid(sid: &str, config: &FilterConfig) -> bool {
    let domain = sid.split(':').nth(2).unwrap_or("");
    if !domain.ends_with("_app") {
        return false;
    }
    if config
        .allow_system_sids
        .iter()
        .any(|prefix| !prefix.is_empty() && domain.contains(prefix.as_str()))
    {
        return true;
    }
    config
        .system_sid_packages
        .keys()
        .any(|prefix| !prefix.is_empty() && domain.contains(prefix.as_str()))
}

/// 系统 uid 的 app 域对应的包名（见 [`FilterConfig::system_sid_packages`]）。
///
/// `getKeyAttestationApplicationId` 对 uid 1000 返回空，包名解析不出来，按包
/// 判定的 scope 就永远命不中；这里把域映射回包名，后面照常走 scope 判定。
fn sid_mapped_packages(sid: &str, config: &FilterConfig) -> Vec<String> {
    let domain = sid.split(':').nth(2).unwrap_or("");
    if domain.is_empty() {
        return Vec::new();
    }
    config
        .system_sid_packages
        .iter()
        .filter(|(prefix, _)| !prefix.is_empty() && domain.contains(prefix.as_str()))
        .flat_map(|(_, packages)| packages.iter().cloned())
        .collect()
}

pub fn evaluate(
    scoop: &[String],
    config: &FilterConfig,
    uid: u32,
    resolution: PackageResolution,
) -> FilterDecision {
    evaluate_with_sid(scoop, config, uid, "", resolution)
}

/// [`evaluate`] 带调用方 SELinux 上下文：系统 uid 的 ROM app（见
/// [`sid_allows_system_uid`]）也能走到接管分支。
pub fn evaluate_with_sid(
    scoop: &[String],
    config: &FilterConfig,
    uid: u32,
    sid: &str,
    resolution: PackageResolution,
) -> FilterDecision {
    let mut resolution = resolution;
    // 系统 uid 的 ROM app：uid 1000 解析出来的是「所有系统包 + android」，直接按它
    // 判定两头不占好——`android` 前缀会把每笔调用当平台流量拒掉，scoop 里也永远
    // 对不上。sid 命中映射时就用映射的包名整个换掉，之后照常走 scope 判定。
    let mapped = sid_mapped_packages(sid, config);
    if !mapped.is_empty() {
        resolution = PackageResolution::Known(mapped);
    }

    if !config.enabled {
        // 主开关关着 ≠“谁都能接”：系统进程（init / system_server / keystore /
        // vold / root）一律留在系统后端，否则开机期的 keystore 流量会全拐到我们这里，
        // 系统拿到它用不了的回复就是开机即重启。普通应用（每用户 10000–19999）
        // 和显式绑定的系统 app 域照旧放行。
        let app_uid = uid % AID_USER_OFFSET >= AID_APP_START;
        let allowed = app_uid || sid_allows_system_uid(sid, config);
        return FilterDecision {
            allowed,
            reason: if allowed {
                FilterReason::Disabled
            } else {
                FilterReason::RejectedAndroidPackage
            },
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }

    // Non-app callers (uid < AID_APP_START: init, system_server, keystore
    // itself, root, shell) always stay on the system backend, global scope or
    // not.  Intercepting system_server's own keystore traffic during boot makes
    // the system take a reply it cannot use and restart - observed on-device as
    // "boots and immediately powers off/reboots" with `global_scope: true`.
    if config.block_android_package
        && uid % AID_USER_OFFSET < AID_APP_START
        && !sid_allows_system_uid(sid, config)
    {
        return FilterDecision {
            allowed: false,
            reason: FilterReason::RejectedAndroidPackage,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }
    // Global scope ("全局作用域", toggled in the A-side WebUI's remote config)
    // intercepts ordinary apps, and *also* whatever is listed in the scope
    // explicitly (so Google Play / GMS components keep being handled).  ROM
    // system packages that were never listed are left on the system backend:
    // they already hold keys in the system keystore, so taking them over breaks
    // their blobs - a ROM service failing like that has already taken a device
    // into a boot loop (`com.zte.usebalance`).  `deny_packages` stays the
    // escape hatch on top of that.  Only the master switch turns interception
    // off entirely; whether a handled request is served locally or remotely is
    // decided elsewhere and is not affected by this setting.
    if config.global_scope {
        let packages = match resolution {
            PackageResolution::Known(packages) => packages,
            PackageResolution::Unknown => Vec::new(),
        };
        let explicitly_in_scope =
            !scoop.is_empty() && packages.iter().any(|pkg| scoop.iter().any(|s| s == pkg));
        let denied = packages
            .iter()
            .any(|pkg| config.deny_packages.contains(pkg));
        let system_like = packages.iter().any(|pkg| is_system_package_name(pkg));
        // deny_packages 是安全阀（防开机循环那类事故），必须压过 scoop 显式收录
        // ——与非全局路径（denylist 先于 scope）口径一致，否则 target.txt 并入
        // scoop 后 overlap 的 deny 条目会静默失效。
        let allowed = !denied && (explicitly_in_scope || !system_like);
        return FilterDecision {
            allowed,
            reason: if allowed {
                FilterReason::GlobalScope
            } else if denied {
                FilterReason::RejectedByDenylist
            } else {
                FilterReason::RejectedSystemPackage
            },
            packages,
        };
    }

    if config.block_android_package
        && uid % AID_USER_OFFSET < AID_APP_START
        && !sid_allows_system_uid(sid, config)
    {
        return FilterDecision {
            allowed: false,
            reason: FilterReason::RejectedAndroidPackage,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
        };
    }

    let packages = match resolution {
        PackageResolution::Known(packages) => packages,
        PackageResolution::Unknown => {
            let allowed = config.allow_unknown_package;
            return FilterDecision {
                allowed,
                reason: if allowed {
                    FilterReason::Allowed
                } else {
                    FilterReason::RejectedUnknownPackage
                },
                packages: Vec::new(),
            };
        }
    };

    let reason = if config.block_android_package
        && packages
            .iter()
            .any(|pkg| pkg == "android" || pkg.starts_with("android."))
    {
        FilterReason::RejectedAndroidPackage
    } else if packages
        .iter()
        .any(|pkg| config.deny_packages.contains(pkg))
    {
        FilterReason::RejectedByDenylist
    } else if !packages.iter().any(|pkg| scoop.contains(pkg)) {
        FilterReason::RejectedNotInScope
    } else {
        FilterReason::Allowed
    };

    FilterDecision {
        allowed: reason == FilterReason::Allowed,
        reason,
        packages,
    }
}

#[cfg(test)]
mod tests;
