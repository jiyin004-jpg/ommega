use kmr_common::consts::{AID_APP_START, AID_USER_OFFSET};

use crate::config::FilterConfig;

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

pub fn evaluate(
    scoop: &[String],
    config: &FilterConfig,
    uid: u32,
    resolution: PackageResolution,
) -> FilterDecision {
    if !config.enabled {
        return FilterDecision {
            allowed: true,
            reason: FilterReason::Disabled,
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
    if config.block_android_package && uid % AID_USER_OFFSET < AID_APP_START {
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
        // deny_packages 是安全阀（防 com.zte.* 开机循环那类事故），必须压过
        // scoop 显式收录——与非全局路径（denylist 先于 scope）口径一致，否则
        // target.txt 并入 scoop 后 overlap 的 deny 条目会静默失效。
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

    if config.block_android_package && uid % AID_USER_OFFSET < AID_APP_START {
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
