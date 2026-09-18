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
    /// `filter.global_scope` is on: every caller is handled by ommega,
    /// regardless of `scoop` / deny list / package resolution.
    GlobalScope,
    RejectedAndroidPackage,
    RejectedByDenylist,
    RejectedNotInScope,
    RejectedUnknownPackage,
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

    // Global scope ("全局作用域", toggled in the A-side WebUI's remote config):
    // intercept everything — the scope list, `deny_packages`, the
    // android-package rule and the unknown-package rule are all skipped, so
    // whoever calls is handled.  Only the master switch above can still turn
    // interception off.  Whether a handled request is served locally or by the
    // remote relay is decided elsewhere and is not affected by this setting.
    if config.global_scope {
        return FilterDecision {
            allowed: true,
            reason: FilterReason::GlobalScope,
            packages: match resolution {
                PackageResolution::Known(packages) => packages,
                PackageResolution::Unknown => Vec::new(),
            },
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
