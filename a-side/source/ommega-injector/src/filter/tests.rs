use super::*;

fn base_config() -> FilterConfig {
    FilterConfig::default()
}

fn base_scope() -> Vec<String> {
    vec!["com.allowed".to_string()]
}

#[test]
fn disabled_filter_reports_disabled_and_allows() {
    let mut config = base_config();
    config.enabled = false;

    let decision = evaluate(&base_scope(), &config, 10_000, PackageResolution::Unknown);
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::Disabled);
}

#[test]
fn android_package_is_rejected_when_blocking_is_enabled() {
    let config = base_config();
    let scope = vec!["android".to_string()];

    let decision = evaluate(
        &scope,
        &config,
        10_000,
        PackageResolution::Known(vec!["android".to_string()]),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
}

#[test]
fn denylist_rejection_takes_precedence_over_scope() {
    let mut config = base_config();
    config.block_android_package = false;
    config.deny_packages = vec!["com.example.app".to_string()];
    let scope = vec!["com.example.app".to_string()];

    let decision = evaluate(
        &scope,
        &config,
        10_000,
        PackageResolution::Known(vec!["com.example.app".to_string()]),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedByDenylist);
}

#[test]
fn known_package_outside_scope_is_rejected() {
    let mut config = base_config();
    config.block_android_package = false;

    let decision = evaluate(
        &base_scope(),
        &config,
        10_000,
        PackageResolution::Known(vec!["com.other".to_string()]),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedNotInScope);
}

#[test]
fn unknown_package_policy_only_allows_app_uids() {
    let mut config = base_config();
    config.allow_unknown_package = true;

    for uid in [10_000, 110_000] {
        let decision = evaluate(&base_scope(), &config, uid, PackageResolution::Unknown);
        assert!(decision.allowed);
        assert_eq!(decision.reason, FilterReason::Allowed);
    }
    for uid in [9_999, 109_999] {
        let decision = evaluate(&base_scope(), &config, uid, PackageResolution::Unknown);
        assert!(!decision.allowed);
        assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
    }
}

#[test]
fn root_follows_android_package_policy() {
    let mut config = base_config();
    config.allow_unknown_package = true;

    let decision = evaluate(&base_scope(), &config, 0, PackageResolution::Unknown);
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);

    config.block_android_package = false;
    let decision = evaluate(&base_scope(), &config, 0, PackageResolution::Unknown);
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::Allowed);
}

#[test]
fn android_prefixed_package_in_scope_is_allowed() {
    let config = base_config();
    let scope = vec!["com.android.vending".to_string()];
    let decision = evaluate(
        &scope,
        &config,
        10_000,
        PackageResolution::Known(scope.clone()),
    );
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::Allowed);
}

#[test]
fn empty_scope_keeps_android_and_denylist_precedence() {
    let mut config = base_config();
    config.block_android_package = false;
    let decision = evaluate(
        &[],
        &config,
        10_000,
        PackageResolution::Known(vec!["com.anything".to_string()]),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedNotInScope);

    let config = base_config();
    let decision = evaluate(
        &[],
        &config,
        10_000,
        PackageResolution::Known(vec!["android".to_string()]),
    );
    assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);

    let mut config = base_config();
    config.block_android_package = false;
    config.deny_packages = vec!["com.blocked".to_string()];
    let decision = evaluate(
        &[],
        &config,
        10_000,
        PackageResolution::Known(vec!["com.blocked".to_string()]),
    );
    assert_eq!(decision.reason, FilterReason::RejectedByDenylist);
}

#[test]
fn global_scope_intercepts_apps_outside_the_scoop() {
    let mut config = base_config();
    config.global_scope = true;

    let decision = evaluate(
        &[],
        &config,
        10_000,
        PackageResolution::Known(vec!["com.outside".to_string()]),
    );
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::GlobalScope);
    assert_eq!(decision.packages, vec!["com.outside".to_string()]);
}

#[test]
fn global_scope_intercepts_unresolvable_packages_on_app_uids() {
    let mut config = base_config();
    config.global_scope = true;

    let decision = evaluate(&[], &config, 10_123, PackageResolution::Unknown);
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::GlobalScope);
    assert!(decision.packages.is_empty());
}

#[test]
fn global_scope_keeps_non_app_uids_on_the_system_backend() {
    // Intercepting system_server/keystore/root keystore traffic under global
    // scope made the device restart right after boot; these callers must keep
    // reaching the real backend.
    let mut config = base_config();
    config.global_scope = true;

    for uid in [0, 1_000, 1_017, 2_000] {
        let decision = evaluate(&[], &config, uid, PackageResolution::Unknown);
        assert!(
            !decision.allowed,
            "uid {uid} must stay on the system backend"
        );
        assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
    }
}

#[test]
fn global_scope_leaves_unlisted_rom_packages_alone() {
    // A ROM service holds keys minted before ommega ran; taking it over broke
    // the device (com.zte.usebalance -> boot loop), so global scope skips it.
    let mut config = base_config();
    config.global_scope = true;

    let decision = evaluate(
        &[],
        &config,
        10_342,
        PackageResolution::Known(vec!["com.zte.usebalance".to_string()]),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedSystemPackage);
}

#[test]
fn global_scope_intercepts_google_components_even_when_unlisted() {
    // Play / GMS are ROM components, but users expect them spoofed on every
    // device, so global scope intercepts them without a scoop entry.
    let mut config = base_config();
    config.global_scope = true;

    for package in [
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending",
    ] {
        let decision = evaluate(
            &[],
            &config,
            10_123,
            PackageResolution::Known(vec![package.to_string()]),
        );
        assert!(decision.allowed, "{package} should be handled");
        assert_eq!(decision.reason, FilterReason::GlobalScope);
    }
}

#[test]
fn global_scope_still_intercepts_listed_rom_components() {
    // An explicit scoop entry also covers ROM components that the heuristic
    // would otherwise leave alone.
    let mut config = base_config();
    config.global_scope = true;

    let decision = evaluate(
        &["com.zte.somecomponent".to_string()],
        &config,
        10_400,
        PackageResolution::Known(vec!["com.zte.somecomponent".to_string()]),
    );
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::GlobalScope);
}

#[test]
fn global_scope_still_honours_the_denylist() {
    // The denylist stays the escape hatch even in global scope.
    let mut config = base_config();
    config.global_scope = true;
    config.deny_packages = vec!["com.blocked".to_string()];

    let decision = evaluate(
        &[],
        &config,
        10_000,
        PackageResolution::Known(vec!["com.blocked".to_string()]),
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedByDenylist);
}

#[test]
fn disabled_filter_wins_over_global_scope() {
    let mut config = base_config();
    config.enabled = false;
    config.global_scope = true;

    let decision = evaluate(
        &base_scope(),
        &config,
        10_000,
        PackageResolution::Known(vec!["com.allowed".to_string()]),
    );
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::Disabled);
}
