use super::*;

fn base_config() -> FilterConfig {
    // 默认值现在是「全局作用域开」，而这个文件里绝大多数用例测的是**列表模式**，
    // 所以基线配置里显式关掉；要测全局模式的用例自己置 true。
    FilterConfig {
        global_scope: false,
        ..FilterConfig::default()
    }
}

fn base_scope() -> Vec<String> {
    vec!["com.allowed".to_string()]
}

#[test]
fn engineermode_domain_is_intercepted_on_system_uid() {
    // 一加/OPPO 工程模式：uid 1000 + engineermode_app 域。它的 Key 状态页要做
    // attestation 自检，必须落到 ommega 才看得到我们的链。
    let mut config = base_config();
    config.global_scope = true;
    let scope = vec![
        "com.allowed".to_string(),
        "com.oplus.engineermode".to_string(),
    ];

    let decision = evaluate_with_sid(
        &scope,
        &config,
        1000,
        "u:r:engineermode_app:s0",
        PackageResolution::Unknown,
    );
    assert!(decision.allowed, "engineermode should be intercepted");
    assert_eq!(decision.reason, FilterReason::GlobalScope);
}

#[test]
fn engineermode_domain_is_intercepted_without_global_scope_when_listed() {
    // 没开全局作用域：只按 scoop 判定。uid 1000 解析不出包名（packages=[]），
    // 所以靠 `system_sid_packages` 把域映射回包名，让它跟普通 app 一样命中 scoop。
    let config = base_config();
    let scope = vec!["com.oplus.engineermode".to_string()];

    let decision = evaluate_with_sid(
        &scope,
        &config,
        1000,
        "u:r:engineermode_app:s0",
        PackageResolution::Unknown,
    );
    assert!(decision.allowed, "engineermode is listed in scoop");
    assert_eq!(decision.reason, FilterReason::Allowed);
    assert_eq!(
        decision.packages,
        vec!["com.oplus.engineermode".to_string()]
    );
}

#[test]
fn engineermode_domain_stays_out_when_not_listed() {
    // 没开全局、scoop 里也没它：就不接管，严格按配置来。
    let config = base_config();

    let decision = evaluate_with_sid(
        &base_scope(),
        &config,
        1000,
        "u:r:engineermode_app:s0",
        PackageResolution::Unknown,
    );
    assert!(!decision.allowed, "not listed in scoop, must stay out");
    assert_eq!(decision.reason, FilterReason::RejectedNotInScope);
}

#[test]
fn platform_domain_on_system_uid_stays_on_system_backend() {
    // system_server / init / keystore 这些平台域一律不接管（boot loop 前车之鉴）。
    let mut config = base_config();
    config.global_scope = true;

    for sid in ["u:r:system_server:s0", "u:r:init:s0", "u:r:keystore:s0"] {
        let decision = evaluate_with_sid(
            &base_scope(),
            &config,
            1000,
            sid,
            PackageResolution::Unknown,
        );
        assert!(!decision.allowed, "{sid} must stay on the system backend");
        assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
    }
}

#[test]
fn unrelated_rom_app_domain_is_not_intercepted_by_default() {
    // 默认只认 engineermode 这个域，别的 ROM app 域不乱接管（旧 key blob 会解不开）。
    let mut config = base_config();
    config.global_scope = true;
    let scope = vec!["com.allowed".to_string(), "com.zte.usebalance".to_string()];

    let decision = evaluate_with_sid(
        &scope,
        &config,
        1000,
        "u:r:zte_balance_app:s0",
        PackageResolution::Unknown,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
}

#[test]
fn disabled_filter_reports_disabled_and_allows() {
    let mut config = base_config();
    config.enabled = false;

    let decision = evaluate(&base_scope(), &config, 10_000, PackageResolution::Unknown);
    assert!(decision.allowed);
    assert_eq!(decision.reason, FilterReason::Disabled);
}

/// 主开关关着也不能把系统进程接过来：否则 `enabled = false` 一改就变成“开机期
/// keystore 流量全拐到我们”，系统拿到用不了的回复就是重启。
#[test]
fn disabled_filter_still_rejects_non_app_callers() {
    let mut config = base_config();
    config.enabled = false;

    for uid in [0u32, 1000, 2000, 1017] {
        let decision = evaluate(&base_scope(), &config, uid, PackageResolution::Unknown);
        assert!(!decision.allowed, "uid {uid} 不该被接管");
        assert_eq!(decision.reason, FilterReason::RejectedAndroidPackage);
    }

    // 显式绑定的系统 app 域（工程模式）仍然放行
    let decision = evaluate_with_sid(
        &base_scope(),
        &config,
        1000,
        "u:r:engineermode_app:s0",
        PackageResolution::Unknown,
    );
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

/// The maintenance / authorization branches in `hook::rewrite::request` only
/// fire for non-app callers, so an app cannot have its wrong-interface-token
/// transaction answered from ommega's synthetic maintenance path.
#[test]
fn global_state_interfaces_are_platform_callers_only() {
    // init, system_server, keystore itself, shell, root
    assert!(is_global_state_caller(0));
    assert!(is_global_state_caller(1000));
    assert!(is_global_state_caller(2000));

    // ordinary apps, including secondary users / work profiles
    assert!(!is_global_state_caller(10_000));
    assert!(!is_global_state_caller(10_540));
    assert!(!is_global_state_caller(10_540 + AID_USER_OFFSET as i64));

    // an unset/garbage uid must not be read as uid 0
    assert!(!is_global_state_caller(-1));
}
