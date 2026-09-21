use super::*;
use crate::hook::rewrite::tests::*;
use crate::{
    android::system::keystore2::Domain::Domain,
    android::system::keystore2::IKeystoreService::transactions as service_tx,
    android::system::keystore2::KeyDescriptor::KeyDescriptor,
};
use rsbinder::{Status, StatusCode};
use std::mem::size_of;

#[test]
fn ommega_grant_blocker_preserves_inbound_binder_buffer() {
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.code = service_tx::r#grant;
    tr.data_size = 64;
    tr.offsets_size = size_of::<usize>();
    tr.data.ptr.buffer = 0x1000;
    tr.data.ptr.offsets = 0x2000;

    block_system_request(&mut tr);

    assert_eq!(tr.code, u32::MAX);
    assert_eq!(tr.data_size, 64);
    assert_eq!(tr.offsets_size, size_of::<usize>());
    assert_eq!(unsafe { tr.data.ptr.buffer }, 0x1000);
    assert_eq!(unsafe { tr.data.ptr.offsets }, 0x2000);
}

#[test]
fn grant_and_ungrant_preserve_system_only_when_ommega_unavailable() {
    let _guard = route_state_test_guard();
    let request = ParsedServiceRequest::Grant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
        access_vector: 7,
    };
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };

    let result = precompute_ommega_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| Err(anyhow::Error::new(Status::from(StatusCode::RpcError))),
        |_, _, _| panic!("grant requests must not call ungrant"),
    );

    assert!(matches!(result, OmmegaServicePrecompute::PreserveSystem));

    let request = ParsedServiceRequest::Ungrant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
    };
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };

    let result = precompute_ommega_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| panic!("ungrant requests must not call grant"),
        |_, _, _| Err(anyhow::Error::new(Status::from(StatusCode::NotEnoughData))),
    );

    assert!(matches!(result, OmmegaServicePrecompute::PreserveSystem));
}

#[test]
fn grant_precompute_returns_reachable_ommega_business_error() {
    let request = ParsedServiceRequest::Grant {
        key: sample_key_descriptor(),
        grantee_uid: 12345,
        access_vector: 7,
    };
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };

    let result = precompute_ommega_grant_service_reply_with(
        &request,
        &caller,
        |_, _, _, _| {
            Err(anyhow::Error::new(Status::new_service_specific_error(
                7, None,
            )))
        },
        |_, _, _| panic!("grant requests must not call ungrant"),
    );

    let OmmegaServicePrecompute::Reply(PrecomputedServiceReply::Error(status)) = result else {
        panic!("reachable ommega business error should be precomputed as an authoritative status");
    };
    assert_eq!(
        status.exception_code(),
        rsbinder::ExceptionCode::ServiceSpecific
    );
    assert_eq!(status.service_specific_error(), 7);
}

#[test]
fn service_route_respects_intercept_configuration() {
    let _guard = route_state_test_guard();
    let intercept = config::InterceptConfig::default();

    for request in sample_service_requests() {
        assert_eq!(
            route_for_service_request(&request, &intercept),
            RouteTarget::Ommega,
            "{:?} should use the ommega backend when the method is enabled",
            request.method()
        );
    }

    let intercept = disabled_intercept_config();

    for request in sample_service_requests() {
        assert_eq!(
            route_for_service_request(&request, &intercept),
            RouteTarget::System,
            "{:?} should use the system backend when the method is disabled",
            request.method()
        );
    }

    let mut intercept = disabled_intercept_config();
    intercept.get_key_entry = true;
    assert!(security_level_scoop_enabled(&intercept));
    intercept.get_key_entry = false;
    intercept.get_security_level = true;
    assert!(security_level_scoop_enabled(&intercept));
    intercept.get_security_level = false;
    assert!(!security_level_scoop_enabled(&intercept));
}

#[test]
fn service_route_uses_ommega_for_key_id() {
    let key = KeyDescriptor {
        domain: Domain::KEY_ID,
        nspace: 123,
        alias: None,
        blob: None,
    };

    assert_eq!(
        route_for_service_request(
            &ParsedServiceRequest::GetKeyEntry { key },
            &config::InterceptConfig::default(),
        ),
        RouteTarget::Ommega
    );
}

#[test]
fn unconfirmed_grant_readback_stays_rejected() {
    let _guard = route_state_test_guard();
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedNotInScope,
        packages: vec!["com.grantee".to_string()],
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: String::new(),
        pid: 2000,
    };
    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 123,
        alias: None,
        blob: None,
    };

    assert!(!should_allow_ommega_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry { key: grant },
        &decision,
        &caller,
        |_, _| Ok(false),
    )
    .expect("unconfirmed grant lookup should succeed"));
    assert!(!should_allow_ommega_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry {
            key: sample_key_descriptor(),
        },
        &decision,
        &caller,
        |_, _| -> anyhow::Result<bool> { panic!("non-GRANT descriptors must not be probed") },
    )
    .expect("non-GRANT lookup should succeed"));
}

#[test]
fn soft_rejected_grant_probe_error_is_fail_closed() {
    let _guard = route_state_test_guard();
    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 123,
        alias: None,
        blob: None,
    };
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedUnknownPackage,
        packages: vec![],
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: String::new(),
        pid: 2000,
    };

    let error = should_allow_ommega_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry { key: grant },
        &decision,
        &caller,
        |_, _| Err(anyhow::anyhow!("reachable probe failure")),
    )
    .expect_err("non-unavailable probe errors must block System fallback");

    assert!(error.to_string().contains("reachable probe failure"));
}

#[test]
fn soft_rejected_grant_positive_probe_works_for_service_and_security_level() {
    let _guard = route_state_test_guard();
    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 123,
        alias: None,
        blob: None,
    };
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedUnknownPackage,
        packages: vec![],
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: String::new(),
        pid: 2000,
    };

    assert!(should_allow_ommega_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry { key: grant.clone() },
        &decision,
        &caller,
        |probe_caller, probe_grant| {
            assert_eq!(probe_caller.uid, caller.uid);
            assert_eq!(probe_grant, &grant);
            Ok(true)
        },
    )
    .expect("positive grant probe should succeed"));

    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 321,
        alias: None,
        blob: None,
    };
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedNotInScope,
        packages: vec!["com.grantee".to_string()],
    };

    assert!(should_allow_ommega_grant_security_level_request_with_probe(
        &ParsedSecurityLevelRequest::CreateOperation {
            key: grant.clone(),
            operation_parameters: vec![],
            forced: false,
        },
        &decision,
        &caller,
        |probe_caller, probe_grant| {
            assert_eq!(probe_caller.uid, caller.uid);
            assert_eq!(probe_grant, &grant);
            Ok(true)
        },
    )
    .expect("positive grant probe should succeed"));
}

#[test]
fn denylisted_grant_readback_does_not_probe_ommega() {
    let _guard = route_state_test_guard();
    let grant = KeyDescriptor {
        domain: Domain::GRANT,
        nspace: 123,
        alias: None,
        blob: None,
    };
    let decision = crate::filter::FilterDecision {
        allowed: false,
        reason: crate::filter::FilterReason::RejectedByDenylist,
        packages: vec!["com.blocked".to_string()],
    };
    let caller = CallerInfo {
        uid: 10002,
        sid: String::new(),
        pid: 2000,
    };

    assert!(!should_allow_ommega_grant_service_request_with_probe(
        &ParsedServiceRequest::GetKeyEntry { key: grant },
        &decision,
        &caller,
        |_, _| -> anyhow::Result<bool> {
            panic!("denylisted callers must not probe ommega grants")
        },
    )
    .expect("denylisted grant lookup should succeed"));
}
