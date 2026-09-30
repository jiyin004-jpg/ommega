use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, LazyLock, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

use super::binder::{
    binder_transaction_data, create_native_operation_binder, create_native_security_level_binder,
    describe_transaction_objects, format_target, parse_local_binder_target_from_parcel_bytes,
    LocalBinderTarget, NativeBinder, NativeBinderRetirement,
};
use super::{BinderFdToken, BinderStateKey};
use crate::android::system::keystore2::Domain::Domain;
use crate::android::system::keystore2::IKeystoreOperation::IKeystoreOperation as AospKeystoreOperation;
use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use crate::android::system::keystore2::KeyEntryResponse::KeyEntryResponse;
use crate::android::system::keystore2::ResponseCode::ResponseCode;
use crate::config;
use crate::filter::{self, FilterReason, PackageResolution};
use crate::forward::{self, BypassGuard};
use crate::identify::{
    self, AidlMetadataMethod, AuthorizationMethod, OperationMethod, SecurityLevelMethod,
    ServiceMethod,
};
use crate::ipc;
use crate::parcel::{
    self, ParsedAuthorizationRequest, ParsedMaintenanceRequest, ParsedOperationRequest,
    ParsedSecurityLevelRequest, ParsedServiceRequest,
};
use crate::top::jiyin004::ommega::CallerInfo::CallerInfo;
use crate::tracker::{self, SecurityLevelTargetInfo};
use log::{debug, info, warn};
use rsbinder::{ExceptionCode, Status, StatusCode, Strong};

mod mirror;
mod pending;
mod reply;
mod request;
mod synthetic;

pub(super) use mirror::start_mirror_recovery_worker;
use mirror::*;
use pending::*;
use reply::*;
use request::*;
use synthetic::*;

pub(super) use reply::handle_synthetic_br_transaction;
pub(super) use synthetic::{
    bind_operation_publication_connection, cancel_operation_publication_acquire_pending,
    finish_local_operation_publication, finish_operation_publication_probe, lookup_native_binder,
    lookup_native_binder_for, lookup_synthetic_target,
    mark_operation_publication_acquire_committed, mark_operation_publication_acquire_pending,
    mark_operation_publication_completed, next_operation_publication_probe_deadline,
    operation_publication_acquire_is_pending, operation_publication_pending_acquire,
    retire_binder_connection_publications, retire_synthetic_operation_retirement,
    take_operation_publication_probe, OperationPublicationProbe, SyntheticReply,
    SyntheticTargetKind,
};
pub(crate) use synthetic::{drop_synthetic_operation_retirement, retire_native_operation_target};

#[cfg(test)]
pub(super) use synthetic::register_operation_publication_for_test;
#[cfg(test)]
pub(in crate::hook) use tests::route_state_test_guard;

pub(super) use pending::{
    abort_bc_reply, clear_binder_fd_thread_state, clear_outbound_reply_buffers, commit_bc_reply,
    handle_bc_reply, push_pending_frame,
};
#[cfg(test)]
pub(super) use pending::{
    pending_reply_frame_claims_for_test, pending_reply_frame_count_for_test,
    reset_pending_reply_frames_for_test,
};
pub(super) use request::handle_br_transaction;

type OutboundReply = parcel::OwnedReply;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteTarget {
    System,
    Ommega,
}

type AospOperationBinder = Strong<dyn AospKeystoreOperation>;

fn evaluate_caller(
    caller: &CallerInfo,
    cfg: &config::InjectorConfig,
) -> crate::filter::FilterDecision {
    let uid = caller.uid as u32;
    let preflight = filter::evaluate(&cfg.scoop, &cfg.filter, uid, PackageResolution::Unknown);
    if preflight.reason == FilterReason::RejectedAndroidPackage {
        return preflight;
    }

    let package_resolution = {
        let _guard = BypassGuard::enter();
        ipc::resolve_packages_for_uid(uid)
    };
    let decision = filter::evaluate(&cfg.scoop, &cfg.filter, uid, package_resolution);
    if decision.reason == FilterReason::Disabled {
        debug!(
            "event=decision package filter disabled; routing still follows per-method intercept settings"
        );
    }
    decision
}

fn service_request_key(request: &ParsedServiceRequest) -> Option<&KeyDescriptor> {
    match request {
        ParsedServiceRequest::GetKeyEntry { key }
        | ParsedServiceRequest::UpdateSubcomponent { key, .. }
        | ParsedServiceRequest::DeleteKey { key }
        | ParsedServiceRequest::Grant { key, .. }
        | ParsedServiceRequest::Ungrant { key, .. } => Some(key),
        _ => None,
    }
}

fn security_level_request_key(request: &ParsedSecurityLevelRequest) -> Option<&KeyDescriptor> {
    match request {
        ParsedSecurityLevelRequest::GenerateKey {
            key,
            attestation_key: Some(attestation_key),
            ..
        } if key.domain != Domain::BLOB => Some(attestation_key),
        ParsedSecurityLevelRequest::ImportWrappedKey { wrapping_key, .. } => Some(wrapping_key),
        ParsedSecurityLevelRequest::CreateOperation { key, .. }
        | ParsedSecurityLevelRequest::DeleteKey { key }
        | ParsedSecurityLevelRequest::ConvertStorageKeyToEphemeral { storage_key: key } => {
            Some(key)
        }
        _ => None,
    }
}

fn should_allow_ommega_grant_descriptor_with_probe(
    grant: &KeyDescriptor,
    decision: &filter::FilterDecision,
    caller: &CallerInfo,
    mut probe: impl FnMut(&CallerInfo, &KeyDescriptor) -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    if decision.allowed
        || !matches!(
            decision.reason,
            FilterReason::RejectedUnknownPackage | FilterReason::RejectedNotInScope
        )
    {
        return Ok(false);
    }

    if grant.domain != Domain::GRANT {
        return Ok(false);
    }

    ensure_mirror_state_recovered()?;
    probe(caller, grant)
}

fn probe_ommega_grant(caller: &CallerInfo, grant: &KeyDescriptor) -> anyhow::Result<bool> {
    let _guard = BypassGuard::enter();
    match ipc::with_ommega_retry(|ommega| Ok(ommega.r#isGrant(Some(caller), grant)?)) {
        Ok(owned) => Ok(owned),
        Err(error) if ommega_unavailable_error(&error) => {
            debug!(
                "event=decision ommega grant probe unavailable for uid={} pid={} grant_nspace={}: {:#}",
                caller.uid, caller.pid, grant.nspace, error
            );
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn should_allow_ommega_grant_service_request_with_probe(
    request: &ParsedServiceRequest,
    decision: &filter::FilterDecision,
    caller: &CallerInfo,
    mut probe: impl FnMut(&CallerInfo, &KeyDescriptor) -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let Some(grant) = service_request_key(request) else {
        return Ok(false);
    };

    should_allow_ommega_grant_descriptor_with_probe(grant, decision, caller, &mut probe)
}

fn should_allow_ommega_grant_security_level_request_with_probe(
    request: &ParsedSecurityLevelRequest,
    decision: &filter::FilterDecision,
    caller: &CallerInfo,
    mut probe: impl FnMut(&CallerInfo, &KeyDescriptor) -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let Some(grant) = security_level_request_key(request) else {
        return Ok(false);
    };

    should_allow_ommega_grant_descriptor_with_probe(grant, decision, caller, &mut probe)
}

fn precompute_ommega_service_mutator_reply(
    request: &ParsedServiceRequest,
    caller: &CallerInfo,
) -> OmmegaServicePrecompute {
    if let Err(error) = ensure_mirror_state_recovered() {
        warn!(
            "event=route ommega service {:?} blocked by unresolved mirror recovery for uid={} pid={}: {:#}",
            request.method(), caller.uid, caller.pid, error
        );
        return OmmegaServicePrecompute::Reply(PrecomputedServiceReply::Error(
            Status::new_service_specific_error(ResponseCode::SYSTEM_ERROR.0, None),
        ));
    }
    match request {
        ParsedServiceRequest::UpdateSubcomponent {
            key,
            public_cert,
            certificate_chain,
        } => {
            match ipc::with_ommega_once(|ommega| {
                Ok(ommega.r#updateSubcomponent(
                    Some(caller),
                    key,
                    public_cert.as_deref(),
                    certificate_chain.as_deref(),
                )?)
            }) {
                Ok(()) => OmmegaServicePrecompute::Reply(
                    PrecomputedServiceReply::UpdateSubcomponentSuccess,
                ),
                Err(error) if ommega_unavailable_error(&error) => {
                    warn!(
                    "event=route ommega updateSubcomponent unavailable for uid={} pid={}: {:#}; leaving original system request untouched",
                    caller.uid, caller.pid, error
                );
                    OmmegaServicePrecompute::PreserveSystem
                }
                Err(error) => OmmegaServicePrecompute::Reply(PrecomputedServiceReply::Error(
                    precomputed_ommega_error_reply(&error),
                )),
            }
        }
        ParsedServiceRequest::DeleteKey { key } => {
            match ipc::with_ommega_once(|ommega| Ok(ommega.r#deleteKey(Some(caller), key)?)) {
                Ok(()) => OmmegaServicePrecompute::Reply(PrecomputedServiceReply::DeleteKeySuccess),
                Err(error) if ommega_unavailable_error(&error) => {
                    warn!(
                        "event=route ommega deleteKey unavailable for uid={} pid={}: {:#}; leaving original system request untouched",
                        caller.uid, caller.pid, error
                    );
                    OmmegaServicePrecompute::PreserveSystem
                }
                Err(error) => OmmegaServicePrecompute::Reply(PrecomputedServiceReply::Error(
                    precomputed_ommega_error_reply(&error),
                )),
            }
        }
        ParsedServiceRequest::Grant { .. } | ParsedServiceRequest::Ungrant { .. } => {
            precompute_ommega_grant_service_reply_with(
                request,
                caller,
                |caller_info, key, grantee_uid, access_vector| {
                    ipc::with_ommega_once(|ommega| {
                        Ok(ommega.r#grant(Some(caller_info), key, grantee_uid, access_vector)?)
                    })
                },
                |caller_info, key, grantee_uid| {
                    ipc::with_ommega_once(|ommega| {
                        Ok(ommega.r#ungrant(Some(caller_info), key, grantee_uid)?)
                    })
                },
            )
        }
        _ => unreachable!("only service mutators are precomputed"),
    }
}

fn precompute_ommega_grant_service_reply_with(
    request: &ParsedServiceRequest,
    caller: &CallerInfo,
    mut grant: impl FnMut(&CallerInfo, &KeyDescriptor, i32, i32) -> anyhow::Result<KeyDescriptor>,
    mut ungrant: impl FnMut(&CallerInfo, &KeyDescriptor, i32) -> anyhow::Result<()>,
) -> OmmegaServicePrecompute {
    match request {
        ParsedServiceRequest::Grant {
            key,
            grantee_uid,
            access_vector,
        } => match grant(caller, key, *grantee_uid, *access_vector) {
            Ok(ommega_grant) => {
                OmmegaServicePrecompute::Reply(PrecomputedServiceReply::GrantSuccess(ommega_grant))
            }
            Err(error) if ommega_unavailable_error(&error) => {
                warn!(
                    "event=route ommega grant unavailable for uid={} pid={}: {:#}; leaving original system request untouched",
                    caller.uid, caller.pid, error
                );
                OmmegaServicePrecompute::PreserveSystem
            }
            Err(error) => {
                warn!(
                    "event=route ommega grant failed for uid={} pid={}: {:#}; returning ommega error",
                    caller.uid, caller.pid, error
                );
                OmmegaServicePrecompute::Reply(PrecomputedServiceReply::Error(
                    precomputed_ommega_error_reply(&error),
                ))
            }
        },
        ParsedServiceRequest::Ungrant { key, grantee_uid } => {
            match ungrant(caller, key, *grantee_uid) {
                Ok(()) => OmmegaServicePrecompute::Reply(PrecomputedServiceReply::UngrantSuccess),
                Err(error) if ommega_unavailable_error(&error) => {
                    warn!(
                        "event=route ommega ungrant unavailable for uid={} pid={}: {:#}; leaving original system request untouched",
                        caller.uid, caller.pid, error
                    );
                    OmmegaServicePrecompute::PreserveSystem
                }
                Err(error) => {
                    warn!(
                        "event=route ommega ungrant failed for uid={} pid={}: {:#}; returning ommega error",
                        caller.uid, caller.pid, error
                    );
                    OmmegaServicePrecompute::Reply(PrecomputedServiceReply::Error(
                        precomputed_ommega_error_reply(&error),
                    ))
                }
            }
        }
        _ => unreachable!("only grant/ungrant requests are precomputed"),
    }
}

unsafe fn transaction_parts(tr: &binder_transaction_data) -> (*mut u8, usize, *mut usize, usize) {
    (
        tr.data.ptr.buffer as *mut u8,
        tr.data_size,
        tr.data.ptr.offsets as *mut usize,
        tr.offsets_size,
    )
}

fn ommega_unavailable_status(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && ommega_unavailable_status_code(status.transaction_error())
}

fn ommega_unavailable_status_code(status: StatusCode) -> bool {
    ipc::is_rpc_cache_invalidating_status_code(status) || status == StatusCode::NameNotFound
}

fn ommega_unavailable_error(error: &anyhow::Error) -> bool {
    if let Some(unavailable) = error.chain().find_map(|cause| {
        cause
            .downcast_ref::<Status>()
            .map(ommega_unavailable_status)
            .or_else(|| {
                cause
                    .downcast_ref::<StatusCode>()
                    .map(|status| ommega_unavailable_status_code(*status))
            })
    }) {
        return unavailable;
    }

    error.chain().any(|cause| {
        matches!(
            cause.to_string().as_str(),
            "failed to connect to ommega service"
                | "failed to connect to ommega_maintenance service"
                | "failed to connect to ommega_authorization service"
        )
    })
}

fn synthetic_fallback_reply() -> parcel::OwnedReply {
    build_service_specific_reply(ResponseCode::SYSTEM_ERROR.0)
        .expect("synthetic system-error status should serialize")
}

fn precompute_ommega_migrate_reply(call: &PendingMaintenanceCall) -> OmmegaMigratePrecompute {
    let ParsedMaintenanceRequest::MigrateKeyNamespace {
        source,
        destination,
    } = &call.request
    else {
        unreachable!(
            "ommega migrate precompute called for {:?}",
            call.request.method()
        );
    };
    debug_assert_eq!(call.route, RouteTarget::Ommega);

    if let Err(error) = ensure_mirror_state_recovered() {
        warn!(
            "event=route ommega migrateKeyNamespace blocked by unresolved mirror recovery for uid={} pid={}: {:#}",
            call.caller.uid, call.caller.pid, error
        );
        return OmmegaMigratePrecompute::Reply(PrecomputedMaintenanceReply::Error(
            Status::new_service_specific_error(ResponseCode::SYSTEM_ERROR.0, None),
        ));
    }

    let method = call.request.method();
    let result = ipc::with_ommega_maintenance_once(|maintenance| {
        Ok(maintenance.r#migrateKeyNamespace(Some(&call.caller), source, destination)?)
    });
    match result {
        Ok(()) => {
            debug!(
                "event=route ommega authoritative maintenance {:?} succeeded for uid={} pid={}",
                method, call.caller.uid, call.caller.pid
            );
            OmmegaMigratePrecompute::Reply(PrecomputedMaintenanceReply::Success)
        }
        Err(error) if ommega_unavailable_error(&error) => {
            warn!(
                "event=route ommega migrateKeyNamespace unavailable for uid={} pid={}: {:#}; preserving original system request",
                call.caller.uid, call.caller.pid, error
            );
            OmmegaMigratePrecompute::PreserveSystem
        }
        Err(error) => {
            warn!(
                "event=route ommega migrateKeyNamespace failed for uid={} pid={}: {:#}; returning ommega error",
                call.caller.uid, call.caller.pid, error
            );
            OmmegaMigratePrecompute::Reply(PrecomputedMaintenanceReply::Error(
                precomputed_ommega_error_reply(&error),
            ))
        }
    }
}

#[cfg(test)]
mod tests;
