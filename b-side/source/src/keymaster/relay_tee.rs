//! Relay support: a self-contained, minimal bridge to the *real* hardware TEE.
//!
//! This module gathers the few primitives that the relay / attest_proxy /
//! tee_ops forwarding path needs in order to talk to the real on-device
//! keymint HAL, **without** pulling in the rest of the (software) keystore
//! stack:
//!
//!   * `get_system_keymint` / `clear_system_keymint` — connect (and cache) the
//!     real TEE `IKeyMintDevice` binder proxy;
//!   * `key_params_to_aidl` — convert `kmr_wire::KeyParam` (the canonical,
//!     wire-format key parameters) into the AIDL `KeyParameter` list the real
//!     HAL understands;
//!   * the `KEY_MINT_V*` HAL version constants;
//!   * `get_interface_once` — the cached service lookup helper.
//!
//! Everything here depends only on AIDL-generated keymint types and `rsbinder`,
//! so this module can survive on its own if the software keystore modules are
//! removed.

use std::{cell::RefCell, collections::HashMap, sync::Arc, sync::atomic::{AtomicU64, Ordering}};

use anyhow::{anyhow, Context, Result};
use kmr_wire::keymint::KeyParam;
use log::error;
use rsbinder::{hub, DeathRecipient, FromIBinder, StatusCode, Strong, WIBinder};

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, EcCurve::EcCurve, HardwareAuthenticatorType::HardwareAuthenticatorType,
    IKeyMintDevice::IKeyMintDevice, KeyOrigin::KeyOrigin, KeyParameter::KeyParameter as KmKeyParameter,
    KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, MlDsaVariant::MlDsaVariant as AidlMlDsaVariant,
    Tag::Tag,
};

// ---------------------------------------------------------------------------
// HAL version constants (previously defined on `KeyMintDevice`).
// ---------------------------------------------------------------------------

pub const KEY_MINT_V3: i32 = 300;
pub const KEY_MINT_V4: i32 = 400;
pub const KEY_MINT_V5: i32 = 500;

// ---------------------------------------------------------------------------
// Service lookup.
// ---------------------------------------------------------------------------

/// Performs a single `getService` lookup for the named binder service without
/// inheriting version-dependent wait behaviour.  Mirrors the implementation in
/// `keymaster/utils.rs` so the relay path does not depend on it.
///
/// A transport/permission failure is propagated as its own [`StatusCode`]
/// instead of being collapsed into `NameNotFound`: this error text is the only
/// diagnostic the server ever sees (it is stored verbatim as the device's
/// `tee_error`), so "service manager unreachable" and "SELinux denied `find`"
/// must stay distinguishable from "no such service registered".
pub(crate) fn get_interface_once<T: FromIBinder + ?Sized>(
    name: &str,
) -> Result<Strong<T>, StatusCode> {
    match hub::try_get_service(name) {
        Ok(Some(binder)) => FromIBinder::try_from(binder),
        Ok(None) => Err(StatusCode::NameNotFound),
        Err(code) => {
            log::warn!("getService('{name}') failed: {code:?}");
            Err(code)
        }
    }
}

// ---------------------------------------------------------------------------
// Diagnostics: what does this device actually expose?
// ---------------------------------------------------------------------------

/// Service names of the AIDL KeyMint/Keymaster interfaces currently registered
/// with the system service manager, as `ShortInterface/instance` pairs
/// (e.g. `IKeyMintDevice/default`).
fn keymint_aidl_instances() -> Vec<String> {
    // `listServices(dumpPriority)` filters by a dump-priority bitmask on some
    // releases (where 0 means "everything") and returns all of them on others;
    // retry with all three priority bits so neither behaviour yields an empty
    // and therefore misleading list.
    let mut all = hub::list_services(0);
    if all.is_empty() {
        all = hub::list_services(0x7);
    }
    let mut out: Vec<String> = all
        .into_iter()
        .filter_map(|full| {
            let (iface, instance) = full.split_once('/')?;
            let short = iface.rsplit('.').next()?;
            if short.contains("IKeyMint") || short.contains("IKeymaster") {
                Some(format!("{short}/{instance}"))
            } else {
                None
            }
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// HIDL keymaster versions whose *client* library is present on the device
/// (`android.hardware.keymaster@4.1.so` and friends).  A device that predates
/// AIDL KeyMint ships only these, in which case no amount of `getService`
/// retrying will ever find `IKeyMintDevice` — it simply does not exist there.
fn hidl_keymaster_versions() -> Vec<String> {
    const DIRS: [&str; 4] = [
        "/vendor/lib64",
        "/vendor/lib",
        "/system/lib64",
        "/system/lib",
    ];
    let mut out = Vec::new();
    for dir in DIRS {
        // Unreadable directories (SELinux, missing partition) are expected on
        // some devices and simply contribute nothing.
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(version) = name
                .strip_prefix("android.hardware.keymaster@")
                .and_then(|rest| rest.strip_suffix(".so"))
            {
                out.push(version.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Joins at most `max` entries, keeping the result short enough to survive the
/// server's 300-character truncation of `tee_error`.
fn join_capped(items: &[String], max: usize, max_chars: usize) -> String {
    if items.is_empty() {
        return "-".to_string();
    }
    let mut text: String = items
        .iter()
        .take(max)
        .cloned()
        .collect::<Vec<_>>()
        .join(",");
    if items.len() > max {
        text.push_str(",+");
    }
    if text.chars().count() > max_chars {
        text = text.chars().take(max_chars).collect();
        text.push('~');
    }
    text
}

/// One-line description of the KeyMint/Keymaster situation on this device,
/// appended to lookup failures.  It answers the questions `NameNotFound` alone
/// cannot: is the service declared in the VINTF manifest at all, which AIDL
/// instances are actually registered, and does the device ship HIDL keymaster
/// client libraries (i.e. is it an AIDL-KeyMint-less legacy device)?
pub fn keymint_diagnosis(service: &str) -> String {
    format!(
        "decl={} aidl={} hidl_km={}",
        hub::is_declared(service),
        join_capped(&keymint_aidl_instances(), 2, 60),
        join_capped(&hidl_keymaster_versions(), 2, 24),
    )
}

/// The single non-`default`, non-`strongbox` AIDL KeyMint instance registered
/// for the requested interface, if there is exactly one.  The name is leaked so
/// it can key the `&'static str`-keyed proxy cache; the set of instance names a
/// device has is tiny and fixed, so this cannot grow unboundedly.
fn sole_alternate_instance(service: &str) -> Option<&'static str> {
    let (iface, _) = service.rsplit_once('/')?;
    let short = iface.rsplit('.').next()?;
    let prefix = format!("{short}/");
    let mut found: Option<String> = None;
    for name in keymint_aidl_instances() {
        let Some(instance) = name.strip_prefix(&prefix) else {
            continue;
        };
        // `default` is the one that just failed, and `strongbox` is a
        // different security level that must never be substituted silently.
        if instance == "default" || instance.contains("strongbox") {
            continue;
        }
        if found.is_some() {
            // Ambiguous: guessing between instances would be worse than the
            // current failure, so report instead.
            return None;
        }
        found = Some(format!("{iface}/{instance}"));
    }
    found.map(|name| &*Box::leak(name.into_boxed_str()))
}

/// Connects to the requested KeyMint service, mirroring AOSP `keystore2`'s
/// behaviour of resolving the HAL through the *declared* instance list rather
/// than hardcoding `/default`, and reports what the device exposes when the
/// lookup fails.
fn connect_keymint(service: &'static str) -> Result<Strong<dyn IKeyMintDevice>> {
    let first = match get_interface_once::<dyn IKeyMintDevice>(service) {
        Ok(keymint) => return Ok(keymint),
        Err(code) => code,
    };
    // Only the TEE (`/default`) instance may fall back to a differently-named
    // instance.  A missing StrongBox HAL has to keep failing: the A-side maps
    // that to "StrongBox unavailable" and falls back to its local keybox, which
    // is correct — degrading to the TEE HAL would return a TEE chain for a
    // request the caller explicitly made for StrongBox.
    if service.ends_with("/default") {
        if let Some(alt) = sole_alternate_instance(service) {
            match get_interface_once::<dyn IKeyMintDevice>(alt) {
                Ok(keymint) => {
                    log::warn!("KeyMint instance '{service}' is absent; using '{alt}' instead");
                    return Ok(keymint);
                }
                Err(code) => log::warn!("KeyMint instance '{alt}' failed as well: {code:?}"),
            }
        }
    }
    log::warn!(
        "keymint lookup '{service}' failed: {first:?} ({})",
        keymint_diagnosis(service)
    );
    Err(anyhow!("{first:?}; {}", keymint_diagnosis(service)))
}

// ---------------------------------------------------------------------------
// Real TEE keymint proxy (cached).
// ---------------------------------------------------------------------------

/// Global generation counter for keymint cache invalidation.  Incremented
/// whenever a service death is detected, so every thread's thread-local cache
/// is invalidated on the next `get_system_keymint` call.
static KEYMINT_CACHE_GEN: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static SYSTEM_KEYMINT_CACHE: RefCell<Option<HashMap<&'static str, Strong<dyn IKeyMintDevice>>>> =
        const { RefCell::new(None) };
    static SYSTEM_KEYMINT_DEATH: RefCell<Option<HashMap<&'static str, Arc<dyn DeathRecipient>>>> =
        const { RefCell::new(None) };
    /// Thread-local snapshot of KEYMINT_CACHE_GEN at last cache build.
    static KEYMINT_CACHE_LOCAL_GEN: RefCell<u64> = const { RefCell::new(0) };
}

struct SystemKeymintDeath {
    service: &'static str,
}

impl DeathRecipient for SystemKeymintDeath {
    fn binder_died(&self, _who: &WIBinder) {
        clear_system_keymint(self.service);
        log::warn!(
            "system KeyMint verifier service {} died; cache cleared",
            self.service
        );
    }
}

/// Connects to the real hardware keymint HAL for the given service name
/// (e.g. `android.hardware.security.keymint.IKeyMintDevice/default`), caching
/// the proxy and watching for death.
///
/// The cache is thread-local but invalidated globally: when any thread detects
/// a binder death it bumps a global generation counter, and the next call on
/// *any* thread rebuilds its own cache from scratch.
pub fn get_system_keymint(service: &'static str) -> Result<Strong<dyn IKeyMintDevice>> {
    // Fast path: check global generation against thread-local snapshot.
    // If they differ, the cache is stale (some thread observed a death).
    let global_gen = KEYMINT_CACHE_GEN.load(Ordering::Acquire);
    let stale = KEYMINT_CACHE_LOCAL_GEN.with(|g| *g.borrow() != global_gen);
    if stale {
        clear_thread_local_keymint();
        KEYMINT_CACHE_LOCAL_GEN.with(|g| *g.borrow_mut() = global_gen);
    }

    SYSTEM_KEYMINT_CACHE.with(|cache| {
        if let Some(keymint) = cache
            .borrow()
            .as_ref()
            .and_then(|services| services.get(service).cloned())
        {
            return Ok(keymint);
        }

        let keymint: Strong<dyn IKeyMintDevice> = connect_keymint(service)?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(SystemKeymintDeath { service });
        keymint
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))
            .with_context(|| format!("watch {service} death"))?;
        SYSTEM_KEYMINT_DEATH.with(|death| {
            death
                .borrow_mut()
                .get_or_insert_with(HashMap::new)
                .insert(service, recipient);
        });
        cache
            .borrow_mut()
            .get_or_insert_with(HashMap::new)
            .insert(service, keymint.clone());
        Ok(keymint)
    })
}

/// Clears the current thread's keymint cache and death recipients.
fn clear_thread_local_keymint() {
    SYSTEM_KEYMINT_CACHE.with(|cache| {
        *cache.borrow_mut() = None;
    });
    SYSTEM_KEYMINT_DEATH.with(|death| {
        *death.borrow_mut() = None;
    });
}

/// Drops the cached proxy (and death recipient) for `service` across all
/// threads by bumping the global generation counter.  Each thread will
/// rebuild its own cache lazily on the next `get_system_keymint` call.
pub fn clear_system_keymint(_service: &'static str) {
    // Bump the global generation so every thread invalidates its cache on
    // the next lookup.  We pass the service name for logging clarity but
    // invalidate all services — the cost of a full rebuild per thread is
    // negligible compared to a dead binder proxy, and keeping the logic
    // simple (single counter) avoids per-service atomic bookkeeping.
    KEYMINT_CACHE_GEN.fetch_add(1, Ordering::Release);
    log::warn!("system KeyMint cache invalidated (generation bumped); all threads will reconnect on next use");
}

// ---------------------------------------------------------------------------
// KeyMint error-code extraction & HAL version probing.
// ---------------------------------------------------------------------------

/// Extracts a KeyMint `ErrorCode` from a binder `Status` when it carries a
/// service-specific error (the convention AOSP `map_km_error` uses). Returns
/// `None` for non-service-specific failures so callers can tell e.g. -74
/// (ATTESTATION_KEYS_NOT_PROVISIONED) from a generic binder error.
pub fn extract_km_error_code(status: &rsbinder::Status) -> Option<i32> {
    if status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific {
        let se = status.service_specific_error();
        if se < 0 {
            return Some(se);
        }
    }
    None
}

/// Probes the real KeyMint HAL for its implementation version via
/// `getHardwareInfo()` instead of assuming V5. A StrongBox HAL may only
/// implement KeyMint V2/V3; encoding parameters for a newer version can
/// cause version-mismatch errors that look like "not supported".
/// Falls back to `KEY_MINT_V5` if the probe itself fails.
pub fn probe_keymint_version(keymint: &Strong<dyn IKeyMintDevice>) -> i32 {
    match keymint.getHardwareInfo() {
        Ok(info) => {
            log::info!(
                "KeyMint HAL: versionNumber={} securityLevel={:?} name={}",
                info.versionNumber,
                info.securityLevel,
                info.keyMintName
            );
            info.versionNumber
        }
        Err(status) => {
            log::warn!(
                "getHardwareInfo failed: {status:?}; falling back to KEY_MINT_V5"
            );
            KEY_MINT_V5
        }
    }
}

// ---------------------------------------------------------------------------
// Key parameter conversion (kmr_wire::KeyParam -> AIDL KeyParameter).
// ---------------------------------------------------------------------------

pub fn key_params_to_aidl(params: &[KeyParam], km_dev_version: i32) -> Result<Vec<KmKeyParameter>> {
    params
        .iter()
        .cloned()
        .map(|param| key_param_to_aidl(param, km_dev_version))
        .collect()
}

pub fn key_param_to_aidl(kp: KeyParam, km_dev_version: i32) -> Result<KmKeyParameter> {
    use kmr_wire::{keymint::KeyParam as KP, KeySizeInBits};
    let mut tag = Tag(kp.tag() as i32);
    let value = match kp {
        KP::Purpose(v) => KeyParameterValue::KeyPurpose(KeyPurpose(v as i32)),
        KP::Algorithm(v) => KeyParameterValue::Algorithm(Algorithm(v as i32)),
        KP::KeySize(KeySizeInBits(v)) => KeyParameterValue::Integer(v as i32),
        KP::BlockMode(v) => KeyParameterValue::BlockMode(
            crate::android::hardware::security::keymint::BlockMode::BlockMode(v as i32),
        ),
        KP::Digest(v) => KeyParameterValue::Digest(
            crate::android::hardware::security::keymint::Digest::Digest(v as i32),
        ),
        KP::Padding(v) => KeyParameterValue::PaddingMode(
            crate::android::hardware::security::keymint::PaddingMode::PaddingMode(v as i32),
        ),
        KP::CallerNonce => KeyParameterValue::BoolValue(true),
        KP::MinMacLength(v) => KeyParameterValue::Integer(v as i32),
        KP::EcCurve(v) => KeyParameterValue::EcCurve(EcCurve(v as i32)),
        KP::MlDsaVariant(v) if km_dev_version < KEY_MINT_V5 => {
            error!("TA emitted ML_DSA_VARIANT tag but HAL v5 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Integer(v as i32)
        }
        KP::MlDsaVariant(v) => KeyParameterValue::MlDsaVariant(AidlMlDsaVariant(v as i32)),
        KP::RsaPublicExponent(kmr_wire::RsaExponent(v)) => {
            KeyParameterValue::LongInteger(v as i64)
        }
        KP::IncludeUniqueId => KeyParameterValue::BoolValue(true),
        KP::RsaOaepMgfDigest(v) => KeyParameterValue::Digest(
            crate::android::hardware::security::keymint::Digest::Digest(v as i32),
        ),
        KP::BootloaderOnly
        | KP::RollbackResistance
        | KP::EarlyBootOnly
        | KP::NoAuthRequired
        | KP::AllowWhileOnBody
        | KP::TrustedUserPresenceRequired
        | KP::TrustedConfirmationRequired
        | KP::UnlockedDeviceRequired
        | KP::DeviceUniqueAttestation
        | KP::StorageKey
        | KP::ResetSinceIdRotation => KeyParameterValue::BoolValue(true),
        KP::ActiveDatetime(v)
        | KP::OriginationExpireDatetime(v)
        | KP::UsageExpireDatetime(v)
        | KP::CreationDatetime(v)
        | KP::CertificateNotBefore(v)
        | KP::CertificateNotAfter(v) => KeyParameterValue::DateTime(v.ms_since_epoch),
        KP::MaxUsesPerBoot(v)
        | KP::UsageCountLimit(v)
        | KP::UserId(v)
        | KP::AuthTimeout(v)
        | KP::OsVersion(v)
        | KP::OsPatchlevel(v)
        | KP::VendorPatchlevel(v)
        | KP::BootPatchlevel(v)
        | KP::MacLength(v)
        | KP::MaxBootLevel(v) => KeyParameterValue::Integer(v as i32),
        KP::UserAuthType(v) => {
            KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType(v as i32))
        }
        KP::UserSecureId(v) => KeyParameterValue::LongInteger(v as i64),
        KP::ApplicationId(v)
        | KP::ApplicationData(v)
        | KP::RootOfTrust(v)
        | KP::AttestationChallenge(v)
        | KP::AttestationApplicationId(v)
        | KP::AttestationIdBrand(v)
        | KP::AttestationIdDevice(v)
        | KP::AttestationIdProduct(v)
        | KP::AttestationIdSerial(v)
        | KP::AttestationIdImei(v)
        | KP::AttestationIdMeid(v)
        | KP::AttestationIdManufacturer(v)
        | KP::AttestationIdModel(v)
        | KP::Nonce(v)
        | KP::CertificateSerial(v)
        | KP::CertificateSubject(v) => KeyParameterValue::Blob(v),
        KP::AttestationIdSecondImei(v) if km_dev_version < KEY_MINT_V3 => {
            error!("TA emitted ATTESTATION_ID_SECOND_IMEI tag but HAL v3 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Blob(v)
        }
        KP::AttestationIdSecondImei(v) => KeyParameterValue::Blob(v),
        KP::ModuleHash(v) if km_dev_version < KEY_MINT_V4 => {
            error!("TA emitted MODULE_HASH tag but HAL v4 is not supported");
            tag = Tag::INVALID;
            KeyParameterValue::Blob(v)
        }
        KP::ModuleHash(v) => KeyParameterValue::Blob(v),
        KP::Origin(v) => KeyParameterValue::Origin(KeyOrigin(v as i32)),
    };

    Ok(KmKeyParameter { tag, value })
}
