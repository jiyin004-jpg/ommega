use std::sync::Mutex;

use kmr_common::km_err;
use kmr_ta::device::RetrieveAttestationIds;
use kmr_wire::AttestationIdInfo;

use crate::config::config;

pub struct AttestationIdMgr;

static ATTESTATION_IDS: Mutex<Option<AttestationIdInfo>> = Mutex::new(None);

/// 身份项按属性取。厂商给 attestation 单独准备了 `*_for_attestation` 时优先用它，
/// 没有这个属性（AOSP、大部分机型）就退回普通的那项。
fn identity_property(prop: &str) -> Option<Vec<u8>> {
    let read = |name: &str| -> Option<Vec<u8>> {
        rsproperties::get::<String>(name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(String::into_bytes)
    };
    read(&format!("{prop}_for_attestation")).or_else(|| read(prop))
}

/// 身份六项按当前属性取：伪装参数和远端身份改的就是这些属性，改了就认改后的值。
fn with_current_identity(mut ids: AttestationIdInfo) -> AttestationIdInfo {
    let current = |prop: &str, fallback: Vec<u8>| -> Vec<u8> {
        identity_property(prop).unwrap_or(fallback)
    };
    ids.brand = current("ro.product.brand", ids.brand);
    ids.device = current("ro.product.device", ids.device);
    ids.product = current("ro.product.name", ids.product);
    ids.serial = current("ro.serialno", ids.serial);
    ids.manufacturer = current("ro.product.manufacturer", ids.manufacturer);
    ids.model = current("ro.product.model", ids.model);
    ids
}

impl RetrieveAttestationIds for AttestationIdMgr {
    fn get(&self) -> Result<AttestationIdInfo, kmr_common::Error> {
        self.get_ids()?
            .ok_or_else(|| km_err!(CannotAttestIds, "attestation ID info not available"))
    }

    fn get_ids(&self) -> Result<Option<AttestationIdInfo>, kmr_common::Error> {
        let mut cached = ATTESTATION_IDS
            .lock()
            .map_err(|_| km_err!(UnknownError, "attestation ID cache lock poisoned"))?;
        if let Some(ids) = cached.as_ref() {
            return Ok(Some(with_current_identity(ids.clone())));
        }

        let needs_resolution = |device: &crate::config::DeviceProperty| {
            !device.override_telephony_properties
                && (device.imei.trim().is_empty()
                    || device.imei2.trim().is_empty()
                    || device.meid.trim().is_empty())
        };
        let guard = config()
            .read()
            .map_err(|_| km_err!(UnknownError, "config lock poisoned"))?;
        let device = if needs_resolution(&guard.device) {
            drop(guard);
            match crate::plat::device_ids::resolve_runtime_device_ids() {
                Ok(Some(device)) => device,
                Ok(None) => return Ok(None),
                Err(error) => {
                    log::warn!("failed to resolve runtime attestation IDs: {error:#}");
                    return Ok(None);
                }
            }
        } else {
            guard.device.clone()
        };

        let ids = AttestationIdInfo {
            brand: device.brand.into_bytes(),
            device: device.device.into_bytes(),
            product: device.product.into_bytes(),
            serial: device.serial.into_bytes(),
            imei: device.imei.into_bytes(),
            imei2: device.imei2.into_bytes(),
            meid: device.meid.into_bytes(),
            manufacturer: device.manufacturer.into_bytes(),
            model: device.model.into_bytes(),
        };
        *cached = Some(ids.clone());
        Ok(Some(with_current_identity(ids)))
    }

    fn destroy_all(&mut self) -> Result<(), kmr_common::Error> {
        // ignore this
        Ok(())
    }
}
