use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use der::asn1::SetOfVec;
use der::Encode;
use kmr_common::crypto::Sha256;
use kmr_crypto_ommega::sha256::OmmegaSha256;
use log::{debug, error};
use rsbinder::DeathRecipient;

use crate::android::apex::IApexService::IApexService;
use crate::android::security::keystore::IKeyAttestationApplicationIdProvider::IKeyAttestationApplicationIdProvider;
use crate::android::security::keystore::KeyAttestationApplicationId::KeyAttestationApplicationId;
use crate::android::security::keystore::KeyAttestationPackageInfo::KeyAttestationPackageInfo;
use crate::android::system::keystore2::{
    IKeystoreService::IKeystoreService, ResponseCode::ResponseCode,
};
use crate::err;
use crate::keymaster::apex::ApexModuleInfo;
use crate::keymaster::error::KsError;
use crate::keymaster::utils::get_interface_once;

thread_local! {
    static PM: Mutex<Option<rsbinder::Strong<dyn IKeyAttestationApplicationIdProvider>>> = Mutex::new(None);
}

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";

static KEYSTORE_CACHE: OnceLock<Mutex<KeystoreServiceCache>> = OnceLock::new();
static KEYSTORE_INIT: OnceLock<Mutex<()>> = OnceLock::new();
static KEYSTORE_GENERATION: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct KeystoreServiceCache {
    service: Option<rsbinder::Strong<dyn IKeystoreService>>,
    death_recipient: Option<Arc<dyn DeathRecipient>>,
    generation: u64,
}

fn keystore_cache() -> &'static Mutex<KeystoreServiceCache> {
    KEYSTORE_CACHE.get_or_init(Default::default)
}

fn keystore_init_lock() -> &'static Mutex<()> {
    KEYSTORE_INIT.get_or_init(|| Mutex::new(()))
}

fn keystore_service_is_alive(service: &rsbinder::Strong<dyn IKeystoreService>) -> bool {
    service.as_binder().ping_binder().is_ok()
}

struct KeystoreDeathRecipient {
    died: AtomicBool,
    generation: u64,
}

impl rsbinder::DeathRecipient for KeystoreDeathRecipient {
    fn binder_died(&self, _who: &rsbinder::WIBinder) {
        self.died.store(true, Ordering::Release);
        let mut guard = keystore_cache().lock().unwrap();
        if guard.generation != self.generation {
            return;
        }
        guard.service = None;
        guard.death_recipient = None;
        debug!("system keystore binder died; cleared cached instance");
    }
}

fn get_pm() -> anyhow::Result<rsbinder::Strong<dyn IKeyAttestationApplicationIdProvider>> {
    PM.with(|slot| {
        let mut slot = slot.lock().unwrap();
        if let Some(client) = slot.as_ref() {
            return Ok(client.clone());
        }

        let client: rsbinder::Strong<dyn IKeyAttestationApplicationIdProvider> =
            get_interface_once("sec_key_att_app_id_provider")?;
        *slot = Some(client.clone());
        Ok(client)
    })
}

const ERROR_GET_ATTESTATION_APPLICATION_ID_FAILED: i32 = 1;
const KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE: usize = 1024;
const AAID_PKG_INFO_OVERHEAD: usize = 15;
const AAID_SIGNATURE_SIZE: usize = 34;
const AAID_GENERAL_OVERHEAD: usize = 16;

fn reset_pm() {
    PM.with(|p| {
        *p.lock().unwrap() = None;
    });
    debug!("reset cached PM instance to None");
}

pub fn get_keystore_service() -> anyhow::Result<rsbinder::Strong<dyn IKeystoreService>> {
    let _init_guard = keystore_init_lock().lock().unwrap();
    let cached = keystore_cache().lock().unwrap().service.clone();
    if let Some(service) = cached {
        if keystore_service_is_alive(&service) {
            return Ok(service);
        }

        let mut guard = keystore_cache().lock().unwrap();
        guard.service = None;
        guard.death_recipient = None;
    }

    let service: rsbinder::Strong<dyn IKeystoreService> = get_interface_once(KEYSTORE_SERVICE)
        .map_err(|error| anyhow::anyhow!("failed to connect to {KEYSTORE_SERVICE}: {error:?}"))?;
    let generation = KEYSTORE_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    let recipient = Arc::new(KeystoreDeathRecipient {
        died: AtomicBool::new(false),
        generation,
    });
    let death_recipient: Arc<dyn DeathRecipient> = recipient.clone();
    service
        .as_binder()
        .link_to_death(Arc::downgrade(&death_recipient))?;
    if recipient.died.load(Ordering::Acquire) || !keystore_service_is_alive(&service) {
        return Err(anyhow::anyhow!(
            "connected to {KEYSTORE_SERVICE} but binder died during initialization"
        ));
    }

    let mut guard = keystore_cache().lock().unwrap();
    guard.death_recipient = Some(death_recipient);
    guard.service = Some(service.clone());
    guard.generation = generation;
    if recipient.died.load(Ordering::Acquire) {
        guard.service = None;
        guard.death_recipient = None;
        return Err(anyhow::anyhow!(
            "connected to {KEYSTORE_SERVICE} but binder died during initialization"
        ));
    }

    Ok(service)
}

pub fn get_aaid(uid: u32) -> anyhow::Result<Vec<u8>> {
    debug!("resolving AAID uid={}", uid);
    let application_id = if (uid == 0) || (uid == 1000) {
        let info = KeyAttestationPackageInfo {
            packageName: "AndroidSystem".to_string(),
            versionCode: 1,
            ..Default::default()
        };
        KeyAttestationApplicationId {
            packageInfos: vec![info],
        }
    } else {
        get_application_id_from_provider(uid)?
    };

    debug!("resolved application_id={:?}", application_id);

    encode_application_id(application_id)
}

/// 这个 uid 挂着哪些包（AAID 里那几个 `packageInfos` 的包名）。
///
/// SOTER 分流要按「真调用者是谁」判：调用方自己填的 uid / 别名都不可信（实测探测机
/// 填过 Gmail 的 uid），只有内核填的 `sender_euid` 可信；而 uid→包名这个映射得问系统。
/// 那个服务只认 Keystore/Credstore 的 uid，所以只能在这儿翻（daemon 跑在 keystore uid），
/// payload 那边（SOTER 宿主，uid 1000）一问就被拒：
/// `This service can only be used by Keystore or Credstore`。
pub fn package_names_for_uid(uid: u32) -> anyhow::Result<Vec<String>> {
    // 系统自己那两份没有对应的安装包，`get_aaid` 里也是这么特判的。
    if uid == 0 || uid == 1000 {
        return Ok(Vec::new());
    }

    let mut error = None;
    match get_application_id_from_provider(uid) {
        Ok(application_id) => {
            let names = package_names_of(&application_id);
            if !names.is_empty() {
                return Ok(names);
            }
        }
        Err(failed) => error = Some(failed),
    }

    // 不是 user 0 的 uid（多用户 / 分身 / 空间）：`uid = userId * 100000 + appId`。系统那套
    // 正常查表认不出这些用户号 —— 实测生产里的槽位表上见过 `999`(288) / `998`(84) / `997`(33) /
    // `996`(16) / `995`(10) / `994`(4) / `19000`(30)，还有真实的 `10` / `11` / `12`——
    // AAID 要么回空、要么直接报错，于是这些 uid 永远翻不出包名，服务端只能退回按别名/槽位猜
    // （生产日志里 `99910365` / `99910617` 那些就是这么被拦下的）。
    // 同一个 App 的 appId 跟它在 user 0 上那份一致，所以拿 appId 再问一次就能拿到同一个包。
    // 先问 root 侧那张表（它就是系统自己的 `packages.list`，分身的行也在里面，最准）；
    // 表里没这一条（root 侧还没写出来、或者那个 ROM 的表里真没有）再拿 appId 猜一次 ——
    // 同一个 App 的 appId 跟它在 user 0 上那份一致，所以猜也能猜对大多数。
    if let Some(package) = package_from_uid_table(uid) {
        log::info!("event=soter caller uid {uid} 从 root 侧 uid→包名表里翻出 {package}");
        return Ok(vec![package]);
    }
    if let Some(app_id) = other_user_app_id(uid) {
        if let Ok(application_id) = get_application_id_from_provider(app_id) {
            let names = package_names_of(&application_id);
            if !names.is_empty() {
                log::info!(
                    "event=soter caller uid {uid} 不是 user 0（多用户/分身），按 appId {app_id} 翻出 {names:?}"
                );
                return Ok(names);
            }
        }
    }

    // 没翻到就是没翻到（空名单）；但系统真的拒绝了（不是「查无此 uid」）时把错报上去，
    // 调用方那条 warn 日志才有东西可写。
    match error {
        Some(failed) => Err(failed),
        None => Ok(Vec::new()),
    }
}

/// root 侧（`daemon-injector`）周期写出来的「uid → 包名」表。
///
/// 为什么要多这条：AAID 服务在分身/空间/多用户那些 uid 上会回空或直接报错，那些机器就永远
/// 翻不出包名、只能退回按别名/槽位猜。这张表是 root 直接从系统自己的 `packages.list` 抄的，
/// 不依赖那个服务、也不靠 appId 猜（分身那些 999xxxxx 在 `packages.list` 里本来就有行）。
const UID_PACKAGES_PATH: &str = "/data/misc/keystore/ommega/uid_packages";

/// 表的内容 + 什么时候读的。文件不大（几百行），一分钟重读一次就够。
static UID_PACKAGES: std::sync::Mutex<
    Option<(std::time::Instant, std::collections::HashMap<u32, String>)>,
> = std::sync::Mutex::new(None);

/// 从那张表里查这个 uid 挂着哪个包（表不在/读不出来/没这一条都回 `None`）。
fn package_from_uid_table(uid: u32) -> Option<String> {
    const TTL: std::time::Duration = std::time::Duration::from_secs(60);

    let mut guard = UID_PACKAGES.lock().ok()?;
    let stale = guard
        .as_ref()
        .map(|(at, _)| at.elapsed() >= TTL)
        .unwrap_or(true);
    if stale {
        let text = std::fs::read_to_string(UID_PACKAGES_PATH).unwrap_or_default();
        *guard = Some((std::time::Instant::now(), parse_uid_packages(&text)));
    }
    guard.as_ref()?.1.get(&uid).cloned()
}

/// 把「`uid 包名` 一行一条」的表解析成映射。空行、`#` 注释、字段不够的都不算，uid 不是
/// 数字的也跳过。
fn parse_uid_packages(text: &str) -> std::collections::HashMap<u32, String> {
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(uid), Some(package)) = (fields.next(), fields.next()) else {
            continue;
        };
        if let Ok(uid) = uid.parse::<u32>() {
            map.insert(uid, package.to_string());
        }
    }
    map
}

/// root 侧（`daemon-injector`）周期性写出来的「当前前台应用」：一行 `<epoch 秒> <包名>`。
///
/// 它是最后一道兜底：前面三层（内核 uid、root 侧表、appId 回退）都拿不到包名时才用它。
/// 它比前三层弱 —— 前台是谁不等于谁在调 SOTER（支付流程可能在子进程/后台）—— 所以还带
/// 新鲜度阀（文件超过这个秒数就不用）和配置开关（root 侧得不写，它就不存在）。
const FOREGROUND_PATH: &str = "/data/misc/keystore/ommega/foreground";

/// 前台信息算多新鲜才能用。
const FOREGROUND_TTL_SECS: u64 = 8;

/// 前台应用兜底：把那个文件读出来，太旧/格式不对就回 `None`。
pub fn foreground_package() -> Option<String> {
    let text = std::fs::read_to_string(FOREGROUND_PATH).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    parse_foreground(&text, now)
}

/// 解析「前台应用」那个文件：`<epoch 秒> <包名>`，太旧（`FOREGROUND_TTL_SECS`）就不算。
fn parse_foreground(text: &str, now_epoch_secs: u64) -> Option<String> {
    let mut fields = text.split_whitespace();
    let at = fields.next()?.parse::<u64>().ok()?;
    let package = fields.next()?;
    if now_epoch_secs.saturating_sub(at) > FOREGROUND_TTL_SECS {
        return None;
    }
    if package.is_empty() || package == "-" {
        return None;
    }
    Some(package.to_string())
}

fn package_names_of(application_id: &KeyAttestationApplicationId) -> Vec<String> {
    application_id
        .packageInfos
        .iter()
        .map(|info| info.packageName.clone())
        .filter(|name| !name.is_empty())
        .collect()
}

/// 不是 user 0 的 uid（多用户 / 分身 / 空间）回它的 appId；user 0 的就没什么可回退的（appId 就是 uid）。
fn other_user_app_id(uid: u32) -> Option<u32> {
    (multiuser_get_user_id(uid) != 0).then(|| multiuser_get_app_id(uid))
}

fn get_application_id_from_provider(uid: u32) -> anyhow::Result<KeyAttestationApplicationId> {
    let _wd = crate::watchdog::watch("get_aaid: Retrieving AAID by calling service");
    let use_legacy = super::legacy::should_use_aaid_provider();
    let mut tried = 0;
    loop {
        let result = if use_legacy {
            super::legacy::get_application_id(uid)
        } else {
            let pm = get_pm()?;
            let current_uid = unsafe { libc::getuid() };
            let current_euid = unsafe { libc::geteuid() };
            debug!(
                "calling AAID provider as uid={} euid={}",
                current_uid, current_euid
            );
            pm.getKeyAttestationApplicationId(uid as i32)
                .map_err(anyhow::Error::new)
        };

        match result {
            Result::Ok(application_id) => return Ok(application_id),
            Err(error) => {
                if is_transaction_failed_error(&error) && tried < 2 {
                    error!(
                        "getKeyAttestationApplicationId transaction failed uid={}: {:?}",
                        uid, error
                    );
                    error!("resetting cached PM instance after AAID transaction failure");
                    if use_legacy {
                        super::legacy::clear_provider_cache();
                    } else {
                        reset_pm();
                    }
                    tried += 1;
                } else if is_get_attestation_application_id_failed(&error) {
                    return Err(anyhow::anyhow!(KsError::Rc(
                        ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED
                    )));
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to get KeyAttestationApplicationId for UID {}, Error: {:?}",
                        uid,
                        error
                    ));
                }
            }
        }
    }
}

fn is_transaction_failed_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<rsbinder::Status>()
            .is_some_and(|status| {
                status.exception_code() == rsbinder::ExceptionCode::TransactionFailed
            })
            || cause
                .downcast_ref::<rsbinder::StatusCode>()
                .is_some_and(|status| *status == rsbinder::StatusCode::DeadObject)
    })
}

fn is_get_attestation_application_id_failed(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<rsbinder::Status>()
            .is_some_and(|status| {
                status.exception_code() == rsbinder::ExceptionCode::ServiceSpecific
                    && status.service_specific_error()
                        == ERROR_GET_ATTESTATION_APPLICATION_ID_FAILED
            })
    })
}

fn encode_application_id(
    application_id: KeyAttestationApplicationId,
) -> Result<Vec<u8>, anyhow::Error> {
    let sha256 = OmmegaSha256 {};
    let package_infos = application_id.packageInfos;
    let first_package = package_infos
        .first()
        .ok_or_else(|| anyhow::anyhow!("AttestationApplicationId has no package info"))?;

    let mut estimated_encoded_size = AAID_GENERAL_OVERHEAD;

    let mut package_info_records = Vec::new();
    for pkg in &package_infos {
        let package_name = pkg.packageName.as_bytes();
        let package_info = super::aaid::PackageInfoRecord {
            package_name: der::asn1::OctetString::new(package_name)?,
            version: pkg.versionCode as u64,
        };

        estimated_encoded_size = estimated_encoded_size
            .saturating_add(AAID_PKG_INFO_OVERHEAD)
            .saturating_add(package_name.len());
        if estimated_encoded_size > KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE {
            break;
        }
        package_info_records.push(package_info);
    }
    let package_info_set = SetOfVec::from_iter(package_info_records).map_err(|e| {
        anyhow::anyhow!(err!(
            "Failed to encode AttestationApplicationId package infos: {:?}",
            e
        ))
    })?;

    let mut signature_digests = Vec::new();
    for sig in &first_package.signatures {
        let result = sha256
            .hash(sig.data.as_slice())
            .map_err(|e| anyhow::anyhow!("Failed to hash signature: {:?}", e))?;
        signature_digests.push(result);
    }

    let mut signature_digest_records = Vec::new();
    for sig_digest in signature_digests {
        estimated_encoded_size = estimated_encoded_size.saturating_add(AAID_SIGNATURE_SIZE);
        if estimated_encoded_size > KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE {
            break;
        }
        signature_digest_records.push(der::asn1::OctetString::new(sig_digest)?);
    }
    let signature_digests = SetOfVec::from_iter(signature_digest_records).map_err(|e| {
        anyhow::anyhow!(err!(
            "Failed to encode AttestationApplicationId signature digests: {:?}",
            e
        ))
    })?;

    let result = super::aaid::AttestationApplicationId {
        package_info_records: package_info_set,
        signature_digests,
    };

    result
        .to_der()
        .map_err(|e| anyhow::anyhow!("Failed to encode AttestationApplicationId: {:?}", e))
}

pub fn get_apex_module_info() -> anyhow::Result<Vec<ApexModuleInfo>> {
    let apex: rsbinder::Strong<dyn IApexService> = get_interface_once("apexservice")?;
    let result: Vec<crate::android::apex::ApexInfo::ApexInfo> =
        apex.getActivePackages().map_err(|e| {
            log::error!("failed to get active packages: {:?}", e);
            anyhow::anyhow!(err!("getActivePackages failed: {:?}", e))
        })?;

    result
        .iter()
        .map(|i| {
            Ok(ApexModuleInfo {
                package_name: der::asn1::OctetString::new(i.moduleName.as_bytes())?,
                version_code: i.versionCode as u64,
            })
        })
        .collect::<anyhow::Result<Vec<ApexModuleInfo>>>()
        .map_err(|e| anyhow::anyhow!(err!("ApexModuleInfo conversion failed: {:?}", e)))
}

pub use kmr_common::consts::AID_USER_OFFSET;

/// Gets the user id from a uid.
pub fn multiuser_get_user_id(uid: u32) -> u32 {
    uid / AID_USER_OFFSET
}

/// Gets the app id from a uid.
pub fn multiuser_get_app_id(uid: u32) -> u32 {
    uid % AID_USER_OFFSET
}

/// Extracts the android user from the given uid.
pub fn uid_to_android_user(uid: u32) -> u32 {
    multiuser_get_user_id(uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android::security::keystore::Signature::Signature;
    use crate::plat::aaid::AttestationApplicationId as DerAttestationApplicationId;
    use der::Decode;

    fn signature(data: &[u8]) -> Signature {
        Signature {
            data: data.to_vec(),
        }
    }

    fn package(
        package_name: &str,
        version_code: i64,
        signatures: Vec<Signature>,
    ) -> KeyAttestationPackageInfo {
        KeyAttestationPackageInfo {
            packageName: package_name.to_string(),
            versionCode: version_code,
            signatures,
        }
    }

    #[test]
    fn aaid_encoder_uses_first_package_signatures_and_sorts_sets() {
        let app_id = KeyAttestationApplicationId {
            packageInfos: vec![
                package("z.example", 2, vec![signature(b"shared-signature")]),
                package("a.example", 1, vec![signature(b"shared-signature")]),
            ],
        };

        let der = encode_application_id(app_id).expect("AAID should encode");
        let parsed =
            DerAttestationApplicationId::from_der(&der).expect("encoded AAID should parse");

        assert_eq!(parsed.package_info_records.len(), 2);
        assert_eq!(parsed.signature_digests.len(), 1);
    }

    #[test]
    fn aaid_encoder_uses_aosp_package_size_limit() {
        let mut package_infos = Vec::new();
        for idx in 0..9 {
            let package_name = format!("pkg{:02}.{}", idx, "a".repeat(94));
            package_infos.push(package(
                &package_name,
                idx,
                vec![
                    signature(b"signature-1"),
                    signature(b"signature-2"),
                    signature(b"signature-3"),
                ],
            ));
        }

        let der = encode_application_id(KeyAttestationApplicationId {
            packageInfos: package_infos,
        })
        .expect("AAID should encode");
        let parsed =
            DerAttestationApplicationId::from_der(&der).expect("encoded AAID should parse");

        assert!(der.len() <= KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE);
        assert_eq!(parsed.package_info_records.len(), 8);
        assert_eq!(parsed.signature_digests.len(), 0);
    }

    #[test]
    fn aaid_encoder_uses_aosp_signature_size_limit() {
        let signatures = (0..35)
            .map(|idx| signature(format!("signature-{idx}").as_bytes()))
            .collect();
        let app_id = KeyAttestationApplicationId {
            packageInfos: vec![package("a", 1, signatures)],
        };

        let der = encode_application_id(app_id).expect("AAID should encode");
        let parsed =
            DerAttestationApplicationId::from_der(&der).expect("encoded AAID should parse");

        assert!(der.len() <= KEY_ATTESTATION_APPLICATION_ID_MAX_SIZE);
        assert_eq!(parsed.package_info_records.len(), 1);
        assert_eq!(parsed.signature_digests.len(), 29);
    }

    #[test]
    fn aaid_encoder_casts_version_code_to_unsigned() {
        let app_id = KeyAttestationApplicationId {
            packageInfos: vec![package("negative.version", -1, vec![])],
        };

        let der = encode_application_id(app_id).expect("AAID should encode");
        let parsed =
            DerAttestationApplicationId::from_der(&der).expect("encoded AAID should parse");

        assert_eq!(
            parsed
                .package_info_records
                .get(0)
                .expect("package info")
                .version,
            u64::MAX
        );
    }

    /// 不是 user 0 的 uid（分身/空间/多用户）都得能认出、并把 appId 取对。生产槽位表里见过
    /// `999` / `998` / `997` / `996` / `995` / `994` / `19000` 和真实的 `10` / `11` / `12`。
    #[test]
    fn a_non_user_zero_uid_falls_back_to_its_app_id() {
        assert_eq!(other_user_app_id(99910365), Some(10365));
        assert_eq!(other_user_app_id(99910617), Some(10617));
        assert_eq!(other_user_app_id(99610040), Some(10040));
        assert_eq!(other_user_app_id(1_900_010_040), Some(10040));
        // 真实的第二用户（user 10 / 12）。
        assert_eq!(other_user_app_id(1_010_490), Some(10490));
        assert_eq!(other_user_app_id(1_210_392), Some(10392));
        // user 0 的没什么可回退的（appId 就是 uid 本身）。
        assert_eq!(other_user_app_id(10490), None);
        assert_eq!(other_user_app_id(0), None);
        assert_eq!(other_user_app_id(1000), None);
    }

    /// root 侧那张 uid→包名表：一行一条，注释/空行/坏行都跳过，分身 uid 照样认。
    #[test]
    fn the_root_uid_package_table_is_parsed_line_by_line() {
        let table = parse_uid_packages(
            "# uid package\n10490 com.tencent.mm\n99910365 com.tencent.mm\n\n乱写一行\n10491\n  10492   com.taobao.taobao  \n",
        );
        assert_eq!(
            table.get(&10490).map(String::as_str),
            Some("com.tencent.mm")
        );
        assert_eq!(
            table.get(&99910365).map(String::as_str),
            Some("com.tencent.mm")
        );
        assert_eq!(
            table.get(&10492).map(String::as_str),
            Some("com.taobao.taobao")
        );
        assert_eq!(table.get(&10491), None);
        assert_eq!(table.len(), 3);
    }

    /// 前台应用兜底：格式对、且够新鲜才用；旧了/写的是空就回 None。
    #[test]
    fn the_foreground_fallback_needs_to_be_fresh() {
        let now = 1_791_000_000u64;
        assert_eq!(
            parse_foreground(&format!("{now} com.tencent.mm\n"), now),
            Some("com.tencent.mm".to_string())
        );
        // 刚过阀（8 秒）还能用，再旧就不算。
        assert_eq!(
            parse_foreground(
                &format!("{} com.tencent.mm", now - FOREGROUND_TTL_SECS),
                now
            ),
            Some("com.tencent.mm".to_string())
        );
        assert_eq!(
            parse_foreground(
                &format!("{} com.tencent.mm", now - FOREGROUND_TTL_SECS - 1),
                now
            ),
            None,
            "太旧的前台信息不能用"
        );
        // 空包名 / 只有时间 / 根本读不出时间，都不算。
        assert_eq!(parse_foreground(&format!("{now} -\n"), now), None);
        assert_eq!(parse_foreground(&format!("{now}\n"), now), None);
        assert_eq!(parse_foreground("乱写", now), None);
        assert_eq!(parse_foreground("", now), None);
    }
}
