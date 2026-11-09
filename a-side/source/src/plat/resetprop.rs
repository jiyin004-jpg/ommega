use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::Command,
    sync::{Mutex, OnceLock},
};

use anyhow::{anyhow, bail, Context, Result};
use rsbinder::{hub, Status, StatusCode};

const ANDROID_PACKAGE: &str = "android";
const PACKAGE_MANAGER_NATIVE_DESCRIPTOR: &str = "android.content.pm.IPackageManagerNative";
const PACKAGE_MANAGER_NATIVE_SERVICE: &str = "package_native";
const PHONE_DESCRIPTOR: &str = "com.android.internal.telephony.ITelephony";
const PHONE_SERVICE: &str = "phone";
const PHONE_SUB_INFO_DESCRIPTOR: &str = "com.android.internal.telephony.IPhoneSubInfo";
const PHONE_SUB_INFO_SERVICE: &str = "iphonesubinfo";
const TELEPHONY_FEATURE: &str = "android.hardware.telephony";
const TELEPHONY_GSM_FEATURE: &str = "android.hardware.telephony.gsm";
const TELEPHONY_CDMA_FEATURE: &str = "android.hardware.telephony.cdma";
const GET_DEVICE_ID_FOR_PHONE_TRANSACTION: rsbinder::TransactionCode =
    rsbinder::FIRST_CALL_TRANSACTION + 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TelephonyTransactions {
    get_imei_for_slot: rsbinder::TransactionCode,
    get_meid_for_slot: Option<rsbinder::TransactionCode>,
}

#[derive(Clone, Copy)]
enum PhoneIdentifierKind {
    DeviceId,
    Imei,
    Meid,
}

impl PhoneIdentifierKind {
    fn command(self) -> &'static str {
        match self {
            Self::DeviceId => "GET_DEVICE_ID",
            Self::Imei => "GET_IMEI",
            Self::Meid => "GET_MEID",
        }
    }

    fn from_command(command: &str) -> Option<Self> {
        match command {
            "GET_DEVICE_ID" => Some(Self::DeviceId),
            "GET_IMEI" => Some(Self::Imei),
            "GET_MEID" => Some(Self::Meid),
            _ => None,
        }
    }
}

/// 模块自带的那份 resetprop（`vendor/resetprop-rs` 编译出来的）。
///
/// 只认这一个路径：`customize.sh` 把与设备 ABI 匹配的那份装进 `libs/`，
/// `layout.sh` 再搬到 `bin/`。管理器的 resetprop 行为不统一（有的直接写属性区、
/// 有的只发 socket），读出来的值到底反映哪个时刻说不清，一律不用。
/// resetprop 的唯一位置：模块内的 `libs/<abi>/resetprop`（ELF，ksu 域可 execute）。
///
/// ABI 用**编译期常量**（`cfg!`），不去读 `ro.product.cpu.abi`：
/// `rsproperties` 在 keymint 这个静态进程里读不到属性区，读失败就会拼出
/// `libs/x86/resetprop`（不存在）→ 属性全读不到 → 证书里的 verifiedBootKey 变全零。
fn resetprop_path() -> String {
    let abi = if cfg!(target_arch = "aarch64") {
        "arm64-v8a"
    } else if cfg!(target_arch = "arm") {
        "armeabi-v7a"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "x86"
    };
    format!("/data/adb/modules/ommega/libs/{abi}/resetprop")
}

#[derive(Clone)]
pub struct ResetpropCommand {
    program: String,
    prepend_arg: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelephonyFeatures {
    pub any: bool,
    pub gsm: bool,
    pub cdma: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("service {0} unavailable")]
pub(crate) struct BinderServiceUnavailable(pub(crate) String);

fn require_binder_service<T>(name: &str, lookup: rsbinder::Result<Option<T>>) -> Result<T> {
    match lookup {
        Ok(Some(service)) => Ok(service),
        Ok(None) | Err(StatusCode::DeadObject) | Err(StatusCode::NotEnoughData) => {
            Err(BinderServiceUnavailable(name.to_string()).into())
        }
        // FailedTransaction is deliberately excluded: rsbinder also uses it for AIDL exceptions.
        Err(error) => {
            Err(error).with_context(|| format!("failed to look up Binder service {name}"))
        }
    }
}

static HELPER: OnceLock<Mutex<ResetpropHelperClient>> = OnceLock::new();

pub fn bootstrap_privileged_helper() -> Result<()> {
    if HELPER.get().is_some() {
        return Ok(());
    }

    let commands = resetprop_candidates();
    if commands.is_empty() {
        log::warn!("resetprop unavailable to privileged helper: no usable binary found");
    }

    let (parent, child) = UnixStream::pair().context("failed to create resetprop socketpair")?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to fork resetprop helper");
    }
    if pid == 0 {
        drop(parent);
        // 这个 helper 是 fork 出来的，comm 直接从主进程继承（就是伪装名）。
        // 再给它一个独立的名字：一个 PID 列表里两个同名进程反而值得多看一眼。
        if let Some(name) = crate::stealth::cached_name("helper") {
            if let Some(base) = name.rsplit('/').next() {
                crate::stealth::set_comm(base);
            }
        }
        let exit_code = match helper_loop(child, commands) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("resetprop helper exiting after fatal error: {error:#}");
                1
            }
        };
        unsafe { libc::_exit(exit_code) };
    }

    drop(child);
    let client = ResetpropHelperClient { stream: parent };
    if HELPER.set(Mutex::new(client)).is_err() {
        log::debug!("resetprop helper was already installed");
    } else {
        log::info!("started privileged resetprop helper process pid={pid}");
    }

    Ok(())
}

pub fn runtime_write_and_verify_property(property: &str, value: &str) -> Result<()> {
    with_helper(|helper| helper.write_and_verify_property(property, value))
}

pub fn runtime_get_device_id_for_phone(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::DeviceId, slot)
}

pub fn runtime_get_imei_for_slot(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::Imei, slot)
}

pub fn runtime_get_meid_for_slot(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::Meid, slot)
}

fn runtime_get_phone_identifier(kind: PhoneIdentifierKind, slot: i32) -> Result<Option<String>> {
    if !matches!(slot, 0 | 1) {
        bail!("unsupported phone slot {slot}");
    }
    with_helper(|helper| helper.get_phone_identifier(kind, slot))
}

pub fn runtime_telephony_features() -> Result<TelephonyFeatures> {
    with_helper(|helper| {
        Ok(TelephonyFeatures {
            any: helper.has_system_feature(TELEPHONY_FEATURE)?,
            gsm: helper.has_system_feature(TELEPHONY_GSM_FEATURE)?,
            cdma: helper.has_system_feature(TELEPHONY_CDMA_FEATURE)?,
        })
    })
}

pub(crate) fn is_binder_service_unavailable(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<BinderServiceUnavailable>().is_some())
}

fn with_helper<T>(call: impl FnOnce(&mut ResetpropHelperClient) -> Result<T>) -> Result<T> {
    let helper = HELPER
        .get()
        .ok_or_else(|| anyhow!("privileged resetprop helper is unavailable"))?;
    let mut helper = helper
        .lock()
        .map_err(|_| anyhow!("privileged resetprop helper lock poisoned"))?;
    call(&mut helper)
}

pub fn direct_write_and_verify_property(property: &str, value: &str) -> Result<()> {
    let candidates = resetprop_candidates();
    if candidates.is_empty() {
        return Err(anyhow!("no usable resetprop binary found"));
    }

    let mut last_error = None;
    for command in &candidates {
        match execute_write_and_verify(command, property, value) {
            Ok(()) => return Ok(()),
            Err(error) => {
                // 第一个没成最常见的原因就是这个域 exec 不了那个路径（SELinux），
                // 或者那一份自己不吃饭。换下一个接着试，别一条路走死。
                log::debug!("resetprop {} 没成: {error:#}", command.program);
                last_error = Some(error);
            }
        }
    }

    Err(last_error.expect("candidates is not empty"))
}

pub fn read_string_property(name: &str) -> Option<String> {
    if let Some(value) = rsproperties::get::<String>(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Some(value);
    }
    // rsproperties 直接 mmap `/dev/__properties__` 解析属性区，在 keymint 这种静态
    // 链接的进程里拿不到（返回 Err，被 `.ok()` 吞掉后静默走进兼容回退，于是证书就
    // 用了开机快照而不是当前属性）。
    //
    // 退回模块自带的 resetprop：它在同一台设备上实测能读到实时值（`resetprop <name>`
    // 打印当前值），而且就住在 `/data/adb` 下，keymint 一定 exec 得动。
    read_property_via_resetprop(name)
}

/// 用模块自带的 resetprop 读一次属性（`resetprop <name>` 打印当前值）。
fn read_property_via_resetprop(name: &str) -> Option<String> {
    for command in resetprop_candidates() {
        let Ok(output) = std::process::Command::new(&command.program)
            .arg(name)
            .output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !value.is_empty() {
            return Some(value);
        }
    }
    None
}

/// 所有可用的 resetprop（现在只有一个）。
///
/// 读写属性用的 resetprop。只有一个位置，所以这里永远返回 0 或 1 个元素
/// （保留列表形态是为了让 `read_property_via_resetprop` / 写路径不必改签名）。
pub fn resetprop_candidates() -> Vec<ResetpropCommand> {
    let path = resetprop_path();
    if Path::new(&path).exists() {
        vec![ResetpropCommand {
            program: path,
            prepend_arg: None,
        }]
    } else {
        Vec::new()
    }
}
fn execute_write_and_verify(command: &ResetpropCommand, property: &str, value: &str) -> Result<()> {
    let mut process = Command::new(&command.program);
    if let Some(prepend_arg) = &command.prepend_arg {
        process.arg(prepend_arg);
    }
    let status = process
        .arg(property)
        .arg(value)
        .status()
        .with_context(|| format!("failed to execute resetprop for {property}"))?;
    if !status.success() {
        bail!("resetprop failed for {property} with status {status}");
    }

    let actual = read_string_property(property)
        .ok_or_else(|| anyhow!("property {property} missing after resetprop write"))?;
    if actual.eq_ignore_ascii_case(value) {
        Ok(())
    } else {
        bail!(
            "property verification failed for {property}: expected {value}, got {}",
            actual
        )
    }
}

struct ResetpropHelperClient {
    stream: UnixStream,
}

impl ResetpropHelperClient {
    fn write_and_verify_property(&mut self, property: &str, value: &str) -> Result<()> {
        let response = self.request(&format!("SET\t{property}\t{value}\n"))?;
        if response == "OK" {
            Ok(())
        } else {
            bail!("unexpected resetprop helper response")
        }
    }

    fn get_phone_identifier(
        &mut self,
        kind: PhoneIdentifierKind,
        slot: i32,
    ) -> Result<Option<String>> {
        let response = self.request(&format!("{}\t{slot}\n", kind.command()))?;
        if response == "NONE" {
            return Ok(None);
        }
        if let Some(value) = response.strip_prefix("OK\t") {
            if value.is_empty() {
                bail!("phone identifier helper returned an empty value");
            }
            return Ok(Some(value.to_string()));
        }
        bail!("unexpected phone identifier helper response")
    }

    fn has_system_feature(&mut self, feature: &str) -> Result<bool> {
        match self.request(&format!("HAS_FEATURE\t{feature}\n"))?.as_str() {
            "TRUE" => Ok(true),
            "FALSE" => Ok(false),
            _ => bail!("unexpected telephony feature helper response"),
        }
    }

    fn request(&mut self, request: &str) -> Result<String> {
        self.stream
            .write_all(request.as_bytes())
            .context("failed to send privileged helper request")?;
        self.stream
            .flush()
            .context("failed to flush privileged helper request")?;

        let mut response = String::new();
        let mut reader = BufReader::new(
            self.stream
                .try_clone()
                .context("failed to clone privileged helper stream")?,
        );
        let read = reader
            .read_line(&mut response)
            .context("failed to read privileged helper response")?;
        if read == 0 {
            bail!("privileged helper closed unexpectedly");
        }
        let response = response.trim_end_matches(['\r', '\n']);
        if let Some(service) = response.strip_prefix("UNAVAILABLE\t") {
            return Err(BinderServiceUnavailable(service.to_string()).into());
        }
        if let Some(error) = response.strip_prefix("ERR\t") {
            bail!("{error}");
        }
        Ok(response.to_string())
    }
}

fn execute_phone_identifier(kind: PhoneIdentifierKind, slot: i32) -> Result<Option<String>> {
    rsbinder::ProcessState::init_default()
        .map_err(|error| anyhow!("failed to initialize Binder in privileged helper: {error}"))?;

    let transactions = telephony_transactions();
    let (service, expected_descriptor, transaction, label) = match kind {
        PhoneIdentifierKind::DeviceId => (
            PHONE_SUB_INFO_SERVICE,
            PHONE_SUB_INFO_DESCRIPTOR,
            Some(GET_DEVICE_ID_FOR_PHONE_TRANSACTION),
            "device ID",
        ),
        PhoneIdentifierKind::Imei => (
            PHONE_SERVICE,
            PHONE_DESCRIPTOR,
            Some(transactions.get_imei_for_slot),
            "IMEI",
        ),
        PhoneIdentifierKind::Meid => (
            PHONE_SERVICE,
            PHONE_DESCRIPTOR,
            transactions.get_meid_for_slot,
            "MEID",
        ),
    };
    let Some(transaction) = transaction else {
        return Ok(None);
    };

    let binder = require_binder_service(service, hub::try_get_service(service))?;
    let descriptor = binder.descriptor();
    if descriptor != expected_descriptor {
        bail!("{service} descriptor mismatch: {descriptor}");
    }
    let proxy = binder
        .as_proxy()
        .with_context(|| format!("{service} binder was unexpectedly local"))?;
    let mut data = proxy
        .prepare_transact(true)
        .with_context(|| format!("failed to prepare {label} transaction"))?;
    data.write(&slot)
        .with_context(|| format!("failed to write {label} slot"))?;
    data.write(ANDROID_PACKAGE)
        .with_context(|| format!("failed to write {label} calling package"))?;
    data.write(ANDROID_PACKAGE)
        .with_context(|| format!("failed to write {label} calling feature"))?;

    let mut reply = proxy
        .submit_transact(transaction, &data, rsbinder::FLAG_CLEAR_BUF)
        .with_context(|| format!("{label} transact failed"))?
        .with_context(|| format!("{label} returned no reply"))?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .with_context(|| format!("failed to decode {label} reply status"))?;
    if !status.is_ok() {
        bail!("{label} returned non-ok status: {status}");
    }

    let Some(value): Option<String> = reply
        .read()
        .with_context(|| format!("failed to decode {label} value"))?
    else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        bail!("{label} returned an invalid identifier");
    }
    Ok(Some(value.to_string()))
}

fn execute_has_system_feature(feature: &str) -> Result<bool> {
    rsbinder::ProcessState::init_default()
        .map_err(|error| anyhow!("failed to initialize Binder in privileged helper: {error}"))?;

    let binder = require_binder_service(
        PACKAGE_MANAGER_NATIVE_SERVICE,
        hub::try_get_service(PACKAGE_MANAGER_NATIVE_SERVICE),
    )?;
    let descriptor = binder.descriptor();
    if descriptor != PACKAGE_MANAGER_NATIVE_DESCRIPTOR {
        bail!("PackageManager descriptor mismatch: {descriptor}");
    }
    let proxy = binder
        .as_proxy()
        .context("PackageManager binder was unexpectedly local")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare PackageManager transaction")?;
    data.write(feature)
        .context("failed to write PackageManager feature name")?;
    data.write(&0_i32)
        .context("failed to write PackageManager feature version")?;

    let mut reply = proxy
        .submit_transact(
            has_system_feature_transaction(kmr_common::android_version::android_major_version()),
            &data,
            rsbinder::FLAG_CLEAR_BUF,
        )
        .context("PackageManager hasSystemFeature transact failed")?
        .context("PackageManager hasSystemFeature returned no reply")?;
    reply.set_data_position(0);

    let status: Status = reply
        .read()
        .context("failed to decode PackageManager hasSystemFeature status")?;
    if !status.is_ok() {
        bail!("PackageManager hasSystemFeature returned non-ok status: {status}");
    }
    reply
        .read()
        .context("failed to decode PackageManager hasSystemFeature result")
}

fn has_system_feature_transaction(android_major: Option<i32>) -> rsbinder::TransactionCode {
    let offset = match android_major {
        Some(..=13) => 12,
        Some(14) => 9,
        Some(15 | 16) | None => 10,
        Some(17..) => 13,
    };
    rsbinder::FIRST_CALL_TRANSACTION + offset
}

fn telephony_transactions() -> TelephonyTransactions {
    telephony_transactions_for(kmr_common::android_version::android_major_version())
}

fn telephony_transactions_for(android_major: Option<i32>) -> TelephonyTransactions {
    let (imei_offset, meid_offset) = match android_major {
        Some(version) if version <= 12 => (149, Some(151)),
        Some(13) => (145, Some(147)),
        Some(14) => (148, Some(151)),
        Some(version) if version >= 17 => (132, None),
        _ => (147, Some(150)),
    };

    TelephonyTransactions {
        get_imei_for_slot: rsbinder::FIRST_CALL_TRANSACTION + imei_offset,
        get_meid_for_slot: meid_offset.map(|offset| rsbinder::FIRST_CALL_TRANSACTION + offset),
    }
}

fn parse_phone_identifier_request(line: &str) -> Option<(PhoneIdentifierKind, &str)> {
    let (command, slot) = line.split_once('\t')?;
    PhoneIdentifierKind::from_command(command).map(|kind| (kind, slot))
}

fn parse_feature_request(line: &str) -> Option<&str> {
    let feature = line.strip_prefix("HAS_FEATURE\t")?;
    matches!(
        feature,
        TELEPHONY_FEATURE | TELEPHONY_GSM_FEATURE | TELEPHONY_CDMA_FEATURE
    )
    .then_some(feature)
}

fn helper_error_response(error: &anyhow::Error) -> String {
    if let Some(error) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<BinderServiceUnavailable>())
    {
        format!("UNAVAILABLE\t{}\n", error.0)
    } else {
        format!("ERR\t{error:#}\n")
    }
}

fn helper_loop(stream: UnixStream, commands: Vec<ResetpropCommand>) -> Result<()> {
    let reader_stream = stream
        .try_clone()
        .context("failed to clone resetprop helper socket")?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .context("failed to read resetprop helper request")?;
        if read == 0 {
            return Ok(());
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        let response = if let Some(feature) = parse_feature_request(trimmed) {
            match execute_has_system_feature(feature) {
                Ok(true) => "TRUE\n".to_string(),
                Ok(false) => "FALSE\n".to_string(),
                Err(error) => helper_error_response(&error),
            }
        } else if let Some((kind, slot)) = parse_phone_identifier_request(trimmed) {
            match slot.parse::<i32>() {
                Ok(slot) if matches!(slot, 0 | 1) => match execute_phone_identifier(kind, slot) {
                    Ok(Some(value)) => format!("OK\t{value}\n"),
                    Ok(None) => "NONE\n".to_string(),
                    Err(error) => helper_error_response(&error),
                },
                _ => "ERR\tinvalid phone identifier helper request\n".to_string(),
            }
        } else {
            match parse_request(&line) {
                Ok((property, value)) => {
                    // 挨个试：第一个多是 exec 不通（这个域没权限），换下一个。
                    let mut last_error = None;
                    let mut done = false;
                    for command in &commands {
                        match execute_write_and_verify(command, &property, &value) {
                            Ok(()) => {
                                done = true;
                                break;
                            }
                            Err(error) => last_error = Some(error),
                        }
                    }
                    if done {
                        "OK\n".to_string()
                    } else {
                        match last_error {
                            Some(error) => helper_error_response(&error),
                            None => "ERR\tresetprop is unavailable\n".to_string(),
                        }
                    }
                }
                Err(error) => format!("ERR\t{error:#}\n"),
            }
        };
        writer
            .write_all(response.as_bytes())
            .context("failed to write resetprop helper response")?;
        writer
            .flush()
            .context("failed to flush resetprop helper response")?;
    }
}

fn parse_request(line: &str) -> Result<(String, String)> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, '\t');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("SET"), Some(property), Some(value))
            if !property.trim().is_empty() && !value.trim().is_empty() =>
        {
            Ok((property.to_string(), value.to_string()))
        }
        _ => Err(anyhow!("invalid resetprop helper request: {trimmed:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telephony_transactions_match_android_12_through_17() {
        use rsbinder::FIRST_CALL_TRANSACTION;

        assert_eq!(
            GET_DEVICE_ID_FOR_PHONE_TRANSACTION,
            FIRST_CALL_TRANSACTION + 3
        );
        for (version, offset) in [(12, 12), (13, 12), (14, 9), (15, 10), (16, 10), (17, 13)] {
            assert_eq!(
                has_system_feature_transaction(Some(version)),
                FIRST_CALL_TRANSACTION + offset
            );
        }
        for (version, imei, meid) in [
            (12, 149, Some(151)),
            (13, 145, Some(147)),
            (14, 148, Some(151)),
            (15, 147, Some(150)),
            (16, 147, Some(150)),
            (17, 132, None),
        ] {
            let transactions = telephony_transactions_for(Some(version));
            assert_eq!(
                transactions.get_imei_for_slot,
                FIRST_CALL_TRANSACTION + imei
            );
            assert_eq!(
                transactions.get_meid_for_slot,
                meid.map(|offset| FIRST_CALL_TRANSACTION + offset)
            );
        }
    }

    #[test]
    fn feature_helper_accepts_only_telephony_features() {
        for feature in [
            TELEPHONY_FEATURE,
            TELEPHONY_GSM_FEATURE,
            TELEPHONY_CDMA_FEATURE,
        ] {
            assert_eq!(
                parse_feature_request(&format!("HAS_FEATURE\t{feature}")),
                Some(feature)
            );
        }
        assert_eq!(
            parse_feature_request("HAS_FEATURE\tandroid.hardware.camera"),
            None
        );
        assert_eq!(parse_feature_request("HAS_FEATURE"), None);
    }

    #[test]
    fn service_unavailable_response_round_trips() {
        let (client_stream, mut helper_stream) = UnixStream::pair().unwrap();
        let unavailable: anyhow::Error = BinderServiceUnavailable(PHONE_SERVICE.to_string()).into();
        helper_stream
            .write_all(helper_error_response(&unavailable).as_bytes())
            .unwrap();

        let mut client = ResetpropHelperClient {
            stream: client_stream,
        };
        let error = client
            .get_phone_identifier(PhoneIdentifierKind::Imei, 0)
            .unwrap_err();

        assert!(is_binder_service_unavailable(&error));
        assert_eq!(error.to_string(), "service phone unavailable");
    }

    #[test]
    fn service_lookup_only_retries_missing_or_transport_failures() {
        assert_eq!(
            require_binder_service(PHONE_SERVICE, Ok(Some(7_u8))).unwrap(),
            7
        );

        let unavailable: [rsbinder::Result<Option<()>>; 3] = [
            Ok(None),
            Err(StatusCode::DeadObject),
            Err(StatusCode::NotEnoughData),
        ];
        for lookup in unavailable {
            let error = require_binder_service(PHONE_SERVICE, lookup).unwrap_err();
            assert!(is_binder_service_unavailable(&error));
            assert_eq!(helper_error_response(&error), "UNAVAILABLE\tphone\n");
        }

        for status in [
            StatusCode::NameNotFound,
            StatusCode::PermissionDenied,
            StatusCode::FailedTransaction,
            StatusCode::WouldBlock,
            StatusCode::TimedOut,
            StatusCode::RpcError,
        ] {
            let error = require_binder_service::<()>(PHONE_SERVICE, Err(status)).unwrap_err();
            assert!(!is_binder_service_unavailable(&error));
            assert!(error
                .chain()
                .any(|cause| cause.downcast_ref::<StatusCode>() == Some(&status)));
            assert!(helper_error_response(&error).starts_with("ERR\t"));
        }
    }
}
