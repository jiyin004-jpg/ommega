use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};

use crate::{
    config::{ConfigFile, OsVersionSpec, RawTrustConfig, ResolvedTrust},
    plat::resetprop,
};

const SECURITY_PATCH_PROP: &str = "ro.build.version.security_patch";
const SECURITY_PATCH_FALLBACK: &str = "2025-06-05";
const VENDOR_PATCH_PROP: &str = "ro.vendor.build.security_patch";
const BOOT_PATCH_PROP: &str = "ro.vendor.boot_security_patch";

/// 面板「伪装参数」曾经写的那个名字（部分 ROM 用这个）。与上面等价。
const BOOT_PATCH_ALT_PROP: &str = "ro.boot.build.security_patch";
/// AProbe 的 A13 查的就是这个名字（`boot.image`，不是 `boot.build`）。
const BOOT_PATCH_APROBE_PROP: &str = "ro.boot.image.build.security_patch";

/// boot 补丁的三个属性变体，第一个是权威名。
///
/// 归一之后三个一起写成同一个值：面板伪装只写这一处，检测器（AProbe A13 读的是
/// `ro.boot.image.build.security_patch`）和出链读的也就是同一份，不用每处各猜一遍。
const BOOT_PATCH_VARIANTS: [&str; 3] =
    [BOOT_PATCH_APROBE_PROP, BOOT_PATCH_PROP, BOOT_PATCH_ALT_PROP];
const VBMETA_KEY_PROP: &str = "ro.boot.vbmeta.public_key_digest";
const VBMETA_HASH_PROP: &str = "ro.boot.vbmeta.digest";
const AVB_HEADER_SIZE: usize = 256;
const AVB_FOOTER_SIZE: usize = 64;
const AVB_MAX_VBMETA_SIZE: usize = 64 * 1024;
const AVB_VERSION_MAJOR: u32 = 1;
const AVB_VERSION_MINOR: u32 = 4;
const AVB_DESCRIPTOR_SIZE: usize = 16;
const AVB_PROPERTY_DESCRIPTOR_SIZE: usize = 32;
const AVB_PROPERTY_TAG: u64 = 0;
const BOOT_AVB_PROPERTY: &[u8] = b"com.android.build.boot.security_patch";
const BOOT_HEADER_PREFIX_SIZE: usize = 48;
const BOOT_HEADER_VERSION_OFFSET: usize = 40;
const BOOT_HEADER_V3_OS_VERSION_OFFSET: usize = 16;
const BOOT_HEADER_LEGACY_OS_VERSION_OFFSET: usize = 44;
const BUILD_PROP_PATHS: &[&str] = &[
    "/system/build.prop",
    "/system/system/build.prop",
    "/product/build.prop",
    "/system_ext/build.prop",
    "/vendor/build.prop",
    "/odm/build.prop",
    "/vendor/default.prop",
    "/default.prop",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPatchLevels {
    pub security_patch: String,
    pub os_patchlevel: String,
    pub vendor_patchlevel: String,
    pub boot_patchlevel: String,
    pub observed_security_patch: Option<String>,
    pub write_security_patch: bool,
}

pub fn bootstrap_vbmeta(config_file: &ConfigFile) -> Result<ResolvedTrust> {
    let patches = resolve_patch_levels(&config_file.trust)?;
    let os_version = match config_file.trust.os_version {
        OsVersionSpec::Auto => kmr_common::android_version::android_major_version().unwrap_or(16),
        OsVersionSpec::Fixed(value) => value,
    };

    Ok(ResolvedTrust {
        os_version,
        security_patch: patches.security_patch,
        os_patchlevel: patches.os_patchlevel,
        vendor_patchlevel: patches.vendor_patchlevel,
        boot_patchlevel: patches.boot_patchlevel,
    })
}

pub(crate) fn write_runtime_security_patch(desired: &str, previous: Option<&str>) -> Result<()> {
    write_security_patch_with_rollback(
        resetprop::runtime_write_and_verify_property,
        resetprop::read_string_property,
        desired,
        previous,
    )
}

/// daemon 通过环境变量传进来的 verified-boot hash（`OMMEGA_BOOT_HASH`）。
///
/// 为什么需要它：keymint 进程里 `rsproperties` 读属性区不可靠（读不到时不报错，
/// 静默退回「从原机 vbmeta 分区算出来的值」），而 daemon 是 shell 域，
/// `getprop` 拿到的一定是检测器也能看到的那一份。开机解析 config 和出证上报都用它。
pub(crate) fn boot_hash_from_env() -> Option<[u8; 32]> {
    let raw = std::env::var("OMMEGA_BOOT_HASH").ok()?;
    parse_hex_32(raw.trim()).ok()
}

/// 同理，vbmeta 公钥摘要。
pub(crate) fn boot_key_from_env() -> Option<[u8; 32]> {
    let raw = std::env::var("OMMEGA_BOOT_KEY").ok()?;
    parse_hex_32(raw.trim()).ok()
}

/// daemon 通过环境变量传进来的 boot 补丁级别（`OMMEGA_PATCH_BOOT`）。
///
/// 为什么需要：三个候选属性里，`ro.vendor.boot_security_patch` 落在
/// `vendor_default_prop`，而 `ro.boot.build.security_patch` /
/// `ro.boot.image.build.security_patch` 落在 `bootloader_prop`。不少 ROM 不给
/// keystore 域读 vendor_default_prop（NX721J 实测：policy 里只放行了
/// vendor_security_patch_level_prop），keymint 里又没法 fork resetprop 兜底
/// （entrypoint 被拒），于是三个都读不到，退回 boot 镜像编译日期——检测器的 A13
/// 拿 719 跟 `ro.boot.image.build.security_patch` 一对就报不一致。
///
/// daemon 是 shell 域，`getprop` 读得到真实值，开机时传进来。
fn boot_patchlevel_from_env() -> Option<String> {
    let raw = std::env::var("OMMEGA_PATCH_BOOT").ok()?;
    let value = raw.trim().to_string();
    (!value.is_empty()).then_some(value)
}

/// 出证路径上 key / hash 的短缓存：一次出证要读两个属性，各 fork 一个进程（实测
/// 单次 22ms）。而 attest 往往是连着来几笔（generateKey 一笔、getKeyEntry 一笔、
/// 再换算法一笔），3 秒内复用同一份读结果就够了。
///
/// 只缓存**成功**的结果：读失败不缓存，下一次直接重试（不会把一次性的权限问题
/// 锁死两秒）。
const ROT_CACHE_TTL: Duration = Duration::from_secs(3);

fn cached_hex_property(name: &'static str) -> Option<[u8; 32]> {
    type Slot = Mutex<Option<(Instant, [u8; 32])>>;
    static KEY_CACHE: OnceLock<Slot> = OnceLock::new();
    static HASH_CACHE: OnceLock<Slot> = OnceLock::new();

    let cell = if name == VBMETA_KEY_PROP {
        KEY_CACHE.get_or_init(|| Mutex::new(None))
    } else {
        HASH_CACHE.get_or_init(|| Mutex::new(None))
    };

    if let Ok(guard) = cell.lock() {
        if let Some((at, value)) = guard.as_ref() {
            if at.elapsed() < ROT_CACHE_TTL {
                return Some(*value);
            }
        }
    }

    let value = read_hex_property(name)?;
    if let Ok(mut guard) = cell.lock() {
        *guard = Some((Instant::now(), value));
    }
    Some(value)
}

/// 解锁设备的 `ro.boot.vbmeta.public_key_digest` 本来就是空的（原生全零），
/// 而 `verifiedBootKey` 全零本身就是个「未签名/解锁」特征，不能就这么发出去。
///
/// 用 boot hash 派生一个稳定的非零值：同一台设备每次一样、不同设备不一样，
/// 也仍然属同一台机器的根。
fn derived_boot_key(hash: &[u8; 32]) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(hash);
    ctx.update(b"ommega/vbmeta-public-key");
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// 当前 RootOfTrust：key / hash 读**当刻属性**（2 秒内复用），锁定与验证状态固定
/// 「已锁定 + 已验证」。
///
/// 顺序：读属性（带短缓存）→ daemon 启动时读好的环境变量（兜底）。
/// **不能反过来**：env 是开机快照，运行中 daemon 会把 B 的属性同步过来（physical
/// 模式），快照就是旧的 —— 证书和 `getprop` 一对就是 mismatch。
///
/// key 全零（设备没这个属性）时用 hash 派生，不发全零证书；hash 全零就真的没招，
/// 但那种情况下证书本身也没法自洽，保留零值并交给上层报错。
///
/// 代价：缓存过期后的第一笔出证要 fork 两次（约 40ms）；连着来的几笔零开销。
/// 属性真变了（daemon 同步了 B 的值）最多晚 2 秒被发现，可接受。
pub(crate) fn runtime_root_of_trust() -> ([u8; 32], [u8; 32], bool, u32) {
    let hash = cached_hex_property(VBMETA_HASH_PROP)
        .or_else(boot_hash_from_env)
        .unwrap_or([0u8; 32]);
    let key = cached_hex_property(VBMETA_KEY_PROP)
        .filter(|k| k.iter().any(|b| *b != 0))
        .or_else(boot_key_from_env)
        .filter(|k| k.iter().any(|b| *b != 0))
        .unwrap_or_else(|| derived_boot_key(&hash));
    (key, hash, true, 0)
}

pub(crate) fn resolve_patch_levels(trust: &RawTrustConfig) -> Result<ResolvedPatchLevels> {
    let observed_security_patch = resetprop::read_string_property(SECURITY_PATCH_PROP);
    let security_patch = observed_security_patch
        .clone()
        .or_else(|| read_build_prop_value(SECURITY_PATCH_PROP));
    if security_patch.is_none() {
        log::warn!(
            "failed to read {SECURITY_PATCH_PROP} from properties or build.prop; using {SECURITY_PATCH_FALLBACK}"
        );
    }
    let vendor_patch = resetprop::read_string_property(VENDOR_PATCH_PROP)
        .or_else(|| read_build_prop_value(VENDOR_PATCH_PROP));
    let property_boot_patch = boot_patchlevel_from_env()
        .or_else(|| resetprop::read_string_property(BOOT_PATCH_PROP))
        .or_else(|| read_build_prop_value(BOOT_PATCH_PROP))
        // 面板「伪装参数」写的是 AOSP 常见名 `ro.boot.build.security_patch`，
        // 而厂商习惯用 `ro.vendor.boot_security_patch`。两个都认，否则用户在面板上
        // 写了值，证书里却还是 bootimage 编译日期。
        .or_else(|| resetprop::read_string_property(BOOT_PATCH_ALT_PROP))
        .or_else(|| read_build_prop_value(BOOT_PATCH_ALT_PROP))
        // AProbe 的 A13 直接读这个名字，三个变体都认，免得检测器查的跟我们写的不是同一个。
        .or_else(|| resetprop::read_string_property(BOOT_PATCH_APROBE_PROP))
        .or_else(|| read_build_prop_value(BOOT_PATCH_APROBE_PROP))
        // 上面的开机属性在不少 ROM 上根本读不到（keystore 域没有 vendor_default_prop /
        // bootloader_prop 的读权限），那就退到「设备自己报的安全补丁」这两个属性：
        // 它们是 build.prop 里的静态值，读文件就能拿到，而且检测器一般都拿它们当基准。
        // 比退回 boot 镜像编译日期（可能差好几个月）准得多。
        .or_else(|| resetprop::read_string_property(VENDOR_PATCH_PROP))
        .or_else(|| read_build_prop_value(VENDOR_PATCH_PROP))
        .or_else(|| resetprop::read_string_property(SECURITY_PATCH_PROP))
        .or_else(|| read_build_prop_value(SECURITY_PATCH_PROP));
    // boot 分区内嵌 vbmeta 里的补丁日期是**镜像事实**：跟 os/vendor 同一次 OTA，
    // 不会像 bootloader 属性那样停在旧值（本机实测属性 2025-03-01、分区 2026-08-01，
    // 因为厂商没跟着刷 bootloader）。所以 auto 模式下它排在属性前面，两者不一致时
    // 以它为准并打一条 warn —— 以前是属性优先，旧日期就此锁进链里。
    let avb_boot_patch = match read_abl_boot_patchlevel() {
        Ok(value) => Some(value.to_string()),
        Err(error) => {
            log::debug!("failed to resolve boot patch level from boot metadata: {error:#}");
            None
        }
    };
    if let (Some(prop), Some(avb)) = (property_boot_patch.as_deref(), avb_boot_patch.as_deref()) {
        if boot_patchlevel_wire(prop) != boot_patchlevel_wire(avb) {
            log::warn!(
                "boot patch level mismatch: property {prop}, boot image {avb}; using the boot image value"
            );
        }
    }
    // 顺序：daemon 算好的最终值（伪装优先）→ boot 分区真值 → 属性 → 编译日期。
    //
    // 以前属性排第一，属性被污染后旧日期就锁进链里；反过来把 AVB 排第一又有另一个
    // 毛病：用户明明伪装了日期，链上还是真值。所以优先级统一在 daemon 里定，结果落进
    // `patch.state`，这里只管用它。
    let state_boot_patch = read_boot_patchlevel_state();
    let boot_patch = if trust.boot_patchlevel.trim() == "auto" {
        state_boot_patch
            .clone()
            .or(avb_boot_patch.clone())
            .or(property_boot_patch.clone())
            .or_else(bootimage_date_patchlevel)
    } else {
        property_boot_patch
    };
    let latest = [
        trust.security_patch.as_str(),
        trust.os_patchlevel.as_str(),
        trust.vendor_patchlevel.as_str(),
        trust.boot_patchlevel.as_str(),
    ]
    .iter()
    .any(|value| value.trim() == "latest")
    .then(current_patchlevel)
    .transpose()?;
    resolve_patch_levels_from(
        trust,
        security_patch.as_deref(),
        vendor_patch.as_deref(),
        boot_patch.as_deref(),
        observed_security_patch.as_deref(),
        latest.as_deref(),
    )
}

/// `ro.bootimage.build.date.utc` 的 epoch 秒转成 YYYYMMDD。
///
/// AVB 里没给 boot 补丁级别时用它当近似值：检测器比的就是这个属性（boot 镜像
/// 的编译日期）跟链上的 boot 补丁级别，差一个月以上就报警。
fn bootimage_date_patchlevel() -> Option<String> {
    let raw = resetprop::read_string_property("ro.bootimage.build.date.utc")?;
    let secs: i64 = raw.trim().parse().ok()?;
    if secs <= 0 {
        return None;
    }
    let (y, m, d) = civil_from_days(secs / 86400);
    Some(format!("{y:04}{m:02}{d:02}"))
}

/// Howard Hinnant 的 `days_from_civil` 逆运算：epoch 天数 → (年, 月, 日)。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn resolve_patch_levels_from(
    trust: &RawTrustConfig,
    security_property: Option<&str>,
    vendor_property: Option<&str>,
    boot_property: Option<&str>,
    observed_security_property: Option<&str>,
    latest: Option<&str>,
) -> Result<ResolvedPatchLevels> {
    let security_auto = security_property.unwrap_or(SECURITY_PATCH_FALLBACK);
    let security_patch =
        resolve_security_patch_value(&trust.security_patch, security_auto, latest)?;
    let os_patchlevel = resolve_patchlevel_mode(
        "os_patchlevel",
        &trust.os_patchlevel,
        &security_patch,
        latest,
    )?;
    let vendor_auto = vendor_property.unwrap_or(&os_patchlevel);
    let vendor_patchlevel = resolve_patchlevel_mode(
        "vendor_patchlevel",
        &trust.vendor_patchlevel,
        vendor_auto,
        latest,
    )?;
    let boot_auto = boot_property.unwrap_or(&os_patchlevel);
    let boot_patchlevel =
        resolve_patchlevel_mode("boot_patchlevel", &trust.boot_patchlevel, boot_auto, latest)?;
    let write_security_patch = observed_security_property.is_some()
        && trust.security_patch.trim() != "auto"
        && observed_security_property != Some(security_patch.as_str());

    Ok(ResolvedPatchLevels {
        security_patch,
        os_patchlevel,
        vendor_patchlevel,
        boot_patchlevel,
        observed_security_patch: observed_security_property.map(str::to_string),
        write_security_patch,
    })
}

fn resolve_security_patch_value(mode: &str, auto: &str, latest: Option<&str>) -> Result<String> {
    match mode.trim() {
        "auto" => Ok(auto.to_string()),
        "latest" => latest
            .map(str::to_string)
            .ok_or_else(|| anyhow!("latest value was not resolved for security_patch")),
        value if crate::config::is_security_patch_date(value) => Ok(value.to_string()),
        value => Err(anyhow!("invalid security_patch value: {value}")),
    }
}

fn resolve_patchlevel_mode(
    field: &str,
    mode: &str,
    auto: &str,
    latest: Option<&str>,
) -> Result<String> {
    match mode.trim() {
        "auto" => Ok(auto.to_string()),
        "latest" => latest
            .map(str::to_string)
            .ok_or_else(|| anyhow!("latest value was not resolved for {field}")),
        value if !value.is_empty() => Ok(value.to_string()),
        value => Err(anyhow!("invalid {field} value: {value}")),
    }
}

fn current_patchlevel() -> Result<String> {
    let (year, month) = current_year_month()?;
    Ok(format!("{year:04}-{month:02}-05"))
}

fn read_build_prop_value(key: &str) -> Option<String> {
    BUILD_PROP_PATHS.iter().find_map(|path| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|contents| parse_build_prop_value(&contents, key))
    })
}

fn parse_build_prop_value(contents: &str, key: &str) -> Option<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find_map(|line| {
            let (candidate_key, candidate_value) = line.split_once('=')?;
            (candidate_key.trim() == key).then(|| candidate_value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
}

fn write_security_patch_with_rollback<W, R>(
    mut writer: W,
    reader: R,
    desired: &str,
    previous: Option<&str>,
) -> Result<()>
where
    W: FnMut(&str, &str) -> Result<()>,
    R: Fn(&str) -> Option<String>,
{
    let previous = previous
        .ok_or_else(|| anyhow!("{SECURITY_PATCH_PROP} is missing; refusing to create it"))?;
    let current = reader(SECURITY_PATCH_PROP)
        .ok_or_else(|| anyhow!("{SECURITY_PATCH_PROP} disappeared; refusing to create it"))?;
    if current != previous {
        bail!(
            "{SECURITY_PATCH_PROP} changed while the update was prepared; refusing to overwrite it"
        );
    }

    let write_error = match writer(SECURITY_PATCH_PROP, desired) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    let actual = reader(SECURITY_PATCH_PROP);
    if actual.as_deref() == Some(desired) {
        log::warn!("security patch writer returned an error, but the desired value was verified");
        return Ok(());
    }
    if actual.as_deref() == Some(previous) {
        return Err(write_error).context("security patch write failed without changing property");
    }
    if actual.is_none() {
        return Err(write_error)
            .context("security patch write failed and property disappeared; rollback skipped");
    }

    let rollback_error = writer(SECURITY_PATCH_PROP, previous).err();
    let actual = reader(SECURITY_PATCH_PROP);
    if actual.as_deref() == Some(previous) {
        return Err(write_error).context("security patch write failed; previous state restored");
    }
    if actual.as_deref() == Some(desired) {
        log::warn!(
            "security patch rollback could not be confirmed, but the desired value was verified"
        );
        return Ok(());
    }
    Err(anyhow!(
        "security patch write failed: {write_error:#}; rollback failed: {}; current property state: {}",
        rollback_error
            .map(|error| format!("{error:#}"))
            .unwrap_or_else(|| "property verification did not restore the previous state".into()),
        actual.as_deref().unwrap_or("<missing>")
    ))
}

fn current_year_month() -> Result<(i32, u32)> {
    #[cfg(unix)]
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        if now < 0 {
            bail!("libc::time returned a negative timestamp");
        }
        let mut local = std::mem::zeroed::<libc::tm>();
        if libc::localtime_r(&now, &mut local).is_null() {
            bail!("libc::localtime_r failed");
        }
        Ok((local.tm_year + 1900, (local.tm_mon + 1) as u32))
    }

    #[cfg(not(unix))]
    {
        Err(anyhow!(
            "current_year_month is unsupported on this platform"
        ))
    }
}

fn read_hex_property(name: &str) -> Option<[u8; 32]> {
    let value = resetprop::read_string_property(name)?;
    parse_hex_32(&value)
        .map_err(|error| {
            log::warn!("ignoring invalid property {name}={value}: {error:#}");
        })
        .ok()
}

fn parse_hex_32(value: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(value).with_context(|| format!("invalid hex value {value}"))?;
    decoded
        .try_into()
        .map_err(|decoded: Vec<u8>| anyhow!("hex value must be 32 bytes, got {}", decoded.len()))
}

/// 比较用的线值：`2026-08-01` 与 `20260801` 视为同一个补丁日期。
fn boot_patchlevel_wire(value: &str) -> Option<u32> {
    crate::keymaster::keymint_device::extract_boot_patchlevel(value).ok()
}

/// boot 分区里的补丁日期（`YYYY-MM-DD`）。开机归一时用它对齐三个属性，
/// 免得每次出链都要去翻分区。
pub fn boot_image_patchlevel_date() -> Result<String> {
    let raw = read_abl_boot_patchlevel()?;
    let value = crate::keymaster::keymint_device::extract_boot_patchlevel(&raw)
        .map_err(anyhow::Error::msg)?;
    Ok(format!(
        "{:04}-{:02}-{:02}",
        value / 10000,
        (value / 100) % 100,
        value % 100
    ))
}

/// 顶层 vbmeta 的公钥摘要（SHA256(public key)），就是链上的 `verifiedBootKey`。
///
/// bootloader 只在 bootconfig 里给 `androidboot.vbmeta.digest`（对应 verifiedBootHash），
/// 不给公钥摘要；原生 HAL 自己读分区算。以前我们拿 boot hash 派生一个、后来变成全零，
/// 两个都不是真值，检测器一看就知道。这里按 AVB 规范算真的。
pub fn boot_image_public_key_digest() -> Result<String> {
    let slot_suffix = resetprop::read_string_property("ro.boot.slot_suffix").unwrap_or_default();
    let top_level = load_vbmeta_blob(&find_top_level_vbmeta_path(&slot_suffix)?)?;
    let key = avb_public_key(&top_level)?;
    Ok(hex::encode(
        ring::digest::digest(&ring::digest::SHA256, key).as_ref(),
    ))
}

/// 在 vbmeta 里找 AVB 公钥结构：`num_bits(u32=2048) + n0inv(u32) + modulus(256) + rr(256)`。
///
/// 不定死偏移：这台 ROM 的 offset 字段跟 AOSP 的基准不一致（hash_offset 是 0、公钥偏移
/// 相对 aux block），按规矩解析会指错地方；直接按结构扫反而稳，同一把 key 扫到的几处
/// 摘要都一样。
fn avb_public_key(vbmeta: &[u8]) -> Result<&[u8]> {
    const KEY_LEN: usize = 520;
    // 先走 O(1)：按 header 里的偏移取候选，两种基准都试（AOSP 是相对文件头，
    // 本机这 ROM 实测是相对 aux block）。取到先验证结构像公钥，不像才退化成扫描。
    if vbmeta.len() >= AVB_HEADER_SIZE && &vbmeta[..4] == b"AVB0" {
        if let (Ok(pub_off), Ok(pub_sz), Ok(auth_sz)) = (
            be_u64(&vbmeta[64..72]),
            be_u64(&vbmeta[72..80]),
            be_u64(&vbmeta[12..20]),
        ) {
            if pub_sz == KEY_LEN {
                for start in [pub_off, AVB_HEADER_SIZE + auth_sz + pub_off] {
                    if let Some(candidate) = vbmeta.get(start..start + KEY_LEN) {
                        if looks_like_avb_public_key(candidate) {
                            return Ok(candidate);
                        }
                    }
                }
            }
        }
    }
    // 兜底：按结构扫。不定死偏移是因为各 ROM 的 offset 基准不一定一样，
    // 扫一遍最多 64KB/4 = 16K 次比较，只在上面全部失败时才走。
    if vbmeta.len() < KEY_LEN {
        bail!("vbmeta is too small to hold a public key");
    }
    for start in (0..=vbmeta.len() - KEY_LEN).step_by(4) {
        let candidate = &vbmeta[start..start + KEY_LEN];
        if looks_like_avb_public_key(candidate) {
            return Ok(candidate);
        }
    }
    bail!("no AVB public key found in vbmeta")
}

/// AVB 公钥结构：`num_bits(u32=2048) + n0inv(u32) + modulus(256) + rr(256)`。
fn looks_like_avb_public_key(candidate: &[u8]) -> bool {
    const RSA_2048_BITS: [u8; 4] = [0x00, 0x00, 0x08, 0x00];
    candidate.len() >= 8
        && candidate[..4] == RSA_2048_BITS
        && candidate[4..8].iter().any(|b| *b != 0)
}

/// bootloader 实际算出来的 vbmeta 摘要（`androidboot.vbmeta.digest`）。
///
/// `ro.boot.vbmeta.digest` 只是 init 从 bootconfig 拄过来的一份，抄完谁都能 resetprop；
/// 一旦抄坏，链和属性就会互相喂着错下去。bootconfig 本身是 bootloader 写的、只读的，
/// 拿它当最后的真值。
pub fn bootloader_vbmeta_digest() -> Option<String> {
    for path in ["/proc/bootconfig", "/proc/cmdline"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some(value) = find_bootloader_digest(&text) {
            return Some(value);
        }
    }
    None
}

fn find_bootloader_digest(text: &str) -> Option<String> {
    for line in text.lines() {
        // bootconfig 是 `key = "value"`，cmdline 是 `key=value`。
        let Some(rest) = line.trim().strip_prefix("androidboot.vbmeta.digest") else {
            continue;
        };
        let value = rest
            .trim_start_matches(|c: char| c == '=' || c.is_whitespace())
            .trim_matches('"')
            .trim();
        if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(value.to_ascii_lowercase());
        }
    }
    None
}

/// 归一后的 boot 补丁值落盘位置（daemon 写、keymint 读）。
///
/// 为什么不直接让 keymint 读 props.conf：keystore 域读不了 `/data/adb`；而这个文件
/// 就在 `/data/misc/ommega` 里，是 TA 自己的目录。伪装和真值的优先级只在 daemon 里
/// 判一次，落进这个文件，出链就只认它 —— 不会出现「属性伪装了、链上却是真值」。
const PATCH_STATE_PATH: &str = "/data/misc/ommega/patch.state";

/// 读 daemon 算好的 boot 补丁值。
fn read_boot_patchlevel_state() -> Option<String> {
    let text = std::fs::read_to_string(PATCH_STATE_PATH).ok()?;
    text.lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "boot_patchlevel").then(|| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
}

fn read_abl_boot_patchlevel() -> Result<String> {
    let slot_suffix = resetprop::read_string_property("ro.boot.slot_suffix").unwrap_or_default();
    let boot_path = find_avb_partition_path(&slot_suffix, "boot")
        .context("failed to locate active boot partition")?;
    read_abl_boot_patchlevel_from_paths(find_top_level_vbmeta_path(&slot_suffix), &boot_path)
        .map(|value| value.to_string())
}

fn read_abl_boot_patchlevel_from_paths(
    top_level_path: Result<PathBuf>,
    boot_path: &Path,
) -> Result<u32> {
    let top_level_error = match top_level_path {
        Ok(path) => {
            let top_level = load_vbmeta_blob(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            if let Some(value) = vbmeta_boot_patchlevel(&top_level)? {
                return Ok(value);
            }
            None
        }
        Err(error) => {
            log::debug!("failed to locate top-level vbmeta; checking boot image: {error:#}");
            Some(error)
        }
    };

    match load_embedded_vbmeta_blob(boot_path) {
        Ok(embedded) => {
            if let Some(value) = vbmeta_boot_patchlevel(&embedded)? {
                return Ok(value);
            }
        }
        Err(error) => {
            if let Some(top_level_error) = top_level_error {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read top-level vbmeta from {} after {top_level_error:#}",
                        boot_path.display()
                    )
                });
            }
            log::debug!(
                "failed to read embedded boot vbmeta from {}; using boot header: {error:#}",
                boot_path.display()
            );
        }
    }
    read_boot_header_patchlevel(boot_path)
}

fn vbmeta_boot_patchlevel(vbmeta: &[u8]) -> Result<Option<u32>> {
    if let Some(value) = avb_property_value(vbmeta, BOOT_AVB_PROPERTY)? {
        return parse_boot_patchlevel_property(value)
            .map(Some)
            .ok_or_else(|| anyhow!("invalid com.android.build.boot.security_patch AVB property"));
    }
    Ok(None)
}

fn avb_property_value<'a>(vbmeta: &'a [u8], key: &[u8]) -> Result<Option<&'a [u8]>> {
    let mut descriptors = avb_descriptors(vbmeta)?;
    while !descriptors.is_empty() {
        let descriptor = take_avb_descriptor(&mut descriptors)?;
        if be_u64(&descriptor[..8])? as u64 != AVB_PROPERTY_TAG
            || descriptor.len() < AVB_PROPERTY_DESCRIPTOR_SIZE
        {
            continue;
        }

        let key_len = be_u64(&descriptor[16..24])?;
        let value_len = be_u64(&descriptor[24..32])?;
        let Some(key_end) = AVB_PROPERTY_DESCRIPTOR_SIZE.checked_add(key_len) else {
            continue;
        };
        let Some(value_start) = key_end.checked_add(1) else {
            continue;
        };
        let Some(value_end) = value_start.checked_add(value_len) else {
            continue;
        };
        let Some(value_nul) = value_end.checked_add(1) else {
            continue;
        };
        if value_nul > descriptor.len()
            || descriptor.get(key_end) != Some(&0)
            || descriptor.get(value_end) != Some(&0)
        {
            continue;
        }
        if descriptor.get(AVB_PROPERTY_DESCRIPTOR_SIZE..key_end) == Some(key) {
            return Ok(descriptor.get(value_start..value_end));
        }
    }
    Ok(None)
}

fn avb_descriptors(vbmeta: &[u8]) -> Result<&[u8]> {
    let total_size = validated_vbmeta_size(vbmeta)?;
    if total_size > vbmeta.len() {
        bail!("vbmeta block sizes exceed the available data");
    }

    let auth_block_size = be_u64(&vbmeta[12..20])?;
    let aux_block_size = be_u64(&vbmeta[20..28])?;
    let descriptors_offset = be_u64(&vbmeta[96..104])?;
    let descriptors_size = be_u64(&vbmeta[104..112])?;
    let aux_start = AVB_HEADER_SIZE
        .checked_add(auth_block_size)
        .ok_or_else(|| anyhow!("vbmeta auxiliary block start overflow"))?;
    let aux_end = aux_start
        .checked_add(aux_block_size)
        .ok_or_else(|| anyhow!("vbmeta auxiliary block end overflow"))?;
    let descriptors_start = aux_start
        .checked_add(descriptors_offset)
        .ok_or_else(|| anyhow!("vbmeta descriptor start overflow"))?;
    let descriptors_end = descriptors_start
        .checked_add(descriptors_size)
        .ok_or_else(|| anyhow!("vbmeta descriptor end overflow"))?;
    if aux_end > total_size || descriptors_end > aux_end {
        bail!("vbmeta descriptor range is outside the auxiliary block");
    }
    Ok(&vbmeta[descriptors_start..descriptors_end])
}

fn take_avb_descriptor<'a>(descriptors: &mut &'a [u8]) -> Result<&'a [u8]> {
    if descriptors.len() < AVB_DESCRIPTOR_SIZE {
        bail!("truncated AVB descriptor header");
    }
    let bytes_following = be_u64(&descriptors[8..16])?;
    if bytes_following & 7 != 0 {
        bail!("AVB descriptor size is not divisible by 8");
    }
    let total_size = AVB_DESCRIPTOR_SIZE
        .checked_add(bytes_following)
        .ok_or_else(|| anyhow!("AVB descriptor size overflow"))?;
    if total_size > descriptors.len() {
        bail!("AVB descriptor exceeds the descriptor block");
    }
    let (descriptor, remaining) = descriptors.split_at(total_size);
    *descriptors = remaining;
    Ok(descriptor)
}

fn parse_boot_patchlevel_property(value: &[u8]) -> Option<u32> {
    crate::keymaster::keymint_device::extract_patchlevel(std::str::from_utf8(value).ok()?).ok()
}

fn read_boot_header_patchlevel(path: &Path) -> Result<u32> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open boot image {}", path.display()))?;
    let mut header = [0u8; BOOT_HEADER_PREFIX_SIZE];
    file.read_exact(&mut header)
        .with_context(|| format!("failed to read boot image header from {}", path.display()))?;
    boot_header_patchlevel(&header)
}

fn boot_header_patchlevel(header: &[u8]) -> Result<u32> {
    if header.len() < BOOT_HEADER_PREFIX_SIZE || &header[..8] != b"ANDROID!" {
        bail!("invalid boot image header");
    }

    let header_version =
        le_u32(&header[BOOT_HEADER_VERSION_OFFSET..BOOT_HEADER_VERSION_OFFSET + 4])?;
    let os_version_offset = if header_version >= 3 {
        if header_version > 4 {
            bail!("unsupported boot image header version {header_version}");
        }
        BOOT_HEADER_V3_OS_VERSION_OFFSET
    } else {
        BOOT_HEADER_LEGACY_OS_VERSION_OFFSET
    };
    let os_version = le_u32(&header[os_version_offset..os_version_offset + 4])?;
    let year = 2000 + ((os_version >> 4) & 0x7f);
    let month = os_version & 0xf;
    Ok(year * 10_000 + month * 100)
}

fn validated_vbmeta_size(header: &[u8]) -> Result<usize> {
    if header.len() < AVB_HEADER_SIZE || &header[..4] != b"AVB0" {
        bail!("invalid vbmeta header");
    }
    let required_major = be_u32(&header[4..8])?;
    let required_minor = be_u32(&header[8..12])?;
    if required_major != AVB_VERSION_MAJOR || required_minor > AVB_VERSION_MINOR {
        bail!("unsupported required libavb version {required_major}.{required_minor}");
    }
    if header[175] != 0 {
        bail!("vbmeta release string is not NUL-terminated");
    }

    let auth_block_size = be_u64(&header[12..20])?;
    let aux_block_size = be_u64(&header[20..28])?;
    if auth_block_size & 63 != 0 || aux_block_size & 63 != 0 {
        bail!("vbmeta inner block size is not divisible by 64");
    }
    let total_size = AVB_HEADER_SIZE
        .checked_add(auth_block_size)
        .and_then(|value| value.checked_add(aux_block_size))
        .ok_or_else(|| anyhow!("vbmeta size overflow"))?;
    if total_size > AVB_MAX_VBMETA_SIZE {
        bail!("vbmeta image exceeds the 64 KiB libavb limit");
    }
    Ok(total_size)
}

fn find_top_level_vbmeta_path(slot_suffix: &str) -> Result<PathBuf> {
    find_avb_partition_path(slot_suffix, "vbmeta")
}

fn find_avb_partition_path(slot_suffix: &str, partition_name: &str) -> Result<PathBuf> {
    let mut names = Vec::with_capacity(2);
    if !slot_suffix.is_empty() {
        names.push(format!("{partition_name}{slot_suffix}"));
    }
    names.push(partition_name.to_string());

    for candidate in names.into_iter().flat_map(|name| {
        [
            PathBuf::from(format!("/dev/block/by-name/{name}")),
            PathBuf::from(format!("/dev/block/bootdevice/by-name/{name}")),
        ]
    }) {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(anyhow!(
        "no {partition_name} partition found for slot suffix '{slot_suffix}'"
    ))
}

fn load_vbmeta_blob(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open vbmeta image {}", path.display()))?;
    load_vbmeta_blob_at(&mut file, 0, None)
        .with_context(|| format!("failed to load vbmeta image {}", path.display()))
}

fn load_embedded_vbmeta_blob(path: &Path) -> Result<Vec<u8>> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open partition {}", path.display()))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .with_context(|| format!("failed to read partition magic from {}", path.display()))?;
    if &magic == b"AVB0" {
        return load_vbmeta_blob_at(&mut file, 0, None)
            .with_context(|| format!("failed to load standalone vbmeta from {}", path.display()));
    }

    let partition_size = file
        .seek(SeekFrom::End(0))
        .with_context(|| format!("failed to determine partition size for {}", path.display()))?;
    let footer_offset = partition_size
        .checked_sub(AVB_FOOTER_SIZE as u64)
        .ok_or_else(|| anyhow!("partition is smaller than an AVB footer"))?;
    file.seek(SeekFrom::Start(footer_offset))
        .context("failed to seek to AVB footer")?;
    let mut footer = [0u8; AVB_FOOTER_SIZE];
    file.read_exact(&mut footer)
        .context("failed to read AVB footer")?;
    if &footer[..4] != b"AVBf" {
        bail!("partition has neither AVB0 header nor AVBf footer");
    }
    if be_u32(&footer[4..8])? > 1 {
        bail!("unsupported AVB footer major version");
    }

    let vbmeta_offset = be_u64(&footer[20..28])?;
    let vbmeta_size = be_u64(&footer[28..36])?;
    if vbmeta_size < AVB_HEADER_SIZE {
        bail!("AVB footer declares a vbmeta block smaller than its header");
    }
    if vbmeta_size > AVB_MAX_VBMETA_SIZE {
        bail!("AVB footer vbmeta block exceeds the 64 KiB libavb limit");
    }
    let vbmeta_offset_u64 = u64::try_from(vbmeta_offset).context("vbmeta offset is too large")?;
    let vbmeta_size_u64 = u64::try_from(vbmeta_size).context("vbmeta size is too large")?;
    let vbmeta_end = vbmeta_offset_u64
        .checked_add(vbmeta_size_u64)
        .ok_or_else(|| anyhow!("embedded vbmeta range overflow"))?;
    if vbmeta_end > partition_size {
        bail!("embedded vbmeta range exceeds the partition");
    }
    load_vbmeta_blob_at(&mut file, vbmeta_offset_u64, Some(vbmeta_size))
        .with_context(|| format!("failed to load embedded vbmeta from {}", path.display()))
}

fn load_vbmeta_blob_at(
    file: &mut File,
    offset: u64,
    maximum_size: Option<usize>,
) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .context("failed to seek to vbmeta header")?;
    let mut header = [0u8; AVB_HEADER_SIZE];
    file.read_exact(&mut header)
        .context("failed to read vbmeta header")?;

    let total_size = validated_vbmeta_size(&header)?;
    if let Some(maximum_size) = maximum_size {
        if total_size > maximum_size {
            bail!("vbmeta header exceeds its containing block");
        }
    }

    let mut blob = vec![0u8; total_size];
    blob[..AVB_HEADER_SIZE].copy_from_slice(&header);
    file.read_exact(&mut blob[AVB_HEADER_SIZE..])
        .with_context(|| {
            format!(
                "failed to read {} bytes of vbmeta data",
                total_size - AVB_HEADER_SIZE
            )
        })?;
    Ok(blob)
}

fn be_u64(bytes: &[u8]) -> Result<usize> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| anyhow!("expected 8 bytes, got {}", bytes.len()))?;
    usize::try_from(u64::from_be_bytes(array)).context("value does not fit in usize")
}

fn be_u32(bytes: &[u8]) -> Result<u32> {
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| anyhow!("expected 4 bytes, got {}", bytes.len()))?;
    Ok(u32::from_be_bytes(array))
}

fn le_u32(bytes: &[u8]) -> Result<u32> {
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| anyhow!("expected 4 bytes, got {}", bytes.len()))?;
    Ok(u32::from_le_bytes(array))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_image_epoch_turns_into_a_patchlevel_date() {
        // 1787129795 = 2026-08-19T00:56:35Z
        assert_eq!(civil_from_days(1_787_129_795 / 86400), (2026, 8, 19));
        // 1770000000 = 2026-02-02
        assert_eq!(civil_from_days(1_770_000_000 / 86400), (2026, 2, 2));
        // 0 = 1970-01-01
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn boot_patchlevel_uses_vbmeta_property_then_header() {
        let direct = build_test_vbmeta_with_descriptors(
            0,
            &build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2026-02-01"),
        );
        assert_eq!(vbmeta_boot_patchlevel(&direct).unwrap(), Some(20260201));

        let mut duplicate = build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2026-13-01");
        duplicate.extend(build_test_property_descriptor(
            BOOT_AVB_PROPERTY,
            b"2026-02-01",
        ));
        let first_invalid = build_test_vbmeta_with_descriptors(0, &duplicate);
        assert!(vbmeta_boot_patchlevel(&first_invalid).is_err());

        let no_property = build_test_vbmeta_with_descriptors(0, &[]);
        assert_eq!(vbmeta_boot_patchlevel(&no_property).unwrap(), None);
    }

    #[test]
    fn boot_patchlevel_uses_embedded_vbmeta_before_header() {
        let dir = tempfile::tempdir().unwrap();
        let top_level_path = dir.path().join("vbmeta");
        let boot_path = dir.path().join("boot");
        std::fs::write(&top_level_path, build_test_vbmeta_with_descriptors(0, &[])).unwrap();

        let embedded = build_test_vbmeta_with_descriptors(
            0,
            &build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2026-02-01"),
        );
        std::fs::write(&boot_path, build_test_boot_image(Some(&embedded))).unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path.clone()), &boot_path).unwrap(),
            20260201
        );

        let mut zero_header = build_test_boot_image(Some(&embedded));
        zero_header[BOOT_HEADER_V3_OS_VERSION_OFFSET..BOOT_HEADER_V3_OS_VERSION_OFFSET + 4].fill(0);
        std::fs::write(&boot_path, zero_header).unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path.clone()), &boot_path).unwrap(),
            20260201
        );
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(
                Err(anyhow!("missing top-level vbmeta")),
                &boot_path,
            )
            .unwrap(),
            20260201
        );

        let embedded_without_property = build_test_vbmeta_with_descriptors(0, &[]);
        std::fs::write(
            &boot_path,
            build_test_boot_image(Some(&embedded_without_property)),
        )
        .unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path.clone()), &boot_path).unwrap(),
            20250900
        );

        std::fs::write(&boot_path, build_test_boot_image(None)).unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path.clone()), &boot_path).unwrap(),
            20250900
        );

        std::fs::write(
            &top_level_path,
            build_test_vbmeta_with_descriptors(
                0,
                &build_test_property_descriptor(BOOT_AVB_PROPERTY, b"2027-01-01"),
            ),
        )
        .unwrap();
        let mut zero_header = build_test_boot_image(Some(&embedded));
        zero_header[BOOT_HEADER_V3_OS_VERSION_OFFSET..BOOT_HEADER_V3_OS_VERSION_OFFSET + 4].fill(0);
        std::fs::write(&boot_path, zero_header).unwrap();
        assert_eq!(
            read_abl_boot_patchlevel_from_paths(Ok(top_level_path), &boot_path).unwrap(),
            20270101
        );
    }

    #[test]
    fn boot_header_patchlevel_decodes_legacy_and_modern_headers() {
        for (header_version, offset) in [
            (0u32, BOOT_HEADER_LEGACY_OS_VERSION_OFFSET),
            (4u32, BOOT_HEADER_V3_OS_VERSION_OFFSET),
        ] {
            let mut header = [0u8; BOOT_HEADER_PREFIX_SIZE];
            header[..8].copy_from_slice(b"ANDROID!");
            header[BOOT_HEADER_VERSION_OFFSET..BOOT_HEADER_VERSION_OFFSET + 4]
                .copy_from_slice(&header_version.to_le_bytes());
            let os_version = (25u32 << 4) | 9;
            header[offset..offset + 4].copy_from_slice(&os_version.to_le_bytes());
            assert_eq!(boot_header_patchlevel(&header).unwrap(), 20250900);

            header[offset..offset + 4].fill(0);
            assert_eq!(boot_header_patchlevel(&header).unwrap(), 20000000);
        }
    }

    #[test]
    fn boot_patchlevel_property_uses_aosp_date_parser() {
        for (value, expected) in [
            (b"2025-09-05".as_slice(), Some(20250905)),
            (b"2025-9-5".as_slice(), None),
            (b"  +2025-02-31".as_slice(), None),
            (b"2025-13-01".as_slice(), None),
            (b"2025-12-01x".as_slice(), None),
        ] {
            assert_eq!(parse_boot_patchlevel_property(value), expected, "{value:?}");
        }

        let mut oversized = vec![0u8; AVB_HEADER_SIZE];
        oversized[..4].copy_from_slice(b"AVB0");
        oversized[4..8].copy_from_slice(&AVB_VERSION_MAJOR.to_be_bytes());
        oversized[20..28].copy_from_slice(&(AVB_MAX_VBMETA_SIZE as u64).to_be_bytes());
        assert!(validated_vbmeta_size(&oversized).is_err());

        let mut avb_1_4 = vec![0u8; AVB_HEADER_SIZE];
        avb_1_4[..4].copy_from_slice(b"AVB0");
        avb_1_4[4..8].copy_from_slice(&AVB_VERSION_MAJOR.to_be_bytes());
        avb_1_4[8..12].copy_from_slice(&AVB_VERSION_MINOR.to_be_bytes());
        assert_eq!(validated_vbmeta_size(&avb_1_4).unwrap(), AVB_HEADER_SIZE);
    }

    #[test]
    fn patchlevel_auto_uses_each_aosp_property() {
        let resolved = resolve_patch_levels_from(
            &RawTrustConfig::default(),
            Some("2025-12-01"),
            Some("2025-11-05"),
            Some("2025-10-05"),
            Some("2025-12-01"),
            None,
        )
        .unwrap();
        assert_eq!(resolved.security_patch, "2025-12-01");
        assert_eq!(resolved.os_patchlevel, "2025-12-01");
        assert_eq!(resolved.vendor_patchlevel, "2025-11-05");
        assert_eq!(resolved.boot_patchlevel, "2025-10-05");
        assert!(!resolved.write_security_patch);
    }

    #[test]
    fn patchlevel_sources_are_not_date_filtered_before_wire_conversion() {
        let resolved = resolve_patch_levels_from(
            &RawTrustConfig::default(),
            Some("raw-security"),
            Some("raw-vendor"),
            Some("raw-boot"),
            Some("raw-security"),
            None,
        )
        .unwrap();
        assert_eq!(resolved.security_patch, "raw-security");
        assert_eq!(resolved.os_patchlevel, "raw-security");
        assert_eq!(resolved.vendor_patchlevel, "raw-vendor");
        assert_eq!(resolved.boot_patchlevel, "raw-boot");
    }

    #[test]
    fn patchlevel_fallbacks_and_overrides_are_independent() {
        let trust = RawTrustConfig {
            security_patch: "2026-04-05".to_string(),
            os_patchlevel: "2026-03-05".to_string(),
            vendor_patchlevel: "auto".to_string(),
            boot_patchlevel: "latest".to_string(),
            ..Default::default()
        };
        let resolved = resolve_patch_levels_from(
            &trust,
            Some("2025-12-01"),
            None,
            None,
            Some("2025-12-01"),
            Some("2026-07-05"),
        )
        .unwrap();
        assert_eq!(resolved.security_patch, "2026-04-05");
        assert_eq!(resolved.os_patchlevel, "2026-03-05");
        assert_eq!(resolved.vendor_patchlevel, "2026-03-05");
        assert_eq!(resolved.boot_patchlevel, "2026-07-05");
        assert_eq!(
            resolved.observed_security_patch.as_deref(),
            Some("2025-12-01")
        );
        assert!(resolved.write_security_patch);
    }

    #[test]
    fn build_prop_security_value_is_not_treated_as_a_runtime_property() {
        let trust = RawTrustConfig {
            security_patch: "2026-04-05".to_string(),
            ..Default::default()
        };
        let resolved =
            resolve_patch_levels_from(&trust, Some("2025-12-01"), None, None, None, None).unwrap();
        assert_eq!(resolved.security_patch, "2026-04-05");
        assert!(resolved.observed_security_patch.is_none());
        assert!(!resolved.write_security_patch);
    }

    #[test]
    fn build_prop_parser_uses_an_exact_nonempty_key() {
        let contents = r#"
# comment
ro.vendor.boot_security_patch = 2025-10-05
ro.vendor.boot_security_patch.extra = ignored
"#;
        assert_eq!(
            parse_build_prop_value(contents, BOOT_PATCH_PROP).as_deref(),
            Some("2025-10-05")
        );
    }

    #[test]
    fn security_patch_write_accepts_a_verified_lost_ack() {
        let state = std::cell::RefCell::new(Some("2025-12-01".to_string()));
        let result = write_security_patch_with_rollback(
            |_, desired| {
                *state.borrow_mut() = Some(desired.to_string());
                Err(anyhow!("lost acknowledgment"))
            },
            |_| state.borrow().clone(),
            "2026-07-05",
            Some("2025-12-01"),
        );
        assert!(result.is_ok());
        assert_eq!(state.borrow().as_deref(), Some("2026-07-05"));
    }

    #[test]
    fn security_patch_write_refuses_to_create_a_missing_property() {
        let writes = std::cell::Cell::new(0);
        let result = write_security_patch_with_rollback(
            |_, _| {
                writes.set(writes.get() + 1);
                Ok(())
            },
            |_| None,
            "2026-07-05",
            Some("2025-12-01"),
        );
        assert!(result.is_err());
        assert_eq!(writes.get(), 0);
    }

    fn build_test_vbmeta_with_descriptors(flags: u32, descriptors: &[u8]) -> Vec<u8> {
        let aux_block_size = (descriptors.len() + 63) & !63;
        let mut blob = vec![0u8; AVB_HEADER_SIZE + aux_block_size];
        blob[..4].copy_from_slice(b"AVB0");
        blob[4..8].copy_from_slice(&AVB_VERSION_MAJOR.to_be_bytes());
        blob[20..28].copy_from_slice(&(aux_block_size as u64).to_be_bytes());
        blob[104..112].copy_from_slice(&(descriptors.len() as u64).to_be_bytes());
        blob[120..124].copy_from_slice(&flags.to_be_bytes());
        blob[AVB_HEADER_SIZE..AVB_HEADER_SIZE + descriptors.len()].copy_from_slice(descriptors);
        blob
    }

    fn build_test_property_descriptor(key: &[u8], value: &[u8]) -> Vec<u8> {
        let unpadded_size = AVB_PROPERTY_DESCRIPTOR_SIZE + key.len() + 1 + value.len() + 1;
        let total_size = (unpadded_size + 7) & !7;
        let mut descriptor = vec![0u8; total_size];
        descriptor[..8].copy_from_slice(&AVB_PROPERTY_TAG.to_be_bytes());
        descriptor[8..16]
            .copy_from_slice(&((total_size - AVB_DESCRIPTOR_SIZE) as u64).to_be_bytes());
        descriptor[16..24].copy_from_slice(&(key.len() as u64).to_be_bytes());
        descriptor[24..32].copy_from_slice(&(value.len() as u64).to_be_bytes());
        descriptor[32..32 + key.len()].copy_from_slice(key);
        let value_start = 32 + key.len() + 1;
        descriptor[value_start..value_start + value.len()].copy_from_slice(value);
        descriptor
    }

    fn build_test_boot_image(embedded_vbmeta: Option<&[u8]>) -> Vec<u8> {
        let mut image = vec![0u8; BOOT_HEADER_PREFIX_SIZE];
        image[..8].copy_from_slice(b"ANDROID!");
        image[BOOT_HEADER_VERSION_OFFSET..BOOT_HEADER_VERSION_OFFSET + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        image[BOOT_HEADER_V3_OS_VERSION_OFFSET..BOOT_HEADER_V3_OS_VERSION_OFFSET + 4]
            .copy_from_slice(&((25u32 << 4) | 9).to_le_bytes());

        if let Some(vbmeta) = embedded_vbmeta {
            let vbmeta_offset = image.len();
            image.extend_from_slice(vbmeta);
            let mut footer = [0u8; AVB_FOOTER_SIZE];
            footer[..4].copy_from_slice(b"AVBf");
            footer[4..8].copy_from_slice(&1u32.to_be_bytes());
            footer[20..28].copy_from_slice(&(vbmeta_offset as u64).to_be_bytes());
            footer[28..36].copy_from_slice(&(vbmeta.len() as u64).to_be_bytes());
            image.extend_from_slice(&footer);
        }
        image
    }
}
