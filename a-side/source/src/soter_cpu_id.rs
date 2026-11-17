//! 把 A 端本地兜底要报的 cpu_id 摆到 payload 读得到的地方，并让转发请求带上它。
//!
//! 兜底那条路的密钥是我们自己的（本地自签的 ASK/AuthKey），身份也必须用本机自己的号；
//! 借真机（B）的号会让判证器按值对比出不一致。号只从真实属性派生
//! （`ro.boot.serialno` / `ro.serialno`），读不到序列号就不报号、也不编一个 —— 转发
//! 干脆不带 `cpu_id`，由服务端按当时的年月日时分现造。
//!
//! 落盘给 SOTER 宿主（uid 1000）读。算法与 payload 里的 `soter_local::cpu_id_from` 一致。

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;

/// 主循环节拍。
const TICK: Duration = Duration::from_secs(60);

/// 派生用的前缀，跟 payload 那份一字不差。
const SEED: &str = "ommega-a-side-soter:";

/// MTK（Kinibi）的号头。
const MTK_PREFIX: &str = "09000000";
/// 高通（QSEE）的号头。
const QCOM_PREFIX: &str = "00000000";

static DERIVED: Mutex<Option<String>> = Mutex::new(None);
static STARTED: OnceLock<()> = OnceLock::new();

/// 起派生线程（幂等）。只读属性 + 写一个小文件，不发请求。
pub fn start() {
    if STARTED.set(()).is_err() {
        return;
    }
    ensure_last_auth_file();
    std::thread::spawn(|| loop {
        // 已有号（服务端学过或人工写的）不能被本地序列号算出的值覆盖：SOTER 身份必须
        // 是 B 端 TEE 那个号，两边不一致判证方就会判「设备换了」。只有什么都没有时才
        // 现算一个兜底。
        if let Some((value, source)) = read_mirror() {
            store(value, &source);
        } else {
            match derive() {
                Some(value) => {
                    if let Err(error) = write_mirror(&value) {
                        log::warn!(
                            "soter cpu_id could not be written to {}: {error:#}",
                            kmr_common::soter_relay::CPU_ID_WRITE_PATH
                        );
                    }
                    store(value, "derived");
                }
                // 读不到真实序列号：把之前那份也撤了，转发不带 cpu_id，让服务端按时间造。
                None => forget(),
            }
        }
        std::thread::sleep(TICK);
    });
}

/// 认证时间戳落点：root 侧预建成 0666。keystore 域只在拿到 HAT 时写它、system 域的
/// SOTER 宿主读它，两边都没权限建文件、只能写/读现成的这一个。
fn ensure_last_auth_file() {
    use std::os::unix::fs::PermissionsExt;
    let path = kmr_common::soter_relay::LAST_AUTH_PATH;
    if !std::path::Path::new(path).exists() {
        let _ = std::fs::write(path, "last_auth: 0\n");
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
}

/// 没有真实属性可报时：清掉缓存并删掉写下的副本，留着它等于继续报一个不成立的身份。
fn forget() {
    let had_value = DERIVED
        .lock()
        .map(|mut guard| guard.take().is_some())
        .unwrap_or(false);
    let path = kmr_common::soter_relay::CPU_ID_WRITE_PATH;
    let removed = std::fs::remove_file(path).is_ok();
    if had_value || removed {
        log::warn!(
            "soter cpu_id has no real source (no serialno); reporting none and dropping {path}"
        );
    }
}

/// 当前该报给服务端的 cpu_id；没有真实来源返回 `None`。
/// 顺序：内存 → 副本文件 → 现派生。
pub fn current() -> Option<String> {
    if let Some(value) = cached() {
        return Some(value);
    }
    if let Some((value, source)) = read_mirror() {
        store(value.clone(), &source);
        return Some(value);
    }
    let value = derive()?;
    store(value.clone(), "derived");
    Some(value)
}

fn cached() -> Option<String> {
    DERIVED.lock().ok()?.clone()
}

fn store(value: String, source: &str) {
    if let Ok(mut guard) = DERIVED.lock() {
        let changed = guard.as_deref() != Some(value.as_str());
        if changed {
            log::info!("soter local cpu_id -> {value} ({source})");
        }
        *guard = Some(value);
    }
}

/// 读一份之前写下的副本（daemon 刚起来、内存还空的时候用）。
fn read_mirror() -> Option<(String, String)> {
    read_mirror_from(&kmr_common::soter_relay::CPU_ID_PATHS)
}

fn read_mirror_from(paths: &[&str]) -> Option<(String, String)> {
    for path in paths {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if let Some(value) = kmr_common::soter_relay::parse_cpu_id(&text) {
            return Some((value, format!("file {path}")));
        }
        log::warn!("soter cpu_id at {path} has no usable value; ignoring it");
    }
    None
}

/// 现算一个：序列号从系统属性读（root 读得到）。读不到就没有号，不编。
fn derive() -> Option<String> {
    id_for_serial(serial().as_deref())
}

/// `serial()` 的结果到该报的号：没有序列号就没有号。
fn id_for_serial(serial: Option<&str>) -> Option<String> {
    serial.map(local_id_from_serial)
}

fn serial() -> Option<String> {
    for name in ["ro.boot.serialno", "ro.serialno"] {
        let value = rsproperties::get_or(name, String::new());
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// 平台前缀，跟 payload 的 `soter_local::platform()` 同一套判据：明确是高通才报
/// `00000000`，其余（天玑、展锐、三星这类认不出来的）一律按天玑的 `09000000`。
/// 派生号的号头必须和本地兜底那条路一致，不然同一台机器两边报两个号。
fn platform_prefix() -> &'static str {
    let soc = rsproperties::get_or("ro.soc.manufacturer", String::new()).to_lowercase();
    let board = rsproperties::get_or("ro.board.platform", String::new()).to_lowercase();
    let qcom = soc.contains("qcom")
        || soc.contains("qualcomm")
        || soc.contains("qti")
        || board.starts_with("qcom");
    if qcom {
        QCOM_PREFIX
    } else {
        MTK_PREFIX
    }
}

/// 转发时告诉服务端这台机器的平台，服务端在没收到真机号、要现造一个时按它选号头。
/// 只有明确是高通才报 `qcom`，其余都按天玑那套。
pub fn soc_hint() -> &'static str {
    if platform_prefix() == QCOM_PREFIX {
        "qcom"
    } else {
        "mtk"
    }
}

/// 一台像真机的号：平台前缀 + `sha256("ommega-a-side-soter:" + serial)` 前 12 字节。
/// 跟 payload 的 `soter_local::cpu_id_from` 同一个算法。
fn local_id_from_serial(serial: &str) -> String {
    local_id_with_prefix(serial, platform_prefix())
}

fn local_id_with_prefix(serial: &str, prefix: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, format!("{SEED}{serial}").as_bytes());
    let mut out = String::from(prefix);
    for byte in &digest.as_ref()[..12] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 写副本：先写临时文件再 rename，读的一方永远读不到半截。内容没变就不动文件。
/// 读者是 payload（每 30 秒看一次）和启动器（每 5 秒镜像一次）。
fn write_mirror(value: &str) -> Result<()> {
    write_mirror_to(
        kmr_common::soter_relay::CPU_ID_WRITE_PATH,
        "soter_cpu_id",
        value,
    )
}

fn write_mirror_to(path: &str, key: &str, value: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let body = format!("{key}: {value}\n");
    if std::fs::read_to_string(path).ok().as_deref() == Some(body.as_str()) {
        return Ok(());
    }
    let tmp = format!("{path}.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    drop(file);
    // 644：这份值不是秘密（App 走 SOTER 本来就看得到），启动器要拿它去镜像。
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 算法钉死：这个序列号必须派生出这个号，payload 那边算出来得是同一个
    /// （两边算法一字不差），号头按平台换。
    #[test]
    fn the_derived_id_matches_the_payload_one() {
        assert_eq!(
            local_id_with_prefix("320143945328", MTK_PREFIX),
            "09000000043df759af14a088ee5307dc"
        );
        assert_eq!(
            local_id_with_prefix("320143945328", QCOM_PREFIX),
            "00000000043df759af14a088ee5307dc"
        );
        assert_eq!(local_id_with_prefix("320143945328", MTK_PREFIX).len(), 32);
    }

    /// 现编的号跟着平台走，不能被写死成 MTK 那套。
    #[test]
    fn the_derived_id_carries_the_platform_prefix() {
        let id = local_id_from_serial("320143945328");
        assert!(id.starts_with(platform_prefix()), "id = {id}");
        assert_eq!(id.len(), 32);
        assert!(soc_hint() == "mtk" || soc_hint() == "qcom");
    }

    /// 读不到序列号就返回 `None`，转发时不带 cpu_id。
    #[test]
    fn a_missing_serial_yields_no_id_at_all() {
        assert_eq!(id_for_serial(None), None);
        assert_eq!(
            id_for_serial(Some("320143945328")),
            Some(local_id_from_serial("320143945328"))
        );
    }

    /// 写副本：内容没变不重写，键名写对。
    #[test]
    fn writing_a_mirror_is_idempotent_and_keyed() {
        let dir = std::env::temp_dir().join(format!("ommega-cpuid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("soter_cpu_id");
        let path = path.to_str().unwrap();
        let value = "09000000043df759af14a088ee5307dc";
        write_mirror_to(path, "soter_cpu_id", value).unwrap();
        let body = std::fs::read_to_string(path).unwrap();
        assert_eq!(body, "soter_cpu_id: 09000000043df759af14a088ee5307dc\n");
        assert_eq!(
            kmr_common::soter_relay::parse_cpu_id(&body).as_deref(),
            Some(value)
        );
        // 第二次写同样内容，文件不重写。
        let first = std::fs::metadata(path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_mirror_to(path, "soter_cpu_id", value).unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().modified().unwrap(), first);
        // 换值就重写。
        write_mirror_to(path, "soter_cpu_id", "090000005171734c42866bea148b21f5").unwrap();
        assert!(std::fs::read_to_string(path)
            .unwrap()
            .contains("5171734c42866bea148b21f5"));
    }

    /// 副本文件怎么读：用临时目录，不碰设备上那两份真位置。
    #[test]
    fn the_mirror_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("ommega-cpuid-r-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("soter_cpu_id");
        let value = "09000000043df759af14a088ee5307dc";
        std::fs::write(&path, format!("soter_cpu_id: {value}\n")).unwrap();
        let (read, source) = read_mirror_from(&[path.to_str().unwrap()]).expect("得读出来");
        assert_eq!(read, value);
        assert!(source.starts_with("file "), "source = {source}");
        // 空文件/坏内容当作没有。
        let bad = dir.join("bad");
        std::fs::write(&bad, "soter_cpu_id: 09000000\n").unwrap();
        assert_eq!(read_mirror_from(&[bad.to_str().unwrap()]), None);
    }
}
