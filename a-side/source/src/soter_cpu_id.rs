//! 把 A 端本地兜底要报的 cpu_id 摆到 payload 读得到的地方，并让转发请求带上它。
//!
//! 兜底那条路的密钥是我们自己的（本地自签的 ASK/AuthKey），身份也必须用本机自己的号；
//! 借真机（B）的号会让判证器按值对比出不一致。号只从真实属性派生
//! （`ro.boot.serialno` / `ro.serialno`），读不到序列号就不报号、也不编一个 —— 转发
//! 干脆不带 `cpu_id`，由服务端按当时的年月日时分现造。
//!
//! 落盘是因为 SOTER 宿主是 uid 1000，读不到 daemon 的域。算法必须和 payload 里的
//! `soter_local::cpu_id_from` 一致，否则同一条兜底路会因为文件在不在而报两个号。

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;

/// 主循环节拍。
const TICK: Duration = Duration::from_secs(60);

/// 派生用的前缀，跟 payload 那份一字不差。
const SEED: &str = "ommega-a-side-soter:";

static DERIVED: Mutex<Option<String>> = Mutex::new(None);
static STARTED: OnceLock<()> = OnceLock::new();

/// 起派生线程（幂等）。
/// 只读属性 + 写一个小文件，不发请求；放后台是因为它定期看一眼序列号，热路径只读缓存。
pub fn start() {
    if STARTED.set(()).is_err() {
        return;
    }
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

/// 当前该报给服务端的 cpu_id；没有真实来源返回 `None`，转发时不带这个字段。
/// 不发请求：内存有就用内存，否则看副本文件，再否则现派生；没有序列号就 `None`。
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

/// 一台像真机的号：`09000000` + `sha256("ommega-a-side-soter:" + serial)` 前 12 字节。
/// 跟 payload 的 `soter_local::cpu_id_from` 同一个算法。
fn local_id_from_serial(serial: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, format!("{SEED}{serial}").as_bytes());
    let mut out = String::from("09000000");
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
    /// （两边算法一字不差）。
    #[test]
    fn the_derived_id_matches_the_payload_one() {
        assert_eq!(
            local_id_from_serial("320143945328"),
            "09000000043df759af14a088ee5307dc"
        );
        assert_eq!(local_id_from_serial("320143945328").len(), 32);
    }

    /// 读不到序列号就没有号：不拿写死的种子编一个（否则每台机器报同一个号）。
    /// 转发时不带 cpu_id，交给服务端按时间造。
    #[test]
    fn a_missing_serial_yields_no_id_at_all() {
        assert_eq!(id_for_serial(None), None);
        assert_eq!(
            id_for_serial(Some("320143945328")),
            Some("09000000043df759af14a088ee5307dc".to_string())
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
        // 第二次写同样内容：文件不该被重写（不然启动器每轮都会镜像一遍）。
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
