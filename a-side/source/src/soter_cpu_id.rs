//! 学真机的 cpu_id，并把它摆到 payload 读得到的地方（A 端 daemon 侧）。
//!
//! 为什么要学：SOTER 的身份是 `(cpu_id, uid)` 一起绑的，而这一套栈里能给出这个号的有
//! 三处 —— 真机（B 端 TEE）自己报的那个（`09000000` + 12 字节，天底下只有它有）、服务端
//! 那两层按设备名派生出来的、以及 A 端本地自签本来按 `ro.boot.serialno` 派生的。三个号
//! 不一样，同一个 App 在不同层上就成了不同设备：微信会重走一轮开通流程，检测器两次一
//! 对比直接报「两次 cpuid 不一致」。
//!
//! 做法：跟服务端要一次 `get_device_id`。那个 op 属于「ASK 身份类」，服务端只会让真机答
//! （`handlers.rs::soter_identity_op`），所以答回来的就是真值。学到之后写一份到自己
//! 写得动的地方（daemon 跑在 keystore uid 里，只有 `/data/misc/keystore/ommega` 进得去），
//! 启动器 `daemon-injector` 再镜像到 app 域给宿主里那份 payload 读（见
//! [`kmr_common::soter_relay::CPU_ID_PATHS`]）。每次转发的 SOTER 请求也带上它，服务端那
//! 两层就跟着报同一个号。
//!
//! B 端不参与：那个号是它 TA 自己的，我们既改不了也不用改。

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::remote::{remote_enabled, RemoteRelay};

/// 学到之后多久重新学一次。真机 cpu_id 一辈子不换，这个间隔只是兜底：开头 B 端不在线、
/// 或者真机换了 TEE 的时候，隔一天自己纠一次。
const REFRESH: Duration = Duration::from_secs(24 * 60 * 60);
/// 没学到时多久再试一次（B 端不在线时别一直拿请求去敲门）。
const RETRY: Duration = Duration::from_secs(5 * 60);
/// 主循环节拍。
const TICK: Duration = Duration::from_secs(60);

/// 学到的值（来路只在换值那行日志里出现，不占一个字段）。
struct Learned {
    value: String,
    learned_at: Instant,
}

static LEARNED: Mutex<Option<Learned>> = Mutex::new(None);
static STARTED: OnceLock<()> = OnceLock::new();

/// 起学习线程（幂等：main 里调一次，`forward()` 里兜底再调也没事）。
///
/// 学习要发请求、可能等好几秒，所以绝不能放在 `forward()` 那条路上同步做 —— 那笔 HAL
/// 调用在宿主里等着，多等一秒就是一秒的卡顿。这里只在后台慢慢学，`current()` 只读缓存。
pub fn start() {
    if STARTED.set(()).is_err() {
        return;
    }
    std::thread::spawn(|| loop {
        // 探测机那份是按设备名算出来的，不用等 B 端，开机就先摆好。
        if let Err(error) = write_probe_mirror() {
            log::debug!("soter probe cpu_id not written yet: {error:#}");
        }
        let stale = match LEARNED.lock() {
            Ok(guard) => guard
                .as_ref()
                .map_or(true, |learned| learned.learned_at.elapsed() >= REFRESH),
            // 锁坏了：这一轮不学，下一轮再来。
            Err(_) => false,
        };
        let mut delay = TICK;
        if stale {
            match learn() {
                Ok(()) => {}
                Err(error) => {
                    log::debug!("soter cpu_id not learned yet: {error:#}");
                    delay = RETRY;
                }
            }
        }
        std::thread::sleep(delay);
    });
}

/// 当前该报给服务端的真机 cpu_id。没学到返回 `None`（转发时就照旧不带这个字段）。
///
/// 这条路不发请求：内存里有就用内存，没有才顺手看一眼副本文件（daemon 重启之后第一笔
/// 调用就走这里），再没有就等学习线程。
pub fn current() -> Option<String> {
    if let Some(value) = cached() {
        return Some(value);
    }
    let (value, source) = read_mirror()?;
    store(value.clone(), source);
    Some(value)
}

/// 缓存里那份，够不够新鲜由 `start()` 的循环负责刷新，读的地方不挑。
fn cached() -> Option<String> {
    LEARNED
        .lock()
        .ok()?
        .as_ref()
        .map(|learned| learned.value.clone())
}

fn store(value: String, source: String) {
    if let Ok(mut guard) = LEARNED.lock() {
        let changed = guard.as_ref().is_none_or(|learned| learned.value != value);
        if changed {
            log::info!("soter cpu_id -> {value} ({source})");
        }
        *guard = Some(Learned {
            value,
            learned_at: Instant::now(),
        });
    }
}

/// 读一份之前写下的副本（daemon 刚起来、内存还空的时候用）。
fn read_mirror() -> Option<(String, String)> {
    read_mirror_from(&kmr_common::soter_relay::CPU_ID_PATHS)
}

/// `read_mirror` 里跟「从哪读」无关的那半（测试拿临时文件跑）。
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

/// 走一趟远程把真机的 cpu_id 要回来，学到手才写文件。
fn learn() -> Result<()> {
    let value = fetch_device_id()?;
    if let Err(error) = write_mirror(&value) {
        // 学是学到了（这次转发就能用上），只是下次重启要重学一遍 —— 值得留一行。
        log::warn!(
            "soter cpu_id could not be written to {}: {error:#}",
            kmr_common::soter_relay::CPU_ID_WRITE_PATH
        );
    }
    store(value, "relay".to_string());
    Ok(())
}

/// 探测机（春秋 / 鸭子）那套该报的号：按设备名派生，跟服务端 `builtin` 层
/// （`soter_mint::virtual_device_id`）同一个值。
///
/// 为什么要有一份单独的：探测流量不该看到被中继那台机器的身份（那串号是采样值，
/// 探测器认得出来）；但同一轮探测的 ASK / AuthKey、以及「远程不通退回本地自签」那条路
/// 又必须报同一个号，所以两边都用这个算得出来的号。
fn write_probe_mirror() -> Result<()> {
    let device_id = RemoteRelay::device_id()?;
    let value = virtual_id_for(&device_id);
    write_mirror_to(
        kmr_common::soter_relay::PROBE_CPU_ID_WRITE_PATH,
        "soter_probe_cpu_id",
        &value,
    )
}

fn fetch_device_id() -> Result<String> {
    if !remote_enabled() {
        return Err(anyhow!("远程没开，先不学"));
    }
    let reply = RemoteRelay::soter(&json!({ "op": "get_device_id" }))?
        .ok_or_else(|| anyhow!("服务端没给答复（B 端不在线？）"))?;
    let value = device_id_from_reply(&reply)
        .ok_or_else(|| anyhow!("答复里没有可用的真机 cpu_id: {reply}"))?;
    // 第二个卡子：老服务端不带 `layer`，但虚拟号是算得出来的。
    if is_server_virtual_id(&value, RemoteRelay::device_id().ok().as_deref()) {
        return Err(anyhow!(
            "这次答的是服务端按设备名派生的虚拟号，不是真机，丢掉（等 B 端在线再学）"
        ));
    }
    Ok(value)
}

/// 服务端那两层派生设备号的办法（`server/source/src/soter_mint.rs::virtual_device_id`）：
/// `sha256("ommega-server-soter:" + device_id)` 前 12 字节小写十六进制，前面补 `09000000`。
///
/// 拄这一遍是为了兜住老服务端：`layer` 标记是跟这次改动一起上的，而老服务端答的虚拟号
/// 跟真机的答复长得一模一样 —— 只有把这个算得出来的假号提前排掉，才不至于在一台老服务端
/// 上（正好 B 端离线的时候）把假身份学进来。
fn virtual_id_for(device_id: &str) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        format!("ommega-server-soter:{device_id}").as_bytes(),
    );
    let mut out = String::from("09000000");
    for byte in &digest.as_ref()[..12] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn is_server_virtual_id(value: &str, device_id: Option<&str>) -> bool {
    device_id.is_some_and(|device_id| value == virtual_id_for(device_id))
}

/// 从答复里取真机 cpu_id。**不是真机答的一律不认**。
///
/// 服务端那两层（keybox / self_signed）答的 `get_device_id` 是它按设备名自己派生的号，
/// 拿它去当设备身份等于把身份换成假的；`soter_mint::run` 给这种答复打了个 `layer` 标记，
/// 这里就靠它分辨。跨代兼容：老服务端不带 `layer` 时无法分辨，只能信（原来那套就是信）。
fn device_id_from_reply(reply: &Value) -> Option<String> {
    if let Some(layer) = reply.get("layer").and_then(Value::as_str) {
        log::warn!("soter cpu_id: 这次是服务端 {layer} 层答的，不是真机，不拿它当设备身份");
        return None;
    }
    if reply.get("error_code").and_then(Value::as_i64) != Some(0) {
        return None;
    }
    // 真机那份答复里 `text` 就是那 32 个字符；`data` 是同样的字节加一个结尾的 NUL。
    if let Some(text) = reply.get("text").and_then(Value::as_str) {
        let text = text.trim_end_matches('\0').trim();
        if kmr_common::soter_relay::is_cpu_id(text) {
            return Some(text.to_string());
        }
    }
    let data = reply.get("data").and_then(Value::as_str)?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim_end_matches('\0').trim();
    kmr_common::soter_relay::is_cpu_id(text).then(|| text.to_string())
}

/// 写 daemon 自己那份副本：先写临时文件再 rename，读的一方（payload 每 30 秒看一眼，
/// 启动器每 5 秒镜像一次）永远读不到半截。内容没变就不动文件。
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
    // 644：这份值不是秘密（App 通过 SOTER 本来就看得到），启动器要拿它去镜像。
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_device_answer_is_taken() {
        // 真机（B 端 TEE）那份答复的形状：text 没有结尾 NUL，data 有。
        let reply = json!({
            "data": "MDkwMDAwMDA1MTcxNzM0YzQyODY2YmVhMTQ4YjIxZjUA",
            "error_code": 0,
            "length": 33,
            "op": "get_device_id",
            "text": "090000005171734c42866bea148b21f5"
        });
        assert_eq!(
            device_id_from_reply(&reply).as_deref(),
            Some("090000005171734c42866bea148b21f5")
        );
        // 只有 data（没有 text）也认，结尾 NUL 要去掉。
        let data_only = json!({
            "data": "MDkwMDAwMDA1MTcxNzM0YzQyODY2YmVhMTQ4YjIxZjUA",
            "error_code": 0
        });
        assert_eq!(
            device_id_from_reply(&data_only).as_deref(),
            Some("090000005171734c42866bea148b21f5")
        );
    }

    #[test]
    fn a_server_layer_answer_is_refused() {
        // 服务端自己那两层答的是它按设备名派生的号，拿它当设备身份就是把身份换假的。
        let reply = json!({
            "data": "MDkwMDAwMDBjZWViNWRjM2M4ZTAyMTZhNWY3NGNmZWI=",
            "error_code": 0,
            "layer": "self_signed",
            "text": "09000000ceeb5dc3c8e0216a5f74cfeb"
        });
        assert_eq!(device_id_from_reply(&reply), None);
    }

    #[test]
    fn a_failure_or_a_bad_shape_is_not_guessed() {
        for reply in [
            json!({"error_code": -5, "op": "get_device_id"}),
            json!({"error_code": 0, "text": "09000000"}),
            json!({"error_code": 0, "text": "090000005171734c42866bea148b21fz"}),
            json!({"error_code": 0, "data": "not base64!!"}),
            json!({"error_code": 0}),
            json!({"error": "no B-side device reporting SOTER support is online"}),
        ] {
            assert_eq!(
                device_id_from_reply(&reply),
                None,
                "{reply} 不该被当设备身份"
            );
        }
    }

    #[test]
    fn the_servers_virtual_id_is_recognised() {
        // 这批值都是实打实算过的（服务端那边的 virtual_device_id 同一套）。
        let real = "device-b-c3f204aa";
        assert_eq!(virtual_id_for(real), "09000000ceeb5dc3c8e0216a5f74cfeb");
        assert!(is_server_virtual_id(
            "09000000ceeb5dc3c8e0216a5f74cfeb",
            Some(real)
        ));
        assert!(!is_server_virtual_id(
            "090000005171734c42866bea148b21f5",
            Some(real)
        ));
        // 不知道设备名就不排（宁可靠 `layer` 那个卡子）。
        assert!(!is_server_virtual_id(
            "09000000ceeb5dc3c8e0216a5f74cfeb",
            None
        ));
    }

    /// 写副本：内容没变不重写，两个键各写各的。
    #[test]
    fn writing_a_mirror_is_idempotent_and_keyed() {
        let dir = std::env::temp_dir().join(format!("ommega-mirror-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("soter_probe_cpu_id");
        let path = path.to_str().unwrap();
        let value = "09000000ceeb5dc3c8e0216a5f74cfeb";
        write_mirror_to(path, "soter_probe_cpu_id", value).unwrap();
        let body = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            body,
            "soter_probe_cpu_id: 09000000ceeb5dc3c8e0216a5f74cfeb\n"
        );
        assert_eq!(
            kmr_common::soter_relay::parse_probe_cpu_id(&body).as_deref(),
            Some(value)
        );
        // 第二次写同样内容：文件不该被重写（不然启动器每轮都会镜像一遍）。
        let first = std::fs::metadata(path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_mirror_to(path, "soter_probe_cpu_id", value).unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().modified().unwrap(), first);
        // 换值就重写。
        write_mirror_to(
            path,
            "soter_probe_cpu_id",
            "090000005171734c42866bea148b21f5",
        )
        .unwrap();
        assert!(std::fs::read_to_string(path)
            .unwrap()
            .contains("5171734c42866bea148b21f5"));
    }

    #[test]
    fn the_mirror_round_trips_through_a_file() {
        // 只碰临时目录，不碰设备上那两个真位置。
        let dir = std::env::temp_dir().join(format!("ommega-cpuid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("soter_cpu_id");
        let value = "090000005171734c42866bea148b21f5";
        let body = format!("soter_cpu_id: {value}\n");
        std::fs::write(&path, &body).unwrap();
        let (read, source) = read_mirror_from(&[path.to_str().unwrap()]).expect("得读出来");
        assert_eq!(read, value);
        assert!(source.starts_with("file "), "source = {source}");
    }
}
