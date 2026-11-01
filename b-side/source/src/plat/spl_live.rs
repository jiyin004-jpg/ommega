//! 第二种让本机真 TEE 按 A 端日期出链的做法：**运行中直接改 KeyMint TA 的
//! attestation 配置**，不碰系统属性、不弹 keymint HAL、也不重启 keystore2。
//!
//! 第一种（[`super::patchlevel`]）是 resetprop + 弹 HAL 重读，秒级、全局生效；
//! 这一种是往 TA 发两条命令（`keymint_set_version` + `configure`），单次 0.5ms，
//! 签完立刻发回基线。代价是它只认高通那套 `KeymasterUtils` 通道，而且要在
//! `uid 1000` 的进程里跑 —— 所以设备侧是独立的 `spl_daemon`（`native/spl/`），
//! 我们这边只是它的一个 socket 客户端。
//!
//! 协议（abstract unix socket `@spl-daemon`，见 `native/spl/README.md`）：
//!
//! ```text
//! APPLY <os> <sys> <vendor> [flag] [hold_ms]   ->  OK applied us=.. rc=..
//! RESTORE                                      ->  OK restored in ..ms
//! STATUS                                       ->  OK base=os/sys/vendor/flag cur=.. applied=.. hold_ms_left=..
//! ```
//!
//! 窗口期就是「APPLY 到 RESTORE」这一段（实测 0.5ms 下发 + 签发那几十毫秒），
//! 期间别的 App 发起认证也会看到目标值 —— 跟第一种一样，只是窗口短得多。
//! daemon 自己还有看门狗：hold_ms 到点没等到 RESTORE 就回基线，relay 中途挂掉
//! 也不会把假日期留在设备上。

use std::io::{Read, Write};
#[cfg(target_os = "android")]
use std::os::android::net::SocketAddrExt;
#[cfg(target_os = "linux")]
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;

/// 选哪种方法：`prop`（第一种，默认）或 `live`（这一种）。
pub const METHOD_KEY: &str = "OMMEGA_RELAY_PATCHLEVEL_METHOD";

const SOCK_NAME: &str = "spl-daemon";
/// APPLY/RESTORE 正常都是亚毫秒到几毫秒；这个值只是防止卡死在 socket 上。
const IO_TIMEOUT: Duration = Duration::from_millis(800);
/// 连着失败就别每笔都白等一次超时，先退回第一种跑一会儿。
const FAIL_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    /// resetprop 改属性 + 让 keymint HAL 重读（`plat::patchlevel`）。
    Prop,
    /// 直接改 TA 的 configure（本模块）。
    Live,
}

impl Method {
    pub fn parse(raw: Option<&str>) -> Method {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("live") => Method::Live,
            _ => Method::Prop,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Method::Prop => "prop",
            Method::Live => "live",
        }
    }
}

/// TA configure 收的那四个数（`os` / `sys` / `vendor` / SPU flag）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Values {
    pub os: u32,
    pub sys: u32,
    pub vendor: u32,
    pub flag: u32,
}

/// daemon 的 `STATUS`：`base` 是它认定的本机基线，`cur` 是它最后下发的值。
/// 两者不相等，说明上一笔还没 `RESTORE`（或者半道挂了，等看门狗）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub base: Values,
    pub cur: Values,
    pub applied: bool,
}

fn request(line: &str) -> Result<String> {
    let addr = SocketAddr::from_abstract_name(SOCK_NAME.as_bytes())
        .context("build abstract socket addr")?;
    let mut sock = UnixStream::connect_addr(&addr)
        .with_context(|| format!("connect @{SOCK_NAME}（daemon 没起来？）"))?;
    sock.set_read_timeout(Some(IO_TIMEOUT)).ok();
    sock.set_write_timeout(Some(IO_TIMEOUT)).ok();
    // 一次写完：daemon 读完就 reply 然后 close，分两次写的话第二段会 EPIPE
    // （命令本身已经到了，但这个错误会被当成「RESTORE 失败」报出来）。
    sock.write_all(format!("{line}\n").as_bytes())
        .context("write to spl daemon")?;
    let mut buf = [0u8; 256];
    let n = sock.read(&mut buf).context("read from spl daemon")?;
    if n == 0 {
        return Err(anyhow!("spl daemon closed the connection without a reply"));
    }
    let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
    if text.starts_with("OK") {
        Ok(text)
    } else {
        Err(anyhow!("spl daemon said: {text}"))
    }
}

/// daemon 眼里的基线（它开机时从系统属性推的，或者最后一次显式设的）。
fn status() -> Result<Status> {
    let reply = request("STATUS")?;
    parse_status(&reply).ok_or_else(|| anyhow!("unexpected STATUS reply: {reply}"))
}

/// `OK base=160000/202608/20260801/3 cur=...` -> 四个数。
fn parse_status(reply: &str) -> Option<Status> {
    let grab = |prefix: &str| -> Option<Values> {
        let raw = reply
            .split_whitespace()
            .find_map(|t| t.strip_prefix(prefix))?;
        let mut it = raw.split('/');
        Some(Values {
            os: it.next()?.parse().ok()?,
            sys: it.next()?.parse().ok()?,
            vendor: it.next()?.parse().ok()?,
            flag: it.next()?.parse().ok()?,
        })
    };
    let base = grab("base=")?;
    let cur = grab("cur=").unwrap_or(base);
    let applied = reply
        .split_whitespace()
        .find_map(|t| t.strip_prefix("applied="))
        .is_some_and(|v| v == "1");
    Some(Status { base, cur, applied })
}

/// A 端上报的三个数：`os_version` = 160000、`os_patch_level` = 202608、
/// `vendor_patch_level` = 20260801。缺哪个就用本机基线补哪个。
fn values_from_payload(payload: &Value, base: &Values) -> Option<Values> {
    let ctx = payload.get("device_attest_context").unwrap_or(payload);
    let field = |name: &str| {
        ctx.get(name)
            .or_else(|| payload.get(name))
            .and_then(Value::as_i64)
    };
    let os = field("os_version")
        .filter(|v| (10_000..=999_999).contains(v))
        .map(|v| v as u32)
        .unwrap_or(base.os);
    let sys = field("os_patch_level")
        .filter(|v| valid_yyyymm(*v))
        .map(|v| v as u32)
        .unwrap_or(base.sys);
    let vendor = field("vendor_patch_level")
        .filter(|v| valid_yyyymmdd(*v))
        .map(|v| v as u32)
        .unwrap_or(base.vendor);
    if os == base.os && sys == base.sys && vendor == base.vendor {
        // 全都等于本机现值：不用下发，省一次窗口。
        return None;
    }
    Some(Values {
        os,
        sys,
        vendor,
        flag: base.flag,
    })
}

fn valid_yyyymm(v: i64) -> bool {
    (200_001..=209_912).contains(&v) && (1..=12).contains(&(v % 100))
}

fn valid_yyyymmdd(v: i64) -> bool {
    if !(20_000_101..=20_991_231).contains(&v) {
        return false;
    }
    let (y, m, d) = (v / 10_000, (v / 100) % 100, v % 100);
    let max_day = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => return false,
    };
    (1..=max_day).contains(&d)
}

/* ------------------------------ 失败熔断 ------------------------------ */

/// 上一次 live 失败的时刻。连不上/平台不支持时别每笔认证都白等 800ms。
static FAILED_AT: Mutex<Option<Instant>> = Mutex::new(None);

fn cooling_down() -> bool {
    FAILED_AT
        .lock()
        .ok()
        .and_then(|g| *g)
        .is_some_and(|t| t.elapsed() < FAIL_COOLDOWN)
}

fn note_failure() {
    if let Ok(mut g) = FAILED_AT.lock() {
        *g = Some(Instant::now());
    }
}

fn note_success() {
    if let Ok(mut g) = FAILED_AT.lock() {
        *g = None;
    }
}

/* ------------------------------- 使用侧 ------------------------------- */

/// 已经 APPLY 过、还没 RESTORE 的一次改动。drop 时一定回基线。
pub struct LiveGuard {
    restored: bool,
    sent: Values,
}

impl LiveGuard {
    pub fn values(&self) -> Values {
        self.sent
    }

    /// 这次真的发过 APPLY 吗？false 表示值本来就是目标值，没开窗口。
    pub fn applied(&self) -> bool {
        !self.restored
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        request("RESTORE").map(|_| ())
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        if let Err(e) = self.restore() {
            // daemon 的看门狗会兜底（APPLY 时带了 hold），这里只记一下。
            log::warn!("spl live: 回基线失败（交给 daemon 看门狗）：{e:#}");
        }
    }
}

/// 按 payload 下发改动，返回一个活着就占着窗口的 guard。
/// `hold_ms` 是丢给 daemon 看门狗的兜底时长，比正常签发时间留宽一点。
pub fn apply_from_payload(payload: &Value, hold_ms: u32) -> Result<LiveGuard> {
    if cooling_down() {
        return Err(anyhow!("上次失败还没过冷却期"));
    }
    let st = status().inspect_err(|_| note_failure())?;
    // 目标值 = 请求里要的那组；请求没带就用本机基线。注意不能因为
    // 「请求值 == 基线」就直接跳过 —— daemon 最后下发的 `cur` 也可能是
    // 上一次留下的（上一笔 RESTORE 没走到），不补一次 APPLY 就纠不回来。
    let want = values_from_payload(payload, &st.base).unwrap_or(st.base);
    if want == st.cur {
        // daemon 最后下发的就是它：可能上一笔的 RESTORE 没走到，但值已经是
        // 我们要的，直接沿用，不再开一次窗口。
        return Ok(LiveGuard {
            restored: true,
            sent: want,
        });
    }
    let line = format!(
        "APPLY {} {} {} {} {}",
        want.os, want.sys, want.vendor, want.flag, hold_ms
    );
    match request(&line) {
        Ok(reply) => {
            note_success();
            log::info!("spl live: {reply}");
            Ok(LiveGuard {
                restored: false,
                sent: want,
            })
        }
        Err(e) => {
            note_failure();
            Err(e)
        }
    }
}

/// 给状态页/日志用的一句话。
pub fn describe(values: &Values) -> String {
    format!(
        "{}/{}/{}/flag={}",
        values.os, values.sys, values.vendor, values.flag
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn method_defaults_to_prop() {
        assert_eq!(Method::parse(None), Method::Prop);
        assert_eq!(Method::parse(Some("")), Method::Prop);
        assert_eq!(Method::parse(Some("prop")), Method::Prop);
        assert_eq!(Method::parse(Some("LIVE")), Method::Live);
        assert_eq!(Method::parse(Some(" live ")), Method::Live);
        // 拼错的不算开：宁可走已经验证过的第一种，也不去瞎试。
        assert_eq!(Method::parse(Some("list")), Method::Prop);
    }

    #[test]
    fn parses_status_reply() {
        let reply = "OK base=160000/202608/20260801/3 cur=170000/202609/20260901/3 applied=1 hold_ms_left=1500";
        assert_eq!(
            parse_status(reply),
            Some(Status {
                base: Values {
                    os: 160000,
                    sys: 202608,
                    vendor: 20260801,
                    flag: 3
                },
                cur: Values {
                    os: 170000,
                    sys: 202609,
                    vendor: 20260901,
                    flag: 3
                },
                applied: true,
            })
        );
        // 没有 cur（老 daemon）就当它等于 base。
        let bare = "OK base=160000/202608/20260801/3 applied=0";
        let st = parse_status(bare).unwrap();
        assert_eq!(st.cur, st.base);
        assert!(!st.applied);
        assert_eq!(parse_status("OK pong"), None);
        assert_eq!(parse_status("OK base=1/2/3"), None);
    }

    #[test]
    fn validates_dates() {
        assert!(valid_yyyymm(202608));
        assert!(!valid_yyyymm(202613));
        assert!(!valid_yyyymm(202600));
        assert!(valid_yyyymmdd(20260801));
        assert!(valid_yyyymmdd(20240229));
        assert!(!valid_yyyymmdd(20230229));
        assert!(!valid_yyyymmdd(20260431));
        assert!(!valid_yyyymmdd(160000));
    }

    #[test]
    fn payload_overrides_only_what_it_carries() {
        let base = Values {
            os: 160000,
            sys: 202608,
            vendor: 20260801,
            flag: 3,
        };
        let full = json!({"device_attest_context": {
            "os_version": 170000,
            "os_patch_level": 202609,
            "vendor_patch_level": 20260901
        }});
        assert_eq!(
            values_from_payload(&full, &base),
            Some(Values {
                os: 170000,
                sys: 202609,
                vendor: 20260901,
                flag: 3
            })
        );
        // 只带 sys：另外两个用基线。
        let partial = json!({"device_attest_context": {"os_patch_level": 202609}});
        assert_eq!(
            values_from_payload(&partial, &base),
            Some(Values {
                os: 160000,
                sys: 202609,
                vendor: 20260801,
                flag: 3
            })
        );
        // 越界的不采信，退回基线。
        let bad =
            json!({"device_attest_context": {"os_version": 7, "vendor_patch_level": 20261340}});
        assert_eq!(values_from_payload(&bad, &base), None);
        // 跟基线一样 = 不需要窗口。
        let same = json!({"os_version": 160000});
        assert_eq!(values_from_payload(&same, &base), None);
    }
}
