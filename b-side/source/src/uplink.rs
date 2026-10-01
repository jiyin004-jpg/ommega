//! 出口网卡：把 relay 的请求钉在一条真能通的物理链路上。
//!
//! 抄的是 A 端 `remote.rs` 那一套，理由一样：VPN 起来之后系统会把普通流量塞进
//! 隧道（netd 把连接的 fwmark 指向 VPN 网络、默认路由落到 tun 上），去我们自己
//! 服务端的那一份也被一起抓走 —— 慢、抖，坏的时候干脆不通。唯一能把 socket 从
//! 隧道里摘出来的办法是点名出口设备（`SO_BINDTODEVICE`，reqwest 的
//! `.interface()` 干的就是这个）。
//!
//! 跟 A 端不一样的地方有两处，都是 B 这台机器上实测出来的：
//!
//! 1. 排除名单里加了厂商隧道。A 端那份名单不看 `vgate0`，而它确实查得到 IPv4
//!    路由（`/proc/net/route` 里有它），于是会被当成候选去竞速 —— 可它正是要躲
//!    的那条隧道。`tun0` 靠 `tun` 前缀就被排掉了，`vgate0` 得单独列。
//! 2. 这里只管「谁算候选、谁答话」，选出来的结果由调用方缓存。B 端一秒能打几百
//!    个请求，每条都探一次等于把流量翻倍；缓存几秒、只在失败时重选就够用了。
//!
//! 另外 `bind_iface` 默认是 `none`（不绑）。这台机器上 relay 的流量本来就出
//! wlan0（`ip rule` 把所有本机进程的路由都送进 `table wlan0`，隧道是空的），
//! 绑上去没有收益，反而会丢掉系统自己的「WiFi 断了切蜂窝」那套切换。要绑就
//! 显式配 `auto` / `always` / 网卡名。

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use reqwest::blocking::Client;

/// 一条候选链路答话的时间上限。刻意短：正常网络里一个来回远小于这个数，探路的
/// 意义就是从死链路上快点跑开。
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// 服务端的存活探针，以及它的答复体。
///
/// `/api/ping/` 不碰任何状态、固定回 `pong`，正好拿来当探针目标：便宜，而且答复
/// 体认得出是不是我们的服务端。探 `/` 的话，任何 HTTP 回答都算数 —— 运营商门户、
/// 酒店登录页把请求吞了也会答一个 200。
const PING_PATH: &str = "/api/ping/";
const PING_BODY: &str = "pong";

const SYS_CLASS_NET: &str = "/sys/class/net";

/// `bind_iface` 这个配置值是什么意思。
#[derive(Debug, PartialEq, Eq)]
pub enum BindChoice {
    /// `none` / `off` —— 从不绑定。
    Never,
    /// 空或 `auto` —— 只在 VPN 起着的时候绑。
    Auto,
    /// `always` / `on` —— 总是绑到一条物理链路上。
    Always,
    /// 写死的网卡名，原样使用。
    Named(String),
}

pub fn classify_bind_iface(raw: &str) -> BindChoice {
    let v = raw.trim();
    if v.eq_ignore_ascii_case("none") || v.eq_ignore_ascii_case("off") {
        BindChoice::Never
    } else if v.eq_ignore_ascii_case("always") || v.eq_ignore_ascii_case("on") {
        BindChoice::Always
    } else if v.is_empty() || v.eq_ignore_ascii_case("auto") {
        BindChoice::Auto
    } else {
        BindChoice::Named(v.to_string())
    }
}

/// 这条请求该从哪个网卡出去。`None` 就是不绑，交给系统自己决定。
///
/// `auto` 只在 VPN 起着的时候才绑：钉死一条链路会连系统自己的「WiFi 掉线切蜂窝」
/// 一起丢掉，没有隧道要躲的时候纯是亏。想要固定走某条网卡的部署直接写网卡名。
pub fn desired_iface(bind_iface: &str, base_url: &str) -> Option<String> {
    match classify_bind_iface(bind_iface) {
        BindChoice::Never => None,
        BindChoice::Always => race_uplink(&uplink_candidates(), base_url),
        BindChoice::Auto if vpn_active() => race_uplink(&uplink_candidates(), base_url),
        BindChoice::Auto => None,
        // 写死的名字就当它存在能用 —— 那是内核说了算，不是我们。
        BindChoice::Named(name) => Some(name),
    }
}

/// 现在有没有 VPN 起着。`VpnService` 一定会在 `/sys/class/net` 里留一个 `tun`
/// 设备，老的 pptp/l2tp 路径留 `ppp`；名字都是 `tun0` / `ppp0` 这种形状，认前缀
/// 就够了。
fn vpn_active() -> bool {
    let Ok(entries) = std::fs::read_dir(SYS_CLASS_NET) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("tun") || n.starts_with("ppp") || n.starts_with("tap"))
    })
}

/// 现在能扛 relay 流量的物理网卡，好的排前面。
///
/// 两个坑（A 端在 Z60 Ultra 上踩过、B 这台也一样）：
/// `dummy0` 和 `lo` 都报 `operstate=unknown` 且 `carrier=1`，光看状态分不出是不是
/// 真网卡，所以虚拟设备只能按名字排掉；而蜂窝那些 `rmnet_data*` / `ccmni*` 同样报
/// `unknown`（它们没有真实的链路层状态），只看 `up` 又会把蜂窝漏掉。
///
/// 这还不够：拿不到 IPv4 地址的网卡绑上去等于绑了个没有路由的设备。`/proc/net/route`
/// 列的正好是当前持有 IPv4 路由的那些接口，拿它做交叉过滤最准。
///
/// 注意这只说明「有地址」，不代表「真通到外面」—— 那件事只看 `probe`。
pub fn uplink_candidates() -> Vec<String> {
    let with_ip = ifaces_with_ipv4();
    if with_ip.is_empty() {
        return Vec::new();
    }

    let Ok(entries) = std::fs::read_dir(SYS_CLASS_NET) else {
        return Vec::new();
    };
    let mut found: Vec<(u8, String)> = Vec::new();
    for e in entries.flatten() {
        let entry_name = e.file_name();
        let Some(name) = entry_name.to_str() else {
            continue;
        };
        if is_virtual_iface(name) || !with_ip.iter().any(|n| n == name) {
            continue;
        }
        let state = std::fs::read_to_string(format!("{SYS_CLASS_NET}/{name}/operstate"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        // `operstate` 读不到（某些 SELinux 域下会被拒）不该因此刷掉这个设备：
        // `/proc/net/route` 已经证明它扛着 IPv4 路由，能不能通由探针说了算。
        if !state.is_empty() && state != "up" && state != "unknown" {
            continue;
        }
        found.push((uplink_rank(name), name.to_string()));
    }
    found.sort();
    found.into_iter().map(|(_, name)| name).collect()
}

/// 探针打哪儿。配的 URL 末尾带斜杠时不能拼出双斜杠。
pub fn probe_url(base_url: &str) -> String {
    format!("{}{PING_PATH}", base_url.trim_end_matches('/'))
}

/// 从 `iface` 出去（`None` 就按系统默认路由）能不能真打到服务端。
///
/// 拿着 IPv4 地址不等于有能用的路由：连上一个上游已经挂掉的 WiFi —— 或者卡在
/// 运营商门户后面 —— 一样拿得到 DHCP 租约，`wlan0` 看着健健康康，从它发出去的
/// 东西全没了。短请求是唯一老实的测法，而终点会答一个认得出的固定内容：传输层
/// 失败说明这条链路扛不动，答出来的不是 `pong` 说明中间有东西把请求吞了。
pub fn probe(base_url: &str, iface: Option<&str>) -> bool {
    // 没得探（URL 没配或者形状不对）就当通 —— 别把配置问题变成「所有网卡都不通」。
    if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
        return true;
    }
    let mut builder = Client::builder()
        .no_proxy()
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        // 探针只问「包出得去吗」，证书问题不是路由问题。
        .danger_accept_invalid_certs(true);
    if let Some(name) = iface {
        builder = builder.interface(name);
    }
    let Ok(client) = builder.build() else {
        return false;
    };
    let Ok(resp) = client.get(probe_url(base_url)).send() else {
        return false;
    };
    resp.status().is_success() && resp.text().is_ok_and(|body| body.trim() == PING_BODY)
}

/// 让候选链路互相竞速，谁先答话用谁。
///
/// 用竞速而不是排序，是这个选择能自己纠正的关键：一条上游已经挂掉的 WiFi 链路
/// 就是不会答话，自己就输了 —— 没人需要先发现它死了，也没人等某个缓存的判断过期。
/// 输的那些探针只是发了个无害的 GET，丢掉就完了；阻塞请求取消不了，也不需要取消。
fn race_uplink(candidates: &[String], base_url: &str) -> Option<String> {
    // 闭包要 `'static` 才能搬进探针线程，所以 URL 按值拿走而不是借用。
    let url = base_url.to_string();
    let probe: Arc<dyn Fn(&str) -> bool + Send + Sync> =
        Arc::new(move |name: &str| probe(&url, Some(name)));
    race_with(candidates, probe)
}

/// 竞速本身，探针注入进来是为了能脱开网络测。
fn race_with(
    candidates: &[String],
    probe: Arc<dyn Fn(&str) -> bool + Send + Sync>,
) -> Option<String> {
    match candidates.len() {
        0 => None,
        // 只有一条链路就没得选：探它不会改变答案，别让调用方白等一个来回。
        // 「只有蜂窝」和「只有 WiFi」就是这种情况。
        1 => Some(candidates[0].clone()),
        _ => {
            let (tx, rx) = mpsc::channel();
            for name in candidates {
                let tx = tx.clone();
                let name = name.clone();
                let probe = Arc::clone(&probe);
                std::thread::spawn(move || {
                    if probe(&name) {
                        let _ = tx.send(name);
                    }
                });
            }
            // 不 drop 的话，只要还有发送端的克隆活着，通道就不算关闭 —— 探针全
            // 失败的那种竞速会一直等到超时，而不是最后一个探针报完就返回。
            drop(tx);
            match rx.recv_timeout(PROBE_TIMEOUT + Duration::from_millis(200)) {
                Ok(winner) => {
                    log::info!(
                        "出口网卡竞速获胜: {winner}（候选: {}）",
                        candidates.join(",")
                    );
                    Some(winner)
                }
                // 谁都没答话。这时候宁可不绑，也不要硬钉一条刚刚证明打不通的链路 ——
                // 绑上去就回到起点了（卡在一条不扛流量的 WiFi 上），不绑的话至少
                // 系统还能自己跟着网络走。
                Err(_) => {
                    log::warn!(
                        "没有网卡答话，这次不绑定，交给系统默认路由（候选: {}）",
                        candidates.join(",")
                    );
                    None
                }
            }
        }
    }
}

/// 当前持有 IPv4 地址的接口，取自 `/proc/net/route`（跳过表头）。
fn ifaces_with_ipv4() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let Ok(text) = std::fs::read_to_string("/proc/net/route") else {
        return names;
    };
    for line in text.lines().skip(1) {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        if !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// 虚拟设备、隧道、桥、回环、dummy，以及各家 VPN 自己开的接口。
fn is_virtual_iface(name: &str) -> bool {
    const VIRTUAL: &[&str] = &[
        "lo",
        "dummy",
        "tun",
        "tap",
        "ppp",
        "sit",
        "ip6",
        "ip_",
        "gre",
        "gretap",
        "erspan",
        "ifb",
        "p2p",
        "r_rmnet",
        "veth",
        "br",
        "bond",
        "vlan",
        "nrm",
        "rmnet_ipa",
        // B 这台机器上实测到的厂商隧道：`vgate0` 跟在默认路由后面、真挂了的时候
        // 就是它把包吞了，`ovnet*` / `wondertap*` 同族。名字排掉，别让探针去替
        // 隧道背书。
        "vgate",
        "ovnet",
        "wondertap",
    ];
    VIRTUAL.iter().any(|prefix| name.starts_with(prefix))
}

/// 物理链路之间的偏好：有线 > WiFi > 蜂窝 > 其它。跟 Android 自己的排序一致。
fn uplink_rank(name: &str) -> u8 {
    if name.starts_with("eth") {
        0
    } else if name.starts_with("wlan") {
        1
    } else if name.starts_with("rmnet") || name.starts_with("ccmni") || name.starts_with("pdp") {
        2
    } else {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn config_values_are_classified_as_documented() {
        assert_eq!(classify_bind_iface(""), BindChoice::Auto);
        assert_eq!(classify_bind_iface(" auto "), BindChoice::Auto);
        assert_eq!(classify_bind_iface("none"), BindChoice::Never);
        assert_eq!(classify_bind_iface("OFF"), BindChoice::Never);
        assert_eq!(classify_bind_iface("always"), BindChoice::Always);
        assert_eq!(classify_bind_iface("On"), BindChoice::Always);
        assert_eq!(
            classify_bind_iface("wlan0"),
            BindChoice::Named("wlan0".to_string())
        );
    }

    #[test]
    fn a_literal_name_is_taken_at_face_value() {
        // 写死的名字不探、不改：能不能用是内核的事。
        assert_eq!(
            desired_iface("ccmni0", "http://1.2.3.4:10886"),
            Some("ccmni0".to_string())
        );
    }

    #[test]
    fn never_binds() {
        assert_eq!(desired_iface("none", "http://1.2.3.4:10886"), None);
        assert_eq!(desired_iface("off", ""), None);
    }

    /// B 端最要紧的一条：`vgate0` 是厂商隧道，它查得到 IPv4 路由，绝不能当候选。
    #[test]
    fn vendor_tunnels_are_not_uplinks() {
        for n in [
            "vgate0",
            "ovnet0",
            "wondertap0",
            "tun0",
            "tap0",
            "ppp0",
            "dummy0",
            "lo",
            "ifb0",
            "p2p0",
            "ip6tnl0",
            "gre0",
        ] {
            assert!(is_virtual_iface(n), "{n} 不该被当成物理出口");
        }
        for n in ["wlan0", "eth0", "rmnet_data0", "ccmni0"] {
            assert!(!is_virtual_iface(n), "{n} 是正经出口");
        }
    }

    #[test]
    fn ranking_prefers_wired_then_wifi_then_cellular() {
        assert!(uplink_rank("eth0") < uplink_rank("wlan0"));
        assert!(uplink_rank("wlan0") < uplink_rank("rmnet_data0"));
        assert_eq!(uplink_rank("ccmni0"), uplink_rank("rmnet_data0"));
        assert!(uplink_rank("rmnet_data0") < uplink_rank("somethingelse0"));
    }

    #[test]
    fn the_probe_goes_to_the_liveness_endpoint() {
        assert_eq!(
            probe_url("http://1.2.3.4:10886"),
            "http://1.2.3.4:10886/api/ping/"
        );
        assert_eq!(
            probe_url("http://1.2.3.4:10886/"),
            "http://1.2.3.4:10886/api/ping/"
        );
    }

    #[test]
    fn the_faster_uplink_wins_the_race() {
        let slow = Arc::new(AtomicUsize::new(0));
        let slow2 = Arc::clone(&slow);
        let probe = Arc::new(move |name: &str| {
            if name == "slow0" {
                slow2.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(300));
                true
            } else {
                true
            }
        });
        let got = race_with(
            &["slow0".to_string(), "fast0".to_string()],
            probe as Arc<dyn Fn(&str) -> bool + Send + Sync>,
        );
        assert_eq!(got, Some("fast0".to_string()));
    }

    #[test]
    fn a_single_candidate_is_not_probed() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&calls);
        let probe = Arc::new(move |_: &str| {
            c2.fetch_add(1, Ordering::SeqCst);
            false
        });
        let got = race_with(
            &["wlan0".to_string()],
            probe as Arc<dyn Fn(&str) -> bool + Send + Sync>,
        );
        assert_eq!(got, Some("wlan0".to_string()));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "只有一条链路时不该白跑一趟探针"
        );
    }

    #[test]
    fn nobody_answering_leaves_the_socket_unbound() {
        let probe = Arc::new(|_: &str| false);
        let got = race_with(
            &["wlan0".to_string(), "ccmni0".to_string()],
            probe as Arc<dyn Fn(&str) -> bool + Send + Sync>,
        );
        assert_eq!(got, None, "全都不通就不绑，别钉死一条死链路");
    }

    #[test]
    fn a_malformed_url_is_not_treated_as_a_dead_link() {
        // URL 没配好是配置问题，不是「网卡不通」；别因此把所有出口都刷掉。
        assert!(probe("", Some("wlan0")));
        assert!(probe("110.40.170.96:10886", Some("wlan0")));
    }

    /// 拿真设备的状态过一遍：候选里不能出现虚拟设备，也不能出现没有 IPv4 路由
    /// 的接口。在开发机上没这些文件，这条会空跑过去。
    #[test]
    fn candidates_are_real_uplinks_with_ipv4() {
        let cands = uplink_candidates();
        eprintln!("候选出口: {cands:?}");
        let with_ip = ifaces_with_ipv4();
        for c in &cands {
            assert!(!is_virtual_iface(c), "{c} 是虚拟设备，不该当候选");
            assert!(with_ip.contains(c), "{c} 没有 IPv4 路由，绑上去也没用");
        }
        let mut sorted = cands.clone();
        sorted.sort_by_key(|n| uplink_rank(n));
        assert_eq!(cands, sorted, "候选应该按偏好排好序");
    }
}
