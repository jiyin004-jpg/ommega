//! 出口网卡：把去 relay 的请求钉在一条真能通的物理链路上。
//!
//! VPN 起来后系统会把普通流量塞进隧道，连去我们自己服务端的那份也被抓走。唯一能把
//! socket 从隧道里摘出来的办法是点名出口设备（`SO_BINDTODEVICE`，reqwest 的
//! `.interface()`）。判断口径必须与 A 端 `remote.rs` 一致。
//!
//! 一个网卡名字都不认：候选是当前握着 IPv4 路由的接口（`/proc/net/route`），是不是
//! 真网卡只看内核描述（`/sys/class/net/<n>/device`、链路层 `type`），谁能用由探针定。
//!
//! 缓存由调用方负责（见 [`desired_iface`]）：B 端一秒几百个请求，每条都探等于把流量
//! 翻倍。`bind_iface` 默认 `auto`：先试系统默认路由，通了不绑；`none` 永不绑；
//! `always` 总是挑；也可以直接写网卡名。

use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;

/// 一条候选链路答话的时间上限。短是为了从死链路上快点跑开。
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// 存活探针路径与答复体。`/api/ping/` 无状态、固定回 `pong`，答复体可确认对端是
/// 我们的服务端；探 `/` 会让运营商门户的 200 也算通。
const PING_PATH: &str = "/api/ping/";
const PING_BODY: &str = "pong";

const SYS_CLASS_NET: &str = "/sys/class/net";

/// `bind_iface` 的配置值。
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

/// 这条请求该从哪个网卡出去，`None` 表示不绑、交给系统默认路由。
///
/// 没 VPN 且 `auto` 时直接不绑；有 VPN 先试系统默认路由，通了也不绑，打不通才挑
/// 一条，挑不到同样不绑。读文件不缓存，发探针的两条路径有缓存（见 [`PICK_TTL`]）。
pub fn desired_iface(bind_iface: &str, base_url: &str) -> Option<String> {
    let choice = classify_bind_iface(bind_iface);
    match &choice {
        // 这两种不用探，缓存也没意义。
        BindChoice::Never => return None,
        // 显式接口名先探再绑：名字写错或链路没起来时直接 bind 会弄断 poll 循环。
        // 探不通就退回自动挑一条。
        BindChoice::Named(name) => {
            if let Some(hit) = cached_pick(bind_iface, base_url) {
                return hit;
            }
            let picked = if probe(base_url, Some(name)) {
                Some(name.clone())
            } else {
                log::warn!("出口：配的 {name} 到不了 relay，自己挑一条");
                pick_uplink(base_url)
            };
            store_pick(bind_iface, base_url, picked.clone());
            return picked;
        }
        _ => {}
    }
    // 没 VPN 就不动；这一步只读文件，不必缓存。
    if choice == BindChoice::Auto && !vpn_present() {
        return None;
    }
    if let Some(hit) = cached_pick(bind_iface, base_url) {
        return hit;
    }
    let picked = match choice {
        BindChoice::Always => pick_uplink(base_url),
        // auto：系统默认那条先试，通了就不绑。
        _ if probe(base_url, None) => {
            log::info!("出口：系统默认那条路能到 relay，这次不绑网卡");
            None
        }
        _ => {
            log::warn!("出口：系统默认那条路到不了 relay，自己挑一条");
            pick_uplink(base_url)
        }
    };
    store_pick(bind_iface, base_url, picked.clone());
    match &picked {
        Some(name) => log::info!("出口：定下来绑 {name}（缓存 {PICK_TTL:?}，过后重挑）"),
        None => log::info!("出口：不绑，交给系统默认路由"),
    }
    picked
}

/// 上一次挑选的结论，连同算出它的配置与服务端地址。挑选要发探针，而
/// `desired_iface` 每个请求都会被问到，结论必须留一段时间。
static PICK_CACHE: Mutex<Option<CachedPick>> = Mutex::new(None);

struct CachedPick {
    bind_iface: String,
    base_url: String,
    iface: Option<String>,
    at: Instant,
}

/// 结论保留时间。链路断了最多等这么久就会重挑，再短等于没缓存。
///
/// 断网由两个机制兜：探测失败会重选；请求失败时 `reset_http_client()` 调
/// [`invalidate_pick`] 清这份缓存。
const PICK_TTL: Duration = Duration::from_secs(60);

/// 丢掉缓存结论，下次重新挑。调用方在「这条路刚证明打不通」时用。
pub fn invalidate_pick() {
    if let Ok(mut guard) = PICK_CACHE.lock() {
        *guard = None;
    }
}

fn cached_pick(bind_iface: &str, base_url: &str) -> Option<Option<String>> {
    let guard = PICK_CACHE.lock().ok()?;
    let cached = guard.as_ref()?;
    if cached.bind_iface == bind_iface
        && cached.base_url == base_url
        && cached.at.elapsed() < PICK_TTL
    {
        Some(cached.iface.clone())
    } else {
        None
    }
}

fn store_pick(bind_iface: &str, base_url: &str, iface: Option<String>) {
    if let Ok(mut guard) = PICK_CACHE.lock() {
        *guard = Some(CachedPick {
            bind_iface: bind_iface.to_string(),
            base_url: base_url.to_string(),
            iface,
            at: Instant::now(),
        });
    }
}

/// 现在有没有 VPN 起着。`VpnService` 留下的设备名是 `tun`（老 pptp/l2tp 是
/// `ppp`，桥接是 `tap`），这是 Android 通用约定。
///
/// 只看名字不够：`tunl0` / `ip6tnl0` 是内核常驻的隧道设备（down、无地址），还得查
/// `flags` 的 IFF_UP。漏判只是不绑，误判最多白花一次探针。
fn vpn_present() -> bool {
    // auto 模式下每笔请求都会问到；缓存 3 秒，VPN 起断最多晚 3 秒被发现。
    static CACHE: Mutex<Option<(bool, Instant)>> = Mutex::new(None);
    const TTL: Duration = Duration::from_secs(3);
    if let Ok(guard) = CACHE.lock() {
        if let Some((present, at)) = *guard {
            if at.elapsed() < TTL {
                return present;
            }
        }
    }
    let Ok(entries) = std::fs::read_dir(SYS_CLASS_NET) else {
        return false;
    };
    let present = entries.flatten().any(|e| {
        e.file_name()
            .to_str()
            .is_some_and(|n| is_vpn_name(n) && iface_is_up(n))
    });
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some((present, Instant::now()));
    }
    present
}

/// 名字像不像 VPN 隧道。
fn is_vpn_name(name: &str) -> bool {
    name.starts_with("tun") || name.starts_with("ppp") || name.starts_with("tap")
}

/// 接口是不是 up：`/sys/class/net/<name>/flags` 是十六进制串，最低位是 IFF_UP。
/// 读不到（SELinux 可能拒）就当 up —— 漏判 VPN 会退回可能已被抓死的默认路由。
fn iface_is_up(name: &str) -> bool {
    match std::fs::read_to_string(format!("{SYS_CLASS_NET}/{name}/flags")) {
        Ok(text) => u32::from_str_radix(text.trim().trim_start_matches("0x"), 16)
            .is_ok_and(|flags| flags & 0x1 != 0),
        Err(_) => true,
    }
}

/// 挑一条真能打到服务端的出口。挑不到就不绑，保留系统自己跟着网络走的能力。
fn pick_uplink(base_url: &str) -> Option<String> {
    let (preferred, rest) = candidates();
    if preferred.is_empty() && rest.is_empty() {
        log::warn!("没有接口握着 IPv4 路由，出口交给系统默认路由");
        return None;
    }
    // 两轮：先让物理链路竞速，全都不答话才退到隧道类接口。
    if let Some(winner) = race_uplink(&preferred, base_url) {
        return Some(winner);
    }
    if rest.is_empty() {
        return None;
    }
    log::warn!(
        "物理链路都没答话，退到其余接口再试一轮（候选: {}）",
        rest.join(",")
    );
    race_uplink(&rest, base_url)
}

/// 接口看起来是不是一块真网卡（而非隧道、网桥、dummy 这类）。
///
/// 不看名字，只看内核描述：`/sys/class/net/<n>/device` 有挂载点的是总线设备
/// （PCIe/SDIO/USB）；链路层 `type` 为 1（以太网）或 519（RAWIP，rmnet / ccmni
/// 报这个）。两个都读不到就当不是物理链路，只是落到第二轮，能不能用由探针定。
fn physical_like(name: &str) -> bool {
    let base = format!("{SYS_CLASS_NET}/{name}");
    if std::path::Path::new(&format!("{base}/device")).exists() {
        return true;
    }
    match std::fs::read_to_string(format!("{base}/type")) {
        Ok(t) => t.trim().parse::<u32>().is_ok_and(|n| n == 1 || n == 519),
        Err(_) => false,
    }
}

/// 现在握着 IPv4 路由的接口，分成两组：(看着像真网卡的，其余的)。
///
/// 只认 `/proc/net/route` 里出现过的接口：绑到没有路由的设备上等于绑个空壳。
/// `operstate` 为 `down` 的剔除，但读不到必须保留（某些 SELinux 域会拒）；蜂窝
/// `rmnet_data*` / `ccmni*` 报 `unknown`，所以 `unknown` 必须放行。
///
/// 组内按偏好排序（有线 > WiFi > 蜂窝 > 其它），只影响日志，不影响入选。
pub fn candidates() -> (Vec<String>, Vec<String>) {
    let with_ip = ifaces_with_ipv4();
    if with_ip.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let live: Vec<String> = with_ip
        .into_iter()
        .filter(|name| {
            let state = std::fs::read_to_string(format!("{SYS_CLASS_NET}/{name}/operstate"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            state.is_empty() || state == "up" || state == "unknown"
        })
        .collect();
    split_candidates(live, physical_like)
}

/// 所有候选，物理的排前面。给日志和测试用。
pub fn uplink_candidates() -> Vec<String> {
    let (mut preferred, rest) = candidates();
    preferred.extend(rest);
    preferred
}

/// 探针打哪儿。配的 URL 末尾带斜杠时不能拼出双斜杠。
pub fn probe_url(base_url: &str) -> String {
    format!("{}{PING_PATH}", base_url.trim_end_matches('/'))
}

/// 从 `iface` 出去（`None` 走系统默认路由）能不能真打到服务端。
///
/// 拿到 IPv4 地址不等于有可用路由：上游已挂的 WiFi 或运营商门户照样发 DHCP 租约。
/// 只有短请求能验：传输层失败算不通，答复体不是 `pong` 也算不通（中间有东西吞了）。
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

/// 让候选链路互相竞速，谁先答话用谁。上游已挂的链路自然不会答话，无需先排序或
/// 等缓存过期；输掉的探针只是被丢弃的 GET，阻塞请求也无需取消。
fn race_uplink(candidates: &[String], base_url: &str) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
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
        // 单条也要探：第一轮往往只有一条候选，不探就会钉在死链路上。
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
            // 不 drop 的话通道永不关闭，全失败的竞速会拖到超时而不是立即返回。
            drop(tx);
            match rx.recv_timeout(PROBE_TIMEOUT + Duration::from_millis(200)) {
                Ok(winner) => {
                    log::info!(
                        "出口网卡竞速获胜: {winner}（候选: {}）",
                        candidates.join(",")
                    );
                    Some(winner)
                }
                // 谁都没答话就宁可不绑，别硬钉一条刚证明打不通的链路。
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

/// 把候选按「像不像真网卡」分成两组，组内按偏好排序。判据由参数注入以便测试：
/// 开发机上没有 `/sys/class/net`，`physical_like` 一律返回 false。
fn split_candidates(
    live: Vec<String>,
    is_physical: impl Fn(&str) -> bool,
) -> (Vec<String>, Vec<String>) {
    let mut preferred: Vec<(u8, String)> = Vec::new();
    let mut rest: Vec<(u8, String)> = Vec::new();
    for name in live {
        let ranked = (uplink_rank(&name), name);
        if is_physical(&ranked.1) {
            preferred.push(ranked);
        } else {
            rest.push(ranked);
        }
    }
    preferred.sort();
    rest.sort();
    (
        preferred.into_iter().map(|(_, name)| name).collect(),
        rest.into_iter().map(|(_, name)| name).collect(),
    )
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
        assert_eq!(
            classify_bind_iface("ccmni0"),
            BindChoice::Named("ccmni0".to_string())
        );
    }

    #[test]
    fn never_binds() {
        assert_eq!(desired_iface("none", "http://1.2.3.4:10886"), None);
        assert_eq!(desired_iface("off", ""), None);
    }

    /// 名单不参与选卡：名字再怪，只要内核说是真网卡、探针能通，就该走它。
    #[test]
    fn candidate_grouping_only_asks_the_kernel() {
        let live: Vec<String> = ["vgate0", "wlan0", "rmnet_data3", "something0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // 假的判据：只有 wlan0 挂着 device。
        let (preferred, rest) = split_candidates(live, |n| n == "wlan0");
        assert_eq!(preferred, vec!["wlan0"]);
        // 剩下的一个都没丢，只是在第二轮。
        assert_eq!(rest, vec!["rmnet_data3", "something0", "vgate0"]);
    }

    #[test]
    fn host_without_sysfs_reports_nothing_physical() {
        // 开发机上没有 `/sys/class/net`；读不到就当不是物理链路，只落到第二轮。
        #[cfg(not(target_os = "android"))]
        assert!(!physical_like("wlan0"));
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
    fn a_single_candidate_is_probed_too() {
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
        assert_eq!(got, None, "一条也得探：探不着就不绑，比钉死一条死链路强");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "单条候选也要真探一次");
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

    /// 拿真设备状态过一遍：候选必须握着 IPv4 路由。开发机上这条会空跑过去。
    #[test]
    fn candidates_hold_ipv4_routes() {
        let cands = uplink_candidates();
        eprintln!("候选出口: {cands:?}");
        let with_ip = ifaces_with_ipv4();
        for c in &cands {
            assert!(with_ip.contains(c), "{c} 没握着 IPv4 路由，绑上去也用不上");
        }
    }
}
