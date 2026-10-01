//! 出口网卡：把 relay 的请求钉在一条真能通的物理链路上。
//!
//! 跟 A 端 `remote.rs` 里那套是同一份逻辑（两边分开实现，判断口径要求一致）：
//! VPN 起来之后系统会把普通流量塞进隧道（netd 把连接的 fwmark 指向 VPN 网络、
//! 默认路由落到 tun 上），去我们自己服务端的那一份也被一起抓走 —— 慢、抖，坏的
//! 时候干脆不通。唯一能把 socket 从隧道里摘出来的办法是点名出口设备
//! （`SO_BINDTODEVICE`，reqwest 的 `.interface()` 干的就是这个）。
//!
//! 跟 A 端不一样的地方：
//!
//! 1. 候选和「谁先答话」这套逻辑在这里是独立模块（A 端塞在 `remote.rs` 里），
//!    调用方负责缓存结果：B 端一秒能打几百个请求，每条都探一次等于把流量翻倍，
//!    缓存几秒、只在失败时重选就够用了。
//!
//! 关于「哪张卡能用」：一个名字都不认。候选就是当前握着 IPv4 路由的那些接口
//! （`/proc/net/route`），是不是真网卡只看内核对它的描述
//! （`/sys/class/net/<n>/device` 挂载点、`type` 链路层类型），谁能用最后由探针
//! 说了算。任何机型、插什么网卡都走同一条判断路径，不用照着机型补名单。
//!
//! `bind_iface` 默认是 `auto`：先试系统默认那条路，通了就不绑（一台正常机器到
//! 这儿就结束了，系统自己的「WiFi 断了切蜂窝」也留着）；默认那条打不通才去挑。
//! `none` 是永不绑，`always` 是总是挑，也可以直接写网卡名。

use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

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
/// 没 VPN 的时候什么都不动：不绑最省事，也把系统自己的「WiFi 掉了切蜂窝」留着 ——
/// 一台正常机器到这儿就结束了。有 VPN 才往下走：先试系统默认那条路，通了也不绑；
/// 只有默认那条打不通（VPN 把流量拓死、或者默认路由指向上游已经挂掉的链路）才
/// 自己挑一条。挑不到同样不绑，回系统默认。
///
/// 读文件那一步不缓存（便宜）；要发探针的那两步有缓存，见 [`PICK_TTL`]。
pub fn desired_iface(bind_iface: &str, base_url: &str) -> Option<String> {
    let choice = classify_bind_iface(bind_iface);
    match &choice {
        // 这两种不用探，缓存也没意义。
        BindChoice::Never => return None,
        BindChoice::Named(name) => return Some(name.clone()),
        _ => {}
    }
    // 没 VPN 就不动，而且这一步只看文件，不必缓存。
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

/// 上一次挑选的结论，以及它是对着哪份配置、哪个服务端地址算出来的。
///
/// 挑选要发探针，而 `desired_iface` 每个请求都会被问到（B 端一秒几百个）——
/// 结论留几秒，不然等于把流量翻倍。
static PICK_CACHE: Mutex<Option<CachedPick>> = Mutex::new(None);

struct CachedPick {
    bind_iface: String,
    base_url: String,
    iface: Option<String>,
    at: Instant,
}

/// 结论留多久。链路断了最多等这么久就会重挑，再短就等于没缓存。
const PICK_TTL: Duration = Duration::from_secs(5);

/// 把缓存的结论扔掉，下次重新挑。调用方在「这条路刚证明打不通」时用。
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

/// 现在有没有 VPN 起着。`VpnService` 一定会在 `/sys/class/net` 里留一个 `tun`
/// 设备，老的 pptp/l2tp 路径留 `ppp`，名字都是 `tun0` / `ppp0` 这种形状 —— 这是
/// Android 的通用约定，跟机型无关。
///
/// 它只决定「要不要开始挑」：漏判的后果跟没 VPN 一样（不绑），不会把链路选错；
/// 误判最多白花一次探针。
fn vpn_present() -> bool {
    let Ok(entries) = std::fs::read_dir(SYS_CLASS_NET) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name().to_str().is_some_and(|n| {
            n.starts_with("tun") || n.starts_with("ppp") || n.starts_with("tap")
        })
    })
}

/// 挑一条真能打到服务端的出口。挑不到就不绑 —— 硬钉一条刚证明打不通的链路，
/// 等于把「系统自己跟着网络走」这点能力也丢掉。
fn pick_uplink(base_url: &str) -> Option<String> {
    let (preferred, rest) = candidates();
    if preferred.is_empty() && rest.is_empty() {
        log::warn!("没有接口握着 IPv4 路由，出口交给系统默认路由");
        return None;
    }
    // 两轮：先让「看着像真网卡」的互相竞速，它们全都不答话才退到隧道那一类。
    // 有条条路可选时优先走物理链路，而不是谁答话快就听谁的。
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

/// 这块接口看起来是不是一块真网卡（而不是隧道、网桥、dummy 这类东西）。
///
/// 不看名字 —— 名字是厂商和内核版本随口起的，`vgate0` 这种隧道谁也不会预先
/// 知道。只看内核对它的描述：
///
/// - `/sys/class/net/<n>/device` 有挂载点的是挂在总线上的真设备（PCIe/SDIO/USB）；
///   tun / dummy / 网桥 / vlan 这类都没有。
/// - 链路层类型 `type` 是 1（以太网）或 519（RAWIP，蜂窝 rmnet / ccmni 报这个）。
///
/// 两个都读不到（SELinux 在有的域下会拒）就当它不是物理链路：那只是让它落到
/// 第二轮，漏不了 —— 能不能用最终还是探针说了算。
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
/// 一个接口得出现在 `/proc/net/route` 里才有意义 —— 那说明它当前真的扛着一条
/// IPv4 路由；绑到一个没有路由的设备上等于绑了个空壳。这里一个名字都不排：
/// 名单式的过滤换个机型就会漏掉真出口，能不能用交给探针。
///
/// `operstate` 看不顺眼的不算（`down` 这种），但 **读不到不算** —— 某些 SELinux
/// 域下会被拒，而 `/proc/net/route` 已经证明它扛着 IPv4 路由了。蜂窝
/// （`rmnet_data*` / `ccmni*`）报文报 `unknown`，所以 `unknown` 必须放行。
///
/// 两组内部按偏好排序（有线 > WiFi > 蜂窝 > 其它），只是让日志好读，不影响入选。
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
        // 单条也要探。两轮挑卡里，第一轮往往就一条候选，不探的话它就算死了
        // 也会被选中 —— 白白钉在一条打不通的链路上。
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

/// 把候选按「像不像真网卡」分成两组，组内按偏好排序。
///
/// 单独拎出来是为了能注一个假的判据进去测：开发机上没 `/sys/class/net`，
/// `physical_like` 一律返回 false，分组逻辑就测不着了。
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

    /// 名单不再参与选卡：名字长得再怪，只要内核说它像真网卡、探针能打通，就该走它。
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
        // 开发机上没有 `/sys/class/net`；读不到就当不是物理链路，它只是落到第二轮。
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

    /// 拿真设备的状态过一遍：候选必须握着 IPv4 路由。开发机上没这些文件，
    /// 这条会空跑过去。
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
