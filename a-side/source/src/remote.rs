// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Remote TEE relay client (A-side).
//!
//! When `[remote].enabled` is set in `config.toml`, attestation / sign / decrypt
//! for A-side keys are forwarded to the relay_server (and from there to a B-side
//! real hardware TEE).  This module uses `reqwest::blocking::Client` to talk to
//! the relay_server API, mirroring the protocol used by the B-side relay agent
//! (`ommegaclient-b`).
//!
//! The relay_server uses a self-signed certificate by default, so
//! `tls_insecure` (default true) accepts any server certificate — matching the
//! B-side client behaviour.
//!
//! One long-lived reqwest client is kept in a cache and picked per request from
//! the current `tls_insecure` config value and the outgoing interface the
//! traffic should use (see `desired_iface`).  The client carries its own internal
//! connection pool, so concurrent requests are not serialised through a single
//! Mutex — fixing the previous single-connection pool bottleneck.  reqwest also
//! natively supports chunked transfer encoding and HTTP keep-alive, both of which
//! the hand-written client did not.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use reqwest::blocking::Client;
use reqwest::Method;
use serde_json::{json, Value};

use crate::config;

const CONNECT_TIMEOUT_MS: u64 = 3000;
const READ_TIMEOUT_MS: u64 = 30_000;

/// A relay-server client.  All configuration is read from `config().remote`.
pub struct RemoteRelay;

// ── reqwest client management ──────────────────────────────────────────

/// A cached client together with the inputs it was built from.
///
/// The interface is part of the identity because it follows VPN state: pinning
/// it in a `OnceLock` the way `tls_insecure` used to be pinned would freeze
/// whatever was decided the first time a request went out.
struct CachedClient {
    insecure: bool,
    iface: Option<String>,
    client: Client,
}

/// The connection pool.  Rebuilt only when `tls_insecure` or the chosen
/// interface changes; otherwise the same client (and its pool) is reused.
static CLIENT_CACHE: Mutex<Option<CachedClient>> = Mutex::new(None);

/// Returns a reqwest blocking client for the current `tls_insecure` setting and
/// the interface traffic should leave from.
fn get_client() -> Result<Client> {
    // Snapshot just the fields we need.  Picking an interface can probe the
    // candidate links, which blocks for up to `PROBE_TIMEOUT` per candidate, and
    // that must not happen while the config lock is held.
    let (insecure, bind_iface, base_url) = {
        let guard = config::config()
            .read()
            .map_err(|_| anyhow!("config lock poisoned"))?;
        (
            guard.remote.tls_insecure,
            guard.remote.bind_iface.clone(),
            guard.remote.url.clone(),
        )
    };
    let iface = desired_iface(&bind_iface, &base_url);

    let mut slot = CLIENT_CACHE
        .lock()
        .map_err(|_| anyhow!("client cache lock poisoned"))?;

    if let Some(cached) = slot.as_ref() {
        if cached.insecure == insecure && cached.iface == iface {
            return Ok(cached.client.clone());
        }
    }

    if let Some(name) = iface.as_deref() {
        log::info!("relay traffic bound to interface {name}");
    }
    let client = build_client(insecure, iface.as_deref());
    *slot = Some(CachedClient {
        insecure,
        iface,
        client,
    });

    Ok(slot
        .as_ref()
        .expect("client was just stored")
        .client
        .clone())
}

fn build_client(insecure: bool, iface: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .timeout(Duration::from_millis(READ_TIMEOUT_MS))
        .user_agent("ommegaclient-a/1.3");

    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }

    if let Some(name) = iface {
        // `SO_BINDTODEVICE`: pin the socket to a physical uplink so the routing
        // rules that steer traffic into a VPN tunnel do not capture it.
        builder = builder.interface(name);
    }

    builder
        .build()
        .expect("failed to build reqwest blocking client")
}

// ── outgoing interface selection ───────────────────────────────────────

/// What the `bind_iface` config value means.
#[derive(Debug, PartialEq, Eq)]
enum BindChoice {
    /// `none` / `off` — never bind.
    Never,
    /// Empty or `auto` (the default) — try the OS default route first, bind only
    /// when that route cannot reach the relay.
    Auto,
    /// `always` / `on` — always look for an uplink to bind to.
    Always,
    /// A literal interface name, used as given.
    Named(String),
}

fn classify_bind_iface(raw: &str) -> BindChoice {
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

const SYS_CLASS_NET: &str = "/sys/class/net";

/// Decides which interface (if any) this request should leave from.
///
/// Why bind at all: with a VPN up, the OS steers ordinary traffic into the
/// tunnel — netd points the connection's fwmark at the VPN network and the
/// default route ends up on `tun`.  Traffic to our own relay server gets caught
/// by the same rules, so it goes through the tunnel too: slower, jittery, and in
/// the bad cases simply unreachable.  The only way to keep a socket out of that
/// is to name its outgoing device (`SO_BINDTODEVICE`, which is what reqwest's
/// `.interface()` sets).
///
/// With no VPN up nothing is touched at all: an unbound socket interferes least
/// and keeps the OS's own "WiFi dropped, fall back to cellular" switching, so a
/// healthy machine is finished right there.  With a VPN the system default route
/// is tried first — if the relay answers over it, nothing is bound either; only
/// when that route cannot reach the relay (the VPN swallowed the traffic, or the
/// default route points at a dead upstream) is an uplink picked.  Nothing usable
/// leaves the socket unbound as well.
///
/// The file-reading step is not cached (it is cheap); the steps that send probes
/// are, see `PICK_TTL`.
fn desired_iface(bind_iface: &str, base_url: &str) -> Option<String> {
    let choice = classify_bind_iface(bind_iface);
    match &choice {
        // These two need no probe, so there is nothing to cache.
        BindChoice::Never => return None,
        // An explicit name is taken at face value: whether it exists or works is
        // the kernel's call, not ours.
        BindChoice::Named(name) => return Some(name.clone()),
        _ => {}
    }
    if choice == BindChoice::Auto && !vpn_present() {
        return None;
    }
    if let Some(hit) = cached_pick(bind_iface, base_url) {
        return hit;
    }
    let picked = match choice {
        BindChoice::Always => pick_uplink(base_url),
        // `auto`: try the OS default route first; only a route that cannot reach
        // the relay is worth overriding.
        _ if probe_iface(None, base_url) => {
            log::info!("uplink: the OS default route reaches the relay, nothing bound");
            None
        }
        _ => {
            log::warn!("uplink: the OS default route cannot reach the relay, picking one");
            pick_uplink(base_url)
        }
    };
    store_pick(bind_iface, base_url, picked.clone());
    match &picked {
        Some(name) => log::info!("uplink: settled on {name} (cached for {PICK_TTL:?})"),
        None => log::info!("uplink: unbound, using the OS default route"),
    }
    picked
}

/// A cached pick, and what it was computed from.
///
/// Picking sends probes, and `desired_iface` is asked on every request — holding
/// the answer for a few seconds is what stops that from doubling the traffic.
static PICK_CACHE: Mutex<Option<CachedPick>> = Mutex::new(None);

struct CachedPick {
    bind_iface: String,
    base_url: String,
    iface: Option<String>,
    at: Instant,
}

/// How long a pick is trusted.  A link that dies is re-picked after at most this
/// long; much shorter and the cache does nothing.
const PICK_TTL: Duration = Duration::from_secs(5);

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

/// Whether a VPN is currently up.  `VpnService` always leaves a `tun` device in
/// `/sys/class/net` and the older pptp/l2tp paths leave a `ppp`; the names are
/// always `tun0` / `ppp0` shaped — an Android-wide convention, not something that
/// varies per device model.
///
/// It only decides whether picking starts: missing one means "behave like there
/// is no VPN" (nothing is bound), never a wrong link, and a false positive costs
/// at most one extra probe.
fn vpn_present() -> bool {
    let Ok(entries) = std::fs::read_dir(SYS_CLASS_NET) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("tun") || n.starts_with("ppp") || n.starts_with("tap"))
    })
}

/// Picks an uplink that can actually reach the relay.  Nothing usable leaves the
/// socket unbound — pinning one that just proved it cannot carry traffic would
/// throw away the OS's own ability to follow the network.
fn pick_uplink(base_url: &str) -> Option<String> {
    let (preferred, rest) = candidates();
    if preferred.is_empty() && rest.is_empty() {
        log::warn!("no interface holds an IPv4 route; leaving the socket unbound");
        return None;
    }
    // Two rounds: the interfaces that look like real NICs race first, and only
    // when none of them answers does the rest (tunnels, vendor devices) get a
    // turn.  With more than one usable path that prefers physical links over
    // whichever one happens to answer first.
    if let Some(winner) = race_uplink(&preferred, base_url) {
        return Some(winner);
    }
    if rest.is_empty() {
        return None;
    }
    log::warn!(
        "no physical-looking uplink answered; trying the rest ({})",
        rest.join(",")
    );
    race_uplink(&rest, base_url)
}

/// Whether this interface looks like a real network card rather than a tunnel,
/// bridge or dummy device.
///
/// Names are never consulted: they are whatever the vendor and the kernel felt
/// like calling things, and nobody can pre-list a vendor tunnel such as
/// `vgate0`.  What the kernel says about the device is what counts:
///
/// - `/sys/class/net/<n>/device` exists only for devices hanging off a bus
///   (PCIe / SDIO / USB); tun, dummy, bridges and vlan interfaces have none.
/// - The link-layer `type` is 1 (ethernet) or 519 (RAWIP, which cellular
///   `rmnet` / `ccmni` report).
///
/// Both unreadable (SELinux denies them in some domains) counts as "not
/// physical": that only pushes the device to the second round, it is never
/// dropped — the reachability probe has the final say either way.
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

/// The relay's liveness endpoint, and the body it answers with.
///
/// `/api/ping/` returns a fixed `pong` without touching any state, which makes it
/// the right probe target: cheap enough to hit while picking an interface, and
/// its body identifies the relay.  Probing `/` instead would accept any HTTP
/// answer, including one from a captive portal or a carrier interstitial that
/// swallowed the request.
const PING_PATH: &str = "/api/ping/";
const PING_BODY: &str = "pong";

/// How long a single reachability probe may take before that interface is
/// written off.
const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// Where a reachability probe goes.  A trailing slash on the configured URL must
/// not double up.
fn probe_url(base_url: &str) -> String {
    format!("{}{PING_PATH}", base_url.trim_end_matches('/'))
}

/// Whether traffic sent through `iface` actually reaches the relay server.
///
/// Holding an IPv4 address is not the same as having a working route.  A phone
/// joined to a WiFi network whose upstream is down — or stuck behind a captive
/// portal — still gets a DHCP lease, so `wlan0` looks perfectly healthy while
/// everything sent through it disappears.  Ranking by name alone then picks
/// WiFi forever and forwarding is dead until the user finds a working network.
///
/// A short request is the only honest test, and the endpoint answers a known
/// body: a transport failure means the interface cannot carry the request, while
/// an answer that is not `pong` means something in between swallowed it.
///
/// `None` probes whichever route the OS picks on its own — the "does the default
/// path reach the relay at all" question that decides whether anything has to be
/// bound.
fn probe_iface(iface: Option<&str>, base_url: &str) -> bool {
    // Nothing to probe against (unconfigured or malformed URL) — do not turn a
    // configuration problem into "no interface works".
    if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
        return true;
    }
    let mut builder = Client::builder()
        .no_proxy()
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        // The probe only asks whether packets get there; a certificate problem
        // is not a routing problem.
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

/// Races the candidate uplinks against each other and returns whichever one
/// answers the probe first.
///
/// Racing rather than ranking is what makes the choice self-correcting: a WiFi
/// link whose upstream died simply never answers, so it loses on its own —
/// nobody has to notice it is dead and nobody waits for a cached decision to
/// expire.  The losers' probes only ever send a harmless GET and are dropped;
/// a blocking request cannot be cancelled, and none is needed.
///
/// Only the probe races.  The real request still goes out exactly once, over the
/// winner: attestation is not idempotent, and sending it down both links would
/// make the B-side TEE do the work twice.
fn race_uplink(candidates: &[String], base_url: &str) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    // The closure must be `'static` to move into the probe threads, so the URL is
    // captured by value instead of borrowed.
    let url = base_url.to_string();
    let probe: Arc<dyn Fn(&str) -> bool + Send + Sync> =
        Arc::new(move |name: &str| probe_iface(Some(name), &url));
    race_with(candidates, probe)
}

/// The racing itself, with the probe injected so it can be tested without a
/// network.
fn race_with(
    candidates: &[String],
    probe: Arc<dyn Fn(&str) -> bool + Send + Sync>,
) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }

    let (tx, rx) = std::sync::mpsc::channel();
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
    // Without this the channel would stay open as long as any clone of the
    // sender lives, so a race where every probe fails would block for the full
    // timeout instead of returning as soon as the last probe reports.
    drop(tx);
    match rx.recv_timeout(PROBE_TIMEOUT + Duration::from_millis(200)) {
        Ok(winner) => {
            log::info!(
                "relay uplink race won by {winner} (candidates: {})",
                candidates.join(",")
            );
            Some(winner)
        }
        // Nothing answered.  Leave the socket unbound rather than pinning a link
        // that just failed to reach the relay: binding one anyway would put us
        // back where this started — stuck on a WiFi link that carries nothing —
        // and an unbound socket at least lets the OS follow the network.  This
        // also covers a `url` that resolves through the tunnel (Clash fake-IP),
        // where no physical link can ever answer.
        Err(_) => {
            log::warn!(
                "no uplink answered a probe; leaving the socket unbound (candidates: {})",
                candidates.join(",")
            );
            None
        }
    }
}

/// The interfaces currently holding an IPv4 address, as listed in
/// `/proc/net/route` (header row skipped).
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

/// The interfaces that hold an IPv4 route right now, split into (looks like a
/// real NIC, everything else), each group best first.
///
/// An interface has to appear in `/proc/net/route` to count at all: that is what
/// proves it currently carries an IPv4 route, and binding to a device without
/// one means binding to an empty shell.  No name is filtered here — a name list
/// goes stale the moment another vendor shows up, and a missed real uplink is a
/// worse failure than an extra probe.  Reachability is decided by `probe_iface`.
///
/// `operstate` that says `down` is skipped, but an *unreadable* one is not
/// (SELinux denies it in some domains): `/proc/net/route` already proved the
/// route exists.  Cellular interfaces report `unknown`, so that value has to
/// pass too.
fn candidates() -> (Vec<String>, Vec<String>) {
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

/// Splits candidates by "does it look physical", best first inside each group.
///
/// Separate from `candidates` so a test can inject its own verdict: a dev box has
/// no `/sys/class/net`, so `physical_like` is false for everything there.
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

/// Preference among physical uplinks: wired, then WiFi, then cellular, then
/// anything else.  Matches how Android itself ranks networks.  This only orders
/// the log output; which link is used is still decided by the probe race.
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

/// Minimal HTTP(S) request helper backed by reqwest.
///
/// Returns `(status, body)`.  HTTP error responses (4xx / 5xx) are returned as
/// `Ok` with the corresponding status code — only transport-level failures
/// produce `Err`.  This matches the original hand-written client contract so
/// callers (`post_json` and its retry logic) behave identically.
fn http_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>)> {
    let client = get_client()?;
    let method = method
        .parse::<Method>()
        .map_err(|e| anyhow!("invalid HTTP method {method}: {e}"))?;

    let mut req = client.request(method, url);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    if let Some(b) = body {
        req = req.body(b.to_vec());
    }

    let resp = req
        .send()
        .with_context(|| format!("HTTP request to {url}"))?;

    let status = resp.status().as_u16();
    let body_bytes = resp
        .bytes()
        .with_context(|| format!("reading response body from {url}"))?
        .to_vec();

    Ok((status, body_bytes))
}

// ── RemoteRelay public API ─────────────────────────────────────────────

impl RemoteRelay {
    fn remote() -> Result<config::RemoteConfig> {
        let guard = config::config()
            .read()
            .map_err(|_| anyhow!("config lock poisoned"))?;
        Ok(guard.remote.clone())
    }

    fn base_url() -> Result<String> {
        let r = Self::remote()?;
        if !r.enabled {
            return Err(anyhow!("remote relay not enabled"));
        }
        if r.url.is_empty() {
            return Err(anyhow!("remote url not configured"));
        }
        Ok(r.url.trim_end_matches('/').to_string())
    }

    fn token() -> Result<String> {
        let r = Self::remote()?;
        if r.token.is_empty() {
            return Err(anyhow!("remote token not configured"));
        }
        Ok(r.token)
    }

    fn device_id() -> Result<String> {
        let r = Self::remote()?;
        if r.device_id.is_empty() {
            return Err(anyhow!("remote device_id not configured"));
        }
        Ok(r.device_id)
    }

    /// POST a JSON body to a relay endpoint.  Returns `Ok(Some(json))` on 2xx
    /// with a JSON body, `Ok(None)` if the remote is unreachable/non-2xx.
    fn post_json(path: &str, body: &Value) -> Result<Option<Value>> {
        let url = format!("{}{}", Self::base_url()?, path);
        let body_str = serde_json::to_string(body)?;
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Relay-Token".to_string(), Self::token()?),
        ];
        // Transient transport failures (connect timeout, network jitter, TLS
        // handshake) are retried once before giving up. Without the retry a
        // single dropped attempt falls back to the local software keybox and
        // briefly emits a self-signed chain. HTTP error responses are NOT
        // retried — the server answered, and its body carries the real result.
        let (status, resp) = match http_request("POST", &url, &headers, Some(body_str.as_bytes())) {
            Ok(v) => v,
            Err(first) => {
                log::warn!("remote {path} transport error, retrying once: {first:#}");
                http_request("POST", &url, &headers, Some(body_str.as_bytes()))
                    .map_err(|second| anyhow!("{first:#}; retry also failed: {second:#}"))?
            }
        };
        if !(200..300).contains(&status) {
            log::warn!("remote {path} HTTP {status}");
            return Ok(None);
        }
        if resp.is_empty() {
            return Ok(None);
        }
        // A 2xx response that is not JSON is a server/protocol error, not
        // "remote unavailable" — surface it loudly instead of silently falling
        // back to the local software keybox (which would emit a self-signed
        // chain and hide the real failure).
        serde_json::from_slice(&resp)
            .map(Some)
            .map_err(|e| anyhow!("relay returned malformed JSON (status {status}): {e}"))
    }

    /// Forward an attestation request.  `challenge` is the caller's nonce.
    pub fn attest(
        challenge: &[u8],
        alias: &str,
        app_id_der: &[u8],
        params: &kmr_ta::device::RemoteAttestParams,
        cert_serial: Option<&[u8]>,
    ) -> Result<Option<Value>> {
        let mut ctx = serde_json::Map::new();
        ctx.insert(
            "attestation_application_id".to_string(),
            Value::String(base64_encode(app_id_der)),
        );
        // Use the device's real verified-boot key/hash from the resolved trust
        // config (client-a forwards `AndroidDeviceUtils.bootKey/bootHash`).
        let (vb_key, vb_hash) = Self::verified_boot_values();
        ctx.insert(
            "verified_boot_key".to_string(),
            Value::String(base64_encode(&vb_key)),
        );
        ctx.insert(
            "verified_boot_hash".to_string(),
            Value::String(base64_encode(&vb_hash)),
        );
        ctx.insert("device_locked".to_string(), Value::Bool(true));
        ctx.insert("verified_boot_state".to_string(), Value::from(0));
        ctx.insert(
            "creation_datetime_ms".to_string(),
            Value::from(Self::now_ms()),
        );
        // Forward the app's key-generation parameters (mirroring client-a) so
        // the B-side TEE mints a key matching the request, not an EC-P256 default.
        if let Some(algo) = params.key_algorithm {
            ctx.insert("key_algorithm".to_string(), Value::from(algo));
        }
        if let Some(size) = params.key_size {
            ctx.insert("key_size".to_string(), Value::from(size));
        }
        if let Some(curve) = params.ec_curve {
            ctx.insert("ec_curve".to_string(), Value::from(curve));
        }
        if !params.purpose.is_empty() {
            ctx.insert(
                "purpose".to_string(),
                Value::Array(params.purpose.iter().copied().map(Value::from).collect()),
            );
        }
        if !params.digest.is_empty() {
            ctx.insert(
                "digest".to_string(),
                Value::Array(params.digest.iter().copied().map(Value::from).collect()),
            );
        }
        if !params.padding.is_empty() {
            ctx.insert(
                "padding".to_string(),
                Value::Array(params.padding.iter().copied().map(Value::from).collect()),
            );
        }
        if let Some(mgf) = params.mgf_digest {
            ctx.insert("mgf_digest".to_string(), Value::from(mgf));
        }
        if let Some(exponent) = params.rsa_public_exponent {
            ctx.insert("rsa_public_exponent".to_string(), Value::from(exponent));
        }
        if let Some(subject) = &params.certificate_subject {
            ctx.insert(
                "certificate_subject".to_string(),
                Value::String(base64_encode(subject)),
            );
        }
        if let Some(not_before) = params.certificate_not_before_ms {
            ctx.insert(
                "certificate_not_before_ms".to_string(),
                Value::from(not_before),
            );
        }
        if let Some(not_after) = params.certificate_not_after_ms {
            ctx.insert(
                "certificate_not_after_ms".to_string(),
                Value::from(not_after),
            );
        }
        if let Some(serial) = cert_serial {
            ctx.insert(
                "certificate_serial".to_string(),
                Value::String(base64_encode(serial)),
            );
        }
        // Forward the requesting security level (1 = TEE, 2 = StrongBox) so the
        // relay tags the attestation extension the same way the A-side reported
        // it. Without this a STRONGBOX request minted remotely is mislabelled as
        // TEE (the relay's `attestation_security_level` default is 1).
        if let Some(security_level) = params.security_level {
            ctx.insert(
                "attestation_security_level".to_string(),
                Value::from(i64::from(security_level)),
            );
        }
        // User-authentication / authorization-list entries the app asked for, as
        // `[tag, value]` pairs (502/503/504/505/506/507/508/509; the value is
        // only meaningful for 504 USER_AUTH_TYPE and 505 AUTH_TIMEOUT, the rest
        // are presence markers). The A-side software KeyMint does enforce the
        // policy locally, but the *attestation* is minted remotely, so the
        // entries have to travel with the request: a leaf that says
        // `NO_AUTH_REQUIRED` for a key created with
        // `setUserAuthenticationRequired(true)` contradicts itself, and one
        // without `USER_AUTH_TYPE`/`AUTH_TIMEOUT` drops the policy — both are
        // detectable from an app (TrustAttestor:
        // `hardware.attestation.user_auth_metadata` / `user_auth_policy`).
        // The server keybox layer writes every tag here except 502 (AOSP emits
        // the SID for `importWrappedKey()` only); the B-side real TEE needs 502
        // as well.
        if !params.user_auth.is_empty() {
            ctx.insert(
                "user_auth".to_string(),
                Value::Array(
                    params
                        .user_auth
                        .iter()
                        .map(|(tag, value)| json!([*tag, *value]))
                        .collect(),
                ),
            );
        }
        // Forward the device's OS version + security patch level so the relay
        // can emit KM_TAG_OS_VERSION (705) / KM_TAG_OS_PATCH_LEVEL (706) in the
        // teeEnforced authorization list. Software attestations that omit these
        // two tags are flagged as tampered by self-check apps (e.g. 密钥认证
        // 1.7's `checkTagOrderMisordered` requires 704/705/706 all present).
        let os_version = match config::config().read() {
            Ok(g) => (g.trust.os_version.max(0) as u32) * 10000,
            Err(_) => {
                (kmr_common::android_version::android_major_version().unwrap_or(16) as u32) * 10000
            }
        };
        if os_version > 0 {
            ctx.insert("os_version".to_string(), Value::from(os_version));
        }
        let os_patch_level = match config::config().read() {
            Ok(g) => patch_level_to_yyyymm(&g.trust.os_patchlevel),
            Err(_) => None,
        }
        .or_else(|| {
            crate::plat::resetprop::read_string_property("ro.build.version.security_patch")
                .as_deref()
                .and_then(patch_level_to_yyyymm)
        });
        if let Some(patch) = os_patch_level {
            ctx.insert("os_patch_level".to_string(), Value::from(patch));
        }
        // KeyMint 3.0+ also carries per-partition patch levels
        // (KM_TAG_VENDOR_PATCH_LEVEL 707 / KM_TAG_BOOT_PATCH_LEVEL 708).
        // Real TEE attestations include them; omitting them makes the server
        // keybox layer fail STRONG integrity checks that expect them.
        // Prefer the device's real partition patch props; the resolved config
        // `[trust]` values can be stale/malformed (e.g. a bogus "2026-30").
        let vendor_patch_level =
            crate::plat::resetprop::read_string_property("ro.vendor.build.security_patch")
                .as_deref()
                .and_then(patch_level_to_yyyymm)
                .or_else(|| match config::config().read() {
                    Ok(g) => patch_level_to_yyyymm(&g.trust.vendor_patchlevel),
                    Err(_) => None,
                })
                .or(os_patch_level);
        if let Some(patch) = vendor_patch_level {
            ctx.insert("vendor_patch_level".to_string(), Value::from(patch));
        }
        let boot_patch_level =
            crate::plat::resetprop::read_string_property("ro.boot.build.security_patch")
                .as_deref()
                .and_then(patch_level_to_yyyymm)
                .or_else(|| match config::config().read() {
                    Ok(g) => patch_level_to_yyyymm(&g.trust.boot_patchlevel),
                    Err(_) => None,
                })
                .or(os_patch_level);
        if let Some(patch) = boot_patch_level {
            ctx.insert("boot_patch_level".to_string(), Value::from(patch));
        }
        // The B-side reads `device_attest_context` (nested form) for the
        // appid and optional serial; the full key params are passed through.
        let body = json!({
            "challenge": base64_encode(challenge),
            "alias": alias,
            "device_id": Self::device_id()?,
            "device_attest_context": Value::Object(ctx),
        });
        Self::post_json("/api/attest/", &body)
    }

    /// Millis since epoch (used for `creation_datetime_ms`).
    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Resolved verified-boot key/hash from `config().trust` (32 bytes each).
    /// Falls back to zeros if the config lock is unavailable (never fatal).
    fn verified_boot_values() -> ([u8; 32], [u8; 32]) {
        match config::config().read() {
            Ok(g) => (g.trust.vb_key, g.trust.vb_hash),
            Err(_) => ([0u8; 32], [0u8; 32]),
        }
    }

    /// Forward a sign request for a remote key.
    pub fn sign(alias: &str, data: &[u8], algorithm: &str) -> Result<Option<Value>> {
        let body = json!({
            "alias": alias,
            "data": base64_encode(data),
            "algorithm": algorithm,
            "device_id": Self::device_id()?,
        });
        Self::post_json("/api/sign/", &body)
    }

    /// Forward a decrypt request for a remote key.
    pub fn decrypt(alias: &str, data: &[u8], algorithm: &str) -> Result<Option<Value>> {
        let body = json!({
            "alias": alias,
            "data": base64_encode(data),
            "algorithm": algorithm,
            "device_id": Self::device_id()?,
        });
        Self::post_json("/api/decrypt/", &body)
    }

    /// Forward one SOTER operation to a B-side device.
    ///
    /// `payload` is the operation plus its arguments (`{"op": "export_ask_public_key",
    /// "uid": 10373, ...}`); `device_id` is filled in here so the server prefers a
    /// B端 carrying this device's own id and otherwise load-balances to another one
    /// that reported SOTER support.
    ///
    /// `Ok(None)` means no B-side can serve SOTER right now — the server answers a
    /// capability error (`no B-side device reporting SOTER support is online`, or
    /// the chosen device's own HAL error) and this method maps it to "not
    /// available", so the caller falls back to whatever it does without
    /// forwarding instead of inventing an answer.
    pub fn soter(payload: &Value) -> Result<Option<Value>> {
        let mut body = match payload.as_object() {
            Some(map) => map.clone(),
            None => return Err(anyhow!("soter payload must be a JSON object")),
        };
        body.insert("device_id".to_string(), Value::from(Self::device_id()?));
        Self::post_json("/api/soter/", &Value::Object(body))
    }
}

fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Convert a "YYYY-MM-DD" patch level string to the YYYYMM integer the relay
/// expects for KM_TAG_OS_PATCH_LEVEL (706).
fn patch_level_to_yyyymm(value: &str) -> Option<u32> {
    let s = value.trim();
    // Accept both "YYYY-MM-DD" (or "YYYY-MM") and bare "YYYYMM".
    if s.len() >= 6 {
        let (year, month) = if s.as_bytes().get(4) == Some(&b'-') {
            (s[0..4].parse::<u32>().ok()?, s[5..7].parse::<u32>().ok()?)
        } else {
            (s[0..4].parse::<u32>().ok()?, s[4..6].parse::<u32>().ok()?)
        };
        if (1..=12).contains(&month) {
            return Some(year * 100 + month);
        }
    }
    None
}

/// Convenience: `true` if remote relay is enabled in config.
pub fn remote_enabled() -> bool {
    match config::config().read() {
        Ok(g) => g.remote.enabled && !g.remote.url.is_empty(),
        Err(_) => false,
    }
}

/// Convenience: `true` if the remote chain may fall back to local processing.
///
/// The flat A-side config spells this `local_hw` (`RemoteConfig::fallback_local`
/// is what the WebUI writes under that name); a lock poisoned by another thread
/// means we cannot tell, and the legacy client-a behaviour always fell back, so
/// answer `true`.
pub fn fallback_local() -> bool {
    match config::config().read() {
        Ok(g) => g.remote.fallback_local,
        Err(_) => true,
    }
}

/// Adapts [`RemoteRelay`] to the TA's [`kmr_ta::device::RemoteBackend`] trait.
pub struct RemoteRelayBackend;

impl kmr_ta::device::RemoteBackend for RemoteRelayBackend {
    fn attest(
        &self,
        challenge: &[u8],
        app_id_der: &[u8],
        alias: &str,
        cert_serial: Option<&[u8]>,
        params: &kmr_ta::device::RemoteAttestParams,
    ) -> Result<Option<Vec<Vec<u8>>>, kmr_common::Error> {
        // Transport-level failure (connect timeout / network unreachable / TLS
        // handshake) means the relay is unavailable — report `Ok(None)` so the
        // TA falls back to the local software keybox (matching client-a, which
        // treats an unreachable remote as "do it locally").
        let resp = match RemoteRelay::attest(challenge, alias, app_id_der, params, cert_serial) {
            Ok(resp) => resp,
            Err(e) => {
                log::warn!("remote relay unavailable, falling back to local: {e:#}");
                return Ok(None);
            }
        };
        let Some(resp) = resp else {
            return Ok(None);
        };
        // The relay wraps the result as `{ result: { cert_chain: [...] } }`.
        let result = resp.get("result").cloned().unwrap_or(resp);
        // Smart-mode StrongBox policy: when the relay decides the B device HAS a
        // StrongBox HAL but cannot deliver (attestation keys not provisioned /
        // hardware type unavailable), it returns a 200 body carrying the B error
        // verbatim plus a `relay_error_kind` marker. That must reach the calling
        // app as a real KeyMint error — NOT fall back to the local software
        // keybox, which would mint a StrongBox-level chain from the A-side's own
        // keybox and hide the true device state. Only these marked responses
        // error out; every other failure keeps returning `Ok(None)` so the local
        // fallback path (incl. Smart-mode branch 4) is unchanged.
        let kind = result.get("relay_error_kind").and_then(Value::as_str);
        if let Some(kind) = kind {
            let msg = result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("relay: StrongBox attestation refused by B device");
            log::warn!("remote StrongBox attestation refused by B device (kind={kind}): {msg}");
            return Err(match kind {
                "strongbox_unprovisioned" => {
                    kmr_common::km_err!(AttestationKeysNotProvisioned, "{msg}")
                }
                "strongbox_unavailable" => {
                    kmr_common::km_err!(HardwareTypeUnavailable, "{msg}")
                }
                _ => kmr_common::km_err!(UnknownError, "{msg}"),
            });
        }
        let chain = match result.get("cert_chain") {
            Some(Value::Array(certs)) => certs
                .iter()
                .filter_map(|c| c.as_str())
                .filter_map(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
                .collect::<Vec<Vec<u8>>>(),
            _ => Vec::new(),
        };
        if chain.is_empty() {
            log::warn!("remote attest returned empty cert chain");
            return Ok(None);
        }
        Ok(Some(chain))
    }

    fn sign(
        &self,
        alias: &str,
        data: &[u8],
        algorithm: &str,
    ) -> Result<Option<Vec<u8>>, kmr_common::Error> {
        let Some(resp) = RemoteRelay::sign(alias, data, algorithm)
            .map_err(|e| kmr_common::km_err!(UnknownError, "remote sign: {e:#}"))?
        else {
            return Ok(None);
        };
        let result = resp.get("result").cloned().unwrap_or(resp);
        let sig_b64 = result
            .get("signature")
            .or_else(|| result.get("data"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                kmr_common::km_err!(UnknownError, "remote sign response missing signature")
            })?;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| kmr_common::km_err!(UnknownError, "bad remote signature base64: {e}"))?;
        Ok(Some(sig))
    }

    fn decrypt(
        &self,
        alias: &str,
        data: &[u8],
        algorithm: &str,
    ) -> Result<Option<Vec<u8>>, kmr_common::Error> {
        let Some(resp) = RemoteRelay::decrypt(alias, data, algorithm)
            .map_err(|e| kmr_common::km_err!(UnknownError, "remote decrypt: {e:#}"))?
        else {
            return Ok(None);
        };
        let result = resp.get("result").cloned().unwrap_or(resp);
        let plain_b64 = result.get("data").and_then(Value::as_str).ok_or_else(|| {
            kmr_common::km_err!(UnknownError, "remote decrypt response missing data")
        })?;
        let plain = base64::engine::general_purpose::STANDARD
            .decode(plain_b64)
            .map_err(|e| kmr_common::km_err!(UnknownError, "bad remote decrypt base64: {e}"))?;
        Ok(Some(plain))
    }

    fn enabled(&self) -> bool {
        remote_enabled()
    }

    fn fallback_local(&self) -> bool {
        fallback_local()
    }
}

#[cfg(test)]
mod iface_choice_tests {
    use super::*;

    #[test]
    fn bind_iface_spellings_map_to_the_right_choice() {
        assert_eq!(classify_bind_iface(""), BindChoice::Auto);
        assert_eq!(classify_bind_iface("  auto "), BindChoice::Auto);
        assert_eq!(classify_bind_iface("none"), BindChoice::Never);
        assert_eq!(classify_bind_iface("OFF"), BindChoice::Never);
        assert_eq!(classify_bind_iface("always"), BindChoice::Always);
        assert_eq!(classify_bind_iface("On"), BindChoice::Always);
        assert_eq!(
            classify_bind_iface(" wlan0 "),
            BindChoice::Named("wlan0".to_string())
        );
        // A real device name that happens to start with a keyword must not be
        // mistaken for the keyword itself.
        assert_eq!(
            classify_bind_iface("offload0"),
            BindChoice::Named("offload0".to_string())
        );
    }

    /// A literal name is used as given, valid or not — the kernel's call.
    #[test]
    fn a_literal_name_is_taken_at_face_value() {
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

    /// A name list is not what decides any more: whatever the kernel calls a
    /// device, it still gets tried — the strange names simply land in the second
    /// round instead of being thrown away.
    #[test]
    fn candidate_grouping_only_asks_the_kernel() {
        let live: Vec<String> = ["vgate0", "wlan0", "rmnet_data3", "something0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Stand-in verdict: only wlan0 has a `device` link.
        let (preferred, rest) = split_candidates(live, |n| n == "wlan0");
        assert_eq!(preferred, vec!["wlan0"]);
        // Nothing was dropped, it is only queued for round two.
        assert_eq!(rest, vec!["rmnet_data3", "something0", "vgate0"]);
    }

    #[test]
    fn host_without_sysfs_reports_nothing_physical() {
        // A dev box has no `/sys/class/net`; unreadable counts as "not physical",
        // which only pushes the device to the second round.
        #[cfg(not(target_os = "android"))]
        assert!(!physical_like("wlan0"));
    }

    #[test]
    fn wired_beats_wifi_beats_cellular() {
        assert!(uplink_rank("eth0") < uplink_rank("wlan0"));
        assert!(uplink_rank("wlan0") < uplink_rank("rmnet_data3"));
        assert!(uplink_rank("rmnet_data0") < uplink_rank("something0"));
    }

    /// The probe must hit the liveness endpoint, not the root: only `/api/ping/`
    /// answers a body that identifies the relay.
    #[test]
    fn the_probe_goes_to_the_liveness_endpoint() {
        assert_eq!(
            probe_url("http://1.2.3.4:10886"),
            "http://1.2.3.4:10886/api/ping/"
        );
        // A trailing slash on the configured URL must not double up.
        assert_eq!(
            probe_url("http://1.2.3.4:10886/"),
            "http://1.2.3.4:10886/api/ping/"
        );
    }

    /// The reported failure: the phone is joined to a WiFi network with no
    /// upstream, so `wlan0` holds a lease and looks healthy while nothing sent
    /// through it arrives.  It never answers the probe, so it loses the race on
    /// its own and cellular carries the traffic — no ranking involved.
    #[test]
    fn a_wifi_link_with_no_upstream_loses_the_race() {
        let cands = vec!["wlan0".to_string(), "rmnet_data2".to_string()];
        let probe: Arc<dyn Fn(&str) -> bool + Send + Sync> =
            Arc::new(|name: &str| name == "rmnet_data2");
        assert_eq!(race_with(&cands, probe).as_deref(), Some("rmnet_data2"));
    }

    /// The link that answers first wins, whatever its name — this is what makes
    /// the choice follow the network rather than a fixed preference.
    #[test]
    fn the_faster_link_wins_the_race() {
        let cands = vec!["wlan0".to_string(), "rmnet_data2".to_string()];
        let probe: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|name: &str| {
            if name == "wlan0" {
                std::thread::sleep(Duration::from_millis(250));
            }
            true
        });
        assert_eq!(race_with(&cands, probe).as_deref(), Some("rmnet_data2"));
    }

    /// A lone candidate is probed like any other: if it cannot reach the relay
    /// the socket stays unbound, which beats pinning a link that carries nothing.
    #[test]
    fn a_single_uplink_is_probed_too() {
        let probe: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|_: &str| false);
        assert_eq!(race_with(&["wlan0".to_string()], probe), None);
    }

    /// If nothing answers, the socket is left unbound instead of pinned to a
    /// link that just proved it cannot reach the relay — pinning one anyway is
    /// the original bug.
    #[test]
    fn when_nothing_answers_the_socket_is_left_unbound() {
        let cands = vec!["wlan0".to_string(), "rmnet_data2".to_string()];
        let dead: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|_: &str| false);
        assert_eq!(race_with(&cands, dead), None);
    }

    /// An empty candidate list is not a race at all — and must not make the
    /// caller wait for a timeout that can never be won.
    #[test]
    fn no_candidates_is_not_a_race() {
        let probe: Arc<dyn Fn(&str) -> bool + Send + Sync> =
            Arc::new(|_: &str| panic!("an empty race must not probe"));
        assert_eq!(race_with(&[], probe), None::<String>);
    }
}
