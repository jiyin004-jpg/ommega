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
//! A reqwest client is kept in a process-wide slot and handed out per request;
//! it is rebuilt only when `tls_insecure` or the outgoing interface changes.
//! Each client has its own internal connection pool, so concurrent requests
//! are not serialised through a single connection — fixing the previous single-
//! connection pool bottleneck.  reqwest also natively supports chunked transfer
//! encoding and HTTP keep-alive, both of which the hand-written client did not.

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use reqwest::blocking::Client;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config;

const CONNECT_TIMEOUT_MS: u64 = 2000;
const READ_TIMEOUT_MS: u64 = 30_000;

/// How long a single candidate interface gets to answer a reachability probe.
/// Deliberately short: a working link on this kind of network answers in well
/// under 250 ms, and the whole point of probing is to get off a dead link
/// quickly.
const PROBE_TIMEOUT: Duration = Duration::from_millis(800);

/// A relay-server client.  All configuration is read from `config().remote`.
pub struct RemoteRelay;

// ── dead remote aliases ────────────────────────────────────────────────

/// Aliases the relay has definitively told us have no private key on any
/// fulfilment layer (no B-side device holds it and the server keybox session
/// does not either).
///
/// Why remember them: a client that ignores the "key not found" answer would
/// otherwise drive one HTTP round trip per sign attempt — the observed bug was
/// 21001 sign calls over 13 hours for an alias that never had a matching
/// attestation. Once an alias is known dead, its sign/decrypt calls short-
/// circuit to the same terminal result without touching the network.
///
/// Deliberately in-memory only: the mark is a hint learned from a *remote*
/// answer, and a restart (or a successful attestation, which recreates the
/// key) must be able to clear it. The alias space is effectively unbounded, so
/// the map is capped; forgetting a dead alias only costs one more round trip.
static DEAD_REMOTE_ALIASES: Mutex<Option<HashSet<String>>> = Mutex::new(None);
const MAX_DEAD_ALIASES: usize = 4096;

/// Result of a relay sign/decrypt request.
#[derive(Clone, Debug)]
pub enum RemoteReply {
    /// The relay answered 2xx with a JSON body.
    Json(Value),
    /// The relay could not serve the request (transport failure, or a non-2xx
    /// answer that does not identify a missing key). Callers may fall back to
    /// local processing.
    Unavailable,
    /// The relay answered definitively that the alias has no private key on any
    /// fulfilment layer. This is terminal for the alias.
    KeyNotFound,
}

/// `true` if `alias` was already marked dead by a previous relay answer.
fn is_alias_dead(alias: &str) -> bool {
    DEAD_REMOTE_ALIASES
        .lock()
        .map(|guard| guard.as_ref().is_some_and(|set| set.contains(alias)))
        .unwrap_or(false)
}

/// Remember that the relay has no key for `alias`.
fn mark_alias_dead(alias: &str) {
    let Ok(mut guard) = DEAD_REMOTE_ALIASES.lock() else {
        return;
    };
    let set = guard.get_or_insert_with(HashSet::new);
    if set.len() >= MAX_DEAD_ALIASES {
        set.clear();
    }
    set.insert(alias.to_string());
}

/// Drop the dead mark for `alias`.  Called when an attestation for the alias
/// succeeds, which means the relay has (re)created the key behind it.
fn clear_alias_dead(alias: &str) {
    if let Ok(mut guard) = DEAD_REMOTE_ALIASES.lock() {
        if let Some(set) = guard.as_mut() {
            set.remove(alias);
        }
    }
}

/// Whether a non-2xx relay response body identifies the terminal "this alias
/// has no key" condition.
///
/// Two shapes have to be accepted: the current server adds
/// `"error_kind": "no_such_key"`, while older builds only carried the message
/// text (`no key for alias '…' (call attest first)`, or `no server_keybox
/// session`). A body that does not parse as JSON is scanned as raw text.
fn relay_body_says_no_key(text: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        if value_has_no_such_key_kind(&value) {
            return true;
        }
        if let Some(error) = value.get("error").and_then(Value::as_str) {
            if error_text_says_no_key(error) {
                return true;
            }
        }
    }
    error_text_says_no_key(text)
}

/// Recursively look for an `error_kind` of `no_such_key` anywhere in a JSON
/// body (the relay may wrap the failure in `result` or `detail`).
fn value_has_no_such_key_kind(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get("error_kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("no_such_key"))
                || map.values().any(value_has_no_such_key_kind)
        }
        Value::Array(items) => items.iter().any(value_has_no_such_key_kind),
        _ => false,
    }
}

/// The relay's own wording for "this alias has no private key anywhere".
fn error_text_says_no_key(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    const MARKERS: [&str; 4] = [
        "no key for alias",
        "no server_keybox session",
        "no_such_key",
        "no such key",
    ];
    MARKERS.iter().any(|marker| lower.contains(marker))
}

// ── remote key rebuild recipes ─────────────────────────────────────────

/// Serialisable mirror of [`kmr_ta::device::RemoteAttestParams`].
///
/// Why a mirror instead of storing the TA type directly: `RemoteAttestParams`
/// lives in the TA crate, which does not depend on serde, and the key blob CBOR
/// path cannot carry it either (`kmr_common`, which owns `RemoteRef`, cannot
/// depend on `kmr_ta`).  Every field here is exactly one field of the TA type,
/// so nothing the B-side needs to mint a matching key is dropped.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RecipeParams {
    pub key_algorithm: Option<i32>,
    pub key_size: Option<i32>,
    pub ec_curve: Option<i32>,
    pub purpose: Vec<i32>,
    pub digest: Vec<i32>,
    pub mgf_digest: Option<i32>,
    pub padding: Vec<i32>,
    pub rsa_public_exponent: Option<u64>,
    pub certificate_subject: Option<Vec<u8>>,
    pub certificate_not_before_ms: Option<i64>,
    pub certificate_not_after_ms: Option<i64>,
    pub security_level: Option<i32>,
    pub attestation_ids: Vec<(u32, Vec<u8>)>,
    pub user_auth: Vec<(u32, i64)>,
}

impl RecipeParams {
    /// Capture the parameters a key was minted with.
    fn capture(params: &kmr_ta::device::RemoteAttestParams) -> Self {
        Self {
            key_algorithm: params.key_algorithm,
            key_size: params.key_size,
            ec_curve: params.ec_curve,
            purpose: params.purpose.clone(),
            digest: params.digest.clone(),
            mgf_digest: params.mgf_digest,
            padding: params.padding.clone(),
            rsa_public_exponent: params.rsa_public_exponent,
            certificate_subject: params.certificate_subject.clone(),
            certificate_not_before_ms: params.certificate_not_before_ms,
            certificate_not_after_ms: params.certificate_not_after_ms,
            security_level: params.security_level,
            attestation_ids: params.attestation_ids.clone(),
            user_auth: params.user_auth.clone(),
        }
    }

    /// Rebuild the TA parameters for a re-attestation.
    fn to_attest_params(&self) -> kmr_ta::device::RemoteAttestParams {
        kmr_ta::device::RemoteAttestParams {
            key_algorithm: self.key_algorithm,
            key_size: self.key_size,
            ec_curve: self.ec_curve,
            purpose: self.purpose.clone(),
            digest: self.digest.clone(),
            mgf_digest: self.mgf_digest,
            padding: self.padding.clone(),
            rsa_public_exponent: self.rsa_public_exponent,
            certificate_subject: self.certificate_subject.clone(),
            certificate_not_before_ms: self.certificate_not_before_ms,
            certificate_not_after_ms: self.certificate_not_after_ms,
            security_level: self.security_level,
            attestation_ids: self.attestation_ids.clone(),
            user_auth: self.user_auth.clone(),
        }
    }
}

/// Everything needed to recreate the private key behind one remote alias.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteRecipe {
    /// The challenge the key was minted with.
    pub challenge: Vec<u8>,
    /// The app's attestation application id (DER) the key was minted for.
    pub app_id_der: Vec<u8>,
    /// The effective certificate serial the key was minted with.
    pub cert_serial: Option<Vec<u8>>,
    /// Key-generation parameters the B-side TEE must reproduce.
    pub params: RecipeParams,
}

/// Disk file (next to `config.toml`) that carries rebuild recipes across
/// restarts.  A keyblob outlives a reboot, so the recipe that goes with it has
/// to as well — otherwise the first lost B-side key after a restart would stay
/// terminal.
///
/// Known tradeoff (see the delivery notes): the recipe is keyed by alias in
/// this side file rather than inside the keyblob.  Losing this file (e.g. a
/// factory reset of the A-side state dir) means an already-minted remote key
/// can no longer be rebuilt in place; the alias then keeps the deterministic
/// `KEY_NOT_FOUND` behaviour.  A keyblob copy is not reachable from here: the
/// recipe would have to live in `kmr_common::crypto::RemoteRef`, but
/// `kmr_common` cannot depend on `kmr_ta`, and this backend never sees the
/// decrypted keyblob.
const RECIPE_FILE: &str = "/data/misc/keystore/ommega/remote_recipes.json";

/// Upper bound on remembered recipes.  The alias space is effectively
/// unbounded; forgetting a recipe only costs one failed rebuild, so the map may
/// be dropped wholesale when it grows too big.
const MAX_RECIPES: usize = 4096;

/// alias -> rebuild recipe, loaded from [`RECIPE_FILE`] on first use.
#[derive(Default)]
struct RecipeStoreState {
    recipes: HashMap<String, RemoteRecipe>,
}

static RECIPE_STORE: Mutex<Option<RecipeStoreState>> = Mutex::new(None);

fn load_recipes() -> RecipeStoreState {
    let recipes = std::fs::read(RECIPE_FILE)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<HashMap<String, RemoteRecipe>>(&bytes).ok())
        .unwrap_or_default();
    RecipeStoreState { recipes }
}

fn persist_recipes(recipes: &HashMap<String, RemoteRecipe>) {
    // Tests never touch the device state directory.
    if cfg!(test) {
        let _ = recipes;
        return;
    }
    let Ok(json) = serde_json::to_vec(recipes) else {
        log::warn!("failed to serialize remote rebuild recipes");
        return;
    };
    if let Some(parent) = std::path::Path::new(RECIPE_FILE).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Best effort: the in-memory copy still covers this process.
    if let Err(e) = std::fs::write(RECIPE_FILE, json) {
        log::debug!("failed to persist remote rebuild recipes: {e}");
    }
}

/// Remember how the key behind `alias` was minted, so a later "no key" answer
/// from the relay can be answered by recreating the key on the same device.
fn store_recipe(alias: &str, recipe: RemoteRecipe) {
    let Ok(mut guard) = RECIPE_STORE.lock() else {
        return;
    };
    let state = guard.get_or_insert_with(load_recipes);
    if state.recipes.len() >= MAX_RECIPES && !state.recipes.contains_key(alias) {
        state.recipes.clear();
    }
    state.recipes.insert(alias.to_string(), recipe);
    persist_recipes(&state.recipes);
}

/// The rebuild recipe for `alias`, if one was ever recorded.
fn recipe_for(alias: &str) -> Option<RemoteRecipe> {
    let Ok(mut guard) = RECIPE_STORE.lock() else {
        return None;
    };
    let state = guard.get_or_insert_with(load_recipes);
    state.recipes.get(alias).cloned()
}

/// Minimum interval between two rebuild attempts for the same alias.
///
/// A key that is gone for good would otherwise re-attest on every sign call,
/// turning one lost key into a stream of attestation round trips.
const REBUILD_THROTTLE: Duration = Duration::from_secs(10);

/// alias -> when its last rebuild was allowed.
static LAST_REBUILD: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// Claim the right to rebuild `alias` at `now`.  `true` at most once per
/// [`REBUILD_THROTTLE`] window.  Time is a parameter so the policy can be
/// tested without sleeping.
fn take_rebuild_slot(alias: &str, now: Instant) -> bool {
    let Ok(mut guard) = LAST_REBUILD.lock() else {
        return false;
    };
    let map = guard.get_or_insert_with(HashMap::new);
    if map.len() >= MAX_DEAD_ALIASES && !map.contains_key(alias) {
        map.clear();
    }
    let allowed = match map.get(alias) {
        Some(last) => now.saturating_duration_since(*last) >= REBUILD_THROTTLE,
        None => true,
    };
    if allowed {
        map.insert(alias.to_string(), now);
    }
    allowed
}

/// Run one remote sign/decrypt attempt and, when the relay answers that the
/// alias has no private key *and* a rebuild recipe is available, recreate the
/// key on the same B-side device and retry once.
///
/// Rebuilding produces a **new key pair**: a private key that went missing
/// cannot be recovered, only recreated with the same attributes and the same
/// alias.  The relay's binding table routes the re-attestation back to the
/// device that holds the alias, and a successful attestation clears the remote
/// side's dead-alias mark (and ours, via `clear_alias_dead`).
///
/// The attempt and rebuild closures are injected so the whole decision matrix
/// can be exercised without HTTP.
fn remote_op_with_rebuild<F, R>(alias: &str, mut attempt: F, mut rebuild: R) -> Result<RemoteReply>
where
    F: FnMut() -> Result<RemoteReply>,
    R: FnMut() -> Result<bool>,
{
    let first = attempt()?;
    if !matches!(first, RemoteReply::KeyNotFound) {
        return Ok(first);
    }
    // At most one rebuild per call and at most one per alias per throttle
    // window, so a permanently missing key cannot become an attestation loop.
    if !take_rebuild_slot(alias, Instant::now()) {
        log::debug!("remote rebuild for alias {alias} is throttled");
        return Ok(RemoteReply::KeyNotFound);
    }
    match rebuild() {
        Ok(true) => {}
        Ok(false) => return Ok(RemoteReply::KeyNotFound),
        Err(e) => {
            log::warn!("remote rebuild for alias {alias} failed: {e:#}");
            return Ok(RemoteReply::KeyNotFound);
        }
    }
    // Retry exactly once, now that the key exists again.
    attempt()
}

/// Re-attest `alias` with its stored recipe so the B-side device recreates the
/// private key.  Returns `true` only when the relay answered a usable chain.
fn rebuild_remote_key(alias: &str) -> Result<bool> {
    let Some(recipe) = recipe_for(alias) else {
        log::warn!(
            "relay has no key for alias {alias} and no rebuild recipe is known; staying terminal"
        );
        return Ok(false);
    };
    let params = recipe.params.to_attest_params();
    let resp = RemoteRelay::attest(
        &recipe.challenge,
        alias,
        &recipe.app_id_der,
        &params,
        recipe.cert_serial.as_deref(),
    )?;
    let Some(resp) = resp else {
        log::warn!("rebuild attestation for alias {alias} was refused by the relay");
        return Ok(false);
    };
    if !attest_response_has_chain(&resp) {
        log::warn!("rebuild attestation for alias {alias} returned no certificate chain");
        return Ok(false);
    }
    // The key exists again; let the retried sign/decrypt reach the relay.
    clear_alias_dead(alias);
    log::info!("rebuilt remote key for alias {alias} after the B-side lost it");
    Ok(true)
}

/// Whether a relay `/api/attest/` answer carries a usable leaf chain (and is not
/// one of the marked smart-mode failures).
fn attest_response_has_chain(resp: &Value) -> bool {
    let result = resp.get("result").unwrap_or(resp);
    if result.get("relay_error_kind").is_some() {
        return false;
    }
    result
        .get("cert_chain")
        .and_then(Value::as_array)
        .is_some_and(|certs| certs.iter().any(Value::is_string))
}

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
        // This client only ever talks to our own relay server.  The environment
        // proxies reqwest picks up by default exist for tools that browse the
        // open internet; on a forwarding path they only redirect the request
        // somewhere it does not belong.
        .no_proxy()
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
    /// Empty or `auto` (the default) — bind only while a VPN is up.
    Auto,
    /// `always` / `on` — always bind to a physical uplink.
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
/// Why `auto` binds only when a VPN is present: pinning one interface would also
/// throw away the OS's own "WiFi dropped, fall back to cellular" switching,
/// which is pure downside when there is no VPN to avoid.  Deployments that want
/// a fixed interface can name it explicitly.
fn desired_iface(bind_iface: &str, base_url: &str) -> Option<String> {
    match classify_bind_iface(bind_iface) {
        BindChoice::Never => None,
        BindChoice::Always => race_uplink(&uplink_candidates(), base_url),
        BindChoice::Auto if vpn_active() => race_uplink(&uplink_candidates(), base_url),
        BindChoice::Auto => None,
        // An explicit name is taken at face value: whether it exists or works is
        // the kernel's call, not ours.
        BindChoice::Named(name) => Some(name),
    }
}

/// Whether a VPN is currently up.  `VpnService` always leaves a `tun` device in
/// `/sys/class/net` and the older pptp/l2tp paths leave a `ppp`; the names are
/// always `tun0` / `ppp0` shaped, so a prefix check is enough.
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

/// The physical uplinks that could carry relay traffic right now, best first.
///
/// Measured on a Z60 Ultra (Android 16), two traps: `dummy0` and `lo` both
/// report `operstate=unknown` with `carrier=1`, indistinguishable from a real
/// NIC by state alone, so virtual devices have to be excluded by name; and the
/// cellular `rmnet_data*` interfaces also report `unknown` (they have no real
/// link-layer state), so testing for `up` alone would skip them.
///
/// That is still not enough: `rmnet_data0/1` sit at `operstate=unknown` with no
/// IP address most of the time, and binding to one of those means binding to a
/// device with no route.  `/proc/net/route` lists exactly the interfaces that
/// currently hold an IPv4 address (two rows on the device above: `wlan0` and
/// `rmnet_data3`), which makes it a precise cross-filter.
///
/// Note this says nothing about whether the link actually reaches anywhere —
/// see `probe_iface`.
fn uplink_candidates() -> Vec<String> {
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
        // An unreadable `operstate` (SELinux denies it in some domains) must not
        // disqualify the device: `/proc/net/route` already proved it carries an
        // IPv4 route, and the reachability probe is the real check.
        if !state.is_empty() && state != "up" && state != "unknown" {
            continue;
        }
        found.push((uplink_rank(name), name.to_string()));
    }
    found.sort();
    found.into_iter().map(|(_, name)| name).collect()
}

/// The relay's liveness endpoint, and the body it answers with.
///
/// `/api/ping/` returns a fixed `pong` without touching any state, which makes
/// it the right probe target: cheap enough to hit on every request, and its body
/// identifies the relay.  Probing `/` instead would accept any HTTP answer,
/// including one from a captive portal or a carrier interstitial that swallowed
/// the request.
const PING_PATH: &str = "/api/ping/";
const PING_BODY: &str = "pong";

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
fn probe_iface(iface: &str, base_url: &str) -> bool {
    // Nothing to probe against (unconfigured or malformed URL) — do not turn a
    // configuration problem into "no interface works".
    if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
        return true;
    }
    let Ok(client) = Client::builder()
        .interface(iface)
        .no_proxy()
        .connect_timeout(PROBE_TIMEOUT)
        .timeout(PROBE_TIMEOUT)
        // The probe only asks whether packets get there; a certificate problem
        // is not a routing problem.
        .danger_accept_invalid_certs(true)
        .build()
    else {
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
    // The closure must be `'static` to move into the probe threads, so the URL is
    // captured by value instead of borrowed.
    let url = base_url.to_string();
    let probe: Arc<dyn Fn(&str) -> bool + Send + Sync> =
        Arc::new(move |name: &str| probe_iface(name, &url));
    race_with(candidates, probe)
}

/// The racing itself, with the probe injected so it can be tested without a
/// network.
fn race_with(
    candidates: &[String],
    probe: Arc<dyn Fn(&str) -> bool + Send + Sync>,
) -> Option<String> {
    match candidates.len() {
        0 => None,
        // One link is not a choice: probing it cannot change the answer, so do
        // not make the caller wait a round trip to learn nothing.  This is the
        // "only mobile data" and "only WiFi" case.
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
            // Without this the channel would stay open as long as any clone of
            // the sender lives, so a race where every probe fails would block for
            // the full timeout instead of returning as soon as the last probe
            // reports.
            drop(tx);
            match rx.recv_timeout(PROBE_TIMEOUT + Duration::from_millis(200)) {
                Ok(winner) => {
                    log::info!(
                        "relay uplink race won by {winner} (candidates: {})",
                        candidates.join(",")
                    );
                    Some(winner)
                }
                // Nothing answered.  Leave the socket unbound rather than
                // pinning a link that just failed to reach the relay: binding
                // one anyway would put us back where this started — stuck on a
                // WiFi link that carries nothing — and an unbound socket at
                // least lets the OS follow the network.  This also covers a
                // `url` that resolves through the tunnel (Clash fake-IP), where
                // no physical link can ever answer.
                Err(_) => {
                    log::warn!(
                        "no uplink answered a probe; leaving the socket unbound (candidates: {})",
                        candidates.join(",")
                    );
                    None
                }
            }
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

/// Virtual or otherwise unsuitable devices: tunnels, bridges, loopback, dummy,
/// and the VPN's own interfaces.
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
    ];
    VIRTUAL.iter().any(|prefix| name.starts_with(prefix))
}

/// Preference among physical uplinks: wired, then WiFi, then cellular, then
/// anything else.  Matches how Android itself ranks networks.
fn uplink_rank(name: &str) -> u8 {
    if name.starts_with("eth") {
        0
    } else if name.starts_with("wlan") {
        1
    } else if name.starts_with("rmnet") {
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

    /// POST a JSON body to a relay endpoint and return the raw `(status, body)`
    /// for every answer, including non-2xx ones (whose body carries the reason).
    /// Only a transport failure or a body that cannot be serialised is `Err`;
    /// transport failures are retried once.
    fn post_raw(path: &str, body: &Value) -> Result<(u16, Vec<u8>)> {
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
        match http_request("POST", &url, &headers, Some(body_str.as_bytes())) {
            Ok(v) => Ok(v),
            Err(first) => {
                log::warn!("remote {path} transport error, retrying once: {first:#}");
                // A transport failure usually means the link we pinned the
                // socket to cannot carry traffic.  The retry re-races the
                // candidates, so it leaves by whichever link answers now.
                http_request("POST", &url, &headers, Some(body_str.as_bytes()))
                    .map_err(|second| anyhow!("{first:#}; retry also failed: {second:#}"))
            }
        }
    }

    /// POST a JSON body to a relay endpoint.  Returns `Ok(Some(json))` on 2xx
    /// with a JSON body, `Ok(None)` if the remote is unreachable/non-2xx.
    fn post_json(path: &str, body: &Value) -> Result<Option<Value>> {
        let (status, resp) = Self::post_raw(path, body)?;
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

    /// POST a sign/decrypt body and classify the answer.  A non-2xx body that
    /// names a missing key marks `alias` dead (and short-circuits later calls),
    /// while every other non-2xx answer stays "unavailable" so the caller can
    /// keep its existing fallback behaviour.
    fn post_reply(path: &str, body: &Value, alias: &str) -> Result<RemoteReply> {
        if is_alias_dead(alias) {
            return Ok(RemoteReply::KeyNotFound);
        }
        let (status, resp) = Self::post_raw(path, body)?;
        if (200..300).contains(&status) {
            if resp.is_empty() {
                return Ok(RemoteReply::Unavailable);
            }
            return serde_json::from_slice(&resp)
                .map(RemoteReply::Json)
                .map_err(|e| anyhow!("relay returned malformed JSON (status {status}): {e}"));
        }
        let text = String::from_utf8_lossy(&resp);
        if relay_body_says_no_key(&text) {
            log::warn!(
                "remote {path} HTTP {status}: relay has no key for alias {alias}; caching it as dead"
            );
            mark_alias_dead(alias);
            return Ok(RemoteReply::KeyNotFound);
        }
        log::warn!("remote {path} HTTP {status}");
        Ok(RemoteReply::Unavailable)
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
        // 把本机对外宣称的 KeyMint 版本也带上：服务端 keybox 层原来只能按
        // `os_version` 猜（Android 16 → 400），而本机实际是 300，于是同一次认证里
        // 只要一个算法落到 B 的 TEE、另一个落到 keybox，两条链的
        // attestationVersion/keymasterVersion 就对不上（TrustAttestor 的
        // `hardware.attestation.algorithm_differential`）。
        let advertised_version =
            crate::plat::keymint_profile::advertised_version(params.security_level.unwrap_or(1));
        if advertised_version > 0 {
            ctx.insert(
                "attest_record_version".to_string(),
                Value::from(i64::from(advertised_version)),
            );
            ctx.insert(
                "keymint_record_version".to_string(),
                Value::from(i64::from(advertised_version)),
            );
        }
        // Device properties / ID attestation the app asked to be attested, as
        // `[tag, base64(value)]` pairs (710..=717, plus 723 for the second IMEI). A
        // real device puts
        // these in the leaf's teeEnforced list whenever the app requested them
        // (Android 15 fills brand/device/product/manufacturer/model itself), so
        // the relay and the server keybox layer have to reproduce them instead
        // of minting a chain with no IDs at all.
        if !params.attestation_ids.is_empty() {
            ctx.insert(
                "attestation_ids".to_string(),
                Value::Array(
                    params
                        .attestation_ids
                        .iter()
                        .map(|(tag, value)| json!([*tag, base64_encode(value)]))
                        .collect(),
                ),
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

    /// Forward a sign request for a remote key.  `RemoteReply::KeyNotFound`
    /// means the relay has definitively answered that the alias has no private
    /// key on any layer; the caller must turn that into a terminal error, not a
    /// retryable one.
    pub fn sign(alias: &str, data: &[u8], algorithm: &str) -> Result<RemoteReply> {
        let body = json!({
            "alias": alias,
            "data": base64_encode(data),
            "algorithm": algorithm,
            "device_id": Self::device_id()?,
        });
        Self::post_reply("/api/sign/", &body, alias)
    }

    /// Forward a decrypt request for a remote key (see [`Self::sign`]).
    pub fn decrypt(alias: &str, data: &[u8], algorithm: &str) -> Result<RemoteReply> {
        let body = json!({
            "alias": alias,
            "data": base64_encode(data),
            "algorithm": algorithm,
            "device_id": Self::device_id()?,
        });
        Self::post_reply("/api/decrypt/", &body, alias)
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
        // A successful attestation means the relay has (re)created the key for
        // this alias, so a previous "no key" mark must not keep forwarding off.
        clear_alias_dead(alias);
        // Keep the recipe this key was minted with: it is what lets a later
        // "the B-side lost the key" answer be repaired in place instead of
        // failing the app's sign/decrypt.
        store_recipe(
            alias,
            RemoteRecipe {
                challenge: challenge.to_vec(),
                app_id_der: app_id_der.to_vec(),
                cert_serial: cert_serial.map(|s| s.to_vec()),
                params: RecipeParams::capture(params),
            },
        );
        Ok(Some(chain))
    }

    fn sign(
        &self,
        alias: &str,
        data: &[u8],
        algorithm: &str,
    ) -> Result<Option<Vec<u8>>, kmr_common::Error> {
        let resp = match remote_op_with_rebuild(
            alias,
            || RemoteRelay::sign(alias, data, algorithm),
            || rebuild_remote_key(alias),
        ) {
            Ok(RemoteReply::Json(resp)) => resp,
            // The remote is unavailable (or answered something we cannot act
            // on): fall back to local processing exactly as before.
            Ok(RemoteReply::Unavailable) => return Ok(None),
            // Terminal: no fulfilment layer has a private key for this alias,
            // and the in-place rebuild (when one was possible) did not bring it
            // back.  Report the dedicated code so Keystore returns KEY_NOT_FOUND
            // to the app instead of the retryable UNKNOWN_ERROR.
            Ok(RemoteReply::KeyNotFound) => {
                return Err(kmr_common::km_err!(
                    RemoteKeyNotFound,
                    "remote sign: relay has no key for alias '{alias}'"
                ))
            }
            Err(e) => return Err(kmr_common::km_err!(UnknownError, "remote sign: {e:#}")),
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
        let resp = match remote_op_with_rebuild(
            alias,
            || RemoteRelay::decrypt(alias, data, algorithm),
            || rebuild_remote_key(alias),
        ) {
            Ok(RemoteReply::Json(resp)) => resp,
            Ok(RemoteReply::Unavailable) => return Ok(None),
            Ok(RemoteReply::KeyNotFound) => {
                return Err(kmr_common::km_err!(
                    RemoteKeyNotFound,
                    "remote decrypt: relay has no key for alias '{alias}'"
                ))
            }
            Err(e) => return Err(kmr_common::km_err!(UnknownError, "remote decrypt: {e:#}")),
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
mod relay_error_tests {
    use super::*;

    /// The current server annotates the terminal failure with
    /// `"error_kind": "no_such_key"`, at the top level or nested.
    #[test]
    fn error_kind_no_such_key_is_recognized() {
        assert!(relay_body_says_no_key(
            r#"{"error_kind":"no_such_key","error":"boom"}"#
        ));
        assert!(relay_body_says_no_key(
            r#"{"result":{"error_kind":"NO_SUCH_KEY"}}"#
        ));
        assert!(relay_body_says_no_key(
            r#"{"detail":{"nested":{"error_kind":"no_such_key"}}}"#
        ));
    }

    /// Older servers only carried the message text.  This is the exact body
    /// observed in production.
    #[test]
    fn missing_alias_text_is_recognized() {
        let body = concat!(
            r#"{"error":"all fulfilment layers failed for device "#,
            r#"device-b-c3f204aa: no key for alias 'ommega-remote-0123456789abcdef' "#,
            r#"(call attest first)"}'"#,
        );
        assert!(relay_body_says_no_key(body));
        // The keybox-session variant names the same condition differently.
        assert!(relay_body_says_no_key(
            "no server_keybox session for device"
        ));
        // A body that is not JSON at all must still be scanned as text.
        assert!(relay_body_says_no_key("500 no key for alias 'x'"));
    }

    /// Anything that is not specifically "this alias has no key" must stay
    /// `Unavailable`, so the existing local fallback keeps working.
    #[test]
    fn unrelated_failures_are_not_no_such_key() {
        assert!(!relay_body_says_no_key(""));
        assert!(!relay_body_says_no_key("pong"));
        assert!(!relay_body_says_no_key("internal server error"));
        assert!(!relay_body_says_no_key(
            r#"{"error":"no B-side device reporting SOTER support is online"}"#
        ));
        assert!(!relay_body_says_no_key(
            r#"{"error_kind":"strongbox_unavailable"}"#
        ));
    }

    /// Marking is per-alias, and a successful attestation must clear it so the
    /// rebuilt key is forwarded again.  Uses a private alias so the global map
    /// is not shared with the other test.
    #[test]
    fn dead_alias_mark_is_scoped_and_clearable() {
        let alias = "ommega-remote-cafebabecafebabe";
        let other = "ommega-remote-feedfacefeedface";
        clear_alias_dead(alias);
        clear_alias_dead(other);
        assert!(!is_alias_dead(alias));
        mark_alias_dead(alias);
        assert!(is_alias_dead(alias));
        assert!(
            !is_alias_dead(other),
            "marking one alias must not affect another"
        );
        clear_alias_dead(alias);
        assert!(!is_alias_dead(alias));
    }
}

#[cfg(test)]
mod remote_rebuild_tests {
    use super::*;
    use anyhow::anyhow;
    use serde_json::json;
    use std::cell::Cell;

    fn sample_recipe(challenge: &[u8]) -> RemoteRecipe {
        RemoteRecipe {
            challenge: challenge.to_vec(),
            app_id_der: vec![1, 2, 3],
            cert_serial: Some(vec![7]),
            params: RecipeParams {
                key_algorithm: Some(3),
                key_size: Some(256),
                ec_curve: Some(1),
                purpose: vec![2],
                digest: vec![4],
                security_level: Some(1),
                ..Default::default()
            },
        }
    }

    fn json_reply() -> RemoteReply {
        RemoteReply::Json(json!({ "signature": "AA==" }))
    }

    /// A recorded recipe is found by its own alias, and an alias with no recipe
    /// reports none (the two cases the rebuild path branches on).
    #[test]
    fn recipes_are_scoped_to_their_alias() {
        let alias = "ommega-remote-00000000000000a1";
        let other = "ommega-remote-00000000000000a2";
        store_recipe(alias, sample_recipe(b"c1"));
        assert_eq!(recipe_for(alias).unwrap().challenge, b"c1".to_vec());
        assert!(
            recipe_for(other).is_none(),
            "an unknown alias has no recipe"
        );
    }

    /// The recipe survives its persistable form unchanged: every field the
    /// B-side needs to mint a matching key must come back.
    #[test]
    fn recipe_params_survive_the_persistable_form() {
        let original = kmr_ta::device::RemoteAttestParams {
            key_algorithm: Some(1),
            key_size: Some(2048),
            ec_curve: None,
            purpose: vec![2, 3],
            digest: vec![4],
            mgf_digest: Some(1),
            padding: vec![1, 2],
            rsa_public_exponent: Some(65537),
            certificate_subject: Some(vec![0x30, 0x00]),
            certificate_not_before_ms: Some(1_700_000_000_000),
            certificate_not_after_ms: Some(1_800_000_000_000),
            security_level: Some(2),
            attestation_ids: vec![(710, b"brand".to_vec())],
            user_auth: vec![(504, 2), (505, 30)],
        };
        let persisted = serde_json::to_vec(&RecipeParams::capture(&original)).unwrap();
        let restored: RecipeParams = serde_json::from_slice(&persisted).unwrap();
        let back = restored.to_attest_params();
        assert_eq!(format!("{back:?}"), format!("{original:?}"));
    }

    /// A rebuild is allowed at most once per window per alias; another alias has
    /// its own window; the window reopens after the throttle interval.
    #[test]
    fn rebuild_slots_are_throttled_per_alias_and_reopen() {
        let alias = "ommega-remote-00000000000000b1";
        let other = "ommega-remote-00000000000000b2";
        let t0 = Instant::now();
        assert!(take_rebuild_slot(alias, t0), "first rebuild is allowed");
        assert!(
            !take_rebuild_slot(alias, t0 + Duration::from_millis(1)),
            "a second rebuild inside the window is refused"
        );
        assert!(
            take_rebuild_slot(other, t0 + Duration::from_millis(2)),
            "another alias is not throttled by this one"
        );
        assert!(
            take_rebuild_slot(alias, t0 + REBUILD_THROTTLE),
            "the window reopens after the throttle interval"
        );
    }

    /// `KeyNotFound` -> rebuild -> one retry, and the retry's answer wins.
    #[test]
    fn key_not_found_rebuilds_then_retries() {
        let alias = "ommega-remote-00000000000000c1";
        let attempts = Cell::new(0);
        let rebuilds = Cell::new(0);
        let out = remote_op_with_rebuild(
            alias,
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    Ok(RemoteReply::KeyNotFound)
                } else {
                    Ok(json_reply())
                }
            },
            || {
                rebuilds.set(rebuilds.get() + 1);
                Ok(true)
            },
        )
        .unwrap();
        assert!(matches!(out, RemoteReply::Json(_)));
        assert_eq!(attempts.get(), 2, "exactly one retry");
        assert_eq!(rebuilds.get(), 1, "exactly one rebuild");
    }

    /// A retry that is also refused must not loop: the terminal answer comes
    /// back after exactly one rebuild.
    #[test]
    fn a_retry_that_also_fails_stays_terminal_after_one_rebuild() {
        let alias = "ommega-remote-00000000000000c2";
        let attempts = Cell::new(0);
        let rebuilds = Cell::new(0);
        let out = remote_op_with_rebuild(
            alias,
            || {
                attempts.set(attempts.get() + 1);
                Ok(RemoteReply::KeyNotFound)
            },
            || {
                rebuilds.set(rebuilds.get() + 1);
                Ok(true)
            },
        )
        .unwrap();
        assert!(matches!(out, RemoteReply::KeyNotFound));
        assert_eq!(attempts.get(), 2);
        assert_eq!(rebuilds.get(), 1);
    }

    /// If the rebuild itself fails, the caller keeps the existing terminal
    /// behaviour and does not retry.
    #[test]
    fn a_failed_rebuild_does_not_retry() {
        let alias = "ommega-remote-00000000000000c3";
        let attempts = Cell::new(0);
        let out = remote_op_with_rebuild(
            alias,
            || {
                attempts.set(attempts.get() + 1);
                Ok(RemoteReply::KeyNotFound)
            },
            || Ok(false),
        )
        .unwrap();
        assert!(matches!(out, RemoteReply::KeyNotFound));
        assert_eq!(attempts.get(), 1, "no retry when the rebuild failed");
    }

    /// A transport error while rebuilding must not change the outcome either.
    #[test]
    fn a_rebuild_error_does_not_retry() {
        let alias = "ommega-remote-00000000000000c4";
        let attempts = Cell::new(0);
        let out = remote_op_with_rebuild(
            alias,
            || {
                attempts.set(attempts.get() + 1);
                Ok(RemoteReply::KeyNotFound)
            },
            || Err(anyhow!("relay unreachable")),
        )
        .unwrap();
        assert!(matches!(out, RemoteReply::KeyNotFound));
        assert_eq!(attempts.get(), 1);
    }

    /// Only the "no such key" answer triggers a rebuild; every other answer is
    /// passed straight through untouched.
    #[test]
    fn other_answers_never_trigger_a_rebuild() {
        for reply in [RemoteReply::Unavailable, json_reply()] {
            let alias = "ommega-remote-00000000000000c5";
            let rebuilds = Cell::new(0);
            let out = remote_op_with_rebuild(
                alias,
                || Ok(reply.clone()),
                || {
                    rebuilds.set(rebuilds.get() + 1);
                    Ok(true)
                },
            )
            .unwrap();
            assert_eq!(
                matches!(out, RemoteReply::Unavailable),
                matches!(reply, RemoteReply::Unavailable)
            );
            assert_eq!(rebuilds.get(), 0, "no rebuild for a non-KeyNotFound answer");
        }
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

    #[test]
    fn virtual_devices_are_never_picked() {
        for name in [
            "lo",
            "dummy0",
            "tun0",
            "ppp0",
            "ip6tnl0",
            "ip_vti0",
            "ifb0",
            "sit0",
            "gre0",
            "gretap0",
            "erspan0",
            "p2p0",
            "r_rmnet_data3",
            "rmnet_ipa0",
        ] {
            assert!(is_virtual_iface(name), "{name} must count as virtual");
        }
        for name in ["wlan0", "wlan1", "eth0", "rmnet_data0", "rmnet_data3"] {
            assert!(!is_virtual_iface(name), "{name} is a real uplink");
        }
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
    /// its own and cellular carries the traffic — no ranking involved, nothing to
    /// notice, no cached decision to expire.
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

    /// One uplink is not a choice: it must be taken with no probe at all.  The
    /// probe closure panics if it is ever called.
    #[test]
    fn a_single_uplink_is_never_probed() {
        let no_probe: Arc<dyn Fn(&str) -> bool + Send + Sync> =
            Arc::new(|_: &str| panic!("a lone uplink must not be probed"));
        let wifi_only = vec!["wlan0".to_string()];
        assert_eq!(
            race_with(&wifi_only, Arc::clone(&no_probe)).as_deref(),
            Some("wlan0")
        );
        let cell_only = vec!["rmnet_data2".to_string()];
        assert_eq!(
            race_with(&cell_only, Arc::clone(&no_probe)).as_deref(),
            Some("rmnet_data2")
        );
    }

    /// If nothing answers, the socket is left unbound instead of pinned to a
    /// link that just proved it cannot reach the relay — pinning one anyway is
    /// the original bug.  No candidates at all means the same thing.
    #[test]
    fn when_nothing_answers_the_socket_is_left_unbound() {
        let cands = vec!["wlan0".to_string(), "rmnet_data2".to_string()];
        let dead: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|_: &str| false);
        assert_eq!(race_with(&cands, dead), None);
        let any: Arc<dyn Fn(&str) -> bool + Send + Sync> = Arc::new(|_: &str| true);
        assert_eq!(race_with(&[], any), None);
    }

    /// Manual on-device check, kept out of the normal run because it needs a
    /// real device with a live uplink and a reachable relay.  On the device:
    ///
    ///     OMMEGA_PROBE_URL=http://1.2.3.4:10886 ./keymint_t \
    ///         on_device_pick_report --ignored --nocapture
    ///
    /// Prints the candidate uplinks, what a reachability probe says about each,
    /// and which one the picker would use.
    #[test]
    #[ignore]
    fn on_device_pick_report() {
        let base_url = std::env::var("OMMEGA_PROBE_URL").unwrap_or_default();
        let candidates = uplink_candidates();
        println!("candidates = {candidates:?}");
        for c in &candidates {
            println!("  probe {c} -> {}", probe_iface(c, &base_url));
        }
        println!("race winner = {:?}", race_uplink(&candidates, &base_url));
    }
}
