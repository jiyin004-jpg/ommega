//! Auto keybox refresh: periodically pull keybox material from configured
//! upstream URLs, parse it into PEM identities, and store it under a fixed
//! device_id (mirrors Django's `keybox_automation.py`).
//!
//! Supports:
//!   - http and https (reqwest + rustls, no system OpenSSL)
//!   - primary URL + mirror URL + GitHub mirror rewrites
//!   - hex- and base64-wrapped payloads
//!   - keybox XML, bare PEM bundles, or JSON/text wrappers
//!
//! All DB writes go through the parameterised `upsert_device_identity`, so no
//! string is ever interpolated into SQL (SQL-injection safe).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde_json::Value;

use crate::db::Db;
use crate::keybox::KeyboxData;
use crate::queue::TaskStore;

/// Global enable flag for the auto-refresh background loop.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// 后台线程是否真的被拉起来了。`ENABLED` 只是"用户想不想让它跑"，而线程只在
/// `KEYBOX_REFRESH_ENABLED=true` 时由 main 启动一次。两者分开记，才能让管理接口
/// 分辨"开关开着但根本没线程"这种状态 —— 否则状态页会报 enabled 而实际不刷新。
static STARTED: AtomicBool = AtomicBool::new(false);

/// Runtime-overridable device_id per source name (initialised from env, editable
/// via the admin API).
static DEVICE_IDS: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn device_ids() -> &'static Mutex<HashMap<String, String>> {
    DEVICE_IDS.get_or_init(|| {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let mut m = HashMap::new();
        m.insert(
            "yurikey".to_string(),
            env("KEYBOX_DEVICE_B1_ID", "device-b-1"),
        );
        m.insert(
            "public".to_string(),
            env("KEYBOX_DEVICE_B2_ID", "device-b-2"),
        );
        Mutex::new(m)
    })
}

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// 真正在跑：开关开着，而且后台线程确实启动了。状态页与管理接口报的是这个值。
pub fn is_running() -> bool {
    STARTED.load(Ordering::Relaxed) && ENABLED.load(Ordering::Relaxed)
}

/// 后台线程是否已被启动（与开关无关）。
pub fn is_started() -> bool {
    STARTED.load(Ordering::Relaxed)
}

pub fn set_enabled(v: bool) {
    ENABLED.store(v, Ordering::Relaxed);
}

/// Global enable flag for the auto-cover step: after an auto-keybox refresh
/// successfully fetches keys, also write them (unconditionally) into the
/// server-side identity of every currently-online B device id, so serverbox
/// mode can out-证 for those devices. Disabling clears the rows it wrote.
static COVER_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn cover_enabled() -> bool {
    COVER_ENABLED.load(Ordering::Relaxed)
}

pub fn set_cover_enabled(v: bool) {
    COVER_ENABLED.store(v, Ordering::Relaxed);
}

/// Runtime cover-source selection for the auto-cover step:
///   - `"auto"` (default): use every source that fetched keys this run, in
///     `configured_sources()` order — later sources/identities overwrite
///     earlier ones per algorithm, so the last source to write wins.
///   - a configured source name (e.g. `"yurikey"` / `"kow"`): only that
///     source's fetched keys are used to cover online B device ids.
static COVER_SOURCE: OnceLock<Mutex<String>> = OnceLock::new();

fn cover_source_slot() -> &'static Mutex<String> {
    COVER_SOURCE.get_or_init(|| Mutex::new("auto".to_string()))
}

/// The current cover-source selection (`"auto"` or a configured source name).
pub fn cover_source() -> String {
    crate::util::mu(cover_source_slot()).clone()
}

/// Set the cover source. Accepts `"auto"` or a name present in
/// `configured_sources()`. Returns `false` for an unknown value.
pub fn set_cover_source(name: &str) -> bool {
    let ok = name == "auto" || configured_sources().iter().any(|s| s.name == name);
    if ok {
        *crate::util::mu(cover_source_slot()) = name.to_string();
    }
    ok
}

/// Get the current device_id for a source name.
pub fn device_id_for(name: &str) -> String {
    crate::util::mu(device_ids())
        .get(name)
        .cloned()
        .unwrap_or_default()
}

/// Set (override) the device_id for a source name.
pub fn set_device_id(name: &str, device_id: &str) {
    crate::util::mu(device_ids()).insert(name.to_string(), device_id.to_string());
}

/// 公开源默认的仓库搜索入口。匿名 search 接口是 10 次/分钟，这里两小时才打一
/// 次，余量很大。
const DEFAULT_PUBLIC_SEARCH_URL: &str =
    "https://api.github.com/search/repositories?q=keybox&sort=updated&per_page=30";
/// 一轮最多看几个仓库、最多收几条身份 —— 别让一轮刷新跑太久。
const PUBLIC_MAX_REPOS: usize = 20;
pub const PUBLIC_MAX_IDENTITIES: usize = 6;
/// keybox 文件在仓库里就这几个常见位置。
const PUBLIC_PATHS: &[&str] = &["keybox.xml", "keybox", "module/keybox.xml"];

/// A single configured upstream keybox source.
#[derive(Debug, Clone)]
pub struct KeyboxSource {
    pub name: String,
    pub device_id: String,
    pub url_primary: String,
    pub url_mirror: String,
    pub decode_hex: bool,
    /// When true, `url_primary` is a JSON API returning a `keyboxes` list (each
    /// with `identity`/`status`); valid entries are downloaded individually and
    /// matched to `device_id` with `-1`, `-2`, ... suffixes.
    pub api_list: bool,
    /// When true, `url_primary` is a GitHub repository-search API. Every hit is
    /// probed for a keybox file at the usual paths and the first usable one is
    /// stored. `search/repositories` needs no auth, and the raw file fetches
    /// consume no API quota, so this stays well inside the anonymous limits.
    pub search_repos: bool,
}

/// Build the configured sources from environment variables (URLs) and the
/// runtime-overridable device_id map.
pub fn configured_sources() -> Vec<KeyboxSource> {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    vec![
        KeyboxSource {
            name: "yurikey".to_string(),
            device_id: device_id_for("yurikey"),
            url_primary: env(
                "KEYBOX_YURI_URL",
                "https://raw.githubusercontent.com/Yurii0307/yurikey/main/key",
            ),
            url_mirror: env(
                "KEYBOX_YURI_MIRROR_URL",
                "https://gh-proxy.com/https://raw.githubusercontent.com/Yurii0307/yurikey/main/key",
            ),
            decode_hex: false,
            api_list: false,
            search_repos: false,
        },
        KeyboxSource {
            name: "public".to_string(),
            device_id: device_id_for("public"),
            url_primary: env("KEYBOX_PUBLIC_SEARCH_URL", DEFAULT_PUBLIC_SEARCH_URL),
            // 仓库里的 keybox 文件是直接取 raw 的（不走 API 配额），所以这一项是
            // 取文件失败时换哪个镜像，而不是 API 镜像。
            url_mirror: env("KEYBOX_PUBLIC_MIRROR", "https://gh-proxy.com/"),
            decode_hex: false,
            api_list: false,
            search_repos: true,
        },
    ]
}

/// Fetch a URL over http/https, returning the body text.
///
// 取网页文本统一走 `crate::http::get_text`（那边记了为什么不用 reqwest）。

/// Fetch the source body.
///
/// 候选顺序按「实测能通的排前面」：raw.githubusercontent.com 直连在这台机器上要么
/// 30s 超时、要么被 CF 挡，几家公共镜像反而秒回，所以主址是 raw 链接时把它压到最后
/// 兜底；主址不是 raw 的（API 类源）还是主址优先。重复的地址去掉，少打几个空包。
fn fetch_source(src: &KeyboxSource) -> anyhow::Result<String> {
    let candidates = fetch_candidates(src);

    let mut last_err: Option<anyhow::Error> = None;
    for (i, url) in candidates.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(Duration::from_secs(2));
        }
        match crate::http::get_text(url, Duration::from_secs(30)) {
            Ok(body) => return Ok(body),
            Err(e) => {
                tracing::warn!("autokeybox fetch failed url={url} err={e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no candidate URL")))
}

/// 「试哪个地址」的排序，和网络分开，方便直接钉住顺序。
fn fetch_candidates(src: &KeyboxSource) -> Vec<String> {
    let published = raw_url_mirrors(&src.url_primary);
    let mut candidates: Vec<String> = Vec::new();
    if published.is_empty() {
        candidates.push(src.url_primary.clone());
        if !src.url_mirror.is_empty() {
            candidates.push(src.url_mirror.clone());
        }
    } else {
        candidates.extend(published);
        if !src.url_mirror.is_empty() {
            candidates.push(src.url_mirror.clone());
        }
        candidates.push(src.url_primary.clone());
    }
    candidates.extend(raw_url_mirrors(&src.url_mirror));
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|u| !u.is_empty() && seen.insert(u.clone()));
    candidates
}

/// Decode hex- or base64-wrapped payloads (mirrors `_maybe_decode_ns_payload`).
fn maybe_decode_ns_payload(raw: &str, decode_hex: bool) -> String {
    let mut text = raw.trim().to_string();
    if text.is_empty() {
        return text;
    }
    if decode_hex {
        let hex_only: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if !hex_only.is_empty() && hex_only.len().is_multiple_of(2) {
            if let Ok(decoded) = hex_decode(&hex_only) {
                if let Ok(s) = String::from_utf8(decoded) {
                    text = s;
                }
            }
        }
    }
    // Try base64 if the whole thing looks like a compact base64 blob.
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.is_empty() {
        if let Ok(decoded) = base64_decode(&compact) {
            let s = String::from_utf8_lossy(&decoded).into_owned();
            if s.contains('<') || s.contains("BEGIN ") || s.contains("AndroidAttestation") {
                text = s;
            }
        }
    }
    text
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(bytes)
}

fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

/// Normalise raw source text into a keybox-XML-compatible payload.
fn build_keybox_xml(source_text: &str, source_name: &str) -> String {
    let raw = source_text.trim();
    // 已经是 keybox XML 就直接过。别只认 `<?xml` 开头 —— 有些源（yurikey 那个就是
    // base64 解出来的）省了声明，直接 `<AndroidAttestation>` 开头；漏判就会掉进下面
    // 的 PEM 合成分支，拼出来的证书链是空的，白拿一份材料还过不了校验。
    if raw.contains("<AndroidAttestation") || raw.contains("<Keybox") {
        return raw.to_string();
    }
    // Extract PEM blocks from wrapped text and synthesise a minimal keybox XML.
    let pem_blocks = extract_pem_blocks(raw);
    let certs: Vec<&String> = pem_blocks
        .iter()
        .filter(|b| b.contains("BEGIN CERTIFICATE"))
        .collect();
    let keys: Vec<&String> = pem_blocks
        .iter()
        .filter(|b| !b.contains("BEGIN CERTIFICATE"))
        .collect();
    if !keys.is_empty() {
        // 证书按顺序挂在每把钥匙下面（通常这种文件里就一对）。没有证书的话链就是
        // 空的，入库校验会把它挡掉 —— 但至少形状是完整的，日志能看出是被校验拒的。
        let chain: String = certs
            .iter()
            .map(|c| format!("      <Certificate format=\"pem\">{c}      </Certificate>\n"))
            .collect();
        let mut out = Vec::new();
        for k in keys {
            out.push(format!(
                "  <Key>\n    <PrivateKey>{k}</PrivateKey>\n    <CertificateChain>\n{chain}    </CertificateChain>\n  </Key>"
            ));
        }
        return format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AndroidAttestation source=\"{source_name}\">\n{}\n</AndroidAttestation>\n",
            out.join("\n")
        );
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AndroidAttestation source=\"{source_name}\">\n  <Raw><![CDATA[\n{raw}\n  ]]></Raw>\n</AndroidAttestation>\n"
    )
}

/// Extract `-----BEGIN ...----- ... -----END ...-----` blocks from text.
fn extract_pem_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut cur = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("-----BEGIN ") {
            in_block = true;
            cur.clear();
            cur.push_str(line);
            cur.push('\n');
        } else if in_block {
            cur.push_str(line);
            cur.push('\n');
            if line.trim().starts_with("-----END ") {
                out.push(cur.clone());
                in_block = false;
                cur.clear();
            }
        }
    }
    out
}

/// Refresh a single source: fetch -> decode -> parse -> store.
pub fn refresh_one(src: &KeyboxSource, db: &Db) -> Vec<KeyboxData> {
    if src.search_repos {
        return refresh_public_source(src, db);
    }
    if src.api_list {
        return refresh_api_list_source(src, db);
    }
    let body = match fetch_source(src) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("autokeybox fetch failed source={} err={e}", src.name);
            return Vec::new();
        }
    };
    let decoded = maybe_decode_ns_payload(&body, src.decode_hex);
    let xml = build_keybox_xml(&decoded, &src.name);
    let parsed = match crate::keybox::parse_keybox_xml_all(&xml) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("autokeybox parse failed source={} err={e}", src.name);
            return Vec::new();
        }
    };
    if parsed.is_empty() {
        tracing::warn!("autokeybox parse empty source={}", src.name);
        return Vec::new();
    }
    // Store under the source's target device id (existing semantics) and return
    // the identities that were actually stored, so `refresh_all` can feed them
    // to the auto-cover step for every online B device id.
    let stored: Vec<KeyboxData> = parsed
        .into_iter()
        .filter(|kb| store_identity(db, src, &src.device_id, kb))
        .collect();
    tracing::info!(
        "autokeybox updated device_id={} source={} identities={}",
        src.device_id,
        src.name,
        stored.len()
    );
    stored
}

/// 采到的第 `taken` 份材料（从 0 起）挂在哪个 device_id 下。
///
/// A 端取公开 keybox 的路由扫的是主 id 加 `-1…-(PUBLIC_MAX_IDENTITIES-1)`，所以
/// 编号必须是「第几份材料」而不是仓库下标 —— 用下标的话第一份常常落在够不着的
/// 号上，采了跟没采一样。
pub fn public_device_id(base: &str, taken: usize) -> String {
    if taken == 0 {
        base.to_string()
    } else {
        format!("{base}-{taken}")
    }
}

/// 采集公开仓库里的 keybox。
///
/// 只花一次 API 调用（搜仓库），之后按常见路径直连 raw / CDN 取文件 —— 那些请求不
/// 算 GitHub API 配额，所以可以放心多试几个仓库和几个路径。拿到内容后走和其它源一
/// 样的解析 + 校验 + 入库流程，坏数据进不了池子。
fn refresh_public_source(src: &KeyboxSource, db: &Db) -> Vec<KeyboxData> {
    let body = match public_http_get(&src.url_primary, 25) {
        Some(b) => b,
        None => {
            tracing::warn!("autokeybox public search failed url={}", src.url_primary);
            return Vec::new();
        }
    };
    let repos: Vec<(String, String)> = match serde_json::from_str::<Value>(&body) {
        Ok(Value::Object(o)) => o
            .get("items")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|it| {
                        let full = it.get("full_name").and_then(Value::as_str)?;
                        let br = it
                            .get("default_branch")
                            .and_then(Value::as_str)
                            .unwrap_or("main");
                        Some((full.to_string(), br.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    if repos.is_empty() {
        tracing::warn!("autokeybox public search empty source={}", src.name);
        return Vec::new();
    }
    tracing::info!(
        "autokeybox public search source={} repos={}",
        src.name,
        repos.len()
    );

    let mut stored: Vec<KeyboxData> = Vec::new();
    let mut tried = 0usize;
    // 采到材料的第几个仓库 —— 编号要用这个，不是仓库下标。用下标的话第一份材料
    // 往往落在 device-b-2-9 这种位置，而 A 端取公开 keybox 的接口只扫主 id 和
    // -1/-2/-3，那份材料就等于白采了。
    let mut taken = 0usize;
    'outer: for (full, br) in repos.iter().take(PUBLIC_MAX_REPOS) {
        for path in PUBLIC_PATHS {
            for url in public_file_urls(src, full, br, path) {
                tried += 1;
                let txt = match public_http_get(&url, 8) {
                    Some(t) => t,
                    None => continue,
                };
                if !(txt.contains("BEGIN CERTIFICATE") || txt.contains("<AndroidAttestation")) {
                    continue;
                }
                let xml = build_keybox_xml(&maybe_decode_ns_payload(&txt, false), &src.name);
                // 解析失败不记 warn：同一个文件会因镜像被重试好几遍，一条 warn 重复
                // 好几次；debug 里能看到是哪个仓库的哪个 URL 挖到了东西但不成形。
                let parsed = match crate::keybox::parse_keybox_xml_all(&xml) {
                    Ok(p) if !p.is_empty() => p,
                    Ok(_) => {
                        tracing::debug!("autokeybox public parse empty repo={full} url={url}");
                        continue;
                    }
                    Err(e) => {
                        tracing::debug!(
                            "autokeybox public parse failed repo={full} url={url} err={e}"
                        );
                        continue;
                    }
                };
                // 第一份用源自己的 device_id，后面的往下排 -1、-2 …。只有真的入库了
                // 才往后排，不然校验不过的那几份会白占编号，后面的就跳过了一个号。
                let device_id = public_device_id(&src.device_id, taken);
                let before = stored.len();
                for kb in parsed {
                    if store_identity(db, src, &device_id, &kb) {
                        stored.push(kb);
                    }
                }
                if stored.len() > before {
                    taken += 1;
                }
                if stored.len() >= PUBLIC_MAX_IDENTITIES {
                    break 'outer;
                }
                // 这个仓库已经找到能用的 keybox 了，换下一个仓库（不然会接着拿
                // 同一个仓库的其他路径重复入库）。
                continue 'outer;
            }
        }
    }
    tracing::info!(
        "autokeybox updated device_id={} source={} identities={} urls_tried={tried}",
        src.device_id,
        src.name,
        stored.len()
    );
    stored
}

/// 公开源专用取文件 —— 走系统 curl，不走 reqwest。
///
/// gh-proxy 和 jsdelivr 都在 Cloudflare 后面，而这个机房里的 reqwest（rustls）
/// 过不了它的 bot 检查，会一直挂到超时；curl 实测每个都是秒回。服务端本来就装
/// 了 curl，这里不多一个依赖。
fn public_http_get(url: &str, timeout_secs: u64) -> Option<String> {
    match crate::http::get_text(url, Duration::from_secs(timeout_secs)) {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::debug!("autokeybox public get failed url={url} err={e}");
            None
        }
    }
}

/// 一个 raw.githubusercontent.com 链接的备选镜像。顺序按机房实测的可用性和速度
/// 排：gh-proxy 和 jsdelivr 都是秒回，raw 本身放最后兜底。
fn raw_url_mirrors(url: &str) -> Vec<String> {
    let Some(rest) = url.strip_prefix("https://raw.githubusercontent.com/") else {
        return Vec::new();
    };
    // rest 是 <owner>/<repo>/<branch>/<path...>
    let parts: Vec<&str> = rest.splitn(4, '/').collect();
    if parts.len() < 4 {
        return Vec::new();
    }
    vec![
        format!("https://gh-proxy.com/{url}"),
        format!(
            "https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}",
            owner = parts[0],
            repo = parts[1],
            branch = parts[2],
            path = parts[3]
        ),
    ]
}

/// 一个文件的几条候选取法：源自己配的镜像排最前，然后是上面的公共镜像，
/// raw 本身放最后兜底。
fn public_file_urls(src: &KeyboxSource, full: &str, branch: &str, path: &str) -> Vec<String> {
    let raw = format!("https://raw.githubusercontent.com/{full}/{branch}/{path}");
    let mut out: Vec<String> = Vec::new();
    let mirror = src.url_mirror.trim_end_matches('/');
    if !mirror.is_empty() {
        out.push(format!("{mirror}/{raw}"));
    }
    out.extend(raw_url_mirrors(&raw));
    out.push(raw);
    let mut seen = std::collections::HashSet::new();
    out.retain(|u| seen.insert(u.clone()));
    out
}

/// Refresh an API-list source: fetch the keybox list, filter `valid` entries,
/// download each, and match them to `device_id` with `-1`/`-2`/... suffixes.
/// Returns the identities that were fetched & stored (for the cover step).
fn refresh_api_list_source(src: &KeyboxSource, db: &Db) -> Vec<KeyboxData> {
    let list_body = match fetch_source(src) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!("autokeybox list fetch failed source={} err={e}", src.name);
            return Vec::new();
        }
    };
    // Parse the JSON list: { "keyboxes": [ { "identity", "status", ... } ] }
    let identities: Vec<String> = match serde_json::from_str::<Value>(&list_body) {
        Ok(Value::Object(o)) => o
            .get("keyboxes")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter(|kb| kb.get("status").and_then(Value::as_str) == Some("valid"))
                    .filter_map(|kb| kb.get("identity").and_then(Value::as_str).map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    };

    if identities.is_empty() {
        tracing::warn!("autokeybox list empty/parse failed source={}", src.name);
        return Vec::new();
    }
    tracing::info!(
        "autokeybox list source={} valid_count={}",
        src.name,
        identities.len()
    );

    let base = src.device_id.clone();
    let mut stored: Vec<KeyboxData> = Vec::new();
    for (i, identity) in identities.iter().enumerate() {
        // First valid keybox -> base device_id; subsequent -> base-N (base-1,
        // base-2, ...). The suffix is `i`, not `i + 1`, so the second identity
        // gets `base-1` as documented.
        let device_id = if i == 0 {
            base.clone()
        } else {
            format!("{base}-{i}")
        };
        match download_and_store(db, src, identity, &device_id) {
            Ok(kbs) if !kbs.is_empty() => {
                tracing::info!(
                    "autokeybox stored {device_id} source={} identities={}",
                    src.name,
                    kbs.len()
                );
                stored.extend(kbs);
            }
            Ok(_) => {
                tracing::warn!(
                    "autokeybox download rejected source={} identity={identity}",
                    src.name
                );
            }
            Err(e) => {
                tracing::warn!(
                    "autokeybox download failed source={} identity={identity} err={e}",
                    src.name
                );
            }
        }
    }
    stored
}

/// Download a single keybox by identity and store it under `device_id`.
/// Returns Ok(identities stored) on success, Ok(empty) if the server rejected
/// (e.g. bot challenge), Err on network/parse failure.
fn download_and_store(
    db: &Db,
    src: &KeyboxSource,
    identity: &str,
    device_id: &str,
) -> anyhow::Result<Vec<KeyboxData>> {
    // Step 1: POST /api/keyboxes/:identity/download -> { token, url }
    let dl_endpoint = format!("{}/api/keyboxes/{identity}/download", base_url(src));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Mozilla/5.0")
        .build()?;
    let resp = client
        .post(&dl_endpoint)
        .header("Content-Type", "application/json")
        .send()?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        // Server-side rejection (bot challenge / not found / forbidden).
        tracing::warn!("autokeybox download endpoint {dl_endpoint} -> {status}: {text}");
        return Ok(Vec::new());
    }
    // Parse token/url.
    let (token, direct_url) = match serde_json::from_str::<Value>(&text) {
        Ok(v) => (
            v.get("token").and_then(Value::as_str).map(String::from),
            v.get("url").and_then(Value::as_str).map(String::from),
        ),
        Err(_) => (None, None),
    };

    // Step 2: fetch the actual keybox content.
    let content = if let Some(url) = direct_url {
        crate::http::get_text(&url, Duration::from_secs(30))?
    } else if let Some(tok) = token {
        let dl_url = format!("{}/download/{tok}", base_url(src));
        crate::http::get_text(&dl_url, Duration::from_secs(30))?
    } else {
        // The download response itself might be the keybox content.
        if text.contains("BEGIN ") || text.contains("<Keybox") || text.contains("<?xml") {
            text
        } else {
            tracing::warn!("autokeybox download response unrecognized: {text}");
            return Ok(Vec::new());
        }
    };

    // Parse and store (may contain RSA + EC), returning what was stored so the
    // caller can feed it to the auto-cover step.
    let decoded = maybe_decode_ns_payload(&content, false);
    let xml = build_keybox_xml(&decoded, &src.name);
    let parsed = crate::keybox::parse_keybox_xml_all(&xml)?;
    let stored: Vec<KeyboxData> = parsed
        .into_iter()
        .filter(|kb| store_identity(db, src, device_id, kb))
        .collect();
    Ok(stored)
}

fn base_url(src: &KeyboxSource) -> String {
    // Strip the trailing /api/keyboxes to get the site root.
    let u = src.url_primary.clone();
    let u = u.trim_end_matches('/');
    if let Some(idx) = u.find("/api/") {
        u[..idx].to_string()
    } else {
        u.to_string()
    }
}

/// 入库前的质量门：私钥配不配链、链像不像造出来的、链上的证书有没有被吊销。
/// 返回 `Some(原因)` 表示这份材料该扔。
///
/// 吊销名单要联网，万一没拉下来（`attstatus` 那边会记 warn），这道就放行 ——
/// 不能因为网络问题把整条采集链路卡死。
fn reject_reason(private_key_pem: &str, chain_pem: &str) -> Option<String> {
    if let Some(why) = crate::cert::identity_problem(private_key_pem, chain_pem) {
        return Some(why);
    }
    if let Some((serial, status)) = crate::attstatus::revoked_reason(chain_pem) {
        return Some(format!(
            "certificate serial {serial} is {status} in the attestation status list"
        ));
    }
    None
}

/// Store an identity under a source's target device id. Returns whether it was
/// actually written (`false` when validation or the DB write failed).
fn store_identity(db: &Db, src: &KeyboxSource, device_id: &str, kb: &KeyboxData) -> bool {
    // 采集是自动跑的，宁可少收一份也不能把坏材料塞进池子 —— 出证时会直接失败。
    if let Some(why) = reject_reason(&kb.private_key_pem, &kb.certificate_chain_pem) {
        tracing::warn!(
            "autokeybox skip device_id={device_id} source={} reason={why}",
            src.name
        );
        return false;
    }
    let identity = crate::db::DeviceIdentity {
        device_id: device_id.to_string(),
        algorithm: kb.algorithm.clone(),
        certificate_chain_pem: kb.certificate_chain_pem.clone(),
        private_key_pem_cipher: kb.private_key_pem.clone(),
        active: true,
        machine_id: format!("auto:{}", src.name),
        created_at: String::new(),
    };
    match db.upsert_device_identity(&identity) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("autokeybox store failed device_id={device_id} err={e}");
            false
        }
    }
}

/// Store a fetched identity under `device_id`, tagged `auto-cover:<source>` so
/// `clear_auto_cover` can later remove exactly the rows this mode wrote.
fn store_cover_identity(db: &Db, device_id: &str, source: &str, kb: &KeyboxData) {
    if let Some(why) = reject_reason(&kb.private_key_pem, &kb.certificate_chain_pem) {
        tracing::warn!("autokeybox cover skip device_id={device_id} source={source} reason={why}");
        return;
    }
    let identity = crate::db::DeviceIdentity {
        device_id: device_id.to_string(),
        algorithm: kb.algorithm.clone(),
        certificate_chain_pem: kb.certificate_chain_pem.clone(),
        private_key_pem_cipher: kb.private_key_pem.clone(),
        active: true,
        machine_id: format!("auto-cover:{source}"),
        created_at: String::new(),
    };
    if let Err(e) = db.upsert_device_identity(&identity) {
        tracing::warn!(
            "autokeybox cover store failed device_id={device_id} source={source} err={e}"
        );
    }
}

/// Write every fetched identity into the server-side identity of every online B
/// device id (deduplicated by the (device_id, algorithm) unique key — later
/// identities in `fetched` order win, so each online id ends with one EC and/or
/// one RSA from a deterministic source order).
fn apply_cover(db: &Db, store: &TaskStore, fetched: &[(String, KeyboxData)]) {
    let online = store.connected_device_ids_sync();
    if online.is_empty() {
        tracing::info!("autokeybox cover: no online B device ids to cover");
        return;
    }
    tracing::info!(
        "autokeybox cover: writing {} fetched identity/ies into {} online B device id(s)",
        fetched.len(),
        online.len()
    );
    for device_id in &online {
        for (source, kb) in fetched {
            store_cover_identity(db, device_id, source, kb);
        }
    }
}

/// Delete every identity the auto-cover mode wrote (`machine_id auto-cover:*`).
/// Returns the number of deleted rows.
pub fn clear_auto_cover(db: &Db) -> anyhow::Result<u64> {
    let n = db.delete_device_identities_by_machine_prefix("auto-cover")?;
    tracing::info!("autokeybox cover cleared {n} auto-covered identities");
    Ok(n)
}

/// 拿吊销名单给池子做体检：`auto:*` / `auto-cover:*` 这些自动写进来的身份，链上
/// 有证书被吊销的就删掉，返回清了几条。
///
/// 只动自动写的行 —— 手动上传的身份是人自己挑的，删不删由人决定。同一个 device_id
/// 的 EC 和 RSA 是一份材料的两半，删的时候一起走。
fn sweep_revoked(db: &Db) -> usize {
    if crate::attstatus::cached().is_none() {
        return 0; // ensure() 里已经记过日志，这里不重复刷屏
    }
    let rows = match db.list_device_identities_meta() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("autokeybox status sweep: 读身份列表失败: {e}");
            return 0;
        }
    };
    let mut removed = 0;
    for row in rows {
        if !row.machine_id.starts_with("auto") {
            continue;
        }
        let Some((serial, status)) = crate::attstatus::revoked_reason(&row.certificate_chain_pem)
        else {
            continue;
        };
        tracing::warn!(
            "autokeybox status sweep: 已吊销 device_id={} algo={} machine_id={} serial={serial} status={status}",
            row.device_id,
            row.algorithm,
            row.machine_id
        );
        if let Err(e) = db.delete_device_identity(&row.device_id) {
            tracing::warn!("autokeybox status sweep: 删 {} 失败: {e}", row.device_id);
            continue;
        }
        removed += 1;
    }
    removed
}

/// Refresh all configured sources once (blocking). When the auto-cover flag is
/// on and the fetched identities are non-empty, also writes them into the
/// server-side identity of every online B device id (`store` provides the
/// online snapshot; pass `None` when no store is available — cover is skipped).
pub fn refresh_all(db: &Db, store: Option<&TaskStore>) {
    // 每轮先看一眼吊销名单，顺手给池子做个体检。被吊销的材料留在池子里只会害事
    // （出证时对面一查就拒），清掉之后这轮采集会把缺的槽位重新填上。
    crate::attstatus::ensure(false);
    let removed = sweep_revoked(db);
    if removed > 0 {
        tracing::warn!("autokeybox status sweep: 本轮清掉 {removed} 条已吊销身份");
    }
    let mut fetched: Vec<(String, KeyboxData)> = Vec::new();
    for src in configured_sources() {
        match std::panic::catch_unwind(|| refresh_one(&src, db)) {
            Ok(kbs) => {
                for kb in kbs {
                    fetched.push((src.name.clone(), kb));
                }
            }
            Err(e) => {
                tracing::warn!(
                    "autokeybox refresh panicked source={} err={:?}",
                    src.name,
                    e
                );
            }
        }
    }
    if cover_enabled() && !fetched.is_empty() {
        let chosen = cover_source();
        // Only the selected source's fetched keys take part in the cover.
        // "auto" = all sources in order (later wins per algorithm).
        let selected: Vec<(String, KeyboxData)> = if chosen == "auto" {
            fetched
        } else {
            fetched.into_iter().filter(|(s, _)| s == &chosen).collect()
        };
        if selected.is_empty() {
            tracing::warn!(
                "autokeybox cover: chosen source '{chosen}' fetched nothing this run; skip cover"
            );
        } else {
            tracing::info!(
                "autokeybox cover: using source '{chosen}' ({} identity/ies)",
                selected.len()
            );
            match store {
                Some(store) => apply_cover(db, store, &selected),
                None => tracing::warn!(
                    "autokeybox cover enabled but no online-device store available; skipping cover"
                ),
            }
        }
    }
}

/// Start the background refresh loop in a dedicated thread. Runs an immediate
/// refresh, then repeats every `interval`. Stops when the flag is cleared.
/// `store` is used (only when cover mode is on) to snapshot online B device ids.
pub fn start_background(db: Arc<Db>, store: Arc<TaskStore>, interval: Duration) {
    std::thread::Builder::new()
        .name("autokeybox".to_string())
        .spawn(move || {
            STARTED.store(true, Ordering::Relaxed);
            tracing::info!("autokeybox loop started interval={:?}", interval);
            loop {
                // 禁用时挂起等待而不是退出线程：一旦退出就没人再拉起（toggle 只翻
                // 标志位），admin 会一直报 enabled=true 而刷新早已停止。
                if !is_enabled() {
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
                refresh_all(&db, Some(store.as_ref()));
                // Sleep in small slices so a disable can be observed promptly.
                let mut waited = Duration::ZERO;
                while waited < interval {
                    if !is_enabled() {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                    waited += Duration::from_secs(1);
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src_for_test() -> KeyboxSource {
        KeyboxSource {
            name: "public".to_string(),
            device_id: "device-b-2".to_string(),
            url_primary: DEFAULT_PUBLIC_SEARCH_URL.to_string(),
            url_mirror: "https://gh-proxy.com/".to_string(),
            decode_hex: false,
            api_list: false,
            search_repos: true,
        }
    }

    /// 没有 `<?xml` 声明、直接 `<AndroidAttestation>` 开头的 keybox（yurikey 那
    /// 个 base64 解出来就是这形状，公开仓库里也有一半是）必须原样过 —— 一旦掉进
    /// PEM 合成分支，证书链就变空，拿去入库必然被校验拒掉。
    #[test]
    fn keybox_xml_without_a_declaration_passes_through() {
        let xml =
            "<AndroidAttestation>\n<NumberOfKeyboxes>1</NumberOfKeyboxes>\n</AndroidAttestation>";
        assert_eq!(build_keybox_xml(xml, "public"), xml);
    }

    /// 拆散的 PEM（私钥 + 证书各一段）合出来的 XML 得把证书真的挂到链接里，
    /// 不能只留一个空的 `<CertificateChain>`。
    #[test]
    fn synthesised_xml_pairs_the_certificate_with_the_key() {
        const KEY: &str = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
        const CERT: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        let xml = build_keybox_xml(&format!("{KEY}\n{CERT}\n"), "public");
        let parsed = crate::keybox::parse_keybox_xml_all(&xml).expect("synth xml should parse");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].cert_count, 1);
        assert!(parsed[0].private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(parsed[0]
            .certificate_chain_pem
            .contains("BEGIN CERTIFICATE"));
    }

    /// 取文件的候选 URL：源自己配的镜像排最前，raw 兜底，重复的去掉。重复的
    /// 请求看着无害，但一轮 240 个 URL 里白白多打几十个。
    #[test]
    fn file_urls_put_the_configured_mirror_first_and_dedupe() {
        let src = src_for_test();
        let urls = public_file_urls(&src, "a/b", "main", "keybox.xml");
        let raw = "https://raw.githubusercontent.com/a/b/main/keybox.xml";
        assert_eq!(urls[0], format!("https://gh-proxy.com/{raw}"));
        assert_eq!(urls.last().unwrap(), raw);
        assert_eq!(urls.len(), 3, "{urls:?}");
        let mut sorted = urls.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), urls.len(), "{urls:?}");
    }

    /// 编号方案要和 A 端取公开 keybox 的接口对得上：第一份必须在主 id 上。
    #[test]
    fn public_device_ids_start_at_the_base_id() {
        assert_eq!(public_device_id("device-b-2", 0), "device-b-2");
        assert_eq!(public_device_id("device-b-2", 1), "device-b-2-1");
        assert_eq!(
            public_device_id("device-b-2", PUBLIC_MAX_IDENTITIES - 1),
            format!("device-b-2-{}", PUBLIC_MAX_IDENTITIES - 1)
        );
    }

    /// raw 主址先走镜像、直连兜底；普通 API 主址还是主址优先。顺序错了不会
    /// 致命，但 raw 那条会先白等 30s 超时，而且真通了还要跟 CF 磨。
    #[test]
    fn fetch_order_puts_mirrors_before_a_raw_primary() {
        let raw = "https://raw.githubusercontent.com/Yurii0307/yurikey/main/key";
        let mut src = src_for_test();
        src.url_primary = raw.to_string();
        src.url_mirror = String::new();
        let got = fetch_candidates(&src);
        assert_eq!(got[0], format!("https://gh-proxy.com/{raw}"));
        assert_eq!(got.last().unwrap(), raw);

        let mut api = src_for_test();
        api.url_primary = "https://keybox.example.com/api/keyboxes".to_string();
        api.url_mirror = "https://mirror.example.com/api/keyboxes".to_string();
        assert_eq!(
            fetch_candidates(&api),
            vec![api.url_primary.clone(), api.url_mirror.clone()]
        );
    }

    /// raw 链接拆不干净时不要瞎拼镜像地址。
    #[test]
    fn raw_url_mirrors_ignores_foreign_hosts() {
        assert!(raw_url_mirrors("https://example.com/keybox.xml").is_empty());
        assert!(raw_url_mirrors("https://raw.githubusercontent.com/a/b").is_empty());
    }
}
