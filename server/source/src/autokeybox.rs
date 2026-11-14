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

/// 后台线程是否真的被拉起来了：线程只在 `KEYBOX_REFRESH_ENABLED=true` 时由 main
/// 启动一次，与 `ENABLED` 分开记，才能分辨"开关开着但没有线程"。
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

/// 管理接口改过的开关落在 statedb 的 meta 里，重启后以它为准（否则又退回 .env）。
const META_KEY: &str = "keybox_refresh";

/// 算出这台服务端开机后的实际开关：持久化的值优先，没有才用启动配置。
pub fn desired_from_state(config_value: bool) -> bool {
    match crate::statedb::shared().get_meta(META_KEY) {
        Ok(Some(v)) => v == "1",
        Ok(None) => config_value,
        Err(e) => {
            tracing::warn!("autokeybox: 读持久化开关失败，用启动配置: {e:#}");
            config_value
        }
    }
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
    // 写穿：重启后按它恢复，而不是回到 .env 里的启动值。
    if let Err(e) = crate::statedb::shared().set_meta(META_KEY, if v { "1" } else { "0" }) {
        tracing::warn!("autokeybox: 持久化开关失败: {e:#}");
    }
}

/// Global enable flag for the auto-cover step: after an auto-keybox refresh
/// successfully fetches keys, also write them (unconditionally) into the
/// server-side identity of every currently-online B device id, so serverbox
/// mode can attest for those devices. Disabling clears the rows it wrote.
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

/// 公开源默认的仓库搜索入口：匿名 search 限 10 次/分钟，两小时一次余量充足。
const DEFAULT_PUBLIC_SEARCH_URL: &str =
    "https://api.github.com/search/repositories?q=keybox&sort=updated&per_page=30";
/// 一轮最多看几个仓库、最多收几条身份 —— 别让一轮刷新跑太久。
const PUBLIC_MAX_REPOS: usize = 20;
pub const PUBLIC_MAX_IDENTITIES: usize = 6;
/// 一个仓库最多下几个文件：公开仓库常躺几十个 keybox，EC 与 RSA 各一份就够。
const PUBLIC_MAX_FILES_PER_REPO: usize = 8;
/// 整轮公开源最多下几个文件（跨仓库一起算）。
const PUBLIC_MAX_FILES_TOTAL: usize = 24;
/// 列不出目录时退回的常见 keybox 路径。
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
            // 文件走 raw 直取、不吃 API 配额，所以这一项是取文件失败时的镜像，不是 API 镜像。
            url_mirror: env("KEYBOX_PUBLIC_MIRROR", "https://gh-proxy.com/"),
            decode_hex: false,
            api_list: false,
            search_repos: true,
        },
    ]
}

// Fetch a URL over http/https via `crate::http::get_text`; see there for why
// reqwest is not used.

/// Fetch the source body.
/// 候选顺序：主址是 raw 链接时压到最后兜底（直连常 30s 超时或被 Cloudflare 挡），
/// 公共镜像优先；主址不是 raw 的（API 类源）仍主址优先。重复地址去掉。
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
    // 已是 keybox XML 就直接过。不能只认 `<?xml` 开头：有些源省了声明，直接以
    // `<AndroidAttestation>` 开头，误判会掉进 PEM 合成分支并拼出空证书链。
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
        // 证书按顺序挂到每把钥匙下；无证书时链为空，入库校验会拒掉这份材料。
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

/// 第 `taken` 份材料（从 0 起）挂在哪个 device_id 下。
/// A 端只扫主 id 加 `-1…-(PUBLIC_MAX_IDENTITIES-1)`，所以编号必须按「第几份材料」
/// 而不是仓库下标，否则第一份常落在够不着的号上。
pub fn public_device_id(base: &str, taken: usize) -> String {
    if taken == 0 {
        base.to_string()
    } else {
        format!("{base}-{taken}")
    }
}

/// 采集公开仓库里的 keybox。
/// 只花一次 API 调用（搜仓库），之后直连 raw / CDN 取文件不吃 GitHub 配额；
/// 内容走与其它源相同的解析、校验、入库流程。
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
    // 已采到的材料份数：编号用它，不是仓库下标（见 public_device_id）。
    let mut taken = 0usize;
    // 本轮已下文件数，以及已到手算法（EC、RSA 各一份即可收工）。
    let mut files_fetched = 0usize;
    let mut algos: std::collections::HashSet<String> = std::collections::HashSet::new();
    'outer: for (full, br) in repos.iter().take(PUBLIC_MAX_REPOS) {
        // 先列出仓库里的 .xml 再挑着下：只试固定路径会漏掉 `Yurikey58.xml` 这类文件。
        let mut paths: Vec<String> = public_repo_xml_files(full, br)
            .into_iter()
            .take(PUBLIC_MAX_FILES_PER_REPO)
            .collect();
        if paths.is_empty() {
            paths = PUBLIC_PATHS.iter().map(|p| (*p).to_string()).collect();
        }
        for path in paths {
            if files_fetched >= PUBLIC_MAX_FILES_TOTAL {
                break 'outer;
            }
            for url in public_file_urls(src, full, br, &path) {
                tried += 1;
                let txt = match public_http_get(&url, 8) {
                    Some(t) => t,
                    None => continue,
                };
                files_fetched += 1;
                if !(txt.contains("BEGIN CERTIFICATE") || txt.contains("<AndroidAttestation")) {
                    continue;
                }
                let xml = build_keybox_xml(&maybe_decode_ns_payload(&txt, false), &src.name);
                // 解析失败只记 debug：同一文件会被多个镜像重试，warn 会重复刷屏。
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
                // 第一份用源自己的 device_id，之后排 -1、-2…；只有真入库才递增，
                // 否则被校验拒掉的会白占编号。
                let device_id = public_device_id(&src.device_id, taken);
                let before = stored.len();
                for kb in parsed {
                    if store_identity(db, src, &device_id, &kb) {
                        algos.insert(kb.algorithm.clone());
                        stored.push(kb);
                    }
                }
                if stored.len() >= PUBLIC_MAX_IDENTITIES {
                    break 'outer;
                }
                if stored.len() > before {
                    taken += 1;
                }
                // EC 与 RSA 常分处同一仓库的不同文件，本文件处理完先看同仓库的下一个。
                break;
            }
            if algos.contains("ec") && algos.contains("rsa") {
                break 'outer;
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

/// 公开源专用取文件，走系统 curl。
/// gh-proxy 和 jsdelivr 在 Cloudflare 后面，reqwest（rustls）过不了 bot 检查会挂到
/// 超时，curl 则正常；服务端已装 curl，不额外引入依赖。
fn public_http_get(url: &str, timeout_secs: u64) -> Option<String> {
    match crate::http::get_text(url, Duration::from_secs(timeout_secs)) {
        Ok(t) => Some(t),
        Err(e) => {
            tracing::debug!("autokeybox public get failed url={url} err={e}");
            None
        }
    }
}

/// URL 路径转义：公开仓库的文件名含空格、引号、括号（如 `keybox (1).xml`），
/// 原样拼进 URL 会被 curl 拒收。保留 RFC3986 允许的路径字符，其余编码为 %XX。
fn url_encode_path(p: &str) -> String {
    let mut out = String::new();
    for b in p.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'/'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// 列一个仓库里所有 .xml 文件的相对路径。
/// 用 jsdelivr 的 data 接口列目录（不要 token，不吃 GitHub 匿名限额）；列不出来
/// （仓库未被分发 / 接口失败）返回空，调用方退回固定常见路径。
fn public_repo_xml_files(full: &str, branch: &str) -> Vec<String> {
    let url = format!("https://data.jsdelivr.com/v1/packages/gh/{full}@{branch}?structure=flat");
    let Some(txt) = public_http_get(&url, 10) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<Value>(&txt) else {
        return Vec::new();
    };
    let Some(arr) = v.get("files").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|f| f.get("name").and_then(Value::as_str))
        .filter(|n| n.to_ascii_lowercase().ends_with(".xml"))
        .map(|n| url_encode_path(n.trim_start_matches('/')))
        .collect()
}

/// raw.githubusercontent.com 链接的备选镜像：gh-proxy、jsdelivr，raw 本身兜底。
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

/// 一个文件的候选取法：源自己配的镜像最前，然后是公共镜像，raw 兜底。
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

/// 入库前的质量门：私钥是否配链、链是否像伪造、证书是否被吊销。
/// 返回 `Some(原因)` 表示该丢弃。吊销名单需联网，拉不到时放行，不因网络问题
/// 卡死采集链路。
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

/// 该 device id 是否被控制台钉成 StrongBox 身份。
/// 源采集（含 cover）只能写 TEE 那份，StrongBox 一律人工指定，采集入口都先过这道。
fn is_strongbox_identity(device_id: &str) -> bool {
    crate::identity_policy::snapshot().1.as_deref() == Some(device_id)
}

/// Store an identity under a source's target device id. Returns whether it was
/// actually written (`false` when validation or the DB write failed).
fn store_identity(db: &Db, src: &KeyboxSource, device_id: &str, kb: &KeyboxData) -> bool {
    // 源采集只喂 TEE：被钉成 StrongBox 的 id 不能写，否则级别串用。
    if is_strongbox_identity(device_id) {
        tracing::warn!(
            "autokeybox skip device_id={device_id} source={} reason=strongbox identity is manual-only",
            src.name
        );
        return false;
    }
    // 采集自动运行：坏材料入池会让出证直接失败，宁可少收一份。
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
    if is_strongbox_identity(device_id) {
        tracing::warn!(
            "autokeybox cover skip device_id={device_id} source={source} reason=strongbox identity is manual-only"
        );
        return;
    }
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

/// 用吊销名单清池子：自动写入的身份（`auto:*` / `auto-cover:*`）链上有证书被
/// 吊销即删除，返回清除条数。只动自动写的行；同一 device_id 的 EC 与 RSA 一起删。
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
    // 每轮先查吊销名单清理池子（吊销材料会让出证被拒），随后本轮采集会补上缺的槽位。
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
                // 禁用时挂起而非退出线程：退出后没人再拉起（toggle 只翻标志位），
                // admin 会一直报 enabled=true 而刷新早已停止。
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

    /// 公开仓库文件名带空格、引号、括号，不编码 curl 会报 "URL rejected"。
    #[test]
    fn public_file_names_get_url_encoded() {
        assert_eq!(url_encode_path("keybox (1).xml"), "keybox%20(1).xml");
        assert_eq!(
            url_encode_path("don't buy! it's free for you_v68.xml"),
            "don't%20buy!%20it's%20free%20for%20you_v68.xml"
        );
        assert_eq!(url_encode_path("Yurikey58.xml"), "Yurikey58.xml");
        // `?` 和 `#` 必须转义，否则会被当成查询串/片段的开头。
        assert_eq!(url_encode_path("a?b#c.xml"), "a%3Fb%23c.xml");
    }

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

    /// 无 `<?xml` 声明、直接 `<AndroidAttestation>` 开头的 keybox 必须原样过：
    /// 一旦掉进 PEM 合成分支，证书链为空，入库必被校验拒掉。
    #[test]
    fn keybox_xml_without_a_declaration_passes_through() {
        let xml =
            "<AndroidAttestation>\n<NumberOfKeyboxes>1</NumberOfKeyboxes>\n</AndroidAttestation>";
        assert_eq!(build_keybox_xml(xml, "public"), xml);
    }

    /// 拆散的 PEM（私钥 + 证书）合成 XML 时证书必须真挂进链，不能是空 `<CertificateChain>`。
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

    /// 取文件的候选 URL：源自己配的镜像最前，raw 兜底，并去重。
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

    /// raw 主址先走镜像、直连兜底；API 主址仍主址优先（否则先白等 30s 超时）。
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
