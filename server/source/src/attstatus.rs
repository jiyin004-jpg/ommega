//! Google attestation 吊销名单。
//!
//! 名单 JSON 的键是证书序列号，值是 `{status: REVOKED|SUSPENDED, reason: ...}`。
//! 链上任何一张证书都可能被列入，池子里留着这种 keybox，出证时对面一查就拒。
//!
//! 候选顺序：磁盘缓存 → 仓库镜像 → 本机代理问官方 → 直连官方。
//! 拉不到就沿用上一次的（哪怕过期）；一份都没有时不拦（`revoked_reason` 返回
//! None），只在日志里说明 —— 采集和出证不能被名单的网络问题卡死。这里只读不写库。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 名单有效期 6 小时：Google 那边大约一天才动一次。
const TTL: Duration = Duration::from_secs(6 * 60 * 60);
/// 仓库镜像，由 `.github/workflows/relay-assets.yml` 定时刷新。
const MIRROR: &str =
    "https://raw.githubusercontent.com/jiyin004-jpg/ommega/relay-assets/attestation-status.json";
const OFFICIAL: &str = "https://android.googleapis.com/attestation/status";
/// 本机出口代理。服务器直连官方地址不通，走它才通。
const PROXY_DEFAULT: &str = "http://127.0.0.1:7890";
/// 名单磁盘缓存路径，重启不必重新联网。
const CACHE_DEFAULT: &str = "/opt/relay/attestation_status.json";

#[derive(Debug, Default)]
pub struct StatusList {
    /// 十进制序列号 -> `REVOKED(KEY_COMPROMISE)` 形式的可读状态
    entries: HashMap<String, String>,
    fetched_at: u64,
    source: String,
}

impl StatusList {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 有 `len` 就得有它（clippy 的 `len_without_is_empty`）。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn age_secs(&self) -> u64 {
        now().saturating_sub(self.fetched_at)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cell() -> &'static RwLock<Option<Arc<StatusList>>> {
    static LIST: OnceLock<RwLock<Option<Arc<StatusList>>>> = OnceLock::new();
    LIST.get_or_init(|| RwLock::new(None))
}

/// 同一时刻只允许一个线程拉名单，避免并发重复请求。
fn fetch_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

// 锁中毒也继续用：存的是名单快照，读到旧数据比 panic 好。
fn read_cell() -> Option<Arc<StatusList>> {
    match cell().read() {
        Ok(g) => g.clone(),
        Err(e) => e.into_inner().clone(),
    }
}

fn write_cell(list: Arc<StatusList>) {
    match cell().write() {
        Ok(mut g) => *g = Some(list),
        Err(e) => *e.into_inner() = Some(list),
    }
}

fn cache_path() -> String {
    std::env::var("OMMEGA_ATTESTATION_STATUS_CACHE").unwrap_or_else(|_| CACHE_DEFAULT.to_string())
}

fn proxy_url() -> String {
    std::env::var("OMMEGA_OUT_PROXY").unwrap_or_else(|_| PROXY_DEFAULT.to_string())
}

/// 现在这份名单（可能是过期的，也可能是空的）。
pub fn cached() -> Option<Arc<StatusList>> {
    read_cell()
}

/// 解析名单 JSON。
/// 键有两种写法：十进制序列号与十六进制（RKP 的 128 位）。查询侧只按十进制找，
/// 所以每个键都要展开成别名，只认十进制会漏掉一大半。
pub fn parse(body: &str, source: &str) -> anyhow::Result<StatusList> {
    let v: serde_json::Value = serde_json::from_str(body)?;
    let entries = v
        .get("entries")
        .and_then(|e| e.as_object())
        .ok_or_else(|| anyhow::anyhow!("no entries object in status list"))?;
    let total = entries.len();
    let mut map = HashMap::with_capacity(total * 2);
    let mut hex_keys = 0usize;
    for (serial, val) in entries {
        let status = val
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("REVOKED");
        let reason = val.get("reason").and_then(|s| s.as_str()).unwrap_or("");
        let text = if reason.is_empty() {
            status.to_string()
        } else {
            format!("{status}({reason})")
        };
        if !serial.bytes().all(|b| b.is_ascii_digit()) {
            hex_keys += 1;
        }
        for alias in key_aliases(serial) {
            map.insert(alias, text.clone());
        }
    }
    tracing::info!(
        "attstatus: 名单 {total} 条（十六进制写法 {hex_keys} 个、十进制 {} 个），展开成 {} 个查表键",
        total - hex_keys,
        map.len()
    );
    Ok(StatusList {
        entries: map,
        fetched_at: now(),
        source: source.to_string(),
    })
}

/// 一个名单键的所有可能含义：原样，以及按十六进制解出的十进制形式。
/// 偶数长度的纯数字两种解释都合法，故都存 —— 顶多多一个别名，不会漏。
fn key_aliases(key: &str) -> Vec<String> {
    let k = key.trim().to_ascii_lowercase();
    let mut out = vec![k.clone()];
    if let Some(bytes) = hex_to_bytes(&k) {
        out.push(serial_decimal(&bytes));
    }
    out.sort();
    out.dedup();
    out
}

/// 十六进制字符串转字节。长度为奇、太长、含非 hex 字符都算不认。
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() > 128 || !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// 拉一份新名单：按候选顺序逐个试，成功就落盘并进内存。
/// 磁盘缓存是最后兜底 —— 网络全挂时旧名单也比没有强。
pub fn fetch() -> anyhow::Result<StatusList> {
    let mut last_err: Option<anyhow::Error> = None;
    let proxy = proxy_url();
    // 顺序：镜像（远端 raw 可能慢，超时放宽）→ 本地代理问官方 → 直连官方兜底。
    // 服务器直连 android.googleapis.com 走不通，直连这项只是备用。
    let attempts = [
        (MIRROR, 30u64, false),
        (OFFICIAL, 20, true),
        (OFFICIAL, 15, false),
    ];
    for (url, secs, via_proxy) in attempts {
        let timeout = Duration::from_secs(secs);
        let got = if via_proxy {
            crate::http::get_text_via(url, timeout, &proxy)
        } else {
            crate::http::get_text(url, timeout)
        };
        match got {
            Ok(body) => match parse(&body, url) {
                Ok(list) => {
                    let path = cache_path();
                    if let Err(e) = std::fs::write(&path, &body) {
                        tracing::warn!("attstatus: 写缓存 {path} 失败: {e}");
                    }
                    return Ok(list);
                }
                Err(e) => {
                    tracing::warn!("attstatus: 解析 {url} 失败: {e}");
                    last_err = Some(e);
                }
            },
            Err(e) => {
                if via_proxy {
                    tracing::warn!("attstatus: 经代理 {proxy} 拉 {url} 失败: {e}");
                } else {
                    tracing::warn!("attstatus: 拉 {url} 失败: {e}");
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no status list URL")))
}

/// 从磁盘缓存读一份，启动或网络全挂时用。
fn load_cache() -> Option<StatusList> {
    let path = cache_path();
    let meta = std::fs::metadata(&path).ok()?;
    let body = std::fs::read_to_string(&path).ok()?;
    // 用文件 mtime 当抓取时间：新旧看的是抓取时刻，不是读取时刻。
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match parse(&body, &format!("cache:{path}")) {
        Ok(mut list) => {
            list.fetched_at = mtime;
            Some(list)
        }
        Err(e) => {
            tracing::warn!("attstatus: 缓存 {path} 解析失败: {e}");
            None
        }
    }
}

/// 保证内存里有一份名单，返回当前可用的那份。
/// `force = false` 仅在「没有」或「过期」时拉取；`force = true` 是手动刷新。
pub fn ensure(force: bool) -> Option<Arc<StatusList>> {
    // 拿锁后重查新鲜度：并发调用者只会外发一次请求。
    let _guard = match fetch_lock().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let current = cached();
    // 内存为空时先读磁盘缓存垫上，重启和断网启动都不必等联网。
    let current = match current {
        Some(list) => Some(list),
        None => match load_cache() {
            Some(list) => {
                let list = Arc::new(list);
                tracing::info!(
                    "attstatus: 启动时用磁盘缓存 {} 条（{} 秒前抓的）",
                    list.len(),
                    list.age_secs()
                );
                write_cell(list.clone());
                Some(list)
            }
            None => None,
        },
    };
    if !force {
        if let Some(list) = &current {
            if list.age_secs() < TTL.as_secs() {
                return Some(list.clone());
            }
        }
    }
    match fetch() {
        Ok(list) => {
            let list = Arc::new(list);
            tracing::info!(
                "attstatus: 名单已更新 {} 条 source={}",
                list.len(),
                list.source()
            );
            write_cell(list.clone());
            Some(list)
        }
        Err(e) => {
            if current.is_none() {
                if let Some(list) = load_cache() {
                    let list = Arc::new(list);
                    tracing::warn!(
                        "attstatus: 拉取失败（{e}），改用磁盘缓存 {} 条，抓取时间 {} 秒前",
                        list.len(),
                        list.age_secs()
                    );
                    write_cell(list.clone());
                    return Some(list);
                }
            }
            match current {
                Some(list) => {
                    tracing::warn!(
                        "attstatus: 拉取失败（{e}），沿用内存里那份（{} 秒前抓的，{} 条）",
                        list.age_secs(),
                        list.len()
                    );
                    Some(list)
                }
                None => {
                    tracing::warn!("attstatus: 一份名单都没有（{e}），这轮不查吊销");
                    None
                }
            }
        }
    }
}

/// 链上任一证书被吊销就返回（序列号, 状态）；没有名单时返回 None。
/// 每张证书都查：泄露的多半是整条链，Google 可能挂其中任意一张。
pub fn revoked_reason(chain_pem: &str) -> Option<(String, String)> {
    let list = cached()?;
    lookup(&list, &chain_serials(chain_pem))
}

/// 拿一串序列号（十进制）去名单里翻。
fn lookup(list: &StatusList, serials: &[String]) -> Option<(String, String)> {
    for serial in serials {
        if let Some(status) = list.entries.get(serial) {
            return Some((serial.clone(), status.clone()));
        }
    }
    None
}

/// 证书链上每张证书的序列号（十进制字符串，leaf 在前）。
fn chain_serials(chain_pem: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(certs) = crate::cert::parse_chain_pem(chain_pem) else {
        return out;
    };
    for der in &certs {
        if let Ok((_, c)) = x509_parser::parse_x509_certificate(der) {
            out.push(serial_decimal(c.raw_serial()));
        }
    }
    out
}

/// 序列号（大端字节）转十进制字符串，名单里的键就是这个形式。
/// 手写代替 BigInt：序列号最多二十来个字节，这点乘加够用。
fn serial_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0]; // 十进制位，低位在前
    for b in bytes {
        let mut carry = *b as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    let s: String = digits.iter().rev().map(|d| (b'0' + d) as char).collect();
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_decimal_matches_openssl() {
        // 根证书序列号 D50FF25BA3F2D6B3 对应的十进制值
        assert_eq!(
            serial_decimal(&[0xD5, 0x0F, 0xF2, 0x5B, 0xA3, 0xF2, 0xD6, 0xB3]),
            "15352756130135856819"
        );
        assert_eq!(serial_decimal(&[0x01]), "1");
        assert_eq!(serial_decimal(&[0x00, 0x01]), "1");
        assert_eq!(serial_decimal(&[0x00]), "0");
        assert_eq!(serial_decimal(&[0xFF]), "255");
    }

    #[test]
    fn parse_keeps_status_and_reason() {
        let body = r#"{"entries":{"123":{"status":"REVOKED","reason":"KEY_COMPROMISE"},
                                  "456":{"status":"SUSPENDED"}}}"#;
        let list = parse(body, "test").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list.entries.get("123").unwrap(), "REVOKED(KEY_COMPROMISE)");
        assert_eq!(list.entries.get("456").unwrap(), "SUSPENDED");
    }

    #[test]
    fn parse_rejects_junk() {
        assert!(parse("not json", "test").is_err());
        assert!(parse("{}", "test").is_err());
    }

    /// 十六进制键必须在加载时转出十进制别名，否则查询侧会漏。
    #[test]
    fn hex_and_decimal_keys_both_hit() {
        // 第一个键是十六进制写法：5cb838f1fe157a85 = 6681152659205225093
        let body = r#"{"entries":{"5cb838f1fe157a85":{"status":"REVOKED","reason":"KEY_COMPROMISE"},
                                  "259652641773276899376585379834768919766":{"status":"SUSPENDED"}}}"#;
        let list = parse(body, "test").unwrap();
        let dec_of_hex = serial_decimal(&[0x5C, 0xB8, 0x38, 0xF1, 0xFE, 0x15, 0x7A, 0x85]);
        assert_eq!(dec_of_hex, "6681152659205225093");
        assert!(lookup(&list, &[dec_of_hex]).is_some());
        assert!(lookup(
            &list,
            &["259652641773276899376585379834768919766".to_string()]
        )
        .is_some());
        assert!(lookup(&list, &["12345".to_string()]).is_none());
    }

    #[test]
    fn key_aliases_cover_both_spellings() {
        let a = key_aliases("c35747a084470c3135aeefe2b8d40cd6");
        assert!(a.contains(&"c35747a084470c3135aeefe2b8d40cd6".to_string()));
        assert!(a.contains(&"259652641773276899376585379834768919766".to_string()));
        // 长度为奇的十六进制（不合法的写法）只留原样
        assert_eq!(key_aliases("abc"), vec!["abc".to_string()]);
    }

    #[test]
    fn chain_serials_are_decimal() {
        // 自签假链，只验序列号转出来是纯数字
        let id = crate::cert::generate_self_signed("ec", 1).unwrap();
        let serials = chain_serials(&id.certificate_chain_pem);
        assert!(!serials.is_empty());
        for s in serials {
            assert!(s.bytes().all(|b| b.is_ascii_digit()), "{s} 不是十进制");
        }
    }
}
