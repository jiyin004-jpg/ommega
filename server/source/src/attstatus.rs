//! Google 的 attestation 吊销名单。
//!
//! 名单本体是 `android.googleapis.com/attestation/status` 那份 JSON：键是证书序列号的
//! **十进制**字符串，值是 `{status: REVOKED|SUSPENDED, reason: ...}`。keybox 里那套
//! 私钥加证书链，就是被 KeyMint 拿去签 attestation 的东西，所以链上任何一张证书的
//! 序列号都可能出现在这份名单里 —— 池子里留着被吊销的 keybox，出证时对面一查就拒，
//! 还不如早点扔掉换一份。
//!
//! 这台机器直连不到 googleapis（墙里），所以候选顺序是：
//!   1. 本地磁盘缓存（够新就直接用，连请求都不发）
//!   2. 我们自己仓库里的镜像（GitHub Actions 定时抓，服务器能直连 raw）
//!   3. 本机的小代理出去问官方地址（mihomo 挂在 127.0.0.1:7890，实测 0.2 秒回）
//!   4. 实在不行再直连官方地址兜一手（当前线路下走不通，留着备用）
//!
//! 拉不到就沿用上一次的，哪怕已经过期；一份都没有的时候不拦（`revoked_reason`
//! 返回 None），只在日志里说明。采集和出证不能被这份名单的网络问题卡死。
//!
//! 名单是给「已经入库的身份」和「正要入库的身份」做体检用的，所以这里只读不写库。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 名单多新算够新。Google 那边大概一天动一次，六小时拉一回足够。
const TTL: Duration = Duration::from_secs(6 * 60 * 60);
/// 我们自己仓库里的镜像，由 `.github/workflows/relay-assets.yml` 定时刷新。
const MIRROR: &str =
    "https://raw.githubusercontent.com/jiyin004-jpg/ommega/relay-assets/attestation-status.json";
const OFFICIAL: &str = "https://android.googleapis.com/attestation/status";
/// 本机出墙代理（mihomo，见 /etc/mihomo/config.yaml）。服务器直连官方地址是不通的，
/// 走它就秒回；它自身不可用时退回直连，再不行才用磁盘缓存。
const PROXY_DEFAULT: &str = "http://127.0.0.1:7890";
/// 拉下来的名单存这儿，重启不用重新联网。
const CACHE_DEFAULT: &str = "/opt/relay/attestation_status.json";

#[derive(Debug, Default)]
pub struct StatusList {
    /// 序列号（十进制字符串）-> `REVOKED(KEY_COMPROMISE)` 这种可读状态
    entries: HashMap<String, String>,
    fetched_at: u64,
    source: String,
}

impl StatusList {
    pub fn len(&self) -> usize {
        self.entries.len()
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

/// 同一时刻只让一个线程去拉名单，别在同一秒里往外甩好几个请求。
fn fetch_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

// 锁中毒（别的线程 panic 在里面）也接着用：这儿存的就是一份名单快照，
// 真出问题大不了读到旧数据，比直接 panic 好。
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
///
/// 键有两种写法，实测各占一半：一部分是十进制序列号（浅年头的 attestation 证书，
/// 序列号才六十来位），一部分是十六进制（RKP 那些 128 位的）。所以每个键都要展开成
/// 别名存着，查询那边只拿十进制去找 —— 光认十进制会漏掉一半条目。
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

/// 一个名单键可能的所有含义：原样，以及把它当十六进制数读出来的十进制形式。
///
/// 纯数字的键放哪个筐里都不奇怪（偶数长度的纯数字既是合法十进制也是合法十六进制），
/// 所以两种都存 —— 顶多多一个别名，不会漏。
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
    if s.is_empty() || s.len() > 128 || s.len() % 2 != 0 {
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

/// 拉一份新名单。先把能用的候选按顺序试一遍，成功就落盘 + 进内存。
///
/// 磁盘缓存是最后兜底：网络全挂的时候，一份旧名单也比没有强。
pub fn fetch() -> anyhow::Result<StatusList> {
    let mut last_err: Option<anyhow::Error> = None;
    let proxy = proxy_url();
    // 顺序有讲究：先走墙内镜像（远端 raw 偶尔要 10 秒才回，超时给宽点）；镜像还没上线
    // 或拉不到时，直接经本地代理问 Google（实测 0.2 秒）；最后才是直连官方兜底
    // —— 服务器到 android.googleapis.com 是连不通的，留着只是为了它哪天网络变好。
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

/// 从磁盘缓存读一份（启动时用，或网络全挂时兜底）。
fn load_cache() -> Option<StatusList> {
    let path = cache_path();
    let meta = std::fs::metadata(&path).ok()?;
    let body = std::fs::read_to_string(&path).ok()?;
    // 文件时间当抓取时间：判断新旧要看内容是什么时候抓的，不是什么时候读的。
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

/// 保证内存里有一份名单。
///
/// `force = false` 时只在「没有」或「过期」时才去拉；`force = true` 用于手动刷新。
/// 返回当前可用的那份。
pub fn ensure(force: bool) -> Option<Arc<StatusList>> {
    // 启动那一瞬有两处会同时要名单（常驻刷新线程 + 采集/出证那条路），不加锁就
    // 会各自往外发一次请求。拿住锁的人先再查一遍新鲜度，第二个人就直接拿现成的。
    let _guard = match fetch_lock().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let current = cached();
    // 刚启动时内存是空的，但磁盘上可能躺着一份还够新的（TTL 内），先拿它垫上，
    // 重启就不用干等着联网了；断网的时候启动也不会为此卡一下。
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

/// 这批证书链里有没有被吊销的。命中就返回（序列号, 状态），没名单时返回 None。
///
/// 链上每张证书都查：泄露出去的多半是整条链，Google 那边挂哪一张都有可能。
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

/// 序列号（大端字节）转十进制字符串 —— 名单里的键就是这个形式。
///
/// 手写而不是拉 BigInt 进来：序列号最多二十来个字节，这点乘加够用了。
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
        // 池子里那份 keybox 的根证书序列号，openssl 读出来是 D50FF25BA3F2D6B3
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

    /// 名单里两种写法混着（实测 977 个十进制 + 778 个十六进制），查询只拿十进制去找，
    /// 所以十六进制键必须在加载时就转出十进制别名。
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

    /// 链上的序列号要转成十进制再查：名单的键就是这个形式。
    #[test]
    fn chain_serials_are_decimal() {
        // 一条自签的假链，序列号是随机生的 —— 只验它转出来的是纯数字
        let id = crate::cert::generate_self_signed("ec").unwrap();
        let serials = chain_serials(&id.certificate_chain_pem);
        assert!(!serials.is_empty());
        for s in serials {
            assert!(s.bytes().all(|b| b.is_ascii_digit()), "{s} 不是十进制");
        }
    }
}
