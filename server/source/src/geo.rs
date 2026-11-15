//! Offline IP-to-region lookup using the ip2region `ip2region.xdb` database.
//!
//! Implements the xdb v2 memory-search algorithm (same as the official
//! `binding/c/xdb_searcher.c`):
//!   - 256-byte header
//!   - 256 x 256 vector index (each entry 8 bytes: s_ptr + e_ptr, little-endian)
//!   - segment index entries: start_ip(4) + end_ip(4) + data_len(2) + data_ptr(4)
//!   - region string format: `国家|区域|省份|城市|ISP`
//!
//! The database is loaded fully into memory once; lookups are pure in-memory
//! binary search (no disk I/O per query).

use std::sync::Arc;

const HEADER_LEN: usize = 256;
const VECTOR_INDEX_COLS: usize = 256;
const VECTOR_INDEX_SIZE: usize = 8; // s_ptr(4) + e_ptr(4)
const SEGMENT_INDEX_SIZE: usize = 14; // start_ip(4) + end_ip(4) + data_len(2) + data_ptr(4)

pub struct Ip2Region {
    data: Arc<Vec<u8>>,
}

impl Ip2Region {
    /// Load the xdb database from `path`. Returns None if the file is missing
    /// or invalid (lookups then gracefully return an empty region).
    pub fn load(path: &str) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        if bytes.len() <= HEADER_LEN {
            return None;
        }
        Some(Self {
            data: Arc::new(bytes),
        })
    }

    /// 这个 IP 落在哪个省；没库、没命中、境外都返回空串。
    pub fn province(&self, ip: &str) -> String {
        self.search(ip).map(|r| province_of(&r)).unwrap_or_default()
    }

    /// Look up an IPv4 address (dotted-quad string). Returns the region string
    /// `国家|区域|省份|城市|ISP`, or `None` if not found / not IPv4.
    pub fn search(&self, ip: &str) -> Option<String> {
        let ip_bytes = parse_ipv4(ip)?;
        let buf = &self.data;

        // Vector index: use the first two bytes of the IP.
        let il0 = ip_bytes[0] as usize;
        let il1 = ip_bytes[1] as usize;
        let idx = il0 * VECTOR_INDEX_COLS * VECTOR_INDEX_SIZE + il1 * VECTOR_INDEX_SIZE;
        let idx_off = HEADER_LEN + idx;
        if idx_off + VECTOR_INDEX_SIZE > buf.len() {
            return None;
        }
        let s_ptr = read_u32_le(buf, idx_off)? as usize;
        let e_ptr = read_u32_le(buf, idx_off + 4)? as usize;
        if s_ptr == 0 || e_ptr == 0 {
            return None;
        }

        // Binary search over segment index entries within [s_ptr, e_ptr).
        let mut l: usize = 0;
        let mut h: usize = (e_ptr - s_ptr) / SEGMENT_INDEX_SIZE;
        while l <= h {
            let m = (l + h) >> 1;
            let p = s_ptr + m * SEGMENT_INDEX_SIZE;
            if p + SEGMENT_INDEX_SIZE > buf.len() {
                return None;
            }
            let seg_start = &buf[p..p + 4];
            let seg_end = &buf[p + 4..p + 8];
            match ip_bytes.as_slice().cmp(seg_start) {
                std::cmp::Ordering::Less => {
                    if m == 0 {
                        break;
                    }
                    h = m - 1;
                }
                std::cmp::Ordering::Greater => {
                    if ip_bytes.as_slice() > seg_end {
                        l = m + 1;
                    } else {
                        // within [seg_start, seg_end]
                        let data_len = read_u16_le(buf, p + 8)? as usize;
                        let data_ptr = read_u32_le(buf, p + 10)? as usize;
                        return read_region(buf, data_ptr, data_len);
                    }
                }
                std::cmp::Ordering::Equal => {
                    let data_len = read_u16_le(buf, p + 8)? as usize;
                    let data_ptr = read_u32_le(buf, p + 10)? as usize;
                    return read_region(buf, data_ptr, data_len);
                }
            }
        }
        None
    }
}

/// 地区串 `国家|区域|省份|城市|ISP` 里的省份那一段。
/// 空串 / `0`（ip2region 对保留段的取值）都当没识别出来。
pub fn province_of(region: &str) -> String {
    let raw = region.split('|').nth(2).unwrap_or("").trim();
    if raw.is_empty() || raw == "0" {
        return String::new();
    }
    raw.to_string()
}

/// 省份主体名：去掉行政区划后缀，`广东省` 和 `广东` 算同一个。
fn province_core(province: &str) -> &str {
    let p = province.trim();
    for suffix in ["特别行政区", "自治区", "省", "市"] {
        if let Some(stripped) = p.strip_suffix(suffix) {
            return stripped;
        }
    }
    p
}

/// 两次请求是不是同一个省。
///
/// 任一边没识别出省份（境外 IP、VPN、没装库）就当「判断不了」放行 ——
/// 不能因为解析不出来把人锁在卡片外面。
pub fn same_province(a: &str, b: &str) -> bool {
    let a = province_core(a);
    let b = province_core(b);
    a.is_empty() || b.is_empty() || a == b
}

fn read_region(buf: &[u8], ptr: usize, len: usize) -> Option<String> {
    let end = ptr.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[ptr..end]).into_owned())
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*buf.get(off)?, *buf.get(off + 1)?]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *buf.get(off)?,
        *buf.get(off + 1)?,
        *buf.get(off + 2)?,
        *buf.get(off + 3)?,
    ]))
}

#[cfg(test)]
mod province_tests {
    use super::{province_of, same_province};

    #[test]
    fn province_of_takes_the_third_field() {
        assert_eq!(province_of("中国|0|广东省|深圳市|电信"), "广东省");
        assert_eq!(province_of("中国|0|北京市|北京市|联通"), "北京市");
        // 保留段 / 境外 / 空串：一律当没识别出来
        assert_eq!(province_of("中国|0|0|0|0"), "");
        assert_eq!(province_of(""), "");
        assert_eq!(province_of("0|0|0|0|0"), "");
        assert_eq!(province_of("乱写的"), "");
    }

    #[test]
    fn same_province_ignores_suffix_and_unknown() {
        assert!(same_province("广东省", "广东"));
        assert!(same_province("北京市", "北京"));
        assert!(same_province("香港特别行政区", "香港"));
        assert!(same_province("广东省", "广东省"));
        // 真是两个省：不许
        assert!(!same_province("广东省", "河南省"));
        assert!(!same_province("广东", "河南"));
        // 任一边识别不出来：放行，别把人锁死
        assert!(same_province("", "河南省"));
        assert!(same_province("广东省", ""));
        assert!(same_province("", ""));
    }
}

/// Parse a dotted-quad IPv4 string into 4 bytes, or None if invalid.
fn parse_ipv4(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u8>().ok()?;
    }
    Some(out)
}
