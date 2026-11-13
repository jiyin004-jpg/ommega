//! 24 小时内 A 端各包名发来多少笔 SOTER 请求。
//!
//! 数据只在内存里（进程重启清零）：每笔 `/api/soter/` 进来按 `caller_pkg` 记一次，
//! 按分钟分桶、窗口 1440 分钟。量级很小（一个包名最多 1440 个桶），不值得落库；
//! 需要留档的话看 `relay.out.log` 里现成的 `soter: op=… caller_pkg=…` 行。
//!
//! 页面：`/soter`（或 `/soter/`）；原始数据：`/api/soter_stats/`。

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::response::Html;
use axum::Json;
use serde_json::json;

/// 统计窗口：24 小时。
const WINDOW_SECS: u64 = 24 * 3600;
/// 分桶粒度：一分钟。窗口内最多 1440 个桶/包名。
const BUCKET_SECS: u64 = 60;
/// 没带包名的那一堆在页面上的显示名。
const UNKNOWN_PKG: &str = "(未带包名)";

/// 包名 -> 有序列 [(桶号, 该分钟内笔数)]，桶号 = unix 秒 / BUCKET_SECS。
type Buckets = VecDeque<(u64, u32)>;

fn store() -> &'static Mutex<HashMap<String, Buckets>> {
    static STORE: OnceLock<Mutex<HashMap<String, Buckets>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn oldest_bucket(now_bucket: u64) -> u64 {
    now_bucket.saturating_sub(WINDOW_SECS / BUCKET_SECS)
}

/// 记一笔。空包名归到 `(未带包名)`，调用方不用自己判。
pub fn record(pkg: &str) {
    let name = match pkg.trim() {
        "" => UNKNOWN_PKG,
        other => other,
    };
    let bucket = now_secs() / BUCKET_SECS;
    let cutoff = oldest_bucket(bucket);
    let Ok(mut map) = store().lock() else {
        return;
    };
    let entry = map.entry(name.to_string()).or_default();
    match entry.back_mut() {
        Some((last, count)) if *last == bucket => *count += 1,
        _ => entry.push_back((bucket, 1)),
    }
    while entry.front().is_some_and(|(at, _)| *at < cutoff) {
        entry.pop_front();
    }
}

/// 24 小时窗口内的计数，按笔数从多到少。顺手把过期桶清掉。
pub fn snapshot() -> Vec<(String, u64)> {
    let bucket = now_secs() / BUCKET_SECS;
    let cutoff = oldest_bucket(bucket);
    let Ok(mut map) = store().lock() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(map.len());
    for (pkg, buckets) in map.iter_mut() {
        while buckets.front().is_some_and(|(at, _)| *at < cutoff) {
            buckets.pop_front();
        }
        let total: u64 = buckets.iter().map(|(_, n)| u64::from(*n)).sum();
        if total > 0 {
            out.push((pkg.clone(), total));
        }
    }
    map.retain(|_, buckets| !buckets.is_empty());
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

/// GET /api/soter_stats/ —— 给脚本/面板用的原始数据。
pub async fn json_handler() -> Json<serde_json::Value> {
    let rows: Vec<serde_json::Value> = snapshot()
        .into_iter()
        .map(|(pkg, count)| json!({ "package": pkg, "count": count }))
        .collect();
    let total: u64 = snapshot().iter().map(|(_, n)| *n).sum();
    Json(json!({
        "window_hours": WINDOW_SECS / 3600,
        "total": total,
        "packages": rows,
    }))
}

/// GET /soter —— 人看的页面：包名 + 24 小时笔数。
pub async fn page_handler() -> Html<String> {
    let rows = snapshot();
    let total: u64 = rows.iter().map(|(_, n)| *n).sum();
    let mut body = String::new();
    if rows.is_empty() {
        body.push_str(
            "<tr><td colspan=\"3\" class=\"empty\">这 24 小时内还没有 SOTER 请求</td></tr>",
        );
    } else {
        for (index, (pkg, count)) in rows.iter().enumerate() {
            let share = if total == 0 {
                0.0
            } else {
                (*count as f64) * 100.0 / (total as f64)
            };
            body.push_str(&format!(
                "<tr><td class=\"idx\">{}</td><td class=\"pkg\">{}</td>\
                 <td class=\"num\">{}</td><td class=\"num dim\">{share:.1}%</td></tr>",
                index + 1,
                html_escape(pkg),
                count,
            ));
        }
    }
    let page = format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>SOTER 请求统计 · 24h</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; padding: 24px 16px 48px;
         font: 14px/1.55 -apple-system, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
         background: Canvas; color: CanvasText; }}
  .wrap {{ max-width: 720px; margin: 0 auto; }}
  h1 {{ font-size: 18px; margin: 0 0 4px; font-weight: 600; }}
  .meta {{ color: color-mix(in srgb, CanvasText 55%, transparent); font-size: 12px; margin-bottom: 18px; }}
  .meta b {{ color: CanvasText; font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid color-mix(in srgb, CanvasText 12%, transparent); }}
  th {{ font-size: 12px; font-weight: 600; color: color-mix(in srgb, CanvasText 60%, transparent); }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  td.idx {{ width: 34px; color: color-mix(in srgb, CanvasText 40%, transparent); }}
  td.pkg {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }}
  td.dim {{ color: color-mix(in srgb, CanvasText 50%, transparent); }}
  td.empty {{ text-align: center; color: color-mix(in srgb, CanvasText 50%, transparent); padding: 28px 0; }}
  .note {{ margin-top: 18px; font-size: 12px; color: color-mix(in srgb, CanvasText 50%, transparent); }}
  .note code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>SOTER 请求统计</h1>
  <div class="meta">最近 <b>24 小时</b> · 共 <b>{total}</b> 笔 · 来自 <b>{kinds}</b> 个包名 · 每 30 秒自动刷新</div>
  <table>
    <thead><tr><th>#</th><th>包名</th><th class="num">请求次数</th><th class="num">占比</th></tr></thead>
    <tbody>
{body}
    </tbody>
  </table>
  <div class="note">进程内统计，<code>relay_rs</code> 重启后清零；原始数据在 <code>/api/soter_stats/</code>，逐笔明细看 <code>/opt/relay/relay.out.log</code>。</div>
</div>
</body>
</html>
"#,
        total = total,
        kinds = rows.len(),
        body = body,
    );
    Html(page)
}

fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_package_gets_its_own_row() {
        record("com.example.app");
        record("");
        let rows = snapshot();
        let total: u64 = rows.iter().map(|(_, n)| *n).sum();
        assert!(total >= 2, "got {rows:?}");
        assert!(rows.iter().any(|(pkg, _)| pkg == UNKNOWN_PKG));
        assert!(rows.iter().any(|(pkg, _)| pkg == "com.example.app"));
    }

    #[test]
    fn html_escape_handles_the_dangerous_chars() {
        assert_eq!(html_escape("a<b>&\"c"), "a&lt;b&gt;&amp;&quot;c");
    }
}
