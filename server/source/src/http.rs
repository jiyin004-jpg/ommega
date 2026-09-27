//! 走系统 curl 取 HTTP 文本。
//!
//! 为什么不用 reqwest：这个机房里的 reqwest（rustls）过不了 Cloudflare 的 bot 检查，
//! 会一直挂到超时；curl 每次都是秒回。另外这台机器有些域名只解析出 IPv6，而它的
//! IPv6 是不通的 —— curl 会自己退回 IPv4，reqwest 不会。
//!
//! `-f` 是让 404/403 直接算失败：不然拿回来的是一张错误页，照样被当成正文往下解析。

use std::time::Duration;

pub fn get_text(url: &str, timeout: Duration) -> anyhow::Result<String> {
    run_curl(url, timeout, None)
}

/// 同上，但显式走一个 HTTP 代理（服务器上用 127.0.0.1:7890 的 mihomo）。
///
/// 只给「必须出墙」的少数几个请求用；A/B 端那些业务请求一律不走代理。
pub fn get_text_via(url: &str, timeout: Duration, proxy: &str) -> anyhow::Result<String> {
    run_curl(url, timeout, Some(proxy))
}

fn run_curl(url: &str, timeout: Duration, proxy: Option<&str>) -> anyhow::Result<String> {
    let secs = timeout.as_secs().max(1).to_string();
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sSfL", "--max-time", &secs]);
    if let Some(proxy) = proxy {
        cmd.args(["-x", proxy]);
    }
    let out = cmd.arg(url).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "curl exit={:?} {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
