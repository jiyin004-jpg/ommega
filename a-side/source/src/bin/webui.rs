//! A-side web UI server for the Ommega relay module.
//!
//! Serves the static webroot (management panel) and exposes a small JSON API
//! to read/update the relay configuration.
//!
//! Usage: `webui [bind_addr] [webroot_dir]`
//!   - bind_addr defaults to `127.0.0.1:8080`
//!   - webroot_dir defaults to `/data/misc/keystore/ommega/webroot`

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const DEFAULT_WEBROOT: &str = "/data/misc/keystore/ommega/webroot";

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let bind = args.next().unwrap_or_else(|| DEFAULT_BIND.to_string());
    let webroot = args.next().unwrap_or_else(|| DEFAULT_WEBROOT.to_string());
    let webroot = Arc::new(PathBuf::from(webroot));

    let listener =
        TcpListener::bind(&bind).with_context(|| format!("failed to bind webui on {bind}"))?;
    log::info!("webui listening on {bind}, webroot={}", webroot.display());

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let webroot = Arc::clone(&webroot);
        std::thread::spawn(move || {
            if let Err(e) = handle_conn(stream, &webroot) {
                log::warn!("webui request error: {e:#}");
            }
        });
    }
    Ok(())
}

fn handle_conn(mut stream: TcpStream, webroot: &Path) -> Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read until we have the full request head (headers end with \r\n\r\n).
    let header_end = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let content_length = lines
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                Some(v.trim().parse::<usize>().unwrap_or(0))
            } else {
                None
            }
        })
        .next()
        .unwrap_or(0);

    // Read the body if present.
    let mut body = Vec::new();
    if content_length > 0 {
        while body.len() < content_length {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(content_length);
    }

    let (status, resp_body, content_type) = route(&method, &path, &body, webroot)?;
    respond(stream, status, &resp_body, content_type)
}

fn route(
    method: &str,
    path: &str,
    body: &[u8],
    webroot: &Path,
) -> Result<(u16, Vec<u8>, &'static str)> {
    match (method, path) {
        ("GET", "/api/config") => {
            let cfg = load_config_json()?;
            Ok((200, cfg.to_string().into_bytes(), "application/json"))
        }
        ("POST", "/api/config") => {
            let value: Value =
                serde_json::from_slice(body).map_err(|e| anyhow!("invalid JSON: {e}"))?;
            update_config(value)?;
            Ok((200, b"{\"ok\":true}".to_vec(), "application/json"))
        }
        ("GET", "/api/status") => {
            let status = json!({
                "remote_enabled": remote_enabled(),
                "relay": "A-side Ommega relay",
            });
            Ok((200, status.to_string().into_bytes(), "application/json"))
        }
        _ => {
            // Static file serving.
            let rel = if path == "/" {
                "index.html"
            } else {
                path.trim_start_matches('/')
            };
            let file_path = sanitize_path(webroot, rel);
            match fs::read(&file_path) {
                Ok(bytes) => {
                    let ct = content_type_for(&file_path);
                    Ok((200, bytes, ct))
                }
                Err(_) => Ok((404, b"not found".to_vec(), "text/plain")),
            }
        }
    }
}

/// Prevent path traversal outside the webroot.
fn sanitize_path(root: &Path, rel: &str) -> PathBuf {
    let mut out = root.to_path_buf();
    for comp in rel.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

fn content_type_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("woff2") => "font/woff2",
        Some("xml") => "application/xml",
        _ => "application/octet-stream",
    }
}

fn load_config_json() -> Result<Value> {
    let cfg = ommegaclient_config::load()?;
    Ok(json!({
        "remote": {
            "enabled": cfg.remote.enabled,
            "url": cfg.remote.url,
            "token": cfg.remote.token,
            "device_id": cfg.remote.device_id,
            "tls_insecure": cfg.remote.tls_insecure,
            "fallback_local": cfg.remote.fallback_local,
            "debug_logging": cfg.remote.debug_logging,
            "hide_strongbox": cfg.remote.hide_strongbox,
        }
    }))
}

fn update_config(value: Value) -> Result<()> {
    let mut cfg = ommegaclient_config::load()?;
    if let Some(remote) = value.get("remote") {
        if let Some(v) = remote.get("enabled").and_then(Value::as_bool) {
            cfg.remote.enabled = v;
        }
        if let Some(v) = remote.get("url").and_then(Value::as_str) {
            cfg.remote.url = v.to_string();
        }
        if let Some(v) = remote.get("token").and_then(Value::as_str) {
            cfg.remote.token = v.to_string();
        }
        if let Some(v) = remote.get("device_id").and_then(Value::as_str) {
            cfg.remote.device_id = v.to_string();
        }
        if let Some(v) = remote.get("tls_insecure").and_then(Value::as_bool) {
            cfg.remote.tls_insecure = v;
        }
        if let Some(v) = remote.get("fallback_local").and_then(Value::as_bool) {
            cfg.remote.fallback_local = v;
        }
        if let Some(v) = remote.get("debug_logging").and_then(Value::as_bool) {
            cfg.remote.debug_logging = v;
        }
        if let Some(v) = remote.get("hide_strongbox").and_then(Value::as_bool) {
            cfg.remote.hide_strongbox = v;
        }
    }
    ommegaclient_config::save(&cfg)?;
    Ok(())
}

fn remote_enabled() -> bool {
    match ommegaclient_config::load() {
        Ok(c) => c.remote.enabled,
        Err(_) => false,
    }
}

fn respond(mut stream: TcpStream, status: u16, body: &[u8], content_type: &str) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

/// Thin wrapper over the crate's config module (this is a separate binary).
mod ommegaclient_config {
    use super::*;

    pub struct RelayConfig {
        pub remote: RemoteConfig,
    }

    #[derive(Default)]
    pub struct RemoteConfig {
        pub enabled: bool,
        pub url: String,
        pub token: String,
        pub device_id: String,
        pub tls_insecure: bool,
        pub fallback_local: bool,
        pub debug_logging: bool,
        pub hide_strongbox: bool,
    }

    /// Legacy A-side (client-a) flat `key: value` config file.
    ///
    /// Must be the SAME path the keymint daemon reads
    /// (`crate::config::CLIENTA_CONFIG_PATH` = `/data/misc/keystore/ommega/config`).
    /// Writing to `/data/adb/ommega/config` (a different file, not the
    /// `ommegadata` symlink) made the WebUI "remote mode" toggle a no-op on the
    /// daemon, which kept serving the remote chain.
    const CONFIG_PATH: &str = "/data/misc/keystore/ommega/config";

    pub fn load() -> Result<RelayConfig> {
        let raw = fs::read_to_string(CONFIG_PATH).with_context(|| format!("read {CONFIG_PATH}"))?;
        let mut rc = RemoteConfig::default();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some(idx) = line.find(':') else { continue };
            let key = line[..idx].trim().to_lowercase();
            let value = line[idx + 1..].trim().to_string();
            match key.as_str() {
                "url" => rc.url = value,
                "token" => rc.token = value,
                "device_id" => rc.device_id = value,
                "remote" => rc.enabled = parse_bool(&value).unwrap_or(true),
                "local_hw" | "local_depend_hardware" => {
                    if let Some(v) = parse_bool(&value) {
                        // Legacy semantics: local_hw maps to fallback_local here.
                        rc.fallback_local = v;
                    }
                }
                "tls_insecure" | "tls_skip_verify" | "insecure_tls" => {
                    rc.tls_insecure = parse_bool(&value).unwrap_or(false);
                }
                "debug_logging" | "debug" | "verbose" => {
                    rc.debug_logging = parse_bool(&value).unwrap_or(false);
                }
                "hide_strongbox" | "no_strongbox" | "hide_strongbox_keystore" => {
                    rc.hide_strongbox = parse_bool(&value).unwrap_or(false);
                }
                _ => {}
            }
        }
        Ok(RelayConfig { remote: rc })
    }

    pub fn save(cfg: &RelayConfig) -> Result<()> {
        let mut contents = String::new();
        contents.push_str(&format!("url: {}\n", cfg.remote.url));
        contents.push_str(&format!("token: {}\n", cfg.remote.token));
        contents.push_str(&format!("device_id: {}\n", cfg.remote.device_id));
        contents.push_str(&format!("remote: {}\n", cfg.remote.enabled));
        contents.push_str(&format!("local_hw: {}\n", cfg.remote.fallback_local));
        contents.push_str(&format!("tls_insecure: {}\n", cfg.remote.tls_insecure));
        contents.push_str(&format!("debug_logging: {}\n", cfg.remote.debug_logging));
        contents.push_str(&format!("hide_strongbox: {}\n", cfg.remote.hide_strongbox));
        if let Some(parent) = Path::new(CONFIG_PATH).parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(CONFIG_PATH, contents)?;
        Ok(())
    }

    fn parse_bool(value: &str) -> Option<bool> {
        match value.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    }
}
