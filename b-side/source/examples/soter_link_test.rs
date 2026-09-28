//! End-to-end link test for SOTER forwarding.
//!
//! Acts as a throwaway B-side client against a relay_server you run yourself: it
//! polls for tasks exactly like the relay does (same endpoints, same token, same
//! capability report), runs `soter` tasks through the production path, and posts
//! the results back.  It exists so the whole chain can be exercised without
//! touching the installed relay or its config file (`/data/adb/ommega/relay.conf`
//! has a fixed path, so a second relay instance cannot run next to it).
//!
//! ```text
//! # on the PC, with a self-run server:
//! RELAY_TOKEN=linktest RELAY_HTTP_PORT=18086 cargo run --bin relay_rs
//! adb reverse tcp:18086 tcp:18086
//! # push the example, then on the device as root:
//! /data/local/tmp/soter_link_test http://127.0.0.1:18086 linktest <device_id> 90
//! # and from the PC:
//! curl -s -H 'X-Relay-Token: linktest' -H 'Content-Type: application/json' \
//!      -d '{"op":"get_device_id"}' http://127.0.0.1:18086/api/soter/
//! ```
//!
//! A fifth argument `mutation` passes `allow_mutation = true` to the handler;
//! leave it out so the key-creating ops stay refused.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _, Result};
use serde_json::{json, Value};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        return Err(anyhow!(
            "usage: {} <server-url> <token> <device-id> [seconds] [mutation]",
            args[0]
        ));
    }
    let server = args[1].trim_end_matches('/').to_string();
    let token = args[2].clone();
    let device_id = args[3].clone();
    let seconds: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(60);
    let allow_mutation = args.get(5).is_some_and(|s| s == "mutation");

    // Box<dyn Error> is not Send, so anyhow's `context` does not apply here.
    if let Err(e) = rsbinder::ProcessState::init_default() {
        return Err(anyhow!("init binder process state failed: {e}"));
    }
    let caps = ommegaclient_b::caps::report(None);
    println!("link test: server={server} device={device_id} caps={caps:?}");

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(40))
        .build()
        .context("build http client")?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut served = 0u32;

    while Instant::now() < deadline {
        let url = format!(
            "{server}/api/b/poll/?device_id={device_id}&machine_id=linktest&timeout=5&caps={caps}"
        );
        let resp = client
            .get(&url)
            .header("X-Relay-Token", &token)
            .send()
            .with_context(|| format!("poll {url}"))?;
        let status = resp.status().as_u16();
        let body = resp.text().unwrap_or_default();
        match status {
            204 => continue,
            200 => {}
            other => return Err(anyhow!("poll returned {other}: {body}")),
        }
        let task: Value = serde_json::from_str(&body).context("poll body")?;
        let task_id = task
            .get("task_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("poll body has no task_id: {task}"))?
            .to_string();
        let task_type = task.get("task_type").and_then(Value::as_str).unwrap_or("");
        let payload = task.get("payload").cloned().unwrap_or(Value::Null);
        println!("task {task_id} type={task_type} payload={payload}");

        let result = if task_type == "soter" {
            match ommegaclient_b::soter::handle(&payload, allow_mutation) {
                Ok(value) => value,
                Err(e) => json!({ "error": format!("{e:#}") }),
            }
        } else {
            json!({ "error": format!("link test cannot serve task type {task_type:?}") })
        };
        println!("  result: {}", summarize(&result));

        let result_url = format!("{server}/api/b/result/");
        let posted = client
            .post(&result_url)
            .header("X-Relay-Token", &token)
            .json(&json!({ "task_id": task_id, "result": result, "device_id": device_id }))
            .send()
            .with_context(|| format!("post {result_url}"))?;
        println!("  posted: {}", posted.status().as_u16());
        served += 1;
    }

    println!("link test done: served {served} task(s)");
    Ok(())
}

/// Keep the console readable: SOTER replies carry a 450 byte PEM and a 256 byte
/// signature.
fn summarize(value: &Value) -> String {
    let text = value.to_string();
    if text.chars().count() <= 400 {
        return text;
    }
    let head: String = text.chars().take(400).collect();
    format!("{head}... ({} chars)", text.len())
}
