//! 聚合支付（易支付/码支付协议）支持。
//!
//! 支持的平台：彩虹易支付、PayJS、码支付等基于同一协议的聚合支付平台。
//! 只需在 `.env` 中配置：
//!   PAY_GATEWAY     = 平台下单接口地址，如 https://pay.example.com/submit.php
//!   PAY_PID         = 商户号
//!   PAY_KEY         = 商户密钥
//!   PAY_NOTIFY_URL  = 异步通知地址（本服务 /api/card/pay_callback/）
//!   PAY_RETURN_URL  = 支付完成后同步跳转地址
//!
//! 协议说明（易支付标准）：
//!   - 下单：向网关 POST 表单参数 pid/type/out_trade_no/notify_url/return_url/name/money，
//!     连同 MD5 签名，平台返回 JSON：{ code, msg, trade_no, qrcode, cashier_url, url }。
//!   - 签名：按参数名升序拼接 `k1=v1&k2=v2&...&key=商户密钥`，取 MD5 小写。
//!   - 通知：平台回调 notify_url（GET/POST 表单），携带 sign，验签通过且
//!     trade_status == "TRADE_SUCCESS" 即表示支付成功，需应答纯文本 `success`。

use std::collections::BTreeMap;

use md5::{Digest, Md5};
use serde_json::Value;

/// Compute the MD5 hex digest (lowercase) of a string.
pub fn md5_hex(s: &str) -> String {
    let digest = Md5::digest(s.as_bytes());
    format!("{digest:x}")
}

/// Render a QR code as an inline SVG `data:` URI so the front-end can show it
/// with a plain `<img>` tag, with no external JS/CDN dependency.
pub fn qrcode_svg_data_uri(content: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(content.as_bytes()).ok()?;
    let svg_text = code
        .render::<svg::Color>()
        .min_dimensions(260, 260)
        .quiet_zone(true)
        .build();
    let encoded =
        percent_encoding::utf8_percent_encode(&svg_text, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    Some(format!("data:image/svg+xml;charset=utf-8,{encoded}"))
}

/// 易支付签名：参数按 key 升序，跳过空值，末尾拼 `key=商户密钥`，MD5 小写。
pub fn sign(params: &BTreeMap<String, String>, key: &str) -> String {
    let mut s = String::new();
    for (k, v) in params {
        if k == "sign" || k == "sign_type" || v.is_empty() {
            continue;
        }
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('&');
    }
    s.push_str("key=");
    s.push_str(key);
    md5_hex(&s)
}

/// 校验回调签名（不区分大小写比较）。
pub fn verify_sign(params: &BTreeMap<String, String>, key: &str) -> bool {
    let Some(got) = params.get("sign") else {
        return false;
    };
    let expected = sign(params, key);
    got.eq_ignore_ascii_case(&expected)
}

/// 聚合支付下单返回的数据。
pub struct OrderResp {
    /// 平台流水号
    pub trade_no: String,
    /// 二维码内容（可直接用于生成二维码）
    pub qrcode: String,
    /// 收银台地址（可直接打开）
    pub cashier_url: String,
    /// 通用跳转链接
    pub url: String,
}

/// 网关侧的配置：下单地址、商户凭证、回调地址。
pub struct Gateway<'a> {
    pub url: &'a str,
    pub pid: &'a str,
    pub key: &'a str,
    /// 异步通知地址（本服务 /api/card/pay_callback/）
    pub notify_url: &'a str,
    /// 支付完成后同步跳转地址
    pub return_url: &'a str,
}

/// 一笔订单自己的业务参数。
pub struct OrderReq<'a> {
    /// 支付方式，"alipay" | "wxpay"
    pub pay_type: &'a str,
    /// 商户订单号
    pub out_trade_no: &'a str,
    /// 商品名
    pub name: &'a str,
    /// 金额，元，两位小数
    pub money: &'a str,
}

/// 调用聚合支付平台创建支付单。
pub async fn submit_order(gw: Gateway<'_>, order: OrderReq<'_>) -> Result<OrderResp, String> {
    let mut params = BTreeMap::new();
    params.insert("pid".to_string(), gw.pid.to_string());
    params.insert("type".to_string(), order.pay_type.to_string());
    params.insert("out_trade_no".to_string(), order.out_trade_no.to_string());
    params.insert("notify_url".to_string(), gw.notify_url.to_string());
    params.insert("return_url".to_string(), gw.return_url.to_string());
    params.insert("name".to_string(), order.name.to_string());
    params.insert("money".to_string(), order.money.to_string());
    let sign = sign(&params, gw.key);
    params.insert("sign".to_string(), sign);
    params.insert("sign_type".to_string(), "MD5".to_string());

    // 总超时兑底：网关挂起时不能让下单接口无限阻塞（tokio 任务泄漏式挂起）
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("client build failed: {e}"))?;
    let resp = client
        .post(gw.url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("网关请求失败: {e}"))?;
    let text = resp
        .text()
        .await
        .map_err(|e| format!("读取网关响应失败: {e}"))?;

    let v: Value = serde_json::from_str(&text).map_err(|_| format!("网关响应格式错误: {text}"))?;
    let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
    if code != 1 {
        let msg = v.get("msg").and_then(|m| m.as_str()).unwrap_or("unknown");
        return Err(format!("平台下单失败(code={code}): {msg}"));
    }

    Ok(OrderResp {
        trade_no: v
            .get("trade_no")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        qrcode: v
            .get("qrcode")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        cashier_url: v
            .get("cashier_url")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
        url: v
            .get("url")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

/// Parse a URL-encoded form / query string into a map.
pub fn parse_form(input: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for pair in input.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        let k = percent_decode(k);
        let v = percent_decode(v);
        if !k.is_empty() {
            m.insert(k, v);
        }
    }
    m
}

fn percent_decode(s: &str) -> String {
    // `+` denotes space in form encoding.
    let s = s.replace('+', " ");
    percent_encoding::percent_decode_str(&s)
        .decode_utf8_lossy()
        .to_string()
}
