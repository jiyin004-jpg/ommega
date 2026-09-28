//! keybox.xml parsing.
//!
//! A single `keybox.xml` file carries everything the `server_keybox` mode
//! needs: one or more `<Key>` entries, each with a `PrivateKey` PEM and a
//! `CertificateChain` (leaf first). We extract the first usable key pair and
//! store it as a `DeviceIdentity` so the admin UI only needs one file upload.

use anyhow::Context;
use roxmltree::Document;

/// Parsed result of a keybox.xml upload.
#[derive(Debug, Clone)]
pub struct KeyboxData {
    /// Value of `<Keybox DeviceID="...">` (may be empty).
    pub device_id: String,
    /// Normalised algorithm name: `ec` or `rsa`.
    pub algorithm: String,
    /// Private key PEM (SEC1 EC or PKCS#1/PKCS#8 RSA), exactly as in the XML.
    pub private_key_pem: String,
    /// Certificate chain PEM (leaf first, all certificates concatenated).
    pub certificate_chain_pem: String,
    /// Number of certificates in the chain.
    pub cert_count: usize,
}

/// Normalise a PEM block: trim each line's leading/trailing whitespace (keybox
/// XMLs are commonly indented, which breaks PEM parsing if left intact) and
/// return a single newline-terminated body.
fn clean_pem(raw: &str) -> String {
    raw.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Parse the full keybox.xml document.
///
/// A keybox file may carry several `<Keybox>` blocks — 公开仓库里常见的「EC 一个、
/// RSA 一个」就是这个形状 —— and each block holds its own `<Key>`. Every usable
/// `<Key>` with a `<PrivateKey>` is returned, so the admin upload can persist all
/// of them and the fulfil layer can serve whichever algorithm the A-side request
/// asks for.
pub fn parse_keybox_xml_all(xml: &str) -> anyhow::Result<Vec<KeyboxData>> {
    let doc = Document::parse(xml).context("invalid XML")?;
    let root = doc.root_element();

    // 收全所有 `<Keybox>`（`descendants` 含自身，根就是 Keybox 时也在内）。以前只抓
    // 第一个，同一个文件里第二个算法的材料整段就丢了 —— 那些「EC + RSA 双段」的公开
    // keybox 因此永远只进得来 EC。
    let boxes: Vec<roxmltree::Node> = root
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "Keybox")
        .collect();
    // 有的文件省了 `<Keybox>` 这层，直接 `<AndroidAttestation><Key>…`；那就把根当成
    // 唯一一段，DeviceID 也从根上取（没有就留空）。
    let boxes = if boxes.is_empty() { vec![root] } else { boxes };

    let mut out: Vec<KeyboxData> = Vec::new();
    for keybox in boxes {
        // Prefer the direct `DeviceID` attribute, else fall back to a nested one.
        let device_id = keybox
            .attribute("DeviceID")
            .or_else(|| keybox.attribute("deviceID"))
            .unwrap_or("")
            .trim()
            .to_string();

        // 直接子 `<Key>`；一个都没有就放宽到整棵子树（有的文件多包了一层容器）。
        let mut keys: Vec<roxmltree::Node> = keybox
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "Key")
            .collect();
        if keys.is_empty() {
            keys = keybox
                .descendants()
                .filter(|n| n.is_element() && n.tag_name().name() == "Key")
                .collect();
        }

        for key in keys {
            let algorithm = key
                .attribute("algorithm")
                .map(|a| {
                    let l = a.to_ascii_lowercase();
                    if l.contains("rsa") {
                        "rsa".to_string()
                    } else {
                        "ec".to_string()
                    }
                })
                .unwrap_or_else(|| "ec".to_string());

            // <PrivateKey format="pem">...</PrivateKey>
            let priv_pem = child_text(key, "PrivateKey").map(|s| clean_pem(&s));

            // <CertificateChain> -> <Certificate format="pem"> ...
            let chain_pem = extract_certificate_chain(key);
            let cert_count = count_certificates(&chain_pem);

            if let Some(private_key_pem) = priv_pem {
                out.push(KeyboxData {
                    device_id: device_id.clone(),
                    algorithm,
                    private_key_pem,
                    certificate_chain_pem: chain_pem,
                    cert_count,
                });
            }
        }
    }

    if out.is_empty() {
        anyhow::bail!("no usable <Key> with <PrivateKey> found");
    }
    Ok(out)
}

/// 一个元素里的全部文本子节点拼起来。
///
/// keybox 文件里常夹着 `<!--t.me/xxx-->` 这类注释，注释既可能落在内容前面、也可能
/// 正好插进 base64 中间把文本切成几段；只取第一个文本节点的话，后面那段就没了，
/// 拿去解 base64 会报个看不懂的 “Invalid symbol …”。这里统统拼上。
fn node_text(node: &roxmltree::Node) -> String {
    node.children()
        .filter(|c| c.is_text())
        .filter_map(|c| c.text())
        .collect::<Vec<_>>()
        .join("")
}

/// Return the text of the first child element named `tag`.
fn child_text(node: roxmltree::Node, tag: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag)
        .map(|n| node_text(&n))
}

/// Concatenate all `<Certificate>` PEM blocks under `<CertificateChain>`.
fn extract_certificate_chain(key: roxmltree::Node) -> String {
    let mut out = String::new();
    if let Some(chain) = key
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "CertificateChain")
    {
        for cert in chain
            .children()
            .filter(|n| n.is_element() && n.tag_name().name() == "Certificate")
        {
            let text = node_text(&cert);
            if !text.trim().is_empty() {
                out.push_str(&clean_pem(&text));
            }
        }
    }
    out
}

fn count_certificates(pem_chain: &str) -> usize {
    cert_count(pem_chain)
}

/// Public helper: count certificates in a PEM chain (used by the admin UI).
pub fn cert_count(pem_chain: &str) -> usize {
    pem::parse_many(pem_chain).map(|v| v.len()).unwrap_or(0)
}

/// 把 PEM 链里的每张证书原样切出来（不重新编码，避免动到证书字节）。
fn cert_pem_blocks(chain: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut inside = false;
    for line in chain.lines() {
        let t = line.trim();
        if t == "-----BEGIN CERTIFICATE-----" {
            inside = true;
            cur.clear();
            cur.push_str(t);
            cur.push('\n');
        } else if inside {
            cur.push_str(t);
            cur.push('\n');
            if t == "-----END CERTIFICATE-----" {
                out.push(std::mem::take(&mut cur));
                inside = false;
            }
        }
    }
    out
}

/// 把一条已存的身份重新拼成 keybox.xml 文本。
///
/// `parse_keybox_xml_all` 的逆操作：池子里的身份按 PEM 分开存，而 A 端要的是
/// keybox.xml 这个形状，所以往设备送之前得拼回去。私钥和证书都原样保留。
///
/// 现在只有测试还在用它（公开池那条路要一次塞两种算法，直接走
/// `build_keybox_xml_with_keys`），所以非 test 构建里编不进去，省得留个死函数。
#[cfg(test)]
pub fn build_keybox_xml(
    device_id: &str,
    algorithm: &str,
    private_key_pem: &str,
    cert_chain_pem: &str,
) -> String {
    build_keybox_xml_with_keys(
        device_id,
        &[(
            algorithm.to_string(),
            private_key_pem.to_string(),
            cert_chain_pem.to_string(),
        )],
    )
}

/// 同一个 `<Keybox>` 里塞多段 `<Key>`（EC 一份、RSA 一份）。
///
/// A 端要的是「两种算法都在」：上游只给一种材料的话，请求落到缺的那种上头就只能
/// 报错。所以公开池那条路会把同一个槽位上凑得到的算法一起发过去。
pub fn build_keybox_xml_with_keys(device_id: &str, keys: &[(String, String, String)]) -> String {
    let blocks: String = keys
        .iter()
        .map(|(algorithm, private_key_pem, cert_chain_pem)| {
            key_block_xml(algorithm, private_key_pem, cert_chain_pem)
        })
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<AndroidAttestation>\n  <NumberOfKeyboxes>1</NumberOfKeyboxes>\n  <Keybox DeviceID=\"{device_id}\">\n{blocks}  </Keybox>\n</AndroidAttestation>\n"
    )
}

fn key_block_xml(algorithm: &str, private_key_pem: &str, cert_chain_pem: &str) -> String {
    let algo = if algorithm.eq_ignore_ascii_case("rsa") {
        "rsa"
    } else {
        "ecdsa"
    };
    let certs = cert_pem_blocks(cert_chain_pem);

    let mut key = String::new();
    for l in private_key_pem.lines() {
        let t = l.trim();
        if t.is_empty() {
            continue;
        }
        key.push_str("                    ");
        key.push_str(t);
        key.push('\n');
    }

    let mut chain = String::new();
    for c in &certs {
        chain.push_str("                <Certificate format=\"pem\">\n");
        for l in c.lines() {
            chain.push_str("                    ");
            chain.push_str(l);
            chain.push('\n');
        }
        chain.push_str("                </Certificate>\n");
    }

    format!(
        "    <Key algorithm=\"{algo}\">\n      <PrivateKey format=\"pem\">\n{key}      </PrivateKey>\n      <CertificateChain>\n        <NumberOfCertificates>{n}</NumberOfCertificates>\n{chain}      </CertificateChain>\n    </Key>\n",
        n = certs.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一个文件里 EC、RSA 各一个 `<Keybox>`，两段都得出来。
    ///
    /// 公开仓库里那种「EC + RSA 双段」文件以前只进得来第一个，RSA 整段白丢。
    #[test]
    fn both_keyboxes_are_parsed() {
        let xml = r#"<AndroidAttestation>
<NumberOfKeyboxes>2</NumberOfKeyboxes>
<Keybox DeviceID="dev-a">
<Key algorithm="ecdsa">
<PrivateKey format="pem">KEY-EC</PrivateKey>
<CertificateChain><NumberOfCertificates>1</NumberOfCertificates><Certificate format="pem">CERT-EC</Certificate></CertificateChain>
</Key>
</Keybox>
<Keybox DeviceID="dev-a">
<Key algorithm="rsa">
<PrivateKey format="pem">KEY-RSA</PrivateKey>
<CertificateChain><NumberOfCertificates>1</NumberOfCertificates><Certificate format="pem">CERT-RSA</Certificate></CertificateChain>
</Key>
</Keybox>
</AndroidAttestation>"#;
        let got = parse_keybox_xml_all(xml).expect("两段的文件应该能解析");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].algorithm, "ec");
        assert!(got[0].private_key_pem.contains("KEY-EC"));
        assert_eq!(got[1].algorithm, "rsa");
        assert!(got[1].private_key_pem.contains("KEY-RSA"));
        assert!(got[1].certificate_chain_pem.contains("CERT-RSA"));
        assert_eq!(got[1].device_id, "dev-a");
    }

    /// 注释插在内容中间时，文本要拼回去，不能只留第一段（那正是 “Invalid symbol 61,
    /// offset 1377” 的来源）。
    #[test]
    fn comments_inside_content_do_not_truncate_it() {
        let xml = r#"<AndroidAttestation><Keybox DeviceID="x"><Key algorithm="rsa">
<PrivateKey format="pem">AAA<!--t.me/xxx-->BBB</PrivateKey>
<CertificateChain><Certificate format="pem">CCC<!--note-->DDD</Certificate></CertificateChain>
</Key></Keybox></AndroidAttestation>"#;
        let got = parse_keybox_xml_all(xml).expect("注释包着的段也该解析");
        assert_eq!(got.len(), 1);
        assert!(
            got[0].private_key_pem.contains("AAABBB"),
            "私钥被截断了: {:?}",
            got[0].private_key_pem
        );
        assert!(
            got[0].certificate_chain_pem.contains("CCCDDD"),
            "证书被截断了: {:?}",
            got[0].certificate_chain_pem
        );
    }

    /// 没有 `<Keybox>` 这层（直接 `<AndroidAttestation><Key>`）也要能解析。
    #[test]
    fn key_without_a_keybox_wrapper_still_parses() {
        let xml = r#"<AndroidAttestation><Key algorithm="ecdsa"><PrivateKey format="pem">K</PrivateKey><CertificateChain><Certificate format="pem">C</Certificate></CertificateChain></Key></AndroidAttestation>"#;
        let got = parse_keybox_xml_all(xml).expect("没有 Keybox 层也该解析");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].algorithm, "ec");
    }

    /// 两种算法拼成一份 XML，再解析回来还是两份 —— 公开池现在就是这么发的。
    ///
    /// 以前一次只发一种算法，A 端拿到的 keybox 永远只有半套材料，请求落到缺的
    /// 那一半上就只有报错。
    #[test]
    fn multi_key_xml_round_trips_both_algorithms() {
        let keys = vec![
            (
                "ec".to_string(),
                "-----BEGIN EC PRIVATE KEY-----\nAAA\n-----END EC PRIVATE KEY-----\n".to_string(),
                "-----BEGIN CERTIFICATE-----\nCCC\n-----END CERTIFICATE-----\n".to_string(),
            ),
            (
                "rsa".to_string(),
                "-----BEGIN RSA PRIVATE KEY-----\nBBB\n-----END RSA PRIVATE KEY-----\n".to_string(),
                "-----BEGIN CERTIFICATE-----\nDDD\n-----END CERTIFICATE-----\n".to_string(),
            ),
        ];
        let xml = build_keybox_xml_with_keys("dev-x", &keys);

        let parsed = parse_keybox_xml_all(&xml).expect("拼出来的 XML 应该能解析回来");
        assert_eq!(parsed.len(), 2, "两段 Key 都该在: {xml}");
        assert_eq!(parsed[0].algorithm, "ec");
        assert!(parsed[0].private_key_pem.contains("AAA"));
        assert_eq!(parsed[1].algorithm, "rsa");
        assert!(parsed[1].private_key_pem.contains("BBB"));
        assert!(parsed[1].certificate_chain_pem.contains("DDD"));
        assert_eq!(parsed[0].device_id, "dev-x");
        assert_eq!(parsed[1].device_id, "dev-x");
        assert_eq!(xml.matches("<Key algorithm=").count(), 2);
    }

    /// 单份那版还是老形状（两个 `<Key>` 的容器版本兼容它）。
    #[test]
    fn single_key_xml_still_has_the_old_shape() {
        let xml = build_keybox_xml(
            "dev-y",
            "rsa",
            "-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----\n",
            "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
        );
        assert_eq!(xml.matches("<Key algorithm=").count(), 1);
        assert!(xml.contains("algorithm=\"rsa\""));
        assert!(xml.contains("<NumberOfKeyboxes>1</NumberOfKeyboxes>"));

        let parsed = parse_keybox_xml_all(&xml).expect("单份也该能解析");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].algorithm, "rsa");
        assert_eq!(parsed[0].device_id, "dev-y");
    }
}
