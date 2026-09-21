//! keybox.xml parsing.
//!
//! A single `keybox.xml` file carries everything the `server_keybox` mode
//! needs: one or more `<Key>` entries, each with a `PrivateKey` PEM and a
//! `CertificateChain` (leaf first). We extract the first usable key pair and
//! store it as a `DeviceIdentity` so the admin UI only needs one file upload.

use anyhow::{anyhow, Context};
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
/// A single keybox.xml may carry multiple `<Key>` entries (e.g. one RSA and one
/// EC). Every usable `<Key>` with a `<PrivateKey>` is returned, so the admin
/// upload can persist all of them and the fulfil layer can serve whichever
/// algorithm the A-side request asks for.
pub fn parse_keybox_xml_all(xml: &str) -> anyhow::Result<Vec<KeyboxData>> {
    let doc = Document::parse(xml).context("invalid XML")?;
    let root = doc.root_element();

    // Locate the `<Keybox>` element.
    let keybox = find_descendant(root, "Keybox")
        .or_else(|| find_descendant(root, "AndroidAttestation"))
        .ok_or_else(|| anyhow!("no <Keybox> element found"))?;

    // Prefer the direct `DeviceID` attribute, else fall back to a nested one.
    let device_id = keybox
        .attribute("DeviceID")
        .or_else(|| keybox.attribute("deviceID"))
        .unwrap_or("")
        .to_string();

    let mut out: Vec<KeyboxData> = Vec::new();
    for key in keybox
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "Key")
    {
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

    if out.is_empty() {
        anyhow::bail!("no usable <Key> with <PrivateKey> found");
    }
    Ok(out)
}

/// Depth-first search for the first element whose name matches.
fn find_descendant<'a, 'i>(
    node: roxmltree::Node<'a, 'i>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'i>> {
    if node.is_element() && node.tag_name().name() == name {
        return Some(node);
    }
    for child in node.children() {
        if let Some(found) = find_descendant(child, name) {
            return Some(found);
        }
    }
    None
}

/// Return the trimmed text of the first child element named `tag`.
fn child_text(node: roxmltree::Node, tag: &str) -> Option<String> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == tag)
        .and_then(|n| n.text())
        .map(str::to_string)
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
            if let Some(text) = cert.text() {
                out.push_str(&clean_pem(text));
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
