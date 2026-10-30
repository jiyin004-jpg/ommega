use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, OnceLock, RwLock,
    },
};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::Encode;
use kmr_common::{
    crypto::{ec, rsa, KeyMaterial, Sha256},
    Error,
};
use kmr_crypto_ommega::{ec::OmmegaEc, mldsa::OmmegaMlDsa, rsa::OmmegaRsa, sha256::OmmegaSha256};
use kmr_ta::device::{
    RetrieveCertSigningInfo, SigningAlgorithm, SigningInfoSnapshot, SigningKeyType,
};
use kmr_wire::keymint;
use log::{debug, error, info, warn};
use regex::Regex;
use x509_cert::der as x509_der;
use x509_cert::Certificate;

pub const KEYBOX_PATH: &str = "/data/misc/keystore/ommega/keybox_tee.xml";

/// StrongBox 级别单独的一份 keybox。文件不存在或解析不了就用内置的 StrongBox 那份，
/// **不会**回落到 TEE 那份 —— 回落就是「StrongBox 请求拿 TEE 链」。
pub const STRONGBOX_KEYBOX_PATH: &str = "/data/misc/keystore/ommega/keybox_strongbox.xml";

const BUNDLED_KEYBOX_XML: &str = include_str!("../template/keybox_tee.xml");
/// 内置的 StrongBox 级 keybox。文件丢了或读坏了就用它，不再退回 TEE 那份 ——
/// 退回主 keybox 就是「StrongBox 请求拿 TEE 链」，证书标签和叶子级别直接对不上。
const BUNDLED_STRONGBOX_KEYBOX_XML: &str = include_str!("../template/keybox_strongbox.xml");

lazy_static::lazy_static! {
    pub static ref KEYBOX: RwLock<KeyBox> = RwLock::new(KeyBox::new());
    /// StrongBox 级别的 keybox；`None` = 没配（回落 `KEYBOX`）。
    pub static ref KEYBOX_SB: RwLock<Option<KeyBox>> = RwLock::new(None);
    static ref KEYBOX_IO_LOCK: Mutex<()> = Mutex::new(());
    static ref KEY_BLOCK_RE: Regex =
        Regex::new(r#"(?s)<Key\s+algorithm="([^"]+)">\s*(.*?)\s*</Key>"#).unwrap();
    static ref PRIVATE_KEY_RE: Regex =
        Regex::new(r#"(?s)<PrivateKey[^>]*>\s*(.*?)\s*</PrivateKey>"#).unwrap();
    static ref CERT_COUNT_RE: Regex =
        Regex::new(r#"(?s)<NumberOfCertificates>\s*(\d+)\s*</NumberOfCertificates>"#).unwrap();
    static ref CERT_RE: Regex =
        Regex::new(r#"(?s)<Certificate(?:\s+[^>]*)?>\s*(.*?)\s*</Certificate>"#).unwrap();
}

static KEYBOX_WATCHER: OnceLock<()> = OnceLock::new();
static KEYBOX_DB_RETIRE_ALLOWED: AtomicBool = AtomicBool::new(false);
static KEYBOX_RUNTIME_LOADED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct CertSignAlgoInfo {
    key: KeyMaterial,
    key_der: Vec<u8>,
    chain: Vec<keymint::Certificate>,
}

#[derive(Clone)]
pub struct KeyBox {
    rsa_info: Option<CertSignAlgoInfo>,
    ec_info: Option<CertSignAlgoInfo>,
    identity_digest: [u8; 32],
}

#[derive(Clone, Copy)]
enum KeyAlgorithm {
    Ec,
    Rsa,
}

struct ParsedKeyEntry {
    key_der: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

impl KeyBox {
    pub fn new() -> Self {
        Self::from_xml_str(BUNDLED_KEYBOX_XML).expect("bundled keybox_tee.xml must be valid")
    }

    pub fn from_xml_str(xml: &str) -> Result<Self> {
        let mut rsa_entry = None;
        let mut ec_entry = None;

        for captures in KEY_BLOCK_RE.captures_iter(xml) {
            let algorithm = match captures.get(1).map(|m| m.as_str().trim()) {
                Some("ecdsa") | Some("ec") => KeyAlgorithm::Ec,
                Some("rsa") => KeyAlgorithm::Rsa,
                Some(other) => bail!("unsupported key algorithm `{other}` in keybox.xml"),
                None => bail!("missing key algorithm in keybox.xml"),
            };
            let body = captures
                .get(2)
                .map(|m| m.as_str())
                .ok_or_else(|| anyhow!("missing key block body"))?;
            let entry = ParsedKeyEntry::from_xml_block(body).with_context(|| {
                format!("failed to parse {:?} key entry", algorithm_name(algorithm))
            })?;
            match algorithm {
                KeyAlgorithm::Ec => ec_entry = Some(entry),
                KeyAlgorithm::Rsa => rsa_entry = Some(entry),
            }
        }

        let rsa_info = rsa_entry.map(Self::build_rsa_info).transpose()?;
        let ec_info = ec_entry.map(Self::build_ec_info).transpose()?;
        if rsa_info.is_none() && ec_info.is_none() {
            bail!("keybox.xml must contain at least one RSA or EC key entry");
        }
        let identity_digest = Self::compute_identity_digest(rsa_info.as_ref(), ec_info.as_ref())?;

        Ok(Self {
            rsa_info,
            ec_info,
            identity_digest,
        })
    }

    fn build_rsa_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("RSA certificate chain is empty");
        }
        let key = rsa::import_pkcs1_key(&entry.key_der)
            .map(|(key, _, _)| key)
            .map_err(|e| anyhow!("failed to import RSA private key: {e:?}"))?;
        let chain: Vec<keymint::Certificate> = entry
            .chain
            .into_iter()
            .map(|encoded_certificate| keymint::Certificate {
                encoded_certificate,
            })
            .collect();
        validate_chain_matches_key(&key, &chain, KeyAlgorithm::Rsa)?;
        Ok(CertSignAlgoInfo {
            key,
            key_der: entry.key_der,
            chain,
        })
    }

    fn build_ec_info(entry: ParsedKeyEntry) -> Result<CertSignAlgoInfo> {
        if entry.chain.is_empty() {
            bail!("EC certificate chain is empty");
        }
        let key = ec::import_sec1_private_key(&entry.key_der)
            .map_err(|e| anyhow!("failed to import EC private key: {e:?}"))?;
        let chain: Vec<keymint::Certificate> = entry
            .chain
            .into_iter()
            .map(|encoded_certificate| keymint::Certificate {
                encoded_certificate,
            })
            .collect();
        validate_chain_matches_key(&key, &chain, KeyAlgorithm::Ec)?;
        Ok(CertSignAlgoInfo {
            key,
            key_der: entry.key_der,
            chain,
        })
    }

    fn compute_identity_digest(
        rsa_info: Option<&CertSignAlgoInfo>,
        ec_info: Option<&CertSignAlgoInfo>,
    ) -> Result<[u8; 32]> {
        let mut material = Vec::new();
        if let Some(rsa_info) = rsa_info {
            append_labeled_bytes(&mut material, b"rsa-key", &rsa_info.key_der);
            append_labeled_chain(&mut material, b"rsa-chain", &rsa_info.chain);
        }
        if let Some(ec_info) = ec_info {
            append_labeled_bytes(&mut material, b"ec-key", &ec_info.key_der);
            append_labeled_chain(&mut material, b"ec-chain", &ec_info.chain);
        }

        OmmegaSha256 {}
            .hash(&material)
            .map_err(|e| anyhow!("failed to hash keybox identity: {e:?}"))
    }

    fn refresh_identity_digest(&mut self) -> Result<()> {
        self.identity_digest =
            Self::compute_identity_digest(self.rsa_info.as_ref(), self.ec_info.as_ref())?;
        Ok(())
    }

    pub fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }

    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        // 证书里的「签发者用哪种钥匙」跟「叶子用哪种钥匙」是两件独立的事：RSA 叶
        // 子完全可以由 EC 签发（反之亦然）。而大多数分发的 keybox 只有一个 EC 条目，
        // 以前在这里只按 `algo_hint` 硬选，于是所有 RSA 钥匙的认证都报
        // 「keybox has no Rsa signing key」—— Duck Detector 的 KeyMint crypto 项就
        // 是靠这些 RSA 变体判红的。
        //
        // 所以：要的那一种没有就用另一种顶上（优先 EC），链路和身份都不换。
        let wanted = match key_type.algo_hint {
            SigningAlgorithm::Rsa => "RSA",
            SigningAlgorithm::Ec => "EC",
        };
        let info = match key_type.algo_hint {
            SigningAlgorithm::Rsa => self.rsa_info.as_ref().or(self.ec_info.as_ref()),
            SigningAlgorithm::Ec => self.ec_info.as_ref().or(self.rsa_info.as_ref()),
        };
        let info = info.ok_or_else(|| {
            kmr_common::km_err!(UnknownError, "keybox has no {wanted} signing key")
        })?;

        Ok(SigningInfoSnapshot {
            signing_key: info.key.clone(),
            cert_chain: info.chain.clone(),
            identity_digest: self.identity_digest,
        })
    }

    pub fn update_rsa_keybox(
        &mut self,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        self.update_keybox(KeyAlgorithm::Rsa, key_der, chain)
    }

    pub fn update_ec_keybox(
        &mut self,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        self.update_keybox(KeyAlgorithm::Ec, key_der, chain)
    }

    fn update_keybox(
        &mut self,
        algorithm: KeyAlgorithm,
        key_der: Vec<u8>,
        chain: Vec<keymint::Certificate>,
    ) -> Result<()> {
        let entry = ParsedKeyEntry {
            key_der,
            chain: chain
                .into_iter()
                .map(|certificate| certificate.encoded_certificate)
                .collect(),
        };
        match algorithm {
            KeyAlgorithm::Ec => self.ec_info = Some(Self::build_ec_info(entry)?),
            KeyAlgorithm::Rsa => self.rsa_info = Some(Self::build_rsa_info(entry)?),
        }
        self.refresh_identity_digest()
    }

    pub fn to_xml_string(&self) -> String {
        let blocks = [
            (
                KeyAlgorithm::Ec,
                self.ec_info
                    .as_ref()
                    .map(|info| ("ecdsa", "EC PRIVATE KEY", info)),
            ),
            (
                KeyAlgorithm::Rsa,
                self.rsa_info
                    .as_ref()
                    .map(|info| ("rsa", "RSA PRIVATE KEY", info)),
            ),
        ]
        .into_iter()
        .filter_map(|(algorithm, info)| {
            info.map(|(name, private_label, info)| {
                Self::to_xml_block(algorithm, name, private_label, info)
            })
        })
        .collect::<Vec<_>>()
        .join("\n");

        format!(
            concat!(
                "<?xml version=\"1.0\"?>\n",
                "<AndroidAttestation>\n",
                "<NumberOfKeyboxes>{keybox_count}</NumberOfKeyboxes>\n",
                "<Keybox DeviceID=\"sw\">\n",
                "{blocks}\n",
                "</Keybox>\n",
                "</AndroidAttestation>\n"
            ),
            keybox_count = if self.rsa_info.is_some() && self.ec_info.is_some() {
                2
            } else {
                1
            },
            blocks = blocks,
        )
    }

    fn to_xml_block(
        _algorithm: KeyAlgorithm,
        name: &str,
        private_label: &str,
        info: &CertSignAlgoInfo,
    ) -> String {
        let certificates = info
            .chain
            .iter()
            .map(|certificate| {
                format!(
                    "<Certificate format=\"pem\">\n{}\n</Certificate>",
                    encode_pem_block("CERTIFICATE", &certificate.encoded_certificate)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            concat!(
                "<Key algorithm=\"{name}\">\n",
                "<PrivateKey format=\"pem\">\n",
                "{private_key}\n",
                "</PrivateKey>\n",
                "<CertificateChain>\n",
                "<NumberOfCertificates>{cert_count}</NumberOfCertificates>\n",
                "{certificates}\n",
                "</CertificateChain>\n",
                "</Key>"
            ),
            name = name,
            private_key = encode_pem_block(private_label, &info.key_der),
            cert_count = info.chain.len(),
            certificates = certificates,
        )
    }
}

impl Default for KeyBox {
    fn default() -> Self {
        Self::new()
    }
}

impl ParsedKeyEntry {
    fn from_xml_block(block: &str) -> Result<Self> {
        let private_key_pem = PRIVATE_KEY_RE
            .captures(block)
            .and_then(|captures| captures.get(1))
            .map(|m| m.as_str())
            .context("missing <PrivateKey> block")?;
        let key_der = decode_pem(private_key_pem)?;

        let expected_cert_count = CERT_COUNT_RE
            .captures(block)
            .and_then(|captures| captures.get(1))
            .map(|m| m.as_str())
            .context("missing <NumberOfCertificates> in certificate chain")?
            .parse::<usize>()
            .context("invalid certificate count in keybox.xml")?;

        let chain = CERT_RE
            .captures_iter(block)
            .filter_map(|captures| captures.get(1).map(|m| m.as_str()))
            .map(decode_pem)
            .collect::<Result<Vec<_>>>()?;

        if chain.len() != expected_cert_count {
            bail!(
                "certificate count mismatch: declared {}, parsed {}",
                expected_cert_count,
                chain.len()
            );
        }

        Ok(Self { key_der, chain })
    }
}

fn append_labeled_bytes(buffer: &mut Vec<u8>, label: &[u8], data: &[u8]) {
    buffer.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buffer.extend_from_slice(data);
}

fn append_labeled_chain(buffer: &mut Vec<u8>, label: &[u8], chain: &[keymint::Certificate]) {
    buffer.extend_from_slice(&(label.len() as u32).to_be_bytes());
    buffer.extend_from_slice(label);
    buffer.extend_from_slice(&(chain.len() as u32).to_be_bytes());
    for certificate in chain {
        buffer.extend_from_slice(&(certificate.encoded_certificate.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&certificate.encoded_certificate);
    }
}

fn algorithm_name(algorithm: KeyAlgorithm) -> &'static str {
    match algorithm {
        KeyAlgorithm::Ec => "EC",
        KeyAlgorithm::Rsa => "RSA",
    }
}

fn validate_chain_matches_key(
    key: &KeyMaterial,
    chain: &[keymint::Certificate],
    algorithm: KeyAlgorithm,
) -> Result<()> {
    let first_cert = chain
        .first()
        .context("certificate chain must contain a leaf certificate")?;
    let certificate = <Certificate as x509_der::Decode>::from_der(&first_cert.encoded_certificate)
        .with_context(|| {
            format!(
                "failed to parse {} leaf certificate from keybox chain",
                algorithm_name(algorithm)
            )
        })?;
    let mut spki_buf = Vec::new();
    let derived_spki = key
        .subject_public_key_info(
            &mut spki_buf,
            &OmmegaEc::default(),
            &OmmegaRsa::default(),
            &OmmegaMlDsa,
        )
        .map_err(|e| {
            anyhow!(
                "failed to derive {} public key info from private key: {e:?}",
                algorithm_name(algorithm)
            )
        })?
        .context("symmetric key cannot back an attestation certificate")?
        .to_der()
        .with_context(|| {
            format!(
                "failed to encode {} public key info from private key",
                algorithm_name(algorithm)
            )
        })?;
    let certificate_spki =
        x509_der::Encode::to_der(certificate.tbs_certificate().subject_public_key_info())
            .with_context(|| {
                format!(
                    "failed to encode {} public key info from certificate chain",
                    algorithm_name(algorithm)
                )
            })?;
    if derived_spki != certificate_spki {
        bail!(
            "{} certificate chain does not match the supplied private key",
            algorithm_name(algorithm)
        );
    }
    Ok(())
}

fn decode_pem(pem: &str) -> Result<Vec<u8>> {
    let base64_body = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .collect::<String>();

    if base64_body.is_empty() {
        bail!("empty PEM payload");
    }

    STANDARD
        .decode(base64_body.as_bytes())
        .context("failed to decode PEM payload")
}

fn encode_pem_block(label: &str, der: &[u8]) -> String {
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {label}-----\n"));
    let base64 = STANDARD.encode(der);
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is valid UTF-8"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----"));
    pem
}

fn temp_keybox_path(path: &str) -> PathBuf {
    let target = Path::new(path);
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("keybox_tee.xml");
    let temp_name = format!(".{file_name}.tmp-{}", std::process::id());
    target
        .parent()
        .map(|parent| parent.join(&temp_name))
        .unwrap_or_else(|| PathBuf::from(temp_name))
}

fn write_keybox_xml(path: &str, xml: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create keybox directory {}", parent.display()))?;
    }
    let temp_path = temp_keybox_path(path);
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .with_context(|| format!("failed to open temporary keybox {}", temp_path.display()))?;
        file.write_all(xml.as_bytes())
            .with_context(|| format!("failed to write temporary keybox {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temporary keybox {}", temp_path.display()))?;
    }

    #[cfg(windows)]
    if Path::new(path).exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to replace keybox at {path} on Windows"))?;
    }

    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to atomically replace keybox at {path}"))
}

fn write_bundled_keybox(path: &str) -> Result<()> {
    write_keybox_xml(path, BUNDLED_KEYBOX_XML)
}

pub fn ensure_keybox_file(path: &str) -> Result<()> {
    if Path::new(path).exists() {
        return Ok(());
    }
    info!(
        "keybox_tee.xml missing at {}; seeding bundled template",
        path
    );
    write_bundled_keybox(path)
}

/// StrongBox 那份也补盘：文件不在就写内置的，不然面板上看不到，重启后又被当成没配。
fn ensure_strongbox_keybox_file() {
    if Path::new(STRONGBOX_KEYBOX_PATH).exists() {
        return;
    }
    info!("keybox_strongbox.xml missing at {STRONGBOX_KEYBOX_PATH}; seeding bundled strongbox template");
    if let Err(error) = write_keybox_xml(STRONGBOX_KEYBOX_PATH, BUNDLED_STRONGBOX_KEYBOX_XML) {
        warn!("failed to seed {STRONGBOX_KEYBOX_PATH}: {error:#}");
    }
}

fn is_bundled_keybox_xml(xml: &str) -> bool {
    xml.trim() == BUNDLED_KEYBOX_XML.trim()
}

fn retire_stale_keybox_bound_entries(current_identity: [u8; 32]) {
    if !db_retirement_allowed() {
        warn!("skipping stale keybox-bound DB retirement while active keybox came from fallback");
        return;
    }

    match crate::global::DB.with(|db| {
        db.borrow_mut()
            .retire_stale_keybox_bound_entries(current_identity)
    }) {
        Ok(0) => debug!("no stale keybox-bound key entries needed retirement"),
        Ok(retired) => info!("retired {retired} stale keybox-bound key entries"),
        Err(error) => error!("failed to retire stale keybox-bound key entries: {error:#}"),
    }
}

fn install_keybox(
    new_keybox: KeyBox,
    retire_db_entries: bool,
    db_retirement_allowed: bool,
) -> bool {
    let new_identity = new_keybox.identity_digest();
    let changed = {
        let mut keybox = KEYBOX.write().unwrap();
        let changed = keybox.identity_digest() != new_identity;
        *keybox = new_keybox;
        changed
    };
    KEYBOX_DB_RETIRE_ALLOWED.store(db_retirement_allowed, Ordering::Release);
    KEYBOX_RUNTIME_LOADED.store(true, Ordering::Release);

    if changed {
        crate::keymaster::keymint_device::clear_initialized_attestation_caches();
    }

    if retire_db_entries {
        retire_stale_keybox_bound_entries(new_identity);
    }

    changed
}

pub fn db_retirement_allowed() -> bool {
    KEYBOX_DB_RETIRE_ALLOWED.load(Ordering::Acquire)
}

fn is_fallback_continuation(keybox: &KeyBox, contents: &str) -> bool {
    let current_identity = KEYBOX
        .read()
        .map(|current| current.identity_digest())
        .unwrap_or([0u8; 32]);
    is_fallback_continuation_with_state(
        keybox,
        contents,
        KEYBOX_RUNTIME_LOADED.load(Ordering::Acquire),
        db_retirement_allowed(),
        current_identity,
    )
}

fn is_fallback_continuation_with_state(
    keybox: &KeyBox,
    contents: &str,
    runtime_loaded: bool,
    retirement_allowed: bool,
    current_identity: [u8; 32],
) -> bool {
    runtime_loaded
        && !retirement_allowed
        && is_bundled_keybox_xml(contents)
        && current_identity == keybox.identity_digest()
}

fn load_keybox_with_fallback(path: &str) -> Result<(KeyBox, bool)> {
    match fs::read_to_string(path) {
        Ok(contents) => match KeyBox::from_xml_str(&contents) {
            Ok(keybox) => {
                let fallback_origin = is_fallback_continuation(&keybox, &contents);
                Ok((keybox, fallback_origin))
            }
            Err(error) => {
                // Do not overwrite the on-disk file here. The webroot UI writes
                // the keybox via `mv` + `cat << EOF`, and the inotify watcher can
                // observe an empty/partial file while the new contents are still
                // being written. Overwriting it with the bundled template here
                // would destroy a just-written valid keybox. Instead we fall back
                // to the bundled template in memory and leave the file untouched;
                // a later `IN_CLOSE_WRITE` event re-reads the completed file.
                warn!(
                    "invalid keybox_tee.xml at {}: {:#}; using bundled template in memory (file left intact)",
                    path, error
                );
                Ok((KeyBox::new(), true))
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            info!(
                "keybox_tee.xml missing at {}; using bundled template in memory",
                path
            );
            Ok((KeyBox::new(), true))
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to read keybox_tee.xml from {path}"))
        }
    }
}

pub fn reload_from_disk() -> Result<bool> {
    reload_from_disk_inner(true)
}

fn reload_from_disk_inner(retire_db_entries: bool) -> Result<bool> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let (keybox, used_fallback) = load_keybox_with_fallback(KEYBOX_PATH)?;
    let changed = install_keybox(keybox, retire_db_entries, !used_fallback);
    // StrongBox 那份：没有文件就用内置的，读坏了也一样，永不回落到主 keybox。
    let sb = load_strongbox_keybox();
    // 换了 StrongBox 的链也要把已缓存的 attestation key 清掉，否则 kmr-ta 会继续用
    // 上一次初始化好的叶子，面板里换了文件也看不到变化（只有主 keybox 变化才清的
    // 旧逻辑漏掉了这一边）。
    let sb_changed = {
        let old = KEYBOX_SB
            .read()
            .ok()
            .and_then(|g| g.as_ref().map(|k| k.identity_digest()));
        let new = sb.as_ref().map(|k| k.identity_digest());
        old != new
    };
    if let Ok(mut guard) = KEYBOX_SB.write() {
        *guard = sb;
    }
    if sb_changed {
        crate::keymaster::keymint_device::clear_initialized_attestation_caches();
        info!("strongbox keybox identity updated from {STRONGBOX_KEYBOX_PATH}");
    }
    if changed {
        info!(
            "active keybox identity updated from {} (fallback={})",
            KEYBOX_PATH, used_fallback
        );
    } else {
        debug!(
            "keybox reload completed without identity change (fallback={})",
            used_fallback
        );
    }
    Ok(changed)
}

pub fn initialize() -> Result<()> {
    ensure_keybox_file(KEYBOX_PATH)?;
    ensure_strongbox_keybox_file();
    reload_from_disk_inner(false)?;
    KEYBOX_WATCHER.get_or_init(|| {
        if let Err(error) = kmr_common::runtime::file_watch::spawn_path_watcher(
            "ommega-keybox-watch",
            PathBuf::from(KEYBOX_PATH),
            |_trigger| {
                if let Err(reload_error) = reload_from_disk() {
                    error!("failed to reload keybox_tee.xml after change: {reload_error:#}");
                }
            },
        ) {
            error!("failed to watch keybox_tee.xml: {error:#}");
        }
        // StrongBox 那份同理：面板里选完文件就该生效，不该等下次开机。
        if let Err(error) = kmr_common::runtime::file_watch::spawn_path_watcher(
            "ommega-keybox-sb-watch",
            PathBuf::from(STRONGBOX_KEYBOX_PATH),
            |_trigger| {
                if let Err(reload_error) = reload_from_disk() {
                    error!("failed to reload keybox_strongbox.xml after change: {reload_error:#}");
                }
            },
        ) {
            // 大多数设备上这个文件一开始不存在，watcher 可能装不上，不算错误。
            debug!("strongbox keybox watcher not installed: {error:#}");
        }
    });
    Ok(())
}

pub fn update_rsa_keybox(key_der: Vec<u8>, chain: Vec<keymint::Certificate>) -> Result<bool> {
    update_keybox_file(KeyAlgorithm::Rsa, key_der, chain)
}

pub fn update_ec_keybox(key_der: Vec<u8>, chain: Vec<keymint::Certificate>) -> Result<bool> {
    update_keybox_file(KeyAlgorithm::Ec, key_der, chain)
}

fn update_keybox_file(
    algorithm: KeyAlgorithm,
    key_der: Vec<u8>,
    chain: Vec<keymint::Certificate>,
) -> Result<bool> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let mut keybox = KEYBOX.read().unwrap().clone();
    keybox.update_keybox(algorithm, key_der, chain)?;
    write_keybox_xml(KEYBOX_PATH, &keybox.to_xml_string())?;
    Ok(install_keybox(keybox, true, true))
}

pub fn current_identity_digest() -> [u8; 32] {
    KEYBOX.read().unwrap().identity_digest()
}

/// 按级别取身份摘要：StrongBox 用它自己那份（文件或内置），TEE 用主 keybox。
pub fn current_identity_digest_for(strongbox: bool) -> [u8; 32] {
    if strongbox {
        if let Ok(guard) = KEYBOX_SB.read() {
            if let Some(kb) = guard.as_ref() {
                return kb.identity_digest();
            }
        }
    }
    current_identity_digest()
}

/// 读 StrongBox 那份 keybox。文件不存在或解析失败都退回**内置的 StrongBox 模板**，
/// 绝不回落到主 keybox（那样 StrongBox 请求会拿着 TEE 的链出去）。
fn load_strongbox_keybox() -> Option<KeyBox> {
    match std::fs::read_to_string(STRONGBOX_KEYBOX_PATH) {
        Ok(xml) => match KeyBox::from_xml_str(&xml) {
            Ok(keybox) => {
                info!("strongbox keybox loaded from {STRONGBOX_KEYBOX_PATH}");
                Some(keybox)
            }
            Err(error) => {
                warn!("invalid strongbox keybox at {STRONGBOX_KEYBOX_PATH}: {error:#}; using the bundled one");
                Some(bundled_strongbox_keybox())
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            debug!("{STRONGBOX_KEYBOX_PATH} not found; using the bundled strongbox keybox");
            Some(bundled_strongbox_keybox())
        }
        Err(error) => {
            warn!("failed to read {STRONGBOX_KEYBOX_PATH}: {error:#}; using the bundled one");
            Some(bundled_strongbox_keybox())
        }
    }
}

fn bundled_strongbox_keybox() -> KeyBox {
    KeyBox::from_xml_str(BUNDLED_STRONGBOX_KEYBOX_XML)
        .expect("bundled keybox_strongbox.xml must be valid")
}

pub(crate) fn signing_certificate_ders_from_disk() -> Result<Vec<Vec<u8>>> {
    let _io_guard = KEYBOX_IO_LOCK.lock().unwrap();
    let (keybox, _) = load_keybox_with_fallback(KEYBOX_PATH)?;
    let mut certs = Vec::new();
    if let Some(rsa_info) = &keybox.rsa_info {
        certs.push(rsa_info.chain[0].encoded_certificate.clone());
    }
    if let Some(ec_info) = &keybox.ec_info {
        certs.push(ec_info.chain[0].encoded_certificate.clone());
    }
    Ok(certs)
}

pub struct KeyboxManager {
    /// STRONGBOX 级别的 TA 用 StrongBox 自己那份 keybox。
    pub strongbox: bool,
}

impl RetrieveCertSigningInfo for KeyboxManager {
    fn signing_info(&self, key_type: SigningKeyType) -> Result<SigningInfoSnapshot, Error> {
        if self.strongbox {
            if let Ok(guard) = KEYBOX_SB.read() {
                if let Some(keybox) = guard.as_ref() {
                    return keybox.signing_info(key_type);
                }
            }
            // 初始化还没跑完（或锁被毒了）也不能退回 TEE：直接用内置那份。
            return bundled_strongbox_keybox().signing_info(key_type);
        }
        let keybox = KEYBOX
            .read()
            .map_err(|_| kmr_common::km_err!(UnknownError, "failed to lock KEYBOX"))?;
        keybox.signing_info(key_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_ta::device::SigningKey;

    fn write_temp_keybox(name: &str, contents: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("ommega-keybox-{name}-{}.xml", std::process::id()));
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn parses_bundled_template() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        // 内置的是 TEE 那份：叶子 + 中间 CA + 根，RSA / EC 各一条。
        assert_eq!(keybox.ec_info.as_ref().unwrap().chain.len(), 3);
        assert_eq!(keybox.rsa_info.as_ref().unwrap().chain.len(), 3);
        assert_ne!(keybox.identity_digest(), [0u8; 32]);
    }

    #[test]
    fn bundled_strongbox_keybox_is_separate_from_the_tee_one() {
        let tee = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let sb = bundled_strongbox_keybox();
        assert_eq!(sb.ec_info.as_ref().unwrap().chain.len(), 3);
        assert_eq!(sb.rsa_info.as_ref().unwrap().chain.len(), 3);
        // 两份内置材料必须不同：共用一份就是「TEE 请求拿 StrongBox 链」的根。
        assert_ne!(sb.identity_digest(), tee.identity_digest());
        // 链上标签也要对：TEE 那份标 TEE，StrongBox 那份标 StrongBox。
        assert!(chain_has_label(&sb, KeyAlgorithm::Ec, b"StrongBox"));
        assert!(!chain_has_label(&sb, KeyAlgorithm::Ec, b"TEE"));
        assert!(chain_has_label(&tee, KeyAlgorithm::Ec, b"TEE"));
        assert!(!chain_has_label(&tee, KeyAlgorithm::Ec, b"StrongBox"));
    }

    /// 链里有没有某个明文标签（title 2.5.4.12 的值直接以 ASCII 进 DER）。
    fn chain_has_label(keybox: &KeyBox, algorithm: KeyAlgorithm, label: &[u8]) -> bool {
        let info = match algorithm {
            KeyAlgorithm::Ec => keybox.ec_info.as_ref(),
            KeyAlgorithm::Rsa => keybox.rsa_info.as_ref(),
        };
        let Some(info) = info else { return false };
        info.chain.iter().any(|cert| {
            cert.encoded_certificate
                .windows(label.len())
                .any(|w| w == label)
        })
    }

    #[test]
    fn parses_ec_only_keybox() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let ec_block = KeyBox::to_xml_block(
            KeyAlgorithm::Ec,
            "ecdsa",
            "EC PRIVATE KEY",
            keybox.ec_info.as_ref().unwrap(),
        );
        let ec_only_xml = format!(
            "<?xml version=\"1.0\"?>\n<AndroidAttestation>\n<NumberOfKeyboxes>1</NumberOfKeyboxes>\n<Keybox DeviceID=\"yurikey\">\n{ec_block}\n</Keybox>\n</AndroidAttestation>\n"
        );

        let parsed = KeyBox::from_xml_str(&ec_only_xml).unwrap();
        assert!(parsed.ec_info.is_some());
        assert!(parsed.rsa_info.is_none());
        assert_eq!(
            parsed
                .signing_info(SigningKeyType {
                    which: SigningKey::Batch,
                    algo_hint: SigningAlgorithm::Ec,
                })
                .unwrap()
                .cert_chain,
            keybox.ec_info.as_ref().unwrap().chain
        );
        // 只有 EC 一枚时，RSA 请求也能拿到（用 EC 签）—— 证书签发者与叶子钥匙
        // 算法本就是两件事，以前这里硬选才让 RSA 认证全部失败。
        assert_eq!(
            parsed
                .signing_info(SigningKeyType {
                    which: SigningKey::Batch,
                    algo_hint: SigningAlgorithm::Rsa,
                })
                .unwrap()
                .cert_chain,
            keybox.ec_info.as_ref().unwrap().chain
        );
        assert_eq!(parsed.to_xml_string().matches("<Key algorithm=").count(), 1);
        // Round-trips to a valid, single-keybox document.
        let round_tripped = KeyBox::from_xml_str(&parsed.to_xml_string()).unwrap();
        assert_eq!(round_tripped.identity_digest(), parsed.identity_digest());
    }

    #[test]
    fn rejects_invalid_xml() {
        assert!(KeyBox::from_xml_str("<AndroidAttestation/>").is_err());
    }

    #[test]
    fn identity_changes_when_chain_changes() {
        let original = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let mut changed = original.clone();
        let extra_cert = changed.ec_info.as_ref().unwrap().chain[0].clone();
        changed.ec_info.as_mut().unwrap().chain.push(extra_cert);
        changed.refresh_identity_digest().unwrap();

        let modified = KeyBox::from_xml_str(&changed.to_xml_string()).unwrap();
        assert_ne!(original.identity_digest(), modified.identity_digest());
    }

    #[test]
    fn rejects_mismatched_private_key_and_certificate_chain() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();
        let rsa_cert = encode_pem_block(
            "CERTIFICATE",
            &keybox.rsa_info.as_ref().unwrap().chain[0].encoded_certificate,
        );
        let ec_cert = encode_pem_block(
            "CERTIFICATE",
            &keybox.ec_info.as_ref().unwrap().chain[0].encoded_certificate,
        );
        let modified_xml = BUNDLED_KEYBOX_XML.replacen(&rsa_cert, &ec_cert, 1);
        assert!(KeyBox::from_xml_str(&modified_xml).is_err());
    }

    #[test]
    fn signing_snapshot_keeps_key_chain_and_digest_in_sync() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        let rsa_snapshot = keybox
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Rsa,
            })
            .unwrap();
        assert_eq!(rsa_snapshot.identity_digest, keybox.identity_digest());
        validate_chain_matches_key(
            &rsa_snapshot.signing_key,
            &rsa_snapshot.cert_chain,
            KeyAlgorithm::Rsa,
        )
        .unwrap();

        let ec_snapshot = keybox
            .signing_info(SigningKeyType {
                which: SigningKey::Batch,
                algo_hint: SigningAlgorithm::Ec,
            })
            .unwrap();
        assert_eq!(ec_snapshot.identity_digest, keybox.identity_digest());
        validate_chain_matches_key(
            &ec_snapshot.signing_key,
            &ec_snapshot.cert_chain,
            KeyAlgorithm::Ec,
        )
        .unwrap();
    }

    #[test]
    fn invalid_file_falls_back_in_memory_without_overwriting() {
        let path = write_temp_keybox("invalid", "<not-xml>");
        let (keybox, used_fallback) = load_keybox_with_fallback(path.to_str().unwrap()).unwrap();
        assert!(used_fallback);
        assert_eq!(keybox.identity_digest(), KeyBox::new().identity_digest());
        // The on-disk file must be left untouched so a partially-written keybox
        // isn't clobbered while the UI is still writing it.
        let written = fs::read_to_string(path).unwrap();
        assert_eq!(written, "<not-xml>");
    }

    #[test]
    fn valid_keybox_file_is_not_rewritten() {
        let path = write_temp_keybox("valid", BUNDLED_KEYBOX_XML);
        let (_, used_fallback) = load_keybox_with_fallback(path.to_str().unwrap()).unwrap();
        assert!(!used_fallback);
        let written = fs::read_to_string(path).unwrap();
        assert_eq!(written, BUNDLED_KEYBOX_XML);
    }

    #[test]
    fn explicit_bundled_template_is_retirement_eligible_before_runtime_fallback() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        assert!(!is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            false,
            false,
            keybox.identity_digest(),
        ));
    }

    #[test]
    fn non_bundled_keybox_is_retirement_eligible() {
        let modified_xml = format!("{BUNDLED_KEYBOX_XML}\n<!-- explicit local keybox -->\n");
        let path = write_temp_keybox("modified", &modified_xml);

        let (_, used_fallback) = load_keybox_with_fallback(path.to_str().unwrap()).unwrap();

        assert!(!used_fallback);
    }

    #[test]
    fn rewritten_bundled_template_can_continue_runtime_fallback() {
        let keybox = KeyBox::from_xml_str(BUNDLED_KEYBOX_XML).unwrap();

        assert!(is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            true,
            false,
            keybox.identity_digest(),
        ));
        assert!(!is_fallback_continuation_with_state(
            &keybox,
            BUNDLED_KEYBOX_XML,
            true,
            true,
            keybox.identity_digest(),
        ));
    }
}
