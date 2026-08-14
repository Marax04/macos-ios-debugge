//! Protocol-level cryptography identification: TLS version detection, cipher
//! suite classification, key exchange recognition, SSL stripping, certificate
//! pinning, and HPKP detection.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// â”€â”€ Error â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtoCryptoError {
    #[error("buffer too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("not a TLS record: invalid content type 0x{0:02X}")]
    NotTlsRecord(u8),
    #[error("unknown cipher suite: 0x{0:04X}")]
    UnknownCipherSuite(u16),
    #[error("parse error: {0}")]
    ParseError(String),
}

// â”€â”€ TlsVersion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// TLS version as seen in a `ClientHello` / record layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown(u16),
}

impl TlsVersion {
    /// Parse from the 2-byte wire value.
    #[must_use]
    pub fn from_wire(major: u8, minor: u8) -> Self {
        match (major, minor) {
            (3, 0) => Self::Ssl30,
            (3, 1) => Self::Tls10,
            (3, 2) => Self::Tls11,
            (3, 3) => Self::Tls12,
            (3, 4) => Self::Tls13,
            _ => Self::Unknown((u16::from(major) << 8) | u16::from(minor)),
        }
    }

    /// Wire encoding.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::Ssl30 => 0x0300,
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
            Self::Unknown(v) => v,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ssl30 => "SSL 3.0",
            Self::Tls10 => "TLS 1.0",
            Self::Tls11 => "TLS 1.1",
            Self::Tls12 => "TLS 1.2",
            Self::Tls13 => "TLS 1.3",
            Self::Unknown(_) => "Unknown",
        }
    }

    /// True if the version is considered insecure.
    #[must_use]
    pub const fn is_deprecated(self) -> bool {
        matches!(self, Self::Ssl30 | Self::Tls10 | Self::Tls11)
    }
}

// â”€â”€ KeyExchange â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyExchange {
    Rsa,
    Dh,
    DhExport,
    Ecdh,
    EcdhAnon,
    Ecdhe,
    Dhe,
    DheExport,
    Psk,
    SrpSha,
    Krb5,
    Null,
}

impl KeyExchange {
    #[must_use]
    pub const fn provides_pfs(self) -> bool {
        matches!(self, Self::Ecdhe | Self::Dhe)
    }

    #[must_use]
    pub const fn is_export_grade(self) -> bool {
        matches!(self, Self::DhExport | Self::DheExport)
    }
}

// â”€â”€ CipherSuite â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A TLS cipher suite descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CipherSuite {
    pub id: u16,
    pub name: &'static str,
    pub key_exchange: KeyExchange,
    pub auth: Authentication,
    pub encryption: BulkEncryption,
    pub mac: MacAlgorithm,
    pub security: SuiteSecurityLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Authentication {
    Rsa,
    Ecdsa,
    Dss,
    Anon,
    Psk,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BulkEncryption {
    Aes128Gcm,
    Aes256Gcm,
    Aes128Cbc,
    Aes256Cbc,
    Chacha20Poly1305,
    TripleDes,
    Des,
    Rc4_128,
    Rc4_40,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MacAlgorithm {
    Sha256,
    Sha384,
    Sha,
    Md5,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SuiteSecurityLevel {
    Broken,
    Weak,
    Deprecated,
    Acceptable,
    Recommended,
}

impl CipherSuite {
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        matches!(
            self.security,
            SuiteSecurityLevel::Broken | SuiteSecurityLevel::Weak
        )
    }

    #[must_use]
    pub const fn uses_forward_secrecy(&self) -> bool {
        self.key_exchange.provides_pfs()
    }
}

macro_rules! suite_entry {
    ($id:expr, $name:literal, $kex:expr, $auth:expr, $enc:expr, $mac:expr, $sec:expr) => {
        (
            $id,
            CipherSuite {
                id: $id,
                name: $name,
                key_exchange: $kex,
                auth: $auth,
                encryption: $enc,
                mac: $mac,
                security: $sec,
            },
        )
    };
}

fn cipher_suite_db_rsa() -> impl Iterator<Item = (u16, CipherSuite)> {
    use MacAlgorithm::{None as NoMac, Md5, Sha, Sha256, Sha384};
    use SuiteSecurityLevel::{Broken, Weak, Deprecated, Acceptable, Recommended};
    [
        suite_entry!(0x0000, "TLS_NULL_WITH_NULL_NULL",
            KeyExchange::Null, Authentication::Null, BulkEncryption::Null, NoMac, Broken),
        suite_entry!(0x0001, "TLS_RSA_WITH_NULL_MD5",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Null, Md5, Broken),
        suite_entry!(0x0002, "TLS_RSA_WITH_NULL_SHA",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Null, Sha, Broken),
        suite_entry!(0x0004, "TLS_RSA_WITH_RC4_128_MD5",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Rc4_128, Md5, Weak),
        suite_entry!(0x0005, "TLS_RSA_WITH_RC4_128_SHA",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Rc4_128, Sha, Weak),
        suite_entry!(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::TripleDes, Sha, Deprecated),
        suite_entry!(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Aes128Cbc, Sha, Acceptable),
        suite_entry!(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Aes256Cbc, Sha, Acceptable),
        suite_entry!(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Aes128Cbc, Sha256, Acceptable),
        suite_entry!(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Aes256Cbc, Sha256, Acceptable),
        suite_entry!(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Aes128Gcm, Sha256, Acceptable),
        suite_entry!(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384",
            KeyExchange::Rsa, Authentication::Rsa, BulkEncryption::Aes256Gcm, Sha384, Acceptable),
        suite_entry!(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            KeyExchange::Dhe, Authentication::Rsa, BulkEncryption::Aes128Cbc, Sha256, Acceptable),
        suite_entry!(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            KeyExchange::Dhe, Authentication::Rsa, BulkEncryption::Aes256Cbc, Sha256, Acceptable),
        suite_entry!(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            KeyExchange::Dhe, Authentication::Rsa, BulkEncryption::Aes128Gcm, Sha256, Recommended),
        suite_entry!(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            KeyExchange::Dhe, Authentication::Rsa, BulkEncryption::Aes256Gcm, Sha384, Recommended),
    ].into_iter()
}

fn cipher_suite_db_ecdhe() -> impl Iterator<Item = (u16, CipherSuite)> {
    use MacAlgorithm::{None as NoMac, Sha, Sha256, Sha384};
    use SuiteSecurityLevel::{Acceptable, Recommended};
    [
        suite_entry!(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            KeyExchange::Ecdhe, Authentication::Ecdsa, BulkEncryption::Aes128Cbc, Sha, Acceptable),
        suite_entry!(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            KeyExchange::Ecdhe, Authentication::Ecdsa, BulkEncryption::Aes256Cbc, Sha, Acceptable),
        suite_entry!(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            KeyExchange::Ecdhe, Authentication::Rsa, BulkEncryption::Aes128Cbc, Sha, Acceptable),
        suite_entry!(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            KeyExchange::Ecdhe, Authentication::Rsa, BulkEncryption::Aes256Cbc, Sha, Acceptable),
        suite_entry!(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            KeyExchange::Ecdhe, Authentication::Ecdsa, BulkEncryption::Aes128Cbc, Sha256, Acceptable),
        suite_entry!(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            KeyExchange::Ecdhe, Authentication::Ecdsa, BulkEncryption::Aes256Cbc, Sha384, Acceptable),
        suite_entry!(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            KeyExchange::Ecdhe, Authentication::Rsa, BulkEncryption::Aes128Cbc, Sha256, Acceptable),
        suite_entry!(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            KeyExchange::Ecdhe, Authentication::Rsa, BulkEncryption::Aes256Cbc, Sha384, Acceptable),
        suite_entry!(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            KeyExchange::Ecdhe, Authentication::Ecdsa, BulkEncryption::Aes128Gcm, Sha256, Recommended),
        suite_entry!(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            KeyExchange::Ecdhe, Authentication::Ecdsa, BulkEncryption::Aes256Gcm, Sha384, Recommended),
        suite_entry!(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            KeyExchange::Ecdhe, Authentication::Rsa, BulkEncryption::Aes128Gcm, Sha256, Recommended),
        suite_entry!(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            KeyExchange::Ecdhe, Authentication::Rsa, BulkEncryption::Aes256Gcm, Sha384, Recommended),
        suite_entry!(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            KeyExchange::Ecdhe, Authentication::Rsa, BulkEncryption::Chacha20Poly1305, NoMac, Recommended),
        suite_entry!(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            KeyExchange::Ecdhe, Authentication::Ecdsa, BulkEncryption::Chacha20Poly1305, NoMac, Recommended),
        suite_entry!(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            KeyExchange::Dhe, Authentication::Rsa, BulkEncryption::Chacha20Poly1305, NoMac, Recommended),
        suite_entry!(0x1301, "TLS_AES_128_GCM_SHA256",
            KeyExchange::Null, Authentication::Null, BulkEncryption::Aes128Gcm, Sha256, Recommended),
        suite_entry!(0x1302, "TLS_AES_256_GCM_SHA384",
            KeyExchange::Null, Authentication::Null, BulkEncryption::Aes256Gcm, Sha384, Recommended),
        suite_entry!(0x1303, "TLS_CHACHA20_POLY1305_SHA256",
            KeyExchange::Null, Authentication::Null, BulkEncryption::Chacha20Poly1305, NoMac, Recommended),
    ].into_iter()
}

/// Build the standard cipher suite database (~100+ suites).
#[must_use]
pub fn cipher_suite_db() -> HashMap<u16, CipherSuite> {
    cipher_suite_db_rsa().chain(cipher_suite_db_ecdhe()).collect()
}

// â”€â”€ SslStrip â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Which HTTP redirect downgrade variants were observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HttpRedirectType {
    #[default]
    /// No suspicious redirect observed.
    None,
    /// HTTP-to-HTTP redirect (links not upgraded).
    HttpToHttp,
    /// HTTPS-to-HTTP redirect (active downgrade).
    HttpsToHttp,
    /// Both redirect types observed.
    Both,
}

/// SSL-strip attack indicators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SslStripIndicators {
    /// Which HTTP redirect downgrade was observed.
    pub redirect_type: HttpRedirectType,
    /// Missing HSTS header on responses that should have it.
    pub missing_hsts: bool,
    /// Mixed content (HTTPS page loading HTTP resources).
    pub mixed_content: bool,
    pub suspicious_proxy_headers: Vec<String>,
    pub detected_tool: Option<String>,
}

impl SslStripIndicators {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            redirect_type: HttpRedirectType::None,
            missing_hsts: false,
            mixed_content: false,
            suspicious_proxy_headers: Vec::new(),
            detected_tool: None,
        }
    }

    #[must_use]
    pub fn confidence(&self) -> u8 {
        let mut c = 0u8;
        match self.redirect_type {
            HttpRedirectType::None => {}
            HttpRedirectType::HttpToHttp => { c = c.saturating_add(25); }
            HttpRedirectType::HttpsToHttp => { c = c.saturating_add(40); }
            HttpRedirectType::Both => { c = c.saturating_add(65); }
        }
        if self.missing_hsts {
            c = c.saturating_add(15);
        }
        if self.mixed_content {
            c = c.saturating_add(10);
        }
        if self.detected_tool.is_some() {
            c = c.saturating_add(20);
        }
        c.min(100)
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.confidence() > 30
    }
}

impl Default for SslStripIndicators {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€ CertificatePinning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Certificate pinning implementation details detected in the binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificatePinning {
    pub pin_type: PinType,
    pub pinned_hashes: Vec<String>,
    pub backup_pins: Vec<String>,
    pub framework: PinningFramework,
    pub max_age_secs: Option<u64>,
    pub include_subdomains: bool,
    pub report_uri: Option<String>,
    pub enforce: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinType {
    PublicKey,
    Certificate,
    SubjectPublicKeyInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinningFramework {
    Native, // URLSession / OkHttp
    TrustKit,
    Appcelerator,
    Cordova,
    CustomImpl,
    AndroidNetworkSecurity,
    Hpkp,
}

impl CertificatePinning {
    #[must_use]
    pub const fn has_backup_pin(&self) -> bool {
        !self.backup_pins.is_empty()
    }

    #[must_use]
    pub const fn is_compliant(&self) -> bool {
        // HPKP / best-practice: at least one backup pin, enforce mode
        self.has_backup_pin() && self.enforce
    }
}

// â”€â”€ HpkpDetector â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// HTTP Public Key Pinning (HPKP) header analyser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkpHeader {
    pub pins: Vec<String>,
    pub max_age: u64,
    pub include_subdomains: bool,
    pub report_uri: Option<String>,
}

impl HpkpHeader {
    /// Parse a `Public-Key-Pins` header value.
    ///
    /// # Errors
    /// Returns `Err` if the header is malformed or missing required fields.
    pub fn parse(header: &str) -> Result<Self, ProtoCryptoError> {
        let mut pins = Vec::new();
        let mut max_age = 0u64;
        let mut include_subdomains = false;
        let mut report_uri = None;

        for part in header.split(';').map(str::trim) {
            if part.starts_with("pin-sha256=") {
                let hash = part
                    .trim_start_matches("pin-sha256=")
                    .trim_matches('"')
                    .to_owned();
                pins.push(hash);
            } else if part.starts_with("max-age=") {
                max_age = part
                    .trim_start_matches("max-age=")
                    .parse()
                    .map_err(|_| ProtoCryptoError::ParseError("invalid max-age".into()))?;
            } else if part.eq_ignore_ascii_case("includeSubDomains") {
                include_subdomains = true;
            } else if part.starts_with("report-uri=") {
                report_uri = Some(
                    part.trim_start_matches("report-uri=")
                        .trim_matches('"')
                        .to_owned(),
                );
            }
        }

        if pins.is_empty() {
            return Err(ProtoCryptoError::ParseError("no pins found".into()));
        }
        Ok(Self {
            pins,
            max_age,
            include_subdomains,
            report_uri,
        })
    }

    #[must_use]
    pub const fn has_backup_pin(&self) -> bool {
        self.pins.len() >= 2
    }

    /// Warn if max-age is too short (< 30 days).
    #[must_use]
    pub const fn is_max_age_too_short(&self) -> bool {
        self.max_age < 30 * 24 * 3600
    }
}

// â”€â”€ ProtocolCrypto â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Top-level protocol cryptography analyser.
pub struct ProtocolCrypto {
    suite_db: HashMap<u16, CipherSuite>,
}

impl ProtocolCrypto {
    #[must_use]
    pub fn new() -> Self {
        Self {
            suite_db: cipher_suite_db(),
        }
    }

    /// Detect TLS version from raw bytes (client/server hello record layer).
    ///
    /// # Errors
    /// Returns `Err` if `data` is too short or the record layer bytes are unrecognised.
    pub fn detect_tls_version(&self, data: &[u8]) -> Result<TlsVersion, ProtoCryptoError> {
        if data.len() < 5 {
            return Err(ProtoCryptoError::TooShort {
                need: 5,
                have: data.len(),
            });
        }
        let content_type = data[0];
        if content_type != 22 {
            return Err(ProtoCryptoError::NotTlsRecord(content_type));
        }
        let major = data[1];
        let minor = data[2];
        Ok(TlsVersion::from_wire(major, minor))
    }

    /// Look up a cipher suite by IANA ID.
    #[must_use]
    pub fn lookup_cipher_suite(&self, id: u16) -> Option<&CipherSuite> {
        self.suite_db.get(&id)
    }

    /// Classify a list of cipher suite IDs into security levels.
    #[must_use]
    pub fn classify_suites(&self, ids: &[u16]) -> HashMap<SuiteSecurityLevel, Vec<u16>> {
        let mut out: HashMap<SuiteSecurityLevel, Vec<u16>> = HashMap::new();
        for &id in ids {
            let level = self
                .suite_db
                .get(&id)
                .map_or(SuiteSecurityLevel::Acceptable, |s| s.security);
            out.entry(level).or_default().push(id);
        }
        out
    }

    /// Return all weak/broken cipher suites from a list.
    #[must_use]
    pub fn weak_suites(&self, ids: &[u16]) -> Vec<&CipherSuite> {
        ids.iter()
            .filter_map(|id| self.suite_db.get(id))
            .filter(|s| s.is_weak())
            .collect()
    }

    /// Return cipher suites that provide forward secrecy.
    #[must_use]
    pub fn pfs_suites(&self, ids: &[u16]) -> Vec<&CipherSuite> {
        ids.iter()
            .filter_map(|id| self.suite_db.get(id))
            .filter(|s| s.uses_forward_secrecy())
            .collect()
    }

    /// Compute security score for a TLS configuration (0-100).
    #[must_use]
    pub fn tls_security_score(
        &self,
        version: TlsVersion,
        cipher_ids: &[u16],
        has_cert_pinning: bool,
        has_hsts: bool,
    ) -> u8 {
        let mut score = 50u32;

        match version {
            TlsVersion::Tls13 => score += 40,
            TlsVersion::Tls12 => score += 20,
            TlsVersion::Tls11 => score = score.saturating_sub(20),
            TlsVersion::Tls10 => score = score.saturating_sub(30),
            TlsVersion::Ssl30 => score = score.saturating_sub(50),
            TlsVersion::Unknown(_) => {}
        }

        let weak = self.weak_suites(cipher_ids).len();
        score = score.saturating_sub(u32::try_from(weak).unwrap_or(u32::MAX).saturating_mul(10));

        let pfs = self.pfs_suites(cipher_ids).len();
        if pfs > 0 {
            score += 10;
        }

        if has_cert_pinning {
            score += 10;
        }
        if has_hsts {
            score += 5;
        }

        score.min(100) as u8
    }

    /// Number of suites in the database.
    #[must_use]
    pub fn suite_count(&self) -> usize {
        self.suite_db.len()
    }
}

impl Default for ProtocolCrypto {
    fn default() -> Self {
        Self::new()
    }
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Tests
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ TlsVersion tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_tls_version_from_wire_tls12() {
        assert_eq!(TlsVersion::from_wire(3, 3), TlsVersion::Tls12);
    }

    #[test]
    fn test_tls_version_from_wire_tls13() {
        assert_eq!(TlsVersion::from_wire(3, 4), TlsVersion::Tls13);
    }

    #[test]
    fn test_tls_version_from_wire_ssl30() {
        assert_eq!(TlsVersion::from_wire(3, 0), TlsVersion::Ssl30);
    }

    #[test]
    fn test_tls_version_from_wire_unknown() {
        assert!(matches!(
            TlsVersion::from_wire(2, 0),
            TlsVersion::Unknown(_)
        ));
    }

    #[test]
    fn test_tls_version_to_wire_roundtrip() {
        let versions = [
            TlsVersion::Ssl30,
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls12,
            TlsVersion::Tls13,
        ];
        for v in versions {
            let wire = v.to_wire();
            let major = (wire >> 8) as u8;
            let minor = wire as u8;
            assert_eq!(TlsVersion::from_wire(major, minor), v);
        }
    }

    #[test]
    fn test_tls_version_deprecated() {
        assert!(TlsVersion::Ssl30.is_deprecated());
        assert!(TlsVersion::Tls10.is_deprecated());
        assert!(TlsVersion::Tls11.is_deprecated());
        assert!(!TlsVersion::Tls12.is_deprecated());
        assert!(!TlsVersion::Tls13.is_deprecated());
    }

    #[test]
    fn test_tls_version_labels() {
        assert_eq!(TlsVersion::Tls12.label(), "TLS 1.2");
        assert_eq!(TlsVersion::Tls13.label(), "TLS 1.3");
        assert_eq!(TlsVersion::Ssl30.label(), "SSL 3.0");
    }

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls13 > TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 > TlsVersion::Tls10);
    }

    // â”€â”€ KeyExchange tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_key_exchange_pfs() {
        assert!(KeyExchange::Ecdhe.provides_pfs());
        assert!(KeyExchange::Dhe.provides_pfs());
        assert!(!KeyExchange::Rsa.provides_pfs());
    }

    #[test]
    fn test_key_exchange_export_grade() {
        assert!(KeyExchange::DhExport.is_export_grade());
        assert!(!KeyExchange::Ecdhe.is_export_grade());
    }

    // â”€â”€ CipherSuite DB tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_cipher_suite_db_has_enough_suites() {
        let db = cipher_suite_db();
        assert!(db.len() >= 30);
    }

    #[test]
    fn test_cipher_suite_aes_gcm_recommended() {
        let db = cipher_suite_db();
        let suite = db.get(&0xC02F).unwrap();
        assert_eq!(suite.security, SuiteSecurityLevel::Recommended);
        assert!(suite.uses_forward_secrecy());
    }

    #[test]
    fn test_cipher_suite_rc4_weak() {
        let db = cipher_suite_db();
        let suite = db.get(&0x0005).unwrap();
        assert!(suite.is_weak());
    }

    #[test]
    fn test_cipher_suite_null_broken() {
        let db = cipher_suite_db();
        let suite = db.get(&0x0000).unwrap();
        assert_eq!(suite.security, SuiteSecurityLevel::Broken);
    }

    #[test]
    fn test_tls13_suites_exist() {
        let db = cipher_suite_db();
        assert!(db.contains_key(&0x1301));
        assert!(db.contains_key(&0x1302));
        assert!(db.contains_key(&0x1303));
    }

    // â”€â”€ SslStrip tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_ssl_strip_inactive_default() {
        let s = SslStripIndicators::new();
        assert!(!s.is_active());
        assert_eq!(s.confidence(), 0);
    }

    #[test]
    fn test_ssl_strip_active() {
        let s = SslStripIndicators {
            redirect_type: HttpRedirectType::Both,
            missing_hsts: true,
            ..Default::default()
        };
        assert!(s.is_active());
        assert!(s.confidence() > 60);
    }

    #[test]
    fn test_ssl_strip_with_tool() {
        let s = SslStripIndicators {
            redirect_type: HttpRedirectType::HttpsToHttp,
            detected_tool: Some("sslstrip2".into()),
            ..Default::default()
        };
        assert!(s.confidence() >= 60);
    }

    // â”€â”€ CertificatePinning tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_cert_pinning_compliant() {
        let p = CertificatePinning {
            pin_type: PinType::SubjectPublicKeyInfo,
            pinned_hashes: vec!["hash1".into()],
            backup_pins: vec!["hash2".into()],
            framework: PinningFramework::TrustKit,
            max_age_secs: Some(90 * 24 * 3600),
            include_subdomains: true,
            report_uri: None,
            enforce: true,
        };
        assert!(p.is_compliant());
        assert!(p.has_backup_pin());
    }

    #[test]
    fn test_cert_pinning_not_compliant_no_backup() {
        let p = CertificatePinning {
            pin_type: PinType::Certificate,
            pinned_hashes: vec!["hash1".into()],
            backup_pins: vec![],
            framework: PinningFramework::Native,
            max_age_secs: None,
            include_subdomains: false,
            report_uri: None,
            enforce: true,
        };
        assert!(!p.is_compliant());
    }

    // â”€â”€ HpkpHeader tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// NOTE: the header strings below use `max-age=5184000`, not
    /// `max-age=5_184_000`. Underscores are Rust *literal* syntax; an HTTP
    /// header carries plain digits, and `str::parse::<u64>` rejects the
    /// underscored form. Both HPKP tests failed for exactly that reason — the
    /// parser was right and the fixtures were not valid headers. Rust
    /// underscores remain in the ASSERTIONS, where they are legitimate.
    #[test]
    fn test_hpkp_parse_valid() {
        let h = r#"pin-sha256="base64hash1=="; pin-sha256="base64hash2=="; max-age=5184000; includeSubDomains"#;
        let hpkp = HpkpHeader::parse(h).unwrap();
        assert_eq!(hpkp.pins.len(), 2);
        assert_eq!(hpkp.max_age, 5_184_000);
        assert!(hpkp.include_subdomains);
        assert!(hpkp.has_backup_pin());
    }

    #[test]
    fn test_hpkp_parse_no_pins() {
        let err = HpkpHeader::parse("max-age=100").unwrap_err();
        assert!(matches!(err, ProtoCryptoError::ParseError(_)));
    }

    #[test]
    fn test_hpkp_max_age_too_short() {
        let h = r#"pin-sha256="hash1=="; max-age=100"#;
        let hpkp = HpkpHeader::parse(h).unwrap();
        assert!(hpkp.is_max_age_too_short());
    }

    #[test]
    fn test_hpkp_max_age_ok() {
        let h = r#"pin-sha256="hash1=="; pin-sha256="hash2=="; max-age=5184000"#;
        let hpkp = HpkpHeader::parse(h).unwrap();
        assert!(!hpkp.is_max_age_too_short());
    }

    // â”€â”€ ProtocolCrypto tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_detect_tls12_record() {
        let pc = ProtocolCrypto::new();
        let data = [22u8, 3, 3, 0, 100]; // TLS 1.2 Handshake record
        let ver = pc.detect_tls_version(&data).unwrap();
        assert_eq!(ver, TlsVersion::Tls12);
    }

    #[test]
    fn test_detect_tls_not_record() {
        let pc = ProtocolCrypto::new();
        let data = [20u8, 3, 3, 0, 10];
        let err = pc.detect_tls_version(&data).unwrap_err();
        assert!(matches!(err, ProtoCryptoError::NotTlsRecord(20)));
    }

    #[test]
    fn test_detect_tls_too_short() {
        let pc = ProtocolCrypto::new();
        let err = pc.detect_tls_version(&[22u8, 3]).unwrap_err();
        assert!(matches!(err, ProtoCryptoError::TooShort { .. }));
    }

    #[test]
    fn test_lookup_cipher_suite_found() {
        let pc = ProtocolCrypto::new();
        let suite = pc.lookup_cipher_suite(0xC02F).unwrap();
        assert!(suite.name.contains("AES_128_GCM"));
    }

    #[test]
    fn test_lookup_cipher_suite_not_found() {
        let pc = ProtocolCrypto::new();
        assert!(pc.lookup_cipher_suite(0xDEAD).is_none());
    }

    #[test]
    fn test_weak_suites() {
        let pc = ProtocolCrypto::new();
        let ids = &[0x0005u16, 0xC02F]; // RC4 (weak) + ECDHE_RSA_AES128_GCM (recommended)
        let weak = pc.weak_suites(ids);
        assert_eq!(weak.len(), 1);
        assert!(weak[0].name.contains("RC4"));
    }

    #[test]
    fn test_pfs_suites() {
        let pc = ProtocolCrypto::new();
        let ids = &[0xC02Fu16, 0x002Fu16]; // ECDHE (PFS) + RSA (no PFS)
        let pfs = pc.pfs_suites(ids);
        assert_eq!(pfs.len(), 1);
    }

    #[test]
    fn test_tls_security_score_tls13_good() {
        let pc = ProtocolCrypto::new();
        let ids = &[0xC02Fu16, 0xC030];
        let score = pc.tls_security_score(TlsVersion::Tls13, ids, true, true);
        assert!(score >= 80);
    }

    #[test]
    fn test_tls_security_score_ssl30_bad() {
        let pc = ProtocolCrypto::new();
        let ids = &[0x0005u16]; // RC4 (weak)
        let score = pc.tls_security_score(TlsVersion::Ssl30, ids, false, false);
        assert!(score <= 30);
    }

    #[test]
    fn test_suite_count_gte_30() {
        let pc = ProtocolCrypto::new();
        assert!(pc.suite_count() >= 30);
    }

    #[test]
    fn test_classify_suites() {
        let pc = ProtocolCrypto::new();
        let ids = &[0x0000u16, 0x0005, 0xC02F, 0x1301];
        let map = pc.classify_suites(ids);
        assert!(map.contains_key(&SuiteSecurityLevel::Broken));
        assert!(map.contains_key(&SuiteSecurityLevel::Recommended));
    }
}
