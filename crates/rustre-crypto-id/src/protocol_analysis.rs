//! Protocol cryptographic analysis for `rustre-crypto-id`.
//!
//! Analyses handshake traces for TLS, SSH, `WireGuard`, and `OpenPGP` to identify
//! the cryptographic algorithms in use, detect weaknesses, and produce a
//! structured report.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ProtocolAnalysisError {
    #[error("insufficient data: need at least {0} bytes, got {1}")]
    InsufficientData(usize, usize),
    #[error("unknown protocol version: {0:#04x}")]
    UnknownVersion(u16),
    #[error("parse error at offset {offset}: {reason}")]
    Parse { offset: usize, reason: String },
    #[error("unsupported cipher suite: {0:#06x}")]
    UnsupportedCipherSuite(u16),
    #[error("{0}")]
    Other(String),
}

// ── Protocol kind ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolKind {
    Tls,
    Ssh,
    WireGuard,
    OpenPgp,
}

impl std::fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls      => write!(f, "TLS"),
            Self::Ssh      => write!(f, "SSH"),
            Self::WireGuard => write!(f, "WireGuard"),
            Self::OpenPgp  => write!(f, "OpenPGP"),
        }
    }
}

// ── SecurityLevel ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    Broken,
    Weak,
    Acceptable,
    Strong,
    VeryStrong,
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broken    => write!(f, "BROKEN"),
            Self::Weak      => write!(f, "WEAK"),
            Self::Acceptable => write!(f, "ACCEPTABLE"),
            Self::Strong    => write!(f, "STRONG"),
            Self::VeryStrong => write!(f, "VERY_STRONG"),
        }
    }
}

// ── CipherSuiteInfo ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuiteInfo {
    pub iana_value: u16,
    pub name: String,
    pub key_exchange: String,
    pub authentication: String,
    pub encryption: String,
    pub mac: String,
    pub level: SecurityLevel,
    pub forward_secrecy: bool,
    pub aead: bool,
}

impl CipherSuiteInfo {
    /// Decode the IANA cipher suite value into structured info.
    #[must_use]
    pub fn from_iana(value: u16) -> Self {
        match value {
            0x1301..=0x1303           => Self::from_iana_tls13(value),
            0xC02B | 0xC02C | 0xCCA9 | 0x0033 => Self::from_iana_ecdhe(value),
            0x000A | 0x0004 | 0x0000  => Self::from_iana_legacy(value),
            _ => Self {
                iana_value: value,
                name: format!("UNKNOWN({value:#06x})"),
                key_exchange: "UNKNOWN".into(),
                authentication: "UNKNOWN".into(),
                encryption: "UNKNOWN".into(),
                mac: "UNKNOWN".into(),
                level: SecurityLevel::Acceptable,
                forward_secrecy: false,
                aead: false,
            },
        }
    }

    fn from_iana_tls13(value: u16) -> Self {
        match value {
            0x1301 => Self {
                iana_value: value, name: "TLS_AES_128_GCM_SHA256".into(),
                key_exchange: "TLS1.3-ECDHE".into(), authentication: "TLS1.3-ECDSA/RSA".into(),
                encryption: "AES-128-GCM".into(), mac: "SHA-256".into(),
                level: SecurityLevel::Strong, forward_secrecy: true, aead: true,
            },
            0x1302 => Self {
                iana_value: value, name: "TLS_AES_256_GCM_SHA384".into(),
                key_exchange: "TLS1.3-ECDHE".into(), authentication: "TLS1.3-ECDSA/RSA".into(),
                encryption: "AES-256-GCM".into(), mac: "SHA-384".into(),
                level: SecurityLevel::VeryStrong, forward_secrecy: true, aead: true,
            },
            _ /* 0x1303 */ => Self {
                iana_value: value, name: "TLS_CHACHA20_POLY1305_SHA256".into(),
                key_exchange: "TLS1.3-ECDHE".into(), authentication: "TLS1.3-ECDSA/RSA".into(),
                encryption: "ChaCha20-Poly1305".into(), mac: "SHA-256".into(),
                level: SecurityLevel::VeryStrong, forward_secrecy: true, aead: true,
            },
        }
    }

    fn from_iana_ecdhe(value: u16) -> Self {
        match value {
            0xC02B => Self {
                iana_value: value, name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
                key_exchange: "ECDHE".into(), authentication: "RSA".into(),
                encryption: "AES-128-GCM".into(), mac: "SHA-256".into(),
                level: SecurityLevel::Strong, forward_secrecy: true, aead: true,
            },
            0xC02C => Self {
                iana_value: value, name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
                key_exchange: "ECDHE".into(), authentication: "RSA".into(),
                encryption: "AES-256-GCM".into(), mac: "SHA-384".into(),
                level: SecurityLevel::Strong, forward_secrecy: true, aead: true,
            },
            0xCCA9 => Self {
                iana_value: value, name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
                key_exchange: "ECDHE".into(), authentication: "ECDSA".into(),
                encryption: "ChaCha20-Poly1305".into(), mac: "SHA-256".into(),
                level: SecurityLevel::VeryStrong, forward_secrecy: true, aead: true,
            },
            _ /* 0x0033 */ => Self {
                iana_value: value, name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA".into(),
                key_exchange: "DHE".into(), authentication: "RSA".into(),
                encryption: "AES-128-CBC".into(), mac: "SHA-1".into(),
                level: SecurityLevel::Acceptable, forward_secrecy: true, aead: false,
            },
        }
    }

    fn from_iana_legacy(value: u16) -> Self {
        match value {
            0x000A => Self {
                iana_value: value, name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
                key_exchange: "RSA".into(), authentication: "RSA".into(),
                encryption: "3DES-EDE-CBC".into(), mac: "SHA-1".into(),
                level: SecurityLevel::Weak, forward_secrecy: false, aead: false,
            },
            0x0004 => Self {
                iana_value: value, name: "TLS_RSA_WITH_RC4_128_MD5".into(),
                key_exchange: "RSA".into(), authentication: "RSA".into(),
                encryption: "RC4-128".into(), mac: "MD5".into(),
                level: SecurityLevel::Broken, forward_secrecy: false, aead: false,
            },
            _ /* 0x0000 */ => Self {
                iana_value: value, name: "TLS_NULL_WITH_NULL_NULL".into(),
                key_exchange: "NULL".into(), authentication: "NULL".into(),
                encryption: "NULL".into(), mac: "NULL".into(),
                level: SecurityLevel::Broken, forward_secrecy: false, aead: false,
            },
        }
    }
}

// ── TlsVersion ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown(u16),
}

impl TlsVersion {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            0x0300 => Self::Ssl30,
            0x0301 => Self::Tls10,
            0x0302 => Self::Tls11,
            0x0303 => Self::Tls12,
            0x0304 => Self::Tls13,
            other  => Self::Unknown(other),
        }
    }

    #[must_use]
    pub const fn security_level(self) -> SecurityLevel {
        match self {
            Self::Ssl30 | Self::Tls10 => SecurityLevel::Broken,
            Self::Tls11 | Self::Unknown(_) => SecurityLevel::Weak,
            Self::Tls12               => SecurityLevel::Acceptable,
            Self::Tls13               => SecurityLevel::VeryStrong,
        }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssl30      => write!(f, "SSLv3.0"),
            Self::Tls10      => write!(f, "TLS 1.0"),
            Self::Tls11      => write!(f, "TLS 1.1"),
            Self::Tls12      => write!(f, "TLS 1.2"),
            Self::Tls13      => write!(f, "TLS 1.3"),
            Self::Unknown(v) => write!(f, "Unknown({v:#06x})"),
        }
    }
}

// ── TlsAnalysis ───────────────────────────────────────────────────────────────

/// Analysis of a TLS `ClientHello` or `ServerHello` byte sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAnalysis {
    /// Parsed TLS record/handshake version.
    pub version: TlsVersion,
    /// Cipher suites offered / selected.
    pub cipher_suites: Vec<CipherSuiteInfo>,
    /// Whether SNI extension is present.
    pub has_sni: bool,
    /// Whether session resumption appears to be attempted.
    pub session_resumption: bool,
    /// Extensions seen (TLS extension type numbers).
    pub extensions: Vec<u16>,
    /// Overall security assessment.
    pub security_level: SecurityLevel,
    /// Human-readable findings.
    pub findings: Vec<String>,
}

impl TlsAnalysis {
    /// Parse a raw TLS `ClientHello` byte slice.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolAnalysisError` if the data is too short or does not
    /// begin with a valid TLS handshake record.
    pub fn parse_client_hello(data: &[u8]) -> Result<Self, ProtocolAnalysisError> {
        if data.len() < 5 {
            return Err(ProtocolAnalysisError::InsufficientData(5, data.len()));
        }
        // TLS record header: type(1) + version(2) + length(2)
        let record_type = data[0];
        if record_type != 0x16 {
            return Err(ProtocolAnalysisError::Parse {
                offset: 0,
                reason: format!("expected handshake record (0x16), got {record_type:#04x}"),
            });
        }
        let record_version = TlsVersion::from_u16(u16::from_be_bytes([data[1], data[2]]));
        if data.len() < 9 {
            return Err(ProtocolAnalysisError::InsufficientData(9, data.len()));
        }
        // Handshake header at offset 5: type(1) + length(3)
        let hs_type = data[5];
        if hs_type != 0x01 {
            return Err(ProtocolAnalysisError::Parse {
                offset: 5,
                reason: format!("expected ClientHello (0x01), got {hs_type:#04x}"),
            });
        }
        // Client version at offset 9
        if data.len() < 11 {
            return Err(ProtocolAnalysisError::InsufficientData(11, data.len()));
        }
        let client_version = TlsVersion::from_u16(u16::from_be_bytes([data[9], data[10]]));

        // Session ID at offset 43: length byte then N bytes
        let mut offset = 43;
        if data.len() <= offset {
            return Ok(Self::minimal(record_version, client_version));
        }
        let session_len = data[offset] as usize;
        let session_resumption = session_len > 0;
        // Validate that the session ID fits within remaining data before advancing.
        if data.len() < offset + 1 + session_len {
            return Ok(Self::minimal(record_version, client_version));
        }
        offset += 1 + session_len;

        // Cipher suites: 2-byte count then pairs
        if data.len() < offset + 2 {
            return Ok(Self::minimal(record_version, client_version));
        }
        let cs_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        let mut cipher_suites = Vec::new();
        // Clamp cs_end to data.len() so an attacker-supplied length cannot drive
        // the iterator past the end of the buffer.
        let cs_end = (offset + cs_len).min(data.len());
        while offset + 1 < cs_end && offset + 1 < data.len() {
            let cs = u16::from_be_bytes([data[offset], data[offset + 1]]);
            cipher_suites.push(CipherSuiteInfo::from_iana(cs));
            offset += 2;
        }
        offset = cs_end;

        // Compression methods
        if data.len() > offset {
            let comp_len = data[offset] as usize;
            offset += 1 + comp_len;
        }

        // Extensions
        let (extensions, has_sni) = Self::parse_tls_extensions(data, offset);

        // Assess overall security
        let (security_level, findings) =
            Self::assess_client_hello_security(&cipher_suites, client_version, has_sni);

        Ok(Self {
            version: record_version,
            cipher_suites,
            has_sni,
            session_resumption,
            extensions,
            security_level,
            findings,
        })
    }

    fn parse_tls_extensions(data: &[u8], offset: usize) -> (Vec<u16>, bool) {
        let mut extensions = Vec::new();
        let mut has_sni = false;
        if data.len() < offset + 2 { return (extensions, has_sni); }
        let ext_total = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        let mut pos = offset + 2;
        let ext_end = (pos + ext_total).min(data.len());
        // Each extension header is 4 bytes (2 type + 2 length).
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len  = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            extensions.push(ext_type);
            if ext_type == 0x0000 { has_sni = true; }
            let next = pos + 4 + ext_len;
            if next > ext_end || next < pos { break; }
            pos = next;
        }
        (extensions, has_sni)
    }

    fn assess_client_hello_security(
        cipher_suites: &[CipherSuiteInfo],
        client_version: TlsVersion,
        has_sni: bool,
    ) -> (SecurityLevel, Vec<String>) {
        let suite_level = cipher_suites.iter().map(|cs| cs.level)
            .min().unwrap_or(SecurityLevel::Acceptable);
        let security_level = suite_level.min(client_version.security_level());
        let mut findings = Vec::new();
        if client_version == TlsVersion::Ssl30 || client_version == TlsVersion::Tls10 {
            findings.push(format!("Deprecated protocol version offered: {client_version}"));
        }
        if cipher_suites.iter().any(|cs| cs.level == SecurityLevel::Broken) {
            findings.push("One or more BROKEN cipher suites offered".into());
        }
        if !cipher_suites.iter().any(|cs| cs.forward_secrecy) {
            findings.push("No forward-secret cipher suites offered".into());
        }
        if !cipher_suites.iter().any(|cs| cs.aead) {
            findings.push("No AEAD cipher suites offered".into());
        }
        if has_sni { findings.push("SNI extension present".into()); }
        (security_level, findings)
    }

    fn minimal(record_version: TlsVersion, client_version: TlsVersion) -> Self {
        let level = client_version.security_level();
        Self {
            version: record_version,
            cipher_suites: Vec::new(),
            has_sni: false,
            session_resumption: false,
            extensions: Vec::new(),
            security_level: level,
            findings: vec!["Insufficient data for full parse".into()],
        }
    }

    /// Return only the cipher suites with `SecurityLevel <= Weak`.
    #[must_use]
    pub fn weak_suites(&self) -> Vec<&CipherSuiteInfo> {
        self.cipher_suites
            .iter()
            .filter(|cs| cs.level <= SecurityLevel::Weak)
            .collect()
    }

    /// True if at least one TLS 1.3 cipher suite was offered.
    #[must_use]
    pub fn supports_tls13(&self) -> bool {
        self.cipher_suites.iter().any(|cs| {
            matches!(cs.iana_value, 0x1301..=0x1303)
        })
    }
}

// ── SshKeyExchange ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SshKexAlgorithm {
    DiffieHellmanGroup1Sha1,
    DiffieHellmanGroup14Sha1,
    DiffieHellmanGroup14Sha256,
    DiffieHellmanGroup16Sha512,
    EcdhSha2Nistp256,
    EcdhSha2Nistp384,
    EcdhSha2Nistp521,
    Curve25519Sha256,
    Unknown,
}

impl SshKexAlgorithm {
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            "diffie-hellman-group1-sha1"   => Self::DiffieHellmanGroup1Sha1,
            "diffie-hellman-group14-sha1"  => Self::DiffieHellmanGroup14Sha1,
            "diffie-hellman-group14-sha256" => Self::DiffieHellmanGroup14Sha256,
            "diffie-hellman-group16-sha512" => Self::DiffieHellmanGroup16Sha512,
            "ecdh-sha2-nistp256"           => Self::EcdhSha2Nistp256,
            "ecdh-sha2-nistp384"           => Self::EcdhSha2Nistp384,
            "ecdh-sha2-nistp521"           => Self::EcdhSha2Nistp521,
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => Self::Curve25519Sha256,
            _                              => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn security_level(self) -> SecurityLevel {
        match self {
            Self::DiffieHellmanGroup1Sha1  => SecurityLevel::Broken,
            Self::DiffieHellmanGroup14Sha1 => SecurityLevel::Weak,
            Self::DiffieHellmanGroup14Sha256 | Self::EcdhSha2Nistp256 | Self::Unknown => SecurityLevel::Acceptable,
            Self::DiffieHellmanGroup16Sha512 | Self::EcdhSha2Nistp384 | Self::EcdhSha2Nistp521 => SecurityLevel::Strong,
            Self::Curve25519Sha256         => SecurityLevel::VeryStrong,
        }
    }

    #[must_use]
    pub const fn forward_secrecy(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Analysis of an SSH connection banner and key-exchange init.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAnalysis {
    /// SSH protocol version string (e.g. "SSH-2.0-OpenSSH_8.9").
    pub version_string: String,
    /// Major SSH protocol version (1 or 2).
    pub ssh_version: u8,
    /// Key-exchange algorithms advertised.
    pub kex_algorithms: Vec<SshKexAlgorithm>,
    /// Host-key types advertised.
    pub host_key_types: Vec<String>,
    /// Encryption algorithms (client→server).
    pub encryption_client_server: Vec<String>,
    /// Encryption algorithms (server→client).
    pub encryption_server_client: Vec<String>,
    /// MAC algorithms (client→server).
    pub mac_client_server: Vec<String>,
    /// Overall security level.
    pub security_level: SecurityLevel,
    /// Human-readable findings.
    pub findings: Vec<String>,
}

impl SshAnalysis {
    /// Parse the SSH version banner line.
    ///
    /// # Errors
    ///
    /// Returns `ProtocolAnalysisError::Parse` if `banner` does not start with `"SSH-"`.
    pub fn parse_banner(banner: &str) -> Result<Self, ProtocolAnalysisError> {
        if !banner.starts_with("SSH-") {
            return Err(ProtocolAnalysisError::Parse {
                offset: 0,
                reason: "not an SSH banner".into(),
            });
        }
        let parts: Vec<&str> = banner.splitn(3, '-').collect();
        let ssh_version: u8 = if parts.get(1).copied().unwrap_or("").starts_with('2') {
            2
        } else {
            1
        };

        let mut findings = Vec::new();
        if ssh_version == 1 {
            findings.push("SSHv1 detected — protocol is broken and must not be used".into());
        }

        let security_level = if ssh_version == 1 { SecurityLevel::Broken } else { SecurityLevel::Acceptable };

        Ok(Self {
            version_string: banner.trim().to_string(),
            ssh_version,
            kex_algorithms: Vec::new(),
            host_key_types: Vec::new(),
            encryption_client_server: Vec::new(),
            encryption_server_client: Vec::new(),
            mac_client_server: Vec::new(),
            security_level,
            findings,
        })
    }

    /// Add key exchange algorithms from a comma-separated list.
    pub fn add_kex_algorithms(&mut self, kex_list: &str) {
        for name in kex_list.split(',').map(str::trim) {
            let alg = SshKexAlgorithm::from_name(name);
            self.kex_algorithms.push(alg);
        }
        self.assess_security();
    }

    fn assess_security(&mut self) {
        let worst_kex = self.kex_algorithms
            .iter()
            .map(|k| k.security_level())
            .min()
            .unwrap_or(SecurityLevel::Acceptable);

        if worst_kex < self.security_level {
            self.security_level = worst_kex;
        }

        if self.kex_algorithms.contains(&SshKexAlgorithm::DiffieHellmanGroup1Sha1) {
            self.findings.push("diffie-hellman-group1-sha1 (Logjam-vulnerable) present".into());
        }
        if self.mac_client_server.iter().any(|m| m.contains("md5")) {
            self.findings.push("MD5-based MAC algorithm offered".into());
        }
        if self.encryption_client_server.iter().any(|e| e.starts_with("arcfour")) {
            self.findings.push("RC4 (arcfour) encryption offered — broken cipher".into());
        }
    }

    /// Set the host key types and evaluate.
    pub fn set_host_key_types(&mut self, types: Vec<String>) {
        if types.iter().any(|t| t == "ssh-dss") {
            self.findings.push("DSS (DSA) host key present — deprecated key type".into());
        }
        self.host_key_types = types;
    }
}

// ── WireGuardAnalysis ─────────────────────────────────────────────────────────

/// Type tag for a `WireGuard` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WgMessageType {
    Initiation,
    Response,
    CookieReply,
    Transport,
    Unknown(u8),
}

impl WgMessageType {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Initiation,
            2 => Self::Response,
            3 => Self::CookieReply,
            4 => Self::Transport,
            v => Self::Unknown(v),
        }
    }
}

impl std::fmt::Display for WgMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initiation   => write!(f, "Initiation"),
            Self::Response     => write!(f, "Response"),
            Self::CookieReply  => write!(f, "CookieReply"),
            Self::Transport    => write!(f, "Transport"),
            Self::Unknown(v)   => write!(f, "Unknown({v})"),
        }
    }
}

/// Analysis of `WireGuard` handshake packets.
///
/// `WireGuard` uses a fixed crypto suite: Curve25519, ChaCha20-Poly1305, BLAKE2s.
/// Analysis focuses on message structure correctness and anomaly detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardAnalysis {
    pub message_types: Vec<WgMessageType>,
    pub initiation_count: usize,
    pub response_count: usize,
    pub transport_count: usize,
    /// Expected fields present in the initiation message.
    pub has_valid_initiation: bool,
    /// Whether any replay-window anomalies are detected.
    pub replay_anomaly: bool,
    /// Fixed crypto suite (always the same for `WireGuard`).
    pub crypto_suite: WireGuardCryptoSuite,
    pub security_level: SecurityLevel,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardCryptoSuite {
    pub key_exchange: String,
    pub encryption:  String,
    pub hash:        String,
    pub mac:         String,
}

impl Default for WireGuardCryptoSuite {
    fn default() -> Self {
        Self {
            key_exchange: "Curve25519".into(),
            encryption:   "ChaCha20-Poly1305".into(),
            hash:         "BLAKE2s".into(),
            mac:          "Poly1305".into(),
        }
    }
}

impl WireGuardAnalysis {
    /// Parse a slice of `WireGuard` packets (concatenated).
    ///
    /// # Errors
    ///
    /// Returns `ProtocolAnalysisError::InsufficientData` if `data` is empty or
    /// a packet header is incomplete.
    pub fn parse_packets(data: &[u8]) -> Result<Self, ProtocolAnalysisError> {
        if data.is_empty() {
            return Err(ProtocolAnalysisError::InsufficientData(1, 0));
        }
        let mut message_types = Vec::new();
        let mut offset = 0usize;
        let mut initiation_count = 0usize;
        let mut response_count   = 0usize;
        let mut transport_count  = 0usize;
        let mut has_valid_initiation = false;

        while offset < data.len() {
            let msg_type = WgMessageType::from_byte(data[offset]);
            message_types.push(msg_type);
            let (msg_len, valid) = match msg_type {
                WgMessageType::Initiation  => {
                    initiation_count += 1;
                    // Initiation: 148 bytes total
                    let valid = offset + 148 <= data.len();
                    if valid { has_valid_initiation = true; }
                    (148, valid)
                }
                WgMessageType::Response    => {
                    response_count += 1;
                    (92, offset + 92 <= data.len())
                }
                WgMessageType::CookieReply => (64, offset + 64 <= data.len()),
                WgMessageType::Transport   => {
                    transport_count += 1;
                    if offset + 16 > data.len() { break; }
                    // offset + 10 and offset + 11 are safe: we confirmed offset + 16 <= data.len()
                    let len_field = u16::from_le_bytes([data[offset + 10], data[offset + 11]]) as usize;
                    // Use checked_add to prevent wrapping on adversarial len_field values.
                    let Some(msg_total) = (16usize).checked_add(len_field) else { break };
                    let valid = offset.checked_add(msg_total).is_some_and(|end| end <= data.len());
                    (msg_total, valid)
                }
                WgMessageType::Unknown(_)  => break,
            };
            if !valid { break; }
            offset += msg_len;
        }

        let mut findings = Vec::new();
        findings.push("WireGuard fixed crypto suite: Curve25519 + ChaCha20-Poly1305 + BLAKE2s".to_string());
        if initiation_count > 0 && response_count == 0 {
            findings.push("Initiation without Response — possible handshake failure".into());
        }

        Ok(Self {
            message_types,
            initiation_count,
            response_count,
            transport_count,
            has_valid_initiation,
            replay_anomaly: false,
            crypto_suite: WireGuardCryptoSuite::default(),
            security_level: SecurityLevel::VeryStrong,
            findings,
        })
    }

    /// Check a counter sequence for replay anomalies.
    /// Counters must be strictly increasing.
    pub fn check_replay_window(&mut self, counters: &[u64]) {
        for i in 1..counters.len() {
            if counters[i] <= counters[i - 1] {
                self.replay_anomaly = true;
                self.findings.push(format!(
                    "Replay anomaly: counter {i} ({}) <= counter {prev} ({})",
                    counters[i],
                    counters[i - 1],
                    prev = i - 1
                ));
            }
        }
    }
}

// ── OpenPgpAnalysis ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PgpPublicKeyAlgorithm {
    Rsa,
    Dsa,
    Elgamal,
    Ecdh,
    Ecdsa,
    EdDsa,
    Unknown(u8),
}

impl PgpPublicKeyAlgorithm {
    #[must_use]
    pub const fn from_id(id: u8) -> Self {
        match id {
            1..=3 => Self::Rsa,
            17         => Self::Dsa,
            16         => Self::Elgamal,
            18         => Self::Ecdh,
            19         => Self::Ecdsa,
            22         => Self::EdDsa,
            v          => Self::Unknown(v),
        }
    }

    #[must_use]
    pub const fn security_level(self) -> SecurityLevel {
        match self {
            Self::Dsa | Self::Elgamal  => SecurityLevel::Weak,
            Self::Rsa | Self::Unknown(_) => SecurityLevel::Acceptable,
            Self::Ecdsa | Self::Ecdh   => SecurityLevel::Strong,
            Self::EdDsa                => SecurityLevel::VeryStrong,
        }
    }
}

impl std::fmt::Display for PgpPublicKeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rsa          => write!(f, "RSA"),
            Self::Dsa          => write!(f, "DSA"),
            Self::Elgamal      => write!(f, "Elgamal"),
            Self::Ecdh         => write!(f, "ECDH"),
            Self::Ecdsa        => write!(f, "ECDSA"),
            Self::EdDsa        => write!(f, "EdDSA"),
            Self::Unknown(v)   => write!(f, "Unknown({v})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PgpSymmetricAlgorithm {
    Plaintext,
    Idea,
    TripleDes,
    Cast5,
    Blowfish,
    Aes128,
    Aes192,
    Aes256,
    Twofish,
    Camellia128,
    Camellia192,
    Camellia256,
    Unknown(u8),
}

impl PgpSymmetricAlgorithm {
    #[must_use]
    pub const fn from_id(id: u8) -> Self {
        match id {
            0  => Self::Plaintext,
            1  => Self::Idea,
            2  => Self::TripleDes,
            3  => Self::Cast5,
            4  => Self::Blowfish,
            7  => Self::Aes128,
            8  => Self::Aes192,
            9  => Self::Aes256,
            10 => Self::Twofish,
            11 => Self::Camellia128,
            12 => Self::Camellia192,
            13 => Self::Camellia256,
            v  => Self::Unknown(v),
        }
    }

    #[must_use]
    pub const fn security_level(self) -> SecurityLevel {
        match self {
            Self::Plaintext                 => SecurityLevel::Broken,
            Self::Idea | Self::Blowfish | Self::Cast5 | Self::TripleDes => SecurityLevel::Weak,
            Self::Aes128 | Self::Camellia128 => SecurityLevel::Strong,
            Self::Aes192 | Self::Aes256 | Self::Twofish |
            Self::Camellia192 | Self::Camellia256 => SecurityLevel::VeryStrong,
            Self::Unknown(_)                => SecurityLevel::Acceptable,
        }
    }
}

/// Analysis of an `OpenPGP` packet stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPgpAnalysis {
    /// Public key algorithms found in the stream.
    pub public_key_algorithms: Vec<PgpPublicKeyAlgorithm>,
    /// Symmetric algorithms found in the stream.
    pub symmetric_algorithms: Vec<PgpSymmetricAlgorithm>,
    /// Number of public-key packets parsed.
    pub public_key_packet_count: usize,
    /// Number of signature packets parsed.
    pub signature_packet_count: usize,
    /// Number of encrypted-data packets parsed.
    pub encrypted_data_count: usize,
    /// Detected key strengths (bit sizes where available).
    pub key_sizes: Vec<u32>,
    pub security_level: SecurityLevel,
    pub findings: Vec<String>,
}

/// Mutable accumulator passed through `OpenPGP` packet processing.
struct PgpParseState {
    public_key_algorithms: Vec<PgpPublicKeyAlgorithm>,
    symmetric_algorithms: Vec<PgpSymmetricAlgorithm>,
    public_key_packet_count: usize,
    signature_packet_count: usize,
    encrypted_data_count: usize,
    key_sizes: Vec<u32>,
    findings: Vec<String>,
}

impl OpenPgpAnalysis {
    /// Parse a raw `OpenPGP` binary packet stream.
    ///
    /// # Errors
    /// Returns `Err` if `data` is empty or contains malformed `OpenPGP` packets.
    pub fn parse_packet_stream(data: &[u8]) -> Result<Self, ProtocolAnalysisError> {
        if data.is_empty() {
            return Err(ProtocolAnalysisError::InsufficientData(1, 0));
        }
        let mut offset = 0usize;
        let mut state = PgpParseState {
            public_key_algorithms: Vec::new(),
            symmetric_algorithms: Vec::new(),
            public_key_packet_count: 0,
            signature_packet_count: 0,
            encrypted_data_count: 0,
            key_sizes: Vec::new(),
            findings: Vec::new(),
        };

        while offset < data.len() {
            let tag_byte = data[offset];
            if tag_byte & 0x80 == 0 {
                state.findings.push(format!("Non-packet byte {tag_byte:#04x} at offset {offset}"));
                break;
            }
            let Some((packet_tag, body_len, header_len)) =
                Self::parse_pgp_packet_header(data, offset, tag_byte) else { break };

            let body_start = match offset.checked_add(header_len) {
                Some(v) if v <= data.len() => v,
                _ => break,
            };
            let body_end = body_start.saturating_add(body_len).min(data.len());
            let body = &data[body_start..body_end];

            Self::process_pgp_packet(packet_tag, body, &mut state);

            offset = body_end;
            if body_len == 0 { break; }
        }

        let pk_level  = state.public_key_algorithms.iter().map(|a| a.security_level()).min().unwrap_or(SecurityLevel::Acceptable);
        let sym_level = state.symmetric_algorithms.iter().map(|a| a.security_level()).min().unwrap_or(SecurityLevel::Acceptable);
        let security_level = pk_level.min(sym_level);

        if state.public_key_algorithms.contains(&PgpPublicKeyAlgorithm::Dsa) {
            state.findings.push("DSA key present — considered weak, prefer EdDSA".into());
        }
        if state.symmetric_algorithms.contains(&PgpSymmetricAlgorithm::Plaintext) {
            state.findings.push("Plaintext symmetric algorithm — no encryption!".into());
        }

        Ok(Self {
            public_key_algorithms: state.public_key_algorithms,
            symmetric_algorithms: state.symmetric_algorithms,
            public_key_packet_count: state.public_key_packet_count,
            signature_packet_count: state.signature_packet_count,
            encrypted_data_count: state.encrypted_data_count,
            key_sizes: state.key_sizes,
            security_level,
            findings: state.findings,
        })
    }

    /// Parse a single `OpenPGP` packet header, returning `(tag, body_len, header_len)`.
    fn parse_pgp_packet_header(data: &[u8], offset: usize, tag_byte: u8) -> Option<(usize, usize, usize)> {
        if tag_byte & 0x40 != 0 {
            let tag = (tag_byte & 0x3F) as usize;
            if offset + 1 >= data.len() { return None; }
            let first = data[offset + 1];
            let (body_len, hl) = if first < 192 {
                (first as usize, 2)
            } else if first < 224 {
                if offset + 2 >= data.len() { return None; }
                let body = ((first as usize - 192) << 8) + (data[offset + 2] as usize) + 192;
                (body, 3)
            } else {
                if offset + 5 >= data.len() { return None; }
                let body = u32::from_be_bytes([
                    data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5],
                ]) as usize;
                (body, 6)
            };
            Some((tag, body_len, hl))
        } else {
            let tag = ((tag_byte & 0x3C) >> 2) as usize;
            let len_type = tag_byte & 0x03;
            let (body_len, hl) = match len_type {
                0 => { if offset + 1 >= data.len() { return None; } (data[offset + 1] as usize, 2) }
                1 => { if offset + 2 >= data.len() { return None; }
                       (u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize, 3) }
                2 => { if offset + 4 >= data.len() { return None; }
                       (u32::from_be_bytes([data[offset+1], data[offset+2], data[offset+3], data[offset+4]]) as usize, 5) }
                _ => return None,
            };
            Some((tag, body_len, hl))
        }
    }

    fn process_pgp_packet(packet_tag: usize, body: &[u8], state: &mut PgpParseState) {
        match packet_tag {
            6 | 14 => {
                state.public_key_packet_count += 1;
                if !body.is_empty() {
                    let pk_algo = PgpPublicKeyAlgorithm::from_id(*body.get(5).unwrap_or(&0));
                    state.public_key_algorithms.push(pk_algo);
                    if matches!(pk_algo, PgpPublicKeyAlgorithm::Rsa) && body.len() >= 8 {
                        let bit_count = u16::from_be_bytes([body[6], body[7]]);
                        state.key_sizes.push(u32::from(bit_count));
                        if bit_count < 2048 {
                            state.findings.push(format!("Weak RSA key: {bit_count} bits"));
                        }
                    }
                }
            }
            2 => {
                state.signature_packet_count += 1;
                if body.len() >= 2 {
                    let sig_algo = PgpPublicKeyAlgorithm::from_id(*body.get(3).unwrap_or(&0));
                    if !state.public_key_algorithms.contains(&sig_algo) {
                        state.public_key_algorithms.push(sig_algo);
                    }
                }
            }
            9 | 11 | 18 => {
                state.encrypted_data_count += 1;
                if !body.is_empty() && packet_tag == 9 {
                    state.symmetric_algorithms.push(PgpSymmetricAlgorithm::from_id(body[0]));
                }
            }
            1
                if body.len() >= 4 => {
                    let pk_algo = PgpPublicKeyAlgorithm::from_id(body[3]);
                    if !state.public_key_algorithms.contains(&pk_algo) {
                        state.public_key_algorithms.push(pk_algo);
                    }
                }
            _ => {}
        }
    }
}

// ── ProtocolReport ────────────────────────────────────────────────────────────

/// Aggregated report from analysing one or more protocol handshakes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolReport {
    pub protocol: ProtocolKind,
    pub overall_security: SecurityLevel,
    pub tls: Option<TlsAnalysis>,
    pub ssh: Option<SshAnalysis>,
    pub wireguard: Option<WireGuardAnalysis>,
    pub openpgp: Option<OpenPgpAnalysis>,
    /// All findings from all sub-analyses, de-duplicated.
    pub all_findings: Vec<String>,
    /// Recommended remediations.
    pub recommendations: Vec<String>,
}

impl ProtocolReport {
    /// Build a report for a TLS analysis.
    #[must_use]
    pub fn from_tls(analysis: TlsAnalysis) -> Self {
        let level = analysis.security_level;
        let mut all_findings = analysis.findings.clone();
        let recommendations = Self::recommendations_for_level(level, ProtocolKind::Tls);
        all_findings.dedup();
        Self {
            protocol: ProtocolKind::Tls,
            overall_security: level,
            tls: Some(analysis),
            ssh: None,
            wireguard: None,
            openpgp: None,
            all_findings,
            recommendations,
        }
    }

    /// Build a report for an SSH analysis.
    #[must_use]
    pub fn from_ssh(analysis: SshAnalysis) -> Self {
        let level = analysis.security_level;
        let mut all_findings = analysis.findings.clone();
        let recommendations = Self::recommendations_for_level(level, ProtocolKind::Ssh);
        all_findings.dedup();
        Self {
            protocol: ProtocolKind::Ssh,
            overall_security: level,
            tls: None,
            ssh: Some(analysis),
            wireguard: None,
            openpgp: None,
            all_findings,
            recommendations,
        }
    }

    /// Build a report for a `WireGuard` analysis.
    #[must_use]
    pub fn from_wireguard(analysis: WireGuardAnalysis) -> Self {
        let level = analysis.security_level;
        let mut all_findings = analysis.findings.clone();
        let recommendations = Self::recommendations_for_level(level, ProtocolKind::WireGuard);
        all_findings.dedup();
        Self {
            protocol: ProtocolKind::WireGuard,
            overall_security: level,
            tls: None,
            ssh: None,
            wireguard: Some(analysis),
            openpgp: None,
            all_findings,
            recommendations,
        }
    }

    /// Build a report for an `OpenPGP` analysis.
    #[must_use]
    pub fn from_openpgp(analysis: OpenPgpAnalysis) -> Self {
        let level = analysis.security_level;
        let mut all_findings = analysis.findings.clone();
        let recommendations = Self::recommendations_for_level(level, ProtocolKind::OpenPgp);
        all_findings.dedup();
        Self {
            protocol: ProtocolKind::OpenPgp,
            overall_security: level,
            tls: None,
            ssh: None,
            wireguard: None,
            openpgp: Some(analysis),
            all_findings,
            recommendations,
        }
    }

    fn recommendations_for_level(level: SecurityLevel, proto: ProtocolKind) -> Vec<String> {
        let mut recs = Vec::new();
        match level {
            SecurityLevel::Broken => {
                recs.push(format!("CRITICAL: {proto} configuration uses broken algorithms — immediate remediation required"));
            }
            SecurityLevel::Weak => {
                recs.push(format!("WARNING: {proto} configuration uses weak algorithms — upgrade recommended"));
            }
            SecurityLevel::Acceptable => {
                recs.push(format!("{proto}: consider upgrading to stronger algorithms where supported"));
            }
            SecurityLevel::Strong | SecurityLevel::VeryStrong => {
                recs.push(format!("{proto}: configuration is cryptographically sound"));
            }
        }
        match proto {
            ProtocolKind::Tls => {
                recs.push("Recommend enforcing TLS 1.3 exclusively".into());
                recs.push("Disable CBC cipher suites to prevent BEAST/LUCKY13".into());
            }
            ProtocolKind::Ssh => {
                recs.push("Recommend curve25519-sha256 for key exchange".into());
                recs.push("Disable ssh-dss host keys".into());
            }
            ProtocolKind::WireGuard => {
                recs.push("WireGuard crypto is fixed and modern — no changes needed".into());
            }
            ProtocolKind::OpenPgp => {
                recs.push("Recommend Ed25519 / Curve25519 key types".into());
                recs.push("Prefer AES-256 symmetric encryption".into());
            }
        }
        recs
    }

    /// Return `true` if the overall security level is at least `Acceptable`.
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        self.overall_security >= SecurityLevel::Acceptable
    }

    /// Summarise findings as a multiline string.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Protocol: {}", self.protocol));
        lines.push(format!("Security: {}", self.overall_security));
        for f in &self.all_findings {
            lines.push(format!("  [finding] {f}"));
        }
        for r in &self.recommendations {
            lines.push(format!("  [rec] {r}"));
        }
        lines.join("\n")
    }
}

// ── ProtocolAnalysis ──────────────────────────────────────────────────────────

/// Top-level dispatcher: auto-detect protocol from raw bytes and produce a report.
pub struct ProtocolAnalysis;

impl ProtocolAnalysis {
    /// Attempt to auto-detect the protocol from raw bytes and produce a report.
    ///
    /// # Errors
    /// Returns `Err` if `data` is empty, the protocol cannot be detected, or parsing fails.
    pub fn auto_detect(data: &[u8]) -> Result<ProtocolReport, ProtocolAnalysisError> {
        if data.is_empty() {
            return Err(ProtocolAnalysisError::InsufficientData(1, 0));
        }
        // TLS: starts with 0x16 (handshake)
        if data[0] == 0x16 {
            let tls = TlsAnalysis::parse_client_hello(data)?;
            return Ok(ProtocolReport::from_tls(tls));
        }
        // SSH: starts with "SSH-"
        if data.starts_with(b"SSH-") {
            let banner = std::str::from_utf8(data)
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("");
            let ssh = SshAnalysis::parse_banner(banner)?;
            return Ok(ProtocolReport::from_ssh(ssh));
        }
        // WireGuard: first byte is 1-4 (message type)
        if matches!(data[0], 1..=4) {
            let wg = WireGuardAnalysis::parse_packets(data)?;
            return Ok(ProtocolReport::from_wireguard(wg));
        }
        // OpenPGP: first byte has bit 7 set
        if data[0] & 0x80 != 0 {
            let pgp = OpenPgpAnalysis::parse_packet_stream(data)?;
            return Ok(ProtocolReport::from_openpgp(pgp));
        }
        Err(ProtocolAnalysisError::Parse {
            offset: 0,
            reason: "unable to detect protocol".into(),
        })
    }

    /// Analyse a TLS `ClientHello` directly.
    ///
    /// # Errors
    /// Returns `Err` if `data` is too short or contains an invalid TLS handshake.
    pub fn analyse_tls(data: &[u8]) -> Result<ProtocolReport, ProtocolAnalysisError> {
        let tls = TlsAnalysis::parse_client_hello(data)?;
        Ok(ProtocolReport::from_tls(tls))
    }

    /// Analyse an SSH banner.
    ///
    /// # Errors
    /// Returns `Err` if the banner is not a valid SSH identification string.
    pub fn analyse_ssh(banner: &str) -> Result<ProtocolReport, ProtocolAnalysisError> {
        let ssh = SshAnalysis::parse_banner(banner)?;
        Ok(ProtocolReport::from_ssh(ssh))
    }

    /// Analyse `WireGuard` packets.
    ///
    /// # Errors
    /// Returns `Err` if `data` contains malformed `WireGuard` messages.
    pub fn analyse_wireguard(data: &[u8]) -> Result<ProtocolReport, ProtocolAnalysisError> {
        let wg = WireGuardAnalysis::parse_packets(data)?;
        Ok(ProtocolReport::from_wireguard(wg))
    }

    /// Analyse an `OpenPGP` packet stream.
    ///
    /// # Errors
    /// Returns `Err` if `data` contains malformed `OpenPGP` packets.
    pub fn analyse_openpgp(data: &[u8]) -> Result<ProtocolReport, ProtocolAnalysisError> {
        let pgp = OpenPgpAnalysis::parse_packet_stream(data)?;
        Ok(ProtocolReport::from_openpgp(pgp))
    }

    /// Summarise all security levels across multiple reports.
    #[must_use]
    pub fn aggregate_security(reports: &[ProtocolReport]) -> SecurityLevel {
        reports
            .iter()
            .map(|r| r.overall_security)
            .min()
            .unwrap_or(SecurityLevel::VeryStrong)
    }

    /// Return a flat list of all unique findings from a set of reports.
    #[must_use]
    pub fn collect_findings(reports: &[ProtocolReport]) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out  = Vec::new();
        for r in reports {
            for f in &r.all_findings {
                if seen.insert(f.clone()) {
                    out.push(f.clone());
                }
            }
        }
        out
    }
}

// ── Weak-cipher and extension catalogues ─────────────────────────────────────

/// All IANA TLS cipher suites considered broken.
pub const BROKEN_CIPHER_SUITES: &[u16] = &[
    0x0000, // TLS_NULL_WITH_NULL_NULL
    0x0001, // TLS_RSA_WITH_NULL_MD5
    0x0002, // TLS_RSA_WITH_NULL_SHA
    0x0004, // TLS_RSA_WITH_RC4_128_MD5
    0x0005, // TLS_RSA_WITH_RC4_128_SHA
    0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA (no FS, deprecated)
];

/// TLS extension type numbers (selected).
#[must_use]
pub const fn tls_extension_name(ext_type: u16) -> &'static str {
    match ext_type {
        0x0000 => "server_name",
        0x0001 => "max_fragment_length",
        0x000A => "supported_groups",
        0x000B => "ec_point_formats",
        0x000D => "signature_algorithms",
        0x0010 => "application_layer_protocol_negotiation",
        0x0015 => "padding",
        0x0016 => "encrypt_then_mac",
        0x0017 => "extended_master_secret",
        0x0023 => "session_ticket",
        0x0028 | 0x0033 => "key_share",
        0x0029 => "pre_shared_key",
        0x002A => "early_data",
        0x002B => "supported_versions",
        0x002C => "cookie",
        0x002D => "psk_key_exchange_modes",
        0x002F => "certificate_authorities",
        0xFF01 => "renegotiation_info",
        _ => "unknown",
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

/// Statistics aggregated from a batch of protocol analyses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisBatchStats {
    pub total: usize,
    pub broken: usize,
    pub weak: usize,
    pub acceptable: usize,
    pub strong: usize,
    pub very_strong: usize,
    pub protocol_counts: HashMap<String, usize>,
}

impl AnalysisBatchStats {
    #[must_use]
    pub fn from_reports(reports: &[ProtocolReport]) -> Self {
        let mut stats = Self { total: reports.len(), ..Default::default() };
        for r in reports {
            *stats.protocol_counts.entry(r.protocol.to_string()).or_insert(0) += 1;
            match r.overall_security {
                SecurityLevel::Broken    => stats.broken    += 1,
                SecurityLevel::Weak      => stats.weak      += 1,
                SecurityLevel::Acceptable => stats.acceptable += 1,
                SecurityLevel::Strong    => stats.strong    += 1,
                SecurityLevel::VeryStrong => stats.very_strong += 1,
            }
        }
        stats
    }

    /// Fraction of reports that are at least Acceptable.
    #[must_use]
    pub fn compliance_ratio(&self) -> f64 {
        if self.total == 0 { return 1.0; }
        let num = u32::try_from(self.acceptable + self.strong + self.very_strong)
            .unwrap_or(u32::MAX);
        let den = u32::try_from(self.total).unwrap_or(1);
        f64::from(num) / f64::from(den)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper: minimal valid TLS ClientHello ─────────────────────────────────

    fn make_client_hello(version: u16, cs: &[u16]) -> Vec<u8> {
        let mut hello = Vec::new();
        // Record header
        hello.push(0x16); // content type: handshake
        hello.extend_from_slice(&version.to_be_bytes());
        // Length placeholder — we fill at end
        hello.push(0x00); hello.push(0x00);
        // Handshake header
        hello.push(0x01); // ClientHello
        hello.push(0x00); hello.push(0x00); hello.push(0x00); // length placeholder
        // Client version
        hello.extend_from_slice(&version.to_be_bytes());
        // Random: 32 bytes
        hello.extend_from_slice(&[0xAB; 32]);
        // Session ID length: 0
        hello.push(0x00);
        // Cipher suites length + list
        let cs_len = (cs.len() * 2) as u16;
        hello.extend_from_slice(&cs_len.to_be_bytes());
        for &c in cs { hello.extend_from_slice(&c.to_be_bytes()); }
        // Compression: 1 method (null)
        hello.push(0x01); hello.push(0x00);
        // No extensions
        hello
    }

    #[test]
    fn test_tls_analysis_tls12_aes_gcm() {
        let data = make_client_hello(0x0303, &[0xC02B, 0xC02C]);
        let analysis = TlsAnalysis::parse_client_hello(&data).unwrap();
        assert_eq!(analysis.version, TlsVersion::Tls12);
        assert_eq!(analysis.cipher_suites.len(), 2);
        assert!(analysis.cipher_suites.iter().all(|cs| cs.forward_secrecy));
    }

    #[test]
    fn test_tls_analysis_broken_rc4() {
        let data = make_client_hello(0x0301, &[0x0004]);
        let analysis = TlsAnalysis::parse_client_hello(&data).unwrap();
        assert!(analysis.security_level <= SecurityLevel::Broken);
        assert_eq!(analysis.weak_suites().len(), 1);
    }

    #[test]
    fn test_tls_analysis_tls13_suite() {
        let data = make_client_hello(0x0303, &[0x1301, 0x1302, 0x1303]);
        let analysis = TlsAnalysis::parse_client_hello(&data).unwrap();
        assert!(analysis.supports_tls13());
        assert!(analysis.cipher_suites.iter().all(|cs| cs.aead));
    }

    #[test]
    fn test_tls_version_security_levels() {
        assert_eq!(TlsVersion::from_u16(0x0300).security_level(), SecurityLevel::Broken);
        assert_eq!(TlsVersion::from_u16(0x0301).security_level(), SecurityLevel::Broken);
        assert_eq!(TlsVersion::from_u16(0x0302).security_level(), SecurityLevel::Weak);
        assert_eq!(TlsVersion::from_u16(0x0303).security_level(), SecurityLevel::Acceptable);
        assert_eq!(TlsVersion::from_u16(0x0304).security_level(), SecurityLevel::VeryStrong);
    }

    #[test]
    fn test_tls_insufficient_data() {
        let result = TlsAnalysis::parse_client_hello(&[0x16, 0x03]);
        assert!(matches!(result, Err(ProtocolAnalysisError::InsufficientData(_, _))));
    }

    #[test]
    fn test_tls_wrong_content_type() {
        let data = make_client_hello(0x0303, &[0x1301]);
        let mut bad = data;
        bad[0] = 0x17; // application_data instead of handshake
        let result = TlsAnalysis::parse_client_hello(&bad);
        assert!(matches!(result, Err(ProtocolAnalysisError::Parse { .. })));
    }

    #[test]
    fn test_cipher_suite_from_iana_tls13() {
        let cs = CipherSuiteInfo::from_iana(0x1301);
        assert_eq!(cs.name, "TLS_AES_128_GCM_SHA256");
        assert!(cs.forward_secrecy);
        assert!(cs.aead);
        assert_eq!(cs.level, SecurityLevel::Strong);
    }

    #[test]
    fn test_cipher_suite_broken_rc4() {
        let cs = CipherSuiteInfo::from_iana(0x0004);
        assert_eq!(cs.level, SecurityLevel::Broken);
        assert!(!cs.forward_secrecy);
    }

    #[test]
    fn test_cipher_suite_unknown() {
        let cs = CipherSuiteInfo::from_iana(0xFFFF);
        assert!(cs.name.contains("UNKNOWN"));
    }

    #[test]
    fn test_ssh_analysis_valid_banner() {
        let analysis = SshAnalysis::parse_banner("SSH-2.0-OpenSSH_8.9p1").unwrap();
        assert_eq!(analysis.ssh_version, 2);
        assert!(!analysis.findings.iter().any(|f| f.contains("SSHv1")));
    }

    #[test]
    fn test_ssh_analysis_v1_banner() {
        let analysis = SshAnalysis::parse_banner("SSH-1.99-OpenSSH_3.0").unwrap();
        assert_eq!(analysis.ssh_version, 1);
        assert!(analysis.security_level == SecurityLevel::Broken);
    }

    #[test]
    fn test_ssh_analysis_invalid_banner() {
        let result = SshAnalysis::parse_banner("HTTP/1.1 200 OK");
        assert!(result.is_err());
    }

    #[test]
    fn test_ssh_kex_algorithms() {
        let mut analysis = SshAnalysis::parse_banner("SSH-2.0-OpenSSH_9.0").unwrap();
        analysis.add_kex_algorithms("curve25519-sha256,diffie-hellman-group1-sha1");
        assert!(analysis.findings.iter().any(|f| f.contains("group1-sha1")));
        assert_eq!(analysis.security_level, SecurityLevel::Broken);
    }

    #[test]
    fn test_ssh_kex_algorithm_levels() {
        assert_eq!(SshKexAlgorithm::from_name("curve25519-sha256").security_level(), SecurityLevel::VeryStrong);
        assert_eq!(SshKexAlgorithm::from_name("diffie-hellman-group1-sha1").security_level(), SecurityLevel::Broken);
        assert_eq!(SshKexAlgorithm::from_name("ecdh-sha2-nistp521").security_level(), SecurityLevel::Strong);
    }

    #[test]
    fn test_wireguard_initiation_message() {
        let mut data = vec![0u8; 148];
        data[0] = 1; // Initiation
        let analysis = WireGuardAnalysis::parse_packets(&data).unwrap();
        assert!(analysis.has_valid_initiation);
        assert_eq!(analysis.initiation_count, 1);
        assert_eq!(analysis.security_level, SecurityLevel::VeryStrong);
    }

    #[test]
    fn test_wireguard_response_message() {
        let mut data = vec![0u8; 92];
        data[0] = 2; // Response
        let analysis = WireGuardAnalysis::parse_packets(&data).unwrap();
        assert_eq!(analysis.response_count, 1);
    }

    #[test]
    fn test_wireguard_replay_detection() {
        let data = vec![4u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut analysis = WireGuardAnalysis::parse_packets(&data).unwrap();
        analysis.check_replay_window(&[100, 99, 101]);
        assert!(analysis.replay_anomaly);
    }

    #[test]
    fn test_wireguard_no_replay() {
        let data = vec![4u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut analysis = WireGuardAnalysis::parse_packets(&data).unwrap();
        analysis.check_replay_window(&[1, 2, 3, 4, 5]);
        assert!(!analysis.replay_anomaly);
    }

    #[test]
    fn test_wireguard_empty() {
        let result = WireGuardAnalysis::parse_packets(&[]);
        assert!(matches!(result, Err(ProtocolAnalysisError::InsufficientData(_, _))));
    }

    #[test]
    fn test_wireguard_crypto_suite() {
        let data = vec![1u8; 148];
        let analysis = WireGuardAnalysis::parse_packets(&data).unwrap();
        assert_eq!(analysis.crypto_suite.key_exchange, "Curve25519");
        assert_eq!(analysis.crypto_suite.encryption, "ChaCha20-Poly1305");
        assert_eq!(analysis.crypto_suite.hash, "BLAKE2s");
    }

    #[test]
    fn test_pgp_public_key_algorithm_levels() {
        assert_eq!(PgpPublicKeyAlgorithm::from_id(22).security_level(), SecurityLevel::VeryStrong); // EdDSA
        assert_eq!(PgpPublicKeyAlgorithm::from_id(17).security_level(), SecurityLevel::Weak);      // DSA
        assert_eq!(PgpPublicKeyAlgorithm::from_id(1).security_level(), SecurityLevel::Acceptable); // RSA
    }

    #[test]
    fn test_pgp_symmetric_algorithm_levels() {
        assert_eq!(PgpSymmetricAlgorithm::from_id(0).security_level(), SecurityLevel::Broken);    // Plaintext
        assert_eq!(PgpSymmetricAlgorithm::from_id(9).security_level(), SecurityLevel::VeryStrong); // AES-256
        assert_eq!(PgpSymmetricAlgorithm::from_id(2).security_level(), SecurityLevel::Weak);      // 3DES
    }

    #[test]
    fn test_pgp_empty_stream() {
        let result = OpenPgpAnalysis::parse_packet_stream(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pgp_invalid_packet() {
        // First byte without bit 7 set = not a valid PGP packet tag
        let data = vec![0x00, 0x00];
        let analysis = OpenPgpAnalysis::parse_packet_stream(&data).unwrap();
        assert!(!analysis.findings.is_empty());
    }

    #[test]
    fn test_protocol_report_from_tls() {
        let data = make_client_hello(0x0304, &[0x1301]);
        let tls = TlsAnalysis::parse_client_hello(&data).unwrap();
        let report = ProtocolReport::from_tls(tls);
        assert_eq!(report.protocol, ProtocolKind::Tls);
        assert!(report.is_acceptable());
    }

    #[test]
    fn test_protocol_report_summary() {
        let data = make_client_hello(0x0303, &[0xC02B]);
        let tls = TlsAnalysis::parse_client_hello(&data).unwrap();
        let report = ProtocolReport::from_tls(tls);
        let summary = report.summary();
        assert!(summary.contains("TLS"));
    }

    #[test]
    fn test_protocol_analysis_auto_detect_tls() {
        let data = make_client_hello(0x0303, &[0x1301]);
        let report = ProtocolAnalysis::auto_detect(&data).unwrap();
        assert_eq!(report.protocol, ProtocolKind::Tls);
    }

    #[test]
    fn test_protocol_analysis_auto_detect_ssh() {
        let data = b"SSH-2.0-OpenSSH_9.0\r\n".to_vec();
        let report = ProtocolAnalysis::auto_detect(&data).unwrap();
        assert_eq!(report.protocol, ProtocolKind::Ssh);
    }

    #[test]
    fn test_protocol_analysis_auto_detect_wireguard() {
        let data = vec![1u8; 148];
        let report = ProtocolAnalysis::auto_detect(&data).unwrap();
        assert_eq!(report.protocol, ProtocolKind::WireGuard);
    }

    #[test]
    fn test_protocol_analysis_auto_detect_pgp() {
        // New-format packet with tag byte having bit 7 set
        let data = vec![0xC0u8, 0x01, 0xFF];
        let report = ProtocolAnalysis::auto_detect(&data).unwrap();
        assert_eq!(report.protocol, ProtocolKind::OpenPgp);
    }

    #[test]
    fn test_protocol_analysis_empty_fails() {
        let result = ProtocolAnalysis::auto_detect(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_security_min() {
        let tls13_data = make_client_hello(0x0304, &[0x1301]);
        let tls10_data = make_client_hello(0x0301, &[0x0004]);
        let report1 = ProtocolAnalysis::analyse_tls(&tls13_data).unwrap();
        let report2 = ProtocolAnalysis::analyse_tls(&tls10_data).unwrap();
        let agg = ProtocolAnalysis::aggregate_security(&[report1, report2]);
        assert_eq!(agg, SecurityLevel::Broken);
    }

    #[test]
    fn test_collect_findings_dedup() {
        let data = make_client_hello(0x0301, &[0x0004]);
        let r1 = ProtocolAnalysis::analyse_tls(&data).unwrap();
        let r2 = ProtocolAnalysis::analyse_tls(&data).unwrap();
        let findings = ProtocolAnalysis::collect_findings(&[r1, r2]);
        // Findings should be de-duplicated
        let unique_count = findings.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, findings.len());
    }

    #[test]
    fn test_batch_stats() {
        let tls_data = make_client_hello(0x0303, &[0x1301]);
        let wg_data  = vec![1u8; 148];
        let r1 = ProtocolAnalysis::analyse_tls(&tls_data).unwrap();
        let r2 = ProtocolAnalysis::analyse_wireguard(&wg_data).unwrap();
        let stats = AnalysisBatchStats::from_reports(&[r1, r2]);
        assert_eq!(stats.total, 2);
        assert!(stats.compliance_ratio() > 0.0);
    }

    #[test]
    fn test_batch_stats_empty() {
        let stats = AnalysisBatchStats::from_reports(&[]);
        assert_eq!(stats.compliance_ratio(), 1.0);
    }

    #[test]
    fn test_tls_extension_name() {
        assert_eq!(tls_extension_name(0x0000), "server_name");
        assert_eq!(tls_extension_name(0x002B), "supported_versions");
        assert_eq!(tls_extension_name(0x9999), "unknown");
    }

    #[test]
    fn test_broken_cipher_suite_list() {
        assert!(BROKEN_CIPHER_SUITES.contains(&0x0000));
        assert!(BROKEN_CIPHER_SUITES.contains(&0x0004));
    }

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Broken < SecurityLevel::Weak);
        assert!(SecurityLevel::Weak   < SecurityLevel::Acceptable);
        assert!(SecurityLevel::Acceptable < SecurityLevel::Strong);
        assert!(SecurityLevel::Strong < SecurityLevel::VeryStrong);
    }

    #[test]
    fn test_protocol_kind_display() {
        assert_eq!(ProtocolKind::Tls.to_string(), "TLS");
        assert_eq!(ProtocolKind::Ssh.to_string(), "SSH");
        assert_eq!(ProtocolKind::WireGuard.to_string(), "WireGuard");
        assert_eq!(ProtocolKind::OpenPgp.to_string(), "OpenPGP");
    }

    #[test]
    fn test_wg_message_type_display() {
        assert_eq!(WgMessageType::Initiation.to_string(), "Initiation");
        assert_eq!(WgMessageType::Unknown(99).to_string(), "Unknown(99)");
    }

    #[test]
    fn test_pgp_algorithm_display() {
        assert_eq!(PgpPublicKeyAlgorithm::Rsa.to_string(), "RSA");
        assert_eq!(PgpPublicKeyAlgorithm::EdDsa.to_string(), "EdDSA");
        assert_eq!(PgpPublicKeyAlgorithm::Unknown(99).to_string(), "Unknown(99)");
    }
}
