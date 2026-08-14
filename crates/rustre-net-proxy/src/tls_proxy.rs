//! TLS proxy — intercept and analyze TLS handshakes in MITM scenarios.
//!
//! Provides:
//! - [`TlsHandshakeParser`] — pars`ClientHello`lo `ServerHello`lo from raw bytes
//! - [`TlsProxy`] — manage TLS intercept sessions
//! - [`TlsInterceptSession`] — per-connection state machine
//! - Certificate generation stubs (via `rcgen`)
//! - SNI extraction
//! - Cipher suite and extension logging

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
pub use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::ProxyError;

// ────────────────────────────────────────────────────────────────────────────
// TLS constants
// ────────────────────────────────────────────────────────────────────────────

/// TLS record content types (RFC 5246 §6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
    Unknown(u8),
}

impl From<u8> for TlsContentType {
    fn from(b: u8) -> Self {
        match b {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            24 => Self::Heartbeat,
            x => Self::Unknown(x),
        }
    }
}

/// TLS handshake message types (RFC 5246 §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    Unknown(u8),
}

impl From<u8> for HandshakeType {
    fn from(b: u8) -> Self {
        match b {
            0 => Self::HelloRequest,
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            11 => Self::Certificate,
            12 => Self::ServerKeyExchange,
            13 => Self::CertificateRequest,
            14 => Self::ServerHelloDone,
            15 => Self::CertificateVerify,
            16 => Self::ClientKeyExchange,
            20 => Self::Finished,
            x => Self::Unknown(x),
        }
    }
}

impl fmt::Display for HandshakeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelloRequest => write!(f, "HelloRequest"),
            Self::ClientHello => write!(f, "ClientHello"),
            Self::ServerHello => write!(f, "ServerHello"),
            Self::Certificate => write!(f, "Certificate"),
            Self::ServerKeyExchange => write!(f, "ServerKeyExchange"),
            Self::CertificateRequest => write!(f, "CertificateRequest"),
            Self::ServerHelloDone => write!(f, "ServerHelloDone"),
            Self::CertificateVerify => write!(f, "CertificateVerify"),
            Self::ClientKeyExchange => write!(f, "ClientKeyExchange"),
            Self::Finished => write!(f, "Finished"),
            Self::Unknown(x) => write!(f, "Unknown({x})"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TLS record header
// ────────────────────────────────────────────────────────────────────────────

/// TLS record layer header (5 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRecord {
    pub content_type: TlsContentType,
    /// Legacy version field (0x0303 = TLS 1.2, 0x0301 = TLS 1.0 compat).
    pub version: u16,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl TlsRecord {
    /// Parse the first TLS record from `data`.
    ///
    /// # Errors
    /// Returns [`ProxyError::InvalidRequest`] if the buffer is too short or
    /// the claimed length exceeds available data.
    pub fn parse(data: &[u8]) -> Result<Self, ProxyError> {
        if data.len() < 5 {
            return Err(ProxyError::InvalidRequest(format!(
                "TLS record too short: {} bytes",
                data.len()
            )));
        }
        let content_type = TlsContentType::from(data[0]);
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]);
        let end = 5 + length as usize;
        if data.len() < end {
            return Err(ProxyError::InvalidRequest(format!(
                "TLS record payload truncated: need {end}, have {}",
                data.len()
            )));
        }
        Ok(Self {
            content_type,
            version,
            length,
            payload: data[5..end].to_vec(),
        })
    }

    /// Total wire size including the 5-byte header.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        5 + self.payload.len()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Cipher suite names
// ────────────────────────────────────────────────────────────────────────────

/// Return a human-readable name for a 2-byte cipher suite code.
#[must_use]
pub const fn cipher_suite_name(code: u16) -> &'static str {
    match code {
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0x00FF => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        _ => "UNKNOWN",
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TLS extension
// ────────────────────────────────────────────────────────────────────────────

/// A parsed TLS extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl TlsExtension {
    /// Extension type 0 = `server_name` (SNI).
    #[must_use]
    pub const fn is_sni(&self) -> bool {
        self.ext_type == 0
    }

    /// Supported version list extension (43 = 0x002B).
    #[must_use]
    pub const fn is_supported_versions(&self) -> bool {
        self.ext_type == 43
    }

    /// Extract the SNI hostname from an SNI extension.
    #[must_use]
    pub fn sni_hostname(&self) -> Option<String> {
        if !self.is_sni() || self.data.len() < 5 {
            return None;
        }
        // server_name_list length (2) + name_type (1) + name_length (2) + name
        let name_len = u16::from_be_bytes([self.data[3], self.data[4]]) as usize;
        let start = 5usize;
        // Use checked_add to guard against overflow before the bounds check.
        let end = start.checked_add(name_len)?;
        if self.data.len() >= end {
            std::str::from_utf8(&self.data[start..end])
                .ok()
                .map(str::to_string)
        } else {
            None
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// ClientHello
// ────────────────────────────────────────────────────────────────────────────

/// A parsed TLS 1.x `ClientHello` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    /// Advertised client version (may differ from negotiated).
    pub legacy_version: u16,
    /// 32-byte random nonce.
    pub random: [u8; 32],
    /// Session ID bytes (0–32 bytes).
    pub session_id: Vec<u8>,
    /// Supported cipher suites in preference order.
    pub cipher_suites: Vec<u16>,
    /// Supported compression methods.
    pub compression_methods: Vec<u8>,
    /// Extensions.
    pub extensions: Vec<TlsExtension>,
}

impl ClientHello {
    /// Extract the SNI hostname from extensions, if present.
    #[must_use]
    pub fn sni(&self) -> Option<String> {
        self.extensions
            .iter()
            .find(|e| e.is_sni())
            .and_then(TlsExtension::sni_hostname)
    }

    /// List all cipher suite names.
    #[must_use]
    pub fn cipher_suite_names(&self) -> Vec<&'static str> {
        self.cipher_suites
            .iter()
            .map(|&c| cipher_suite_name(c))
            .collect()
    }

    /// Returns `true` if the client advertises TLS 1.3 support via the
    /// `supported_versions` extension.
    #[must_use]
    pub fn supports_tls13(&self) -> bool {
        self.extensions.iter().any(|e| {
            if !e.is_supported_versions() {
                return false;
            }
            // versions list: 1 byte length (in bytes), then 2-byte versions
            if e.data.is_empty() {
                return false;
            }
            let count = e.data[0] as usize; // byte count of the list
            // Clamp to available data to avoid out-of-bounds reads.
            let list_end = 1usize.saturating_add(count).min(e.data.len());
            let mut i = 1;
            while i + 1 < list_end {
                let v = u16::from_be_bytes([e.data[i], e.data[i + 1]]);
                if v == 0x0304 {
                    return true;
                } // TLS 1.3
                i += 2;
            }
            false
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TLS handshake parser
// ────────────────────────────────────────────────────────────────────────────

/// Low-level parser for TLS handshake messages.
pub struct TlsHandshakeParser;

impl TlsHandshakeParser {
    /// Parse a `ClientHello` from a raw TLS record payload (the handshake body
    /// after the 5-byte TLS record header).
    ///
    /// Expects the data to start at the Handshake layer (type byte first).
    ///
    /// # Errors
    /// Returns [`ProxyError::InvalidRequest`] on any parse failure.
    pub fn parse_client_hello(data: &[u8]) -> Result<ClientHello, ProxyError> {
        let err = |msg: &str| ProxyError::InvalidRequest(msg.to_string());

        if data.len() < 4 {
            return Err(err("ClientHello too short for handshake header"));
        }
        if data[0] != 1 {
            return Err(err(&format!("expected ClientHello (1), got {}", data[0])));
        }

        // Handshake header: type(1) + length(3)
        let _msg_len = (u32::from(data[1]) << 16) | (u32::from(data[2]) << 8) | u32::from(data[3]);

        let mut pos = 4;

        // Legacy version
        if pos + 2 > data.len() {
            return Err(err("truncated: legacy_version"));
        }
        let legacy_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // Random (32 bytes)
        if pos + 32 > data.len() {
            return Err(err("truncated: random"));
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // Session ID
        if pos >= data.len() {
            return Err(err("truncated: session_id length"));
        }
        let sid_len = data[pos] as usize;
        pos += 1;
        if pos + sid_len > data.len() {
            return Err(err("truncated: session_id"));
        }
        let session_id = data[pos..pos + sid_len].to_vec();
        pos += sid_len;

        // Cipher suites
        if pos + 2 > data.len() {
            return Err(err("truncated: cipher_suites length"));
        }
        let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + cs_len > data.len() {
            return Err(err("truncated: cipher_suites"));
        }
        let mut cipher_suites = Vec::with_capacity(cs_len / 2);
        let mut i = 0;
        while i + 1 < cs_len {
            cipher_suites.push(u16::from_be_bytes([data[pos + i], data[pos + i + 1]]));
            i += 2;
        }
        pos += cs_len;

        // Compression methods
        if pos >= data.len() {
            return Err(err("truncated: compression_methods length"));
        }
        let cm_len = data[pos] as usize;
        pos += 1;
        if pos + cm_len > data.len() {
            return Err(err("truncated: compression_methods"));
        }
        let compression_methods = data[pos..pos + cm_len].to_vec();
        pos += cm_len;

        // Extensions
        let mut extensions = Vec::new();
        if pos + 2 <= data.len() {
            let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            let ext_end = pos + ext_total;
            while pos + 4 <= ext_end.min(data.len()) {
                let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
                pos += 4;
                if pos + ext_len > data.len() {
                    break;
                }
                let ext_data = data[pos..pos + ext_len].to_vec();
                extensions.push(TlsExtension {
                    ext_type,
                    data: ext_data,
                });
                pos += ext_len;
            }
        }

        Ok(ClientHello {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Extract just the SNI hostname from raw `ClientHello` bytes, without
    /// allocating a full [`ClientHello`].
    #[must_use]
    pub fn extract_sni(data: &[u8]) -> Option<String> {
        Self::parse_client_hello(data).ok()?.sni()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Certificate generation stub
// ────────────────────────────────────────────────────────────────────────────

/// A generated self-signed certificate + private key in PEM format.
#[derive(Debug, Clone)]
pub struct GeneratedCert {
    /// PEM-encoded certificate.
    pub cert_pem: String,
    /// PEM-encoded RSA private key.
    pub key_pem: String,
    /// Common name used.
    pub common_name: String,
}

/// Generate a self-signed certificate for the given hostname.
///
/// Uses `rcgen` under the hood to produce an RSA-style key pair and a
/// DER-encoded certificate wrapped in PEM.
///
/// # Errors
/// Returns [`ProxyError::ConfigError`] if key/cert generation fails.
pub fn generate_cert_for_host(hostname: &str) -> Result<GeneratedCert, ProxyError> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    let mut params = CertificateParams::new(vec![hostname.to_string()])
        .map_err(|e| ProxyError::ConfigError(format!("cert params: {e}")))?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    dn.push(DnType::OrganizationName, "RustRE MITM Proxy");
    params.distinguished_name = dn;
    params.subject_alt_names =
        vec![SanType::DnsName(hostname.to_string().try_into().map_err(
            |e| ProxyError::ConfigError(format!("invalid hostname: {e}")),
        )?)];

    let key_pair =
        KeyPair::generate().map_err(|e| ProxyError::ConfigError(format!("key generation: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ProxyError::ConfigError(format!("cert self-sign: {e}")))?;

    Ok(GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        common_name: hostname.to_string(),
    })
}

// ────────────────────────────────────────────────────────────────────────────
// TLS intercept session
// ────────────────────────────────────────────────────────────────────────────

/// State of a TLS intercept session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsSessionState {
    /// Waiting for the first `ClientHello` bytes.
    AwaitingClientHello,
    /// `ClientHello` received and parsed.
    ClientHelloParsed,
    /// Server cert generated, waiting for upstream.
    CertGenerated,
    /// Handshake complete on both sides.
    Established,
    /// Session terminated.
    Closed,
    /// Error state.
    Failed,
}

/// Per-connection TLS intercept session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInterceptSession {
    pub id: u64,
    pub client_addr: SocketAddr,
    pub state: TlsSessionState,
    /// Hostname extracted from SNI.
    pub sni: Option<String>,
    /// Client-offered cipher suites.
    pub offered_ciphers: Vec<u16>,
    /// Negotiated cipher suite (if known).
    pub negotiated_cipher: Option<u16>,
    /// Whether the client supports TLS 1.3.
    pub client_tls13: bool,
    /// Raw `ClientHello` bytes for logging.
    pub client_hello_raw: Vec<u8>,
    /// Total bytes forwarded client→server.
    pub bytes_to_server: u64,
    /// Total bytes forwarded server→client.
    pub bytes_to_client: u64,
}

impl TlsInterceptSession {
    /// Create a new session in the awaiting state.
    #[must_use] 
    pub const fn new(id: u64, client_addr: SocketAddr) -> Self {
        Self {
            id,
            client_addr,
            state: TlsSessionState::AwaitingClientHello,
            sni: None,
            offered_ciphers: Vec::new(),
            negotiated_cipher: None,
            client_tls13: false,
            client_hello_raw: Vec::new(),
            bytes_to_server: 0,
            bytes_to_client: 0,
        }
    }

    /// Feed raw data from the client to try to parse a `ClientHello`.
    ///
    /// Transitions the session to [`TlsSessionState::ClientHelloParsed`] on
    /// success.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn feed_client_data(&mut self, data: &[u8]) -> Result<(), ProxyError> {
        if self.state != TlsSessionState::AwaitingClientHello {
            self.bytes_to_server += data.len() as u64;
            return Ok(());
        }

        // Try to parse TLS record
        let record = TlsRecord::parse(data)?;
        if record.content_type != TlsContentType::Handshake {
            return Err(ProxyError::InvalidRequest(
                "expected TLS Handshake record".to_string(),
            ));
        }

        self.client_hello_raw = data[..record.wire_len()].to_vec();
        let hello = TlsHandshakeParser::parse_client_hello(&record.payload)?;

        self.sni = hello.sni();
        self.offered_ciphers.clone_from(&hello.cipher_suites);
        self.client_tls13 = hello.supports_tls13();
        self.state = TlsSessionState::ClientHelloParsed;
        self.bytes_to_server += data.len() as u64;
        Ok(())
    }

    /// Mark cert as generated and transition state.
    pub fn mark_cert_generated(&mut self) {
        if self.state == TlsSessionState::ClientHelloParsed {
            self.state = TlsSessionState::CertGenerated;
        }
    }

    /// Mark handshake as complete.
    pub const fn mark_established(&mut self, negotiated_cipher: Option<u16>) {
        self.negotiated_cipher = negotiated_cipher;
        self.state = TlsSessionState::Established;
    }

    /// Record bytes flowing to the client.
    pub const fn record_bytes_to_client(&mut self, n: u64) {
        self.bytes_to_client += n;
    }

    /// Close the session.
    pub const fn close(&mut self) {
        self.state = TlsSessionState::Closed;
    }

    /// Mark session as failed.
    pub const fn fail(&mut self) {
        self.state = TlsSessionState::Failed;
    }

    /// Negotiated cipher name.
    #[must_use]
    pub fn negotiated_cipher_name(&self) -> &'static str {
        self.negotiated_cipher
            .map_or("(none)", cipher_suite_name)
    }

    /// Summary for logging.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "TlsSession[{}] client={} sni={} state={:?} ciphers={} tls13={}",
            self.id,
            self.client_addr,
            self.sni.as_deref().unwrap_or("(none)"),
            self.state,
            self.offered_ciphers.len(),
            self.client_tls13,
        )
    }
}

// ────────────────────────────────────────────────────────────────────────────
// TLS proxy
// ────────────────────────────────────────────────────────────────────────────

/// Certificate cache entry.
#[derive(Debug, Clone)]
struct CertEntry {
    cert_pem: String,
    key_pem: String,
}

/// Manages a pool of TLS intercept sessions and a certificate cache.
pub struct TlsProxy {
    sessions: RwLock<HashMap<u64, TlsInterceptSession>>,
    cert_cache: RwLock<HashMap<String, CertEntry>>,
    next_id: std::sync::atomic::AtomicU64,
    /// Whether to generate MITM certs on demand.
    pub mitm_certs: bool,
}

impl TlsProxy {
    /// Create a new TLS proxy.
    #[must_use]
    pub fn new(mitm_certs: bool) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            cert_cache: RwLock::new(HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
            mitm_certs,
        }
    }

    /// Allocate a new session for the given client.
    pub fn new_session(&self, client_addr: SocketAddr) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let session = TlsInterceptSession::new(id, client_addr);
        self.sessions.write().insert(id, session);
        id
    }

    /// Feed raw client data into the session identified by `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn feed(&self, id: u64, data: &[u8]) -> Result<(), ProxyError> {
        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(&id)
            .ok_or_else(|| ProxyError::InvalidRequest(format!("no TLS session {id}")))?;
        session.feed_client_data(data)
    }

    /// Get a snapshot of a session.
    #[must_use]
    pub fn session(&self, id: u64) -> Option<TlsInterceptSession> {
        self.sessions.read().get(&id).cloned()
    }

    /// Get or generate a certificate for the given hostname.
    ///
    /// # Errors
    /// Returns [`ProxyError::ConfigError`] if cert generation fails.
    pub fn get_or_generate_cert(&self, hostname: &str) -> Result<(String, String), ProxyError> {
        if let Some(entry) = self.cert_cache.read().get(hostname) {
            return Ok((entry.cert_pem.clone(), entry.key_pem.clone()));
        }
        if !self.mitm_certs {
            return Err(ProxyError::ConfigError(
                "MITM cert generation disabled".to_string(),
            ));
        }
        let cert = generate_cert_for_host(hostname)?;
        let entry = CertEntry {
            cert_pem: cert.cert_pem.clone(),
            key_pem: cert.key_pem.clone(),
        };
        self.cert_cache.write().insert(hostname.to_string(), entry);
        Ok((cert.cert_pem, cert.key_pem))
    }

    /// Close a session.
    pub fn close_session(&self, id: u64) {
        if let Some(s) = self.sessions.write().get_mut(&id) {
            s.close();
        }
    }

    /// Remove a closed/failed session.
    pub fn remove_session(&self, id: u64) {
        self.sessions.write().remove(&id);
    }

    /// Number of active sessions.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Number of cached certificates.
    #[must_use]
    pub fn cert_cache_size(&self) -> usize {
        self.cert_cache.read().len()
    }

    /// All session summaries for logging.
    #[must_use]
    pub fn all_summaries(&self) -> Vec<String> {
        self.sessions.read().values().map(TlsInterceptSession::summary).collect()
    }
}

impl Default for TlsProxy {
    fn default() -> Self {
        Self::new(false)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SNI extraction helpers
// ────────────────────────────────────────────────────────────────────────────

/// Attempt to extract an SNI hostname from a raw TCP payload.
///
/// Returns `None` if the data is not a valid TLS `ClientHello` or has no SNI.
#[must_use]
pub fn extract_sni_from_tcp_payload(data: &[u8]) -> Option<String> {
    let record = TlsRecord::parse(data).ok()?;
    if record.content_type != TlsContentType::Handshake {
        return None;
    }
    TlsHandshakeParser::extract_sni(&record.payload)
}

// ────────────────────────────────────────────────────────────────────────────
// Cipher suite analysis
// ────────────────────────────────────────────────────────────────────────────

/// Weakness categories for cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherStrength {
    Strong,
    Weak,
    Broken,
    Unknown,
}

/// Classify a cipher suite by its security strength.
#[must_use]
pub const fn classify_cipher(code: u16) -> CipherStrength {
    match code {
        // TLS 1.3 suites — strong
        // ECDHE+GCM — strong
        0x1301..=0x1303 | 0xC02B | 0xC02C | 0xC02F | 0xC030 => CipherStrength::Strong,
        // RSA+CBC — weak (no forward secrecy)
        0x002F | 0x0035 | 0x003C | 0x003D | 0x009C | 0x009D | 0xC013 | 0xC014 => CipherStrength::Weak,
        // RSA+GCM — weak (no forward secrecy)
        // ECDHE+CBC — borderline
        // NULL/EXPORT/RC4 ranges — broken
        0x0000..=0x001F => CipherStrength::Broken,
        _ => CipherStrength::Unknown,
    }
}

/// Summarise the cipher suite list from a `ClientHello`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherAnalysis {
    pub total: usize,
    pub strong: usize,
    pub weak: usize,
    pub broken: usize,
    pub unknown: usize,
    pub supports_forward_secrecy: bool,
}

impl CipherAnalysis {
    /// Analyse a slice of cipher suite codes.
    #[must_use]
    pub fn analyse(suites: &[u16]) -> Self {
        let mut strong = 0usize;
        let mut weak = 0usize;
        let mut broken = 0usize;
        let mut unknown = 0usize;
        for &c in suites {
            match classify_cipher(c) {
                CipherStrength::Strong => strong += 1,
                CipherStrength::Weak => weak += 1,
                CipherStrength::Broken => broken += 1,
                CipherStrength::Unknown => unknown += 1,
            }
        }
        // Forward secrecy if any ECDHE or DHE suite present
        let supports_forward_secrecy = suites.iter().any(|&c| {
            matches!(
                c,
                0xC02B | 0xC02C | 0xC02F | 0xC030 | 0xC013 | 0xC014 | 0x1301 | 0x1302 | 0x1303
            )
        });
        Self {
            total: suites.len(),
            strong,
            weak,
            broken,
            unknown,
            supports_forward_secrecy,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn dummy_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    // ── TlsContentType ────────────────────────────────────────────────────────

    #[test]
    fn test_content_type_from_u8() {
        assert_eq!(TlsContentType::from(22), TlsContentType::Handshake);
        assert_eq!(TlsContentType::from(23), TlsContentType::ApplicationData);
        assert_eq!(TlsContentType::from(21), TlsContentType::Alert);
        assert!(matches!(
            TlsContentType::from(99),
            TlsContentType::Unknown(99)
        ));
    }

    // ── HandshakeType ─────────────────────────────────────────────────────────

    #[test]
    fn test_handshake_type_from_u8() {
        assert_eq!(HandshakeType::from(1), HandshakeType::ClientHello);
        assert_eq!(HandshakeType::from(2), HandshakeType::ServerHello);
        assert_eq!(HandshakeType::from(20), HandshakeType::Finished);
        assert!(matches!(
            HandshakeType::from(42),
            HandshakeType::Unknown(42)
        ));
    }

    #[test]
    fn test_handshake_type_display() {
        assert_eq!(HandshakeType::ClientHello.to_string(), "ClientHello");
        assert_eq!(HandshakeType::Unknown(7).to_string(), "Unknown(7)");
    }

    // ── TlsRecord ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_record_parse_valid() {
        // content_type=22, version=0x0303, length=4, payload=[1,2,3,4]
        let data = &[22u8, 3, 3, 0, 4, 1, 2, 3, 4];
        let rec = TlsRecord::parse(data).unwrap();
        assert_eq!(rec.content_type, TlsContentType::Handshake);
        assert_eq!(rec.version, 0x0303);
        assert_eq!(rec.length, 4);
        assert_eq!(rec.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_tls_record_too_short() {
        let data = &[22u8, 3, 3];
        assert!(TlsRecord::parse(data).is_err());
    }

    #[test]
    fn test_tls_record_payload_truncated() {
        // Claims 10 bytes but only 3 provided
        let data = &[22u8, 3, 3, 0, 10, 1, 2, 3];
        assert!(TlsRecord::parse(data).is_err());
    }

    #[test]
    fn test_tls_record_wire_len() {
        let data = &[23u8, 3, 3, 0, 2, 0xFF, 0xFE];
        let rec = TlsRecord::parse(data).unwrap();
        assert_eq!(rec.wire_len(), 7);
    }

    // ── cipher_suite_name ─────────────────────────────────────────────────────

    #[test]
    fn test_cipher_suite_name_known() {
        assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(
            cipher_suite_name(0xC02F),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn test_cipher_suite_name_unknown() {
        assert_eq!(cipher_suite_name(0xDEAD), "UNKNOWN");
    }

    // ── TlsExtension ─────────────────────────────────────────────────────────

    #[test]
    fn test_extension_sni_detection() {
        let ext = TlsExtension {
            ext_type: 0,
            data: vec![],
        };
        assert!(ext.is_sni());
        let ext2 = TlsExtension {
            ext_type: 43,
            data: vec![],
        };
        assert!(!ext2.is_sni());
    }

    #[test]
    fn test_extension_sni_hostname_parse() {
        // SNI extension data for "example.com":
        // list_len(2) + name_type(1) + name_len(2) + name
        let hostname = b"example.com";
        let name_len = u16::try_from(hostname.len()).unwrap_or(u16::MAX);
        let list_len: u16 = 3 + name_len; // type + len_bytes + name
        let mut data = Vec::new();
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0); // name_type = host_name
        data.extend_from_slice(&name_len.to_be_bytes());
        data.extend_from_slice(hostname);
        let ext = TlsExtension { ext_type: 0, data };
        assert_eq!(ext.sni_hostname(), Some("example.com".to_string()));
    }

    // ── ClientHello parsing ───────────────────────────────────────────────────

    fn build_minimal_client_hello() -> Vec<u8> {
        let mut ch = Vec::new();
        ch.push(1u8); // ClientHello
        // Placeholder length (3 bytes) — we'll fill after
        let body_start = ch.len() + 3;
        ch.extend_from_slice(&[0u8; 3]);
        let before_body = ch.len();

        ch.extend_from_slice(&[3u8, 3]); // version TLS 1.2
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0u8); // session_id length = 0
        ch.extend_from_slice(&[0u8, 4]); // cipher_suites length = 4
        ch.extend_from_slice(&[0x13, 0x01, 0xC0, 0x2F]); // 2 suites
        ch.push(1u8); // compression_methods length = 1
        ch.push(0u8); // null compression
        // No extensions
        ch.extend_from_slice(&[0u8, 0]); // extensions length = 0

        let body_len = ch.len() - before_body;
        ch[1] = u8::try_from((body_len >> 16) & 0xFF).unwrap_or(u8::MAX);
        ch[2] = u8::try_from((body_len >> 8) & 0xFF).unwrap_or(u8::MAX);
        ch[3] = u8::try_from(body_len & 0xFF).unwrap_or(u8::MAX);
        let _ = body_start; // suppress warning
        ch
    }

    #[test]
    fn test_parse_client_hello_minimal() {
        let data = build_minimal_client_hello();
        let ch = TlsHandshakeParser::parse_client_hello(&data).unwrap();
        assert_eq!(ch.legacy_version, 0x0303);
        assert_eq!(ch.cipher_suites.len(), 2);
        assert!(ch.cipher_suites.contains(&0x1301));
    }

    #[test]
    fn test_parse_client_hello_wrong_type() {
        let mut data = build_minimal_client_hello();
        data[0] = 2; // ServerHello instead
        assert!(TlsHandshakeParser::parse_client_hello(&data).is_err());
    }

    #[test]
    fn test_parse_client_hello_too_short() {
        assert!(TlsHandshakeParser::parse_client_hello(&[1u8, 0, 0]).is_err());
    }

    #[test]
    fn test_client_hello_cipher_names() {
        let data = build_minimal_client_hello();
        let ch = TlsHandshakeParser::parse_client_hello(&data).unwrap();
        let names = ch.cipher_suite_names();
        assert!(names.contains(&"TLS_AES_128_GCM_SHA256"));
    }

    // ── TlsInterceptSession ───────────────────────────────────────────────────

    #[test]
    fn test_session_initial_state() {
        let s = TlsInterceptSession::new(1, dummy_addr());
        assert_eq!(s.state, TlsSessionState::AwaitingClientHello);
        assert!(s.sni.is_none());
    }

    #[test]
    fn test_session_mark_established() {
        let mut s = TlsInterceptSession::new(2, dummy_addr());
        s.state = TlsSessionState::CertGenerated;
        s.mark_established(Some(0xC02F));
        assert_eq!(s.state, TlsSessionState::Established);
        assert_eq!(
            s.negotiated_cipher_name(),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
    }

    #[test]
    fn test_session_close() {
        let mut s = TlsInterceptSession::new(3, dummy_addr());
        s.close();
        assert_eq!(s.state, TlsSessionState::Closed);
    }

    #[test]
    fn test_session_fail() {
        let mut s = TlsInterceptSession::new(4, dummy_addr());
        s.fail();
        assert_eq!(s.state, TlsSessionState::Failed);
    }

    #[test]
    fn test_session_bytes_accounting() {
        let mut s = TlsInterceptSession::new(5, dummy_addr());
        s.state = TlsSessionState::Established;
        s.record_bytes_to_client(1024);
        assert_eq!(s.bytes_to_client, 1024);
    }

    #[test]
    fn test_session_summary() {
        let s = TlsInterceptSession::new(6, dummy_addr());
        let summary = s.summary();
        assert!(summary.contains("TlsSession[6]"));
    }

    // ── TlsProxy ──────────────────────────────────────────────────────────────

    #[test]
    fn test_proxy_new_session() {
        let proxy = TlsProxy::new(false);
        let id = proxy.new_session(dummy_addr());
        assert!(id > 0);
        assert_eq!(proxy.session_count(), 1);
    }

    #[test]
    fn test_proxy_session_snapshot() {
        let proxy = TlsProxy::new(false);
        let id = proxy.new_session(dummy_addr());
        let snap = proxy.session(id).unwrap();
        assert_eq!(snap.id, id);
    }

    #[test]
    fn test_proxy_close_and_remove() {
        let proxy = TlsProxy::new(false);
        let id = proxy.new_session(dummy_addr());
        proxy.close_session(id);
        assert_eq!(proxy.session(id).unwrap().state, TlsSessionState::Closed);
        proxy.remove_session(id);
        assert_eq!(proxy.session_count(), 0);
    }

    #[test]
    fn test_proxy_feed_invalid_record() {
        let proxy = TlsProxy::new(false);
        let id = proxy.new_session(dummy_addr());
        assert!(proxy.feed(id, &[23u8, 3, 3, 0, 1, 0xFF]).is_err());
    }

    #[test]
    fn test_proxy_all_summaries() {
        let proxy = TlsProxy::new(false);
        proxy.new_session(dummy_addr());
        proxy.new_session(dummy_addr());
        assert_eq!(proxy.all_summaries().len(), 2);
    }

    // ── CipherAnalysis ────────────────────────────────────────────────────────

    #[test]
    fn test_cipher_analysis_strong() {
        let suites = vec![0x1301u16, 0x1302, 0xC02F];
        let analysis = CipherAnalysis::analyse(&suites);
        assert_eq!(analysis.strong, 3);
        assert_eq!(analysis.weak, 0);
        assert!(analysis.supports_forward_secrecy);
    }

    #[test]
    fn test_cipher_analysis_weak() {
        let suites = vec![0x002Fu16, 0x0035];
        let analysis = CipherAnalysis::analyse(&suites);
        assert_eq!(analysis.weak, 2);
        assert!(!analysis.supports_forward_secrecy);
    }

    #[test]
    fn test_cipher_analysis_broken() {
        let suites = vec![0x0001u16, 0x0005]; // NULL/export range
        let analysis = CipherAnalysis::analyse(&suites);
        assert_eq!(analysis.broken, 2);
    }

    #[test]
    fn test_classify_cipher() {
        assert_eq!(classify_cipher(0x1301), CipherStrength::Strong);
        assert_eq!(classify_cipher(0x002F), CipherStrength::Weak);
        assert_eq!(classify_cipher(0x0001), CipherStrength::Broken);
        assert_eq!(classify_cipher(0xDEAD), CipherStrength::Unknown);
    }

    // ── extract_sni_from_tcp_payload ──────────────────────────────────────────

    #[test]
    fn test_extract_sni_non_tls_data() {
        let data = b"GET / HTTP/1.1\r\n";
        assert!(extract_sni_from_tcp_payload(data).is_none());
    }

    #[test]
    fn test_extract_sni_application_data_record() {
        // Application data record, not a ClientHello
        let data = &[23u8, 3, 3, 0, 1, 0xAB];
        assert!(extract_sni_from_tcp_payload(data).is_none());
    }
}
