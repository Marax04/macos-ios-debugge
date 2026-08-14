//! `tls_dissector` — Full TLS 1.2/1.3 dissector.
//!
//! Provides [`TlsDissector`] which parses raw TLS records and reconstructs
//! handshake messages, cipher suites, certificates, and key-exchange parameters.
//! [`TlsSession`] tracks the state machine for a full handshake.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TlsError {
    #[error("buffer too short: need {need}, got {got}")]
    TooShort { need: usize, got: usize },
    #[error("invalid content type: {0}")]
    InvalidContentType(u8),
    #[error("invalid handshake type: {0}")]
    InvalidHandshakeType(u8),
    #[error("unsupported TLS version: {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },
    #[error("malformed field: {0}")]
    MalformedField(String),
    #[error("unexpected message in state {state}: got {got}")]
    UnexpectedMessage { state: String, got: String },
    #[error("certificate parse error: {0}")]
    CertificateError(String),
    #[error("session not found")]
    SessionNotFound,
}

const fn need(buf: &[u8], n: usize) -> Result<(), TlsError> {
    if buf.len() < n {
        Err(TlsError::TooShort {
            need: n,
            got: buf.len(),
        })
    } else {
        Ok(())
    }
}

// ─── TlsVersion ───────────────────────────────────────────────────────────────

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
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn to_u16(self) -> u16 {
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
    pub fn is_tls13(self) -> bool {
        self == Self::Tls13
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssl30 => write!(f, "SSLv3.0"),
            Self::Tls10 => write!(f, "TLSv1.0"),
            Self::Tls11 => write!(f, "TLSv1.1"),
            Self::Tls12 => write!(f, "TLSv1.2"),
            Self::Tls13 => write!(f, "TLSv1.3"),
            Self::Unknown(v) => write!(f, "Unknown(0x{v:04x})"),
        }
    }
}

// ─── ContentType ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Heartbeat,
    Unknown(u8),
}

impl ContentType {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            24 => Self::Heartbeat,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
            Self::Heartbeat => 24,
            Self::Unknown(v) => v,
        }
    }
}

impl fmt::Display for ContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChangeCipherSpec => write!(f, "ChangeCipherSpec"),
            Self::Alert => write!(f, "Alert"),
            Self::Handshake => write!(f, "Handshake"),
            Self::ApplicationData => write!(f, "ApplicationData"),
            Self::Heartbeat => write!(f, "Heartbeat"),
            Self::Unknown(v) => write!(f, "Unknown({v})"),
        }
    }
}

// ─── TlsRecord ────────────────────────────────────────────────────────────────

/// A single TLS record (5-byte header + payload).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRecord {
    pub content_type: ContentType,
    pub version: TlsVersion,
    pub payload: Vec<u8>,
}

impl TlsRecord {
    #[must_use] 
    pub const fn new(ct: ContentType, version: TlsVersion, payload: Vec<u8>) -> Self {
        Self {
            content_type: ct,
            version,
            payload,
        }
    }

    /// Serialize to wire format.
    ///
    /// # Panics
    /// Panics if the payload exceeds 65535 bytes (not a valid TLS record).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        assert!(
            self.payload.len() <= 65535,
            "TLS record payload too large: {} bytes (max 65535)",
            self.payload.len()
        );
        let len = u16::try_from(self.payload.len()).unwrap_or(u16::MAX);
        let v = self.version.to_u16();
        // Serialise both 16-bit fields big-endian.
        //
        // These used to read `u8::try_from(v).unwrap_or(u8::MAX)` for the low
        // byte, which is not a truncation: `try_from` *fails* for anything
        // above 255 and the fallback substitutes 0xFF. Every TLS version is
        // >= 0x0100, so every record this produced carried version 0xNNFF —
        // 0x0303 (TLS 1.2) went out as 0x03FF — and any payload longer than
        // 255 bytes had its length corrupted the same way.
        let mut out = vec![self.content_type.to_u8()];
        out.extend_from_slice(&v.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a single record from `buf`; returns record + bytes consumed.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), TlsError> {
        need(buf, 5)?;
        let ct = ContentType::from_u8(buf[0]);
        let version = TlsVersion::from_u16(u16::from_be_bytes([buf[1], buf[2]]));
        let length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        need(buf, 5 + length)?;
        let payload = buf[5..5 + length].to_vec();
        Ok((
            Self {
                content_type: ct,
                version,
                payload,
            },
            5 + length,
        ))
    }

    #[must_use] 
    pub fn is_handshake(&self) -> bool {
        self.content_type == ContentType::Handshake
    }

    #[must_use] 
    pub fn is_application_data(&self) -> bool {
        self.content_type == ContentType::ApplicationData
    }
}

// ─── HandshakeType ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    NewSessionTicket,
    EndOfEarlyData,
    EncryptedExtensions,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    KeyUpdate,
    Unknown(u8),
}

impl HandshakeType {
    #[must_use] 
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::HelloRequest,
            1 => Self::ClientHello,
            2 => Self::ServerHello,
            4 => Self::NewSessionTicket,
            5 => Self::EndOfEarlyData,
            8 => Self::EncryptedExtensions,
            11 => Self::Certificate,
            12 => Self::ServerKeyExchange,
            13 => Self::CertificateRequest,
            14 => Self::ServerHelloDone,
            15 => Self::CertificateVerify,
            16 => Self::ClientKeyExchange,
            20 => Self::Finished,
            24 => Self::KeyUpdate,
            other => Self::Unknown(other),
        }
    }

    #[must_use] 
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::HelloRequest => 0,
            Self::ClientHello => 1,
            Self::ServerHello => 2,
            Self::NewSessionTicket => 4,
            Self::EndOfEarlyData => 5,
            Self::EncryptedExtensions => 8,
            Self::Certificate => 11,
            Self::ServerKeyExchange => 12,
            Self::CertificateRequest => 13,
            Self::ServerHelloDone => 14,
            Self::CertificateVerify => 15,
            Self::ClientKeyExchange => 16,
            Self::Finished => 20,
            Self::KeyUpdate => 24,
            Self::Unknown(v) => v,
        }
    }
}

impl fmt::Display for HandshakeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── CipherSuite ──────────────────────────────────────────────────────────────

/// A TLS cipher suite identified by its two-byte code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    pub const TLS_AES_128_GCM_SHA256: Self = Self(0x1301);
    pub const TLS_AES_256_GCM_SHA384: Self = Self(0x1302);
    pub const TLS_CHACHA20_POLY1305_SHA256: Self = Self(0x1303);
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02B);
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Self = Self(0xC02C);
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: Self = Self(0x002F);
    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: Self = Self(0x00FF);

    #[must_use] 
    pub const fn is_tls13(self) -> bool {
        matches!(self.0, 0x1301..=0x1305)
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self.0 {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            0xC02B => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xC02C => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x00FF => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:04x})", self.name(), self.0)
    }
}

// ─── Extension ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl Extension {
    #[must_use] 
    pub const fn new(ext_type: u16, data: Vec<u8>) -> Self {
        Self { ext_type, data }
    }

    /// Parse a single extension from `buf`; returns ext + bytes consumed.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), TlsError> {
        need(buf, 4)?;
        let ext_type = u16::from_be_bytes([buf[0], buf[1]]);
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        need(buf, 4 + length)?;
        Ok((
            Self {
                ext_type,
                data: buf[4..4 + length].to_vec(),
            },
            4 + length,
        ))
    }

    /// Try to read SNI from a `server_name` extension (type 0x0000).
    pub fn sni(&self) -> Option<String> {
        if self.ext_type != 0x0000 || self.data.len() < 5 {
            return None;
        }
        // server_name_list_length (2) + name_type (1) + name_length (2) + name
        let name_len = u16::from_be_bytes([self.data[3], self.data[4]]) as usize;
        if self.data.len() < 5 + name_len {
            return None;
        }
        std::str::from_utf8(&self.data[5..5 + name_len])
            .ok()
            .map(str::to_owned)
    }
}

// ─── Handshake ────────────────────────────────────────────────────────────────

/// A parsed TLS handshake message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    pub msg_type: HandshakeType,
    pub body: Vec<u8>,
}

impl Handshake {
    #[must_use] 
    pub const fn new(msg_type: HandshakeType, body: Vec<u8>) -> Self {
        Self { msg_type, body }
    }

    /// Parse a handshake message from raw bytes.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), TlsError> {
        need(buf, 4)?;
        let msg_type = HandshakeType::from_u8(buf[0]);
        let length = (u32::from_be_bytes([0, buf[1], buf[2], buf[3]])) as usize;
        need(buf, 4 + length)?;
        let body = buf[4..4 + length].to_vec();
        Ok((Self { msg_type, body }, 4 + length))
    }

    /// Serialize to bytes.
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = u32::try_from(self.body.len()).unwrap_or(u32::MAX);
        let mut out = vec![
            self.msg_type.to_u8(),
            u8::try_from(n >> 16).unwrap_or(u8::MAX),
            u8::try_from(n >> 8).unwrap_or(u8::MAX),
            u8::try_from(n).unwrap_or(u8::MAX),
        ];
        out.extend_from_slice(&self.body);
        out
    }

    /// Parse `ClientHello` / `ServerHello` cipher suite list from body.
    #[must_use] 
    pub fn cipher_suites(&self) -> Vec<CipherSuite> {
        match self.msg_type {
            HandshakeType::ClientHello => {
                if self.body.len() < 34 {
                    return vec![];
                }
                // skip version(2) + random(32)
                let mut off = 34;
                // session_id length
                if off >= self.body.len() {
                    return vec![];
                }
                let sid_len = self.body[off] as usize;
                off += 1 + sid_len;
                if off + 2 > self.body.len() {
                    return vec![];
                }
                let cs_len = u16::from_be_bytes([self.body[off], self.body[off + 1]]) as usize;
                off += 2;
                if off + cs_len > self.body.len() {
                    return vec![];
                }
                (0..cs_len / 2)
                    .map(|i| {
                        CipherSuite(u16::from_be_bytes([
                            self.body[off + i * 2],
                            self.body[off + i * 2 + 1],
                        ]))
                    })
                    .collect()
            }
            HandshakeType::ServerHello => {
                if self.body.len() < 34 + 1 {
                    return vec![];
                }
                let sid_len = self.body[34] as usize;
                let off = 35 + sid_len;
                if off + 2 > self.body.len() {
                    return vec![];
                }
                vec![CipherSuite(u16::from_be_bytes([
                    self.body[off],
                    self.body[off + 1],
                ]))]
            }
            _ => vec![],
        }
    }

    /// Extract `HandshakeType` name.
    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self.msg_type {
            HandshakeType::ClientHello => "ClientHello",
            HandshakeType::ServerHello => "ServerHello",
            HandshakeType::Certificate => "Certificate",
            HandshakeType::Finished => "Finished",
            _ => "Other",
        }
    }
}

// ─── Certificate ──────────────────────────────────────────────────────────────

/// A single DER-encoded certificate extracted from a TLS Certificate message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub index: usize,
    pub der: Vec<u8>,
}

impl Certificate {
    #[must_use] 
    pub const fn new(index: usize, der: Vec<u8>) -> Self {
        Self { index, der }
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.der.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.der.is_empty()
    }

    /// Parse the certificate list from a Certificate handshake body.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_list(body: &[u8]) -> Result<Vec<Self>, TlsError> {
        // Cap to avoid unbounded Vec growth from adversarial input.
        const MAX_CERTS: usize = 64;
        need(body, 3)?;
        let list_len = (u32::from_be_bytes([0, body[0], body[1], body[2]])) as usize;
        if body.len() < 3 + list_len {
            return Err(TlsError::TooShort {
                need: 3 + list_len,
                got: body.len(),
            });
        }
        let mut certs = Vec::new();
        let mut off = 3usize;
        let end = 3 + list_len;
        let mut idx = 0;
        while off + 3 <= end && idx < MAX_CERTS {
            let cert_len =
                (u32::from_be_bytes([0, body[off], body[off + 1], body[off + 2]])) as usize;
            off += 3;
            if off + cert_len > end {
                return Err(TlsError::MalformedField("cert length overflow".into()));
            }
            certs.push(Self::new(idx, body[off..off + cert_len].to_vec()));
            off += cert_len;
            idx += 1;
        }
        Ok(certs)
    }
}

// ─── KeyExchange ──────────────────────────────────────────────────────────────

/// Key exchange parameters extracted from `ServerKeyExchange` / `ClientKeyExchange`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchange {
    pub algorithm: KeyExchangeAlgorithm,
    pub params: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyExchangeAlgorithm {
    Rsa,
    DiffieHellman,
    Ecdh,
    EcdhEphemeral,
    Unknown,
}

impl fmt::Display for KeyExchangeAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl KeyExchange {
    #[must_use] 
    pub const fn new(algorithm: KeyExchangeAlgorithm, params: Vec<u8>) -> Self {
        Self { algorithm, params }
    }

    #[must_use] 
    pub const fn param_len(&self) -> usize {
        self.params.len()
    }
}

// ─── AlertLevel / AlertDescription ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertLevel {
    Warning,
    Fatal,
    Unknown(u8),
}

impl AlertLevel {
    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Warning,
            2 => Self::Fatal,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: u8,
}

impl Alert {
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(data: &[u8]) -> Result<Self, TlsError> {
        need(data, 2)?;
        Ok(Self {
            level: AlertLevel::from_u8(data[0]),
            description: data[1],
        })
    }
}

// ─── TlsSessionState ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsSessionState {
    Initial,
    ClientHelloSent,
    ServerHelloReceived,
    CertificateReceived,
    KeyExchangeDone,
    ChangeCipherSpec,
    Established,
    Closed,
    Error,
}

impl fmt::Display for TlsSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── TlsSession ───────────────────────────────────────────────────────────────

/// Tracks the full handshake state for one TLS connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSession {
    pub id: u64,
    pub state: TlsSessionState,
    pub version: Option<TlsVersion>,
    pub negotiated_cipher: Option<CipherSuite>,
    pub sni: Option<String>,
    pub certificates: Vec<Certificate>,
    pub key_exchange: Option<KeyExchange>,
    pub client_random: Option<[u8; 32]>,
    pub server_random: Option<[u8; 32]>,
    pub records_seen: u64,
    pub alerts: Vec<Alert>,
}

impl TlsSession {
    #[must_use] 
    pub const fn new(id: u64) -> Self {
        Self {
            id,
            state: TlsSessionState::Initial,
            version: None,
            negotiated_cipher: None,
            sni: None,
            certificates: Vec::new(),
            key_exchange: None,
            client_random: None,
            server_random: None,
            records_seen: 0,
            alerts: Vec::new(),
        }
    }

    #[must_use] 
    pub fn is_established(&self) -> bool {
        self.state == TlsSessionState::Established
    }

    #[must_use] 
    pub const fn cert_count(&self) -> usize {
        self.certificates.len()
    }
}

// ─── TlsDissector ─────────────────────────────────────────────────────────────

/// Full TLS 1.2/1.3 dissector.
///
/// Parses raw byte streams into [`TlsRecord`]s, dissects handshake messages,
/// and maintains per-session state via [`TlsSession`].
#[derive(Debug, Default)]
pub struct TlsDissector {
    sessions: HashMap<u64, TlsSession>,
    next_id: u64,
    records_parsed: u64,
    handshakes_parsed: u64,
    parse_errors: u64,
}

impl TlsDissector {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    // ── Sessions ──────────────────────────────────────────────────────────

    pub fn new_session(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.sessions.insert(id, TlsSession::new(id));
        id
    }

    #[must_use] 
    pub fn session(&self, id: u64) -> Option<&TlsSession> {
        self.sessions.get(&id)
    }

    pub fn session_mut(&mut self, id: u64) -> Option<&mut TlsSession> {
        self.sessions.get_mut(&id)
    }

    #[must_use] 
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    // ── Record parsing ────────────────────────────────────────────────────

    /// Parse all TLS records from `buf`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_records(buf: &[u8]) -> Result<Vec<TlsRecord>, TlsError> {
        let mut records = Vec::new();
        let mut off = 0usize;
        while off < buf.len() {
            let (rec, consumed) = TlsRecord::parse(&buf[off..])?;
            off += consumed;
            records.push(rec);
        }
        Ok(records)
    }

    /// Parse all handshake messages from a handshake record payload.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_handshakes(payload: &[u8]) -> Result<Vec<Handshake>, TlsError> {
        let mut msgs = Vec::new();
        let mut off = 0usize;
        while off < payload.len() {
            let (msg, consumed) = Handshake::parse(&payload[off..])?;
            off += consumed;
            msgs.push(msg);
        }
        Ok(msgs)
    }

    /// Feed a raw TLS stream fragment into session `id`; updates session state.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn feed(&mut self, session_id: u64, data: &[u8]) -> Result<Vec<TlsRecord>, TlsError> {
        let records = Self::parse_records(data).inspect_err(|_e| {
            self.parse_errors += 1;
        })?;

        self.records_parsed += records.len() as u64;

        if let Some(session) = self.sessions.get_mut(&session_id) {
            for rec in &records {
                session.records_seen += 1;
                match rec.content_type {
                    ContentType::Handshake => {
                        if let Ok(msgs) = Self::parse_handshakes(&rec.payload) {
                            self.handshakes_parsed += msgs.len() as u64;
                            for msg in msgs {
                                Self::update_session_state(session, &msg);
                            }
                        }
                    }
                    ContentType::Alert => {
                        if let Ok(alert) = Alert::parse(&rec.payload) {
                            session.alerts.push(alert);
                            session.state = TlsSessionState::Closed;
                        }
                    }
                    ContentType::ChangeCipherSpec => {
                        if session.state != TlsSessionState::Established {
                            session.state = TlsSessionState::ChangeCipherSpec;
                        }
                    }
                    ContentType::ApplicationData
                        if session.state == TlsSessionState::ChangeCipherSpec => {
                            session.state = TlsSessionState::Established;
                        }
                    _ => {}
                }
            }
        }

        Ok(records)
    }

    fn update_session_state(session: &mut TlsSession, msg: &Handshake) {
        match msg.msg_type {
            HandshakeType::ClientHello => {
                session.state = TlsSessionState::ClientHelloSent;
                // Extract version from body[0..2]
                if msg.body.len() >= 2 {
                    let v = u16::from_be_bytes([msg.body[0], msg.body[1]]);
                    session.version = Some(TlsVersion::from_u16(v));
                }
                // Extract random from body[2..34]
                if msg.body.len() >= 34 {
                    let mut rnd = [0u8; 32];
                    rnd.copy_from_slice(&msg.body[2..34]);
                    session.client_random = Some(rnd);
                }
            }
            HandshakeType::ServerHello => {
                session.state = TlsSessionState::ServerHelloReceived;
                if msg.body.len() >= 2 {
                    let v = u16::from_be_bytes([msg.body[0], msg.body[1]]);
                    session.version = Some(TlsVersion::from_u16(v));
                }
                if msg.body.len() >= 34 {
                    let mut rnd = [0u8; 32];
                    rnd.copy_from_slice(&msg.body[2..34]);
                    session.server_random = Some(rnd);
                }
                let suites = msg.cipher_suites();
                if let Some(&cs) = suites.first() {
                    session.negotiated_cipher = Some(cs);
                }
            }
            HandshakeType::Certificate => {
                session.state = TlsSessionState::CertificateReceived;
                if let Ok(certs) = Certificate::parse_list(&msg.body) {
                    session.certificates = certs;
                }
            }
            HandshakeType::ServerKeyExchange => {
                session.state = TlsSessionState::KeyExchangeDone;
                session.key_exchange = Some(KeyExchange::new(
                    KeyExchangeAlgorithm::EcdhEphemeral,
                    msg.body.clone(),
                ));
            }
            HandshakeType::ClientKeyExchange => {
                session.key_exchange = Some(KeyExchange::new(
                    KeyExchangeAlgorithm::Rsa,
                    msg.body.clone(),
                ));
            }
            HandshakeType::Finished => {
                session.state = TlsSessionState::Established;
            }
            _ => {}
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────

    #[must_use] 
    pub const fn records_parsed(&self) -> u64 {
        self.records_parsed
    }

    #[must_use] 
    pub const fn handshakes_parsed(&self) -> u64 {
        self.handshakes_parsed
    }

    #[must_use] 
    pub const fn parse_errors(&self) -> u64 {
        self.parse_errors
    }

    #[must_use] 
    pub fn established_sessions(&self) -> Vec<&TlsSession> {
        self.sessions
            .values()
            .filter(|s| s.state == TlsSessionState::Established)
            .collect()
    }

    /// Build a human-readable summary.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "sessions={} records_parsed={} handshakes={} errors={}",
            self.sessions.len(),
            self.records_parsed,
            self.handshakes_parsed,
            self.parse_errors
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- TlsVersion ---

    #[test]
    fn test_tls_version_from_u16() {
        assert_eq!(TlsVersion::from_u16(0x0303), TlsVersion::Tls12);
        assert_eq!(TlsVersion::from_u16(0x0304), TlsVersion::Tls13);
        assert_eq!(TlsVersion::from_u16(0x0301), TlsVersion::Tls10);
        assert_eq!(TlsVersion::from_u16(0xDEAD), TlsVersion::Unknown(0xDEAD));
    }

    #[test]
    fn test_tls_version_round_trip() {
        for v in [
            TlsVersion::Tls10,
            TlsVersion::Tls11,
            TlsVersion::Tls12,
            TlsVersion::Tls13,
        ] {
            assert_eq!(TlsVersion::from_u16(v.to_u16()), v);
        }
    }

    #[test]
    fn test_tls_version_is_tls13() {
        assert!(TlsVersion::Tls13.is_tls13());
        assert!(!TlsVersion::Tls12.is_tls13());
    }

    #[test]
    fn test_tls_version_display() {
        assert_eq!(TlsVersion::Tls12.to_string(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls13.to_string(), "TLSv1.3");
    }

    // --- ContentType ---

    #[test]
    fn test_content_type_round_trip() {
        for ct in [
            ContentType::Handshake,
            ContentType::Alert,
            ContentType::ApplicationData,
            ContentType::ChangeCipherSpec,
        ] {
            assert_eq!(ContentType::from_u8(ct.to_u8()), ct);
        }
    }

    #[test]
    fn test_content_type_unknown() {
        assert_eq!(ContentType::from_u8(99), ContentType::Unknown(99));
    }

    // --- TlsRecord ---

    #[test]
    fn test_tls_record_to_bytes_parse_round_trip() {
        let rec = TlsRecord::new(ContentType::Handshake, TlsVersion::Tls12, vec![1, 2, 3, 4]);
        let bytes = rec.to_bytes();
        assert_eq!(bytes[0], 22); // Handshake
        let (parsed, consumed) = TlsRecord::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.payload, vec![1, 2, 3, 4]);
        assert_eq!(parsed.version, TlsVersion::Tls12);
    }

    #[test]
    fn test_tls_record_parse_too_short() {
        assert!(TlsRecord::parse(&[22, 3, 3]).is_err());
    }

    #[test]
    fn test_tls_record_parse_payload_truncated() {
        // Header says length=10 but only 3 bytes follow
        let buf = [22u8, 3, 3, 0, 10, 1, 2, 3];
        assert!(TlsRecord::parse(&buf).is_err());
    }

    #[test]
    fn test_tls_record_is_handshake() {
        let rec = TlsRecord::new(ContentType::Handshake, TlsVersion::Tls12, vec![]);
        assert!(rec.is_handshake());
        assert!(!rec.is_application_data());
    }

    #[test]
    fn test_tls_record_is_application_data() {
        let rec = TlsRecord::new(ContentType::ApplicationData, TlsVersion::Tls12, vec![]);
        assert!(rec.is_application_data());
    }

    // --- Handshake ---

    #[test]
    fn test_handshake_parse_round_trip() {
        let body = vec![0u8; 10];
        let hs = Handshake::new(HandshakeType::ClientHello, body.clone());
        let bytes = hs.to_bytes();
        let (parsed, consumed) = Handshake::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn test_handshake_type_from_u8() {
        assert_eq!(HandshakeType::from_u8(1), HandshakeType::ClientHello);
        assert_eq!(HandshakeType::from_u8(2), HandshakeType::ServerHello);
        assert_eq!(HandshakeType::from_u8(11), HandshakeType::Certificate);
        assert_eq!(HandshakeType::from_u8(20), HandshakeType::Finished);
        assert!(matches!(
            HandshakeType::from_u8(99),
            HandshakeType::Unknown(99)
        ));
    }

    #[test]
    fn test_handshake_too_short() {
        assert!(Handshake::parse(&[1, 0, 0]).is_err());
    }

    // --- CipherSuite ---

    #[test]
    fn test_cipher_suite_is_tls13() {
        assert!(CipherSuite::TLS_AES_128_GCM_SHA256.is_tls13());
        assert!(CipherSuite::TLS_CHACHA20_POLY1305_SHA256.is_tls13());
        assert!(!CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA.is_tls13());
    }

    #[test]
    fn test_cipher_suite_name() {
        assert_eq!(
            CipherSuite::TLS_AES_128_GCM_SHA256.name(),
            "TLS_AES_128_GCM_SHA256"
        );
        assert_eq!(CipherSuite(0x9999).name(), "UNKNOWN");
    }

    #[test]
    fn test_cipher_suite_display() {
        let s = CipherSuite::TLS_AES_256_GCM_SHA384.to_string();
        assert!(s.contains("TLS_AES_256_GCM_SHA384"));
        assert!(s.contains("0x1302"));
    }

    // --- Extension ---

    #[test]
    fn test_extension_parse() {
        // type=0x000F, length=3, data=[1,2,3]
        let buf = [0x00u8, 0x0F, 0x00, 0x03, 1, 2, 3];
        let (ext, consumed) = Extension::parse(&buf).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(ext.ext_type, 0x000F);
        assert_eq!(ext.data, [1, 2, 3]);
    }

    #[test]
    fn test_extension_sni_extraction() {
        // Build a minimal SNI extension body: list_len(2) + name_type(1) + name_len(2) + name
        let name = b"example.com";
        let name_len = u16::try_from(name.len()).unwrap_or(u16::MAX);
        let list_len = 3 + name_len; // name_type + name_len_field + name
        let mut data = Vec::new();
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0); // name_type = host_name
        data.extend_from_slice(&name_len.to_be_bytes());
        data.extend_from_slice(name);
        let ext = Extension::new(0x0000, data);
        assert_eq!(ext.sni(), Some("example.com".to_string()));
    }

    #[test]
    fn test_extension_sni_wrong_type() {
        let ext = Extension::new(0x0001, vec![0; 10]);
        assert!(ext.sni().is_none());
    }

    // --- Certificate ---

    #[test]
    fn test_certificate_parse_list_single() {
        let cert_data = vec![0u8; 20];
        let cert_len = u32::try_from(cert_data.len()).unwrap_or(u32::MAX);
        let total = 3 + cert_data.len();
        let total_u32 = u32::try_from(total).unwrap_or(u32::MAX);
        let mut body = vec![
            ((total_u32 >> 16) & 0xFF) as u8,
            ((total_u32 >> 8) & 0xFF) as u8,
            (total_u32 & 0xFF) as u8,
            ((cert_len >> 16) & 0xFF) as u8,
            ((cert_len >> 8) & 0xFF) as u8,
            (cert_len & 0xFF) as u8,
        ];
        body.extend_from_slice(&cert_data);
        let certs = Certificate::parse_list(&body).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].len(), 20);
    }

    #[test]
    fn test_certificate_is_empty() {
        let c = Certificate::new(0, vec![]);
        assert!(c.is_empty());
    }

    // --- KeyExchange ---

    #[test]
    fn test_key_exchange_new() {
        let kx = KeyExchange::new(KeyExchangeAlgorithm::Ecdh, vec![1, 2, 3]);
        assert_eq!(kx.algorithm, KeyExchangeAlgorithm::Ecdh);
        assert_eq!(kx.param_len(), 3);
    }

    // --- Alert ---

    #[test]
    fn test_alert_parse() {
        let alert = Alert::parse(&[2, 40]).unwrap();
        assert_eq!(alert.level, AlertLevel::Fatal);
        assert_eq!(alert.description, 40);
    }

    #[test]
    fn test_alert_parse_too_short() {
        assert!(Alert::parse(&[2]).is_err());
    }

    // --- TlsSession ---

    #[test]
    fn test_tls_session_new() {
        let sess = TlsSession::new(42);
        assert_eq!(sess.id, 42);
        assert_eq!(sess.state, TlsSessionState::Initial);
        assert!(!sess.is_established());
    }

    #[test]
    fn test_tls_session_cert_count() {
        let mut sess = TlsSession::new(1);
        sess.certificates.push(Certificate::new(0, vec![1; 10]));
        assert_eq!(sess.cert_count(), 1);
    }

    // --- TlsDissector ---

    #[test]
    fn test_dissector_new_session() {
        let mut d = TlsDissector::new();
        let id = d.new_session();
        assert!(d.session(id).is_some());
        assert_eq!(d.session_count(), 1);
    }

    #[test]
    fn test_dissector_multiple_sessions() {
        let mut d = TlsDissector::new();
        let _a = d.new_session();
        let _b = d.new_session();
        assert_eq!(d.session_count(), 2);
    }

    #[test]
    fn test_dissector_feed_application_data() {
        let mut d = TlsDissector::new();
        let sid = d.new_session();
        // Simulate ChangeCipherSpec → ApplicationData transition
        let ccs =
            TlsRecord::new(ContentType::ChangeCipherSpec, TlsVersion::Tls12, vec![1]).to_bytes();
        let app =
            TlsRecord::new(ContentType::ApplicationData, TlsVersion::Tls12, vec![0xAB]).to_bytes();
        let mut stream = ccs;
        stream.extend_from_slice(&app);
        let recs = d.feed(sid, &stream).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(d.session(sid).unwrap().state, TlsSessionState::Established);
    }

    #[test]
    fn test_dissector_parse_records_empty() {
        let records = TlsDissector::parse_records(&[]).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_dissector_parse_records_multiple() {
        let r1 = TlsRecord::new(ContentType::Alert, TlsVersion::Tls12, vec![1, 0]).to_bytes();
        let r2 =
            TlsRecord::new(ContentType::ApplicationData, TlsVersion::Tls12, vec![2]).to_bytes();
        let mut buf = r1;
        buf.extend_from_slice(&r2);
        let records = TlsDissector::parse_records(&buf).unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_dissector_summary() {
        let d = TlsDissector::new();
        assert!(d.summary().contains("sessions=0"));
    }

    #[test]
    fn test_dissector_established_sessions_empty() {
        let d = TlsDissector::new();
        assert!(d.established_sessions().is_empty());
    }

    #[test]
    fn test_dissector_error_increments() {
        let mut d = TlsDissector::new();
        let sid = d.new_session();
        // Malformed data — should produce a parse error
        let _ = d.feed(sid, &[22, 3, 3, 0, 10, 1]);
        assert_eq!(d.parse_errors(), 1);
    }

    #[test]
    fn test_dissector_alert_closes_session() {
        let mut d = TlsDissector::new();
        let sid = d.new_session();
        let alert = TlsRecord::new(ContentType::Alert, TlsVersion::Tls12, vec![2, 0]).to_bytes();
        d.feed(sid, &alert).unwrap();
        assert_eq!(d.session(sid).unwrap().state, TlsSessionState::Closed);
    }

    #[test]
    fn test_tls_session_state_display() {
        assert_eq!(TlsSessionState::Initial.to_string(), "Initial");
        assert_eq!(TlsSessionState::Established.to_string(), "Established");
    }

    #[test]
    fn test_key_exchange_algorithm_display() {
        assert_eq!(KeyExchangeAlgorithm::Ecdh.to_string(), "Ecdh");
    }

    #[test]
    fn test_alert_level_warning() {
        let alert = Alert::parse(&[1, 90]).unwrap();
        assert_eq!(alert.level, AlertLevel::Warning);
    }

    #[test]
    fn test_tls_record_empty_payload() {
        let rec = TlsRecord::new(ContentType::ApplicationData, TlsVersion::Tls13, vec![]);
        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), 5); // header only
        let (parsed, _) = TlsRecord::parse(&bytes).unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_cipher_suite_equality() {
        assert_eq!(
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_128_GCM_SHA256
        );
        assert_ne!(
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384
        );
    }

    #[test]
    fn test_dissector_records_count() {
        let mut d = TlsDissector::new();
        let sid = d.new_session();
        let rec =
            TlsRecord::new(ContentType::ApplicationData, TlsVersion::Tls12, vec![1]).to_bytes();
        d.feed(sid, &rec).unwrap();
        assert_eq!(d.records_parsed(), 1);
    }

    #[test]
    fn test_dissector_session_mut() {
        let mut d = TlsDissector::new();
        let sid = d.new_session();
        if let Some(s) = d.session_mut(sid) {
            s.sni = Some("test.example.com".into());
        }
        assert_eq!(
            d.session(sid).unwrap().sni.as_deref(),
            Some("test.example.com")
        );
    }
}
