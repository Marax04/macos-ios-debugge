//! TLS handshake fuzzer: ClientHello mutations, cipher suite injection,
//! extension fuzzing, and record fragmentation attacks.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use serde::{Deserialize, Serialize};

// ── TLS constants ─────────────────────────────────────────────────────────────

/// TLS record types.
pub mod record_type {
    pub const CHANGE_CIPHER_SPEC: u8 = 0x14;
    pub const ALERT: u8 = 0x15;
    pub const HANDSHAKE: u8 = 0x16;
    pub const APPLICATION_DATA: u8 = 0x17;
}

/// TLS handshake message types.
pub mod handshake_type {
    pub const CLIENT_HELLO: u8 = 0x01;
    pub const SERVER_HELLO: u8 = 0x02;
    pub const CERTIFICATE: u8 = 0x0B;
    pub const SERVER_HELLO_DONE: u8 = 0x0E;
    pub const CLIENT_KEY_EXCHANGE: u8 = 0x10;
    pub const FINISHED: u8 = 0x14;
}

/// Common TLS cipher suites.
pub mod cipher_suites {
    pub const TLS_NULL_WITH_NULL_NULL: [u8; 2] = [0x00, 0x00];
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: [u8; 2] = [0x00, 0x2F];
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: [u8; 2] = [0x00, 0x35];
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: [u8; 2] = [0x00, 0x3C];
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: [u8; 2] = [0x00, 0x3D];
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: [u8; 2] = [0xC0, 0x2F];
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: [u8; 2] = [0xC0, 0x30];
    pub const TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
    pub const TLS_AES_256_GCM_SHA384: [u8; 2] = [0x13, 0x02];
    pub const TLS_CHACHA20_POLY1305_SHA256: [u8; 2] = [0x13, 0x03];
    pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: [u8; 2] = [0xFF, 0xFF];
}

/// TLS extension types.
pub mod extension_type {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const MAX_FRAGMENT_LENGTH: u16 = 0x0001;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SUPPORTED_GROUPS: u16 = 0x000A;
    pub const EC_POINT_FORMATS: u16 = 0x000B;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000D;
    pub const ALPN: u16 = 0x0010;
    pub const HEARTBEAT: u16 = 0x000F;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const SUPPORTED_VERSIONS: u16 = 0x002B;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002D;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const RENEGOTIATION_INFO: u16 = 0xFF01;
}

// ── TLS version ───────────────────────────────────────────────────────────────

/// TLS protocol version as 2-byte representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsVersion(pub u8, pub u8);

impl TlsVersion {
    pub const SSL_3_0: Self = Self(0x03, 0x00);
    pub const TLS_1_0: Self = Self(0x03, 0x01);
    pub const TLS_1_1: Self = Self(0x03, 0x02);
    pub const TLS_1_2: Self = Self(0x03, 0x03);
    pub const TLS_1_3: Self = Self(0x03, 0x04);

    #[must_use]
    pub const fn bytes(self) -> [u8; 2] { [self.0, self.1] }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self(0x03, 0x00) => "SSLv3",
            Self(0x03, 0x01) => "TLSv1.0",
            Self(0x03, 0x02) => "TLSv1.1",
            Self(0x03, 0x03) => "TLSv1.2",
            Self(0x03, 0x04) => "TLSv1.3",
            _ => "unknown",
        }
    }
}

// ── ClientHello builder ───────────────────────────────────────────────────────

/// Builds a TLS ClientHello handshake message.
#[derive(Debug, Clone)]
pub struct ClientHelloBuilder {
    legacy_version: TlsVersion,
    random: [u8; 32],
    session_id: Vec<u8>,
    cipher_suites: Vec<[u8; 2]>,
    compression_methods: Vec<u8>,
    extensions: Vec<TlsExtension>,
}

/// A TLS extension (type + data).
#[derive(Debug, Clone)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

impl TlsExtension {
    #[must_use]
    pub fn new(ext_type: u16, data: Vec<u8>) -> Self { Self { ext_type, data } }

    /// Serialize: type (2 bytes) + length (2 bytes) + data
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.extend_from_slice(&self.ext_type.to_be_bytes());
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Build an SNI extension for the given hostname.
    #[must_use]
    pub fn server_name(hostname: &str) -> Self {
        let name_bytes = hostname.as_bytes();
        let mut data = Vec::new();
        let list_len = 1 + 2 + name_bytes.len(); // type + len + name
        data.extend_from_slice(&(list_len as u16).to_be_bytes());
        data.push(0x00); // name_type = host_name
        data.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(name_bytes);
        Self::new(extension_type::SERVER_NAME, data)
    }

    /// Build an ALPN extension.
    #[must_use]
    pub fn alpn(protocols: &[&str]) -> Self {
        let mut list = Vec::new();
        for proto in protocols {
            let b = proto.as_bytes();
            list.push(b.len() as u8);
            list.extend_from_slice(b);
        }
        let mut data = Vec::new();
        data.extend_from_slice(&(list.len() as u16).to_be_bytes());
        data.extend(list);
        Self::new(extension_type::ALPN, data)
    }

    /// Build a supported_versions extension listing the given versions.
    #[must_use]
    pub fn supported_versions(versions: &[TlsVersion]) -> Self {
        let mut data = vec![(versions.len() * 2) as u8];
        for v in versions {
            data.push(v.0);
            data.push(v.1);
        }
        Self::new(extension_type::SUPPORTED_VERSIONS, data)
    }
}

impl Default for ClientHelloBuilder {
    fn default() -> Self {
        Self {
            legacy_version: TlsVersion::TLS_1_2,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites: vec![
                cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                cipher_suites::TLS_RSA_WITH_AES_128_CBC_SHA,
                cipher_suites::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            ],
            compression_methods: vec![0x00],
            extensions: Vec::new(),
        }
    }
}

impl ClientHelloBuilder {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn legacy_version(mut self, v: TlsVersion) -> Self { self.legacy_version = v; self }
    pub fn random(mut self, r: [u8; 32]) -> Self { self.random = r; self }
    pub fn session_id(mut self, id: Vec<u8>) -> Self { self.session_id = id; self }
    pub fn cipher_suites(mut self, cs: Vec<[u8; 2]>) -> Self { self.cipher_suites = cs; self }
    pub fn compression_methods(mut self, cm: Vec<u8>) -> Self { self.compression_methods = cm; self }
    pub fn add_extension(mut self, ext: TlsExtension) -> Self { self.extensions.push(ext); self }

    /// Serialize the ClientHello payload (without record layer header).
    #[must_use]
    pub fn build_payload(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // Legacy version
        body.extend_from_slice(&self.legacy_version.bytes());

        // Random (32 bytes)
        body.extend_from_slice(&self.random);

        // Session ID
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);

        // Cipher suites
        let cs_len = self.cipher_suites.len() * 2;
        body.extend_from_slice(&(cs_len as u16).to_be_bytes());
        for cs in &self.cipher_suites {
            body.extend_from_slice(cs);
        }

        // Compression methods
        body.push(self.compression_methods.len() as u8);
        body.extend_from_slice(&self.compression_methods);

        // Extensions
        if !self.extensions.is_empty() {
            let mut ext_bytes = Vec::new();
            for ext in &self.extensions {
                ext_bytes.extend(ext.serialize());
            }
            body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
            body.extend(ext_bytes);
        }

        body
    }

    /// Wrap the ClientHello payload in a full TLS record.
    #[must_use]
    pub fn build_record(&self) -> Vec<u8> {
        let payload = self.build_payload();
        build_handshake_record(handshake_type::CLIENT_HELLO, &payload, self.legacy_version)
    }
}

/// Build a TLS handshake record: record header + handshake header + body.
#[must_use]
pub fn build_handshake_record(msg_type: u8, body: &[u8], version: TlsVersion) -> Vec<u8> {
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(msg_type);
    // 3-byte length
    let len = body.len() as u32;
    hs.push((len >> 16) as u8);
    hs.push((len >> 8) as u8);
    hs.push(len as u8);
    hs.extend_from_slice(body);

    let mut record = Vec::with_capacity(5 + hs.len());
    record.push(record_type::HANDSHAKE);
    record.extend_from_slice(&version.bytes());
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend(hs);
    record
}

// ── TLS fuzz mutation strategies ──────────────────────────────────────────────

/// How to mutate a ClientHello.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsFuzzStrategy {
    /// Inject random/unusual cipher suites.
    RandomCipherSuites,
    /// Send an extremely large session ID (up to 255 bytes).
    LargeSessionId,
    /// Inject a malformed extension with oversized data.
    OversizedExtension(u16),
    /// Send a truncated ClientHello.
    TruncateAt(usize),
    /// Fragment the record across multiple TCP segments.
    RecordFragmentation { fragment_size: usize },
    /// Override the record layer version with an unusual value.
    BadRecordVersion(TlsVersion),
    /// Zero out the Random bytes.
    ZeroRandom,
    /// Flood with many cipher suites (256 entries).
    CipherSuiteFlood,
    /// Send an empty ClientHello body.
    EmptyBody,
    /// Duplicate all extensions.
    DuplicateExtensions,
    /// Send a heartbeat extension with type 3 (invalid).
    InvalidHeartbeatMode,
    /// Set cipher suite count to 0xFFFF (integer overflow attempt).
    CipherSuiteCountOverflow,
}

impl TlsFuzzStrategy {
    /// Apply this strategy to a base `ClientHelloBuilder`, returning the mutated record bytes.
    #[must_use]
    pub fn apply(&self, base: &ClientHelloBuilder) -> Vec<MutatedRecord> {
        match self {
            Self::RandomCipherSuites => {
                let bad_suites: Vec<[u8; 2]> = (0..20u8)
                    .map(|i| [i.wrapping_mul(7), i.wrapping_mul(13)])
                    .collect();
                let record = base.clone().cipher_suites(bad_suites).build_record();
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "random_ciphers".into() }]
            }
            Self::LargeSessionId => {
                let session_id = vec![0xABu8; 255];
                let record = base.clone().session_id(session_id).build_record();
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "large_sid".into() }]
            }
            Self::OversizedExtension(ext_type) => {
                let big_data = vec![0xFFu8; 65000];
                let ext = TlsExtension::new(*ext_type, big_data);
                let record = base.clone().add_extension(ext).build_record();
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "oversized_ext".into() }]
            }
            Self::TruncateAt(n) => {
                let mut record = base.build_record();
                record.truncate(*n);
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "truncated".into() }]
            }
            Self::RecordFragmentation { fragment_size } => {
                let record = base.build_record();
                let fragments = fragment_record(&record, *fragment_size);
                fragments.into_iter().enumerate().map(|(i, f)| MutatedRecord {
                    bytes: f,
                    strategy: format!("{self:?}"),
                    label: format!("fragment_{}", i),
                }).collect()
            }
            Self::BadRecordVersion(v) => {
                let payload = base.build_payload();
                let record = build_handshake_record(handshake_type::CLIENT_HELLO, &payload, *v);
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "bad_version".into() }]
            }
            Self::ZeroRandom => {
                let record = base.clone().random([0u8; 32]).build_record();
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "zero_random".into() }]
            }
            Self::CipherSuiteFlood => {
                let suites: Vec<[u8; 2]> = (0..=255u8).map(|i| [0x00, i]).collect();
                let record = base.clone().cipher_suites(suites).build_record();
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "cs_flood".into() }]
            }
            Self::EmptyBody => {
                let record = build_handshake_record(handshake_type::CLIENT_HELLO, &[], TlsVersion::TLS_1_2);
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "empty_body".into() }]
            }
            Self::DuplicateExtensions => {
                let sni = TlsExtension::server_name("test.example.com");
                let record = base.clone()
                    .add_extension(sni.clone())
                    .add_extension(sni)
                    .build_record();
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "dup_ext".into() }]
            }
            Self::InvalidHeartbeatMode => {
                let ext = TlsExtension::new(extension_type::HEARTBEAT, vec![0x03]);
                let record = base.clone().add_extension(ext).build_record();
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "bad_heartbeat".into() }]
            }
            Self::CipherSuiteCountOverflow => {
                // Manually build a record with cs_len = 0xFFFF
                let mut payload = base.legacy_version.bytes().to_vec();
                payload.extend_from_slice(&[0u8; 32]); // random
                payload.push(0); // session id len = 0
                payload.extend_from_slice(&[0xFF, 0xFE]); // cipher suite count = 65534 bytes
                let record = build_handshake_record(handshake_type::CLIENT_HELLO, &payload, TlsVersion::TLS_1_2);
                vec![MutatedRecord { bytes: record, strategy: format!("{self:?}"), label: "cs_overflow".into() }]
            }
        }
    }
}

/// A single mutated TLS record to send.
#[derive(Debug, Clone)]
pub struct MutatedRecord {
    pub bytes: Vec<u8>,
    pub strategy: String,
    pub label: String,
}

/// Fragment a TLS record into multiple pieces of at most `fragment_size` bytes.
#[must_use]
pub fn fragment_record(record: &[u8], fragment_size: usize) -> Vec<Vec<u8>> {
    if fragment_size == 0 || record.len() <= fragment_size {
        return vec![record.to_vec()];
    }
    // Extract record layer header (5 bytes) and rebuild with smaller payload fragments
    if record.len() < 5 {
        return vec![record.to_vec()];
    }
    let rec_type = record[0];
    let version = [record[1], record[2]];
    let payload = &record[5..];

    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let end = (offset + fragment_size).min(payload.len());
        let chunk = &payload[offset..end];
        let mut frag = Vec::with_capacity(5 + chunk.len());
        frag.push(rec_type);
        frag.extend_from_slice(&version);
        frag.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        frag.extend_from_slice(chunk);
        fragments.push(frag);
        offset = end;
    }
    fragments
}

// ── TLS fuzzer ────────────────────────────────────────────────────────────────

/// Result of one TLS fuzz probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsFuzzResult {
    ServerHelloReceived { version: [u8; 2], cipher: [u8; 2] },
    AlertReceived { level: u8, description: u8 },
    EmptyResponse,
    ConnectionClosed,
    ConnectFailed(String),
    SendTimeout,
    RecvTimeout,
    Unexpected(Vec<u8>),
}

impl TlsFuzzResult {
    #[must_use]
    pub fn is_anomalous(&self) -> bool {
        matches!(self, Self::EmptyResponse | Self::ConnectionClosed | Self::Unexpected(_))
    }
}

/// Async TLS fuzzer.
pub struct TlsFuzzer {
    target: SocketAddr,
    connect_timeout_ms: u64,
    send_timeout_ms: u64,
    recv_timeout_ms: u64,
    base_hello: ClientHelloBuilder,
    strategies: Vec<TlsFuzzStrategy>,
    results: Vec<(String, TlsFuzzResult)>,
}

impl TlsFuzzer {
    #[must_use]
    pub fn new(target: SocketAddr) -> Self {
        let mut base = ClientHelloBuilder::new();
        // Add SNI for the target hostname
        base = base.add_extension(TlsExtension::server_name("localhost"));
        Self {
            target,
            connect_timeout_ms: 3000,
            send_timeout_ms: 3000,
            recv_timeout_ms: 3000,
            base_hello: base,
            strategies: TlsFuzzer::default_strategies(),
            results: Vec::new(),
        }
    }

    fn default_strategies() -> Vec<TlsFuzzStrategy> {
        vec![
            TlsFuzzStrategy::ZeroRandom,
            TlsFuzzStrategy::LargeSessionId,
            TlsFuzzStrategy::CipherSuiteFlood,
            TlsFuzzStrategy::EmptyBody,
            TlsFuzzStrategy::DuplicateExtensions,
            TlsFuzzStrategy::InvalidHeartbeatMode,
            TlsFuzzStrategy::RandomCipherSuites,
            TlsFuzzStrategy::TruncateAt(5),
            TlsFuzzStrategy::TruncateAt(20),
            TlsFuzzStrategy::OversizedExtension(extension_type::SESSION_TICKET),
            TlsFuzzStrategy::RecordFragmentation { fragment_size: 1 },
            TlsFuzzStrategy::BadRecordVersion(TlsVersion::SSL_3_0),
            TlsFuzzStrategy::CipherSuiteCountOverflow,
        ]
    }

    pub fn add_strategy(&mut self, s: TlsFuzzStrategy) {
        self.strategies.push(s);
    }

    /// Run all configured strategies against the target.
    pub async fn run_all(&mut self) -> Vec<(String, TlsFuzzResult)> {
        let strats = std::mem::take(&mut self.strategies);
        for strategy in &strats {
            let records = strategy.apply(&self.base_hello);
            for record in records {
                let result = self.probe(&record.bytes).await;
                self.results.push((record.label.clone(), result));
            }
        }
        self.strategies = strats;
        self.results.clone()
    }

    async fn probe(&self, record: &[u8]) -> TlsFuzzResult {
        let connect_fut = TcpStream::connect(self.target);
        let stream = match timeout(Duration::from_millis(self.connect_timeout_ms), connect_fut).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return TlsFuzzResult::ConnectFailed(e.to_string()),
            Err(_) => return TlsFuzzResult::ConnectFailed("timeout".into()),
        };

        let (mut reader, mut writer) = stream.into_split();

        // Send
        if timeout(Duration::from_millis(self.send_timeout_ms), writer.write_all(record))
            .await
            .is_err()
        {
            return TlsFuzzResult::SendTimeout;
        }

        // Receive
        let mut buf = vec![0u8; 4096];
        match timeout(Duration::from_millis(self.recv_timeout_ms), reader.read(&mut buf)).await {
            Err(_) => TlsFuzzResult::RecvTimeout,
            Ok(Err(_)) => TlsFuzzResult::ConnectionClosed,
            Ok(Ok(0)) => TlsFuzzResult::EmptyResponse,
            Ok(Ok(n)) => {
                let resp = &buf[..n];
                Self::parse_response(resp)
            }
        }
    }

    fn parse_response(resp: &[u8]) -> TlsFuzzResult {
        if resp.len() < 5 {
            return TlsFuzzResult::Unexpected(resp.to_vec());
        }
        match resp[0] {
            record_type::HANDSHAKE if resp.len() >= 10 => {
                // Check for ServerHello: handshake[4] = msg_type
                if resp[5] == handshake_type::SERVER_HELLO && resp.len() >= 11 {
                    let version = [resp[9], resp[10]];
                    let cipher = if resp.len() >= 43 { [resp[43], resp[44]] } else { [0, 0] };
                    TlsFuzzResult::ServerHelloReceived { version, cipher }
                } else {
                    TlsFuzzResult::Unexpected(resp.to_vec())
                }
            }
            record_type::ALERT if resp.len() >= 7 => {
                TlsFuzzResult::AlertReceived { level: resp[5], description: resp[6] }
            }
            _ => TlsFuzzResult::Unexpected(resp.to_vec()),
        }
    }

    #[must_use]
    pub fn results(&self) -> &[(String, TlsFuzzResult)] { &self.results }

    #[must_use]
    pub fn anomalous_results(&self) -> Vec<&(String, TlsFuzzResult)> {
        self.results.iter().filter(|(_, r)| r.is_anomalous()).collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_builder_basic() {
        let hello = ClientHelloBuilder::new()
            .add_extension(TlsExtension::server_name("example.com"))
            .build_record();
        // Record starts with handshake(0x16) + TLSv1.2(0x03 0x03)
        assert_eq!(hello[0], record_type::HANDSHAKE);
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x03);
    }

    #[test]
    fn client_hello_contains_sni() {
        let payload = ClientHelloBuilder::new()
            .add_extension(TlsExtension::server_name("test.example.com"))
            .build_payload();
        // SNI "test.example.com" should appear in the payload
        assert!(payload.windows(16).any(|w| w == b"test.example.com"));
    }

    #[test]
    fn client_hello_cipher_suites() {
        let payload = ClientHelloBuilder::new()
            .cipher_suites(vec![cipher_suites::TLS_AES_128_GCM_SHA256])
            .build_payload();
        // Payload should contain 0x13 0x01
        assert!(payload.windows(2).any(|w| w == [0x13, 0x01]));
    }

    #[test]
    fn fragment_record_splits_correctly() {
        let record = vec![record_type::HANDSHAKE, 0x03, 0x03, 0x00, 0x06, 1, 2, 3, 4, 5, 6];
        let frags = fragment_record(&record, 3);
        assert!(frags.len() > 1);
        // Each fragment has a valid 5-byte header
        for frag in &frags {
            assert!(frag.len() >= 5);
            assert_eq!(frag[0], record_type::HANDSHAKE);
        }
    }

    #[test]
    fn strategy_large_session_id() {
        let base = ClientHelloBuilder::new();
        let records = TlsFuzzStrategy::LargeSessionId.apply(&base);
        assert_eq!(records.len(), 1);
        // The record should be longer due to 255-byte session ID
        let normal = base.build_record();
        assert!(records[0].bytes.len() > normal.len());
    }

    #[test]
    fn strategy_empty_body() {
        let base = ClientHelloBuilder::new();
        let records = TlsFuzzStrategy::EmptyBody.apply(&base);
        assert_eq!(records.len(), 1);
        // Record header (5) + handshake header (4) + empty body = 9 bytes
        assert_eq!(records[0].bytes.len(), 9);
    }

    #[test]
    fn strategy_truncate() {
        let base = ClientHelloBuilder::new();
        let records = TlsFuzzStrategy::TruncateAt(5).apply(&base);
        assert_eq!(records[0].bytes.len(), 5);
    }

    #[test]
    fn strategy_fragmentation_multiple() {
        let base = ClientHelloBuilder::new();
        let records = TlsFuzzStrategy::RecordFragmentation { fragment_size: 1 }.apply(&base);
        // Should produce many 1-byte fragments
        assert!(records.len() > 5);
    }

    #[test]
    fn tls_version_names() {
        assert_eq!(TlsVersion::TLS_1_2.name(), "TLSv1.2");
        assert_eq!(TlsVersion::TLS_1_3.name(), "TLSv1.3");
        assert_eq!(TlsVersion::SSL_3_0.name(), "SSLv3");
    }

    #[test]
    fn extension_alpn_serialize() {
        let ext = TlsExtension::alpn(&["http/1.1", "h2"]);
        let bytes = ext.serialize();
        // Type (2) + length (2) + data
        assert!(bytes.len() > 4);
        assert_eq!(bytes[0], (extension_type::ALPN >> 8) as u8);
        assert_eq!(bytes[1], (extension_type::ALPN & 0xFF) as u8);
    }

    #[test]
    fn supported_versions_extension() {
        let ext = TlsExtension::supported_versions(&[TlsVersion::TLS_1_3, TlsVersion::TLS_1_2]);
        assert!(ext.data.contains(&0x04)); // TLS 1.3 minor = 0x04
        assert!(ext.data.contains(&0x03)); // TLS 1.2 minor = 0x03
    }

    #[test]
    fn parse_response_alert() {
        // Alert record: 0x15 (alert) + version + len + level + description
        let resp = [0x15u8, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        let result = TlsFuzzer::parse_response(&resp);
        assert!(matches!(result, TlsFuzzResult::AlertReceived { description: 0x28, .. }));
    }

    #[test]
    fn cipher_suite_flood_strategy() {
        let base = ClientHelloBuilder::new();
        let records = TlsFuzzStrategy::CipherSuiteFlood.apply(&base);
        assert_eq!(records.len(), 1);
    }
}
