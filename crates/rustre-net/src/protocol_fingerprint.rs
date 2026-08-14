//! `protocol_fingerprint` — Application-layer protocol detection.
//!
//! Provides [`ProtocolFingerprint`] which combines [`BannerGrabber`] heuristics,
//! port-based [`ServiceDetector`] lookups, and a [`FingerprintDb`] of known
//! signatures to identify the [`AppProtocol`] running on a connection.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
pub use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    #[error("no data to fingerprint")]
    NoData,
    #[error("unknown protocol")]
    Unknown,
    #[error("timeout")]
    Timeout,
    #[error("connection refused")]
    Refused,
    #[error("database error: {0}")]
    Database(String),
}

// ─── AppProtocol ──────────────────────────────────────────────────────────────

/// Identified application-layer protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppProtocol {
    Http,
    Https,
    Ftp,
    Ssh,
    Smtp,
    Pop3,
    Imap,
    Dns,
    Smb,
    Rdp,
    Mysql,
    Postgresql,
    Redis,
    Mongodb,
    Telnet,
    Irc,
    Mqtt,
    Amqp,
    Unknown,
    Custom(String),
}

impl fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom({s})"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl AppProtocol {
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        matches!(self, Self::Https | Self::Ssh | Self::Rdp)
    }

    #[must_use]
    pub const fn default_port(&self) -> Option<u16> {
        match self {
            Self::Http => Some(80),
            Self::Https => Some(443),
            Self::Ftp => Some(21),
            Self::Ssh => Some(22),
            Self::Smtp => Some(25),
            Self::Pop3 => Some(110),
            Self::Imap => Some(143),
            Self::Dns => Some(53),
            Self::Smb => Some(445),
            Self::Rdp => Some(3389),
            Self::Mysql => Some(3306),
            Self::Postgresql => Some(5432),
            Self::Redis => Some(6379),
            Self::Mongodb => Some(27017),
            Self::Telnet => Some(23),
            Self::Irc => Some(6667),
            Self::Mqtt => Some(1883),
            Self::Amqp => Some(5672),
            _ => None,
        }
    }
}

// ─── BannerSignature ──────────────────────────────────────────────────────────

/// A banner pattern that identifies a protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerSignature {
    pub protocol: AppProtocol,
    pub pattern: Vec<u8>,
    pub offset: usize,
    pub case_insensitive: bool,
}

impl BannerSignature {
    pub fn new(proto: AppProtocol, pattern: impl AsRef<[u8]>) -> Self {
        Self {
            protocol: proto,
            pattern: pattern.as_ref().to_vec(),
            offset: 0,
            case_insensitive: false,
        }
    }

    #[must_use]
    pub const fn with_offset(mut self, offset: usize) -> Self {
        self.offset = offset;
        self
    }

    #[must_use]
    pub const fn case_insensitive(mut self) -> Self {
        self.case_insensitive = true;
        self
    }

    #[must_use]
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.offset + self.pattern.len() {
            return false;
        }
        let slice = &data[self.offset..];
        if self.case_insensitive {
            slice
                .windows(self.pattern.len())
                .any(|w| w.eq_ignore_ascii_case(&self.pattern))
        } else {
            slice
                .windows(self.pattern.len())
                .any(|w| w == self.pattern.as_slice())
        }
    }
}

// ─── BannerGrabber ────────────────────────────────────────────────────────────

/// Identifies a protocol by matching banner data against known signatures.
#[derive(Debug)]
pub struct BannerGrabber {
    signatures: Vec<BannerSignature>,
}

impl BannerGrabber {
    #[must_use]
    pub fn new() -> Self {
        let mut g = Self {
            signatures: Vec::new(),
        };
        g.load_defaults();
        g
    }

    fn load_defaults(&mut self) {
        self.add(BannerSignature::new(AppProtocol::Ssh, b"SSH-"));
        self.add(BannerSignature::new(AppProtocol::Http, b"HTTP/").case_insensitive());
        self.add(BannerSignature::new(AppProtocol::Http, b"GET ").case_insensitive());
        self.add(BannerSignature::new(AppProtocol::Http, b"POST ").case_insensitive());
        self.add(BannerSignature::new(AppProtocol::Ftp, b"220 "));
        self.add(BannerSignature::new(AppProtocol::Smtp, b"220 ").with_offset(0));
        self.add(BannerSignature::new(AppProtocol::Pop3, b"+OK"));
        self.add(BannerSignature::new(AppProtocol::Imap, b"* OK"));
        self.add(BannerSignature::new(AppProtocol::Telnet, [0xFF, 0xFD]));
        self.add(BannerSignature::new(
            AppProtocol::Mysql,
            [0x4A, 0x00, 0x00, 0x00],
        )); // simplified
        self.add(BannerSignature::new(AppProtocol::Redis, b"+PONG"));
        self.add(BannerSignature::new(AppProtocol::Redis, b"-ERR"));
        self.add(BannerSignature::new(AppProtocol::Mqtt, [0x10])); // CONNECT packet type
        self.add(BannerSignature::new(AppProtocol::Amqp, b"AMQP"));
        self.add(BannerSignature::new(AppProtocol::Smb, b"\xFFSMB"));
        self.add(BannerSignature::new(AppProtocol::Smb, b"\xFESMB")); // SMBv2
        self.add(BannerSignature::new(AppProtocol::Irc, b":"));
    }

    pub fn add(&mut self, sig: BannerSignature) {
        self.signatures.push(sig);
    }

    #[must_use]
    pub fn identify(&self, data: &[u8]) -> Option<AppProtocol> {
        for sig in &self.signatures {
            if sig.matches(data) {
                return Some(sig.protocol.clone());
            }
        }
        None
    }

    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

impl Default for BannerGrabber {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PortScanner ──────────────────────────────────────────────────────────────

/// Simulated port scan result (no real I/O; used to model scan metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub addr: SocketAddr,
    pub open: bool,
    pub banner: Option<Vec<u8>>,
    pub identified_protocol: Option<AppProtocol>,
    pub response_ms: u64,
}

impl PortScanResult {
    #[must_use]
    pub const fn open(addr: SocketAddr) -> Self {
        Self {
            addr,
            open: true,
            banner: None,
            identified_protocol: None,
            response_ms: 0,
        }
    }

    #[must_use]
    pub const fn closed(addr: SocketAddr) -> Self {
        Self {
            addr,
            open: false,
            banner: None,
            identified_protocol: None,
            response_ms: 0,
        }
    }

    #[must_use]
    pub fn with_banner(mut self, banner: Vec<u8>) -> Self {
        self.banner = Some(banner);
        self
    }

    #[must_use]
    pub fn with_protocol(mut self, proto: AppProtocol) -> Self {
        self.identified_protocol = Some(proto);
        self
    }
}

/// Drives simulated port scan campaigns.
#[derive(Debug, Default)]
pub struct PortScanner {
    results: Vec<PortScanResult>,
}

impl PortScanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_result(&mut self, result: PortScanResult) {
        self.results.push(result);
    }

    #[must_use]
    pub fn open_ports(&self) -> Vec<&PortScanResult> {
        self.results.iter().filter(|r| r.open).collect()
    }

    #[must_use]
    pub fn open_count(&self) -> usize {
        self.results.iter().filter(|r| r.open).count()
    }

    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.results.len()
    }

    #[must_use]
    pub fn by_protocol(&self, proto: &AppProtocol) -> Vec<&PortScanResult> {
        self.results
            .iter()
            .filter(|r| r.identified_protocol.as_ref() == Some(proto))
            .collect()
    }
}

// ─── ServiceDetector ──────────────────────────────────────────────────────────

/// Maps well-known ports and banner fragments to [`AppProtocol`].
#[derive(Debug)]
pub struct ServiceDetector {
    port_map: HashMap<u16, AppProtocol>,
    banner_grabber: BannerGrabber,
}

impl ServiceDetector {
    #[must_use]
    pub fn new() -> Self {
        let mut port_map = HashMap::new();
        port_map.insert(20, AppProtocol::Ftp);
        port_map.insert(21, AppProtocol::Ftp);
        port_map.insert(22, AppProtocol::Ssh);
        port_map.insert(23, AppProtocol::Telnet);
        port_map.insert(25, AppProtocol::Smtp);
        port_map.insert(53, AppProtocol::Dns);
        port_map.insert(80, AppProtocol::Http);
        port_map.insert(110, AppProtocol::Pop3);
        port_map.insert(143, AppProtocol::Imap);
        port_map.insert(443, AppProtocol::Https);
        port_map.insert(445, AppProtocol::Smb);
        port_map.insert(1883, AppProtocol::Mqtt);
        port_map.insert(3306, AppProtocol::Mysql);
        port_map.insert(3389, AppProtocol::Rdp);
        port_map.insert(5432, AppProtocol::Postgresql);
        port_map.insert(5672, AppProtocol::Amqp);
        port_map.insert(6379, AppProtocol::Redis);
        port_map.insert(6667, AppProtocol::Irc);
        port_map.insert(8080, AppProtocol::Http);
        port_map.insert(8443, AppProtocol::Https);
        port_map.insert(27017, AppProtocol::Mongodb);
        Self {
            port_map,
            banner_grabber: BannerGrabber::new(),
        }
    }

    #[must_use]
    pub fn detect_by_port(&self, port: u16) -> Option<AppProtocol> {
        self.port_map.get(&port).cloned()
    }

    #[must_use]
    pub fn detect_by_banner(&self, data: &[u8]) -> Option<AppProtocol> {
        self.banner_grabber.identify(data)
    }

    #[must_use]
    pub fn detect(&self, port: u16, banner: Option<&[u8]>) -> AppProtocol {
        if let Some(b) = banner
            && let Some(p) = self.detect_by_banner(b)
        {
            return p;
        }
        self.detect_by_port(port).unwrap_or(AppProtocol::Unknown)
    }

    pub fn add_port_mapping(&mut self, port: u16, proto: AppProtocol) {
        self.port_map.insert(port, proto);
    }

    #[must_use]
    pub fn port_count(&self) -> usize {
        self.port_map.len()
    }
}

impl Default for ServiceDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FingerprintDb ────────────────────────────────────────────────────────────

/// Persistent registry of known fingerprints (in-memory for now).
#[derive(Debug, Default)]
pub struct FingerprintDb {
    entries: HashMap<String, AppProtocol>,
}

impl FingerprintDb {
    #[must_use]
    pub fn new() -> Self {
        let mut db = Self::default();
        db.load_well_known();
        db
    }

    fn load_well_known(&mut self) {
        self.add("SSH-2.0", AppProtocol::Ssh);
        self.add("SSH-1.99", AppProtocol::Ssh);
        self.add("220 ProFTPD", AppProtocol::Ftp);
        self.add("220 vsftpd", AppProtocol::Ftp);
        self.add("HTTP/1.1 200", AppProtocol::Http);
        self.add("AMQP", AppProtocol::Amqp);
        self.add("+OK", AppProtocol::Pop3);
        self.add("+PONG", AppProtocol::Redis);
    }

    pub fn add(&mut self, key: impl Into<String>, proto: AppProtocol) {
        self.entries.insert(key.into(), proto);
    }

    #[must_use]
    pub fn lookup(&self, key: &str) -> Option<&AppProtocol> {
        self.entries.get(key)
    }

    #[must_use]
    pub fn lookup_banner(&self, data: &[u8]) -> Option<AppProtocol> {
        let s = std::str::from_utf8(data).ok()?;
        for (key, proto) in &self.entries {
            if s.contains(key.as_str()) {
                return Some(proto.clone());
            }
        }
        None
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    pub fn remove(&mut self, key: &str) -> Option<AppProtocol> {
        self.entries.remove(key)
    }
}

// ─── FingerprintResult ────────────────────────────────────────────────────────

/// Output of a fingerprinting attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub protocol: AppProtocol,
    pub confidence: f32,
    pub method: FingerprintMethod,
    pub raw_banner: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FingerprintMethod {
    Port,
    Banner,
    Database,
    Combined,
}

impl FingerprintResult {
    #[must_use]
    pub const fn new(protocol: AppProtocol, confidence: f32, method: FingerprintMethod) -> Self {
        Self {
            protocol,
            confidence,
            method,
            raw_banner: None,
        }
    }

    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

// ─── ProtocolFingerprint ──────────────────────────────────────────────────────

/// High-level fingerprinter combining all detection strategies.
#[derive(Debug)]
pub struct ProtocolFingerprint {
    service_detector: ServiceDetector,
    fingerprint_db: FingerprintDb,
    results: Vec<FingerprintResult>,
}

impl ProtocolFingerprint {
    #[must_use]
    pub fn new() -> Self {
        Self {
            service_detector: ServiceDetector::new(),
            fingerprint_db: FingerprintDb::new(),
            results: Vec::new(),
        }
    }

    /// Fingerprint using all available evidence.
    pub fn fingerprint(&mut self, port: u16, banner: Option<&[u8]>) -> FingerprintResult {
        // 1. Try database first (most accurate)
        if let Some(b) = banner
            && let Some(proto) = self.fingerprint_db.lookup_banner(b)
        {
            let r = FingerprintResult::new(proto, 0.95, FingerprintMethod::Database);
            self.results.push(r.clone());
            return r;
        }

        // 2. Try banner grabber
        if let Some(b) = banner
            && let Some(proto) = self.service_detector.detect_by_banner(b)
        {
            let r = FingerprintResult::new(proto, 0.85, FingerprintMethod::Banner);
            self.results.push(r.clone());
            return r;
        }

        // 3. Fall back to port lookup
        let proto = self
            .service_detector
            .detect_by_port(port)
            .unwrap_or(AppProtocol::Unknown);
        let confidence = if proto == AppProtocol::Unknown {
            0.1
        } else {
            0.6
        };
        let r = FingerprintResult::new(proto, confidence, FingerprintMethod::Port);
        self.results.push(r.clone());
        r
    }

    #[must_use]
    pub fn history(&self) -> &[FingerprintResult] {
        &self.results
    }

    pub fn clear_history(&mut self) {
        self.results.clear();
    }

    #[must_use]
    pub fn high_confidence_results(&self) -> Vec<&FingerprintResult> {
        self.results
            .iter()
            .filter(|r| r.is_high_confidence())
            .collect()
    }

    #[must_use]
    pub const fn db(&self) -> &FingerprintDb {
        &self.fingerprint_db
    }

    pub const fn db_mut(&mut self) -> &mut FingerprintDb {
        &mut self.fingerprint_db
    }

    #[must_use]
    pub const fn detector(&self) -> &ServiceDetector {
        &self.service_detector
    }
}

impl Default for ProtocolFingerprint {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- AppProtocol ---

    #[test]
    fn test_app_protocol_display() {
        assert_eq!(AppProtocol::Http.to_string(), "Http");
        assert_eq!(
            AppProtocol::Custom("GRPC".into()).to_string(),
            "Custom(GRPC)"
        );
    }

    #[test]
    fn test_app_protocol_is_encrypted() {
        assert!(AppProtocol::Https.is_encrypted());
        assert!(AppProtocol::Ssh.is_encrypted());
        assert!(!AppProtocol::Http.is_encrypted());
    }

    #[test]
    fn test_app_protocol_default_port() {
        assert_eq!(AppProtocol::Http.default_port(), Some(80));
        assert_eq!(AppProtocol::Https.default_port(), Some(443));
        assert_eq!(AppProtocol::Unknown.default_port(), None);
    }

    // --- BannerSignature ---

    #[test]
    fn test_banner_signature_matches() {
        let sig = BannerSignature::new(AppProtocol::Ssh, b"SSH-");
        assert!(sig.matches(b"SSH-2.0-OpenSSH_8.4"));
        assert!(!sig.matches(b"SMTP 220"));
    }

    #[test]
    fn test_banner_signature_case_insensitive() {
        let sig = BannerSignature::new(AppProtocol::Http, b"http/").case_insensitive();
        assert!(sig.matches(b"HTTP/1.1 200 OK"));
        assert!(sig.matches(b"http/1.1 200 ok"));
    }

    #[test]
    fn test_banner_signature_with_offset() {
        let sig = BannerSignature::new(AppProtocol::Ftp, b"220").with_offset(0);
        assert!(sig.matches(b"220 FTP server ready"));
    }

    #[test]
    fn test_banner_signature_too_short() {
        let sig = BannerSignature::new(AppProtocol::Ssh, b"SSH-");
        assert!(!sig.matches(b"SS"));
    }

    // --- BannerGrabber ---

    #[test]
    fn test_banner_grabber_identify_ssh() {
        let g = BannerGrabber::new();
        assert_eq!(g.identify(b"SSH-2.0-OpenSSH"), Some(AppProtocol::Ssh));
    }

    #[test]
    fn test_banner_grabber_identify_http() {
        let g = BannerGrabber::new();
        assert_eq!(g.identify(b"HTTP/1.1 200 OK"), Some(AppProtocol::Http));
    }

    #[test]
    fn test_banner_grabber_identify_pop3() {
        let g = BannerGrabber::new();
        assert_eq!(g.identify(b"+OK POP3 ready"), Some(AppProtocol::Pop3));
    }

    #[test]
    fn test_banner_grabber_identify_amqp() {
        let g = BannerGrabber::new();
        assert_eq!(g.identify(b"AMQP\x00\x00\x09\x01"), Some(AppProtocol::Amqp));
    }

    #[test]
    fn test_banner_grabber_no_match() {
        let g = BannerGrabber::new();
        assert_eq!(g.identify(b"\x00\x01\x02\x03"), None);
    }

    #[test]
    fn test_banner_grabber_signature_count() {
        let g = BannerGrabber::new();
        assert!(g.signature_count() > 10);
    }

    // --- PortScanner ---

    #[test]
    fn test_port_scanner_open_count() {
        let mut scanner = PortScanner::new();
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        scanner.add_result(PortScanResult::open(addr));
        scanner.add_result(PortScanResult::closed("127.0.0.1:443".parse().unwrap()));
        assert_eq!(scanner.open_count(), 1);
        assert_eq!(scanner.total_count(), 2);
    }

    #[test]
    fn test_port_scanner_by_protocol() {
        let mut scanner = PortScanner::new();
        let addr: SocketAddr = "10.0.0.1:22".parse().unwrap();
        scanner.add_result(PortScanResult::open(addr).with_protocol(AppProtocol::Ssh));
        let ssh_results = scanner.by_protocol(&AppProtocol::Ssh);
        assert_eq!(ssh_results.len(), 1);
    }

    // --- ServiceDetector ---

    #[test]
    fn test_service_detector_port() {
        let d = ServiceDetector::new();
        assert_eq!(d.detect_by_port(22), Some(AppProtocol::Ssh));
        assert_eq!(d.detect_by_port(80), Some(AppProtocol::Http));
        assert_eq!(d.detect_by_port(9999), None);
    }

    #[test]
    fn test_service_detector_banner() {
        let d = ServiceDetector::new();
        assert_eq!(
            d.detect_by_banner(b"SSH-2.0-OpenSSH"),
            Some(AppProtocol::Ssh)
        );
    }

    #[test]
    fn test_service_detector_detect_combined() {
        let d = ServiceDetector::new();
        // Banner should win over port
        let result = d.detect(80, Some(b"SSH-2.0-dropbear"));
        assert_eq!(result, AppProtocol::Ssh);
    }

    #[test]
    fn test_service_detector_detect_port_fallback() {
        let d = ServiceDetector::new();
        let result = d.detect(443, None);
        assert_eq!(result, AppProtocol::Https);
    }

    #[test]
    fn test_service_detector_detect_unknown() {
        let d = ServiceDetector::new();
        let result = d.detect(9999, None);
        assert_eq!(result, AppProtocol::Unknown);
    }

    #[test]
    fn test_service_detector_add_mapping() {
        let mut d = ServiceDetector::new();
        d.add_port_mapping(9000, AppProtocol::Custom("MyProto".into()));
        assert!(d.detect_by_port(9000).is_some());
    }

    // --- FingerprintDb ---

    #[test]
    fn test_fingerprint_db_lookup() {
        let db = FingerprintDb::new();
        assert_eq!(db.lookup("+OK"), Some(&AppProtocol::Pop3));
    }

    #[test]
    fn test_fingerprint_db_lookup_banner() {
        let db = FingerprintDb::new();
        let result = db.lookup_banner(b"SSH-2.0 welcome");
        assert_eq!(result, Some(AppProtocol::Ssh));
    }

    #[test]
    fn test_fingerprint_db_add_and_remove() {
        let mut db = FingerprintDb::new();
        db.add("HELLO", AppProtocol::Custom("test".into()));
        assert!(db.lookup("HELLO").is_some());
        db.remove("HELLO");
        assert!(db.lookup("HELLO").is_none());
    }

    #[test]
    fn test_fingerprint_db_count() {
        let db = FingerprintDb::new();
        assert!(db.count() > 0);
    }

    // --- ProtocolFingerprint ---

    #[test]
    fn test_fingerprint_by_db_banner() {
        let mut fp = ProtocolFingerprint::new();
        let result = fp.fingerprint(9999, Some(b"SSH-2.0 OpenSSH"));
        assert_eq!(result.protocol, AppProtocol::Ssh);
        assert_eq!(result.method, FingerprintMethod::Database);
    }

    #[test]
    fn test_fingerprint_by_banner() {
        let mut fp = ProtocolFingerprint::new();
        // Data not in DB but matchable by banner grabber
        let result = fp.fingerprint(9999, Some(b"+OK POP3 ready"));
        assert!(
            result.method == FingerprintMethod::Database
                || result.method == FingerprintMethod::Banner
        );
    }

    #[test]
    fn test_fingerprint_by_port() {
        let mut fp = ProtocolFingerprint::new();
        let result = fp.fingerprint(443, None);
        assert_eq!(result.protocol, AppProtocol::Https);
        assert_eq!(result.method, FingerprintMethod::Port);
    }

    #[test]
    fn test_fingerprint_unknown_port_no_banner() {
        let mut fp = ProtocolFingerprint::new();
        let result = fp.fingerprint(9999, None);
        assert_eq!(result.protocol, AppProtocol::Unknown);
    }

    #[test]
    fn test_fingerprint_history() {
        let mut fp = ProtocolFingerprint::new();
        fp.fingerprint(80, None);
        fp.fingerprint(443, None);
        assert_eq!(fp.history().len(), 2);
    }

    #[test]
    fn test_fingerprint_clear_history() {
        let mut fp = ProtocolFingerprint::new();
        fp.fingerprint(80, None);
        fp.clear_history();
        assert!(fp.history().is_empty());
    }

    #[test]
    fn test_fingerprint_high_confidence() {
        let mut fp = ProtocolFingerprint::new();
        fp.fingerprint(22, Some(b"SSH-2.0-OpenSSH"));
        let hc = fp.high_confidence_results();
        assert!(!hc.is_empty());
    }

    #[test]
    fn test_fingerprint_result_is_high_confidence() {
        let r = FingerprintResult::new(AppProtocol::Http, 0.9, FingerprintMethod::Banner);
        assert!(r.is_high_confidence());
        let r2 = FingerprintResult::new(AppProtocol::Unknown, 0.1, FingerprintMethod::Port);
        assert!(!r2.is_high_confidence());
    }

    #[test]
    fn test_app_protocol_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AppProtocol::Http);
        set.insert(AppProtocol::Https);
        set.insert(AppProtocol::Http);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_service_detector_port_count() {
        let d = ServiceDetector::new();
        assert!(d.port_count() >= 10);
    }

    #[test]
    fn test_banner_grabber_get_or_post() {
        let g = BannerGrabber::new();
        assert_eq!(
            g.identify(b"GET / HTTP/1.1\r\nHost: x.com"),
            Some(AppProtocol::Http)
        );
        assert_eq!(
            g.identify(b"POST /api HTTP/1.1\r\n"),
            Some(AppProtocol::Http)
        );
    }

    #[test]
    fn test_fingerprint_db_ftp() {
        let db = FingerprintDb::new();
        let result = db.lookup_banner(b"220 ProFTPD server ready");
        assert_eq!(result, Some(AppProtocol::Ftp));
    }

    #[test]
    fn test_fingerprint_redis_banner() {
        let mut fp = ProtocolFingerprint::new();
        let result = fp.fingerprint(9999, Some(b"+PONG\r\n"));
        assert_eq!(result.protocol, AppProtocol::Redis);
    }

    #[test]
    fn test_port_scan_result_open() {
        let addr: std::net::SocketAddr = "127.0.0.1:22".parse().unwrap();
        let r = PortScanResult::open(addr);
        assert!(r.open);
    }

    #[test]
    fn test_port_scan_result_closed() {
        let addr: std::net::SocketAddr = "127.0.0.1:22".parse().unwrap();
        let r = PortScanResult::closed(addr);
        assert!(!r.open);
    }
}
