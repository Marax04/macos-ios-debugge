//! Network protocol fingerprinting from packet payload bytes.
//!
//! Identifies the application-layer protocol in use (HTTP, TLS, DNS, SMB, …)
//! by matching the leading bytes of the payload against a bank of
//! [`PayloadPattern`]s.  Each pattern carries confidence and metadata so that
//! callers can pick the best match or inspect all candidates.

use std::fmt;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Detected protocol ─────────────────────────────────────────────────────────

/// Application-layer protocol identified by the fingerprinter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectedProtocol {
    Http,
    Https,
    Tls,
    Dns,
    DnsOverTls,
    Smb,
    Smb2,
    Ftp,
    FtpData,
    Ssh,
    Smtp,
    Pop3,
    Imap,
    Rdp,
    Irc,
    Telnet,
    Mqtt,
    Memcached,
    Redis,
    Mysql,
    Postgres,
    Ldap,
    Kerberos,
    NetBios,
    Modbus,
    Dnp3,
    Unknown,
}

impl fmt::Display for DetectedProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Http       => "HTTP",
            Self::Https      => "HTTPS",
            Self::Tls        => "TLS",
            Self::Dns        => "DNS",
            Self::DnsOverTls => "DNS-over-TLS",
            Self::Smb        => "SMB",
            Self::Smb2       => "SMB2",
            Self::Ftp        => "FTP",
            Self::FtpData    => "FTP-Data",
            Self::Ssh        => "SSH",
            Self::Smtp       => "SMTP",
            Self::Pop3       => "POP3",
            Self::Imap       => "IMAP",
            Self::Rdp        => "RDP",
            Self::Irc        => "IRC",
            Self::Telnet     => "Telnet",
            Self::Mqtt       => "MQTT",
            Self::Memcached  => "Memcached",
            Self::Redis      => "Redis",
            Self::Mysql      => "MySQL",
            Self::Postgres   => "PostgreSQL",
            Self::Ldap       => "LDAP",
            Self::Kerberos   => "Kerberos",
            Self::NetBios    => "NetBIOS",
            Self::Modbus     => "Modbus",
            Self::Dnp3       => "DNP3",
            Self::Unknown    => "Unknown",
        };
        f.write_str(s)
    }
}

// ── Pattern match kind ────────────────────────────────────────────────────────

/// How a [`PayloadPattern`] matches the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchKind {
    /// The payload must start with the given bytes.
    Prefix(Vec<u8>),
    /// The payload must contain the given bytes at the given offset.
    AtOffset { offset: usize, bytes: Vec<u8> },
    /// The payload must contain the given bytes anywhere within the first
    /// `scan_limit` bytes.
    Contains { bytes: Vec<u8>, scan_limit: usize },
    /// The payload must contain the ASCII string prefix (case-insensitive).
    AsciiPrefix(String),
    /// Combination: all sub-patterns must match.
    All(Vec<Self>),
    /// Combination: any sub-pattern must match.
    Any(Vec<Self>),
}

impl MatchKind {
    /// Evaluate this match kind against `payload`.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        match self {
            Self::Prefix(bytes) => payload.starts_with(bytes),
            Self::AtOffset { offset, bytes } => {
                if *offset + bytes.len() > payload.len() {
                    return false;
                }
                &payload[*offset..*offset + bytes.len()] == bytes.as_slice()
            }
            Self::Contains { bytes, scan_limit } => {
                let limit = (*scan_limit).min(payload.len());
                if bytes.len() > limit {
                    return false;
                }
                payload[..limit].windows(bytes.len()).any(|w| w == bytes.as_slice())
            }
            Self::AsciiPrefix(s) => {
                if payload.len() < s.len() {
                    return false;
                }
                payload[..s.len()].eq_ignore_ascii_case(s.as_bytes())
            }
            Self::All(sub) => sub.iter().all(|p| p.matches(payload)),
            Self::Any(sub) => sub.iter().any(|p| p.matches(payload)),
        }
    }
}

// ── Payload pattern ───────────────────────────────────────────────────────────

/// A named pattern used to fingerprint a protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadPattern {
    /// Human-readable name for this pattern.
    pub name: String,
    /// The protocol this pattern identifies.
    pub protocol: DetectedProtocol,
    /// Matching logic.
    pub kind: MatchKind,
    /// Expected transport-layer port (0 = any).
    pub default_port: u16,
    /// Confidence score [0, 100] when this pattern matches.
    pub confidence: u8,
    /// Minimum payload length required for this pattern to be attempted.
    pub min_payload_len: usize,
}

impl PayloadPattern {
    /// Build a new pattern.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        protocol: DetectedProtocol,
        kind: MatchKind,
        default_port: u16,
        confidence: u8,
    ) -> Self {
        Self {
            name: name.into(),
            protocol,
            kind,
            default_port,
            confidence,
            min_payload_len: 0,
        }
    }

    /// Set the minimum payload length required.
    #[must_use]
    pub const fn with_min_len(mut self, n: usize) -> Self {
        self.min_payload_len = n;
        self
    }

    /// Returns `true` if this pattern matches the given payload.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        if payload.len() < self.min_payload_len {
            return false;
        }
        self.kind.matches(payload)
    }
}

// ── Protocol match result ─────────────────────────────────────────────────────

/// A single fingerprint match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMatch {
    /// The protocol that was identified.
    pub protocol: DetectedProtocol,
    /// The pattern that produced this match.
    pub pattern_name: String,
    /// Confidence score adjusted for port alignment [0, 100].
    pub confidence: u8,
    /// Whether the observed transport port matches the protocol default.
    pub port_aligned: bool,
}

impl ProtocolMatch {
    /// Return a short description of this match.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} via '{}' (confidence={}, port_aligned={})",
            self.protocol, self.pattern_name, self.confidence, self.port_aligned
        )
    }
}

// ── Protocol fingerprinter ────────────────────────────────────────────────────

/// Identifies the application-layer protocol of a packet payload by matching
/// against a configurable bank of [`PayloadPattern`]s.
///
/// The built-in pattern bank covers 20+ common protocols.  Call
/// [`ProtocolFingerprinter::with_defaults`] to initialise from the built-in
/// patterns, or [`ProtocolFingerprinter::new`] for an empty bank.
pub struct ProtocolFingerprinter {
    patterns: Vec<PayloadPattern>,
}

impl ProtocolFingerprinter {
    /// Create an empty fingerprinter.
    #[must_use]
    pub const fn new() -> Self {
        Self { patterns: Vec::new() }
    }

    /// Create a fingerprinter pre-loaded with the built-in pattern bank.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut fp = Self::new();
        fp.load_defaults();
        fp
    }

    /// Add a custom pattern.
    pub fn add_pattern(&mut self, pattern: PayloadPattern) {
        self.patterns.push(pattern);
    }

    /// Fingerprint the given payload and return ALL matching results, sorted by
    /// confidence descending.
    ///
    /// `dst_port` is used to boost confidence when it matches the protocol
    /// default port.
    #[must_use]
    pub fn fingerprint(&self, payload: &[u8], dst_port: u16) -> Vec<ProtocolMatch> {
        let mut results: Vec<ProtocolMatch> = self
            .patterns
            .iter()
            .filter(|p| p.matches(payload))
            .map(|p| {
                let port_aligned = p.default_port != 0 && p.default_port == dst_port;
                let confidence = if port_aligned {
                    p.confidence.saturating_add(10).min(100)
                } else if p.default_port != 0 && dst_port != 0 {
                    p.confidence.saturating_sub(5)
                } else {
                    p.confidence
                };
                ProtocolMatch {
                    protocol: p.protocol,
                    pattern_name: p.name.clone(),
                    confidence,
                    port_aligned,
                }
            })
            .collect();

        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Return the best (highest confidence) match, or `None` if no pattern
    /// matches.
    #[must_use]
    pub fn best_match(&self, payload: &[u8], dst_port: u16) -> Option<ProtocolMatch> {
        self.fingerprint(payload, dst_port).into_iter().next()
    }

    /// Return the detected protocol, or [`DetectedProtocol::Unknown`].
    #[must_use]
    pub fn detect(&self, payload: &[u8], dst_port: u16) -> DetectedProtocol {
        self.best_match(payload, dst_port)
            .map_or(DetectedProtocol::Unknown, |m| m.protocol)
    }

    /// Return `true` if any pattern matches the payload above the given
    /// confidence threshold.
    #[must_use]
    pub fn is_above_threshold(&self, payload: &[u8], dst_port: u16, threshold: u8) -> bool {
        self.fingerprint(payload, dst_port)
            .iter()
            .any(|m| m.confidence >= threshold)
    }

    /// Return the number of patterns loaded.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Return patterns grouped by protocol.
    #[must_use]
    pub fn patterns_by_protocol(&self) -> HashMap<String, Vec<&PayloadPattern>> {
        let mut map: HashMap<String, Vec<&PayloadPattern>> = HashMap::new();
        for p in &self.patterns {
            map.entry(p.protocol.to_string()).or_default().push(p);
        }
        map
    }

    // ── Built-in pattern bank ─────────────────────────────────────────────────

    fn load_defaults(&mut self) {
        // HTTP request methods
        self.add_pattern(
            PayloadPattern::new("http-get",    DetectedProtocol::Http, MatchKind::AsciiPrefix("GET ".to_string()), 80, 90)
                .with_min_len(4),
        );
        self.add_pattern(
            PayloadPattern::new("http-post",   DetectedProtocol::Http, MatchKind::AsciiPrefix("POST ".to_string()), 80, 90)
                .with_min_len(5),
        );
        self.add_pattern(
            PayloadPattern::new("http-head",   DetectedProtocol::Http, MatchKind::AsciiPrefix("HEAD ".to_string()), 80, 85)
                .with_min_len(5),
        );
        self.add_pattern(
            PayloadPattern::new("http-put",    DetectedProtocol::Http, MatchKind::AsciiPrefix("PUT ".to_string()), 80, 85)
                .with_min_len(4),
        );
        self.add_pattern(
            PayloadPattern::new("http-delete", DetectedProtocol::Http, MatchKind::AsciiPrefix("DELETE ".to_string()), 80, 85)
                .with_min_len(7),
        );
        self.add_pattern(
            PayloadPattern::new("http-options",DetectedProtocol::Http, MatchKind::AsciiPrefix("OPTIONS ".to_string()), 80, 80)
                .with_min_len(8),
        );
        self.add_pattern(
            PayloadPattern::new("http-response",DetectedProtocol::Http, MatchKind::AsciiPrefix("HTTP/1.".to_string()), 80, 90)
                .with_min_len(7),
        );
        self.add_pattern(
            PayloadPattern::new("http2-preface",DetectedProtocol::Http, MatchKind::Prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()), 80, 95)
                .with_min_len(24),
        );

        // TLS/SSL ClientHello: byte 0 = 0x16 (handshake), byte 1 = 0x03 (version major)
        self.add_pattern(
            PayloadPattern::new("tls-clienthello", DetectedProtocol::Tls,
                MatchKind::All(vec![
                    MatchKind::AtOffset { offset: 0, bytes: vec![0x16] },
                    MatchKind::AtOffset { offset: 1, bytes: vec![0x03] },
                    MatchKind::AtOffset { offset: 5, bytes: vec![0x01] },
                ]),
                443, 95).with_min_len(6),
        );
        self.add_pattern(
            PayloadPattern::new("tls-alert", DetectedProtocol::Tls,
                MatchKind::All(vec![
                    MatchKind::AtOffset { offset: 0, bytes: vec![0x15] },
                    MatchKind::AtOffset { offset: 1, bytes: vec![0x03] },
                ]),
                443, 80).with_min_len(3),
        );
        self.add_pattern(
            PayloadPattern::new("tls-appdata", DetectedProtocol::Tls,
                MatchKind::All(vec![
                    MatchKind::AtOffset { offset: 0, bytes: vec![0x17] },
                    MatchKind::AtOffset { offset: 1, bytes: vec![0x03] },
                ]),
                443, 75).with_min_len(3),
        );

        // DNS: transaction ID (2 bytes) + flags (QR=0 for query), standard query
        // We match on the DNS question section marker bytes.
        self.add_pattern(
            PayloadPattern::new("dns-query", DetectedProtocol::Dns,
                MatchKind::All(vec![
                    // Flags high byte: bit 7 = 0 (query), bits 3-6 = 0 (QUERY opcode)
                    MatchKind::AtOffset { offset: 2, bytes: vec![0x01] }, // RD flag set
                    // QDCOUNT >= 1
                    MatchKind::AtOffset { offset: 4, bytes: vec![0x00] },
                    MatchKind::AtOffset { offset: 5, bytes: vec![0x01] },
                ]),
                53, 70).with_min_len(12),
        );
        self.add_pattern(
            PayloadPattern::new("dns-response", DetectedProtocol::Dns,
                MatchKind::All(vec![
                    MatchKind::AtOffset { offset: 2, bytes: vec![0x81] }, // QR=1, RD=1
                ]),
                53, 65).with_min_len(12),
        );

        // SMB1: \xFFSMB
        self.add_pattern(
            PayloadPattern::new("smb1", DetectedProtocol::Smb,
                MatchKind::Prefix(b"\xFFSMB".to_vec()),
                445, 95).with_min_len(4),
        );
        // SMB2: \xFESMB
        self.add_pattern(
            PayloadPattern::new("smb2", DetectedProtocol::Smb2,
                MatchKind::Prefix(b"\xFESMB".to_vec()),
                445, 95).with_min_len(4),
        );
        // SMB3 (negotiated): same magic as SMB2
        self.add_pattern(
            PayloadPattern::new("smb3", DetectedProtocol::Smb2,
                MatchKind::Prefix(b"\xFESMB".to_vec()),
                445, 90).with_min_len(4),
        );

        // FTP server greeting
        self.add_pattern(
            PayloadPattern::new("ftp-greeting", DetectedProtocol::Ftp,
                MatchKind::AsciiPrefix("220 ".to_string()),
                21, 90).with_min_len(4),
        );
        self.add_pattern(
            PayloadPattern::new("ftp-user",  DetectedProtocol::Ftp,
                MatchKind::AsciiPrefix("USER ".to_string()),
                21, 85).with_min_len(5),
        );
        self.add_pattern(
            PayloadPattern::new("ftp-pass",  DetectedProtocol::Ftp,
                MatchKind::AsciiPrefix("PASS ".to_string()),
                21, 85).with_min_len(5),
        );

        // SSH banner
        self.add_pattern(
            PayloadPattern::new("ssh-banner", DetectedProtocol::Ssh,
                MatchKind::AsciiPrefix("SSH-".to_string()),
                22, 98).with_min_len(4),
        );

        // SMTP greeting / commands
        self.add_pattern(
            PayloadPattern::new("smtp-greeting", DetectedProtocol::Smtp,
                MatchKind::AsciiPrefix("220 ".to_string()),
                25, 75).with_min_len(4),
        );
        self.add_pattern(
            PayloadPattern::new("smtp-ehlo", DetectedProtocol::Smtp,
                MatchKind::AsciiPrefix("EHLO ".to_string()),
                25, 90).with_min_len(5),
        );
        self.add_pattern(
            PayloadPattern::new("smtp-helo", DetectedProtocol::Smtp,
                MatchKind::AsciiPrefix("HELO ".to_string()),
                25, 90).with_min_len(5),
        );

        // POP3
        self.add_pattern(
            PayloadPattern::new("pop3-ok", DetectedProtocol::Pop3,
                MatchKind::AsciiPrefix("+OK".to_string()),
                110, 80).with_min_len(3),
        );

        // IMAP
        self.add_pattern(
            PayloadPattern::new("imap-greeting", DetectedProtocol::Imap,
                MatchKind::AsciiPrefix("* OK".to_string()),
                143, 80).with_min_len(4),
        );

        // RDP: x.224 CRPDU
        self.add_pattern(
            PayloadPattern::new("rdp", DetectedProtocol::Rdp,
                MatchKind::AtOffset { offset: 1, bytes: vec![0xE0] },
                3389, 70).with_min_len(4),
        );

        // IRC
        self.add_pattern(
            PayloadPattern::new("irc-nick",  DetectedProtocol::Irc,
                MatchKind::AsciiPrefix("NICK ".to_string()),
                6667, 85).with_min_len(5),
        );
        self.add_pattern(
            PayloadPattern::new("irc-privmsg", DetectedProtocol::Irc,
                MatchKind::Contains { bytes: b"PRIVMSG ".to_vec(), scan_limit: 512 },
                6667, 80).with_min_len(8),
        );

        // MQTT CONNECT
        self.add_pattern(
            PayloadPattern::new("mqtt-connect", DetectedProtocol::Mqtt,
                MatchKind::All(vec![
                    MatchKind::AtOffset { offset: 0, bytes: vec![0x10] },  // CONNECT
                    MatchKind::Contains { bytes: b"MQTT".to_vec(), scan_limit: 16 },
                ]),
                1883, 90).with_min_len(6),
        );

        // Memcached: text protocol
        self.add_pattern(
            PayloadPattern::new("memcached-get", DetectedProtocol::Memcached,
                MatchKind::AsciiPrefix("get ".to_string()),
                11211, 85).with_min_len(4),
        );
        self.add_pattern(
            PayloadPattern::new("memcached-set", DetectedProtocol::Memcached,
                MatchKind::AsciiPrefix("set ".to_string()),
                11211, 80).with_min_len(4),
        );

        // Redis inline commands
        self.add_pattern(
            PayloadPattern::new("redis-inline", DetectedProtocol::Redis,
                MatchKind::AsciiPrefix("PING".to_string()),
                6379, 85).with_min_len(4),
        );
        self.add_pattern(
            PayloadPattern::new("redis-resp", DetectedProtocol::Redis,
                MatchKind::Prefix(b"*".to_vec()),
                6379, 70).with_min_len(1),
        );

        // MySQL: server greeting (starts with length bytes then protocol version 10)
        self.add_pattern(
            PayloadPattern::new("mysql-greeting", DetectedProtocol::Mysql,
                MatchKind::AtOffset { offset: 4, bytes: vec![0x0A] },
                3306, 75).with_min_len(5),
        );

        // Postgres startup: length (4 bytes, big-endian) + protocol version
        self.add_pattern(
            PayloadPattern::new("postgres-startup", DetectedProtocol::Postgres,
                MatchKind::AtOffset { offset: 4, bytes: vec![0x00, 0x03] },
                5432, 70).with_min_len(6),
        );

        // LDAP: SEQUENCE tag 0x30
        self.add_pattern(
            PayloadPattern::new("ldap", DetectedProtocol::Ldap,
                MatchKind::Prefix(b"\x30".to_vec()),
                389, 50).with_min_len(4),
        );

        // NetBIOS session service
        self.add_pattern(
            PayloadPattern::new("netbios", DetectedProtocol::NetBios,
                MatchKind::AtOffset { offset: 0, bytes: vec![0x00] },
                139, 55).with_min_len(4),
        );

        // Modbus ADU: transaction ID followed by 0x00 0x00 (protocol ID)
        self.add_pattern(
            PayloadPattern::new("modbus", DetectedProtocol::Modbus,
                MatchKind::AtOffset { offset: 2, bytes: vec![0x00, 0x00] },
                502, 65).with_min_len(8),
        );
    }
}

impl Default for ProtocolFingerprinter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl fmt::Debug for ProtocolFingerprinter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolFingerprinter")
            .field("pattern_count", &self.patterns.len())
            .finish()
    }
}

// ── Convenience functions ─────────────────────────────────────────────────────

/// Fingerprint the given payload bytes against the built-in pattern bank.
///
/// Returns the best [`ProtocolMatch`], or `None` when no pattern matches.
#[must_use]
pub fn fingerprint_payload(payload: &[u8], dst_port: u16) -> Option<ProtocolMatch> {
    ProtocolFingerprinter::with_defaults().best_match(payload, dst_port)
}

/// Quick protocol detection returning just the [`DetectedProtocol`].
#[must_use]
pub fn detect_protocol(payload: &[u8], dst_port: u16) -> DetectedProtocol {
    ProtocolFingerprinter::with_defaults().detect(payload, dst_port)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fp() -> ProtocolFingerprinter {
        ProtocolFingerprinter::with_defaults()
    }

    #[test]
    fn test_http_get() {
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(fp().detect(payload, 80), DetectedProtocol::Http);
    }

    #[test]
    fn test_http_post() {
        let payload = b"POST /api HTTP/1.1\r\n";
        assert_eq!(fp().detect(payload, 80), DetectedProtocol::Http);
    }

    #[test]
    fn test_http_response() {
        let payload = b"HTTP/1.1 200 OK\r\n";
        assert_eq!(fp().detect(payload, 80), DetectedProtocol::Http);
    }

    #[test]
    fn test_tls_clienthello() {
        // type=0x16, major=0x03, minor=0x03, len(2), HandshakeType=0x01
        let payload = &[0x16u8, 0x03, 0x03, 0x00, 0x50, 0x01, 0x00, 0x00, 0x4C];
        assert_eq!(fp().detect(payload, 443), DetectedProtocol::Tls);
    }

    #[test]
    fn test_smb1() {
        let payload = b"\xFFSMB\x72\x00\x00\x00\x00";
        assert_eq!(fp().detect(payload, 445), DetectedProtocol::Smb);
    }

    #[test]
    fn test_smb2() {
        let payload = b"\xFESMB\x40\x00\x00\x00";
        assert_eq!(fp().detect(payload, 445), DetectedProtocol::Smb2);
    }

    #[test]
    fn test_ssh_banner() {
        let payload = b"SSH-2.0-OpenSSH_8.9p1\r\n";
        assert_eq!(fp().detect(payload, 22), DetectedProtocol::Ssh);
    }

    #[test]
    fn test_smtp_ehlo() {
        let payload = b"EHLO mail.example.com\r\n";
        assert_eq!(fp().detect(payload, 25), DetectedProtocol::Smtp);
    }

    #[test]
    fn test_ftp_greeting() {
        let payload = b"220 FTP server ready\r\n";
        // FTP and SMTP both match 220, but FTP port 21 is checked.
        let matches = fp().fingerprint(payload, 21);
        assert!(matches.iter().any(|m| m.protocol == DetectedProtocol::Ftp));
    }

    #[test]
    fn test_pop3_ok() {
        let payload = b"+OK POP3 server ready\r\n";
        assert_eq!(fp().detect(payload, 110), DetectedProtocol::Pop3);
    }

    #[test]
    fn test_imap_greeting() {
        let payload = b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n";
        assert_eq!(fp().detect(payload, 143), DetectedProtocol::Imap);
    }

    #[test]
    fn test_irc_nick() {
        let payload = b"NICK testuser\r\n";
        assert_eq!(fp().detect(payload, 6667), DetectedProtocol::Irc);
    }

    #[test]
    fn test_redis_ping() {
        let payload = b"PING\r\n";
        assert_eq!(fp().detect(payload, 6379), DetectedProtocol::Redis);
    }

    #[test]
    fn test_memcached_get() {
        let payload = b"get mykey\r\n";
        assert_eq!(fp().detect(payload, 11211), DetectedProtocol::Memcached);
    }

    #[test]
    fn test_unknown_payload() {
        let payload = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        // Should not confidently match anything meaningful.
        let matches = fp().fingerprint(payload, 9999);
        let high_confidence = matches.iter().any(|m| m.confidence > 80);
        assert!(!high_confidence);
    }

    #[test]
    fn test_all_matches_returned() {
        // FTP 220 and SMTP 220 both match the greeting pattern.
        let payload = b"220 Service ready\r\n";
        let matches = fp().fingerprint(payload, 0);
        assert!(matches.len() >= 2, "expected multiple protocol candidates");
    }

    #[test]
    fn test_port_aligned_boost() {
        let payload = b"GET / HTTP/1.1\r\n";
        let aligned   = fp().fingerprint(payload, 80);
        let unaligned = fp().fingerprint(payload, 9999);
        let conf_aligned   = aligned.first().map_or(0, |m| m.confidence);
        let conf_unaligned = unaligned.first().map_or(0, |m| m.confidence);
        assert!(conf_aligned >= conf_unaligned);
    }

    #[test]
    fn test_best_match_returns_highest() {
        let payload = b"GET / HTTP/1.1\r\n";
        let best = fp().best_match(payload, 80).unwrap();
        let all = fp().fingerprint(payload, 80);
        assert_eq!(best.confidence, all[0].confidence);
    }

    #[test]
    fn test_pattern_count() {
        let fp = ProtocolFingerprinter::with_defaults();
        assert!(fp.pattern_count() >= 20);
    }

    #[test]
    fn test_fingerprint_payload_convenience() {
        let payload = b"SSH-2.0-libssh2_1.10.0\r\n";
        let result = fingerprint_payload(payload, 22);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, DetectedProtocol::Ssh);
    }

    #[test]
    fn test_custom_pattern() {
        let mut fp = ProtocolFingerprinter::new();
        fp.add_pattern(PayloadPattern::new(
            "my-protocol",
            DetectedProtocol::Unknown,
            MatchKind::Prefix(b"MYPROTO".to_vec()),
            9999,
            99,
        ).with_min_len(7));
        let result = fp.detect(b"MYPROTO hello", 9999);
        assert_eq!(result, DetectedProtocol::Unknown);
    }

    #[test]
    fn test_detect_protocol_convenience() {
        assert_eq!(detect_protocol(b"SSH-2.0-OpenSSH", 22), DetectedProtocol::Ssh);
    }
}
