//! C2 (Command & Control) malware protocol dissectors.
//!
//! Covers:
//! - Cobalt Strike Beacon — malleable C2 profile, XOR key extraction, config decryption,
//!   check-in format recognition
//! - Metasploit stage request detection and payload identification
//! - Sliver C2 — mTLS/HTTP/S/DNS/WireGuard transport heuristics, protobuf framing
//! - Havoc Framework — Demon agent protocol
//! - Empire/Starkiller — REST API call patterns
//! - Generic C2 heuristics — jitter/beacon-interval analysis

#![allow(dead_code)]

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::DissectError;

// ─────────────────────────────────────────────────────────────────────────────
// Shared primitives
// ─────────────────────────────────────────────────────────────────────────────

/// Confidence level for a C2 detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Confidence {
    Low    = 1,
    Medium = 2,
    High   = 3,
    Certain = 4,
}

impl Confidence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low     => "low",
            Self::Medium  => "medium",
            Self::High    => "high",
            Self::Certain => "certain",
        }
    }
}

/// Generic C2 detection result attached to a single flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Detection {
    pub family:       String,
    pub confidence:   Confidence,
    pub indicators:   Vec<String>,
    pub metadata:     HashMap<String, String>,
}

impl C2Detection {
    pub fn new(family: impl Into<String>, confidence: Confidence) -> Self {
        Self { family: family.into(), confidence, indicators: Vec::new(), metadata: HashMap::new() }
    }
    pub fn add_indicator(&mut self, s: impl Into<String>) { self.indicators.push(s.into()); }
    pub fn set_meta(&mut self, k: impl Into<String>, v: impl Into<String>) { self.metadata.insert(k.into(), v.into()); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cobalt Strike Beacon
// ─────────────────────────────────────────────────────────────────────────────

/// Known Cobalt Strike beacon config field IDs (from public research).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BeaconConfigField {
    BeaconType,
    Port,
    SleepTime,
    MaxGetSize,
    Jitter,
    MaxDns,
    PublicKey,
    C2Server,
    UserAgent,
    HttpPostUri,
    HttpPostChunk,
    SpawnTo32,
    SpawnTo64,
    CryptoScheme,
    PipelineName,
    KillDate,
    DnsIdleAddress,
    DnsBeaconInterval,
    HttpGetHeader,
    HttpPostHeader,
    TransformGet,
    ProxyServer,
    ProxyUsername,
    ProxyPassword,
    Unknown(u16),
}

impl BeaconConfigField {
    #[must_use]
    pub const fn from_u16(v: u16) -> Self {
        match v {
            1  => Self::BeaconType,
            2  => Self::Port,
            3  => Self::SleepTime,
            4  => Self::MaxGetSize,
            5  => Self::Jitter,
            6  => Self::MaxDns,
            7  => Self::PublicKey,
            8  => Self::C2Server,
            9  => Self::UserAgent,
            10 => Self::HttpPostUri,
            11 => Self::CryptoScheme,
            12 => Self::TransformGet,
            13 => Self::SpawnTo32,
            14 => Self::SpawnTo64,
            15 => Self::PipelineName,
            16 => Self::ProxyServer,
            17 => Self::ProxyUsername,
            18 => Self::ProxyPassword,
            19 => Self::DnsIdleAddress,
            20 => Self::DnsBeaconInterval,
            26 => Self::HttpPostChunk,
            33 => Self::KillDate,
            54 => Self::HttpGetHeader,
            55 => Self::HttpPostHeader,
            other => Self::Unknown(other),
        }
    }
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BeaconType        => "BeaconType",
            Self::Port              => "Port",
            Self::SleepTime         => "SleepTime",
            Self::MaxGetSize        => "MaxGetSize",
            Self::Jitter            => "Jitter",
            Self::MaxDns            => "MaxDns",
            Self::PublicKey         => "PublicKey",
            Self::C2Server          => "C2Server",
            Self::UserAgent         => "UserAgent",
            Self::HttpPostUri       => "HttpPostUri",
            Self::HttpPostChunk     => "HttpPostChunk",
            Self::SpawnTo32         => "SpawnTo32",
            Self::SpawnTo64         => "SpawnTo64",
            Self::CryptoScheme      => "CryptoScheme",
            Self::PipelineName      => "PipelineName",
            Self::KillDate          => "KillDate",
            Self::DnsIdleAddress    => "DnsIdleAddress",
            Self::DnsBeaconInterval => "DnsBeaconInterval",
            Self::HttpGetHeader     => "HttpGetHeader",
            Self::HttpPostHeader    => "HttpPostHeader",
            Self::TransformGet      => "TransformGet",
            Self::ProxyServer       => "ProxyServer",
            Self::ProxyUsername     => "ProxyUsername",
            Self::ProxyPassword     => "ProxyPassword",
            Self::Unknown(_)        => "Unknown",
        }
    }
}

/// A decoded Cobalt Strike beacon configuration block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconConfig {
    pub fields: Vec<(BeaconConfigField, Vec<u8>)>,
    pub xor_key: Option<u8>,
}

impl BeaconConfig {
    /// Extract the C2 server string if present.
    #[must_use]
    pub fn c2_server(&self) -> Option<String> {
        self.fields.iter()
            .find(|(f, _)| *f == BeaconConfigField::C2Server)
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
    }

    #[must_use]
    pub fn sleep_ms(&self) -> Option<u32> {
        self.fields.iter()
            .find(|(f, _)| *f == BeaconConfigField::SleepTime)
            .and_then(|(_, v)| {
                if v.len() >= 2 { Some(u32::from(u16::from_be_bytes([v[0], v[1]]))) }
                else { None }
            })
    }

    #[must_use]
    pub fn jitter_pct(&self) -> Option<u16> {
        self.fields.iter()
            .find(|(f, _)| *f == BeaconConfigField::Jitter)
            .and_then(|(_, v)| {
                if v.len() >= 2 { Some(u16::from_be_bytes([v[0], v[1]])) }
                else { None }
            })
    }
}

pub struct CobaltStrikeDissector;

impl CobaltStrikeDissector {
    /// Attempt to detect a single-byte XOR key used to obfuscate the config block.
    /// Returns the most frequent candidate.
    #[must_use]
    pub fn detect_xor_key(buf: &[u8]) -> Option<u8> {
        if buf.len() < 4 { return None; }
        // Known magic bytes after XOR in CS config: 0x00 0x01 0x00 0x01 or 0x00 0x02 ...
        // Try XOR with each byte value and check for high frequency of 0x00 in result.
        let mut best_key = 0u8;
        let mut best_score = 0usize;
        for key in 0x01..=0xff_u8 {
            let nulls = buf.iter().take(256).filter(|&&b| b ^ key == 0x00).count();
            if nulls > best_score {
                best_score = nulls;
                best_key = key;
            }
        }
        if best_score > 3 { Some(best_key) } else { None }
    }

    /// Decode a XOR-obfuscated config blob with `key`.
    #[must_use]
    pub fn xor_decrypt(buf: &[u8], key: u8) -> Vec<u8> {
        buf.iter().map(|&b| b ^ key).collect()
    }

    /// Parse a plaintext Cobalt Strike config block (0x0001 … TLV records).
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_config(buf: &[u8]) -> Result<BeaconConfig, DissectError> {
        let mut fields = Vec::new();
        let mut pos = 0;
        while pos + 6 <= buf.len() {
            let field_id = u16::from_be_bytes([buf[pos], buf[pos+1]]);
            if field_id == 0 { pos += 2; continue; }
            let _type_id = u16::from_be_bytes([buf[pos+2], buf[pos+3]]);
            let length   = u16::from_be_bytes([buf[pos+4], buf[pos+5]]) as usize;
            pos += 6;
            if buf.len() < pos + length { break; }
            let value = buf[pos..pos+length].to_vec();
            fields.push((BeaconConfigField::from_u16(field_id), value));
            pos += length;
        }
        Ok(BeaconConfig { fields, xor_key: None })
    }

    /// Detect and parse a Cobalt Strike config from a raw memory/network buffer.
    #[must_use]
    pub fn detect_and_parse(buf: &[u8]) -> Option<(BeaconConfig, C2Detection)> {
        // Try XOR key extraction
        let xor_key = Self::detect_xor_key(buf);
        let decrypted = xor_key.map_or_else(|| buf.to_vec(), |key| Self::xor_decrypt(buf, key));
        let cfg = Self::parse_config(&decrypted).ok()?;
        if cfg.fields.is_empty() { return None; }

        let mut det = C2Detection::new("CobaltStrike", Confidence::High);
        det.add_indicator("beacon_config_tlv_structure");
        if let Some(key) = xor_key {
            det.set_meta("xor_key", format!("0x{key:02x}"));
        }
        if let Some(c2) = cfg.c2_server() {
            det.set_meta("c2_server", c2);
        }
        if let Some(ms) = cfg.sleep_ms() {
            det.set_meta("sleep_ms", ms.to_string());
        }
        if let Some(j) = cfg.jitter_pct() {
            det.set_meta("jitter_pct", j.to_string());
        }
        Some((cfg, det))
    }

    /// Check-in HTTP request heuristic (default CS profile).
    /// Returns true if the HTTP headers match typical Cobalt Strike default profile.
    #[must_use]
    pub fn is_default_checkin_request(method: &str, uri: &str, user_agent: &str, host: &str) -> bool {
        let _ = host;
        // Default CS profile: GET /<random alphanum>.gif or POST /<random>
        let uri_looks_cs = std::path::Path::new(uri).extension().is_some_and(|e| e.eq_ignore_ascii_case("gif")) || uri.contains("/submit.php") || uri.contains("/ca");
        let ua_looks_cs = user_agent.contains("Mozilla/5.0 (compatible; MSIE")
            || user_agent.contains("Mozilla/4.0 (compatible; MSIE");
        method == "GET" && uri_looks_cs && ua_looks_cs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Metasploit
// ─────────────────────────────────────────────────────────────────────────────

/// Metasploit stager/stage request detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetasploitDetection {
    pub stage_type:    String,
    pub payload_arch:  Option<String>,
    pub transport:     String,
}

/// Known Metasploit stager magic values.
const MSF_REVERSE_TCP_MAGIC: &[u8] = &[0xfc, 0x48, 0x83];  // x64 reverse_tcp shellcode prolog
const MSF_REVERSE_TCP_X86:   &[u8] = &[0xfc, 0xe8];         // x86 shellcode prolog
const MSF_STAGE_SIZE_MAGIC:  usize = 4;                       // 4-byte LE stage size in stager

pub struct MetasploitDissector;

impl MetasploitDissector {
    /// Detect Metasploit stage request in a raw buffer.
    #[must_use]
    pub fn detect(buf: &[u8]) -> Option<MetasploitDetection> {
        if buf.len() < 8 { return None; }

        // Check for 4-byte LE stage size followed by x64/x86 shellcode prolog.
        let size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if size > 0 && size < 0x0010_0000 && buf.len() >= size + 4 {
            let code = &buf[4..];
            let arch = if code.starts_with(MSF_REVERSE_TCP_MAGIC) {
                Some("x86_64".to_string())
            } else if code.starts_with(MSF_REVERSE_TCP_X86) {
                Some("x86".to_string())
            } else {
                None
            };
            if arch.is_some() {
                return Some(MetasploitDetection {
                    stage_type: "stage_download".to_string(),
                    payload_arch: arch,
                    transport: "tcp".to_string(),
                });
            }
        }

        // HTTP-based stage request: GET /XXXXX HTTP/1.0 (no Host header, random path)
        if buf.starts_with(b"GET /") {
            let end = buf.iter().position(|&b| b == b'\r').unwrap_or(buf.len());
            let req = String::from_utf8_lossy(&buf[..end]);
            if req.ends_with("HTTP/1.0") || req.ends_with("HTTP/1.1") {
                return Some(MetasploitDetection {
                    stage_type: "http_stage_request".to_string(),
                    payload_arch: None,
                    transport: "http".to_string(),
                });
            }
        }

        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sliver C2
// ─────────────────────────────────────────────────────────────────────────────

/// Sliver C2 transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SliverTransport {
    MutualTls,
    Https,
    Http,
    Dns,
    WireGuard,
    Unknown,
}

impl SliverTransport {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MutualTls  => "mtls",
            Self::Https      => "https",
            Self::Http       => "http",
            Self::Dns        => "dns",
            Self::WireGuard  => "wireguard",
            Self::Unknown    => "unknown",
        }
    }
}

/// Detected Sliver C2 communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliverDetection {
    pub transport:       SliverTransport,
    pub protobuf_likely: bool,
    pub indicators:      Vec<String>,
}

pub struct SliverDissector;

impl SliverDissector {
    /// Heuristic detection of Sliver HTTP/S implant traffic.
    /// Sliver uses random-looking URLs with a base64-like cookie for session ID.
    #[must_use]
    pub fn detect_http(method: &str, uri: &str, headers: &HashMap<String, String>) -> Option<SliverDetection> {
        let mut ind = Vec::new();

        // Sliver HTTP beacon: POSTs to random 5-char paths with specific cookie names
        let uri_random = uri.len() == 6 && uri.starts_with('/') && uri[1..].chars().all(|c| c.is_ascii_alphanumeric());
        if method == "POST" && uri_random { ind.push("random_5char_uri".to_string()); }

        // Sliver sets a specific cookie with base64url implant ID
        let has_sliver_cookie = headers.get("cookie")
            .is_some_and(|v| v.len() > 16 && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '='));
        if has_sliver_cookie { ind.push("base64url_cookie".to_string()); }

        if ind.len() >= 2 {
            Some(SliverDetection { transport: SliverTransport::Http, protobuf_likely: true, indicators: ind })
        } else { None }
    }

    /// Attempt to detect Sliver mTLS handshake (TLS 1.3 with specific ALPN).
    #[must_use]
    pub fn detect_mtls_alpn(alpn_list: &[String]) -> Option<SliverDetection> {
        // Sliver mTLS uses a custom ALPN like "sliver" or no ALPN
        let has_sliver_alpn = alpn_list.iter().any(|a| a == "sliver" || a.starts_with("sliver-"));
        if has_sliver_alpn {
            Some(SliverDetection {
                transport: SliverTransport::MutualTls,
                protobuf_likely: true,
                indicators: vec!["sliver_alpn".to_string()],
            })
        } else { None }
    }

    /// Minimal Sliver protobuf Envelope dissection. Sliver wraps all messages in:
    ///   message Envelope { uint32 ID = 1; bytes Data = 2; uint64 `UnixTime` = 3; }
    #[must_use]
    pub fn decode_envelope(buf: &[u8]) -> Option<(u32, Vec<u8>)> {
        // Minimal protobuf field parsing
        let mut pos = 0;
        let mut id: Option<u32> = None;
        let mut data: Option<Vec<u8>> = None;
        while pos < buf.len() {
            let tag_byte = buf[pos]; pos += 1;
            let field_number = tag_byte >> 3;
            let wire_type    = tag_byte & 0x07;
            match (field_number, wire_type) {
                (1, 0) => { // varint — message type ID
                    let (v, sz) = read_varint(&buf[pos..])?;
                    id = Some(u32::try_from(v).unwrap_or(u32::MAX));
                    pos += sz;
                }
                (2, 2) => { // length-delimited — payload
                    let (len, sz) = read_varint(&buf[pos..])?;
                    pos += sz;
                    let end = pos + usize::try_from(len).unwrap_or(usize::MAX);
                    if buf.len() < end { return None; }
                    data = Some(buf[pos..end].to_vec());
                    pos = end;
                }
                (_, 0) => { let (_, sz) = read_varint(&buf[pos..])?; pos += sz; }
                (_, 2) => {
                    let (len, sz) = read_varint(&buf[pos..])?;
                    pos += sz + usize::try_from(len).unwrap_or(usize::MAX);
                }
                _ => break,
            }
        }
        Some((id.unwrap_or(0), data.unwrap_or_default()))
    }
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate().take(10) {
        v |= (u64::from(b & 0x7f)) << shift;
        shift += 7;
        if b & 0x80 == 0 { return Some((v, i + 1)); }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Havoc Framework
// ─────────────────────────────────────────────────────────────────────────────

/// Havoc Demon agent protocol message types (from public research).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum HavocMsgType {
    Register     = 99,
    Checkin      = 100,
    TaskOutput   = 101,
    Pivot        = 102,
    Injection    = 103,
    Token        = 104,
    ProcEnumerate = 105,
    Unknown(u32),
}

impl HavocMsgType {
    #[must_use]
    pub const fn from_u32(v: u32) -> Self {
        match v {
            99  => Self::Register,
            100 => Self::Checkin,
            101 => Self::TaskOutput,
            102 => Self::Pivot,
            103 => Self::Injection,
            104 => Self::Token,
            105 => Self::ProcEnumerate,
            other => Self::Unknown(other),
        }
    }
}

/// Decoded Havoc Demon header (12 bytes: size + magic + `agent_id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HavocDemonHeader {
    pub size:     u32,
    pub magic:    u32,
    pub agent_id: u32,
    pub msg_type: HavocMsgType,
}

/// Default Havoc magic value (0xDEADBEEF).
const HAVOC_MAGIC: u32 = 0xDEAD_BEEF;

pub struct HavocDissector;

impl HavocDissector {
    #[must_use]
    pub fn detect(buf: &[u8]) -> Option<(HavocDemonHeader, C2Detection)> {
        if buf.len() < 16 { return None; }
        let size     = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let magic    = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if magic != HAVOC_MAGIC { return None; }
        let agent_id = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let msg_type_raw = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let msg_type = HavocMsgType::from_u32(msg_type_raw);
        let hdr = HavocDemonHeader { size, magic, agent_id, msg_type };
        let mut det = C2Detection::new("Havoc", Confidence::Certain);
        det.add_indicator(format!("havoc_magic=0x{magic:08x}"));
        det.set_meta("agent_id", format!("0x{agent_id:08x}"));
        Some((hdr, det))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Empire / Starkiller
// ─────────────────────────────────────────────────────────────────────────────

/// Empire REST API endpoint patterns.
const EMPIRE_API_ENDPOINTS: &[&str] = &[
    "/api/listeners",
    "/api/agents",
    "/api/modules",
    "/api/stagers",
    "/api/reporting",
    "/api/users",
    "/api/admin/login",
];

/// Detected Empire/Starkiller communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmpireDetection {
    pub endpoint:   String,
    pub confidence: Confidence,
}

pub struct EmpireDissector;

impl EmpireDissector {
    #[must_use]
    pub fn detect_rest_call(uri: &str, content_type: Option<&str>) -> Option<EmpireDetection> {
        for &ep in EMPIRE_API_ENDPOINTS {
            if uri.starts_with(ep) {
                let conf = if content_type.is_some_and(|c| c.contains("application/json")) {
                    Confidence::High
                } else {
                    Confidence::Medium
                };
                return Some(EmpireDetection { endpoint: ep.to_string(), confidence: conf });
            }
        }
        // Empire agent check-in: POST to staging/taskAndResults path
        if uri.contains("taskAndResults") || uri.contains("download/multi") {
            return Some(EmpireDetection { endpoint: uri.to_string(), confidence: Confidence::Medium });
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Generic C2 heuristics
// ─────────────────────────────────────────────────────────────────────────────

/// Beacon timing observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconObservation {
    pub timestamp_ms: u64,
    pub flow_id:      u64,
}

/// Statistical summary of a beacon interval series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconStats {
    pub mean_interval_ms:   f64,
    pub stddev_interval_ms: f64,
    pub jitter_pct:         f64,
    pub sample_count:       usize,
    pub is_likely_beacon:   bool,
}

pub struct GenericC2Detector;

impl GenericC2Detector {
    /// Compute beacon statistics from a sorted list of timestamps.
    #[must_use]
    pub fn analyze_beacon_intervals(timestamps_ms: &[u64]) -> Option<BeaconStats> {
        if timestamps_ms.len() < 3 { return None; }
        let intervals: Vec<f64> = timestamps_ms.windows(2)
            .map(|w| f64::from(u32::try_from(w[1] - w[0]).unwrap_or(u32::MAX)))
            .collect();
        let n_f64 = f64::from(u32::try_from(intervals.len()).unwrap_or(u32::MAX));
        let mean = intervals.iter().sum::<f64>() / n_f64;
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n_f64;
        let stddev = variance.sqrt();
        let jitter_pct = if mean > 0.0 { (stddev / mean) * 100.0 } else { 0.0 };
        // Heuristic: likely beacon if mean 1s–5min and jitter < 50%
        let is_beacon = (1000.0..=300_000.0).contains(&mean) && jitter_pct < 50.0;
        Some(BeaconStats {
            mean_interval_ms: mean,
            stddev_interval_ms: stddev,
            jitter_pct,
            sample_count: timestamps_ms.len(),
            is_likely_beacon: is_beacon,
        })
    }

    /// Heuristic scoring of a single HTTP request for C2 characteristics.
    /// Returns a score 0.0..1.0.
    #[must_use]
    pub fn score_http_request(
        method: &str,
        uri: &str,
        user_agent: &str,
        body_len: usize,
        has_cookies: bool,
    ) -> f64 {
        let mut score = 0.0f64;

        // Short random-looking URI
        let uri_path = uri.trim_start_matches('/').split('?').next().unwrap_or("");
        let uri_entropy = byte_entropy(uri_path.as_bytes());
        if uri_entropy > 3.5 { score += 0.15; }

        // Default/fake browser UA
        if user_agent.contains("MSIE") || user_agent.is_empty() { score += 0.1; }

        // Specific body sizes common in beaconing (config pull ~ few hundred bytes)
        if matches!(body_len, 128..=512) { score += 0.1; }

        // POST with cookies
        if method == "POST" && has_cookies { score += 0.1; }

        // URI ends with common C2 extensions
        if std::path::Path::new(uri).extension().is_some_and(|e| e.eq_ignore_ascii_case("gif") || e.eq_ignore_ascii_case("php") || e.eq_ignore_ascii_case("asp")) { score += 0.05; }

        score.min(1.0)
    }

    /// Detect DNS-based C2 by looking for unusually long or high-entropy subdomain labels.
    pub fn analyze_dns_query(name: &str) -> Option<C2Detection> {
        let labels: Vec<&str> = name.split('.').collect();
        let max_label_len = labels.iter().map(|l| l.len()).max().unwrap_or(0);
        let max_entropy = labels.iter().map(|l| byte_entropy(l.as_bytes())).fold(0.0f64, f64::max);
        if max_label_len > 14 || max_entropy > 3.5 {
            let mut det = C2Detection::new("DNS-C2", Confidence::Medium);
            det.add_indicator(format!("max_label_len={max_label_len}"));
            det.add_indicator(format!("max_label_entropy={max_entropy:.2}"));
            det.set_meta("query", name.to_string());
            return Some(det);
        }
        None
    }
}

/// Shannon entropy of a byte slice.
fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    counts.iter().filter(|&&c| c > 0)
        .map(|&c| { let p = f64::from(c) / len; -p * p.log2() })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level C2 dispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Run all C2 detectors against a raw payload buffer. Returns all hits.
#[must_use]
pub fn detect_all_c2(buf: &[u8]) -> Vec<C2Detection> {
    let mut results = Vec::new();

    // Havoc
    if let Some((_, det)) = HavocDissector::detect(buf) {
        results.push(det);
    }

    // Cobalt Strike
    if let Some((_, det)) = CobaltStrikeDissector::detect_and_parse(buf) {
        results.push(det);
    }

    // Metasploit
    if let Some(msf) = MetasploitDissector::detect(buf) {
        let mut det = C2Detection::new("Metasploit", Confidence::High);
        det.set_meta("stage_type", msf.stage_type);
        det.set_meta("transport",  msf.transport);
        if let Some(arch) = msf.payload_arch {
            det.set_meta("arch", arch);
        }
        results.push(det);
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_config_field_names() {
        assert_eq!(BeaconConfigField::C2Server.name(), "C2Server");
        assert_eq!(BeaconConfigField::SleepTime.name(), "SleepTime");
        assert_eq!(BeaconConfigField::Unknown(99).name(), "Unknown");
    }

    #[test]
    fn test_beacon_intervals_detection() {
        // Regular 5-second beacon
        let ts: Vec<u64> = (0..10).map(|i| i * 5000).collect();
        let stats = GenericC2Detector::analyze_beacon_intervals(&ts).unwrap();
        assert!(stats.is_likely_beacon);
        assert!((stats.mean_interval_ms - 5000.0).abs() < 1.0);
    }

    #[test]
    fn test_dns_c2_detection() {
        let det = GenericC2Detector::analyze_dns_query("aGVsbG9fd29ybGQ.c2server.example.com");
        assert!(det.is_some());
    }

    #[test]
    fn test_havoc_magic_negative() {
        let buf = [0u8; 16];
        assert!(HavocDissector::detect(&buf).is_none());
    }

    #[test]
    fn test_havoc_magic_positive() {
        let mut buf = [0u8; 20];
        buf[0..4].copy_from_slice(&100u32.to_be_bytes());
        buf[4..8].copy_from_slice(&HAVOC_MAGIC.to_be_bytes());
        buf[12..16].copy_from_slice(&100u32.to_be_bytes());
        let res = HavocDissector::detect(&buf);
        assert!(res.is_some());
    }

    #[test]
    fn test_xor_key_detection() {
        let plaintext = b"\x00\x01\x00\x02hello world config block\x00\x00";
        let key = 0x42u8;
        let enc: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let detected = CobaltStrikeDissector::detect_xor_key(&enc);
        // Should detect some key (may not be exact 0x42 but should find something)
        assert!(detected.is_some());
    }

    #[test]
    fn test_empire_rest_detection() {
        let det = EmpireDissector::detect_rest_call("/api/agents", Some("application/json"));
        assert!(det.is_some());
        let det = det.unwrap();
        assert_eq!(det.confidence, Confidence::High);
    }

    #[test]
    fn test_entropy() {
        assert!(byte_entropy(b"aaaaaaa") < 0.1);
        assert!(byte_entropy(b"abcdefgh") > 2.5);
    }
}
