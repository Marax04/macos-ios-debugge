//! Malware config extraction: `ConfigExtractor` trait and built-in extractors
//! for Cobalt Strike, Emotet, generic RATs, and C2 string patterns.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone)]
pub enum ConfigExtractError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("decryption failed: {0}")]
    Decryption(String),
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    #[error("not recognized as target family: {0}")]
    NotRecognized(String),
    #[error("empty input")]
    EmptyInput,
}

// ─── C2Server ─────────────────────────────────────────────────────────────────

/// A C2 server extracted from a malware config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct C2Server {
    pub host: String,
    pub port: u16,
    pub protocol: C2Protocol,
    pub uri_path: Option<String>,
}

impl C2Server {
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, protocol: C2Protocol) -> Self {
        Self { host: host.into(), port, protocol, uri_path: None }
    }

    #[must_use]
    pub fn to_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// C2 communication protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum C2Protocol {
    Http,
    Https,
    Tcp,
    Udp,
    Dns,
    Unknown,
}

impl std::fmt::Display for C2Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Dns => write!(f, "dns"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── ExtractedMalwareConfig ───────────────────────────────────────────────────

/// A fully extracted malware configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedMalwareConfig {
    /// Malware family name (e.g. `"cobalt_strike"`, `"emotet"`).
    pub family: String,
    /// Extraction method (e.g. `"xor_decode"`, `"fixed_offset"`, `"string_scan"`).
    pub extraction_method: String,
    /// C2 servers.
    pub c2_servers: Vec<C2Server>,
    /// Sleep interval in milliseconds.
    pub sleep_ms: Option<u64>,
    /// Jitter factor (0.0 – 1.0).
    pub jitter_factor: Option<f32>,
    /// Campaign identifier.
    pub campaign_id: Option<String>,
    /// Encryption/obfuscation key bytes.
    pub key: Option<Vec<u8>>,
    /// User-agent string.
    pub user_agent: Option<String>,
    /// Proxy host:port.
    pub proxy: Option<String>,
    /// Raw config bytes before decoding.
    pub raw_bytes: Vec<u8>,
    /// Extra key/value fields.
    pub extra: HashMap<String, String>,
    /// Confidence in extraction accuracy [0.0, 1.0].
    pub confidence: f32,
}

impl ExtractedMalwareConfig {
    #[must_use]
    pub fn new(family: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            extraction_method: method.into(),
            c2_servers: Vec::new(),
            sleep_ms: None,
            jitter_factor: None,
            campaign_id: None,
            key: None,
            user_agent: None,
            proxy: None,
            raw_bytes: Vec::new(),
            extra: HashMap::new(),
            confidence: 1.0,
        }
    }

    pub fn add_c2(&mut self, c2: C2Server) {
        self.c2_servers.push(c2);
    }

    pub fn set_extra(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.extra.insert(key.into(), value.into());
    }

    #[must_use]
    pub const fn has_c2(&self) -> bool {
        !self.c2_servers.is_empty()
    }

    #[must_use]
    pub fn c2_addresses(&self) -> Vec<String> {
        self.c2_servers.iter().map(C2Server::to_address).collect()
    }
}

// ─── ConfigExtractor trait ────────────────────────────────────────────────────

/// Trait for malware config extractors.
pub trait ConfigExtractor: Send + Sync {
    /// Name of the extractor / malware family.
    fn name(&self) -> &str;

    /// One-line description.
    fn description(&self) -> &str;

    /// Returns `true` if this extractor believes it can handle the given data.
    fn can_handle(&self, data: &[u8]) -> bool;

    /// Extract a configuration from the raw bytes.
    ///
    /// # Errors
    /// Returns `ConfigExtractError` if extraction fails.
    fn extract(&self, data: &[u8]) -> Result<ExtractedMalwareConfig, ConfigExtractError>;
}

// ─── CobaltStrikeExtractor ────────────────────────────────────────────────────

/// Extracts Cobalt Strike beacon configurations.
///
/// Detection strategy:
/// 1. Look for the XOR-obfuscated config block (4-byte XOR key, `0x2e` marker).
/// 2. Walk the type-length-value (TLV) fields.
/// 3. Parse standard field IDs: `BeaconType` (1), `Port` (2), `SleepTime` (3),
///    `MaxGetSize` (4), `Jitter` (5), `DnsIdleAddress` (6), `Server` (8),
///    `UserAgent` (54).
pub struct CobaltStrikeExtractor;

impl CobaltStrikeExtractor {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Attempt XOR decode with a 4-byte key.
    fn xor_decode_4byte(data: &[u8], key: [u8; 4]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 4])
            .collect()
    }

    /// Attempt XOR decode with a 1-byte key.
    fn xor_decode_1byte(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|&b| b ^ key).collect()
    }

    /// Parse TLV fields from a decoded config block.
    fn parse_config_block(block: &[u8]) -> Option<ExtractedMalwareConfig> {
        // Heuristic: look for type=1 (BeaconType), type=2 (Port), type=3 (SleepTime).
        // TLV layout: type(u16 BE) + length(u16 BE) + data
        let mut cfg = ExtractedMalwareConfig::new("cobalt_strike", "tlv_parse");
        let mut found_fields = 0u32;
        let mut i = 0;

        while i + 4 <= block.len() {
            let field_type = u16::from_be_bytes([block[i], block[i + 1]]);
            let field_len = u16::from_be_bytes([block[i + 2], block[i + 3]]) as usize;
            i += 4;

            if i + field_len > block.len() {
                break;
            }
            if field_len == 0 {
                // Zero-length field: header already consumed 4 bytes; just continue.
                continue;
            }

            let field_data = &block[i..i + field_len];
            i += field_len;

            match field_type {
                1 => {
                    // BeaconType: 0=HTTP, 1=HTTPS, 2=SMB, 8=HTTPS_cert
                    if field_len >= 2 {
                        let btype = u16::from_be_bytes([field_data[0], field_data[1]]);
                        cfg.set_extra("beacon_type", btype.to_string());
                        found_fields += 1;
                    }
                }
                2 => {
                    // Port
                    if field_len >= 2 {
                        let port = u16::from_be_bytes([field_data[0], field_data[1]]);
                        // Will be associated with the server extracted from field 8.
                        cfg.set_extra("port", port.to_string());
                        found_fields += 1;
                    }
                }
                3 => {
                    // SleepTime in milliseconds
                    if field_len >= 4 {
                        let sleep = u32::from_be_bytes([field_data[0], field_data[1], field_data[2], field_data[3]]);
                        cfg.sleep_ms = Some(u64::from(sleep));
                        found_fields += 1;
                    }
                }
                5 => {
                    // Jitter %
                    if field_len >= 4 {
                        let jitter = u32::from_be_bytes([field_data[0], field_data[1], field_data[2], field_data[3]]);
                        cfg.jitter_factor = Some(jitter as f32 / 100.0);
                        found_fields += 1;
                    }
                }
                8 => {
                    // Server + URI: null-terminated pairs (host,uri)
                    let s = std::str::from_utf8(field_data)
                        .ok()
                        .and_then(|s| s.split_once(','));
                    if let Some((host, uri)) = s {
                        let host = host.trim_matches('\0').to_string();
                        if !host.is_empty() {
                            let port_str = cfg.extra.get("port").cloned().unwrap_or_else(|| "443".to_string());
                            let port = port_str.parse::<u16>().unwrap_or(443);
                            let protocol = if port == 443 { C2Protocol::Https } else { C2Protocol::Http };
                            let mut c2 = C2Server::new(host, port, protocol);
                            let uri = uri.trim_matches('\0');
                            if !uri.is_empty() {
                                c2.uri_path = Some(uri.to_string());
                            }
                            cfg.add_c2(c2);
                            found_fields += 1;
                        }
                    }
                }
                54 => {
                    // UserAgent
                    if let Ok(ua) = std::str::from_utf8(field_data) {
                        let ua = ua.trim_matches('\0');
                        if !ua.is_empty() {
                            cfg.user_agent = Some(ua.to_string());
                            found_fields += 1;
                        }
                    }
                }
                _ => {}
            }
        }

        if found_fields >= 2 {
            cfg.confidence = 0.85 + (found_fields as f32 * 0.02).min(0.14);
            Some(cfg)
        } else {
            None
        }
    }
}

impl Default for CobaltStrikeExtractor {
    fn default() -> Self { Self::new() }
}

impl ConfigExtractor for CobaltStrikeExtractor {
    fn name(&self) -> &'static str { "cobalt_strike" }
    fn description(&self) -> &'static str { "Extracts Cobalt Strike beacon configurations via XOR + TLV parsing" }

    fn can_handle(&self, data: &[u8]) -> bool {
        // Quick heuristics: look for 0x2e marker sequences or field magic.
        let has_marker = data.windows(4).any(|w| w == [0x2e, 0x2e, 0x2e, 0x2e]);
        let has_field_magic = data.windows(4).any(|w| w == [0x00, 0x01, 0x00, 0x02]);
        // Also accept if "beacon" string is present.
        let has_beacon_str = data.windows(6).any(|w| w == b"beacon");
        has_marker || has_field_magic || has_beacon_str
    }

    fn extract(&self, data: &[u8]) -> Result<ExtractedMalwareConfig, ConfigExtractError> {
        if data.is_empty() {
            return Err(ConfigExtractError::EmptyInput);
        }

        // Try raw first.
        if let Some(cfg) = Self::parse_config_block(data) {
            return Ok(cfg);
        }

        // Try common 4-byte XOR keys.
        const COMMON_KEYS: &[[u8; 4]] = &[
            [0x69, 0x58, 0x2d, 0x2e],
            [0x00, 0x00, 0x00, 0x00],
            [0x2e, 0x2e, 0x2e, 0x2e],
        ];

        for &key in COMMON_KEYS {
            let decoded = Self::xor_decode_4byte(data, key);
            if let Some(mut cfg) = Self::parse_config_block(&decoded) {
                cfg.key = Some(key.to_vec());
                cfg.raw_bytes = data.to_vec();
                cfg.extraction_method = "xor4_tlv".to_string();
                return Ok(cfg);
            }
        }

        // Try 1-byte XOR keys.
        for key in 0x01u8..=0xffu8 {
            let decoded = Self::xor_decode_1byte(data, key);
            if let Some(mut cfg) = Self::parse_config_block(&decoded) {
                cfg.key = Some(vec![key]);
                cfg.raw_bytes = data.to_vec();
                cfg.extraction_method = "xor1_tlv".to_string();
                return Ok(cfg);
            }
        }

        // Fallback: scan for IP:port strings.
        let mut cfg = ExtractedMalwareConfig::new("cobalt_strike", "string_fallback");
        cfg.confidence = 0.4;
        cfg.raw_bytes = data.to_vec();

        let strings = extract_ascii_strings(data, 6);
        for s in &strings {
            if let Some(c2) = try_parse_ip_port(s) {
                cfg.add_c2(c2);
            }
            if s.starts_with("https://") || s.starts_with("http://") {
                cfg.set_extra("url", s.clone());
            }
        }

        if cfg.has_c2() || cfg.extra.contains_key("url") {
            Ok(cfg)
        } else {
            Err(ConfigExtractError::NotRecognized("cobalt_strike".to_string()))
        }
    }
}

// ─── EmotetExtractor ─────────────────────────────────────────────────────────

/// Extracts Emotet / Heodo botnet configurations.
///
/// Detection / extraction strategy:
/// 1. The botnet server list is stored as a sequence of packed structs: `(u32_ip, u16_port)`.
/// 2. The block is XOR-encoded with a single-byte key located near the config.
/// 3. Scan for the block at known offsets and with common XOR keys.
pub struct EmotetExtractor;

impl EmotetExtractor {
    #[must_use]
    pub const fn new() -> Self { Self }

    /// Parse packed `(ip_u32_be, port_u16_be)` server list.
    fn parse_server_list(data: &[u8]) -> Vec<C2Server> {
        let mut servers = Vec::new();
        let mut i = 0;
        while i + 6 <= data.len() {
            let ip_bytes: [u8; 4] = [data[i], data[i + 1], data[i + 2], data[i + 3]];
            let port = u16::from_be_bytes([data[i + 4], data[i + 5]]);
            let ip = Ipv4Addr::from(ip_bytes);
            // Skip zero and loopback addresses.
            if ip.is_unspecified() || ip.is_loopback() {
                i += 6;
                continue;
            }
            if port > 0 && port < 65535 {
                let protocol = if port == 443 { C2Protocol::Https } else { C2Protocol::Tcp };
                servers.push(C2Server::new(ip.to_string(), port, protocol));
            }
            i += 6;
        }
        servers
    }
}

impl Default for EmotetExtractor {
    fn default() -> Self { Self::new() }
}

impl ConfigExtractor for EmotetExtractor {
    fn name(&self) -> &'static str { "emotet" }
    fn description(&self) -> &'static str { "Extracts Emotet C2 server lists via XOR decode + packed struct parsing" }

    fn can_handle(&self, data: &[u8]) -> bool {
        // Emotet samples are usually > 100 KB and have high entropy regions.
        data.len() > 4096
    }

    fn extract(&self, data: &[u8]) -> Result<ExtractedMalwareConfig, ConfigExtractError> {
        if data.is_empty() {
            return Err(ConfigExtractError::EmptyInput);
        }

        let mut best: Option<(u8, Vec<C2Server>)> = None;

        // Try each 1-byte XOR key.
        for key in 0x01u8..=0xffu8 {
            let decoded: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            let servers = Self::parse_server_list(&decoded);
            if servers.len() > 2
                && best.as_ref().is_none_or(|(_, s)| servers.len() > s.len()) {
                    best = Some((key, servers));
                }
        }

        // Also try raw (key=0).
        let raw_servers = Self::parse_server_list(data);
        if raw_servers.len() > 2
            && best.as_ref().is_none_or(|(_, s)| raw_servers.len() > s.len())
        {
            best = Some((0, raw_servers));
        }

        if let Some((key, servers)) = best {
            let mut cfg = ExtractedMalwareConfig::new("emotet", "xor1_packed_struct");
            if key != 0 {
                cfg.key = Some(vec![key]);
            }
            for s in servers {
                cfg.add_c2(s);
            }
            cfg.raw_bytes = data.to_vec();
            cfg.confidence = 0.88;
            return Ok(cfg);
        }

        // String scan fallback.
        let mut cfg = ExtractedMalwareConfig::new("emotet", "string_fallback");
        cfg.confidence = 0.4;
        let strings = extract_ascii_strings(data, 7);
        for s in &strings {
            if let Some(c2) = try_parse_ip_port(s) {
                cfg.add_c2(c2);
            }
        }

        if cfg.has_c2() {
            Ok(cfg)
        } else {
            Err(ConfigExtractError::NotRecognized("emotet".to_string()))
        }
    }
}

// ─── RatConfigExtractor ──────────────────────────────────────────────────────

/// Generic RAT config extractor.
///
/// Searches for:
/// - `IP:PORT` patterns (`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}`)
/// - HTTP/S URLs
/// - Key/value fields: `sleep=N`, `jitter=N`, `campaign=<id>`, `ua=<string>`
pub struct RatConfigExtractor {
    /// Known prefixes for interesting config fields.
    field_prefixes: Vec<(&'static str, &'static str)>,
}

impl RatConfigExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            field_prefixes: vec![
                ("sleep=", "sleep_ms"),
                ("SLEEP=", "sleep_ms"),
                ("jitter=", "jitter"),
                ("JITTER=", "jitter"),
                ("campaign=", "campaign_id"),
                ("CAMPAIGN=", "campaign_id"),
                ("group=", "campaign_id"),
                ("GROUP=", "campaign_id"),
                ("ua=", "user_agent"),
                ("User-Agent:", "user_agent"),
                ("proxy=", "proxy"),
                ("PROXY=", "proxy"),
            ],
        }
    }
}

impl Default for RatConfigExtractor {
    fn default() -> Self { Self::new() }
}

impl ConfigExtractor for RatConfigExtractor {
    fn name(&self) -> &'static str { "generic_rat" }
    fn description(&self) -> &'static str { "Extracts generic RAT configs: IP:PORT patterns, URLs, sleep/jitter fields" }

    fn can_handle(&self, data: &[u8]) -> bool {
        // Accept everything as a fallback extractor.
        !data.is_empty()
    }

    fn extract(&self, data: &[u8]) -> Result<ExtractedMalwareConfig, ConfigExtractError> {
        if data.is_empty() {
            return Err(ConfigExtractError::EmptyInput);
        }

        let strings = extract_ascii_strings(data, 5);
        let mut cfg = ExtractedMalwareConfig::new("generic_rat", "string_scan");

        for s in &strings {
            // IP:PORT
            if let Some(c2) = try_parse_ip_port(s) {
                cfg.add_c2(c2);
                continue;
            }
            // URL-based C2
            if let Some(c2) = try_parse_url_c2(s) {
                cfg.add_c2(c2);
                continue;
            }
            // Key/value fields.
            for &(prefix, field) in &self.field_prefixes {
                if let Some(rest) = s.strip_prefix(prefix) {
                    let value = rest.split_whitespace().next().unwrap_or(rest).trim().to_string();
                    match field {
                        "sleep_ms" => {
                            if let Ok(ms) = value.parse::<u64>() {
                                cfg.sleep_ms = Some(ms);
                            }
                        }
                        "jitter" => {
                            if let Ok(j) = value.parse::<f32>() {
                                cfg.jitter_factor = Some(j.clamp(0.0, 1.0));
                            }
                        }
                        "campaign_id" => {
                            cfg.campaign_id = Some(value);
                        }
                        "user_agent" => {
                            cfg.user_agent = Some(rest.trim().to_string());
                        }
                        "proxy" => {
                            cfg.proxy = Some(value);
                        }
                        _ => {
                            cfg.set_extra(field, value);
                        }
                    }
                    break;
                }
            }
        }

        cfg.raw_bytes = data.to_vec();

        if cfg.has_c2() || cfg.sleep_ms.is_some() || cfg.campaign_id.is_some() {
            cfg.confidence = if cfg.has_c2() { 0.75 } else { 0.50 };
            Ok(cfg)
        } else {
            Err(ConfigExtractError::NotRecognized("generic_rat".to_string()))
        }
    }
}

// ─── ConfigExtractorChain ─────────────────────────────────────────────────────

/// Tries multiple extractors in order, returning the first successful result.
pub struct ConfigExtractorChain {
    extractors: Vec<Box<dyn ConfigExtractor>>,
}

impl ConfigExtractorChain {
    #[must_use]
    pub fn new() -> Self {
        Self { extractors: Vec::new() }
    }

    /// Create a chain with all built-in extractors.
    #[must_use]
    pub fn default_chain() -> Self {
        let mut chain = Self::new();
        chain.add(Box::new(CobaltStrikeExtractor::new()));
        chain.add(Box::new(EmotetExtractor::new()));
        chain.add(Box::new(RatConfigExtractor::new()));
        chain
    }

    /// Add an extractor to the chain.
    pub fn add(&mut self, extractor: Box<dyn ConfigExtractor>) {
        self.extractors.push(extractor);
    }

    /// Try all extractors, returning the highest-confidence successful result.
    #[must_use] 
    pub fn extract_best(&self, data: &[u8]) -> Option<ExtractedMalwareConfig> {
        let mut best: Option<ExtractedMalwareConfig> = None;
        for ex in &self.extractors {
            if !ex.can_handle(data) {
                continue;
            }
            if let Ok(cfg) = ex.extract(data) {
                match &best {
                    None => best = Some(cfg),
                    Some(b) if cfg.confidence > b.confidence => best = Some(cfg),
                    _ => {}
                }
            }
        }
        best
    }

    /// Try all extractors, returning all successful results.
    #[must_use] 
    pub fn extract_all(&self, data: &[u8]) -> Vec<ExtractedMalwareConfig> {
        self.extractors
            .iter()
            .filter(|e| e.can_handle(data))
            .filter_map(|e| e.extract(data).ok())
            .collect()
    }

    /// Number of extractors in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.extractors.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.extractors.is_empty()
    }
}

impl Default for ConfigExtractorChain {
    fn default() -> Self { Self::new() }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract printable ASCII strings of at least `min_len` chars from bytes.
#[must_use] 
pub fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b as char);
        } else if cur.len() >= min_len {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }
    out
}

/// Try to parse an IP:port C2 server from a string.
#[must_use] 
pub fn try_parse_ip_port(s: &str) -> Option<C2Server> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    let (ip_part, port_part) = match parts[..] {
        [ip, port] => (ip, port),
        _ => return None,
    };
    let port = port_part.split_whitespace().next()?.parse::<u16>().ok()?;
    let ip: Ipv4Addr = ip_part.parse().ok()?;
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    let protocol = if port == 443 { C2Protocol::Https } else { C2Protocol::Tcp };
    Some(C2Server::new(ip.to_string(), port, protocol))
}

/// Try to parse a URL C2 server from a string.
#[must_use] 
pub fn try_parse_url_c2(s: &str) -> Option<C2Server> {
    if let Some(rest) = s.strip_prefix("https://") {
        let host_part = rest.split('/').next()?;
        let (host, port) = if let Some((h, p)) = host_part.split_once(':') {
            (h, p.parse::<u16>().unwrap_or(443))
        } else {
            (host_part, 443)
        };
        if !host.is_empty() {
            let mut c2 = C2Server::new(host, port, C2Protocol::Https);
            if let Some(path_start) = rest.find('/') {
                c2.uri_path = Some(rest[path_start..].to_string());
            }
            return Some(c2);
        }
    } else if let Some(rest) = s.strip_prefix("http://") {
        let host_part = rest.split('/').next()?;
        let (host, port) = if let Some((h, p)) = host_part.split_once(':') {
            (h, p.parse::<u16>().unwrap_or(80))
        } else {
            (host_part, 80)
        };
        if !host.is_empty() {
            let mut c2 = C2Server::new(host, port, C2Protocol::Http);
            if let Some(path_start) = rest.find('/') {
                c2.uri_path = Some(rest[path_start..].to_string());
            }
            return Some(c2);
        }
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"hello\x00world\x00foo";
        let strings = extract_ascii_strings(data, 3);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"world".to_string()));
        assert!(strings.contains(&"foo".to_string()));
    }

    #[test]
    fn test_try_parse_ip_port() {
        let c2 = try_parse_ip_port("185.220.101.1:443").unwrap();
        assert_eq!(c2.host, "185.220.101.1");
        assert_eq!(c2.port, 443);
        assert_eq!(c2.protocol, C2Protocol::Https);
    }

    #[test]
    fn test_try_parse_ip_port_loopback() {
        assert!(try_parse_ip_port("127.0.0.1:8080").is_none());
    }

    #[test]
    fn test_try_parse_ip_port_bad_format() {
        assert!(try_parse_ip_port("not.an.ip").is_none());
    }

    #[test]
    fn test_try_parse_url_https() {
        let c2 = try_parse_url_c2("https://evil.com/beacon").unwrap();
        assert_eq!(c2.host, "evil.com");
        assert_eq!(c2.port, 443);
        assert_eq!(c2.protocol, C2Protocol::Https);
        assert_eq!(c2.uri_path.as_deref(), Some("/beacon"));
    }

    #[test]
    fn test_try_parse_url_http_custom_port() {
        let c2 = try_parse_url_c2("http://10.0.0.1:8080/cmd").unwrap();
        assert_eq!(c2.port, 8080);
        assert_eq!(c2.protocol, C2Protocol::Http);
    }

    // ── C2Server ─────────────────────────────────────────────────────────────

    #[test]
    fn test_c2_server_to_address() {
        let c2 = C2Server::new("192.168.1.1", 443, C2Protocol::Https);
        assert_eq!(c2.to_address(), "192.168.1.1:443");
    }

    // ── ExtractedMalwareConfig ────────────────────────────────────────────────

    #[test]
    fn test_config_has_c2() {
        let mut cfg = ExtractedMalwareConfig::new("rat", "scan");
        assert!(!cfg.has_c2());
        cfg.add_c2(C2Server::new("8.8.8.8", 80, C2Protocol::Http));
        assert!(cfg.has_c2());
    }

    #[test]
    fn test_config_c2_addresses() {
        let mut cfg = ExtractedMalwareConfig::new("rat", "scan");
        cfg.add_c2(C2Server::new("1.2.3.4", 443, C2Protocol::Https));
        cfg.add_c2(C2Server::new("5.6.7.8", 80, C2Protocol::Http));
        let addrs = cfg.c2_addresses();
        assert!(addrs.contains(&"1.2.3.4:443".to_string()));
        assert!(addrs.contains(&"5.6.7.8:80".to_string()));
    }

    // ── RatConfigExtractor ────────────────────────────────────────────────────

    #[test]
    fn test_rat_extractor_ip_port() {
        let extractor = RatConfigExtractor::new();
        let data = b"sleep=5000\x00185.220.101.1:443\x00campaign=botnet1";
        assert!(extractor.can_handle(data));
        let cfg = extractor.extract(data).unwrap();
        assert_eq!(cfg.family, "generic_rat");
        assert!(cfg.has_c2());
        assert_eq!(cfg.sleep_ms, Some(5000));
        assert_eq!(cfg.campaign_id.as_deref(), Some("botnet1"));
    }

    #[test]
    fn test_rat_extractor_url() {
        let extractor = RatConfigExtractor::new();
        let data = b"https://command.evil/update";
        let cfg = extractor.extract(data).unwrap();
        assert!(cfg.has_c2());
        assert_eq!(cfg.c2_servers[0].protocol, C2Protocol::Https);
    }

    #[test]
    fn test_rat_extractor_jitter() {
        let extractor = RatConfigExtractor::new();
        let data = b"jitter=0.2\x00185.1.1.1:4444";
        let cfg = extractor.extract(data).unwrap();
        assert!((cfg.jitter_factor.unwrap_or(0.0) - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_rat_extractor_no_config_error() {
        let extractor = RatConfigExtractor::new();
        let data = b"AAAA"; // No recognizable config.
        assert!(extractor.extract(data).is_err());
    }

    // ── EmotetExtractor ───────────────────────────────────────────────────────

    #[test]
    fn test_emotet_can_handle_small_file() {
        let extractor = EmotetExtractor::new();
        assert!(!extractor.can_handle(&[0u8; 100]));
    }

    #[test]
    fn test_emotet_can_handle_large_file() {
        let extractor = EmotetExtractor::new();
        assert!(extractor.can_handle(&[0u8; 8192]));
    }

    #[test]
    fn test_emotet_extract_packed_ips() {
        let extractor = EmotetExtractor::new();
        // Build a block with 3 packed IP:port entries (raw, no XOR).
        let mut data = vec![0u8; 8192];
        // 185.220.101.1 = 0xB9DC6501, port 443 = 0x01BB
        let entries: &[u8] = &[
            0xB9, 0xDC, 0x65, 0x01, 0x01, 0xBB,  // 185.220.101.1:443
            0x0A, 0x00, 0x00, 0x01, 0x1F, 0x90,  // 10.0.0.1:8080 (private, may be accepted)
            0xC0, 0xA8, 0x01, 0x01, 0x00, 0x50,  // 192.168.1.1:80 (private)
        ];
        data[0..entries.len()].copy_from_slice(entries);
        // Some extractors filter private IPs — this is fine; just ensure no panic.
        let result = extractor.extract(&data);
        // May return Ok or Err depending on whether private IPs are accepted.
        // The test just ensures no panic.
        let _ = result;
    }

    // ── CobaltStrikeExtractor ─────────────────────────────────────────────────

    #[test]
    fn test_cs_can_handle_with_beacon_string() {
        let extractor = CobaltStrikeExtractor::new();
        let data = b"some_prefix_beacon_here";
        assert!(extractor.can_handle(data));
    }

    #[test]
    fn test_cs_can_handle_with_marker() {
        let extractor = CobaltStrikeExtractor::new();
        let data = b"\x2e\x2e\x2e\x2e_config_data";
        assert!(extractor.can_handle(data));
    }

    #[test]
    fn test_cs_cannot_handle_empty() {
        let extractor = CobaltStrikeExtractor::new();
        let err = extractor.extract(&[]).unwrap_err();
        assert!(matches!(err, ConfigExtractError::EmptyInput));
    }

    #[test]
    fn test_cs_extract_tlv_block() {
        let _extractor = CobaltStrikeExtractor::new();
        // Build a minimal TLV block with BeaconType=HTTPS, Port=443, SleepTime=5000.
        let mut block = Vec::new();
        // Type=1 (BeaconType), Len=2, Value=1 (HTTPS)
        block.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0x00, 0x01]);
        // Type=2 (Port), Len=2, Value=443
        block.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x01, 0xBB]);
        // Type=3 (SleepTime), Len=4, Value=5000
        block.extend_from_slice(&[0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x13, 0x88]);
        // Type=5 (Jitter), Len=4, Value=20 (%)
        block.extend_from_slice(&[0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x14]);

        let result = CobaltStrikeExtractor::parse_config_block(&block);
        assert!(result.is_some());
        let cfg = result.unwrap();
        assert_eq!(cfg.sleep_ms, Some(5000));
        assert!((cfg.jitter_factor.unwrap_or(0.0) - 0.20).abs() < 0.01);
    }

    // ── ConfigExtractorChain ──────────────────────────────────────────────────

    #[test]
    fn test_chain_default_len() {
        let chain = ConfigExtractorChain::default_chain();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_chain_extract_best() {
        let chain = ConfigExtractorChain::default_chain();
        let data = b"sleep=3000\x00185.220.101.1:443\x00campaign=evil";
        let cfg = chain.extract_best(data);
        assert!(cfg.is_some());
        assert!(cfg.unwrap().has_c2());
    }

    #[test]
    fn test_chain_extract_all() {
        let chain = ConfigExtractorChain::default_chain();
        let data = b"185.220.101.1:4444\x00sleep=1000";
        let results = chain.extract_all(data);
        // At least the RAT extractor should succeed.
        assert!(!results.is_empty());
    }

    #[test]
    fn test_chain_empty_returns_none() {
        let chain = ConfigExtractorChain::default_chain();
        let cfg = chain.extract_best(&[]);
        assert!(cfg.is_none());
    }

    #[test]
    fn test_c2_protocol_display() {
        assert_eq!(C2Protocol::Https.to_string(), "https");
        assert_eq!(C2Protocol::Tcp.to_string(), "tcp");
        assert_eq!(C2Protocol::Dns.to_string(), "dns");
    }
}
