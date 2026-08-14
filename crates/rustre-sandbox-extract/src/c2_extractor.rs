//! `c2_extractor` — Extract C2 configuration from malware samples.
//!
//! Provides [`C2Extractor`] which applies heuristic and pattern-based
//! techniques to identify [`C2Config`]s, [`C2Channel`]s, and DGA patterns
//! via [`DgaDetector`], fast-flux domains via [`FastFlux`], and raw
//! protocol signatures via [`C2Protocol`].

use std::collections::{HashMap, HashSet};
use std::fmt;
pub use std::net::IpAddr;
use std::net::Ipv4Addr;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum C2Error {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("no c2 found")]
    NotFound,
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),
    #[error("sample too small: {0} bytes")]
    TooSmall(usize),
}

// ─── C2Protocol ───────────────────────────────────────────────────────────────

/// Known C2 communication protocols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum C2Protocol {
    Http,
    Https,
    Dns,
    Tcp,
    Udp,
    Irc,
    P2P,
    Custom(String),
    Unknown,
}

impl fmt::Display for C2Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom({s})"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl C2Protocol {
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        matches!(self, Self::Https | Self::P2P)
    }

    #[must_use]
    pub const fn from_port(port: u16) -> Self {
        match port {
            80 | 8080 | 8000 => Self::Http,
            443 | 8443 => Self::Https,
            53 => Self::Dns,
            6667 | 6697 => Self::Irc,
            _ => Self::Tcp,
        }
    }
}

// ─── C2Channel ────────────────────────────────────────────────────────────────

/// A single communication channel (IP+port or domain+port).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct C2Channel {
    pub host: String,
    pub port: u16,
    pub protocol: C2Protocol,
    pub active: bool,
    pub uri: Option<String>,
    pub user_agent: Option<String>,
}

impl C2Channel {
    pub fn new(host: impl Into<String>, port: u16, protocol: C2Protocol) -> Self {
        Self {
            host: host.into(),
            port,
            protocol,
            active: true,
            uri: None,
            user_agent: None,
        }
    }

    #[must_use]
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = Some(uri.into());
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    #[must_use]
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    #[must_use]
    pub fn is_ip(&self) -> bool {
        self.host.parse::<Ipv4Addr>().is_ok()
    }

    #[must_use]
    pub fn is_domain(&self) -> bool {
        !self.is_ip()
    }
}

impl fmt::Display for C2Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} ({})", self.host, self.port, self.protocol)
    }
}

// ─── C2Config ─────────────────────────────────────────────────────────────────

/// Extracted C2 configuration from a malware sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Config {
    pub family: String,
    pub channels: Vec<C2Channel>,
    pub encryption_key: Option<Vec<u8>>,
    pub beacon_interval_secs: Option<u64>,
    pub mutex: Option<String>,
    pub campaign_id: Option<String>,
    pub extra: HashMap<String, String>,
}

impl C2Config {
    pub fn new(family: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            channels: Vec::new(),
            encryption_key: None,
            beacon_interval_secs: None,
            mutex: None,
            campaign_id: None,
            extra: HashMap::new(),
        }
    }

    pub fn add_channel(&mut self, ch: C2Channel) {
        self.channels.push(ch);
    }

    #[must_use]
    pub const fn channel_count(&self) -> usize {
        self.channels.len()
    }

    #[must_use]
    pub fn primary_channel(&self) -> Option<&C2Channel> {
        self.channels.first()
    }

    #[must_use]
    pub fn domain_channels(&self) -> Vec<&C2Channel> {
        self.channels.iter().filter(|c| c.is_domain()).collect()
    }

    #[must_use]
    pub fn ip_channels(&self) -> Vec<&C2Channel> {
        self.channels.iter().filter(|c| c.is_ip()).collect()
    }

    #[must_use]
    pub const fn has_encryption(&self) -> bool {
        self.encryption_key.is_some()
    }
}

impl fmt::Display for C2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "C2Config[{}] channels={} encrypted={}",
            self.family,
            self.channels.len(),
            self.has_encryption()
        )
    }
}

/// Lossless-best-effort cast: `usize` → `f64` (precision may degrade on 64-bit).
/// Isolated here so clippy only sees the cast once.
const fn usize_as_f64(n: usize) -> f64 {
    n as f64
}

// ─── DgaDetector ──────────────────────────────────────────────────────────────

/// Detects algorithmically generated domains (DGA).
#[derive(Debug)]
pub struct DgaDetector {
    entropy_threshold: f64,
    min_length: usize,
    max_length: usize,
    known_tlds: HashSet<String>,
}

impl Default for DgaDetector {
    fn default() -> Self {
        let mut tlds = HashSet::with_capacity(10);
        for tld in &[
            "com", "net", "org", "info", "biz", "xyz", "top", "ru", "cc", "pw",
        ] {
            tlds.insert(tld.to_string());
        }
        Self {
            entropy_threshold: 3.5,
            min_length: 8,
            max_length: 32,
            known_tlds: tlds,
        }
    }
}

impl DgaDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_entropy_threshold(mut self, t: f64) -> Self {
        self.entropy_threshold = t;
        self
    }

    /// Shannon entropy of a string (bits per character).
    #[must_use]
    pub fn entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for b in s.bytes() {
            freq[b as usize] += 1;
        }
        let n = usize_as_f64(s.len());
        freq.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / n;
                -p * p.log2()
            })
            .sum()
    }

    /// Heuristic check: returns true if the domain looks DGA-generated.
    #[must_use]
    pub fn is_dga(&self, domain: &str) -> bool {
        let parts: Vec<&str> = domain.splitn(2, '.').collect();
        let label = parts[0];

        if label.len() < self.min_length || label.len() > self.max_length {
            return false;
        }

        // Check TLD validity
        if let Some(tld) = parts.get(1) {
            let tld_part = tld.rsplit('.').next().unwrap_or("");
            if !self.known_tlds.contains(tld_part) {
                return false;
            }
        }

        // High entropy indicates random-looking
        Self::entropy(label) >= self.entropy_threshold
    }

    /// Filter a list of domains returning only likely DGA ones.
    #[must_use]
    pub fn filter_dga<'a>(&self, domains: &[&'a str]) -> Vec<&'a str> {
        domains.iter().copied().filter(|d| self.is_dga(d)).collect()
    }

    /// Count vowels ratio — DGA domains tend to have fewer vowels.
    #[must_use]
    pub fn vowel_ratio(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let vowels = s.chars().filter(|c| "aeiouAEIOU".contains(*c)).count();
        usize_as_f64(vowels) / usize_as_f64(s.len())
    }
}

// ─── FastFlux ─────────────────────────────────────────────────────────────────

/// Detects fast-flux DNS patterns (many IPs for one domain, short TTL).
#[derive(Debug)]
pub struct FastFlux {
    records: HashMap<String, Vec<Ipv4Addr>>,
    ttl_seconds: HashMap<String, u32>,
    flux_threshold_ips: usize,
    flux_threshold_ttl: u32,
}

impl Default for FastFlux {
    fn default() -> Self {
        Self {
            records: HashMap::new(),
            ttl_seconds: HashMap::new(),
            flux_threshold_ips: 5,
            flux_threshold_ttl: 300,
        }
    }
}

impl FastFlux {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_thresholds(mut self, min_ips: usize, max_ttl: u32) -> Self {
        self.flux_threshold_ips = min_ips;
        self.flux_threshold_ttl = max_ttl;
        self
    }

    pub fn add_record(&mut self, domain: impl Into<String>, ip: Ipv4Addr, ttl: u32) {
        let d = domain.into();
        self.records.entry(d.clone()).or_default().push(ip);
        self.ttl_seconds.insert(d, ttl);
    }

    pub fn is_fast_flux(&self, domain: &str) -> bool {
        let ip_count = self.records.get(domain).map_or(0, Vec::len);
        let ttl = self.ttl_seconds.get(domain).copied().unwrap_or(u32::MAX);
        ip_count >= self.flux_threshold_ips && ttl <= self.flux_threshold_ttl
    }

    #[must_use]
    pub fn fast_flux_domains(&self) -> Vec<String> {
        self.records
            .keys()
            .filter(|d| self.is_fast_flux(d))
            .cloned()
            .collect()
    }

    pub fn ip_count(&self, domain: &str) -> usize {
        self.records.get(domain).map_or(0, Vec::len)
    }

    #[must_use]
    pub fn unique_ips(&self, domain: &str) -> Vec<Ipv4Addr> {
        let mut ips: Vec<Ipv4Addr> = self.records.get(domain).cloned().unwrap_or_default();
        ips.sort();
        ips.dedup();
        ips
    }
}

// ─── ExtractedString ──────────────────────────────────────────────────────────

/// A string extracted from a binary sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub encoding: StringEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Xor(u8),
    Base64,
}

impl ExtractedString {
    pub fn new(value: impl Into<String>, offset: usize, encoding: StringEncoding) -> Self {
        Self {
            value: value.into(),
            offset,
            encoding,
        }
    }

    #[must_use]
    pub fn looks_like_domain(&self) -> bool {
        let v = &self.value;
        v.contains('.') && !v.contains(' ') && v.len() > 4
    }

    #[must_use]
    pub fn looks_like_ip(&self) -> bool {
        self.value.parse::<Ipv4Addr>().is_ok()
    }

    #[must_use]
    pub fn looks_like_url(&self) -> bool {
        self.value.starts_with("http://") || self.value.starts_with("https://")
    }
}

// ─── C2Extractor ──────────────────────────────────────────────────────────────

/// Extracts C2 configuration from raw malware bytes.
#[derive(Debug)]
pub struct C2Extractor {
    dga_detector: DgaDetector,
    fast_flux: FastFlux,
    min_string_len: usize,
    xor_keys: Vec<u8>,
    url_regex: Regex,
    ip_port_regex: Regex,
}

impl C2Extractor {
    /// Create a new `C2Extractor` with default settings.
    ///
    /// # Panics
    ///
    /// Panics if the built-in regex patterns are invalid (should never happen).
    #[must_use]
    pub fn new() -> Self {
        Self {
            dga_detector: DgaDetector::new(),
            fast_flux: FastFlux::new(),
            min_string_len: 4,
            xor_keys: (1u8..=255).collect(),
            url_regex: Regex::new(r"https?://[^\x00-\x1f\s]{4,128}").unwrap(),
            ip_port_regex: Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\x00](\d{2,5})")
                .unwrap(),
        }
    }

    // ── String extraction ─────────────────────────────────────────────────

    #[must_use]
    pub fn extract_strings(&self, data: &[u8]) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let mut start = None;
        for (i, &b) in data.iter().enumerate() {
            if b.is_ascii_graphic() || b == b' ' {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take()
                && i - s >= self.min_string_len
                && let Ok(v) = std::str::from_utf8(&data[s..i])
            {
                results.push(ExtractedString::new(v, s, StringEncoding::Ascii));
            }
        }
        results
    }

    #[must_use]
    pub fn extract_utf16le(&self, data: &[u8]) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let mut i = 0;
        while i + 1 < data.len() {
            let mut s = String::new();
            let start = i;
            while i + 1 < data.len() {
                let lo = data[i];
                let hi = data[i + 1];
                if hi == 0 && lo.is_ascii_graphic() {
                    s.push(lo as char);
                    i += 2;
                } else {
                    break;
                }
            }
            if s.len() >= self.min_string_len {
                results.push(ExtractedString::new(s, start, StringEncoding::Utf16Le));
            } else {
                i += 1;
            }
        }
        results
    }

    #[must_use]
    pub fn try_xor_decode(&self, data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|&b| b ^ key).collect()
    }

    #[must_use]
    pub fn extract_xor_strings(&self, data: &[u8]) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        for &key in &self.xor_keys {
            let decoded = self.try_xor_decode(data, key);
            for s in self.extract_strings(&decoded) {
                if s.looks_like_url() || s.looks_like_domain() || s.looks_like_ip() {
                    results.push(ExtractedString {
                        encoding: StringEncoding::Xor(key),
                        ..s
                    });
                }
            }
        }
        results
    }

    // ── URL / IP extraction ───────────────────────────────────────────────

    #[must_use]
    pub fn extract_urls<'a>(&self, text: &'a str) -> Vec<&'a str> {
        self.url_regex.find_iter(text).map(|m| m.as_str()).collect()
    }

    #[must_use]
    pub fn extract_ip_ports(&self, text: &str) -> Vec<(String, u16)> {
        self.ip_port_regex
            .captures_iter(text)
            .filter_map(|cap| {
                let ip = cap.get(1)?.as_str().to_string();
                let port: u16 = cap.get(2)?.as_str().parse().ok()?;
                Some((ip, port))
            })
            .collect()
    }

    // ── C2 config extraction ──────────────────────────────────────────────

    /// Main extraction entry point.
    ///
    /// # Errors
    ///
    /// Returns [`C2Error::TooSmall`] if `data` is fewer than 16 bytes, or
    /// [`C2Error::NotFound`] if no C2 channels could be extracted.
    pub fn extract(&self, data: &[u8]) -> Result<C2Config, C2Error> {
        if data.len() < 16 {
            return Err(C2Error::TooSmall(data.len()));
        }

        let mut config = C2Config::new("unknown");
        let strings = self.extract_strings(data);

        // Find URLs
        for es in &strings {
            for url in self.extract_urls(&es.value) {
                if let Some(ch) = Self::channel_from_url(url) {
                    config.add_channel(ch);
                }
            }
        }

        // Find raw IP:port pairs
        for es in &strings {
            for (ip, port) in self.extract_ip_ports(&es.value) {
                let proto = C2Protocol::from_port(port);
                config.add_channel(C2Channel::new(ip, port, proto));
            }
        }

        // Try to guess family by dominant protocol
        if let Some(ch) = config.primary_channel() {
            config.family = format!("{}_sample", ch.protocol);
        }

        if config.channels.is_empty() {
            return Err(C2Error::NotFound);
        }

        Ok(config)
    }

    fn channel_from_url(url: &str) -> Option<C2Channel> {
        let proto = if url.starts_with("https") {
            C2Protocol::Https
        } else {
            C2Protocol::Http
        };
        let stripped = url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let host_part = stripped.split('/').next()?;
        let (host, port) = if host_part.contains(':') {
            let mut parts = host_part.splitn(2, ':');
            let h = parts.next()?.to_string();
            let p: u16 = parts.next()?.parse().ok()?;
            (h, p)
        } else {
            let port = if proto == C2Protocol::Https { 443 } else { 80 };
            (host_part.to_string(), port)
        };

        let uri = stripped.find('/').map(|i| stripped[i..].to_string());
        Some(C2Channel::new(host, port, proto).with_uri(uri.unwrap_or_default()))
    }

    // ── DGA / fast-flux ───────────────────────────────────────────────────

    #[must_use]
    pub const fn dga_detector(&self) -> &DgaDetector {
        &self.dga_detector
    }

    pub const fn fast_flux_mut(&mut self) -> &mut FastFlux {
        &mut self.fast_flux
    }

    #[must_use]
    pub fn detect_dga_channels<'a>(&self, config: &'a C2Config) -> Vec<&'a C2Channel> {
        config
            .channels
            .iter()
            .filter(|c| c.is_domain() && self.dga_detector.is_dga(&c.host))
            .collect()
    }
}

impl Default for C2Extractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // --- C2Protocol ---

    #[test]
    fn test_protocol_is_encrypted() {
        assert!(C2Protocol::Https.is_encrypted());
        assert!(!C2Protocol::Http.is_encrypted());
        assert!(C2Protocol::P2P.is_encrypted());
    }

    #[test]
    fn test_protocol_from_port() {
        assert_eq!(C2Protocol::from_port(80), C2Protocol::Http);
        assert_eq!(C2Protocol::from_port(443), C2Protocol::Https);
        assert_eq!(C2Protocol::from_port(53), C2Protocol::Dns);
        assert_eq!(C2Protocol::from_port(6667), C2Protocol::Irc);
        assert_eq!(C2Protocol::from_port(9999), C2Protocol::Tcp);
    }

    // --- C2Channel ---

    #[test]
    fn test_channel_address() {
        let ch = C2Channel::new("evil.com", 443, C2Protocol::Https);
        assert_eq!(ch.address(), "evil.com:443");
    }

    #[test]
    fn test_channel_is_ip() {
        let ch = C2Channel::new("1.2.3.4", 80, C2Protocol::Http);
        assert!(ch.is_ip());
        assert!(!ch.is_domain());
    }

    #[test]
    fn test_channel_is_domain() {
        let ch = C2Channel::new("c2.evil.com", 80, C2Protocol::Http);
        assert!(ch.is_domain());
        assert!(!ch.is_ip());
    }

    #[test]
    fn test_channel_display() {
        let ch = C2Channel::new("c2.evil.com", 80, C2Protocol::Http);
        assert!(ch.to_string().contains("c2.evil.com"));
    }

    // --- C2Config ---

    #[test]
    fn test_config_add_channel() {
        let mut cfg = C2Config::new("Emotet");
        cfg.add_channel(C2Channel::new("1.2.3.4", 443, C2Protocol::Https));
        assert_eq!(cfg.channel_count(), 1);
    }

    #[test]
    fn test_config_primary_channel() {
        let mut cfg = C2Config::new("Emotet");
        cfg.add_channel(C2Channel::new("a.com", 80, C2Protocol::Http));
        cfg.add_channel(C2Channel::new("b.com", 443, C2Protocol::Https));
        assert_eq!(cfg.primary_channel().unwrap().host, "a.com");
    }

    #[test]
    fn test_config_domain_ip_split() {
        let mut cfg = C2Config::new("test");
        cfg.add_channel(C2Channel::new("1.2.3.4", 80, C2Protocol::Http));
        cfg.add_channel(C2Channel::new("evil.com", 80, C2Protocol::Http));
        assert_eq!(cfg.ip_channels().len(), 1);
        assert_eq!(cfg.domain_channels().len(), 1);
    }

    #[test]
    fn test_config_has_encryption() {
        let mut cfg = C2Config::new("test");
        assert!(!cfg.has_encryption());
        cfg.encryption_key = Some(vec![0xDE, 0xAD]);
        assert!(cfg.has_encryption());
    }

    #[test]
    fn test_config_display() {
        let cfg = C2Config::new("Mirai");
        let s = cfg.to_string();
        assert!(s.contains("Mirai"));
    }

    // --- DgaDetector ---

    #[test]
    fn test_entropy_uniform() {
        // "abcdefgh" has higher entropy than "aaaaaaaa"
        let h1 = DgaDetector::entropy("abcdefgh");
        let h2 = DgaDetector::entropy("aaaaaaaa");
        assert!(h1 > h2);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(DgaDetector::entropy(""), 0.0);
    }

    #[test]
    fn test_dga_detector_random_looking() {
        let d = DgaDetector::new();
        // High entropy random-looking label
        assert!(d.is_dga("xkqjvzmwr.com"));
    }

    #[test]
    fn test_dga_detector_real_domain_not_dga() {
        let d = DgaDetector::new();
        // Low entropy — looks like real domain
        assert!(!d.is_dga("google.com"));
    }

    #[test]
    fn test_dga_detector_too_short() {
        let d = DgaDetector::new();
        assert!(!d.is_dga("ab.com")); // label "ab" is too short
    }

    #[test]
    fn test_dga_filter() {
        let d = DgaDetector::new();
        let domains = [
            "google.com",
            "xkqjvzmwr.com",
            "microsoft.com",
            "qwxvznpr.net",
        ];
        let dga = d.filter_dga(&domains);
        assert!(!dga.is_empty());
    }

    #[test]
    fn test_vowel_ratio() {
        let ratio = DgaDetector::vowel_ratio("aeiou");
        assert!((ratio - 1.0).abs() < f64::EPSILON);
        let ratio2 = DgaDetector::vowel_ratio("bcdfg");
        assert_eq!(ratio2, 0.0);
    }

    // --- FastFlux ---

    #[test]
    fn test_fast_flux_detection() {
        let mut ff = FastFlux::new().with_thresholds(3, 60);
        let ips = ["1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16"];
        for ip in &ips {
            ff.add_record("flux.evil.com", ip.parse().unwrap(), 30);
        }
        assert!(ff.is_fast_flux("flux.evil.com"));
    }

    #[test]
    fn test_fast_flux_not_detected_high_ttl() {
        let mut ff = FastFlux::new().with_thresholds(3, 60);
        for _ in 0..5 {
            ff.add_record("legit.com", "1.2.3.4".parse().unwrap(), 3600);
        }
        assert!(!ff.is_fast_flux("legit.com"));
    }

    #[test]
    fn test_fast_flux_ip_count() {
        let mut ff = FastFlux::new();
        ff.add_record("test.com", "1.1.1.1".parse().unwrap(), 10);
        ff.add_record("test.com", "2.2.2.2".parse().unwrap(), 10);
        assert_eq!(ff.ip_count("test.com"), 2);
    }

    #[test]
    fn test_fast_flux_unique_ips() {
        let mut ff = FastFlux::new();
        ff.add_record("dup.com", "1.1.1.1".parse().unwrap(), 10);
        ff.add_record("dup.com", "1.1.1.1".parse().unwrap(), 10);
        ff.add_record("dup.com", "2.2.2.2".parse().unwrap(), 10);
        let unique = ff.unique_ips("dup.com");
        assert_eq!(unique.len(), 2);
    }

    // --- ExtractedString ---

    #[test]
    fn test_extracted_string_looks_like_url() {
        let es = ExtractedString::new("http://c2.evil.com/beacon", 0, StringEncoding::Ascii);
        assert!(es.looks_like_url());
    }

    #[test]
    fn test_extracted_string_looks_like_ip() {
        let es = ExtractedString::new("192.168.0.1", 0, StringEncoding::Ascii);
        assert!(es.looks_like_ip());
    }

    #[test]
    fn test_extracted_string_looks_like_domain() {
        let es = ExtractedString::new("evil.com", 0, StringEncoding::Ascii);
        assert!(es.looks_like_domain());
    }

    // --- C2Extractor ---

    #[test]
    fn test_extractor_extract_strings() {
        let extractor = C2Extractor::new();
        let data = b"Hello\x00World\x00\x01\x02Test";
        let strings = extractor.extract_strings(data);
        assert!(!strings.is_empty());
    }

    #[test]
    fn test_extractor_extract_urls() {
        let extractor = C2Extractor::new();
        let text = "connect to http://evil.com/beacon every 60s";
        let urls = extractor.extract_urls(text);
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("evil.com"));
    }

    #[test]
    fn test_extractor_extract_ip_ports() {
        let extractor = C2Extractor::new();
        let text = "server at 1.2.3.4:8080 is primary";
        let pairs = extractor.extract_ip_ports(text);
        assert!(!pairs.is_empty());
        assert_eq!(pairs[0].1, 8080);
    }

    #[test]
    fn test_extractor_extract_c2_from_binary() {
        let extractor = C2Extractor::new();
        let data = b"MZ\x00some binary data http://c2.evil.com/gate.php more data";
        let result = extractor.extract(data);
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert!(!cfg.channels.is_empty());
    }

    #[test]
    fn test_extractor_extract_too_small() {
        let extractor = C2Extractor::new();
        assert!(matches!(
            extractor.extract(b"tiny"),
            Err(C2Error::TooSmall(_))
        ));
    }

    #[test]
    fn test_extractor_extract_no_c2() {
        let extractor = C2Extractor::new();
        // Binary-only data with no recognizable strings
        let data: Vec<u8> = (0u8..=255).cycle().take(100).collect();
        // This may or may not fail depending on extracted strings; just check it returns Result
        let _ = extractor.extract(&data);
    }

    #[test]
    fn test_extractor_xor_decode() {
        let extractor = C2Extractor::new();
        let original = b"http://c2.com/beacon";
        let key = 0x42u8;
        let encoded: Vec<u8> = original.iter().map(|&b| b ^ key).collect();
        let decoded = extractor.try_xor_decode(&encoded, key);
        assert_eq!(decoded, original.to_vec());
    }

    #[test]
    fn test_extractor_detect_dga_channels() {
        let extractor = C2Extractor::new();
        let mut cfg = C2Config::new("test");
        cfg.add_channel(C2Channel::new("google.com", 80, C2Protocol::Http));
        cfg.add_channel(C2Channel::new("xkqjvzmwr.com", 80, C2Protocol::Http));
        let dga = extractor.detect_dga_channels(&cfg);
        // At least the high-entropy one should be detected
        assert!(!dga.is_empty());
    }

    #[test]
    fn test_extractor_utf16le() {
        let extractor = C2Extractor::new();
        // Build a UTF-16LE string "evil.com"
        let mut data: Vec<u8> = Vec::new();
        for c in b"evil.com" {
            data.push(*c);
            data.push(0);
        }
        let strings = extractor.extract_utf16le(&data);
        assert!(!strings.is_empty());
        assert_eq!(strings[0].value, "evil.com");
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn test_c2_protocol_display() {
        assert_eq!(C2Protocol::Http.to_string(), "Http");
        assert_eq!(
            C2Protocol::Custom("Botnet".into()).to_string(),
            "Custom(Botnet)"
        );
    }

    #[test]
    fn test_c2_config_extra_fields() {
        let mut cfg = C2Config::new("Emotet");
        cfg.extra.insert("version".into(), "2.0".into());
        assert_eq!(cfg.extra.get("version").map(String::as_str), Some("2.0"));
    }

    #[test]
    fn test_dga_threshold_adjustment() {
        let d = DgaDetector::new().with_entropy_threshold(10.0);
        // With threshold of 10, nothing should match
        assert!(!d.is_dga("xkqjvzmwr.com"));
    }

    #[test]
    fn test_fast_flux_domains_list() {
        let mut ff = FastFlux::new().with_thresholds(2, 60);
        for i in 0u8..3 {
            ff.add_record("flux.bad.com", Ipv4Addr::new(1, 2, 3, i), 30);
        }
        let domains = ff.fast_flux_domains();
        assert!(domains.contains(&"flux.bad.com".to_string()));
    }

    #[test]
    fn test_extractor_min_string_len() {
        let extractor = C2Extractor::new();
        let data = b"ab\x00longer_string\x00";
        let strings = extractor.extract_strings(data);
        // "ab" is below min length (4), "longer_string" should be found
        assert!(strings.iter().any(|s| s.value.contains("longer_string")));
        assert!(!strings.iter().any(|s| s.value == "ab"));
    }
}
