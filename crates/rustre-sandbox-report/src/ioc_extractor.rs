//! `ioc_extractor` — IOC extraction from raw sandbox text/log data.
//!
//! Scans strings, process command lines, network logs, and registry activity
//! to extract Indicators of Compromise using regex-free finite-state pattern
//! matching suitable for no-std-compatible contexts.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Ioc, IocKind, IocSet};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum IocExtractorError {
    #[error("empty input")]
    EmptyInput,
    #[error("parse error: {0}")]
    ParseError(String),
}

// ─── IocExtractorConfig ───────────────────────────────────────────────────────

/// Bitmask controlling which IOC types to extract and deduplication behaviour.
#[derive(Debug, Clone, Copy)]
pub struct IocExtractFlags(u16);

impl IocExtractFlags {
    const IPS:      u16 = 0b0000_0000_0001;
    const DOMAINS:  u16 = 0b0000_0000_0010;
    const URLS:     u16 = 0b0000_0000_0100;
    const PATHS:    u16 = 0b0000_0000_1000;
    const REGISTRY: u16 = 0b0000_0001_0000;
    const MUTEXES:  u16 = 0b0000_0010_0000;
    const HASHES:   u16 = 0b0000_0100_0000;
    const EMAILS:   u16 = 0b0000_1000_0000;
    const DEDUP:    u16 = 0b0001_0000_0000;
    const SKIP_PRIV:u16 = 0b0010_0000_0000;
    const SKIP_BEN: u16 = 0b0100_0000_0000;

    /// Default flags (all types on, emails off, dedup + skip-private + skip-benign on).
    #[must_use]
    pub const fn defaults() -> Self {
        Self(Self::IPS | Self::DOMAINS | Self::URLS | Self::PATHS | Self::REGISTRY
            | Self::MUTEXES | Self::HASHES | Self::DEDUP | Self::SKIP_PRIV | Self::SKIP_BEN)
    }

    #[must_use] pub const fn extract_ips(self)         -> bool { self.0 & Self::IPS      != 0 }
    #[must_use] pub const fn extract_domains(self)     -> bool { self.0 & Self::DOMAINS  != 0 }
    #[must_use] pub const fn extract_urls(self)        -> bool { self.0 & Self::URLS     != 0 }
    #[must_use] pub const fn extract_paths(self)       -> bool { self.0 & Self::PATHS    != 0 }
    #[must_use] pub const fn extract_registry(self)    -> bool { self.0 & Self::REGISTRY != 0 }
    #[must_use] pub const fn extract_mutexes(self)     -> bool { self.0 & Self::MUTEXES  != 0 }
    #[must_use] pub const fn extract_hashes(self)      -> bool { self.0 & Self::HASHES   != 0 }
    #[must_use] pub const fn extract_emails(self)      -> bool { self.0 & Self::EMAILS   != 0 }
    #[must_use] pub const fn deduplicate(self)         -> bool { self.0 & Self::DEDUP    != 0 }
    #[must_use] pub const fn skip_private_ips(self)    -> bool { self.0 & Self::SKIP_PRIV!= 0 }
    #[must_use] pub const fn skip_benign_domains(self) -> bool { self.0 & Self::SKIP_BEN != 0 }

    /// Enable extraction of email addresses.
    #[must_use]
    pub const fn with_emails(self) -> Self { Self(self.0 | Self::EMAILS) }
    /// Include private IP addresses.
    #[must_use]
    pub const fn with_private_ips(self) -> Self { Self(self.0 & !Self::SKIP_PRIV) }
}

impl Default for IocExtractFlags {
    fn default() -> Self { Self::defaults() }
}

/// Configuration for the IOC extractor.
#[derive(Debug, Clone)]
pub struct IocExtractorConfig {
    /// Minimum confidence to include an extracted IOC.
    pub min_confidence: u8,
    /// Which IOC types to extract and how to post-process them.
    pub flags: IocExtractFlags,
}

impl Default for IocExtractorConfig {
    fn default() -> Self {
        Self {
            min_confidence: 50,
            flags: IocExtractFlags::defaults(),
        }
    }
}

impl IocExtractorConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_min_confidence(mut self, c: u8) -> Self {
        self.min_confidence = c;
        self
    }

    #[must_use]
    pub const fn include_private_ips(mut self) -> Self {
        self.flags = self.flags.with_private_ips();
        self
    }

    // Accessor forwarding methods for the flags.
    #[must_use] pub const fn extract_ips(&self)         -> bool { self.flags.extract_ips() }
    #[must_use] pub const fn extract_domains(&self)     -> bool { self.flags.extract_domains() }
    #[must_use] pub const fn extract_urls(&self)        -> bool { self.flags.extract_urls() }
    #[must_use] pub const fn extract_paths(&self)       -> bool { self.flags.extract_paths() }
    #[must_use] pub const fn extract_registry(&self)    -> bool { self.flags.extract_registry() }
    #[must_use] pub const fn extract_mutexes(&self)     -> bool { self.flags.extract_mutexes() }
    #[must_use] pub const fn extract_hashes(&self)      -> bool { self.flags.extract_hashes() }
    #[must_use] pub const fn extract_emails(&self)      -> bool { self.flags.extract_emails() }
    #[must_use] pub const fn deduplicate(&self)         -> bool { self.flags.deduplicate() }
    #[must_use] pub const fn skip_private_ips(&self)    -> bool { self.flags.skip_private_ips() }
    #[must_use] pub const fn skip_benign_domains(&self) -> bool { self.flags.skip_benign_domains() }
}

// ─── IP parsing ──────────────────────────────────────────────────────────────

/// Parse a dotted-decimal IPv4 address from `s`.
/// Returns `(octets, end_byte_offset)` or `None`.
fn parse_ipv4(s: &[u8], start: usize) -> Option<([u8; 4], usize)> {
    let mut octets = [0u8; 4];
    let mut pos = start;
    for (i, octet) in octets.iter_mut().enumerate() {
        if pos >= s.len() {
            return None;
        }
        let mut val: u32 = 0;
        let mut digits = 0usize;
        while pos < s.len() && s[pos].is_ascii_digit() {
            val = val * 10 + u32::from(s[pos] - b'0');
            if val > 255 {
                return None;
            }
            pos += 1;
            digits += 1;
        }
        if digits == 0 || digits > 3 {
            return None;
        }
        *octet = u8::try_from(val).unwrap_or(u8::MAX);
        if i < 3 {
            if pos >= s.len() || s[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    Some((octets, pos))
}

/// Returns `true` if `octets` represents a private/loopback/multicast address.
#[must_use]
const fn is_private_ip(octets: [u8; 4]) -> bool {
    matches!(
        octets,
        [10 | 127 | 255 | 224..=239, ..] | [172, 16..=31, ..] | [192, 168, ..] | [169, 254, ..]
    )
}

/// Extract all IPv4 addresses from `text`.
fn extract_ips(text: &str, skip_private: bool) -> Vec<(String, u8)> {
    let bytes = text.as_bytes();
    let mut results = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit()
            && let Some((octets, end)) = parse_ipv4(bytes, i)
        {
            // Ensure the next character is not a digit or dot (avoid matching partial numbers)
            // `:` (port separator) is a valid terminator — it must NOT
            // invalidate a preceding IPv4 match.  Only digits / dots
            // continuing the address are disqualifying.
            let after_ok = end >= bytes.len()
                || (!bytes[end].is_ascii_digit() && bytes[end] != b'.');
            // Ensure preceding character is not a digit or dot
            let before_ok = i == 0
                || (!bytes[i - 1].is_ascii_digit() && bytes[i - 1] != b'.');
            if after_ok
                && before_ok
                && (!skip_private || !is_private_ip(octets))
            {
                let ip = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
                results.push((ip, 85));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    results
}

// ─── Domain parsing ───────────────────────────────────────────────────────────

const KNOWN_TLDS: &[&str] = &[
    "com", "net", "org", "io", "co", "edu", "gov", "mil", "int", "biz", "info", "name", "pro",
    "aero", "coop", "museum", "xxx", "onion", "tk", "ru", "cn", "de", "uk", "fr", "jp", "au",
    "in", "br", "nl", "it", "es", "ca", "pl", "se", "no", "fi", "dk", "cz", "sk", "hu", "ro",
];

const BENIGN_DOMAINS: &[&str] = &[
    "microsoft.com",
    "google.com",
    "windows.com",
    "windowsupdate.com",
    "msftconnecttest.com",
    "googleapis.com",
    "gstatic.com",
    "live.com",
    "office.com",
    "outlook.com",
    "apple.com",
    "icloud.com",
    "akamai.net",
    "cloudflare.com",
    "digicert.com",
    "verisign.com",
    "ocsp.sectigo.com",
    "crl.microsoft.com",
];

const fn is_valid_domain_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

fn extract_domains(text: &str, skip_benign: bool) -> Vec<(String, u8)> {
    let mut results = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Split on whitespace and non-printable characters, then scan tokens.
    for token in text.split_whitespace() {
        let tok = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
        if tok.len() < 4 || tok.len() > 253 {
            continue;
        }
        // Must contain at least one dot.
        if !tok.contains('.') {
            continue;
        }
        // All parts must be valid label characters.
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() < 2 {
            continue;
        }
        if parts.iter().any(|p| p.is_empty() || p.len() > 63) {
            continue;
        }
        if !parts
            .iter()
            .all(|p| p.bytes().all(is_valid_domain_char))
        {
            continue;
        }
        // TLD must be known.
        let tld = parts.last().unwrap().to_ascii_lowercase();
        if !KNOWN_TLDS.contains(&tld.as_str()) {
            continue;
        }
        // Skip if all-numeric (IP address would already be caught).
        if parts.iter().all(|p| p.parse::<u32>().is_ok()) {
            continue;
        }
        let domain = tok.to_lowercase();
        if skip_benign && BENIGN_DOMAINS.iter().any(|b| domain.ends_with(b)) {
            continue;
        }
        if seen.insert(domain.clone()) {
            results.push((domain, 75));
        }
    }
    results
}

// ─── URL extraction ───────────────────────────────────────────────────────────

fn extract_urls(text: &str) -> Vec<(String, u8)> {
    let mut results = Vec::new();
    let prefixes = ["http://", "https://", "ftp://"];
    for &prefix in &prefixes {
        let mut search = text;
        while let Some(idx) = search.find(prefix) {
            let start = idx;
            let rest = &search[start..];
            // Take until whitespace or quote
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '>')
                .unwrap_or(rest.len());
            let url = &rest[..end];
            if url.len() > prefix.len() + 2 {
                results.push((url.to_owned(), 90));
            }
            search = &search[start + prefix.len()..];
        }
    }
    results
}

// ─── File path extraction ─────────────────────────────────────────────────────

fn extract_paths(text: &str) -> Vec<(String, u8)> {
    let mut results = Vec::new();
    let windows_prefixes = [r"C:\", r"D:\", r"E:\", r"%APPDATA%", r"%TEMP%", r"%USERPROFILE%"];
    let unix_prefixes = ["/tmp/", "/etc/", "/usr/", "/var/", "/home/", "/proc/"];

    for token in text.split_whitespace() {
        let tok = token.trim_matches(|c: char| c == '"' || c == '\'' || c == ',');
        for &pfx in windows_prefixes.iter().chain(unix_prefixes.iter()) {
            if tok.starts_with(pfx) || tok.to_uppercase().starts_with(&pfx.to_uppercase()) {
                results.push((tok.to_owned(), 80));
                break;
            }
        }
    }
    results
}

// ─── Registry key extraction ──────────────────────────────────────────────────

fn extract_registry_keys(text: &str) -> Vec<(String, u8)> {
    let mut results = Vec::new();
    let prefixes = [
        "HKEY_LOCAL_MACHINE",
        "HKEY_CURRENT_USER",
        "HKEY_CLASSES_ROOT",
        "HKEY_USERS",
        "HKLM\\",
        "HKCU\\",
        "HKCR\\",
    ];
    for token in text.split_whitespace() {
        let tok = token.trim_matches(|c: char| c == '"' || c == '\'');
        for &pfx in &prefixes {
            if tok.to_uppercase().starts_with(pfx) && tok.len() > pfx.len() + 2 {
                results.push((tok.to_owned(), 88));
                break;
            }
        }
    }
    results
}

// ─── Mutex extraction ─────────────────────────────────────────────────────────

fn extract_mutexes(text: &str) -> Vec<(String, u8)> {
    let mut results = Vec::new();
    let keywords = [
        "Global\\", "Local\\", "mutex_", "Mutex_", "MUTEX_",
        "_mutex", "_Mutex",
    ];
    for token in text.split_whitespace() {
        for &kw in &keywords {
            if token.contains(kw) {
                let trimmed = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-' && c != '\\');
                if trimmed.len() > 3 {
                    results.push((trimmed.to_owned(), 70));
                }
                break;
            }
        }
    }
    results
}

// ─── Hash extraction ──────────────────────────────────────────────────────────

fn is_hex_str(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn extract_hashes(text: &str) -> Vec<(String, u8)> {
    let mut results = Vec::new();
    // Hashes may be embedded in "key=value" style tokens (e.g. `md5=<hex>`).
    // Walk the whole text and collect every maximal hex run, then keep the ones
    // matching MD5 / SHA-1 / SHA-256 lengths.
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            // Safe: slice was checked to be ASCII hex digits, which are valid UTF-8.
            let tok = std::str::from_utf8(&bytes[start..i]).unwrap_or("");
            // Defensive: `is_hex_str` is the canonical predicate; using it
            // here keeps the helper wired into the public surface so future
            // refactors of the walker do not silently bypass validation.
            if is_hex_str(tok) {
                match tok.len() {
                    32 | 40 => results.push((tok.to_lowercase(), 95)), // MD5 / SHA-1
                    64 => results.push((tok.to_lowercase(), 98)),       // SHA-256
                    _ => {}
                }
            }
        } else {
            i += 1;
        }
    }
    results
}

// ─── Email extraction ─────────────────────────────────────────────────────────

fn extract_emails(text: &str) -> Vec<(String, u8)> {
    let mut results = Vec::new();
    for token in text.split_whitespace() {
        let tok = token.trim_matches(|c: char| c == ',' || c == '"' || c == '\'');
        if let Some(at_pos) = tok.find('@') {
            let local = &tok[..at_pos];
            let domain = &tok[at_pos + 1..];
            if !local.is_empty()
                && local.len() <= 64
                && domain.contains('.')
                && domain.len() > 3
                && domain.len() <= 255
                && local.bytes().all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&b))
            {
                results.push((tok.to_owned(), 80));
            }
        }
    }
    results
}

// ─── IocExtractor ────────────────────────────────────────────────────────────

/// Extracts IOCs from free-form text or log data.
#[derive(Debug, Clone)]
pub struct IocExtractor {
    config: IocExtractorConfig,
}

impl IocExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: IocExtractorConfig::default(),
        }
    }

    #[must_use]
    pub const fn with_config(config: IocExtractorConfig) -> Self {
        Self { config }
    }

    /// Extract all IOCs from `text` and return an `IocSet`.
    ///
    /// # Errors
    /// Returns `IocExtractorError::EmptyInput` if `text` is empty.
    pub fn extract(&self, text: &str) -> Result<IocSet, IocExtractorError> {
        if text.is_empty() {
            return Err(IocExtractorError::EmptyInput);
        }
        let mut set = IocSet::new();

        if self.config.extract_ips() {
            for (ip, conf) in extract_ips(text, self.config.skip_private_ips()) {
                if conf >= self.config.min_confidence {
                    set.add(Ioc::new(IocKind::Ip, ip, conf, "network traffic"));
                }
            }
        }

        if self.config.extract_domains() {
            for (dom, conf) in extract_domains(text, self.config.skip_benign_domains()) {
                if conf >= self.config.min_confidence {
                    set.add(Ioc::new(IocKind::Domain, dom, conf, "dns/network"));
                }
            }
        }

        if self.config.extract_urls() {
            for (url, conf) in extract_urls(text) {
                if conf >= self.config.min_confidence {
                    set.add(Ioc::new(IocKind::Url, url, conf, "http activity"));
                }
            }
        }

        if self.config.extract_paths() {
            for (path, conf) in extract_paths(text) {
                if conf >= self.config.min_confidence {
                    set.add(Ioc::new(IocKind::FilePath, path, conf, "file activity"));
                }
            }
        }

        if self.config.extract_registry() {
            for (key, conf) in extract_registry_keys(text) {
                if conf >= self.config.min_confidence {
                    set.add(Ioc::new(IocKind::RegistryKey, key, conf, "registry activity"));
                }
            }
        }

        if self.config.extract_mutexes() {
            for (mx, conf) in extract_mutexes(text) {
                if conf >= self.config.min_confidence {
                    set.add(Ioc::new(IocKind::Mutex, mx, conf, "synchronisation object"));
                }
            }
        }

        if self.config.extract_hashes() {
            for (hash, conf) in extract_hashes(text) {
                if conf >= self.config.min_confidence {
                    set.add(Ioc::new(IocKind::FileHash, hash, conf, "file hash"));
                }
            }
        }

        if self.config.extract_emails() {
            for (email, conf) in extract_emails(text) {
                if conf >= self.config.min_confidence {
                    set.add(Ioc::new(IocKind::Email, email, conf, "email address"));
                }
            }
        }

        if self.config.deduplicate() {
            set.deduplicate();
        }

        Ok(set)
    }

    /// Extract IOCs from multiple text sources and merge them.
    ///
    /// # Errors
    /// Returns `IocExtractorError::EmptyInput` if all inputs are empty.
    pub fn extract_from_sources(&self, sources: &[&str]) -> Result<IocSet, IocExtractorError> {
        let joined = sources.join("\n");
        self.extract(&joined)
    }

    /// Extract IOCs from a list of API call log lines.
    ///
    /// Parses lines of the form `"[PID:TS] API(arg1, arg2, ...)"`.
    /// Extracts embedded strings as potential IOCs.
    #[must_use]
    pub fn extract_from_api_log(&self, log: &str) -> IocSet {
        let text = log.lines()
            .flat_map(|line| {
                // Extract quoted strings from the line
                let mut strs = Vec::new();
                let mut in_quote = false;
                let mut buf = String::new();
                for c in line.chars() {
                    match c {
                        '"' => {
                            if in_quote && !buf.is_empty() {
                                strs.push(buf.clone());
                                buf.clear();
                            }
                            in_quote = !in_quote;
                        }
                        c if in_quote => buf.push(c),
                        _ => {}
                    }
                }
                strs
            })
            .collect::<Vec<_>>()
            .join("\n");

        self.extract(&text).unwrap_or_default()
    }
}

impl Default for IocExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ExtractionStats ─────────────────────────────────────────────────────────

/// Statistics from an extraction run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionStats {
    pub total_iocs: usize,
    pub ip_count: usize,
    pub domain_count: usize,
    pub url_count: usize,
    pub path_count: usize,
    pub registry_count: usize,
    pub mutex_count: usize,
    pub hash_count: usize,
    pub email_count: usize,
    pub avg_confidence: f64,
}

/// Converts a confidence sum and count to an `f64` average.
/// Both values are clamped to `u32` before conversion to avoid precision loss.
fn confidence_avg(sum: u64, count: usize) -> f64 {
    let sum32 = u32::try_from(sum).unwrap_or(u32::MAX);
    let cnt32 = u32::try_from(count).unwrap_or(u32::MAX);
    f64::from(sum32) / f64::from(cnt32)
}

impl ExtractionStats {
    /// Compute stats from an `IocSet`.
    #[must_use]
    pub fn from_ioc_set(set: &IocSet) -> Self {
        let total = set.iocs.len();
        let mut ip = 0;
        let mut dom = 0;
        let mut url = 0;
        let mut path = 0;
        let mut reg = 0;
        let mut mtx = 0;
        let mut hash = 0;
        let mut email = 0;
        let mut conf_sum: u64 = 0;

        for ioc in &set.iocs {
            conf_sum += u64::from(ioc.confidence);
            match ioc.kind {
                IocKind::Ip => ip += 1,
                IocKind::Domain => dom += 1,
                IocKind::Url => url += 1,
                IocKind::FilePath => path += 1,
                IocKind::RegistryKey => reg += 1,
                IocKind::Mutex => mtx += 1,
                IocKind::FileHash => hash += 1,
                IocKind::Email => email += 1,
                IocKind::Other(_) => {}
            }
        }

        let avg_confidence = if total > 0 {
            confidence_avg(conf_sum, total)
        } else {
            0.0
        };

        Self {
            total_iocs: total,
            ip_count: ip,
            domain_count: dom,
            url_count: url,
            path_count: path,
            registry_count: reg,
            mutex_count: mtx,
            hash_count: hash,
            email_count: email,
            avg_confidence,
        }
    }
}

// ─── MultiSourceExtractor ─────────────────────────────────────────────────────

/// Collects IOCs from multiple labelled sources and merges them into one set.
#[derive(Debug, Clone, Default)]
pub struct MultiSourceExtractor {
    extractor: IocExtractor,
    sources: Vec<(String, String)>, // (label, text)
}

impl MultiSourceExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(config: IocExtractorConfig) -> Self {
        Self {
            extractor: IocExtractor::with_config(config),
            sources: Vec::new(),
        }
    }

    /// Add a labelled text source.
    pub fn add_source(&mut self, label: impl Into<String>, text: impl Into<String>) {
        self.sources.push((label.into(), text.into()));
    }

    /// Run extraction on all sources and return a merged `IocSet` plus stats.
    #[must_use]
    pub fn run(&self) -> (IocSet, ExtractionStats) {
        let mut merged = IocSet::new();
        for (_, text) in &self.sources {
            if let Ok(set) = self.extractor.extract(text) {
                for ioc in set.iocs {
                    merged.add(ioc);
                }
            }
        }
        merged.deduplicate();
        let stats = ExtractionStats::from_ioc_set(&merged);
        (merged, stats)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extractor() -> IocExtractor {
        IocExtractor::new()
    }

    #[test]
    fn extract_public_ip() {
        let set = extractor()
            .extract("connecting to 185.220.101.1:443")
            .unwrap();
        let ips = set.by_kind(&IocKind::Ip);
        assert!(!ips.is_empty());
        assert_eq!(ips[0].value, "185.220.101.1");
    }

    #[test]
    fn skip_private_ip_by_default() {
        let set = extractor()
            .extract("dns query to 192.168.1.1")
            .unwrap();
        let ips = set.by_kind(&IocKind::Ip);
        assert!(ips.is_empty());
    }

    #[test]
    fn include_private_ip_when_configured() {
        let ex = IocExtractor::with_config(IocExtractorConfig::new().include_private_ips());
        let set = ex.extract("host 192.168.1.1 seen").unwrap();
        let ips = set.by_kind(&IocKind::Ip);
        assert!(!ips.is_empty());
    }

    #[test]
    fn extract_domain() {
        let set = extractor()
            .extract("dns query for evilsite.net")
            .unwrap();
        let doms = set.by_kind(&IocKind::Domain);
        assert!(!doms.is_empty());
    }

    #[test]
    fn skip_benign_domain() {
        let set = extractor()
            .extract("request to microsoft.com succeeded")
            .unwrap();
        let doms = set.by_kind(&IocKind::Domain);
        assert!(doms.iter().all(|d| !d.value.contains("microsoft")));
    }

    #[test]
    fn extract_url() {
        let set = extractor()
            .extract("GET https://c2.evil.io/beacon HTTP/1.1")
            .unwrap();
        let urls = set.by_kind(&IocKind::Url);
        assert!(!urls.is_empty());
    }

    #[test]
    fn extract_windows_path() {
        let set = extractor()
            .extract(r"wrote file C:\Windows\Temp\payload.exe")
            .unwrap();
        let paths = set.by_kind(&IocKind::FilePath);
        assert!(!paths.is_empty());
    }

    #[test]
    fn extract_registry_key() {
        let set = extractor()
            .extract(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run set to payload.exe")
            .unwrap();
        let regs = set.by_kind(&IocKind::RegistryKey);
        assert!(!regs.is_empty());
    }

    #[test]
    fn extract_sha256() {
        let sha = "a".repeat(64);
        let set = extractor()
            .extract(&format!("file hash {sha}"))
            .unwrap();
        let hashes = set.by_kind(&IocKind::FileHash);
        assert!(!hashes.is_empty());
    }

    #[test]
    fn extract_md5() {
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let set = extractor()
            .extract(&format!("md5={md5}"))
            .unwrap();
        let hashes = set.by_kind(&IocKind::FileHash);
        assert!(!hashes.is_empty());
    }

    #[test]
    fn extract_mutex() {
        let set = extractor()
            .extract("created mutex Global\\EvilMutex_2024")
            .unwrap();
        let mutexes = set.by_kind(&IocKind::Mutex);
        assert!(!mutexes.is_empty());
    }

    #[test]
    fn empty_input_errors() {
        let err = extractor().extract("").unwrap_err();
        assert!(matches!(err, IocExtractorError::EmptyInput));
    }

    #[test]
    fn deduplicate_removes_duplicates() {
        let set = extractor()
            .extract("185.220.101.1 185.220.101.1 185.220.101.1")
            .unwrap();
        let ips = set.by_kind(&IocKind::Ip);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn extract_from_sources() {
        let ex = extractor();
        let set = ex.extract_from_sources(&[
            "connected to 185.220.101.2",
            "dns malware.io resolved",
        ]).unwrap();
        assert!(!set.is_empty());
    }

    #[test]
    fn extraction_stats_counts() {
        let set = extractor()
            .extract("ip 8.8.1.2 domain evil.io")
            .unwrap();
        let stats = ExtractionStats::from_ioc_set(&set);
        assert!(stats.total_iocs > 0);
        assert!(stats.avg_confidence > 0.0);
    }

    #[test]
    fn multi_source_extractor() {
        let mut mse = MultiSourceExtractor::new();
        mse.add_source("network", "connected to 45.33.32.156");
        mse.add_source("registry", r"HKCU\Run set to bad.exe");
        let (_set, stats) = mse.run();
        assert!(stats.total_iocs > 0);
    }

    #[test]
    fn extract_from_api_log() {
        let log = r#"[1234:0] CreateFile("C:\evil\payload.exe", WRITE)"#;
        let ex = extractor();
        let set = ex.extract_from_api_log(log);
        // The quoted path should be extracted
        let paths = set.by_kind(&IocKind::FilePath);
        assert!(!paths.is_empty());
    }

    #[test]
    fn is_private_ip_loopback() {
        assert!(is_private_ip([127, 0, 0, 1]));
    }

    #[test]
    fn is_private_ip_rfc1918() {
        assert!(is_private_ip([10, 0, 0, 1]));
        assert!(is_private_ip([192, 168, 1, 1]));
        assert!(is_private_ip([172, 16, 0, 1]));
    }

    #[test]
    fn is_not_private_ip_public() {
        assert!(!is_private_ip([8, 8, 8, 8]));
        assert!(!is_private_ip([185, 220, 101, 1]));
    }

    #[test]
    fn parse_ipv4_valid() {
        let (octets, end) = parse_ipv4(b"1.2.3.4", 0).unwrap();
        assert_eq!(octets, [1, 2, 3, 4]);
        assert_eq!(end, 7);
    }

    #[test]
    fn parse_ipv4_invalid_octet() {
        assert!(parse_ipv4(b"999.0.0.1", 0).is_none());
    }

    #[test]
    fn extract_url_ftp() {
        let set = extractor()
            .extract("upload to ftp://files.evil.io/data.bin done")
            .unwrap();
        let urls = set.by_kind(&IocKind::Url);
        assert!(!urls.is_empty());
    }

    #[test]
    fn no_domain_from_integer_octets() {
        // Dotted IP should not also appear as domain
        let set = extractor()
            .extract("target 8.8.8.8")
            .unwrap();
        let doms = set.by_kind(&IocKind::Domain);
        assert!(doms.iter().all(|d| d.value != "8.8.8.8"));
    }

    #[test]
    fn extraction_stats_zero_for_empty_set() {
        let set = IocSet::new();
        let stats = ExtractionStats::from_ioc_set(&set);
        assert_eq!(stats.total_iocs, 0);
        assert!(stats.avg_confidence.abs() < f64::EPSILON);
    }
}
