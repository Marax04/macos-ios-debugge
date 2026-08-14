//! Memory string extraction and classification.
//!
//! Provides Unicode/ASCII scanners, URL detectors, IP/domain extractors,
//! credential pattern detectors, and entropy-based string classifiers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StringError {
    #[error("encoding error: {0}")]
    EncodingError(String),
    #[error("pattern compile error: {0}")]
    PatternError(String),
}

// ─── String classification ────────────────────────────────────────────────────

/// Classification of an extracted string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringClass {
    /// A URL (http/https/ftp/file/etc.).
    Url,
    /// An IPv4 address.
    Ipv4,
    /// An IPv6 address.
    Ipv6,
    /// A domain name.
    Domain,
    /// A file system path (Windows or UNIX).
    FilePath,
    /// A Windows registry key path.
    RegistryKey,
    /// A Base64-encoded blob.
    Base64,
    /// A credential-related string (password, token, key).
    Credential,
    /// A command-line invocation.
    CommandLine,
    /// An email address.
    Email,
    /// A GUID/UUID.
    Guid,
    /// A hex-encoded blob.
    HexBlob,
    /// An import/export name (from a PE section).
    PeSymbol,
    /// Appears to be obfuscated or high-entropy.
    HighEntropy,
    /// Unclassified printable string.
    Plain,
}

impl StringClass {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Domain => "domain",
            Self::FilePath => "filepath",
            Self::RegistryKey => "registry_key",
            Self::Base64 => "base64",
            Self::Credential => "credential",
            Self::CommandLine => "cmdline",
            Self::Email => "email",
            Self::Guid => "guid",
            Self::HexBlob => "hex_blob",
            Self::PeSymbol => "pe_symbol",
            Self::HighEntropy => "high_entropy",
            Self::Plain => "plain",
        }
    }
}

// ─── Extracted string ─────────────────────────────────────────────────────────

/// A string extracted from a memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    /// Virtual address where the string was found.
    pub address: u64,
    /// The string content.
    pub value: String,
    /// Encoding: "ascii" or "utf16le".
    pub encoding: String,
    /// Classification.
    pub class: StringClass,
    /// Shannon entropy of the string bytes.
    pub entropy: f32,
    /// Length in characters.
    pub length: usize,
}

impl ExtractedString {
    #[must_use]
    pub fn new(address: u64, value: String, encoding: &str) -> Self {
        let length = value.len();
        let entropy = string_entropy(&value);
        let class = StringClassifier::classify(&value);
        Self {
            address,
            value,
            encoding: encoding.to_string(),
            class,
            entropy,
            length,
        }
    }
}

fn string_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f32;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f32 / len;
        p.mul_add(-p.log2(), acc)
    })
}

// ─── ASCII scanner ────────────────────────────────────────────────────────────

/// Extracts ASCII printable strings from raw bytes.
pub struct AsciiScanner {
    pub min_length: usize,
}

impl AsciiScanner {
    #[must_use]
    pub const fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    /// Extract all ASCII strings from `data`, returning `(offset, string)` pairs.
    #[must_use]
    pub fn extract(&self, data: &[u8], base_addr: u64) -> Vec<ExtractedString> {
        let mut result = Vec::new();
        let mut run = Vec::<u8>::with_capacity(self.min_length * 2);
        let mut run_start = 0usize;
        for (i, &b) in data.iter().enumerate() {
            if (0x20..=0x7E).contains(&b) {
                if run.is_empty() {
                    run_start = i;
                }
                run.push(b);
            } else {
                if run.len() >= self.min_length
                    && let Ok(s) = String::from_utf8(run.clone()) {
                        result.push(ExtractedString::new(
                            base_addr + run_start as u64,
                            s,
                            "ascii",
                        ));
                    }
                run.clear();
            }
        }
        if run.len() >= self.min_length
            && let Ok(s) = String::from_utf8(run.clone()) {
                result.push(ExtractedString::new(
                    base_addr + run_start as u64,
                    s,
                    "ascii",
                ));
            }
        result
    }
}

// ─── UTF-16LE scanner ────────────────────────────────────────────────────────

/// Extracts UTF-16LE strings from raw bytes.
pub struct Utf16Scanner {
    pub min_length: usize,
}

impl Utf16Scanner {
    #[must_use]
    pub const fn new(min_length: usize) -> Self {
        Self { min_length }
    }

    #[must_use]
    pub fn extract(&self, data: &[u8], base_addr: u64) -> Vec<ExtractedString> {
        let mut result = Vec::new();
        let mut run: Vec<u16> = Vec::new();
        let mut run_start = 0usize;
        for (i, chunk) in data.chunks_exact(2).enumerate() {
            let w = u16::from_le_bytes([chunk[0], chunk[1]]);
            if (0x0020..=0x007E).contains(&w) {
                if run.is_empty() {
                    run_start = i * 2;
                }
                run.push(w);
            } else {
                if run.len() >= self.min_length {
                    let s = String::from_utf16_lossy(&run);
                    result.push(ExtractedString::new(
                        base_addr + run_start as u64,
                        s,
                        "utf16le",
                    ));
                }
                run.clear();
            }
        }
        if run.len() >= self.min_length {
            let s = String::from_utf16_lossy(&run);
            result.push(ExtractedString::new(
                base_addr + run_start as u64,
                s,
                "utf16le",
            ));
        }
        result
    }
}

// ─── String classifier ────────────────────────────────────────────────────────

/// Classifies strings by their content patterns.
pub struct StringClassifier;

impl StringClassifier {
    /// Classify a string based on its content.
    #[must_use]
    pub fn classify(s: &str) -> StringClass {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return StringClass::Plain;
        }

        if Self::is_url(trimmed) {
            return StringClass::Url;
        }
        if Self::is_ipv4(trimmed) {
            return StringClass::Ipv4;
        }
        if Self::is_ipv6(trimmed) {
            return StringClass::Ipv6;
        }
        if Self::is_email(trimmed) {
            return StringClass::Email;
        }
        if Self::is_guid(trimmed) {
            return StringClass::Guid;
        }
        if Self::is_registry_key(trimmed) {
            return StringClass::RegistryKey;
        }
        if Self::is_windows_path(trimmed) || Self::is_unix_path(trimmed) {
            return StringClass::FilePath;
        }
        if Self::is_credential(trimmed) {
            return StringClass::Credential;
        }
        if Self::is_command_line(trimmed) {
            return StringClass::CommandLine;
        }
        if Self::is_hex_blob(trimmed) {
            return StringClass::HexBlob;
        }
        if Self::is_base64(trimmed) {
            return StringClass::Base64;
        }
        if Self::is_domain(trimmed) {
            return StringClass::Domain;
        }
        if Self::is_pe_symbol(trimmed) {
            return StringClass::PeSymbol;
        }
        if string_entropy(trimmed) > 4.5 {
            return StringClass::HighEntropy;
        }
        StringClass::Plain
    }

    #[must_use]
    pub fn is_url(s: &str) -> bool {
        let lower = s.to_lowercase();
        lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ftp://")
            || lower.starts_with("file://")
            || lower.starts_with("ldap://")
            || lower.starts_with("smtp://")
    }

    #[must_use]
    pub fn is_ipv4(s: &str) -> bool {
        let mut parts = s.split('.');
        let count = parts.clone().count();
        if count != 4 {
            return false;
        }
        parts.all(|p| p.parse::<u8>().is_ok())
    }

    #[must_use]
    pub fn is_ipv6(s: &str) -> bool {
        s.contains(':')
            && s.len() >= 7
            && s.len() <= 39
            && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
    }

    #[must_use]
    pub fn is_email(s: &str) -> bool {
        let parts: Vec<&str> = s.split('@').collect();
        if parts.len() != 2 {
            return false;
        }
        !parts[0].is_empty() && parts[1].contains('.') && parts[1].len() > 2
    }

    #[must_use]
    pub fn is_guid(s: &str) -> bool {
        let s = s.trim_matches(|c| c == '{' || c == '}');
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return false;
        }
        let expected_lens = [8, 4, 4, 4, 12];
        parts
            .iter()
            .zip(expected_lens.iter())
            .all(|(p, &l)| p.len() == l && p.chars().all(|c| c.is_ascii_hexdigit()))
    }

    #[must_use]
    pub fn is_registry_key(s: &str) -> bool {
        let upper = s.to_uppercase();
        upper.starts_with("HKLM\\")
            || upper.starts_with("HKCU\\")
            || upper.starts_with("HKEY_LOCAL_MACHINE\\")
            || upper.starts_with("HKEY_CURRENT_USER\\")
            || upper.starts_with("HKCR\\")
            || upper.starts_with("HKU\\")
    }

    #[must_use]
    pub fn is_windows_path(s: &str) -> bool {
        let upper = s.to_uppercase();
        (upper.starts_with("C:\\")
            || upper.starts_with("D:\\")
            || upper.starts_with("E:\\")
            || upper.starts_with("\\DEVICE\\")
            || upper.starts_with("\\\\"))
            && s.len() > 3
    }

    #[must_use]
    pub fn is_unix_path(s: &str) -> bool {
        s.starts_with("/proc/")
            || s.starts_with("/sys/")
            || s.starts_with("/etc/")
            || s.starts_with("/usr/")
            || s.starts_with("/var/")
            || s.starts_with("/home/")
            || s.starts_with("/dev/")
            || s.starts_with("/tmp/")
    }

    #[must_use]
    pub fn is_credential(s: &str) -> bool {
        let lower = s.to_lowercase();
        let keywords = [
            "password",
            "passwd",
            "secret",
            "apikey",
            "api_key",
            "token",
            "bearer ",
            "authorization:",
            "private_key",
            "access_key",
            "aws_",
            "auth_token",
        ];
        keywords.iter().any(|k| lower.contains(k))
    }

    #[must_use]
    pub fn is_command_line(s: &str) -> bool {
        let lower = s.to_lowercase();
        // Starts with common command prefixes
        lower.starts_with("cmd.exe")
            || lower.starts_with("powershell")
            || lower.starts_with("wscript")
            || lower.starts_with("cscript")
            || lower.starts_with("python")
            || lower.starts_with("bash")
            || lower.starts_with("sh ")
            || lower.starts_with("net ")
            || (s.contains(".exe ") && s.contains(' '))
    }

    #[must_use]
    pub fn is_hex_blob(s: &str) -> bool {
        s.len() >= 32 && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    #[must_use]
    pub fn is_base64(s: &str) -> bool {
        if s.len() < 16 {
            return false;
        }
        let b64_chars = s
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .count();
        let ratio = b64_chars as f32 / s.len() as f32;
        ratio > 0.95 && s.len().is_multiple_of(4)
    }

    #[must_use]
    pub fn is_domain(s: &str) -> bool {
        let tlds = [
            ".com", ".net", ".org", ".io", ".gov", ".edu", ".co.uk", ".de", ".ru", ".cn", ".info",
            ".biz", ".us", ".uk",
        ];
        let lower = s.to_lowercase();
        tlds.iter().any(|t| lower.ends_with(t))
            && s.len() > 4
            && s.chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    }

    #[must_use]
    pub fn is_pe_symbol(s: &str) -> bool {
        // Common PE export names: Pascal or snake_case ASCII identifiers
        s.len() >= 4
            && s.len() <= 64
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@' || c == '?')
            && s.chars().any(char::is_alphabetic)
    }

    /// Classify a collection of strings and return counts per class.
    #[must_use]
    pub fn classify_batch(strings: &[ExtractedString]) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::with_capacity(16);
        for s in strings {
            *counts.entry(s.class.as_str().to_string()).or_insert(0) += 1;
        }
        counts
    }
}

// ─── URL extractor ────────────────────────────────────────────────────────────

/// High-performance URL extractor.
pub struct UrlExtractor;

impl UrlExtractor {
    #[must_use]
    pub fn extract_from_bytes(data: &[u8]) -> Vec<String> {
        let mut urls = Vec::new();
        let schemes: &[&[u8]] = &[b"http://", b"https://", b"ftp://", b"file://", b"ldap://"];
        for scheme in schemes {
            let mut pos = 0;
            while pos + scheme.len() < data.len() {
                if data[pos..].starts_with(scheme) {
                    let end = data[pos..]
                        .iter()
                        .position(|&b| {
                            b == b' '
                                || b == b'\x00'
                                || b == b'\n'
                                || b == b'\r'
                                || b == b'"'
                                || b == b'\''
                                || b < 0x20
                        }).map_or_else(|| data.len().min(pos + 2048), |i| pos + i);
                    if end > pos + scheme.len()
                        && let Ok(s) = std::str::from_utf8(&data[pos..end]) {
                            urls.push(s.to_string());
                        }
                    pos = end;
                } else {
                    pos += 1;
                }
            }
        }
        urls.sort();
        urls.dedup();
        urls
    }

    /// Extract URLs from a list of already-extracted strings.
    #[must_use]
    pub fn from_strings(strings: &[ExtractedString]) -> Vec<String> {
        strings
            .iter()
            .filter(|s| s.class == StringClass::Url)
            .map(|s| s.value.clone())
            .collect()
    }
}

// ─── IP address extractor ─────────────────────────────────────────────────────

/// Extracts IPv4 and IPv6 addresses from raw bytes.
pub struct IpExtractor;

impl IpExtractor {
    /// Extract IPv4 addresses from a string.
    #[must_use]
    pub fn extract_ipv4_from_str(s: &str) -> Vec<String> {
        let mut result = Vec::new();
        let bytes = s.as_bytes();
        let mut pos = 0;
        while pos < bytes.len() {
            // Look for a digit followed by dots
            if bytes[pos].is_ascii_digit() {
                let start = pos;
                let mut end = pos;
                while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
                    end += 1;
                }
                let candidate = &s[start..end];
                if StringClassifier::is_ipv4(candidate) {
                    result.push(candidate.to_string());
                    pos = end;
                    continue;
                }
            }
            pos += 1;
        }
        result
    }

    /// Extract private IPv4 ranges.
    #[must_use]
    pub fn is_private_ipv4(s: &str) -> bool {
        s.starts_with("10.")
            || s.starts_with("192.168.")
            || (s.starts_with("172.") && {
                let second: u8 = s
                    .split('.')
                    .nth(1)
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0);
                (16..=31).contains(&second)
            })
    }
}

// ─── Credential pattern detector ─────────────────────────────────────────────

/// A detected credential pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPattern {
    pub pattern_type: CredentialPatternType,
    pub raw_value: String,
    pub address: u64,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialPatternType {
    NtlmHash,
    LmHash,
    Base64Encoded,
    PlainTextPassword,
    BearerToken,
    ApiKey,
    AwsKey,
    PrivateKeyPem,
    KerberosTicket,
}

impl CredentialPatternType {
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::NtlmHash => "ntlm_hash",
            Self::LmHash => "lm_hash",
            Self::Base64Encoded => "base64",
            Self::PlainTextPassword => "plaintext_password",
            Self::BearerToken => "bearer_token",
            Self::ApiKey => "api_key",
            Self::AwsKey => "aws_key",
            Self::PrivateKeyPem => "private_key_pem",
            Self::KerberosTicket => "kerberos_ticket",
        }
    }
}

pub struct CredentialDetector;

impl CredentialDetector {
    /// Scan strings for credential patterns.
    #[must_use]
    pub fn detect(strings: &[ExtractedString]) -> Vec<CredentialPattern> {
        let mut patterns = Vec::new();
        for s in strings {
            let value = s.value.trim();
            // NTLM hash: 32 hex chars
            if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
                patterns.push(CredentialPattern {
                    pattern_type: CredentialPatternType::NtlmHash,
                    raw_value: value.to_string(),
                    address: s.address,
                    confidence: 0.7,
                });
                continue;
            }
            // AWS access key: starts with AKIA
            if value.starts_with("AKIA")
                && value.len() == 20
                && value
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            {
                patterns.push(CredentialPattern {
                    pattern_type: CredentialPatternType::AwsKey,
                    raw_value: value.to_string(),
                    address: s.address,
                    confidence: 0.95,
                });
                continue;
            }
            // Bearer token
            let lower = value.to_lowercase();
            if lower.starts_with("bearer ") && value.len() > 10 {
                patterns.push(CredentialPattern {
                    pattern_type: CredentialPatternType::BearerToken,
                    raw_value: value.to_string(),
                    address: s.address,
                    confidence: 0.9,
                });
                continue;
            }
            // PEM private key
            if value.contains("BEGIN PRIVATE KEY") || value.contains("BEGIN RSA PRIVATE KEY") {
                patterns.push(CredentialPattern {
                    pattern_type: CredentialPatternType::PrivateKeyPem,
                    raw_value: value.chars().take(64).collect(),
                    address: s.address,
                    confidence: 0.99,
                });
                continue;
            }
            // Base64 blobs (potential encoded credentials)
            if s.class == StringClass::Base64 && s.length >= 32 {
                patterns.push(CredentialPattern {
                    pattern_type: CredentialPatternType::Base64Encoded,
                    raw_value: value.chars().take(64).collect(),
                    address: s.address,
                    confidence: 0.5,
                });
            }
        }
        patterns
    }

    /// Scan raw bytes for NT hash patterns.
    #[must_use]
    pub fn scan_nt_hashes(data: &[u8]) -> Vec<(u64, String)> {
        let mut hashes = Vec::new();
        let mut pos = 0usize;
        while pos + 32 <= data.len() {
            let slice = &data[pos..pos + 32];
            if slice.iter().all(u8::is_ascii_hexdigit)
                && let Ok(s) = std::str::from_utf8(slice) {
                    hashes.push((pos as u64, s.to_string()));
                    pos += 32;
                    continue;
                }
            pos += 1;
        }
        hashes
    }
}

// ─── Combined memory string analyzer ─────────────────────────────────────────

/// Unified memory string analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStringAnalysis {
    pub total_strings: usize,
    pub ascii_count: usize,
    pub unicode_count: usize,
    pub class_distribution: HashMap<String, usize>,
    pub urls: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub domains: Vec<String>,
    pub credentials: Vec<CredentialPattern>,
    pub top_strings: Vec<ExtractedString>,
}

impl MemoryStringAnalysis {
    #[must_use]
    pub fn analyze(data: &[u8], base_addr: u64, min_len: usize) -> Self {
        let ascii = AsciiScanner::new(min_len).extract(data, base_addr);
        let unicode = Utf16Scanner::new(min_len).extract(data, base_addr);
        let ascii_count = ascii.len();
        let unicode_count = unicode.len();
        let mut all: Vec<ExtractedString> = ascii.into_iter().chain(unicode).collect();
        all.sort_by_key(|a| a.address);
        let total_strings = all.len();
        let class_distribution = StringClassifier::classify_batch(&all);
        let urls: Vec<String> = all
            .iter()
            .filter(|s| s.class == StringClass::Url)
            .map(|s| s.value.clone())
            .collect();
        let ip_addresses: Vec<String> = all
            .iter()
            .filter(|s| s.class == StringClass::Ipv4 || s.class == StringClass::Ipv6)
            .map(|s| s.value.clone())
            .collect();
        let domains: Vec<String> = all
            .iter()
            .filter(|s| s.class == StringClass::Domain)
            .map(|s| s.value.clone())
            .collect();
        let credentials = CredentialDetector::detect(&all);
        // Top strings by entropy descending
        let mut top = all.clone();
        top.sort_by(|a, b| {
            b.entropy
                .partial_cmp(&a.entropy)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        top.truncate(20);
        Self {
            total_strings,
            ascii_count,
            unicode_count,
            class_distribution,
            urls,
            ip_addresses,
            domains,
            credentials,
            top_strings: top,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_scanner_extracts() {
        let data = b"hello world\x00short\x00this is long enough";
        let scanner = AsciiScanner::new(8);
        let strings = scanner.extract(data, 0x1000);
        assert!(strings.iter().any(|s| s.value.contains("hello world")));
        assert!(!strings.iter().any(|s| s.value == "short"));
    }

    #[test]
    fn utf16_scanner_extracts() {
        let mut data = Vec::new();
        for c in "hello world utf16".chars() {
            data.extend_from_slice(&(c as u16).to_le_bytes());
        }
        data.extend_from_slice(&[0, 0]);
        let scanner = Utf16Scanner::new(6);
        let strings = scanner.extract(&data, 0x2000);
        assert!(strings.iter().any(|s| s.value.contains("hello")));
        assert_eq!(strings[0].encoding, "utf16le");
    }

    #[test]
    fn classify_url() {
        assert_eq!(
            StringClassifier::classify("https://example.com/path"),
            StringClass::Url
        );
        assert_eq!(
            StringClassifier::classify("http://evil.com"),
            StringClass::Url
        );
    }

    #[test]
    fn classify_ipv4() {
        assert_eq!(
            StringClassifier::classify("192.168.1.100"),
            StringClass::Ipv4
        );
        assert_ne!(StringClassifier::classify("999.1.2.3"), StringClass::Ipv4);
    }

    #[test]
    fn classify_email() {
        assert_eq!(
            StringClassifier::classify("user@example.com"),
            StringClass::Email
        );
        assert_ne!(StringClassifier::classify("notanemail"), StringClass::Email);
    }

    #[test]
    fn classify_guid() {
        let guid = "{550e8400-e29b-41d4-a716-446655440000}";
        assert_eq!(StringClassifier::classify(guid), StringClass::Guid);
    }

    #[test]
    fn classify_registry_key() {
        assert_eq!(
            StringClassifier::classify(r"HKLM\SOFTWARE\Microsoft\Windows"),
            StringClass::RegistryKey
        );
        assert_eq!(
            StringClassifier::classify(r"HKCU\Software\test"),
            StringClass::RegistryKey
        );
    }

    #[test]
    fn classify_windows_path() {
        assert_eq!(
            StringClassifier::classify(r"C:\Windows\System32\notepad.exe"),
            StringClass::FilePath
        );
    }

    #[test]
    fn classify_base64() {
        // Valid base64 string
        let b64 = "dGVzdHRlc3R0ZXN0dGVzdA=="; // "testtesttesttest"
        assert_eq!(StringClassifier::classify(b64), StringClass::Base64);
    }

    #[test]
    fn classify_hex_blob() {
        let hex = "deadbeefcafebabe0102030405060708090a0b0c0d0e0f10";
        assert_eq!(StringClassifier::classify(hex), StringClass::HexBlob);
    }

    #[test]
    fn credential_detector_ntlm() {
        let strings = vec![ExtractedString {
            address: 0x1000,
            value: "31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            encoding: "ascii".into(),
            class: StringClass::HexBlob,
            entropy: 3.5,
            length: 32,
        }];
        let creds = CredentialDetector::detect(&strings);
        assert!(!creds.is_empty());
        assert_eq!(creds[0].pattern_type, CredentialPatternType::NtlmHash);
    }

    #[test]
    fn credential_detector_aws_key() {
        let strings = vec![ExtractedString {
            address: 0x2000,
            value: "AKIAIOSFODNN7EXAMPLE".into(),
            encoding: "ascii".into(),
            class: StringClass::Plain,
            entropy: 3.0,
            length: 20,
        }];
        let creds = CredentialDetector::detect(&strings);
        assert!(!creds.is_empty());
        assert_eq!(creds[0].pattern_type, CredentialPatternType::AwsKey);
    }

    #[test]
    fn ip_extractor_private() {
        assert!(IpExtractor::is_private_ipv4("10.0.0.1"));
        assert!(IpExtractor::is_private_ipv4("192.168.1.1"));
        assert!(IpExtractor::is_private_ipv4("172.16.0.1"));
        assert!(!IpExtractor::is_private_ipv4("8.8.8.8"));
    }

    #[test]
    fn ip_extractor_from_string() {
        let s = "connected to 192.168.1.1 and also 10.0.0.1";
        let ips = IpExtractor::extract_ipv4_from_str(s);
        assert!(ips.contains(&"192.168.1.1".to_string()));
        assert!(ips.contains(&"10.0.0.1".to_string()));
    }

    #[test]
    fn url_extractor_from_bytes() {
        let data = b"GET https://example.com/path HTTP/1.1\r\nHost: example.com\r\n";
        let urls = UrlExtractor::extract_from_bytes(data);
        assert!(urls.iter().any(|u| u.contains("example.com")));
    }

    #[test]
    fn memory_string_analysis() {
        let data = b"https://c2.evil.com/beacon\x00password=secret123\x00127.0.0.1\x00";
        let analysis = MemoryStringAnalysis::analyze(data, 0x1000, 6);
        assert!(analysis.total_strings > 0);
    }

    #[test]
    fn string_class_as_str() {
        assert_eq!(StringClass::Url.as_str(), "url");
        assert_eq!(StringClass::HighEntropy.as_str(), "high_entropy");
        assert_eq!(StringClass::Credential.as_str(), "credential");
    }
}
