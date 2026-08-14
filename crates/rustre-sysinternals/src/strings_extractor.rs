//! `strings_extractor` — Strings.exe-equivalent
//!
//! Scans memory/file for ASCII and Unicode strings, minimum-length filtering,
//! encoding detection, deduplication, classification, and export.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::SysinternalsError;

// ─── StringEncoding ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
    Utf16Be,
    Utf8,
    Latin1,
}

impl fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ascii => write!(f, "ASCII"),
            Self::Utf16Le => write!(f, "UTF-16LE"),
            Self::Utf16Be => write!(f, "UTF-16BE"),
            Self::Utf8 => write!(f, "UTF-8"),
            Self::Latin1 => write!(f, "Latin-1"),
        }
    }
}

// ─── StringCategory ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StringCategory {
    FilePath,
    RegistryKey,
    Url,
    IpAddress,
    Email,
    CreditCard,
    ApiName,
    GuidOrClsid,
    Base64,
    CommandLine,
    UserAgent,
    DomainName,
    ErrorMessage,
    Generic,
}

impl fmt::Display for StringCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FilePath => "FilePath",
            Self::RegistryKey => "RegistryKey",
            Self::Url => "URL",
            Self::IpAddress => "IPAddress",
            Self::Email => "Email",
            Self::CreditCard => "CreditCard",
            Self::ApiName => "APIName",
            Self::GuidOrClsid => "GUID/CLSID",
            Self::Base64 => "Base64",
            Self::CommandLine => "CommandLine",
            Self::UserAgent => "UserAgent",
            Self::DomainName => "Domain",
            Self::ErrorMessage => "ErrorMessage",
            Self::Generic => "Generic",
        };
        write!(f, "{s}")
    }
}

// ─── ExtractedString ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    /// The string value.
    pub value: String,
    /// Byte offset within the source.
    pub offset: u64,
    /// Source section or region name.
    pub section: String,
    /// Encoding.
    pub encoding: StringEncoding,
    /// Length in characters.
    pub length: usize,
    /// Heuristic category.
    pub category: StringCategory,
    /// Entropy of the string (0.0 to 8.0 bits per byte).
    pub entropy: f64,
    /// Whether this string appears to be encrypted/obfuscated.
    pub possibly_obfuscated: bool,
    /// Number of times this exact string appeared (after dedup).
    pub occurrence_count: u32,
}

impl ExtractedString {
    #[must_use]
    pub fn new(
        value: impl Into<String>,
        offset: u64,
        section: impl Into<String>,
        encoding: StringEncoding,
    ) -> Self {
        let value = value.into();
        let length = value.chars().count();
        let entropy = compute_entropy(value.as_bytes());
        let category = classify_string(&value);
        let possibly_obfuscated = entropy > 5.5 && length > 10;
        Self {
            value,
            offset,
            section: section.into(),
            encoding,
            length,
            category,
            entropy,
            possibly_obfuscated,
            occurrence_count: 1,
        }
    }

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{:#010x},{},{},{},{:.3},{},{}",
            crate::csv_field(&self.value),
            self.offset,
            crate::csv_field(&self.section),
            self.encoding,
            self.category,
            self.entropy,
            self.occurrence_count,
            self.possibly_obfuscated,
        )
    }
}

// ─── Shannon entropy ─────────────────────────────────────────────────────────

fn usize_to_f64(x: usize) -> f64 {
    let lo = u32::try_from(x & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let hi = u32::try_from(x.checked_shr(32).unwrap_or(0)).unwrap_or(0);
    f64::from(hi).mul_add(4_294_967_296.0_f64, f64::from(lo))
}
fn u64_to_usize(x: u64) -> usize { usize::try_from(x).unwrap_or(usize::MAX) }

fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = usize_to_f64(data.len());
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy
}

// ─── String classifier ────────────────────────────────────────────────────────

fn classify_string(s: &str) -> StringCategory {
    // URL
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
        return StringCategory::Url;
    }
    // Email
    if s.contains('@') && s.contains('.') && !s.contains(' ') && s.len() < 80 {
        let at = s.find('@').unwrap();
        let after_at = &s[at + 1..];
        if after_at.contains('.') {
            return StringCategory::Email;
        }
    }
    // Registry
    if s.to_uppercase().starts_with("HKEY_") || s.starts_with("HKLM\\") || s.starts_with("HKCU\\") {
        return StringCategory::RegistryKey;
    }
    // File path (Windows)
    if (s.len() > 3 && s.chars().nth(1) == Some(':') && s.chars().nth(2) == Some('\\'))
        || s.starts_with("\\\\")
        || s.starts_with("\\??\\")
        || s.starts_with("\\Device\\")
    {
        return StringCategory::FilePath;
    }
    // Unix path
    if s.starts_with("/usr/") || s.starts_with("/etc/") || s.starts_with("/proc/") || s.starts_with("/tmp/") {
        return StringCategory::FilePath;
    }
    // IP address
    if is_ip_address(s) {
        return StringCategory::IpAddress;
    }
    // GUID
    if is_guid(s) {
        return StringCategory::GuidOrClsid;
    }
    // API name (common patterns)
    if is_api_name(s) {
        return StringCategory::ApiName;
    }
    // Base64
    if is_likely_base64(s) {
        return StringCategory::Base64;
    }
    // Command line
    if s.contains(" -") && (s.contains(".exe") || s.contains("cmd") || s.contains("powershell")) {
        return StringCategory::CommandLine;
    }
    // User-Agent
    if s.contains("Mozilla/") || s.contains("AppleWebKit") || s.contains("User-Agent") {
        return StringCategory::UserAgent;
    }
    // Domain-like
    if is_domain_like(s) {
        return StringCategory::DomainName;
    }
    StringCategory::Generic
}

fn is_ip_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        return parts.iter().all(|p| p.parse::<u8>().is_ok());
    }
    false
}

fn is_guid(s: &str) -> bool {
    let s = s.trim_matches(|c| c == '{' || c == '}');
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() == 5 {
        let lens = [8, 4, 4, 4, 12];
        return parts
            .iter()
            .zip(lens.iter())
            .all(|(p, &l)| p.len() == l && p.chars().all(|c| c.is_ascii_hexdigit()));
    }
    false
}

const API_PREFIXES: &[&str] = &[
    "Nt", "Zw", "Rtl", "Ldr", "Mm", "Ex", "Ke", "Io", "Ps", "Ob",
    "Se", "Ci", "Cm", "Reg", "Http", "Crypto", "Bcrypt", "Ncrypt",
];

fn is_api_name(s: &str) -> bool {
    if s.len() < 4 || s.len() > 80 {
        return false;
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    API_PREFIXES.iter().any(|&p| s.starts_with(p))
        || s.ends_with('A')
        || s.ends_with('W')
        || s.ends_with("Ex")
}

fn is_likely_base64(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }
    let base64_chars: HashSet<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            .chars()
            .collect();
    let pct = usize_to_f64(s.chars().filter(|c| base64_chars.contains(c)).count()) / usize_to_f64(s.len());
    pct > 0.92 && s.len().is_multiple_of(4)
}

fn is_domain_like(s: &str) -> bool {
    if s.len() < 4 || s.len() > 255 || s.contains(' ') {
        return false;
    }
    let tlds = [".com", ".net", ".org", ".io", ".gov", ".edu", ".ru", ".cn", ".uk", ".de"];
    tlds.iter().any(|tld| s.ends_with(tld))
}

// ─── ExtractionOptions ───────────────────────────────────────────────────────

/// Encoding flags for string extraction, grouped to avoid struct-excessive-bools.
#[derive(Debug, Clone)]
pub struct EncodingFlags {
    /// Extract ASCII strings.
    pub ascii: bool,
    /// Extract UTF-16LE strings.
    pub utf16le: bool,
    /// Extract UTF-16BE strings.
    pub utf16be: bool,
}

impl Default for EncodingFlags {
    fn default() -> Self {
        Self { ascii: true, utf16le: true, utf16be: false }
    }
}

#[derive(Debug, Clone)]
pub struct ExtractionOptions {
    /// Minimum string length (default: 4).
    pub min_length: usize,
    /// Maximum string length (0 = no limit).
    pub max_length: usize,
    /// Encoding flags (ASCII, UTF-16LE, UTF-16BE).
    pub encodings: EncodingFlags,
    /// Deduplicate strings.
    pub dedup: bool,
    /// Filter to specific categories only (empty = all).
    pub categories: Vec<StringCategory>,
    /// Only return strings with entropy above threshold (0 = off).
    pub min_entropy: f64,
    /// Offset to start scanning.
    pub start_offset: u64,
    /// Max bytes to scan (0 = all).
    pub max_bytes: u64,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: 0,
            encodings: EncodingFlags::default(),
            dedup: true,
            categories: Vec::new(),
            min_entropy: 0.0,
            start_offset: 0,
            max_bytes: 0,
        }
    }
}

impl ExtractionOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_min_length(mut self, n: usize) -> Self {
        self.min_length = n;
        self
    }

    #[must_use]
    pub const fn no_dedup(mut self) -> Self {
        self.dedup = false;
        self
    }

    #[must_use]
    pub const fn ascii_only(mut self) -> Self {
        self.encodings.ascii = true;
        self.encodings.utf16le = false;
        self.encodings.utf16be = false;
        self
    }

    #[must_use]
    pub const fn unicode_only(mut self) -> Self {
        self.encodings.ascii = false;
        self.encodings.utf16le = true;
        self.encodings.utf16be = true;
        self
    }

    #[must_use]
    pub const fn with_min_entropy(mut self, e: f64) -> Self {
        self.min_entropy = e;
        self
    }
}

// ─── Core extraction ─────────────────────────────────────────────────────────

const fn is_printable_ascii(b: u8) -> bool {
    b >= 0x20 && b < 0x7F
}

/// Extract ASCII strings from a byte slice.
fn extract_ascii(
    data: &[u8],
    base_offset: u64,
    section: &str,
    opts: &ExtractionOptions,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut start = None;
    // Guard: start_offset must be within the buffer.
    let start_byte = u64_to_usize(opts.start_offset).min(data.len());
    let scan_data = if opts.max_bytes > 0 {
        // Use saturating_add to avoid overflow when computing the end offset.
        let end = start_byte.saturating_add(u64_to_usize(opts.max_bytes)).min(data.len());
        &data[start_byte..end]
    } else if start_byte > 0 {
        &data[start_byte..]
    } else {
        data
    };

    for (i, &b) in scan_data.iter().enumerate() {
        if is_printable_ascii(b) || b == b'\t' {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            let len = i - s;
            if len >= opts.min_length && let Ok(st) = std::str::from_utf8(&scan_data[s..i]) {
                let max_ok = opts.max_length == 0 || len <= opts.max_length;
                if max_ok {
                    let es = ExtractedString::new(
                        st,
                        base_offset + start_byte as u64 + s as u64,
                        section,
                        StringEncoding::Ascii,
                    );
                    if opts.min_entropy <= 0.0 || es.entropy >= opts.min_entropy {
                        results.push(es);
                    }
                }
            }
        }
    }
    // Handle string at end of buffer.
    if let Some(s) = start {
        let len = scan_data.len() - s;
        if len >= opts.min_length && let Ok(st) = std::str::from_utf8(&scan_data[s..]) {
            let max_ok = opts.max_length == 0 || len <= opts.max_length;
            if max_ok {
                let es = ExtractedString::new(
                    st,
                    base_offset + start_byte as u64 + s as u64,
                    section,
                    StringEncoding::Ascii,
                );
                if opts.min_entropy <= 0.0 || es.entropy >= opts.min_entropy {
                    results.push(es);
                }
            }
        }
    }
    results
}

/// Extract UTF-16LE strings from a byte slice.
fn extract_utf16le(
    data: &[u8],
    base_offset: u64,
    section: &str,
    opts: &ExtractionOptions,
) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    if data.len() < 2 {
        return results;
    }
    // Guard: clamp start_offset to avoid panic on out-of-bounds slice.
    let start_i = u64_to_usize(opts.start_offset).min(data.len());
    let end_i = if opts.max_bytes > 0 {
        // Use saturating_add to avoid overflow when combining offsets.
        start_i.saturating_add(u64_to_usize(opts.max_bytes)).min(data.len())
    } else {
        data.len()
    };
    let scan_data = &data[start_i..end_i];

    let mut chars: Vec<char> = Vec::new();
    let mut str_start: Option<usize> = None;

    let pairs = scan_data.len() / 2;
    for i in 0..pairs {
        let lo = scan_data[i * 2];
        let hi = scan_data[i * 2 + 1];
        let codepoint = u16::from_le_bytes([lo, hi]);
        let ch = char::from_u32(u32::from(codepoint)).unwrap_or('\0');
        if ((ch as u32) >= 0x20 && (ch as u32) < 0x7F) || ch == '\t' {
            if str_start.is_none() {
                str_start = Some(i);
            }
            chars.push(ch);
        } else if let Some(s) = str_start.take() {
            if chars.len() >= opts.min_length {
                let st: String = chars.iter().collect();
                let max_ok = opts.max_length == 0 || st.len() <= opts.max_length;
                if max_ok {
                    let es = ExtractedString::new(
                        &st,
                        base_offset + start_i as u64 + s as u64 * 2,
                        section,
                        StringEncoding::Utf16Le,
                    );
                    if opts.min_entropy <= 0.0 || es.entropy >= opts.min_entropy {
                        results.push(es);
                    }
                }
            }
            chars.clear();
        }
    }
    if let Some(s) = str_start
        && chars.len() >= opts.min_length
    {
        let st: String = chars.iter().collect();
        let max_ok = opts.max_length == 0 || st.len() <= opts.max_length;
        if max_ok {
            let es = ExtractedString::new(
                &st,
                base_offset + start_i as u64 + s as u64 * 2,
                section,
                StringEncoding::Utf16Le,
            );
            if opts.min_entropy <= 0.0 || es.entropy >= opts.min_entropy {
                results.push(es);
            }
        }
    }
    results
}

// ─── StringsExtractor ────────────────────────────────────────────────────────

pub struct StringsExtractor {
    opts: ExtractionOptions,
}

impl StringsExtractor {
    #[must_use]
    pub const fn new(opts: ExtractionOptions) -> Self {
        Self { opts }
    }

    /// Extract strings from a byte buffer.
    #[must_use]
    pub fn extract_from_bytes(&self, data: &[u8], section: &str) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        if self.opts.encodings.ascii {
            results.extend(extract_ascii(data, 0, section, &self.opts));
        }
        if self.opts.encodings.utf16le {
            results.extend(extract_utf16le(data, 0, section, &self.opts));
        }
        self.post_process(results)
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    /// Extract strings from a file on disk.
    pub fn extract_from_file(&self, path: &Path) -> Result<Vec<ExtractedString>, SysinternalsError> {
        let data = std::fs::read(path).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        let section = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        Ok(self.extract_from_bytes(&data, section))
    }

    /// Extract strings from multiple sections of a PE-like buffer.
    #[must_use]
    pub fn extract_from_sections(
        &self,
        sections: &[(&str, &[u8])],
    ) -> Vec<ExtractedString> {
        let mut results = Vec::new();
        let mut base_offset: u64 = 0;
        for (name, data) in sections {
            if self.opts.encodings.ascii {
                let mut ascii = extract_ascii(data, base_offset, name, &self.opts);
                results.append(&mut ascii);
            }
            if self.opts.encodings.utf16le {
                let mut uni = extract_utf16le(data, base_offset, name, &self.opts);
                results.append(&mut uni);
            }
            base_offset += data.len() as u64;
        }
        self.post_process(results)
    }

    fn post_process(&self, mut results: Vec<ExtractedString>) -> Vec<ExtractedString> {
        // Filter by categories.
        if !self.opts.categories.is_empty() {
            results.retain(|s| self.opts.categories.contains(&s.category));
        }
        // Deduplicate.
        if self.opts.dedup {
            let mut seen: HashMap<String, usize> = HashMap::new();
            let mut deduped: Vec<ExtractedString> = Vec::new();
            for s in results {
                if let Some(idx) = seen.get(&s.value) {
                    deduped[*idx].occurrence_count += 1;
                } else {
                    seen.insert(s.value.clone(), deduped.len());
                    deduped.push(s);
                }
            }
            results = deduped;
        }
        results
    }
}

// ─── StringsReport ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringsReport {
    pub total: usize,
    pub unique: usize,
    pub by_encoding: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub high_entropy_count: usize,
    pub possibly_obfuscated_count: usize,
    pub interesting: Vec<ExtractedString>,
}

impl StringsReport {
    #[must_use]
    pub fn from_strings(strings: &[ExtractedString]) -> Self {
        let mut by_encoding: HashMap<String, usize> = HashMap::new();
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut high_entropy = 0;
        let mut obfuscated = 0;

        for s in strings {
            *by_encoding.entry(s.encoding.to_string()).or_default() += 1;
            *by_category.entry(s.category.to_string()).or_default() += 1;
            if s.entropy > 6.5 {
                high_entropy += 1;
            }
            if s.possibly_obfuscated {
                obfuscated += 1;
            }
        }

        let mut interesting: Vec<ExtractedString> = strings
            .iter()
            .filter(|s| {
                matches!(
                    s.category,
                    StringCategory::Url
                        | StringCategory::IpAddress
                        | StringCategory::Email
                        | StringCategory::RegistryKey
                        | StringCategory::CommandLine
                )
            })
            .cloned()
            .collect();
        interesting.truncate(50);

        Self {
            total: strings.len(),
            unique: strings.len(),
            by_encoding,
            by_category,
            high_entropy_count: high_entropy,
            possibly_obfuscated_count: obfuscated,
            interesting,
        }
    }

    /// Export to CSV.
    #[must_use]
    pub fn to_csv(strings: &[ExtractedString]) -> String {
        let mut out =
            String::from("Value,Offset,Section,Encoding,Category,Entropy,Count,Obfuscated\n");
        for s in strings {
            out.push_str(&s.to_csv_row());
            out.push('\n');
        }
        out
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_basic() {
        let data = b"Hello, World!\x00\x01\x02test";
        let opts = ExtractionOptions::new().with_min_length(4);
        let ex = StringsExtractor::new(opts);
        let strings = ex.extract_from_bytes(data, "test");
        assert!(!strings.is_empty());
        assert!(strings.iter().any(|s| s.value.as_str() == "Hello, World!"));
    }

    #[test]
    fn test_extract_utf16le() {
        // "test" in UTF-16LE
        let data: Vec<u8> = "test"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let opts = ExtractionOptions::new().unicode_only().with_min_length(4);
        let ex = StringsExtractor::new(opts);
        let strings = ex.extract_from_bytes(&data, "buf");
        assert!(!strings.is_empty());
        assert!(strings.iter().any(|s| s.value == "test"));
    }

    #[test]
    fn test_min_length_filter() {
        let data = b"ab\x00hello world\x00xy\x00";
        let opts = ExtractionOptions::new().with_min_length(6);
        let ex = StringsExtractor::new(opts);
        let strings = ex.extract_from_bytes(data, "x");
        assert!(strings.iter().all(|s| s.length >= 6));
    }

    #[test]
    fn test_dedup() {
        let data = b"hello\x00world\x00hello\x00";
        let opts = ExtractionOptions::new().with_min_length(4);
        let ex = StringsExtractor::new(opts);
        let strings = ex.extract_from_bytes(data, "x");
        let hello: Vec<_> = strings.iter().filter(|s| s.value == "hello").collect();
        assert_eq!(hello.len(), 1);
        assert_eq!(hello[0].occurrence_count, 2);
    }

    #[test]
    fn test_classify_url() {
        let s = ExtractedString::new("https://evil.com/payload.exe", 0, "x", StringEncoding::Ascii);
        assert_eq!(s.category, StringCategory::Url);
    }

    #[test]
    fn test_classify_registry_key() {
        let s = ExtractedString::new(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, "x", StringEncoding::Ascii);
        assert_eq!(s.category, StringCategory::RegistryKey);
    }

    #[test]
    fn test_classify_file_path() {
        let s = ExtractedString::new("C:\\Windows\\System32\\cmd.exe", 0, "x", StringEncoding::Ascii);
        assert_eq!(s.category, StringCategory::FilePath);
    }

    #[test]
    fn test_classify_ip_address() {
        let s = ExtractedString::new("192.168.1.1", 0, "x", StringEncoding::Ascii);
        assert_eq!(s.category, StringCategory::IpAddress);
    }

    #[test]
    fn test_classify_guid() {
        let s = ExtractedString::new("{6D809377-6AF0-444B-8957-A3773F02200E}", 0, "x", StringEncoding::Ascii);
        assert_eq!(s.category, StringCategory::GuidOrClsid);
    }

    #[test]
    fn test_classify_email() {
        let s = ExtractedString::new("user@evil.com", 0, "x", StringEncoding::Ascii);
        assert_eq!(s.category, StringCategory::Email);
    }

    #[test]
    fn test_entropy_high() {
        // Random-looking data encoded as base64 has high entropy.
        let random = b"xK9mPq2nRzW8yJvC5sL1tH3dBfGhNwAe";
        let e = compute_entropy(random);
        assert!(e > 3.0);
    }

    #[test]
    fn test_entropy_zero() {
        let all_a = b"aaaaaaaaaaaaaaaa";
        let e = compute_entropy(all_a);
        assert!(e < 0.01);
    }

    #[test]
    fn test_is_likely_base64() {
        assert!(is_likely_base64("dGVzdHN0cmluZ2Jhc2U2NA=="));
        assert!(!is_likely_base64("this is not base64!!!"));
    }

    #[test]
    fn test_is_guid() {
        assert!(is_guid("{6D809377-6AF0-444B-8957-A3773F02200E}"));
        assert!(!is_guid("not-a-guid"));
    }

    #[test]
    fn test_extract_from_sections() {
        let sec1 = b"Hello world\x00";
        let sec2 = b"ntdll.dll\x00kernel32.dll\x00";
        let opts = ExtractionOptions::new().with_min_length(5);
        let ex = StringsExtractor::new(opts);
        let strings = ex.extract_from_sections(&[(".data", sec1), (".rdata", sec2)]);
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        assert!(values.contains(&"Hello world"));
        assert!(values.contains(&"ntdll.dll"));
        // Check section tagging.
        let hello = strings.iter().find(|s| s.value == "Hello world").unwrap();
        assert_eq!(hello.section, ".data");
    }

    #[test]
    fn test_strings_report() {
        let strings = vec![
            ExtractedString::new("https://evil.com", 0, "x", StringEncoding::Ascii),
            ExtractedString::new("C:\\Windows\\cmd.exe", 10, "x", StringEncoding::Ascii),
        ];
        let report = StringsReport::from_strings(&strings);
        assert_eq!(report.total, 2);
        assert!(!report.interesting.is_empty());
    }

    #[test]
    fn test_strings_report_csv() {
        let strings = vec![ExtractedString::new("hello", 0, "x", StringEncoding::Ascii)];
        let csv = StringsReport::to_csv(&strings);
        assert!(csv.contains("Value"));
        assert!(csv.contains("hello"));
    }
}
