//! `ioc_extractor` — IOC extraction from YARA match context:
//! C2 domains, IP addresses, mutex names, registry keys, file paths,
//! identified via specialized pattern matching within match data.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ── IOC types ─────────────────────────────────────────────────────────────────

/// A single extracted Indicator of Compromise.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocValue {
    /// IPv4 or IPv6 address.
    IpAddress(String),
    /// Domain name.
    Domain(String),
    /// URL (`<scheme://host/path>`).
    Url(String),
    /// Mutex/semaphore name.
    Mutex(String),
    /// Windows registry key path.
    RegistryKey(String),
    /// File system path.
    FilePath(String),
    /// Email address.
    Email(String),
    /// MD5 hash (32 hex chars).
    HashMd5(String),
    /// SHA-1 hash (40 hex chars).
    HashSha1(String),
    /// SHA-256 hash (64 hex chars).
    HashSha256(String),
    /// User-agent string.
    UserAgent(String),
    /// Named pipe.
    NamedPipe(String),
    /// Service name.
    ServiceName(String),
    /// Scheduled task name.
    ScheduledTask(String),
    /// Generic string IOC that doesn't fit a more specific category.
    Generic { kind: String, value: String },
}

impl IocValue {
    /// IOC category name.
    #[must_use]
    pub const fn kind(&self) -> &str {
        match self {
            Self::IpAddress(_)    => "ip_address",
            Self::Domain(_)       => "domain",
            Self::Url(_)          => "url",
            Self::Mutex(_)        => "mutex",
            Self::RegistryKey(_)  => "registry_key",
            Self::FilePath(_)     => "file_path",
            Self::Email(_)        => "email",
            Self::HashMd5(_)      => "md5",
            Self::HashSha1(_)     => "sha1",
            Self::HashSha256(_)   => "sha256",
            Self::UserAgent(_)    => "user_agent",
            Self::NamedPipe(_)    => "named_pipe",
            Self::ServiceName(_)  => "service_name",
            Self::ScheduledTask(_) => "scheduled_task",
            Self::Generic { kind, .. } => kind.as_str(),
        }
    }

    /// The raw string value of the IOC.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::IpAddress(v)
            | Self::Domain(v)
            | Self::Url(v)
            | Self::Mutex(v)
            | Self::RegistryKey(v)
            | Self::FilePath(v)
            | Self::Email(v)
            | Self::HashMd5(v)
            | Self::HashSha1(v)
            | Self::HashSha256(v)
            | Self::UserAgent(v)
            | Self::NamedPipe(v)
            | Self::ServiceName(v)
            | Self::ScheduledTask(v) => v,
            Self::Generic { value, .. } => value,
        }
    }
}

/// Confidence level for an extracted IOC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IocConfidence {
    Low,
    Medium,
    High,
}

/// A single extracted IOC with provenance metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedIoc {
    pub ioc: IocValue,
    pub confidence: IocConfidence,
    /// File offset where this IOC was found.
    pub offset: u64,
    /// YARA rule that triggered this extraction (if any).
    pub source_rule: Option<String>,
    /// The raw bytes from which the IOC was extracted.
    pub raw_bytes: Vec<u8>,
    /// Context (up to 32 bytes before and after).
    pub context: String,
}

/// Complete IOC extraction report for a sample.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IocReport {
    pub sample_label: String,
    pub iocs: Vec<ExtractedIoc>,
    pub summary: IocSummary,
}

impl IocReport {
    pub fn new(label: impl Into<String>) -> Self {
        Self { sample_label: label.into(), iocs: Vec::new(), summary: IocSummary::default() }
    }

    pub fn add(&mut self, ioc: ExtractedIoc) {
        self.iocs.push(ioc);
    }

    pub fn build_summary(&mut self) {
        self.summary = IocSummary::from_iocs(&self.iocs);
    }

    /// Deduplicate IOC values (keep highest confidence for each unique value).
    pub fn deduplicate(&mut self) {
        let mut best: HashMap<String, ExtractedIoc> = HashMap::new();
        for ioc in self.iocs.drain(..) {
            let key = format!("{}:{}", ioc.ioc.kind(), ioc.ioc.value());
            let entry = best.entry(key).or_insert_with(|| ioc.clone());
            if ioc.confidence > entry.confidence {
                *entry = ioc;
            }
        }
        self.iocs = best.into_values().collect();
        self.iocs.sort_by(|a, b| {
            b.confidence.cmp(&a.confidence).then(a.offset.cmp(&b.offset))
        });
    }

    /// All unique IP addresses.
    #[must_use]
    pub fn ip_addresses(&self) -> Vec<&str> {
        self.iocs.iter()
            .filter_map(|e| if let IocValue::IpAddress(v) = &e.ioc { Some(v.as_str()) } else { None })
            .collect()
    }

    /// All unique domains.
    #[must_use]
    pub fn domains(&self) -> Vec<&str> {
        self.iocs.iter()
            .filter_map(|e| if let IocValue::Domain(v) = &e.ioc { Some(v.as_str()) } else { None })
            .collect()
    }
}

/// Summary counts of IOCs by type.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IocSummary {
    pub ip_addresses: usize,
    pub domains: usize,
    pub urls: usize,
    pub mutexes: usize,
    pub registry_keys: usize,
    pub file_paths: usize,
    pub hashes: usize,
    pub named_pipes: usize,
    pub other: usize,
    pub total: usize,
}

impl IocSummary {
    fn from_iocs(iocs: &[ExtractedIoc]) -> Self {
        let mut s = Self::default();
        for ioc in iocs {
            match &ioc.ioc {
                IocValue::IpAddress(_)    => s.ip_addresses += 1,
                IocValue::Domain(_)       => s.domains += 1,
                IocValue::Url(_)          => s.urls += 1,
                IocValue::Mutex(_)        => s.mutexes += 1,
                IocValue::RegistryKey(_)  => s.registry_keys += 1,
                IocValue::FilePath(_)     => s.file_paths += 1,
                IocValue::HashMd5(_) | IocValue::HashSha1(_) | IocValue::HashSha256(_) => s.hashes += 1,
                IocValue::NamedPipe(_)    => s.named_pipes += 1,
                _                         => s.other += 1,
            }
            s.total += 1;
        }
        s
    }
}

// ── Extractor ─────────────────────────────────────────────────────────────────

/// IOC extraction engine.
pub struct IocExtractor {
    /// Known mutex name prefixes to watch for.
    mutex_prefixes: Vec<String>,
    /// Known pipe name prefixes.
    pipe_prefixes: Vec<String>,
    /// Minimum string length to consider.
    min_string_len: usize,
    /// Whether to extract IOCs from wide (UTF-16LE) strings.
    wide_strings: bool,
}

impl IocExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mutex_prefixes: vec![
                "Global\\".into(),
                "Local\\".into(),
                "{".into(),
            ],
            pipe_prefixes: vec![
                "\\\\.\\pipe\\".into(),
                "\\pipe\\".into(),
            ],
            min_string_len: 4,
            wide_strings: true,
        }
    }

    /// Extract all IOCs from raw binary data.
    ///
    /// Scans both as ASCII strings and as UTF-16LE wide strings.
    pub fn extract(&self, data: &[u8], label: impl Into<String>) -> IocReport {
        let mut report = IocReport::new(label);

        // Extract ASCII strings
        for (offset, s) in extract_printable_strings(data, self.min_string_len) {
            self.classify_string(&s, offset, data, None, &mut report);
        }

        // Extract UTF-16LE wide strings
        if self.wide_strings {
            for (offset, s) in extract_wide_strings(data, self.min_string_len) {
                self.classify_string(&s, offset, data, None, &mut report);
            }
        }

        report.deduplicate();
        report.build_summary();
        report
    }

    /// Extract IOCs with hints from matched YARA rule names.
    ///
    /// Rule names can bias the extractor toward specific IOC types.
    pub fn extract_with_rules(
        &self,
        data: &[u8],
        label: impl Into<String>,
        matched_rules: &[String],
    ) -> IocReport {
        let mut report = IocReport::new(label);

        // Determine which IOC types to prioritize based on rules.
        let look_for_c2 = matched_rules.iter().any(|r| {
            r.contains("C2") || r.contains("Beacon") || r.contains("Backdoor")
        });
        let look_for_ransomware_ioc = matched_rules.iter().any(|r| {
            r.contains("Ransomware") || r.contains("Ryuk") || r.contains("LockBit")
        });
        let _look_for_creds = matched_rules.iter().any(|r| {
            r.contains("Mimikatz") || r.contains("credential") || r.contains("lsass")
        });

        for (offset, s) in extract_printable_strings(data, self.min_string_len) {
            self.classify_string(&s, offset, data, None, &mut report);
        }
        if self.wide_strings {
            for (offset, s) in extract_wide_strings(data, self.min_string_len) {
                self.classify_string(&s, offset, data, None, &mut report);
            }
        }

        // Additional targeted extraction
        if look_for_c2 {
            Self::extract_c2_patterns(data, &mut report);
        }
        if look_for_ransomware_ioc {
            Self::extract_ransom_note_iocs(data, &mut report);
        }

        report.deduplicate();
        report.build_summary();
        report
    }

    // ── Classification ────────────────────────────────────────────────────────

    fn classify_string(
        &self,
        s: &str,
        offset: u64,
        data: &[u8],
        source_rule: Option<&str>,
        report: &mut IocReport,
    ) {
        // URL
        if let Some(ioc) = try_parse_url(s) {
            report.add(Self::make_ioc(ioc, IocConfidence::High, offset, data, source_rule));
            return;
        }
        // IP address
        if let Some(ioc) = try_parse_ip(s) {
            report.add(Self::make_ioc(ioc, IocConfidence::High, offset, data, source_rule));
            return;
        }
        // Domain name
        if let Some(ioc) = try_parse_domain(s) {
            report.add(Self::make_ioc(ioc, IocConfidence::Medium, offset, data, source_rule));
            return;
        }
        // Registry key
        if let Some(ioc) = try_parse_registry(s) {
            report.add(Self::make_ioc(ioc, IocConfidence::High, offset, data, source_rule));
            return;
        }
        // File path
        if let Some(ioc) = try_parse_filepath(s) {
            report.add(Self::make_ioc(ioc, IocConfidence::Medium, offset, data, source_rule));
            return;
        }
        // Named pipe
        for prefix in &self.pipe_prefixes {
            if s.starts_with(prefix.as_str()) {
                let ioc = IocValue::NamedPipe(s.to_string());
                report.add(Self::make_ioc(ioc, IocConfidence::High, offset, data, source_rule));
                return;
            }
        }
        // Mutex
        for prefix in &self.mutex_prefixes {
            if s.starts_with(prefix.as_str()) {
                let ioc = IocValue::Mutex(s.to_string());
                report.add(Self::make_ioc(ioc, IocConfidence::Medium, offset, data, source_rule));
                return;
            }
        }
        // Hash
        if let Some(ioc) = try_parse_hash(s) {
            report.add(Self::make_ioc(ioc, IocConfidence::High, offset, data, source_rule));
            return;
        }
        // Email
        if let Some(ioc) = try_parse_email(s) {
            report.add(Self::make_ioc(ioc, IocConfidence::Medium, offset, data, source_rule));
        }
    }

    fn make_ioc(
        ioc: IocValue,
        confidence: IocConfidence,
        offset: u64,
        data: &[u8],
        source_rule: Option<&str>,
    ) -> ExtractedIoc {
        let raw = ioc.value().as_bytes().to_vec();
        // Clamp offset to data.len() so context extraction never goes out of
        // bounds even when `offset` was derived from a wide-string scan and
        // may point slightly past the data slice.
        let off = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
        let ctx_start = off.saturating_sub(16);
        let ctx_end = off.saturating_add(raw.len()).saturating_add(16).min(data.len());
        let ctx_bytes = &data[ctx_start..ctx_end];
        let context = ctx_bytes.iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();

        ExtractedIoc {
            ioc,
            confidence,
            offset,
            source_rule: source_rule.map(ToString::to_string),
            raw_bytes: raw,
            context,
        }
    }

    fn extract_c2_patterns(data: &[u8], report: &mut IocReport) {
        // Search for HTTP User-Agent strings
        let ua_markers: &[&[u8]] = &[
            b"Mozilla/", b"User-Agent:", b"User-agent:",
        ];
        for &marker in ua_markers {
            let mut pos = 0;
            while pos + marker.len() <= data.len() {
                if &data[pos..pos + marker.len()] == marker {
                    let end = (pos + 256).min(data.len());
                    let line: String = data[pos..end].iter()
                        .take_while(|&&b| b != b'\r' && b != b'\n' && b != 0)
                        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                        .collect();
                    if line.len() > 16 {
                        report.add(ExtractedIoc {
                            ioc: IocValue::UserAgent(line.trim().to_string()),
                            confidence: IocConfidence::High,
                            offset: pos as u64,
                            source_rule: None,
                            raw_bytes: Vec::new(),
                            context: String::new(),
                        });
                    }
                    pos += marker.len();
                } else {
                    pos += 1;
                }
            }
        }
    }

    fn extract_ransom_note_iocs(data: &[u8], report: &mut IocReport) {
        // Look for Tor onion addresses
        for (off, s) in extract_printable_strings(data, 16) {
            if s.to_ascii_lowercase().ends_with(".onion") && s.len() >= 22 {
                report.add(ExtractedIoc {
                    ioc: IocValue::Domain(s.trim().to_string()),
                    confidence: IocConfidence::High,
                    offset: off,
                    source_rule: Some("ransomware_tor_c2".into()),
                    raw_bytes: Vec::new(),
                    context: String::new(),
                });
            }
        }
        // Look for Bitcoin/Monero addresses
        for (off, s) in extract_printable_strings(data, 26) {
            if looks_like_bitcoin_address(&s) {
                report.add(ExtractedIoc {
                    ioc: IocValue::Generic { kind: "crypto_address".into(), value: s },
                    confidence: IocConfidence::Medium,
                    offset: off,
                    source_rule: None,
                    raw_bytes: Vec::new(),
                    context: String::new(),
                });
            }
        }
    }
}

impl Default for IocExtractor {
    fn default() -> Self { Self::new() }
}

// ── String extraction ─────────────────────────────────────────────────────────

/// Extract printable ASCII strings of at least `min_len` bytes.
#[must_use]
pub fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<(u64, String)> {
    let mut result = Vec::new();
    let mut start = None;
    let mut buf = Vec::new();

    for (i, &b) in data.iter().enumerate() {
        if (0x20..0x7F).contains(&b) {
            if start.is_none() { start = Some(i); }
            buf.push(b);
        } else if let Some(s) = start.take() {
            if buf.len() >= min_len && let Ok(text) = String::from_utf8(buf.clone()) {
                result.push((u64::try_from(s).unwrap_or(u64::MAX), text));
            }
            buf.clear();
        }
    }
    if let Some(s) = start && buf.len() >= min_len && let Ok(text) = String::from_utf8(buf) {
        result.push((u64::try_from(s).unwrap_or(u64::MAX), text));
    }
    result
}

/// Extract UTF-16LE wide strings of at least `min_len` characters.
#[must_use]
pub fn extract_wide_strings(data: &[u8], min_len: usize) -> Vec<(u64, String)> {
    let mut result = Vec::new();
    if data.len() < 2 { return result; }

    let mut start = None;
    let mut chars = Vec::new();

    let mut i = 0;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        if hi == 0 && (0x20..0x7F).contains(&lo) {
            if start.is_none() { start = Some(i); }
            chars.push(char::from(lo));
        } else if let Some(s) = start.take() {
            if chars.len() >= min_len {
                result.push((u64::try_from(s).unwrap_or(u64::MAX), chars.iter().collect()));
            }
            chars.clear();
        }
        i += 2;
    }
    if let Some(s) = start && chars.len() >= min_len {
        result.push((u64::try_from(s).unwrap_or(u64::MAX), chars.iter().collect()));
    }
    result
}

// ── Pattern parsers ───────────────────────────────────────────────────────────

fn try_parse_url(s: &str) -> Option<IocValue> {
    for scheme in &["http://", "https://", "ftp://", "ftps://"] {
        if s.to_lowercase().starts_with(scheme) && s.len() > scheme.len() + 4 {
            return Some(IocValue::Url(s.to_string()));
        }
    }
    None
}

fn try_parse_ip(s: &str) -> Option<IocValue> {
    // IPv4: four 0–255 numbers separated by dots.
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return Some(IocValue::IpAddress(s.to_string()));
    }
    // Rough IPv6 check
    if s.contains(':') && s.len() >= 7 && s.split(':').count() >= 4
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
    {
        return Some(IocValue::IpAddress(s.to_string()));
    }
    None
}

fn try_parse_domain(s: &str) -> Option<IocValue> {
    const KNOWN_TLDS: &[&str] = &[
        ".com", ".net", ".org", ".io", ".co", ".gov", ".edu", ".ru", ".cn",
        ".de", ".uk", ".fr", ".onion", ".xyz", ".top", ".info", ".biz",
    ];
    let lower = s.to_lowercase();
    if !lower.contains('.') { return None; }
    // Exclude file paths and registry keys
    if s.contains('\\') || s.contains('/') { return None; }
    if s.starts_with('.') || s.ends_with('.') { return None; }
    if !KNOWN_TLDS.iter().any(|tld| lower.ends_with(tld)) { return None; }
    // Basic domain character check
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') && s.len() >= 4 {
        return Some(IocValue::Domain(s.to_string()));
    }
    None
}

fn try_parse_registry(s: &str) -> Option<IocValue> {
    const HIVES: &[&str] = &[
        "HKLM\\", "HKCU\\", "HKCR\\", "HKU\\", "HKCC\\",
        "HKEY_LOCAL_MACHINE\\", "HKEY_CURRENT_USER\\",
        "HKEY_CLASSES_ROOT\\", "HKEY_USERS\\",
    ];
    let upper = s.to_uppercase();
    if HIVES.iter().any(|h| upper.starts_with(h)) {
        return Some(IocValue::RegistryKey(s.to_string()));
    }
    None
}

fn try_parse_filepath(s: &str) -> Option<IocValue> {
    // Windows absolute path
    if s.len() >= 4 && s.chars().nth(1) == Some(':') && s.chars().nth(2) == Some('\\') {
        return Some(IocValue::FilePath(s.to_string()));
    }
    // UNC path
    if s.starts_with("\\\\") && s.len() > 4 {
        return Some(IocValue::FilePath(s.to_string()));
    }
    // Unix absolute path
    if s.starts_with('/') && s.len() > 4 && !s.contains('\0') {
        return Some(IocValue::FilePath(s.to_string()));
    }
    None
}

fn try_parse_email(s: &str) -> Option<IocValue> {
    if let Some(at) = s.rfind('@') {
        let local = &s[..at];
        let domain = &s[at + 1..];
        if !local.is_empty() && domain.contains('.')
            && local.chars().all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
            && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Some(IocValue::Email(s.to_string()));
        }
    }
    None
}

fn try_parse_hash(s: &str) -> Option<IocValue> {
    let clean: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    if clean != s { return None; } // only pure hex
    match s.len() {
        32 => Some(IocValue::HashMd5(s.to_lowercase())),
        40 => Some(IocValue::HashSha1(s.to_lowercase())),
        64 => Some(IocValue::HashSha256(s.to_lowercase())),
        _ => None,
    }
}

fn looks_like_bitcoin_address(s: &str) -> bool {
    let len = s.len();
    // P2PKH: starts with 1, 26-35 chars
    // P2SH: starts with 3, 34 chars
    // Bech32: starts with bc1, 42 chars
    if (s.starts_with('1') || s.starts_with('3')) && (26..=35).contains(&len) {
        return s.chars().all(|c| c.is_ascii_alphanumeric() && c != '0' && c != 'O' && c != 'I' && c != 'l');
    }
    if s.starts_with("bc1") && len == 42 {
        return s.chars().all(|c| c.is_ascii_alphanumeric());
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip() {
        assert!(try_parse_ip("192.168.1.1").is_some());
        assert!(try_parse_ip("10.0.0.1").is_some());
        assert!(try_parse_ip("256.0.0.1").is_none()); // invalid octet
        assert!(try_parse_ip("not_an_ip").is_none());
    }

    #[test]
    fn test_extract_domain() {
        assert!(try_parse_domain("evil.com").is_some());
        assert!(try_parse_domain("c2.attacker.net").is_some());
        assert!(try_parse_domain("localhost").is_none()); // no TLD
        assert!(try_parse_domain("C:\\Windows").is_none()); // path chars
    }

    #[test]
    fn test_extract_url() {
        assert!(try_parse_url("https://evil.com/beacon").is_some());
        assert!(try_parse_url("http://192.168.1.1/stage").is_some());
        assert!(try_parse_url("evil.com").is_none());
    }

    #[test]
    fn test_extract_registry_key() {
        assert!(try_parse_registry("HKLM\\SOFTWARE\\Microsoft").is_some());
        assert!(try_parse_registry("HKEY_LOCAL_MACHINE\\Run").is_some());
        assert!(try_parse_registry("C:\\Windows").is_none());
    }

    #[test]
    fn test_extract_hash() {
        assert!(matches!(try_parse_hash("d41d8cd98f00b204e9800998ecf8427e"), Some(IocValue::HashMd5(_))));
        assert!(matches!(try_parse_hash("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"), Some(IocValue::HashSha1(_))));
        assert!(try_parse_hash("short").is_none());
    }

    #[test]
    fn test_extract_from_binary() {
        let extractor = IocExtractor::new();
        let mut data = b"XXXXXXXXXXXXXXXHKLM\\SOFTWARE\\Microsoft\\WindowsXXXXXXX".to_vec();
        data.extend_from_slice(b"XXXXXXXXXXX192.168.1.100XXXXXXXXXXXXXXXXXX");
        data.extend_from_slice(b"XXXXXXXXXXXhttps://c2.evil.com/checkXXXXXX");
        let report = extractor.extract(&data, "test");
        assert!(!report.iocs.is_empty());
        let has_registry = report.iocs.iter().any(|e| matches!(e.ioc, IocValue::RegistryKey(_)));
        let has_url = report.iocs.iter().any(|e| matches!(e.ioc, IocValue::Url(_)));
        assert!(has_registry, "should extract registry key");
        assert!(has_url, "should extract URL");
    }

    #[test]
    fn test_wide_string_extraction() {
        // Build a wide string "HELLO"
        let wide: Vec<u8> = b"HELLO".iter().flat_map(|&b| [b, 0]).collect();
        let mut data = vec![0u8; 16];
        data.extend_from_slice(&wide);
        let strings = extract_wide_strings(&data, 4);
        assert!(strings.iter().any(|(_, s)| s == "HELLO"));
    }

    #[test]
    fn test_ioc_report_deduplication() {
        let mut report = IocReport::new("test");
        let ioc = IocValue::IpAddress("1.2.3.4".into());
        report.add(ExtractedIoc {
            ioc: ioc.clone(),
            confidence: IocConfidence::Low,
            offset: 0,
            source_rule: None,
            raw_bytes: Vec::new(),
            context: String::new(),
        });
        report.add(ExtractedIoc {
            ioc,
            confidence: IocConfidence::High,
            offset: 100,
            source_rule: None,
            raw_bytes: Vec::new(),
            context: String::new(),
        });
        report.deduplicate();
        assert_eq!(report.iocs.len(), 1);
        assert_eq!(report.iocs[0].confidence, IocConfidence::High);
    }
}
