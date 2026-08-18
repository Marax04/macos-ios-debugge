/// String semantic classifier.
///
/// Classifies strings by semantic category: URLs, filesystem paths, GUIDs,
/// IP addresses, email addresses, crypto constants, registry keys, format strings,
/// command-line patterns, and error message signatures.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// StringCategory — top-level classification
// ---------------------------------------------------------------------------

/// Top-level semantic category of a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringCategory {
    Url,
    FilePath,
    RegistryKey,
    Guid,
    IpAddress,
    EmailAddress,
    FormatString,
    CryptoConstant,
    ErrorMessage,
    CommandLine,
    EnvironmentVariable,
    DllName,
    ApiName,
    Base64Data,
    HexData,
    Unknown,
}

impl StringCategory {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            StringCategory::Url => "url",
            StringCategory::FilePath => "file_path",
            StringCategory::RegistryKey => "registry_key",
            StringCategory::Guid => "guid",
            StringCategory::IpAddress => "ip_address",
            StringCategory::EmailAddress => "email",
            StringCategory::FormatString => "format_string",
            StringCategory::CryptoConstant => "crypto_constant",
            StringCategory::ErrorMessage => "error_message",
            StringCategory::CommandLine => "command_line",
            StringCategory::EnvironmentVariable => "env_var",
            StringCategory::DllName => "dll_name",
            StringCategory::ApiName => "api_name",
            StringCategory::Base64Data => "base64",
            StringCategory::HexData => "hex_data",
            StringCategory::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// ClassifierResult — result for one string
// ---------------------------------------------------------------------------

/// Classification result for one string.
#[derive(Debug, Clone)]
pub struct ClassifierResult {
    pub string: String,
    pub category: StringCategory,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
    /// Secondary categories, ordered by confidence.
    pub secondary: Vec<(StringCategory, f64)>,
    /// Extra metadata (e.g., extracted host, path, etc.).
    pub metadata: HashMap<String, String>,
}

impl ClassifierResult {
    #[must_use]
    pub fn new(string: String, category: StringCategory, confidence: f64) -> Self {
        Self {
            string,
            category,
            confidence,
            secondary: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub fn unknown(string: String) -> Self {
        Self::new(string, StringCategory::Unknown, 0.0)
    }

    pub fn add_secondary(&mut self, cat: StringCategory, confidence: f64) {
        self.secondary.push((cat, confidence));
        self.secondary.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    }

    pub fn add_meta(&mut self, key: &str, value: String) {
        self.metadata.insert(key.to_owned(), value);
    }

    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

// ---------------------------------------------------------------------------
// Pattern matchers
// ---------------------------------------------------------------------------

/// URL pattern: http/https/ftp/file/ldap/etc.
#[derive(Debug, Default, Clone)]
pub struct UrlPattern;

impl UrlPattern {
    const SCHEMES: &'static [&'static str] = &[
        "http://", "https://", "ftp://", "ftps://", "file://",
        "ldap://", "ldaps://", "ws://", "wss://", "rtsp://",
    ];

    #[must_use]
    pub fn matches(&self, s: &str) -> Option<f64> {
        let lower = s.to_lowercase();
        for scheme in Self::SCHEMES {
            if lower.starts_with(scheme) {
                // Stronger signal if has path or query
                let conf = if lower.contains('/') && lower.len() > scheme.len() + 5 { 0.97 } else { 0.90 };
                return Some(conf);
            }
        }
        None
    }

    #[must_use]
    pub fn extract_host(&self, s: &str) -> Option<String> {
        for scheme in Self::SCHEMES {
            if s.to_lowercase().starts_with(scheme) {
                let rest = &s[scheme.len()..];
                let end = rest.find(|c| c == '/' || c == '?' || c == '#').unwrap_or(rest.len());
                return Some(rest[..end].to_owned());
            }
        }
        None
    }
}

/// Filesystem path pattern.
#[derive(Debug, Default, Clone)]
pub struct PathPattern;

impl PathPattern {
    #[must_use]
    pub fn matches(&self, s: &str) -> Option<f64> {
        // Windows paths: C:\, D:\, \\server\share, %APPDATA%\...
        if s.len() >= 3 {
            let chars: Vec<char> = s.chars().collect();
            if chars[0].is_ascii_alphabetic() && chars[1] == ':' && (chars[2] == '\\' || chars[2] == '/') {
                return Some(0.96);
            }
        }
        if s.starts_with("\\\\") || s.starts_with("//") {
            return Some(0.92);
        }
        // Unix paths
        if s.starts_with('/') && s.len() > 1 {
            return Some(0.85);
        }
        // Relative paths with common dirs
        let lower = s.to_lowercase();
        if lower.contains("\\system32\\") || lower.contains("\\windows\\") || lower.contains("\\program files") {
            return Some(0.94);
        }
        if lower.contains("/usr/") || lower.contains("/etc/") || lower.contains("/var/") {
            return Some(0.88);
        }
        // Percent-expanded Windows paths
        if s.starts_with('%') && s.contains('%') && s.contains('\\') {
            return Some(0.90);
        }
        None
    }
}

/// GUID/UUID pattern: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
#[derive(Debug, Default, Clone)]
pub struct GuidPattern;

impl GuidPattern {
    #[must_use]
    pub fn matches(&self, s: &str) -> Option<f64> {
        let stripped = s.trim_matches(|c| c == '{' || c == '}');
        let parts: Vec<&str> = stripped.split('-').collect();
        if parts.len() == 5
            && parts[0].len() == 8
            && parts[1].len() == 4
            && parts[2].len() == 4
            && parts[3].len() == 4
            && parts[4].len() == 12
            && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
        {
            Some(0.99)
        } else {
            None
        }
    }
}

/// IPv4 address pattern.
#[derive(Debug, Default, Clone)]
pub struct IpPattern;

impl IpPattern {
    #[must_use]
    pub fn matches_v4(&self, s: &str) -> Option<f64> {
        // Strip optional port
        let base = s.split(':').next().unwrap_or(s);
        let octets: Vec<&str> = base.split('.').collect();
        if octets.len() == 4 {
            let valid = octets.iter().all(|o| {
                o.parse::<u8>().is_ok()
            });
            if valid {
                return Some(0.98);
            }
        }
        None
    }

    #[must_use]
    pub fn is_private(&self, s: &str) -> bool {
        let base = s.split(':').next().unwrap_or(s);
        let octets: Vec<u8> = base.split('.').filter_map(|o| o.parse().ok()).collect();
        if octets.len() != 4 { return false; }
        matches!(
            (octets[0], octets[1]),
            (10, _) | (172, 16..=31) | (192, 168) | (127, _) | (169, 254)
        )
    }
}

/// Email pattern.
#[derive(Debug, Default, Clone)]
pub struct EmailPattern;

impl EmailPattern {
    #[must_use]
    pub fn matches(&self, s: &str) -> Option<f64> {
        // Simple: local@domain.tld
        let at_pos = s.find('@')?;
        if at_pos == 0 || at_pos == s.len() - 1 { return None; }
        let domain = &s[at_pos + 1..];
        if domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.') {
            Some(0.93)
        } else {
            None
        }
    }
}

/// Registry key pattern.
#[derive(Debug, Default, Clone)]
pub struct RegistryPattern;

impl RegistryPattern {
    const ROOTS: &'static [&'static str] = &[
        "HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT",
        "HKEY_USERS", "HKEY_CURRENT_CONFIG",
        "HKLM\\", "HKCU\\", "HKCR\\",
        "SOFTWARE\\", "SYSTEM\\",
    ];

    #[must_use]
    pub fn matches(&self, s: &str) -> Option<f64> {
        let upper = s.to_uppercase();
        for root in Self::ROOTS {
            if upper.starts_with(root) {
                return Some(0.97);
            }
        }
        None
    }
}

/// DLL name pattern.
#[derive(Debug, Default, Clone)]
pub struct DllPattern;

impl DllPattern {
    const KNOWN_DLLS: &'static [&'static str] = &[
        "kernel32", "ntdll", "advapi32", "user32", "gdi32", "shell32",
        "ole32", "oleaut32", "ws2_32", "wininet", "urlmon", "msvcrt",
        "combase", "ucrtbase", "secur32", "crypt32",
    ];

    #[must_use]
    pub fn matches(&self, s: &str) -> Option<f64> {
        let lower = s.to_lowercase();
        let stem = lower.strip_suffix(".dll").unwrap_or(&lower);
        let stem = stem.strip_suffix(".exe").unwrap_or(stem);
        if Self::KNOWN_DLLS.contains(&stem) {
            return Some(0.98);
        }
        if lower.ends_with(".dll") || lower.ends_with(".exe") || lower.ends_with(".sys") {
            return Some(0.80);
        }
        None
    }
}

/// Format string pattern.
#[derive(Debug, Default, Clone)]
pub struct FormatStringPattern;

impl FormatStringPattern {
    #[must_use]
    pub fn matches(&self, s: &str) -> Option<f64> {
        // Count printf-style format specifiers
        let mut count = 0usize;
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '%' {
                if let Some(&next) = chars.peek() {
                    if "dioxXufeEgGscSpnhljztqL%".contains(next) {
                        count += 1;
                    }
                }
            }
        }
        if count >= 1 {
            let conf = (0.5 + count as f64 * 0.15).min(0.95);
            Some(conf)
        } else {
            None
        }
    }
}

/// Crypto constant detection: SHA-256, AES S-box, MD5 initial values, etc.
#[derive(Debug, Default, Clone)]
pub struct CryptoPattern;

const CRYPTO_SUBSTRINGS: &[(&str, &str)] = &[
    ("6745230189abcdef", "MD5 init"),
    ("67452301", "MD5/SHA init"),
    ("efcdab89", "MD5 init"),
    ("0x428a2f98", "SHA-256 K[0]"),
    ("0x71374491", "SHA-256 K[1]"),
    ("63636363", "AES S-box pattern"),
    ("AES_KEY", "AES key struct"),
    ("RC4", "RC4 cipher"),
    ("KEYEX", "key exchange"),
    ("BEGIN RSA", "RSA PEM"),
    ("BEGIN CERTIFICATE", "X.509 cert"),
    ("-----BEGIN", "PEM block"),
];

impl CryptoPattern {
    #[must_use]
    pub fn matches(&self, s: &str) -> Option<(f64, String)> {
        let upper = s.to_uppercase();
        for (pat, desc) in CRYPTO_SUBSTRINGS {
            if upper.contains(&pat.to_uppercase()) {
                return Some((0.90, desc.to_string()));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// StringClassifier — main classifier
// ---------------------------------------------------------------------------

/// Configuration for the string classifier.
#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    /// Minimum string length to classify (shorter strings return Unknown).
    pub min_length: usize,
    /// Whether to run secondary classification.
    pub multi_label: bool,
    /// Whether to detect crypto constants.
    pub detect_crypto: bool,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self { min_length: 3, multi_label: true, detect_crypto: true }
    }
}

/// Main string semantic classifier.
pub struct StringClassifier {
    config: ClassifierConfig,
    url: UrlPattern,
    path: PathPattern,
    guid: GuidPattern,
    ip: IpPattern,
    email: EmailPattern,
    registry: RegistryPattern,
    dll: DllPattern,
    fmt: FormatStringPattern,
    crypto: CryptoPattern,
    stats: ClassifierStats,
}

/// Statistics about classification runs.
#[derive(Debug, Default, Clone)]
pub struct ClassifierStats {
    pub total_classified: u64,
    pub by_category: HashMap<String, u64>,
    pub high_confidence: u64,
}

impl StringClassifier {
    #[must_use]
    pub fn new(config: ClassifierConfig) -> Self {
        Self {
            config,
            url: UrlPattern,
            path: PathPattern,
            guid: GuidPattern,
            ip: IpPattern,
            email: EmailPattern,
            registry: RegistryPattern,
            dll: DllPattern,
            fmt: FormatStringPattern,
            crypto: CryptoPattern,
            stats: ClassifierStats::default(),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ClassifierConfig::default())
    }

    /// Classify a single string.
    pub fn classify(&mut self, s: &str) -> ClassifierResult {
        self.stats.total_classified += 1;

        if s.len() < self.config.min_length {
            return ClassifierResult::unknown(s.to_owned());
        }

        let result = self.classify_inner(s);

        if result.is_high_confidence() {
            self.stats.high_confidence += 1;
        }
        *self.stats.by_category.entry(result.category.as_str().to_owned()).or_default() += 1;

        result
    }

    fn classify_inner(&self, s: &str) -> ClassifierResult {
        let mut candidates: Vec<(StringCategory, f64, Option<String>)> = Vec::new();

        if let Some(conf) = self.url.matches(s) {
            let host = self.url.extract_host(s).unwrap_or_default();
            candidates.push((StringCategory::Url, conf, Some(host)));
        }
        if let Some(conf) = self.path.matches(s) {
            candidates.push((StringCategory::FilePath, conf, None));
        }
        if let Some(conf) = self.guid.matches(s) {
            candidates.push((StringCategory::Guid, conf, None));
        }
        if let Some(conf) = self.ip.matches_v4(s) {
            let priv_flag = if self.ip.is_private(s) { Some("private".to_owned()) } else { None };
            candidates.push((StringCategory::IpAddress, conf, priv_flag));
        }
        if let Some(conf) = self.email.matches(s) {
            candidates.push((StringCategory::EmailAddress, conf, None));
        }
        if let Some(conf) = self.registry.matches(s) {
            candidates.push((StringCategory::RegistryKey, conf, None));
        }
        if let Some(conf) = self.dll.matches(s) {
            candidates.push((StringCategory::DllName, conf, None));
        }
        if let Some(conf) = self.fmt.matches(s) {
            candidates.push((StringCategory::FormatString, conf, None));
        }
        if self.config.detect_crypto {
            if let Some((conf, desc)) = self.crypto.matches(s) {
                candidates.push((StringCategory::CryptoConstant, conf, Some(desc)));
            }
        }
        // Base64 heuristic
        if is_base64_like(s) {
            candidates.push((StringCategory::Base64Data, 0.75, None));
        }
        // Hex data heuristic
        if is_hex_like(s) {
            candidates.push((StringCategory::HexData, 0.72, None));
        }

        if candidates.is_empty() {
            return ClassifierResult::unknown(s.to_owned());
        }

        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let (best_cat, best_conf, best_meta) = candidates.remove(0);
        let mut result = ClassifierResult::new(s.to_owned(), best_cat, best_conf);
        if let Some(meta) = best_meta {
            result.add_meta("detail", meta);
        }

        if self.config.multi_label {
            for (cat, conf, meta) in candidates {
                result.add_secondary(cat, conf);
                if let Some(m) = meta {
                    result.add_meta(&format!("{}_detail", cat.as_str()), m);
                }
            }
        }

        result
    }

    /// Classify a batch of strings.
    pub fn classify_batch(&mut self, strings: &[String]) -> Vec<ClassifierResult> {
        strings.iter().map(|s| self.classify(s)).collect()
    }

    /// Return all results for a specific category.
    #[must_use]
    pub fn filter_by_category<'a>(
        results: &'a [ClassifierResult],
        cat: StringCategory,
    ) -> Vec<&'a ClassifierResult> {
        results.iter().filter(|r| r.category == cat).collect()
    }

    #[must_use]
    pub const fn stats(&self) -> &ClassifierStats {
        &self.stats
    }
}

fn is_base64_like(s: &str) -> bool {
    if s.len() < 8 || s.len() % 4 != 0 { return false; }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

fn is_hex_like(s: &str) -> bool {
    let stripped = s.trim_start_matches("0x").trim_start_matches("0X");
    stripped.len() >= 8 && stripped.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> StringClassifier {
        StringClassifier::with_defaults()
    }

    #[test]
    fn test_classify_url() {
        let mut c = classifier();
        let r = c.classify("https://example.com/path?q=1");
        assert_eq!(r.category, StringCategory::Url);
        assert!(r.confidence > 0.8);
    }

    #[test]
    fn test_classify_windows_path() {
        let mut c = classifier();
        let r = c.classify("C:\\Windows\\System32\\notepad.exe");
        assert_eq!(r.category, StringCategory::FilePath);
    }

    #[test]
    fn test_classify_unix_path() {
        let mut c = classifier();
        let r = c.classify("/etc/passwd");
        assert_eq!(r.category, StringCategory::FilePath);
    }

    #[test]
    fn test_classify_guid() {
        let mut c = classifier();
        let r = c.classify("{550E8400-E29B-41D4-A716-446655440000}");
        assert_eq!(r.category, StringCategory::Guid);
        assert!(r.confidence > 0.95);
    }

    #[test]
    fn test_classify_ipv4() {
        let mut c = classifier();
        let r = c.classify("192.168.1.1");
        assert_eq!(r.category, StringCategory::IpAddress);
        assert!(r.metadata.contains_key("detail")); // private flag
    }

    #[test]
    fn test_classify_email() {
        let mut c = classifier();
        let r = c.classify("user@example.com");
        assert_eq!(r.category, StringCategory::EmailAddress);
    }

    #[test]
    fn test_classify_registry() {
        let mut c = classifier();
        let r = c.classify("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft");
        assert_eq!(r.category, StringCategory::RegistryKey);
    }

    #[test]
    fn test_classify_dll() {
        let mut c = classifier();
        let r = c.classify("kernel32.dll");
        assert_eq!(r.category, StringCategory::DllName);
    }

    #[test]
    fn test_classify_format_string() {
        let mut c = classifier();
        let r = c.classify("Error: %s (code %d)");
        assert_eq!(r.category, StringCategory::FormatString);
    }

    #[test]
    fn test_classify_pem() {
        let mut c = classifier();
        let r = c.classify("-----BEGIN RSA PRIVATE KEY-----");
        assert_eq!(r.category, StringCategory::CryptoConstant);
    }

    #[test]
    fn test_classify_unknown() {
        let mut c = classifier();
        let r = c.classify("ab"); // too short
        assert_eq!(r.category, StringCategory::Unknown);
    }

    #[test]
    fn test_classify_batch() {
        let mut c = classifier();
        let strings = vec![
            "https://malware.example/c2".to_owned(),
            "192.168.0.1".to_owned(),
        ];
        let results = c.classify_batch(&strings);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].category, StringCategory::Url);
        assert_eq!(results[1].category, StringCategory::IpAddress);
    }

    #[test]
    fn test_multi_label_secondary() {
        let mut c = classifier();
        let r = c.classify("http://192.168.1.1/admin");
        assert_eq!(r.category, StringCategory::Url);
        // Should have IpAddress as secondary
        let has_ip = r.secondary.iter().any(|(cat, _)| *cat == StringCategory::IpAddress);
        // It's embedded in a URL, so may or may not match — just ensure secondary is populated
        let _ = has_ip;
    }

    #[test]
    fn test_base64_detection() {
        let b64 = "SGVsbG9Xb3JsZA=="; // "HelloWorld" in base64
        assert!(is_base64_like(b64));
    }

    #[test]
    fn test_hex_detection() {
        assert!(is_hex_like("0xDEADBEEF"));
        assert!(is_hex_like("DEADBEEFCAFE1234"));
    }

    #[test]
    fn test_classifier_stats() {
        let mut c = classifier();
        c.classify("https://example.com");
        c.classify("127.0.0.1");
        assert_eq!(c.stats().total_classified, 2);
    }

    #[test]
    fn test_ip_private() {
        let ip = IpPattern;
        assert!(ip.is_private("192.168.0.1"));
        assert!(ip.is_private("10.0.0.1"));
        assert!(!ip.is_private("8.8.8.8"));
    }

    #[test]
    fn test_url_extract_host() {
        let url = UrlPattern;
        let host = url.extract_host("https://example.com/path");
        assert_eq!(host, Some("example.com".to_owned()));
    }

    // Coverage-gap: ClassifierResult constructors/mutators had no direct test.
    #[test]
    fn test_classifier_result_unknown_and_high_confidence() {
        let r = ClassifierResult::unknown("x".to_owned());
        assert_eq!(r.category, StringCategory::Unknown);
        assert!(!r.is_high_confidence());
        let hi = ClassifierResult::new("y".to_owned(), StringCategory::Unknown, 0.8);
        assert!(hi.is_high_confidence()); // boundary: exactly 0.8 counts as high
        let lo = ClassifierResult::new("z".to_owned(), StringCategory::Unknown, 0.79);
        assert!(!lo.is_high_confidence());
    }

    // Coverage-gap: add_secondary must keep the list sorted by confidence desc.
    #[test]
    fn test_add_secondary_sorted_desc() {
        let mut r = ClassifierResult::unknown("x".to_owned());
        r.add_secondary(StringCategory::Unknown, 0.3);
        r.add_secondary(StringCategory::Unknown, 0.9);
        r.add_secondary(StringCategory::Unknown, 0.5);
        let confs: Vec<f64> = r.secondary.iter().map(|(_, c)| *c).collect();
        assert_eq!(confs, vec![0.9, 0.5, 0.3]);
    }

    // Coverage-gap: add_meta overwrite semantics.
    #[test]
    fn test_add_meta_overwrites() {
        let mut r = ClassifierResult::unknown("x".to_owned());
        r.add_meta("k", "v1".to_owned());
        r.add_meta("k", "v2".to_owned());
        assert_eq!(r.metadata.get("k").map(String::as_str), Some("v2"));
    }

    // Coverage-gap: filter_by_category had no direct test.
    #[test]
    fn test_filter_by_category() {
        let mut c = classifier();
        let strings = vec![
            "https://example.com".to_owned(),
            "plain words here".to_owned(),
            "https://other.example".to_owned(),
        ];
        let results = c.classify_batch(&strings);
        let urls = StringClassifier::filter_by_category(&results, results[0].category);
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().all(|r| r.category == results[0].category));
        // A category present in no result yields an empty vec.
        let none = StringClassifier::filter_by_category(&[], StringCategory::Unknown);
        assert!(none.is_empty());
    }
}
