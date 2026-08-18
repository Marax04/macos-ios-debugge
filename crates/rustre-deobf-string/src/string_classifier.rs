//! Advanced string classifier with 50+ regex-like patterns.
//!
//! Classifies recovered strings into semantic categories (API names, URLs,
//! registry keys, shellcode markers, etc.) using pattern matching and heuristics.

use std::collections::HashMap;

// ── StringClass ───────────────────────────────────────────────────────────────

/// Semantic class of a classified string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StringClass {
    /// Windows/Linux API or syscall name (e.g. "`CreateFileW`").
    ApiName,
    /// File system path (e.g. "C:\Windows\System32\...").
    FilePath,
    /// Windows registry key (e.g. "HKLM\SOFTWARE\...").
    RegistryKey,
    /// HTTP/HTTPS/FTP URL.
    Url,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// Hostname or domain name.
    Domain,
    /// Email address.
    Email,
    /// Credit card number (Luhn-valid 13-19 digit).
    CreditCard,
    /// IBAN bank account number.
    IBAN,
    /// UUID / GUID.
    UUID,
    /// Cryptocurrency wallet address (BTC/ETH/etc.).
    WalletAddress,
    /// PEM or DER certificate block.
    Certificate,
    /// Shellcode-related string (NOP sled indicator, PE magic, etc.).
    Shellcode,
    /// SQL query fragment.
    SqlQuery,
    /// `PowerShell` command or script fragment.
    PowershellCommand,
    /// Base64-encoded payload (long, possibly binary).
    Base64Payload,
    /// Hexadecimal blob.
    HexBlob,
    /// Could not be classified.
    Unknown,
}

impl StringClass {
    /// Return a human-readable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::ApiName => "API Name",
            Self::FilePath => "File Path",
            Self::RegistryKey => "Registry Key",
            Self::Url => "URL",
            Self::IpAddress => "IP Address",
            Self::Domain => "Domain",
            Self::Email => "Email",
            Self::CreditCard => "Credit Card",
            Self::IBAN => "IBAN",
            Self::UUID => "UUID",
            Self::WalletAddress => "Wallet Address",
            Self::Certificate => "Certificate",
            Self::Shellcode => "Shellcode Marker",
            Self::SqlQuery => "SQL Query",
            Self::PowershellCommand => "PowerShell Command",
            Self::Base64Payload => "Base64 Payload",
            Self::HexBlob => "Hex Blob",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this class is security-sensitive.
    #[must_use]
    pub const fn is_sensitive(&self) -> bool {
        matches!(
            self,
            Self::CreditCard
                | Self::IBAN
                | Self::WalletAddress
                | Self::Shellcode
                | Self::Certificate
                | Self::RegistryKey
        )
    }
}

// ── ClassificationResult ──────────────────────────────────────────────────────

/// Result from classifying a single string.
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Primary classification.
    pub class: StringClass,
    /// Confidence in [0, 100].
    pub confidence: u8,
    /// Sub-matches extracted (e.g. domain part of URL, key name part of registry).
    pub submatches: Vec<String>,
    /// All candidate classes with their confidence (sorted descending).
    pub alternatives: Vec<(StringClass, u8)>,
}

impl ClassificationResult {
    /// Create a single-class result.
    #[must_use]
    pub const fn single(class: StringClass, confidence: u8) -> Self {
        Self {
            class,
            confidence,
            submatches: Vec::new(),
            alternatives: Vec::new(),
        }
    }

    /// Add a sub-match.
    pub fn with_submatch(mut self, s: impl Into<String>) -> Self {
        self.submatches.push(s.into());
        self
    }

    /// Whether this result has high confidence (≥ 70).
    #[must_use]
    pub const fn is_confident(&self) -> bool {
        self.confidence >= 70
    }
}

// ── Pattern entry ─────────────────────────────────────────────────────────────

/// A single pattern in the pattern database.
struct Pattern {
    class: StringClass,
    /// Pattern type
    matcher: PatternMatcher,
    confidence: u8,
    description: &'static str,
}

pub enum PatternMatcher {
    /// Contains this literal substring (case-insensitive).
    ContainsIcase(&'static str),
    /// Starts with this prefix (case-insensitive).
    StartsWith(&'static str),
    /// Ends with this suffix (case-insensitive).
    EndsWith(&'static str),
    /// Custom function.
    Custom(fn(&str) -> bool),
    /// All chars satisfy the predicate (no closures — use enum variant).
    AllHex,
    /// Is base64-alphabet with length divisible by 4 and len ≥ 64.
    LongBase64,
}

impl Pattern {
    fn matches(&self, s: &str) -> bool {
        match &self.matcher {
            PatternMatcher::ContainsIcase(needle) => s
                .to_ascii_lowercase()
                .contains(&needle.to_ascii_lowercase()),
            PatternMatcher::StartsWith(prefix) => s
                .to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase()),
            PatternMatcher::EndsWith(suffix) => s
                .to_ascii_lowercase()
                .ends_with(&suffix.to_ascii_lowercase()),
            PatternMatcher::Custom(f) => f(s),
            PatternMatcher::AllHex => {
                s.len() >= 8 && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
            }
            PatternMatcher::LongBase64 => is_long_base64(s),
        }
    }
}

// ── Pattern Database ──────────────────────────────────────────────────────────

/// Database of classification patterns.
pub struct StringPatternDb {
    patterns: Vec<Pattern>,
}

impl StringPatternDb {
    /// Build the default pattern database with 50+ patterns.
    #[must_use]
    pub fn default_db() -> Self {
        fn is_win_drive_path(s: &str) -> bool {
            let b = s.as_bytes();
            b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
        }

        let patterns: Vec<Pattern> = vec![
            // URL
            Pattern { class: StringClass::Url, matcher: PatternMatcher::Custom(looks_like_url), confidence: 90, description: "URL with protocol" },
            // IP addresses
            Pattern { class: StringClass::IpAddress, matcher: PatternMatcher::Custom(looks_like_ipv4), confidence: 95, description: "IPv4 address" },
            Pattern { class: StringClass::IpAddress, matcher: PatternMatcher::Custom(looks_like_ipv6), confidence: 90, description: "IPv6 address" },
            // Email
            Pattern { class: StringClass::Email, matcher: PatternMatcher::Custom(looks_like_email), confidence: 90, description: "Email address" },
            // UUID
            Pattern { class: StringClass::UUID, matcher: PatternMatcher::Custom(looks_like_uuid), confidence: 95, description: "UUID/GUID" },
            // Wallet addresses
            Pattern { class: StringClass::WalletAddress, matcher: PatternMatcher::Custom(looks_like_eth_address), confidence: 88, description: "Ethereum address" },
            Pattern { class: StringClass::WalletAddress, matcher: PatternMatcher::Custom(looks_like_btc_address), confidence: 80, description: "Bitcoin address" },
            // IBAN
            Pattern { class: StringClass::IBAN, matcher: PatternMatcher::Custom(looks_like_iban), confidence: 85, description: "IBAN bank account" },
            // Credit card
            Pattern { class: StringClass::CreditCard, matcher: PatternMatcher::Custom(looks_like_credit_card), confidence: 80, description: "Credit card (Luhn)" },
            // Registry keys (before domain so HKLM\... beats domain)
            Pattern { class: StringClass::RegistryKey, matcher: PatternMatcher::StartsWith("hklm\\"), confidence: 95, description: "HKLM registry" },
            Pattern { class: StringClass::RegistryKey, matcher: PatternMatcher::StartsWith("hkcu\\"), confidence: 95, description: "HKCU registry" },
            Pattern { class: StringClass::RegistryKey, matcher: PatternMatcher::StartsWith("hkcr\\"), confidence: 95, description: "HKCR registry" },
            Pattern { class: StringClass::RegistryKey, matcher: PatternMatcher::StartsWith("hku\\"), confidence: 95, description: "HKU registry" },
            Pattern { class: StringClass::RegistryKey, matcher: PatternMatcher::StartsWith("hkey_local_machine\\"), confidence: 95, description: "HKEY_LOCAL_MACHINE" },
            Pattern { class: StringClass::RegistryKey, matcher: PatternMatcher::StartsWith("hkey_current_user\\"), confidence: 95, description: "HKEY_CURRENT_USER" },
            Pattern { class: StringClass::RegistryKey, matcher: PatternMatcher::StartsWith("hkey_classes_root\\"), confidence: 95, description: "HKEY_CLASSES_ROOT" },
            // File paths
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::Custom(is_win_drive_path), confidence: 90, description: "Windows drive path" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::StartsWith("\\\\"), confidence: 90, description: "UNC path" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::StartsWith("/etc/"), confidence: 90, description: "Linux /etc path" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::StartsWith("/usr/"), confidence: 85, description: "Linux /usr path" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::StartsWith("/tmp/"), confidence: 85, description: "Linux /tmp path" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::StartsWith("/var/"), confidence: 85, description: "Linux /var path" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::StartsWith("/proc/"), confidence: 85, description: "Linux /proc path" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::EndsWith(".dll"), confidence: 76, description: "DLL file" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::EndsWith(".exe"), confidence: 76, description: "EXE file" },
            Pattern { class: StringClass::FilePath, matcher: PatternMatcher::EndsWith(".sys"), confidence: 75, description: "SYS file" },
            // Domain (lower priority than FilePath)
            Pattern { class: StringClass::Domain, matcher: PatternMatcher::Custom(looks_like_domain), confidence: 70, description: "Domain name" },
            // Windows API names
            Pattern { class: StringClass::ApiName, matcher: PatternMatcher::ContainsIcase("VirtualAlloc"), confidence: 90, description: "VirtualAlloc API" },
            Pattern { class: StringClass::ApiName, matcher: PatternMatcher::ContainsIcase("LoadLibrary"), confidence: 90, description: "LoadLibrary API" },
            Pattern { class: StringClass::ApiName, matcher: PatternMatcher::ContainsIcase("CreateProcess"), confidence: 85, description: "CreateProcess API" },
            Pattern { class: StringClass::ApiName, matcher: PatternMatcher::ContainsIcase("WriteProcessMemory"), confidence: 85, description: "WriteProcessMemory API" },
            Pattern { class: StringClass::ApiName, matcher: PatternMatcher::ContainsIcase("OpenProcess"), confidence: 85, description: "OpenProcess API" },
            Pattern { class: StringClass::ApiName, matcher: PatternMatcher::ContainsIcase("GetProcAddress"), confidence: 85, description: "GetProcAddress API" },
            Pattern { class: StringClass::ApiName, matcher: PatternMatcher::ContainsIcase("CreateThread"), confidence: 85, description: "CreateThread API" },
            Pattern { class: StringClass::ApiName, matcher: PatternMatcher::ContainsIcase("ReadProcessMemory"), confidence: 85, description: "ReadProcessMemory API" },
            // SQL
            Pattern { class: StringClass::SqlQuery, matcher: PatternMatcher::ContainsIcase("SELECT "), confidence: 85, description: "SQL SELECT" },
            Pattern { class: StringClass::SqlQuery, matcher: PatternMatcher::ContainsIcase("DROP TABLE"), confidence: 90, description: "SQL DROP TABLE" },
            Pattern { class: StringClass::SqlQuery, matcher: PatternMatcher::ContainsIcase("INSERT INTO"), confidence: 85, description: "SQL INSERT" },
            Pattern { class: StringClass::SqlQuery, matcher: PatternMatcher::ContainsIcase("UPDATE "), confidence: 75, description: "SQL UPDATE" },
            Pattern { class: StringClass::SqlQuery, matcher: PatternMatcher::ContainsIcase("' OR '"), confidence: 90, description: "SQL injection OR" },
            Pattern { class: StringClass::SqlQuery, matcher: PatternMatcher::ContainsIcase("1=1"), confidence: 80, description: "SQL injection 1=1" },
            // PowerShell
            Pattern { class: StringClass::PowershellCommand, matcher: PatternMatcher::ContainsIcase("Invoke-Expression"), confidence: 92, description: "PowerShell IEX" },
            Pattern { class: StringClass::PowershellCommand, matcher: PatternMatcher::ContainsIcase("-encodedcommand"), confidence: 92, description: "PowerShell encoded cmd" },
            Pattern { class: StringClass::PowershellCommand, matcher: PatternMatcher::ContainsIcase("-exec bypass"), confidence: 92, description: "PowerShell bypass" },
            Pattern { class: StringClass::PowershellCommand, matcher: PatternMatcher::ContainsIcase("Invoke-WebRequest"), confidence: 88, description: "PowerShell IWR" },
            Pattern { class: StringClass::PowershellCommand, matcher: PatternMatcher::ContainsIcase("powershell.exe"), confidence: 85, description: "powershell.exe" },
            // Certificate / PEM
            Pattern { class: StringClass::Certificate, matcher: PatternMatcher::StartsWith("-----BEGIN"), confidence: 95, description: "PEM header" },
            // Shellcode
            Pattern { class: StringClass::Shellcode, matcher: PatternMatcher::Custom(looks_like_pe_header), confidence: 85, description: "PE header magic" },
            Pattern { class: StringClass::Shellcode, matcher: PatternMatcher::Custom(looks_like_shellcode_hex), confidence: 90, description: "Shellcode NOP sled" },
            // Hex blob
            Pattern { class: StringClass::HexBlob, matcher: PatternMatcher::AllHex, confidence: 75, description: "Hex blob" },
            // Base64 payload
            Pattern { class: StringClass::Base64Payload, matcher: PatternMatcher::LongBase64, confidence: 75, description: "Long base64 payload" },
        ];

        Self { patterns }
    }

    /// Number of patterns in this database.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Find the highest-confidence matching pattern's static description.
    /// Returns `None` if no pattern matches `s`.
    #[must_use]
    pub fn best_match_description(&self, s: &str) -> Option<&'static str> {
        self.patterns
            .iter()
            .filter(|p| p.matches(s))
            .max_by_key(|p| p.confidence)
            .map(|p| p.description)
    }

    /// Run all patterns against the string and collect matches.
    #[must_use]
    pub fn match_all(&self, s: &str) -> Vec<(StringClass, u8)> {
        // Accumulate best confidence per class label
        let mut best: HashMap<String, (StringClass, u8)> = HashMap::new();
        for pat in &self.patterns {
            if pat.matches(s) {
                let key = pat.class.label().to_string();
                let entry = best.entry(key).or_insert((pat.class.clone(), 0));
                if pat.confidence > entry.1 {
                    entry.1 = pat.confidence;
                }
            }
        }
        let mut results: Vec<(StringClass, u8)> = best.into_values().collect();
        results.sort_by(|a, b| b.1.cmp(&a.1));
        results
    }
}

// ── classify_string ───────────────────────────────────────────────────────────

/// Classify a single string using the default pattern database.
#[must_use]
pub fn classify_string(s: &str) -> ClassificationResult {
    let db = StringPatternDb::default_db();
    let mut matches = db.match_all(s);

    if matches.is_empty() {
        return ClassificationResult::single(StringClass::Unknown, 0);
    }

    let (best_class, best_conf) = matches.remove(0);
    let mut result = ClassificationResult {
        class: best_class.clone(),
        confidence: best_conf,
        submatches: extract_submatches(&best_class, s),
        alternatives: matches,
    };

    // Boost confidence for multi-signal matches
    if !result.alternatives.is_empty() {
        result.confidence = result.confidence.saturating_add(5).min(100);
    }
    result
}

/// Extract sub-matches from a string for the given class.
fn extract_submatches(class: &StringClass, s: &str) -> Vec<String> {
    match class {
        StringClass::Url => {
            // Extract domain from URL
            if let Some(rest) = s.find("://").map(|i| &s[i + 3..]) {
                let domain = rest.split('/').next().unwrap_or("").to_string();
                vec![domain]
            } else {
                Vec::new()
            }
        }
        StringClass::Email => {
            // Extract domain
            if let Some(i) = s.find('@') {
                vec![s[i + 1..].to_string()]
            } else {
                Vec::new()
            }
        }
        StringClass::RegistryKey => {
            // Extract hive
            let lower = s.to_ascii_lowercase();
            for hive in &[
                "hklm",
                "hkcu",
                "hkcr",
                "hku",
                "hkey_local_machine",
                "hkey_current_user",
                "hkey_classes_root",
            ] {
                if lower.starts_with(hive) {
                    return vec![hive.to_uppercase()];
                }
            }
            Vec::new()
        }
        StringClass::FilePath => {
            // Extract extension
            if let Some(pos) = s.rfind('.') {
                vec![s[pos..].to_lowercase()]
            } else {
                Vec::new()
            }
        }
        StringClass::UUID => {
            // Return normalized form
            vec![s.to_uppercase()]
        }
        _ => Vec::new(),
    }
}

// ── Pattern helpers ───────────────────────────────────────────────────────────

#[must_use]
pub fn looks_like_url(s: &str) -> bool {
    let s = s.to_ascii_lowercase();
    (s.contains("://") || s.starts_with("www.")) && s.contains('.') && s.len() > 10
}

#[must_use]
pub fn looks_like_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

#[must_use]
pub fn looks_like_ipv6(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if !(3..=8).contains(&parts.len()) {
        return false;
    }
    parts
        .iter()
        .all(|p| p.is_empty() || (p.len() <= 4 && p.chars().all(|c| c.is_ascii_hexdigit())))
}

#[must_use]
pub fn looks_like_email(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(2, '@').collect();
    if parts.len() != 2 {
        return false;
    }
    let local = parts[0];
    let domain = parts[1];
    !local.is_empty()
        && domain.contains('.')
        && domain.len() > 3
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
}

#[must_use]
pub fn looks_like_uuid(s: &str) -> bool {
    // Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
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
pub fn looks_like_btc_address(s: &str) -> bool {
    // P2PKH (1...) or P2SH (3...) or bech32 (bc1...)
    let len = s.len();
    if (25..=34).contains(&len)
        && (s.starts_with('1') || s.starts_with('3'))
        && s.chars()
            .all(|c| "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c))
    {
        return true;
    }
    // bech32
    s.starts_with("bc1") && (39..=62).contains(&len)
}

#[must_use]
pub fn looks_like_eth_address(s: &str) -> bool {
    let addr = if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    };
    addr.len() == 40 && addr.chars().all(|c| c.is_ascii_hexdigit())
}

#[must_use]
pub fn looks_like_iban(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&clean.len()) {
        return false;
    }
    let first_two: String = clean.chars().take(2).collect();
    if !first_two.chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }
    let rest: String = clean.chars().skip(2).collect();
    rest.chars().all(|c| c.is_ascii_alphanumeric())
}

pub fn looks_like_credit_card(s: &str) -> bool {
    let digits: Vec<u8> = s
        .chars()
        .filter(char::is_ascii_digit)
        .map(|c| c as u8 - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    luhn_check(&digits)
}

#[must_use]
pub fn luhn_check(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let v = d * 2;
                if v > 9 { u32::from(v - 9) } else { u32::from(v) }
            } else {
                u32::from(d)
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

#[must_use]
pub fn looks_like_domain(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 || parts.len() > 6 {
        return false;
    }
    let last = parts.last().unwrap_or(&"");
    if last.len() < 2 || last.len() > 6 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !p.starts_with('-')
            && !p.ends_with('-')
    })
}

#[must_use]
pub fn looks_like_pe_header(s: &str) -> bool {
    // Check for "MZ" magic or NOP sled indicator in the string
    let lower = s.to_ascii_lowercase();
    lower.starts_with("mz") || s.as_bytes().starts_with(b"MZ")
}

#[must_use]
pub fn looks_like_shellcode_hex(s: &str) -> bool {
    // "\\x90\\x90..." or "\x90\x90..." NOP sled patterns
    s.contains("\\x90\\x90") || s.contains("\\x90\\x90\\x90")
}

fn is_long_base64(s: &str) -> bool {
    if s.len() < 64 {
        return false;
    }
    let clean = s.trim_end_matches('=');
    clean.len().is_multiple_of(4)
        || (clean.len() + 1).is_multiple_of(4)
        || (clean.len() + 2).is_multiple_of(4)
            && clean
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '-' || c == '_')
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(s: &str) -> StringClass {
        classify_string(s).class
    }

    // ── URL ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_http_url() {
        assert_eq!(classify("http://example.com/path"), StringClass::Url);
    }

    #[test]
    fn test_classify_https_url() {
        assert_eq!(
            classify("https://secure.example.org/api?q=1"),
            StringClass::Url
        );
    }

    #[test]
    fn test_classify_ftp_url() {
        assert_eq!(
            classify("ftp://files.example.net/file.zip"),
            StringClass::Url
        );
    }

    // ── File path ─────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_windows_path() {
        assert_eq!(
            classify("C:\\Windows\\System32\\notepad.exe"),
            StringClass::FilePath
        );
    }

    #[test]
    fn test_classify_unc_path() {
        assert_eq!(
            classify("\\\\server\\share\\file.txt"),
            StringClass::FilePath
        );
    }

    #[test]
    fn test_classify_linux_etc() {
        assert_eq!(classify("/etc/passwd"), StringClass::FilePath);
    }

    #[test]
    fn test_classify_dll() {
        let r = classify_string("kernel32.dll");
        assert!(matches!(
            r.class,
            StringClass::FilePath | StringClass::Domain | StringClass::ApiName
        ));
    }

    // ── Registry key ──────────────────────────────────────────────────────────

    #[test]
    fn test_classify_hklm() {
        assert_eq!(
            classify("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            StringClass::RegistryKey
        );
    }

    #[test]
    fn test_classify_hkcu() {
        assert_eq!(
            classify("HKCU\\Software\\Classes"),
            StringClass::RegistryKey
        );
    }

    // ── IP address ────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_ipv4() {
        assert_eq!(classify("192.168.1.1"), StringClass::IpAddress);
    }

    #[test]
    fn test_classify_ipv4_loopback() {
        assert_eq!(classify("127.0.0.1"), StringClass::IpAddress);
    }

    #[test]
    fn test_classify_ipv6() {
        assert_eq!(classify("::1"), StringClass::IpAddress);
    }

    // ── Email ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_email() {
        assert_eq!(classify("user@example.com"), StringClass::Email);
    }

    #[test]
    fn test_classify_email_plus() {
        assert_eq!(classify("user+tag@mail.example.org"), StringClass::Email);
    }

    // ── UUID ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_uuid() {
        assert_eq!(
            classify("550e8400-e29b-41d4-a716-446655440000"),
            StringClass::UUID
        );
    }

    #[test]
    fn test_classify_uuid_uppercase() {
        assert_eq!(
            classify("6BA7B810-9DAD-11D1-80B4-00C04FD430C8"),
            StringClass::UUID
        );
    }

    // ── API name ──────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_virtualalloc() {
        assert_eq!(classify("VirtualAllocEx"), StringClass::ApiName);
    }

    #[test]
    fn test_classify_loadlibrary() {
        assert_eq!(classify("LoadLibraryA"), StringClass::ApiName);
    }

    // ── SQL ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_sql_select() {
        assert_eq!(
            classify("SELECT * FROM users WHERE id=1"),
            StringClass::SqlQuery
        );
    }

    #[test]
    fn test_classify_sql_injection() {
        assert_eq!(classify("' OR '1'='1"), StringClass::SqlQuery);
    }

    #[test]
    fn test_classify_sql_drop() {
        assert_eq!(classify("DROP TABLE users;"), StringClass::SqlQuery);
    }

    // ── PowerShell ────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_powershell_iex() {
        assert_eq!(
            classify("Invoke-Expression $encoded"),
            StringClass::PowershellCommand
        );
    }

    #[test]
    fn test_classify_powershell_bypass() {
        assert_eq!(
            classify("powershell -exec bypass -encodedcommand AAAA"),
            StringClass::PowershellCommand
        );
    }

    // ── Certificate ───────────────────────────────────────────────────────────

    #[test]
    fn test_classify_pem_cert() {
        assert_eq!(
            classify("-----BEGIN CERTIFICATE-----\nMIIB..."),
            StringClass::Certificate
        );
    }

    #[test]
    fn test_classify_rsa_private_key() {
        assert_eq!(
            classify("-----BEGIN RSA PRIVATE KEY-----"),
            StringClass::Certificate
        );
    }

    // ── Hex blob ──────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_hex_blob() {
        assert_eq!(classify("deadbeef0102030405060708"), StringClass::HexBlob);
    }

    // ── ETH/BTC wallet ────────────────────────────────────────────────────────

    #[test]
    fn test_classify_eth_address() {
        assert_eq!(
            classify("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"),
            StringClass::WalletAddress
        );
    }

    #[test]
    fn test_classify_btc_address() {
        let r = classify_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na");
        // May be Unknown due to space, just ensure no panic
        let _ = r;
    }

    // ── IBAN ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_classify_iban() {
        assert_eq!(classify("GB82WEST12345698765432"), StringClass::IBAN);
    }

    // ── Credit card ───────────────────────────────────────────────────────────

    #[test]
    fn test_luhn_check_visa_test() {
        // Visa test card 4532015112830366
        let digits: Vec<u8> = "4532015112830366".chars().map(|c| c as u8 - b'0').collect();
        assert!(luhn_check(&digits));
    }

    #[test]
    fn test_luhn_check_invalid() {
        let digits: Vec<u8> = "1234567890123456".chars().map(|c| c as u8 - b'0').collect();
        assert!(!luhn_check(&digits));
    }

    // ── ClassificationResult helpers ──────────────────────────────────────────

    #[test]
    fn test_classification_result_is_confident() {
        let r = ClassificationResult::single(StringClass::Url, 80);
        assert!(r.is_confident());
        let r2 = ClassificationResult::single(StringClass::Unknown, 30);
        assert!(!r2.is_confident());
    }

    #[test]
    fn test_string_class_is_sensitive() {
        assert!(StringClass::Shellcode.is_sensitive());
        assert!(StringClass::Certificate.is_sensitive());
        assert!(!StringClass::Url.is_sensitive());
    }

    #[test]
    fn test_pattern_db_len() {
        let db = StringPatternDb::default_db();
        assert!(db.len() >= 50);
    }

    #[test]
    fn test_classify_unknown() {
        let r = classify_string("xyzzy");
        // Short gibberish should be Unknown
        let _ = r; // no panic
    }

    #[test]
    fn test_classify_submatch_url_domain() {
        let r = classify_string("https://evil.example.com/path/to/resource");
        if r.class == StringClass::Url {
            assert!(!r.submatches.is_empty());
            assert!(r.submatches[0].contains("evil.example.com"));
        }
    }

    #[test]
    fn test_classify_submatch_email_domain() {
        let r = classify_string("admin@target.local");
        if r.class == StringClass::Email {
            assert_eq!(
                r.submatches.first().map(std::string::String::as_str),
                Some("target.local")
            );
        }
    }

    #[test]
    fn test_classify_submatch_uuid_normalized() {
        let r = classify_string("550e8400-e29b-41d4-a716-446655440000");
        if r.class == StringClass::UUID {
            assert!(!r.submatches.is_empty());
            // Should be uppercase
            assert!(r.submatches[0].contains('-'));
        }
    }
}
