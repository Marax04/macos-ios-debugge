//! String classification and heuristic extraction.
//!
//! Provides functions to classify binary strings into meaningful categories:
//! URLs, IP addresses, email addresses, file paths, format strings, registry
//! keys, crypto constants, and obfuscated/high-entropy strings.

use crate::FoundString;

// ─────────────────────────────────────────────────────────────────────────────
// URL / URI extraction
// ─────────────────────────────────────────────────────────────────────────────

/// A URL or URI found in a binary.
#[derive(Debug, Clone)]
pub struct ExtractedUrl {
    /// The full URL string.
    pub url: String,
    /// The scheme (e.g. `"https"`).
    pub scheme: String,
    /// Host portion, if parseable.
    pub host: Option<String>,
    /// Path portion.
    pub path: Option<String>,
    /// Whether the URL appears well-formed.
    pub well_formed: bool,
}

/// Extract all URL-like strings from a collection of [`FoundString`]s.
#[must_use]
pub fn extract_urls(strings: &[FoundString]) -> Vec<ExtractedUrl> {
    let schemes = [
        "https://", "http://", "ftp://", "ftps://", "file://", "ws://", "wss://",
    ];
    let mut out = Vec::new();
    for s in strings {
        let v = &s.value;
        let lower = v.to_ascii_lowercase();
        for scheme_str in &schemes {
            if lower.starts_with(scheme_str) {
                let rest = &v[scheme_str.len()..];
                let (host, path) = rest.find('/').map_or_else(
                    || (Some(rest.to_owned()), None),
                    |slash| (Some(rest[..slash].to_owned()), Some(rest[slash..].to_owned())),
                );
                let well_formed = host.as_deref().is_some_and(|h| !h.is_empty());
                out.push(ExtractedUrl {
                    url: v.clone(),
                    scheme: scheme_str.trim_end_matches("://").to_owned(),
                    host,
                    path,
                    well_formed,
                });
                break;
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// IP address extraction
// ─────────────────────────────────────────────────────────────────────────────

/// An extracted IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedIp {
    /// The original string containing the IP.
    pub raw: String,
    /// Parsed octets for IPv4, or None for IPv6.
    pub ipv4_octets: Option<[u8; 4]>,
    /// True if this looks like an IPv6 address.
    pub is_ipv6: bool,
    /// Whether the address is a private range.
    pub is_private: bool,
}

impl ExtractedIp {
    /// Dotted-decimal string representation of an IPv4 address.
    #[must_use]
    pub fn dotted_decimal(&self) -> Option<String> {
        self.ipv4_octets
            .map(|o| format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
    }
}

/// Try to parse a dotted-decimal IPv4 address from a string.
#[must_use]
pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        octets[i] = p.parse::<u8>().ok()?;
    }
    Some(octets)
}

/// Whether an IPv4 address is in a private range (RFC 1918, loopback, link-local).
#[must_use]
pub const fn is_private_ipv4(octets: [u8; 4]) -> bool {
    matches!(
        octets,
        [10 | 127, ..] | [169, 254, ..] | [172, 16..=31, ..] | [192, 168, ..]
    )
}

/// Extract all IP-like strings from a collection of [`FoundString`]s.
#[must_use]
pub fn extract_ips(strings: &[FoundString]) -> Vec<ExtractedIp> {
    let mut out = Vec::new();
    for s in strings {
        let v = s.value.trim();
        if let Some(octets) = parse_ipv4(v) {
            let is_private = is_private_ipv4(octets);
            out.push(ExtractedIp {
                raw: v.to_owned(),
                ipv4_octets: Some(octets),
                is_ipv6: false,
                is_private,
            });
        } else if v.contains(':')
            && v.split(':').count() >= 3
            && v.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
        {
            out.push(ExtractedIp {
                raw: v.to_owned(),
                ipv4_octets: None,
                is_ipv6: true,
                is_private: false,
            });
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Email address extraction
// ─────────────────────────────────────────────────────────────────────────────

/// An extracted email address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedEmail {
    /// Full email address.
    pub email: String,
    /// Local part (before `@`).
    pub local: String,
    /// Domain part (after `@`).
    pub domain: String,
}

/// Extract email-like strings from a collection of [`FoundString`]s.
#[must_use]
pub fn extract_emails(strings: &[FoundString]) -> Vec<ExtractedEmail> {
    let mut out = Vec::new();
    for s in strings {
        let v = &s.value;
        if let Some(at) = v.find('@') {
            let local = &v[..at];
            let domain = &v[at + 1..];
            if !local.is_empty()
                && domain.contains('.')
                && local
                    .chars()
                    .all(|c| c.is_alphanumeric() || "+-._%".contains(c))
                && domain
                    .chars()
                    .all(|c| c.is_alphanumeric() || "-.".contains(c))
            {
                out.push(ExtractedEmail {
                    email: v.clone(),
                    local: local.to_owned(),
                    domain: domain.to_owned(),
                });
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Format string detection
// ─────────────────────────────────────────────────────────────────────────────

/// A detected format string and its specifiers.
#[derive(Debug, Clone)]
pub struct DetectedFormatString {
    /// The string value.
    pub value: String,
    /// The format specifiers found (e.g. `["%s", "%d"]`).
    pub specifiers: Vec<String>,
    /// True if the format string may be dangerous (e.g. `%n`).
    pub is_dangerous: bool,
}

/// Analyze a string value for printf-style format specifiers.
#[must_use]
pub fn detect_format_string(value: &str) -> Option<DetectedFormatString> {
    let spec_chars = [
        'd', 'i', 'u', 'o', 'x', 'X', 'f', 'F', 'e', 'E', 'g', 'G', 'c', 's', 'p', 'n', '%', 'q',
        'v', 'b',
    ];
    let mut specifiers = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 1 < bytes.len() {
            // Skip flags, width, precision
            let mut j = i + 1;
            while j < bytes.len() && b"-+ #0123456789.*hlLzjt".contains(&bytes[j]) {
                j += 1;
            }
            if j < bytes.len() {
                let c = bytes[j] as char;
                if spec_chars.contains(&c) {
                    let spec: String = value[i..=j].to_owned();
                    specifiers.push(spec);
                }
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    if specifiers.is_empty() {
        return None;
    }
    let is_dangerous = specifiers.iter().any(|s| s.ends_with('n'));
    Some(DetectedFormatString {
        value: value.to_owned(),
        specifiers,
        is_dangerous,
    })
}

/// Extract format strings from a collection of [`FoundString`]s.
#[must_use]
pub fn extract_format_strings(strings: &[FoundString]) -> Vec<DetectedFormatString> {
    strings
        .iter()
        .filter_map(|s| detect_format_string(&s.value))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto constant detection
// ─────────────────────────────────────────────────────────────────────────────

/// A detected cryptographic constant or marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoConstant {
    /// Human-readable name (e.g. `"AES S-box"`).
    pub name: String,
    /// Algorithm this constant belongs to.
    pub algorithm: String,
    /// Confidence: 0–100.
    pub confidence: u8,
}

/// Well-known cryptographic string constants.
const CRYPTO_STRINGS: &[(&str, &str, &str, u8)] = &[
    // (substring to look for, name, algorithm, confidence)
    (
        "-----BEGIN CERTIFICATE-----",
        "PEM Certificate header",
        "X.509",
        99,
    ),
    (
        "-----BEGIN PRIVATE KEY-----",
        "PEM Private Key header",
        "RSA/EC",
        99,
    ),
    (
        "-----BEGIN RSA PRIVATE KEY-----",
        "PEM RSA Private Key header",
        "RSA",
        99,
    ),
    (
        "-----BEGIN EC PRIVATE KEY-----",
        "PEM EC Private Key header",
        "ECDSA",
        99,
    ),
    (
        "-----BEGIN PUBLIC KEY-----",
        "PEM Public Key header",
        "RSA/EC",
        99,
    ),
    (
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
        "RSA-2048 ASN.1 prefix",
        "RSA",
        95,
    ),
    (
        "expand 32-byte k",
        "ChaCha20/Salsa20 constant",
        "ChaCha20",
        99,
    ),
    ("expand 16-byte k", "Salsa20/16 constant", "Salsa20", 99),
    ("SHA-256", "SHA-256 identifier", "SHA-2", 80),
    ("SHA-512", "SHA-512 identifier", "SHA-2", 80),
    ("AES-", "AES mode identifier", "AES", 75),
    ("RSA-", "RSA key size identifier", "RSA", 75),
    ("EC-", "EC identifier", "ECC", 70),
    ("ECDSA", "ECDSA name", "ECDSA", 80),
    ("ed25519", "Ed25519 name", "EdDSA", 90),
    ("curve25519", "Curve25519 name", "X25519", 90),
    ("hmac", "HMAC name", "HMAC", 70),
    ("bcrypt", "bcrypt name", "bcrypt", 95),
    ("scrypt", "scrypt name", "scrypt", 95),
    ("argon2", "Argon2 name", "Argon2", 95),
    ("pbkdf2", "PBKDF2 name", "PBKDF2", 95),
    ("md5", "MD5 name", "MD5", 80),
    ("sha1", "SHA-1 name", "SHA-1", 80),
    ("rc4", "RC4 name", "RC4", 85),
    ("blowfish", "Blowfish name", "Blowfish", 90),
    ("des", "DES name", "DES", 75),
    ("3des", "Triple-DES name", "3DES", 80),
];

/// Detect cryptographic constants in a string value.
#[must_use]
pub fn detect_crypto_constant(value: &str) -> Vec<CryptoConstant> {
    let lower = value.to_ascii_lowercase();
    CRYPTO_STRINGS
        .iter()
        .filter(|(pattern, _, _, _)| lower.contains(&pattern.to_ascii_lowercase()))
        .map(|(_, name, algo, confidence)| CryptoConstant {
            name: (*name).to_owned(),
            algorithm: (*algo).to_owned(),
            confidence: *confidence,
        })
        .collect()
}

/// Extract all crypto constants from a collection of [`FoundString`]s.
#[must_use]
pub fn extract_crypto_constants(strings: &[FoundString]) -> Vec<(String, Vec<CryptoConstant>)> {
    strings
        .iter()
        .filter_map(|s| {
            let consts = detect_crypto_constant(&s.value);
            if consts.is_empty() {
                None
            } else {
                Some((s.value.clone(), consts))
            }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Obfuscation detection
// ─────────────────────────────────────────────────────────────────────────────

/// Signals that a string may be obfuscated.
#[derive(Debug, Clone)]
pub struct ObfuscationSignal {
    /// The string value.
    pub value: String,
    /// Shannon entropy (high entropy suggests encryption/encoding).
    pub entropy: f64,
    /// Whether the string is valid Base64.
    pub looks_base64: bool,
    /// Whether the string appears to be hex-encoded data.
    pub looks_hex: bool,
    /// Overall obfuscation score (0–100).
    pub score: u8,
}

/// Check whether a string looks like Base64.
#[must_use]
pub fn looks_like_base64(s: &str) -> bool {
    if s.len() < 8 || !s.len().is_multiple_of(4) {
        return false;
    }
    let valid: usize = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    valid == s.len()
}

/// Check whether a string looks like a hex-encoded blob.
#[must_use]
pub fn looks_like_hex(s: &str) -> bool {
    if s.len() < 8 || !s.len().is_multiple_of(2) {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Compute Shannon entropy of a byte slice.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    // Canonical implementation for the whole crate: `string_obf_detector`,
    // `string_xref` and `patterns::shannon_entropy_str` all delegate here.
    // u64 counts and an exact length divisor, so no clamping at u32::MAX.
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / n;
        p.mul_add(-p.log2(), acc)
    })
}

/// Analyse a string for obfuscation signals.
#[must_use]
pub fn detect_obfuscation(value: &str) -> ObfuscationSignal {
    let bytes = value.as_bytes();
    let entropy = shannon_entropy(bytes);
    let looks_base64 = looks_like_base64(value);
    let looks_hex = looks_like_hex(value);

    // Score: high entropy contributes most.
    // entropy ∈ [0.0, 8.0]; map linearly to [0, 60].
    // Compute via integer byte counts to avoid f64→u8 cast.
    let entropy_score = {
        // entropy ∈ [0.0, 8.0]; map linearly to [0, 60] and take the floor.
        let scaled = (entropy / 8.0 * 60.0).clamp(0.0, 60.0);
        // Convert f64 → u8 without a lossy cast: largest integer ≤ scaled.
        (0..=60u8).take_while(|&s| f64::from(s) <= scaled).last().unwrap_or(0)
    };
    let base64_score: u8 = if looks_base64 { 30 } else { 0 };
    let hex_score: u8 = if looks_hex { 20 } else { 0 };
    let score = entropy_score
        .saturating_add(base64_score)
        .saturating_add(hex_score)
        .min(100);

    ObfuscationSignal {
        value: value.to_owned(),
        entropy,
        looks_base64,
        looks_hex,
        score,
    }
}

/// Extract high-obfuscation strings from a collection of [`FoundString`]s.
///
/// Only strings with an obfuscation score >= `min_score` are returned.
#[must_use]
pub fn extract_obfuscated(strings: &[FoundString], min_score: u8) -> Vec<ObfuscationSignal> {
    strings
        .iter()
        .map(|s| detect_obfuscation(&s.value))
        .filter(|sig| sig.score >= min_score)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// StringClass / StringClassifier
// ─────────────────────────────────────────────────────────────────────────────

/// High-level semantic class for a found string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringClass {
    /// HTTP/HTTPS/FTP/etc URL.
    Url,
    /// File-system path (Unix or Windows).
    FilePath,
    /// Windows Registry key.
    Registry,
    /// Email address.
    Email,
    /// Base64-encoded data.
    Base64Encoded,
    /// Hex-encoded data.
    HexEncoded,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// Domain name (e.g. `"evil.example.com"`).
    Domain,
    /// Known malware family name or indicator.
    MalwareFamily,
    /// No more-specific class was matched.
    Generic,
}

impl std::fmt::Display for StringClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Url => "URL",
            Self::FilePath => "FilePath",
            Self::Registry => "Registry",
            Self::Email => "Email",
            Self::Base64Encoded => "Base64Encoded",
            Self::HexEncoded => "HexEncoded",
            Self::IpAddress => "IpAddress",
            Self::Domain => "Domain",
            Self::MalwareFamily => "MalwareFamily",
            Self::Generic => "Generic",
        };
        f.write_str(s)
    }
}

/// Known malware-family name fragments (lower-case).
const MALWARE_NAMES: &[&str] = &[
    "mimikatz",
    "cobalt strike",
    "cobaltstrike",
    "meterpreter",
    "metasploit",
    "wannacry",
    "wanna",
    "petya",
    "notpetya",
    "emotet",
    "trickbot",
    "ryuk",
    "lockbit",
    "revil",
    "maze ransomware",
    "darkside",
    "blackcat",
    "alphv",
    "lazarus",
    "apt28",
    "apt29",
    "cozy bear",
    "fancy bear",
    "redline",
    "raccoon",
    "agent tesla",
    "njrat",
    "asyncrat",
    "quasarrat",
    "remcos",
    "gh0strat",
    "netbus",
    "zeus",
    "dridex",
    "qakbot",
    "qbot",
];

/// Classifier that maps a string value to its [`StringClass`].
pub struct StringClassifier;

impl StringClassifier {
    /// Classify a single string into its most specific [`StringClass`].
    ///
    /// The precedence (first match wins) is:
    /// Email > URL > `IpAddress` > Domain > Registry > `FilePath` >
    /// `MalwareFamily` > `Base64Encoded` > `HexEncoded` > Generic.
    #[must_use]
    pub fn classify(s: &str) -> StringClass {
        let trimmed = s.trim();
        let lower = trimmed.to_ascii_lowercase();

        // Email: must contain '@' and look valid before URL check
        if let Some(at) = trimmed.find('@') {
            let local = &trimmed[..at];
            let domain = &trimmed[at + 1..];
            if !local.is_empty()
                && domain.contains('.')
                && local
                    .chars()
                    .all(|c| c.is_alphanumeric() || "+-._%".contains(c))
                && domain
                    .chars()
                    .all(|c| c.is_alphanumeric() || "-.".contains(c))
            {
                return StringClass::Email;
            }
        }

        // URL
        let url_schemes = [
            "https://", "http://", "ftp://", "ftps://", "file://", "ws://", "wss://",
        ];
        if url_schemes.iter().any(|sc| lower.starts_with(sc)) {
            return StringClass::Url;
        }

        // IP address (IPv4)
        if parse_ipv4(trimmed).is_some() {
            return StringClass::IpAddress;
        }
        // IPv6: colon-hex pattern
        if trimmed.contains(':')
            && trimmed.split(':').count() >= 3
            && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
        {
            return StringClass::IpAddress;
        }

        // Windows registry
        if trimmed.starts_with("HKEY_")
            || trimmed.starts_with("HKLM\\")
            || trimmed.starts_with("HKCU\\")
            || trimmed.starts_with("Software\\")
            || trimmed.starts_with("SOFTWARE\\")
            || trimmed.starts_with("SYSTEM\\")
        {
            return StringClass::Registry;
        }

        // File path
        let is_win_path = trimmed.len() >= 3
            && trimmed
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && (trimmed.as_bytes().get(1) == Some(&b':') || trimmed.contains('\\'));
        let is_unix_path =
            trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../");
        if is_win_path || is_unix_path {
            return StringClass::FilePath;
        }

        // Domain heuristic: word.word or word.word.word, no spaces, not an IP
        let dot_count = trimmed.chars().filter(|&c| c == '.').count();
        if dot_count >= 1
            && !trimmed.contains(' ')
            && trimmed.len() >= 4
            && trimmed
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
        {
            // Exclude numeric-only octets (already handled as IP above)
            let parts: Vec<&str> = trimmed.split('.').collect();
            let last = parts.last().unwrap_or(&"");
            let all_parts_non_empty = parts.iter().all(|p| !p.is_empty());
            // TLD: 2-6 alpha chars
            if all_parts_non_empty
                && (2..=6).contains(&last.len())
                && last.chars().all(|c| c.is_ascii_alphabetic())
            {
                return StringClass::Domain;
            }
        }

        // Malware family
        if MALWARE_NAMES.iter().any(|&name| lower.contains(name)) {
            return StringClass::MalwareFamily;
        }

        // Base64
        if looks_like_base64(trimmed) {
            return StringClass::Base64Encoded;
        }

        // Hex blob
        if looks_like_hex(trimmed) {
            return StringClass::HexEncoded;
        }

        StringClass::Generic
    }

    /// Returns `true` if the string looks suspicious from a security perspective.
    ///
    /// Triggers for: hardcoded credentials, sensitive paths, crypto material,
    /// private keys, high-entropy blobs, C2-style domain patterns, etc.
    #[must_use]
    pub fn is_suspicious(s: &str) -> bool {
        let lower = s.to_ascii_lowercase();

        // Hardcoded credential keywords
        let cred_keywords = [
            "password",
            "passwd",
            "passw0rd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "bearer",
            "private_key",
            "privatekey",
            "client_secret",
            "admin123",
            "letmein",
            "changeme",
        ];
        if cred_keywords.iter().any(|k| lower.contains(k)) {
            return true;
        }

        // PEM / crypto material
        if s.contains("-----BEGIN") || s.contains("-----END") {
            return true;
        }

        // Hardcoded sensitive Windows paths
        let sensitive_paths = [
            "\\sam",
            "\\ntds.dit",
            "\\lsass",
            "\\system32\\config",
            "/etc/passwd",
            "/etc/shadow",
            "/root/",
            "/.ssh/",
        ];
        if sensitive_paths.iter().any(|p| lower.contains(p)) {
            return true;
        }

        // Very high Shannon entropy (> 5.5 bits) for non-trivial strings
        if s.len() >= 16 {
            let entropy = shannon_entropy(s.as_bytes());
            if entropy > 5.5 {
                return true;
            }
        }

        // Base64 / hex blobs of meaningful length
        if s.len() >= 32 && (looks_like_base64(s) || looks_like_hex(s)) {
            return true;
        }

        // Known malware-related strings
        if MALWARE_NAMES.iter().any(|&name| lower.contains(name)) {
            return true;
        }

        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, FoundString, StringEncoding};

    fn make_string(v: &str) -> FoundString {
        FoundString {
            address: Address::new(0),
            length: v.len(),
            encoding: StringEncoding::Ascii,
            value: v.to_owned(),
            char_count: v.len(),
            is_null_terminated: false,
            xref_count: 0,
        }
    }

    #[test]
    fn test_extract_urls_https() {
        let strings = vec![make_string("https://example.com/path")];
        let urls = extract_urls(&strings);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].scheme, "https");
        assert_eq!(urls[0].host.as_deref(), Some("example.com"));
        assert!(urls[0].well_formed);
    }

    #[test]
    fn test_extract_urls_no_match() {
        let strings = vec![make_string("just a regular string")];
        assert!(extract_urls(&strings).is_empty());
    }

    #[test]
    fn test_extract_urls_ftp() {
        let strings = vec![make_string("ftp://files.example.com/pub")];
        let urls = extract_urls(&strings);
        assert_eq!(urls[0].scheme, "ftp");
    }

    #[test]
    fn test_parse_ipv4_valid() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
        assert_eq!(parse_ipv4("10.0.0.1"), Some([10, 0, 0, 1]));
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        assert_eq!(parse_ipv4("300.0.0.1"), None);
        assert_eq!(parse_ipv4("192.168.1"), None);
        assert_eq!(parse_ipv4("not.an.ip.addr"), None);
    }

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_ipv4([10, 0, 0, 1]));
        assert!(is_private_ipv4([192, 168, 0, 1]));
        assert!(is_private_ipv4([172, 16, 0, 1]));
        assert!(is_private_ipv4([127, 0, 0, 1]));
        assert!(!is_private_ipv4([8, 8, 8, 8]));
    }

    #[test]
    fn test_extract_ips() {
        let strings = vec![
            make_string("192.168.1.1"),
            make_string("not an ip"),
            make_string("10.0.0.1"),
        ];
        let ips = extract_ips(&strings);
        assert_eq!(ips.len(), 2);
        assert!(ips[0].is_private);
        assert!(ips[1].is_private);
    }

    #[test]
    fn test_extract_emails() {
        let strings = vec![
            make_string("user@example.com"),
            make_string("admin@corp.internal"),
            make_string("not-an-email"),
        ];
        let emails = extract_emails(&strings);
        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0].local, "user");
        assert_eq!(emails[0].domain, "example.com");
    }

    #[test]
    fn test_detect_format_string_basic() {
        let r = detect_format_string("Error: %s at line %d");
        let r = r.unwrap();
        assert!(r.specifiers.contains(&"%s".to_owned()));
        assert!(r.specifiers.contains(&"%d".to_owned()));
        assert!(!r.is_dangerous);
    }

    #[test]
    fn test_detect_format_string_dangerous() {
        let r = detect_format_string("%n writes to address");
        let r = r.unwrap();
        assert!(r.is_dangerous);
    }

    #[test]
    fn test_detect_format_string_none() {
        assert!(detect_format_string("hello world").is_none());
    }

    #[test]
    fn test_detect_crypto_constant_pem() {
        let consts = detect_crypto_constant("-----BEGIN CERTIFICATE-----\nMIIDxx");
        assert!(!consts.is_empty());
        assert!(consts[0].algorithm == "X.509");
    }

    #[test]
    fn test_detect_crypto_constant_chacha() {
        let consts = detect_crypto_constant("expand 32-byte k");
        assert!(!consts.is_empty());
        assert_eq!(consts[0].algorithm, "ChaCha20");
        assert_eq!(consts[0].confidence, 99);
    }

    #[test]
    fn test_detect_crypto_constant_no_match() {
        let consts = detect_crypto_constant("hello world");
        assert!(consts.is_empty());
    }

    #[test]
    fn test_looks_like_base64() {
        assert!(looks_like_base64("SGVsbG8gV29ybGQ="));
        assert!(looks_like_base64("YWJjZA=="));
        assert!(!looks_like_base64("not base64!!"));
        assert!(!looks_like_base64("abc")); // length < 8
    }

    #[test]
    fn test_looks_like_hex() {
        assert!(looks_like_hex("deadbeef"));
        assert!(looks_like_hex("0102030405060708090a0b0c0d0e0f10"));
        assert!(!looks_like_hex("deadbeeg")); // 'g' not hex
        assert!(!looks_like_hex("abc")); // length < 8
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        let data = vec![0u8; 100]; // all zeros
        assert!((shannon_entropy(&data) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_shannon_entropy_max() {
        // 256 distinct bytes → max entropy = 8 bits
        let data: Vec<u8> = (0..=255u8).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 1e-3);
    }

    #[test]
    fn test_detect_obfuscation_high_entropy() {
        // A base64 string
        let sig = detect_obfuscation("SGVsbG8gV29ybGQ=");
        assert!(sig.score > 30);
        assert!(sig.looks_base64);
    }

    #[test]
    fn test_detect_obfuscation_plaintext() {
        let sig = detect_obfuscation("hello world");
        assert!(sig.score < 50);
        assert!(!sig.looks_base64);
    }

    #[test]
    fn test_extract_obfuscated_threshold() {
        let strings = vec![
            make_string("hello world"),      // low score
            make_string("SGVsbG8gV29ybGQ="), // base64, higher score
        ];
        let obf = extract_obfuscated(&strings, 30);
        assert!(!obf.is_empty());
    }

    #[test]
    fn test_extract_format_strings() {
        let strings = vec![
            make_string("hello"),
            make_string("value=%d ptr=%p"),
            make_string("Error: %s"),
        ];
        let fmts = extract_format_strings(&strings);
        assert_eq!(fmts.len(), 2);
    }

    #[test]
    fn test_extract_crypto_constants() {
        let strings = vec![
            make_string("using AES-256-GCM"),
            make_string("just a string"),
        ];
        let consts = extract_crypto_constants(&strings);
        assert_eq!(consts.len(), 1);
        assert!(consts[0].0.contains("AES"));
    }

    // ── Additional pure-function edge case tests ─────────────────────────────

    #[test]
    fn test_parse_ipv4_valid_and_edge_octets() {
        assert_eq!(parse_ipv4("0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4("255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
    }

    #[test]
    fn test_parse_ipv4_malformed_returns_none() {
        assert_eq!(parse_ipv4(""), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv4("1.2.3.4.5"), None);
        assert_eq!(parse_ipv4("256.0.0.0"), None);
        assert_eq!(parse_ipv4("a.b.c.d"), None);
        assert_eq!(parse_ipv4("1.-1.0.0"), None);
        assert_eq!(parse_ipv4("1..2.3"), None);
    }

    #[test]
    fn test_is_private_ipv4_classification() {
        assert!(is_private_ipv4([10, 0, 0, 1]));
        assert!(is_private_ipv4([127, 0, 0, 1]));
        assert!(is_private_ipv4([169, 254, 1, 1]));
        assert!(is_private_ipv4([172, 16, 0, 0]));
        assert!(is_private_ipv4([172, 31, 255, 255]));
        assert!(is_private_ipv4([192, 168, 0, 1]));
        // Public addresses.
        assert!(!is_private_ipv4([8, 8, 8, 8]));
        assert!(!is_private_ipv4([172, 32, 0, 0]));
        assert!(!is_private_ipv4([172, 15, 0, 0]));
    }

    #[test]
    fn test_looks_like_base64_boundaries() {
        // Too short.
        assert!(!looks_like_base64(""));
        assert!(!looks_like_base64("abc"));
        // Valid base64-ish content.
        assert!(looks_like_base64("SGVsbG8gV29ybGQhIQ=="));
        // Contains non-base64 chars.
        assert!(!looks_like_base64("not base64 because spaces"));
    }

    #[test]
    fn test_looks_like_hex_boundaries() {
        assert!(!looks_like_hex(""));
        assert!(looks_like_hex("deadbeefcafebabe"));
        assert!(looks_like_hex("DEADBEEF"));
        // Mixed letters/digits with non-hex chars rejected.
        assert!(!looks_like_hex("xyz123"));
    }

    #[test]
    fn test_shannon_entropy_extremes() {
        // Empty data → 0 entropy.
        assert_eq!(shannon_entropy(&[]), 0.0);
        // Single repeated byte → 0 entropy.
        let zeros = vec![0u8; 100];
        assert!(shannon_entropy(&zeros).abs() < 1e-9);
        // Uniform distribution over 256 bytes → ~8 bits.
        let uniform: Vec<u8> = (0..=255u8).collect();
        let h = shannon_entropy(&uniform);
        assert!(h > 7.9 && h <= 8.0, "expected ~8 bits, got {h}");
    }

    #[test]
    fn test_detect_format_string_basic_and_dangerous() {
        let plain = detect_format_string("just text");
        assert!(plain.is_none());
        let fmt = detect_format_string("hello %s number %d").unwrap();
        assert!(fmt.specifiers.iter().any(|s| s == "%s"));
        assert!(fmt.specifiers.iter().any(|s| s == "%d"));
        assert!(!fmt.is_dangerous);
        let dangerous = detect_format_string("count: %n").unwrap();
        assert!(dangerous.is_dangerous);
    }

    #[test]
    fn test_extract_ips_ipv6_requires_three_segments() {
        // Two-segment colon-hex strings (e.g. a timestamp "12:34") must NOT be
        // reported as IPv6 — matches StringClassifier::classify's >= 3 segment rule.
        let strings = vec![
            make_string("12:34"),
            make_string("dead:beef"),
            make_string("fe80::1"),
            make_string("2001:db8::ff00:42"),
        ];
        let ips = extract_ips(&strings);
        assert_eq!(ips.len(), 2);
        assert!(ips.iter().all(|ip| ip.is_ipv6));
        assert!(ips.iter().any(|ip| ip.raw == "fe80::1"));
    }

    #[test]
    fn test_detect_format_string_escape_percent() {
        // %% is a literal percent, not a specifier of interest as a format arg.
        let _ = detect_format_string("100%% done");
        // No panic; whether None or Some, it shouldn't crash on edge.
    }
}
