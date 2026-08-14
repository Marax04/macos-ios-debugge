//! String cross-reference analysis for `rustre-analysis-xref`.
//!
//! Builds a string → function reference map, identifies:
//!
//! * **Format strings** — strings that contain `%d`, `%s`, etc., with the
//!   inferred type and count of format specifiers.
//! * **Error messages** — strings that start with known error prefixes, linked
//!   to the functions that emit them.
//! * **Hardcoded credentials** — strings matching common credential patterns
//!   (API keys, passwords, private-key headers, base64 blobs of typical key
//!   sizes).
//! * **String → caller** mapping — which functions reference a given string,
//!   and at which instruction addresses.

use std::collections::HashMap;

use rustre_core::address::Address;

// ─────────────────────────────────────────────────────────────────────────────
// String reference
// ─────────────────────────────────────────────────────────────────────────────

/// A reference from a function instruction to a string literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StringRef {
    /// Address of the instruction that loads or computes the string address.
    pub insn_addr: Address,
    /// Address of the function that contains the instruction.
    pub function_addr: Address,
    /// Address of the string in the binary.
    pub string_addr: Address,
}

// ─────────────────────────────────────────────────────────────────────────────
// Format-string analysis
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a single `%`-conversion specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FmtSpecKind {
    /// `%d`, `%i` — signed integer.
    SignedInt,
    /// `%u`, `%o`, `%x`, `%X` — unsigned integer.
    UnsignedInt,
    /// `%f`, `%e`, `%g`, `%a` — floating-point.
    Float,
    /// `%s` — string pointer.
    StringPtr,
    /// `%p` — void pointer.
    Pointer,
    /// `%c` — character.
    Char,
    /// `%n` — write-back (dangerous).
    WriteBack,
    /// Other / unknown specifier.
    Other,
}

/// One parsed format specifier.
#[derive(Debug, Clone)]
pub struct FmtSpec {
    /// Zero-based position in the format string.
    pub position: usize,
    /// The classification of this specifier.
    pub kind: FmtSpecKind,
    /// The raw character (e.g. `'d'`, `'s'`).
    pub ch: char,
}

/// Parsed information about a format string.
#[derive(Debug, Clone)]
pub struct FormatStringInfo {
    /// Address of the string.
    pub string_addr: Address,
    /// The raw string content.
    pub raw: String,
    /// All parsed format specifiers.
    pub specs: Vec<FmtSpec>,
}

impl FormatStringInfo {
    /// Return `true` if the format string contains any `%n` specifiers.
    #[must_use]
    pub fn has_write_back(&self) -> bool {
        self.specs.iter().any(|s| s.kind == FmtSpecKind::WriteBack)
    }

    /// Return the number of format arguments expected.
    #[must_use]
    pub const fn arg_count(&self) -> usize {
        self.specs.len()
    }
}

/// Parse a format string and return information about its specifiers.
#[must_use]
pub fn parse_format_string(raw: &str, string_addr: Address) -> Option<FormatStringInfo> {
    let mut specs = Vec::new();
    let chars: Vec<char> = raw.chars().collect();
    let len = chars.len();
    let mut i = 0usize;

    while i < len {
        if chars[i] != '%' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= len {
            break;
        }
        // Skip flags, width, precision.
        while i < len && matches!(chars[i], '-' | '+' | ' ' | '#' | '0' | '1'..='9' | '.' | '*') {
            i += 1;
        }
        // Skip length modifier.
        if i < len && matches!(chars[i], 'h' | 'l' | 'L' | 'z' | 'j' | 't' | 'q') {
            i += 1;
            // Second modifier (e.g., `ll`, `hh`).
            if i < len && matches!(chars[i], 'h' | 'l') {
                i += 1;
            }
        }
        if i >= len {
            break;
        }
        let ch = chars[i];
        if ch == '%' {
            i += 1;
            continue; // escaped %%
        }
        let kind = match ch {
            'd' | 'i' => FmtSpecKind::SignedInt,
            'u' | 'o' | 'x' | 'X' => FmtSpecKind::UnsignedInt,
            'f' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => FmtSpecKind::Float,
            's' | 'S' => FmtSpecKind::StringPtr,
            'p' | 'P' => FmtSpecKind::Pointer,
            'c' | 'C' => FmtSpecKind::Char,
            'n' => FmtSpecKind::WriteBack,
            _ => FmtSpecKind::Other,
        };
        specs.push(FmtSpec {
            position: specs.len(),
            kind,
            ch,
        });
        i += 1;
    }

    if specs.is_empty() {
        return None;
    }

    Some(FormatStringInfo {
        string_addr,
        raw: raw.to_owned(),
        specs,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Error message detection
// ─────────────────────────────────────────────────────────────────────────────

/// An error message string linked to the functions that emit it.
#[derive(Debug, Clone)]
pub struct ErrorMessage {
    /// Address of the string.
    pub string_addr: Address,
    /// Raw string content.
    pub raw: String,
    /// Functions that reference this error string.
    pub emitter_functions: Vec<Address>,
    /// Severity heuristic based on keywords.
    pub severity: ErrorSeverity,
}

/// Heuristic severity level of an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    /// Informational / debug message.
    Info,
    /// Warning.
    Warning,
    /// Non-fatal error.
    Error,
    /// Fatal / critical.
    Critical,
}

/// Heuristically classify a string as an error message, returning its severity.
#[must_use]
pub fn classify_error_message(s: &str) -> Option<ErrorSeverity> {
    let lower = s.to_lowercase();

    // Fatal / critical keywords.
    if lower.contains("fatal")
        || lower.contains("panic")
        || lower.contains("abort")
        || lower.contains("critical")
        || lower.starts_with("unhandled")
    {
        return Some(ErrorSeverity::Critical);
    }

    // Error keywords.
    if lower.starts_with("error")
        || lower.starts_with("err:")
        || lower.starts_with("failed")
        || lower.contains("cannot")
        || lower.contains("unable to")
        || lower.contains("could not")
    {
        return Some(ErrorSeverity::Error);
    }

    // Warning keywords.
    if lower.starts_with("warn")
        || lower.starts_with("warning")
        || lower.contains("deprecated")
    {
        return Some(ErrorSeverity::Warning);
    }

    // Info keywords.
    if lower.starts_with("info")
        || lower.starts_with("debug")
        || lower.starts_with("note")
        || lower.starts_with("trace")
    {
        return Some(ErrorSeverity::Info);
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardcoded credential detection
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a potential hardcoded credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// AWS-style access key (`AKIA…`).
    AwsAccessKey,
    /// PEM private key header.
    PemPrivateKey,
    /// Base64-encoded blob of typical key size (32, 64, 128 chars decoded).
    Base64KeyBlob,
    /// `password` / `passwd` assignment pattern.
    PasswordAssignment,
    /// `Authorization: Bearer …` token.
    BearerToken,
    /// Generic high-entropy string longer than 20 characters.
    HighEntropyString,
}

/// A detected hardcoded credential.
#[derive(Debug, Clone)]
pub struct HardcodedCredential {
    /// Address of the string containing the potential credential.
    pub string_addr: Address,
    /// The raw string content.
    pub raw: String,
    /// Classification.
    pub kind: CredentialKind,
    /// Shannon entropy of the string (higher → more likely a real key).
    pub entropy: f64,
}

/// Compute the Shannon entropy (bits/symbol) of a byte slice.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// Test a string for hardcoded credentials.
#[must_use]
pub fn detect_hardcoded_credential(raw: &str, string_addr: Address) -> Option<HardcodedCredential> {
    let entropy = shannon_entropy(raw.as_bytes());

    // PEM private key header.
    if raw.starts_with("-----BEGIN") && raw.contains("PRIVATE KEY") {
        return Some(HardcodedCredential {
            string_addr,
            raw: raw.to_owned(),
            kind: CredentialKind::PemPrivateKey,
            entropy,
        });
    }

    // AWS access key prefix.
    if raw.starts_with("AKIA") && raw.len() == 20 {
        return Some(HardcodedCredential {
            string_addr,
            raw: raw.to_owned(),
            kind: CredentialKind::AwsAccessKey,
            entropy,
        });
    }

    // Bearer token.
    if raw.to_ascii_lowercase().starts_with("bearer ") && raw.len() > 20 {
        return Some(HardcodedCredential {
            string_addr,
            raw: raw.to_owned(),
            kind: CredentialKind::BearerToken,
            entropy,
        });
    }

    // Password assignment pattern.
    let lower = raw.to_lowercase();
    if (lower.starts_with("password=") || lower.starts_with("passwd=")) && raw.len() > 10 {
        return Some(HardcodedCredential {
            string_addr,
            raw: raw.to_owned(),
            kind: CredentialKind::PasswordAssignment,
            entropy,
        });
    }

    // Base64-like blob: all base64 characters, length that decodes to a key size.
    let is_base64_char = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=';
    if raw.len() >= 24 && raw.chars().all(is_base64_char) {
        let decoded_bytes = (raw.len() * 3) / 4;
        if matches!(decoded_bytes, 16 | 24 | 32 | 48 | 64) {
            return Some(HardcodedCredential {
                string_addr,
                raw: raw.to_owned(),
                kind: CredentialKind::Base64KeyBlob,
                entropy,
            });
        }
    }

    // High-entropy fallback.
    if entropy >= 4.5 && raw.len() >= 20 {
        return Some(HardcodedCredential {
            string_addr,
            raw: raw.to_owned(),
            kind: CredentialKind::HighEntropyString,
            entropy,
        });
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// StringXrefDatabase
// ─────────────────────────────────────────────────────────────────────────────

/// Central string cross-reference database.
#[derive(Debug, Default)]
pub struct StringXrefDatabase {
    /// Registered strings: address → raw content.
    pub strings: HashMap<u64, String>,
    /// String address → references from functions.
    pub refs: HashMap<u64, Vec<StringRef>>,
    /// Parsed format strings.
    pub format_strings: HashMap<u64, FormatStringInfo>,
    /// Error messages.
    pub error_messages: HashMap<u64, ErrorMessage>,
    /// Detected credentials.
    pub credentials: Vec<HardcodedCredential>,
}

impl StringXrefDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a string and run all classification passes.
    pub fn register_string(&mut self, addr: Address, raw: String) {
        let addr_u64 = addr.as_u64();

        // Format string check.
        if let Some(info) = parse_format_string(&raw, addr) {
            self.format_strings.insert(addr_u64, info);
        }

        // Error message check.
        if let Some(severity) = classify_error_message(&raw) {
            self.error_messages.insert(
                addr_u64,
                ErrorMessage {
                    string_addr: addr,
                    raw: raw.clone(),
                    emitter_functions: Vec::new(),
                    severity,
                },
            );
        }

        // Credential check.
        if let Some(cred) = detect_hardcoded_credential(&raw, addr) {
            self.credentials.push(cred);
        }

        self.strings.insert(addr_u64, raw);
    }

    /// Add a reference from a function instruction to a string.
    pub fn add_ref(&mut self, r: StringRef) {
        // Update emitter lists for error messages.
        if let Some(msg) = self.error_messages.get_mut(&r.string_addr.as_u64())
            && !msg.emitter_functions.contains(&r.function_addr)
        {
            msg.emitter_functions.push(r.function_addr);
        }
        self.refs
            .entry(r.string_addr.as_u64())
            .or_default()
            .push(r);
    }

    /// Return all references to a given string address.
    #[must_use]
    pub fn refs_to(&self, string_addr: Address) -> &[StringRef] {
        self.refs
            .get(&string_addr.as_u64())
            .map_or(&[], Vec::as_slice)
    }

    /// Return all functions that reference a given string.
    #[must_use]
    pub fn callers_of(&self, string_addr: Address) -> Vec<Address> {
        self.refs_to(string_addr)
            .iter()
            .map(|r| r.function_addr)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// Total number of registered strings.
    #[must_use]
    pub fn string_count(&self) -> usize {
        self.strings.len()
    }

    /// Total number of format strings.
    #[must_use]
    pub fn format_string_count(&self) -> usize {
        self.format_strings.len()
    }

    /// Total number of detected error messages.
    #[must_use]
    pub fn error_message_count(&self) -> usize {
        self.error_messages.len()
    }

    /// Total number of detected credentials.
    #[must_use]
    pub const fn credential_count(&self) -> usize {
        self.credentials.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // ── Format string ─────────────────────────────────────────────────────────

    #[test]
    fn parse_format_string_basic() {
        let info = parse_format_string("Hello %s, you are %d years old", addr(0x1000));
        let info = info.unwrap();
        assert_eq!(info.specs.len(), 2);
        assert_eq!(info.specs[0].kind, FmtSpecKind::StringPtr);
        assert_eq!(info.specs[1].kind, FmtSpecKind::SignedInt);
    }

    #[test]
    fn parse_format_string_no_specs_returns_none() {
        assert!(parse_format_string("no format specifiers here", addr(0x2000)).is_none());
    }

    #[test]
    fn parse_format_string_escaped_percent() {
        let info = parse_format_string("100%% complete", addr(0x3000));
        assert!(info.is_none(), "escaped %% should not count as a specifier");
    }

    #[test]
    fn parse_format_string_write_back_detected() {
        let info = parse_format_string("%n", addr(0x4000)).unwrap();
        assert!(info.has_write_back());
    }

    // ── Error message ─────────────────────────────────────────────────────────

    #[test]
    fn error_message_critical() {
        assert_eq!(
            classify_error_message("FATAL: out of memory"),
            Some(ErrorSeverity::Critical)
        );
    }

    #[test]
    fn error_message_error() {
        assert_eq!(
            classify_error_message("Error: file not found"),
            Some(ErrorSeverity::Error)
        );
    }

    #[test]
    fn error_message_warning() {
        assert_eq!(
            classify_error_message("Warning: deprecated API"),
            Some(ErrorSeverity::Warning)
        );
    }

    #[test]
    fn error_message_none() {
        assert_eq!(classify_error_message("Hello, world!"), None);
    }

    // ── Credential detection ──────────────────────────────────────────────────

    #[test]
    fn pem_key_detected() {
        let cred = detect_hardcoded_credential(
            "-----BEGIN RSA PRIVATE KEY-----",
            addr(0x5000),
        );
        assert!(cred.is_some());
        assert_eq!(cred.unwrap().kind, CredentialKind::PemPrivateKey);
    }

    #[test]
    fn aws_key_detected() {
        let cred = detect_hardcoded_credential("AKIAIOSFODNN7EXAMPLE", addr(0x6000));
        assert!(cred.is_some());
        assert_eq!(cred.unwrap().kind, CredentialKind::AwsAccessKey);
    }

    #[test]
    fn password_assignment_detected() {
        let cred = detect_hardcoded_credential("password=s3cr3t!2024", addr(0x7000));
        assert!(cred.is_some());
        assert_eq!(cred.unwrap().kind, CredentialKind::PasswordAssignment);
    }

    #[test]
    fn high_entropy_string_detected() {
        // 24+ chars of high-entropy data.
        let cred = detect_hardcoded_credential("xK9#mP2!qR7@nL4$vJ8^wB5%", addr(0x8000));
        assert!(cred.is_some());
    }

    // ── Shannon entropy ───────────────────────────────────────────────────────

    #[test]
    fn entropy_all_same_bytes_is_zero() {
        let data = vec![0xAA; 100];
        let e = shannon_entropy(&data);
        assert!(e < 1e-9, "uniform data should have entropy ~0");
    }

    #[test]
    fn entropy_uniform_distribution() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        // 256 equally likely symbols → entropy = 8 bits
        assert!((e - 8.0).abs() < 0.01, "expected entropy ~8, got {e}");
    }

    // ── StringXrefDatabase ────────────────────────────────────────────────────

    #[test]
    fn database_register_and_ref() {
        let mut db = StringXrefDatabase::new();
        db.register_string(addr(0xA000), "Error: connection refused".into());
        db.add_ref(StringRef {
            insn_addr: addr(0x1005),
            function_addr: addr(0x1000),
            string_addr: addr(0xA000),
        });

        assert_eq!(db.string_count(), 1);
        assert_eq!(db.error_message_count(), 1);
        let refs = db.refs_to(addr(0xA000));
        assert_eq!(refs.len(), 1);

        // Error message should list the emitter function.
        let msg = db.error_messages.get(&0xA000).unwrap();
        assert!(msg.emitter_functions.contains(&addr(0x1000)));
    }

    #[test]
    fn database_format_string_registered() {
        let mut db = StringXrefDatabase::new();
        db.register_string(addr(0xB000), "value = %d\n".into());
        assert_eq!(db.format_string_count(), 1);
    }

    #[test]
    fn callers_of_deduplication() {
        let mut db = StringXrefDatabase::new();
        db.register_string(addr(0xC000), "some string".into());

        // Same function references the string twice.
        for insn in [0x100, 0x110] {
            db.add_ref(StringRef {
                insn_addr: addr(insn),
                function_addr: addr(0x1000),
                string_addr: addr(0xC000),
            });
        }

        let callers = db.callers_of(addr(0xC000));
        assert_eq!(callers.len(), 1);
    }
}
