//! `rustre-analysis-string`
//!
//! String detection and encoding analysis.
//! Finds ASCII, UTF-8, UTF-16 LE/BE, UTF-32 LE/BE, Latin-1, and Shift-JIS
//! strings inside raw binary slices, and stores them in a queryable database.
//!
//! Additional modules:
//! * [`classify`] — URL/IP/email/format-string/crypto/obfuscation detection.
//! * [`similarity`] — edit distance, Jaro-Winkler, clustering, templates.

pub mod classify;
pub mod decompiler_literal;
pub mod decrypt;
pub mod patterns;
pub mod encoded_string_decoder;
pub mod encoding_detect;
pub mod similarity;
pub mod stackstring;
pub mod string_deobfuscator;
pub mod string_recovery;
pub mod string_xref;
pub use string_xref::{StringRecord, StringXref, string_xrefs};
pub mod unicode_detector;
pub mod string_clusterer;
pub mod string_decoder;
pub mod string_pattern_library;
pub mod string_classifier;
pub mod string_obf_detector;
pub mod string_context_extractor;

pub use stackstring::{
    StackStore, StackString, StackStringConfig, StringRef, link_string_xrefs, most_referenced,
    reconstruct_stack_strings, reconstruct_stack_strings_from_llil,
};

pub use encoding_detect::{
    ByteFrequency, DetectedEncoding, EncodingDetector, EncodingDetectorConfig, EncodingKind,
    XorKeyCandidate, auto_decode, base64_decode, detect_base64, detect_hex_encoded, detect_rot_n,
    detect_rot13, detect_xor_single_byte, encoding_summary, estimate_xor_key_length, hex_decode,
    recover_xor_multibyte_key, rot_byte, rot_decode, rot13_decode, xor_decode_multibyte,
    xor_decode_single, xor_key_candidates,
};

pub use decrypt::{
    BulkDecryptor, DecryptionAlgorithm, DecryptionResult, KeyExtractInstr, StringDecryptionConfig,
    StubInstr, StubPattern, auto_decrypt, decrypt_base64, decrypt_hex, decrypt_rot_n,
    decrypt_string_blobs, decrypt_xor_byte, decrypt_xor_key, detected_to_result,
    extract_multibyte_key_from_instrs, extract_xor_key_from_instrs, group_by_algorithm,
    identify_stub_pattern,
};

pub use classify::{
    CryptoConstant, DetectedFormatString, ExtractedEmail, ExtractedIp, ExtractedUrl,
    ObfuscationSignal, StringClass, StringClassifier, detect_crypto_constant, detect_format_string,
    detect_obfuscation, extract_crypto_constants, extract_emails, extract_format_strings,
    extract_ips, extract_obfuscated, extract_urls, is_private_ipv4, looks_like_base64,
    looks_like_hex, parse_ipv4, shannon_entropy,
};
pub use similarity::{
    StringCluster, cluster_strings, extract_template, jaccard_ngram, jaro, jaro_winkler,
    lcs_length, lcs_similarity, levenshtein, levenshtein_similarity, ngrams,
};

use ahash::AHashMap;
use rustre_core::address::{Address, AddressRange};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// StringEncoding
// ---------------------------------------------------------------------------

/// The text encoding of a found string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    /// Windows wide strings (LE).
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
    /// ISO-8859-1
    Latin1,
    ShiftJis,
}

impl fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8",
            Self::Utf16Le => "UTF-16 LE",
            Self::Utf16Be => "UTF-16 BE",
            Self::Utf32Le => "UTF-32 LE",
            Self::Utf32Be => "UTF-32 BE",
            Self::Latin1 => "Latin-1",
            Self::ShiftJis => "Shift-JIS",
        };
        f.write_str(s)
    }
}

impl StringEncoding {
    /// Minimum bytes per code unit for this encoding.
    #[must_use]
    pub const fn min_char_bytes(&self) -> usize {
        match self {
            Self::Ascii | Self::Utf8 | Self::Latin1 | Self::ShiftJis => 1,
            Self::Utf16Le | Self::Utf16Be => 2,
            Self::Utf32Le | Self::Utf32Be => 4,
        }
    }

    /// Whether this encoding is Unicode.
    #[must_use]
    pub const fn is_unicode(&self) -> bool {
        matches!(
            self,
            Self::Utf8 | Self::Utf16Le | Self::Utf16Be | Self::Utf32Le | Self::Utf32Be
        )
    }
}

// ---------------------------------------------------------------------------
// FoundString
// ---------------------------------------------------------------------------

/// A string found in a binary.
#[derive(Debug, Clone)]
pub struct FoundString {
    /// Virtual address where the string starts.
    pub address: Address,
    /// Byte length in memory.
    pub length: usize,
    pub encoding: StringEncoding,
    /// Decoded Rust `String`.
    pub value: String,
    /// Number of Unicode code points.
    pub char_count: usize,
    pub is_null_terminated: bool,
    /// How many code xrefs point here (filled by the caller later).
    pub xref_count: usize,
}

impl fmt::Display for FoundString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] {:?}", self.address, self.encoding, self.value)
    }
}

impl FoundString {
    /// Whether all characters in the value are printable (no control chars).
    #[must_use]
    pub fn is_printable(&self) -> bool {
        self.value.chars().all(|c| !c.is_control())
    }

    /// Heuristic: looks like a file-system path.
    #[must_use]
    pub fn looks_like_path(&self) -> bool {
        let v = &self.value;
        // Windows absolute or relative path
        (v.len() >= 3
            && v.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && v.starts_with(|c: char| c.is_ascii_alphabetic())
            && (v.as_bytes().get(1) == Some(&b':') || v.contains('\\')))
            || v.starts_with('/')
            || v.starts_with("./")
            || v.starts_with("../")
    }

    /// Heuristic: looks like a URL.
    #[must_use]
    pub fn looks_like_url(&self) -> bool {
        let v = self.value.to_ascii_lowercase();
        v.starts_with("http://")
            || v.starts_with("https://")
            || v.starts_with("ftp://")
            || v.starts_with("file://")
    }

    /// Heuristic: contains a printf-style format specifier.
    #[must_use]
    pub fn looks_like_format_string(&self) -> bool {
        let v = &self.value;
        let specifiers = [
            "%s", "%d", "%i", "%u", "%x", "%X", "%f", "%p", "%c", "%o", "%e",
        ];
        specifiers.iter().any(|s| v.contains(s))
    }

    /// Heuristic: looks like a Windows registry key.
    #[must_use]
    pub fn looks_like_registry_key(&self) -> bool {
        let v = &self.value;
        v.starts_with("HKEY_")
            || v.starts_with("HKLM\\")
            || v.starts_with("HKCU\\")
            || v.starts_with("Software\\")
            || v.starts_with("SOFTWARE\\")
            || v.starts_with("SYSTEM\\")
    }

    /// Shannon entropy of the string bytes (based on the raw UTF-8 encoding of `value`).
    #[must_use]
    pub fn entropy(&self) -> f64 {
        let bytes = self.value.as_bytes();
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let n = f64::from(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        counts.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
            let p = f64::from(c) / n;
            p.mul_add(-p.log2(), acc)
        })
    }

    /// Returns `true` if this string is considered interesting for analysis.
    ///
    /// A string is interesting when its character count exceeds 8 **and** its
    /// [`StringClass`] is not [`StringClass::Generic`], or when it is flagged
    /// as suspicious by [`StringClassifier::is_suspicious`].
    #[must_use]
    pub fn is_interesting(&self) -> bool {
        use crate::classify::{StringClass, StringClassifier};
        if StringClassifier::is_suspicious(&self.value) {
            return true;
        }
        self.char_count > 8 && StringClassifier::classify(&self.value) != StringClass::Generic
    }
}

// ---------------------------------------------------------------------------
// StringScannerConfig
// ---------------------------------------------------------------------------

/// Configuration for the [`StringScanner`].
#[derive(Debug, Clone)]
pub struct StringScannerConfig {
    pub min_length: usize,
    pub max_length: usize,
    pub encodings: Vec<StringEncoding>,
    pub require_null_terminator: bool,
    pub allow_high_ascii: bool,
    pub skip_ranges: Vec<AddressRange>,
}

impl Default for StringScannerConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: 4096,
            encodings: vec![
                StringEncoding::Ascii,
                StringEncoding::Utf16Le,
                StringEncoding::Utf8,
            ],
            require_null_terminator: true,
            allow_high_ascii: false,
            skip_ranges: Vec::new(),
        }
    }
}

impl StringScannerConfig {
    /// Config that scans for all supported encodings.
    #[must_use]
    pub fn all_encodings() -> Self {
        Self {
            encodings: vec![
                StringEncoding::Ascii,
                StringEncoding::Utf8,
                StringEncoding::Utf16Le,
                StringEncoding::Utf16Be,
                StringEncoding::Utf32Le,
                StringEncoding::Utf32Be,
                StringEncoding::Latin1,
                StringEncoding::ShiftJis,
            ],
            ..Self::default()
        }
    }

    /// Fast config: ASCII only, min 4 chars.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            encodings: vec![StringEncoding::Ascii],
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// StringScanner
// ---------------------------------------------------------------------------

/// Scans byte slices for human-readable strings in various encodings.
pub struct StringScanner {
    pub config: StringScannerConfig,
}

impl Default for StringScanner {
    fn default() -> Self {
        Self::new(StringScannerConfig::default())
    }
}

impl StringScanner {
    /// Create a scanner with the given configuration.
    #[must_use]
    pub const fn new(config: StringScannerConfig) -> Self {
        Self { config }
    }

    /// Scan `bytes` (loaded at `base`) for strings in all configured encodings.
    #[must_use]
    pub fn scan(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        let mut results: Vec<FoundString> = Vec::new();
        for enc in &self.config.encodings {
            let found = match enc {
                StringEncoding::Ascii => self.scan_ascii(base, bytes),
                StringEncoding::Utf8 => self.scan_utf8(base, bytes),
                StringEncoding::Utf16Le => self.scan_utf16_le(base, bytes),
                StringEncoding::Utf16Be => self.scan_utf16_be(base, bytes),
                StringEncoding::Utf32Le => self.scan_utf32_le(base, bytes),
                StringEncoding::Utf32Be => self.scan_utf32_be(base, bytes),
                StringEncoding::Latin1 => self.scan_latin1(base, bytes),
                StringEncoding::ShiftJis => self.scan_shiftjis(base, bytes),
            };
            results.extend(found);
        }
        results.sort_unstable_by_key(|s| s.address.0);
        results
    }

    /// Scan for null-terminated ASCII strings.
    #[must_use]
    pub fn scan_ascii(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        let mut results = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            let start = i;
            while i < bytes.len()
                && Self::is_printable_ascii_cfg(bytes[i], self.config.allow_high_ascii)
            {
                i += 1;
            }
            let end = i;
            let null_terminated = i < bytes.len() && bytes[i] == 0;
            if null_terminated || !self.config.require_null_terminator {
                let len = end - start;
                if len >= self.config.min_length && len <= self.config.max_length {
                    // With `allow_high_ascii`, bytes 0x80..=0xFF are accepted as
                    // part of the run.  `from_utf8_lossy` would collapse every
                    // one of them into the same U+FFFD replacement char, so the
                    // reported `value` would no longer correspond to the bytes
                    // actually at `address` (and `char_count` would be wrong).
                    // Decode them as Latin-1 instead — the same convention
                    // `scan_latin1` already uses — which is byte-recoverable.
                    let run = &bytes[start..end];
                    let value = if self.config.allow_high_ascii {
                        run.iter().map(|&b| b as char).collect::<String>()
                    } else {
                        String::from_utf8_lossy(run).into_owned()
                    };
                    let char_count = value.chars().count();
                    results.push(FoundString {
                        address: base + start as u64,
                        length: len + usize::from(null_terminated),
                        encoding: StringEncoding::Ascii,
                        char_count,
                        value,
                        is_null_terminated: null_terminated,
                        xref_count: 0,
                    });
                }
            }
            if i < bytes.len() {
                i += 1; // skip NUL or non-printable
            }
        }
        results
    }

    /// Scan for null-terminated UTF-16 LE strings.
    #[must_use]
    pub fn scan_utf16_le(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        self.scan_utf16(base, bytes, false)
    }

    /// Scan for null-terminated UTF-8 strings.
    #[must_use]
    pub fn scan_utf8(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        let mut results = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            if !Self::is_valid_utf8_start(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            let mut raw: Vec<u8> = Vec::new();
            while i < bytes.len() {
                let b = bytes[i];
                if b == 0 {
                    break;
                }
                // Count expected continuation bytes
                let seq_len = if b < 0x80 {
                    if Self::is_printable_ascii(b) {
                        1
                    } else {
                        break;
                    }
                } else if (0xC2..=0xDF).contains(&b) {
                    2
                } else if (0xE0..=0xEF).contains(&b) {
                    3
                } else if (0xF0..=0xF4).contains(&b) {
                    4
                } else {
                    break;
                };
                if i + seq_len > bytes.len() {
                    break;
                }
                // Verify continuation bytes
                let valid = (1..seq_len).all(|k| (bytes[i + k] & 0xC0) == 0x80);
                if !valid {
                    break;
                }
                raw.extend_from_slice(&bytes[i..i + seq_len]);
                i += seq_len;
            }
            let null_terminated = i < bytes.len() && bytes[i] == 0;
            if null_terminated || !self.config.require_null_terminator {
                let byte_len = raw.len();
                if byte_len >= self.config.min_length
                    && byte_len <= self.config.max_length
                    && let Ok(value) = String::from_utf8(raw)
                {
                    let char_count = value.chars().count();
                    if char_count >= self.config.min_length {
                        results.push(FoundString {
                            address: base + start as u64,
                            length: byte_len + usize::from(null_terminated),
                            encoding: StringEncoding::Utf8,
                            char_count,
                            value,
                            is_null_terminated: null_terminated,
                            xref_count: 0,
                        });
                    }
                }
            }
            if i < bytes.len() {
                i += 1;
            }
        }
        results
    }

    /// Scan for a C string at a specific address within `bytes`.
    #[must_use]
    pub fn read_cstring(&self, base: Address, bytes: &[u8], addr: Address) -> Option<FoundString> {
        if addr.0 < base.0 {
            return None;
        }
        let offset = usize::try_from(addr.0 - base.0).ok()?;
        if offset >= bytes.len() {
            return None;
        }
        let slice = &bytes[offset..];
        let end = slice.iter().position(|&b| b == 0)?;
        if end < self.config.min_length {
            return None;
        }
        let value = String::from_utf8_lossy(&slice[..end]).into_owned();
        let char_count = value.chars().count();
        Some(FoundString {
            address: addr,
            length: end + 1,
            encoding: StringEncoding::Ascii,
            char_count,
            value,
            is_null_terminated: true,
            xref_count: 0,
        })
    }

    /// Scan for Pascal-style length-prefixed strings (1-byte length prefix).
    #[must_use]
    pub fn scan_pascal_strings(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        let mut results = Vec::new();
        let mut i = 0usize;
        while i + 1 < bytes.len() {
            let len = bytes[i] as usize;
            if len >= self.config.min_length && i + 1 + len <= bytes.len() {
                let slice = &bytes[i + 1..i + 1 + len];
                if slice.iter().all(|&b| Self::is_printable_ascii(b)) {
                    let value = String::from_utf8_lossy(slice).into_owned();
                    let char_count = value.chars().count();
                    results.push(FoundString {
                        address: base + i as u64,
                        length: 1 + len,
                        encoding: StringEncoding::Ascii,
                        char_count,
                        value,
                        is_null_terminated: false,
                        xref_count: 0,
                    });
                    i += 1 + len;
                    continue;
                }
            }
            i += 1;
        }
        results
    }

    fn is_printable_ascii(b: u8) -> bool {
        (0x20..0x7F).contains(&b)
    }

    fn is_printable_ascii_cfg(b: u8, allow_high: bool) -> bool {
        (0x20..0x7F).contains(&b) || (allow_high && b >= 0x80)
    }

    fn is_valid_utf8_start(b: u8) -> bool {
        // Valid leading byte or plain ASCII printable
        (0x20..0x7F).contains(&b) || (0xC2..=0xF4).contains(&b)
    }

    // -----------------------------------------------------------------------
    // Private helpers for additional encodings
    // -----------------------------------------------------------------------

    fn scan_utf16(&self, base: Address, bytes: &[u8], big_endian: bool) -> Vec<FoundString> {
        let enc = if big_endian {
            StringEncoding::Utf16Be
        } else {
            StringEncoding::Utf16Le
        };
        let mut results = Vec::new();
        if bytes.len() < 2 {
            return results;
        }
        let mut i = 0usize;
        // Align to 2 bytes
        while i + 1 < bytes.len() {
            let start = i;
            let mut units: Vec<u16> = Vec::new();
            while i + 1 < bytes.len() {
                let unit = if big_endian {
                    u16::from_be_bytes([bytes[i], bytes[i + 1]])
                } else {
                    u16::from_le_bytes([bytes[i], bytes[i + 1]])
                };
                if unit == 0 {
                    break;
                }
                // Accept printable BMP characters
                if let Some(c) = char::from_u32(u32::from(unit)) {
                    if c.is_control() && c != '\t' {
                        break;
                    }
                } else {
                    break;
                }
                units.push(unit);
                i += 2;
            }
            let null_terminated = i + 1 < bytes.len() && bytes[i] == 0 && bytes[i + 1] == 0;
            let char_count = units.len();
            if (null_terminated || !self.config.require_null_terminator)
                && char_count >= self.config.min_length
                && char_count <= self.config.max_length
                && let Ok(value) = String::from_utf16(&units) {
                    let byte_length = char_count * 2 + if null_terminated { 2 } else { 0 };
                    results.push(FoundString {
                        address: base + start as u64,
                        length: byte_length,
                        encoding: enc,
                        char_count,
                        value,
                        is_null_terminated: null_terminated,
                        xref_count: 0,
                    });
                }
            if i + 1 < bytes.len() {
                i += 2; // skip NUL pair or invalid byte
            } else {
                break;
            }
        }
        results
    }

    fn scan_utf32(&self, base: Address, bytes: &[u8], big_endian: bool) -> Vec<FoundString> {
        let enc = if big_endian {
            StringEncoding::Utf32Be
        } else {
            StringEncoding::Utf32Le
        };
        let mut results = Vec::new();
        if bytes.len() < 4 {
            return results;
        }
        let mut i = 0usize;
        while i + 3 < bytes.len() {
            let start = i;
            let mut chars: Vec<char> = Vec::new();
            while i + 3 < bytes.len() {
                let unit = if big_endian {
                    u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                } else {
                    u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                };
                if unit == 0 {
                    break;
                }
                if let Some(c) = char::from_u32(unit) {
                    if c.is_control() && c != '\t' {
                        break;
                    }
                    chars.push(c);
                } else {
                    break;
                }
                i += 4;
            }
            let null_terminated = i + 3 < bytes.len()
                && bytes[i] == 0
                && bytes[i + 1] == 0
                && bytes[i + 2] == 0
                && bytes[i + 3] == 0;
            let char_count = chars.len();
            if (null_terminated || !self.config.require_null_terminator)
                && char_count >= self.config.min_length
                && char_count <= self.config.max_length
            {
                let value: String = chars.iter().collect();
                let byte_length = char_count * 4 + if null_terminated { 4 } else { 0 };
                results.push(FoundString {
                    address: base + start as u64,
                    length: byte_length,
                    encoding: enc,
                    char_count,
                    value,
                    is_null_terminated: null_terminated,
                    xref_count: 0,
                });
            }
            if i + 3 < bytes.len() {
                i += 4;
            } else {
                break;
            }
        }
        results
    }

    fn scan_utf16_be(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        self.scan_utf16(base, bytes, true)
    }

    fn scan_utf32_le(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        self.scan_utf32(base, bytes, false)
    }

    fn scan_utf32_be(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        self.scan_utf32(base, bytes, true)
    }

    fn scan_latin1(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        // Latin-1: printable range 0x20-0x7E and 0xA0-0xFF
        let mut results = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            let start = i;
            let mut raw: Vec<u8> = Vec::new();
            while i < bytes.len() {
                let b = bytes[i];
                if b == 0 {
                    break;
                }
                if (0x20..0x7F).contains(&b) || b >= 0xA0 {
                    raw.push(b);
                    i += 1;
                } else {
                    break;
                }
            }
            let null_terminated = i < bytes.len() && bytes[i] == 0;
            let len = raw.len();
            if (null_terminated || !self.config.require_null_terminator)
                && len >= self.config.min_length
                && len <= self.config.max_length
            {
                // Convert Latin-1 to Unicode
                let value: String = raw.iter().map(|&b| b as char).collect();
                results.push(FoundString {
                    address: base + start as u64,
                    length: len + usize::from(null_terminated),
                    encoding: StringEncoding::Latin1,
                    char_count: len,
                    value,
                    is_null_terminated: null_terminated,
                    xref_count: 0,
                });
            }
            if i < bytes.len() {
                i += 1;
            }
        }
        results
    }

    fn scan_shiftjis(&self, base: Address, bytes: &[u8]) -> Vec<FoundString> {
        // Heuristic: treat single-byte Shift-JIS (0x20-0x7E, 0xA1-0xDF) as printable.
        // Full decoding would require a lookup table; this is a reasonable approximation.
        let mut results = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            let start = i;
            let mut raw: Vec<u8> = Vec::new();
            while i < bytes.len() {
                let b = bytes[i];
                if b == 0 {
                    break;
                }
                if (0x20..0x7F).contains(&b) || (0xA1..=0xDF).contains(&b) {
                    raw.push(b);
                    i += 1;
                } else if (0x81..=0x9F).contains(&b) || (0xE0..=0xFC).contains(&b) {
                    // Two-byte Shift-JIS sequence
                    if i + 1 < bytes.len() {
                        let b2 = bytes[i + 1];
                        if (0x40..=0x7E).contains(&b2) || (0x80..=0xFC).contains(&b2) {
                            raw.push(b);
                            raw.push(b2);
                            i += 2;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            let null_terminated = i < bytes.len() && bytes[i] == 0;
            let len = raw.len();
            if (null_terminated || !self.config.require_null_terminator)
                && len >= self.config.min_length
                && len <= self.config.max_length
            {
                let value = String::from_utf8_lossy(&raw).into_owned();
                results.push(FoundString {
                    address: base + start as u64,
                    length: len + usize::from(null_terminated),
                    encoding: StringEncoding::ShiftJis,
                    char_count: value.chars().count(),
                    value,
                    is_null_terminated: null_terminated,
                    xref_count: 0,
                });
            }
            if i < bytes.len() {
                i += 1;
            }
        }
        results
    }
}

// ---------------------------------------------------------------------------
// StringDatabase
// ---------------------------------------------------------------------------

/// A queryable collection of found strings.
pub struct StringDatabase {
    pub strings: Vec<FoundString>,
    // Keyed on virtual addresses from binary input — AHashMap prevents
    // hash-collision DoS if an attacker can influence the address layout
    // (dos-hash-collision).
    by_address: AHashMap<u64, usize>,
}

impl Default for StringDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl StringDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            by_address: AHashMap::new(),
        }
    }

    /// Scan `bytes` at `base` using `config` and build a database.
    #[must_use]
    pub fn from_scan(base: Address, bytes: &[u8], config: StringScannerConfig) -> Self {
        let scanner = StringScanner::new(config);
        let found = scanner.scan(base, bytes);
        let mut db = Self::new();
        for s in found {
            db.add(s);
        }
        db
    }

    /// Insert a [`FoundString`] into the database.
    ///
    /// If a string with the same start address is already present, the new entry
    /// is silently dropped so that `count()` and `at()` remain consistent.
    pub fn add(&mut self, s: FoundString) {
        let addr = s.address.0;
        // Use `entry` to check atomically: only push when the address is new.
        let entry = self.by_address.entry(addr);
        if let std::collections::hash_map::Entry::Vacant(v) = entry {
            let idx = self.strings.len();
            self.strings.push(s);
            v.insert(idx);
        }
        // If already present (Occupied), skip the push so count() == reachable via at().
    }

    /// Look up a string by its start address.
    #[must_use]
    pub fn at(&self, addr: Address) -> Option<&FoundString> {
        self.by_address.get(&addr.0).map(|&idx| &self.strings[idx])
    }

    /// Iterate over all stored strings.
    pub fn iter(&self) -> impl Iterator<Item = &FoundString> {
        self.strings.iter()
    }

    /// Total number of strings stored.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.strings.len()
    }

    /// All strings with the given encoding.
    #[must_use]
    pub fn filter_by_encoding(&self, enc: &StringEncoding) -> Vec<&FoundString> {
        self.strings.iter().filter(|s| &s.encoding == enc).collect()
    }

    /// Strings that are "interesting": paths, URLs, format strings, or registry keys.
    #[must_use]
    pub fn interesting_strings(&self) -> Vec<&FoundString> {
        self.strings
            .iter()
            .filter(|s| {
                s.looks_like_path()
                    || s.looks_like_url()
                    || s.looks_like_format_string()
                    || s.looks_like_registry_key()
            })
            .collect()
    }

    /// The `n` longest strings.
    #[must_use]
    pub fn longest(&self, n: usize) -> Vec<&FoundString> {
        let mut sorted: Vec<&FoundString> = self.strings.iter().collect();
        sorted.sort_unstable_by(|a, b| b.length.cmp(&a.length));
        sorted.truncate(n);
        sorted
    }

    /// Case-insensitive substring search over string values.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&FoundString> {
        let lower_q = query.to_ascii_lowercase();
        self.strings
            .iter()
            .filter(|s| s.value.to_ascii_lowercase().contains(&lower_q))
            .collect()
    }

    /// Compute aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> StringStats {
        let total = self.strings.len();
        let mut by_encoding: HashMap<String, usize> = HashMap::new();
        let mut max_length = 0usize;
        let mut total_length = 0usize;
        let mut format_string_count = 0usize;
        let mut url_count = 0usize;
        let mut path_count = 0usize;
        let mut interesting_count = 0usize;

        for s in &self.strings {
            *by_encoding.entry(s.encoding.to_string()).or_insert(0) += 1;
            total_length += s.length;
            if s.length > max_length {
                max_length = s.length;
            }
            let is_fmt = s.looks_like_format_string();
            let is_url = s.looks_like_url();
            let is_path = s.looks_like_path();
            let is_reg = s.looks_like_registry_key();
            if is_fmt {
                format_string_count += 1;
            }
            if is_url {
                url_count += 1;
            }
            if is_path {
                path_count += 1;
            }
            if is_fmt || is_url || is_path || is_reg {
                interesting_count += 1;
            }
        }

        let avg_length = if total > 0 {
            f64::from(u32::try_from(total_length).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        } else {
            0.0
        };

        // Delegate to StringStats::compute which correctly distinguishes
        // classified_count (non-Generic class) from interesting_count.
        let _ = (total, by_encoding, avg_length, max_length, interesting_count,
                 format_string_count, url_count, path_count);
        StringStats::compute(&self.strings)
    }
}

// ---------------------------------------------------------------------------
// StringStats
// ---------------------------------------------------------------------------

/// Aggregate statistics over a [`StringDatabase`].
pub struct StringStats {
    pub total: usize,
    pub by_encoding: HashMap<String, usize>,
    pub avg_length: f64,
    pub max_length: usize,
    pub interesting_count: usize,
    pub format_string_count: usize,
    pub url_count: usize,
    pub path_count: usize,
    /// Count of strings whose [`crate::classify::StringClass`] is not `Generic`.
    pub classified_count: usize,
    /// The longest string value found (or empty if none).
    pub longest: String,
    /// The shortest interesting string value found (or empty if none).
    pub shortest_interesting: String,
}

impl StringStats {
    /// Compute statistics from a slice of [`FoundString`]s.
    ///
    /// This is a standalone constructor that does not require a [`StringDatabase`].
    #[must_use]
    pub fn compute(strings: &[FoundString]) -> Self {
        use crate::classify::{StringClass, StringClassifier};

        let total = strings.len();
        let mut by_encoding: HashMap<String, usize> = HashMap::new();
        let mut max_length = 0usize;
        let mut total_length = 0usize;
        let mut format_string_count = 0usize;
        let mut url_count = 0usize;
        let mut path_count = 0usize;
        let mut interesting_count = 0usize;
        let mut classified_count = 0usize;
        let mut longest_val = String::new();
        let mut shortest_interesting: Option<String> = None;

        for s in strings {
            *by_encoding.entry(s.encoding.to_string()).or_insert(0) += 1;
            total_length += s.length;

            if s.length > max_length {
                max_length = s.length;
                longest_val.clone_from(&s.value);
            }

            let is_fmt = s.looks_like_format_string();
            let is_url = s.looks_like_url();
            let is_path = s.looks_like_path();
            let is_reg = s.looks_like_registry_key();
            if is_fmt {
                format_string_count += 1;
            }
            if is_url {
                url_count += 1;
            }
            if is_path {
                path_count += 1;
            }
            if is_fmt || is_url || is_path || is_reg {
                interesting_count += 1;
            }

            let class = StringClassifier::classify(&s.value);
            if class != StringClass::Generic {
                classified_count += 1;
            }

            if s.is_interesting() {
                match &shortest_interesting {
                    None => shortest_interesting = Some(s.value.clone()),
                    Some(prev) if s.char_count < prev.chars().count() => {
                        shortest_interesting = Some(s.value.clone());
                    }
                    _ => {}
                }
            }
        }

        let avg_length = if total > 0 {
            f64::from(u32::try_from(total_length).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        } else {
            0.0
        };

        Self {
            total,
            by_encoding,
            avg_length,
            max_length,
            interesting_count,
            format_string_count,
            url_count,
            path_count,
            classified_count,
            longest: longest_val,
            shortest_interesting: shortest_interesting.unwrap_or_default(),
        }
    }
}

// ---------------------------------------------------------------------------
// XOR key detection
// ---------------------------------------------------------------------------

/// Detect a single-byte XOR key used to encode a buffer.
///
/// Uses a frequency analysis against the expected ASCII printable range:
/// the key that would produce the most printable bytes (0x20–0x7E) when
/// XOR-applied to every byte wins.  Returns `None` when no key produces a
/// majority of printable output.
///
/// The function also biases toward keys that decode the buffer to valid
/// null-terminated strings (common in malware XOR obfuscation).
#[must_use]
pub fn detect_xor_key(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }

    // Score each candidate key 0x01..=0xFF (skip 0x00, identity).
    let mut best_key = 0u8;
    let mut best_score = 0usize;

    for key in 1u8..=255 {
        // Count bytes that would be printable ASCII after XOR.
        let printable = data
            .iter()
            .filter(|&&b| {
                let decoded = b ^ key;
                (0x20..=0x7E).contains(&decoded)
            })
            .count();

        // Small bonus for producing a NUL terminator (common in C strings).
        let has_nul_term = data.iter().any(|&b| b ^ key == 0x00);
        let nul_bonus = if has_nul_term { data.len() / 10 } else { 0 };

        // Use the NUL bonus only as a tiebreaker, not to inflate the primary score.
        // Compare candidates: prefer more printable bytes, break ties with NUL bonus.
        if printable > best_score || (printable == best_score && nul_bonus > 0) {
            best_score = printable;
            best_key = key;
        }
    }

    // Require that more than 70% of the bytes are printable when decoded.
    // Only the raw printable count is compared against the threshold (not the NUL bonus).
    let threshold = (data.len() * 7) / 10;
    if best_score >= threshold {
        Some(best_key)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// StringRecoveryPass
// ---------------------------------------------------------------------------

use rustre_analysis::{AnalysisConfig, AnalysisError, AnalysisKind, AnalysisPass, AnalysisResult};

/// An [`AnalysisPass`] that scans all memory segments for ASCII, UTF-8, and
/// UTF-16 LE strings and returns the total count in
/// [`AnalysisResult::strings_found`].
pub struct StringRecoveryPass {
    config: StringScannerConfig,
}

impl StringRecoveryPass {
    /// Create a `StringRecoveryPass` with default scanner settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: StringScannerConfig::default(),
        }
    }

    /// Create a `StringRecoveryPass` with custom scanner settings.
    #[must_use]
    pub const fn with_config(config: StringScannerConfig) -> Self {
        Self { config }
    }
}

impl Default for StringRecoveryPass {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for StringRecoveryPass {
    fn name(&self) -> &'static str {
        "string_recovery"
    }

    fn kind(&self) -> AnalysisKind {
        AnalysisKind::StringRecovery
    }

    fn description(&self) -> &'static str {
        "Scans memory segments for ASCII, UTF-8, and UTF-16 LE strings"
    }

    async fn run(
        &self,
        view: &rustre_core::binary_view::BinaryView,
        _config: &AnalysisConfig,
    ) -> Result<AnalysisResult, AnalysisError> {
        let start = std::time::Instant::now();
        let scanner = StringScanner::new(self.config.clone());

        let strings_found: usize = {
            let mem = view.mem.read();
            mem.segments
                .iter()
                .map(|seg| scanner.scan(seg.range.start, &seg.data).len())
                .sum()
        };

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        Ok(AnalysisResult {
            kind: AnalysisKind::StringRecovery,
            functions_found: 0,
            data_refs_found: 0,
            strings_found,
            duration_ms,
            warnings: Vec::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    // 1. scan_ascii on known bytes
    #[test]
    fn test_scan_ascii_basic() {
        let config = StringScannerConfig::fast();
        let scanner = StringScanner::new(config);
        let data = b"hello\0world\0";
        let found = scanner.scan_ascii(addr(0x1000), data);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].value, "hello");
        assert_eq!(found[0].address, addr(0x1000));
        assert!(found[0].is_null_terminated);
        assert_eq!(found[1].value, "world");
        assert_eq!(found[1].address, addr(0x1006));
    }

    // 2. scan_ascii skips short strings
    #[test]
    fn test_scan_ascii_min_length() {
        let mut config = StringScannerConfig::fast();
        config.min_length = 5;
        let scanner = StringScanner::new(config);
        let data = b"hi\0hello world\0";
        let found = scanner.scan_ascii(addr(0), data);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, "hello world");
    }

    // 3. scan_utf16_le on UTF-16 encoded bytes
    #[test]
    fn test_scan_utf16_le() {
        // Encode "test" as UTF-16 LE: t=0x74, e=0x65, s=0x73, t=0x74, NUL=0x0000
        let chars = ['t', 'e', 's', 't'];
        let mut bytes: Vec<u8> = Vec::new();
        for c in &chars {
            let code = *c as u16;
            bytes.extend_from_slice(&code.to_le_bytes());
        }
        bytes.extend_from_slice(&[0x00, 0x00]); // NUL terminator

        let scanner = StringScanner::default();
        let found = scanner.scan_utf16_le(addr(0x2000), &bytes);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, "test");
        assert_eq!(found[0].encoding, StringEncoding::Utf16Le);
        assert!(found[0].is_null_terminated);
        assert_eq!(found[0].address, addr(0x2000));
    }

    // 4. scan_utf8 on UTF-8 bytes
    #[test]
    fn test_scan_utf8() {
        let data = b"rust\0code\0";
        let scanner = StringScanner::default();
        let found = scanner.scan_utf8(addr(0), data);
        assert!(found.iter().any(|s| s.value == "rust"));
        assert!(found.iter().any(|s| s.value == "code"));
    }

    // 5. read_cstring at specific offset
    #[test]
    fn test_read_cstring() {
        let data = b"foobar\0hello\0";
        let scanner = StringScanner::default();
        let result = scanner.read_cstring(addr(0x100), data, addr(0x107));
        assert!(result.is_some());
        let s = result.unwrap();
        assert_eq!(s.value, "hello");
        assert!(s.is_null_terminated);
    }

    // 6. read_cstring returns None for out-of-bounds
    #[test]
    fn test_read_cstring_oob() {
        let data = b"test\0";
        let scanner = StringScanner::default();
        assert!(
            scanner
                .read_cstring(addr(0x100), data, addr(0x200))
                .is_none()
        );
    }

    // 7. looks_like_path
    #[test]
    fn test_looks_like_path() {
        let make = |v: &str| FoundString {
            address: addr(0),
            length: v.len(),
            encoding: StringEncoding::Ascii,
            value: v.to_string(),
            char_count: v.len(),
            is_null_terminated: false,
            xref_count: 0,
        };
        assert!(make("C:\\Windows\\System32").looks_like_path());
        assert!(make("/usr/bin/bash").looks_like_path());
        assert!(!make("hello world").looks_like_path());
    }

    // 8. looks_like_url
    #[test]
    fn test_looks_like_url() {
        let make = |v: &str| FoundString {
            address: addr(0),
            length: v.len(),
            encoding: StringEncoding::Ascii,
            value: v.to_string(),
            char_count: v.len(),
            is_null_terminated: false,
            xref_count: 0,
        };
        assert!(make("http://example.com").looks_like_url());
        assert!(make("https://secure.example.com/path").looks_like_url());
        assert!(!make("example.com").looks_like_url());
    }

    // 9. looks_like_format_string
    #[test]
    fn test_looks_like_format_string() {
        let make = |v: &str| FoundString {
            address: addr(0),
            length: v.len(),
            encoding: StringEncoding::Ascii,
            value: v.to_string(),
            char_count: v.len(),
            is_null_terminated: false,
            xref_count: 0,
        };
        assert!(make("Error: %s at line %d").looks_like_format_string());
        assert!(make("Value=%x").looks_like_format_string());
        assert!(!make("hello world").looks_like_format_string());
    }

    // 10. entropy on known strings
    #[test]
    fn test_entropy() {
        let uniform = FoundString {
            address: addr(0),
            length: 4,
            encoding: StringEncoding::Ascii,
            value: "aaaa".to_string(),
            char_count: 4,
            is_null_terminated: false,
            xref_count: 0,
        };
        assert!((uniform.entropy() - 0.0).abs() < 1e-9);

        let varied = FoundString {
            address: addr(0),
            length: 2,
            encoding: StringEncoding::Ascii,
            value: "ab".to_string(),
            char_count: 2,
            is_null_terminated: false,
            xref_count: 0,
        };
        assert!((varied.entropy() - 1.0).abs() < 1e-9);
    }

    // 11. StringDatabase::from_scan populates correctly
    #[test]
    fn test_database_from_scan() {
        let data = b"hello\0world\0";
        let config = StringScannerConfig::fast();
        let db = StringDatabase::from_scan(addr(0x1000), data, config);
        assert_eq!(db.count(), 2);
    }

    // 12. StringDatabase::at lookup
    #[test]
    fn test_database_at() {
        let data = b"hello\0world\0";
        let config = StringScannerConfig::fast();
        let db = StringDatabase::from_scan(addr(0x1000), data, config);
        let s = db.at(addr(0x1000)).unwrap();
        assert_eq!(s.value, "hello");
        assert!(db.at(addr(0x9999)).is_none());
    }

    // 13. StringDatabase::search case-insensitive
    #[test]
    fn test_database_search() {
        let data = b"Hello\0WORLD\0";
        let config = StringScannerConfig::fast();
        let db = StringDatabase::from_scan(addr(0), data, config);
        let results = db.search("hello");
        assert!(!results.is_empty());
        assert!(results[0].value.eq_ignore_ascii_case("hello"));
    }

    // 14. StringDatabase::interesting_strings filter
    #[test]
    fn test_database_interesting_strings() {
        let mut db = StringDatabase::new();
        let add = |db: &mut StringDatabase, v: &str| {
            db.add(FoundString {
                address: addr(db.count() as u64 * 0x100),
                length: v.len(),
                encoding: StringEncoding::Ascii,
                value: v.to_string(),
                char_count: v.len(),
                is_null_terminated: true,
                xref_count: 0,
            });
        };
        add(&mut db, "hello");
        add(&mut db, "http://malware.example.com");
        add(&mut db, "Error: %s");
        add(&mut db, "C:\\Windows\\Temp");

        let interesting = db.interesting_strings();
        assert_eq!(interesting.len(), 3);
    }

    // 15. StringScannerConfig::default settings
    #[test]
    fn test_config_default() {
        let cfg = StringScannerConfig::default();
        assert_eq!(cfg.min_length, 4);
        assert!(cfg.require_null_terminator);
        assert!(cfg.encodings.contains(&StringEncoding::Ascii));
        assert!(cfg.encodings.contains(&StringEncoding::Utf16Le));
    }

    // 16. StringEncoding::min_char_bytes for all variants
    #[test]
    fn test_encoding_min_char_bytes() {
        assert_eq!(StringEncoding::Ascii.min_char_bytes(), 1);
        assert_eq!(StringEncoding::Utf8.min_char_bytes(), 1);
        assert_eq!(StringEncoding::Latin1.min_char_bytes(), 1);
        assert_eq!(StringEncoding::ShiftJis.min_char_bytes(), 1);
        assert_eq!(StringEncoding::Utf16Le.min_char_bytes(), 2);
        assert_eq!(StringEncoding::Utf16Be.min_char_bytes(), 2);
        assert_eq!(StringEncoding::Utf32Le.min_char_bytes(), 4);
        assert_eq!(StringEncoding::Utf32Be.min_char_bytes(), 4);
    }

    // 17. StringEncoding::is_unicode
    #[test]
    fn test_encoding_is_unicode() {
        assert!(!StringEncoding::Ascii.is_unicode());
        assert!(!StringEncoding::Latin1.is_unicode());
        assert!(StringEncoding::Utf8.is_unicode());
        assert!(StringEncoding::Utf16Le.is_unicode());
        assert!(StringEncoding::Utf32Be.is_unicode());
    }

    // 18. StringStats populated correctly
    #[test]
    fn test_string_stats() {
        let data = b"hello\0world\0";
        let config = StringScannerConfig::fast();
        let db = StringDatabase::from_scan(addr(0x1000), data, config);
        let stats = db.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(*stats.by_encoding.get("ASCII").unwrap(), 2);
        assert!(stats.avg_length > 0.0);
        assert!(stats.max_length >= 6); // "hello\0" = 6 bytes
    }

    // 19. scan_pascal_strings
    #[test]
    fn test_scan_pascal_strings() {
        let mut data = vec![5u8]; // length prefix
        data.extend_from_slice(b"hello"); // 5 chars
        data.push(4);
        data.extend_from_slice(b"rust");

        let config = StringScannerConfig::fast();
        let scanner = StringScanner::new(config);
        let found = scanner.scan_pascal_strings(addr(0), &data);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].value, "hello");
        assert_eq!(found[1].value, "rust");
    }

    // 20. looks_like_registry_key
    #[test]
    fn test_looks_like_registry_key() {
        let make = |v: &str| FoundString {
            address: addr(0),
            length: v.len(),
            encoding: StringEncoding::Ascii,
            value: v.to_string(),
            char_count: v.len(),
            is_null_terminated: false,
            xref_count: 0,
        };
        assert!(make("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft").looks_like_registry_key());
        assert!(make("Software\\Classes").looks_like_registry_key());
        assert!(!make("just a string").looks_like_registry_key());
    }

    fn make_fs(v: &str, enc: StringEncoding, address: u64) -> FoundString {
        FoundString {
            address: addr(address),
            length: v.len(),
            encoding: enc,
            value: v.to_string(),
            char_count: v.chars().count(),
            is_null_terminated: false,
            xref_count: 0,
        }
    }

    // Coverage-gap: is_printable had no direct test.
    #[test]
    fn test_is_printable() {
        assert!(make_fs("hello world", StringEncoding::Ascii, 0).is_printable());
        assert!(!make_fs("he\u{1}llo", StringEncoding::Ascii, 0).is_printable());
        // Empty string is vacuously printable.
        assert!(make_fs("", StringEncoding::Ascii, 0).is_printable());
    }

    // Coverage-gap: all_encodings had no direct test.
    #[test]
    fn test_all_encodings_config() {
        let cfg = StringScannerConfig::all_encodings();
        assert_eq!(cfg.encodings.len(), 8);
        assert!(cfg.encodings.contains(&StringEncoding::Ascii));
        assert!(cfg.encodings.contains(&StringEncoding::ShiftJis));
    }

    // Coverage-gap: filter_by_encoding had no direct test.
    #[test]
    fn test_filter_by_encoding() {
        let mut db = StringDatabase::new();
        db.add(make_fs("a", StringEncoding::Ascii, 0x10));
        db.add(make_fs("b", StringEncoding::Utf8, 0x20));
        db.add(make_fs("c", StringEncoding::Ascii, 0x30));
        let ascii = db.filter_by_encoding(&StringEncoding::Ascii);
        assert_eq!(ascii.len(), 2);
        assert!(ascii.iter().all(|s| s.encoding == StringEncoding::Ascii));
        assert!(db.filter_by_encoding(&StringEncoding::Utf32Be).is_empty());
    }

    // Coverage-gap: longest had no direct test.
    #[test]
    fn test_longest() {
        let mut db = StringDatabase::new();
        db.add(make_fs("aa", StringEncoding::Ascii, 0x10));
        db.add(make_fs("aaaa", StringEncoding::Ascii, 0x20));
        db.add(make_fs("aaa", StringEncoding::Ascii, 0x30));
        let top2 = db.longest(2);
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].value, "aaaa");
        assert_eq!(top2[1].value, "aaa");
        // n larger than the database returns everything, no panic.
        assert_eq!(db.longest(10).len(), 3);
        assert!(db.longest(0).is_empty());
    }

    // Coverage-gap: detect_xor_key had no direct test.
    #[test]
    fn test_detect_xor_key() {
        assert_eq!(detect_xor_key(&[]), None);
        let plain = b"The quick brown fox jumps over the lazy dog.\0";
        let key = 0x5Au8;
        let enc: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        assert_eq!(detect_xor_key(&enc), Some(key));
    }
}

#[cfg(test)]
mod property_tests;
