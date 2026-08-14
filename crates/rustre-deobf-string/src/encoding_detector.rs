//! Detect and decode string encodings: base64 variants, hex strings,
//! URL percent-encoding, Unicode escapes, ROT13/ROT47, custom alphabet substitution.
//!
//! # Layer distinction
//! This module covers **standard / well-known encodings** (RFC 4648 Base64,
//! URL percent-encoding, Unicode `\uXXXX`, ROT-13, ROT-47, hex strings, and
//! single-byte alphabet substitution detected by frequency).
//!
//! For **non-standard / custom** encodings (Base32, RotN for N≠13, full
//! 256-byte substitution tables, reversed strings, custom-alphabet Base64/32)
//! see [`crate::custom_encoding_detector`].

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// EncodingKind — the detected encoding type
// ─────────────────────────────────────────────────────────────────────────────

/// The encoding scheme detected or applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingKind {
    /// Standard Base64 (RFC 4648, alphabet A-Z a-z 0-9 + /).
    Base64Standard,
    /// URL-safe Base64 (RFC 4648, alphabet A-Z a-z 0-9 - _).
    Base64UrlSafe,
    /// Base64 with a custom alphabet (64 unique printable characters).
    Base64Custom,
    /// Hexadecimal string with optional 0x prefix or spaces.
    HexString,
    /// URL percent-encoding (%XX).
    UrlPercent,
    /// Unicode \\uXXXX escape sequences.
    UnicodeEscape,
    /// ROT13 (letters only).
    Rot13,
    /// ROT47 (printable ASCII 33–126).
    Rot47,
    /// Custom single-byte alphabet substitution.
    CustomSubstitution,
    /// No encoding detected.
    None,
}

impl fmt::Display for EncodingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64Standard => write!(f, "base64-standard"),
            Self::Base64UrlSafe => write!(f, "base64-urlsafe"),
            Self::Base64Custom => write!(f, "base64-custom"),
            Self::HexString => write!(f, "hex-string"),
            Self::UrlPercent => write!(f, "url-percent"),
            Self::UnicodeEscape => write!(f, "unicode-escape"),
            Self::Rot13 => write!(f, "rot13"),
            Self::Rot47 => write!(f, "rot47"),
            Self::CustomSubstitution => write!(f, "custom-substitution"),
            Self::None => write!(f, "none"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecodedString — result of an encoding detection + decoding pass
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded string together with provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedString {
    /// The original (encoded) input.
    pub encoded: String,
    /// The decoded output bytes.
    pub decoded_bytes: Vec<u8>,
    /// Decoded as UTF-8 string if valid.
    pub decoded_str: Option<String>,
    /// Detected encoding.
    pub kind: EncodingKind,
    /// Confidence that the decoding is correct (0–100).
    pub confidence: u8,
}

impl DecodedString {
    /// Create a new `DecodedString`.
    #[must_use]
    pub fn new(encoded: String, decoded_bytes: Vec<u8>, kind: EncodingKind, confidence: u8) -> Self {
        let decoded_str = std::str::from_utf8(&decoded_bytes).ok().map(std::borrow::ToOwned::to_owned);
        Self {
            encoded,
            decoded_bytes,
            decoded_str,
            kind,
            confidence,
        }
    }

    /// Returns `true` if the decoded bytes form valid UTF-8.
    #[must_use]
    pub fn is_valid_utf8(&self) -> bool {
        self.decoded_str.is_some()
    }

    /// Returns the printable ASCII ratio of the decoded bytes.
    #[must_use]
    pub fn printable_ratio(&self) -> f64 {
        if self.decoded_bytes.is_empty() {
            return 0.0;
        }
        self.decoded_bytes
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .count() as f64
            / self.decoded_bytes.len() as f64
    }
}

impl fmt::Display for DecodedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self
            .decoded_str
            .as_deref()
            .unwrap_or("<non-utf8>");
        write!(f, "DecodedString[{}] conf={} : {:?}", self.kind, self.confidence, value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EncodingResult — result of a multi-strategy detection scan
// ─────────────────────────────────────────────────────────────────────────────

/// The result of running all encoding detectors against a single input.
#[derive(Debug, Clone)]
pub struct EncodingResult {
    /// The input string that was analysed.
    pub input: String,
    /// All candidate decodings, sorted by confidence (highest first).
    pub candidates: Vec<DecodedString>,
    /// The highest-confidence candidate (None if no encoding detected).
    pub best: Option<DecodedString>,
}

impl EncodingResult {
    /// Create an empty result.
    #[must_use]
    pub fn new(input: String) -> Self {
        Self {
            input,
            candidates: Vec::new(),
            best: None,
        }
    }

    /// Add a candidate and update `best` if this is higher confidence.
    pub fn add_candidate(&mut self, candidate: DecodedString) {
        let conf = candidate.confidence;
        if self.best.as_ref().is_none_or(|b| conf > b.confidence) {
            self.best = Some(candidate.clone());
        }
        self.candidates.push(candidate);
    }

    /// Sort candidates by descending confidence.
    pub fn sort_candidates(&mut self) {
        self.candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    }

    /// Returns `true` if any encoding was detected.
    #[must_use]
    pub fn any_detected(&self) -> bool {
        self.best.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64Detector — detects and decodes base64 variants
// ─────────────────────────────────────────────────────────────────────────────

/// Detects and decodes Base64 strings in standard, URL-safe, and custom alphabets.
#[derive(Debug, Clone, Default)]
pub struct Base64Detector {
    /// Optional custom alphabets to try (each 64 bytes).
    custom_alphabets: Vec<Vec<u8>>,
}

impl Base64Detector {
    /// Create a detector with no custom alphabets.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a custom 64-byte alphabet.
    pub fn add_custom_alphabet(&mut self, alphabet: Vec<u8>) {
        if alphabet.len() == 64 {
            self.custom_alphabets.push(alphabet);
        }
    }

    /// Check whether `s` looks like standard Base64 (A-Z a-z 0-9 + / =).
    #[must_use]
    pub fn is_standard(s: &str) -> bool {
        if s.len() < 4 {
            return false;
        }
        let s = s.trim_end_matches('=');
        s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/'))
            && s.len() % 4 != 1 // valid length
    }

    /// Check whether `s` looks like URL-safe Base64 (A-Z a-z 0-9 - _).
    #[must_use]
    pub fn is_url_safe(s: &str) -> bool {
        if s.len() < 4 {
            return false;
        }
        let s = s.trim_end_matches('=');
        s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
    }

    /// Decode standard Base64.
    #[must_use]
    pub fn decode_standard(s: &str) -> Option<Vec<u8>> {
        decode_base64(s, false)
    }

    /// Decode URL-safe Base64 (- → +, _ → /).
    #[must_use]
    pub fn decode_url_safe(s: &str) -> Option<Vec<u8>> {
        let normalized: String = s.chars().map(|c| match c { '-' => '+', '_' => '/', c => c }).collect();
        decode_base64(&normalized, false)
    }

    /// Decode Base64 with a custom alphabet (remaps input bytes through `alphabet`).
    #[must_use]
    pub fn decode_custom(input: &[u8], alphabet: &[u8; 64]) -> Option<Vec<u8>> {
        let mut table = [255u8; 256];
        for (i, &c) in alphabet.iter().enumerate() {
            table[c as usize] = i as u8;
        }
        let mut out = Vec::new();
        let clean: Vec<u8> = input.iter().copied().filter(|&b| b != b'=').collect();
        let mut i = 0;
        while i + 3 < clean.len() {
            let v = [
                table[clean[i] as usize],
                table[clean[i + 1] as usize],
                table[clean[i + 2] as usize],
                table[clean[i + 3] as usize],
            ];
            if v.iter().any(|&x| x == 255) {
                return None;
            }
            out.push((v[0] << 2) | (v[1] >> 4));
            if clean.get(i + 2).copied().unwrap_or(b'=') != b'=' { out.push((v[1] << 4) | (v[2] >> 2)); }
            if clean.get(i + 3).copied().unwrap_or(b'=') != b'=' { out.push((v[2] << 6) | v[3]); }
            i += 4;
        }
        Some(out)
    }

    /// Run all base64 variants on `s` and return matching candidates.
    #[must_use]
    pub fn detect_and_decode(&self, s: &str) -> Vec<DecodedString> {
        let mut results = Vec::new();

        if Self::is_standard(s) {
            if let Some(bytes) = Self::decode_standard(s) {
                let conf = 90u8;
                results.push(DecodedString::new(s.to_owned(), bytes, EncodingKind::Base64Standard, conf));
            }
        }
        if Self::is_url_safe(s) {
            if let Some(bytes) = Self::decode_url_safe(s) {
                let conf = 88u8;
                results.push(DecodedString::new(s.to_owned(), bytes, EncodingKind::Base64UrlSafe, conf));
            }
        }
        for alpha in &self.custom_alphabets {
            if alpha.len() == 64 {
                let arr: [u8; 64] = alpha.as_slice().try_into().unwrap();
                if let Some(bytes) = Self::decode_custom(s.as_bytes(), &arr) {
                    results.push(DecodedString::new(s.to_owned(), bytes, EncodingKind::Base64Custom, 75));
                }
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexStringDetector — detects and decodes hex-encoded strings
// ─────────────────────────────────────────────────────────────────────────────

/// Detects hex-encoded strings in several common formats.
#[derive(Debug, Clone, Default)]
pub struct HexStringDetector;

impl HexStringDetector {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Returns `true` if `s` looks like a plain hex string (even length, all hex digits).
    #[must_use]
    pub fn is_raw_hex(s: &str) -> bool {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        s.len() >= 2 && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Returns `true` if `s` is a `0x`-prefixed hex value.
    #[must_use]
    pub fn is_prefixed_hex(s: &str) -> bool {
        (s.starts_with("0x") || s.starts_with("0X")) && Self::is_raw_hex(s)
    }

    /// Decode a raw or prefixed hex string into bytes.
    #[must_use]
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        let clean = s.trim_start_matches("0x").trim_start_matches("0X")
            .replace([' ', ',', '_'], "");
        if clean.len() % 2 != 0 {
            return None;
        }
        clean.as_bytes().chunks(2).map(|c| {
            let hi = hex_nibble(c[0])?;
            let lo = hex_nibble(c[1])?;
            Some((hi << 4) | lo)
        }).collect()
    }

    /// Detect runs of hex characters in `s` (at least 4 bytes = 8 hex chars).
    #[must_use]
    pub fn find_hex_runs(s: &str) -> Vec<(usize, String)> {
        let mut results = Vec::new();
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_hexdigit() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let run = &s[start..i];
                if run.len() >= 8 && run.len() % 2 == 0 {
                    results.push((start, run.to_owned()));
                }
            } else {
                i += 1;
            }
        }
        results
    }

    /// Detect and decode hex strings in `s`.
    #[must_use]
    pub fn detect_and_decode(&self, s: &str) -> Vec<DecodedString> {
        let mut results = Vec::new();
        if Self::is_raw_hex(s) || Self::is_prefixed_hex(s) {
            if let Some(bytes) = Self::decode(s) {
                let conf = if bytes.iter().all(|&b| b.is_ascii_graphic() || b == b' ') { 85 } else { 60 };
                results.push(DecodedString::new(s.to_owned(), bytes, EncodingKind::HexString, conf));
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL and Unicode decoders
// ─────────────────────────────────────────────────────────────────────────────

/// Decode URL percent-encoded string (`%XX`).
#[must_use]
pub fn decode_url_percent(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Detect `%XX` patterns in `s`.
#[must_use]
pub fn is_url_encoded(s: &str) -> bool {
    s.contains('%') && s.as_bytes().windows(3).any(|w| {
        w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit()
    })
}

/// Decode `\\uXXXX` Unicode escape sequences.
#[must_use]
pub fn decode_unicode_escapes(s: &str) -> Option<String> {
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 5 < chars.len() && chars[i + 1] == 'u' {
            let hex: String = chars[i + 2..i + 6].iter().collect();
            let code = u32::from_str_radix(&hex, 16).ok()?;
            let c = char::from_u32(code)?;
            result.push(c);
            i += 6;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }
    Some(result)
}

/// Returns `true` if `s` contains `\\uXXXX` sequences.
#[must_use]
pub fn has_unicode_escapes(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.windows(6).any(|w| {
        w[0] == b'\\' && w[1] == b'u'
            && w[2..6].iter().all(|b| b.is_ascii_hexdigit())
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// ROT-13 / ROT-47 encoders
// ─────────────────────────────────────────────────────────────────────────────

/// Apply ROT-13 to a string (letters only).
#[must_use]
pub fn rot13(s: &str) -> String {
    s.chars().map(|c| {
        if c.is_ascii_uppercase() {
            (b'A' + (c as u8 - b'A' + 13) % 26) as char
        } else if c.is_ascii_lowercase() {
            (b'a' + (c as u8 - b'a' + 13) % 26) as char
        } else {
            c
        }
    }).collect()
}

/// Apply ROT-47 to a string (printable ASCII 33–126).
#[must_use]
pub fn rot47(s: &str) -> String {
    s.chars().map(|c| {
        let b = c as u8;
        if (33..=126).contains(&b) {
            (33 + (b - 33 + 47) % 94) as char
        } else {
            c
        }
    }).collect()
}

/// Returns `true` if applying ROT-13 to `s` produces a higher English score.
#[must_use]
pub fn looks_like_rot13(s: &str) -> bool {
    let decoded = rot13(s);
    english_score(decoded.as_bytes()) > english_score(s.as_bytes()) + 0.02
}

/// Returns `true` if applying ROT-47 to `s` produces a higher printable ratio.
#[must_use]
pub fn looks_like_rot47(s: &str) -> bool {
    let decoded = rot47(s);
    printable_ratio(decoded.as_bytes()) > printable_ratio(s.as_bytes()) + 0.05
}

// ─────────────────────────────────────────────────────────────────────────────
// Custom alphabet substitution detector
// ─────────────────────────────────────────────────────────────────────────────

/// Attempts to detect and reverse a custom monoalphabetic substitution.
///
/// Uses frequency analysis: the most frequent byte is assumed to map to space (0x20)
/// or the most frequent ASCII letter.
#[derive(Debug, Clone)]
pub struct CustomAlphabetSubstitution {
    /// Mapping: ciphertext byte → plaintext byte.
    pub table: [u8; 256],
}

impl Default for CustomAlphabetSubstitution {
    fn default() -> Self {
        Self { table: [0u8; 256] }
    }
}

impl CustomAlphabetSubstitution {
    /// Create a new substitution cipher with the identity mapping.
    #[must_use]
    pub fn identity() -> Self {
        let mut table = [0u8; 256];
        for i in 0usize..256 {
            table[i] = i as u8;
        }
        Self { table }
    }

    /// Build a substitution table from frequency analysis, assuming the most
    /// frequent ciphertext byte maps to the space character (0x20).
    #[must_use]
    pub fn from_frequency_analysis(ciphertext: &[u8]) -> Self {
        let mut freq = [0u64; 256];
        for &b in ciphertext {
            freq[b as usize] += 1;
        }
        let most_freq = freq
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map(|(i, _)| i as u8)
            .unwrap_or(0);

        let mut table: [u8; 256] = std::array::from_fn(|i| i as u8);
        // Swap most frequent ciphertext byte with space.
        table.swap(most_freq as usize, 0x20);
        Self { table }
    }

    /// Apply the substitution table to bytes.
    #[must_use]
    pub fn apply(&self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| self.table[b as usize]).collect()
    }

    /// Score the substitution by printable ratio of the result.
    #[must_use]
    pub fn score(&self, ciphertext: &[u8]) -> f64 {
        let dec = self.apply(ciphertext);
        printable_ratio(&dec)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EncodingDetector — top-level multi-strategy detector
// ─────────────────────────────────────────────────────────────────────────────

/// Multi-strategy encoding detector.
///
/// Tries all registered encoding strategies against a string and returns
/// all candidates, sorted by confidence.
#[derive(Debug, Clone)]
pub struct EncodingDetector {
    base64: Base64Detector,
    hex: HexStringDetector,
    /// Whether to attempt ROT variants.
    pub try_rot: bool,
    /// Whether to attempt URL decoding.
    pub try_url: bool,
    /// Whether to attempt Unicode escape decoding.
    pub try_unicode: bool,
    /// Whether to attempt custom substitution.
    pub try_substitution: bool,
    /// Minimum confidence to include a result.
    pub min_confidence: u8,
}

impl EncodingDetector {
    /// Create a detector with all strategies enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base64: Base64Detector::new(),
            hex: HexStringDetector::new(),
            try_rot: true,
            try_url: true,
            try_unicode: true,
            try_substitution: false,
            min_confidence: 40,
        }
    }

    /// Register a custom Base64 alphabet.
    pub fn add_custom_base64_alphabet(&mut self, alphabet: Vec<u8>) {
        self.base64.add_custom_alphabet(alphabet);
    }

    /// Run all strategies against `input` and return an [`EncodingResult`].
    #[must_use]
    pub fn detect(&self, input: &str) -> EncodingResult {
        let mut result = EncodingResult::new(input.to_owned());

        // Base64 variants.
        for c in self.base64.detect_and_decode(input) {
            if c.confidence >= self.min_confidence {
                result.add_candidate(c);
            }
        }

        // Hex strings.
        for c in self.hex.detect_and_decode(input) {
            if c.confidence >= self.min_confidence {
                result.add_candidate(c);
            }
        }

        // URL percent encoding.
        if self.try_url && is_url_encoded(input) {
            if let Some(bytes) = decode_url_percent(input) {
                let conf = 80u8;
                result.add_candidate(DecodedString::new(
                    input.to_owned(), bytes, EncodingKind::UrlPercent, conf,
                ));
            }
        }

        // Unicode escapes.
        if self.try_unicode && has_unicode_escapes(input) {
            if let Some(decoded) = decode_unicode_escapes(input) {
                let bytes = decoded.as_bytes().to_vec();
                result.add_candidate(DecodedString::new(
                    input.to_owned(), bytes, EncodingKind::UnicodeEscape, 85,
                ));
            }
        }

        // ROT-13.
        if self.try_rot && looks_like_rot13(input) {
            let decoded = rot13(input);
            result.add_candidate(DecodedString::new(
                input.to_owned(),
                decoded.as_bytes().to_vec(),
                EncodingKind::Rot13,
                75,
            ));
        }

        // ROT-47.
        if self.try_rot && looks_like_rot47(input) {
            let decoded = rot47(input);
            result.add_candidate(DecodedString::new(
                input.to_owned(),
                decoded.as_bytes().to_vec(),
                EncodingKind::Rot47,
                65,
            ));
        }

        // Custom substitution.
        if self.try_substitution {
            let sub = CustomAlphabetSubstitution::from_frequency_analysis(input.as_bytes());
            let dec = sub.apply(input.as_bytes());
            let pr = printable_ratio(&dec);
            if pr > 0.75 {
                let conf = (pr * 60.0).min(100.0) as u8;
                result.add_candidate(DecodedString::new(
                    input.to_owned(), dec, EncodingKind::CustomSubstitution, conf,
                ));
            }
        }

        result.sort_candidates();
        result
    }

    /// Batch-detect encodings for a list of strings.
    #[must_use]
    pub fn detect_batch(&self, inputs: &[&str]) -> Vec<EncodingResult> {
        inputs.iter().map(|s| self.detect(s)).collect()
    }

    /// Scan `text` for embedded Base64 blobs (minimum 16 characters).
    #[must_use]
    pub fn scan_for_base64_blobs(text: &str) -> Vec<(usize, String, Vec<u8>)> {
        let mut results = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if is_b64_char(bytes[i]) {
                let start = i;
                while i < bytes.len() && is_b64_char(bytes[i]) {
                    i += 1;
                }
                // Consume optional padding.
                while i < bytes.len() && bytes[i] == b'=' {
                    i += 1;
                }
                let blob = &text[start..i];
                if blob.len() >= 16 {
                    if let Some(decoded) = decode_base64(blob, false) {
                        results.push((start, blob.to_owned(), decoded));
                    }
                }
            } else {
                i += 1;
            }
        }
        results
    }

    /// Build a simple encoding frequency map from a list of strings.
    #[must_use]
    pub fn frequency_map(results: &[EncodingResult]) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for r in results {
            if let Some(best) = &r.best {
                *map.entry(best.kind.to_string()).or_insert(0) += 1;
            }
        }
        map
    }
}

impl Default for EncodingDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

fn decode_base64(s: &str, url_safe: bool) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        let val = if url_safe {
            b64_val_url(c)?
        } else {
            b64_val_std(c)?
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn b64_val_std(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn b64_val_url(c: u8) -> Option<u8> {
    match c {
        b'-' => Some(62),
        b'_' => Some(63),
        _ => b64_val_std(c),
    }
}

fn is_b64_char(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'-' | b'_')
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    data.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count() as f64
        / data.len() as f64
}

fn english_score(data: &[u8]) -> f64 {
    const FREQ: [f64; 26] = [
        0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697, 0.0015,
        0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599, 0.0633, 0.0906,
        0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007,
    ];
    if data.is_empty() { return 0.0; }
    let mut score = 0.0f64;
    for &b in data {
        if b.is_ascii_lowercase() { score += FREQ[(b - b'a') as usize]; }
        else if b.is_ascii_uppercase() { score += FREQ[(b - b'A') as usize]; }
        else if b == b' ' { score += 0.13; }
    }
    score / data.len() as f64
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_standard_roundtrip() {
        // "Hello, World!" in standard base64 = SGVsbG8sIFdvcmxkIQ==
        let encoded = "SGVsbG8sIFdvcmxkIQ==";
        let decoded = Base64Detector::decode_standard(encoded).unwrap();
        assert_eq!(decoded, b"Hello, World!");
    }

    #[test]
    fn base64_url_safe() {
        // URL-safe base64 for "\xfb\xff" = +/= standard → -_= url-safe
        let encoded = "Hello-World_";
        assert!(Base64Detector::is_url_safe(encoded));
    }

    #[test]
    fn hex_decode_basic() {
        let decoded = HexStringDetector::decode("48656c6c6f").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn hex_decode_prefixed() {
        let decoded = HexStringDetector::decode("0x48656c6c6f").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn url_percent_decode() {
        let decoded = decode_url_percent("Hello%20World").unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn unicode_escape_decode() {
        let decoded = decode_unicode_escapes("\\u0048\\u0065\\u006c\\u006c\\u006f").unwrap();
        assert_eq!(decoded, "Hello");
    }

    #[test]
    fn rot13_roundtrip() {
        assert_eq!(rot13(&rot13("Hello World")), "Hello World");
    }

    #[test]
    fn rot47_roundtrip() {
        let original = "Test123!";
        assert_eq!(rot47(&rot47(original)), original);
    }

    #[test]
    fn detector_finds_base64() {
        let det = EncodingDetector::new();
        let result = det.detect("SGVsbG8sIFdvcmxkIQ==");
        assert!(result.any_detected());
        assert!(result.best.as_ref().unwrap().decoded_str.as_deref() == Some("Hello, World!"));
    }

    #[test]
    fn detector_finds_hex() {
        let det = EncodingDetector::new();
        let result = det.detect("48656c6c6f");
        assert!(result.any_detected());
    }

    #[test]
    fn scan_for_base64_blobs_finds_embedded() {
        let text = "prefix SGVsbG8sIFdvcmxkIQ== suffix";
        let blobs = EncodingDetector::scan_for_base64_blobs(text);
        assert!(!blobs.is_empty());
        assert_eq!(blobs[0].2, b"Hello, World!");
    }

    #[test]
    fn custom_substitution_applies_table() {
        let sub = CustomAlphabetSubstitution::identity();
        let data = b"test";
        assert_eq!(sub.apply(data), data);
    }

    #[test]
    fn frequency_map_counts_kinds() {
        let det = EncodingDetector::new();
        let r1 = det.detect("SGVsbG8=");
        let r2 = det.detect("48656c6c6f");
        let map = EncodingDetector::frequency_map(&[r1, r2]);
        assert!(!map.is_empty());
    }
}
