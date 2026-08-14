//! Custom string-encoding detector: base64 variants, lookup tables, byte maps.
//!
//! Identifies when a string has been encoded with a non-standard alphabet or
//! a custom byte-substitution table, and attempts to recover the underlying
//! plaintext.

use std::collections::HashMap;
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// CustomEncodingKind
// ─────────────────────────────────────────────────────────────────────────────

/// The broad class of custom encoding detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CustomEncodingKind {
    /// Standard RFC 4648 base64.
    Base64Standard,
    /// URL-safe base64 (+ → -, / → _).
    Base64UrlSafe,
    /// Base64 with a completely custom 64-character alphabet.
    Base64Custom(String),
    /// Base32 (A-Z 2-7).
    Base32Standard,
    /// Base32 with a custom 32-character alphabet.
    Base32Custom(String),
    /// Simple ROT-13 substitution.
    Rot13,
    /// ROT-N for N ≠ 13.
    RotN(u8),
    /// A full 256-byte substitution table (custom alphabet mapping).
    SubstitutionTable,
    /// Reversed byte string.
    Reversed,
    /// Hex encoding (0-9 a-f).
    HexLower,
    /// Hex encoding (0-9 A-F).
    HexUpper,
    /// Unknown / unrecognised.
    Unknown,
}

impl fmt::Display for CustomEncodingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64Standard   => write!(f, "base64-standard"),
            Self::Base64UrlSafe    => write!(f, "base64-url-safe"),
            Self::Base64Custom(a)  => write!(f, "base64-custom({a})"),
            Self::Base32Standard   => write!(f, "base32-standard"),
            Self::Base32Custom(a)  => write!(f, "base32-custom({a})"),
            Self::Rot13            => write!(f, "rot13"),
            Self::RotN(n)          => write!(f, "rot{n}"),
            Self::SubstitutionTable => write!(f, "substitution-table"),
            Self::Reversed         => write!(f, "reversed"),
            Self::HexLower         => write!(f, "hex-lower"),
            Self::HexUpper         => write!(f, "hex-upper"),
            Self::Unknown          => write!(f, "unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CustomAlphabet
// ─────────────────────────────────────────────────────────────────────────────

/// A custom base-N alphabet string and its reverse lookup table.
#[derive(Debug, Clone)]
pub struct CustomAlphabet {
    /// The 64 (or 32) characters in order.
    pub chars: Vec<u8>,
    /// Reverse lookup: byte value → position (0-63 or 0-31).
    pub reverse: HashMap<u8, u8>,
    /// Padding character, if any.
    pub padding: Option<u8>,
}

impl CustomAlphabet {
    /// Build from a slice of characters.
    ///
    /// # Errors
    /// Returns `Err` if `chars` is not 64 or 32 unique bytes.
    pub fn new(chars: &[u8], padding: Option<u8>) -> Result<Self, String> {
        if chars.len() != 64 && chars.len() != 32 {
            return Err(format!("alphabet must be 32 or 64 chars, got {}", chars.len()));
        }
        let mut reverse = HashMap::new();
        for (i, &c) in chars.iter().enumerate() {
            if reverse.insert(c, i as u8).is_some() {
                return Err(format!("duplicate character {c:#04x} in alphabet"));
            }
        }
        Ok(Self { chars: chars.to_vec(), reverse, padding })
    }

    /// Standard base64 alphabet.
    #[must_use]
    pub fn base64_standard() -> Self {
        let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        Self::new(alpha, Some(b'=')).expect("valid standard alphabet")
    }

    /// URL-safe base64 alphabet.
    #[must_use]
    pub fn base64_url_safe() -> Self {
        let alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        Self::new(alpha, Some(b'=')).expect("valid url-safe alphabet")
    }

    /// Returns `true` when `data` uses only characters from this alphabet
    /// (and optionally the padding character).
    #[must_use]
    pub fn is_valid_input(&self, data: &[u8]) -> bool {
        data.iter().all(|&b| {
            self.reverse.contains_key(&b)
                || self.padding.map_or(false, |p| b == p)
                || b == b'\n' || b == b'\r'
        })
    }

    /// Encode raw bytes using this base-64 alphabet.
    #[must_use]
    pub fn encode64(&self, data: &[u8]) -> Vec<u8> {
        if self.chars.len() != 64 { return vec![]; }
        let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
            out.push(self.chars[(b0 >> 2) as usize]);
            out.push(self.chars[((b0 & 0x03) << 4 | b1 >> 4) as usize]);
            if chunk.len() > 1 {
                out.push(self.chars[((b1 & 0x0f) << 2 | b2 >> 6) as usize]);
            } else if let Some(p) = self.padding { out.push(p); }
            if chunk.len() > 2 {
                out.push(self.chars[(b2 & 0x3f) as usize]);
            } else if let Some(p) = self.padding { out.push(p); }
        }
        out
    }

    /// Decode base-64 encoded data back to raw bytes.
    ///
    /// # Errors
    /// Returns `Err` with a description on invalid input.
    pub fn decode64(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.chars.len() != 64 {
            return Err("not a base-64 alphabet".to_owned());
        }
        let data: Vec<u8> = data.iter().filter(|&&b| b != b'\n' && b != b'\r').copied().collect();
        let pad = self.padding.unwrap_or(b'=');
        let stripped: Vec<u8> = data.iter().filter(|&&b| b != pad).copied().collect();

        if stripped.len() % 4 > 2 {
            // 3 without padding is still valid
        }

        let mut out = Vec::with_capacity(stripped.len() * 3 / 4);
        for chunk in stripped.chunks(4) {
            let v: Vec<u8> = chunk.iter().map(|b| {
                self.reverse.get(b).copied().unwrap_or(0)
            }).collect();
            let b0 = (v[0] << 2) | (v.get(1).copied().unwrap_or(0) >> 4);
            out.push(b0);
            if chunk.len() > 2 {
                let b1 = (v[1] << 4) | (v.get(2).copied().unwrap_or(0) >> 2);
                out.push(b1);
            }
            if chunk.len() > 3 {
                let b2 = (v[2] << 6) | v.get(3).copied().unwrap_or(0);
                out.push(b2);
            }
        }
        Ok(out)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EncodingPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A detected encoding pattern with confidence score and decoded payload.
#[derive(Debug, Clone)]
pub struct EncodingPattern {
    /// What kind of encoding was detected.
    pub kind: CustomEncodingKind,
    /// Confidence in the detection (0.0 – 1.0).
    pub confidence: f64,
    /// Decoded plaintext bytes (empty if decoding is not possible without a key).
    pub decoded: Vec<u8>,
}

impl EncodingPattern {
    /// Returns `true` when we have high confidence (≥ 0.8).
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.confidence >= 0.8
    }

    /// Returns the decoded text as a UTF-8 string, or a lossy conversion.
    #[must_use]
    pub fn decoded_text(&self) -> String {
        String::from_utf8_lossy(&self.decoded).into_owned()
    }
}

impl fmt::Display for EncodingPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (conf={:.2})", self.kind, self.confidence)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CustomEncodingDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detect and decode custom string encodings in binary data.
#[derive(Debug, Default)]
pub struct CustomEncodingDetector {
    /// Whether to try ROT-N variations beyond ROT-13.
    pub try_rot_n: bool,
    /// Custom alphabets to try as potential base64 replacements.
    pub custom_alphabets: Vec<CustomAlphabet>,
    /// Minimum confidence to include in results.
    pub min_confidence: f64,
}

impl CustomEncodingDetector {
    /// Create a detector with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            try_rot_n: true,
            custom_alphabets: Vec::new(),
            min_confidence: 0.5,
        }
    }

    /// Register an additional custom alphabet to test.
    pub fn add_alphabet(&mut self, alpha: CustomAlphabet) {
        self.custom_alphabets.push(alpha);
    }

    /// Attempt to detect the encoding of `data`.
    ///
    /// Returns all detected patterns sorted by confidence descending.
    #[must_use]
    pub fn detect_encoding(&self, data: &[u8]) -> Vec<EncodingPattern> {
        let mut results = Vec::new();

        // 1. Hex
        if let Some(p) = self.try_hex(data) { results.push(p); }

        // 2. Standard base64
        if let Some(p) = self.try_base64(data, &CustomAlphabet::base64_standard(), CustomEncodingKind::Base64Standard) {
            results.push(p);
        }

        // 3. URL-safe base64
        if let Some(p) = self.try_base64(data, &CustomAlphabet::base64_url_safe(), CustomEncodingKind::Base64UrlSafe) {
            results.push(p);
        }

        // 4. Custom alphabets
        for alpha in &self.custom_alphabets {
            let kind = if alpha.chars.len() == 64 {
                CustomEncodingKind::Base64Custom(String::from_utf8_lossy(&alpha.chars).into_owned())
            } else {
                CustomEncodingKind::Base32Custom(String::from_utf8_lossy(&alpha.chars).into_owned())
            };
            if let Some(p) = self.try_base64(data, alpha, kind) {
                results.push(p);
            }
        }

        // 5. ROT-13 / ROT-N
        if let Some(p) = self.try_rot(data, 13) { results.push(p); }
        if self.try_rot_n {
            for n in (1u8..=25).filter(|&n| n != 13) {
                if let Some(p) = self.try_rot(data, n) {
                    if p.confidence >= self.min_confidence { results.push(p); }
                }
            }
        }

        // 6. Reversed
        if let Some(p) = self.try_reversed(data) { results.push(p); }

        // 7. Substitution table inference
        if let Some(p) = self.try_substitution_table(data) { results.push(p); }

        results.retain(|p| p.confidence >= self.min_confidence);
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    fn try_hex(&self, data: &[u8]) -> Option<EncodingPattern> {
        if data.len() < 4 || data.len() % 2 != 0 { return None; }
        let lower = data.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'\n' | b'\r'));
        let upper = data.iter().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F' | b'\n' | b'\r'));
        if !lower && !upper { return None; }

        let clean: Vec<u8> = data.iter().filter(|&&b| b != b'\n' && b != b'\r').copied().collect();
        if clean.len() % 2 != 0 { return None; }
        let decoded: Vec<u8> = clean.chunks(2).filter_map(|c| {
            let hi = hex_nibble(c[0])?;
            let lo = hex_nibble(c[1])?;
            Some((hi << 4) | lo)
        }).collect();

        let score = crate::xor_string_decoder::score_plaintext(&decoded);
        let kind = if lower { CustomEncodingKind::HexLower } else { CustomEncodingKind::HexUpper };
        Some(EncodingPattern { kind, confidence: 0.7 + score * 0.3, decoded })
    }

    fn try_base64(&self, data: &[u8], alpha: &CustomAlphabet, kind: CustomEncodingKind) -> Option<EncodingPattern> {
        let clean: Vec<u8> = data.iter().filter(|&&b| b != b'\n' && b != b'\r').copied().collect();
        if clean.len() < 4 { return None; }
        if !alpha.is_valid_input(&clean) { return None; }

        let ratio = clean.len() as f64 / data.len() as f64;
        if ratio < 0.9 { return None; }

        let decoded = alpha.decode64(&clean).ok()?;
        let text_score = crate::xor_string_decoder::score_plaintext(&decoded);
        let confidence = 0.7 + text_score * 0.3;
        Some(EncodingPattern { kind, confidence, decoded })
    }

    fn try_rot(&self, data: &[u8], n: u8) -> Option<EncodingPattern> {
        // Only try if data looks like ASCII text
        let looks_ascii = data.iter().all(|&b| b.is_ascii());
        if !looks_ascii { return None; }
        let decoded: Vec<u8> = data.iter().map(|&b| rot_byte(b, n)).collect();
        let score = crate::xor_string_decoder::score_plaintext(&decoded);
        if score < 0.4 { return None; }
        let kind = if n == 13 { CustomEncodingKind::Rot13 } else { CustomEncodingKind::RotN(n) };
        Some(EncodingPattern { kind, confidence: 0.5 + score * 0.5, decoded })
    }

    fn try_reversed(&self, data: &[u8]) -> Option<EncodingPattern> {
        if data.len() < 4 { return None; }
        let reversed: Vec<u8> = data.iter().rev().copied().collect();
        let score = crate::xor_string_decoder::score_plaintext(&reversed);
        if score < 0.6 { return None; }
        Some(EncodingPattern { kind: CustomEncodingKind::Reversed, confidence: 0.5 + score * 0.5, decoded: reversed })
    }

    fn try_substitution_table(&self, data: &[u8]) -> Option<EncodingPattern> {
        // Heuristic: if the byte distribution entropy is low but not uniform,
        // and there are ~printable-range bytes, it may be a substitution cipher.
        if data.len() < 8 { return None; }
        let mut freq = [0u32; 256];
        for &b in data { freq[b as usize] += 1; }
        let unique = freq.iter().filter(|&&c| c > 0).count();
        // If very few unique bytes in a long string — probable substitution
        if unique < 10 || unique > 200 { return None; }
        // All bytes in printable range: 0x20–0x7e
        let printable = data.iter().all(|&b| (0x20..=0x7e).contains(&b));
        if !printable { return None; }
        // Cannot decode without the table; return detection only
        Some(EncodingPattern {
            kind: CustomEncodingKind::SubstitutionTable,
            confidence: 0.55,
            decoded: vec![],
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Standalone helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Detect the encoding of `data` using default settings.
#[must_use]
pub fn detect_encoding(data: &[u8]) -> Vec<EncodingPattern> {
    CustomEncodingDetector::new().detect_encoding(data)
}

fn rot_byte(b: u8, n: u8) -> u8 {
    match b {
        b'A'..=b'Z' => b'A' + (b - b'A' + n) % 26,
        b'a'..=b'z' => b'a' + (b - b'a' + n) % 26,
        _ => b,
    }
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_kind_display() {
        assert_eq!(format!("{}", CustomEncodingKind::Base64Standard), "base64-standard");
        assert_eq!(format!("{}", CustomEncodingKind::Rot13), "rot13");
        assert_eq!(format!("{}", CustomEncodingKind::RotN(7)), "rot7");
        assert_eq!(format!("{}", CustomEncodingKind::HexLower), "hex-lower");
    }

    #[test]
    fn custom_alphabet_base64_standard_roundtrip() {
        let alpha = CustomAlphabet::base64_standard();
        let data = b"Hello, world! This is a test.";
        let encoded = alpha.encode64(data);
        let decoded = alpha.decode64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn custom_alphabet_is_valid() {
        let alpha = CustomAlphabet::base64_standard();
        assert!(alpha.is_valid_input(b"SGVsbG8="));
        assert!(!alpha.is_valid_input(b"\x00\x01\x02"));
    }

    #[test]
    fn custom_alphabet_duplicate_char_errors() {
        let bad: Vec<u8> = std::iter::repeat(b'A').take(64).collect();
        assert!(CustomAlphabet::new(&bad, None).is_err());
    }

    #[test]
    fn custom_alphabet_wrong_length_errors() {
        let bad: Vec<u8> = (0u8..16).collect();
        assert!(CustomAlphabet::new(&bad, None).is_err());
    }

    #[test]
    fn detect_encoding_hex_lower() {
        // "Hello" = 48 65 6c 6c 6f
        let patterns = detect_encoding(b"48656c6c6f");
        assert!(patterns.iter().any(|p| p.kind == CustomEncodingKind::HexLower),
            "should detect hex-lower; got: {:?}", patterns.iter().map(|p| &p.kind).collect::<Vec<_>>());
    }

    #[test]
    fn detect_encoding_base64_standard() {
        // base64 of "Hello, World!"
        let patterns = detect_encoding(b"SGVsbG8sIFdvcmxkIQ==");
        assert!(patterns.iter().any(|p| p.kind == CustomEncodingKind::Base64Standard));
        let b64 = patterns.iter().find(|p| p.kind == CustomEncodingKind::Base64Standard).unwrap();
        assert!(b64.confidence > 0.7);
    }

    #[test]
    fn detect_encoding_rot13() {
        // "Hello" ROT13 = "Uryyb"
        let patterns = detect_encoding(b"Uryyb");
        let rot = patterns.iter().find(|p| p.kind == CustomEncodingKind::Rot13);
        assert!(rot.is_some(), "should detect ROT13");
        let rot = rot.unwrap();
        assert_eq!(rot.decoded, b"Hello");
    }

    #[test]
    fn detect_encoding_reversed() {
        // "Hello World" reversed = "dlroW olleH"
        let patterns = detect_encoding(b"dlroW olleH");
        let rev = patterns.iter().find(|p| p.kind == CustomEncodingKind::Reversed);
        assert!(rev.is_some(), "should detect reversed");
        if let Some(p) = rev {
            assert_eq!(p.decoded, b"Hello World");
        }
    }

    #[test]
    fn detect_encoding_garbage_no_confident() {
        let garbage: Vec<u8> = (0..50).map(|i| (i * 37 + 5) as u8).collect();
        let patterns = detect_encoding(&garbage);
        let confident = patterns.iter().filter(|p| p.is_confident()).count();
        // Garbage should not produce many confident detections
        assert!(confident <= 1);
    }

    #[test]
    fn encoding_pattern_decoded_text() {
        let p = EncodingPattern {
            kind: CustomEncodingKind::Rot13,
            confidence: 0.9,
            decoded: b"Hello".to_vec(),
        };
        assert_eq!(p.decoded_text(), "Hello");
        assert!(p.is_confident());
    }

    #[test]
    fn rot_byte_alpha() {
        assert_eq!(rot_byte(b'A', 13), b'N');
        assert_eq!(rot_byte(b'z', 1), b'a');
        assert_eq!(rot_byte(b' ', 13), b' ');
    }

    #[test]
    fn custom_encoding_detector_with_alphabet() {
        let mut det = CustomEncodingDetector::new();
        let alpha = CustomAlphabet::base64_url_safe();
        det.add_alphabet(alpha);
        // data encoded with url-safe base64
        let alpha2 = CustomAlphabet::base64_url_safe();
        let encoded = alpha2.encode64(b"test string here!");
        let results = det.detect_encoding(&encoded);
        assert!(results.iter().any(|p| matches!(p.kind, CustomEncodingKind::Base64UrlSafe | CustomEncodingKind::Base64Custom(_))));
    }

    #[test]
    fn hex_nibble_all_valid() {
        for &(c, expected) in &[(b'0', 0), (b'9', 9), (b'a', 10), (b'f', 15), (b'A', 10), (b'F', 15)] {
            assert_eq!(hex_nibble(c), Some(expected));
        }
        assert_eq!(hex_nibble(b'g'), None);
    }
}
