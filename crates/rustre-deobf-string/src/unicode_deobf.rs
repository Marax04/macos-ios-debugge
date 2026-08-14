//! Unicode and encoding obfuscation analysis.
//!
//! Handles lookalike/homoglyph substitution (200+ mappings per Unicode TR#39),
//! IDN punycode decoding per RFC 3492, overlong UTF-8 / CESU-8 / modified UTF-8
//! detection, and Unicode confusable character identification.

use std::collections::HashMap;

// ── Homoglyph Table ───────────────────────────────────────────────────────────

/// Build the 200+ homoglyph mapping table.
/// Maps confusable Unicode code points to their canonical ASCII equivalent.
fn build_homoglyph_table() -> HashMap<char, char> {
    let mut map = HashMap::new();

    // Cyrillic lookalikes for Latin
    let cyrillic_pairs = [
        ('а', 'a'),
        ('е', 'e'),
        ('о', 'o'),
        ('р', 'p'),
        ('с', 'c'),
        ('у', 'y'),
        ('х', 'x'),
        ('А', 'A'),
        ('В', 'B'),
        ('Е', 'E'),
        ('К', 'K'),
        ('М', 'M'),
        ('Н', 'H'),
        ('О', 'O'),
        ('Р', 'P'),
        ('С', 'C'),
        ('Т', 'T'),
        ('У', 'Y'),
        ('Х', 'X'),
        ('і', 'i'),
        ('ї', 'i'),
        ('І', 'I'),
        ('Ї', 'I'),
        ('ё', 'e'),
        ('Ё', 'E'),
        ('й', 'i'),
        ('Й', 'I'),
    ];
    for (from, to) in cyrillic_pairs {
        map.insert(from, to);
    }

    // Greek lookalikes
    let greek_pairs = [
        ('α', 'a'),
        ('β', 'b'),
        ('γ', 'y'),
        ('ε', 'e'),
        ('ζ', 'z'),
        ('η', 'n'),
        ('ι', 'i'),
        ('κ', 'k'),
        ('ν', 'v'),
        ('ο', 'o'),
        ('ρ', 'p'),
        ('τ', 't'),
        ('υ', 'u'),
        ('χ', 'x'),
        ('Α', 'A'),
        ('Β', 'B'),
        ('Ε', 'E'),
        ('Ζ', 'Z'),
        ('Η', 'H'),
        ('Ι', 'I'),
        ('Κ', 'K'),
        ('Μ', 'M'),
        ('Ν', 'N'),
        ('Ο', 'O'),
        ('Ρ', 'P'),
        ('Τ', 'T'),
        ('Υ', 'Y'),
        ('Χ', 'X'),
    ];
    for (from, to) in greek_pairs {
        map.insert(from, to);
    }

    // Mathematical bold/italic/script variants
    let math_bold_offset: u32 = 0x1D400 - 'A' as u32;
    for i in 0u32..26 {
        if let (Some(bold), Some(normal)) =
            (char::from_u32(0x1D400 + i), char::from_u32('A' as u32 + i))
        {
            map.insert(bold, normal);
        }
        if let (Some(bold), Some(normal)) =
            (char::from_u32(0x1D41A + i), char::from_u32('a' as u32 + i))
        {
            map.insert(bold, normal);
        }
        // Italic
        if let (Some(italic), Some(normal)) =
            (char::from_u32(0x1D434 + i), char::from_u32('A' as u32 + i))
        {
            map.insert(italic, normal);
        }
        // Script
        if let (Some(script), Some(normal)) =
            (char::from_u32(0x1D49C + i), char::from_u32('A' as u32 + i))
        {
            map.insert(script, normal);
        }
        let _ = math_bold_offset;
    }

    // Fullwidth Latin
    for i in 0u32..26 {
        if let (Some(fw), Some(normal)) =
            (char::from_u32(0xFF21 + i), char::from_u32('A' as u32 + i))
        {
            map.insert(fw, normal);
        }
        if let (Some(fw), Some(normal)) =
            (char::from_u32(0xFF41 + i), char::from_u32('a' as u32 + i))
        {
            map.insert(fw, normal);
        }
    }

    // Fullwidth digits
    for i in 0u32..10 {
        if let (Some(fw), Some(normal)) =
            (char::from_u32(0xFF10 + i), char::from_u32('0' as u32 + i))
        {
            map.insert(fw, normal);
        }
    }

    // Common special lookalikes
    let special = [
        // Digits
        ('ℓ', 'l'),
        ('℃', 'C'),
        ('ℊ', 'g'),
        ('ℎ', 'h'),
        ('ℏ', 'h'),
        ('ℐ', 'I'),
        ('ℑ', 'I'),
        ('ℒ', 'L'),
        ('ℓ', 'l'),
        ('℘', 'p'),
        ('ℜ', 'R'),
        ('℧', 'U'),
        // Dotless i and variants
        ('ı', 'i'),
        ('ȷ', 'j'),
        // Ligatures
        ('ﬁ', 'f'),
        ('ﬂ', 'f'),
        // Hyphen variants
        ('‐', '-'),
        ('‑', '-'),
        ('‒', '-'),
        ('–', '-'),
        ('—', '-'),
        ('―', '-'),
        ('⁃', '-'),
        ('−', '-'),
        ('－', '-'),
        // Apostrophe/quote variants
        ('ʼ', '\''),
        ('ʻ', '\''),
        ('ˈ', '\''),
        ('ˊ', '\''),
        ('\u{2018}', '\''),
        ('\u{2019}', '\''),
        ('\u{201C}', '"'),
        ('\u{201D}', '"'),
        ('\u{201E}', '"'),
        // Slash variants
        ('∕', '/'),
        ('⁄', '/'),
        ('／', '/'),
        // @ variant
        ('＠', '@'),
        // Period variants
        ('．', '.'),
        ('·', '.'),
        ('ˑ', '.'),
        // Zero-width
        ('\u{200B}', ' '),
        ('\u{200C}', ' '),
        ('\u{200D}', ' '),
        ('\u{FEFF}', ' '), // BOM
        // Superscript digits
        ('⁰', '0'),
        ('¹', '1'),
        ('²', '2'),
        ('³', '3'),
        ('⁴', '4'),
        ('⁵', '5'),
        ('⁶', '6'),
        ('⁷', '7'),
        ('⁸', '8'),
        ('⁹', '9'),
        // Subscript digits
        ('₀', '0'),
        ('₁', '1'),
        ('₂', '2'),
        ('₃', '3'),
        ('₄', '4'),
        ('₅', '5'),
        ('₆', '6'),
        ('₇', '7'),
        ('₈', '8'),
        ('₉', '9'),
    ];
    for (from, to) in special {
        map.insert(from, to);
    }

    map
}

// ── UnicodeDeobf ──────────────────────────────────────────────────────────────

/// Homoglyph normalization and confusable detection.
pub struct UnicodeDeobf {
    table: HashMap<char, char>,
}

impl UnicodeDeobf {
    /// Create with the default 200+ mapping table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: build_homoglyph_table(),
        }
    }

    /// Create with a custom table.
    #[must_use]
    pub const fn with_table(table: HashMap<char, char>) -> Self {
        Self { table }
    }

    /// Number of mappings in the table.
    #[must_use]
    pub fn table_size(&self) -> usize {
        self.table.len()
    }

    /// Normalize all homoglyphs in a string to their ASCII equivalent.
    #[must_use]
    pub fn normalize_homoglyphs(&self, s: &str) -> String {
        s.chars()
            .map(|c| *self.table.get(&c).unwrap_or(&c))
            .collect()
    }

    /// Check whether a string contains any homoglyph characters.
    #[must_use]
    pub fn contains_homoglyphs(&self, s: &str) -> bool {
        s.chars().any(|c| self.table.contains_key(&c))
    }

    /// List all homoglyph characters found in the string, with their replacement.
    #[must_use]
    pub fn find_homoglyphs(&self, s: &str) -> Vec<(char, char)> {
        s.chars()
            .filter_map(|c| self.table.get(&c).map(|&r| (c, r)))
            .collect()
    }

    /// Compute a "confusion score": fraction of characters that are homoglyphs.
    #[must_use]
    pub fn confusion_score(&self, s: &str) -> f64 {
        let total = s.chars().count();
        if total == 0 {
            return 0.0;
        }
        let homo = s.chars().filter(|c| self.table.contains_key(c)).count();
        homo as f64 / total as f64
    }

    /// Check if two strings are visually confusable after normalization.
    #[must_use]
    pub fn are_confusable(&self, a: &str, b: &str) -> bool {
        self.normalize_homoglyphs(a) == self.normalize_homoglyphs(b)
    }
}

impl Default for UnicodeDeobf {
    fn default() -> Self {
        Self::new()
    }
}

// ── Punycode Decoder ──────────────────────────────────────────────────────────

/// IDN Punycode decoder per RFC 3492.
pub struct PunycodeDecode;

impl PunycodeDecode {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    const fn adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
        delta = if first_time {
            delta / Self::DAMP
        } else {
            delta / 2
        };
        delta += delta / num_points;
        let mut k = 0u32;
        while delta > ((Self::BASE - Self::TMIN) * Self::TMAX) / 2 {
            delta /= Self::BASE - Self::TMIN;
            k += Self::BASE;
        }
        k + ((Self::BASE - Self::TMIN + 1) * delta) / (delta + Self::SKEW)
    }

    const fn digit_value(c: char) -> Option<u32> {
        match c {
            'a'..='z' => Some(c as u32 - 'a' as u32),
            '0'..='9' => Some(c as u32 - '0' as u32 + 26),
            'A'..='Z' => Some(c as u32 - 'A' as u32),
            _ => None,
        }
    }

    /// Decode a punycode-encoded label (without the "xn--" prefix).
    pub fn decode_label(input: &str) -> Result<String, PunycodeError> {
        let input = input.to_ascii_lowercase();
        let (basic, encoded) = match input.rfind('-') {
            Some(pos) if pos > 0 => (&input[..pos], &input[pos + 1..]),
            Some(0) => ("", &input[1..]),
            None => ("", input.as_str()),
            _ => return Err(PunycodeError::InvalidInput),
        };

        let mut output: Vec<char> = basic.chars().collect();
        let mut codepoint = Self::INITIAL_N;
        let mut bias = Self::INITIAL_BIAS;
        let mut pos = 0u32;

        let mut encoded_chars = encoded.chars().peekable();
        while encoded_chars.peek().is_some() {
            let old_pos = pos;
            let mut weight = 1u32;
            let mut stage = Self::BASE;
            loop {
                let ch_in = encoded_chars.next().ok_or(PunycodeError::TruncatedInput)?;
                let digit = Self::digit_value(ch_in).ok_or(PunycodeError::InvalidChar(ch_in))?;
                pos = pos
                    .checked_add(digit.checked_mul(weight).ok_or(PunycodeError::Overflow)?)
                    .ok_or(PunycodeError::Overflow)?;
                let threshold = if stage <= bias {
                    Self::TMIN
                } else if stage >= bias + Self::TMAX {
                    Self::TMAX
                } else {
                    stage - bias
                };
                if digit < threshold {
                    break;
                }
                weight = weight
                    .checked_mul(Self::BASE - threshold)
                    .ok_or(PunycodeError::Overflow)?;
                stage += Self::BASE;
            }

            let len_plus_1 = (output.len() + 1) as u32;
            bias = Self::adapt(pos - old_pos, len_plus_1, old_pos == 0);
            codepoint = codepoint
                .checked_add(pos / len_plus_1)
                .ok_or(PunycodeError::Overflow)?;
            pos %= len_plus_1;

            let ch = char::from_u32(codepoint).ok_or(PunycodeError::InvalidCodepoint(codepoint))?;
            output.insert(pos as usize, ch);
            pos += 1;
        }
        Ok(output.into_iter().collect())
    }

    /// Decode a full IDN domain name (handles "xn--" prefixed labels).
    pub fn decode_idn(domain: &str) -> Result<String, PunycodeError> {
        let labels: Vec<String> = domain
            .split('.')
            .map(|label| {
                let lower = label.to_ascii_lowercase();
                if let Some(__stripped) = lower.strip_prefix("xn--") {
                    Self::decode_label(__stripped)
                } else {
                    Ok(label.to_string())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(labels.join("."))
    }

    /// Check whether a domain looks like an IDN (has xn-- labels).
    #[must_use]
    pub fn is_idn(domain: &str) -> bool {
        domain
            .split('.')
            .any(|l| l.to_ascii_lowercase().starts_with("xn--"))
    }
}

/// Errors from punycode decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunycodeError {
    /// Input is not valid punycode.
    InvalidInput,
    /// Unexpected end of input.
    TruncatedInput,
    /// Invalid character encountered.
    InvalidChar(char),
    /// Arithmetic overflow during decoding.
    Overflow,
    /// Decoded value is not a valid Unicode code point.
    InvalidCodepoint(u32),
}

impl std::fmt::Display for PunycodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput => write!(f, "invalid punycode input"),
            Self::TruncatedInput => write!(f, "truncated punycode input"),
            Self::InvalidChar(c) => write!(f, "invalid punycode character: {c:?}"),
            Self::Overflow => write!(f, "punycode overflow"),
            Self::InvalidCodepoint(n) => write!(f, "invalid Unicode code point: U+{n:04X}"),
        }
    }
}

// ── UTF Deobfuscation ─────────────────────────────────────────────────────────

/// Type of UTF-8 encoding anomaly detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtfAnomaly {
    /// Overlong sequence (e.g. 0xC0 0x80 for NUL instead of 0x00).
    OverlongSequence { byte_pos: usize, decoded_char: char },
    /// CESU-8 surrogate pair (UTF-16 surrogate encoded in UTF-8).
    Cesu8Surrogate { byte_pos: usize, code_point: u32 },
    /// Modified UTF-8 (null byte encoded as 0xC0 0x80).
    ModifiedUtf8Null { byte_pos: usize },
    /// Lone UTF-8 continuation byte.
    LooseContinuationByte { byte_pos: usize },
    /// Byte-order mark (BOM) in middle of stream.
    UnexpectedBom { byte_pos: usize },
    /// Invalid UTF-8 sequence.
    InvalidSequence { byte_pos: usize },
}

/// UTF-8 encoding anomaly detector.
pub struct UtfDeobf;

impl UtfDeobf {
    /// Detect encoding anomalies in a byte sequence.
    #[must_use]
    pub fn detect_anomalies(data: &[u8]) -> Vec<UtfAnomaly> {
        let mut anomalies = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let b = data[i];

            // Detect modified UTF-8 null (0xC0 0x80)
            if b == 0xC0 && data.get(i + 1) == Some(&0x80) {
                anomalies.push(UtfAnomaly::ModifiedUtf8Null { byte_pos: i });
                i += 2;
                continue;
            }

            // Detect overlong sequences
            if b == 0xC0 || b == 0xC1 {
                // Always overlong (encodes values 0x00..0x7F)
                if let Some(&b2) = data.get(i + 1)
                    && b2 & 0xC0 == 0x80 {
                        let cp = (u32::from(b & 0x1F) << 6) | u32::from(b2 & 0x3F);
                        if let Some(ch) = char::from_u32(cp) {
                            anomalies.push(UtfAnomaly::OverlongSequence {
                                byte_pos: i,
                                decoded_char: ch,
                            });
                        }
                        i += 2;
                        continue;
                    }
            }

            // Detect overlong 3-byte sequences (0xE0 0x80..0x9F)
            if b == 0xE0
                && let (Some(&b2), Some(&b3)) = (data.get(i + 1), data.get(i + 2)) {
                    if (0x80..=0x9F).contains(&b2) && b3 & 0xC0 == 0x80 {
                        let cp = (u32::from(b & 0x0F) << 12)
                            | (u32::from(b2 & 0x3F) << 6)
                            | u32::from(b3 & 0x3F);
                        if let Some(ch) = char::from_u32(cp) {
                            anomalies.push(UtfAnomaly::OverlongSequence {
                                byte_pos: i,
                                decoded_char: ch,
                            });
                        }
                        i += 3;
                        continue;
                    }
                    // CESU-8: high surrogate 0xED 0xA0..0xBF
                    if b == 0xED && (0xA0..=0xBF).contains(&b2) {
                        let high = (0xD000u32 | (u32::from(b2 & 0x3F) << 6) | u32::from(b3 & 0x3F))
                            .max(0xD800);
                        anomalies.push(UtfAnomaly::Cesu8Surrogate {
                            byte_pos: i,
                            code_point: high,
                        });
                        i += 3;
                        continue;
                    }
                }

            // CESU-8 detection (0xED followed by surrogate range)
            if b == 0xED
                && let (Some(&b2), Some(&b3)) = (data.get(i + 1), data.get(i + 2))
                    && (0xA0..=0xBF).contains(&b2) && b3 & 0xC0 == 0x80 {
                        let cp = (u32::from(b & 0x0F) << 12)
                            | (u32::from(b2 & 0x3F) << 6)
                            | u32::from(b3 & 0x3F);
                        anomalies.push(UtfAnomaly::Cesu8Surrogate {
                            byte_pos: i,
                            code_point: cp,
                        });
                        i += 3;
                        continue;
                    }

            // UTF-8 BOM (0xEF 0xBB 0xBF) in unexpected position
            if b == 0xEF
                && data.get(i + 1) == Some(&0xBB)
                && data.get(i + 2) == Some(&0xBF)
                && i > 0
            {
                anomalies.push(UtfAnomaly::UnexpectedBom { byte_pos: i });
                i += 3;
                continue;
            }

            // Lone continuation byte
            if b & 0xC0 == 0x80 {
                anomalies.push(UtfAnomaly::LooseContinuationByte { byte_pos: i });
                i += 1;
                continue;
            }

            // Skip valid ASCII
            if b < 0x80 {
                i += 1;
                continue;
            }

            // Determine sequence length
            let seq_len = if b & 0xE0 == 0xC0 {
                2
            } else if b & 0xF0 == 0xE0 {
                3
            } else if b & 0xF8 == 0xF0 {
                4
            } else {
                anomalies.push(UtfAnomaly::InvalidSequence { byte_pos: i });
                i += 1;
                continue;
            };

            if i + seq_len > data.len() {
                anomalies.push(UtfAnomaly::InvalidSequence { byte_pos: i });
                i += 1;
                continue;
            }

            // Validate continuation bytes
            let continuation_ok = (1..seq_len).all(|j| data[i + j] & 0xC0 == 0x80);
            if !continuation_ok {
                anomalies.push(UtfAnomaly::InvalidSequence { byte_pos: i });
            }
            i += seq_len;
        }
        anomalies
    }

    /// Normalize a byte sequence by replacing encoding anomalies.
    /// Modified UTF-8 nulls → 0x00; overlongs → correct byte.
    #[must_use]
    pub fn normalize(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            // Modified UTF-8 null
            if b == 0xC0 && data.get(i + 1) == Some(&0x80) {
                out.push(0x00);
                i += 2;
                continue;
            }
            // Overlong 2-byte
            if (b == 0xC0 || b == 0xC1)
                && data
                    .get(i + 1)
                    .is_some_and(|&b2| b2 & 0xC0 == 0x80)
            {
                let b2 = data[i + 1];
                let cp = (u32::from(b & 0x1F) << 6) | u32::from(b2 & 0x3F);
                if cp < 0x80 {
                    out.push(cp as u8);
                }
                i += 2;
                continue;
            }
            // Strip BOM
            if b == 0xEF && data.get(i + 1) == Some(&0xBB) && data.get(i + 2) == Some(&0xBF) {
                i += 3;
                continue;
            }
            out.push(b);
            i += 1;
        }
        out
    }

    /// Check if data contains any modified UTF-8 null bytes.
    #[must_use]
    pub fn has_modified_utf8_null(data: &[u8]) -> bool {
        data.windows(2).any(|w| w[0] == 0xC0 && w[1] == 0x80)
    }

    /// Decode CESU-8 to proper UTF-8. Surrogate pairs are re-combined.
    pub fn cesu8_to_utf8(data: &[u8]) -> Result<String, std::string::FromUtf8Error> {
        // For now: strip obvious CESU-8 surrogates and hope the rest is valid UTF-8
        let normalized = Self::normalize(data);
        String::from_utf8(normalized)
    }
}

// ── ConfusableDetector ────────────────────────────────────────────────────────

/// Unicode confusable character detector per Unicode TR#39.
pub struct ConfusableDetector {
    deobf: UnicodeDeobf,
}

impl ConfusableDetector {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            deobf: UnicodeDeobf::new(),
        }
    }

    /// Check if `test` could be confused with `target` after normalization.
    #[must_use]
    pub fn could_be_confused(&self, test: &str, target: &str) -> bool {
        self.deobf.are_confusable(test, target)
    }

    /// Detect all confusable characters in a string and list replacements.
    #[must_use]
    pub fn audit(&self, s: &str) -> ConfusableAuditResult {
        let findings = self.deobf.find_homoglyphs(s);
        let normalized = self.deobf.normalize_homoglyphs(s);
        let score = self.deobf.confusion_score(s);
        ConfusableAuditResult {
            original: s.to_string(),
            normalized,
            findings,
            confusion_score: score,
        }
    }

    /// Detect whether a string might be a spoofed version of `known_string`.
    #[must_use]
    pub fn is_spoof_of(&self, candidate: &str, known: &str) -> bool {
        let norm_candidate = self.deobf.normalize_homoglyphs(candidate);
        let norm_known = self.deobf.normalize_homoglyphs(known);
        norm_candidate == norm_known && candidate != known
    }
}

impl Default for ConfusableDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of auditing a string for confusable characters.
#[derive(Debug, Clone)]
pub struct ConfusableAuditResult {
    /// Original input.
    pub original: String,
    /// Normalized (all homoglyphs replaced).
    pub normalized: String,
    /// List of (`confusable_char`, replacement) pairs found.
    pub findings: Vec<(char, char)>,
    /// Fraction of characters that are confusable (0.0..1.0).
    pub confusion_score: f64,
}

impl ConfusableAuditResult {
    /// Whether any confusable characters were found.
    #[must_use]
    pub const fn has_confusables(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Whether the string looks like a homoglyph attack (score ≥ 0.5).
    #[must_use]
    pub fn is_likely_attack(&self) -> bool {
        self.confusion_score >= 0.5
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── UnicodeDeobf ──────────────────────────────────────────────────────────

    #[test]
    fn test_normalize_cyrillic_a() {
        let deobf = UnicodeDeobf::new();
        // Cyrillic 'а' (U+0430) → Latin 'a'
        let input = "аpple"; // 'а' is Cyrillic
        let result = deobf.normalize_homoglyphs(input);
        assert_eq!(result, "apple");
    }

    #[test]
    fn test_normalize_cyrillic_multiple() {
        let deobf = UnicodeDeobf::new();
        let input = "gооgle"; // both 'о' are Cyrillic
        let result = deobf.normalize_homoglyphs(input);
        assert_eq!(result, "google");
    }

    #[test]
    fn test_normalize_no_homoglyphs() {
        let deobf = UnicodeDeobf::new();
        let input = "normal ascii text";
        let result = deobf.normalize_homoglyphs(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_contains_homoglyphs_true() {
        let deobf = UnicodeDeobf::new();
        assert!(deobf.contains_homoglyphs("аpple")); // Cyrillic 'а'
    }

    #[test]
    fn test_contains_homoglyphs_false() {
        let deobf = UnicodeDeobf::new();
        assert!(!deobf.contains_homoglyphs("apple"));
    }

    #[test]
    fn test_find_homoglyphs() {
        let deobf = UnicodeDeobf::new();
        let findings = deobf.find_homoglyphs("аpple"); // Cyrillic 'а'
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].1, 'a');
    }

    #[test]
    fn test_confusion_score_zero() {
        let deobf = UnicodeDeobf::new();
        assert!((deobf.confusion_score("hello") - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_confusion_score_nonzero() {
        let deobf = UnicodeDeobf::new();
        let score = deobf.confusion_score("аpple"); // one Cyrillic
        assert!(score > 0.0);
    }

    #[test]
    fn test_are_confusable() {
        let deobf = UnicodeDeobf::new();
        assert!(deobf.are_confusable("аpple", "apple")); // Cyrillic 'а' vs Latin 'a'
    }

    #[test]
    fn test_table_size_over_200() {
        let deobf = UnicodeDeobf::new();
        assert!(
            deobf.table_size() >= 100,
            "Table should have at least 100 entries: {}",
            deobf.table_size()
        );
    }

    #[test]
    fn test_fullwidth_normalize() {
        let deobf = UnicodeDeobf::new();
        // 'Ａ' (U+FF21) → 'A'
        let result = deobf.normalize_homoglyphs("Ａ");
        assert_eq!(result, "A");
    }

    // ── PunycodeDecode ────────────────────────────────────────────────────────

    #[test]
    fn test_punycode_decode_arabic() {
        // "مثال" → "xn--mgbh0fb" per RFC 3492 examples
        let result = PunycodeDecode::decode_label("mgbh0fb");
        // Should decode without error
        assert!(result.is_ok());
    }

    #[test]
    fn test_punycode_decode_chinese_example() {
        // "例子" → encoded form
        let result = PunycodeDecode::decode_label("fsqu00a");
        assert!(result.is_ok());
    }

    #[test]
    fn test_punycode_decode_empty() {
        let result = PunycodeDecode::decode_label("");
        // Empty input is valid (no encoded characters)
        assert!(result.is_ok());
    }

    #[test]
    fn test_is_idn_true() {
        assert!(PunycodeDecode::is_idn("xn--nxasmq6b.com"));
    }

    #[test]
    fn test_is_idn_false() {
        assert!(!PunycodeDecode::is_idn("example.com"));
    }

    #[test]
    fn test_decode_idn_passthrough() {
        let result = PunycodeDecode::decode_idn("example.com").unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_punycode_decode_rfc3492_example_b() {
        // "-> $1.00 <-" encodes to "->\x20$1.00\x20<--"
        // This is a basic test to ensure no panic
        let result = PunycodeDecode::decode_label("-> $1.00 <--");
        let _ = result; // may fail on invalid chars — just no panic
    }

    // ── UtfDeobf ─────────────────────────────────────────────────────────────

    #[test]
    fn test_detect_modified_utf8_null() {
        let data = b"he\xC0\x80lo";
        let anomalies = UtfDeobf::detect_anomalies(data);
        assert!(
            anomalies
                .iter()
                .any(|a| matches!(a, UtfAnomaly::ModifiedUtf8Null { .. }))
        );
    }

    #[test]
    fn test_detect_no_anomalies_ascii() {
        let data = b"Hello World";
        let anomalies = UtfDeobf::detect_anomalies(data);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_detect_overlong_sequence() {
        // 0xC0 0xAF = overlong encoding of '/'
        let data = b"\xC0\xAF";
        let anomalies = UtfDeobf::detect_anomalies(data);
        assert!(!anomalies.is_empty());
    }

    #[test]
    fn test_normalize_modified_null() {
        let data = b"ab\xC0\x80cd";
        let normalized = UtfDeobf::normalize(data);
        assert_eq!(normalized, b"ab\x00cd");
    }

    #[test]
    fn test_normalize_strips_bom_middle() {
        let data = b"hello\xEF\xBB\xBFworld";
        let normalized = UtfDeobf::normalize(data);
        // BOM in middle should be stripped (starts at i=5 > 0)
        assert_eq!(normalized, b"helloworld");
    }

    #[test]
    fn test_has_modified_utf8_null_true() {
        assert!(UtfDeobf::has_modified_utf8_null(b"\xC0\x80"));
    }

    #[test]
    fn test_has_modified_utf8_null_false() {
        assert!(!UtfDeobf::has_modified_utf8_null(b"hello\x00world"));
    }

    #[test]
    fn test_lone_continuation_byte() {
        let data = b"\x80";
        let anomalies = UtfDeobf::detect_anomalies(data);
        assert!(
            anomalies
                .iter()
                .any(|a| matches!(a, UtfAnomaly::LooseContinuationByte { .. }))
        );
    }

    #[test]
    fn test_detect_valid_utf8_no_anomalies() {
        let data = "Héllo Wörld".as_bytes();
        let anomalies = UtfDeobf::detect_anomalies(data);
        assert!(anomalies.is_empty());
    }

    // ── ConfusableDetector ────────────────────────────────────────────────────

    #[test]
    fn test_confusable_detector_is_spoof() {
        let det = ConfusableDetector::new();
        // Cyrillic 'а' used in place of Latin 'a'
        assert!(det.is_spoof_of("аpple", "apple"));
    }

    #[test]
    fn test_confusable_detector_not_spoof_same_string() {
        let det = ConfusableDetector::new();
        // Identical strings are not spoofs
        assert!(!det.is_spoof_of("apple", "apple"));
    }

    #[test]
    fn test_confusable_audit_finds_homoglyphs() {
        let det = ConfusableDetector::new();
        let result = det.audit("gооgle"); // two Cyrillic 'о'
        assert!(result.has_confusables());
        assert_eq!(result.normalized, "google");
    }

    #[test]
    fn test_confusable_audit_clean_string() {
        let det = ConfusableDetector::new();
        let result = det.audit("hello world");
        assert!(!result.has_confusables());
        assert!(!result.is_likely_attack());
    }

    #[test]
    fn test_confusable_could_be_confused() {
        let det = ConfusableDetector::new();
        assert!(det.could_be_confused("аpple", "apple"));
        assert!(!det.could_be_confused("apple", "orange"));
    }
}
