//! Encoded-string decoder for `rustre-analysis-string`.
//!
//! Decodes strings that have been obfuscated or transported via a secondary
//! encoding layer on top of their raw character data:
//!
//! * **Base64** — standard RFC 4648, URL-safe (`-_`), and custom alphabets.
//! * **Hex encoding** — lowercase / uppercase / mixed pairs.
//! * **URL percent-encoding** — `%XX` sequences.
//! * **HTML entities** — `&amp;`, `&#xNN;`, `&#DDD;`.
//! * **Unicode escapes** — `\uXXXX` and `\UXXXXXXXX`.
//! * **ROT-13** — letter rotation cipher.
//! * **XOR single-byte** — auto-detect key via frequency analysis.
//! * **Custom XOR key** — caller-supplied key.
//! * **Common regex patterns** — pattern library for recognising typical
//!   obfuscation schemes before attempting decoding.

// ─────────────────────────────────────────────────────────────────────────────
// Base64
// ─────────────────────────────────────────────────────────────────────────────

/// A Base64 alphabet descriptor.
#[derive(Debug, Clone)]
pub struct Base64Alphabet {
    /// Name of this variant (e.g. `"standard"`, `"url_safe"`, `"custom"`).
    pub name: String,
    /// 64-character alphabet, in value order 0..63.
    pub chars: [u8; 64],
    /// Padding character (typically `=`; `None` if no padding is used).
    pub padding: Option<u8>,
}

impl Base64Alphabet {
    /// Standard RFC 4648 alphabet (`A–Z a–z 0–9 + /`).
    #[must_use]
    pub fn standard() -> Self {
        Self {
            name: "standard".into(),
            chars: *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            padding: Some(b'='),
        }
    }

    /// RFC 4648 §5 URL-safe alphabet (`A–Z a–z 0–9 - _`).
    #[must_use]
    pub fn url_safe() -> Self {
        Self {
            name: "url_safe".into(),
            chars: *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
            padding: Some(b'='),
        }
    }

    /// Build a reverse lookup table from character to value.
    #[must_use]
    pub fn reverse_table(&self) -> [u8; 256] {
        let mut table = [0xFFu8; 256];
        for (val, &ch) in self.chars.iter().enumerate() {
            table[ch as usize] = u8::try_from(val).unwrap_or(0xFF);
        }
        if let Some(pad) = self.padding {
            table[pad as usize] = 0xFE; // sentinel for padding
        }
        table
    }

    /// Decode `input` using this alphabet.  Returns `None` on invalid input.
    #[must_use]
    pub fn decode(&self, input: &[u8]) -> Option<Vec<u8>> {
        let table = self.reverse_table();
        let mut output = Vec::with_capacity(input.len() * 3 / 4 + 1);
        let mut buf = [0u8; 4];
        let mut buf_len = 0usize;

        for &byte in input {
            if byte == b'\n' || byte == b'\r' || byte == b' ' {
                continue;
            }
            let val = table[byte as usize];
            if val == 0xFE {
                // Padding — stop.
                break;
            }
            if val == 0xFF {
                return None; // invalid character
            }
            buf[buf_len] = val;
            buf_len += 1;
            if buf_len == 4 {
                output.push((buf[0] << 2) | (buf[1] >> 4));
                output.push((buf[1] << 4) | (buf[2] >> 2));
                output.push((buf[2] << 6) | buf[3]);
                buf_len = 0;
            }
        }

        // Handle remaining bytes.
        match buf_len {
            2 => output.push((buf[0] << 2) | (buf[1] >> 4)),
            3 => {
                output.push((buf[0] << 2) | (buf[1] >> 4));
                output.push((buf[1] << 4) | (buf[2] >> 2));
            }
            0 => {}
            _ => return None, // 1 leftover sextet is invalid base64
        }

        Some(output)
    }
}

/// Try to decode `input` as Base64 using standard, then URL-safe, then no-padding
/// alphabets.  Returns the decoded bytes and the alphabet name.
#[must_use]
pub fn decode_base64_auto(input: &[u8]) -> Option<(Vec<u8>, String)> {
    let alphabets = [Base64Alphabet::standard(), Base64Alphabet::url_safe()];
    for alpha in &alphabets {
        if let Some(decoded) = alpha.decode(input)
            && !decoded.is_empty()
        {
            return Some((decoded, alpha.name.clone()));
        }
    }
    None
}

/// Return `true` if `input` looks like a Base64 string.
#[must_use]
pub fn is_likely_base64(input: &[u8]) -> bool {
    if input.len() < 4 || !input.len().is_multiple_of(4) {
        // Allow non-padded b64 of reasonable length.
        if input.len() < 4 { return false; }
    }
    let valid: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_\n\r ";
    input.iter().all(|b| valid.contains(b))
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex decoding
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a hex-encoded string (e.g. `"48656c6c6f"`).
///
/// Accepts uppercase, lowercase, and mixed hex.  Optionally tolerates spaces
/// or colons between byte pairs (e.g. `"48:65:6C:6C:6F"`).
#[must_use]
pub fn decode_hex(input: &str) -> Option<Vec<u8>> {
    // Strip delimiters.
    let clean: String = input
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect();

    if !clean.len().is_multiple_of(2) || clean.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();

    for pair in bytes.chunks(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }

    Some(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Return `true` if `input` looks like hex-encoded data (even length, all hex
/// digits, optionally separated by spaces/colons).
#[must_use]
pub fn is_likely_hex(input: &str) -> bool {
    // Only hex digits and the documented separators (spaces/colons) are
    // allowed; previously arbitrary characters were silently dropped, so
    // strings like "zz!ed" were misclassified as hex.
    if !input
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == ' ' || c == ':')
    {
        return false;
    }
    let clean: String = input.chars().filter(char::is_ascii_hexdigit).collect();
    !clean.is_empty() && clean.len().is_multiple_of(2)
}

// ─────────────────────────────────────────────────────────────────────────────
// URL percent-decoding
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a URL percent-encoded string (e.g. `"Hello%20World"`).
#[must_use]
pub fn decode_url(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML entity decoding
// ─────────────────────────────────────────────────────────────────────────────

/// Decode HTML entities in `input`.
///
/// Handles:
/// * Named entities: `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&nbsp;`.
/// * Decimal numeric: `&#123;`.
/// * Hex numeric: `&#x7B;`.
#[must_use]
pub fn decode_html_entities(input: &str) -> String {
    let named: &[(&str, &str)] = &[
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&apos;", "'"),
        ("&nbsp;", "\u{00A0}"),
        ("&copy;", "©"),
        ("&reg;", "®"),
    ];

    // Numeric entities first.
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'&' && i + 2 < bytes.len() && bytes[i + 1] == b'#' {
            // Find closing `;`.
            if let Some(semi) = bytes[i..].iter().position(|&b| b == b';') {
                let inner = &input[i + 2..i + semi];
                let cp = if inner.starts_with('x') || inner.starts_with('X') {
                    u32::from_str_radix(&inner[1..], 16).ok()
                } else {
                    inner.parse::<u32>().ok()
                };
                if let Some(cp) = cp
                    && let Some(c) = char::from_u32(cp)
                {
                    result.push(c);
                    i += semi + 1;
                    continue;
                }
            }
        }
        let c = input[i..].chars().next().expect("i is on a char boundary");
        result.push(c);
        i += c.len_utf8();
    }

    // Named entity substitution.
    let mut out = result;
    for (entity, replacement) in named {
        out = out.replace(entity, replacement);
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Unicode escape decoding
// ─────────────────────────────────────────────────────────────────────────────

/// Decode `\uXXXX` and `\UXXXXXXXX` Unicode escape sequences.
#[must_use]
pub fn decode_unicode_escapes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0usize;

    while i < len {
        if chars[i] == '\\' && i + 1 < len {
            match chars[i + 1] {
                'u' if i + 6 <= len => {
                    let hex: String = chars[i + 2..i + 6].iter().collect();
                    if let Ok(cp) = u32::from_str_radix(&hex, 16)
                        && let Some(c) = char::from_u32(cp)
                    {
                        result.push(c);
                        i += 6;
                        continue;
                    }
                }
                'U' if i + 10 <= len => {
                    let hex: String = chars[i + 2..i + 10].iter().collect();
                    if let Ok(cp) = u32::from_str_radix(&hex, 16)
                        && let Some(c) = char::from_u32(cp)
                    {
                        result.push(c);
                        i += 10;
                        continue;
                    }
                }
                'n' => { result.push('\n'); i += 2; continue; }
                'r' => { result.push('\r'); i += 2; continue; }
                't' => { result.push('\t'); i += 2; continue; }
                '\\' => { result.push('\\'); i += 2; continue; }
                _ => {}
            }
        }
        result.push(chars[i]);
        i += 1;
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// ROT-13
// ─────────────────────────────────────────────────────────────────────────────

/// Apply ROT-13 to `input` (letters only; other characters pass through).
#[must_use]
pub fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'A'..='Z' => char::from(b'A' + (c as u8 - b'A' + 13) % 26),
            'a'..='z' => char::from(b'a' + (c as u8 - b'a' + 13) % 26),
            _ => c,
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR decoding
// ─────────────────────────────────────────────────────────────────────────────

/// Decode `data` by XOR-ing every byte with `key`.
#[must_use]
pub fn xor_single(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

/// Decode `data` by XOR-ing with a repeating multi-byte `key`.
#[must_use]
pub fn xor_multi(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Attempt to auto-detect the single-byte XOR key by frequency analysis.
///
/// Assumes the plaintext is ASCII text with space (`0x20`) as the most common
/// byte, so the most frequent ciphertext byte XOR `0x20` is the candidate key.
///
/// Returns `None` when the input carries no frequency signal to reason from:
/// an empty buffer, or one where every present byte occurs equally often (a
/// permutation, a counter, a ramp) so "most frequent" is an arbitrary pick.
///
/// # Why this returns an `Option`
///
/// It used to return a bare `u8`, which cannot express "this is not
/// XOR-encoded". On an EMPTY buffer `max_by_key` selected index 0 and the
/// function confidently answered `0x00 ^ 0x20 = 0x20` — a key, for no data.
/// On unencrypted input it likewise always produced some key. The sibling
/// detector in `crate::detect_xor_key` has always returned `Option<u8>`; this
/// one now agrees, so neither can silently promise a key it did not find.
#[must_use]
pub fn detect_xor_key(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let (most_frequent, top_count) = freq
        .iter()
        .enumerate()
        .max_by_key(|(_, c)| *c)
        .map(|(i, c)| (u8::try_from(i).unwrap_or(0), *c))?;

    // No signal: every byte that occurs, occurs the same number of times, so
    // the "most frequent" byte is whichever one the scan happened to see
    // first. Frequency analysis has nothing to say about such a buffer.
    let distinct_at_top = freq.iter().filter(|&&c| c == top_count).count();
    if distinct_at_top > 1 && freq.iter().filter(|&&c| c > 0).count() == distinct_at_top {
        return None;
    }

    // XOR with 0x20 (space) to get candidate key.
    Some(most_frequent ^ 0x20)
}

/// Auto-detect the key and decode with it.
///
/// `None` when [`detect_xor_key`] finds no key — decoding with a key that was
/// never found would return plausible-looking bytes that mean nothing.
#[must_use]
pub fn decode_xor_auto(data: &[u8]) -> Option<(Vec<u8>, u8)> {
    let key = detect_xor_key(data)?;
    Some((xor_single(data, key), key))
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern-library for obfuscation recognition
// ─────────────────────────────────────────────────────────────────────────────

/// Known obfuscation patterns for quick pre-screening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationPattern {
    Base64Standard,
    Base64UrlSafe,
    HexEncoded,
    UrlEncoded,
    HtmlEntities,
    UnicodeEscapes,
    Rot13,
    XorSingleByte,
    XorMultiByte,
}

impl ObfuscationPattern {
    /// Return a short label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Base64Standard => "base64_standard",
            Self::Base64UrlSafe => "base64_url_safe",
            Self::HexEncoded => "hex",
            Self::UrlEncoded => "url_encoded",
            Self::HtmlEntities => "html_entities",
            Self::UnicodeEscapes => "unicode_escapes",
            Self::Rot13 => "rot13",
            Self::XorSingleByte => "xor_single",
            Self::XorMultiByte => "xor_multi",
        }
    }
}

/// Detect likely obfuscation patterns in a byte slice.
#[must_use]
pub fn detect_obfuscation_patterns(data: &[u8]) -> Vec<ObfuscationPattern> {
    let mut patterns = Vec::new();

    let s = std::str::from_utf8(data).unwrap_or("");

    // Base64 check.
    if is_likely_base64(data) {
        if data.iter().any(|&b| b == b'-' || b == b'_') {
            patterns.push(ObfuscationPattern::Base64UrlSafe);
        } else {
            patterns.push(ObfuscationPattern::Base64Standard);
        }
    }

    // Hex check.
    if is_likely_hex(s) && data.len() >= 4 {
        patterns.push(ObfuscationPattern::HexEncoded);
    }

    // URL encoding check.
    if s.contains('%') && s.chars().filter(|&c| c == '%').count() >= 1 {
        let pct: usize = s.chars().filter(|&c| c == '%').count();
        let len = s.len();
        if pct * 3 < len {
            patterns.push(ObfuscationPattern::UrlEncoded);
        }
    }

    // HTML entity check.
    if s.contains("&amp;") || s.contains("&lt;") || s.contains("&#") {
        patterns.push(ObfuscationPattern::HtmlEntities);
    }

    // Unicode escape check.
    if s.contains("\\u") || s.contains("\\U") {
        patterns.push(ObfuscationPattern::UnicodeEscapes);
    }

    // ROT-13 heuristic: if decoding produces more ASCII printable than raw.
    if data.iter().all(|b| b.is_ascii_alphabetic() || b.is_ascii_whitespace()) {
        let decoded = rot13(s);
        // If decoded has more common English letters, flag as possible ROT-13.
        let eng_freq = |t: &str| -> usize {
            t.chars().filter(|c| matches!(c, 'e'|'t'|'a'|'o'|'i'|'n'|'s'|'h'|'r')).count()
        };
        if eng_freq(&decoded) > eng_freq(s) + 2 {
            patterns.push(ObfuscationPattern::Rot13);
        }
    }

    patterns
}

// ─────────────────────────────────────────────────────────────────────────────
// Universal decoder
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a universal decode attempt.
#[derive(Debug, Clone)]
pub struct UniversalDecodeResult {
    /// The decoded plaintext string.
    pub text: String,
    /// Obfuscation pattern that was detected and applied.
    pub pattern: ObfuscationPattern,
    /// Whether the decoding produced valid UTF-8.
    pub is_valid_utf8: bool,
}

/// Try all known decoding strategies on `data` and return all successful results.
#[must_use]
pub fn universal_decode(data: &[u8]) -> Vec<UniversalDecodeResult> {
    let mut results = Vec::new();
    let patterns = detect_obfuscation_patterns(data);

    for pat in &patterns {
        match pat {
            ObfuscationPattern::Base64Standard | ObfuscationPattern::Base64UrlSafe => {
                if let Some((decoded, _)) = decode_base64_auto(data) {
                    let text = String::from_utf8_lossy(&decoded).into_owned();
                    let is_valid_utf8 = String::from_utf8(decoded).is_ok();
                    results.push(UniversalDecodeResult { text, pattern: pat.clone(), is_valid_utf8 });
                }
            }
            ObfuscationPattern::HexEncoded => {
                if let Ok(s) = std::str::from_utf8(data)
                    && let Some(decoded) = decode_hex(s)
                {
                    let text = String::from_utf8_lossy(&decoded).into_owned();
                    let is_valid_utf8 = String::from_utf8(decoded).is_ok();
                    results.push(UniversalDecodeResult { text, pattern: pat.clone(), is_valid_utf8 });
                }
            }
            ObfuscationPattern::UrlEncoded => {
                if let Ok(s) = std::str::from_utf8(data) {
                    let text = decode_url(s);
                    results.push(UniversalDecodeResult { text, pattern: pat.clone(), is_valid_utf8: true });
                }
            }
            ObfuscationPattern::HtmlEntities => {
                if let Ok(s) = std::str::from_utf8(data) {
                    let text = decode_html_entities(s);
                    results.push(UniversalDecodeResult { text, pattern: pat.clone(), is_valid_utf8: true });
                }
            }
            ObfuscationPattern::UnicodeEscapes => {
                if let Ok(s) = std::str::from_utf8(data) {
                    let text = decode_unicode_escapes(s);
                    results.push(UniversalDecodeResult { text, pattern: pat.clone(), is_valid_utf8: true });
                }
            }
            ObfuscationPattern::Rot13 => {
                if let Ok(s) = std::str::from_utf8(data) {
                    let text = rot13(s);
                    results.push(UniversalDecodeResult { text, pattern: pat.clone(), is_valid_utf8: true });
                }
            }
            ObfuscationPattern::XorSingleByte => {
                // No key found -> no XOR decode to report. Previously this
                // called a detector that always returned some key, and the
                // `decoded.is_empty()` clause below then admitted the result
                // of decoding NOTHING as a successful decode.
                let Some((decoded, _key)) = decode_xor_auto(data) else {
                    continue;
                };
                let text = String::from_utf8_lossy(&decoded).into_owned();
                let is_valid_utf8 = std::str::from_utf8(&decoded).is_ok();
                // Only include if decoded looks reasonable (printable ratio > 0.8).
                // ratio > 0.8 ↔ printable * 10 > decoded.len() * 8
                let printable = decoded.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
                if !decoded.is_empty() && printable * 10 > decoded.len() * 8 {
                    results.push(UniversalDecodeResult { text, pattern: pat.clone(), is_valid_utf8 });
                }
            }
            ObfuscationPattern::XorMultiByte => {}
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Base64 ────────────────────────────────────────────────────────────────

    #[test]
    fn base64_standard_decode_hello() {
        let alpha = Base64Alphabet::standard();
        let decoded = alpha.decode(b"SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn base64_standard_decode_no_padding() {
        let alpha = Base64Alphabet::standard();
        // "Man" = TWFu (no padding needed)
        let decoded = alpha.decode(b"TWFu").unwrap();
        assert_eq!(decoded, b"Man");
    }

    #[test]
    fn base64_url_safe_decode() {
        let alpha = Base64Alphabet::url_safe();
        // Standard base64 of "Hello World!" with +/ replaced by -_
        // "SGVsbG8gV29ybGQh" — only uses A-Z a-z 0-9, works in both.
        let decoded = alpha.decode(b"SGVsbG8gV29ybGQh").unwrap();
        assert_eq!(decoded, b"Hello World!");
    }

    #[test]
    fn base64_invalid_char_returns_none() {
        let alpha = Base64Alphabet::standard();
        assert!(alpha.decode(b"SGVs!G8=").is_none());
    }

    #[test]
    fn base64_auto_decode_standard() {
        let (decoded, name) = decode_base64_auto(b"SGVsbG8=").unwrap();
        assert_eq!(decoded, b"Hello");
        assert_eq!(name, "standard");
    }

    #[test]
    fn is_likely_base64_true() {
        assert!(is_likely_base64(b"SGVsbG8="));
    }

    #[test]
    fn is_likely_base64_false_short() {
        assert!(!is_likely_base64(b"Hi"));
    }

    // ── Hex ───────────────────────────────────────────────────────────────────

    #[test]
    fn hex_decode_hello() {
        let decoded = decode_hex("48656c6c6f").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn hex_decode_uppercase() {
        let decoded = decode_hex("48656C6C6F").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn hex_decode_colon_delimited() {
        let decoded = decode_hex("48:65:6C:6C:6F").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn hex_decode_odd_length_returns_none() {
        assert!(decode_hex("ABC").is_none());
    }

    // ── URL decoding ──────────────────────────────────────────────────────────

    #[test]
    fn url_decode_basic() {
        assert_eq!(decode_url("Hello%20World"), "Hello World");
    }

    #[test]
    fn url_decode_no_encoding() {
        assert_eq!(decode_url("HelloWorld"), "HelloWorld");
    }

    #[test]
    fn url_decode_multiple_sequences() {
        assert_eq!(decode_url("%48%65%6C%6C%6F"), "Hello");
    }

    // ── HTML entities ─────────────────────────────────────────────────────────

    #[test]
    fn html_entity_named() {
        assert_eq!(decode_html_entities("AT&amp;T"), "AT&T");
    }

    #[test]
    fn html_entity_decimal() {
        assert_eq!(decode_html_entities("&#72;&#101;&#108;&#108;&#111;"), "Hello");
    }

    #[test]
    fn html_entity_hex() {
        assert_eq!(decode_html_entities("&#x48;&#x65;&#x6C;&#x6C;&#x6F;"), "Hello");
    }

    // ── Unicode escapes ───────────────────────────────────────────────────────

    #[test]
    fn unicode_escape_decode() {
        assert_eq!(decode_unicode_escapes(r"Hello"), "Hello");
    }

    #[test]
    fn unicode_escape_non_bmp() {
        // U+1F600 GRINNING FACE
        let result = decode_unicode_escapes(r"\U0001F600");
        assert_eq!(result, "\u{1F600}");
    }

    #[test]
    fn unicode_escape_passthrough_non_escape() {
        assert_eq!(decode_unicode_escapes("Hello\\nWorld"), "Hello\nWorld");
    }

    // ── ROT-13 ────────────────────────────────────────────────────────────────

    #[test]
    fn rot13_hello() {
        assert_eq!(rot13("Uryyb"), "Hello");
        assert_eq!(rot13("Hello"), "Uryyb");
    }

    #[test]
    fn rot13_idempotent() {
        let s = "Hello, World! 123";
        assert_eq!(rot13(&rot13(s)), s);
    }

    // ── XOR ───────────────────────────────────────────────────────────────────

    #[test]
    fn xor_single_byte_roundtrip() {
        let plaintext = b"Hello, World!";
        let key = 0x42u8;
        let ciphertext = xor_single(plaintext, key);
        let recovered = xor_single(&ciphertext, key);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn xor_multi_roundtrip() {
        let plaintext = b"Secret message!";
        let key = b"key";
        let ct = xor_multi(plaintext, key);
        let pt = xor_multi(&ct, key);
        assert_eq!(pt, plaintext);
    }

    /// The frequency detector must decline inputs it cannot reason about.
    ///
    /// It used to return a bare `u8` and therefore always answered. On an
    /// EMPTY buffer it produced `0x20` — a key, from no data — and
    /// `decode_xor_auto` handed that to callers as a decode.
    #[test]
    fn detect_xor_key_declines_when_there_is_no_signal() {
        assert_eq!(detect_xor_key(&[]), None, "no data, no key");
        assert_eq!(decode_xor_auto(&[]), None, "nothing to decode");

        // A permutation: every byte occurs exactly once, so "most frequent"
        // is whichever the scan saw first — an arbitrary pick, not evidence.
        let ramp: Vec<u8> = (0u8..=255).collect();
        assert_eq!(
            detect_xor_key(&ramp),
            None,
            "a flat histogram carries no frequency signal"
        );
    }

    /// Positive control for the test above: a real XOR-encoded text must still
    /// be detected, so "declines" cannot be satisfied by declining everything.
    #[test]
    fn detect_xor_key_still_finds_a_real_key() {
        let plain = b"the quick brown fox jumps over the lazy dog again and again";
        for key in [0x11u8, 0x55, 0xAA] {
            let ct = xor_single(plain, key);
            let found = detect_xor_key(&ct)
                .unwrap_or_else(|| panic!("no key found for a text XORed with {key:#x}"));
            assert_eq!(found, key, "wrong key recovered for {key:#x}");
        }
    }

    #[test]
    fn detect_xor_key_basic() {
        // Encode "Hello World" with key 0x55.
        let plain = b"hello world how are you doing today friend";
        let key = 0x55u8;
        let ct = xor_single(plain, key);
        let detected = detect_xor_key(&ct).expect("a text buffer has a frequency signal");
        // The detected key should decode to mostly printable ASCII.
        let decoded = xor_single(&ct, detected);
        let printable = decoded.iter().filter(|&&b| b.is_ascii_graphic() || b == b' ').count();
        assert!(printable * 10 > decoded.len() * 8);
    }

    // ── Obfuscation patterns ──────────────────────────────────────────────────

    #[test]
    fn detect_base64_pattern() {
        let pats = detect_obfuscation_patterns(b"SGVsbG8=");
        assert!(pats.contains(&ObfuscationPattern::Base64Standard));
    }

    #[test]
    fn detect_hex_pattern() {
        let pats = detect_obfuscation_patterns(b"48656c6c6f");
        assert!(pats.contains(&ObfuscationPattern::HexEncoded));
    }

    #[test]
    fn detect_unicode_escape_pattern() {
        // The raw byte string r"Hello" contains literal
        // backslash-u sequences, which the detector should flag as UnicodeEscapes.
        let pats = detect_obfuscation_patterns(b"\\u0048ello");
        assert!(pats.contains(&ObfuscationPattern::UnicodeEscapes));
    }

    // ── Universal decoder ─────────────────────────────────────────────────────

    #[test]
    fn universal_decode_base64() {
        let results = universal_decode(b"SGVsbG8=");
        assert!(!results.is_empty());
        let base64 = results
            .iter()
            .find(|r| matches!(r.pattern, ObfuscationPattern::Base64Standard | ObfuscationPattern::Base64UrlSafe));
        assert!(base64.is_some());
        assert_eq!(base64.unwrap().text, "Hello");
    }

    #[test]
    fn universal_decode_hex() {
        let results = universal_decode(b"48656c6c6f");
        let hex = results.iter().find(|r| r.pattern == ObfuscationPattern::HexEncoded);
        assert!(hex.is_some());
        assert_eq!(hex.unwrap().text, "Hello");
    }
}
