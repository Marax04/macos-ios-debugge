//! Multi-encoding string decoder.
//!
//! Detects and decodes strings from raw binary slices using a variety of
//! common encodings found in malware: UTF-8, UTF-16 LE/BE, Latin-1, CP-1252,
//! Shift-JIS, ASCII, Base64, Hex, URL-encoded, ROT-13, and XOR-1-byte.

use std::fmt;

// ─── Encoding ────────────────────────────────────────────────────────────────

/// All encodings this decoder can recognise and convert.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    Latin1,
    Cp1252,
    ShiftJis,
    Ascii,
    Base64,
    Hex,
    UrlEncoded,
    Rot13,
    Xor1Byte(u8),
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Encoding::Utf8 => write!(f, "UTF-8"),
            Encoding::Utf16Le => write!(f, "UTF-16LE"),
            Encoding::Utf16Be => write!(f, "UTF-16BE"),
            Encoding::Latin1 => write!(f, "Latin-1"),
            Encoding::Cp1252 => write!(f, "CP-1252"),
            Encoding::ShiftJis => write!(f, "Shift-JIS"),
            Encoding::Ascii => write!(f, "ASCII"),
            Encoding::Base64 => write!(f, "Base64"),
            Encoding::Hex => write!(f, "Hex"),
            Encoding::UrlEncoded => write!(f, "URL-Encoded"),
            Encoding::Rot13 => write!(f, "ROT-13"),
            Encoding::Xor1Byte(k) => write!(f, "XOR(0x{k:02x})"),
        }
    }
}

// ─── DetectedString ──────────────────────────────────────────────────────────

/// A string found in the binary data together with its decoded form.
#[derive(Debug, Clone)]
pub struct DetectedString {
    /// Byte offset of the raw data inside the input slice.
    pub offset: u64,
    /// The raw bytes that make up this string.
    pub raw: Vec<u8>,
    /// Encoding that produced the best decoded form.
    pub encoding: Encoding,
    /// The decoded Unicode string.
    pub decoded: String,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
}

// ─── StringDecoderConfig ─────────────────────────────────────────────────────

/// Tuning knobs for [`StringDecoder`].
#[derive(Debug, Clone)]
pub struct StringDecoderConfig {
    /// Minimum decoded character count to keep a result.
    pub min_length: usize,
    /// Minimum ratio of printable characters required.
    pub min_printable_ratio: f64,
    /// Whether to try all 255 XOR keys.
    pub try_xor: bool,
    /// Encodings to attempt, in order.
    pub encodings_to_try: Vec<Encoding>,
}

impl Default for StringDecoderConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            min_printable_ratio: 0.70,
            try_xor: true,
            encodings_to_try: vec![
                Encoding::Ascii,
                Encoding::Utf8,
                Encoding::Utf16Le,
                Encoding::Utf16Be,
                Encoding::Latin1,
                Encoding::Cp1252,
                Encoding::Base64,
                Encoding::Hex,
                Encoding::UrlEncoded,
                Encoding::Rot13,
            ],
        }
    }
}

// ─── StringDecoder ───────────────────────────────────────────────────────────

/// High-level entry point: scan binary data and recover human-readable strings.
pub struct StringDecoder {
    config: StringDecoderConfig,
}

impl StringDecoder {
    #[must_use]
    pub const fn new(config: StringDecoderConfig) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(StringDecoderConfig::default())
    }

    /// Decode a single byte slice using the specified encoding.
    /// Returns `None` when the result fails the printable-ratio or
    /// minimum-length tests.
    #[must_use]
    pub fn decode_bytes(&self, raw: &[u8], encoding: &Encoding) -> Option<String> {
        let decoded = match encoding {
            Encoding::Ascii => decode_ascii(raw)?,
            Encoding::Utf8 => std::str::from_utf8(raw).ok()?.to_owned(),
            Encoding::Utf16Le => decode_utf16_le(raw)?,
            Encoding::Utf16Be => decode_utf16_be(raw)?,
            Encoding::Latin1 => decode_latin1(raw),
            Encoding::Cp1252 => decode_cp1252(raw),
            Encoding::ShiftJis => decode_shift_jis_approx(raw)?,
            Encoding::Base64 => decode_base64(raw)?,
            Encoding::Hex => decode_hex_string(raw)?,
            Encoding::UrlEncoded => decode_url_encoded(raw)?,
            Encoding::Rot13 => rot13_decode(raw),
            Encoding::Xor1Byte(key) => {
                let unxored: Vec<u8> = raw.iter().map(|b| b ^ key).collect();
                decode_ascii(&unxored)?
            }
        };
        if decoded.len() < self.config.min_length {
            return None;
        }
        let ratio = printable_ratio(&decoded);
        if ratio < self.config.min_printable_ratio {
            return None;
        }
        Some(decoded)
    }

    /// Scan the entire `data` slice for strings using all configured encodings.
    /// Returns every successfully decoded [`DetectedString`] found.
    #[must_use]
    pub fn batch_decode(&self, data: &[u8]) -> Vec<DetectedString> {
        let mut results = Vec::new();

        // Plain text encodings: slide a window and extract NUL-terminated runs.
        for enc in &self.config.encodings_to_try {
            match enc {
                Encoding::Ascii | Encoding::Utf8 | Encoding::Latin1 | Encoding::Cp1252 => {
                    self.scan_cstring_runs(data, enc, &mut results);
                }
                Encoding::Utf16Le => {
                    self.scan_utf16_runs(data, false, &mut results);
                }
                Encoding::Utf16Be => {
                    self.scan_utf16_runs(data, true, &mut results);
                }
                Encoding::Base64 => {
                    self.scan_base64_runs(data, &mut results);
                }
                Encoding::Hex => {
                    self.scan_hex_runs(data, &mut results);
                }
                Encoding::UrlEncoded => {
                    self.scan_url_encoded_runs(data, &mut results);
                }
                Encoding::Rot13 => {
                    self.scan_rot13_runs(data, &mut results);
                }
                Encoding::Xor1Byte(_) | Encoding::ShiftJis => {
                    // handled separately below
                }
            }
        }

        // XOR brute-force
        if self.config.try_xor {
            let xor_results = decode_xor_strings(data, self.config.min_length, self.config.min_printable_ratio);
            results.extend(xor_results);
        }

        results.sort_by_key(|d| d.offset);
        results
    }

    // --- internal helpers ---------------------------------------------------

    fn scan_cstring_runs(&self, data: &[u8], enc: &Encoding, out: &mut Vec<DetectedString>) {
        let mut start = 0usize;
        while start < data.len() {
            // Find a printable-run start
            if !is_printable_byte(data[start]) {
                start += 1;
                continue;
            }
            let run_start = start;
            while start < data.len() && (is_printable_byte(data[start]) || data[start] == b'\t' || data[start] == b'\n' || data[start] == b'\r') {
                start += 1;
            }
            let raw = &data[run_start..start];
            if raw.len() < self.config.min_length {
                // `start` already points past the run; do not skip an extra byte
                // which would belong to the next printable run.
                continue;
            }
            if let Some(decoded) = self.decode_bytes(raw, enc) {
                let confidence = compute_confidence(enc, &decoded, raw.len());
                out.push(DetectedString {
                    offset: run_start as u64,
                    raw: raw.to_vec(),
                    encoding: enc.clone(),
                    decoded,
                    confidence,
                });
            }
            start += 1;
        }
    }

    fn scan_utf16_runs(&self, data: &[u8], big_endian: bool, out: &mut Vec<DetectedString>) {
        if data.len() < 4 {
            return;
        }
        let mut i = 0usize;
        while i + 1 < data.len() {
            let (lo, hi) = if big_endian { (data[i + 1], data[i]) } else { (data[i], data[i + 1]) };
            let codepoint = u16::from_le_bytes([lo, hi]);
            if codepoint == 0 || !is_printable_u16(codepoint) {
                i += 2;
                continue;
            }
            let run_start = i;
            while i + 1 < data.len() {
                let (lo2, hi2) = if big_endian { (data[i + 1], data[i]) } else { (data[i], data[i + 1]) };
                let cp = u16::from_le_bytes([lo2, hi2]);
                if cp == 0 { break; }
                if !is_printable_u16(cp) && cp != 0x0009 && cp != 0x000A && cp != 0x000D { break; }
                i += 2;
            }
            let raw = &data[run_start..i];
            if raw.len() < self.config.min_length * 2 {
                i += 2;
                continue;
            }
            let enc = if big_endian { Encoding::Utf16Be } else { Encoding::Utf16Le };
            if let Some(decoded) = self.decode_bytes(raw, &enc) {
                let confidence = compute_confidence(&enc, &decoded, raw.len());
                out.push(DetectedString {
                    offset: run_start as u64,
                    raw: raw.to_vec(),
                    encoding: enc,
                    decoded,
                    confidence,
                });
            }
            i += 2;
        }
    }

    fn scan_base64_runs(&self, data: &[u8], out: &mut Vec<DetectedString>) {
        let b64_chars: fn(u8) -> bool = |b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
        let mut i = 0;
        while i < data.len() {
            if !b64_chars(data[i]) { i += 1; continue; }
            let start = i;
            while i < data.len() && b64_chars(data[i]) { i += 1; }
            let raw = &data[start..i];
            // base64 requires at least ~4 chars and length divisible by 4 (with padding)
            if raw.len() < 8 { continue; }
            if let Some(decoded) = decode_base64(raw) {
                if decoded.len() >= self.config.min_length && printable_ratio(&decoded) >= self.config.min_printable_ratio {
                    out.push(DetectedString {
                        offset: start as u64,
                        raw: raw.to_vec(),
                        encoding: Encoding::Base64,
                        decoded,
                        confidence: 0.75,
                    });
                }
            }
        }
    }

    fn scan_hex_runs(&self, data: &[u8], out: &mut Vec<DetectedString>) {
        let mut i = 0;
        while i < data.len() {
            if !data[i].is_ascii_hexdigit() { i += 1; continue; }
            let start = i;
            while i < data.len() && data[i].is_ascii_hexdigit() { i += 1; }
            let raw = &data[start..i];
            if raw.len() < self.config.min_length * 2 { continue; }
            if raw.len() % 2 != 0 { continue; }
            if let Some(decoded) = decode_hex_string(raw) {
                if decoded.len() >= self.config.min_length && printable_ratio(&decoded) >= self.config.min_printable_ratio {
                    out.push(DetectedString {
                        offset: start as u64,
                        raw: raw.to_vec(),
                        encoding: Encoding::Hex,
                        decoded,
                        confidence: 0.70,
                    });
                }
            }
        }
    }

    fn scan_url_encoded_runs(&self, data: &[u8], out: &mut Vec<DetectedString>) {
        let is_url_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'%' || b == b'+' || b == b'-' || b == b'.' || b == b'_' || b == b'~';
        let mut i = 0;
        while i < data.len() {
            if data[i] != b'%' { i += 1; continue; }
            let start = i;
            while i < data.len() && is_url_byte(data[i]) { i += 1; }
            let raw = &data[start..i];
            if raw.len() < 3 { continue; }
            if let Some(decoded) = decode_url_encoded(raw) {
                if decoded.len() >= self.config.min_length {
                    out.push(DetectedString {
                        offset: start as u64,
                        raw: raw.to_vec(),
                        encoding: Encoding::UrlEncoded,
                        decoded,
                        confidence: 0.65,
                    });
                }
            }
        }
    }

    fn scan_rot13_runs(&self, data: &[u8], out: &mut Vec<DetectedString>) {
        let mut i = 0;
        while i < data.len() {
            if !data[i].is_ascii_alphabetic() { i += 1; continue; }
            let start = i;
            while i < data.len() && (data[i].is_ascii_alphabetic() || data[i] == b' ') { i += 1; }
            let raw = &data[start..i];
            if raw.len() < self.config.min_length { continue; }
            let decoded = rot13_decode(raw);
            // Only keep if the decoded version looks more like English words
            if is_word_like(&decoded) && printable_ratio(&decoded) > 0.90 {
                out.push(DetectedString {
                    offset: start as u64,
                    raw: raw.to_vec(),
                    encoding: Encoding::Rot13,
                    decoded,
                    confidence: 0.55,
                });
            }
        }
    }
}

// ─── Free-standing decode functions ──────────────────────────────────────────

/// Decode a byte slice as pure 7-bit ASCII, returning `None` if any byte ≥ 128.
#[must_use]
pub fn decode_ascii(raw: &[u8]) -> Option<String> {
    if raw.iter().any(|b| *b > 127) {
        return None;
    }
    Some(raw.iter().map(|&b| b as char).collect())
}

/// Decode UTF-16 LE byte pairs into a String.
#[must_use]
pub fn decode_utf16_le(raw: &[u8]) -> Option<String> {
    if raw.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    char::decode_utf16(units.iter().copied()).map(std::result::Result::ok).collect::<Option<String>>()
}

/// Decode UTF-16 BE byte pairs into a String.
#[must_use]
pub fn decode_utf16_be(raw: &[u8]) -> Option<String> {
    if raw.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    char::decode_utf16(units.iter().copied()).map(std::result::Result::ok).collect::<Option<String>>()
}

/// Decode Latin-1 (ISO 8859-1): bytes map 1-to-1 to Unicode codepoints.
#[must_use]
pub fn decode_latin1(raw: &[u8]) -> String {
    raw.iter().map(|&b| b as char).collect()
}

/// Decode Windows CP-1252 (superset of Latin-1 with remapped 0x80–0x9F range).
#[must_use]
pub fn decode_cp1252(raw: &[u8]) -> String {
    raw.iter().map(|&b| cp1252_char(b)).collect()
}

const fn cp1252_char(b: u8) -> char {
    // The 128-159 range has special mappings; everything else is Latin-1.
    match b {
        0x80 => '\u{20AC}', 0x82 => '\u{201A}', 0x83 => '\u{0192}',
        0x84 => '\u{201E}', 0x85 => '\u{2026}', 0x86 => '\u{2020}',
        0x87 => '\u{2021}', 0x88 => '\u{02C6}', 0x89 => '\u{2030}',
        0x8A => '\u{0160}', 0x8B => '\u{2039}', 0x8C => '\u{0152}',
        0x8E => '\u{017D}', 0x91 => '\u{2018}', 0x92 => '\u{2019}',
        0x93 => '\u{201C}', 0x94 => '\u{201D}', 0x95 => '\u{2022}',
        0x96 => '\u{2013}', 0x97 => '\u{2014}', 0x98 => '\u{02DC}',
        0x99 => '\u{2122}', 0x9A => '\u{0161}', 0x9B => '\u{203A}',
        0x9C => '\u{0153}', 0x9E => '\u{017E}', 0x9F => '\u{0178}',
        _ => b as char,
    }
}

/// Approximate Shift-JIS decode: single-byte ASCII range passed through,
/// two-byte sequences converted via a basic lookup.
#[must_use]
pub fn decode_shift_jis_approx(raw: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        if b < 0x80 {
            out.push(b as char);
            i += 1;
        } else if (0x81..=0x9F).contains(&b) || (0xE0..=0xEF).contains(&b) {
            // two-byte sequence; just output a replacement char to keep length
            if i + 1 >= raw.len() { return None; }
            out.push('\u{FFFD}');
            i += 2;
        } else if (0xA1..=0xDF).contains(&b) {
            // half-width katakana
            let cp = 0xFF61u32 + (u32::from(b) - 0xA1);
            out.push(char::from_u32(cp)?);
            i += 1;
        } else {
            return None;
        }
    }
    Some(out)
}

/// Decode RFC-4648 Base64 into a UTF-8 string (returns `None` on invalid input
/// or when the decoded bytes are not valid UTF-8).
#[must_use]
pub fn decode_base64(raw: &[u8]) -> Option<String> {
    // Strip whitespace / padding noise
    let clean: Vec<u8> = raw.iter().copied().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    let decoded = base64_decode_bytes(&clean)?;
    String::from_utf8(decoded).ok()
}

/// Raw Base64 → bytes (no external dependency).
#[must_use]
pub fn base64_decode_bytes(raw: &[u8]) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity((raw.len() / 4).saturating_mul(3));
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &b in raw {
        if b == b'=' { break; }
        let v = table[b as usize];
        if v == 255 { return None; }
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Decode a sequence of hex digit pairs (e.g. `"48656c6c6f"`) into a UTF-8 string.
#[must_use]
pub fn decode_hex_string(raw: &[u8]) -> Option<String> {
    if raw.len() % 2 != 0 { return None; }
    let bytes: Option<Vec<u8>> = raw.chunks_exact(2).map(|pair| {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        Some((hi << 4) | lo)
    }).collect();
    String::from_utf8(bytes?).ok()
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode a URL-percent-encoded byte slice (+ → space, %XX → byte).
#[must_use]
pub fn decode_url_encoded(raw: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => { out.push(b' '); i += 1; }
            b'%' => {
                if i + 2 >= raw.len() { return None; }
                let hi = hex_nibble(raw[i + 1])?;
                let lo = hex_nibble(raw[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => { out.push(b); i += 1; }
        }
    }
    String::from_utf8(out).ok()
}

/// Apply ROT-13 to all ASCII alphabetic bytes; leave others unchanged.
#[must_use]
pub fn rot13_decode(raw: &[u8]) -> String {
    raw.iter().map(|&b| match b {
        b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
        b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
        _ => b,
    } as char).collect()
}

/// Try all 255 non-zero XOR keys against `data`, returning strings where the
/// XOR-decoded output has sufficient printable ratio.
#[must_use]
pub fn decode_xor_strings(data: &[u8], min_len: usize, min_ratio: f64) -> Vec<DetectedString> {
    let mut results = Vec::new();
    for key in 1u8..=255 {
        let decoded_bytes: Vec<u8> = data.iter().map(|b| b ^ key).collect();
        // Scan for printable runs
        let mut start = 0;
        while start < decoded_bytes.len() {
            if !is_printable_byte(decoded_bytes[start]) { start += 1; continue; }
            let run_start = start;
            while start < decoded_bytes.len() && (is_printable_byte(decoded_bytes[start]) || decoded_bytes[start] == b'\t') {
                start += 1;
            }
            let run = &decoded_bytes[run_start..start];
            if run.len() < min_len { continue; }
            if let Some(s) = decode_ascii(run) {
                let ratio = printable_ratio(&s);
                if ratio >= min_ratio {
                    results.push(DetectedString {
                        offset: run_start as u64,
                        raw: data[run_start..start].to_vec(),
                        encoding: Encoding::Xor1Byte(key),
                        decoded: s,
                        confidence: ratio * 0.6, // XOR is lower confidence
                    });
                }
            }
        }
    }
    results
}

/// Detect the most probable encoding of `data` using BOM detection and
/// heuristic scoring.
#[must_use]
pub fn detect_encoding(data: &[u8]) -> Encoding {
    // BOM detection
    if data.starts_with(&[0xFF, 0xFE]) { return Encoding::Utf16Le; }
    if data.starts_with(&[0xFE, 0xFF]) { return Encoding::Utf16Be; }
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) { return Encoding::Utf8; }

    // UTF-8 validity check
    if std::str::from_utf8(data).is_ok() {
        let high = data.iter().filter(|&&b| b > 127).count();
        if high == 0 { return Encoding::Ascii; }
        return Encoding::Utf8;
    }

    // UTF-16 LE: lots of null bytes at odd positions
    let null_odd = data.iter().enumerate().filter(|&(i, &b)| i % 2 == 1 && b == 0).count();
    let null_even = data.iter().enumerate().filter(|&(i, &b)| i % 2 == 0 && b == 0).count();
    if data.len() > 8 {
        if null_odd as f64 / (data.len() as f64 / 2.0) > 0.5 {
            return Encoding::Utf16Le;
        }
        if null_even as f64 / (data.len() as f64 / 2.0) > 0.5 {
            return Encoding::Utf16Be;
        }
    }

    // High-ASCII density suggests Latin-1 / CP-1252
    let high_ascii = data.iter().filter(|&&b| b > 127).count();
    if high_ascii as f64 / data.len() as f64 > 0.10 {
        // CP-1252 remaps 0x80-0x9F; Latin-1 leaves them as control chars
        let cp1252_mapped = data.iter().filter(|&&b| (0x80..=0x9F).contains(&b)).count();
        if cp1252_mapped > 0 { return Encoding::Cp1252; }
        return Encoding::Latin1;
    }

    Encoding::Ascii
}

// ─── helpers ─────────────────────────────────────────────────────────────────

const fn is_printable_byte(b: u8) -> bool {
    b >= 0x20 && b < 0x7F
}

const fn is_printable_u16(cp: u16) -> bool {
    cp >= 0x0020 && cp != 0x007F
}

fn printable_ratio(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let printable = s.chars().filter(|c| !c.is_control() || *c == '\t' || *c == '\n').count();
    printable as f64 / s.chars().count() as f64
}

fn is_word_like(s: &str) -> bool {
    // Very rough heuristic: most chars are ascii letters or spaces
    let letter_space = s.chars().filter(|c| c.is_ascii_alphabetic() || *c == ' ').count();
    letter_space as f64 / s.len() as f64 > 0.70
}

fn compute_confidence(enc: &Encoding, decoded: &str, _raw_len: usize) -> f64 {
    let base = match enc {
        Encoding::Utf8 => 0.95,
        Encoding::Ascii => 0.95,
        Encoding::Utf16Le | Encoding::Utf16Be => 0.90,
        Encoding::Cp1252 => 0.80,
        Encoding::Latin1 => 0.75,
        Encoding::Base64 => 0.75,
        Encoding::Hex => 0.70,
        Encoding::UrlEncoded => 0.70,
        Encoding::Rot13 => 0.55,
        Encoding::Xor1Byte(_) => 0.50,
        Encoding::ShiftJis => 0.70,
    };
    let length_bonus = (decoded.len().min(64) as f64 / 64.0) * 0.05;
    let ratio_score = printable_ratio(decoded);
    (base * ratio_score + length_bonus).min(1.0)
}

// ─── Unit Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_ascii_clean() {
        assert_eq!(decode_ascii(b"Hello"), Some("Hello".to_owned()));
    }

    #[test]
    fn test_decode_ascii_high_byte_returns_none() {
        assert!(decode_ascii(&[0x48, 0x80]).is_none());
    }

    #[test]
    fn test_decode_utf16_le_basic() {
        let raw = b"H\x00e\x00l\x00l\x00o\x00";
        assert_eq!(decode_utf16_le(raw), Some("Hello".to_owned()));
    }

    #[test]
    fn test_decode_utf16_be_basic() {
        let raw = b"\x00H\x00e\x00l\x00l\x00o";
        assert_eq!(decode_utf16_be(raw), Some("Hello".to_owned()));
    }

    #[test]
    fn test_decode_utf16_le_odd_length_none() {
        assert!(decode_utf16_le(b"H\x00e").is_none());
    }

    #[test]
    fn test_decode_latin1_round_trip() {
        let raw: Vec<u8> = (0u8..=255).collect();
        let decoded = decode_latin1(&raw);
        // Latin-1 maps 256 bytes to 256 Unicode code points; String::len()
        // counts UTF-8 bytes, so bytes >= 0x80 each encode as 2-byte sequences.
        assert_eq!(decoded.chars().count(), 256);
    }

    #[test]
    fn test_decode_cp1252_euro_sign() {
        let decoded = decode_cp1252(&[0x80]);
        assert_eq!(decoded, "\u{20AC}");
    }

    #[test]
    fn test_base64_decode_hello() {
        assert_eq!(decode_base64(b"SGVsbG8="), Some("Hello".to_owned()));
    }

    #[test]
    fn test_base64_decode_invalid_returns_none() {
        assert!(decode_base64(b"!!!").is_none());
    }

    #[test]
    fn test_hex_decode_hello() {
        assert_eq!(decode_hex_string(b"48656c6c6f"), Some("Hello".to_owned()));
    }

    #[test]
    fn test_hex_decode_odd_length_none() {
        // Odd number of hex digits → cannot form complete byte pairs → None.
        assert!(decode_hex_string(b"486").is_none());
        // Single hex digit → None.
        assert!(decode_hex_string(b"4").is_none());
    }

    #[test]
    fn test_url_encoded_basic() {
        assert_eq!(decode_url_encoded(b"Hello+World"), Some("Hello World".to_owned()));
        assert_eq!(decode_url_encoded(b"%48%65%6c%6c%6f"), Some("Hello".to_owned()));
    }

    #[test]
    fn test_rot13_hello() {
        assert_eq!(rot13_decode(b"Uryyb"), "Hello".to_owned());
    }

    #[test]
    fn test_rot13_roundtrip() {
        let input = b"The quick brown fox";
        let once = rot13_decode(input);
        let twice = rot13_decode(once.as_bytes());
        assert_eq!(twice, std::str::from_utf8(input).unwrap());
    }

    #[test]
    fn test_detect_encoding_bom_utf16le() {
        assert_eq!(detect_encoding(&[0xFF, 0xFE, 0x41, 0x00]), Encoding::Utf16Le);
    }

    #[test]
    fn test_detect_encoding_ascii() {
        assert_eq!(detect_encoding(b"Hello World"), Encoding::Ascii);
    }

    #[test]
    fn test_detect_encoding_utf8_multibyte() {
        let s = "héllo";
        assert_eq!(detect_encoding(s.as_bytes()), Encoding::Utf8);
    }

    #[test]
    fn test_xor_decode_roundtrip() {
        let original = b"Hello World";
        let key = 42u8;
        let xored: Vec<u8> = original.iter().map(|b| b ^ key).collect();
        let results = decode_xor_strings(&xored, 4, 0.70);
        let found = results.iter().any(|d| d.encoding == Encoding::Xor1Byte(key) && d.decoded.contains("Hello"));
        assert!(found, "XOR key 42 should be found");
    }

    #[test]
    fn test_batch_decode_finds_ascii_string() {
        let mut data = vec![0u8; 8];
        data.extend_from_slice(b"password");
        data.extend_from_slice(&[0, 0, 0]);
        let decoder = StringDecoder::with_defaults();
        let results = decoder.batch_decode(&data);
        assert!(results.iter().any(|d| d.decoded.contains("password")));
    }

    #[test]
    fn test_printable_ratio_full() {
        assert!((printable_ratio("Hello World") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_decoder_min_length_filter() {
        let config = StringDecoderConfig { min_length: 10, ..Default::default() };
        let decoder = StringDecoder::new(config);
        assert!(decoder.decode_bytes(b"Hi", &Encoding::Ascii).is_none());
    }

    #[test]
    fn test_base64_decode_bytes_padding() {
        let result = base64_decode_bytes(b"YQ==");
        assert_eq!(result, Some(vec![b'a']));
    }
}
