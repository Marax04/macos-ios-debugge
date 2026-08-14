//! `string_recovery` — production-grade string recovery pipeline.
//!
//! Provides:
//! * [`StringRecovery`]          — top-level coordinator.
//! * [`StringSource`]            — where a string originates (rodata/stack/heap/encrypted).
//! * [`StringRecoveryStrategy`]  — strategy selector.
//! * [`CharsetDetector`]         — charset/encoding detection (UTF-8/UTF-16/ASCII/Latin-1).
//! * [`NullTerminatedScanner`]   — null-terminated string scanner.
//! * [`LengthPrefixedScanner`]   — length-prefixed string scanner.
//! * [`StringDb`]                — queryable result database.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// StringSource
// ─────────────────────────────────────────────────────────────────────────────

/// Where a recovered string originates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringSource {
    /// Read-only data section (`.rodata`, `.rdata`).
    Rodata,
    /// Stack-allocated string.
    Stack,
    /// Heap-allocated string.
    Heap,
    /// Encrypted/obfuscated string (decrypted at runtime).
    Encrypted,
    /// Embedded in code (e.g. immediate operands).
    Immediate,
    /// Unknown origin.
    Unknown,
}

impl std::fmt::Display for StringSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Rodata => "rodata",
            Self::Stack => "stack",
            Self::Heap => "heap",
            Self::Encrypted => "encrypted",
            Self::Immediate => "immediate",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringRecoveryStrategy
// ─────────────────────────────────────────────────────────────────────────────

/// Which scanning strategy to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringRecoveryStrategy {
    /// Scan for null-terminated strings.
    NullTerminated,
    /// Scan for length-prefixed strings.
    LengthPrefixed,
    /// Scan for both.
    Combined,
    /// XOR-decode then scan.
    XorDecrypt { key: u8 },
    /// Stack-string reconstruction from immediate moves.
    StackString,
}

// ─────────────────────────────────────────────────────────────────────────────
// Charset / encoding detection
// ─────────────────────────────────────────────────────────────────────────────

/// Detected character set / encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Charset {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Latin1,
    Unknown,
}

impl std::fmt::Display for Charset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8",
            Self::Utf16Le => "UTF-16 LE",
            Self::Utf16Be => "UTF-16 BE",
            Self::Latin1 => "Latin-1",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Detects the encoding of a byte slice.
pub struct CharsetDetector;

impl CharsetDetector {
    /// Detect the most likely encoding for `bytes`.
    #[must_use] 
    pub fn detect(bytes: &[u8]) -> Charset {
        if bytes.is_empty() {
            return Charset::Unknown;
        }
        // BOM detection.
        if bytes.starts_with(&[0xFF, 0xFE]) {
            return Charset::Utf16Le;
        }
        if bytes.starts_with(&[0xFE, 0xFF]) {
            return Charset::Utf16Be;
        }
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Charset::Utf8;
        }

        // Check for UTF-16 LE heuristic: every other byte is 0x00 for ASCII chars.
        if bytes.len() >= 4 && bytes.len().is_multiple_of(2) {
            let utf16_le_score = bytes
                .chunks(2)
                .filter(|c| c[1] == 0 && c[0] < 0x80 && c[0] >= 0x20)
                .count();
            if utf16_le_score * 2 > bytes.len() * 3 / 4 {
                return Charset::Utf16Le;
            }
        }

        // Attempt UTF-8 validation.
        if std::str::from_utf8(bytes).is_ok() {
            // Pure ASCII check.
            if bytes.iter().all(|&b| b < 0x80) {
                return Charset::Ascii;
            }
            return Charset::Utf8;
        }

        // Check Latin-1: printable range 0x20–0x7E and 0xA0–0xFF.
        let latin1_ok = bytes
            .iter()
            .all(|&b| (0x20..=0x7E).contains(&b) || (0xA0..=0xFF).contains(&b));
        if latin1_ok {
            return Charset::Latin1;
        }

        Charset::Unknown
    }

    /// Estimate the entropy of a byte slice (bits per byte).
    #[must_use] 
    pub fn entropy(bytes: &[u8]) -> f64 {
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

    /// True if the byte slice looks like printable ASCII (>= 80% printable bytes).
    #[must_use] 
    pub fn is_mostly_ascii(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        let printable = bytes
            .iter()
            .filter(|&&b| (0x20..=0x7E).contains(&b))
            .count();
        printable * 10 >= bytes.len() * 8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecoveredString
// ─────────────────────────────────────────────────────────────────────────────

/// A recovered string with full metadata.
#[derive(Debug, Clone)]
pub struct RecoveredString {
    /// Virtual address where the string resides.
    pub address: u64,
    /// The decoded string value.
    pub value: String,
    /// Length in bytes (in the original encoding).
    pub byte_length: usize,
    /// Detected charset.
    pub charset: Charset,
    /// Origin of the string.
    pub source: StringSource,
    /// Strategy that recovered this string.
    pub strategy: StringRecoveryStrategy,
    /// Whether the string is null-terminated.
    pub null_terminated: bool,
    /// XOR key used for decryption, if any.
    pub xor_key: Option<u8>,
}

impl RecoveredString {
    /// True if the string looks like a file path.
    #[must_use] 
    pub fn looks_like_path(&self) -> bool {
        let v = &self.value;
        v.starts_with('/')
            || v.starts_with("./")
            || v.starts_with("../")
            || (v.len() >= 3
                && v.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && v.as_bytes().get(1) == Some(&b':'))
    }

    /// True if the string looks like a URL.
    #[must_use] 
    pub fn looks_like_url(&self) -> bool {
        let v = self.value.to_ascii_lowercase();
        v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://")
    }

    /// Shannon entropy of the raw bytes of the value.
    #[must_use] 
    pub fn entropy(&self) -> f64 {
        CharsetDetector::entropy(self.value.as_bytes())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NullTerminatedScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scans for null-terminated strings in multiple encodings.
pub struct NullTerminatedScanner {
    pub min_length: usize,
    pub max_length: usize,
}

impl NullTerminatedScanner {
    #[must_use] 
    pub const fn new(min_length: usize, max_length: usize) -> Self {
        Self {
            min_length,
            max_length,
        }
    }

    /// Scan `bytes` at `base` for ASCII null-terminated strings.
    #[must_use] 
    pub fn scan_ascii(
        &self,
        base: u64,
        bytes: &[u8],
        source: StringSource,
    ) -> Vec<RecoveredString> {
        let mut results = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let start = i;
            while i < bytes.len() && bytes[i] != 0 {
                if !(0x09..=0x7E).contains(&bytes[i]) {
                    break;
                }
                i += 1;
            }
            let len = i - start;
            let null_terminated = i < bytes.len() && bytes[i] == 0;
            if null_terminated && len >= self.min_length && len <= self.max_length
                && let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                    results.push(RecoveredString {
                        address: base + start as u64,
                        value: s.to_string(),
                        byte_length: len + 1,
                        charset: Charset::Ascii,
                        source,
                        strategy: StringRecoveryStrategy::NullTerminated,
                        null_terminated: true,
                        xor_key: None,
                    });
                }
            if i < bytes.len() {
                i += 1;
            }
        }
        results
    }

    /// Scan for UTF-16 LE null-terminated strings.
    #[must_use] 
    pub fn scan_utf16_le(
        &self,
        base: u64,
        bytes: &[u8],
        source: StringSource,
    ) -> Vec<RecoveredString> {
        let mut results = Vec::new();
        if bytes.len() < 2 {
            return results;
        }
        let mut i = 0;
        while i + 1 < bytes.len() {
            let start = i;
            let mut units: Vec<u16> = Vec::new();
            while i + 1 < bytes.len() {
                let unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
                if unit == 0 {
                    break;
                }
                if let Some(c) = char::from_u32(u32::from(unit)) {
                    if c.is_control() && c != '\t' {
                        break;
                    }
                    units.push(unit);
                } else {
                    break;
                }
                i += 2;
            }
            let null_terminated = i + 1 < bytes.len() && bytes[i] == 0 && bytes[i + 1] == 0;
            let char_count = units.len();
            if null_terminated && char_count >= self.min_length && char_count <= self.max_length
                && let Ok(s) = String::from_utf16(&units) {
                    results.push(RecoveredString {
                        address: base + start as u64,
                        value: s,
                        byte_length: char_count * 2 + 2,
                        charset: Charset::Utf16Le,
                        source,
                        strategy: StringRecoveryStrategy::NullTerminated,
                        null_terminated: true,
                        xor_key: None,
                    });
                }
            if i + 1 < bytes.len() {
                i += 2;
            } else {
                break;
            }
        }
        results
    }
}

impl Default for NullTerminatedScanner {
    fn default() -> Self {
        Self::new(4, 4096)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LengthPrefixedScanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scans for length-prefixed strings.
pub struct LengthPrefixedScanner {
    pub min_length: usize,
    pub max_length: usize,
}

impl LengthPrefixedScanner {
    #[must_use] 
    pub const fn new(min_length: usize, max_length: usize) -> Self {
        Self {
            min_length,
            max_length,
        }
    }

    /// Scan for 1-byte length-prefixed strings (Pascal-style).
    #[must_use] 
    pub fn scan_pascal(
        &self,
        base: u64,
        bytes: &[u8],
        source: StringSource,
    ) -> Vec<RecoveredString> {
        let mut results = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let len = bytes[i] as usize;
            if len >= self.min_length && len <= self.max_length && i + 1 + len <= bytes.len() {
                let slice = &bytes[i + 1..i + 1 + len];
                if slice.iter().all(|&b| (0x20..0x7F).contains(&b)) {
                    let value = String::from_utf8_lossy(slice).into_owned();
                    results.push(RecoveredString {
                        address: base + i as u64,
                        value,
                        byte_length: 1 + len,
                        charset: Charset::Ascii,
                        source,
                        strategy: StringRecoveryStrategy::LengthPrefixed,
                        null_terminated: false,
                        xor_key: None,
                    });
                    i += 1 + len;
                    continue;
                }
            }
            i += 1;
        }
        results
    }

    /// Scan for 2-byte LE length-prefixed strings (BSTR-style).
    #[must_use] 
    pub fn scan_bstr(&self, base: u64, bytes: &[u8], source: StringSource) -> Vec<RecoveredString> {
        let mut results = Vec::new();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let len = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
            if len >= self.min_length && len <= self.max_length && i + 2 + len <= bytes.len() {
                let slice = &bytes[i + 2..i + 2 + len];
                if slice.iter().all(|&b| (0x20..0x7F).contains(&b)) {
                    let value = String::from_utf8_lossy(slice).into_owned();
                    results.push(RecoveredString {
                        address: base + i as u64,
                        value,
                        byte_length: 2 + len,
                        charset: Charset::Ascii,
                        source,
                        strategy: StringRecoveryStrategy::LengthPrefixed,
                        null_terminated: false,
                        xor_key: None,
                    });
                    i += 2 + len;
                    continue;
                }
            }
            i += 1;
        }
        results
    }
}

impl Default for LengthPrefixedScanner {
    fn default() -> Self {
        Self::new(4, 4096)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XOR Decryptor
// ─────────────────────────────────────────────────────────────────────────────

/// Attempts to decrypt a single-byte XOR-encrypted string buffer.
pub struct XorDecryptor;

impl XorDecryptor {
    /// Try each key 1–255, return the key that maximizes English letter-frequency
    /// score in the decoded output.  Using raw printable count alone causes ties
    /// when a related key maps every printable byte to another printable byte.
    #[must_use]
    pub fn guess_key(data: &[u8]) -> Option<u8> {
        if data.is_empty() {
            return None;
        }
        // English letter frequencies (a-z), scaled to integers for speed.
        // Values loosely proportional to ETAOIN SHRDLU order.
        const FREQ: [u32; 26] = [
            8, 1, 3, 4, 13, 2, 2, 6, 7, 1,  // a-j
            1, 4, 2, 7, 8,  2, 1, 6, 6, 9,  // k-t
            3, 1, 2, 1, 2,  1,               // u-z
        ];
        let score_buf = |key: u8| -> u32 {
            let mut s: u32 = 0;
            let mut printable: usize = 0;
            for &b in data {
                let d = b ^ key;
                if (0x20..=0x7E).contains(&d) {
                    printable += 1;
                }
                if d.is_ascii_alphabetic() {
                    let idx = (d.to_ascii_lowercase() - b'a') as usize;
                    s += FREQ[idx];
                } else if d == b' ' {
                    s += 10; // spaces are very common in English text
                }
            }
            // Only trust the score if the majority of bytes are printable.
            let threshold = (data.len() * 7) / 10;
            if printable >= threshold { s } else { 0 }
        };
        let (best_key, best_score) = (1u8..=255)
            .map(|key| (key, score_buf(key)))
            .max_by_key(|&(_, s)| s)?;
        if best_score > 0 {
            Some(best_key)
        } else {
            None
        }
    }

    /// Decrypt with a known key.
    #[must_use] 
    pub fn decrypt(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|&b| b ^ key).collect()
    }

    /// Scan for XOR-encrypted string blobs.
    #[must_use] 
    pub fn scan(base: u64, bytes: &[u8], source: StringSource) -> Vec<RecoveredString> {
        // Heuristic: try 16-byte windows with high entropy.
        let window = 32;
        let mut results = Vec::new();
        let mut i = 0;
        while i + window <= bytes.len() {
            let chunk = &bytes[i..i + window];
            if CharsetDetector::entropy(chunk) > 3.5
                && let Some(key) = Self::guess_key(chunk) {
                    let decrypted = Self::decrypt(chunk, key);
                    if CharsetDetector::is_mostly_ascii(&decrypted) {
                        let value = String::from_utf8_lossy(&decrypted).into_owned();
                        results.push(RecoveredString {
                            address: base + i as u64,
                            value,
                            byte_length: window,
                            charset: Charset::Ascii,
                            source,
                            strategy: StringRecoveryStrategy::XorDecrypt { key },
                            null_terminated: false,
                            xor_key: Some(key),
                        });
                    }
                }
            i += window;
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StringDb
// ─────────────────────────────────────────────────────────────────────────────

/// A queryable database of recovered strings.
#[derive(Debug, Clone, Default)]
pub struct StringDb {
    pub strings: Vec<RecoveredString>,
    addr_index: HashMap<u64, usize>,
}

impl StringDb {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a recovered string.
    pub fn add(&mut self, s: RecoveredString) {
        let idx = self.strings.len();
        self.addr_index.entry(s.address).or_insert(idx);
        self.strings.push(s);
    }

    /// Add all strings from an iterator.
    pub fn add_all(&mut self, iter: impl IntoIterator<Item = RecoveredString>) {
        for s in iter {
            self.add(s);
        }
    }

    /// Lookup by exact address.
    #[must_use] 
    pub fn at(&self, addr: u64) -> Option<&RecoveredString> {
        self.addr_index.get(&addr).map(|&i| &self.strings[i])
    }

    /// Total number of strings.
    #[must_use] 
    pub const fn count(&self) -> usize {
        self.strings.len()
    }

    /// Filter by source.
    #[must_use] 
    pub fn by_source(&self, src: StringSource) -> Vec<&RecoveredString> {
        self.strings.iter().filter(|s| s.source == src).collect()
    }

    /// Filter by charset.
    #[must_use] 
    pub fn by_charset(&self, cs: Charset) -> Vec<&RecoveredString> {
        self.strings.iter().filter(|s| s.charset == cs).collect()
    }

    /// Case-insensitive substring search.
    #[must_use] 
    pub fn search(&self, query: &str) -> Vec<&RecoveredString> {
        let lq = query.to_ascii_lowercase();
        self.strings
            .iter()
            .filter(|s| s.value.to_ascii_lowercase().contains(&lq))
            .collect()
    }

    /// All encrypted strings.
    #[must_use] 
    pub fn encrypted(&self) -> Vec<&RecoveredString> {
        self.strings
            .iter()
            .filter(|s| s.xor_key.is_some())
            .collect()
    }

    /// All URL-like strings.
    #[must_use] 
    pub fn urls(&self) -> Vec<&RecoveredString> {
        self.strings.iter().filter(|s| s.looks_like_url()).collect()
    }

    /// All path-like strings.
    #[must_use] 
    pub fn paths(&self) -> Vec<&RecoveredString> {
        self.strings
            .iter()
            .filter(|s| s.looks_like_path())
            .collect()
    }

    /// The `n` longest strings by `byte_length`.
    #[must_use] 
    pub fn longest(&self, n: usize) -> Vec<&RecoveredString> {
        let mut sorted: Vec<&RecoveredString> = self.strings.iter().collect();
        sorted.sort_unstable_by(|a, b| b.byte_length.cmp(&a.byte_length));
        sorted.truncate(n);
        sorted
    }

    /// Aggregate statistics.
    #[must_use] 
    pub fn stats(&self) -> StringDbStats {
        let total = self.strings.len();
        let mut by_charset: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();
        let mut max_len = 0;
        let mut total_len = 0;
        let mut encrypted_count = 0;

        for s in &self.strings {
            *by_charset.entry(s.charset.to_string()).or_insert(0) += 1;
            *by_source.entry(s.source.to_string()).or_insert(0) += 1;
            if s.byte_length > max_len {
                max_len = s.byte_length;
            }
            total_len += s.byte_length;
            if s.xor_key.is_some() {
                encrypted_count += 1;
            }
        }

        StringDbStats {
            total,
            by_charset,
            by_source,
            max_length: max_len,
            avg_length: if total > 0 {
                f64::from(u32::try_from(total_len).unwrap_or(u32::MAX))
                    / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
            } else {
                0.0
            },
            encrypted_count,
        }
    }
}

/// Statistics for a [`StringDb`].
#[derive(Debug, Clone)]
pub struct StringDbStats {
    pub total: usize,
    pub by_charset: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
    pub max_length: usize,
    pub avg_length: f64,
    pub encrypted_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// StringRecovery — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for string recovery.
#[derive(Debug, Clone)]
pub struct StringRecoveryConfig {
    pub strategies: Vec<StringRecoveryStrategy>,
    pub min_length: usize,
    pub max_length: usize,
    pub scan_rodata: bool,
    pub attempt_xor_decrypt: bool,
}

impl Default for StringRecoveryConfig {
    fn default() -> Self {
        Self {
            strategies: vec![
                StringRecoveryStrategy::NullTerminated,
                StringRecoveryStrategy::LengthPrefixed,
            ],
            min_length: 4,
            max_length: 4096,
            scan_rodata: true,
            attempt_xor_decrypt: false,
        }
    }
}

/// Top-level string recovery coordinator.
pub struct StringRecovery {
    config: StringRecoveryConfig,
}

impl StringRecovery {
    #[must_use] 
    pub const fn new(config: StringRecoveryConfig) -> Self {
        Self { config }
    }

    #[must_use] 
    pub fn default_config() -> Self {
        Self::new(StringRecoveryConfig::default())
    }

    /// Run string recovery on a byte slice at `base`.
    #[must_use] 
    pub fn recover(&self, base: u64, bytes: &[u8], source: StringSource) -> StringDb {
        let mut db = StringDb::new();
        let nt = NullTerminatedScanner::new(self.config.min_length, self.config.max_length);
        let lp = LengthPrefixedScanner::new(self.config.min_length, self.config.max_length);

        for strategy in &self.config.strategies {
            match strategy {
                StringRecoveryStrategy::NullTerminated => {
                    db.add_all(nt.scan_ascii(base, bytes, source));
                    db.add_all(nt.scan_utf16_le(base, bytes, source));
                }
                StringRecoveryStrategy::LengthPrefixed => {
                    db.add_all(lp.scan_pascal(base, bytes, source));
                    db.add_all(lp.scan_bstr(base, bytes, source));
                }
                StringRecoveryStrategy::Combined => {
                    db.add_all(nt.scan_ascii(base, bytes, source));
                    db.add_all(nt.scan_utf16_le(base, bytes, source));
                    db.add_all(lp.scan_pascal(base, bytes, source));
                    db.add_all(lp.scan_bstr(base, bytes, source));
                }
                StringRecoveryStrategy::XorDecrypt { key } => {
                    let decrypted = XorDecryptor::decrypt(bytes, *key);
                    db.add_all(nt.scan_ascii(base, &decrypted, StringSource::Encrypted).into_iter().map(
                        |mut s| {
                            s.strategy = StringRecoveryStrategy::XorDecrypt { key: *key };
                            s.xor_key = Some(*key);
                            s
                        },
                    ));
                }
                StringRecoveryStrategy::StackString => {}
            }
        }

        if self.config.attempt_xor_decrypt {
            db.add_all(XorDecryptor::scan(base, bytes, source));
        }

        db
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn _addr(base: &str) -> u64 {
        u64::from_str_radix(base.trim_start_matches("0x"), 16).unwrap_or(0)
    }

    // 1. StringSource display.
    #[test]
    fn test_string_source_display() {
        assert_eq!(StringSource::Rodata.to_string(), "rodata");
        assert_eq!(StringSource::Encrypted.to_string(), "encrypted");
        assert_eq!(StringSource::Stack.to_string(), "stack");
    }

    // 2. Charset display.
    #[test]
    fn test_charset_display() {
        assert_eq!(Charset::Ascii.to_string(), "ASCII");
        assert_eq!(Charset::Utf16Le.to_string(), "UTF-16 LE");
    }

    // 3. CharsetDetector: pure ASCII.
    #[test]
    fn test_charset_detect_ascii() {
        let bytes = b"hello world";
        assert_eq!(CharsetDetector::detect(bytes), Charset::Ascii);
    }

    // 4. CharsetDetector: UTF-16 LE via BOM.
    #[test]
    fn test_charset_detect_utf16_le_bom() {
        let bytes = [0xFF, 0xFE, 0x68, 0x00];
        assert_eq!(CharsetDetector::detect(&bytes), Charset::Utf16Le);
    }

    // 5. CharsetDetector: UTF-8 via BOM.
    #[test]
    fn test_charset_detect_utf8_bom() {
        let bytes = [0xEF, 0xBB, 0xBF, b'h', b'i'];
        assert_eq!(CharsetDetector::detect(&bytes), Charset::Utf8);
    }

    // 6. CharsetDetector: empty bytes → Unknown.
    #[test]
    fn test_charset_detect_empty() {
        assert_eq!(CharsetDetector::detect(&[]), Charset::Unknown);
    }

    // 7. CharsetDetector::entropy on uniform.
    #[test]
    fn test_entropy_uniform() {
        let data = [0xAA; 8];
        assert!((CharsetDetector::entropy(&data) - 0.0).abs() < 1e-9);
    }

    // 8. CharsetDetector::entropy on max-entropy.
    #[test]
    fn test_entropy_high() {
        let data: Vec<u8> = (0..=255).collect();
        let h = CharsetDetector::entropy(&data);
        assert!((h - 8.0).abs() < 0.01);
    }

    // 9. CharsetDetector::is_mostly_ascii.
    #[test]
    fn test_is_mostly_ascii() {
        assert!(CharsetDetector::is_mostly_ascii(b"hello world!"));
        assert!(!CharsetDetector::is_mostly_ascii(&[0x01, 0x02, 0x03, 0xFF]));
    }

    // 10. NullTerminatedScanner: basic ASCII.
    #[test]
    fn test_null_terminated_ascii() {
        let data = b"hello\0world\0";
        let scanner = NullTerminatedScanner::default();
        let results = scanner.scan_ascii(0x1000, data, StringSource::Rodata);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "hello");
        assert_eq!(results[1].value, "world");
    }

    // 11. NullTerminatedScanner: filters short strings.
    #[test]
    fn test_null_terminated_min_length() {
        let data = b"hi\0hello world\0";
        let scanner = NullTerminatedScanner::new(5, 4096);
        let results = scanner.scan_ascii(0, data, StringSource::Rodata);
        assert!(results.iter().all(|s| s.value.len() >= 5));
    }

    // 12. NullTerminatedScanner: UTF-16 LE.
    #[test]
    fn test_null_terminated_utf16_le() {
        let chars = "test";
        let mut bytes: Vec<u8> = chars.encode_utf16().flat_map(u16::to_le_bytes).collect();
        bytes.extend_from_slice(&[0x00, 0x00]);
        let scanner = NullTerminatedScanner::default();
        let results = scanner.scan_utf16_le(0x2000, &bytes, StringSource::Rodata);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "test");
        assert_eq!(results[0].charset, Charset::Utf16Le);
    }

    // 13. LengthPrefixedScanner: Pascal.
    #[test]
    fn test_pascal_scanner() {
        let mut data = vec![5u8];
        data.extend_from_slice(b"hello");
        data.push(4);
        data.extend_from_slice(b"rust");
        let scanner = LengthPrefixedScanner::default();
        let results = scanner.scan_pascal(0x3000, &data, StringSource::Rodata);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "hello");
        assert_eq!(results[1].value, "rust");
    }

    // 14. LengthPrefixedScanner: BSTR.
    #[test]
    fn test_bstr_scanner() {
        let payload = b"hello";
        let mut data: Vec<u8> = (payload.len() as u16).to_le_bytes().to_vec();
        data.extend_from_slice(payload);
        let scanner = LengthPrefixedScanner::default();
        let results = scanner.scan_bstr(0, &data, StringSource::Rodata);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "hello");
    }

    // 15. XorDecryptor::decrypt.
    #[test]
    fn test_xor_decrypt() {
        let plain = b"hello";
        let key = 0x42u8;
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let dec = XorDecryptor::decrypt(&enc, key);
        assert_eq!(dec, plain.to_vec());
    }

    // 16. XorDecryptor::guess_key.
    #[test]
    fn test_xor_guess_key() {
        let plain = b"Hello, World! This is a test string.";
        let key = 0x77u8;
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let guessed = XorDecryptor::guess_key(&enc);
        assert_eq!(guessed, Some(key));
    }

    // 17. XorDecryptor::guess_key empty.
    #[test]
    fn test_xor_guess_empty() {
        assert_eq!(XorDecryptor::guess_key(&[]), None);
    }

    // 18. StringDb::add / count / at.
    #[test]
    fn test_string_db_basic() {
        let mut db = StringDb::new();
        let s = RecoveredString {
            address: 0x1000,
            value: "test".into(),
            byte_length: 5,
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: true,
            xor_key: None,
        };
        db.add(s);
        assert_eq!(db.count(), 1);
        assert!(db.at(0x1000).is_some());
        assert!(db.at(0x2000).is_none());
    }

    // 19. StringDb::by_source filter.
    #[test]
    fn test_db_by_source() {
        let mut db = StringDb::new();
        let make = |addr: u64, src: StringSource| RecoveredString {
            address: addr,
            value: "abcde".into(),
            byte_length: 6,
            charset: Charset::Ascii,
            source: src,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: true,
            xor_key: None,
        };
        db.add(make(0x1000, StringSource::Rodata));
        db.add(make(0x2000, StringSource::Stack));
        db.add(make(0x3000, StringSource::Rodata));
        assert_eq!(db.by_source(StringSource::Rodata).len(), 2);
        assert_eq!(db.by_source(StringSource::Stack).len(), 1);
    }

    // 20. StringDb::search case-insensitive.
    #[test]
    fn test_db_search() {
        let mut db = StringDb::new();
        let s = RecoveredString {
            address: 0x1000,
            value: "Hello World".into(),
            byte_length: 12,
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: true,
            xor_key: None,
        };
        db.add(s);
        assert_eq!(db.search("hello").len(), 1);
        assert_eq!(db.search("WORLD").len(), 1);
        assert!(db.search("xyz").is_empty());
    }

    // 21. StringDb::urls filter.
    #[test]
    fn test_db_urls() {
        let mut db = StringDb::new();
        let s = RecoveredString {
            address: 0x1000,
            value: "https://example.com".into(),
            byte_length: 20,
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: true,
            xor_key: None,
        };
        db.add(s);
        assert_eq!(db.urls().len(), 1);
    }

    // 22. StringDb::paths filter.
    #[test]
    fn test_db_paths() {
        let mut db = StringDb::new();
        let s = RecoveredString {
            address: 0x1000,
            value: "/usr/bin/bash".into(),
            byte_length: 14,
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: true,
            xor_key: None,
        };
        db.add(s);
        assert_eq!(db.paths().len(), 1);
    }

    // 23. StringDb::longest.
    #[test]
    fn test_db_longest() {
        let mut db = StringDb::new();
        for (addr, v) in [(0x1000, "hi"), (0x2000, "hello world"), (0x3000, "ab")] {
            db.add(RecoveredString {
                address: addr,
                value: v.into(),
                byte_length: v.len() + 1,
                charset: Charset::Ascii,
                source: StringSource::Rodata,
                strategy: StringRecoveryStrategy::NullTerminated,
                null_terminated: true,
                xor_key: None,
            });
        }
        let top1 = db.longest(1);
        assert_eq!(top1[0].value, "hello world");
    }

    // 24. StringDb::stats.
    #[test]
    fn test_db_stats() {
        let mut db = StringDb::new();
        db.add(RecoveredString {
            address: 0x1000,
            value: "hello".into(),
            byte_length: 6,
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: true,
            xor_key: None,
        });
        let stats = db.stats();
        assert_eq!(stats.total, 1);
        assert_eq!(*stats.by_charset.get("ASCII").unwrap(), 1);
    }

    // 25. RecoveredString::entropy.
    #[test]
    fn test_recovered_string_entropy() {
        let s = RecoveredString {
            address: 0,
            value: "aaaa".into(),
            byte_length: 4,
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: false,
            xor_key: None,
        };
        assert!((s.entropy() - 0.0).abs() < 1e-9);
    }

    // 26. StringRecovery::recover null-terminated ASCII.
    #[test]
    fn test_recovery_null_terminated() {
        let data = b"hello\0world\0";
        let sr = StringRecovery::default_config();
        let db = sr.recover(0x1000, data, StringSource::Rodata);
        assert!(db.count() >= 2);
    }

    // 27. StringRecovery::recover empty data.
    #[test]
    fn test_recovery_empty() {
        let sr = StringRecovery::default_config();
        let db = sr.recover(0x1000, &[], StringSource::Rodata);
        assert_eq!(db.count(), 0);
    }

    // 28. StringRecovery with XOR strategy.
    #[test]
    fn test_recovery_xor_decrypt_strategy() {
        let plain = b"hello world\0";
        let key = 0x42u8;
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let config = StringRecoveryConfig {
            strategies: vec![StringRecoveryStrategy::XorDecrypt { key }],
            min_length: 4,
            ..Default::default()
        };
        let sr = StringRecovery::new(config);
        let db = sr.recover(0x1000, &enc, StringSource::Encrypted);
        assert!(db.count() >= 1);
        assert!(db.strings.iter().any(|s| s.value.contains("hello")));
    }

    // 29. NullTerminatedScanner: UTF-16 LE null terminator.
    #[test]
    fn test_utf16_null_terminator() {
        let scanner = NullTerminatedScanner::default();
        // No null terminator → no result.
        let chars: Vec<u8> = "test"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let r = scanner.scan_utf16_le(0, &chars, StringSource::Rodata);
        assert!(r.is_empty());
    }

    // 30. LengthPrefixedScanner: too short rejected.
    #[test]
    fn test_pascal_min_length() {
        let data = vec![2u8, b'h', b'i']; // length=2, "hi"
        let scanner = LengthPrefixedScanner::new(5, 100);
        let results = scanner.scan_pascal(0, &data, StringSource::Rodata);
        assert!(results.is_empty());
    }

    // 31. RecoveredString::looks_like_url.
    #[test]
    fn test_looks_like_url() {
        let make = |v: &str| RecoveredString {
            address: 0,
            value: v.into(),
            byte_length: v.len(),
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: false,
            xor_key: None,
        };
        assert!(make("https://example.com").looks_like_url());
        assert!(!make("example.com").looks_like_url());
    }

    // 32. RecoveredString::looks_like_path.
    #[test]
    fn test_looks_like_path() {
        let make = |v: &str| RecoveredString {
            address: 0,
            value: v.into(),
            byte_length: v.len(),
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: false,
            xor_key: None,
        };
        assert!(make("/etc/passwd").looks_like_path());
        assert!(!make("hello world").looks_like_path());
    }

    // 33. StringDb::by_charset.
    #[test]
    fn test_db_by_charset() {
        let mut db = StringDb::new();
        db.add(RecoveredString {
            address: 0x1000,
            value: "hello".into(),
            byte_length: 6,
            charset: Charset::Utf16Le,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: true,
            xor_key: None,
        });
        assert_eq!(db.by_charset(Charset::Utf16Le).len(), 1);
        assert!(db.by_charset(Charset::Ascii).is_empty());
    }

    // 34. StringDb::encrypted filter.
    #[test]
    fn test_db_encrypted_filter() {
        let mut db = StringDb::new();
        db.add(RecoveredString {
            address: 0x1000,
            value: "plaintext".into(),
            byte_length: 10,
            charset: Charset::Ascii,
            source: StringSource::Rodata,
            strategy: StringRecoveryStrategy::NullTerminated,
            null_terminated: true,
            xor_key: None,
        });
        db.add(RecoveredString {
            address: 0x2000,
            value: "encrypted".into(),
            byte_length: 10,
            charset: Charset::Ascii,
            source: StringSource::Encrypted,
            strategy: StringRecoveryStrategy::XorDecrypt { key: 0x42 },
            null_terminated: false,
            xor_key: Some(0x42),
        });
        assert_eq!(db.encrypted().len(), 1);
        assert_eq!(db.encrypted()[0].xor_key, Some(0x42));
    }

    // 35. StringDbStats avg_length.
    #[test]
    fn test_stats_avg_length() {
        let mut db = StringDb::new();
        for (addr, v) in [(0x1000u64, "hi"), (0x2000, "hello")] {
            db.add(RecoveredString {
                address: addr,
                value: v.into(),
                byte_length: v.len() + 1,
                charset: Charset::Ascii,
                source: StringSource::Rodata,
                strategy: StringRecoveryStrategy::NullTerminated,
                null_terminated: true,
                xor_key: None,
            });
        }
        let stats = db.stats();
        assert!(stats.avg_length > 0.0);
        assert_eq!(stats.total, 2);
    }

    // 37. Combined strategy runs BOTH null-terminated and length-prefixed scanners.
    #[test]
    fn test_combined_strategy_includes_length_prefixed() {
        // Pascal-style string with NO null terminator: only the LP scanner finds it.
        let mut data = vec![5u8];
        data.extend_from_slice(b"hello");
        let config = StringRecoveryConfig {
            strategies: vec![StringRecoveryStrategy::Combined],
            ..Default::default()
        };
        let db = StringRecovery::new(config).recover(0x1000, &data, StringSource::Rodata);
        assert!(
            db.strings
                .iter()
                .any(|s| s.value == "hello"
                    && s.strategy == StringRecoveryStrategy::LengthPrefixed),
            "Combined must also run length-prefixed scanners"
        );
    }

    // 38. XorDecrypt strategy stamps strategy + xor_key on recovered strings.
    #[test]
    fn test_xor_strategy_metadata() {
        let plain = b"hello world\0";
        let key = 0x42u8;
        let enc: Vec<u8> = plain.iter().map(|&b| b ^ key).collect();
        let config = StringRecoveryConfig {
            strategies: vec![StringRecoveryStrategy::XorDecrypt { key }],
            ..Default::default()
        };
        let db = StringRecovery::new(config).recover(0x1000, &enc, StringSource::Encrypted);
        let s = db
            .strings
            .iter()
            .find(|s| s.value.contains("hello"))
            .expect("decrypted string found");
        assert_eq!(s.xor_key, Some(key));
        assert_eq!(s.strategy, StringRecoveryStrategy::XorDecrypt { key });
        assert_eq!(db.encrypted().len(), 1);
    }

    // 36. NullTerminatedScanner: address offset correct.
    #[test]
    fn test_null_terminated_address() {
        let data = b"\x00hello\0world\0";
        let scanner = NullTerminatedScanner::default();
        let results = scanner.scan_ascii(0x5000, data, StringSource::Rodata);
        assert!(results.iter().all(|s| s.address >= 0x5000));
        assert!(results.iter().any(|s| s.value == "hello"));
    }
}
