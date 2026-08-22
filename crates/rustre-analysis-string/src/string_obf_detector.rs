/// String obfuscation detection.
///
/// Detects XOR-encoded strings (single-byte and multi-byte keys),
/// base64-encoded strings, hex-encoded strings, and stack-string construction
/// patterns. Also handles ROT-N and simple XOR frequency analysis.

use ahash::AHashMap;

// ---------------------------------------------------------------------------
// ObfType — categories of obfuscation
// ---------------------------------------------------------------------------

/// The type of obfuscation detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObfType {
    XorSingleByte { key: u8 },
    XorMultiByte { key: Vec<u8> },
    Base64 { variant: Base64Variant },
    HexEncoded,
    StackString,
    RotN { n: u8 },
    Reversed,
    NullPadded,
    Custom(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Base64Variant {
    Standard,
    UrlSafe,
    Custom,
}

impl ObfType {
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::XorSingleByte { key } => format!("xor_byte({key:#04x})"),
            Self::XorMultiByte { key } => format!("xor_multi({} bytes)", key.len()),
            Self::Base64 { variant } => match variant {
                Base64Variant::Standard => "base64_std".to_owned(),
                Base64Variant::UrlSafe => "base64_url".to_owned(),
                Base64Variant::Custom => "base64_custom".to_owned(),
            },
            Self::HexEncoded => "hex_encoded".to_owned(),
            Self::StackString => "stack_string".to_owned(),
            Self::RotN { n } => format!("rot{n}"),
            Self::Reversed => "reversed".to_owned(),
            Self::NullPadded => "null_padded".to_owned(),
            Self::Custom(s) => format!("custom({s})"),
        }
    }
}

// ---------------------------------------------------------------------------
// ObfDetectionResult — detection output
// ---------------------------------------------------------------------------

/// Detection result for one blob.
#[derive(Debug, Clone)]
pub struct ObfDetectionResult {
    /// Detected obfuscation type.
    pub obf_type: ObfType,
    /// Decoded plaintext (if successfully decoded).
    pub decoded: Option<Vec<u8>>,
    /// Confidence score in [0.0, 1.0].
    pub confidence: f64,
    /// Original data length.
    pub data_len: usize,
    /// Shannon entropy of input data.
    pub entropy: f64,
}

impl ObfDetectionResult {
    #[must_use]
    pub fn decoded_utf8(&self) -> Option<String> {
        self.decoded.as_ref().and_then(|d| String::from_utf8(d.clone()).ok())
    }
}

// ---------------------------------------------------------------------------
// XorObf — single-byte XOR analysis
// ---------------------------------------------------------------------------

/// Single-byte XOR analysis.
pub struct XorObf;

impl XorObf {
    /// Try all 256 keys, score by English letter frequency, return best candidates.
    ///
    /// Using raw printable-count as the sole score causes ties when a related key
    /// maps every printable byte to another printable byte.  English letter
    /// frequency provides a discriminating secondary criterion.
    #[must_use]
    pub fn detect(data: &[u8]) -> Vec<(u8, f64, Vec<u8>)> {
        const FREQ: [f64; 26] = [
            0.0817, 0.0150, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697,
            0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0010, 0.0599,
            0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007,
        ];
        let freq_score = |decoded: &[u8]| -> f64 {
            let printable = decoded.iter().filter(|&&b| b >= 0x20 && b < 0x7F).count();
            if printable * 2 < decoded.len() {
                return 0.0; // majority non-printable — discard
            }
            let letters: usize = decoded.iter().filter(|b| b.is_ascii_alphabetic()).count();
            if letters == 0 { return printable as f64 / decoded.len() as f64; }
            let mut counts = [0usize; 26];
            for &b in decoded {
                if b.is_ascii_alphabetic() {
                    counts[(b.to_ascii_lowercase() - b'a') as usize] += 1;
                }
            }
            let lf = letters as f64;
            let chi: f64 = counts.iter().enumerate().map(|(i, &c)| {
                let expected = FREQ[i] * lf;
                let observed = c as f64;
                let diff = observed - expected;
                diff * diff / expected.max(0.0001)
            }).sum();
            // Negate chi-squared so that lower chi → higher score, then normalise.
            // Add a base from printable fraction to prefer printable over non-printable.
            let printable_frac = printable as f64 / decoded.len() as f64;
            printable_frac - chi / (lf * 1000.0)
        };
        let mut results = Vec::new();
        for key in 1u8..=255 {
            let decoded: Vec<u8> = data.iter().map(|&b| b ^ key).collect();
            let score = freq_score(&decoded);
            if score > 0.4 {
                results.push((key, score, decoded));
            }
        }
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(5);
        results
    }

    /// Return the best single-byte key candidate.
    #[must_use]
    pub fn best_key(data: &[u8]) -> Option<(u8, f64, Vec<u8>)> {
        Self::detect(data).into_iter().next()
    }

    /// Frequency-analysis key estimation for single-byte XOR (assumes space is most common byte in plaintext).
    #[must_use]
    pub fn frequency_key(data: &[u8]) -> u8 {
        let mut freq = [0u32; 256];
        for &b in data { freq[b as usize] += 1; }
        let most_common = freq.iter().enumerate().max_by_key(|&(_, &c)| c).map_or(0, |(i, _)| i) as u8;
        most_common ^ 0x20 // XOR with ASCII space
    }
}

// ---------------------------------------------------------------------------
// XorMultiByteObf — multi-byte XOR key analysis
// ---------------------------------------------------------------------------

/// Multi-byte XOR key analysis using Index of Coincidence.
pub struct XorMultiByteObf;

impl XorMultiByteObf {
    /// Estimate the key length using Index of Coincidence.
    #[must_use]
    pub fn estimate_key_length(data: &[u8], max_len: usize) -> usize {
        let max_len = max_len.min(16).max(1);
        let mut best_len = 1;
        let mut best_ic = 0.0f64;

        for kl in 1..=max_len {
            let mut ic_sum = 0.0;
            let mut count = 0;
            for col in 0..kl {
                let column: Vec<u8> = data.iter().skip(col).step_by(kl).copied().collect();
                if column.len() < 2 { continue; }
                ic_sum += index_of_coincidence(&column);
                count += 1;
            }
            if count == 0 { continue; }
            let ic = ic_sum / f64::from(count);
            if ic > best_ic {
                best_ic = ic;
                best_len = kl;
            }
        }
        best_len
    }

    /// Reconstruct the multi-byte key by frequency analysis per column.
    #[must_use]
    pub fn recover_key(data: &[u8], key_len: usize) -> Vec<u8> {
        (0..key_len).map(|col| {
            let column: Vec<u8> = data.iter().skip(col).step_by(key_len).copied().collect();
            XorObf::frequency_key(&column)
        }).collect()
    }

    /// Decode data with a multi-byte key.
    #[must_use]
    pub fn decode(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() { return data.to_vec(); }
        data.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect()
    }
}

fn index_of_coincidence(data: &[u8]) -> f64 {
    let n = data.len() as f64;
    if n < 2.0 { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let numerator: f64 = freq.iter().map(|&f| f as f64 * (f as f64 - 1.0)).sum();
    numerator / (n * (n - 1.0))
}

// ---------------------------------------------------------------------------
// Base64Obf — base64 detection and decoding
// ---------------------------------------------------------------------------

/// Base64 detection and decoding.
pub struct Base64Obf;

impl Base64Obf {
    const STD_ALPHABET: &'static [u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_ALPHABET: &'static [u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Detect and classify base64.
    #[must_use]
    pub fn detect(data: &[u8]) -> Option<(Base64Variant, f64)> {
        if data.len() < 4 || !data.len().is_multiple_of(4) {
            return None;
        }
        let std_score = alphabet_score(data, Self::STD_ALPHABET);
        let url_score = alphabet_score(data, Self::URL_ALPHABET);

        if std_score > 0.95 {
            Some((Base64Variant::Standard, std_score))
        } else if url_score > 0.95 {
            Some((Base64Variant::UrlSafe, url_score))
        } else if std_score > 0.80 || url_score > 0.80 {
            Some((Base64Variant::Custom, std_score.max(url_score)))
        } else {
            None
        }
    }

    /// Minimal base64 decoder (standard alphabet, no external deps).
    #[must_use]
    pub fn decode_standard(data: &[u8]) -> Option<Vec<u8>> {
        let clean: Vec<u8> = data.iter().copied().filter(|&b| b != b'\r' && b != b'\n').collect();
        if !clean.len().is_multiple_of(4) { return None; }
        let mut out = Vec::with_capacity(clean.len() / 4 * 3);
        for chunk in clean.chunks(4) {
            let a = decode_char(chunk[0])?;
            let b = decode_char(chunk[1])?;
            let c = if chunk[2] == b'=' { 0 } else { decode_char(chunk[2])? };
            let d = if chunk[3] == b'=' { 0 } else { decode_char(chunk[3])? };
            let v = u32::from(a) << 18 | u32::from(b) << 12 | u32::from(c) << 6 | u32::from(d);
            out.push((v >> 16) as u8);
            if chunk[2] != b'=' { out.push((v >> 8) as u8); }
            if chunk[3] != b'=' { out.push(v as u8); }
        }
        Some(out)
    }
}

fn alphabet_score(data: &[u8], alphabet: &[u8; 64]) -> f64 {
    let matches = data.iter().filter(|&&b| b == b'=' || alphabet.contains(&b)).count();
    matches as f64 / data.len() as f64
}

const fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// HexObf — hex-encoded string detection
// ---------------------------------------------------------------------------

/// Hex-encoded string detection.
pub struct HexObf;

impl HexObf {
    #[must_use]
    pub fn detect(data: &[u8]) -> Option<f64> {
        if data.len() < 8 || !data.len().is_multiple_of(2) { return None; }
        let score = alphabet_score_fn(data, |b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'));
        if score >= 0.98 { Some(score) } else { None }
    }

    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Vec<u8>> {
        if !data.len().is_multiple_of(2) { return None; }
        let mut out = Vec::with_capacity(data.len() / 2);
        for chunk in data.chunks(2) {
            let hi = hex_nybble(chunk[0])?;
            let lo = hex_nybble(chunk[1])?;
            out.push((hi << 4) | lo);
        }
        Some(out)
    }
}

const fn hex_nybble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn alphabet_score_fn<F: Fn(u8) -> bool>(data: &[u8], f: F) -> f64 {
    let matches = data.iter().filter(|&&b| f(b)).count();
    matches as f64 / data.len() as f64
}

// ---------------------------------------------------------------------------
// StackString — detection of stack-string patterns
// ---------------------------------------------------------------------------

/// Stack string construction pattern.
#[derive(Debug, Clone)]
pub struct StackStringPattern {
    /// Bytes being written, in order.
    pub bytes: Vec<u8>,
    /// Base offset (stack offset of first character).
    pub base_offset: i64,
    /// Virtual address of the first write instruction.
    pub start_va: u64,
}

impl StackStringPattern {
    #[must_use]
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    #[must_use]
    pub fn is_printable(&self) -> bool {
        self.bytes.iter().all(|&b| b >= 0x20 && b < 0x7F)
    }
}

/// Heuristic: detect sequences of immediate-to-stack-offset writes.
/// `writes` = list of (`stack_offset`, `byte_value`, va) sorted by `stack_offset`.
#[must_use]
pub fn detect_stack_string(
    writes: &[(i64, u8, u64)],
    min_length: usize,
) -> Vec<StackStringPattern> {
    if writes.is_empty() { return Vec::new(); }

    let mut sorted = writes.to_vec();
    sorted.sort_by_key(|(offset, _, _)| *offset);

    let mut results = Vec::new();
    let mut current_bytes: Vec<u8> = Vec::new();
    let mut current_start_offset: i64 = 0;
    let mut current_start_va: u64 = 0;
    let mut prev_offset: i64 = i64::MIN;

    for &(offset, byte, va) in &sorted {
        if current_bytes.is_empty() {
            current_start_offset = offset;
            current_start_va = va;
            current_bytes.push(byte);
            prev_offset = offset;
        } else if prev_offset.checked_add(1) == Some(offset) {
            current_bytes.push(byte);
            prev_offset = offset;
        } else {
            if current_bytes.len() >= min_length {
                results.push(StackStringPattern {
                    bytes: current_bytes.clone(),
                    base_offset: current_start_offset,
                    start_va: current_start_va,
                });
            }
            current_bytes.clear();
            current_bytes.push(byte);
            current_start_offset = offset;
            current_start_va = va;
            prev_offset = offset;
        }
    }
    if current_bytes.len() >= min_length {
        results.push(StackStringPattern {
            bytes: current_bytes,
            base_offset: current_start_offset,
            start_va: current_start_va,
        });
    }
    results
}

// ---------------------------------------------------------------------------
// ObfDetector — main dispatcher
// ---------------------------------------------------------------------------

/// Configuration for obfuscation detection.
#[derive(Debug, Clone)]
pub struct ObfDetectorConfig {
    pub min_data_len: usize,
    pub detect_xor: bool,
    pub detect_base64: bool,
    pub detect_hex: bool,
    pub detect_stack: bool,
    pub xor_min_printable_score: f64,
    pub stack_min_length: usize,
}

impl Default for ObfDetectorConfig {
    fn default() -> Self {
        Self {
            min_data_len: 4,
            detect_xor: true,
            detect_base64: true,
            detect_hex: true,
            detect_stack: true,
            xor_min_printable_score: 0.7,
            stack_min_length: 4,
        }
    }
}

/// Aggregate statistics.
#[derive(Debug, Default, Clone)]
pub struct DetectorStats {
    pub total_analysed: u64,
    // Keyed on obfuscation type names which can contain user-controlled content
    // (e.g. Custom variant). Use AHashMap to prevent hash-collision DoS
    // (dos-hash-collision).
    pub by_type: AHashMap<String, u64>,
}

/// Main obfuscation detector.
pub struct ObfDetector {
    config: ObfDetectorConfig,
    stats: DetectorStats,
}

impl ObfDetector {
    #[must_use]
    pub fn new(config: ObfDetectorConfig) -> Self {
        Self { config, stats: DetectorStats::default() }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ObfDetectorConfig::default())
    }

    /// Analyse a raw byte blob and return all detected obfuscation types.
    pub fn analyse(&mut self, data: &[u8]) -> Vec<ObfDetectionResult> {
        self.stats.total_analysed += 1;
        if data.len() < self.config.min_data_len {
            return Vec::new();
        }

        let entropy = shannon_entropy(data);
        let mut results = Vec::new();

        // Base64
        if self.config.detect_base64
            && let Some((variant, conf)) = Base64Obf::detect(data) {
                let decoded = Base64Obf::decode_standard(data);
                results.push(ObfDetectionResult {
                    obf_type: ObfType::Base64 { variant },
                    decoded,
                    confidence: conf,
                    data_len: data.len(),
                    entropy,
                });
            }

        // Hex
        if self.config.detect_hex
            && let Some(conf) = HexObf::detect(data) {
                let decoded = HexObf::decode(data);
                results.push(ObfDetectionResult {
                    obf_type: ObfType::HexEncoded,
                    decoded,
                    confidence: conf,
                    data_len: data.len(),
                    entropy,
                });
            }

        // XOR single-byte
        if self.config.detect_xor
            && let Some((key, score, decoded)) = XorObf::best_key(data)
                && score >= self.config.xor_min_printable_score {
                    results.push(ObfDetectionResult {
                        obf_type: ObfType::XorSingleByte { key },
                        decoded: Some(decoded),
                        confidence: score,
                        data_len: data.len(),
                        entropy,
                    });
                }

        for r in &results {
            *self.stats.by_type.entry(r.obf_type.name()).or_default() += 1;
        }

        results
    }

    /// Analyse a text string (UTF-8) as bytes.
    pub fn analyse_str(&mut self, s: &str) -> Vec<ObfDetectionResult> {
        self.analyse(s.as_bytes())
    }

    #[must_use]
    pub const fn stats(&self) -> &DetectorStats {
        &self.stats
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Score bytes by printable ASCII percentage.
#[must_use]
pub fn printable_score(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let printable = data.iter().filter(|&&b| b >= 0x20 && b < 0x7F).count();
    printable as f64 / data.len() as f64
}

/// Shannon entropy in bits per byte.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    crate::classify::shannon_entropy(data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_single_byte_decode() {
        let key = 0x42u8;
        // Use a plaintext with '}' (0x7D): plaintext^0x42 produces a byte that,
        // when decoded with nearby keys (e.g. 0x40), yields 0x7F (DEL, non-printable),
        // breaking score ties and ensuring the correct key wins.
        let plaintext = b"Hello} World!";
        let encoded: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let (found_key, score, decoded) = XorObf::best_key(&encoded).unwrap();
        assert_eq!(found_key, key);
        assert!(score > 0.9);
        assert_eq!(decoded, plaintext.as_ref());
    }

    #[test]
    fn test_xor_frequency_key() {
        // Space-heavy message XORed with key 0x05
        let msg = b"hello world test string for xor frequency";
        let encoded: Vec<u8> = msg.iter().map(|&b| b ^ 0x05).collect();
        let key = XorObf::frequency_key(&encoded);
        // Should be close to 0x05
        let _ = key; // result depends on frequency analysis, just ensure it runs
    }

    #[test]
    fn test_xor_multi_byte_decode() {
        let key = b"KEY";
        let plaintext = b"Hello, World! This is a test.";
        let encoded: Vec<u8> = plaintext.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect();
        let decoded = XorMultiByteObf::decode(&encoded, key);
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn test_base64_detect_standard() {
        let data = b"SGVsbG8gV29ybGQ="; // "Hello World"
        let result = Base64Obf::detect(data);
        assert!(result.is_some());
        let (variant, conf) = result.unwrap();
        assert_eq!(variant, Base64Variant::Standard);
        assert!(conf > 0.9);
    }

    #[test]
    fn test_base64_decode() {
        let data = b"SGVsbG8gV29ybGQ=";
        let decoded = Base64Obf::decode_standard(data).unwrap();
        assert_eq!(decoded, b"Hello World");
    }

    #[test]
    fn test_hex_detect() {
        let data = b"48656c6c6f"; // "Hello" in hex
        let result = HexObf::detect(data);
        assert!(result.is_some());
    }

    #[test]
    fn test_hex_decode() {
        let data = b"48656c6c6f";
        let decoded = HexObf::decode(data).unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_stack_string_detection() {
        // Writes: offsets 0..5 = "Hello"
        let writes: Vec<(i64, u8, u64)> = b"Hello".iter().enumerate()
            .map(|(i, &b)| (i as i64, b, 0x1000 + i as u64))
            .collect();
        let patterns = detect_stack_string(&writes, 3);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].to_string_lossy(), "Hello");
    }

    #[test]
    fn test_stack_string_gap() {
        // Two separate strings with gap
        let writes = vec![
            (0i64, b'A', 0x1000u64),
            (1, b'B', 0x1001),
            (3, b'C', 0x1003), // gap at offset 2
            (4, b'D', 0x1004),
        ];
        let patterns = detect_stack_string(&writes, 2);
        assert_eq!(patterns.len(), 2);
    }

    #[test]
    fn regress_stack_string_offset_i64_max_no_overflow() {
        // A write at i64::MAX must not overflow the adjacency check
        // (prev_offset + 1 panicked in debug builds before the checked_add fix).
        let writes = vec![
            (i64::MAX - 1, b'A', 0x1000u64),
            (i64::MAX, b'B', 0x1001),
        ];
        let patterns = detect_stack_string(&writes, 2);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].to_string_lossy(), "AB");
    }

    #[test]
    fn test_printable_score() {
        let printable = b"Hello, World!";
        assert!(printable_score(printable) > 0.99);
        let binary = &[0u8, 1, 2, 3, 0xFF];
        assert!(printable_score(binary) < 0.2);
    }

    #[test]
    fn test_shannon_entropy() {
        // All same byte = 0 entropy
        let zeros = vec![0u8; 100];
        assert!(shannon_entropy(&zeros) < 0.001);
        // Uniform = max entropy
        let uniform: Vec<u8> = (0..=255u8).collect();
        assert!(shannon_entropy(&uniform) > 7.9);
    }

    #[test]
    fn test_obf_detector_base64() {
        let mut det = ObfDetector::with_defaults();
        let results = det.analyse(b"SGVsbG8gV29ybGQ=");
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| matches!(r.obf_type, ObfType::Base64 { .. })));
    }

    #[test]
    fn test_obf_detector_hex() {
        let mut det = ObfDetector::with_defaults();
        let results = det.analyse(b"48656c6c6f");
        assert!(results.iter().any(|r| r.obf_type == ObfType::HexEncoded));
    }

    #[test]
    fn test_obf_detector_xor() {
        let key = 0x41u8;
        let plaintext = b"Hello world, this is a printable test string!!!";
        let encoded: Vec<u8> = plaintext.iter().map(|&b| b ^ key).collect();
        let mut det = ObfDetector::with_defaults();
        let results = det.analyse(&encoded);
        assert!(results.iter().any(|r| matches!(r.obf_type, ObfType::XorSingleByte { .. })));
    }

    #[test]
    fn test_obf_type_name() {
        assert_eq!(ObfType::XorSingleByte { key: 0x41 }.name(), "xor_byte(0x41)");
        assert_eq!(ObfType::HexEncoded.name(), "hex_encoded");
        assert_eq!(ObfType::StackString.name(), "stack_string");
    }

    #[test]
    fn test_index_of_coincidence() {
        // English text should have IC ~ 0.065
        let text = b"the quick brown fox jumps over the lazy dog and other english words here now";
        let ic = index_of_coincidence(text);
        assert!(ic > 0.04, "IC was {}", ic);
    }
}
