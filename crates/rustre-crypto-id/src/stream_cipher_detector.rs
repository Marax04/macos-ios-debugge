//! `stream_cipher_detector` — Detect stream cipher implementations in binary data.
//!
//! Recognises RC4 (KSA and PRGA), `ChaCha20`, Salsa20, A5/1, ZUC, and SNOW 3G
//! through constant-matching and structural byte-pattern scanning.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── StreamCipherKind ──────────────────────────────────────────────────────────

/// Enumeration of known stream cipher algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamCipherKind {
    Rc4,
    ChaCha20,
    Salsa20,
    A5_1,
    Zuc,
    Snow3G,
    Trivium,
    Grain128,
    Unknown,
}

impl std::fmt::Display for StreamCipherKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl StreamCipherKind {
    /// Returns `true` for commonly considered broken or weak ciphers.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(self, Self::Rc4 | Self::A5_1)
    }

    /// Returns `true` if the cipher is generally considered secure.
    #[must_use]
    pub const fn is_modern(self) -> bool {
        matches!(self, Self::ChaCha20 | Self::Salsa20 | Self::Zuc | Self::Grain128)
    }

    /// Typical key size in bytes, or `None` if variable.
    #[must_use]
    pub const fn key_bytes(self) -> Option<usize> {
        match self {
            Self::ChaCha20 | Self::Salsa20 => Some(32),
            Self::A5_1 => Some(8),
            Self::Zuc | Self::Snow3G | Self::Grain128 => Some(16),
            Self::Trivium => Some(10),
            Self::Rc4 | Self::Unknown => None, // Rc4: variable 1-256
        }
    }
}

// ── KeystreamPattern ──────────────────────────────────────────────────────────

/// A byte-level pattern associated with a stream cipher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystreamPattern {
    /// Human-readable description.
    pub description: String,
    /// Cipher being identified.
    pub kind: StreamCipherKind,
    /// Byte pattern.
    pub bytes: Vec<u8>,
    /// Per-byte mask (0xFF = exact, 0x00 = wildcard).
    pub mask: Vec<u8>,
    /// Confidence weight [0.0, 1.0].
    pub weight: f32,
    /// `true` when this pattern comes from a named constant (not opcodes).
    pub is_constant: bool,
}

impl KeystreamPattern {
    /// Create a new pattern entry.
    #[must_use]
    pub fn new(
        description: impl Into<String>,
        kind: StreamCipherKind,
        bytes: Vec<u8>,
        mask: Vec<u8>,
        weight: f32,
        is_constant: bool,
    ) -> Self {
        Self {
            description: description.into(),
            kind,
            bytes,
            mask,
            weight: weight.clamp(0.0, 1.0),
            is_constant,
        }
    }
}

// ── StreamCipherDetection ─────────────────────────────────────────────────────

/// A single detection event returned by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCipherDetection {
    /// Cipher identified.
    pub kind: StreamCipherKind,
    /// Byte offset.
    pub offset: usize,
    /// Confidence [0.0, 1.0].
    pub confidence: f32,
    /// Human-readable evidence description.
    pub evidence: String,
}

impl StreamCipherDetection {
    #[must_use]
    fn new(kind: StreamCipherKind, offset: usize, confidence: f32, evidence: impl Into<String>) -> Self {
        Self { kind, offset, confidence: confidence.clamp(0.0, 1.0), evidence: evidence.into() }
    }

    /// Returns `true` if confidence ≥ 0.80.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.80
    }
}

// ── StreamCipherReport ────────────────────────────────────────────────────────

/// Aggregated report from the stream cipher detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCipherReport {
    /// All detections sorted by offset.
    pub detections: Vec<StreamCipherDetection>,
    /// Ranked `(StreamCipherKind, combined_confidence)` pairs.
    pub ranked: Vec<(StreamCipherKind, f32)>,
}

impl StreamCipherReport {
    /// Returns the top-ranked cipher kind, if any.
    #[must_use]
    pub fn top_kind(&self) -> Option<StreamCipherKind> {
        self.ranked.first().map(|(k, _)| *k)
    }

    /// Histogram: cipher kind → number of detections.
    #[must_use]
    pub fn kind_histogram(&self) -> HashMap<StreamCipherKind, usize> {
        let mut m: HashMap<StreamCipherKind, usize> = HashMap::new();
        for d in &self.detections {
            *m.entry(d.kind).or_insert(0) += 1;
        }
        m
    }

    /// Returns `true` if any detection is high-confidence.
    #[must_use]
    pub fn has_high_confidence(&self) -> bool {
        self.detections.iter().any(StreamCipherDetection::is_high_confidence)
    }
}

// ── built-in pattern database ─────────────────────────────────────────────────

fn builtin_patterns() -> Vec<KeystreamPattern> {
    let mut p = builtin_patterns_rc4_chacha();
    p.extend(builtin_patterns_other());
    p
}

fn builtin_patterns_rc4_chacha() -> Vec<KeystreamPattern> {
    vec![
        KeystreamPattern::new("RC4-KSA-push-256", StreamCipherKind::Rc4,
            vec![0x68,0x00,0x01,0x00,0x00], vec![0xFF,0xFF,0xFF,0xFF,0xFF], 0.62, false),
        KeystreamPattern::new("RC4-CMP-FF", StreamCipherKind::Rc4,
            vec![0x80,0x00,0xFF], vec![0xFF,0x00,0xFF], 0.55, false),
        KeystreamPattern::new("RC4-XCHG-swap", StreamCipherKind::Rc4,
            vec![0x86,0x04,0x08], vec![0xFF,0xFF,0xFF], 0.70, false),
        KeystreamPattern::new("ChaCha20-sigma", StreamCipherKind::ChaCha20,
            b"expand 32-byte k".to_vec(), vec![0xFF;16], 0.98, true),
        KeystreamPattern::new("ChaCha20-expa-LE", StreamCipherKind::ChaCha20,
            0x6170_7865u32.to_le_bytes().to_vec(), vec![0xFF;4], 0.88, true),
        KeystreamPattern::new("ChaCha20-nd3-LE", StreamCipherKind::ChaCha20,
            0x3320_646eu32.to_le_bytes().to_vec(), vec![0xFF;4], 0.88, true),
        KeystreamPattern::new("ChaCha20-2by-LE", StreamCipherKind::ChaCha20,
            0x7962_2d32u32.to_le_bytes().to_vec(), vec![0xFF;4], 0.88, true),
        KeystreamPattern::new("ChaCha20-tek-LE", StreamCipherKind::ChaCha20,
            0x6b20_6574u32.to_le_bytes().to_vec(), vec![0xFF;4], 0.88, true),
        KeystreamPattern::new("Salsa20-sigma", StreamCipherKind::Salsa20,
            b"expand 32-byte k".to_vec(), vec![0xFF;16], 0.85, true),
        KeystreamPattern::new("Salsa20-ROL7", StreamCipherKind::Salsa20,
            vec![0xC1,0xC0,0x07], vec![0xFF,0xF8,0xFF], 0.60, false),
    ]
}

fn builtin_patterns_other() -> Vec<KeystreamPattern> {
    vec![
        KeystreamPattern::new("ZUC-LFSR-const-0x44D7", StreamCipherKind::Zuc,
            0x44D7u16.to_le_bytes().to_vec(), vec![0xFF,0xFF], 0.65, true),
        KeystreamPattern::new("ZUC-D0", StreamCipherKind::Zuc,
            0x44D7u16.to_be_bytes().to_vec(), vec![0xFF,0xFF], 0.65, true),
        KeystreamPattern::new("SNOW3G-MULx", StreamCipherKind::Snow3G,
            vec![0x8E,0x00,0x00,0x00], vec![0xFF,0xFF,0xFF,0xFF], 0.60, true),
        KeystreamPattern::new("Trivium-state-init", StreamCipherKind::Trivium,
            vec![0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00],
            vec![0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF], 0.72, true),
        KeystreamPattern::new("Grain128-LFSR-poly", StreamCipherKind::Grain128,
            0x8000_0057u32.to_le_bytes().to_vec(), vec![0xFF;4], 0.82, true),
        KeystreamPattern::new("A5_1-CMP-100", StreamCipherKind::A5_1,
            vec![0x3D,0x00,0x01,0x00,0x00], vec![0xFF,0xFF,0xFF,0xFF,0xFF], 0.55, false),
        KeystreamPattern::new("A5_1-R1-mask", StreamCipherKind::A5_1,
            0x4FFF_FFF8u32.to_le_bytes().to_vec(), vec![0xFF;4], 0.78, true),
    ]
}

// ── StreamCipherDetector ──────────────────────────────────────────────────────

/// Scans binary data for stream cipher implementations.
pub struct StreamCipherDetector {
    /// Minimum confidence for a detection to be reported.
    pub min_confidence: f32,
    patterns: Vec<KeystreamPattern>,
}

impl Default for StreamCipherDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamCipherDetector {
    /// Create with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self { min_confidence: 0.55, patterns: builtin_patterns() }
    }

    /// Set a custom minimum confidence threshold.
    #[must_use]
    pub const fn with_min_confidence(mut self, min: f32) -> Self {
        self.min_confidence = min;
        self
    }

    /// Add a custom pattern to the detector.
    pub fn add_pattern(&mut self, pat: KeystreamPattern) {
        self.patterns.push(pat);
    }

    /// Scan `binary` and return all individual detections above threshold.
    #[must_use]
    pub fn scan(&self, binary: &[u8]) -> Vec<StreamCipherDetection> {
        let mut out: Vec<StreamCipherDetection> = Vec::new();
        for pat in &self.patterns {
            if pat.weight < self.min_confidence {
                continue;
            }
            for offset in masked_scan(binary, &pat.bytes, &pat.mask) {
                out.push(StreamCipherDetection::new(
                    pat.kind,
                    offset,
                    pat.weight,
                    format!("'{}' at 0x{:X}", pat.description, offset),
                ));
            }
        }
        out.sort_by_key(|d| d.offset);
        out
    }

    /// Identify likely stream ciphers; returns ranked `(kind, combined_confidence)`.
    #[must_use]
    pub fn identify(&self, binary: &[u8]) -> Vec<(StreamCipherKind, f32)> {
        let detections = self.scan(binary);
        let mut buckets: HashMap<StreamCipherKind, Vec<f32>> = HashMap::new();
        for d in detections {
            buckets.entry(d.kind).or_default().push(d.confidence);
        }
        let mut ranked: Vec<(StreamCipherKind, f32)> = buckets
            .into_iter()
            .map(|(k, v)| (k, combined_confidence(v.iter().copied())))
            .filter(|(_, c)| *c >= self.min_confidence)
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked
    }

    /// Full report: detections + ranked identifications.
    #[must_use]
    pub fn full_report(&self, binary: &[u8]) -> StreamCipherReport {
        let detections = self.scan(binary);
        let ranked = self.identify(binary);
        StreamCipherReport { detections, ranked }
    }

    /// Returns `true` if `binary` appears to contain any stream cipher.
    #[must_use]
    pub fn has_stream_cipher(&self, binary: &[u8]) -> bool {
        !self.scan(binary).is_empty()
    }

    /// Returns only high-confidence detections (≥ 0.80).
    #[must_use]
    pub fn high_confidence_detections(&self, binary: &[u8]) -> Vec<StreamCipherDetection> {
        self.scan(binary).into_iter().filter(StreamCipherDetection::is_high_confidence).collect()
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn masked_scan(data: &[u8], pattern: &[u8], mask: &[u8]) -> Vec<usize> {
    let plen = pattern.len();
    if plen == 0 || plen > data.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pos in 0..=(data.len() - plen) {
        let hit = pattern
            .iter()
            .enumerate()
            .all(|(i, &p)| mask[i] == 0x00 || (data[pos + i] & mask[i]) == (p & mask[i]));
        if hit {
            out.push(pos);
        }
    }
    out
}

fn combined_confidence(scores: impl Iterator<Item = f32>) -> f32 {
    let miss = scores.fold(1.0f32, |acc, s| acc * (1.0 - s.clamp(0.0, 1.0)));
    (1.0 - miss).clamp(0.0, 0.99)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_chacha20_sigma_full() {
        let d = StreamCipherDetector::new();
        let dets = d.scan(b"expand 32-byte k");
        assert!(dets.iter().any(|x| x.kind == StreamCipherKind::ChaCha20 && x.confidence >= 0.85));
    }

    #[test]
    fn test_scan_chacha20_expa_le() {
        let b = 0x6170_7865u32.to_le_bytes();
        let d = StreamCipherDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.kind == StreamCipherKind::ChaCha20));
    }

    #[test]
    fn test_identify_chacha20_ranked_first() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x6170_7865u32.to_le_bytes());
        data.extend_from_slice(&0x3320_646eu32.to_le_bytes());
        data.extend_from_slice(&0x7962_2d32u32.to_le_bytes());
        let d = StreamCipherDetector::new();
        let ranked = d.identify(&data);
        assert!(!ranked.is_empty());
        assert_eq!(ranked[0].0, StreamCipherKind::ChaCha20);
    }

    #[test]
    fn test_scan_grain128_poly() {
        let b = 0x8000_0057u32.to_le_bytes();
        let d = StreamCipherDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.kind == StreamCipherKind::Grain128));
    }

    #[test]
    fn test_scan_rc4_push_256() {
        let b = [0x68, 0x00, 0x01, 0x00, 0x00];
        let d = StreamCipherDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.kind == StreamCipherKind::Rc4));
    }

    #[test]
    fn test_scan_rc4_xchg() {
        let b = [0x86, 0x04, 0x08];
        let d = StreamCipherDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.kind == StreamCipherKind::Rc4));
    }

    #[test]
    fn test_scan_a5_1_r1_mask() {
        let b = 0x4FFF_FFF8u32.to_le_bytes();
        let d = StreamCipherDetector::new();
        let dets = d.scan(&b);
        assert!(dets.iter().any(|x| x.kind == StreamCipherKind::A5_1));
    }

    #[test]
    fn test_full_report_top_kind() {
        let data = b"expand 32-byte k";
        let d = StreamCipherDetector::new();
        let report = d.full_report(data);
        assert!(report.top_kind().is_some());
    }

    #[test]
    fn test_kind_histogram() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x6170_7865u32.to_le_bytes()); // chacha20
        data.extend_from_slice(&0x3320_646eu32.to_le_bytes()); // chacha20
        let d = StreamCipherDetector::new();
        let report = d.full_report(&data);
        let hist = report.kind_histogram();
        assert!(hist.get(&StreamCipherKind::ChaCha20).copied().unwrap_or(0) >= 1);
    }

    #[test]
    fn test_has_stream_cipher_true() {
        let data = b"expand 32-byte k";
        let d = StreamCipherDetector::new();
        assert!(d.has_stream_cipher(data));
    }

    #[test]
    fn test_has_stream_cipher_false() {
        let data = b"\x00\x00\x00\x00";
        let d = StreamCipherDetector::new();
        assert!(!d.has_stream_cipher(data));
    }

    #[test]
    fn test_high_confidence_detections() {
        let data = b"expand 32-byte k";
        let d = StreamCipherDetector::new();
        let hc = d.high_confidence_detections(data);
        assert!(!hc.is_empty());
        assert!(hc.iter().all(|det| det.confidence >= 0.80));
    }

    #[test]
    fn test_stream_cipher_kind_predicates() {
        assert!(StreamCipherKind::Rc4.is_weak());
        assert!(StreamCipherKind::A5_1.is_weak());
        assert!(!StreamCipherKind::ChaCha20.is_weak());
        assert!(StreamCipherKind::ChaCha20.is_modern());
        assert!(!StreamCipherKind::Rc4.is_modern());
    }

    #[test]
    fn test_kind_key_bytes() {
        assert_eq!(StreamCipherKind::ChaCha20.key_bytes(), Some(32));
        assert_eq!(StreamCipherKind::Rc4.key_bytes(), None);
    }

    #[test]
    fn test_builtin_patterns_not_empty() {
        assert!(!builtin_patterns().is_empty());
    }

    #[test]
    fn test_min_confidence_filter() {
        let b = [0x68, 0x00, 0x01, 0x00, 0x00]; // RC4, weight 0.62
        let d = StreamCipherDetector::new().with_min_confidence(0.90);
        let dets = d.scan(&b);
        assert!(dets.is_empty()); // 0.62 < 0.90 so filtered
    }
}
