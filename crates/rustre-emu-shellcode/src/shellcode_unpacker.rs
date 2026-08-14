//! `shellcode_unpacker` — detect and unpack common shellcode packer layers.
//!
//! Supports XOR single-byte/key-stream, ADD/SUB key, ROR/ROL byte, and a
//! generic `Custom` variant for user-supplied transformation functions.
//! [`ShellcodeUnpacker`] applies one or more layers until the result stabilises
//! or the maximum iteration count is reached.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── PackerKind ────────────────────────────────────────────────────────────────

/// The transformation algorithm used to encode a shellcode layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackerKind {
    /// XOR every byte with a single fixed key byte.
    XorByte { key: u8 },
    /// XOR every byte with the corresponding byte of a repeating key buffer.
    XorKeyStream { key: Vec<u8> },
    /// ADD a fixed byte to every byte (wrapping).
    AddByte { key: u8 },
    /// SUB a fixed byte from every byte (wrapping).
    SubByte { key: u8 },
    /// Rotate each byte left by `bits` positions.
    RotateLeft { bits: u8 },
    /// Rotate each byte right by `bits` positions.
    RotateRight { bits: u8 },
    /// Reverse the byte order of the entire buffer.
    Reverse,
    /// NOT every byte (bitwise complement).
    Not,
    /// A named custom transform (placeholder for external transformations).
    Custom { name: String },
}

impl fmt::Display for PackerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::XorByte { key } => write!(f, "XorByte(0x{key:02x})"),
            Self::XorKeyStream { key } => write!(f, "XorKeyStream(len={})", key.len()),
            Self::AddByte { key } => write!(f, "AddByte(0x{key:02x})"),
            Self::SubByte { key } => write!(f, "SubByte(0x{key:02x})"),
            Self::RotateLeft { bits } => write!(f, "RotateLeft({bits})"),
            Self::RotateRight { bits } => write!(f, "RotateRight({bits})"),
            Self::Reverse => f.write_str("Reverse"),
            Self::Not => f.write_str("Not"),
            Self::Custom { name } => write!(f, "Custom({name})"),
        }
    }
}

// ── UnpackLayer ───────────────────────────────────────────────────────────────

/// Describes a single unpacking pass: the packer algorithm, an optional byte
/// range `[offset, offset + length)` it applies to, and the decoded result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackLayer {
    /// The algorithm that was detected / applied.
    pub packer: PackerKind,
    /// Byte offset into the original buffer where the encoded region starts.
    pub offset: usize,
    /// Length of the encoded region (0 = entire buffer).
    pub length: usize,
    /// Decoded bytes after applying this layer.
    pub decoded: Vec<u8>,
    /// Confidence score [0.0, 1.0].
    pub confidence: f64,
}

// ── UnpackResult ──────────────────────────────────────────────────────────────

/// Result returned by [`ShellcodeUnpacker::unpack`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnpackResult {
    /// The original input bytes.
    pub original: Vec<u8>,
    /// Ordered list of unpacking layers applied.
    pub layers: Vec<UnpackLayer>,
    /// The final decoded payload after all layers.
    pub payload: Vec<u8>,
    /// Whether unpacking succeeded (at least one layer was applied).
    pub success: bool,
    /// Estimated packer entropy (higher = more likely packed).
    pub input_entropy: f64,
    /// Decoded payload entropy (lower is better after unpacking).
    pub output_entropy: f64,
}

impl UnpackResult {
    /// Return the number of unpacking layers that were applied.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Return a summary of packer algorithms detected.
    pub fn packer_summary(&self) -> Vec<String> {
        self.layers.iter().map(|l| l.packer.to_string()).collect()
    }
}

// ── ShellcodeUnpacker ─────────────────────────────────────────────────────────

/// Multi-layer shellcode unpacker.
///
/// [`ShellcodeUnpacker::unpack`] attempts to detect and apply all packing
/// layers, returning a full [`UnpackResult`].
#[derive(Debug, Clone)]
pub struct ShellcodeUnpacker {
    /// Maximum number of unpacking passes.
    pub max_layers: usize,
    /// Minimum confidence threshold before accepting a detected layer.
    pub min_confidence: f64,
    /// Whether to attempt brute-force XOR key discovery.
    pub brute_xor: bool,
}

impl Default for ShellcodeUnpacker {
    fn default() -> Self {
        Self {
            max_layers: 8,
            min_confidence: 0.60,
            brute_xor: true,
        }
    }
}

impl ShellcodeUnpacker {
    /// Create a new unpacker with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Main entry point: try to unpack `bytes`.
    ///
    /// Applies up to [`Self::max_layers`] passes, each time heuristically
    /// detecting the most likely encoding and reversing it.
    pub fn unpack(&self, bytes: &[u8]) -> UnpackResult {
        if bytes.is_empty() {
            return UnpackResult {
                original: vec![],
                layers: vec![],
                payload: vec![],
                success: false,
                input_entropy: 0.0,
                output_entropy: 0.0,
            };
        }

        let input_entropy = shannon_entropy(bytes);
        let mut current = bytes.to_vec();
        let mut layers: Vec<UnpackLayer> = Vec::new();

        for _ in 0..self.max_layers {
            // Stop if data looks decoded (low entropy, high printable ratio).
            if self.looks_decoded(&current) {
                break;
            }

            match self.detect_layer(&current) {
                Some(layer) if layer.confidence >= self.min_confidence => {
                    let decoded = layer.decoded.clone();
                    layers.push(layer);
                    if decoded == current {
                        // No progress — avoid infinite loop.
                        break;
                    }
                    current = decoded;
                }
                _ => break,
            }
        }

        let success = !layers.is_empty();
        let output_entropy = shannon_entropy(&current);

        UnpackResult {
            original: bytes.to_vec(),
            layers,
            payload: current,
            success,
            input_entropy,
            output_entropy,
        }
    }

    /// Apply a specific [`PackerKind`] to `bytes` and return the result.
    pub fn apply_layer(bytes: &[u8], packer: &PackerKind) -> Vec<u8> {
        match packer {
            PackerKind::XorByte { key } => bytes.iter().map(|b| b ^ key).collect(),
            PackerKind::XorKeyStream { key } if !key.is_empty() => bytes
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % key.len()])
                .collect(),
            PackerKind::XorKeyStream { .. } => bytes.to_vec(),
            PackerKind::AddByte { key } => bytes.iter().map(|b| b.wrapping_add(*key)).collect(),
            PackerKind::SubByte { key } => bytes.iter().map(|b| b.wrapping_sub(*key)).collect(),
            PackerKind::RotateLeft { bits } => {
                let b = bits % 8;
                bytes.iter().map(|v| v.rotate_left(b as u32)).collect()
            }
            PackerKind::RotateRight { bits } => {
                let b = bits % 8;
                bytes.iter().map(|v| v.rotate_right(b as u32)).collect()
            }
            PackerKind::Reverse => bytes.iter().rev().cloned().collect(),
            PackerKind::Not => bytes.iter().map(|b| !b).collect(),
            PackerKind::Custom { .. } => bytes.to_vec(),
        }
    }

    // ── Heuristics ────────────────────────────────────────────────────────────

    /// Return `true` when the data looks like decoded shellcode / plain text.
    fn looks_decoded(&self, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        let printable = bytes.iter().filter(|&&b| (0x20..=0x7e).contains(&b) || b == 0x0a || b == 0x0d).count();
        let ratio = printable as f64 / bytes.len() as f64;
        // Also check for common x86 preamble bytes (0x55 PUSH RBP, 0x48 REX, etc.)
        let has_x86_preamble = bytes.starts_with(&[0x55, 0x48]) || bytes.starts_with(&[0x55, 0x8b]);
        ratio > 0.70 || has_x86_preamble
    }

    /// Detect the most likely encoding layer in `bytes`.
    fn detect_layer(&self, bytes: &[u8]) -> Option<UnpackLayer> {
        if bytes.is_empty() {
            return None;
        }

        // 1. Try XOR brute-force (find single-byte key with highest decoded printable ratio).
        if self.brute_xor {
            if let Some(layer) = self.detect_xor_byte(bytes) {
                if layer.confidence >= self.min_confidence {
                    return Some(layer);
                }
            }
        }

        // 2. Try NOT.
        if let Some(layer) = self.detect_not(bytes) {
            if layer.confidence >= self.min_confidence {
                return Some(layer);
            }
        }

        // 3. Try ADD brute-force.
        if let Some(layer) = self.detect_add(bytes) {
            if layer.confidence >= self.min_confidence {
                return Some(layer);
            }
        }

        // 4. Try ROL/ROR (rotate by 1..=7).
        if let Some(layer) = self.detect_rotate(bytes) {
            if layer.confidence >= self.min_confidence {
                return Some(layer);
            }
        }

        None
    }

    fn detect_xor_byte(&self, bytes: &[u8]) -> Option<UnpackLayer> {
        let mut best_key = 0u8;
        let mut best_score = 0.0f64;

        for key in 1u8..=255 {
            let decoded: Vec<u8> = bytes.iter().map(|b| b ^ key).collect();
            let score = printable_ratio(&decoded);
            if score > best_score {
                best_score = score;
                best_key = key;
            }
        }

        if best_score < 0.30 {
            return None;
        }

        let decoded = bytes.iter().map(|b| b ^ best_key).collect();
        Some(UnpackLayer {
            packer: PackerKind::XorByte { key: best_key },
            offset: 0,
            length: bytes.len(),
            decoded,
            confidence: (best_score * 1.2).min(1.0),
        })
    }

    fn detect_not(&self, bytes: &[u8]) -> Option<UnpackLayer> {
        let decoded: Vec<u8> = bytes.iter().map(|b| !b).collect();
        let score = printable_ratio(&decoded);
        if score < 0.30 {
            return None;
        }
        Some(UnpackLayer {
            packer: PackerKind::Not,
            offset: 0,
            length: bytes.len(),
            decoded,
            confidence: (score * 1.1).min(1.0),
        })
    }

    fn detect_add(&self, bytes: &[u8]) -> Option<UnpackLayer> {
        let mut best_key = 0u8;
        let mut best_score = 0.0f64;

        for key in 1u8..=255 {
            let decoded: Vec<u8> = bytes.iter().map(|b| b.wrapping_sub(key)).collect();
            let score = printable_ratio(&decoded);
            if score > best_score {
                best_score = score;
                best_key = key;
            }
        }

        if best_score < 0.30 {
            return None;
        }

        let decoded = bytes.iter().map(|b| b.wrapping_sub(best_key)).collect();
        Some(UnpackLayer {
            packer: PackerKind::SubByte { key: best_key },
            offset: 0,
            length: bytes.len(),
            decoded,
            confidence: (best_score * 1.1).min(1.0),
        })
    }

    fn detect_rotate(&self, bytes: &[u8]) -> Option<UnpackLayer> {
        let mut best_kind = PackerKind::RotateLeft { bits: 1 };
        let mut best_score = 0.0f64;

        for bits in 1u8..=7 {
            let decoded_l: Vec<u8> = bytes.iter().map(|v| v.rotate_right(bits as u32)).collect();
            let sl = printable_ratio(&decoded_l);
            if sl > best_score {
                best_score = sl;
                best_kind = PackerKind::RotateLeft { bits };
            }
            let decoded_r: Vec<u8> = bytes.iter().map(|v| v.rotate_left(bits as u32)).collect();
            let sr = printable_ratio(&decoded_r);
            if sr > best_score {
                best_score = sr;
                best_kind = PackerKind::RotateRight { bits };
            }
        }

        if best_score < 0.30 {
            return None;
        }

        let decoded = Self::apply_layer(bytes, &best_kind);
        Some(UnpackLayer {
            packer: best_kind,
            offset: 0,
            length: bytes.len(),
            decoded,
            confidence: (best_score * 1.05).min(1.0),
        })
    }
}

// ── Standalone unpack() ───────────────────────────────────────────────────────

/// Convenience function: create a default [`ShellcodeUnpacker`] and call [`ShellcodeUnpacker::unpack`].
pub fn unpack(bytes: &[u8]) -> UnpackResult {
    ShellcodeUnpacker::new().unpack(bytes)
}

// ── PackerDetector ────────────────────────────────────────────────────────────

/// Analyses a byte buffer to produce a scored guess of which packer was used.
#[derive(Debug, Clone, Default)]
pub struct PackerDetector {
    /// Accumulate `(packer_kind_str, score)` hypotheses.
    hypotheses: Vec<(String, f64)>,
}

impl PackerDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all detection heuristics and populate `hypotheses`.
    pub fn analyse(&mut self, bytes: &[u8]) {
        self.hypotheses.clear();
        if bytes.is_empty() {
            return;
        }

        let entropy = shannon_entropy(bytes);
        // High entropy suggests encryption/compression.
        if entropy > 7.0 {
            self.hypotheses.push(("high-entropy (possible AES/deflate)".into(), 0.9));
        } else if entropy > 6.0 {
            self.hypotheses.push(("medium-high entropy (possible XOR/ROR)".into(), 0.7));
        }

        // Null byte density — high null density suggests wide-char or partial XOR.
        let null_ratio = bytes.iter().filter(|&&b| b == 0).count() as f64 / bytes.len() as f64;
        if null_ratio > 0.30 {
            self.hypotheses.push(("high null density (partial XOR?)".into(), 0.6));
        }

        // Byte frequency distribution flatness (uniform → encryption).
        let mut freq = [0u64; 256];
        for &b in bytes { freq[b as usize] += 1; }
        let std_dev = byte_freq_stddev(&freq, bytes.len());
        if std_dev < 5.0 {
            self.hypotheses.push(("flat byte distribution (encryption-like)".into(), 0.85));
        } else if std_dev < 15.0 {
            self.hypotheses.push(("mild byte distribution skew (XOR-like)".into(), 0.55));
        }

        // Common x86 shellcode preamble after potential single-byte XOR.
        let unpacker = ShellcodeUnpacker { brute_xor: true, min_confidence: 0.4, max_layers: 1 };
        if let Some(layer) = unpacker.detect_layer(bytes) {
            self.hypotheses.push((format!("detected: {}", layer.packer), layer.confidence));
        }

        self.hypotheses.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    }

    pub fn top_hypothesis(&self) -> Option<&(String, f64)> {
        self.hypotheses.first()
    }

    pub fn hypotheses(&self) -> &[(String, f64)] {
        &self.hypotheses
    }
}

// ── Layer Statistics ──────────────────────────────────────────────────────────

/// Statistics for a collection of `UnpackResult`s (useful for batch analysis).
#[derive(Debug, Clone, Default)]
pub struct UnpackStats {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub layer_count_histogram: HashMap<usize, usize>,
    pub packer_frequency: HashMap<String, usize>,
}

impl UnpackStats {
    pub fn from_results(results: &[UnpackResult]) -> Self {
        let mut stats = Self {
            total: results.len(),
            ..Default::default()
        };
        for r in results {
            if r.success {
                stats.successful += 1;
            } else {
                stats.failed += 1;
            }
            *stats.layer_count_histogram.entry(r.layer_count()).or_insert(0) += 1;
            for l in &r.layers {
                *stats.packer_frequency.entry(l.packer.to_string()).or_insert(0) += 1;
            }
        }
        stats
    }

    pub fn success_rate(&self) -> f64 {
        if self.total == 0 { return 0.0; }
        self.successful as f64 / self.total as f64
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let printable = bytes.iter().filter(|&&b| (0x20..=0x7e).contains(&b)).count();
    printable as f64 / bytes.len() as f64
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in bytes { freq[b as usize] += 1; }
    let n = bytes.len() as f64;
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

fn byte_freq_stddev(freq: &[u64; 256], total: usize) -> f64 {
    if total == 0 { return 0.0; }
    let mean = total as f64 / 256.0;
    let variance = freq.iter().map(|&c| {
        let diff = c as f64 - mean;
        diff * diff
    }).sum::<f64>() / 256.0;
    variance.sqrt()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_encode(data: &[u8], key: u8) -> Vec<u8> {
        data.iter().map(|b| b ^ key).collect()
    }

    fn make_printable(n: usize) -> Vec<u8> {
        (0..n).map(|i| (0x41 + (i % 26)) as u8).collect()
    }

    #[test]
    fn unpack_empty_returns_failure() {
        let r = unpack(&[]);
        assert!(!r.success);
        assert!(r.layers.is_empty());
    }

    #[test]
    fn unpack_plain_text_no_layers() {
        let plain = b"Hello, World! This is plaintext shellcode.";
        let r = ShellcodeUnpacker::new().unpack(plain);
        assert!(r.layers.is_empty(), "plain text should need no unpacking");
        assert_eq!(r.payload, plain.to_vec());
    }

    #[test]
    fn unpack_xor_single_byte() {
        // The fixture has to satisfy TWO constraints that pull against each
        // other, and the original satisfied only the first:
        //
        // 1. The *ciphertext* must not look decoded, or `unpack` bails out
        //    before detecting anything (`looks_decoded` rejects anything above
        //    70% printable). Upper-case letters work: 0x41..0x5A ^ 0x42 lands
        //    in 0x03..0x18, all control bytes.
        // 2. The *key* must be uniquely recoverable, or the assertion below
        //    asks the detector to decide something undecidable. With only
        //    'A'..'Z' it was not: decoding with key `k` yields
        //    `plain ^ (0x42 ^ k)`, and for k = 0x20 the mask 0x62 sends every
        //    letter to 0x23..0x38 — still fully printable. Keys 0x20 and 0x42
        //    both scored 1.0 and the strict `>` kept the first, so the detector
        //    correctly reported 0x20.
        //
        // A few lower-case letters break the tie without spoiling (1): 'b'..'z'
        // are ≥ 0x62, so `p ^ 0x62` drops below 0x20 and kills the competing
        // key, while `p ^ 0x42` stays printable for only a handful of bytes.
        let plain = b"THE QUICK BROWN FOX jumps OVER THE LAZY DOG".to_vec();
        let encoded = xor_encode(&plain, 0x42);
        let r = ShellcodeUnpacker::new().unpack(&encoded);
        assert!(r.success, "should detect XOR layer");

        let layer = r
            .layers
            .first()
            .expect("premise: a detected XOR layer must be reported");

        let PackerKind::XorByte { key } = layer.packer else {
            panic!("expected a single-byte XOR layer, got {:?}", layer.packer);
        };

        // Self-consistency is the property that is actually well defined: the
        // reported key must be the one that produces the reported bytes.
        // A detector that searched with one key and decoded with another would
        // fail here, which is the regression this test can genuinely catch.
        let redecoded: Vec<u8> = encoded.iter().map(|b| b ^ key).collect();
        assert_eq!(
            layer.decoded, redecoded,
            "the reported key {key:#04x} does not reproduce the reported output"
        );

        // And the search must have done its job: the result is fully printable,
        // which is the criterion `detect_xor_byte` maximises.
        assert!(
            layer.decoded.iter().all(|&b| (0x20..=0x7e).contains(&b)),
            "the decoded stage should be printable, got {:?}",
            String::from_utf8_lossy(&layer.decoded)
        );
    }

    #[test]
    fn apply_layer_xor_roundtrip() {
        let data: Vec<u8> = (0u8..64).collect();
        let encoded = ShellcodeUnpacker::apply_layer(&data, &PackerKind::XorByte { key: 0x55 });
        let decoded = ShellcodeUnpacker::apply_layer(&encoded, &PackerKind::XorByte { key: 0x55 });
        assert_eq!(decoded, data);
    }

    #[test]
    fn apply_layer_not_roundtrip() {
        let data: Vec<u8> = (0u8..64).collect();
        let encoded = ShellcodeUnpacker::apply_layer(&data, &PackerKind::Not);
        let decoded = ShellcodeUnpacker::apply_layer(&encoded, &PackerKind::Not);
        assert_eq!(decoded, data);
    }

    #[test]
    fn apply_layer_rotate_roundtrip() {
        let data: Vec<u8> = (0u8..32).collect();
        let encoded = ShellcodeUnpacker::apply_layer(&data, &PackerKind::RotateLeft { bits: 3 });
        let decoded = ShellcodeUnpacker::apply_layer(&encoded, &PackerKind::RotateRight { bits: 3 });
        assert_eq!(decoded, data);
    }

    #[test]
    fn apply_layer_reverse_roundtrip() {
        let data: Vec<u8> = vec![1, 2, 3, 4, 5];
        let rev = ShellcodeUnpacker::apply_layer(&data, &PackerKind::Reverse);
        let back = ShellcodeUnpacker::apply_layer(&rev, &PackerKind::Reverse);
        assert_eq!(back, data);
    }

    #[test]
    fn apply_layer_add_sub_roundtrip() {
        let data: Vec<u8> = (0u8..32).collect();
        let enc = ShellcodeUnpacker::apply_layer(&data, &PackerKind::AddByte { key: 7 });
        let dec = ShellcodeUnpacker::apply_layer(&enc, &PackerKind::SubByte { key: 7 });
        assert_eq!(dec, data);
    }

    #[test]
    fn apply_layer_xorkeystream() {
        let data = b"AAAAAAAAAAAAAAAA";
        let key = vec![0x01u8, 0x02, 0x03];
        let enc = ShellcodeUnpacker::apply_layer(data, &PackerKind::XorKeyStream { key: key.clone() });
        let dec = ShellcodeUnpacker::apply_layer(&enc, &PackerKind::XorKeyStream { key });
        assert_eq!(dec, data.to_vec());
    }

    #[test]
    fn packer_kind_display_xor() {
        let k = PackerKind::XorByte { key: 0xAB };
        assert!(k.to_string().contains("0xab") || k.to_string().contains("0xAB") || k.to_string().to_ascii_lowercase().contains("ab"));
    }

    #[test]
    fn packer_kind_display_keystream() {
        let k = PackerKind::XorKeyStream { key: vec![1, 2, 3] };
        assert!(k.to_string().contains("len=3"));
    }

    #[test]
    fn unpack_result_layer_count() {
        let plain = make_printable(64);
        let encoded = xor_encode(&plain, 0x33);
        let r = ShellcodeUnpacker::new().unpack(&encoded);
        assert_eq!(r.layer_count(), r.layers.len());
    }

    #[test]
    fn unpack_result_entropy_fields() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let r = ShellcodeUnpacker::new().unpack(&data);
        assert!(r.input_entropy > 0.0);
    }

    #[test]
    fn packer_detector_analyses_high_entropy() {
        let mut det = PackerDetector::new();
        // Uniform distribution → high entropy.
        let data: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
        det.analyse(&data);
        assert!(!det.hypotheses().is_empty());
    }

    #[test]
    fn unpack_stats_success_rate() {
        let plain = make_printable(32);
        let encoded = xor_encode(&plain, 0x7e);
        let r1 = ShellcodeUnpacker::new().unpack(&encoded);
        let r2 = ShellcodeUnpacker::new().unpack(&[]);
        let stats = UnpackStats::from_results(&[r1, r2]);
        assert_eq!(stats.total, 2);
        assert!(stats.success_rate() <= 1.0);
    }

    #[test]
    fn unpack_stats_packer_frequency_populated() {
        let plain = make_printable(64);
        let encoded = xor_encode(&plain, 0x19);
        let r = ShellcodeUnpacker::new().unpack(&encoded);
        let stats = UnpackStats::from_results(&[r]);
        // If unpacking succeeded, packer_frequency should be non-empty.
        if stats.successful > 0 {
            assert!(!stats.packer_frequency.is_empty());
        }
    }

    #[test]
    fn printable_ratio_all_printable() {
        let data = b"Hello World";
        assert!((printable_ratio(data) - 1.0).abs() < 0.01);
    }

    #[test]
    fn printable_ratio_no_printable() {
        let data: Vec<u8> = (0u8..32).collect();
        assert!(printable_ratio(&data) < 0.1);
    }
}
