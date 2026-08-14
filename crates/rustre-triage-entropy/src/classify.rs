//! Region classification, packed-binary scoring, and entropy-gradient anomaly
//! detection for binary triage.
//!
//! Where [`crate::shannon`] answers "how much entropy?" and
//! [`crate::randomness`] answers "is this statistically random?", this module
//! answers "what *kind* of data is this?" — distinguishing native code from
//! compressed streams, encrypted blobs, ASCII text, and padding by combining
//! entropy bands with byte-histogram features.

use serde::{Deserialize, Serialize};

use crate::byte_histogram::ByteHistogram;
use crate::casts::{u64_to_f64, usize_to_f64};

// ─────────────────────────────────────────────────────────────────────────────
// RegionClass
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristic classification of a binary region by its likely content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegionClass {
    /// Long runs of a single value (typically `0x00` or `0xFF`) — alignment
    /// padding or uninitialised data.
    Padding,
    /// Predominantly printable ASCII — strings, configuration, or scripts.
    AsciiText,
    /// Moderate entropy with structured byte usage — native machine code.
    NativeCode,
    /// High entropy with a slightly biased distribution — compressed data
    /// (zlib/LZMA streams retain faint structure).
    Compressed,
    /// Maximal entropy with a near-uniform distribution — encrypted or
    /// otherwise cryptographically random data.
    Encrypted,
    /// Does not fit any other category cleanly.
    Unknown,
}

impl std::fmt::Display for RegionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Padding => "Padding",
            Self::AsciiText => "AsciiText",
            Self::NativeCode => "NativeCode",
            Self::Compressed => "Compressed",
            Self::Encrypted => "Encrypted",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

impl RegionClass {
    /// Classify a byte buffer using entropy bands plus histogram features.
    ///
    /// The heuristic ladder is, in order:
    /// 1. very low entropy + dominant single byte → [`Padding`](Self::Padding);
    /// 2. high printable ratio → [`AsciiText`](Self::AsciiText);
    /// 3. very high entropy + near-uniform distribution →
    ///    [`Encrypted`](Self::Encrypted);
    /// 4. high entropy with mild bias → [`Compressed`](Self::Compressed);
    /// 5. moderate entropy with broad byte usage →
    ///    [`NativeCode`](Self::NativeCode);
    /// 6. otherwise [`Unknown`](Self::Unknown).
    ///
    /// Returns [`Unknown`](Self::Unknown) for empty input.
    #[must_use]
    pub fn classify(data: &[u8]) -> Self {
        if data.is_empty() {
            return Self::Unknown;
        }
        let hist = ByteHistogram::from_bytes(data);
        let entropy = crate::shannon_entropy(data);
        Self::classify_with(entropy, &hist)
    }

    /// Classify from a pre-computed entropy value and [`ByteHistogram`].
    ///
    /// Useful when both metrics have already been computed (e.g. during a
    /// block scan) to avoid recomputing them.
    #[must_use]
    pub fn classify_with(entropy: f64, hist: &ByteHistogram) -> Self {
        if hist.total == 0 {
            return Self::Unknown;
        }
        let printable = hist.printable_ratio();
        let (_, mode_count) = hist.mode();
        let mode_ratio = u64_to_f64(mode_count) / u64_to_f64(hist.total);
        let chi2_norm = hist.chi_squared_normalised();
        let distinct = hist.distinct_count();

        // 1. Padding: a single byte value dominates and entropy is tiny.
        if entropy < 1.0 && (mode_ratio > 0.90 || distinct <= 2) {
            return Self::Padding;
        }

        // 2. ASCII text: mostly printable characters.
        if printable > 0.75 && entropy < 6.0 {
            return Self::AsciiText;
        }

        // 3. Encrypted: maximal entropy with near-uniform distribution.
        if entropy > 7.5 && chi2_norm < 1.5 {
            return Self::Encrypted;
        }

        // 4. Compressed: high entropy but a measurable distribution bias.
        if entropy > 6.5 {
            return Self::Compressed;
        }

        // 5. Native code: mid entropy spread across many byte values.
        if (4.0..=6.5).contains(&entropy) && distinct > 32 && printable < 0.75 {
            return Self::NativeCode;
        }

        Self::Unknown
    }

    /// `true` for classes that warrant closer manual inspection during triage.
    #[must_use]
    pub const fn is_suspicious(self) -> bool {
        matches!(self, Self::Encrypted | Self::Compressed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// packed_score
// ─────────────────────────────────────────────────────────────────────────────

/// Compute a packed-binary likelihood score in `[0.0, 1.0]`.
///
/// The score blends three signals that together characterise packed or
/// protected executables:
/// * high overall entropy (weighted 0.5),
/// * a low printable-ASCII ratio (weighted 0.3),
/// * a near-uniform byte distribution via normalised chi-squared (weighted
///   0.2).
///
/// `0.0` means "very likely a plain, unpacked file"; values approaching `1.0`
/// strongly suggest packing, compression, or encryption. Returns `0.0` for
/// empty input.
#[must_use]
pub fn packed_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let hist = ByteHistogram::from_bytes(data);
    let entropy = crate::shannon_entropy(data);

    // Entropy contribution: 0 below 6.0 bits, ramping to 1 at 8.0 bits.
    let entropy_signal = ((entropy - 6.0) / 2.0).clamp(0.0, 1.0);

    // Printability contribution: high when text is scarce.
    let printable_signal = (1.0 - hist.printable_ratio()).clamp(0.0, 1.0);

    // Uniformity contribution: chi²_norm near 1.0 → uniform → high signal.
    // Map the distance from 1.0 (random ideal) into a [0, 1] closeness score.
    let chi2_norm = hist.chi_squared_normalised();
    let uniform_signal = (1.0 - (chi2_norm - 1.0).abs() / 4.0).clamp(0.0, 1.0);

    0.2f64.mul_add(uniform_signal, 0.5f64.mul_add(entropy_signal, 0.3 * printable_signal)).clamp(0.0, 1.0)
}

/// Convenience predicate: `true` when [`packed_score`] exceeds `0.6`.
#[must_use]
pub fn is_likely_packed(data: &[u8]) -> bool {
    packed_score(data) > 0.6
}

// ─────────────────────────────────────────────────────────────────────────────
// longest_run
// ─────────────────────────────────────────────────────────────────────────────

/// A run of consecutive identical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRun {
    /// Byte offset where the run begins.
    pub offset: usize,
    /// The repeated byte value.
    pub byte: u8,
    /// Length of the run in bytes.
    pub length: usize,
}

/// Find the longest run of a single repeated byte value in `data`.
///
/// Useful for spotting alignment padding, RLE-friendly regions, or fill bytes.
/// Returns `None` for empty input.
#[must_use]
pub fn longest_run(data: &[u8]) -> Option<ByteRun> {
    if data.is_empty() {
        return None;
    }
    let mut best = ByteRun {
        offset: 0,
        byte: data[0],
        length: 1,
    };
    let mut cur_start = 0usize;
    let mut cur_byte = data[0];
    let mut cur_len = 1usize;

    for (i, &b) in data.iter().enumerate().skip(1) {
        if b == cur_byte {
            cur_len += 1;
        } else {
            cur_byte = b;
            cur_start = i;
            cur_len = 1;
        }
        if cur_len > best.length {
            best = ByteRun {
                offset: cur_start,
                byte: cur_byte,
                length: cur_len,
            };
        }
    }
    Some(best)
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy-gradient anomaly detection
// ─────────────────────────────────────────────────────────────────────────────

/// A region whose entropy deviates sharply from its neighbours.
///
/// These transitions frequently mark the boundary of an appended payload,
/// an embedded compressed/encrypted blob, or an overlay tacked onto a file.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct EntropyAnomaly {
    /// Byte offset of the deviating block.
    pub offset: usize,
    /// Entropy of the deviating block.
    pub entropy: f64,
    /// Mean entropy of the neighbouring blocks compared against.
    pub neighbour_mean: f64,
    /// Signed deviation (`entropy - neighbour_mean`).
    pub deviation: f64,
}

impl EntropyAnomaly {
    /// `true` if the block is a sharp *increase* relative to neighbours
    /// (candidate embedded high-entropy payload).
    #[must_use]
    pub fn is_spike(&self) -> bool {
        self.deviation > 0.0
    }
}

/// Detect blocks whose entropy deviates from the local neighbourhood by more
/// than `threshold` bits.
///
/// The buffer is split into non-overlapping `block_size` chunks; for each block
/// the mean entropy of the `radius` blocks on either side is computed, and the
/// block is flagged when `|entropy - neighbour_mean| > threshold`.
///
/// This surfaces *local* anomalies that whole-file entropy misses — for
/// example a small encrypted config embedded in an otherwise low-entropy file.
///
/// Returns an empty `Vec` when `block_size` or `radius` is `0`, when the data
/// is empty, or when there are too few blocks to form a neighbourhood.
#[must_use]
pub fn detect_entropy_anomalies(
    data: &[u8],
    block_size: usize,
    radius: usize,
    threshold: f64,
) -> Vec<EntropyAnomaly> {
    if data.is_empty() || block_size == 0 || radius == 0 {
        return Vec::new();
    }

    let entropies: Vec<f64> = data
        .chunks(block_size)
        .map(crate::shannon_entropy)
        .collect();
    let n = entropies.len();
    if n <= radius {
        return Vec::new();
    }

    let mut anomalies = Vec::new();
    for (i, &e) in entropies.iter().enumerate() {
        let lo = i.saturating_sub(radius);
        let hi = (i + radius + 1).min(n);
        // Mean of the neighbourhood excluding the block itself.
        let mut sum = 0.0f64;
        let mut count = 0usize;
        for (j, &ne) in entropies.iter().enumerate().take(hi).skip(lo) {
            if j != i {
                sum += ne;
                count += 1;
            }
        }
        if count == 0 {
            continue;
        }
        let neighbour_mean = sum / usize_to_f64(count);
        let deviation = e - neighbour_mean;
        if deviation.abs() > threshold {
            anomalies.push(EntropyAnomaly {
                offset: i * block_size,
                entropy: e,
                neighbour_mean,
                deviation,
            });
        }
    }
    anomalies
}

// ─────────────────────────────────────────────────────────────────────────────
// TriageSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level aggregate of every entropy/anomaly metric for a buffer, suitable
/// for a one-shot triage report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageSummary {
    /// Number of bytes analysed.
    pub length: usize,
    /// Overall Shannon entropy (bits per byte).
    pub entropy: f64,
    /// Heuristic content classification.
    pub region_class: RegionClass,
    /// Packed-binary likelihood in `[0.0, 1.0]`.
    pub packed_score: f64,
    /// Fraction of printable-ASCII bytes.
    pub printable_ratio: f64,
    /// Fraction of null bytes.
    pub null_ratio: f64,
    /// Number of distinct byte values present.
    pub distinct_bytes: usize,
    /// The longest single-byte run, if any.
    pub longest_run: Option<ByteRun>,
    /// Number of local entropy anomalies detected with default parameters.
    pub entropy_anomaly_count: usize,
}

impl TriageSummary {
    /// Build a full triage summary over `data`.
    ///
    /// Local entropy anomalies are detected with a 256-byte block size,
    /// neighbourhood radius 4, and a 2.0-bit deviation threshold.
    #[must_use]
    pub fn analyze(data: &[u8]) -> Self {
        let hist = ByteHistogram::from_bytes(data);
        let entropy = crate::shannon_entropy(data);
        let region_class = RegionClass::classify_with(entropy, &hist);
        let anomalies = detect_entropy_anomalies(data, 256, 4, 2.0);
        Self {
            length: data.len(),
            entropy,
            region_class,
            packed_score: packed_score(data),
            printable_ratio: hist.printable_ratio(),
            null_ratio: hist.null_ratio(),
            distinct_bytes: hist.distinct_count(),
            longest_run: longest_run(data),
            entropy_anomaly_count: anomalies.len(),
        }
    }

    /// `true` if the buffer warrants closer inspection: packed, encrypted,
    /// compressed, or showing local entropy anomalies.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.packed_score > 0.6
            || self.region_class.is_suspicious()
            || self.entropy_anomaly_count > 0
    }
}

impl std::fmt::Display for TriageSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Triage(len={}, H={:.3}, class={}, packed={:.2}, printable={:.1}%, null={:.1}%, distinct={}, anomalies={})",
            self.length,
            self.entropy,
            self.region_class,
            self.packed_score,
            self.printable_ratio * 100.0,
            self.null_ratio * 100.0,
            self.distinct_bytes,
            self.entropy_anomaly_count,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_random(n: usize) -> Vec<u8> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let v = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            out.push((v >> 33) as u8);
        }
        out
    }

    fn ascii_text(n: usize) -> Vec<u8> {
        b"Hello, world! This is plain ASCII text for triage testing. "
            .iter()
            .copied()
            .cycle()
            .take(n)
            .collect()
    }

    /// Synthetic "code-like" data: many distinct byte values but a biased
    /// distribution (a handful of common opcodes/operands dominate), giving
    /// mid-range entropy (~4–6 bits) like real machine code.
    fn code_like(n: usize) -> Vec<u8> {
        // Common x86-ish bytes that recur heavily in real code.
        const COMMON: &[u8] = &[
            0x00, 0x48, 0x89, 0x8B, 0xE8, 0xFF, 0x55, 0x5D, 0xC3, 0x0F, 0x83, 0x01, 0x44, 0x24,
        ];
        let mut state: u32 = 0x1234_5678;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let r = (state >> 16) & 0xFF;
            // 75% of bytes come from the common set, 25% are arbitrary in a
            // low/mid band — broad variety, but a strong bias keeps entropy in
            // the native-code range and printable ratio modest.
            let b = if r.is_multiple_of(4) {
                (r % 160) as u8
            } else {
                COMMON[(r as usize) % COMMON.len()]
            };
            out.push(b);
        }
        out
    }

    // ── RegionClass ───────────────────────────────────────────────────────

    #[test]
    fn test_classify_empty_unknown() {
        assert_eq!(RegionClass::classify(&[]), RegionClass::Unknown);
    }

    #[test]
    fn test_classify_padding_zeros() {
        assert_eq!(RegionClass::classify(&[0u8; 4096]), RegionClass::Padding);
    }

    #[test]
    fn test_classify_padding_ff() {
        assert_eq!(RegionClass::classify(&[0xFFu8; 4096]), RegionClass::Padding);
    }

    #[test]
    fn test_classify_ascii_text() {
        assert_eq!(
            RegionClass::classify(&ascii_text(4096)),
            RegionClass::AsciiText
        );
    }

    #[test]
    fn test_classify_encrypted() {
        assert_eq!(
            RegionClass::classify(&pseudo_random(16_384)),
            RegionClass::Encrypted
        );
    }

    #[test]
    fn test_classify_native_code() {
        assert_eq!(
            RegionClass::classify(&code_like(8192)),
            RegionClass::NativeCode
        );
    }

    #[test]
    fn test_classify_display() {
        assert_eq!(RegionClass::Padding.to_string(), "Padding");
        assert_eq!(RegionClass::Encrypted.to_string(), "Encrypted");
        assert_eq!(RegionClass::NativeCode.to_string(), "NativeCode");
    }

    #[test]
    fn test_classify_is_suspicious() {
        assert!(RegionClass::Encrypted.is_suspicious());
        assert!(RegionClass::Compressed.is_suspicious());
        assert!(!RegionClass::AsciiText.is_suspicious());
        assert!(!RegionClass::Padding.is_suspicious());
    }

    // ── packed_score ──────────────────────────────────────────────────────

    #[test]
    fn test_packed_score_empty() {
        assert!((packed_score(&[]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_packed_score_random_high() {
        let s = packed_score(&pseudo_random(16_384));
        assert!(s > 0.8, "score {s} should be high for random data");
    }

    #[test]
    fn test_packed_score_text_low() {
        let s = packed_score(&ascii_text(4096));
        assert!(s < 0.5, "score {s} should be low for text");
    }

    #[test]
    fn test_packed_score_zeros_low() {
        let s = packed_score(&[0u8; 4096]);
        assert!(s < 0.4, "score {s} should be low for zeros");
    }

    #[test]
    fn test_packed_score_in_range() {
        for data in [pseudo_random(2000), ascii_text(2000), vec![0u8; 2000]] {
            let s = packed_score(&data);
            assert!((0.0..=1.0).contains(&s));
        }
    }

    #[test]
    fn test_is_likely_packed() {
        assert!(is_likely_packed(&pseudo_random(16_384)));
        assert!(!is_likely_packed(&ascii_text(4096)));
    }

    // ── longest_run ───────────────────────────────────────────────────────

    #[test]
    fn test_longest_run_empty() {
        assert!(longest_run(&[]).is_none());
    }

    #[test]
    fn test_longest_run_all_same() {
        let run = longest_run(&[0xAAu8; 100]).unwrap();
        assert_eq!(run.byte, 0xAA);
        assert_eq!(run.length, 100);
        assert_eq!(run.offset, 0);
    }

    #[test]
    fn test_longest_run_in_middle() {
        let mut data = vec![1, 2, 3];
        data.extend(vec![9u8; 10]);
        data.extend(vec![4, 5]);
        let run = longest_run(&data).unwrap();
        assert_eq!(run.byte, 9);
        assert_eq!(run.length, 10);
        assert_eq!(run.offset, 3);
    }

    #[test]
    fn test_longest_run_single_byte() {
        let run = longest_run(&[42]).unwrap();
        assert_eq!(run.length, 1);
        assert_eq!(run.byte, 42);
    }

    #[test]
    fn test_longest_run_no_repeats() {
        let data: Vec<u8> = (0u8..=255).collect();
        let run = longest_run(&data).unwrap();
        assert_eq!(run.length, 1);
    }

    // ── detect_entropy_anomalies ──────────────────────────────────────────

    #[test]
    fn test_anomalies_empty() {
        assert!(detect_entropy_anomalies(&[], 256, 4, 2.0).is_empty());
    }

    #[test]
    fn test_anomalies_zero_params() {
        let data = vec![0u8; 4096];
        assert!(detect_entropy_anomalies(&data, 0, 4, 2.0).is_empty());
        assert!(detect_entropy_anomalies(&data, 256, 0, 2.0).is_empty());
    }

    #[test]
    fn test_anomalies_uniform_none() {
        // All-zero file: every block has identical entropy → no deviation.
        let data = vec![0u8; 4096];
        assert!(detect_entropy_anomalies(&data, 256, 4, 2.0).is_empty());
    }

    #[test]
    fn test_anomalies_embedded_high_entropy_spike() {
        // Low-entropy padding with a high-entropy blob embedded in the middle.
        let mut data = vec![0u8; 4096];
        let blob = pseudo_random(512);
        let start = 2048;
        data[start..start + blob.len()].copy_from_slice(&blob);
        let anomalies = detect_entropy_anomalies(&data, 256, 4, 2.0);
        assert!(!anomalies.is_empty(), "should detect embedded blob");
        assert!(anomalies.iter().any(EntropyAnomaly::is_spike));
        // At least one anomaly should sit within the blob region.
        assert!(
            anomalies
                .iter()
                .any(|a| a.offset >= start - 256 && a.offset <= start + blob.len())
        );
    }

    #[test]
    fn test_anomaly_is_spike() {
        let a = EntropyAnomaly {
            offset: 0,
            entropy: 7.9,
            neighbour_mean: 1.0,
            deviation: 6.9,
        };
        assert!(a.is_spike());
        let b = EntropyAnomaly {
            offset: 0,
            entropy: 0.1,
            neighbour_mean: 7.0,
            deviation: -6.9,
        };
        assert!(!b.is_spike());
    }

    // ── TriageSummary ─────────────────────────────────────────────────────

    #[test]
    fn test_triage_summary_zeros() {
        let s = TriageSummary::analyze(&[0u8; 4096]);
        assert_eq!(s.length, 4096);
        assert!((s.entropy - (0.0)).abs() < f64::EPSILON);
        assert_eq!(s.region_class, RegionClass::Padding);
        assert!((s.null_ratio - (1.0)).abs() < f64::EPSILON);
        assert_eq!(s.distinct_bytes, 1);
        assert_eq!(s.longest_run.unwrap().length, 4096);
        assert!(!s.is_suspicious());
    }

    #[test]
    fn test_triage_summary_random_suspicious() {
        let s = TriageSummary::analyze(&pseudo_random(16_384));
        assert!(s.entropy > 7.5);
        assert_eq!(s.region_class, RegionClass::Encrypted);
        assert!(s.packed_score > 0.8);
        assert!(s.is_suspicious());
    }

    #[test]
    fn test_triage_summary_text() {
        let s = TriageSummary::analyze(&ascii_text(4096));
        assert_eq!(s.region_class, RegionClass::AsciiText);
        assert!(s.printable_ratio > 0.75);
    }

    #[test]
    fn test_triage_summary_display() {
        let s = TriageSummary::analyze(&ascii_text(4096));
        let out = s.to_string();
        assert!(out.contains("Triage"));
        assert!(out.contains("class=AsciiText"));
    }

    #[test]
    fn test_triage_summary_embedded_blob_suspicious() {
        let mut data = vec![0u8; 4096];
        let blob = pseudo_random(512);
        data[2048..2048 + blob.len()].copy_from_slice(&blob);
        let s = TriageSummary::analyze(&data);
        assert!(s.entropy_anomaly_count > 0);
        assert!(s.is_suspicious());
    }
}
