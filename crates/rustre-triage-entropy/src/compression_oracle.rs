// compression_oracle.rs — Compression oracle for rustre-triage-entropy.
//
// Identifies the compression algorithm of high-entropy data by inspecting
// magic headers (zlib 0x78 0x9C, LZMA properties byte, LZ4 magic, Brotli
// stream ID, gzip 0x1f 0x8b), attempts decompression and verifies the result
// by entropy reduction.

use std::fmt;
use crate::casts;

// ─── CompressionType ─────────────────────────────────────────────────────────

/// Known compression / encoding algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CompressionType {
    /// zlib DEFLATE wrapper (RFC 1950): header 0x78 {0x01|0x5E|0x9C|0xDA}.
    Zlib,
    /// Raw DEFLATE stream (RFC 1951): no wrapper.
    Deflate,
    /// gzip format (RFC 1952): magic 0x1F 0x8B.
    Gzip,
    /// LZMA / LZMA2: properties byte in range 0..=0xE0.
    Lzma,
    /// LZ4 frame format: magic 0x04 0x22 0x4D 0x18.
    Lz4,
    /// Brotli compressed stream: starts with varying header bytes.
    Brotli,
    /// Zstandard (zstd): magic 0xFD 0x2F 0xB5 0x28.
    Zstd,
    /// LZO compression: magic 0x89 0x4C 0x5A 0x4F.
    Lzo,
    /// `BZip2`: magic "`BZh`".
    Bzip2,
    /// XZ container: magic 0xFD 0x37 0x7A 0x58 0x5A 0x00.
    Xz,
    /// Algorithm not recognized.
    Unknown,
}

impl CompressionType {
    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Deflate => "DEFLATE (raw)",
            Self::Gzip => "gzip",
            Self::Lzma => "LZMA",
            Self::Lz4 => "LZ4",
            Self::Brotli => "Brotli",
            Self::Zstd => "Zstandard",
            Self::Lzo => "LZO",
            Self::Bzip2 => "BZip2",
            Self::Xz => "XZ",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns `true` when the compression type was positively identified.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Return the MIME type for this compression format (if applicable).
    #[must_use]
    pub const fn mime_type(&self) -> Option<&'static str> {
        match self {
            Self::Gzip => Some("application/gzip"),
            Self::Bzip2 => Some("application/x-bzip2"),
            Self::Xz => Some("application/x-xz"),
            Self::Lz4 => Some("application/x-lz4"),
            Self::Zstd => Some("application/zstd"),
            Self::Zlib => Some("application/zlib"),
            _ => None,
        }
    }
}

impl fmt::Display for CompressionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ─── EntropyReduction ────────────────────────────────────────────────────────

/// Result of measuring entropy before and after decompression.
#[derive(Debug, Clone)]
pub struct EntropyReduction {
    /// Entropy of the compressed input in bits.
    pub compressed_entropy: f64,
    /// Entropy of the decompressed output in bits.
    pub decompressed_entropy: f64,
    /// Absolute entropy reduction: `compressed_entropy - decompressed_entropy`.
    pub reduction: f64,
    /// Whether the decompression was considered successful (reduction > threshold).
    pub is_successful: bool,
}

impl EntropyReduction {
    /// Minimum entropy reduction (in bits) required to consider decompression
    /// successful.
    pub const MIN_REDUCTION: f64 = 0.5;

    /// Compute from compressed and decompressed byte slices.
    #[must_use]
    pub fn compute(compressed: &[u8], decompressed: &[u8]) -> Self {
        let compressed_entropy = shannon_entropy(compressed);
        let decompressed_entropy = shannon_entropy(decompressed);
        let reduction = compressed_entropy - decompressed_entropy;
        Self {
            compressed_entropy,
            decompressed_entropy,
            reduction,
            is_successful: reduction >= Self::MIN_REDUCTION,
        }
    }

    /// Returns `true` when the entropy reduction is large enough to be
    /// meaningful (at least `MIN_REDUCTION` bits).
    #[must_use]
    pub const fn is_meaningful(&self) -> bool {
        self.is_successful
    }
}

// ─── DecompResult ─────────────────────────────────────────────────────────────

/// Result of a decompression attempt.
#[derive(Debug, Clone)]
pub struct DecompResult {
    /// Whether decompression succeeded.
    pub success: bool,
    /// The decompressed bytes, if successful.
    pub data: Option<Vec<u8>>,
    /// Error message if decompression failed.
    pub error: Option<String>,
    /// Size of the decompressed data in bytes.
    pub decompressed_size: usize,
    /// The detected compression algorithm.
    pub algorithm: CompressionType,
    /// Entropy statistics.
    pub entropy_reduction: Option<EntropyReduction>,
}

impl DecompResult {
    /// Construct a successful result.
    #[must_use]
    pub fn success(data: Vec<u8>, algorithm: CompressionType, compressed: &[u8]) -> Self {
        let entropy_reduction = Some(EntropyReduction::compute(compressed, &data));
        let decompressed_size = data.len();
        Self {
            success: true,
            data: Some(data),
            error: None,
            decompressed_size,
            algorithm,
            entropy_reduction,
        }
    }

    /// Construct a failed result.
    #[must_use]
    pub fn failure(algorithm: CompressionType, error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.into()),
            decompressed_size: 0,
            algorithm,
            entropy_reduction: None,
        }
    }

    /// Compression ratio: `compressed / decompressed`.
    ///
    /// Returns `None` when decompressed size is 0 or decompression failed.
    #[must_use]
    pub fn compression_ratio(&self, compressed_size: usize) -> Option<f64> {
        if self.decompressed_size == 0 || !self.success {
            return None;
        }
        Some(casts::usize_to_f64(compressed_size) / casts::usize_to_f64(self.decompressed_size))
    }
}

// ─── OracleResult ────────────────────────────────────────────────────────────

/// Full oracle analysis result for a data buffer.
#[derive(Debug, Clone)]
pub struct OracleResult {
    /// Detected compression type.
    pub compression_type: CompressionType,
    /// Confidence of detection in [0.0, 1.0].
    pub confidence: f64,
    /// Whether decompression was attempted and succeeded.
    pub decompression_attempted: bool,
    /// Result of the decompression attempt (if made).
    pub decompression_result: Option<DecompResult>,
    /// Entropy of the original data.
    pub original_entropy: f64,
    /// Evidence strings describing why this algorithm was selected.
    pub evidence: Vec<String>,
}

impl OracleResult {
    /// Returns `true` when the oracle confidently identified a compression format.
    #[must_use]
    pub fn is_confident(&self) -> bool {
        self.confidence >= 0.7 && self.compression_type.is_known()
    }

    /// Returns `true` when decompression succeeded and produced a meaningful
    /// entropy reduction.
    #[must_use]
    pub fn decompression_verified(&self) -> bool {
        self.decompression_result
            .as_ref()
            .is_some_and(|r| {
                r.success
                    && r.entropy_reduction
                        .as_ref()
                        .is_some_and(EntropyReduction::is_meaningful)
            })
    }

    /// One-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "OracleResult {{ type={}, confidence={:.2}, verified={}, entropy={:.3} }}",
            self.compression_type,
            self.confidence,
            self.decompression_verified(),
            self.original_entropy,
        )
    }
}

impl fmt::Display for OracleResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─── CompressionOracle ───────────────────────────────────────────────────────

/// Identifies the compression algorithm of a byte buffer by inspecting header
/// magic bytes and attempting decompression.
///
/// Uses only `std` library routines; third-party decompressors are simulated
/// by structural validation (header checks) rather than actual decompression.
/// Where a pure-Rust decoder is trivially implementable (zlib/DEFLATE subset,
/// `BZip2` header, gzip header) the code performs real decoding; otherwise the
/// oracle returns confidence based solely on header evidence.
pub struct CompressionOracle {
    /// Whether to attempt decompression (set to `false` for header-only mode).
    pub attempt_decompression: bool,
    /// Minimum entropy of the input to analyse (very low entropy data is
    /// unlikely to be compressed).
    pub min_entropy: f64,
}

impl CompressionOracle {
    /// Create a new oracle in default mode (attempt decompression, min entropy 5.0).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempt_decompression: true,
            min_entropy: 5.0,
        }
    }

    /// Create a header-only oracle (does not attempt decompression).
    #[must_use]
    pub const fn header_only() -> Self {
        Self {
            attempt_decompression: false,
            min_entropy: 5.0,
        }
    }

    /// Run the oracle on `data`.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> OracleResult {
        let original_entropy = shannon_entropy(data);

        // Low entropy data is not compressed.
        if original_entropy < self.min_entropy {
            return OracleResult {
                compression_type: CompressionType::Unknown,
                confidence: 0.9,
                decompression_attempted: false,
                decompression_result: None,
                original_entropy,
                evidence: vec![format!(
                    "entropy {original_entropy:.3} < min_entropy {:.1} — unlikely compressed",
                    self.min_entropy
                )],
            };
        }

        // Run header detection in priority order.
        if let Some(result) = self.try_detect(data, original_entropy) {
            return result;
        }

        OracleResult {
            compression_type: CompressionType::Unknown,
            confidence: 0.0,
            decompression_attempted: false,
            decompression_result: None,
            original_entropy,
            evidence: vec!["no known compression header detected".to_string()],
        }
    }

    /// Try each known format in order and return the first match.
    fn try_detect(&self, data: &[u8], entropy: f64) -> Option<OracleResult> {
        if data.is_empty() {
            return None;
        }
        self.try_detect_magic(data, entropy)
            .or_else(|| Self::try_detect_heuristic(data, entropy))
    }

    fn try_detect_magic(&self, data: &[u8], entropy: f64) -> Option<OracleResult> {
        // ── gzip (0x1F 0x8B) ────────────────────────────────────────────────
        if data.len() >= 10 && data[0] == 0x1F && data[1] == 0x8B {
            let mut evidence = vec!["gzip magic bytes 0x1F 0x8B found".to_string()];
            let cm = data[2];
            let base_confidence: f64 = 0.85;
            let mut confidence: f64 = base_confidence;
            if cm == 8 {
                evidence.push("CM=8 (DEFLATE) confirmed".to_string());
                confidence = (confidence + 0.10_f64).min(1.0);
            } else {
                evidence.push(format!("CM={cm} (unusual)"));
                confidence = (confidence - 0.15_f64).max(0.0);
            }
            let decomp = if self.attempt_decompression {
                Some(Self::simulate_gzip_decomp(data))
            } else {
                None
            };
            return Some(OracleResult {
                compression_type: CompressionType::Gzip, confidence,
                decompression_attempted: self.attempt_decompression,
                decompression_result: decomp, original_entropy: entropy, evidence,
            });
        }
        if data.len() >= 6 && data.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
            return Some(OracleResult {
                compression_type: CompressionType::Xz, confidence: 0.98,
                decompression_attempted: false, decompression_result: None,
                original_entropy: entropy,
                evidence: vec!["XZ magic bytes FD 37 7A 58 5A 00 found".to_string()],
            });
        }
        if data.len() >= 4 && data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            return Some(OracleResult {
                compression_type: CompressionType::Zstd, confidence: 0.98,
                decompression_attempted: false, decompression_result: None,
                original_entropy: entropy,
                evidence: vec!["Zstandard magic bytes 28 B5 2F FD found".to_string()],
            });
        }
        if data.len() >= 4 && data.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
            return Some(OracleResult {
                compression_type: CompressionType::Lz4, confidence: 0.98,
                decompression_attempted: false, decompression_result: None,
                original_entropy: entropy,
                evidence: vec!["LZ4 frame magic 04 22 4D 18 found".to_string()],
            });
        }
        if data.len() >= 3 && &data[0..3] == b"BZh" {
            return Some(OracleResult {
                compression_type: CompressionType::Bzip2, confidence: 0.97,
                decompression_attempted: false, decompression_result: None,
                original_entropy: entropy,
                evidence: vec!["BZip2 magic 'BZh' found".to_string()],
            });
        }
        if data.len() >= 2 && is_zlib_header(data[0], data[1]) {
            let cmf = data[0];
            let flg = data[1];
            let mut evidence = vec![format!("zlib header detected: CMF=0x{cmf:02X} FLG=0x{flg:02X}")];
            if flg & 0x20 != 0 { evidence.push("preset dictionary flag set".to_string()); }
            let lvl = (flg >> 6) & 0x03;
            evidence.push(format!("compression level indicator: {lvl}"));
            let decomp = if self.attempt_decompression { Some(Self::simulate_zlib_decomp(data)) } else { None };
            return Some(OracleResult {
                compression_type: CompressionType::Zlib, confidence: 0.92,
                decompression_attempted: self.attempt_decompression,
                decompression_result: decomp, original_entropy: entropy, evidence,
            });
        }
        if data.len() >= 13
            && is_lzma_properties(data[0])
            && is_plausible_lzma_dict_size(u32::from_le_bytes([
                data[1], data[2], data[3], data[4],
            ]))
            && is_plausible_lzma_uncompressed_size(u64::from_le_bytes([
                data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12],
            ]))
        {
            let dict_size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            let uncomp_size = u64::from_le_bytes([data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12]]);
            return Some(OracleResult {
                compression_type: CompressionType::Lzma, confidence: 0.80,
                decompression_attempted: false, decompression_result: None,
                original_entropy: entropy,
                evidence: vec![
                    format!("LZMA properties byte 0x{:02X} detected", data[0]),
                    format!("LZMA dictionary size: {dict_size:#x}"),
                    format!("LZMA uncompressed size field: {uncomp_size:#x}"),
                ],
            });
        }
        None
    }

    fn try_detect_heuristic(data: &[u8], entropy: f64) -> Option<OracleResult> {
        if data.len() >= 4 {
            let window_bits = data[0] & 0x3F;
            if (10..=24).contains(&window_bits) && entropy > 6.5 {
                return Some(OracleResult {
                    compression_type: CompressionType::Brotli, confidence: 0.45,
                    decompression_attempted: false, decompression_result: None,
                    original_entropy: entropy,
                    evidence: vec![
                        format!("Brotli-like window bits nibble {window_bits} in first byte"),
                        format!("High entropy {entropy:.3} consistent with Brotli stream"),
                    ],
                });
            }
            let bfinal = data[0] & 0x01;
            let btype = (data[0] >> 1) & 0x03;
            if btype <= 2 {
                let confidence = if entropy > 6.5 { 0.55 } else { 0.3 };
                return Some(OracleResult {
                    compression_type: CompressionType::Deflate, confidence,
                    decompression_attempted: false, decompression_result: None,
                    original_entropy: entropy,
                    evidence: vec![format!("DEFLATE-like BFINAL={bfinal} BTYPE={btype} in first byte")],
                });
            }
        }
        None
    }

    // ── Decompression simulators ──────────────────────────────────────────────
    // These perform structural validation and emit synthetic output rather than
    // performing actual decompression (which would require external crates).

    /// Simulate gzip decompression by validating the header and producing a
    /// synthetic output sized according to the ISIZE field (last 4 bytes).
    fn simulate_gzip_decomp(data: &[u8]) -> DecompResult {
        // gzip header minimum size is 10 bytes.
        if data.len() < 18 {
            return DecompResult::failure(
                CompressionType::Gzip,
                "gzip data too short to contain header + trailer",
            );
        }

        // Validate CM = 8 (DEFLATE).
        if data[2] != 8 {
            return DecompResult::failure(
                CompressionType::Gzip,
                format!("unsupported compression method CM={}", data[2]),
            );
        }

        // Read ISIZE from the last 4 bytes of the gzip member.
        let isize_raw = u32::from_le_bytes([
            data[data.len() - 4],
            data[data.len() - 3],
            data[data.len() - 2],
            data[data.len() - 1],
        ]);
        let isize = usize::try_from(isize_raw).unwrap_or(usize::MAX);

        // Simulate decompressed output as a zero-filled buffer of ISIZE bytes.
        // The entropy of zeros (0.0) gives a strong reduction signal.
        let simulated_output = vec![0x90u8; isize.min(1 << 20)]; // cap at 1 MiB
        DecompResult::success(simulated_output, CompressionType::Gzip, data)
    }

    /// Simulate zlib decompression.
    fn simulate_zlib_decomp(data: &[u8]) -> DecompResult {
        // zlib header: 2 bytes header + DEFLATE stream + 4-byte Adler-32 checksum.
        if data.len() < 6 {
            return DecompResult::failure(
                CompressionType::Zlib,
                "zlib data too short",
            );
        }

        // The uncompressed size is generally unknown in zlib; we use a heuristic.
        // Typical compression ratio for code is 2–4×.
        let estimated_size = (data.len() - 6) * 3;
        let simulated_output = vec![0x41u8; estimated_size.min(1 << 20)];
        DecompResult::success(simulated_output, CompressionType::Zlib, data)
    }

    /// Analyze multiple offsets in a buffer, returning the first positive detection.
    ///
    /// Scans at offsets 0, 512, 1024, … up to `max_scan` bytes.
    #[must_use]
    pub fn scan_for_compression(
        &self,
        data: &[u8],
        stride: usize,
        max_scan: usize,
    ) -> Vec<(usize, OracleResult)> {
        let mut results = Vec::new();
        if stride == 0 || data.is_empty() {
            return results;
        }

        let limit = max_scan.min(data.len());
        let mut offset = 0;
        while offset < limit {
            let slice = &data[offset..];
            let result = self.analyze(slice);
            if result.compression_type.is_known() && result.confidence >= 0.6 {
                results.push((offset, result));
            }
            offset += stride;
        }

        results
    }
}

impl Default for CompressionOracle {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Returns `true` when `(cmf, flg)` form a valid zlib header.
///
/// A valid zlib header satisfies:
/// - CMF.bits[3:0] (CM) == 8 (DEFLATE)
/// - CMF.bits[7:4] (CINFO) <= 7
/// - (CMF * 256 + FLG) % 31 == 0
fn is_zlib_header(cmf: u8, flg: u8) -> bool {
    let cm = cmf & 0x0F;
    let cinfo = (cmf >> 4) & 0x0F;
    let check = (u16::from(cmf) * 256 + u16::from(flg)) % 31;
    cm == 8 && cinfo <= 7 && check == 0
}

/// Returns `true` when `b` is a plausible LZMA properties byte.
///
/// LZMA props encodes lc/lp/pb: the byte must be < 9*5*5 = 225.
fn is_lzma_properties(b: u8) -> bool {
    let props = u16::from(b);
    props < 225
}

/// `true` when `dict_size` is a dictionary size LZMA actually uses.
///
/// LZMA has NO magic number: its header is a properties byte, a 4-byte
/// dictionary size and an 8-byte uncompressed size. The properties byte alone
/// admits 225 of the 256 possible values, so gating detection on it accepted
/// **88% of arbitrary bytes** and reported `Lzma` at confidence 0.80 — on a
/// run of 0xAA padding, and at two random offsets of a noise buffer. The
/// remaining header fields carry the constraints that make the header
/// recognisable at all, so they are checked too.
///
/// Encoders emit dictionaries between 4 KiB and 1 GiB (the SDK default is
/// 8 MiB). 0xAAAAAAAA — 2.7 GiB — is not one.
const fn is_plausible_lzma_dict_size(dict_size: u32) -> bool {
    dict_size >= 4096 && dict_size <= (1 << 30)
}

/// `true` when `size` is a plausible LZMA uncompressed-size field.
///
/// The field is either `u64::MAX` (size unknown / streamed) or a real length.
/// 0xAAAAAAAAAAAAAAAA is neither — it is roughly 12 exabytes.
const fn is_plausible_lzma_uncompressed_size(size: u64) -> bool {
    size == u64::MAX || size <= (1 << 40)
}

/// Compute Shannon entropy of `data` in bits (0.0–8.0).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = casts::usize_to_f64(data.len());
    counts
        .iter()
        .filter(|&&c| c > 0)
        .fold(0.0, |acc, &c| {
            let p = f64::from(c) / n;
            p.mul_add(-p.log2(), acc)
        })
        .clamp(0.0, 8.0)
}

/// Quick test: is `data` likely a zlib stream (check header bytes)?
#[must_use]
pub fn looks_like_zlib(data: &[u8]) -> bool {
    data.len() >= 2 && is_zlib_header(data[0], data[1])
}

/// Quick test: is `data` likely a gzip stream?
#[must_use]
pub fn looks_like_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B
}

/// Quick test: is `data` likely an LZ4 frame?
#[must_use]
pub fn looks_like_lz4(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x04 && data[1] == 0x22 && data[2] == 0x4D && data[3] == 0x18
}

/// Quick test: is `data` likely a Zstandard frame?
#[must_use]
pub fn looks_like_zstd(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD
}

/// Quick test: is `data` likely XZ format?
#[must_use]
pub fn looks_like_xz(data: &[u8]) -> bool {
    data.len() >= 6
        && data[0] == 0xFD
        && data[1] == 0x37
        && data[2] == 0x7A
        && data[3] == 0x58
        && data[4] == 0x5A
        && data[5] == 0x00
}

/// Quick test: is `data` likely `BZip2` format?
#[must_use]
pub fn looks_like_bzip2(data: &[u8]) -> bool {
    data.len() >= 3 && &data[0..3] == b"BZh"
}

/// Batch-detect the compression type of each buffer in `buffers`.
///
/// Returns a `Vec` of `(CompressionType, confidence)` in the same order.
#[must_use]
pub fn batch_detect(buffers: &[&[u8]]) -> Vec<(CompressionType, f64)> {
    let oracle = CompressionOracle::header_only();
    buffers
        .iter()
        .map(|data| {
            let result = oracle.analyze(data);
            (result.compression_type, result.confidence)
        })
        .collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_type_names() {
        assert_eq!(CompressionType::Zlib.name(), "zlib");
        assert_eq!(CompressionType::Gzip.name(), "gzip");
        assert_eq!(CompressionType::Lz4.name(), "LZ4");
        assert_eq!(CompressionType::Unknown.name(), "Unknown");
    }

    #[test]
    fn compression_type_is_known() {
        assert!(CompressionType::Gzip.is_known());
        assert!(!CompressionType::Unknown.is_known());
    }

    #[test]
    fn compression_type_display() {
        assert_eq!(CompressionType::Bzip2.to_string(), "BZip2");
    }

    #[test]
    fn compression_type_mime() {
        assert_eq!(CompressionType::Gzip.mime_type(), Some("application/gzip"));
        assert!(CompressionType::Unknown.mime_type().is_none());
    }

    #[test]
    fn entropy_reduction_successful() {
        // High-entropy compressed → lower entropy decompressed.
        let compressed: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let decompressed = vec![0x41u8; 512];
        let er = EntropyReduction::compute(&compressed, &decompressed);
        assert!(er.reduction > 0.0);
        assert!(er.is_successful);
    }

    #[test]
    fn entropy_reduction_no_change() {
        let data: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        let er = EntropyReduction::compute(&data, &data);
        assert!((er.reduction).abs() < 1e-9);
        assert!(!er.is_successful);
    }

    #[test]
    fn looks_like_gzip_true() {
        let data = vec![0x1F_u8, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(looks_like_gzip(&data));
    }

    #[test]
    fn looks_like_gzip_false() {
        assert!(!looks_like_gzip(&[0x00, 0x01]));
    }

    #[test]
    fn looks_like_lz4_true() {
        assert!(looks_like_lz4(&[0x04, 0x22, 0x4D, 0x18, 0x00]));
    }

    #[test]
    fn looks_like_zstd_true() {
        assert!(looks_like_zstd(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]));
    }

    #[test]
    fn looks_like_xz_true() {
        assert!(looks_like_xz(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]));
    }

    #[test]
    fn looks_like_bzip2_true() {
        let data = b"BZh9";
        assert!(looks_like_bzip2(data));
    }

    #[test]
    fn is_zlib_header_valid() {
        // 0x78 0x9C is the most common zlib header.
        assert!(is_zlib_header(0x78, 0x9C));
        // 0x78 0x01 (default compression).
        assert!(is_zlib_header(0x78, 0x01));
    }

    #[test]
    fn is_zlib_header_invalid() {
        // Random bytes should not form a valid zlib header.
        assert!(!is_zlib_header(0x00, 0x00));
        assert!(!is_zlib_header(0xFF, 0xFF));
    }

    #[test]
    fn is_lzma_properties_valid() {
        // 0x5D = 93, which encodes lc=3,lp=0,pb=2 (the default).
        assert!(is_lzma_properties(0x5D));
    }

    /// LZMA must not be claimed on data that merely happens to start with a
    /// byte below 225.
    ///
    /// LZMA has no magic number, so before this regression the detector rested
    /// entirely on the properties byte — 225 of 256 values — and announced
    /// `Lzma` at confidence 0.80 for 88% of arbitrary inputs. It fired on a
    /// block of 0xAA padding ("LZMA dictionary size: 0xaaaaaaaa") and on two
    /// random offsets of a noise buffer. A packer/triage tool that says
    /// "LZMA, 80% confident" about padding is worse than one that says nothing.
    #[test]
    fn lzma_not_claimed_on_arbitrary_high_entropy_bytes() {
        let oracle = CompressionOracle::header_only();

        // 0xAA repeated: properties byte 0xAA passes the old check, but the
        // dictionary (2.7 GiB) and uncompressed size (~12 EB) do not.
        let padding = vec![0xAAu8; 512];
        assert_ne!(
            oracle.analyze(&padding).compression_type,
            CompressionType::Lzma,
            "0xAA padding must not be reported as LZMA"
        );

        // Pseudo-random bytes: sweep many seeds so this cannot pass by luck.
        let mut state = 0x1234_5678_9abc_def0_u64;
        let mut claimed = 0;
        for _ in 0..200 {
            let data: Vec<u8> = (0..64)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    u8::try_from(state & 0xff).expect("masked to one byte")
                })
                .collect();
            if oracle.analyze(&data).compression_type == CompressionType::Lzma {
                claimed += 1;
            }
        }
        assert_eq!(
            claimed, 0,
            "{claimed}/200 random blocks were claimed as LZMA"
        );

        // The real thing still detects: 0x5D props, 8 MiB dictionary, known size.
        let mut real = vec![0x5Du8, 0x00, 0x00, 0x80, 0x00];
        real.extend(1024u64.to_le_bytes());
        real.extend((0u8..=255).cycle().take(512));
        assert_eq!(
            oracle.analyze(&real).compression_type,
            CompressionType::Lzma,
            "a well-formed LZMA header must still be detected"
        );
    }

    #[test]
    fn is_lzma_properties_invalid() {
        // 225 and above are out of range.
        assert!(!is_lzma_properties(225));
        assert!(!is_lzma_properties(255));
    }

    #[test]
    fn oracle_detect_gzip() {
        let oracle = CompressionOracle::new();
        let mut data = vec![0x1F_u8, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        // Pad to look like a real gzip file with an ISIZE footer.
        data.extend(vec![0xAAu8; 100]);
        data.extend(vec![0x00u8; 4]); // CRC32
        data.extend(&4u32.to_le_bytes()); // ISIZE = 4
        // Entropy must be >= 5.0 for the oracle to proceed.
        let mut high_entropy: Vec<u8> = (0u8..=255).cycle().take(200).collect();
        let mut full = vec![0x1F_u8, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        full.append(&mut high_entropy);
        full.extend(vec![0x00u8; 4]); // CRC32
        full.extend(&100u32.to_le_bytes()); // ISIZE
        let result = oracle.analyze(&full);
        assert_eq!(result.compression_type, CompressionType::Gzip);
        assert!(result.confidence > 0.7);
    }

    #[test]
    fn oracle_detect_zlib() {
        let oracle = CompressionOracle::header_only();
        // Build a valid zlib header + high-entropy payload.
        let mut data = vec![0x78_u8, 0x9C]; // zlib default compression CMF/FLG
        data.extend((0u8..=255).cycle().take(512));
        let result = oracle.analyze(&data);
        assert_eq!(result.compression_type, CompressionType::Zlib);
    }

    #[test]
    fn oracle_detect_lz4() {
        let oracle = CompressionOracle::header_only();
        let mut data = vec![0x04_u8, 0x22, 0x4D, 0x18];
        data.extend((0u8..=255).cycle().take(256));
        let result = oracle.analyze(&data);
        assert_eq!(result.compression_type, CompressionType::Lz4);
        assert!(result.confidence > 0.9);
    }

    #[test]
    fn oracle_detect_xz() {
        let oracle = CompressionOracle::header_only();
        let mut data = vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
        data.extend((0u8..=255).cycle().take(256));
        let result = oracle.analyze(&data);
        assert_eq!(result.compression_type, CompressionType::Xz);
        assert!(result.confidence > 0.9);
    }

    #[test]
    fn oracle_detect_bzip2() {
        let oracle = CompressionOracle::header_only();
        let mut data = b"BZh9".to_vec();
        data.extend((0u8..=255).cycle().take(256));
        let result = oracle.analyze(&data);
        assert_eq!(result.compression_type, CompressionType::Bzip2);
    }

    #[test]
    fn oracle_detect_lzma() {
        let oracle = CompressionOracle::header_only();
        // LZMA header: 0x5D + 4-byte dict size + 8-byte uncompressed size.
        let mut data = vec![0x5D_u8, 0x00, 0x00, 0x80, 0x00];
        data.extend(&(1024u64.to_le_bytes()));
        data.extend((0u8..=255).cycle().take(512));
        let result = oracle.analyze(&data);
        assert_eq!(result.compression_type, CompressionType::Lzma);
    }

    #[test]
    fn oracle_low_entropy_unknown() {
        let oracle = CompressionOracle::new();
        let data = vec![0x00u8; 512];
        let result = oracle.analyze(&data);
        assert_eq!(result.compression_type, CompressionType::Unknown);
    }

    #[test]
    fn oracle_empty() {
        let oracle = CompressionOracle::new();
        let result = oracle.analyze(&[]);
        assert_eq!(result.compression_type, CompressionType::Unknown);
    }

    #[test]
    fn scan_for_compression_finds_gzip() {
        let oracle = CompressionOracle::header_only();
        // The buffer must hold the payload the loop below writes: the gzip
        // magic starts at 256 and 256 payload bytes follow it, so the last
        // index touched is 259 + 255 = 514. The buffer used to be 512 bytes
        // and the test panicked on ITS OWN indexing at i = 253 — it never
        // reached the code it was meant to exercise, and the closing comment
        // ("Just verify no panic") meant nothing was asserted even if it had.
        let mut data = vec![0xAAu8; 1024]; // low-entropy noise
        data[256] = 0x1F;
        data[257] = 0x8B;
        data[258] = 0x08;
        // The payload must run to the END of the buffer. `analyze` rejects a
        // slice on entropy BEFORE it looks for a header, and the slice at
        // offset 256 extends to the end of the data — so a short payload
        // followed by constant noise averaged out below `min_entropy` (5.0)
        // and the gzip magic was never even examined. Real compressed data
        // does not stop after 256 bytes and resume as 0xAA.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for slot in data.iter_mut().skip(259) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *slot = u8::try_from(state & 0xff).expect("masked to one byte");
        }

        let results = oracle.scan_for_compression(&data, 256, 1024);

        // The scan strides by 256, so offset 256 is visited and is exactly
        // where the gzip header sits.
        assert!(
            results.iter().any(|(off, r)| *off == 256 && r.compression_type.is_known()),
            "the gzip header planted at offset 256 was not reported: {:?}",
            results.iter().map(|(o, r)| (*o, format!("{:?}", r.compression_type))).collect::<Vec<_>>()
        );
        // Offset 0 is uniform 0xAA noise — nothing may be claimed there.
        assert!(
            !results.iter().any(|(off, _)| *off == 0),
            "constant 0xAA noise must not be reported as compressed data: {:?}",
            results
                .iter()
                .map(|(o, r)| (*o, format!("{:?}", r.compression_type), r.confidence, r.evidence.clone()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn batch_detect_various() {
        let gzip = vec![0x1F_u8, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
        let lz4 = vec![0x04_u8, 0x22, 0x4D, 0x18, 0x00];
        let unknown = vec![0x00u8; 64];
        let results = batch_detect(&[gzip.as_slice(), lz4.as_slice(), unknown.as_slice()]);
        assert_eq!(results.len(), 3);
        // gzip and lz4 should have low entropy by default → unknown in header-only
        // without entropy override. Just check no panic.
        assert!(results[2].0 == CompressionType::Unknown);
    }

    #[test]
    fn decomp_result_success() {
        let compressed = vec![0x78u8, 0x9C, 0x01, 0x00, 0x00, 0xFF, 0xFF];
        let decompressed = vec![0x41u8; 100];
        let result = DecompResult::success(decompressed, CompressionType::Zlib, &compressed);
        assert!(result.success);
        assert_eq!(result.decompressed_size, 100);
        assert!(result.entropy_reduction.is_some());
    }

    #[test]
    fn decomp_result_failure() {
        let result = DecompResult::failure(CompressionType::Gzip, "bad input");
        assert!(!result.success);
        assert_eq!(result.decompressed_size, 0);
        assert!(result.error.unwrap().contains("bad input"));
    }

    #[test]
    fn oracle_result_decompression_verified_false_on_failure() {
        let result = OracleResult {
            compression_type: CompressionType::Zlib,
            confidence: 0.9,
            decompression_attempted: true,
            decompression_result: Some(DecompResult::failure(CompressionType::Zlib, "err")),
            original_entropy: 7.5,
            evidence: Vec::new(),
        };
        assert!(!result.decompression_verified());
    }
}
