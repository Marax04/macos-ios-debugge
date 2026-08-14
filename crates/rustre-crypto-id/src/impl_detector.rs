//! `impl_detector` — Detect the *implementation type* of a cryptographic routine.
//!
//! Rather than asking *which* algorithm is present (that is the job of
//! `BinaryScanner`), this module asks *how* it is implemented:
//!
//! * [`ImplType::HardwareAes`] — AES-NI instruction stream detected.
//! * [`ImplType::SoftwareOptimized`] — known bit-sliced / SSSE3 / NEON patterns.
//! * [`ImplType::SoftwareReference`] — simple table-lookup or scalar implementation.
//! * [`ImplType::Unknown`] — not enough evidence to decide.
//!
//! The primary entry point is [`ImplDetector::detect`], which takes a raw byte
//! slice (a function body) and returns an [`ImplFingerprint`].

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ImplType
// ---------------------------------------------------------------------------

/// Classification of a cryptographic implementation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ImplType {
    /// Uses x86 AES-NI instructions (`AESENC`, `AESENCLAST`, `AESDEC`,
    /// `AESDECLAST`, `AESKEYGENASSIST`, `AESIMC`, `PCLMULQDQ`).
    HardwareAes,
    /// Optimised software implementation — detected via SSSE3 `PSHUFB` patterns,
    /// large unrolled loop bodies, or NEON byte-permute instructions.
    SoftwareOptimized,
    /// Reference / portable software implementation — detected via standard
    /// S-box table lookups and scalar XOR/AND byte operations.
    SoftwareReference,
    /// Insufficient evidence to classify the implementation.
    Unknown,
}

impl ImplType {
    /// Return a short descriptive label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::HardwareAes => "hardware-aes",
            Self::SoftwareOptimized => "software-optimized",
            Self::SoftwareReference => "software-reference",
            Self::Unknown => "unknown",
        }
    }

    /// Return `true` if any hardware acceleration was detected.
    #[must_use]
    pub const fn is_hardware_accelerated(self) -> bool {
        matches!(self, Self::HardwareAes)
    }

    /// Return `true` if implementation is software-based.
    #[must_use]
    pub const fn is_software(self) -> bool {
        matches!(self, Self::SoftwareOptimized | Self::SoftwareReference)
    }
}

impl fmt::Display for ImplType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// ImplEvidence — what individual signals contributed to the classification
// ---------------------------------------------------------------------------

/// A single piece of evidence gathered during implementation detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplEvidence {
    /// Short description of what was observed.
    pub description: String,
    /// The implementation type this evidence suggests.
    pub suggests: ImplType,
    /// Confidence contribution in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Byte offset where the evidence was found, if applicable.
    pub offset: Option<usize>,
}

impl ImplEvidence {
    /// Create a new evidence record.
    #[must_use]
    pub fn new(
        description: impl Into<String>,
        suggests: ImplType,
        confidence: f32,
        offset: Option<usize>,
    ) -> Self {
        Self {
            description: description.into(),
            suggests,
            confidence: confidence.clamp(0.0, 1.0),
            offset,
        }
    }
}

impl fmt::Display for ImplEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (conf={:.2})",
            self.suggests, self.description, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// ImplFingerprint — the full result of an implementation detection run
// ---------------------------------------------------------------------------

/// The complete result of running [`ImplDetector::detect`] on a function body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplFingerprint {
    /// Detected implementation type.
    pub impl_type: ImplType,
    /// Overall confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// All evidence records that contributed to the classification.
    pub evidence: Vec<ImplEvidence>,
    /// Total number of bytes analysed.
    pub bytes_analysed: usize,
    /// Number of AES-NI instructions found (0 for non-hardware).
    pub aesni_count: usize,
    /// Number of SSSE3/SSE2 vector instructions found.
    pub vector_insn_count: usize,
    /// Count of byte-substitution patterns (S-box lookups, `PSHUFB` chains).
    pub substitution_patterns: usize,
}

impl ImplFingerprint {
    /// Return `true` if the implementation is considered hardware-accelerated
    /// with at least 50% confidence.
    #[must_use]
    pub fn is_hardware_accelerated(&self) -> bool {
        self.impl_type.is_hardware_accelerated() && self.confidence >= 0.5
    }

    /// Return a human-readable one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} (conf={:.0}%, aesni={}, vec={}, subst={})",
            self.impl_type,
            self.confidence * 100.0,
            self.aesni_count,
            self.vector_insn_count,
            self.substitution_patterns,
        )
    }
}

impl fmt::Display for ImplFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImplFingerprint[{}]", self.summary())
    }
}

// ---------------------------------------------------------------------------
// ImplDetector — the main detector
// ---------------------------------------------------------------------------

/// Detects the implementation type of a cryptographic function body.
///
/// The detector works on raw x86/x86-64 byte streams.  It scans for:
///
/// * AES-NI opcodes (`0F 38 DC` … `0F 3A DF` family).
/// * `PCLMULQDQ` (`66 0F 3A 44`).
/// * SSSE3 `PSHUFB` (`66 0F 38 00`).
/// * SSE2 `PXOR` / `PADD` / `PSUB` families.
/// * Scalar XOR density (high → reference or optimised software).
/// * S-box table-lookup heuristic (frequent memory reads with byte-sized indexing).
#[derive(Debug, Clone, Default)]
pub struct ImplDetector;

impl ImplDetector {
    /// Create a new [`ImplDetector`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect the implementation type from `code` bytes.
    ///
    /// Returns an [`ImplFingerprint`] with `impl_type`, `confidence`, and all
    /// individual evidence records.
    #[must_use]
    pub fn detect(&self, code: &[u8]) -> ImplFingerprint {
        let mut evidence: Vec<ImplEvidence> = Vec::new();
        let mut aesni_count = 0usize;
        let mut vector_insn_count = 0usize;
        let mut substitution_patterns = 0usize;

        // ── AES-NI detection ─────────────────────────────────────────────────
        // All AES-NI instructions use a 3-byte VEX or legacy prefix sequence.
        // Legacy form: 66 0F 38 DC/DD/DE/DF/DB  (aesenc, aesenclast, aesdec, …)
        //              66 0F 3A DF xx            (aeskeygenassist)
        //              66 0F 38 DB               (aesimc)
        // PCLMULQDQ:   66 0F 3A 44 xx xx         (carryless multiply)

        let aesni_ops: &[(&[u8], &str)] = &[
            (&[0x66, 0x0F, 0x38, 0xDC], "AESENC"),
            (&[0x66, 0x0F, 0x38, 0xDD], "AESENCLAST"),
            (&[0x66, 0x0F, 0x38, 0xDE], "AESDEC"),
            (&[0x66, 0x0F, 0x38, 0xDF], "AESDECLAST"),
            (&[0x66, 0x0F, 0x38, 0xDB], "AESIMC"),
            (&[0x66, 0x0F, 0x3A, 0xDF], "AESKEYGENASSIST"),
            (&[0x66, 0x0F, 0x3A, 0x44], "PCLMULQDQ"),
        ];

        for (pattern, name) in aesni_ops {
            let count = count_pattern(code, pattern);
            if count > 0 {
                aesni_count += count;
                evidence.push(ImplEvidence::new(
                    format!("{name} ×{count}"),
                    ImplType::HardwareAes,
                    0.95,
                    first_offset(code, pattern),
                ));
            }
        }

        // ── SSSE3 PSHUFB (used in bit-sliced AES / optimized impls) ─────────
        // Legacy form: 66 0F 38 00 /r
        let pshufb_count = count_pattern(code, &[0x66, 0x0F, 0x38, 0x00]);
        if pshufb_count > 0 {
            vector_insn_count += pshufb_count;
            substitution_patterns += pshufb_count;
            evidence.push(ImplEvidence::new(
                format!("PSHUFB ×{pshufb_count} (optimized software S-box)"),
                ImplType::SoftwareOptimized,
                0.75,
                first_offset(code, &[0x66, 0x0F, 0x38, 0x00]),
            ));
        }

        // ── SSE2 PXOR (66 0F EF) — vector XOR used in AES software ──────────
        let pxor_count = count_pattern(code, &[0x66, 0x0F, 0xEF]);
        if pxor_count > 4 {
            vector_insn_count += pxor_count;
            evidence.push(ImplEvidence::new(
                format!("PXOR ×{pxor_count} (vectorised XOR)"),
                ImplType::SoftwareOptimized,
                0.60,
                first_offset(code, &[0x66, 0x0F, 0xEF]),
            ));
        }

        // ── MOVDQA / MOVDQU — wide data movement ────────────────────────────
        let movdqa_count =
            count_pattern(code, &[0x66, 0x0F, 0x6F]) + count_pattern(code, &[0xF3, 0x0F, 0x6F]);
        if movdqa_count > 2 {
            vector_insn_count += movdqa_count;
            evidence.push(ImplEvidence::new(
                format!("MOVDQA/MOVDQU ×{movdqa_count}"),
                ImplType::SoftwareOptimized,
                0.45,
                first_offset(code, &[0x66, 0x0F, 0x6F]),
            ));
        }

        // ── Scalar XOR density (reference implementation heuristic) ─────────
        // Count standalone XOR r,r (31/33) and XOR r,m patterns.
        let xor_count = code
            .windows(1)
            .filter(|w| w[0] == 0x31 || w[0] == 0x33 || w[0] == 0x35)
            .count();
        if xor_count > 20 && aesni_count == 0 {
            if pshufb_count < 4 {
                evidence.push(ImplEvidence::new(
                    format!("high scalar XOR density ({xor_count})"),
                    ImplType::SoftwareReference,
                    0.55,
                    None,
                ));
            } else {
                evidence.push(ImplEvidence::new(
                    format!("scalar XOR ({xor_count}) alongside vector ops"),
                    ImplType::SoftwareOptimized,
                    0.50,
                    None,
                ));
            }
        }

        // ── MOV r8, [r+r] patterns — byte-indexed table lookup (S-box) ──────
        // Look for `MOVZX r32, BYTE PTR [base+index]` (0F B6 04 xx).
        let movzx_count = count_pattern(code, &[0x0F, 0xB6, 0x04]);
        if movzx_count > 4 {
            substitution_patterns += movzx_count;
            evidence.push(ImplEvidence::new(
                format!("MOVZX byte-table ×{movzx_count} (S-box lookup)"),
                ImplType::SoftwareReference,
                0.70,
                first_offset(code, &[0x0F, 0xB6, 0x04]),
            ));
        }

        // ── Derive final classification ──────────────────────────────────────
        let impl_type = classify(&evidence, aesni_count, vector_insn_count, pshufb_count);
        let confidence = compute_confidence(&evidence, impl_type);

        ImplFingerprint {
            impl_type,
            confidence,
            evidence,
            bytes_analysed: code.len(),
            aesni_count,
            vector_insn_count,
            substitution_patterns,
        }
    }

    /// Batch-detect multiple function byte-slices.
    ///
    /// Returns one [`ImplFingerprint`] per input slice, in order.
    #[must_use]
    pub fn detect_batch(&self, functions: &[&[u8]]) -> Vec<ImplFingerprint> {
        functions.iter().map(|code| self.detect(code)).collect()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Count non-overlapping occurrences of `pattern` in `data`.
fn count_pattern(data: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() || data.len() < pattern.len() {
        return 0;
    }
    let mut count = 0;
    let mut pos = 0;
    while pos + pattern.len() <= data.len() {
        if &data[pos..pos + pattern.len()] == pattern {
            count += 1;
            pos += pattern.len();
        } else {
            pos += 1;
        }
    }
    count
}

/// Return the byte offset of the first occurrence of `pattern` in `data`.
fn first_offset(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len()).position(|w| w == pattern)
}

/// Determine the dominant [`ImplType`] from the evidence gathered.
fn classify(
    evidence: &[ImplEvidence],
    aesni_count: usize,
    vector_insn_count: usize,
    pshufb_count: usize,
) -> ImplType {
    if aesni_count >= 2 {
        return ImplType::HardwareAes;
    }
    if aesni_count == 1 {
        return ImplType::HardwareAes;
    }
    if pshufb_count >= 4 || vector_insn_count >= 8 {
        return ImplType::SoftwareOptimized;
    }
    // Tally vote by weighted confidence.
    let mut hw_weight = 0.0f32;
    let mut opt_weight = 0.0f32;
    let mut ref_weight = 0.0f32;
    for e in evidence {
        match e.suggests {
            ImplType::HardwareAes => hw_weight += e.confidence,
            ImplType::SoftwareOptimized => opt_weight += e.confidence,
            ImplType::SoftwareReference => ref_weight += e.confidence,
            ImplType::Unknown => {}
        }
    }
    let max = hw_weight.max(opt_weight).max(ref_weight);
    if max < 0.30 {
        return ImplType::Unknown;
    }
    if hw_weight >= max {
        ImplType::HardwareAes
    } else if opt_weight >= max {
        ImplType::SoftwareOptimized
    } else {
        ImplType::SoftwareReference
    }
}

/// Compute aggregate confidence for the chosen `impl_type`.
fn compute_confidence(evidence: &[ImplEvidence], impl_type: ImplType) -> f32 {
    let matching: Vec<f32> = evidence
        .iter()
        .filter(|e| e.suggests == impl_type)
        .map(|e| e.confidence)
        .collect();
    if matching.is_empty() {
        return 0.0;
    }
    // Combined confidence: 1 − ∏(1 − cᵢ), clamped.
    let miss = matching.iter().fold(1.0f32, |acc, &c| acc * (1.0 - c));
    (1.0 - miss).clamp(0.0, 0.99)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── ImplType ─────────────────────────────────────────────────────────────

    #[test]
    fn test_impl_type_labels() {
        assert_eq!(ImplType::HardwareAes.label(), "hardware-aes");
        assert_eq!(ImplType::SoftwareOptimized.label(), "software-optimized");
        assert_eq!(ImplType::SoftwareReference.label(), "software-reference");
        assert_eq!(ImplType::Unknown.label(), "unknown");
    }

    #[test]
    fn test_impl_type_is_hardware_accelerated() {
        assert!(ImplType::HardwareAes.is_hardware_accelerated());
        assert!(!ImplType::SoftwareOptimized.is_hardware_accelerated());
    }

    #[test]
    fn test_impl_type_is_software() {
        assert!(ImplType::SoftwareOptimized.is_software());
        assert!(ImplType::SoftwareReference.is_software());
        assert!(!ImplType::HardwareAes.is_software());
        assert!(!ImplType::Unknown.is_software());
    }

    // ── count_pattern ─────────────────────────────────────────────────────────

    #[test]
    fn test_count_pattern_single() {
        let data = &[0x66, 0x0F, 0x38, 0xDC, 0x90];
        assert_eq!(count_pattern(data, &[0x66, 0x0F, 0x38, 0xDC]), 1);
    }

    #[test]
    fn test_count_pattern_multiple() {
        let data = &[0x0F, 0x31, 0x90, 0x0F, 0x31];
        assert_eq!(count_pattern(data, &[0x0F, 0x31]), 2);
    }

    #[test]
    fn test_count_pattern_none() {
        let data = &[0x90u8; 16];
        assert_eq!(count_pattern(data, &[0x66, 0x0F, 0x38, 0xDC]), 0);
    }

    // ── ImplDetector — AES-NI ─────────────────────────────────────────────────

    #[test]
    fn test_detect_aesni_aesenc() {
        // Two AESENC instructions
        let code = [
            0x66, 0x0F, 0x38, 0xDC, 0xC1, // AESENC xmm0, xmm1
            0x66, 0x0F, 0x38, 0xDC, 0xC2, // AESENC xmm0, xmm2
            0xC3, // RET
        ];
        let fp = ImplDetector::new().detect(&code);
        assert_eq!(fp.impl_type, ImplType::HardwareAes, "{fp}");
        assert!(fp.aesni_count >= 2);
        assert!(fp.is_hardware_accelerated());
    }

    #[test]
    fn test_detect_aesni_aesenclast() {
        let code = [
            0x66, 0x0F, 0x38, 0xDD, 0xC1, // AESENCLAST
            0x90,
        ];
        let fp = ImplDetector::new().detect(&code);
        assert_eq!(fp.impl_type, ImplType::HardwareAes);
    }

    #[test]
    fn test_detect_aeskeygenassist() {
        let code = [
            0x66, 0x0F, 0x3A, 0xDF, 0xC1, 0x01, // AESKEYGENASSIST
            0xC3,
        ];
        let fp = ImplDetector::new().detect(&code);
        assert_eq!(fp.impl_type, ImplType::HardwareAes);
    }

    // ── ImplDetector — software optimized ────────────────────────────────────

    #[test]
    fn test_detect_pshufb_optimized() {
        // 6 × PSHUFB → SoftwareOptimized
        let mut code = Vec::new();
        for _ in 0..6 {
            code.extend_from_slice(&[0x66, 0x0F, 0x38, 0x00, 0xC1]);
        }
        code.push(0xC3);
        let fp = ImplDetector::new().detect(&code);
        assert_eq!(fp.impl_type, ImplType::SoftwareOptimized, "{fp}");
    }

    // ── ImplDetector — software reference ────────────────────────────────────

    #[test]
    fn test_detect_sbox_lookup_reference() {
        // 6 × MOVZX r32, BYTE PTR [base+index] → SoftwareReference vote
        let mut code = Vec::new();
        for _ in 0..6 {
            code.extend_from_slice(&[0x0F, 0xB6, 0x04, 0x01]); // MOVZX eax, [rcx+rax]
        }
        // Add heavy scalar XOR (25 ×)
        for _ in 0..25 {
            code.extend_from_slice(&[0x31, 0xC0]); // XOR eax, eax
        }
        code.push(0xC3);
        let fp = ImplDetector::new().detect(&code);
        assert!(
            fp.impl_type == ImplType::SoftwareReference
                || fp.impl_type == ImplType::SoftwareOptimized,
            "expected software impl, got {}",
            fp.impl_type
        );
    }

    // ── ImplDetector — unknown ────────────────────────────────────────────────

    #[test]
    fn test_detect_unknown_nop_sled() {
        let code = vec![0x90u8; 32];
        let fp = ImplDetector::new().detect(&code);
        assert_eq!(fp.impl_type, ImplType::Unknown, "{fp}");
        assert!(!fp.is_hardware_accelerated());
    }

    // ── ImplFingerprint summary ───────────────────────────────────────────────

    #[test]
    fn test_fingerprint_summary_non_empty() {
        let code = [0x66, 0x0F, 0x38, 0xDC, 0xC1, 0xC3];
        let fp = ImplDetector::new().detect(&code);
        let s = fp.summary();
        assert!(!s.is_empty(), "summary should not be empty");
        assert!(s.contains("hardware-aes"), "unexpected summary: {s}");
    }

    // ── batch detect ─────────────────────────────────────────────────────────

    #[test]
    fn test_detect_batch() {
        let aesni = vec![0x66u8, 0x0F, 0x38, 0xDC, 0xC1, 0xC3];
        let nops = vec![0x90u8; 8];
        let detector = ImplDetector::new();
        let results = detector.detect_batch(&[&aesni, &nops]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].impl_type, ImplType::HardwareAes);
        assert_eq!(results[1].impl_type, ImplType::Unknown);
    }

    // ── pclmulqdq ─────────────────────────────────────────────────────────────

    #[test]
    fn test_detect_pclmulqdq() {
        let code = [0x66, 0x0F, 0x3A, 0x44, 0xC1, 0x01, 0xC3];
        let fp = ImplDetector::new().detect(&code);
        assert_eq!(fp.impl_type, ImplType::HardwareAes);
        assert!(fp.aesni_count >= 1);
    }
}
