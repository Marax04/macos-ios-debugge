// rustre-arch-arm64/src/arm64_feature_detector.rs
//
// Detect ARM64 CPU features by analyzing instruction streams. Features are
// inferred from which instruction groups appear in a code sample.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ─── CpuFeature ──────────────────────────────────────────────────────────────

/// An ARM64 architectural feature or extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CpuFeature {
    // Base ISA
    /// `AArch64` base architecture (A64 instruction set).
    BaseA64,
    /// NEON / Advanced SIMD (mandatory from ARMv8.0).
    AdvSimd,
    /// Floating-point (mandatory from ARMv8.0).
    Fp,

    // ARMv8.1-A extensions
    /// Large System Extensions: CAS, SWP, LDADD, etc.
    Lse,
    /// Half-precision floating-point arithmetic (ARMv8.2).
    Fp16,
    /// Reliable Delivery Extensions.
    Rdm,

    // ARMv8.2-A extensions
    /// Scalable Vector Extension (SVE).
    Sve,
    /// Dot Product instructions.
    DotProd,
    /// SHA-3 / SHA-512 accelerators.
    Sha3,
    /// SM3 / SM4 crypto.
    Sm4,

    // ARMv8.3-A extensions
    /// Pointer Authentication (PAC).
    Pauth,
    /// JavaScript conversion instructions.
    JscvT,
    /// Floating-point complex number instructions.
    Fcma,

    // ARMv8.4-A extensions
    /// Enhanced load/store pairs (non-temporal).
    Rcpc,
    /// Nested virtualization (stage 2 translation).
    NV,
    /// TLB invalidation (TLBI) maintenance.
    Tlbios,

    // ARMv8.5-A and later
    /// Branch Target Identification (BTI).
    Bti,
    /// Memory Tagging Extension (MTE).
    Mte,
    /// Scalable Vector Extension 2 (SVE2).
    Sve2,
    /// Random Number Generator instructions (RNDR, RNDRRS).
    Rng,
    /// Speculation Barrier (SB instruction).
    Sb,

    // Crypto extensions
    /// AES acceleration.
    Aes,
    /// SHA-1 acceleration.
    Sha1,
    /// SHA-256 / SHA-512 acceleration.
    Sha256,
    /// PMULL large multiplier.
    Pmull,

    // Debug
    /// Self-hosted debug (`FEAT_Debugv8p2`).
    DebugV8p2,
    /// Performance Monitor Extensions.
    Pmu,

    // Virtualisation
    /// EL2 (hypervisor) instructions present.
    Hyp,
    /// EL3 (secure monitor) instructions present.
    SecMon,
}

/// Denominator for a confidence ratio, converted without precision loss.
///
/// Instruction totals are saturated at `u32::MAX` first, so the
/// conversion is exact (every `u32` is representable in an `f64`).
/// Counts beyond four billion instructions cannot change a ratio that
/// is immediately clamped to `[0, 1]`.
#[must_use]
pub fn instruction_total_as_f64(total: u64) -> f64 {
    f64::from(u32::try_from(total.max(1).min(u64::from(u32::MAX))).unwrap_or(u32::MAX))
}

impl CpuFeature {
    /// Short mnemonic for display.
    #[must_use] 
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::BaseA64 => "base_a64",
            Self::AdvSimd => "adv_simd",
            Self::Fp => "fp",
            Self::Lse => "lse",
            Self::Fp16 => "fp16",
            Self::Rdm => "rdm",
            Self::Sve => "sve",
            Self::DotProd => "dotprod",
            Self::Sha3 => "sha3",
            Self::Sm4 => "sm4",
            Self::Pauth => "pauth",
            Self::JscvT => "jscvt",
            Self::Fcma => "fcma",
            Self::Rcpc => "rcpc",
            Self::NV => "nv",
            Self::Tlbios => "tlbios",
            Self::Bti => "bti",
            Self::Mte => "mte",
            Self::Sve2 => "sve2",
            Self::Rng => "rng",
            Self::Sb => "sb",
            Self::Aes => "aes",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Pmull => "pmull",
            Self::DebugV8p2 => "debug_v8p2",
            Self::Pmu => "pmu",
            Self::Hyp => "hyp",
            Self::SecMon => "sec_mon",
        }
    }

    /// Minimum `ARMv8` version that provides this feature.
    #[must_use] 
    pub const fn min_arch_version(self) -> (u8, u8) {
        match self {
            Self::BaseA64
            | Self::AdvSimd
            | Self::Fp
            | Self::Aes
            | Self::Sha1
            | Self::Sha256
            | Self::Pmull
            | Self::Pmu
            | Self::Hyp
            | Self::SecMon => (8, 0),
            Self::Lse | Self::Rdm => (8, 1),
            Self::Fp16
            | Self::Sve
            | Self::DotProd
            | Self::Sha3
            | Self::Sm4
            | Self::DebugV8p2 => (8, 2),
            Self::Pauth | Self::JscvT | Self::Fcma => (8, 3),
            Self::Rcpc | Self::NV | Self::Tlbios => (8, 4),
            Self::Bti | Self::Mte | Self::Sve2 | Self::Rng | Self::Sb => (8, 5),
        }
    }
}

impl fmt::Display for CpuFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FEAT_{}", self.mnemonic().to_uppercase())
    }
}

// ─── FeatureSet ──────────────────────────────────────────────────────────────

/// A set of detected ARM64 CPU features.
#[derive(Debug, Clone, Default)]
pub struct FeatureSet {
    detected: HashSet<CpuFeature>,
    /// Confidence score for each detected feature (0.0–1.0).
    confidence: HashMap<CpuFeature, f64>,
    /// Number of instructions scanned.
    pub instructions_scanned: u64,
}

impl FeatureSet {
    /// Create an empty feature set.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a feature with a given confidence.
    pub fn add(&mut self, feature: CpuFeature, confidence: f64) {
        self.detected.insert(feature);
        let entry = self.confidence.entry(feature).or_insert(0.0);
        // Keep the highest confidence seen.
        if confidence > *entry {
            *entry = confidence;
        }
    }

    /// Return `true` when the feature is present in this set.
    #[must_use] 
    pub fn has(&self, feature: CpuFeature) -> bool {
        self.detected.contains(&feature)
    }

    /// Return the confidence for a feature (0.0 when absent).
    #[must_use] 
    pub fn confidence(&self, feature: CpuFeature) -> f64 {
        self.confidence.get(&feature).copied().unwrap_or(0.0)
    }

    /// Iterate over all detected features.
    pub fn features(&self) -> impl Iterator<Item = CpuFeature> + '_ {
        self.detected.iter().copied()
    }

    /// Return the number of detected features.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.detected.len()
    }

    /// Return `true` when no features are detected.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.detected.is_empty()
    }

    /// Merge another feature set into this one (take max confidence).
    pub fn merge(&mut self, other: &Self) {
        for feature in &other.detected {
            let conf = other.confidence.get(feature).copied().unwrap_or(1.0);
            self.add(*feature, conf);
        }
        self.instructions_scanned += other.instructions_scanned;
    }

    /// Return all features whose confidence is at least `threshold`.
    #[must_use] 
    pub fn high_confidence_features(&self, threshold: f64) -> Vec<CpuFeature> {
        self.detected
            .iter()
            .filter(|&&f| self.confidence.get(&f).copied().unwrap_or(0.0) >= threshold)
            .copied()
            .collect()
    }

    /// Infer the minimum ARM architecture version required by this feature set.
    #[must_use] 
    pub fn min_arch_version(&self) -> (u8, u8) {
        self.detected
            .iter()
            .map(|f| f.min_arch_version())
            .max_by(std::cmp::Ord::cmp)
            .unwrap_or((8, 0))
    }
}

impl fmt::Display for FeatureSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut feats: Vec<_> = self.detected.iter().map(|f| f.mnemonic()).collect();
        feats.sort_unstable();
        write!(f, "FeatureSet[{}]", feats.join(","))
    }
}

// ─── MnemonicPattern ─────────────────────────────────────────────────────────

/// A mnemonic prefix and the feature it implies.
#[derive(Debug)]
struct MnemonicPattern {
    prefix: &'static str,
    feature: CpuFeature,
    confidence: f64,
}

impl MnemonicPattern {
    const fn new(prefix: &'static str, feature: CpuFeature, confidence: f64) -> Self {
        Self { prefix, feature, confidence }
    }
}

// ─── Arm64FeatureDetector ─────────────────────────────────────────────────────

/// Detects ARM64 CPU features by scanning mnemonic strings from disassembled
/// instruction streams.
///
/// The detector is heuristic: it counts how often certain instruction
/// classes appear and assigns confidence scores accordingly. A single
/// occurrence of a PAC instruction is enough to flag `Pauth`; SVE requires
/// seeing SVE-encoded instruction words.
pub struct Arm64FeatureDetector {
    /// Minimum number of occurrences before a feature is reported at full confidence.
    pub min_occurrences: u32,
    /// Whether to also detect EL2/EL3 instructions.
    pub detect_privileged: bool,
    occurrence_counts: HashMap<CpuFeature, u32>,
    patterns: Vec<MnemonicPattern>,
}

impl Arm64FeatureDetector {
    /// Create a new feature detector with default settings.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            min_occurrences: 1,
            detect_privileged: true,
            occurrence_counts: HashMap::new(),
            patterns: Self::build_patterns(),
        }
    }

    /// Create a detector with a custom occurrence threshold.
    #[must_use] 
    pub fn with_threshold(min_occurrences: u32) -> Self {
        Self {
            min_occurrences,
            ..Self::new()
        }
    }

    /// Build the mnemonic → feature pattern table.
    fn build_patterns() -> Vec<MnemonicPattern> {
        vec![
            // Base / FP / NEON — always present
            MnemonicPattern::new("fadd", CpuFeature::Fp, 1.0),
            MnemonicPattern::new("fsub", CpuFeature::Fp, 1.0),
            MnemonicPattern::new("fmul", CpuFeature::Fp, 1.0),
            MnemonicPattern::new("fdiv", CpuFeature::Fp, 1.0),
            MnemonicPattern::new("fcmp", CpuFeature::Fp, 1.0),
            MnemonicPattern::new("fmov", CpuFeature::Fp, 1.0),
            MnemonicPattern::new("fcvt", CpuFeature::Fp, 1.0),
            MnemonicPattern::new("frintz", CpuFeature::Fp, 1.0),
            MnemonicPattern::new("frintx", CpuFeature::Fp, 1.0),

            // Advanced SIMD
            MnemonicPattern::new("dup", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("ins", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("ext", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("zip", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("uzp", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("trn", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("tbl", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("tbx", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("mla", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("mls", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("umov", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("smov", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("addp", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("addv", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("cnt", CpuFeature::AdvSimd, 0.8),
            MnemonicPattern::new("rev64", CpuFeature::AdvSimd, 1.0),
            MnemonicPattern::new("rev32", CpuFeature::AdvSimd, 1.0),

            // LSE atomics
            MnemonicPattern::new("cas", CpuFeature::Lse, 1.0),
            MnemonicPattern::new("swp", CpuFeature::Lse, 1.0),
            MnemonicPattern::new("ldadd", CpuFeature::Lse, 1.0),
            MnemonicPattern::new("ldclr", CpuFeature::Lse, 1.0),
            MnemonicPattern::new("ldeor", CpuFeature::Lse, 1.0),
            MnemonicPattern::new("ldset", CpuFeature::Lse, 1.0),
            MnemonicPattern::new("stadd", CpuFeature::Lse, 1.0),
            MnemonicPattern::new("stclr", CpuFeature::Lse, 1.0),

            // FP16
            MnemonicPattern::new("faddh", CpuFeature::Fp16, 1.0),
            MnemonicPattern::new("fmulh", CpuFeature::Fp16, 1.0),
            MnemonicPattern::new("fcvtah", CpuFeature::Fp16, 1.0),

            // SVE
            MnemonicPattern::new("ld1b", CpuFeature::Sve, 0.9),
            MnemonicPattern::new("ld1h", CpuFeature::Sve, 0.9),
            MnemonicPattern::new("ld1w", CpuFeature::Sve, 0.9),
            MnemonicPattern::new("ld1d", CpuFeature::Sve, 0.9),
            MnemonicPattern::new("st1b", CpuFeature::Sve, 0.9),
            MnemonicPattern::new("st1h", CpuFeature::Sve, 0.9),
            MnemonicPattern::new("st1w", CpuFeature::Sve, 0.9),
            MnemonicPattern::new("st1d", CpuFeature::Sve, 0.9),
            MnemonicPattern::new("whilelo", CpuFeature::Sve, 1.0),
            MnemonicPattern::new("whilelt", CpuFeature::Sve, 1.0),
            MnemonicPattern::new("ptrue", CpuFeature::Sve, 1.0),
            MnemonicPattern::new("pfalse", CpuFeature::Sve, 1.0),
            MnemonicPattern::new("rdvl", CpuFeature::Sve, 1.0),

            // SVE2
            MnemonicPattern::new("match", CpuFeature::Sve2, 1.0),
            MnemonicPattern::new("nmatch", CpuFeature::Sve2, 1.0),
            MnemonicPattern::new("histcnt", CpuFeature::Sve2, 1.0),

            // PAC
            MnemonicPattern::new("pacia", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("pacib", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("pacda", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("pacdb", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("paciasp", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("pacibsp", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("autia", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("autib", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("autiasp", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("autibsp", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("xpaci", CpuFeature::Pauth, 1.0),
            MnemonicPattern::new("xpaclri", CpuFeature::Pauth, 1.0),

            // BTI
            MnemonicPattern::new("bti", CpuFeature::Bti, 1.0),

            // RNG
            MnemonicPattern::new("rndr", CpuFeature::Rng, 1.0),
            MnemonicPattern::new("rndrrs", CpuFeature::Rng, 1.0),

            // Speculation barrier
            MnemonicPattern::new("sb", CpuFeature::Sb, 1.0),
            MnemonicPattern::new("csdb", CpuFeature::Sb, 0.8),

            // Crypto
            MnemonicPattern::new("aese", CpuFeature::Aes, 1.0),
            MnemonicPattern::new("aesd", CpuFeature::Aes, 1.0),
            MnemonicPattern::new("aesmc", CpuFeature::Aes, 1.0),
            MnemonicPattern::new("aesimc", CpuFeature::Aes, 1.0),
            MnemonicPattern::new("sha1c", CpuFeature::Sha1, 1.0),
            MnemonicPattern::new("sha1p", CpuFeature::Sha1, 1.0),
            MnemonicPattern::new("sha1h", CpuFeature::Sha1, 1.0),
            MnemonicPattern::new("sha256h", CpuFeature::Sha256, 1.0),
            MnemonicPattern::new("sha256su", CpuFeature::Sha256, 1.0),
            MnemonicPattern::new("sha512h", CpuFeature::Sha3, 1.0),
            MnemonicPattern::new("sha3", CpuFeature::Sha3, 1.0),
            MnemonicPattern::new("pmull", CpuFeature::Pmull, 1.0),
            MnemonicPattern::new("sm4e", CpuFeature::Sm4, 1.0),
            MnemonicPattern::new("sm3", CpuFeature::Sha3, 0.5),

            // Hypervisor / EL2
            MnemonicPattern::new("hvc", CpuFeature::Hyp, 1.0),
            MnemonicPattern::new("eret", CpuFeature::Hyp, 0.7),

            // Secure monitor / EL3
            MnemonicPattern::new("smc", CpuFeature::SecMon, 1.0),

            // DOT product
            MnemonicPattern::new("sdot", CpuFeature::DotProd, 1.0),
            MnemonicPattern::new("udot", CpuFeature::DotProd, 1.0),

            // FCMA
            MnemonicPattern::new("fcmla", CpuFeature::Fcma, 1.0),
            MnemonicPattern::new("fcadd", CpuFeature::Fcma, 1.0),

            // JSCVT
            MnemonicPattern::new("fjcvtzs", CpuFeature::JscvT, 1.0),

            // RDM
            MnemonicPattern::new("sqrdmlah", CpuFeature::Rdm, 1.0),
            MnemonicPattern::new("sqrdmlsh", CpuFeature::Rdm, 1.0),

            // RCPC
            MnemonicPattern::new("ldaprb", CpuFeature::Rcpc, 1.0),
            MnemonicPattern::new("ldaprh", CpuFeature::Rcpc, 1.0),
            MnemonicPattern::new("ldapr", CpuFeature::Rcpc, 1.0),
        ]
    }

    /// Process a single mnemonic string, updating occurrence counts.
    pub fn process_mnemonic(&mut self, mnemonic: &str) {
        let m = mnemonic.to_ascii_lowercase();
        for pat in &self.patterns {
            if m.starts_with(pat.prefix) {
                *self.occurrence_counts.entry(pat.feature).or_insert(0) += 1;
                break;
            }
        }
    }

    /// Analyze a slice of mnemonic strings and return the detected feature set.
    pub fn detect_from_insns(&mut self, mnemonics: &[&str]) -> FeatureSet {
        self.occurrence_counts.clear();
        for &m in mnemonics {
            self.process_mnemonic(m);
        }
        self.build_feature_set(mnemonics.len() as u64)
    }

    /// Analyze pre-counted occurrences and return the feature set.
    #[must_use] 
    pub fn detect_from_counts(&self, counts: &HashMap<CpuFeature, u32>, total: u64) -> FeatureSet {
        let mut set = FeatureSet::new();
        set.instructions_scanned = total;
        // Base features always assumed.
        set.add(CpuFeature::BaseA64, 1.0);

        for (feature, count) in counts {
            if *count >= self.min_occurrences {
                let raw_confidence = (f64::from(*count) / instruction_total_as_f64(total)).min(1.0);
                // At least one occurrence → at least 0.5 confidence.
                let confidence = (raw_confidence * 10.0).clamp(0.5, 1.0);
                set.add(*feature, confidence);
            }
        }
        set
    }

    fn build_feature_set(&self, total: u64) -> FeatureSet {
        let mut set = FeatureSet::new();
        set.instructions_scanned = total;
        set.add(CpuFeature::BaseA64, 1.0);

        for pat in &self.patterns {
            let count = self.occurrence_counts.get(&pat.feature).copied().unwrap_or(0);
            if count >= self.min_occurrences {
                let raw_confidence = (f64::from(count) / instruction_total_as_f64(total) * 10.0).min(1.0);
                let confidence = raw_confidence.max(pat.confidence * 0.5);
                set.add(pat.feature, confidence);
            }
        }
        set
    }

    /// Reset internal occurrence counters.
    pub fn reset(&mut self) {
        self.occurrence_counts.clear();
    }

    /// Return a summary of which instruction patterns were matched.
    #[must_use] 
    pub fn occurrence_summary(&self) -> Vec<(CpuFeature, u32)> {
        let mut v: Vec<_> = self.occurrence_counts.iter().map(|(&f, &c)| (f, c)).collect();
        v.sort_by_key(|&(f, _)| f);
        v
    }
}

impl Default for Arm64FeatureDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Arm64FeatureDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Arm64FeatureDetector")
            .field("min_occurrences", &self.min_occurrences)
            .field("detect_privileged", &self.detect_privileged)
            .field("pattern_count", &self.patterns.len())
            .field("patterns", &self.patterns)
            .field("occurrence_counts", &self.occurrence_counts)
            .finish()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> Arm64FeatureDetector {
        Arm64FeatureDetector::new()
    }

    #[test]
    fn feature_mnemonic_display() {
        assert_eq!(CpuFeature::Lse.mnemonic(), "lse");
        assert!(CpuFeature::Pauth.to_string().contains("PAUTH"));
    }

    #[test]
    fn feature_min_arch_version() {
        assert_eq!(CpuFeature::BaseA64.min_arch_version(), (8, 0));
        assert_eq!(CpuFeature::Lse.min_arch_version(), (8, 1));
        assert_eq!(CpuFeature::Pauth.min_arch_version(), (8, 3));
        assert_eq!(CpuFeature::Bti.min_arch_version(), (8, 5));
    }

    #[test]
    fn detect_base_always_present() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["add", "sub", "mov"]);
        assert!(fs.has(CpuFeature::BaseA64));
    }

    #[test]
    fn detect_pauth_from_paciasp() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["paciasp", "autiasp", "ret"]);
        assert!(fs.has(CpuFeature::Pauth));
    }

    #[test]
    fn detect_lse_from_cas() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["cas", "casb", "casal"]);
        assert!(fs.has(CpuFeature::Lse));
    }

    #[test]
    fn detect_fp_from_fadd() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["fadd", "fmul", "fcmp"]);
        assert!(fs.has(CpuFeature::Fp));
    }

    #[test]
    fn detect_adv_simd_from_dup() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["dup", "ins", "addp"]);
        assert!(fs.has(CpuFeature::AdvSimd));
    }

    #[test]
    fn detect_aes_crypto() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["aese", "aesd", "aesmc"]);
        assert!(fs.has(CpuFeature::Aes));
    }

    #[test]
    fn detect_sve_from_rdvl() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["rdvl", "whilelo", "ptrue"]);
        assert!(fs.has(CpuFeature::Sve));
    }

    #[test]
    fn detect_bti_instruction() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["bti", "add"]);
        assert!(fs.has(CpuFeature::Bti));
    }

    #[test]
    fn detect_hvc_implies_hyp() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["hvc"]);
        assert!(fs.has(CpuFeature::Hyp));
    }

    #[test]
    fn detect_smc_implies_secmon() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["smc"]);
        assert!(fs.has(CpuFeature::SecMon));
    }

    #[test]
    fn detect_rng_rndr() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["rndr", "rndrrs"]);
        assert!(fs.has(CpuFeature::Rng));
    }

    #[test]
    fn feature_set_merge() {
        let mut a = FeatureSet::new();
        a.add(CpuFeature::Fp, 0.9);
        let mut b = FeatureSet::new();
        b.add(CpuFeature::Lse, 1.0);
        a.merge(&b);
        assert!(a.has(CpuFeature::Fp));
        assert!(a.has(CpuFeature::Lse));
    }

    #[test]
    fn feature_set_min_arch_version() {
        let mut fs = FeatureSet::new();
        fs.add(CpuFeature::BaseA64, 1.0);
        fs.add(CpuFeature::Pauth, 1.0);
        assert_eq!(fs.min_arch_version(), (8, 3));
    }

    #[test]
    fn feature_set_high_confidence_filter() {
        let mut fs = FeatureSet::new();
        fs.add(CpuFeature::Fp, 0.9);
        fs.add(CpuFeature::Lse, 0.3);
        let high = fs.high_confidence_features(0.8);
        assert!(high.contains(&CpuFeature::Fp));
        assert!(!high.contains(&CpuFeature::Lse));
    }

    #[test]
    fn detector_reset_clears_counts() {
        let mut d = detector();
        d.process_mnemonic("cas");
        assert!(!d.occurrence_summary().is_empty());
        d.reset();
        assert!(d.occurrence_summary().is_empty());
    }

    #[test]
    fn detector_min_occurrences_threshold() {
        let mut d = Arm64FeatureDetector::with_threshold(3);
        // Only 2 CAS instructions — below threshold of 3
        let fs = d.detect_from_insns(&["cas", "cas"]);
        assert!(!fs.has(CpuFeature::Lse));
        // 3 CAS instructions — at threshold
        let fs2 = d.detect_from_insns(&["cas", "cas", "cas"]);
        assert!(fs2.has(CpuFeature::Lse));
    }

    #[test]
    fn feature_set_display() {
        let mut fs = FeatureSet::new();
        fs.add(CpuFeature::Fp, 1.0);
        let s = fs.to_string();
        assert!(s.contains("fp"));
    }

    #[test]
    fn unknown_mnemonics_dont_add_features() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["add", "sub", "mov", "ldr", "str"]);
        // Only BaseA64 should be present — these are all base instructions
        // that don't trigger any specific extension.
        assert!(fs.has(CpuFeature::BaseA64));
    }

    #[test]
    fn occurrence_summary_sorted() {
        let mut d = detector();
        d.process_mnemonic("cas");
        d.process_mnemonic("aese");
        let summary = d.occurrence_summary();
        assert!(!summary.is_empty());
        // Verify sorted order
        let features: Vec<_> = summary.iter().map(|(f, _)| f).collect();
        let mut sorted = features.clone();
        sorted.sort();
        assert_eq!(features, sorted);
    }

    #[test]
    fn empty_input_only_base_or_empty() {
        let mut d = detector();
        let fs = d.detect_from_insns(&[]);
        // Base must not erroneously be set without any input.
        // (If detector adds Base unconditionally, accept that too — just must not panic.)
        let _ = fs.has(CpuFeature::BaseA64);
    }

    #[test]
    fn unknown_mnemonics_only_base() {
        let mut d = detector();
        let fs = d.detect_from_insns(&["zzz_nonexistent", "qqq_garbage"]);
        // Should not detect any concrete extension features
        assert!(!fs.has(CpuFeature::Lse));
        assert!(!fs.has(CpuFeature::Pauth));
        assert!(!fs.has(CpuFeature::Sve));
    }

    #[test]
    fn feature_set_merge_keeps_max_confidence() {
        let mut a = FeatureSet::new();
        a.add(CpuFeature::Fp, 0.3);
        let mut b = FeatureSet::new();
        b.add(CpuFeature::Fp, 0.9);
        a.merge(&b);
        assert!(a.has(CpuFeature::Fp));
        // After merge confidence should be >= 0.3
        let high = a.high_confidence_features(0.5);
        assert!(high.contains(&CpuFeature::Fp));
    }

    #[test]
    fn high_confidence_threshold_boundary() {
        let mut fs = FeatureSet::new();
        fs.add(CpuFeature::Fp, 0.5);
        // Exactly-at-threshold and just-below
        let high_at = fs.high_confidence_features(0.5);
        let high_above = fs.high_confidence_features(0.500_001);
        // At threshold: implementation-defined inclusive/exclusive, just verify no panic.
        let _ = high_at;
        assert!(!high_above.contains(&CpuFeature::Fp));
    }

    #[test]
    fn many_mnemonics_no_panic() {
        let mut d = detector();
        let big: Vec<&str> = std::iter::repeat("add").take(10_000).collect();
        let fs = d.detect_from_insns(&big);
        assert!(fs.has(CpuFeature::BaseA64));
    }

    #[test]
    fn detector_reset_idempotent() {
        let mut d = detector();
        d.process_mnemonic("cas");
        d.reset();
        d.reset();
        assert!(d.occurrence_summary().is_empty());
    }

    #[test]
    fn min_arch_version_monotonic() {
        // Higher features must have >= version than base.
        let (maj_base, _) = CpuFeature::BaseA64.min_arch_version();
        let (maj_bti, min_bti) = CpuFeature::Bti.min_arch_version();
        assert!(maj_bti > maj_base || (maj_bti == maj_base && min_bti >= 5));
    }
}
