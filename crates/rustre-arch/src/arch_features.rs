//! `arch_features` — Architecture feature detection and compatibility checking.
//!
//! Detects which CPU features a binary requires, checks compatibility between
//! feature sets, and determines the minimum CPU capable of running the binary.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Feature ─────────────────────────────────────────────────────────────────

/// A discrete CPU/ISA feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Feature {
    // Word size
    Bits32,
    Bits64,
    // ARM instruction sets
    Thumb,
    Thumb2,
    Neon,
    Vfpv2,
    Vfpv3,
    Vfpv4,
    // ARM security extensions
    Pac, // Pointer Authentication Codes
    Mte, // Memory Tagging Extension
    Sve, // Scalable Vector Extension
    Sve2,
    // x86 SIMD
    Sse,
    Sse2,
    Sse3,
    Ssse3,
    Sse41,
    Sse42,
    Avx,
    Avx2,
    Avx512f,
    Avx512bw,
    Avx512dq,
    Avx512vl,
    // x86 misc
    Bmi1,
    Bmi2,
    Popcnt,
    Lzcnt,
    Aes, // AES-NI
    Pclmul,
    Sha,
    Rdrand,
    Rdseed,
    Cmpxchg16b,
    Movbe,
    F16c,
    Fma,
    Adx,
    Clflushopt,
    // Atomic/memory ordering
    Atomic,
    Atomic64,
    // RISC-V Vector
    Rvv,
    // MIPS
    Mips32r2,
    Mips64r2,
    MipsMsa,
    // Generic
    HardFloat,
    SoftFloat,
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Bits32 => "32bit",
            Self::Bits64 => "64bit",
            Self::Thumb => "thumb",
            Self::Thumb2 => "thumb2",
            Self::Neon => "neon",
            Self::Vfpv2 => "vfpv2",
            Self::Vfpv3 => "vfpv3",
            Self::Vfpv4 => "vfpv4",
            Self::Pac => "pac",
            Self::Mte => "mte",
            Self::Sve => "sve",
            Self::Sve2 => "sve2",
            Self::Sse => "sse",
            Self::Sse2 => "sse2",
            Self::Sse3 => "sse3",
            Self::Ssse3 => "ssse3",
            Self::Sse41 => "sse4.1",
            Self::Sse42 => "sse4.2",
            Self::Avx => "avx",
            Self::Avx2 => "avx2",
            Self::Avx512f => "avx512f",
            Self::Avx512bw => "avx512bw",
            Self::Avx512dq => "avx512dq",
            Self::Avx512vl => "avx512vl",
            Self::Bmi1 => "bmi1",
            Self::Bmi2 => "bmi2",
            Self::Popcnt => "popcnt",
            Self::Lzcnt => "lzcnt",
            Self::Aes => "aes",
            Self::Pclmul => "pclmul",
            Self::Sha => "sha",
            Self::Rdrand => "rdrand",
            Self::Rdseed => "rdseed",
            Self::Cmpxchg16b => "cmpxchg16b",
            Self::Movbe => "movbe",
            Self::F16c => "f16c",
            Self::Fma => "fma",
            Self::Adx => "adx",
            Self::Clflushopt => "clflushopt",
            Self::Atomic => "atomic",
            Self::Atomic64 => "atomic64",
            Self::Rvv => "rvv",
            Self::Mips32r2 => "mips32r2",
            Self::Mips64r2 => "mips64r2",
            Self::MipsMsa => "mips-msa",
            Self::HardFloat => "hard-float",
            Self::SoftFloat => "soft-float",
        };
        write!(f, "{s}")
    }
}

// ─── ArchFeatureSet ───────────────────────────────────────────────────────────

/// A set of CPU features associated with a binary or CPU model.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ArchFeatureSet {
    pub features: HashSet<Feature>,
}

impl ArchFeatureSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, f: Feature) {
        self.features.insert(f);
    }

    pub fn remove(&mut self, f: Feature) {
        self.features.remove(&f);
    }

    #[must_use]
    pub fn has(&self, f: Feature) -> bool {
        self.features.contains(&f)
    }

    /// True if this feature set is a superset of `required`.
    #[must_use]
    pub fn satisfies(&self, required: &Self) -> bool {
        required.features.iter().all(|f| self.features.contains(f))
    }

    /// Return features in `required` that are missing from this set.
    #[must_use]
    pub fn missing(&self, required: &Self) -> Vec<Feature> {
        required
            .features
            .iter()
            .filter(|f| !self.features.contains(f))
            .copied()
            .collect()
    }

    /// Intersection with another feature set.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            features: self
                .features
                .intersection(&other.features)
                .copied()
                .collect(),
        }
    }

    /// Union with another feature set.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self {
            features: self.features.union(&other.features).copied().collect(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.features.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    /// Feature names as sorted strings.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .features
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        names.sort();
        names
    }
}

// ─── FeatureDetector ─────────────────────────────────────────────────────────

/// Architecture category for the detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArchKind {
    X86,
    X86_64,
    Arm32,
    Arm64,
    Mips,
    RiscV,
    Wasm,
    Unknown,
}

/// Detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub arch: ArchKind,
    pub detected_features: ArchFeatureSet,
    pub evidence: HashMap<String, Vec<String>>,
}

/// Detects CPU features from binary opcodes / bytes.
pub struct FeatureDetector;

impl FeatureDetector {
    /// Scan a byte slice for x86/x86-64 instruction prefixes and opcodes that
    /// indicate specific feature requirements.
    #[must_use]
    pub fn detect_x86(bytes: &[u8], is_64bit: bool) -> DetectionResult {
        let mut fs = ArchFeatureSet::new();
        let mut evidence: HashMap<String, Vec<String>> = HashMap::new();

        fs.add(if is_64bit {
            Feature::Bits64
        } else {
            Feature::Bits32
        });

        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            match b {
                // VEX/EVEX prefix → AVX or AVX-512
                0xC4 | 0xC5 if i + 1 < bytes.len() => {
                    fs.add(Feature::Avx);
                    evidence
                        .entry("avx".into())
                        .or_default()
                        .push(format!("VEX prefix at {i:#x}"));
                    // Check for EVEX (0x62 prefix).
                }
                0x62 if i + 3 < bytes.len() => {
                    fs.add(Feature::Avx512f);
                    evidence
                        .entry("avx512f".into())
                        .or_default()
                        .push(format!("EVEX prefix at {i:#x}"));
                }
                // 0x66 + 0x0F → SSE2 or later
                0x66 if i + 2 < bytes.len() && bytes[i + 1] == 0x0F => {
                    fs.add(Feature::Sse2);
                    evidence
                        .entry("sse2".into())
                        .or_default()
                        .push(format!("0x66 0x0F at {i:#x}"));
                }
                // 0xF3 + 0x0F → SSE
                0xF3 if i + 2 < bytes.len() && bytes[i + 1] == 0x0F => {
                    fs.add(Feature::Sse);
                    evidence
                        .entry("sse".into())
                        .or_default()
                        .push(format!("0xF3 0x0F at {i:#x}"));
                }
                // 0x0F 0x38 F0..FF → AES-NI / SHA / ...
                0x0F if i + 2 < bytes.len() && bytes[i + 1] == 0x38 => {
                    let op = bytes[i + 2];
                    if (0xDE..=0xDF).contains(&op) {
                        fs.add(Feature::Aes);
                        evidence
                            .entry("aes".into())
                            .or_default()
                            .push(format!("AES-NI at {i:#x}"));
                    }
                    if (0xC8..=0xCB).contains(&op) {
                        fs.add(Feature::Sha);
                        evidence
                            .entry("sha".into())
                            .or_default()
                            .push(format!("SHA at {i:#x}"));
                    }
                }
                // POPCNT: F3 0F B8
                0xF3 if i + 3 < bytes.len() && bytes[i + 1] == 0x0F && bytes[i + 2] == 0xB8 => {
                    fs.add(Feature::Popcnt);
                    fs.add(Feature::Sse42);
                }
                // CMPXCHG16B: 0F C7 /1
                0x0F if i + 2 < bytes.len() && bytes[i + 1] == 0xC7 => {
                    fs.add(Feature::Cmpxchg16b);
                }
                _ => {}
            }
            i += 1;
        }

        DetectionResult {
            arch: if is_64bit {
                ArchKind::X86_64
            } else {
                ArchKind::X86
            },
            detected_features: fs,
            evidence,
        }
    }

    /// Scan ARM32 instructions for Thumb-2 and NEON feature usage.
    #[must_use]
    pub fn detect_arm32(words: &[u32]) -> DetectionResult {
        let mut fs = ArchFeatureSet::new();
        fs.add(Feature::Bits32);

        for &word in words {
            // Thumb-2 32-bit instruction: bits 28:27 = 11, bit 28 set in T32.
            // Simple heuristic: check for NEON instruction patterns.
            // NEON instructions have bits 31:24 = 0b11110 (0xF0..0xFF) in ARM mode.
            let hi_byte = (word >> 24) & 0xFF;
            if (0xF2..=0xF3).contains(&hi_byte) {
                fs.add(Feature::Neon);
            }
            // VFP instructions: coprocessor 10 or 11 (bits 11:8).
            let coproc = (word >> 8) & 0xF;
            if coproc == 10 || coproc == 11 {
                fs.add(Feature::Vfpv2);
            }
        }

        DetectionResult {
            arch: ArchKind::Arm32,
            detected_features: fs,
            evidence: HashMap::new(),
        }
    }

    /// Scan ARM64 instructions for SVE, PAC, and MTE usage.
    #[must_use]
    pub fn detect_arm64(words: &[u32]) -> DetectionResult {
        let mut fs = ArchFeatureSet::new();
        fs.add(Feature::Bits64);
        fs.add(Feature::HardFloat);
        // All ARM64 has NEON by default.
        fs.add(Feature::Neon);

        for &word in words {
            let op0 = (word >> 29) & 0x7;
            // SVE instructions: op0 = 0b010x or 0b110x with specific encoding.
            if op0 == 0x4 || op0 == 0x6 {
                let top8 = (word >> 24) & 0xFF;
                if (0x04..=0x05).contains(&top8) {
                    fs.add(Feature::Sve);
                }
            }
            // PAC instructions: AUTIA, AUTIB, etc. — specific encodings.
            let top12 = (word >> 20) & 0xFFF;
            if top12 == 0xDAC {
                fs.add(Feature::Pac);
            }
        }

        DetectionResult {
            arch: ArchKind::Arm64,
            detected_features: fs,
            evidence: HashMap::new(),
        }
    }
}

// ─── FeatureRequirements ─────────────────────────────────────────────────────

/// CPU feature requirements inferred from a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureRequirements {
    pub minimum_features: ArchFeatureSet,
    pub optional_features: ArchFeatureSet,
    pub arch: ArchKind,
}

impl FeatureRequirements {
    #[must_use]
    pub fn new(arch: ArchKind, minimum_features: ArchFeatureSet) -> Self {
        Self {
            minimum_features,
            optional_features: ArchFeatureSet::new(),
            arch,
        }
    }

    /// True if the provided CPU feature set satisfies the requirements.
    #[must_use]
    pub fn satisfied_by(&self, cpu: &ArchFeatureSet) -> bool {
        cpu.satisfies(&self.minimum_features)
    }

    /// Features present in optional but not minimum.
    #[must_use]
    pub fn optional_only(&self) -> Vec<Feature> {
        self.optional_features
            .features
            .iter()
            .filter(|f| !self.minimum_features.has(**f))
            .copied()
            .collect()
    }
}

// ─── ArchCompatibility ────────────────────────────────────────────────────────

/// Compatibility check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityResult {
    pub is_compatible: bool,
    pub missing_features: Vec<Feature>,
    pub optional_missing: Vec<Feature>,
    pub cpu_name: String,
}

/// Checks architecture compatibility between a binary and a CPU profile.
pub struct ArchCompatibility;

impl ArchCompatibility {
    /// Check compatibility.
    pub fn check(
        binary_requirements: &FeatureRequirements,
        cpu_features: &ArchFeatureSet,
        cpu_name: impl Into<String>,
    ) -> CompatibilityResult {
        let missing = cpu_features.missing(&binary_requirements.minimum_features);
        let optional_missing = cpu_features.missing(&binary_requirements.optional_features);
        CompatibilityResult {
            is_compatible: missing.is_empty(),
            missing_features: missing,
            optional_missing,
            cpu_name: cpu_name.into(),
        }
    }

    /// Find the minimum CPU profile (from a catalogue) that satisfies requirements.
    #[must_use]
    pub fn find_minimum_cpu<'a>(
        requirements: &FeatureRequirements,
        cpu_catalogue: &'a HashMap<String, ArchFeatureSet>,
    ) -> Option<&'a str> {
        // Return the CPU with fewest features that still satisfies requirements.
        let mut best: Option<(&str, usize)> = None;
        for (name, features) in cpu_catalogue {
            if features.satisfies(&requirements.minimum_features) {
                let count = features.len();
                if best.is_none_or(|(_, c)| count < c) {
                    best = Some((name, count));
                }
            }
        }
        best.map(|(name, _)| name)
    }
}

// ─── Well-known CPU profiles ─────────────────────────────────────────────────

/// Returns a catalogue of well-known CPU feature profiles.
#[must_use]
pub fn well_known_cpus() -> HashMap<String, ArchFeatureSet> {
    let mut catalogue = HashMap::new();

    let mut i486 = ArchFeatureSet::new();
    i486.add(Feature::Bits32);
    catalogue.insert("i486".into(), i486);

    let mut pentium3 = ArchFeatureSet::new();
    pentium3.add(Feature::Bits32);
    pentium3.add(Feature::Sse);
    catalogue.insert("pentium3".into(), pentium3);

    let mut core2 = ArchFeatureSet::new();
    for f in [
        Feature::Bits64,
        Feature::Sse,
        Feature::Sse2,
        Feature::Sse3,
        Feature::Ssse3,
    ] {
        core2.add(f);
    }
    catalogue.insert("core2".into(), core2);

    let mut sandybridge = ArchFeatureSet::new();
    for f in [
        Feature::Bits64,
        Feature::Sse,
        Feature::Sse2,
        Feature::Sse3,
        Feature::Ssse3,
        Feature::Sse41,
        Feature::Sse42,
        Feature::Avx,
        Feature::Aes,
        Feature::Popcnt,
    ] {
        sandybridge.add(f);
    }
    catalogue.insert("sandybridge".into(), sandybridge);

    let mut haswell = ArchFeatureSet::new();
    for f in [
        Feature::Bits64,
        Feature::Sse,
        Feature::Sse2,
        Feature::Sse3,
        Feature::Ssse3,
        Feature::Sse41,
        Feature::Sse42,
        Feature::Avx,
        Feature::Avx2,
        Feature::Aes,
        Feature::Popcnt,
        Feature::Bmi1,
        Feature::Bmi2,
        Feature::Fma,
        Feature::F16c,
        Feature::Adx,
        Feature::Rdrand,
    ] {
        haswell.add(f);
    }
    catalogue.insert("haswell".into(), haswell);

    let mut skylake_avx512 = ArchFeatureSet::new();
    for f in [
        Feature::Bits64,
        Feature::Avx512f,
        Feature::Avx512bw,
        Feature::Avx512dq,
        Feature::Avx512vl,
        Feature::Aes,
        Feature::Popcnt,
        Feature::Bmi2,
    ] {
        skylake_avx512.add(f);
    }
    catalogue.insert("skylake-avx512".into(), skylake_avx512);

    let mut cortex_a55 = ArchFeatureSet::new();
    for f in [
        Feature::Bits64,
        Feature::Neon,
        Feature::Vfpv4,
        Feature::HardFloat,
    ] {
        cortex_a55.add(f);
    }
    catalogue.insert("cortex-a55".into(), cortex_a55);

    catalogue
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_set_add_has() {
        let mut fs = ArchFeatureSet::new();
        fs.add(Feature::Avx2);
        assert!(fs.has(Feature::Avx2));
        assert!(!fs.has(Feature::Avx512f));
    }

    #[test]
    fn feature_set_satisfies() {
        let mut cpu = ArchFeatureSet::new();
        cpu.add(Feature::Sse);
        cpu.add(Feature::Sse2);

        let mut required = ArchFeatureSet::new();
        required.add(Feature::Sse);

        assert!(cpu.satisfies(&required));
    }

    #[test]
    fn feature_set_missing() {
        let mut cpu = ArchFeatureSet::new();
        cpu.add(Feature::Sse);

        let mut required = ArchFeatureSet::new();
        required.add(Feature::Sse);
        required.add(Feature::Avx);

        let missing = cpu.missing(&required);
        assert_eq!(missing, vec![Feature::Avx]);
    }

    #[test]
    fn feature_set_intersect() {
        let mut a = ArchFeatureSet::new();
        a.add(Feature::Sse);
        a.add(Feature::Avx);

        let mut b = ArchFeatureSet::new();
        b.add(Feature::Avx);
        b.add(Feature::Avx2);

        let inter = a.intersect(&b);
        assert!(inter.has(Feature::Avx));
        assert!(!inter.has(Feature::Sse));
        assert!(!inter.has(Feature::Avx2));
    }

    #[test]
    fn feature_set_union() {
        let mut a = ArchFeatureSet::new();
        a.add(Feature::Sse);
        let mut b = ArchFeatureSet::new();
        b.add(Feature::Avx);
        let uni = a.union(&b);
        assert!(uni.has(Feature::Sse));
        assert!(uni.has(Feature::Avx));
    }

    #[test]
    fn feature_set_names_sorted() {
        let mut fs = ArchFeatureSet::new();
        fs.add(Feature::Avx);
        fs.add(Feature::Sse);
        let names = fs.names();
        assert!(names.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn feature_display() {
        assert_eq!(Feature::Avx512f.to_string(), "avx512f");
        assert_eq!(Feature::Pac.to_string(), "pac");
    }

    #[test]
    fn detector_x86_sse2() {
        // 0x66 0x0F → SSE2 hint
        let bytes = vec![0x66u8, 0x0F, 0x6F, 0xC0];
        let result = FeatureDetector::detect_x86(&bytes, false);
        assert!(result.detected_features.has(Feature::Sse2));
    }

    #[test]
    fn detector_x86_avx() {
        // VEX prefix 0xC5
        let bytes = vec![0xC5u8, 0xF8, 0x77];
        let result = FeatureDetector::detect_x86(&bytes, true);
        assert!(result.detected_features.has(Feature::Avx));
        assert_eq!(result.arch, ArchKind::X86_64);
    }

    #[test]
    fn detector_x86_64_bit() {
        let result = FeatureDetector::detect_x86(&[], true);
        assert!(result.detected_features.has(Feature::Bits64));
    }

    #[test]
    fn detector_arm32_neon() {
        // Fake NEON word: hi_byte = 0xF2
        let words = vec![0xF200_0000_u32];
        let result = FeatureDetector::detect_arm32(&words);
        assert!(result.detected_features.has(Feature::Neon));
    }

    #[test]
    fn detector_arm64_defaults() {
        let result = FeatureDetector::detect_arm64(&[]);
        assert!(result.detected_features.has(Feature::Bits64));
        assert!(result.detected_features.has(Feature::Neon));
        assert_eq!(result.arch, ArchKind::Arm64);
    }

    #[test]
    fn feature_requirements_satisfied() {
        let mut min = ArchFeatureSet::new();
        min.add(Feature::Avx);
        let req = FeatureRequirements::new(ArchKind::X86_64, min);
        let mut cpu = ArchFeatureSet::new();
        cpu.add(Feature::Avx);
        cpu.add(Feature::Avx2);
        assert!(req.satisfied_by(&cpu));
    }

    #[test]
    fn feature_requirements_not_satisfied() {
        let mut min = ArchFeatureSet::new();
        min.add(Feature::Avx512f);
        let req = FeatureRequirements::new(ArchKind::X86_64, min);
        let mut cpu = ArchFeatureSet::new();
        cpu.add(Feature::Avx);
        assert!(!req.satisfied_by(&cpu));
    }

    #[test]
    fn arch_compatibility_check_compatible() {
        let mut min = ArchFeatureSet::new();
        min.add(Feature::Sse);
        let req = FeatureRequirements::new(ArchKind::X86, min);
        let mut cpu = ArchFeatureSet::new();
        cpu.add(Feature::Sse);
        let result = ArchCompatibility::check(&req, &cpu, "pentium3");
        assert!(result.is_compatible);
        assert!(result.missing_features.is_empty());
    }

    #[test]
    fn arch_compatibility_check_incompatible() {
        let mut min = ArchFeatureSet::new();
        min.add(Feature::Avx512f);
        let req = FeatureRequirements::new(ArchKind::X86_64, min);
        let mut cpu = ArchFeatureSet::new();
        cpu.add(Feature::Avx);
        let result = ArchCompatibility::check(&req, &cpu, "haswell");
        assert!(!result.is_compatible);
        assert!(result.missing_features.contains(&Feature::Avx512f));
    }

    #[test]
    fn well_known_cpus_has_entries() {
        let cpus = well_known_cpus();
        assert!(!cpus.is_empty());
        assert!(cpus.contains_key("haswell"));
    }

    #[test]
    fn find_minimum_cpu() {
        let mut min = ArchFeatureSet::new();
        min.add(Feature::Sse);
        let req = FeatureRequirements::new(ArchKind::X86, min);
        let catalogue = well_known_cpus();
        let cpu = ArchCompatibility::find_minimum_cpu(&req, &catalogue);
        assert!(cpu.is_some());
    }

    #[test]
    fn feature_set_empty() {
        let fs = ArchFeatureSet::new();
        assert!(fs.is_empty());
        assert_eq!(fs.len(), 0);
    }

    #[test]
    fn feature_set_remove() {
        let mut fs = ArchFeatureSet::new();
        fs.add(Feature::Avx);
        fs.remove(Feature::Avx);
        assert!(!fs.has(Feature::Avx));
    }
}
