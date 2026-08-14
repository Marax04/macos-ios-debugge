//! Architecture feature flags: CPU extensions (SSE, AVX, NEON, etc.),
//! [`ArchFeatureFlags`], [`FeatureSet`], [`FeatureFlag`], feature detection.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// FeatureFlag
// ─────────────────────────────────────────────────────────────────────────────

/// A CPU feature / ISA extension that may or may not be present on a given
/// processor variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeatureFlag {
    // ── x86/x86-64 ────────────────────────────────────────────────────────────
    /// MMX integer SIMD (x86).
    Mmx,
    /// SSE — Streaming SIMD Extensions.
    Sse,
    /// SSE2.
    Sse2,
    /// SSE3.
    Sse3,
    /// SSSE3 — Supplemental SSE3.
    Ssse3,
    /// SSE4.1.
    Sse41,
    /// SSE4.2.
    Sse42,
    /// AVX — Advanced Vector Extensions (256-bit).
    Avx,
    /// AVX2.
    Avx2,
    /// AVX-512 foundation.
    Avx512F,
    /// AES-NI hardware AES acceleration.
    AesNi,
    /// PCLMULQDQ — carry-less multiplication.
    Pclmulqdq,
    /// SHA-NI hardware SHA acceleration.
    ShaExt,
    /// RDRAND — hardware random number generator.
    Rdrand,
    /// RDSEED.
    Rdseed,
    /// BMI1 — Bit Manipulation Instructions.
    Bmi1,
    /// BMI2.
    Bmi2,
    /// POPCNT — population count.
    Popcnt,
    /// LZCNT — leading zero count.
    Lzcnt,
    /// FMA3 — Fused Multiply-Add.
    Fma3,
    /// FMA4.
    Fma4,
    /// F16C — half-precision float conversion.
    F16c,
    /// MOVBE — byte-swap move.
    Movbe,
    /// TSX — Transactional Synchronisation Extensions.
    Tsx,
    /// SGX — Software Guard Extensions.
    Sgx,
    /// CET — Control-flow Enforcement Technology.
    Cet,
    /// MPX — Memory Protection Extensions.
    Mpx,

    // ── ARM/AArch64 ───────────────────────────────────────────────────────────
    /// NEON (Advanced SIMD for ARM).
    Neon,
    /// `VFPv3` — Vector Floating-Point.
    Vfpv3,
    /// `VFPv4`.
    Vfpv4,
    /// `AArch64` SVE — Scalable Vector Extension.
    Sve,
    /// `AArch64` SVE2.
    Sve2,
    /// `AArch64` Crypto extensions.
    ArmCrypto,
    /// `AArch64` CRC32 extension.
    ArmCrc32,
    /// `AArch64` Dot-Product extension.
    ArmDotProd,
    /// ARM Thumb-2 ISA.
    Thumb2,
    /// `ARMv8` Pointer Authentication (PAC).
    Pac,
    /// `ARMv8` Branch Target Identification (BTI).
    Bti,
    /// ARMv8.1 Atomics (LDADD etc.).
    Lse,

    // ── MIPS ─────────────────────────────────────────────────────────────────
    /// MIPS SIMD Architecture (MSA).
    MipsMsa,
    /// MIPS FPU.
    MipsFpu,
    /// MIPS DSP extension.
    MipsDsp,
    /// MIPS `MIPS16e` compact ISA.
    Mips16,
    /// `MicroMIPS` compact ISA.
    MicroMips,

    // ── RISC-V ────────────────────────────────────────────────────────────────
    /// RISC-V M — Integer Multiply/Divide.
    RvM,
    /// RISC-V A — Atomic Instructions.
    RvA,
    /// RISC-V F — Single-Precision Float.
    RvF,
    /// RISC-V D — Double-Precision Float.
    RvD,
    /// RISC-V C — Compressed Instructions.
    RvC,
    /// RISC-V V — Vector Extension.
    RvV,
    /// RISC-V B — Bit Manipulation.
    RvB,
    /// RISC-V Zicsr — Control/Status Register.
    RvZicsr,
    /// RISC-V H — Hypervisor Extension.
    RvH,

    // ── PowerPC ───────────────────────────────────────────────────────────────
    /// `AltiVec` / VMX SIMD.
    Altivec,
    /// VSX — Vector Scalar Extensions.
    Vsx,
    /// SPE — Signal Processing Engine (embedded PPC).
    Spe,

    // ── Generic / cross-arch ─────────────────────────────────────────────────
    /// Hardware virtualisation support.
    Virtualisation,
    /// Trusted Execution Environment.
    Tee,
    /// Debug unit / JTAG.
    DebugUnit,

    /// Custom / vendor-specific extension.
    Custom(String),
}

impl FeatureFlag {
    /// Returns the canonical name string for this feature.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Mmx => "mmx",
            Self::Sse => "sse",
            Self::Sse2 => "sse2",
            Self::Sse3 => "sse3",
            Self::Ssse3 => "ssse3",
            Self::Sse41 => "sse4.1",
            Self::Sse42 => "sse4.2",
            Self::Avx => "avx",
            Self::Avx2 => "avx2",
            Self::Avx512F => "avx512f",
            Self::AesNi => "aes",
            Self::Pclmulqdq => "pclmulqdq",
            Self::ShaExt => "sha",
            Self::Rdrand => "rdrand",
            Self::Rdseed => "rdseed",
            Self::Bmi1 => "bmi1",
            Self::Bmi2 => "bmi2",
            Self::Popcnt => "popcnt",
            Self::Lzcnt => "lzcnt",
            Self::Fma3 => "fma",
            Self::Fma4 => "fma4",
            Self::F16c => "f16c",
            Self::Movbe => "movbe",
            Self::Tsx => "tsx",
            Self::Sgx => "sgx",
            Self::Cet => "cet",
            Self::Mpx => "mpx",
            Self::Neon => "neon",
            Self::Vfpv3 => "vfpv3",
            Self::Vfpv4 => "vfpv4",
            Self::Sve => "sve",
            Self::Sve2 => "sve2",
            Self::ArmCrypto => "arm_crypto",
            Self::ArmCrc32 => "arm_crc32",
            Self::ArmDotProd => "arm_dotprod",
            Self::Thumb2 => "thumb2",
            Self::Pac => "pac",
            Self::Bti => "bti",
            Self::Lse => "lse",
            Self::MipsMsa => "msa",
            Self::MipsFpu => "mips_fpu",
            Self::MipsDsp => "mips_dsp",
            Self::Mips16 => "mips16",
            Self::MicroMips => "micromips",
            Self::RvM => "rv_m",
            Self::RvA => "rv_a",
            Self::RvF => "rv_f",
            Self::RvD => "rv_d",
            Self::RvC => "rv_c",
            Self::RvV => "rv_v",
            Self::RvB => "rv_b",
            Self::RvZicsr => "rv_zicsr",
            Self::RvH => "rv_h",
            Self::Altivec => "altivec",
            Self::Vsx => "vsx",
            Self::Spe => "spe",
            Self::Virtualisation => "virtualisation",
            Self::Tee => "tee",
            Self::DebugUnit => "debug_unit",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Returns `true` if this is a SIMD / vector feature.
    #[must_use]
    pub const fn is_simd(&self) -> bool {
        matches!(
            self,
            Self::Mmx | Self::Sse | Self::Sse2 | Self::Sse3 | Self::Ssse3
                | Self::Sse41 | Self::Sse42 | Self::Avx | Self::Avx2 | Self::Avx512F
                | Self::Neon | Self::Sve | Self::Sve2 | Self::MipsMsa | Self::Altivec
                | Self::Vsx | Self::RvV
        )
    }

    /// Returns `true` if this is a crypto acceleration feature.
    #[must_use]
    pub const fn is_crypto(&self) -> bool {
        matches!(
            self,
            Self::AesNi | Self::Pclmulqdq | Self::ShaExt | Self::ArmCrypto
        )
    }

    /// Returns `true` if this feature relates to security / mitigation.
    #[must_use]
    pub const fn is_security(&self) -> bool {
        matches!(self, Self::Sgx | Self::Cet | Self::Mpx | Self::Tee | Self::Pac | Self::Bti)
    }
}

impl std::fmt::Display for FeatureFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FeatureSet
// ─────────────────────────────────────────────────────────────────────────────

/// An ordered, deduplicated set of [`FeatureFlag`]s for a given CPU variant.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureSet {
    flags: HashSet<FeatureFlag>,
    /// Ordered list for deterministic iteration.
    ordered: Vec<FeatureFlag>,
}

impl FeatureSet {
    /// Create an empty feature set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a feature flag.
    pub fn add(&mut self, flag: FeatureFlag) {
        if self.flags.insert(flag.clone()) {
            self.ordered.push(flag);
        }
    }

    /// Remove a feature flag.
    pub fn remove(&mut self, flag: &FeatureFlag) {
        if self.flags.remove(flag) {
            self.ordered.retain(|f| f != flag);
        }
    }

    /// Returns `true` if the feature set contains `flag`.
    #[must_use]
    pub fn has(&self, flag: &FeatureFlag) -> bool {
        self.flags.contains(flag)
    }

    /// Return all SIMD features in this set.
    #[must_use]
    pub fn simd_features(&self) -> Vec<&FeatureFlag> {
        self.ordered.iter().filter(|f| f.is_simd()).collect()
    }

    /// Return all crypto features in this set.
    #[must_use]
    pub fn crypto_features(&self) -> Vec<&FeatureFlag> {
        self.ordered.iter().filter(|f| f.is_crypto()).collect()
    }

    /// Return all security features in this set.
    #[must_use]
    pub fn security_features(&self) -> Vec<&FeatureFlag> {
        self.ordered.iter().filter(|f| f.is_security()).collect()
    }

    /// Return all flags as a slice.
    #[must_use]
    pub fn all(&self) -> &[FeatureFlag] {
        &self.ordered
    }

    /// Number of features.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flags.len()
    }

    /// Returns `true` if the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }

    /// Compute the intersection with another feature set.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for f in &self.ordered {
            if other.has(f) {
                result.add(f.clone());
            }
        }
        result
    }

    /// Compute the union with another feature set.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for f in &other.ordered {
            result.add(f.clone());
        }
        result
    }

    /// Return features present in `self` but not in `other` (difference).
    #[must_use]
    pub fn difference(&self, other: &Self) -> Self {
        let mut result = Self::new();
        for f in &self.ordered {
            if !other.has(f) {
                result.add(f.clone());
            }
        }
        result
    }

    /// Return feature names as a sorted Vec<String>.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.ordered.iter().map(|f| f.name().to_owned()).collect();
        names.sort_unstable();
        names
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchFeatureFlags
// ─────────────────────────────────────────────────────────────────────────────

/// Maps CPU model/variant strings to their supported [`FeatureSet`]s.
///
/// This is a registry of well-known CPU models that can be queried for
/// their feature flags.
#[derive(Debug, Default)]
pub struct ArchFeatureFlags {
    /// Map from CPU model name to its features.
    models: HashMap<String, FeatureSet>,
    /// Base feature set that all models of this architecture share.
    base: FeatureSet,
}

impl ArchFeatureFlags {
    /// Create a new feature flag registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the base feature set shared by all models.
    pub fn set_base(&mut self, features: FeatureSet) {
        self.base = features;
    }

    /// Register a CPU model with its extra (non-base) features.
    pub fn register_model(&mut self, model: impl Into<String>, extra: FeatureSet) {
        self.models.insert(model.into(), extra);
    }

    /// Return the full feature set for `model` (base + model-specific).
    #[must_use]
    pub fn features_for(&self, model: &str) -> FeatureSet {
        let extra = self.models.get(model).cloned().unwrap_or_default();
        self.base.union(&extra)
    }

    /// Return `true` if `model` supports `flag`.
    #[must_use]
    pub fn supports(&self, model: &str, flag: &FeatureFlag) -> bool {
        self.features_for(model).has(flag)
    }

    /// Return all models that support `flag`.
    #[must_use]
    pub fn models_with(&self, flag: &FeatureFlag) -> Vec<String> {
        self.models
            .iter()
            .filter(|(model, _)| self.supports(model, flag))
            .map(|(model, _)| model.clone())
            .collect()
    }

    /// Return all registered model names.
    #[must_use]
    pub fn all_models(&self) -> Vec<&str> {
        self.models.keys().map(String::as_str).collect()
    }

    /// Build the well-known x86-64 feature registry.
    #[must_use]
    pub fn x86_64() -> Self {
        let mut registry = Self::new();

        let mut base = FeatureSet::new();
        for f in [FeatureFlag::Sse, FeatureFlag::Sse2] {
            base.add(f);
        }
        registry.set_base(base);

        let mut haswell = FeatureSet::new();
        for f in [
            FeatureFlag::Sse3, FeatureFlag::Ssse3, FeatureFlag::Sse41, FeatureFlag::Sse42,
            FeatureFlag::Avx, FeatureFlag::Avx2, FeatureFlag::Bmi1, FeatureFlag::Bmi2,
            FeatureFlag::Popcnt, FeatureFlag::Fma3, FeatureFlag::F16c, FeatureFlag::Movbe,
            FeatureFlag::AesNi, FeatureFlag::Rdrand,
        ] {
            haswell.add(f);
        }
        registry.register_model("haswell", haswell);

        let mut skylake = FeatureSet::new();
        for f in [
            FeatureFlag::Sse3, FeatureFlag::Ssse3, FeatureFlag::Sse41, FeatureFlag::Sse42,
            FeatureFlag::Avx, FeatureFlag::Avx2, FeatureFlag::Bmi1, FeatureFlag::Bmi2,
            FeatureFlag::Popcnt, FeatureFlag::Fma3, FeatureFlag::F16c, FeatureFlag::Movbe,
            FeatureFlag::AesNi, FeatureFlag::Rdrand, FeatureFlag::Rdseed, FeatureFlag::Sgx,
        ] {
            skylake.add(f);
        }
        registry.register_model("skylake", skylake);

        let mut icelake = FeatureSet::new();
        for f in [
            FeatureFlag::Avx512F, FeatureFlag::AesNi, FeatureFlag::ShaExt,
            FeatureFlag::Rdrand, FeatureFlag::Rdseed, FeatureFlag::Bmi1,
            FeatureFlag::Bmi2, FeatureFlag::Popcnt, FeatureFlag::Avx,
            FeatureFlag::Avx2, FeatureFlag::Fma3, FeatureFlag::Cet,
        ] {
            icelake.add(f);
        }
        registry.register_model("icelake", icelake);

        registry
    }

    /// Build the well-known ARM64 feature registry.
    #[must_use]
    pub fn arm64() -> Self {
        let mut registry = Self::new();
        let mut base = FeatureSet::new();
        for f in [FeatureFlag::Neon, FeatureFlag::Vfpv4] {
            base.add(f);
        }
        registry.set_base(base);

        let mut cortex_a55 = FeatureSet::new();
        for f in [FeatureFlag::ArmCrc32, FeatureFlag::ArmCrypto] {
            cortex_a55.add(f);
        }
        registry.register_model("cortex-a55", cortex_a55);

        let mut cortex_a710 = FeatureSet::new();
        for f in [
            FeatureFlag::Sve, FeatureFlag::Sve2, FeatureFlag::ArmCrc32,
            FeatureFlag::ArmCrypto, FeatureFlag::ArmDotProd, FeatureFlag::Pac,
            FeatureFlag::Bti, FeatureFlag::Lse,
        ] {
            cortex_a710.add(f);
        }
        registry.register_model("cortex-a710", cortex_a710);

        registry
    }

    /// Build the RISC-V feature registry.
    #[must_use]
    pub fn riscv64() -> Self {
        let mut registry = Self::new();
        let mut base = FeatureSet::new();
        // RISC-V 64-bit baseline: I (base integer) implied.
        base.add(FeatureFlag::RvM);
        base.add(FeatureFlag::RvA);
        base.add(FeatureFlag::RvF);
        base.add(FeatureFlag::RvD);
        base.add(FeatureFlag::RvZicsr);
        registry.set_base(base);

        let mut rv64gc = FeatureSet::new();
        rv64gc.add(FeatureFlag::RvC);
        registry.register_model("rv64gc", rv64gc);

        let mut rv64gcv = FeatureSet::new();
        rv64gcv.add(FeatureFlag::RvC);
        rv64gcv.add(FeatureFlag::RvV);
        registry.register_model("rv64gcv", rv64gcv);

        registry
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_flag_name() {
        assert_eq!(FeatureFlag::Avx512F.name(), "avx512f");
        assert_eq!(FeatureFlag::Neon.name(), "neon");
        assert_eq!(FeatureFlag::Custom("fooext".into()).name(), "fooext");
    }

    #[test]
    fn test_feature_flag_is_simd() {
        assert!(FeatureFlag::Avx2.is_simd());
        assert!(FeatureFlag::Neon.is_simd());
        assert!(!FeatureFlag::AesNi.is_simd());
    }

    #[test]
    fn test_feature_flag_is_crypto() {
        assert!(FeatureFlag::AesNi.is_crypto());
        assert!(!FeatureFlag::Avx.is_crypto());
    }

    #[test]
    fn test_feature_flag_is_security() {
        assert!(FeatureFlag::Cet.is_security());
        assert!(FeatureFlag::Pac.is_security());
        assert!(!FeatureFlag::Avx.is_security());
    }

    #[test]
    fn test_feature_set_add_dedup() {
        let mut fs = FeatureSet::new();
        fs.add(FeatureFlag::Avx);
        fs.add(FeatureFlag::Avx);
        assert_eq!(fs.len(), 1);
    }

    #[test]
    fn test_feature_set_has() {
        let mut fs = FeatureSet::new();
        fs.add(FeatureFlag::Sse2);
        assert!(fs.has(&FeatureFlag::Sse2));
        assert!(!fs.has(&FeatureFlag::Avx));
    }

    #[test]
    fn test_feature_set_remove() {
        let mut fs = FeatureSet::new();
        fs.add(FeatureFlag::Neon);
        fs.remove(&FeatureFlag::Neon);
        assert!(!fs.has(&FeatureFlag::Neon));
        assert!(fs.is_empty());
    }

    #[test]
    fn test_feature_set_simd_subset() {
        let mut fs = FeatureSet::new();
        fs.add(FeatureFlag::Avx);
        fs.add(FeatureFlag::AesNi);
        assert_eq!(fs.simd_features().len(), 1);
    }

    #[test]
    fn test_feature_set_intersection() {
        let mut a = FeatureSet::new();
        a.add(FeatureFlag::Sse);
        a.add(FeatureFlag::Avx);
        let mut b = FeatureSet::new();
        b.add(FeatureFlag::Avx);
        b.add(FeatureFlag::Neon);
        let inter = a.intersection(&b);
        assert_eq!(inter.len(), 1);
        assert!(inter.has(&FeatureFlag::Avx));
    }

    #[test]
    fn test_feature_set_union() {
        let mut a = FeatureSet::new();
        a.add(FeatureFlag::Sse);
        let mut b = FeatureSet::new();
        b.add(FeatureFlag::Avx);
        let u = a.union(&b);
        assert_eq!(u.len(), 2);
    }

    #[test]
    fn test_feature_set_difference() {
        let mut a = FeatureSet::new();
        a.add(FeatureFlag::Sse);
        a.add(FeatureFlag::Avx);
        let mut b = FeatureSet::new();
        b.add(FeatureFlag::Avx);
        let diff = a.difference(&b);
        assert_eq!(diff.len(), 1);
        assert!(diff.has(&FeatureFlag::Sse));
    }

    #[test]
    fn test_arch_feature_flags_x86_64_haswell() {
        let reg = ArchFeatureFlags::x86_64();
        assert!(reg.supports("haswell", &FeatureFlag::Avx2));
        assert!(reg.supports("haswell", &FeatureFlag::Sse));  // from base
        assert!(!reg.supports("haswell", &FeatureFlag::Neon));
    }

    #[test]
    fn test_arch_feature_flags_skylake() {
        let reg = ArchFeatureFlags::x86_64();
        assert!(reg.supports("skylake", &FeatureFlag::Sgx));
        assert!(!reg.supports("skylake", &FeatureFlag::Avx512F));
    }

    #[test]
    fn test_arch_feature_flags_arm64() {
        let reg = ArchFeatureFlags::arm64();
        assert!(reg.supports("cortex-a55", &FeatureFlag::Neon));
        assert!(reg.supports("cortex-a55", &FeatureFlag::ArmCrc32));
        assert!(reg.supports("cortex-a710", &FeatureFlag::Sve2));
        assert!(reg.supports("cortex-a710", &FeatureFlag::Pac));
    }

    #[test]
    fn test_arch_feature_flags_riscv() {
        let reg = ArchFeatureFlags::riscv64();
        assert!(reg.supports("rv64gcv", &FeatureFlag::RvV));
        assert!(reg.supports("rv64gcv", &FeatureFlag::RvC));
        assert!(!reg.supports("rv64gc", &FeatureFlag::RvV));
    }

    #[test]
    fn test_models_with_flag() {
        let reg = ArchFeatureFlags::x86_64();
        let models = reg.models_with(&FeatureFlag::Avx512F);
        assert!(models.contains(&"icelake".to_string()));
        assert!(!models.contains(&"haswell".to_string()));
    }

    #[test]
    fn test_feature_set_names_sorted() {
        let mut fs = FeatureSet::new();
        fs.add(FeatureFlag::Sse2);
        fs.add(FeatureFlag::Avx);
        let names = fs.names();
        assert!(names.windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn test_unknown_model_returns_base_only() {
        let reg = ArchFeatureFlags::x86_64();
        let feats = reg.features_for("unknown_cpu");
        assert!(feats.has(&FeatureFlag::Sse));
        assert!(feats.has(&FeatureFlag::Sse2));
        assert!(!feats.has(&FeatureFlag::Avx));
    }
}
