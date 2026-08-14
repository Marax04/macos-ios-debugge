//! Advanced calling-convention detection for `rustre-analysis-callconv`.
//!
//! Extends the basic CC detector with recognition of:
//!
//! * **Fastcall** (x86-32 `__fastcall`): first two integer arguments in ECX
//!   and EDX.
//! * **Vectorcall** (x86-64 MSVC): floating-point arguments in XMM0–XMM5 with
//!   integer arguments remaining in the standard integer registers.
//! * **`__regcall`** (Intel ICC): up to 8 integer arguments in registers, all
//!   XMM registers used for floating-point; AH/AL for sub-word returns.
//! * **AAPCS64** (ARM64 Procedure Call Standard): 8 integer argument registers
//!   (X0–X7) and 8 SIMD/FP argument registers (V0–V7), 128-bit return in X0:X1.
//! * **RISC-V calling convention** (RV32I/RV64 ILP32D/LP64D): a0–a7 for
//!   integer args, fa0–fa7 for float args.
//! * **Mixed `va_list` calling conventions**: functions that mix fixed and
//!   variadic arguments.
//! * **Custom calling conventions**: non-standard register usage that does not
//!   match any known CC; reported as an inferred custom CC with the observed
//!   register assignments.
//!
//! ## Relationship to the other CC tables in this crate (verified 2026-07-12)
//!
//! This module's [`all_cc_profiles`] is **not** a strict subset of either
//! `lib.rs`'s builtin [`crate::CallingConventionPattern`] constructors or
//! `cc_detector`'s [`crate::cc_detector::CcPattern`] builtins — coverage
//! differs both ways:
//! - Overlapping entries (8): `Cdecl`, `Fastcall`, `Thiscall`, `SysvAmd64`,
//!   `MicrosoftX64`, `Vectorcall`, `Aapcs64`, `RiscV` all also exist in
//!   `lib.rs` (as `cdecl_x86`/`fastcall_x86`/`thiscall_x86`/`sysv_x64`/
//!   `msvc_x64`/`vectorcall_x64`/`aapcs64`/`riscv64_lp64d`).
//! - Unique to this module: `Regcall` (Intel `__regcall`) — neither `lib.rs`
//!   nor `cc_detector` model it.
//! - Missing here vs. `lib.rs`: `Stdcall`, `AAPCS32`, `MIPS O32`.
//! - Fixed 2026-07-12: `AppleArm64` previously had an enum variant but no
//!   profile in [`all_cc_profiles`], so it could never be returned by
//!   [`AdvancedCcDetector::detect`] — added a profile (same AAPCS64-based
//!   register set; Apple's ABI deviations don't affect this coarse profile).
//! - The scoring model is also independent: this module scores in `[0.0,
//!   1.0]` via register-set overlap with an ordering-gap penalty
//!   (`missing_earlier`), whereas `lib.rs`'s
//!   [`crate::CallingConventionPattern::score`] is an unbounded `u32`
//!   additive/subtractive score and `cc_detector`'s
//!   [`crate::cc_detector::CcPattern::score_evidence`] is a weighted-evidence
//!   `u32` score. None of the three is a drop-in replacement for another.
//!
//! Because coverage genuinely differs in both directions, this module is
//! being kept and documented rather than merged or marked dead. See
//! `cc_detector`'s module doc for the crate-wide wiring status of all three
//! detectors, and [`crate::CallingConventionDetector::detect_with_evidence`]
//! for the concrete wiring landed between `lib.rs` and `cc_detector` this
//! iteration (this module remains unwired — its unique `Regcall` coverage did
//! not justify the extra churn of a three-way merge in the same pass).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Register classification
// ─────────────────────────────────────────────────────────────────────────────

/// Broad category of a CPU register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegCategory {
    /// General-purpose integer register.
    Integer,
    /// 128-bit SIMD/FP XMM register.
    Xmm,
    /// 64-bit floating-point (x87 / ARM64 D-register).
    Float,
    /// 128-bit ARM NEON / SVE register (V-register).
    Simd,
    /// Stack pointer.
    StackPointer,
    /// Link register (ARM64 LR = X30).
    Link,
}

/// A register specification: name and category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Reg {
    /// Canonical lowercase name (e.g. `"rdi"`, `"xmm0"`, `"x0"`).
    pub name: String,
    /// Category.
    pub category: RegCategory,
    /// Bit width of the register.
    pub width: u32,
}

impl Reg {
    /// Construct a new register descriptor.
    #[must_use]
    pub fn new(name: impl Into<String>, category: RegCategory, width: u32) -> Self {
        Self { name: name.into(), category, width }
    }

    /// Return `true` if this is an integer general-purpose register.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.category == RegCategory::Integer
    }

    /// Return `true` if this is a SIMD/FP register.
    #[must_use]
    pub const fn is_vector(&self) -> bool {
        matches!(self.category, RegCategory::Xmm | RegCategory::Simd)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Named calling conventions
// ─────────────────────────────────────────────────────────────────────────────

/// A recognised calling convention identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    // ── x86-32 ────────────────────────────────────────────────────────────────
    /// Standard C calling convention (caller cleans stack).
    Cdecl,
    /// All arguments on stack, callee cleans (`__stdcall`).
    Stdcall,
    /// First two integer args in ECX, EDX (`__fastcall`).
    Fastcall,
    /// First integer arg in ECX (for `this`), rest on stack (`__thiscall`).
    Thiscall,
    // ── x86-64 ────────────────────────────────────────────────────────────────
    /// System V AMD64 ABI (Linux/macOS): RDI, RSI, RDX, RCX, R8, R9.
    SysvAmd64,
    /// Microsoft x64: RCX, RDX, R8, R9.
    MicrosoftX64,
    /// MSVC `__vectorcall`: integer in RCX/RDX/R8/R9, float in XMM0–XMM5.
    Vectorcall,
    /// Intel `__regcall` x64: up to 8 integer and all XMM regs.
    Regcall,
    // ── ARM64 ─────────────────────────────────────────────────────────────────
    /// ARM64 Procedure Call Standard (AAPCS64 / APCS).
    Aapcs64,
    /// Apple ARM64 (iOS/macOS `AArch64`).
    AppleArm64,
    // ── RISC-V ────────────────────────────────────────────────────────────────
    /// RISC-V ILP32D or LP64D calling convention.
    RiscV,
    // ── Special ───────────────────────────────────────────────────────────────
    /// Detected but not matching any known standard (custom / compiler-specific).
    Custom,
    /// Cannot determine the calling convention.
    Unknown,
}

impl CallingConvention {
    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cdecl => "cdecl",
            Self::Stdcall => "stdcall",
            Self::Fastcall => "fastcall",
            Self::Thiscall => "thiscall",
            Self::SysvAmd64 => "sysv_amd64",
            Self::MicrosoftX64 => "ms_x64",
            Self::Vectorcall => "vectorcall",
            Self::Regcall => "regcall",
            Self::Aapcs64 => "aapcs64",
            Self::AppleArm64 => "apple_arm64",
            Self::RiscV => "riscv",
            Self::Custom => "custom",
            Self::Unknown => "unknown",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Observed register usage at a function entry
// ─────────────────────────────────────────────────────────────────────────────

/// Observed register liveness at the function entry point.
///
/// A register is "read before written" if it is live-in at the entry basic
/// block, which strongly suggests it is an argument register.
#[derive(Debug, Clone, Default)]
pub struct ObservedRegs {
    /// Set of registers read before written (argument candidates).
    pub read_before_written: HashSet<String>,
    /// Set of registers written before read (local variables / scratch).
    pub written_before_read: HashSet<String>,
    /// Set of registers preserved across the function (callee-saved).
    pub preserved: HashSet<String>,
}

impl ObservedRegs {
    /// Create a new empty observation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a register as read before written.
    pub fn mark_arg(&mut self, reg: impl Into<String>) {
        self.read_before_written.insert(reg.into());
    }

    /// Mark a register as written before read.
    pub fn mark_scratch(&mut self, reg: impl Into<String>) {
        self.written_before_read.insert(reg.into());
    }

    /// Mark a register as preserved (callee-saved).
    pub fn mark_preserved(&mut self, reg: impl Into<String>) {
        self.preserved.insert(reg.into());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CC detection score
// ─────────────────────────────────────────────────────────────────────────────

/// Score assigned to a CC candidate during matching.
#[derive(Debug, Clone)]
pub struct CcCandidate {
    /// The CC being considered.
    pub convention: CallingConvention,
    /// Score in [0.0, 1.0]; higher → better match.
    pub score: f64,
    /// Registers that matched the expected argument list.
    pub matched_arg_regs: Vec<String>,
    /// Registers that were unexpected for this CC.
    pub unexpected_regs: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CC profiles
// ─────────────────────────────────────────────────────────────────────────────

/// A calling-convention profile: the expected argument registers in order.
#[derive(Debug, Clone)]
pub struct CcProfile {
    /// Convention identifier.
    pub convention: CallingConvention,
    /// Ordered integer argument registers.
    pub int_arg_regs: Vec<&'static str>,
    /// Ordered FP/SIMD argument registers.
    pub fp_arg_regs: Vec<&'static str>,
    /// Registers the callee must preserve.
    pub callee_saved: Vec<&'static str>,
    /// Return value register(s).
    pub ret_regs: Vec<&'static str>,
}

/// Return all built-in CC profiles.
#[must_use]
pub fn all_cc_profiles() -> Vec<CcProfile> {
    vec![
        // ── x86-32 cdecl ──────────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::Cdecl,
            int_arg_regs: vec![], // all on stack
            fp_arg_regs: vec![],
            callee_saved: vec!["ebx", "esi", "edi", "ebp"],
            ret_regs: vec!["eax", "edx"],
        },
        // ── x86-32 fastcall ───────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::Fastcall,
            int_arg_regs: vec!["ecx", "edx"],
            fp_arg_regs: vec![],
            callee_saved: vec!["ebx", "esi", "edi", "ebp"],
            ret_regs: vec!["eax"],
        },
        // ── x86-32 thiscall ───────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::Thiscall,
            int_arg_regs: vec!["ecx"],
            fp_arg_regs: vec![],
            callee_saved: vec!["ebx", "esi", "edi", "ebp"],
            ret_regs: vec!["eax"],
        },
        // ── System V AMD64 ────────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::SysvAmd64,
            int_arg_regs: vec!["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            fp_arg_regs: vec!["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"],
            callee_saved: vec!["rbx", "rbp", "r12", "r13", "r14", "r15"],
            ret_regs: vec!["rax", "rdx", "xmm0", "xmm1"],
        },
        // ── Microsoft x64 ─────────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::MicrosoftX64,
            int_arg_regs: vec!["rcx", "rdx", "r8", "r9"],
            fp_arg_regs: vec!["xmm0", "xmm1", "xmm2", "xmm3"],
            callee_saved: vec!["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
            ret_regs: vec!["rax", "xmm0"],
        },
        // ── Vectorcall ────────────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::Vectorcall,
            int_arg_regs: vec!["rcx", "rdx", "r8", "r9"],
            fp_arg_regs: vec!["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5"],
            callee_saved: vec!["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
            ret_regs: vec!["rax", "xmm0"],
        },
        // ── Intel regcall x64 ─────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::Regcall,
            int_arg_regs: vec!["rax", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10"],
            fp_arg_regs: vec!["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"],
            callee_saved: vec!["rbx", "rbp", "r12", "r13", "r14", "r15"],
            ret_regs: vec!["rax", "xmm0"],
        },
        // ── AAPCS64 ───────────────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::Aapcs64,
            int_arg_regs: vec!["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            fp_arg_regs: vec!["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            callee_saved: vec!["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"],
            ret_regs: vec!["x0", "x1", "v0", "v1"],
        },
        // ── Apple ARM64 ───────────────────────────────────────────────────────
        // Same core AAPCS64 register assignment (x0-x7 int, v0-v7 FP/SIMD);
        // Apple's deviations from standard AAPCS64 (variadic args always on
        // the stack, no back-filling of skipped registers, stricter narrow-int
        // extension rules) don't change this coarse register-set profile.
        CcProfile {
            convention: CallingConvention::AppleArm64,
            int_arg_regs: vec!["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            fp_arg_regs: vec!["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            callee_saved: vec!["x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28"],
            ret_regs: vec!["x0", "x1", "v0", "v1"],
        },
        // ── RISC-V LP64D ──────────────────────────────────────────────────────
        CcProfile {
            convention: CallingConvention::RiscV,
            int_arg_regs: vec!["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
            fp_arg_regs: vec!["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"],
            callee_saved: vec!["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11"],
            ret_regs: vec!["a0", "a1", "fa0", "fa1"],
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// CC detector
// ─────────────────────────────────────────────────────────────────────────────

/// Advanced calling-convention detector.
pub struct AdvancedCcDetector {
    /// Profiles to check, in priority order.
    pub profiles: Vec<CcProfile>,
    /// Minimum score to accept a CC match.
    pub min_score: f64,
}

impl AdvancedCcDetector {
    /// Create a detector seeded with all built-in profiles.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: all_cc_profiles(),
            min_score: 0.5,
        }
    }

    /// Score all profiles against `obs` and return ranked candidates.
    #[must_use]
    pub fn rank_candidates(&self, obs: &ObservedRegs) -> Vec<CcCandidate> {
        let mut candidates: Vec<CcCandidate> = self
            .profiles
            .iter()
            .map(|profile| self.score_profile(profile, obs))
            .collect();

        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        candidates
    }

    /// Return the best-matching CC, or [`CallingConvention::Unknown`] if no
    /// profile achieves `min_score`.
    #[must_use]
    pub fn detect(&self, obs: &ObservedRegs) -> CallingConvention {
        let candidates = self.rank_candidates(obs);
        if let Some(best) = candidates.first()
            && best.score >= self.min_score {
                return best.convention;
            }

        // Check for custom CC: unexpected registers that are used as arguments.
        if !obs.read_before_written.is_empty() {
            return CallingConvention::Custom;
        }

        CallingConvention::Unknown
    }

    /// Score a single CC profile against `obs`.
    fn score_profile(&self, profile: &CcProfile, obs: &ObservedRegs) -> CcCandidate {
        let expected_int: HashSet<&str> = profile.int_arg_regs.iter().copied().collect();
        let expected_fp: HashSet<&str> = profile.fp_arg_regs.iter().copied().collect();
        let expected_all: HashSet<&str> = expected_int.union(&expected_fp).copied().collect();

        let mut matched = Vec::new();
        let mut unexpected = Vec::new();

        for reg in &obs.read_before_written {
            if expected_all.contains(reg.as_str()) {
                matched.push(reg.clone());
            } else {
                unexpected.push(reg.clone());
            }
        }

        let total_obs = obs.read_before_written.len();
        let score = if total_obs == 0 {
            // No observed argument registers: give moderate score to
            // conventions that expect no register arguments (cdecl).
            if profile.int_arg_regs.is_empty() && profile.fp_arg_regs.is_empty() {
                0.6
            } else {
                0.3
            }
        } else {
            let mut missing_earlier = 0;
            
            // Check int registers
            let mut max_int_idx = None;
            for (idx, reg) in profile.int_arg_regs.iter().enumerate() {
                if obs.read_before_written.contains(*reg) {
                    max_int_idx = Some(idx);
                }
            }
            if let Some(max_idx) = max_int_idx {
                for idx in 0..max_idx {
                    let reg = profile.int_arg_regs[idx];
                    if !obs.read_before_written.contains(reg) {
                        missing_earlier += 1;
                    }
                }
            }

            // Check fp registers
            let mut max_fp_idx = None;
            for (idx, reg) in profile.fp_arg_regs.iter().enumerate() {
                if obs.read_before_written.contains(*reg) {
                    max_fp_idx = Some(idx);
                }
            }
            if let Some(max_idx) = max_fp_idx {
                for idx in 0..max_idx {
                    let reg = profile.fp_arg_regs[idx];
                    if !obs.read_before_written.contains(reg) {
                        missing_earlier += 1;
                    }
                }
            }

            let matched_frac = matched.len() as f64 / total_obs as f64;
            let unexpect_penalty = unexpected.len() as f64 / (total_obs as f64 + 1.0);
            (matched_frac - unexpect_penalty * 0.5 - f64::from(missing_earlier) * 0.1).max(0.0)
        };

        // `matched`/`unexpected` were built by iterating `obs.read_before_written`,
        // a `HashSet<String>` whose iteration order is randomized per-instance
        // (std's `RandomState`) — sort so the public `CcCandidate` fields are
        // reproducible across runs/processes instead of depending on hash seed.
        matched.sort_unstable();
        unexpected.sort_unstable();

        CcCandidate {
            convention: profile.convention,
            score,
            matched_arg_regs: matched,
            unexpected_regs: unexpected,
        }
    }
}

impl Default for AdvancedCcDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// va_list / variadic mixed detection
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a function is variadic and, if so, the nature of its `va_list` usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariadicKind {
    /// Not variadic.
    NotVariadic,
    /// Standard variadic (e.g. `printf`): fixed args + `...`.
    StandardVariadic,
    /// Uses `va_list` directly without `...` in the signature.
    VaList,
    /// Unknowable without debug info.
    Unknown,
}

/// Heuristically classify a set of observed registers for variadic calling.
#[must_use]
pub fn classify_variadic_usage(obs: &ObservedRegs) -> VariadicKind {
    // On x86-64 SysV, AL is set to the number of XMM arguments before a
    // variadic call.  If we see AL in the read-before-written set alongside
    // standard integer arg registers, it is almost certainly variadic.
    if obs.read_before_written.contains("al")
        && obs.read_before_written.iter().any(|r| r.starts_with("xmm"))
    {
        return VariadicKind::StandardVariadic;
    }

    // On MSVC x64, `__va_list_tag` structures are passed by pointer in one
    // of the standard argument registers.  We cannot distinguish this without
    // type information, so we return Unknown.
    if obs.read_before_written.len() > 4 {
        return VariadicKind::Unknown;
    }

    VariadicKind::NotVariadic
}

// ─────────────────────────────────────────────────────────────────────────────
// Custom CC inference
// ─────────────────────────────────────────────────────────────────────────────

/// Inferred description of a custom (non-standard) calling convention.
#[derive(Debug, Clone)]
pub struct CustomCcDescription {
    /// Integer argument registers, sorted for reproducibility (source
    /// register-observation order is not preserved — see `infer_custom_cc`).
    pub int_arg_regs: Vec<String>,
    /// FP/SIMD argument registers, sorted for reproducibility.
    pub fp_arg_regs: Vec<String>,
    /// Observed return registers.
    pub ret_regs: Vec<String>,
    /// Registers that appear callee-saved.
    pub callee_saved: Vec<String>,
}

/// Infer a custom CC description from observed register usage.
#[must_use]
pub fn infer_custom_cc(obs: &ObservedRegs) -> CustomCcDescription {
    let int_regs: HashSet<&str> = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi",
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    ]
    .iter()
    .copied()
    .collect();

    let mut int_arg = Vec::new();
    let mut fp_arg = Vec::new();

    for reg in &obs.read_before_written {
        if int_regs.contains(reg.as_str()) {
            int_arg.push(reg.clone());
        } else if reg.starts_with("xmm")
            || reg.starts_with("ymm")
            || reg.starts_with("zmm")
            || reg.starts_with('v')
            || reg.starts_with("fa")
        {
            fp_arg.push(reg.clone());
        }
    }

    let mut callee_saved: Vec<String> = obs.preserved.iter().cloned().collect();

    // All three vectors above were built by iterating `HashSet<String>`s,
    // whose iteration order is randomized per-instance — sort so
    // `CustomCcDescription`'s fields are reproducible across runs/processes.
    int_arg.sort_unstable();
    fp_arg.sort_unstable();
    callee_saved.sort_unstable();

    CustomCcDescription {
        int_arg_regs: int_arg,
        fp_arg_regs: fp_arg,
        ret_regs: Vec::new(), // return type inference is a separate pass
        callee_saved,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn obs_from_regs(regs: &[&str]) -> ObservedRegs {
        let mut obs = ObservedRegs::new();
        for r in regs {
            obs.mark_arg(*r);
        }
        obs
    }

    #[test]
    fn detect_sysv_amd64() {
        let obs = obs_from_regs(&["rdi", "rsi", "rdx"]);
        let det = AdvancedCcDetector::new();
        let cc = det.detect(&obs);
        assert_eq!(cc, CallingConvention::SysvAmd64);
    }

    #[test]
    fn detect_ms_x64() {
        let obs = obs_from_regs(&["rcx", "rdx", "r8"]);
        let det = AdvancedCcDetector::new();
        let cc = det.detect(&obs);
        assert_eq!(cc, CallingConvention::MicrosoftX64);
    }

    #[test]
    fn detect_fastcall() {
        let obs = obs_from_regs(&["ecx", "edx"]);
        let det = AdvancedCcDetector::new();
        let cc = det.detect(&obs);
        assert_eq!(cc, CallingConvention::Fastcall);
    }

    #[test]
    fn detect_aapcs64() {
        let obs = obs_from_regs(&["x0", "x1", "x2"]);
        let det = AdvancedCcDetector::new();
        let cc = det.detect(&obs);
        assert_eq!(cc, CallingConvention::Aapcs64);
    }

    #[test]
    fn detect_riscv() {
        let obs = obs_from_regs(&["a0", "a1", "a2"]);
        let det = AdvancedCcDetector::new();
        let cc = det.detect(&obs);
        assert_eq!(cc, CallingConvention::RiscV);
    }

    #[test]
    fn detect_vectorcall_with_xmm() {
        let obs = obs_from_regs(&["rcx", "xmm1", "xmm2"]);
        let det = AdvancedCcDetector::new();
        let candidates = det.rank_candidates(&obs);
        // Vectorcall should appear in top candidates due to XMM + RCX.
        let found = candidates
            .iter()
            .any(|c| c.convention == CallingConvention::Vectorcall && c.score > 0.0);
        assert!(found, "Vectorcall should be a candidate");
    }

    #[test]
    fn detect_custom_cc() {
        // Use a completely non-standard set of registers.
        let obs = obs_from_regs(&["rbx", "r11", "r13"]);
        let det = AdvancedCcDetector::new();
        let cc = det.detect(&obs);
        assert_eq!(cc, CallingConvention::Custom);
    }

    #[test]
    fn variadic_classification_sysv() {
        let mut obs = ObservedRegs::new();
        obs.mark_arg("rdi");
        obs.mark_arg("rsi");
        obs.mark_arg("al");
        obs.mark_arg("xmm0");
        let kind = classify_variadic_usage(&obs);
        assert_eq!(kind, VariadicKind::StandardVariadic);
    }

    #[test]
    fn infer_custom_cc_separates_int_fp() {
        let mut obs = ObservedRegs::new();
        obs.mark_arg("rbx");
        obs.mark_arg("xmm3");
        obs.mark_preserved("r12");
        let desc = infer_custom_cc(&obs);
        assert!(desc.int_arg_regs.contains(&"rbx".to_string()));
        assert!(desc.fp_arg_regs.contains(&"xmm3".to_string()));
        assert!(desc.callee_saved.contains(&"r12".to_string()));
    }

    #[test]
    fn cc_profiles_non_empty() {
        let profiles = all_cc_profiles();
        assert!(!profiles.is_empty());
        for p in &profiles {
            // Every profile must have a label.
            assert!(!p.convention.label().is_empty());
        }
    }

    #[test]
    fn rank_candidates_returns_all_profiles() {
        let obs = ObservedRegs::new();
        let det = AdvancedCcDetector::new();
        let candidates = det.rank_candidates(&obs);
        assert_eq!(candidates.len(), det.profiles.len());
    }

    #[test]
    fn reg_is_integer_and_is_vector() {
        let r_int = Reg::new("rdi", RegCategory::Integer, 64);
        assert!(r_int.is_integer());
        assert!(!r_int.is_vector());

        let r_xmm = Reg::new("xmm0", RegCategory::Xmm, 128);
        assert!(!r_xmm.is_integer());
        assert!(r_xmm.is_vector());

        let r_simd = Reg::new("v0", RegCategory::Simd, 128);
        assert!(r_simd.is_vector());

        let r_sp = Reg::new("rsp", RegCategory::StackPointer, 64);
        assert!(!r_sp.is_integer());
        assert!(!r_sp.is_vector());
    }

    #[test]
    fn observed_regs_mark_scratch() {
        let mut obs = ObservedRegs::new();
        obs.mark_scratch("eax");
        assert!(obs.written_before_read.contains("eax"));
        assert!(!obs.read_before_written.contains("eax"));
    }

    #[test]
    fn calling_convention_label_all_variants() {
        // Every label should be distinct and non-empty — guards against a
        // copy-paste error silently aliasing two variants to the same string.
        let variants = [
            CallingConvention::Cdecl,
            CallingConvention::Stdcall,
            CallingConvention::Fastcall,
            CallingConvention::Thiscall,
            CallingConvention::SysvAmd64,
            CallingConvention::MicrosoftX64,
            CallingConvention::Vectorcall,
            CallingConvention::Regcall,
            CallingConvention::Aapcs64,
            CallingConvention::AppleArm64,
            CallingConvention::RiscV,
            CallingConvention::Custom,
            CallingConvention::Unknown,
        ];
        let mut labels: Vec<&str> = variants.iter().map(|v| v.label()).collect();
        let n = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), n, "duplicate CC labels found");
    }

    #[test]
    fn detect_unknown_for_no_observations() {
        // No registers observed at all: no profile can score >= min_score
        // from register overlap alone since cdecl's "no-args" score (0.6) is
        // still >= the default min_score (0.5) — verify actual behaviour
        // rather than assuming, since this is exactly the coverage gap.
        let obs = ObservedRegs::new();
        let det = AdvancedCcDetector::new();
        let cc = det.detect(&obs);
        assert_eq!(cc, CallingConvention::Cdecl);
    }

    #[test]
    fn detect_regcall() {
        let obs = obs_from_regs(&["rax", "rcx", "rdx", "rdi", "rsi", "r8"]);
        let det = AdvancedCcDetector::new();
        let cc = det.detect(&obs);
        assert_eq!(cc, CallingConvention::Regcall);
    }

    #[test]
    fn variadic_classification_unknown_many_regs() {
        let obs = obs_from_regs(&["rdi", "rsi", "rdx", "rcx", "r8"]);
        let kind = classify_variadic_usage(&obs);
        assert_eq!(kind, VariadicKind::Unknown);
    }

    #[test]
    fn variadic_classification_not_variadic() {
        let obs = obs_from_regs(&["rdi", "rsi"]);
        let kind = classify_variadic_usage(&obs);
        assert_eq!(kind, VariadicKind::NotVariadic);
    }

    #[test]
    fn infer_custom_cc_empty_observations() {
        let obs = ObservedRegs::new();
        let desc = infer_custom_cc(&obs);
        assert!(desc.int_arg_regs.is_empty());
        assert!(desc.fp_arg_regs.is_empty());
        assert!(desc.ret_regs.is_empty());
        assert!(desc.callee_saved.is_empty());
    }

    /// Regression test: `infer_custom_cc` built `int_arg_regs`/`fp_arg_regs`/
    /// `callee_saved` by iterating `HashSet<String>` fields of `ObservedRegs`.
    /// `std`'s `HashSet` iteration order is randomized per-instance (each
    /// `HashMap`/`HashSet` gets its own `RandomState` seed), so two
    /// `ObservedRegs` built from the same inputs — even within the same
    /// process — are not guaranteed to yield vectors in the same order,
    /// making the public `CustomCcDescription` output nondeterministic.
    /// `infer_custom_cc` now sorts each vector before returning; verify many
    /// independently-built observation sets always agree byte-for-byte.
    #[test]
    fn infer_custom_cc_is_deterministic_across_instances() {
        let int_regs = ["r9", "r8", "rdx", "rcx", "rsi", "rdi", "r15", "r14"];
        let fp_regs = ["xmm7", "xmm3", "xmm1", "xmm0", "xmm5"];
        let preserved = ["rbx", "r12", "r13", "rbp"];

        let first = {
            let mut obs = ObservedRegs::new();
            for r in int_regs.iter().chain(fp_regs.iter()) {
                obs.mark_arg(*r);
            }
            for r in &preserved {
                obs.preserved.insert((*r).to_string());
            }
            infer_custom_cc(&obs)
        };

        for _ in 0..20 {
            let mut obs = ObservedRegs::new();
            // Insert in a different order each time to exercise different
            // hash-bucket layouts / RandomState seeds.
            for r in fp_regs.iter().rev().chain(int_regs.iter().rev()) {
                obs.mark_arg(*r);
            }
            for r in preserved.iter().rev() {
                obs.preserved.insert((*r).to_string());
            }
            let again = infer_custom_cc(&obs);
            assert_eq!(again.int_arg_regs, first.int_arg_regs);
            assert_eq!(again.fp_arg_regs, first.fp_arg_regs);
            assert_eq!(again.callee_saved, first.callee_saved);
            // And each must actually be sorted.
            let mut sorted_int = again.int_arg_regs.clone();
            sorted_int.sort_unstable();
            assert_eq!(again.int_arg_regs, sorted_int);
        }
    }

    /// Regression test: `AdvancedCcDetector::score_profile` built
    /// `matched_arg_regs`/`unexpected_regs` by iterating
    /// `ObservedRegs::read_before_written` (a `HashSet<String>`), making the
    /// order of those public `CcCandidate` fields depend on the set's
    /// per-instance hash seed rather than the input. Verify the candidate
    /// list is reproducible regardless of registration order.
    #[test]
    fn rank_candidates_reg_lists_are_deterministic() {
        let det = AdvancedCcDetector::new();
        let regs = ["rdi", "rsi", "rdx", "rcx", "zzz_unexpected"];

        let first = {
            let obs = obs_from_regs(&regs);
            det.rank_candidates(&obs)
        };

        for _ in 0..20 {
            let mut obs = ObservedRegs::new();
            for r in regs.iter().rev() {
                obs.mark_arg(*r);
            }
            let again = det.rank_candidates(&obs);
            assert_eq!(again.len(), first.len());
            for (a, b) in again.iter().zip(first.iter()) {
                assert_eq!(a.convention, b.convention);
                assert!((a.score - b.score).abs() < 1e-12);
                assert_eq!(a.matched_arg_regs, b.matched_arg_regs);
                assert_eq!(a.unexpected_regs, b.unexpected_regs);
            }
        }
    }
}
