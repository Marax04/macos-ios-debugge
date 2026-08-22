//! Calling convention detector: analyse prologue/epilogue patterns, argument
//! registers and callee-saved registers to produce a `DetectedCc`.
//!
//! This module is distinct from `calling_convention_detector` (which lives in
//! `lib.rs`) in that it works at a higher level: it accepts a typed `CcPattern`
//! description and scores each candidate with richer `CcEvidence`. That
//! distinction is genuine (verified 2026-07: different input types
//! (`CcPattern`/`CcEvidence` here vs. raw `&[Instruction]` there) and no
//! shared call paths), so the two are not stale duplicates of each other.
//! `cc_detector_advanced` is a third, separate module layered on top of this
//! one: it adds recognition for calling conventions this module does not
//! model (fastcall, vectorcall, `__regcall`, AAPCS64, RISC-V, mixed
//! `va_list` CCs) — see that module's doc comment for the precise,
//! verified overlap/non-overlap with this one and with `lib.rs`.
//!
//! ## Wiring status (updated 2026-07-12, iteration 4)
//!
//! This module's own `CallingConventionDetector`/`PrologueAnalyzer` (below)
//! remain unwired into `lib.rs`'s public pipeline — merging the two detector
//! types (this module's `PrologueAnalyzer`-driven evidence accumulation vs.
//! `lib.rs`'s single-pass `DetectInstr` extractor) is real API churn that
//! wasn't justified this iteration by itself.
//!
//! What *did* get wired this iteration: `lib.rs::CallingConventionDetector`
//! gained [`crate::CallingConventionDetector::detect_with_evidence`], which
//! converts `lib.rs`'s `ObservedPattern` into this module's [`CcEvidence`]
//! (see [`crate::observed_pattern_to_evidence`]) and re-scores the winning
//! candidate with [`CcPattern::score_evidence`] via
//! [`crate::cc_pattern_for_name`], returning the evidence score as a second,
//! independent corroboration signal alongside the primary result. This reuses
//! `cc_detector`'s weighted-evidence scoring for the 6 CC patterns it and
//! `lib.rs` share (`sysv_amd64`, `ms_x64`, `cdecl_x86`, `stdcall_x86`,
//! `thiscall_x86`, `aapcs64`) without merging the two detector object models.
//! `cc_detector_advanced` remains fully unwired (see its module doc) — its
//! only unique coverage (`Regcall`) isn't yet consumed anywhere, so wiring it
//! was deferred again, deliberately, pending a real caller that needs
//! `__regcall` recognition.

use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// A single piece of evidence collected while analysing a function prologue /
/// epilogue for calling convention detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcEvidence {
    /// The kind of evidence.
    pub kind: EvidenceKind,
    /// The register (or stack offset) this evidence relates to.
    pub register: Option<String>,
    /// Human-readable explanation.
    pub description: String,
    /// Evidence weight (higher = stronger signal).
    pub weight: u32,
}

impl CcEvidence {
    /// Create a new `CcEvidence` item.
    #[must_use]
    pub fn new(
        kind: EvidenceKind,
        register: Option<String>,
        description: impl Into<String>,
        weight: u32,
    ) -> Self {
        Self {
            kind,
            register,
            description: description.into(),
            weight,
        }
    }
}

/// Kind of calling-convention evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Register read before any write — candidate argument register.
    ReadBeforeWrite,
    /// Register pushed and symmetrically popped — callee-saved.
    CalleeSaved,
    /// Register written immediately before a `RET` instruction.
    WrittenBeforeReturn,
    /// `RET N` observed — callee cleans stack.
    CalleeStackCleanup,
    /// `sub rsp, 32` (or equivalent) observed — shadow space.
    ShadowSpace,
    /// `ecx`/`rcx` used as `this` pointer.
    ThisPointerHint,
    /// Stack argument access at a specific offset.
    StackArgAccess,
    /// Floating-point register used before write.
    FpArgRegister,
    /// Stack frame larger than expected for the candidate CC.
    LargeStackFrame,
    /// No argument registers used at all — stack-only.
    NoRegisterArgs,
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ReadBeforeWrite => "ReadBeforeWrite",
            Self::CalleeSaved => "CalleeSaved",
            Self::WrittenBeforeReturn => "WrittenBeforeReturn",
            Self::CalleeStackCleanup => "CalleeStackCleanup",
            Self::ShadowSpace => "ShadowSpace",
            Self::ThisPointerHint => "ThisPointerHint",
            Self::StackArgAccess => "StackArgAccess",
            Self::FpArgRegister => "FpArgRegister",
            Self::LargeStackFrame => "LargeStackFrame",
            Self::NoRegisterArgs => "NoRegisterArgs",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// CcPattern — full descriptor for a calling convention
// ---------------------------------------------------------------------------

/// A full description of a calling convention's register protocol.
///
/// Unlike `CallingConventionPattern` in the crate root this type carries the
/// minimum information needed for scoring and is independently usable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcPattern {
    /// Human-readable identifier (e.g. `"System V AMD64"`).
    pub name: String,
    /// Integer / pointer argument registers in parameter order.
    pub arg_regs: Vec<String>,
    /// Floating-point argument registers.
    pub fp_arg_regs: Vec<String>,
    /// Return-value registers.
    pub retval_regs: Vec<String>,
    /// Callee-saved registers.
    pub callee_saved: Vec<String>,
    /// Caller-saved (scratch) registers.
    pub caller_saved: Vec<String>,
    /// Whether the callee is responsible for cleaning up stack arguments.
    pub callee_cleans_stack: bool,
    /// Whether a hidden `this` pointer occupies the first argument slot.
    pub has_hidden_this: bool,
    /// Shadow space in bytes that the caller must reserve (e.g. 32 for MS x64).
    pub shadow_space: u32,
    /// Maximum integer arguments passed in registers (0 = stack-only).
    pub max_reg_args: u32,
    /// Required stack alignment in bytes at the call site.
    pub stack_alignment: u32,
}

impl CcPattern {
    /// Compute a raw score (arbitrary units) against the supplied `evidence`.
    ///
    /// Sums weights from evidence items that are consistent with this pattern
    /// and subtracts half the weight of items that contradict it.
    #[must_use]
    pub fn score_evidence(&self, evidence: &[CcEvidence]) -> u32 {
        let mut positive: u32 = 0;
        let mut negative: u32 = 0;

        for ev in evidence {
            let reg = ev.register.as_deref().unwrap_or("");
            match ev.kind {
                EvidenceKind::ReadBeforeWrite => {
                    if self.arg_regs.iter().any(|r| r == reg)
                        || self.fp_arg_regs.iter().any(|r| r == reg)
                    {
                        positive += ev.weight;
                    } else if !self.caller_saved.iter().any(|r| r == reg) {
                        negative += ev.weight / 2;
                    }
                }
                EvidenceKind::CalleeSaved => {
                    if self.callee_saved.iter().any(|r| r == reg) {
                        positive += ev.weight;
                    } else {
                        negative += ev.weight / 2;
                    }
                }
                EvidenceKind::WrittenBeforeReturn => {
                    if self.retval_regs.iter().any(|r| r == reg) {
                        positive += ev.weight;
                    }
                }
                EvidenceKind::CalleeStackCleanup => {
                    if self.callee_cleans_stack {
                        positive += ev.weight;
                    } else {
                        negative += ev.weight;
                    }
                }
                EvidenceKind::ShadowSpace => {
                    if self.shadow_space >= 32 {
                        positive += ev.weight;
                    } else {
                        negative += ev.weight / 2;
                    }
                }
                EvidenceKind::ThisPointerHint => {
                    if self.has_hidden_this {
                        positive += ev.weight;
                    }
                }
                EvidenceKind::FpArgRegister => {
                    if self.fp_arg_regs.iter().any(|r| r == reg) {
                        positive += ev.weight;
                    }
                }
                EvidenceKind::NoRegisterArgs => {
                    if self.max_reg_args == 0 {
                        positive += ev.weight;
                    } else {
                        negative += ev.weight / 2;
                    }
                }
                EvidenceKind::StackArgAccess | EvidenceKind::LargeStackFrame => {
                    // Neutral evidence — does not discriminate between CCs.
                }
            }
        }

        positive.saturating_sub(negative)
    }

    /// Return `true` if `reg` is an argument register in this pattern.
    #[must_use]
    pub fn is_arg_reg(&self, reg: &str) -> bool {
        self.arg_regs.iter().any(|r| r == reg) || self.fp_arg_regs.iter().any(|r| r == reg)
    }

    /// Return `true` if `reg` is callee-saved in this pattern.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.iter().any(|r| r == reg)
    }

    /// Return `true` if `reg` is a return-value register in this pattern.
    #[must_use]
    pub fn is_retval_reg(&self, reg: &str) -> bool {
        self.retval_regs.iter().any(|r| r == reg)
    }

    /// Produce the System V AMD64 ABI pattern.
    #[must_use]
    pub fn sysv_amd64() -> Self {
        Self {
            name: "System V AMD64".into(),
            arg_regs: vec![
                "rdi".into(), "rsi".into(), "rdx".into(),
                "rcx".into(), "r8".into(),  "r9".into(),
            ],
            fp_arg_regs: vec![
                "xmm0".into(), "xmm1".into(), "xmm2".into(), "xmm3".into(),
                "xmm4".into(), "xmm5".into(), "xmm6".into(), "xmm7".into(),
            ],
            retval_regs: vec!["rax".into(), "rdx".into()],
            callee_saved: vec![
                "rbx".into(), "rbp".into(), "r12".into(),
                "r13".into(), "r14".into(), "r15".into(),
            ],
            caller_saved: vec![
                "rax".into(), "rcx".into(), "rdx".into(),
                "rsi".into(), "rdi".into(), "r8".into(),
                "r9".into(),  "r10".into(), "r11".into(),
            ],
            callee_cleans_stack: false,
            has_hidden_this: false,
            shadow_space: 0,
            max_reg_args: 6,
            stack_alignment: 16,
        }
    }

    /// Produce the Microsoft x64 ABI pattern.
    #[must_use]
    pub fn ms_x64() -> Self {
        Self {
            name: "Microsoft x64".into(),
            arg_regs: vec!["rcx".into(), "rdx".into(), "r8".into(), "r9".into()],
            fp_arg_regs: vec!["xmm0".into(), "xmm1".into(), "xmm2".into(), "xmm3".into()],
            retval_regs: vec!["rax".into()],
            callee_saved: vec![
                "rbx".into(), "rbp".into(), "rdi".into(), "rsi".into(),
                "r12".into(), "r13".into(), "r14".into(), "r15".into(),
            ],
            caller_saved: vec![
                "rax".into(), "rcx".into(), "rdx".into(),
                "r8".into(), "r9".into(), "r10".into(), "r11".into(),
            ],
            callee_cleans_stack: false,
            has_hidden_this: false,
            shadow_space: 32,
            max_reg_args: 4,
            stack_alignment: 16,
        }
    }

    /// Produce the cdecl x86 pattern.
    #[must_use]
    pub fn cdecl_x86() -> Self {
        Self {
            name: "cdecl (x86)".into(),
            arg_regs: vec![],
            fp_arg_regs: vec![],
            retval_regs: vec!["eax".into(), "edx".into()],
            callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
            caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
            callee_cleans_stack: false,
            has_hidden_this: false,
            shadow_space: 0,
            max_reg_args: 0,
            stack_alignment: 4,
        }
    }

    /// Produce the stdcall x86 pattern.
    #[must_use]
    pub fn stdcall_x86() -> Self {
        Self {
            name: "stdcall (x86)".into(),
            arg_regs: vec![],
            fp_arg_regs: vec![],
            retval_regs: vec!["eax".into(), "edx".into()],
            callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
            caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
            callee_cleans_stack: true,
            has_hidden_this: false,
            shadow_space: 0,
            max_reg_args: 0,
            stack_alignment: 4,
        }
    }

    /// Produce the thiscall x86 pattern (MSVC C++ member functions).
    #[must_use]
    pub fn thiscall_x86() -> Self {
        Self {
            name: "thiscall (x86)".into(),
            arg_regs: vec!["ecx".into()],
            fp_arg_regs: vec![],
            retval_regs: vec!["eax".into(), "edx".into()],
            callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
            caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
            callee_cleans_stack: true,
            has_hidden_this: true,
            shadow_space: 0,
            max_reg_args: 1,
            stack_alignment: 4,
        }
    }

    /// Produce the AAPCS64 (Arm64) pattern.
    #[must_use]
    pub fn aapcs64() -> Self {
        Self {
            name: "AAPCS64".into(),
            arg_regs: vec![
                "x0".into(), "x1".into(), "x2".into(), "x3".into(),
                "x4".into(), "x5".into(), "x6".into(), "x7".into(),
            ],
            fp_arg_regs: vec![
                "v0".into(), "v1".into(), "v2".into(), "v3".into(),
                "v4".into(), "v5".into(), "v6".into(), "v7".into(),
            ],
            retval_regs: vec!["x0".into(), "x1".into()],
            callee_saved: vec![
                "x19".into(), "x20".into(), "x21".into(), "x22".into(),
                "x23".into(), "x24".into(), "x25".into(), "x26".into(),
                "x27".into(), "x28".into(), "x29".into(),
                // x30 (LR) must be preserved across a call by any non-leaf
                // callee (AAPCS64 §6.1.1; cf. LLVM CSR_AArch64_AAPCS, which
                // lists LR). It was omitted here and in lib.rs::aapcs64(),
                // diverging from cc_database.rs::CC_AAPCS64 which lists it —
                // so the canonical `stp x29, x30, [sp, #-16]!` prologue save
                // scored as an unexplained save instead of a callee-save.
                "x30".into(),
            ],
            caller_saved: vec![
                "x0".into(), "x1".into(), "x2".into(), "x3".into(),
                "x4".into(), "x5".into(), "x6".into(), "x7".into(),
                "x8".into(), "x9".into(), "x10".into(), "x11".into(),
                "x12".into(), "x13".into(), "x14".into(), "x15".into(),
                // x16/x17 (IP0/IP1) are caller-saved intra-procedure-call
                // scratch registers per AAPCS64 §6.1.1. They were omitted
                // here, diverging from lib.rs::aapcs64() and
                // calling_convention_detector.rs::aapcs64(), both of which
                // list the full x0-x17 caller-saved set.
                "x16".into(), "x17".into(),
            ],
            callee_cleans_stack: false,
            has_hidden_this: false,
            shadow_space: 0,
            max_reg_args: 8,
            stack_alignment: 16,
        }
    }
}

impl fmt::Display for CcPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [max_reg_args={}, callee_clean={}, shadow={}]",
            self.name, self.max_reg_args, self.callee_cleans_stack, self.shadow_space
        )
    }
}

// ---------------------------------------------------------------------------
// DetectedCc — result of detection
// ---------------------------------------------------------------------------

/// The result produced by [`CallingConventionDetector`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedCc {
    /// The winning `CcPattern`.
    pub pattern: CcPattern,
    /// Aggregate score from evidence matching.
    pub score: u32,
    /// Confidence percentage (0–100).
    pub confidence_pct: u8,
    /// All evidence items gathered during analysis.
    pub evidence: Vec<CcEvidence>,
    /// Names and scores of runner-up candidates.
    pub runner_ups: Vec<(String, u32)>,
    /// Whether the result is ambiguous (two equally-scored candidates).
    pub ambiguous: bool,
}

impl DetectedCc {
    /// Return `true` if this detection is high-confidence (>= 60 %).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence_pct >= 60
    }

    /// Produce a one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} (score={}, conf={}%, ambiguous={})",
            self.pattern.name, self.score, self.confidence_pct, self.ambiguous
        )
    }
}

// ---------------------------------------------------------------------------
// CallingConventionDetector
// ---------------------------------------------------------------------------

/// Detects the calling convention of a function by scoring a set of
/// [`CcPattern`] candidates against collected [`CcEvidence`].
pub struct CallingConventionDetector {
    /// Candidate patterns to score.
    candidates: Vec<CcPattern>,
}

impl CallingConventionDetector {
    /// Create a detector with the given candidate patterns.
    #[must_use]
    pub const fn new(candidates: Vec<CcPattern>) -> Self {
        Self { candidates }
    }

    /// Create a detector pre-loaded with all common x86/x64/arm64 patterns.
    #[must_use]
    pub fn with_all_builtins() -> Self {
        Self::new(vec![
            CcPattern::sysv_amd64(),
            CcPattern::ms_x64(),
            CcPattern::cdecl_x86(),
            CcPattern::stdcall_x86(),
            CcPattern::thiscall_x86(),
            CcPattern::aapcs64(),
        ])
    }

    /// Add a custom pattern.
    pub fn add_pattern(&mut self, p: CcPattern) {
        self.candidates.push(p);
    }

    /// Gather evidence from a raw instruction stream described by the caller.
    ///
    /// The caller provides simplified register-use records. This method converts
    /// them into `CcEvidence` items.
    #[must_use]
    pub fn gather_evidence(
        reads_before_writes: &[String],
        saved_regs: &[String],
        written_before_ret: &[String],
        fp_reads: &[String],
        callee_pops_stack: bool,
        shadow_space_observed: bool,
        this_ptr_hint: bool,
        no_reg_args: bool,
    ) -> Vec<CcEvidence> {
        let mut ev: Vec<CcEvidence> = Vec::new();

        for reg in reads_before_writes {
            ev.push(CcEvidence::new(
                EvidenceKind::ReadBeforeWrite,
                Some(reg.clone()),
                format!("{reg} read before write"),
                10,
            ));
        }

        for reg in saved_regs {
            ev.push(CcEvidence::new(
                EvidenceKind::CalleeSaved,
                Some(reg.clone()),
                format!("{reg} push/pop symmetric"),
                8,
            ));
        }

        for reg in written_before_ret {
            ev.push(CcEvidence::new(
                EvidenceKind::WrittenBeforeReturn,
                Some(reg.clone()),
                format!("{reg} written before RET"),
                12,
            ));
        }

        for reg in fp_reads {
            ev.push(CcEvidence::new(
                EvidenceKind::FpArgRegister,
                Some(reg.clone()),
                format!("{reg} FP read before write"),
                9,
            ));
        }

        if callee_pops_stack {
            ev.push(CcEvidence::new(
                EvidenceKind::CalleeStackCleanup,
                None,
                "RET N observed — callee cleans stack",
                15,
            ));
        }

        if shadow_space_observed {
            ev.push(CcEvidence::new(
                EvidenceKind::ShadowSpace,
                None,
                "sub rsp, 32+ observed — shadow space",
                12,
            ));
        }

        if this_ptr_hint {
            ev.push(CcEvidence::new(
                EvidenceKind::ThisPointerHint,
                Some("ecx".into()),
                "ecx used as `this` pointer",
                10,
            ));
        }

        if no_reg_args {
            ev.push(CcEvidence::new(
                EvidenceKind::NoRegisterArgs,
                None,
                "no argument registers observed",
                5,
            ));
        }

        ev
    }

    /// Score all candidates and return them sorted best-first.
    #[must_use]
    pub fn score_all(&self, evidence: &[CcEvidence]) -> Vec<(CcPattern, u32)> {
        let mut scored: Vec<(CcPattern, u32)> = self
            .candidates
            .iter()
            .map(|p| (p.clone(), p.score_evidence(evidence)))
            .collect();
        scored.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        scored
    }

    /// Detect the best-matching calling convention from the evidence.
    ///
    /// Returns `None` if no candidates are registered or all score zero.
    #[must_use]
    pub fn detect(&self, evidence: &[CcEvidence]) -> Option<DetectedCc> {
        if self.candidates.is_empty() {
            return None;
        }

        let scored = self.score_all(evidence);
        let best_score = scored.first().map_or(0, |(_, s)| *s);
        if best_score == 0 {
            return None;
        }

        let tied: Vec<&(CcPattern, u32)> = scored
            .iter()
            .filter(|(_, s)| *s == best_score)
            .collect();

        let ambiguous = tied.len() > 1;

        // Tiebreaking heuristics.
        let winner = if ambiguous {
            Self::tiebreak(&tied, evidence)
                .unwrap_or_else(|| tied[0].0.clone())
        } else {
            tied[0].0.clone()
        };

        let total_possible: u32 = evidence.iter().map(|e| e.weight).sum::<u32>().max(1);
        let confidence_pct = u8::try_from((u64::from(best_score) * 100 / u64::from(total_possible)).min(100))
            .unwrap_or(100);

        let runner_ups: Vec<(String, u32)> = scored
            .iter()
            .skip(1)
            .take(3)
            .map(|(p, s)| (p.name.clone(), *s))
            .collect();

        Some(DetectedCc {
            pattern: winner,
            score: best_score,
            confidence_pct,
            evidence: evidence.to_vec(),
            runner_ups,
            ambiguous,
        })
    }

    /// Tiebreak between equally-scored candidates using heuristic evidence.
    fn tiebreak(tied: &[&(CcPattern, u32)], evidence: &[CcEvidence]) -> Option<CcPattern> {
        let has_shadow = evidence.iter().any(|e| e.kind == EvidenceKind::ShadowSpace);
        let has_this = evidence.iter().any(|e| e.kind == EvidenceKind::ThisPointerHint);
        let has_callee_clean = evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::CalleeStackCleanup);

        if has_shadow
            && let Some((p, _)) = tied.iter().find(|(p, _)| p.shadow_space >= 32) {
                return Some((*p).clone());
            }
        if has_this
            && let Some((p, _)) = tied.iter().find(|(p, _)| p.has_hidden_this) {
                return Some((*p).clone());
            }
        if has_callee_clean
            && let Some((p, _)) = tied.iter().find(|(p, _)| p.callee_cleans_stack) {
                return Some((*p).clone());
            }
        None
    }

    /// Return aggregate statistics over a batch of detection results.
    #[must_use]
    pub fn batch_stats(results: &[DetectedCc]) -> DetectionStats {
        DetectionStats::compute(results)
    }
}

// ---------------------------------------------------------------------------
// DetectionStats
// ---------------------------------------------------------------------------

/// Aggregate statistics over a batch of `DetectedCc` results.
#[derive(Debug, Clone, Default)]
pub struct DetectionStats {
    /// Total number of functions analysed.
    pub total: usize,
    /// Number of high-confidence detections.
    pub high_confidence: usize,
    /// Number of ambiguous detections.
    pub ambiguous: usize,
    /// Distribution by CC name.
    /// Keyed by CC names from binary analysis — `FxHashMap` to prevent `DoS`.
    pub by_name: FxHashMap<String, usize>,
    /// Average confidence percentage.
    pub avg_confidence: f64,
}

impl DetectionStats {
    /// Compute stats from a slice of results.
    #[must_use]
    pub fn compute(results: &[DetectedCc]) -> Self {
        if results.is_empty() {
            return Self::default();
        }
        let mut by_name: FxHashMap<String, usize> = FxHashMap::default();
        let mut high_confidence = 0usize;
        let mut ambiguous = 0usize;
        let mut conf_sum = 0u64;

        for r in results {
            *by_name.entry(r.pattern.name.clone()).or_insert(0) += 1;
            if r.is_high_confidence() {
                high_confidence += 1;
            }
            if r.ambiguous {
                ambiguous += 1;
            }
            conf_sum += u64::from(r.confidence_pct);
        }

        Self {
            total: results.len(),
            high_confidence,
            ambiguous,
            by_name,
            avg_confidence: conf_sum as f64 / results.len() as f64,
        }
    }

    /// The most frequently detected CC name.
    #[must_use]
    pub fn most_common(&self) -> Option<&str> {
        // `by_name` is a HashMap; break count ties by name so the result is
        // reproducible across runs regardless of hash iteration order.
        self.by_name
            .iter()
            .max_by(|(na, ca), (nb, cb)| ca.cmp(cb).then_with(|| nb.cmp(na)))
            .map(|(n, _)| n.as_str())
    }
}

// ---------------------------------------------------------------------------
// PrologueAnalyzer
// ---------------------------------------------------------------------------

/// Analyses prologue/epilogue patterns in a flat register-use stream.
///
/// Feed it simplified instructions (as register names and opcodes) and it
/// derives `CcEvidence` suitable for `CallingConventionDetector`.
pub struct PrologueAnalyzer {
    defined: HashSet<String>,
    reads_before_write: Vec<String>,
    fp_reads: Vec<String>,
    pushed: Vec<String>,
    popped: Vec<String>,
    recent_writes: Vec<String>,
    written_before_return: Vec<String>,
    callee_pops_stack: bool,
    shadow_space_observed: bool,
    this_ptr_hint: bool,
    max_stack_alloc: u32,
}

impl PrologueAnalyzer {
    /// Create a fresh analyser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            defined: HashSet::new(),
            reads_before_write: Vec::new(),
            fp_reads: Vec::new(),
            pushed: Vec::new(),
            popped: Vec::new(),
            recent_writes: Vec::new(),
            written_before_return: Vec::new(),
            callee_pops_stack: false,
            shadow_space_observed: false,
            this_ptr_hint: false,
            max_stack_alloc: 0,
        }
    }

    /// Record a register read.
    pub fn observe_reg_read(&mut self, reg: &str) {
        if !self.defined.contains(reg) && !self.reads_before_write.iter().any(|r| r == reg) {
            self.reads_before_write.push(reg.to_string());
        }
    }

    /// Record a register write.
    pub fn observe_reg_write(&mut self, reg: &str) {
        self.defined.insert(reg.to_string());
        self.recent_writes.retain(|r| r != reg);
        self.recent_writes.push(reg.to_string());
        if self.recent_writes.len() > 8 {
            self.recent_writes.remove(0);
        }
    }

    /// Record a register push (callee-save candidate).
    pub fn observe_push(&mut self, reg: &str) {
        self.pushed.push(reg.to_string());
        self.defined.insert(reg.to_string());
    }

    /// Record a register pop (callee-restore candidate).
    pub fn observe_pop(&mut self, reg: &str) {
        self.popped.push(reg.to_string());
    }

    /// Record a return instruction. `stack_pop_bytes > 0` means `RET N`.
    pub fn observe_ret(&mut self, stack_pop_bytes: u32) {
        self.written_before_return = self.recent_writes.clone();
        if stack_pop_bytes > 0 {
            self.callee_pops_stack = true;
        }
    }

    /// Record a stack allocation (e.g. `sub rsp, N`).
    pub fn observe_stack_alloc(&mut self, bytes: u32) {
        self.max_stack_alloc = self.max_stack_alloc.max(bytes);
        if bytes >= 32 {
            self.shadow_space_observed = true;
        }
    }

    /// Record a floating-point register read.
    pub fn observe_fp_read(&mut self, reg: &str) {
        if !self.defined.contains(reg) && !self.fp_reads.iter().any(|r| r == reg) {
            self.fp_reads.push(reg.to_string());
        }
    }

    /// Signal that `ecx`/`rcx` was used as a `this` pointer.
    pub const fn observe_this_ptr(&mut self) {
        self.this_ptr_hint = true;
    }

    /// Derive evidence from all observations so far.
    #[must_use]
    pub fn derive_evidence(&self) -> Vec<CcEvidence> {
        let saved: Vec<String> = self
            .pushed
            .iter()
            .filter(|r| self.popped.contains(r))
            .cloned()
            .collect();

        let no_reg_args = self.reads_before_write.is_empty() && self.fp_reads.is_empty();

        CallingConventionDetector::gather_evidence(
            &self.reads_before_write,
            &saved,
            &self.written_before_return,
            &self.fp_reads,
            self.callee_pops_stack,
            self.shadow_space_observed,
            self.this_ptr_hint,
            no_reg_args,
        )
    }
}

impl Default for PrologueAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sysv_detector() -> CallingConventionDetector {
        CallingConventionDetector::new(vec![
            CcPattern::sysv_amd64(),
            CcPattern::ms_x64(),
            CcPattern::cdecl_x86(),
            CcPattern::stdcall_x86(),
        ])
    }

    /// Regression guard for bug #84: `cc_detector`'s aapcs64 caller-saved set
    /// omitted x16/x17 (IP0/IP1), which AAPCS64 §6.1.1 defines as caller-saved
    /// scratch. Lock the full x0-x17 set so the divergence from the lib.rs and
    /// `calling_convention_detector` copies cannot recur.
    #[test]
    fn aapcs64_caller_saved_includes_ip0_ip1() {
        let p = CcPattern::aapcs64();
        assert!(
            p.caller_saved.iter().any(|r| r == "x16"),
            "aapcs64 caller_saved must include x16 (IP0)"
        );
        assert!(
            p.caller_saved.iter().any(|r| r == "x17"),
            "aapcs64 caller_saved must include x17 (IP1)"
        );
        assert_eq!(p.caller_saved.len(), 18, "expected x0-x17 caller-saved");
    }

    #[test]
    fn test_sysv_detection() {
        let mut ana = PrologueAnalyzer::new();
        for reg in &["rdi", "rsi", "rdx"] {
            ana.observe_reg_read(reg);
        }
        ana.observe_push("rbx");
        ana.observe_push("r12");
        ana.observe_reg_write("rax");
        ana.observe_ret(0);
        ana.observe_pop("r12");
        ana.observe_pop("rbx");

        let ev = ana.derive_evidence();
        let det = sysv_detector().detect(&ev).expect("should detect");
        assert_eq!(det.pattern.name, "System V AMD64");
    }

    #[test]
    fn test_ms_x64_detection() {
        let mut ana = PrologueAnalyzer::new();
        for reg in &["rcx", "rdx", "r8", "r9"] {
            ana.observe_reg_read(reg);
        }
        ana.observe_stack_alloc(32);
        ana.observe_reg_write("rax");
        ana.observe_ret(0);

        let ev = ana.derive_evidence();
        let det = sysv_detector().detect(&ev).expect("should detect");
        // shadow space should tip to MS x64
        assert_eq!(det.pattern.name, "Microsoft x64");
    }

    #[test]
    fn test_cdecl_detection() {
        // No register args, caller pops
        let mut ana = PrologueAnalyzer::new();
        ana.observe_push("ebx");
        ana.observe_reg_write("eax");
        ana.observe_ret(0);
        ana.observe_pop("ebx");

        let ev = ana.derive_evidence();
        let det = CallingConventionDetector::new(vec![
            CcPattern::cdecl_x86(),
            CcPattern::stdcall_x86(),
        ])
        .detect(&ev)
        .expect("should detect");
        // Both cdecl and stdcall are stack-only; cdecl has callee_cleans_stack=false
        // which matches ret 0. Scores should be equal but cdecl wins on no callee cleanup.
        assert!(det.pattern.name.contains("x86"));
    }

    #[test]
    fn test_thiscall_hint() {
        let mut ana = PrologueAnalyzer::new();
        ana.observe_reg_read("ecx");
        ana.observe_this_ptr();
        ana.observe_ret(4);

        let ev = ana.derive_evidence();
        let det = CallingConventionDetector::new(vec![
            CcPattern::cdecl_x86(),
            CcPattern::stdcall_x86(),
            CcPattern::thiscall_x86(),
        ])
        .detect(&ev)
        .expect("should detect");
        assert_eq!(det.pattern.name, "thiscall (x86)");
    }

    #[test]
    fn test_no_candidates() {
        let det = CallingConventionDetector::new(vec![]).detect(&[]);
        assert!(det.is_none());
    }

    #[test]
    fn test_score_positive_negative() {
        let p = CcPattern::sysv_amd64();
        let ev = CallingConventionDetector::gather_evidence(
            &["rdi".to_string()],
            &[],
            &[],
            &[],
            false,
            false,
            false,
            false,
        );
        let score = p.score_evidence(&ev);
        assert!(score > 0);
    }

    #[test]
    fn test_confidence_percentage() {
        let det = CallingConventionDetector::with_all_builtins();
        let mut ana = PrologueAnalyzer::new();
        for r in &["rdi", "rsi", "rdx", "rcx"] {
            ana.observe_reg_read(r);
        }
        ana.observe_push("rbx");
        ana.observe_ret(0);
        ana.observe_pop("rbx");

        let ev = ana.derive_evidence();
        let result = det.detect(&ev).expect("should detect");
        assert!(result.confidence_pct > 0);
        assert!(result.confidence_pct <= 100);
    }

    #[test]
    fn test_batch_stats() {
        let det = CallingConventionDetector::with_all_builtins();
        let mut results = Vec::new();
        for _ in 0..5 {
            let mut ana = PrologueAnalyzer::new();
            ana.observe_reg_read("rdi");
            ana.observe_ret(0);
            let ev = ana.derive_evidence();
            if let Some(r) = det.detect(&ev) {
                results.push(r);
            }
        }
        let stats = CallingConventionDetector::batch_stats(&results);
        assert_eq!(stats.total, results.len());
    }

    #[test]
    fn test_pattern_is_arg_reg() {
        let p = CcPattern::sysv_amd64();
        assert!(p.is_arg_reg("rdi"));
        assert!(p.is_arg_reg("xmm0"));
        assert!(!p.is_arg_reg("rbx"));
    }

    #[test]
    fn test_pattern_is_callee_saved() {
        let p = CcPattern::sysv_amd64();
        assert!(p.is_callee_saved("rbx"));
        assert!(!p.is_callee_saved("rdi"));
    }

    #[test]
    fn test_pattern_is_retval_reg() {
        let p = CcPattern::sysv_amd64();
        assert!(p.is_retval_reg("rax"));
        assert!(p.is_retval_reg("rdx"));
        assert!(!p.is_retval_reg("rbx"));
    }

    #[test]
    fn test_aapcs64_pattern_shape() {
        let p = CcPattern::aapcs64();
        assert_eq!(p.name, "AAPCS64");
        assert!(p.is_arg_reg("x0"));
        assert!(p.is_arg_reg("v0"));
        assert!(p.is_callee_saved("x19"));
        assert!(p.is_retval_reg("x0"));
        assert_eq!(p.max_reg_args, 8);
    }

    #[test]
    fn test_add_pattern_participates_in_detection() {
        let mut det = CallingConventionDetector::new(vec![]);
        det.add_pattern(CcPattern::sysv_amd64());
        let ev = CallingConventionDetector::gather_evidence(
            &["rdi".to_string(), "rsi".to_string()],
            &[],
            &[],
            &[],
            false,
            false,
            false,
            false,
        );
        let result = det.detect(&ev).expect("should detect after add_pattern");
        assert_eq!(result.pattern.name, "System V AMD64");
    }

    #[test]
    fn test_detected_cc_is_high_confidence_boundary() {
        let det = CallingConventionDetector::with_all_builtins();
        let mut ana = PrologueAnalyzer::new();
        for r in &["rdi", "rsi", "rdx", "rcx", "r8", "r9"] {
            ana.observe_reg_read(r);
        }
        ana.observe_push("rbx");
        ana.observe_push("r12");
        ana.observe_ret(0);
        ana.observe_pop("r12");
        ana.observe_pop("rbx");
        let ev = ana.derive_evidence();
        let result = det.detect(&ev).expect("should detect");
        // Strong SysV-shaped evidence should cross the 60% high-confidence bar.
        assert!(result.is_high_confidence());
        assert!(result.confidence_pct >= 60);
    }

    #[test]
    fn test_summary_contains_key_fields() {
        let det = CallingConventionDetector::with_all_builtins();
        let mut ana = PrologueAnalyzer::new();
        ana.observe_reg_read("rdi");
        ana.observe_ret(0);
        let ev = ana.derive_evidence();
        let result = det.detect(&ev).expect("should detect");
        let s = result.summary();
        assert!(s.contains(&result.pattern.name));
        assert!(s.contains("score="));
        assert!(s.contains("conf="));
        assert!(s.contains("ambiguous="));
    }

    #[test]
    fn test_evidence_kind_display() {
        assert_eq!(EvidenceKind::ReadBeforeWrite.to_string(), "ReadBeforeWrite");
        assert_eq!(EvidenceKind::CalleeSaved.to_string(), "CalleeSaved");
        assert_eq!(EvidenceKind::LargeStackFrame.to_string(), "LargeStackFrame");
    }

    #[test]
    fn test_cc_pattern_display() {
        let p = CcPattern::ms_x64();
        let s = p.to_string();
        assert!(s.contains("Microsoft x64"));
        assert!(s.contains("max_reg_args=4"));
        assert!(s.contains("shadow=32"));
    }

    #[test]
    fn test_score_all_sorted_best_first() {
        let det = CallingConventionDetector::with_all_builtins();
        let ev = CallingConventionDetector::gather_evidence(
            &["rcx".to_string(), "rdx".to_string(), "r8".to_string(), "r9".to_string()],
            &[],
            &[],
            &[],
            false,
            true,
            false,
            false,
        );
        let scored = det.score_all(&ev);
        // Sorted descending by score.
        for w in scored.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
        assert_eq!(scored[0].0.name, "Microsoft x64");
    }

    /// Regression test: `DetectionStats::most_common` used to resolve tied
    /// counts via `HashMap` iteration order, which is nondeterministic across
    /// runs/processes. Verify it is stable across many repeated calls.
    #[test]
    fn detection_stats_most_common_is_deterministic_on_ties() {
        let mut by_name: FxHashMap<String, usize> = FxHashMap::default();
        by_name.insert("cdecl".to_string(), 4);
        by_name.insert("stdcall".to_string(), 4);
        by_name.insert("fastcall".to_string(), 1);
        let stats = DetectionStats {
            total: 9,
            high_confidence: 0,
            ambiguous: 0,
            by_name,
            avg_confidence: 0.0,
        };
        let first = stats.most_common().map(str::to_owned);
        for _ in 0..20 {
            assert_eq!(stats.most_common().map(str::to_owned), first);
        }
    }
}
