//! Stack cleanup analysis: determine whether a function uses caller-cleans or
//! callee-cleans semantics, track per-call-site stack deltas, and infer the
//! number of stack-passed arguments from the observed SP adjustments.
//!
//! The core type is [`StackCleanupAnalyzer`].  Feed it simplified instruction
//! records from a function body and call it to obtain a [`StackDelta`] summary
//! per return site and an overall [`CleanupKind`] verdict.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CleanupKind
// ---------------------------------------------------------------------------

/// Who is responsible for removing stack-passed arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CleanupKind {
    /// The *caller* adjusts SP after each call (e.g. `cdecl`, `SysV` AMD64).
    CallerCleans,
    /// The *callee* pops arguments before returning (e.g. `stdcall`, `thiscall`).
    CalleeCleans,
    /// No stack arguments detected — cleanup question is moot.
    NoStackArgs,
    /// Both patterns observed — typically indicates mixed or variadic code.
    Mixed,
    /// Not enough evidence to determine cleanup.
    Unknown,
}

impl fmt::Display for CleanupKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CallerCleans => "CallerCleans",
            Self::CalleeCleans => "CalleeCleans",
            Self::NoStackArgs => "NoStackArgs",
            Self::Mixed => "Mixed",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// StackDelta
// ---------------------------------------------------------------------------

/// Observed stack adjustment at a single return (or call) site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackDelta {
    /// Byte offset of the `RET` / `RETN N` instruction within the function.
    pub instr_offset: u64,
    /// Net change in SP at this site (positive = SP increases, i.e. items popped).
    ///
    /// For a `RET N` this is `N`; for a plain `RET` it is `0` (the return
    /// address itself is always implicitly popped, not counted here).
    pub delta: i32,
    /// Whether this is a callee-cleans return (`RET N` with `N > 0`).
    pub callee_pops: bool,
    /// Inferred argument count from `N / pointer_size`.
    pub inferred_arg_count: u32,
    /// Size in bytes of a pointer on the target arch (4 or 8).
    pub pointer_size: u32,
}

impl StackDelta {
    /// Create a new `StackDelta` for a `RET N` instruction.
    #[must_use]
    pub fn from_ret_n(instr_offset: u64, n: u32, pointer_size: u32) -> Self {
        let callee_pops = n > 0;
        let inferred_arg_count = if pointer_size > 0 { n / pointer_size } else { 0 };
        Self {
            instr_offset,
            delta: i32::try_from(n).unwrap_or(i32::MAX),
            callee_pops,
            inferred_arg_count,
            pointer_size,
        }
    }

    /// Create a `StackDelta` for a plain `RET` (no stack adjustment).
    #[must_use]
    pub const fn from_ret(instr_offset: u64, pointer_size: u32) -> Self {
        Self {
            instr_offset,
            delta: 0,
            callee_pops: false,
            inferred_arg_count: 0,
            pointer_size,
        }
    }

    /// Return the stack-argument byte count implied by this delta.
    #[must_use]
    pub const fn stack_arg_bytes(&self) -> u32 {
        if self.delta > 0 {
            self.delta as u32
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// CallerSiteAdjustment
// ---------------------------------------------------------------------------

/// A `SP += N` (or `add rsp, N`) instruction observed in a *caller* function
/// immediately after a `CALL` — evidence of caller-cleanup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerSiteAdjustment {
    /// Byte offset of the SP adjustment instruction.
    pub instr_offset: u64,
    /// Bytes added to SP.
    pub bytes: u32,
    /// Number of stack arguments inferred from `bytes / pointer_size`.
    pub inferred_arg_count: u32,
}

impl CallerSiteAdjustment {
    /// Create from a raw SP adjustment.
    #[must_use]
    pub const fn new(instr_offset: u64, bytes: u32, pointer_size: u32) -> Self {
        let inferred_arg_count = if pointer_size > 0 { bytes / pointer_size } else { 0 };
        Self {
            instr_offset,
            bytes,
            inferred_arg_count,
        }
    }
}

// ---------------------------------------------------------------------------
// StackFrameLayout
// ---------------------------------------------------------------------------

/// Layout information derived from a function's stack frame.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackFrameLayout {
    /// Total bytes allocated for the local frame (sub rsp, N).
    pub local_bytes: u32,
    /// Number of callee-saved registers pushed.
    pub saved_reg_count: u32,
    /// Maximum stack argument offset observed (bytes from initial SP).
    pub max_arg_offset: i32,
    /// Whether a standard frame pointer (`push rbp; mov rbp, rsp`) was observed.
    pub has_frame_pointer: bool,
    /// Whether a red-zone access (negative SP offset < –8 without allocation) was seen.
    pub uses_red_zone: bool,
    /// Alignment padding bytes (difference between raw frame size and aligned size).
    pub alignment_padding: u32,
}

impl StackFrameLayout {
    /// Infer the number of stack-passed arguments from the maximum argument offset.
    ///
    /// `pointer_size` should be 4 for 32-bit, 8 for 64-bit.
    #[must_use]
    pub fn inferred_stack_arg_count(&self, pointer_size: u32) -> u32 {
        if self.max_arg_offset <= 0 || pointer_size == 0 {
            return 0;
        }
        // SAFETY: max_arg_offset > 0 guaranteed by the guard above.
        u32::try_from(self.max_arg_offset).unwrap_or(u32::MAX) / pointer_size
    }
}

// ---------------------------------------------------------------------------
// Simplified instruction records for analysis
// ---------------------------------------------------------------------------

/// Simplified instruction record consumed by `StackCleanupAnalyzer`.
#[derive(Debug, Clone)]
pub enum StackInstr {
    /// A `PUSH reg` instruction.
    Push {
        /// Bytes pushed (2, 4, or 8).
        size: u32,
    },
    /// A `POP reg` instruction.
    Pop {
        /// Bytes popped.
        size: u32,
    },
    /// An SP decrement (frame allocation): `sub rsp, N`.
    SpDecrement {
        /// Bytes subtracted.
        bytes: u32,
    },
    /// An SP increment (cleanup or epilogue): `add rsp, N`.
    SpIncrement {
        /// Bytes added.
        bytes: u32,
        /// Whether this occurs immediately after a `CALL` (caller-cleanup hint).
        after_call: bool,
        /// Byte offset of this instruction.
        offset: u64,
    },
    /// A `RET` or `RETN N` instruction.
    Ret {
        /// Bytes popped by callee (0 for plain `RET`).
        n: u32,
        /// Byte offset of this instruction.
        offset: u64,
    },
    /// A memory access at `[SP + offset]`.
    SpRelAccess {
        /// Signed offset from SP.
        offset: i32,
    },
    /// A `CALL` instruction (used to track post-call adjustments).
    Call,
    /// Frame-pointer setup: `push rbp; mov rbp, rsp` observed.
    FramePointerSetup,
    /// Any other instruction — ignored by the analyzer.
    Other,
}

// ---------------------------------------------------------------------------
// StackCleanupAnalyzer
// ---------------------------------------------------------------------------

/// Analyses the stack cleanup strategy of a function.
///
/// Feed it [`StackInstr`] records from a decoded function body.  After all
/// instructions are consumed, call [`StackCleanupAnalyzer::finish`] to obtain
/// a [`StackCleanupReport`].
pub struct StackCleanupAnalyzer {
    /// Byte size of a pointer on the target architecture.
    pointer_size: u32,
    /// Running SP delta from the function entry (negative = allocated).
    sp_delta: i32,
    /// Maximum frame depth reached.
    max_frame_depth: i32,
    /// Callee-saved pushes observed.
    push_count: u32,
    /// All observed `RET`/`RETN N` instructions.
    ret_sites: Vec<StackDelta>,
    /// All post-call SP adjustments (caller-cleanup evidence).
    caller_adjustments: Vec<CallerSiteAdjustment>,
    /// Max positive SP-relative offset observed (arg access offset).
    max_sp_rel_offset: i32,
    /// Whether a frame pointer setup was observed.
    has_frame_pointer: bool,
    /// Whether any SP-relative access used a negative offset without prior allocation.
    red_zone_candidate: bool,
    /// Frame allocation bytes (from `sub rsp, N`).
    frame_alloc: u32,
    /// Whether a preceding instruction was a CALL.
    last_was_call: bool,
    /// Instruction index counter.
    instr_idx: u64,
}

impl StackCleanupAnalyzer {
    /// Create a new analyzer for a function on the given pointer-size target.
    #[must_use]
    pub fn new(pointer_size: u32) -> Self {
        assert!(pointer_size == 2 || pointer_size == 4 || pointer_size == 8, "pointer_size must be 2, 4, or 8");
        Self {
            pointer_size,
            sp_delta: 0,
            max_frame_depth: 0,
            push_count: 0,
            ret_sites: Vec::new(),
            caller_adjustments: Vec::new(),
            max_sp_rel_offset: 0,
            has_frame_pointer: false,
            red_zone_candidate: false,
            frame_alloc: 0,
            last_was_call: false,
            instr_idx: 0,
        }
    }

    /// Feed one instruction to the analyzer.
    pub fn observe(&mut self, instr: &StackInstr) {
        let idx = self.instr_idx;
        self.instr_idx += 1;

        match instr {
            StackInstr::Push { size } => {
                let sz = i32::try_from(*size).unwrap_or(i32::MAX);
                self.sp_delta = self.sp_delta.saturating_sub(sz);
                self.push_count = self.push_count.saturating_add(1);
                if self.sp_delta < self.max_frame_depth {
                    self.max_frame_depth = self.sp_delta;
                }
                self.last_was_call = false;
            }
            StackInstr::Pop { size } => {
                let sz = i32::try_from(*size).unwrap_or(i32::MAX);
                self.sp_delta = self.sp_delta.saturating_add(sz);
                self.last_was_call = false;
            }
            StackInstr::SpDecrement { bytes } => {
                self.frame_alloc = self.frame_alloc.saturating_add(*bytes);
                let bz = i32::try_from(*bytes).unwrap_or(i32::MAX);
                self.sp_delta = self.sp_delta.saturating_sub(bz);
                if self.sp_delta < self.max_frame_depth {
                    self.max_frame_depth = self.sp_delta;
                }
                self.last_was_call = false;
            }
            StackInstr::SpIncrement { bytes, after_call, offset } => {
                let bz = i32::try_from(*bytes).unwrap_or(i32::MAX);
                self.sp_delta = self.sp_delta.saturating_add(bz);
                if *after_call || self.last_was_call {
                    self.caller_adjustments.push(CallerSiteAdjustment::new(
                        *offset,
                        *bytes,
                        self.pointer_size,
                    ));
                }
                self.last_was_call = false;
            }
            StackInstr::Ret { n, offset } => {
                let delta = StackDelta::from_ret_n(*offset, *n, self.pointer_size);
                self.ret_sites.push(delta);
                let nz = i32::try_from(*n).unwrap_or(i32::MAX);
                self.sp_delta = self.sp_delta.saturating_add(nz);
                self.last_was_call = false;
            }
            StackInstr::SpRelAccess { offset } => {
                if *offset > self.max_sp_rel_offset {
                    self.max_sp_rel_offset = *offset;
                }
                // Negative access without prior allocation → red-zone hint.
                if *offset < 0 && self.frame_alloc == 0 && self.push_count == 0 {
                    self.red_zone_candidate = true;
                }
                self.last_was_call = false;
            }
            StackInstr::Call => {
                self.last_was_call = true;
            }
            StackInstr::FramePointerSetup => {
                self.has_frame_pointer = true;
                self.last_was_call = false;
            }
            StackInstr::Other => {
                self.last_was_call = false;
            }
        }
        let _ = idx;
    }

    /// Feed an iterator of instructions.
    pub fn observe_all<'a, I: IntoIterator<Item = &'a StackInstr>>(&mut self, instrs: I) {
        for i in instrs {
            self.observe(i);
        }
    }

    /// Determine the overall `CleanupKind` from collected observations.
    #[must_use]
    pub fn cleanup_kind(&self) -> CleanupKind {
        let callee_count = self.ret_sites.iter().filter(|r| r.callee_pops).count();
        let plain_count = self.ret_sites.iter().filter(|r| !r.callee_pops).count();
        let caller_count = self.caller_adjustments.len();

        // No evidence at all — including no RET sites (e.g. a tail-calling
        // function whose body never surfaced a RET/RETN instruction to
        // `observe`) and no post-call caller-cleanup adjustments.
        if self.ret_sites.is_empty() && caller_count == 0 && self.max_sp_rel_offset <= 0 {
            return CleanupKind::Unknown;
        }

        let any_stack_ops = callee_count > 0
            || caller_count > 0
            || self.max_sp_rel_offset > 0;

        if !any_stack_ops {
            return CleanupKind::NoStackArgs;
        }

        match (callee_count > 0, caller_count > 0 || plain_count > 0) {
            (true, false) => CleanupKind::CalleeCleans,
            (false, true) => CleanupKind::CallerCleans,
            (true, true) => CleanupKind::Mixed,
            (false, false) => CleanupKind::NoStackArgs,
        }
    }

    /// Derive a `StackFrameLayout` from current observations.
    #[must_use]
    pub const fn frame_layout(&self) -> StackFrameLayout {
        let alignment = if self.pointer_size == 8 { 16u32 } else { 4 };
        let raw = self.frame_alloc
            .saturating_add(self.push_count.saturating_mul(self.pointer_size));
        let aligned = raw.saturating_add(alignment - 1) / alignment * alignment;

        StackFrameLayout {
            local_bytes: self.frame_alloc,
            saved_reg_count: self.push_count,
            max_arg_offset: self.max_sp_rel_offset,
            has_frame_pointer: self.has_frame_pointer,
            uses_red_zone: self.red_zone_candidate,
            alignment_padding: aligned.saturating_sub(raw),
        }
    }

    /// Infer the maximum number of stack-passed arguments.
    #[must_use]
    pub fn inferred_stack_arg_count(&self) -> u32 {
        // Check callee-pops first.
        let from_ret: u32 = self
            .ret_sites
            .iter()
            .filter(|r| r.callee_pops)
            .map(|r| r.inferred_arg_count)
            .max()
            .unwrap_or(0);

        // Check caller adjustments.
        let from_caller: u32 = self
            .caller_adjustments
            .iter()
            .map(|a| a.inferred_arg_count)
            .max()
            .unwrap_or(0);

        // Check SP-relative accesses beyond local frame.
        let layout_count = self.frame_layout().inferred_stack_arg_count(self.pointer_size);

        from_ret.max(from_caller).max(layout_count)
    }

    /// Produce the full cleanup report.
    #[must_use]
    pub fn finish(self) -> StackCleanupReport {
        let kind = self.cleanup_kind();
        let stack_arg_count = self.inferred_stack_arg_count();
        let layout = self.frame_layout();
        StackCleanupReport {
            kind,
            ret_sites: self.ret_sites,
            caller_adjustments: self.caller_adjustments,
            stack_arg_count,
            frame_layout: layout,
            pointer_size: self.pointer_size,
        }
    }
}

// ---------------------------------------------------------------------------
// StackCleanupReport
// ---------------------------------------------------------------------------

/// Full report produced by `StackCleanupAnalyzer::finish`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackCleanupReport {
    /// Whether the function uses caller-cleans or callee-cleans semantics.
    pub kind: CleanupKind,
    /// Per-return-site stack deltas.
    pub ret_sites: Vec<StackDelta>,
    /// Post-call SP adjustments in the caller.
    pub caller_adjustments: Vec<CallerSiteAdjustment>,
    /// Maximum inferred number of stack-passed arguments.
    pub stack_arg_count: u32,
    /// Frame layout.
    pub frame_layout: StackFrameLayout,
    /// Pointer size used.
    pub pointer_size: u32,
}

impl StackCleanupReport {
    /// Return a one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{} | stack_args={} | frame_local={}B | saved_regs={} | fp={}",
            self.kind,
            self.stack_arg_count,
            self.frame_layout.local_bytes,
            self.frame_layout.saved_reg_count,
            self.frame_layout.has_frame_pointer,
        )
    }

    /// Return `true` if the function might be variadic (mixed cleanup or large
    /// number of stack arguments alongside register args).
    #[must_use]
    pub const fn possibly_variadic(&self) -> bool {
        matches!(self.kind, CleanupKind::Mixed)
            || self.stack_arg_count > 6
    }
}

// ---------------------------------------------------------------------------
// BatchStackAnalyzer
// ---------------------------------------------------------------------------

/// Convenience wrapper for analysing multiple functions at once.
pub struct BatchStackAnalyzer {
    pointer_size: u32,
}

impl BatchStackAnalyzer {
    /// Create a batch analyzer for the given pointer width.
    #[must_use]
    pub const fn new(pointer_size: u32) -> Self {
        Self { pointer_size }
    }

    /// Analyse one function's instruction sequence and return its report.
    #[must_use]
    pub fn analyse(&self, instrs: &[StackInstr]) -> StackCleanupReport {
        let mut ana = StackCleanupAnalyzer::new(self.pointer_size);
        ana.observe_all(instrs);
        ana.finish()
    }

    /// Analyse all provided functions and return a map from function index to report.
    #[must_use]
    pub fn analyse_all(&self, functions: &[Vec<StackInstr>]) -> HashMap<usize, StackCleanupReport> {
        functions
            .iter()
            .enumerate()
            .map(|(i, instrs)| (i, self.analyse(instrs)))
            .collect()
    }

    /// Return statistics across all reports.
    #[must_use]
    pub fn stats(reports: &[StackCleanupReport]) -> CleanupStats {
        CleanupStats::compute(reports)
    }
}

// ---------------------------------------------------------------------------
// CleanupStats
// ---------------------------------------------------------------------------

/// Aggregate statistics over a batch of `StackCleanupReport` results.
#[derive(Debug, Clone, Default)]
pub struct CleanupStats {
    pub total: usize,
    pub caller_cleans: usize,
    pub callee_cleans: usize,
    pub no_stack_args: usize,
    pub mixed: usize,
    pub unknown: usize,
    pub avg_stack_arg_count: f64,
    pub max_stack_arg_count: u32,
}

impl CleanupStats {
    /// Compute from a slice of reports.
    #[must_use]
    pub fn compute(reports: &[StackCleanupReport]) -> Self {
        if reports.is_empty() {
            return Self::default();
        }
        let mut s = Self {
            total: reports.len(),
            ..Default::default()
        };
        let mut arg_sum = 0u64;
        for r in reports {
            match r.kind {
                CleanupKind::CallerCleans => s.caller_cleans += 1,
                CleanupKind::CalleeCleans => s.callee_cleans += 1,
                CleanupKind::NoStackArgs => s.no_stack_args += 1,
                CleanupKind::Mixed => s.mixed += 1,
                CleanupKind::Unknown => s.unknown += 1,
            }
            arg_sum += u64::from(r.stack_arg_count);
            s.max_stack_arg_count = s.max_stack_arg_count.max(r.stack_arg_count);
        }
        s.avg_stack_arg_count = arg_sum as f64 / reports.len() as f64;
        s
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn stdcall_fn() -> Vec<StackInstr> {
        vec![
            StackInstr::Push { size: 4 },   // push ebp
            StackInstr::FramePointerSetup,
            StackInstr::SpDecrement { bytes: 8 },
            StackInstr::SpRelAccess { offset: 8 },  // access arg1
            StackInstr::SpRelAccess { offset: 12 }, // access arg2
            StackInstr::SpIncrement { bytes: 8, after_call: false, offset: 20 },
            StackInstr::Pop { size: 4 },     // pop ebp
            StackInstr::Ret { n: 8, offset: 30 },   // RET 8 — callee cleans 2 args
        ]
    }

    fn cdecl_fn() -> Vec<StackInstr> {
        vec![
            StackInstr::Push { size: 4 },
            StackInstr::SpDecrement { bytes: 4 },
            StackInstr::SpRelAccess { offset: 8 },
            StackInstr::SpIncrement { bytes: 4, after_call: false, offset: 20 },
            StackInstr::Pop { size: 4 },
            StackInstr::Ret { n: 0, offset: 30 },  // plain RET — caller cleans
        ]
    }

    #[test]
    fn test_callee_cleans() {
        let mut a = StackCleanupAnalyzer::new(4);
        for i in &stdcall_fn() { a.observe(i); }
        let r = a.finish();
        assert_eq!(r.kind, CleanupKind::CalleeCleans);
    }

    #[test]
    fn test_caller_cleans() {
        let mut a = StackCleanupAnalyzer::new(4);
        for i in &cdecl_fn() { a.observe(i); }
        let r = a.finish();
        // plain RET + sp_rel access → CallerCleans or NoStackArgs
        assert!(matches!(r.kind, CleanupKind::CallerCleans | CleanupKind::NoStackArgs));
    }

    #[test]
    fn test_inferred_arg_count_callee() {
        let instrs = vec![
            StackInstr::Ret { n: 16, offset: 0 },  // 16 / 4 = 4 args
        ];
        let r = BatchStackAnalyzer::new(4).analyse(&instrs);
        assert_eq!(r.stack_arg_count, 4);
    }

    #[test]
    fn test_inferred_arg_count_64bit() {
        let instrs = vec![
            StackInstr::Ret { n: 16, offset: 0 },  // 16 / 8 = 2 args
        ];
        let r = BatchStackAnalyzer::new(8).analyse(&instrs);
        assert_eq!(r.stack_arg_count, 2);
    }

    #[test]
    fn test_frame_layout() {
        let instrs = vec![
            StackInstr::Push { size: 8 },
            StackInstr::FramePointerSetup,
            StackInstr::SpDecrement { bytes: 32 },
            StackInstr::Ret { n: 0, offset: 0 },
        ];
        let r = BatchStackAnalyzer::new(8).analyse(&instrs);
        assert!(r.frame_layout.has_frame_pointer);
        assert_eq!(r.frame_layout.local_bytes, 32);
    }

    #[test]
    fn test_mixed_cleanup() {
        let instrs = vec![
            StackInstr::SpRelAccess { offset: 4 },
            StackInstr::Call,
            StackInstr::SpIncrement { bytes: 4, after_call: true, offset: 10 },
            StackInstr::Ret { n: 4, offset: 20 },
        ];
        let r = BatchStackAnalyzer::new(4).analyse(&instrs);
        assert_eq!(r.kind, CleanupKind::Mixed);
    }

    #[test]
    fn test_no_stack_args() {
        let instrs = vec![
            StackInstr::Ret { n: 0, offset: 0 },
        ];
        let r = BatchStackAnalyzer::new(8).analyse(&instrs);
        assert_eq!(r.kind, CleanupKind::NoStackArgs);
    }

    #[test]
    fn test_stack_delta_from_ret_n() {
        let d = StackDelta::from_ret_n(0, 8, 4);
        assert!(d.callee_pops);
        assert_eq!(d.inferred_arg_count, 2);
        assert_eq!(d.stack_arg_bytes(), 8);
    }

    #[test]
    fn test_stack_delta_plain_ret() {
        let d = StackDelta::from_ret(0, 8);
        assert!(!d.callee_pops);
        assert_eq!(d.inferred_arg_count, 0);
    }

    #[test]
    fn test_batch_analyse_all() {
        let b = BatchStackAnalyzer::new(4);
        let fns = vec![stdcall_fn(), cdecl_fn()];
        let reports = b.analyse_all(&fns);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn test_cleanup_stats() {
        let b = BatchStackAnalyzer::new(4);
        let fns = vec![stdcall_fn(), cdecl_fn()];
        let reports: Vec<StackCleanupReport> = fns.iter().map(|f| b.analyse(f)).collect();
        let stats = BatchStackAnalyzer::stats(&reports);
        assert_eq!(stats.total, 2);
    }

    #[test]
    fn test_possibly_variadic_mixed() {
        let r = StackCleanupReport {
            kind: CleanupKind::Mixed,
            ret_sites: vec![],
            caller_adjustments: vec![],
            stack_arg_count: 2,
            frame_layout: StackFrameLayout::default(),
            pointer_size: 4,
        };
        assert!(r.possibly_variadic());
    }

    #[test]
    fn test_summary_not_empty() {
        let b = BatchStackAnalyzer::new(8);
        let r = b.analyse(&[StackInstr::Ret { n: 0, offset: 0 }]);
        assert!(!r.summary().is_empty());
    }

    // Regression: a tail-calling function that never surfaces an explicit
    // RET/RETN instruction (e.g. it ends in a `jmp` to another function)
    // used to be reported as `Unknown` even when there was strong
    // caller-cleanup evidence from its own call sites. Absence of a RET must
    // not override real evidence.
    #[test]
    fn test_no_ret_site_but_caller_adjustment_is_not_unknown() {
        let instrs = vec![
            StackInstr::Call,
            StackInstr::SpIncrement { bytes: 8, after_call: true, offset: 4 },
            // no Ret instruction observed at all (tail call / truncated view)
        ];
        let r = BatchStackAnalyzer::new(8).analyse(&instrs);
        assert_eq!(r.kind, CleanupKind::CallerCleans);
    }

    // Regression companion: with genuinely zero evidence (no rets, no caller
    // adjustments, no stack-relative accesses) the verdict must still be
    // Unknown, not NoStackArgs — there's no basis to conclude either way.
    #[test]
    fn test_truly_no_evidence_is_unknown() {
        let instrs = vec![StackInstr::Other, StackInstr::FramePointerSetup];
        let r = BatchStackAnalyzer::new(8).analyse(&instrs);
        assert_eq!(r.kind, CleanupKind::Unknown);
    }

    #[test]
    fn test_possibly_variadic_large_stack_arg_count() {
        // Mixed-free but > 6 stack args also signals possible variadic use.
        let r = StackCleanupReport {
            kind: CleanupKind::CallerCleans,
            ret_sites: vec![],
            caller_adjustments: vec![],
            stack_arg_count: 7,
            frame_layout: StackFrameLayout::default(),
            pointer_size: 8,
        };
        assert!(r.possibly_variadic());
    }

    #[test]
    fn test_red_zone_candidate_detected() {
        let instrs = vec![
            StackInstr::SpRelAccess { offset: -8 }, // negative offset, no prior alloc/push
            StackInstr::Ret { n: 0, offset: 4 },
        ];
        let r = BatchStackAnalyzer::new(8).analyse(&instrs);
        assert!(r.frame_layout.uses_red_zone);
    }

    #[test]
    fn test_cleanup_kind_display() {
        assert_eq!(CleanupKind::CallerCleans.to_string(), "CallerCleans");
        assert_eq!(CleanupKind::CalleeCleans.to_string(), "CalleeCleans");
        assert_eq!(CleanupKind::NoStackArgs.to_string(), "NoStackArgs");
        assert_eq!(CleanupKind::Mixed.to_string(), "Mixed");
        assert_eq!(CleanupKind::Unknown.to_string(), "Unknown");
    }
}
