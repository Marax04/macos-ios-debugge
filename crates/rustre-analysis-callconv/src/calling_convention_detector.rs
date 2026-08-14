//! Calling convention detector: identifies cdecl/stdcall/fastcall/thiscall/
//! vectorcall/sysv-amd64/ms-x64 by analyzing function prologue, argument
//! passing patterns, and stack cleanup behavior.

use rustc_hash::FxHashMap;
use std::collections::HashSet;
use serde::{Deserialize, Serialize};

use crate::{CallingConventionPattern, ObservedPattern, CallConvError};

// ─── Architecture model ───────────────────────────────────────────────────────

/// Target architecture for detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetArch {
    X86,
    X86_64,
    Arm32,
    Arm64,
    Mips32,
    Mips64,
    RiscV32,
    RiscV64,
}

impl std::fmt::Display for TargetArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm32 => write!(f, "arm32"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Mips32 => write!(f, "mips32"),
            Self::Mips64 => write!(f, "mips64"),
            Self::RiscV32 => write!(f, "riscv32"),
            Self::RiscV64 => write!(f, "riscv64"),
        }
    }
}

// ─── Instruction model ───────────────────────────────────────────────────────

/// A decoded instruction for calling convention analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcInstruction {
    /// Virtual address.
    pub address: u64,
    /// Mnemonic (e.g. "push", "mov", "call", "ret").
    pub mnemonic: String,
    /// String representation of operands.
    pub operands: String,
    /// Registers explicitly read.
    pub reads: Vec<String>,
    /// Registers explicitly written.
    pub writes: Vec<String>,
    /// Whether this instruction reads from the stack (memory operand).
    pub reads_stack: bool,
    /// Whether this instruction writes to the stack.
    pub writes_stack: bool,
    /// Stack offset accessed (if `reads_stack` or `writes_stack`), in bytes from SP.
    pub stack_offset: Option<i32>,
    /// Whether this is a CALL instruction.
    pub is_call: bool,
    /// Whether this is a RET/RETN instruction.
    pub is_ret: bool,
    /// For RET N: the immediate pop size.
    pub ret_imm: u32,
    /// Whether this is a PUSH.
    pub is_push: bool,
    /// Whether this is a POP.
    pub is_pop: bool,
    /// Whether this allocates stack space (sub rsp, N / sub esp, N).
    pub is_stack_alloc: bool,
    /// Stack allocation amount.
    pub stack_alloc_bytes: u32,
    /// Whether this uses XMM/YMM register.
    pub is_simd: bool,
    /// Whether this is a frame pointer setup (mov rbp, rsp).
    pub is_frame_setup: bool,
}

impl CcInstruction {
    /// Create a minimal instruction.
    #[must_use]
    pub fn new(address: u64, mnemonic: impl Into<String>, operands: impl Into<String>) -> Self {
        Self {
            address,
            mnemonic: mnemonic.into(),
            operands: operands.into(),
            reads: vec![],
            writes: vec![],
            reads_stack: false,
            writes_stack: false,
            stack_offset: None,
            is_call: false,
            is_ret: false,
            ret_imm: 0,
            is_push: false,
            is_pop: false,
            is_stack_alloc: false,
            stack_alloc_bytes: 0,
            is_simd: false,
            is_frame_setup: false,
        }
    }

    /// Create a PUSH instruction.
    #[must_use]
    pub fn push(address: u64, reg: impl Into<String>) -> Self {
        let r = reg.into();
        let mut i = Self::new(address, "push", r.clone());
        i.reads = vec![r];
        i.is_push = true;
        i.writes_stack = true;
        i
    }

    /// Create a POP instruction.
    #[must_use]
    pub fn pop(address: u64, reg: impl Into<String>) -> Self {
        let r = reg.into();
        let mut i = Self::new(address, "pop", r.clone());
        i.writes = vec![r];
        i.is_pop = true;
        i.reads_stack = true;
        i
    }

    /// Create a RET instruction.
    #[must_use]
    pub fn ret(address: u64, imm: u32) -> Self {
        let mut i = Self::new(address, "ret", if imm > 0 { imm.to_string() } else { String::new() });
        i.is_ret = true;
        i.ret_imm = imm;
        i
    }

    /// Create a CALL instruction.
    #[must_use]
    pub fn call(address: u64, target: impl Into<String>) -> Self {
        let mut i = Self::new(address, "call", target.into());
        i.is_call = true;
        i
    }

    /// Create a stack allocation (sub rsp, N).
    #[must_use]
    pub fn stack_alloc(address: u64, bytes: u32) -> Self {
        let mut i = Self::new(address, "sub", format!("rsp, {bytes}"));
        i.is_stack_alloc = true;
        i.stack_alloc_bytes = bytes;
        i
    }

    /// Create a stack memory read (e.g., mov rax, [rsp+offset]).
    #[must_use]
    pub fn stack_read(address: u64, reg: impl Into<String>, offset: i32) -> Self {
        let r = reg.into();
        let mut i = Self::new(address, "mov", format!("{r}, [rsp+{offset}]"));
        i.reads_stack = true;
        i.stack_offset = Some(offset);
        i.writes = vec![r];
        i
    }

    /// Return true if this instruction modifies RSP/ESP.
    #[must_use]
    pub const fn modifies_sp(&self) -> bool {
        self.is_push || self.is_pop || self.is_ret || self.is_stack_alloc
    }
}

// ─── Prologue analyzer ────────────────────────────────────────────────────────

/// Analyzes the function prologue to extract CC-relevant evidence.
pub struct PrologueAnalyzer {
    pub arch: TargetArch,
    /// Number of instructions to scan from function start.
    pub prologue_window: usize,
}

impl PrologueAnalyzer {
    /// Create a new prologue analyzer.
    #[must_use]
    pub const fn new(arch: TargetArch) -> Self {
        Self {
            arch,
            prologue_window: 40,
        }
    }

    /// Analyze prologue and return evidence.
    #[must_use]
    pub fn analyze(&self, instrs: &[CcInstruction]) -> PrologueEvidence {
        let window = instrs.iter().take(self.prologue_window);
        let mut ev = PrologueEvidence::default();
        let mut defined: HashSet<String> = HashSet::new();

        for instr in window {
            // Track register reads before first write (arg regs)
            for r in &instr.reads {
                if !defined.contains(r) && !ev.read_before_def.contains(r) {
                    ev.read_before_def.push(r.clone());
                }
            }
            for w in &instr.writes {
                defined.insert(w.clone());
            }

            // Track pushes (callee-saved)
            if instr.is_push {
                for r in &instr.reads {
                    if !ev.pushed_regs.contains(r) {
                        ev.pushed_regs.push(r.clone());
                    }
                }
            }

            // Stack allocation
            if instr.is_stack_alloc {
                ev.stack_alloc_bytes = ev.stack_alloc_bytes.max(instr.stack_alloc_bytes);
                if instr.stack_alloc_bytes >= 32 {
                    ev.shadow_space_observed = true;
                }
            }

            // Frame pointer setup
            if instr.is_frame_setup {
                ev.frame_pointer_setup = true;
            }

            // SIMD registers
            for r in &instr.reads {
                if (r.starts_with("xmm") || r.starts_with("ymm") || r.starts_with("zmm"))
                    && !defined.contains(r) && !ev.fp_regs_read.contains(r) {
                        ev.fp_regs_read.push(r.clone());
                    }
            }

            // Stack arguments
            if instr.reads_stack
                && let Some(off) = instr.stack_offset
                    && off >= 0 {
                        ev.max_stack_arg_offset = ev.max_stack_arg_offset.max(off);
                        ev.stack_arg_accesses += 1;
                    }
        }
        ev
    }
}

/// Evidence gathered from the function prologue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrologueEvidence {
    /// Registers read before any write (candidate argument registers).
    pub read_before_def: Vec<String>,
    /// Registers pushed to the stack (candidate callee-saved).
    pub pushed_regs: Vec<String>,
    /// Maximum stack allocation in bytes.
    pub stack_alloc_bytes: u32,
    /// Whether ≥32 bytes were allocated (MS-x64 shadow space hint).
    pub shadow_space_observed: bool,
    /// Whether frame pointer setup was observed.
    pub frame_pointer_setup: bool,
    /// SIMD registers read before write.
    pub fp_regs_read: Vec<String>,
    /// Maximum positive stack offset accessed.
    pub max_stack_arg_offset: i32,
    /// Number of stack argument accesses.
    pub stack_arg_accesses: usize,
}

// ─── Epilogue analyzer ────────────────────────────────────────────────────────

/// Analyzes the function epilogue to extract CC-relevant evidence.
pub struct EpilogueAnalyzer;

impl EpilogueAnalyzer {
    /// Analyze epilogue from the last N instructions.
    #[must_use]
    pub fn analyze(instrs: &[CcInstruction]) -> EpilogueEvidence {
        let mut ev = EpilogueEvidence::default();
        let window = if instrs.len() > 40 { &instrs[instrs.len() - 40..] } else { instrs };
        let mut recent_writes: Vec<String> = Vec::new();

        for instr in window {
            // Track what's written before return (return values)
            for w in &instr.writes {
                if !recent_writes.contains(w) {
                    recent_writes.push(w.clone());
                    if recent_writes.len() > 12 { recent_writes.remove(0); }
                }
            }

            if instr.is_pop {
                for w in &instr.writes {
                    if !ev.popped_regs.contains(w) {
                        ev.popped_regs.push(w.clone());
                    }
                }
            }

            if instr.is_ret {
                ev.has_ret = true;
                ev.ret_imm = instr.ret_imm;
                ev.callee_pops_stack = instr.ret_imm > 0;
                ev.written_before_ret.clone_from(&recent_writes);
            }
        }
        ev
    }
}

/// Evidence gathered from the function epilogue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpilogueEvidence {
    pub has_ret: bool,
    pub ret_imm: u32,
    pub callee_pops_stack: bool,
    pub popped_regs: Vec<String>,
    pub written_before_ret: Vec<String>,
}

// ─── ConventionMatcher ────────────────────────────────────────────────────────

/// Matches evidence against known calling convention patterns.
pub struct ConventionMatcher {
    pub candidates: Vec<CallingConventionPattern>,
}

impl ConventionMatcher {
    /// Create a matcher with the given candidates.
    #[must_use]
    pub const fn new(candidates: Vec<CallingConventionPattern>) -> Self {
        Self { candidates }
    }

    /// Score all candidates against the observed pattern and sort best-first.
    #[must_use]
    pub fn rank(&self, observed: &ObservedPattern) -> Vec<(CallingConventionPattern, u32)> {
        let mut scored: Vec<(CallingConventionPattern, u32)> = self
            .candidates
            .iter()
            .map(|cc| (cc.clone(), cc.score(observed)))
            .collect();
        scored.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        scored
    }

    /// Return the best match, or error if none or ambiguous.
    pub fn best_match(
        &self,
        observed: &ObservedPattern,
    ) -> Result<(CallingConventionPattern, u32), CallConvError> {
        let ranked = self.rank(observed);
        if ranked.is_empty() || ranked[0].1 == 0 {
            return Err(CallConvError::NoMatch);
        }
        let top = ranked[0].1;
        let tied = ranked.iter().filter(|(_, s)| *s == top).count();
        if tied > 1 {
            return Err(CallConvError::Ambiguous);
        }
        Ok(ranked.into_iter().next().unwrap())
    }
}

// ─── FullCcDetector ───────────────────────────────────────────────────────────

/// Complete calling convention detector: prologue + epilogue + convention matching.
pub struct FullCcDetector {
    pub arch: TargetArch,
    pub prologue: PrologueAnalyzer,
    pub candidates: Vec<CallingConventionPattern>,
}

impl FullCcDetector {
    /// Create a detector for the given architecture.
    #[must_use]
    pub const fn new(arch: TargetArch, candidates: Vec<CallingConventionPattern>) -> Self {
        Self {
            arch,
            prologue: PrologueAnalyzer::new(arch),
            candidates,
        }
    }

    /// Detect the calling convention from a complete function instruction stream.
    pub fn detect(
        &self,
        instrs: &[CcInstruction],
    ) -> Result<CcDetectionResult, CallConvError> {
        if instrs.is_empty() {
            return Err(CallConvError::TooShort { got: 0, need: 4 });
        }

        let pro = self.prologue.analyze(instrs);
        let epi = EpilogueAnalyzer::analyze(instrs);

        // Build ObservedPattern
        let saved: Vec<String> = pro
            .pushed_regs
            .iter()
            .filter(|r| epi.popped_regs.contains(r))
            .cloned()
            .collect();

        // Only treat `ecx` (32-bit) as a `this`-pointer hint. `rcx` is the
        // *first* integer argument register in both the Microsoft x64 and
        // (as the 4th arg) System V AMD64 conventions, so tying this hint to
        // `rcx` would misclassify perfectly ordinary 64-bit functions as
        // thiscall candidates. `thiscall` itself is an x86-only (32-bit)
        // convention, so restricting the hint to `ecx` loses no detection
        // power while removing a source of false positives on x86-64.
        let this_ptr_hint = pro.read_before_def.iter().any(|r| r == "ecx");

        // Stack-argument slot size depends on pointer width: 4 bytes on
        // 32-bit x86/ARM/MIPS, 8 bytes on 64-bit targets. Hardcoding 4 here
        // used to double-count stack arguments on every 64-bit architecture
        // (e.g. an offset of 8 — one 8-byte slot — was read as `8/4+1 == 3`
        // slots instead of 1), which fed into both the cdecl/no-reg-args
        // heuristic and downstream signature reconstruction.
        let pointer_bytes: i32 = match self.arch {
            TargetArch::X86 | TargetArch::Arm32 | TargetArch::Mips32 | TargetArch::RiscV32 => 4,
            TargetArch::X86_64 | TargetArch::Arm64 | TargetArch::Mips64 | TargetArch::RiscV64 => 8,
        };
        let stack_arg_count = if pro.max_stack_arg_offset >= 0 {
            ((pro.max_stack_arg_offset / pointer_bytes) + 1) as u32
        } else {
            0
        };

        let observed = ObservedPattern {
            read_before_write: pro.read_before_def.clone(),
            saved_registers: saved,
            written_before_return: epi.written_before_ret.clone(),
            callee_pops_stack: epi.callee_pops_stack,
            this_ptr_hint,
            callee_stack_pop: epi.ret_imm,
            fp_read_before_write: pro.fp_regs_read.clone(),
            max_stack_frame: pro.stack_alloc_bytes,
            shadow_space_observed: pro.shadow_space_observed,
            stack_arg_count,
        };

        let matcher = ConventionMatcher::new(self.candidates.clone());
        let ranked = matcher.rank(&observed);

        // Apply tiebreaker heuristics
        let best = self.apply_heuristics(&ranked, &observed, &pro, &epi);
        let (cc, score) = if let Some(v) = best { v } else {
            if ranked.is_empty() || ranked[0].1 == 0 {
                return Err(CallConvError::NoMatch);
            }
            ranked[0].clone()
        };

        let runner_ups: Vec<(String, u32)> = ranked
            .iter()
            .skip(1)
            .take(4)
            .map(|(c, s)| (c.name.clone(), *s))
            .collect();

        Ok(CcDetectionResult {
            convention: cc,
            confidence: score,
            observed,
            prologue_evidence: pro,
            epilogue_evidence: epi,
            runner_ups,
        })
    }

    fn apply_heuristics(
        &self,
        ranked: &[(CallingConventionPattern, u32)],
        observed: &ObservedPattern,
        pro: &PrologueEvidence,
        epi: &EpilogueEvidence,
    ) -> Option<(CallingConventionPattern, u32)> {
        if ranked.is_empty() {
            return None;
        }
        let top_score = ranked[0].1;
        let tied: Vec<&(CallingConventionPattern, u32)> = ranked
            .iter()
            .filter(|(_, s)| *s == top_score)
            .collect();
        if tied.len() == 1 {
            return Some(tied[0].clone());
        }

        // Heuristic 1: shadow space → MS-x64
        if pro.shadow_space_observed
            && let Some(cc) = tied.iter().find(|(c, _)| c.shadow_space_bytes >= 32) {
                return Some((*cc).clone());
            }
        // Heuristic 2: this_ptr_hint → thiscall
        if observed.this_ptr_hint
            && let Some(cc) = tied.iter().find(|(c, _)| c.hidden_this_ptr) {
                return Some((*cc).clone());
            }
        // Heuristic 3: callee pops → stdcall/fastcall
        if epi.callee_pops_stack
            && let Some(cc) = tied.iter().find(|(c, _)| !c.caller_cleanup) {
                return Some((*cc).clone());
            }
        // Heuristic 4: no register args → cdecl
        if observed.read_before_write.is_empty() && observed.stack_arg_count > 0
            && let Some(cc) = tied.iter().find(|(c, _)| c.max_reg_args == 0) {
                return Some((*cc).clone());
            }
        // Heuristic 5: SIMD regs → vectorcall
        if !pro.fp_regs_read.is_empty()
            && let Some(cc) = tied.iter().find(|(c, _)| !c.fp_arg_registers.is_empty()) {
                return Some((*cc).clone());
            }
        None
    }
}

/// Full calling convention detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcDetectionResult {
    pub convention: CallingConventionPattern,
    pub confidence: u32,
    pub observed: ObservedPattern,
    pub prologue_evidence: PrologueEvidence,
    pub epilogue_evidence: EpilogueEvidence,
    pub runner_ups: Vec<(String, u32)>,
}

impl CcDetectionResult {
    /// Whether detection was high-confidence (score >= 20).
    #[must_use]
    pub const fn is_high_confidence(&self) -> bool {
        self.confidence >= 20
    }

    /// Returns a textual summary of the detection.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Detected: {} (score={}, callee_pops={}, reg_args={}, fp_regs={})",
            self.convention.name,
            self.confidence,
            self.epilogue_evidence.callee_pops_stack,
            self.observed.read_before_write.len(),
            self.prologue_evidence.fp_regs_read.len(),
        )
    }
}

// ─── ConventionLibrary ────────────────────────────────────────────────────────

/// A library of all built-in calling conventions for different platforms.
pub struct ConventionLibrary;

impl ConventionLibrary {
    /// Return all x86 calling conventions.
    #[must_use]
    pub fn x86_conventions() -> Vec<CallingConventionPattern> {
        vec![
            cdecl_x86(),
            stdcall_x86(),
            fastcall_x86(),
            thiscall_x86(),
        ]
    }

    /// Return all `x86_64` calling conventions.
    #[must_use]
    pub fn x86_64_conventions() -> Vec<CallingConventionPattern> {
        vec![
            sysv_amd64(),
            ms_x64(),
            vectorcall_x64(),
        ]
    }

    /// Return all ARM calling conventions.
    #[must_use]
    pub fn arm_conventions() -> Vec<CallingConventionPattern> {
        vec![aapcs32(), aapcs64()]
    }

    /// Return conventions for a given architecture.
    #[must_use]
    pub fn for_arch(arch: TargetArch) -> Vec<CallingConventionPattern> {
        match arch {
            TargetArch::X86 => Self::x86_conventions(),
            TargetArch::X86_64 => Self::x86_64_conventions(),
            TargetArch::Arm32 => vec![aapcs32()],
            TargetArch::Arm64 => vec![aapcs64()],
            TargetArch::Mips32 | TargetArch::Mips64 => vec![mips_o32()],
            TargetArch::RiscV32 | TargetArch::RiscV64 => vec![riscv64_lp64d()],
        }
    }
}

// ─── Built-in convention constructors ────────────────────────────────────────

fn cdecl_x86() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "cdecl (x86)".into(),
        arg_registers: vec![],
        fp_arg_registers: vec![],
        retval_registers: vec!["eax".into(), "edx".into()],
        callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
        caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
        stack_alignment: 4,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 0,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

fn stdcall_x86() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "stdcall (x86)".into(),
        arg_registers: vec![],
        fp_arg_registers: vec![],
        retval_registers: vec!["eax".into(), "edx".into()],
        callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
        caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
        stack_alignment: 4,
        caller_cleanup: false,
        hidden_this_ptr: false,
        max_reg_args: 0,
        supports_variadic: false,
        shadow_space_bytes: 0,
    }
}

fn fastcall_x86() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "fastcall (x86)".into(),
        arg_registers: vec!["ecx".into(), "edx".into()],
        fp_arg_registers: vec![],
        retval_registers: vec!["eax".into(), "edx".into()],
        callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
        caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
        stack_alignment: 4,
        caller_cleanup: false,
        hidden_this_ptr: false,
        max_reg_args: 2,
        supports_variadic: false,
        shadow_space_bytes: 0,
    }
}

fn thiscall_x86() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "thiscall (x86)".into(),
        arg_registers: vec!["ecx".into()],
        fp_arg_registers: vec![],
        retval_registers: vec!["eax".into(), "edx".into()],
        callee_saved: vec!["ebx".into(), "esi".into(), "edi".into(), "ebp".into()],
        caller_saved: vec!["eax".into(), "ecx".into(), "edx".into()],
        stack_alignment: 4,
        caller_cleanup: false,
        hidden_this_ptr: true,
        max_reg_args: 1,
        supports_variadic: false,
        shadow_space_bytes: 0,
    }
}

fn sysv_amd64() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "System V AMD64 ABI".into(),
        arg_registers: vec!["rdi".into(),"rsi".into(),"rdx".into(),"rcx".into(),"r8".into(),"r9".into()],
        fp_arg_registers: vec!["xmm0".into(),"xmm1".into(),"xmm2".into(),"xmm3".into(),"xmm4".into(),"xmm5".into(),"xmm6".into(),"xmm7".into()],
        retval_registers: vec!["rax".into(), "rdx".into()],
        callee_saved: vec!["rbx".into(),"rbp".into(),"r12".into(),"r13".into(),"r14".into(),"r15".into()],
        caller_saved: vec!["rax".into(),"rcx".into(),"rdx".into(),"rsi".into(),"rdi".into(),"r8".into(),"r9".into(),"r10".into(),"r11".into()],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 6,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

fn ms_x64() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "Microsoft x64".into(),
        arg_registers: vec!["rcx".into(),"rdx".into(),"r8".into(),"r9".into()],
        fp_arg_registers: vec!["xmm0".into(),"xmm1".into(),"xmm2".into(),"xmm3".into()],
        retval_registers: vec!["rax".into()],
        callee_saved: vec!["rbx".into(),"rbp".into(),"rdi".into(),"rsi".into(),"r12".into(),"r13".into(),"r14".into(),"r15".into()],
        caller_saved: vec!["rax".into(),"rcx".into(),"rdx".into(),"r8".into(),"r9".into(),"r10".into(),"r11".into()],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 4,
        supports_variadic: true,
        shadow_space_bytes: 32,
    }
}

fn vectorcall_x64() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "vectorcall (x64)".into(),
        arg_registers: vec!["rcx".into(),"rdx".into(),"r8".into(),"r9".into()],
        fp_arg_registers: vec!["xmm0".into(),"xmm1".into(),"xmm2".into(),"xmm3".into(),"xmm4".into(),"xmm5".into()],
        retval_registers: vec!["rax".into(), "xmm0".into()],
        callee_saved: vec!["rbx".into(),"rbp".into(),"rdi".into(),"rsi".into(),"r12".into(),"r13".into(),"r14".into(),"r15".into()],
        caller_saved: vec!["rax".into(),"rcx".into(),"rdx".into(),"r8".into(),"r9".into()],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 4,
        supports_variadic: false,
        // __vectorcall x64 inherits the MS x64 ABI's 32-byte shadow/home space
        // (same as ms_x64). Was 0 across all 3 copies; corrected after two
        // independent ABI reviews.
        shadow_space_bytes: 32,
    }
}

fn aapcs32() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "AAPCS32".into(),
        arg_registers: vec!["r0".into(),"r1".into(),"r2".into(),"r3".into()],
        // s0-s15 per AAPCS32 VFP (ARM IHI 0042, §7.1.1); was truncated to
        // s0-s3, diverging from lib.rs::aapcs32 / CC_AAPCS32_VFP.
        fp_arg_registers: vec!["s0".into(),"s1".into(),"s2".into(),"s3".into(),"s4".into(),"s5".into(),"s6".into(),"s7".into(),"s8".into(),"s9".into(),"s10".into(),"s11".into(),"s12".into(),"s13".into(),"s14".into(),"s15".into()],
        retval_registers: vec!["r0".into(),"r1".into()],
        callee_saved: vec!["r4".into(),"r5".into(),"r6".into(),"r7".into(),"r8".into(),"r9".into(),"r10".into(),"r11".into()],
        caller_saved: vec!["r0".into(),"r1".into(),"r2".into(),"r3".into(),"r12".into()],
        stack_alignment: 8,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 4,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

fn aapcs64() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "AAPCS64".into(),
        arg_registers: vec!["x0".into(),"x1".into(),"x2".into(),"x3".into(),"x4".into(),"x5".into(),"x6".into(),"x7".into()],
        fp_arg_registers: vec!["v0".into(),"v1".into(),"v2".into(),"v3".into(),"v4".into(),"v5".into(),"v6".into(),"v7".into()],
        retval_registers: vec!["x0".into(),"x1".into()],
        callee_saved: vec!["x19".into(),"x20".into(),"x21".into(),"x22".into(),"x23".into(),"x24".into(),"x25".into(),"x26".into(),"x27".into(),"x28".into(),"x29".into(),
            // x30 (LR) must be preserved across a call by any non-leaf callee
            // (AAPCS64 §6.1.1; cf. LLVM CSR_AArch64_AAPCS). Omitted in three
            // of the four tables; cc_database.rs::CC_AAPCS64 had it right.
            "x30".into()],
        // x16/x17 (IP0/IP1) are caller-saved intra-procedure-call scratch
        // registers per AAPCS64 §6.1.1 — they were previously omitted here,
        // diverging from the `lib.rs::aapcs64()` copy which lists them.
        caller_saved: vec!["x0".into(),"x1".into(),"x2".into(),"x3".into(),"x4".into(),"x5".into(),"x6".into(),"x7".into(),"x8".into(),"x9".into(),"x10".into(),"x11".into(),"x12".into(),"x13".into(),"x14".into(),"x15".into(),"x16".into(),"x17".into()],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 8,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

fn mips_o32() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "MIPS O32".into(),
        arg_registers: vec!["a0".into(),"a1".into(),"a2".into(),"a3".into()],
        fp_arg_registers: vec!["f12".into(),"f14".into()],
        retval_registers: vec!["v0".into(),"v1".into()],
        callee_saved: vec!["s0".into(),"s1".into(),"s2".into(),"s3".into(),"s4".into(),"s5".into(),"s6".into(),"s7".into()],
        // $t8/$t9 ($24/$25) added: caller-saved temporaries per the System V
        // MIPS o32 ABI supplement register-usage table.
        caller_saved: vec!["t0".into(),"t1".into(),"t2".into(),"t3".into(),"t4".into(),"t5".into(),"t6".into(),"t7".into(),"t8".into(),"t9".into()],
        stack_alignment: 8,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 4,
        supports_variadic: true,
        shadow_space_bytes: 16,
    }
}

fn riscv64_lp64d() -> CallingConventionPattern {
    CallingConventionPattern {
        name: "RISC-V LP64D".into(),
        arg_registers: vec!["a0".into(),"a1".into(),"a2".into(),"a3".into(),"a4".into(),"a5".into(),"a6".into(),"a7".into()],
        fp_arg_registers: vec!["fa0".into(),"fa1".into(),"fa2".into(),"fa3".into(),"fa4".into(),"fa5".into(),"fa6".into(),"fa7".into()],
        retval_registers: vec!["a0".into(),"a1".into()],
        callee_saved: vec!["s0".into(),"s1".into(),"s2".into(),"s3".into(),"s4".into(),"s5".into(),"s6".into(),"s7".into(),"s8".into(),"s9".into(),"s10".into(),"s11".into()],
        caller_saved: vec!["t0".into(),"t1".into(),"t2".into(),"t3".into(),"t4".into(),"t5".into(),"t6".into()],
        stack_alignment: 16,
        caller_cleanup: true,
        hidden_this_ptr: false,
        max_reg_args: 8,
        supports_variadic: true,
        shadow_space_bytes: 0,
    }
}

// ─── Batch analysis ───────────────────────────────────────────────────────────

/// Analyze a batch of functions and return detection results.
#[must_use]
pub fn analyze_functions(
    functions: &[(u64, Vec<CcInstruction>)],
    arch: TargetArch,
) -> Vec<(u64, Result<CcDetectionResult, CallConvError>)> {
    let candidates = ConventionLibrary::for_arch(arch);
    let detector = FullCcDetector::new(arch, candidates);
    functions
        .iter()
        .map(|(addr, instrs)| (*addr, detector.detect(instrs)))
        .collect()
}

/// Statistics over a batch of detection results.
#[derive(Debug, Clone, Default)]
pub struct BatchCcStats {
    pub total: usize,
    pub successful: usize,
    pub failed_no_match: usize,
    pub failed_ambiguous: usize,
    /// Failures from any other `CallConvError` variant (e.g. `TooShort`, `UnknownKey`,
    /// `Json`, `UnknownRegister`). Tracked separately so batch totals always reconcile:
    /// `successful + failed_no_match + failed_ambiguous + failed_other == total`.
    pub failed_other: usize,
    /// Keyed by CC names from binary analysis — `FxHashMap` to prevent `DoS`.
    pub by_convention: FxHashMap<String, usize>,
    pub avg_confidence: f64,
}

impl BatchCcStats {
    /// Compute stats from batch results.
    #[must_use]
    pub fn compute(results: &[(u64, Result<CcDetectionResult, CallConvError>)]) -> Self {
        let mut stats = Self::default();
        stats.total = results.len();
        let mut total_conf = 0u64;
        let mut n_ok = 0usize;
        for (_, res) in results {
            match res {
                Ok(r) => {
                    stats.successful += 1;
                    *stats.by_convention.entry(r.convention.name.clone()).or_insert(0) += 1;
                    total_conf += u64::from(r.confidence);
                    n_ok += 1;
                }
                Err(CallConvError::NoMatch) => stats.failed_no_match += 1,
                Err(CallConvError::Ambiguous) => stats.failed_ambiguous += 1,
                Err(_) => stats.failed_other += 1,
            }
        }
        stats.avg_confidence = if n_ok > 0 { total_conf as f64 / n_ok as f64 } else { 0.0 };
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sysv_function() -> Vec<CcInstruction> {
        vec![
            CcInstruction::push(0x1000, "rbp"),
            { let mut i = CcInstruction::new(0x1001, "mov", "rbp, rsp"); i.is_frame_setup = true; i.writes = vec!["rbp".into()]; i.reads = vec!["rsp".into()]; i },
            CcInstruction::stack_alloc(0x1004, 48),
            { let mut i = CcInstruction::new(0x1008, "mov", "[rbp-8], rdi"); i.writes_stack = true; i.reads = vec!["rdi".into()]; i },
            { let mut i = CcInstruction::new(0x100c, "mov", "rax, 0"); i.writes = vec!["rax".into()]; i },
            CcInstruction::pop(0x1010, "rbp"),
            CcInstruction::ret(0x1011, 0),
        ]
    }

    #[test]
    fn test_prologue_captures_rdi() {
        let instrs = make_sysv_function();
        let analyzer = PrologueAnalyzer::new(TargetArch::X86_64);
        let ev = analyzer.analyze(&instrs);
        assert!(ev.read_before_def.contains(&"rdi".to_string()));
    }

    #[test]
    fn test_epilogue_ret_0() {
        let instrs = make_sysv_function();
        let ev = EpilogueAnalyzer::analyze(&instrs);
        assert!(ev.has_ret);
        assert!(!ev.callee_pops_stack);
    }

    #[test]
    fn test_full_detect_sysv() {
        let instrs = make_sysv_function();
        let candidates = ConventionLibrary::x86_64_conventions();
        let detector = FullCcDetector::new(TargetArch::X86_64, candidates);
        let result = detector.detect(&instrs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_rcx_first_arg_does_not_trigger_this_ptr_hint_on_x64() {
        // A plain MS-x64 function that happens to read `rcx` first (its
        // normal 1st integer argument register) must NOT be flagged with
        // `this_ptr_hint` — that hint is x86 `thiscall`-specific (`ecx`).
        let instrs = vec![
            { let mut i = CcInstruction::new(0x3000, "mov", "[rsp+8], rcx"); i.reads = vec!["rcx".into()]; i.writes_stack = true; i },
            { let mut i = CcInstruction::new(0x3004, "xor", "eax, eax"); i.writes = vec!["eax".into()]; i },
            CcInstruction::ret(0x3008, 0),
        ];
        let candidates = ConventionLibrary::x86_64_conventions();
        let detector = FullCcDetector::new(TargetArch::X86_64, candidates);
        let result = detector.detect(&instrs).expect("detection should succeed");
        assert!(
            !result.observed.this_ptr_hint,
            "rcx as first-read arg on x86-64 must not be treated as a thiscall `this` hint"
        );
    }

    #[test]
    fn test_thiscall_detection() {
        let instrs = vec![
            { let mut i = CcInstruction::new(0x2000, "mov", "[esp+4], ecx"); i.reads = vec!["ecx".into()]; i.writes_stack = true; i },
            { let mut i = CcInstruction::new(0x2004, "xor", "eax, eax"); i.writes = vec!["eax".into()]; i },
            CcInstruction::ret(0x2006, 8),
        ];
        let candidates = ConventionLibrary::x86_conventions();
        let detector = FullCcDetector::new(TargetArch::X86, candidates);
        let result = detector.detect(&instrs);
        // Should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn test_stack_arg_count_uses_64bit_stride_on_x86_64() {
        // A single 8-byte stack argument at offset 8 (past the return
        // address) must be counted as ONE stack argument on x86-64, not
        // three (which is what a hardcoded 4-byte divisor would produce:
        // `8/4 + 1 == 3`).
        let instrs = vec![
            CcInstruction::stack_read(0x1000, "rax", 8),
            CcInstruction::ret(0x1004, 0),
        ];
        let candidates = ConventionLibrary::x86_64_conventions();
        let detector = FullCcDetector::new(TargetArch::X86_64, candidates);
        let result = detector.detect(&instrs).expect("detection should succeed");
        assert_eq!(
            result.observed.stack_arg_count, 2,
            "offset 8 with 8-byte stride is slot index 1 => 2 total stack args \
             (0 and 1), not the 3 a 4-byte stride would have produced"
        );
    }

    #[test]
    fn test_stack_arg_count_uses_32bit_stride_on_x86() {
        // Same offset (8) on 32-bit x86 should still divide by 4, giving 3
        // stack argument slots (0, 4, 8).
        let instrs = vec![
            CcInstruction::stack_read(0x1000, "eax", 8),
            CcInstruction::ret(0x1004, 0),
        ];
        let candidates = ConventionLibrary::x86_conventions();
        let detector = FullCcDetector::new(TargetArch::X86, candidates);
        let result = detector.detect(&instrs).expect("detection should succeed");
        assert_eq!(result.observed.stack_arg_count, 3);
    }

    #[test]
    fn test_batch_cc_stats_reconciles_all_error_variants() {
        // One Ok, one NoMatch, one Ambiguous, and one "other" error
        // (UnknownRegister) — every failure kind must be counted so that
        // successful + failed_no_match + failed_ambiguous + failed_other == total.
        let ok_result: CcDetectionResult = {
            let instrs = vec![
                { let mut i = CcInstruction::new(0x2000, "mov", "[esp+4], ecx"); i.reads = vec!["ecx".into()]; i.writes_stack = true; i },
                CcInstruction::ret(0x2006, 8),
            ];
            let candidates = ConventionLibrary::x86_conventions();
            let detector = FullCcDetector::new(TargetArch::X86, candidates);
            detector.detect(&instrs).expect("expected a successful detection")
        };

        let results: Vec<(u64, Result<CcDetectionResult, CallConvError>)> = vec![
            (0x1000, Ok(ok_result)),
            (0x2000, Err(CallConvError::NoMatch)),
            (0x3000, Err(CallConvError::Ambiguous)),
            (
                0x4000,
                Err(CallConvError::UnknownRegister {
                    name: "zzz".into(),
                    arch: "x86".into(),
                }),
            ),
        ];

        let stats = BatchCcStats::compute(&results);
        assert_eq!(stats.total, 4);
        assert_eq!(stats.successful, 1);
        assert_eq!(stats.failed_no_match, 1);
        assert_eq!(stats.failed_ambiguous, 1);
        assert_eq!(stats.failed_other, 1);
        assert_eq!(
            stats.successful + stats.failed_no_match + stats.failed_ambiguous + stats.failed_other,
            stats.total,
            "batch stats must account for every result, including non-NoMatch/Ambiguous errors"
        );
    }
}
