//! `function_decompiler.rs` — Single-function decompiler entry point.
//!
//! Handles:
//! - Entry-point identification
//! - Exception flow in function body
//! - Tail-call detection
//! - Recursive function handling
//! - Inlining decisions
//! - Signature recovery from calling convention
//! - Variadic function detection

use crate::{
    parse_hex_target, CallingConvention, DecompVariable, DecompiledFunction, DecompilerContext,
    DecompilerError, DecompOptions, IrLevel, VarStorage, VariableRecovery,
};
use crate::signature_recovery::recover_signature_auto;
use rustre_core::arch::Instruction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fmt;
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// CallKind — classification of a call instruction
// ─────────────────────────────────────────────────────────────────────────────

/// How a CALL is classified after analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallKind {
    /// Normal direct call to a concrete address.
    Direct,
    /// Indirect call through a register or memory operand.
    Indirect,
    /// Tail call (jump to another function as the last action).
    TailCall,
    /// Recursive call back into the function itself.
    Recursive,
    /// Library call (target is in an import table).
    LibraryCall,
    /// Inlined callee — the callee's body is folded in.
    Inlined,
}

impl fmt::Display for CallKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Indirect => write!(f, "indirect"),
            Self::TailCall => write!(f, "tail"),
            Self::Recursive => write!(f, "recursive"),
            Self::LibraryCall => write!(f, "library"),
            Self::Inlined => write!(f, "inlined"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallSite — enriched call-site description
// ─────────────────────────────────────────────────────────────────────────────

/// An annotated call site discovered during single-function decompilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Address of the call instruction.
    pub call_addr: u64,
    /// Target address (if statically known).
    pub target_addr: Option<u64>,
    /// Target symbol name (if known from imports/symbols).
    pub target_name: Option<String>,
    /// Classification of the call.
    pub kind: CallKind,
    /// Whether this call is guaranteed to not return.
    pub is_noreturn: bool,
    /// Number of arguments detected (heuristic).
    pub arg_count_hint: Option<usize>,
}

impl CallSite {
    #[must_use] 
    pub const fn direct(call_addr: u64, target: u64) -> Self {
        Self {
            call_addr,
            target_addr: Some(target),
            target_name: None,
            kind: CallKind::Direct,
            is_noreturn: false,
            arg_count_hint: None,
        }
    }

    #[must_use] 
    pub const fn indirect(call_addr: u64) -> Self {
        Self {
            call_addr,
            target_addr: None,
            target_name: None,
            kind: CallKind::Indirect,
            is_noreturn: false,
            arg_count_hint: None,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.target_name = Some(name.into());
        self
    }

    #[must_use] 
    pub const fn with_kind(mut self, kind: CallKind) -> Self {
        self.kind = kind;
        self
    }

    #[must_use] 
    pub const fn mark_noreturn(mut self) -> Self {
        self.is_noreturn = true;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExceptionFlow — exception handling in the function body
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a region of code protected by an exception handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRegion {
    /// Start address of the try block.
    pub try_start: u64,
    /// End address of the try block (exclusive).
    pub try_end: u64,
    /// Handler (catch / except) entry address.
    pub handler_addr: u64,
    /// Kind of exception handling construct.
    pub kind: ExceptionKind,
    /// Filter expression string (for SEH __except).
    pub filter: Option<String>,
}

/// The type of exception construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExceptionKind {
    /// Windows SEH `__try / __except`.
    SehExcept,
    /// Windows SEH `__try / __finally`.
    SehFinally,
    /// C++ `try / catch`.
    CppCatch,
    /// DWARF/GCC cleanup (.`gcc_except_table`).
    DwarfCleanup,
    /// LLVM LSDA landing pad.
    LlvmLandingPad,
    /// Unknown or unrecognised handler.
    Unknown,
}

impl fmt::Display for ExceptionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SehExcept => write!(f, "SEH_EXCEPT"),
            Self::SehFinally => write!(f, "SEH_FINALLY"),
            Self::CppCatch => write!(f, "CPP_CATCH"),
            Self::DwarfCleanup => write!(f, "DWARF_CLEANUP"),
            Self::LlvmLandingPad => write!(f, "LLVM_LP"),
            Self::Unknown => write!(f, "UNKNOWN_EH"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InliningDecision
// ─────────────────────────────────────────────────────────────────────────────

/// Criteria and result of an inlining decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InliningDecision {
    /// Target address of the call that may be inlined.
    pub target_addr: u64,
    /// Whether the callee should be inlined.
    pub should_inline: bool,
    /// Reason for the decision.
    pub reason: InliningReason,
    /// Estimated cost (instruction count of callee body).
    pub callee_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InliningReason {
    TooLarge { limit: usize, actual: usize },
    Recursive,
    ForcedByAttribute,
    SmallLeaf,
    AggressiveMode,
    Disabled,
    NoBody,
}

impl fmt::Display for InliningReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { limit, actual } => write!(f, "too large ({actual} > {limit})"),
            Self::Recursive => write!(f, "recursive"),
            Self::ForcedByAttribute => write!(f, "forced by attribute"),
            Self::SmallLeaf => write!(f, "small leaf"),
            Self::AggressiveMode => write!(f, "aggressive mode"),
            Self::Disabled => write!(f, "inlining disabled"),
            Self::NoBody => write!(f, "no body available"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureRecovery — calling-convention-based signature inference
// ─────────────────────────────────────────────────────────────────────────────

/// Recovered function signature after calling-convention analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredSignature {
    /// Inferred return type string.
    pub return_type: String,
    /// Recovered parameters in order.
    pub params: Vec<RecoveredParam>,
    /// Calling convention used.
    pub calling_convention: CallingConvention,
    /// Confidence 0–100.
    pub confidence: u8,
    /// Whether this is likely a variadic function.
    pub is_variadic: bool,
    /// Whether the function definitely does not return.
    pub is_noreturn: bool,
}

/// A single recovered parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredParam {
    /// Register or stack slot used.
    pub storage: String,
    /// Inferred C type string.
    pub type_str: String,
    /// Suggested parameter name.
    pub name: String,
}

impl RecoveredSignature {
    /// Build a signature string like `int32_t func(int64_t param0, ...)`.
    ///
    /// When `is_noreturn` is set, the C `__attribute__((noreturn))` qualifier
    /// is prepended so downstream consumers (compilers, headers, IDA-style
    /// listings) can faithfully reproduce the diverging-call contract.
    #[must_use] 
    pub fn to_c_string(&self, func_name: &str) -> String {
        let params: Vec<String> = self
            .params
            .iter()
            .map(|p| format!("{} {}", p.type_str, p.name))
            .collect();
        let mut s = String::new();
        if self.is_noreturn {
            s.push_str("__attribute__((noreturn)) ");
        }
        write!(s, "{} {}(", self.return_type, func_name).unwrap();
        s.push_str(&params.join(", "));
        if self.is_variadic {
            if params.is_empty() {
                s.push_str("...");
            } else {
                s.push_str(", ...");
            }
        }
        if params.is_empty() && !self.is_variadic {
            s.push_str("void");
        }
        s.push(')');
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VariadicDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Heuristics to detect variadic functions.
pub struct VariadicDetector {
    /// Known variadic function names.
    known_variadic: HashSet<String>,
}

impl VariadicDetector {
    #[must_use] 
    pub fn new() -> Self {
        let mut known = HashSet::new();
        for name in &[
            "printf", "fprintf", "sprintf", "snprintf", "vprintf",
            "vfprintf", "vsprintf", "vsnprintf", "scanf", "sscanf",
            "wprintf", "wscanf", "swprintf",
        ] {
            known.insert((*name).to_string());
        }
        Self { known_variadic: known }
    }

    /// Returns `true` if the function name matches a known variadic pattern.
    #[must_use] 
    pub fn is_known_variadic(&self, name: &str) -> bool {
        self.known_variadic.contains(name)
    }

    /// Heuristic: check if `va_start` / `ap` registers are accessed.
    #[must_use] 
    pub fn detect_from_instructions(&self, instructions: &[Instruction]) -> bool {
        for instr in instructions {
            let ops = instr.operands.to_lowercase();
            // Look for va_list patterns: `lea rax, [rbp + N]` where N > 16
            // or access to XMM registers at high offsets (register save area).
            if (instr.mnemonic.to_lowercase() == "lea" && ops.contains("xmm"))
                || ops.contains("al_count")
                || ops.contains("overflow_arg_area")
            {
                return true;
            }
        }
        false
    }

    /// Full detection: checks known name first, then instruction heuristics.
    #[must_use] 
    pub fn detect(&self, name: &str, instructions: &[Instruction]) -> bool {
        self.is_known_variadic(name) || self.detect_from_instructions(instructions)
    }
}

impl Default for VariadicDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TailCallDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects tail calls in a function body.
pub struct TailCallDetector {
    /// Address range of the current function.
    func_start: u64,
    func_end: u64,
}

impl TailCallDetector {
    #[must_use] 
    pub const fn new(func_start: u64, func_end: u64) -> Self {
        Self { func_start, func_end }
    }

    /// Returns `true` if the jump at `instr` is a tail call.
    ///
    /// A tail call is an unconditional jump whose target is outside the
    /// current function's address range and is preceded by a stack-restore
    /// sequence (pop rbp / mov rsp,rbp / leave / ret-like).
    #[must_use] 
    pub fn is_tail_call(&self, instr: &Instruction, instrs: &[Instruction], idx: usize) -> bool {
        let mnem = instr.mnemonic.to_lowercase();
        if mnem != "jmp" {
            return false;
        }

        // Parse target.
        let target = parse_hex_target(instr.operands.trim());
        // None (indirect jmp) is treated as external/tail-call
        let is_external = target.is_none_or(|t| t < self.func_start || t >= self.func_end);

        if !is_external {
            return false;
        }

        // Look backwards for stack restore (within 5 instructions).
        let look_back = idx.saturating_sub(5);
        for prev in &instrs[look_back..idx] {
            let pm = prev.mnemonic.to_lowercase();
            if matches!(pm.as_str(), "leave" | "pop" | "ret") {
                return true;
            }
            if pm == "mov" && prev.operands.to_lowercase().contains("rsp") {
                return true;
            }
        }

        false
    }

    /// Scan all instructions and return tail-call sites.
    #[must_use] 
    pub fn find_all(&self, instrs: &[Instruction]) -> Vec<(usize, u64)> {
        let mut results = Vec::new();
        for (idx, instr) in instrs.iter().enumerate() {
            if self.is_tail_call(instr, instrs, idx) {
                if let Some(t) = parse_hex_target(instr.operands.trim()) {
                    results.push((idx, t));
                } else {
                    results.push((idx, 0)); // indirect tail call
                }
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RecursionDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects recursive calls within a function.
pub struct RecursionDetector {
    /// The function's own address.
    func_addr: u64,
}

impl RecursionDetector {
    #[must_use] 
    pub const fn new(func_addr: u64) -> Self {
        Self { func_addr }
    }

    /// Returns the indices of recursive call instructions.
    #[must_use] 
    pub fn find_recursive_calls(&self, instrs: &[Instruction]) -> Vec<usize> {
        instrs
            .iter()
            .enumerate()
            .filter(|(_, i)| {
                i.mnemonic.to_lowercase() == "call" && {
                    parse_hex_target(i.operands.trim()) == Some(self.func_addr)
                }
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    #[must_use] 
    pub fn is_recursive(&self, instrs: &[Instruction]) -> bool {
        !self.find_recursive_calls(instrs).is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// InliningPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Policy that decides whether to inline a callee.
#[derive(Debug, Clone)]
pub struct InliningPolicy {
    /// Maximum callee instruction count eligible for inlining.
    pub max_inline_size: usize,
    /// Allow aggressive inlining of all leaf functions.
    pub aggressive: bool,
    /// Set of function addresses that are forced-inline.
    pub forced_inline: HashSet<u64>,
    /// Set of function addresses that must never be inlined.
    pub never_inline: HashSet<u64>,
}

impl InliningPolicy {
    #[must_use] 
    pub fn new(aggressive: bool, max_inline_size: usize) -> Self {
        Self {
            max_inline_size,
            aggressive,
            forced_inline: HashSet::new(),
            never_inline: HashSet::new(),
        }
    }

    /// Decide whether to inline the callee at `target_addr` with `callee_size` instructions.
    #[must_use] 
    pub fn decide(
        &self,
        target_addr: u64,
        callee_size: usize,
        is_recursive: bool,
        known_body: bool,
    ) -> InliningDecision {
        if !known_body {
            return InliningDecision {
                target_addr,
                should_inline: false,
                reason: InliningReason::NoBody,
                callee_size,
            };
        }

        if is_recursive {
            return InliningDecision {
                target_addr,
                should_inline: false,
                reason: InliningReason::Recursive,
                callee_size,
            };
        }

        if self.never_inline.contains(&target_addr) {
            return InliningDecision {
                target_addr,
                should_inline: false,
                reason: InliningReason::Disabled,
                callee_size,
            };
        }

        if self.forced_inline.contains(&target_addr) {
            return InliningDecision {
                target_addr,
                should_inline: true,
                reason: InliningReason::ForcedByAttribute,
                callee_size,
            };
        }

        if callee_size > self.max_inline_size {
            return InliningDecision {
                target_addr,
                should_inline: false,
                reason: InliningReason::TooLarge {
                    limit: self.max_inline_size,
                    actual: callee_size,
                },
                callee_size,
            };
        }

        if self.aggressive {
            return InliningDecision {
                target_addr,
                should_inline: true,
                reason: InliningReason::AggressiveMode,
                callee_size,
            };
        }

        // Default: inline only small leaf functions (≤ 8 instructions).
        if callee_size <= 8 {
            InliningDecision {
                target_addr,
                should_inline: true,
                reason: InliningReason::SmallLeaf,
                callee_size,
            }
        } else {
            InliningDecision {
                target_addr,
                should_inline: false,
                reason: InliningReason::TooLarge {
                    limit: 8,
                    actual: callee_size,
                },
                callee_size,
            }
        }
    }
}

impl Default for InliningPolicy {
    fn default() -> Self {
        Self::new(false, 32)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureRecoverer
// ─────────────────────────────────────────────────────────────────────────────

/// Recovers function signatures from calling-convention analysis.
pub struct SignatureRecoverer {
    cc: CallingConvention,
    variadic: VariadicDetector,
    /// Map of known no-return function addresses.
    noreturn_addrs: HashSet<u64>,
    /// Map of known no-return names.
    noreturn_names: HashSet<String>,
}

impl SignatureRecoverer {
    #[must_use] 
    pub fn new(cc: CallingConvention) -> Self {
        // Seed from the canonical noreturn vocabulary in rustre-analysis-fn so
        // the signature emitter and the detector stay in sync. This covers
        // libc (`abort`, `exit`), Win32 (`ExitProcess`, `RaiseException`),
        // C++ (`__cxa_throw`), and Rust panic helpers (`panic_fmt`,
        // `panic_bounds_check`, `rust_begin_unwind`, ...).
        let mut noreturn_names = HashSet::new();
        for name in rustre_analysis_fn::noreturn_detector::KNOWN_NORETURN_SYMBOLS {
            noreturn_names.insert((*name).to_string());
        }
        Self {
            cc,
            variadic: VariadicDetector::new(),
            noreturn_addrs: HashSet::new(),
            noreturn_names,
        }
    }

    /// Build a recoverer whose noreturn cache is pre-populated from the result
    /// of a [`rustre_analysis_fn::noreturn_detector::NoreturnDetector`] run.
    ///
    /// This is the production path: the orchestrator runs the detector across
    /// the binary view, then hands the populated detector to the per-function
    /// signature emitter so `__attribute__((noreturn))` can be stamped on
    /// every function in the propagated noreturn closure.
    #[must_use]
    pub fn from_detector(
        cc: CallingConvention,
        det: &rustre_analysis_fn::noreturn_detector::NoreturnDetector,
    ) -> Self {
        let mut me = Self::new(cc);
        for (addr, _evidence) in det.report() {
            me.noreturn_addrs.insert(addr);
        }
        me
    }

    /// Recover the signature for a function.
    #[must_use] 
    pub fn recover(
        &self,
        func_name: &str,
        instrs: &[Instruction],
        call_sites: &[CallSite],
    ) -> RecoveredSignature {
        let param_regs = self.cc.param_regs();
        let is_variadic = self.variadic.detect(func_name, instrs);
        // Gap-H tail-call check: if the last call site (or any TailCall site)
        // targets a known-noreturn callee, this function is noreturn too.
        let last_target_noreturn = call_sites
            .iter()
            .filter(|cs| matches!(cs.kind, CallKind::TailCall))
            .any(|cs| {
                cs.target_addr.is_some_and(|t| self.noreturn_addrs.contains(&t))
                    || cs
                        .target_name
                        .as_deref()
                        .is_some_and(|n| self.noreturn_names.contains(n))
            })
            || call_sites.last().is_some_and(|cs| {
                cs.target_addr.is_some_and(|t| self.noreturn_addrs.contains(&t))
                    && instrs.last().is_some_and(|i| {
                        let m = i.mnemonic.to_lowercase();
                        m != "ret" && m != "retn"
                    })
            });
        let is_noreturn = self.noreturn_names.contains(func_name)
            || instrs.last().is_some_and(|i| {
                i.mnemonic.to_lowercase() == "ud2" || i.mnemonic.to_lowercase() == "hlt"
            })
            || last_target_noreturn;

        // Count how many parameter registers are actually used.
        let mut max_param_reg = 0usize;
        for instr in instrs {
            for (i, reg) in param_regs.iter().enumerate() {
                if instr.operands.to_lowercase().contains(*reg) && i + 1 > max_param_reg {
                    max_param_reg = i + 1;
                }
            }
        }
        // Also check call sites for argument-count hints.
        for cs in call_sites {
            if let Some(hint) = cs.arg_count_hint
                && hint > max_param_reg {
                    max_param_reg = hint;
                }
        }

        let params: Vec<RecoveredParam> = param_regs[..max_param_reg.min(param_regs.len())]
            .iter()
            .enumerate()
            .map(|(i, reg)| RecoveredParam {
                storage: reg.to_string(),
                type_str: "int64_t".to_string(),
                name: format!("param{i}"),
            })
            .collect();

        // Infer return type from usage of rax/eax after calls.
        let return_type = if instrs
            .iter()
            .any(|i| i.operands.to_lowercase().contains("rax") && i.mnemonic.to_lowercase() == "mov")
        {
            "int64_t".to_string()
        } else if is_noreturn {
            "void".to_string()
        } else {
            "int32_t".to_string()
        };

        let confidence = if max_param_reg > 0 { 70u8 } else { 40u8 };

        RecoveredSignature {
            return_type,
            params,
            calling_convention: self.cc,
            confidence,
            is_variadic,
            is_noreturn,
        }
    }

    pub fn add_noreturn_addr(&mut self, addr: u64) {
        self.noreturn_addrs.insert(addr);
    }

    pub fn add_noreturn_name(&mut self, name: impl Into<String>) {
        self.noreturn_names.insert(name.into());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionDecompilerV2 — full single-function decompiler
// ─────────────────────────────────────────────────────────────────────────────

/// Options for single-function decompilation.
#[derive(Debug, Clone)]
pub struct FunctionDecompilerOptions {
    /// Base decompiler options.
    pub base: DecompOptions,
    /// Architecture string (used for CC inference).
    pub arch: String,
    /// Address range of the function (start, end).
    pub func_range: Option<(u64, u64)>,
    /// Set of import addresses (targets that are library calls).
    pub import_addrs: HashSet<u64>,
    /// Map of symbol name → address for known functions.
    pub symbol_map: HashMap<String, u64>,
    /// Inlining policy.
    pub inlining: InliningPolicy,
    /// Maximum instructions before the function is considered too complex.
    pub complexity_limit: usize,
}

impl Default for FunctionDecompilerOptions {
    fn default() -> Self {
        Self {
            base: DecompOptions::default(),
            arch: "x86_64".to_string(),
            func_range: None,
            import_addrs: HashSet::new(),
            symbol_map: HashMap::new(),
            inlining: InliningPolicy::default(),
            complexity_limit: 5000,
        }
    }
}

/// Map an arch string (e.g. `"x86_64-windows-msvc"`) onto the PE flag used by
/// the calling-convention detector.
fn arch_string_hints_pe(arch: &str) -> bool {
    let a = arch.to_ascii_lowercase();
    a.contains("win") || a.contains("msvc") || a.contains("pe")
}

struct PseudocodeInputs<'a> {
    instructions: &'a [Instruction],
    variables: &'a [DecompVariable],
    auto_sig: &'a crate::signature_recovery::RecoveredSignature,
    sig: &'a RecoveredSignature,
    tail_calls: &'a [(usize, u64)],
    is_recursive: bool,
    is_variadic: bool,
}

/// The main single-function decompiler.
pub struct FunctionDecompilerV2 {
    options: FunctionDecompilerOptions,
    sig_recoverer: SignatureRecoverer,
    variadic: VariadicDetector,
}

impl FunctionDecompilerV2 {
    /// Create with default options (`x86_64` `SysV` ABI).
    #[must_use] 
    pub fn new() -> Self {
        let opts = FunctionDecompilerOptions::default();
        let cc = CallingConvention::from_arch(&opts.arch);
        Self {
            sig_recoverer: SignatureRecoverer::new(cc),
            variadic: VariadicDetector::new(),
            options: opts,
        }
    }

    #[must_use] 
    pub fn with_options(options: FunctionDecompilerOptions) -> Self {
        let cc = CallingConvention::from_arch(&options.arch);
        Self {
            sig_recoverer: SignatureRecoverer::new(cc),
            variadic: VariadicDetector::new(),
            options,
        }
    }

    /// Full decompilation entry point for a single function.
    ///
    /// # Errors
    ///
    /// Returns [`DecompilerError::FunctionTooLarge`] when the instruction count
    /// exceeds `options.complexity_limit`.
    pub fn decompile(
        &self,
        address: u64,
        func_name: &str,
        instructions: &[Instruction],
    ) -> Result<DecompiledFunction, DecompilerError> {
        let start = Instant::now();

        if instructions.len() > self.options.complexity_limit {
            return Err(DecompilerError::FunctionTooLarge(address));
        }

        // --- 1. Detect tail calls ---
        let (func_start, func_end) = self.options.func_range.unwrap_or((address, address + instructions.len() as u64 * 4));
        let tail_detector = TailCallDetector::new(func_start, func_end);
        let tail_calls = tail_detector.find_all(instructions);

        // --- 2. Detect recursive calls ---
        let rec_detector = RecursionDetector::new(address);
        let is_recursive = rec_detector.is_recursive(instructions);

        // --- 3. Collect call sites ---
        let call_sites = self.collect_call_sites(address, instructions, &tail_calls);

        // --- 4. Recover variables ---
        let cc = CallingConvention::from_arch(&self.options.arch);
        let mut var_recovery = VariableRecovery::new();
        let variables = var_recovery.recover_from_instructions_with_cc(instructions, cc);

        // --- 5. Recover signature ---
        let is_pe = arch_string_hints_pe(&self.options.arch);
        let auto_sig = recover_signature_auto(instructions, func_name, 64, is_pe);
        let sig = self.sig_recoverer.recover(func_name, instructions, &call_sites);

        // --- 6. Detect variadic ---
        let is_variadic = self.variadic.detect(func_name, instructions);

        // --- 7. Emit pseudo-code ---
        let mut ctx = self.emit_pseudocode(
            address, func_name,
            &PseudocodeInputs {
                instructions,
                variables: &variables,
                auto_sig: &auto_sig,
                sig: &sig,
                tail_calls: &tail_calls,
                is_recursive,
                is_variadic,
            },
        );

        ctx.advance_ir_level(IrLevel::PseudoC);
        for cs in &call_sites {
            if let Some(t) = cs.target_addr {
                ctx.add_call_site(t);
            }
        }

        let elapsed = start.elapsed();
        ctx.record_pass_time("function_decompiler", elapsed);

        Ok(ctx.finish())
    }

    fn collect_call_sites(
        &self,
        address: u64,
        instructions: &[Instruction],
        tail_calls: &[(usize, u64)],
    ) -> Vec<CallSite> {
        let mut call_sites: Vec<CallSite> = Vec::new();
        for (idx, instr) in instructions.iter().enumerate() {
            let mnem = instr.mnemonic.to_lowercase();
            if mnem == "call" {
                if let Some(target) = parse_hex_target(instr.operands.trim()) {
                    let mut site = CallSite::direct(instr.address.0, target);
                    if target == address {
                        site.kind = CallKind::Recursive;
                    } else if self.options.import_addrs.contains(&target) {
                        site.kind = CallKind::LibraryCall;
                    }
                    call_sites.push(site);
                } else {
                    call_sites.push(CallSite::indirect(instr.address.0));
                }
            }
            for &(tc_idx, tc_target) in tail_calls {
                if tc_idx == idx {
                    let mut site = if tc_target == 0 {
                        CallSite::indirect(instr.address.0)
                    } else {
                        CallSite::direct(instr.address.0, tc_target)
                    };
                    site.kind = CallKind::TailCall;
                    call_sites.push(site);
                }
            }
        }
        call_sites
    }

    fn emit_pseudocode(
        &self,
        address: u64,
        func_name: &str,
        inp: &PseudocodeInputs<'_>,
    ) -> DecompilerContext {
        let mut ctx = DecompilerContext::new(address, func_name, self.options.base.clone());
        for var in inp.variables {
            ctx.add_variable(var.clone());
        }
        for param in &inp.auto_sig.params {
            if let Some(reg) = &param.register {
                let already = ctx.variables.iter()
                    .any(|v| matches!(&v.storage, VarStorage::Register(r) if r == reg));
                if !already {
                    ctx.add_variable(DecompVariable {
                        name: param.name.clone(),
                        type_str: param.ty.clone(),
                        is_parameter: true,
                        storage: VarStorage::Register(reg.clone()),
                    });
                }
            } else if let Some(off) = param.stack_offset {
                let already = ctx.variables.iter()
                    .any(|v| matches!(&v.storage, VarStorage::Stack(o) if *o == i64::from(off)));
                if !already {
                    ctx.add_variable(DecompVariable {
                        name: param.name.clone(),
                        type_str: param.ty.clone(),
                        is_parameter: true,
                        storage: VarStorage::Stack(i64::from(off)),
                    });
                }
            }
        }
        ctx.annotate("auto_calling_convention", format!("{:?}", inp.auto_sig.conv));
        let sig_str = inp.sig.to_c_string(func_name);
        ctx.emit_line(format!("// Recovered: {sig_str}"));
        if inp.is_recursive { ctx.emit_line("// NOTE: function is recursive"); }
        if inp.is_variadic  { ctx.emit_line("// NOTE: function appears variadic"); }
        if inp.sig.is_noreturn { ctx.emit_line("// NOTE: function does not return"); }
        for region in &Self::detect_exception_regions(inp.instructions) {
            ctx.emit_line(format!(
                "// EH region [{:#x}, {:#x}) → handler {:#x} [{}]",
                region.try_start, region.try_end, region.handler_addr, region.kind
            ));
        }
        ctx.emit_line(format!("{sig_str} {{"));
        for instr in inp.instructions {
            let expr = Self::lift_instruction(instr);
            ctx.emit_line(format!("  {expr}"));
        }
        for (_, target) in inp.tail_calls {
            if *target != 0 {
                ctx.emit_line(format!("  /* tail_call → {target:#x} */"));
            } else {
                ctx.emit_line("  /* tail_call → indirect */".to_string());
            }
        }
        ctx.emit_line("}".to_string());
        ctx
    }

    /// Detect exception-handling regions from instruction patterns.
    fn detect_exception_regions(instrs: &[Instruction]) -> Vec<ExceptionRegion> {
        let mut regions = Vec::new();
        let mut try_start: Option<u64> = None;

        for (i, instr) in instrs.iter().enumerate() {
            let mnem = instr.mnemonic.to_lowercase();
            let ops = instr.operands.to_lowercase();

            // Windows SEH: look for `mov dword ptr fs:[0], ...` (EXCEPTION_REGISTRATION push)
            if mnem == "mov" && ops.contains("fs:[0]") {
                try_start = Some(instr.address.0);
            }

            // SEH unwind: look for `mov dword ptr fs:[0], -1` (unregister handler)
            if mnem == "mov" && ops.contains("fs:[0]") && ops.contains("-0x1")
                && let Some(start) = try_start.take() {
                    regions.push(ExceptionRegion {
                        try_start: start,
                        try_end: instr.address.0,
                        handler_addr: 0, // would need symbol resolution
                        kind: ExceptionKind::SehExcept,
                        filter: None,
                    });
                }

            // DWARF cleanup: `call __cxa_begin_catch` or `call _Unwind_Resume`
            if mnem == "call"
                && (ops.contains("cxa_begin_catch") || ops.contains("unwind_resume")) {
                    regions.push(ExceptionRegion {
                        try_start: instrs.first().map_or(0, |i| i.address.0),
                        try_end: instr.address.0,
                        handler_addr: instr.address.0,
                        kind: ExceptionKind::DwarfCleanup,
                        filter: None,
                    });
                }

            // GCC __cxa_throw landing pads: typically preceded by `jmp`
            if i > 0 && mnem == "push" && instrs[i - 1].mnemonic.to_lowercase() == "jmp"
                && let Some(start) = try_start.as_ref() {
                    let _ = start;
                }
        }

        regions
    }

    /// Lift a single instruction to a pseudo-C expression string.
    fn lift_instruction(instr: &Instruction) -> String {
        let mnem = instr.mnemonic.to_lowercase();
        let parts: Vec<&str> = instr.operands.splitn(2, ',').collect();

        match mnem.as_str() {
            "mov" | "movq" | "movl" | "movw" | "movb" if parts.len() == 2 => {
                format!("{} = {};", parts[0].trim(), parts[1].trim())
            }
            "lea" if parts.len() == 2 => {
                format!("{} = &{};", parts[0].trim(), parts[1].trim())
            }
            "add" if parts.len() == 2 => {
                format!("{} += {};", parts[0].trim(), parts[1].trim())
            }
            "sub" if parts.len() == 2 => {
                format!("{} -= {};", parts[0].trim(), parts[1].trim())
            }
            "and" if parts.len() == 2 => {
                format!("{} &= {};", parts[0].trim(), parts[1].trim())
            }
            "or" if parts.len() == 2 => {
                format!("{} |= {};", parts[0].trim(), parts[1].trim())
            }
            "xor" if parts.len() == 2 && parts[0].trim() == parts[1].trim() => {
                format!("{} = 0;", parts[0].trim())
            }
            "xor" if parts.len() == 2 => {
                format!("{} ^= {};", parts[0].trim(), parts[1].trim())
            }
            "cmp" if parts.len() == 2 => {
                format!("/* cmp({}, {}) */", parts[0].trim(), parts[1].trim())
            }
            "test" if parts.len() == 2 => {
                format!("/* test({}, {}) */", parts[0].trim(), parts[1].trim())
            }
            "call" => {
                let target = instr.operands.trim();
                format!("{target}();  /* call */")
            }
            "ret" => "return;".to_string(),
            "nop" => "/* nop */".to_string(),
            "push" => format!("push({});", instr.operands.trim()),
            "pop" => format!("{} = pop();", instr.operands.trim()),
            "jmp" => format!("goto {};", instr.operands.trim()),
            "je" | "jz" => format!("if (ZF) goto {};", instr.operands.trim()),
            "jne" | "jnz" => format!("if (!ZF) goto {};", instr.operands.trim()),
            "jl" | "jlt" => format!("if (SF != OF) goto {};", instr.operands.trim()),
            "jg" | "jgt" => format!("if (!ZF && SF == OF) goto {};", instr.operands.trim()),
            _ => format!(
                "/* {} {} */",
                instr.mnemonic, instr.operands
            ),
        }
    }
}

impl Default for FunctionDecompilerV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FunctionDecompilerV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FunctionDecompilerV2 {{ arch: {} }}", self.options.arch)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
// parse_hex_target is defined in crate root (lib.rs) and imported above.

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;

    fn make_instr(addr: u64, mnem: &str, ops: &str) -> Instruction {
        Instruction {
            address: Address::new(addr),
            mnemonic: mnem.to_string(),
            operands: ops.to_string(),
            size: 4,
            operand_list: Vec::new(),
            flags: rustre_core::InstrFlags::NONE,
            bytes: Vec::new(),
            comment: None,
        }
    }

    #[test]
    fn variadic_detection_printf() {
        let det = VariadicDetector::new();
        assert!(det.is_known_variadic("printf"));
        assert!(!det.is_known_variadic("memcpy"));
    }

    #[test]
    fn tail_call_detection() {
        let det = TailCallDetector::new(0x1000, 0x2000);
        let instrs = vec![
            make_instr(0x1000, "push", "rbp"),
            make_instr(0x1004, "leave", ""),
            make_instr(0x1005, "jmp", "0x3000"),
        ];
        assert!(det.is_tail_call(&instrs[2], &instrs, 2));
    }

    #[test]
    fn recursion_detection() {
        let det = RecursionDetector::new(0x1000);
        let instrs = vec![
            make_instr(0x1000, "push", "rbp"),
            make_instr(0x1004, "call", "0x1000"),
            make_instr(0x1008, "ret", ""),
        ];
        assert!(det.is_recursive(&instrs));
    }

    #[test]
    fn inlining_policy_small_leaf() {
        let policy = InliningPolicy::new(false, 32);
        let dec = policy.decide(0x5000, 5, false, true);
        assert!(dec.should_inline);
    }

    #[test]
    fn inlining_policy_too_large() {
        let policy = InliningPolicy::new(false, 32);
        let dec = policy.decide(0x5000, 100, false, true);
        assert!(!dec.should_inline);
    }

    #[test]
    fn signature_recovery_basic() {
        let rec = SignatureRecoverer::new(CallingConvention::SysVAmd64);
        let instrs = vec![
            make_instr(0x1000, "push", "rbp"),
            make_instr(0x1004, "mov", "rbp, rsp"),
            make_instr(0x1008, "mov", "rax, rdi"),
            make_instr(0x100c, "ret", ""),
        ];
        let sig = rec.recover("myfunc", &instrs, &[]);
        assert_eq!(sig.calling_convention, CallingConvention::SysVAmd64);
        assert!(!sig.is_variadic);
        assert!(!sig.params.is_empty());
    }

    #[test]
    fn signature_c_string() {
        let sig = RecoveredSignature {
            return_type: "int32_t".to_string(),
            params: vec![
                RecoveredParam {
                    storage: "rdi".to_string(),
                    type_str: "int64_t".to_string(),
                    name: "param0".to_string(),
                },
            ],
            calling_convention: CallingConvention::SysVAmd64,
            confidence: 70,
            is_variadic: false,
            is_noreturn: false,
        };
        assert_eq!(sig.to_c_string("test"), "int32_t test(int64_t param0)");
    }

    #[test]
    fn full_decompile() {
        let dc = FunctionDecompilerV2::new();
        let instrs = vec![
            make_instr(0x1000, "push", "rbp"),
            make_instr(0x1001, "mov", "rbp, rsp"),
            make_instr(0x1004, "xor", "eax, eax"),
            make_instr(0x1006, "pop", "rbp"),
            make_instr(0x1007, "ret", ""),
        ];
        let result = dc.decompile(0x1000, "test_func", &instrs);
        assert!(result.is_ok());
        let func = result.unwrap();
        assert_eq!(func.address, 0x1000);
        assert!(!func.pseudo_code.is_empty());
    }
}
