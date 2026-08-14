//! `verifier` — Statement-level LLIL type verifier.
//!
//! # Design layer
//! This module operates on a **flat list of [`LlilStmt`]** — the direct output
//! of a lifter — and validates each statement and its sub-expressions for type
//! and size consistency without requiring a control-flow graph.  It is intended
//! to be called immediately after lifting, before any CFG construction.
//!
//! Contrast with [`crate::llil_verification`], which operates on an explicit
//! basic-block CFG ([`crate::llil_verification::VFunction`]) and adds
//! control-flow reachability and flag-liveness passes.  Use both in sequence:
//! this module first (cheap, no CFG overhead), then `llil_verification` once the
//! CFG has been built.
//!
//! # Self-contained stubs
//! To keep the module compilable in isolation (e.g. in unit tests that do not
//! pull in the full crate AST), it re-declares minimal local types (`ILSize`,
//! `RegId`, `FlagId`, `LlilExpr`, `LlilStmt`).  These are intentionally kept
//! in sync with the canonical types in `lib.rs`.

use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// Re-used LLIL types (minimal stubs for standalone compilation)
// ---------------------------------------------------------------------------

/// Byte width of a value or register in LLIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ILSize(pub u8);

impl ILSize {
    pub const B1:  Self = Self(1);
    pub const B2:  Self = Self(2);
    pub const B4:  Self = Self(4);
    pub const B8:  Self = Self(8);
    pub const B16: Self = Self(16);
    pub const PTR: Self = Self(8); // assume 64-bit

    #[must_use] 
    pub const fn bytes(self) -> u8 { self.0 }
    #[must_use] 
    pub fn bits(self) -> u32 { u32::from(self.0) * 8 }
}

impl fmt::Display for ILSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Register identifier in LLIL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegId(pub String);

impl fmt::Display for RegId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Flag identifier in LLIL.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlagId(pub String);

impl fmt::Display for FlagId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Architecture description: valid registers and flags.
#[derive(Debug, Clone, Default)]
pub struct ArchDesc {
    /// Map from register name to its natural size.
    pub registers:      HashMap<String, ILSize>,
    /// Set of valid flag names.
    pub flags:          HashSet<String>,
    /// Address/pointer size for this architecture.
    pub pointer_size:   ILSize,
}

impl ArchDesc {
    #[must_use] 
    pub fn x86_64() -> Self {
        let mut a = Self { pointer_size: ILSize::B8, ..Default::default() };
        // 64-bit GPRs
        for r in &["rax","rbx","rcx","rdx","rsi","rdi","rsp","rbp",
                   "r8","r9","r10","r11","r12","r13","r14","r15","rip"] {
            a.registers.insert(r.to_string(), ILSize::B8);
        }
        // 32-bit
        for r in &["eax","ebx","ecx","edx","esi","edi","esp","ebp",
                   "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d","eip"] {
            a.registers.insert(r.to_string(), ILSize::B4);
        }
        // 16-bit
        for r in &["ax","bx","cx","dx","si","di","sp","bp"] {
            a.registers.insert(r.to_string(), ILSize::B2);
        }
        // 8-bit
        for r in &["al","bl","cl","dl","sil","dil","spl","bpl",
                   "ah","bh","ch","dh"] {
            a.registers.insert(r.to_string(), ILSize::B1);
        }
        // XMM
        for i in 0..16u32 {
            a.registers.insert(format!("xmm{i}"), ILSize::B16);
        }
        // Flags
        for f in &["cf","pf","af","zf","sf","tf","df","of","if"] {
            a.flags.insert(f.to_string());
        }
        a
    }

    #[must_use] 
    pub fn register_size(&self, id: &RegId) -> Option<ILSize> {
        self.registers.get(&id.0).copied()
    }

    #[must_use] 
    pub fn is_valid_register(&self, id: &RegId) -> bool {
        self.registers.contains_key(&id.0)
    }

    #[must_use] 
    pub fn is_valid_flag(&self, id: &FlagId) -> bool {
        self.flags.contains(&id.0)
    }
}

// ---------------------------------------------------------------------------
// LLIL expression types
// ---------------------------------------------------------------------------

/// The type/size information of an LLIL expression result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ILExprType {
    pub size: ILSize,
    pub kind: ILTypeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ILTypeKind {
    Int,
    Float,
    Pointer,
    Bool,   // 1-bit condition
    Void,
}

impl ILExprType {
    #[must_use] 
    pub const fn int(size: ILSize) -> Self { Self { size, kind: ILTypeKind::Int } }
    #[must_use] 
    pub const fn float(size: ILSize) -> Self { Self { size, kind: ILTypeKind::Float } }
    #[must_use] 
    pub const fn ptr(size: ILSize) -> Self { Self { size, kind: ILTypeKind::Pointer } }
    #[must_use] 
    pub const fn bool_() -> Self { Self { size: ILSize::B1, kind: ILTypeKind::Bool } }
    #[must_use] 
    pub const fn void() -> Self { Self { size: ILSize(0), kind: ILTypeKind::Void } }
}

// ---------------------------------------------------------------------------
// LLIL expression nodes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum LlilExpr {
    // Terminals
    Const     { size: ILSize, value: u64 },
    ConstPtr  { size: ILSize, value: u64 },
    Reg       { size: ILSize, id: RegId },
    RegSplit  { size: ILSize, high: RegId, low: RegId },
    Flag      { id: FlagId },
    Undef     { size: ILSize },
    // Memory
    Load      { size: ILSize, src: Box<Self> },
    // Arithmetic
    Add       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Sub       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Mul       { size: ILSize, left: Box<Self>, right: Box<Self> },
    MulsDp    { size: ILSize, left: Box<Self>, right: Box<Self> },
    MuluDp    { size: ILSize, left: Box<Self>, right: Box<Self> },
    Divu      { size: ILSize, left: Box<Self>, right: Box<Self> },
    Divs      { size: ILSize, left: Box<Self>, right: Box<Self> },
    Modu      { size: ILSize, left: Box<Self>, right: Box<Self> },
    Mods      { size: ILSize, left: Box<Self>, right: Box<Self> },
    Neg       { size: ILSize, src: Box<Self> },
    Not       { size: ILSize, src: Box<Self> },
    // Bitwise
    And       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Or        { size: ILSize, left: Box<Self>, right: Box<Self> },
    Xor       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Lsl       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Lsr       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Asr       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Ror       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Rol       { size: ILSize, left: Box<Self>, right: Box<Self> },
    // Comparison (result is boolean)
    CmpE      { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpNe     { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpSlt    { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpUlt    { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpSle    { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpUle    { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpSgt    { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpUgt    { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpSge    { size: ILSize, left: Box<Self>, right: Box<Self> },
    CmpUge    { size: ILSize, left: Box<Self>, right: Box<Self> },
    // Extension / truncation
    ZeroExtend { size: ILSize, src: Box<Self> },
    SignExtend  { size: ILSize, src: Box<Self> },
    LowPart     { size: ILSize, src: Box<Self> },
    // Float
    Fadd       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Fsub       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Fmul       { size: ILSize, left: Box<Self>, right: Box<Self> },
    Fdiv       { size: ILSize, left: Box<Self>, right: Box<Self> },
    FloatConv  { size: ILSize, src: Box<Self> },
    FloatToInt { size: ILSize, src: Box<Self> },
    IntToFloat { size: ILSize, src: Box<Self> },
    // Misc
    Adc        { size: ILSize, left: Box<Self>, right: Box<Self>, carry: Box<Self> },
    Sbb        { size: ILSize, left: Box<Self>, right: Box<Self>, borrow: Box<Self> },
    // Address-of
    AddressOf  { size: ILSize, id: RegId },
    // Temp register
    Temp       { size: ILSize, index: u32 },
}

impl LlilExpr {
    #[must_use] 
    pub const fn result_size(&self) -> ILSize {
        match self {
            Self::CmpE    { .. } | Self::CmpNe  { .. }
            | Self::CmpSlt  { .. } | Self::CmpUlt { .. }
            | Self::CmpSle  { .. } | Self::CmpUle { .. }
            | Self::CmpSgt  { .. } | Self::CmpUgt { .. }
            | Self::CmpSge  { .. } | Self::CmpUge { .. }
            | Self::Flag     { .. }                                       => ILSize::B1,
            Self::Const   { size, .. } | Self::ConstPtr { size, .. }
            | Self::Reg     { size, .. } | Self::RegSplit { size, .. }
            | Self::Undef   { size }
            | Self::Load    { size, .. }
            | Self::Add     { size, .. } | Self::Sub  { size, .. }
            | Self::Mul     { size, .. } | Self::Neg  { size, .. }
            | Self::Not     { size, .. }
            | Self::MulsDp  { size, .. } | Self::MuluDp { size, .. }
            | Self::Divu    { size, .. } | Self::Divs  { size, .. }
            | Self::Modu    { size, .. } | Self::Mods  { size, .. }
            | Self::And     { size, .. } | Self::Or   { size, .. }
            | Self::Xor     { size, .. } | Self::Lsl  { size, .. }
            | Self::Lsr     { size, .. } | Self::Asr  { size, .. }
            | Self::Ror     { size, .. } | Self::Rol  { size, .. }
            | Self::ZeroExtend { size, .. } | Self::SignExtend { size, .. }
            | Self::LowPart  { size, .. }
            | Self::Fadd    { size, .. } | Self::Fsub  { size, .. }
            | Self::Fmul    { size, .. } | Self::Fdiv  { size, .. }
            | Self::FloatConv  { size, .. } | Self::FloatToInt { size, .. }
            | Self::IntToFloat { size, .. }
            | Self::Adc     { size, .. } | Self::Sbb  { size, .. }
            | Self::AddressOf { size, .. }
            | Self::Temp     { size, .. }                                 => *size,
        }
    }
}

// ---------------------------------------------------------------------------
// LLIL statement nodes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum LlilStmt {
    /// Set register: reg = val
    SetReg   { dest: RegId, src: LlilExpr },
    /// Set register split: high:low = val (used for wide multiply results)
    SetRegSplit { high: RegId, low: RegId, src: LlilExpr },
    /// Set flag: flag = val
    SetFlag  { flag: FlagId, src: LlilExpr },
    /// Store to memory: *[addr].size = val
    Store    { size: ILSize, dest: LlilExpr, src: LlilExpr },
    /// Push to stack
    Push     { size: ILSize, src: LlilExpr },
    /// Pop from stack
    Pop      { size: ILSize, dest: RegId },
    /// Unconditional jump
    Jump     { target: LlilExpr },
    /// Jump to target if condition is true
    JumpTo   { targets: Vec<(u64, LlilExpr)> },
    /// Conditional branch: if (cond) goto `true_target` else goto `false_target`
    JumpIf   { cond: LlilExpr, true_target: u64, false_target: u64 },
    /// Function call
    Call     { target: LlilExpr, params: Vec<LlilExpr> },
    /// System call
    Syscall,
    /// Return from function
    Ret      { src: LlilExpr },
    /// No-operation
    Nop,
    /// Undefined behaviour (used for unrecognised instructions)
    Undef,
    /// Breakpoint / trap
    Trap     { vector: u64 },
    /// Intrinsic (architecture-specific)
    Intrinsic { name: String, inputs: Vec<LlilExpr>, outputs: Vec<RegId> },
}

// ---------------------------------------------------------------------------
// Violation types
// ---------------------------------------------------------------------------

/// Severity of a verification violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational note, not necessarily wrong.
    Info,
    /// Likely a lift error, but execution might still be correct.
    Warning,
    /// Definite type inconsistency.
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info    => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Error   => write!(f, "ERR "),
        }
    }
}

/// The specific kind of violation detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationKind {
    /// Size mismatch between two related expressions.
    SizeMismatch { expected: ILSize, actual: ILSize, context: String },
    /// Reference to a register not defined in the architecture.
    UndefinedRegister(RegId),
    /// Reference to a flag not defined in the architecture.
    UndefinedFlag(FlagId),
    /// Operation is structurally invalid (e.g., sign-extend to smaller size).
    InvalidOperation { op: String, reason: String },
    /// Instruction is unreachable (dead code).
    DeadCode,
    /// `JumpIf` condition is not boolean (`ILSize::B1`).
    NonBoolCondition { actual_size: ILSize },
    /// Call target does not have pointer size.
    InvalidCallTarget { actual_size: ILSize },
    /// ZeroExtend/SignExtend applied with wrong direction.
    ExtensionSizeError { op: &'static str, src_size: ILSize, dst_size: ILSize },
    /// Truncation to larger or equal size.
    TruncationSizeError { src_size: ILSize, dst_size: ILSize },
    /// Store size exceeds address space width.
    StoreOversized { store_size: ILSize, pointer_size: ILSize },
    /// Load address expression has wrong size.
    LoadAddressSizeMismatch { actual: ILSize, expected: ILSize },
    /// Stack pointer usage anomaly (push/pop imbalance).
    StackImbalance { delta: i64 },
    /// Division/modulo right-hand side might be zero (statically zero constant).
    ConstantDivideByZero,
    /// Operand type mismatch (e.g., float op on int).
    TypeMismatch { expected_kind: &'static str, actual_kind: &'static str },
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeMismatch { expected, actual, context } =>
                write!(f, "size mismatch in {context}: expected {expected} bytes, got {actual}"),
            Self::UndefinedRegister(r) =>
                write!(f, "undefined register: {r}"),
            Self::UndefinedFlag(fl) =>
                write!(f, "undefined flag: {fl}"),
            Self::InvalidOperation { op, reason } =>
                write!(f, "invalid operation {op}: {reason}"),
            Self::DeadCode =>
                write!(f, "unreachable code (dead code)"),
            Self::NonBoolCondition { actual_size } =>
                write!(f, "JumpIf condition must be 1 byte (bool), got {actual_size}"),
            Self::InvalidCallTarget { actual_size } =>
                write!(f, "call target must be pointer-sized, got {actual_size}"),
            Self::ExtensionSizeError { op, src_size, dst_size } =>
                write!(f, "{op}: source size {src_size} >= destination size {dst_size}"),
            Self::TruncationSizeError { src_size, dst_size } =>
                write!(f, "LowPart: destination size {dst_size} >= source size {src_size}"),
            Self::StoreOversized { store_size, pointer_size } =>
                write!(f, "store size {store_size} > pointer size {pointer_size}"),
            Self::LoadAddressSizeMismatch { actual, expected } =>
                write!(f, "load address is {actual} bytes, expected {expected}"),
            Self::StackImbalance { delta } =>
                write!(f, "stack imbalance: net delta = {delta} bytes"),
            Self::ConstantDivideByZero =>
                write!(f, "constant divide by zero"),
            Self::TypeMismatch { expected_kind, actual_kind } =>
                write!(f, "type mismatch: expected {expected_kind} expression, got {actual_kind}"),
        }
    }
}

/// A single verification violation.
#[derive(Debug, Clone)]
pub struct Violation {
    pub instruction_idx: usize,
    pub severity:        Severity,
    pub kind:            ViolationKind,
    pub description:     String,
    pub suggestion:      Option<String>,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] insn#{}: {} — {}",
            self.severity, self.instruction_idx, self.kind, self.description)?;
        if let Some(s) = &self.suggestion {
            write!(f, " | HINT: {s}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fix suggestions
// ---------------------------------------------------------------------------

fn suggest_size_mismatch(expected: ILSize, actual: ILSize, context: &str) -> String {
    if actual.bytes() < expected.bytes() {
        format!(
            "Consider using ZeroExtend({expected}, src) or SignExtend({expected}, src) to widen the {context} from {actual} to {expected} bytes"
        )
    } else {
        format!(
            "Consider using LowPart({expected}, src) to truncate the {context} from {actual} to {expected} bytes"
        )
    }
}

fn suggest_undefined_register(id: &RegId, arch: &ArchDesc) -> String {
    // Find the closest register name by Levenshtein-like heuristic (prefix match)
    let prefix: String = id.0.chars().take(2).collect();
    let candidates: Vec<&String> = arch.registers.keys()
        .filter(|r| r.starts_with(&prefix))
        .take(3)
        .collect();
    if candidates.is_empty() {
        format!("Register '{id}' is not in the architecture register list")
    } else {
        format!("Register '{}' is not defined. Did you mean: {}?",
            id, candidates.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
    }
}

fn suggest_non_bool_condition(actual: ILSize) -> String {
    format!(
        "Wrap the condition with CmpNe(1, condition, Const(1, 0)) or use a comparison \
         expression that produces ILSize::B1 (got {actual} bytes)"
    )
}

fn suggest_extension_error(op: &str, src: ILSize, dst: ILSize) -> String {
    if dst <= src {
        format!("{op}: use LowPart({dst}, src) to shrink from {src} to {dst} bytes")
    } else {
        format!("{op}: ensure dst_size ({dst}) > src_size ({src})")
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct VerificationStats {
    pub total_instructions:   usize,
    pub valid_instructions:   usize,
    pub violation_count:      usize,
    pub error_count:          usize,
    pub warning_count:        usize,
    pub info_count:           usize,
    /// Percentage of instructions that have no violations.
    pub coverage_pct:         f64,
    /// Number of unique violation kinds seen.
    pub unique_violation_kinds: usize,
    /// Max violation depth (nested expression level where violation was found).
    pub max_expr_depth:       usize,
}

impl VerificationStats {
    fn compute(total: usize, violations: &[Violation]) -> Self {
        let violation_count = violations.len();
        let error_count   = violations.iter().filter(|v| v.severity == Severity::Error).count();
        let warning_count = violations.iter().filter(|v| v.severity == Severity::Warning).count();
        let info_count    = violations.iter().filter(|v| v.severity == Severity::Info).count();
        // Instructions with at least one violation
        let bad_insns: HashSet<usize> = violations.iter().map(|v| v.instruction_idx).collect();
        let valid_instructions = total.saturating_sub(bad_insns.len());
        let coverage_pct = if total == 0 { 100.0 } else {
            (f64::from(u32::try_from(valid_instructions).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))) * 100.0
        };
        // Unique kinds
        let mut kinds: HashSet<String> = HashSet::new();
        for v in violations {
            kinds.insert(format!("{:?}", std::mem::discriminant(&v.kind)));
        }
        Self {
            total_instructions:   total,
            valid_instructions,
            violation_count,
            error_count,
            warning_count,
            info_count,
            coverage_pct,
            unique_violation_kinds: kinds.len(),
            max_expr_depth: 0,
        }
    }
}

impl fmt::Display for VerificationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "Instructions: {}/{} valid ({:.1}%), Violations: {} ({} errors, {} warnings, {} info)",
            self.valid_instructions, self.total_instructions, self.coverage_pct,
            self.violation_count, self.error_count, self.warning_count, self.info_count
        )
    }
}

// ---------------------------------------------------------------------------
// Verification report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub function_name: String,
    pub violations:    Vec<Violation>,
    pub stats:         VerificationStats,
}

impl VerificationReport {
    #[must_use] 
    pub fn is_valid(&self) -> bool {
        !self.violations.iter().any(|v| v.severity == Severity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Violation> {
        self.violations.iter().filter(|v| v.severity == Severity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Violation> {
        self.violations.iter().filter(|v| v.severity == Severity::Warning)
    }

    #[must_use] 
    pub fn for_instruction(&self, idx: usize) -> Vec<&Violation> {
        self.violations.iter().filter(|v| v.instruction_idx == idx).collect()
    }
}

impl fmt::Display for VerificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== LLIL Verification: {} ===", self.function_name)?;
        writeln!(f, "{}", self.stats)?;
        if self.violations.is_empty() {
            writeln!(f, "No violations found.")?;
        } else {
            for v in &self.violations {
                writeln!(f, "  {v}")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Expression verifier (recursive)
// ---------------------------------------------------------------------------

struct ExprVerifier<'a> {
    arch:     &'a ArchDesc,
    insn_idx: usize,
    depth:    usize,
    max_depth: &'a mut usize,
}

impl<'a> ExprVerifier<'a> {
    const fn new(arch: &'a ArchDesc, insn_idx: usize, max_depth: &'a mut usize) -> Self {
        ExprVerifier { arch, insn_idx, depth: 0, max_depth }
    }

    /// Depth at which deeply-nested expressions are flagged with an Info
    /// note (purely informational — not a correctness issue, but useful for
    /// downstream simplification passes).
    const DEEP_EXPR_INFO_THRESHOLD: usize = 16;

    const fn push(&mut self) { self.depth += 1; if self.depth > *self.max_depth { *self.max_depth = self.depth; } }
    const fn pop(&mut self)  { if self.depth > 0 { self.depth -= 1; } }

    /// Emit an Info-level diagnostic when a nested expression crosses
    /// [`Self::DEEP_EXPR_INFO_THRESHOLD`]. Called by [`verify_expr`] on entry.
    fn maybe_note_depth(&self, violations: &mut Vec<Violation>) {
        if self.depth == Self::DEEP_EXPR_INFO_THRESHOLD {
            violations.push(self.v_info(
                ViolationKind::DeadCode, // reused as a generic "informational" kind
                format!(
                    "expression nesting reached depth {} — consider simplification",
                    self.depth
                ),
            ));
        }
    }

    fn v_error(&self, kind: ViolationKind, desc: impl Into<String>, hint: Option<String>) -> Violation {
        Violation { instruction_idx: self.insn_idx, severity: Severity::Error,
            kind, description: desc.into(), suggestion: hint }
    }
    fn v_warn(&self, kind: ViolationKind, desc: impl Into<String>, hint: Option<String>) -> Violation {
        Violation { instruction_idx: self.insn_idx, severity: Severity::Warning,
            kind, description: desc.into(), suggestion: hint }
    }
    fn v_info(&self, kind: ViolationKind, desc: impl Into<String>) -> Violation {
        Violation { instruction_idx: self.insn_idx, severity: Severity::Info,
            kind, description: desc.into(), suggestion: None }
    }

    fn vexpr_reg(&self, id: &RegId, size: ILSize, v: &mut Vec<Violation>) {
        if !self.arch.is_valid_register(id) {
            let hint = suggest_undefined_register(id, self.arch);
            v.push(self.v_error(ViolationKind::UndefinedRegister(id.clone()),
                format!("register {id} used but not defined in arch"), Some(hint)));
        } else if let Some(arch_size) = self.arch.register_size(id)
            && arch_size != size {
            v.push(self.v_error(
                ViolationKind::SizeMismatch { expected: arch_size, actual: size, context: format!("Reg({id})") },
                format!("register {id} is {arch_size} bytes but used as {size}"),
                Some(suggest_size_mismatch(arch_size, size, &format!("Reg({id})")))));
        }
    }

    fn vexpr_reg_split(&self, high: &RegId, low: &RegId, size: ILSize, v: &mut Vec<Violation>) {
        for rid in &[high, low] {
            if !self.arch.is_valid_register(rid) {
                let hint = suggest_undefined_register(rid, self.arch);
                v.push(self.v_error(ViolationKind::UndefinedRegister((*rid).clone()),
                    format!("register {rid} in RegSplit not defined in arch"), Some(hint)));
            }
        }
        if let (Some(hs), Some(ls)) = (self.arch.register_size(high), self.arch.register_size(low)) {
            if hs != ls {
                v.push(self.v_warn(
                    ViolationKind::SizeMismatch { expected: hs, actual: ls, context: "RegSplit halves".into() },
                    format!("RegSplit halves have different sizes: {hs} vs {ls}"), None));
            }
            let expected_total = ILSize(u8::try_from((u16::from(hs.bytes()) * 2).min(u16::from(u8::MAX))).expect("bounded by u8::MAX"));
            if size != expected_total {
                v.push(self.v_error(
                    ViolationKind::SizeMismatch { expected: expected_total, actual: size, context: "RegSplit result".into() },
                    format!("RegSplit result should be {expected_total} bytes (2x {hs} byte halves)"), None));
            }
        }
    }

    fn vexpr_load(&mut self, size: ILSize, src: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(src, v);
        let src_size = src.result_size();
        if src_size != self.arch.pointer_size {
            v.push(self.v_error(
                ViolationKind::LoadAddressSizeMismatch { actual: src_size, expected: self.arch.pointer_size },
                format!("Load address is {} bytes but pointer size is {}", src_size, self.arch.pointer_size),
                Some(format!("Use ZeroExtend({}, addr) or SignExtend to adjust the address expression", self.arch.pointer_size))));
        }
        let _ = size;
    }

    fn vexpr_binary_arith(&mut self, size: ILSize, left: &LlilExpr, right: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(left, v);
        self.verify_expr(right, v);
        let ls = left.result_size();
        let rs = right.result_size();
        if ls != size {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: size, actual: ls, context: "left operand".into() },
                format!("left operand size {ls} != op result size {size}"),
                Some(suggest_size_mismatch(size, ls, "left operand"))));
        }
        if rs != size {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: size, actual: rs, context: "right operand".into() },
                format!("right operand size {rs} != op result size {size}"),
                Some(suggest_size_mismatch(size, rs, "right operand"))));
        }
    }

    fn vexpr_shift(&mut self, size: ILSize, left: &LlilExpr, right: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(left, v);
        self.verify_expr(right, v);
        let ls = left.result_size();
        if ls != size {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: size, actual: ls, context: "shift operand".into() },
                format!("shift operand {ls} bytes != result size {size}"),
                Some(suggest_size_mismatch(size, ls, "shift left operand"))));
        }
    }

    fn vexpr_div(&mut self, size: ILSize, left: &LlilExpr, right: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(left, v);
        self.verify_expr(right, v);
        if let LlilExpr::Const { value: 0, .. } = right {
            v.push(self.v_error(ViolationKind::ConstantDivideByZero,
                String::from("divisor is constant zero"),
                Some(String::from("Replace with a non-zero divisor or add a guard"))));
        }
        let ls = left.result_size();
        let rs = right.result_size();
        if ls != size || rs != size {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: size, actual: ls, context: "div/mod operand".into() },
                format!("div operand sizes: left={ls}, right={rs}, result={size}"), None));
        }
    }

    fn vexpr_wide_mul(&mut self, size: ILSize, left: &LlilExpr, right: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(left, v);
        self.verify_expr(right, v);
        let ls = left.result_size();
        let expected_result = ILSize(ls.bytes() * 2);
        if size != expected_result {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: expected_result, actual: size, context: "MulDp result".into() },
                format!("double-precision multiply result should be {expected_result} bytes for {ls} byte operands"), None));
        }
    }

    fn vexpr_cmp(&mut self, size: ILSize, left: &LlilExpr, right: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(left, v);
        self.verify_expr(right, v);
        let ls = left.result_size();
        let rs = right.result_size();
        if ls != rs {
            v.push(self.v_warn(ViolationKind::SizeMismatch { expected: ls, actual: rs, context: "comparison operands".into() },
                format!("comparison operands have different sizes: {ls} vs {rs}"),
                Some(format!("Sign-extend or zero-extend one operand to match the other ({} bytes)", ls.max(rs)))));
        }
        let _ = size;
    }

    fn vexpr_unary(&mut self, size: ILSize, src: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(src, v);
        let ss = src.result_size();
        if ss != size {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: size, actual: ss, context: "unary operand".into() },
                format!("unary operand {ss} bytes != result size {size}"),
                Some(suggest_size_mismatch(size, ss, "unary operand"))));
        }
    }

    fn vexpr_float_binary(&mut self, size: ILSize, left: &LlilExpr, right: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(left, v);
        self.verify_expr(right, v);
        if !matches!(size.bytes(), 4 | 8 | 10 | 16) {
            v.push(self.v_warn(ViolationKind::InvalidOperation { op: "float".into(), reason: format!("unusual float size: {size}") },
                format!("float op has unusual size {size} bytes"),
                Some("Standard float sizes are 4 (f32) or 8 (f64)".into())));
        }
        let ls = left.result_size();
        let rs = right.result_size();
        if ls != size || rs != size {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: size, actual: ls, context: "float op operand".into() },
                format!("float operand sizes: left={ls}, right={rs}, result={size}"), None));
        }
    }

    fn vexpr_adc(&mut self, size: ILSize, left: &LlilExpr, right: &LlilExpr, carry: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(left, v);
        self.verify_expr(right, v);
        self.verify_expr(carry, v);
        let cs = carry.result_size();
        if cs != ILSize::B1 {
            v.push(self.v_warn(ViolationKind::NonBoolCondition { actual_size: cs },
                format!("ADC carry should be B1 (bool), got {cs}"),
                Some("Carry should be a 1-byte expression from a flag or comparison".into())));
        }
        let ls = left.result_size();
        let rs = right.result_size();
        if ls != size || rs != size {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: size, actual: ls, context: "Adc operand".into() },
                format!("Adc operand sizes mismatch: left={ls}, right={rs}, result={size}"), None));
        }
    }

    fn vexpr_sbb(&mut self, size: ILSize, left: &LlilExpr, right: &LlilExpr, borrow: &LlilExpr, v: &mut Vec<Violation>) {
        self.verify_expr(left, v);
        self.verify_expr(right, v);
        self.verify_expr(borrow, v);
        let bs = borrow.result_size();
        if bs != ILSize::B1 {
            v.push(self.v_warn(ViolationKind::NonBoolCondition { actual_size: bs },
                format!("SBB borrow should be B1 (bool), got {bs}"), None));
        }
        let ls = left.result_size();
        if ls != size {
            v.push(self.v_error(ViolationKind::SizeMismatch { expected: size, actual: ls, context: "Sbb operand".into() },
                format!("Sbb operand size {ls} != result {size}"), None));
        }
    }

    fn vexpr_address_of(&self, size: ILSize, id: &RegId, v: &mut Vec<Violation>) {
        if size != self.arch.pointer_size {
            v.push(self.v_warn(ViolationKind::SizeMismatch { expected: self.arch.pointer_size, actual: size, context: "AddressOf".into() },
                format!("AddressOf result is {size} bytes, expected pointer size {}", self.arch.pointer_size), None));
        }
        if !self.arch.is_valid_register(id) {
            let hint = suggest_undefined_register(id, self.arch);
            v.push(self.v_error(ViolationKind::UndefinedRegister(id.clone()),
                format!("AddressOf references undefined register {id}"), Some(hint)));
        }
    }

    fn verify_expr(&mut self, expr: &LlilExpr, violations: &mut Vec<Violation>) {
        self.push();
        self.maybe_note_depth(violations);
        match expr {
            LlilExpr::Reg { id, size } => self.vexpr_reg(id, *size, violations),
            LlilExpr::RegSplit { high, low, size } => self.vexpr_reg_split(high, low, *size, violations),
            LlilExpr::Flag { id } => {
                if !self.arch.is_valid_flag(id) {
                    let valid = self.arch.flags.iter().map(String::as_str).collect::<Vec<_>>().join(", ");
                    violations.push(self.v_error(ViolationKind::UndefinedFlag(id.clone()),
                        format!("flag {id} not defined in architecture"), Some(format!("Valid flags: {valid}"))));
                }
            }
            LlilExpr::Load { size, src } => self.vexpr_load(*size, src, violations),
            LlilExpr::Add { size, left, right }
            | LlilExpr::Sub { size, left, right }
            | LlilExpr::Mul { size, left, right }
            | LlilExpr::And { size, left, right }
            | LlilExpr::Or  { size, left, right }
            | LlilExpr::Xor { size, left, right } => self.vexpr_binary_arith(*size, left, right, violations),
            LlilExpr::Lsl { size, left, right }
            | LlilExpr::Lsr { size, left, right }
            | LlilExpr::Asr { size, left, right }
            | LlilExpr::Ror { size, left, right }
            | LlilExpr::Rol { size, left, right } => self.vexpr_shift(*size, left, right, violations),
            LlilExpr::Divu { size, left, right }
            | LlilExpr::Divs { size, left, right }
            | LlilExpr::Modu { size, left, right }
            | LlilExpr::Mods { size, left, right } => self.vexpr_div(*size, left, right, violations),
            LlilExpr::MulsDp { size, left, right }
            | LlilExpr::MuluDp { size, left, right } => self.vexpr_wide_mul(*size, left, right, violations),
            LlilExpr::CmpE  { size, left, right }
            | LlilExpr::CmpNe  { size, left, right }
            | LlilExpr::CmpSlt { size, left, right }
            | LlilExpr::CmpUlt { size, left, right }
            | LlilExpr::CmpSle { size, left, right }
            | LlilExpr::CmpUle { size, left, right }
            | LlilExpr::CmpSgt { size, left, right }
            | LlilExpr::CmpUgt { size, left, right }
            | LlilExpr::CmpSge { size, left, right }
            | LlilExpr::CmpUge { size, left, right } => self.vexpr_cmp(*size, left, right, violations),
            LlilExpr::Neg { size, src } | LlilExpr::Not { size, src } => self.vexpr_unary(*size, src, violations),
            LlilExpr::SignExtend { size, src } => {
                self.verify_expr(src, violations);
                let ss = src.result_size();
                if *size <= ss {
                    violations.push(self.v_error(ViolationKind::ExtensionSizeError { op: "SignExtend", src_size: ss, dst_size: *size },
                        format!("SignExtend: dst {size} bytes must be > src {ss} bytes"),
                        Some(suggest_extension_error("SignExtend", ss, *size))));
                }
            }
            LlilExpr::ZeroExtend { size, src } => {
                self.verify_expr(src, violations);
                let ss = src.result_size();
                if *size <= ss {
                    violations.push(self.v_error(ViolationKind::ExtensionSizeError { op: "ZeroExtend", src_size: ss, dst_size: *size },
                        format!("ZeroExtend: dst {size} bytes must be > src {ss} bytes"),
                        Some(suggest_extension_error("ZeroExtend", ss, *size))));
                }
            }
            LlilExpr::LowPart { size, src } => {
                self.verify_expr(src, violations);
                let ss = src.result_size();
                if *size >= ss {
                    violations.push(self.v_error(ViolationKind::TruncationSizeError { src_size: ss, dst_size: *size },
                        format!("LowPart: dst {size} bytes must be < src {ss} bytes"),
                        Some(format!("Ensure LowPart destination size ({size}) < source size ({ss})"))));
                }
            }
            LlilExpr::Fadd { size, left, right }
            | LlilExpr::Fsub { size, left, right }
            | LlilExpr::Fmul { size, left, right }
            | LlilExpr::Fdiv { size, left, right } => self.vexpr_float_binary(*size, left, right, violations),
            LlilExpr::FloatConv  { size, src }
            | LlilExpr::FloatToInt { size, src }
            | LlilExpr::IntToFloat { size, src } => { self.verify_expr(src, violations); let _ = size; }
            LlilExpr::Adc { size, left, right, carry } => self.vexpr_adc(*size, left, right, carry, violations),
            LlilExpr::Sbb { size, left, right, borrow } => self.vexpr_sbb(*size, left, right, borrow, violations),
            LlilExpr::AddressOf { size, id } => self.vexpr_address_of(*size, id, violations),
            LlilExpr::Const { .. }
            | LlilExpr::ConstPtr { .. }
            | LlilExpr::Undef { .. }
            | LlilExpr::Temp { .. } => {}
        }
        self.pop();
    }
}

// ---------------------------------------------------------------------------
// Statement verifier
// ---------------------------------------------------------------------------

fn vstmt_push_violation(violations: &mut Vec<Violation>, insn_idx: usize, severity: Severity, kind: ViolationKind, desc: String, hint: Option<String>) {
    violations.push(Violation { instruction_idx: insn_idx, severity, kind, description: desc, suggestion: hint });
}

fn vstmt_vexpr(expr: &LlilExpr, insn_idx: usize, arch: &ArchDesc, violations: &mut Vec<Violation>, max_depth: &mut usize) {
    let mut ev = ExprVerifier::new(arch, insn_idx, max_depth);
    ev.verify_expr(expr, violations);
}

fn vstmt_setreg(dest: &RegId, src: &LlilExpr, insn_idx: usize, arch: &ArchDesc, v: &mut Vec<Violation>, md: &mut usize) {
    vstmt_vexpr(src, insn_idx, arch, v, md);
    if !arch.is_valid_register(dest) {
        let hint = suggest_undefined_register(dest, arch);
        vstmt_push_violation(v, insn_idx, Severity::Error, ViolationKind::UndefinedRegister(dest.clone()),
            format!("SetReg destination '{dest}' not in architecture"), Some(hint));
    } else if let Some(reg_sz) = arch.register_size(dest) {
        let val_sz = src.result_size();
        if reg_sz != val_sz {
            vstmt_push_violation(v, insn_idx, Severity::Error,
                ViolationKind::SizeMismatch { expected: reg_sz, actual: val_sz, context: format!("SetReg {dest}") },
                format!("SetReg {dest}: register is {reg_sz} bytes but value is {val_sz}"),
                Some(suggest_size_mismatch(reg_sz, val_sz, &format!("SetReg {dest}"))));
        }
    }
}

fn vstmt_setregsplit(high: &RegId, low: &RegId, src: &LlilExpr, insn_idx: usize, arch: &ArchDesc, v: &mut Vec<Violation>, md: &mut usize) {
    vstmt_vexpr(src, insn_idx, arch, v, md);
    for rid in &[high, low] {
        if !arch.is_valid_register(rid) {
            let hint = suggest_undefined_register(rid, arch);
            vstmt_push_violation(v, insn_idx, Severity::Error, ViolationKind::UndefinedRegister((*rid).clone()),
                format!("SetRegSplit: register '{rid}' not in architecture"), Some(hint));
        }
    }
    let src_sz = src.result_size();
    if let (Some(hs), Some(ls)) = (arch.register_size(high), arch.register_size(low)) {
        let expected = ILSize(hs.bytes() + ls.bytes());
        if src_sz != expected {
            vstmt_push_violation(v, insn_idx, Severity::Error,
                ViolationKind::SizeMismatch { expected, actual: src_sz, context: "SetRegSplit src".into() },
                format!("SetRegSplit: source is {src_sz} bytes, expected {expected} bytes ({hs} + {ls})"), None);
        }
    }
}

fn vstmt_setflag(flag: &FlagId, src: &LlilExpr, insn_idx: usize, arch: &ArchDesc, v: &mut Vec<Violation>, md: &mut usize) {
    vstmt_vexpr(src, insn_idx, arch, v, md);
    if !arch.is_valid_flag(flag) {
        vstmt_push_violation(v, insn_idx, Severity::Error, ViolationKind::UndefinedFlag(flag.clone()),
            format!("SetFlag: flag '{flag}' not defined in architecture"),
            Some(format!("Valid flags: {}", arch.flags.iter().map(String::as_str).collect::<Vec<_>>().join(", "))));
    }
    let sz = src.result_size();
    if sz != ILSize::B1 {
        vstmt_push_violation(v, insn_idx, Severity::Warning,
            ViolationKind::SizeMismatch { expected: ILSize::B1, actual: sz, context: "SetFlag value".into() },
            format!("SetFlag value should be 1 byte (bool), got {sz}"),
            Some("Flags should be set from comparison expressions (CmpE, etc.) that produce B1".into()));
    }
}

fn vstmt_store(size: ILSize, dest: &LlilExpr, src: &LlilExpr, insn_idx: usize, arch: &ArchDesc, v: &mut Vec<Violation>, md: &mut usize) {
    vstmt_vexpr(dest, insn_idx, arch, v, md);
    vstmt_vexpr(src, insn_idx, arch, v, md);
    let addr_sz = dest.result_size();
    if addr_sz != arch.pointer_size {
        vstmt_push_violation(v, insn_idx, Severity::Warning,
            ViolationKind::LoadAddressSizeMismatch { actual: addr_sz, expected: arch.pointer_size },
            format!("Store address is {addr_sz} bytes, expected pointer size {}", arch.pointer_size),
            Some(format!("Ensure address expression produces {} bytes", arch.pointer_size)));
    }
    if size > arch.pointer_size {
        vstmt_push_violation(v, insn_idx, Severity::Error,
            ViolationKind::StoreOversized { store_size: size, pointer_size: arch.pointer_size },
            format!("Store size {size} > pointer size {}", arch.pointer_size),
            Some("Reduce store size or use multiple stores".into()));
    }
    let val_sz = src.result_size();
    if val_sz != size {
        vstmt_push_violation(v, insn_idx, Severity::Error,
            ViolationKind::SizeMismatch { expected: size, actual: val_sz, context: "Store value".into() },
            format!("Store declared size {size} but value has size {val_sz}"),
            Some(suggest_size_mismatch(size, val_sz, "Store value")));
    }
}

fn verify_stmt(
    stmt:       &LlilStmt,
    insn_idx:   usize,
    arch:       &ArchDesc,
    violations: &mut Vec<Violation>,
    max_depth:  &mut usize,
    stack_delta: &mut i64,
) {
    macro_rules! vexpr { ($e:expr) => { vstmt_vexpr($e, insn_idx, arch, violations, max_depth) }; }
    macro_rules! err { ($kind:expr, $desc:expr, $hint:expr) => {
        vstmt_push_violation(violations, insn_idx, Severity::Error, $kind, $desc.to_string(), $hint) }; }

    match stmt {
        LlilStmt::SetReg { dest, src } => vstmt_setreg(dest, src, insn_idx, arch, violations, max_depth),
        LlilStmt::SetRegSplit { high, low, src } => vstmt_setregsplit(high, low, src, insn_idx, arch, violations, max_depth),
        LlilStmt::SetFlag { flag, src } => vstmt_setflag(flag, src, insn_idx, arch, violations, max_depth),
        LlilStmt::Store { size, dest, src } => vstmt_store(*size, dest, src, insn_idx, arch, violations, max_depth),
        LlilStmt::Push { size, src } => {
            vexpr!(src);
            *stack_delta -= i64::from((*size).bytes());
            let val_sz = src.result_size();
            if val_sz != *size {
                err!(ViolationKind::SizeMismatch { expected: *size, actual: val_sz, context: "Push".into() },
                    format!("Push declared size {} but value is {}", size, val_sz),
                    Some(suggest_size_mismatch(*size, val_sz, "Push operand")));
            }
        }
        LlilStmt::Pop { size, dest } => {
            *stack_delta += i64::from((*size).bytes());
            if !arch.is_valid_register(dest) {
                let hint = suggest_undefined_register(dest, arch);
                err!(ViolationKind::UndefinedRegister(dest.clone()),
                    format!("Pop destination '{}' not in architecture", dest), Some(hint));
            } else if let Some(reg_sz) = arch.register_size(dest) && reg_sz != *size {
                err!(ViolationKind::SizeMismatch { expected: reg_sz, actual: *size, context: "Pop".into() },
                    format!("Pop size {} but destination register is {}", size, reg_sz), None);
            }
        }
        LlilStmt::Jump { target } => {
            vexpr!(target);
            let ts = target.result_size();
            if ts != arch.pointer_size {
                err!(ViolationKind::InvalidCallTarget { actual_size: ts },
                    format!("Jump target is {} bytes, expected pointer size {}", ts, arch.pointer_size),
                    Some(format!("Ensure jump target is {} bytes", arch.pointer_size)));
            }
        }
        LlilStmt::JumpIf { cond, .. } => {
            vexpr!(cond);
            let cs = cond.result_size();
            if cs != ILSize::B1 {
                err!(ViolationKind::NonBoolCondition { actual_size: cs },
                    format!("JumpIf condition is {} bytes, must be 1 (bool)", cs),
                    Some(suggest_non_bool_condition(cs)));
            }
        }
        LlilStmt::JumpTo { targets } => { for (_, cond) in targets { vexpr!(cond); } }
        LlilStmt::Call { target, params } => {
            vexpr!(target);
            let ts = target.result_size();
            if ts != arch.pointer_size {
                err!(ViolationKind::InvalidCallTarget { actual_size: ts },
                    format!("Call target is {} bytes, expected pointer size {}", ts, arch.pointer_size),
                    Some(format!("Call target must be {} bytes (pointer-sized)", arch.pointer_size)));
            }
            for p in params { vexpr!(p); }
        }
        LlilStmt::Ret { src } => { vexpr!(src); }
        LlilStmt::Intrinsic { inputs, outputs, .. } => {
            for inp in inputs { vexpr!(inp); }
            for out in outputs {
                if !arch.is_valid_register(out) {
                    let hint = suggest_undefined_register(out, arch);
                    err!(ViolationKind::UndefinedRegister(out.clone()),
                        format!("Intrinsic output register '{}' not in architecture", out), Some(hint));
                }
            }
        }
        LlilStmt::Nop | LlilStmt::Undef | LlilStmt::Trap { .. } | LlilStmt::Syscall => {}
    }
}

// ---------------------------------------------------------------------------
// Main verifier
// ---------------------------------------------------------------------------

/// LLIL type and consistency verifier.
pub struct LlilVerifier {
    arch: ArchDesc,
}

impl LlilVerifier {
    #[must_use] 
    pub const fn new(arch: ArchDesc) -> Self { Self { arch } }

    #[must_use] 
    pub fn for_x86_64() -> Self { Self::new(ArchDesc::x86_64()) }

    /// Verify a sequence of LLIL statements (a single function body).
    #[must_use] 
    pub fn verify(
        &self,
        function_name: &str,
        stmts:         &[LlilStmt],
    ) -> VerificationReport {
        let mut violations  = Vec::new();
        let mut max_depth   = 0usize;
        let mut stack_delta = 0i64;

        for (idx, stmt) in stmts.iter().enumerate() {
            verify_stmt(stmt, idx, &self.arch, &mut violations, &mut max_depth, &mut stack_delta);
        }

        // Check overall stack balance (if non-zero, warn)
        if stack_delta != 0 {
            violations.push(Violation {
                instruction_idx: stmts.len().saturating_sub(1),
                severity:        Severity::Warning,
                kind:            ViolationKind::StackImbalance { delta: stack_delta },
                description:     format!("function has net stack delta of {stack_delta} bytes"),
                suggestion:      Some("Ensure push/pop count is balanced, or this is a non-standard calling convention".into()),
            });
        }

        let mut vstats = VerificationStats::compute(stmts.len(), &violations);
        vstats.max_expr_depth = max_depth;

        VerificationReport {
            function_name: function_name.to_string(),
            violations,
            stats: vstats,
        }
    }

    /// Quick validity check — returns true if no errors (warnings allowed).
    #[must_use] 
    pub fn is_valid(&self, stmts: &[LlilStmt]) -> bool {
        self.verify("", stmts).is_valid()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> LlilVerifier { LlilVerifier::for_x86_64() }

    fn reg(name: &str, size: u8) -> LlilExpr {
        LlilExpr::Reg { size: ILSize(size), id: RegId(name.into()) }
    }

    fn cnst(size: u8, value: u64) -> LlilExpr {
        LlilExpr::Const { size: ILSize(size), value }
    }

    #[test]
    fn test_valid_setreg() {
        let v = verifier();
        let stmts = vec![LlilStmt::SetReg { dest: RegId("rax".into()), src: cnst(8, 42) }];
        let report = v.verify("test", &stmts);
        assert!(report.is_valid(), "unexpected violations: {:?}", report.violations);
    }

    #[test]
    fn test_setreg_size_mismatch() {
        let v = verifier();
        let stmts = vec![LlilStmt::SetReg {
            dest: RegId("rax".into()),
            src: cnst(4, 42),  // 4 bytes but rax is 8
        }];
        let report = v.verify("test", &stmts);
        assert!(!report.is_valid());
        assert!(report.violations.iter().any(|v| matches!(v.kind, ViolationKind::SizeMismatch { .. })));
    }

    #[test]
    fn test_undefined_register() {
        let v = verifier();
        let stmts = vec![LlilStmt::SetReg { dest: RegId("xyz99".into()), src: cnst(8, 0) }];
        let report = v.verify("test", &stmts);
        assert!(report.violations.iter().any(|v| matches!(v.kind, ViolationKind::UndefinedRegister(_))));
    }

    #[test]
    fn test_jump_if_non_bool() {
        let v = verifier();
        let stmts = vec![LlilStmt::JumpIf {
            cond:         cnst(4, 1),  // 4 bytes instead of 1
            true_target:  0x1000,
            false_target: 0x2000,
        }];
        let report = v.verify("test", &stmts);
        assert!(report.violations.iter().any(|v| matches!(v.kind, ViolationKind::NonBoolCondition { .. })));
    }

    #[test]
    fn test_jump_if_bool_ok() {
        let v = verifier();
        let stmts = vec![LlilStmt::JumpIf {
            cond: LlilExpr::CmpE {
                size:  ILSize::B8,
                left:  Box::new(reg("rax", 8)),
                right: Box::new(cnst(8, 0)),
            },
            true_target:  0x1000,
            false_target: 0x2000,
        }];
        let report = v.verify("test", &stmts);
        assert!(report.is_valid());
    }

    #[test]
    fn test_sign_extend_invalid() {
        let v = verifier();
        // SignExtend from 8 to 4 bytes (wrong direction)
        let stmts = vec![LlilStmt::SetReg {
            dest: RegId("eax".into()),
            src: LlilExpr::SignExtend {
                size: ILSize::B4,
                src:  Box::new(reg("rax", 8)),
            },
        }];
        let report = v.verify("test", &stmts);
        assert!(report.violations.iter().any(|v| matches!(v.kind, ViolationKind::ExtensionSizeError { .. })));
    }

    #[test]
    fn test_zero_extend_valid() {
        let v = verifier();
        let stmts = vec![LlilStmt::SetReg {
            dest: RegId("rax".into()),
            src: LlilExpr::ZeroExtend {
                size: ILSize::B8,
                src:  Box::new(reg("eax", 4)),
            },
        }];
        let report = v.verify("test", &stmts);
        assert!(report.is_valid(), "{:?}", report.violations);
    }

    #[test]
    fn test_const_divide_by_zero() {
        let v = verifier();
        let stmts = vec![LlilStmt::SetReg {
            dest: RegId("rax".into()),
            src: LlilExpr::Divu {
                size:  ILSize::B8,
                left:  Box::new(cnst(8, 100)),
                right: Box::new(cnst(8, 0)),  // divide by zero!
            },
        }];
        let report = v.verify("test", &stmts);
        assert!(report.violations.iter().any(|v| matches!(v.kind, ViolationKind::ConstantDivideByZero)));
    }

    #[test]
    fn test_call_target_size() {
        let v = verifier();
        let stmts = vec![LlilStmt::Call {
            target: cnst(4, 0x1234),  // should be 8 bytes for x86-64
            params: vec![],
        }];
        let report = v.verify("test", &stmts);
        assert!(report.violations.iter().any(|v| matches!(v.kind, ViolationKind::InvalidCallTarget { .. })));
    }

    #[test]
    fn test_stack_balance() {
        let v = verifier();
        let stmts = vec![
            LlilStmt::Push { size: ILSize::B8, src: cnst(8, 0) },
            LlilStmt::Push { size: ILSize::B8, src: cnst(8, 0) },
            LlilStmt::Pop  { size: ILSize::B8, dest: RegId("rax".into()) },
            // Missing second pop — stack imbalance
        ];
        let report = v.verify("test", &stmts);
        assert!(report.violations.iter().any(|v| matches!(v.kind, ViolationKind::StackImbalance { .. })));
    }

    #[test]
    fn test_stats() {
        let v = verifier();
        let stmts: Vec<LlilStmt> = vec![
            LlilStmt::SetReg { dest: RegId("rax".into()), src: cnst(8, 1) },
            LlilStmt::Nop,
        ];
        let report = v.verify("test_fn", &stmts);
        assert_eq!(report.stats.total_instructions, 2);
        assert_eq!(report.stats.valid_instructions, 2);
        assert!((report.stats.coverage_pct - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_lowpart_valid() {
        let v = verifier();
        let stmts = vec![LlilStmt::SetReg {
            dest: RegId("eax".into()),
            src:  LlilExpr::LowPart { size: ILSize::B4, src: Box::new(reg("rax", 8)) },
        }];
        let report = v.verify("test", &stmts);
        assert!(report.is_valid(), "{:?}", report.violations);
    }

    #[test]
    fn test_lowpart_invalid() {
        let v = verifier();
        // LowPart to larger size is invalid
        let stmts = vec![LlilStmt::SetReg {
            dest: RegId("rax".into()),
            src:  LlilExpr::LowPart { size: ILSize::B8, src: Box::new(reg("eax", 4)) },
        }];
        let report = v.verify("test", &stmts);
        assert!(report.violations.iter().any(|v| matches!(v.kind, ViolationKind::TruncationSizeError { .. })));
    }
}
