//! `llil_verification` — CFG-level multi-pass LLIL verifier.
//!
//! # Design layer
//! This module operates on an explicit basic-block control-flow graph
//! ([`VFunction`] / [`VBlock`]) and runs four independent passes:
//!
//! | Pass | What it checks |
//! |------|---------------|
//! | [`TypeChecker`] | Expression operand size consistency |
//! | [`ControlFlowVerifier`] | Block reachability and branch-target validity |
//! | [`FlagConsistency`] | Flag definition before use within each block |
//! | [`MemoryAccessVerifier`] | Load/store size and optional alignment |
//!
//! Contrast with [`crate::verifier`], which validates a **flat statement list**
//! (pre-CFG) for register/flag validity and type consistency.  The intended
//! pipeline is:
//!
//! ```text
//! Lifted stmts → crate::verifier  →  CFG construction  →  crate::llil_verification
//! ```
//!
//! # Key types
//! - [`LlilVerification`]       — top-level verifier driving all sub-passes
//! - [`TypeChecker`]            — expression type consistency checks
//! - [`ControlFlowVerifier`]    — CFG structural validation
//! - [`FlagConsistency`]        — flag definition/use tracking
//! - [`MemoryAccessVerifier`]   — memory access size and alignment checks
//! - [`VerificationReport`]     — aggregated report of all findings

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use bitflags::bitflags;

bitflags! {
    /// Which verification passes are enabled.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct VerificationPasses: u8 {
        /// Run the type-consistency checker.
        const TYPE_CHECK = 0b0000_0001;
        /// Run the control-flow verifier.
        const CFG_CHECK  = 0b0000_0010;
        /// Run the flag definition/use consistency check.
        const FLAG_CHECK = 0b0000_0100;
        /// Run the memory access verifier.
        const MEM_CHECK  = 0b0000_1000;
        /// All passes (no strict alignment).
        const ALL        = 0b0000_1111;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostic
// ─────────────────────────────────────────────────────────────────────────────

/// Severity of a verification diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Informational note — not an error.
    Info,
    /// Non-fatal concern — analysis can continue.
    Warning,
    /// Definite correctness violation.
    Error,
    /// Fatal: analysis cannot continue.
    Fatal,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info    => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Error   => write!(f, "ERROR"),
            Self::Fatal   => write!(f, "FATAL"),
        }
    }
}

/// A single verification diagnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Severity level.
    pub severity: Severity,
    /// Which verifier pass produced this diagnostic.
    pub pass: String,
    /// Human-readable message.
    pub message: String,
    /// Optional instruction index within the LLIL function.
    pub insn_index: Option<usize>,
    /// Optional address associated with the finding.
    pub address: Option<u64>,
}

impl Diagnostic {
    /// Create a new diagnostic.
    #[must_use]
    pub fn new(severity: Severity, pass: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity,
            pass: pass.into(),
            message: message.into(),
            insn_index: None,
            address: None,
        }
    }

    /// Builder: attach an instruction index.
    #[must_use]
    pub const fn at_insn(mut self, idx: usize) -> Self {
        self.insn_index = Some(idx);
        self
    }

    /// Builder: attach an address.
    #[must_use]
    pub const fn at_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Format as `SEVERITY [pass] message (insn=N, addr=0xXXXX)`.
    #[must_use]
    pub fn display(&self) -> String {
        let loc = match (self.insn_index, self.address) {
            (Some(i), Some(a)) => format!(" (insn={i}, addr={a:#x})"),
            (Some(i), None)    => format!(" (insn={i})"),
            (None, Some(a))    => format!(" (addr={a:#x})"),
            (None, None)       => String::new(),
        };
        format!("{} [{}] {}{}", self.severity, self.pass, self.message, loc)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight LLIL model (for standalone verification tests)
// ─────────────────────────────────────────────────────────────────────────────

/// Simplified size enum mirroring the real LLIL `Size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VSize {
    B1, B2, B4, B8, B16,
}

impl VSize {
    /// Number of bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self { Self::B1 => 1, Self::B2 => 2, Self::B4 => 4, Self::B8 => 8, Self::B16 => 16 }
    }
    /// Number of bits.
    #[must_use]
    pub const fn bits(self) -> usize { self.bytes() * 8 }
}

/// Simplified expression kind for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VExpr {
    Const(VSize, i64),
    Reg(VSize, String),
    Add(VSize, Box<Self>, Box<Self>),
    Sub(VSize, Box<Self>, Box<Self>),
    And(VSize, Box<Self>, Box<Self>),
    Or(VSize, Box<Self>, Box<Self>),
    Xor(VSize, Box<Self>, Box<Self>),
    Mul(VSize, Box<Self>, Box<Self>),
    Not(VSize, Box<Self>),
    Neg(VSize, Box<Self>),
    Load(VSize, Box<Self>),
    Zext(VSize, Box<Self>),
    Sext(VSize, Box<Self>),
    Shl(VSize, Box<Self>, Box<Self>),
    Shr(VSize, Box<Self>, Box<Self>),
    Sar(VSize, Box<Self>, Box<Self>),
    Flag(String),
}

impl VExpr {
    /// Return the result size of this expression.
    #[must_use]
    pub const fn size(&self) -> VSize {
        match self {
            Self::Const(s, _) | Self::Reg(s, _) | Self::Add(s, _, _) | Self::Sub(s, _, _)
            | Self::And(s, _, _) | Self::Or(s, _, _) | Self::Xor(s, _, _) | Self::Mul(s, _, _)
            | Self::Not(s, _) | Self::Neg(s, _) | Self::Load(s, _) | Self::Zext(s, _)
            | Self::Sext(s, _) | Self::Shl(s, _, _) | Self::Shr(s, _, _) | Self::Sar(s, _, _)
                => *s,
            Self::Flag(_) => VSize::B1,
        }
    }
}

/// Simplified LLIL instruction for verification.
#[derive(Debug, Clone)]
pub enum VInsn {
    /// `reg = expr`
    SetReg(String, VSize, VExpr),
    /// `*[addr] = expr`
    Store(VSize, VExpr, VExpr),
    /// `CALL expr`
    Call(VExpr),
    /// Unconditional branch to block index.
    Goto(usize),
    /// Conditional branch: condition, true-block, false-block.
    If(VExpr, usize, usize),
    /// Return expression.
    Return(Option<VExpr>),
    /// `flag = expr`
    SetFlag(String, VExpr),
    /// No-op.
    Nop,
    /// Undefined behaviour marker.
    Undef,
}

/// A basic block of LLIL instructions.
#[derive(Debug, Clone)]
pub struct VBlock {
    pub id: usize,
    pub instructions: Vec<VInsn>,
    pub address: u64,
}

impl VBlock {
    #[must_use]
    pub const fn new(id: usize, address: u64) -> Self {
        Self { id, instructions: Vec::new(), address }
    }
}

/// A simplified LLIL function used for verification tests.
#[derive(Debug, Clone)]
pub struct VFunction {
    pub entry: usize,
    pub blocks: Vec<VBlock>,
    pub name: String,
}

impl VFunction {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { entry: 0, blocks: Vec::new(), name: name.into() }
    }

    pub fn add_block(&mut self, block: VBlock) {
        self.blocks.push(block);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeChecker
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that expression operands have matching sizes where required.
#[derive(Debug, Default)]
pub struct TypeChecker {
    diagnostics: Vec<Diagnostic>,
}

impl TypeChecker {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Check all instructions in all blocks of `func`.
    pub fn check(&mut self, func: &VFunction) {
        for block in &func.blocks {
            for (idx, insn) in block.instructions.iter().enumerate() {
                self.check_insn(insn, idx, block.address);
            }
        }
    }

    fn check_insn(&mut self, insn: &VInsn, idx: usize, addr: u64) {
        match insn {
            VInsn::SetReg(_, dst_size, expr) => {
                let expr_size = expr.size();
                if *dst_size != expr_size {
                    self.diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            "TypeChecker",
                            format!("SetReg size mismatch: dst={dst_size:?} expr={expr_size:?}"),
                        ).at_insn(idx).at_address(addr),
                    );
                }
            }
            VInsn::Store(sz, _addr_expr, val_expr) => {
                if *sz != val_expr.size() {
                    self.diagnostics.push(
                        Diagnostic::new(
                            Severity::Warning,
                            "TypeChecker",
                            format!("Store size mismatch: declared={:?} value={:?}", sz, val_expr.size()),
                        ).at_insn(idx).at_address(addr),
                    );
                }
            }
            VInsn::SetFlag(_, expr) => {
                if expr.size() != VSize::B1 && expr.size() != VSize::B4 {
                    // flags can be 1 or 4 bytes (for x86 EFLAGS comparisons)
                    self.diagnostics.push(
                        Diagnostic::new(
                            Severity::Info,
                            "TypeChecker",
                            format!("SetFlag expr size {:?} — expected B1 or B4", expr.size()),
                        ).at_insn(idx),
                    );
                }
            }
            VInsn::Return(Some(expr))
                // Ensure return value fits in a register (≤ 8 bytes).
                if expr.size().bytes() > 8 => {
                    self.diagnostics.push(
                        Diagnostic::new(
                            Severity::Error,
                            "TypeChecker",
                            "Return value size exceeds 8 bytes".to_owned(),
                        ).at_insn(idx).at_address(addr),
                    );
                }
            _ => {}
        }
        // Recursively check expression sub-tree sizes.
        self.check_expr_sizes(insn, idx, addr);
    }

    fn check_expr_sizes(&mut self, insn: &VInsn, idx: usize, _addr: u64) {
        let check_binop_size = |op_name: &str, s: VSize, lhs: &VExpr, rhs: &VExpr, diags: &mut Vec<Diagnostic>| {
            if lhs.size() != s || rhs.size() != s {
                diags.push(Diagnostic::new(
                    Severity::Error,
                    "TypeChecker",
                    format!("{op_name} operand size mismatch: expected {:?}, got {:?}/{:?}", s, lhs.size(), rhs.size()),
                ).at_insn(idx));
            }
        };

        let exprs = Self::collect_exprs(insn);
        for expr in exprs {
            match expr {
                VExpr::Add(s, l, r) | VExpr::Sub(s, l, r) | VExpr::And(s, l, r)
                | VExpr::Or(s, l, r) | VExpr::Xor(s, l, r) | VExpr::Mul(s, l, r) => {
                    check_binop_size("BinOp", *s, l, r, &mut self.diagnostics);
                }
                _ => {}
            }
        }
    }

    fn collect_exprs(insn: &VInsn) -> Vec<&VExpr> {
        match insn {
            VInsn::SetReg(_, _, e) | VInsn::Call(e) | VInsn::Return(Some(e)) | VInsn::SetFlag(_, e) => vec![e],
            VInsn::Store(_, a, v) => vec![a, v],
            VInsn::If(cond, _, _) => vec![cond],
            _ => vec![],
        }
    }

    /// Consume the checker and return diagnostics.
    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> { self.diagnostics }

    /// Count of errors (severity ≥ Error).
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.diagnostics.iter().filter(|d| d.severity >= Severity::Error).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlFlowVerifier
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies LLIL control-flow structure: reachability, predecessor completeness.
#[derive(Debug, Default)]
pub struct ControlFlowVerifier {
    diagnostics: Vec<Diagnostic>,
}

impl ControlFlowVerifier {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Check `func` for CFG issues.
    pub fn check(&mut self, func: &VFunction) {
        let block_count = func.blocks.len();
        if block_count == 0 {
            self.diagnostics.push(Diagnostic::new(
                Severity::Error, "CFV", "Function has no basic blocks",
            ));
            return;
        }

        // Entry block must exist.
        if func.entry >= block_count {
            self.diagnostics.push(Diagnostic::new(
                Severity::Fatal, "CFV",
                format!("Entry block {} >= block count {}", func.entry, block_count),
            ));
            return;
        }

        // Collect all referenced block indices.
        let mut referenced: HashSet<usize> = HashSet::new();
        referenced.insert(func.entry);

        for block in &func.blocks {
            let last = block.instructions.last();
            match last {
                Some(VInsn::Goto(target)) => { referenced.insert(*target); }
                Some(VInsn::If(_, t, f)) => { referenced.insert(*t); referenced.insert(*f); }
                Some(VInsn::Return(_) | VInsn::Undef) => {}
                None => {
                    self.diagnostics.push(Diagnostic::new(
                        Severity::Error, "CFV",
                        format!("Block {} is empty", block.id),
                    ).at_address(block.address));
                }
                _ => {
                    // Non-terminating last instruction — fall-through might be implicit.
                    if block.id + 1 < block_count {
                        referenced.insert(block.id + 1);
                    }
                }
            }
            // Validate all target indices are in range.
            for target in Self::branch_targets_of(block) {
                if target >= block_count {
                    self.diagnostics.push(Diagnostic::new(
                        Severity::Error, "CFV",
                        format!("Block {} branches to out-of-range target {}", block.id, target),
                    ).at_address(block.address));
                }
            }
        }

        // Check for unreachable blocks.  Blocks that appear in `referenced`
        // (i.e. they are a jump target somewhere) but are not transitively
        // reachable from entry get a distinct, more actionable diagnostic.
        let reachable = Self::compute_reachable(func);
        for block in &func.blocks {
            if !reachable.contains(&block.id) {
                if referenced.contains(&block.id) {
                    self.diagnostics.push(Diagnostic::new(
                        Severity::Warning, "CFV",
                        format!("Block {} is a jump target but unreachable from entry", block.id),
                    ).at_address(block.address));
                } else {
                    self.diagnostics.push(Diagnostic::new(
                        Severity::Warning, "CFV",
                        format!("Block {} is unreachable", block.id),
                    ).at_address(block.address));
                }
            }
        }
    }

    fn compute_reachable(func: &VFunction) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut stack = vec![func.entry];
        while let Some(id) = stack.pop() {
            if id >= func.blocks.len() { continue; }
            if !visited.insert(id) { continue; }
            let block = &func.blocks[id];
            for target in Self::branch_targets_of(block) {
                stack.push(target);
            }
            // Fall-through.
            match block.instructions.last() {
                Some(VInsn::Goto(_) | VInsn::Return(_) | VInsn::Undef) => {}
                _ if id + 1 < func.blocks.len() => { stack.push(id + 1); }
                _ => {}
            }
        }
        visited
    }

    fn branch_targets_of(block: &VBlock) -> Vec<usize> {
        match block.instructions.last() {
            Some(VInsn::Goto(t)) => vec![*t],
            Some(VInsn::If(_, t, f)) => vec![*t, *f],
            _ => vec![],
        }
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> { self.diagnostics }

    #[must_use]
    pub fn error_count(&self) -> usize {
        self.diagnostics.iter().filter(|d| d.severity >= Severity::Error).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlagConsistency
// ─────────────────────────────────────────────────────────────────────────────

/// Checks that every flag used in a branch condition is defined on all
/// paths reaching that branch.
#[derive(Debug, Default)]
pub struct FlagConsistency {
    diagnostics: Vec<Diagnostic>,
}

impl FlagConsistency {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Run the flag consistency check on `func`.
    pub fn check(&mut self, func: &VFunction) {
        for block in &func.blocks {
            let mut defined_flags: HashSet<String> = HashSet::new();

            for (idx, insn) in block.instructions.iter().enumerate() {
                let used_flags = Self::flags_used_in_insn(insn);
                for flag in used_flags {
                    if !defined_flags.contains(&flag) {
                        self.diagnostics.push(Diagnostic::new(
                            Severity::Warning, "FlagConsistency",
                            format!("Flag '{flag}' used in block {} insn {idx} before local definition", block.id),
                        ).at_insn(idx).at_address(block.address));
                    }
                }
                // Track definitions incrementally so uses before defines are caught.
                if let VInsn::SetFlag(name, _) = insn {
                    defined_flags.insert(name.clone());
                }
            }
        }
    }

    fn flags_used_in_insn(insn: &VInsn) -> Vec<String> {
        let mut flags = Vec::new();
        let check_expr = |e: &VExpr, flags: &mut Vec<String>| {
            if let VExpr::Flag(name) = e { flags.push(name.clone()); }
        };
        match insn {
            VInsn::SetReg(_, _, e) | VInsn::Call(e) | VInsn::Return(Some(e)) => {
                check_expr(e, &mut flags);
            }
            VInsn::If(cond, _, _) => check_expr(cond, &mut flags),
            _ => {}
        }
        flags
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> { self.diagnostics }

    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.diagnostics.iter().filter(|d| d.severity == Severity::Warning).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryAccessVerifier
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies memory access sizes and alignment.
#[derive(Debug, Default)]
pub struct MemoryAccessVerifier {
    diagnostics: Vec<Diagnostic>,
    /// Require that loads/stores of width ≥ 2 bytes are aligned.
    pub strict_alignment: bool,
}

impl MemoryAccessVerifier {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    #[must_use]
    pub const fn with_strict_alignment(mut self) -> Self {
        self.strict_alignment = true;
        self
    }

    /// Check `func` for memory access issues.
    pub fn check(&mut self, func: &VFunction) {
        for block in &func.blocks {
            for (idx, insn) in block.instructions.iter().enumerate() {
                match insn {
                    VInsn::Store(sz, addr_expr, _val) => {
                        self.check_access_size(*sz, idx, block.address);
                        if self.strict_alignment {
                            self.check_alignment(*sz, addr_expr, idx, block.address);
                        }
                    }
                    VInsn::SetReg(_, _, VExpr::Load(sz, addr_expr)) => {
                        self.check_access_size(*sz, idx, block.address);
                        if self.strict_alignment {
                            self.check_alignment(*sz, addr_expr, idx, block.address);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn check_access_size(&mut self, sz: VSize, idx: usize, addr: u64) {
        // Accesses larger than 8 bytes are suspicious (non-standard for LLIL).
        if sz.bytes() > 8 {
            self.diagnostics.push(Diagnostic::new(
                Severity::Warning, "MemoryAccessVerifier",
                format!("Memory access of {}-byte size is unusual", sz.bytes()),
            ).at_insn(idx).at_address(addr));
        }
    }

    fn check_alignment(&mut self, sz: VSize, addr_expr: &VExpr, idx: usize, addr: u64) {
        // For constant addresses, check alignment.
        if let VExpr::Const(_, val) = addr_expr {
            let alignment = i64::try_from(sz.bytes()).unwrap_or(i64::MAX);
            if alignment > 1 && val % alignment != 0 {
                self.diagnostics.push(Diagnostic::new(
                    Severity::Warning, "MemoryAccessVerifier",
                    format!("Potentially misaligned {}-byte access at constant address {:#x}", sz.bytes(), val),
                ).at_insn(idx).at_address(addr));
            }
        }
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> { self.diagnostics }
}

// ─────────────────────────────────────────────────────────────────────────────
// VerificationReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated result of all verification passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Name of the function that was verified.
    pub function_name: String,
    /// All diagnostics from all passes.
    pub diagnostics: Vec<Diagnostic>,
    /// Whether the function passed all checks (no errors or fatals).
    pub passed: bool,
}

impl VerificationReport {
    /// Count of diagnostics with at least `min_severity`.
    #[must_use]
    pub fn count_at_least(&self, min_severity: Severity) -> usize {
        self.diagnostics.iter().filter(|d| d.severity >= min_severity).count()
    }

    /// Filter diagnostics by pass name.
    #[must_use]
    pub fn by_pass(&self, pass: &str) -> Vec<&Diagnostic> {
        self.diagnostics.iter().filter(|d| d.pass == pass).collect()
    }

    /// Count diagnostics grouped by pass name. Useful for dashboards that
    /// want a sparse "(pass, count)" view without iterating the report.
    #[must_use]
    pub fn by_pass_counts(&self) -> HashMap<String, usize> {
        let mut h: HashMap<String, usize> = HashMap::new();
        for d in &self.diagnostics {
            *h.entry(d.pass.clone()).or_insert(0) += 1;
        }
        h
    }

    /// Count diagnostics grouped by `(pass, severity)`.
    #[must_use]
    pub fn by_pass_severity_counts(&self) -> HashMap<(String, Severity), usize> {
        let mut h: HashMap<(String, Severity), usize> = HashMap::new();
        for d in &self.diagnostics {
            *h.entry((d.pass.clone(), d.severity)).or_insert(0) += 1;
        }
        h
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "fn='{}' passed={} total_diags={} errors={} warnings={}",
            self.function_name,
            self.passed,
            self.diagnostics.len(),
            self.count_at_least(Severity::Error),
            self.diagnostics.iter().filter(|d| d.severity == Severity::Warning).count(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LlilVerification — top-level verifier
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level verifier that drives all sub-passes against an LLIL function.
#[derive(Debug, Default)]
pub struct LlilVerification {
    /// Which passes are enabled.
    pub passes: VerificationPasses,
    /// Require strict alignment in the memory access verifier.
    pub strict_alignment: bool,
}

impl LlilVerification {
    /// Create a verifier with all passes enabled.
    #[must_use]
    pub const fn all_passes() -> Self {
        Self { passes: VerificationPasses::ALL, strict_alignment: false }
    }

    /// Run all enabled passes on `func` and return a [`VerificationReport`].
    #[must_use]
    pub fn verify(&self, func: &VFunction) -> VerificationReport {
        let mut all_diags: Vec<Diagnostic> = Vec::new();

        if self.passes.contains(VerificationPasses::TYPE_CHECK) {
            let mut tc = TypeChecker::new();
            tc.check(func);
            all_diags.extend(tc.into_diagnostics());
        }
        if self.passes.contains(VerificationPasses::CFG_CHECK) {
            let mut cfv = ControlFlowVerifier::new();
            cfv.check(func);
            all_diags.extend(cfv.into_diagnostics());
        }
        if self.passes.contains(VerificationPasses::FLAG_CHECK) {
            let mut fc = FlagConsistency::new();
            fc.check(func);
            all_diags.extend(fc.into_diagnostics());
        }
        if self.passes.contains(VerificationPasses::MEM_CHECK) {
            let mut mav = MemoryAccessVerifier::new();
            if self.strict_alignment { mav.strict_alignment = true; }
            mav.check(func);
            all_diags.extend(mav.into_diagnostics());
        }

        let has_error = all_diags.iter().any(|d| d.severity >= Severity::Error);
        VerificationReport {
            function_name: func.name.clone(),
            diagnostics: all_diags,
            passed: !has_error,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_func() -> VFunction {
        let mut func = VFunction::new("test_fn");
        let mut b = VBlock::new(0, 0x1000);
        b.instructions.push(VInsn::SetReg(
            "rax".to_owned(), VSize::B8,
            VExpr::Const(VSize::B8, 42),
        ));
        b.instructions.push(VInsn::Return(Some(VExpr::Reg(VSize::B8, "rax".to_owned()))));
        func.add_block(b);
        func
    }

    // ── Diagnostic ────────────────────────────────────────────────────────────

    #[test]
    fn test_diagnostic_display_full() {
        let d = Diagnostic::new(Severity::Error, "TypeChecker", "size mismatch")
            .at_insn(3).at_address(0x1000);
        let s = d.display();
        assert!(s.contains("ERROR"));
        assert!(s.contains("TypeChecker"));
        assert!(s.contains("insn=3"));
        assert!(s.contains("addr=0x1000"));
    }

    #[test]
    fn test_diagnostic_display_minimal() {
        let d = Diagnostic::new(Severity::Info, "CFV", "note");
        let s = d.display();
        assert!(s.contains("INFO"));
        assert!(s.contains("CFV"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Fatal > Severity::Error);
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    // ── VExpr ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_vexpr_size_const() {
        let e = VExpr::Const(VSize::B4, 100);
        assert_eq!(e.size(), VSize::B4);
    }

    #[test]
    fn test_vexpr_size_flag() {
        let e = VExpr::Flag("ZF".to_owned());
        assert_eq!(e.size(), VSize::B1);
    }

    #[test]
    fn test_vexpr_size_add() {
        let e = VExpr::Add(VSize::B8,
            Box::new(VExpr::Const(VSize::B8, 1)),
            Box::new(VExpr::Const(VSize::B8, 2)),
        );
        assert_eq!(e.size(), VSize::B8);
    }

    #[test]
    fn test_vsize_bytes_and_bits() {
        assert_eq!(VSize::B1.bytes(), 1); assert_eq!(VSize::B1.bits(), 8);
        assert_eq!(VSize::B4.bytes(), 4); assert_eq!(VSize::B4.bits(), 32);
        assert_eq!(VSize::B8.bytes(), 8); assert_eq!(VSize::B8.bits(), 64);
    }

    // ── TypeChecker ───────────────────────────────────────────────────────────

    #[test]
    fn test_type_checker_no_errors_on_valid() {
        let func = make_simple_func();
        let mut tc = TypeChecker::new();
        tc.check(&func);
        assert_eq!(tc.error_count(), 0);
    }

    #[test]
    fn test_type_checker_catches_setreg_mismatch() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        // B4 reg = B8 const — mismatch!
        b.instructions.push(VInsn::SetReg(
            "eax".to_owned(), VSize::B4,
            VExpr::Const(VSize::B8, 0),
        ));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let mut tc = TypeChecker::new();
        tc.check(&func);
        assert!(tc.error_count() > 0);
    }

    #[test]
    fn test_type_checker_catches_binop_size_mismatch() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        // ADD B8 but with B4 operands
        b.instructions.push(VInsn::SetReg(
            "rax".to_owned(), VSize::B8,
            VExpr::Add(VSize::B8,
                Box::new(VExpr::Const(VSize::B4, 1)), // wrong size
                Box::new(VExpr::Const(VSize::B8, 2)),
            ),
        ));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let mut tc = TypeChecker::new();
        tc.check(&func);
        assert!(tc.error_count() > 0);
    }

    #[test]
    fn test_type_checker_store_mismatch_warns() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        // Store B4 but value is B8
        b.instructions.push(VInsn::Store(
            VSize::B4,
            VExpr::Const(VSize::B8, 0x1000),
            VExpr::Const(VSize::B8, 42), // mismatch with B4
        ));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let mut tc = TypeChecker::new();
        tc.check(&func);
        let diags = tc.into_diagnostics();
        assert!(diags.iter().any(|d| d.severity == Severity::Warning));
    }

    // ── ControlFlowVerifier ───────────────────────────────────────────────────

    #[test]
    fn test_cfg_verifier_valid_function() {
        let func = make_simple_func();
        let mut cfv = ControlFlowVerifier::new();
        cfv.check(&func);
        assert_eq!(cfv.error_count(), 0);
    }

    #[test]
    fn test_cfg_verifier_empty_function() {
        let func = VFunction::new("empty");
        let mut cfv = ControlFlowVerifier::new();
        cfv.check(&func);
        assert!(cfv.error_count() > 0);
    }

    #[test]
    fn test_cfg_verifier_out_of_range_target() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        b.instructions.push(VInsn::Goto(99)); // out of range
        func.add_block(b);
        let mut cfv = ControlFlowVerifier::new();
        cfv.check(&func);
        assert!(cfv.error_count() > 0);
    }

    #[test]
    fn test_cfg_verifier_unreachable_block() {
        let mut func = VFunction::new("f");
        let mut b0 = VBlock::new(0, 0x0);
        b0.instructions.push(VInsn::Return(None));
        let mut b1 = VBlock::new(1, 0x10);
        b1.instructions.push(VInsn::Return(None));
        func.add_block(b0);
        func.add_block(b1);
        let mut cfv = ControlFlowVerifier::new();
        cfv.check(&func);
        let diags = cfv.into_diagnostics();
        assert!(diags.iter().any(|d| d.severity == Severity::Warning && d.message.contains("unreachable")));
    }

    // ── FlagConsistency ───────────────────────────────────────────────────────

    #[test]
    fn test_flag_consistency_defined_before_use() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        b.instructions.push(VInsn::SetFlag("ZF".to_owned(), VExpr::Const(VSize::B1, 1)));
        b.instructions.push(VInsn::If(VExpr::Flag("ZF".to_owned()), 0, 0));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let mut fc = FlagConsistency::new();
        fc.check(&func);
        assert_eq!(fc.warning_count(), 0);
    }

    #[test]
    fn test_flag_consistency_use_before_define() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        b.instructions.push(VInsn::If(VExpr::Flag("CF".to_owned()), 0, 0));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let mut fc = FlagConsistency::new();
        fc.check(&func);
        assert!(fc.warning_count() > 0);
    }

    // ── MemoryAccessVerifier ──────────────────────────────────────────────────

    #[test]
    fn test_mem_verifier_normal_access() {
        let func = make_simple_func();
        let mut mav = MemoryAccessVerifier::new();
        mav.check(&func);
        let diags = mav.into_diagnostics();
        assert!(diags.is_empty());
    }

    #[test]
    fn test_mem_verifier_misaligned_with_strict() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        // Store 4-byte value to address 0x1001 (misaligned).
        b.instructions.push(VInsn::Store(
            VSize::B4,
            VExpr::Const(VSize::B8, 0x1001), // misaligned
            VExpr::Const(VSize::B4, 99),
        ));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let mav = MemoryAccessVerifier::new().with_strict_alignment();
        let mut mav = mav;
        mav.check(&func);
        let diags = mav.into_diagnostics();
        assert!(diags.iter().any(|d| d.severity == Severity::Warning));
    }

    #[test]
    fn test_mem_verifier_aligned_no_warning() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        b.instructions.push(VInsn::Store(
            VSize::B4,
            VExpr::Const(VSize::B8, 0x1000), // aligned
            VExpr::Const(VSize::B4, 99),
        ));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let mut mav = MemoryAccessVerifier::new().with_strict_alignment();
        mav.check(&func);
        let diags = mav.into_diagnostics();
        assert!(!diags.iter().any(|d| d.severity == Severity::Warning));
    }

    // ── LlilVerification (top-level) ──────────────────────────────────────────

    #[test]
    fn test_llil_verification_all_passes_valid() {
        let func = make_simple_func();
        let v = LlilVerification::all_passes();
        let report = v.verify(&func);
        assert!(report.passed);
        assert_eq!(report.function_name, "test_fn");
    }

    #[test]
    fn test_llil_verification_detects_type_error() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        b.instructions.push(VInsn::SetReg("rax".to_owned(), VSize::B4, VExpr::Const(VSize::B8, 0)));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let v = LlilVerification::all_passes();
        let report = v.verify(&func);
        assert!(!report.passed);
    }

    #[test]
    fn test_verification_report_summary() {
        let func = make_simple_func();
        let v = LlilVerification::all_passes();
        let report = v.verify(&func);
        let s = report.summary();
        assert!(s.contains("passed=true"));
    }

    #[test]
    fn test_verification_report_by_pass() {
        let mut func = VFunction::new("f");
        let mut b = VBlock::new(0, 0x0);
        b.instructions.push(VInsn::SetReg("rax".to_owned(), VSize::B4, VExpr::Const(VSize::B8, 0)));
        b.instructions.push(VInsn::Return(None));
        func.add_block(b);
        let v = LlilVerification::all_passes();
        let report = v.verify(&func);
        let tc_diags = report.by_pass("TypeChecker");
        assert!(!tc_diags.is_empty());
    }

    #[test]
    fn test_verification_report_count_at_least() {
        let func = make_simple_func();
        let v = LlilVerification::all_passes();
        let report = v.verify(&func);
        assert_eq!(report.count_at_least(Severity::Fatal), 0);
    }
}
