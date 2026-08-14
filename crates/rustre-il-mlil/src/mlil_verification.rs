//! `mlil_verification` — Verify MLIL SSA correctness.
//!
//! Verifies that a Medium-Level Intermediate Language (MLIL) function in SSA
//! form obeys the SSA invariants: single-definition, proper phi-node placement,
//! dominance of all uses by their definitions.
//!
//! # Key types
//! - [`MlilVerification`]         — top-level SSA verifier
//! - [`SsaVerifier`]              — checks single-assignment property
//! - [`PhiConsistency`]           — validates phi-node operand counts
//! - [`UseDefCheck`]              — verifies every use is dominated by its def
//! - [`DominanceVerifier`]        — builds and exposes the dominator tree
//! - [`MlilVerificationReport`]   — aggregated report

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight SSA/MLIL model for standalone tests
// ─────────────────────────────────────────────────────────────────────────────

/// An SSA variable: `name#version`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SsaVar {
    pub name: String,
    pub version: u32,
}

impl SsaVar {
    #[must_use]
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self { name: name.into(), version }
    }
}

impl std::fmt::Display for SsaVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.name, self.version)
    }
}

/// A simplified MLIL expression.
#[derive(Debug, Clone)]
pub enum MExpr {
    Var(SsaVar),
    Const(i64),
    Add(Box<Self>, Box<Self>),
    Sub(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Xor(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Load(u8, Box<Self>), // (size_bytes, addr)
    Phi(Vec<SsaVar>),     // PHI node
    Call(Box<Self>, Vec<Self>),
    Cmp(CmpOp, Box<Self>, Box<Self>),
}

impl MExpr {
    /// Collect all [`SsaVar`] references (uses) in this expression.
    #[must_use]
    pub fn uses(&self) -> Vec<SsaVar> {
        match self {
            Self::Var(v) => vec![v.clone()],
            Self::Const(_) => vec![],
            Self::Add(a, b) | Self::Sub(a, b) | Self::Mul(a, b)
            | Self::And(a, b) | Self::Or(a, b) | Self::Xor(a, b)
            | Self::Cmp(_, a, b) => {
                let mut v = a.uses(); v.extend(b.uses()); v
            }
            Self::Not(e) | Self::Load(_, e) => e.uses(),
            Self::Phi(vars) => vars.clone(),
            Self::Call(target, args) => {
                let mut v = target.uses();
                for a in args { v.extend(a.uses()); }
                v
            }
        }
    }

    /// `true` if this expression is a phi node.
    #[must_use]
    pub const fn is_phi(&self) -> bool { matches!(self, Self::Phi(_)) }
}

/// Comparison operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp { Eq, Ne, Lt, Gt, Le, Ge }

/// A simplified MLIL instruction.
#[derive(Debug, Clone)]
pub enum MInsn {
    /// `ssa_var = expr`
    Assign(SsaVar, MExpr),
    /// `*[addr_expr] = val_expr`
    Store(u8, MExpr, MExpr),
    /// Unconditional branch to block index.
    Goto(usize),
    /// Conditional branch.
    If(MExpr, usize, usize),
    /// Return.
    Return(Option<MExpr>),
    /// Intrinsic call with output variables.
    Intrinsic(Vec<SsaVar>, String, Vec<MExpr>),
}

impl MInsn {
    /// Collect all SSA variable definitions in this instruction.
    #[must_use]
    pub fn definitions(&self) -> Vec<SsaVar> {
        match self {
            Self::Assign(v, _) => vec![v.clone()],
            Self::Intrinsic(outs, _, _) => outs.clone(),
            _ => vec![],
        }
    }

    /// Collect all SSA variable uses.
    #[must_use]
    pub fn uses(&self) -> Vec<SsaVar> {
        match self {
            Self::Assign(_, e) => e.uses(),
            Self::Store(_, a, v) => { let mut u = a.uses(); u.extend(v.uses()); u }
            Self::Goto(_) => vec![],
            Self::If(cond, _, _) => cond.uses(),
            Self::Return(Some(e)) => e.uses(),
            Self::Return(None) => vec![],
            Self::Intrinsic(_, _, args) => args.iter().flat_map(MExpr::uses).collect(),
        }
    }
}

/// A basic block of MLIL instructions.
#[derive(Debug, Clone)]
pub struct MBlock {
    pub id: usize,
    pub instructions: Vec<MInsn>,
    pub address: u64,
    pub predecessors: Vec<usize>,
    pub successors: Vec<usize>,
}

impl MBlock {
    #[must_use]
    pub const fn new(id: usize, address: u64) -> Self {
        Self { id, instructions: Vec::new(), address, predecessors: Vec::new(), successors: Vec::new() }
    }
}

/// A simplified MLIL SSA function.
#[derive(Debug, Clone)]
pub struct MFunction {
    pub name: String,
    pub entry: usize,
    pub blocks: Vec<MBlock>,
}

impl MFunction {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), entry: 0, blocks: Vec::new() }
    }

    pub fn add_block(&mut self, block: MBlock) {
        self.blocks.push(block);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostic
// ─────────────────────────────────────────────────────────────────────────────

/// Severity of an MLIL verification diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MSeverity {
    Info,
    Warning,
    Error,
    Fatal,
}

impl std::fmt::Display for MSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A verification diagnostic for MLIL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MDiagnostic {
    pub severity: MSeverity,
    pub pass: String,
    pub message: String,
    pub block_id: Option<usize>,
    pub insn_index: Option<usize>,
}

impl MDiagnostic {
    #[must_use]
    pub fn new(severity: MSeverity, pass: impl Into<String>, message: impl Into<String>) -> Self {
        Self { severity, pass: pass.into(), message: message.into(), block_id: None, insn_index: None }
    }

    #[must_use]
    pub const fn at(mut self, block_id: usize, insn_index: usize) -> Self {
        self.block_id = Some(block_id);
        self.insn_index = Some(insn_index);
        self
    }

    #[must_use]
    pub fn display(&self) -> String {
        let loc = match (self.block_id, self.insn_index) {
            (Some(b), Some(i)) => format!(" (bb{b}:insn{i})"),
            _ => String::new(),
        };
        format!("{} [{}] {}{}", self.severity, self.pass, self.message, loc)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SsaVerifier — single-definition check
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies the single-assignment property: each SSA variable is defined at
/// most once across the entire function.
#[derive(Debug, Default)]
pub struct SsaVerifier {
    diagnostics: Vec<MDiagnostic>,
}

impl SsaVerifier {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Run the check on `func`.
    pub fn check(&mut self, func: &MFunction) {
        let mut defined: HashMap<SsaVar, (usize, usize)> = HashMap::new(); // var → (block, insn)

        for block in &func.blocks {
            for (idx, insn) in block.instructions.iter().enumerate() {
                for def in insn.definitions() {
                    if let Some((prev_block, prev_idx)) = defined.get(&def) {
                        self.diagnostics.push(MDiagnostic::new(
                            MSeverity::Error,
                            "SsaVerifier",
                            format!(
                                "SSA variable '{}' defined more than once: first at bb{}:insn{}, again at bb{}:insn{}",
                                def, prev_block, prev_idx, block.id, idx
                            ),
                        ).at(block.id, idx));
                    } else {
                        defined.insert(def, (block.id, idx));
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<MDiagnostic> { self.diagnostics }

    #[must_use]
    pub fn error_count(&self) -> usize {
        self.diagnostics.iter().filter(|d| d.severity >= MSeverity::Error).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PhiConsistency — phi node operand check
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that each phi-node operand count matches the number of
/// predecessors of the block containing the phi.
#[derive(Debug, Default)]
pub struct PhiConsistency {
    diagnostics: Vec<MDiagnostic>,
}

impl PhiConsistency {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Check all phi nodes in `func`.
    pub fn check(&mut self, func: &MFunction) {
        for block in &func.blocks {
            let pred_count = block.predecessors.len();
            for (idx, insn) in block.instructions.iter().enumerate() {
                if let MInsn::Assign(_, MExpr::Phi(operands)) = insn {
                    // Phi at entry block must have 0 operands or exactly 1 (initial value).
                    if block.id == func.entry && !operands.is_empty() && operands.len() != 1 {
                        self.diagnostics.push(MDiagnostic::new(
                            MSeverity::Warning,
                            "PhiConsistency",
                            format!("Phi at entry block {} has {} operands (expected 0 or 1)", block.id, operands.len()),
                        ).at(block.id, idx));
                    } else if block.id != func.entry && pred_count > 1 && operands.len() != pred_count {
                        self.diagnostics.push(MDiagnostic::new(
                            MSeverity::Error,
                            "PhiConsistency",
                            format!(
                                "Phi in bb{} has {} operands but block has {} predecessors",
                                block.id, operands.len(), pred_count
                            ),
                        ).at(block.id, idx));
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<MDiagnostic> { self.diagnostics }

    #[must_use]
    pub fn error_count(&self) -> usize {
        self.diagnostics.iter().filter(|d| d.severity >= MSeverity::Error).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DominanceVerifier — dominator tree builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the immediate-dominator tree for a function's CFG using a simple
/// iterative algorithm (Cooper et al.).
#[derive(Debug, Default)]
pub struct DominanceVerifier {
    /// `idom[n]` = immediate dominator of block `n` (`usize::MAX` for entry).
    pub idom: Vec<usize>,
    diagnostics: Vec<MDiagnostic>,
}

impl DominanceVerifier {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Compute the dominator tree for `func`.
    pub fn compute(&mut self, func: &MFunction) {
        let n = func.blocks.len();
        if n == 0 {
            self.diagnostics.push(MDiagnostic::new(
                MSeverity::Error, "DominanceVerifier", "Empty function",
            ));
            return;
        }

        // Build predecessor list indexed by block id.
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for block in &func.blocks {
            for &succ in &block.successors {
                if succ < n { preds[succ].push(block.id); }
            }
            // Also use explicit predecessors field.
            for &p in &block.predecessors {
                if p < n && !preds[block.id].contains(&p) {
                    preds[block.id].push(p);
                }
            }
        }

        // RPO order (simple BFS from entry for a connected CFG).
        let order = self.rpo(func);

        // Initialise idom.
        self.idom = vec![usize::MAX; n];
        self.idom[func.entry] = func.entry;

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &order {
                if b == func.entry { continue; }
                let mut new_idom = usize::MAX;
                for &p in &preds[b] {
                    if self.idom[p] == usize::MAX { continue; }
                    if new_idom == usize::MAX {
                        new_idom = p;
                    } else {
                        new_idom = self.intersect(new_idom, p, &order);
                    }
                }
                if new_idom != self.idom[b] {
                    self.idom[b] = new_idom;
                    changed = true;
                }
            }
        }
    }

    /// `true` if block `a` dominates block `b`.
    #[must_use]
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        if a == b { return true; }
        let n = self.idom.len();
        if b >= n { return false; }
        let mut current = b;
        loop {
            let dom = self.idom[current];
            if dom == current { return dom == a; }
            if dom >= n || dom == usize::MAX { return false; }
            if dom == a { return true; }
            current = dom;
        }
    }

    fn rpo(&self, func: &MFunction) -> Vec<usize> {
        let n = func.blocks.len();
        let mut visited = vec![false; n];
        let mut postorder = Vec::new();
        // Iterative DFS collecting nodes in postorder (after all successors).
        let mut stack: Vec<(usize, usize)> = vec![(func.entry, 0)];
        if func.entry < n {
            visited[func.entry] = true;
        }
        while let Some((b, idx)) = stack.last_mut() {
            let b = *b;
            let successors = &func.blocks[b].successors;
            if *idx < successors.len() {
                let s = successors[*idx];
                *idx += 1;
                if s < n && !visited[s] {
                    visited[s] = true;
                    stack.push((s, 0));
                }
            } else {
                stack.pop();
                postorder.push(b);
            }
        }
        postorder.reverse();
        postorder
    }

    fn intersect(&self, mut a: usize, mut b: usize, order: &[usize]) -> usize {
        let pos: HashMap<usize, usize> = order.iter().enumerate().map(|(i, &b)| (b, i)).collect();
        let n = self.idom.len();
        loop {
            if a == b { return a; }
            let pa = pos.get(&a).copied().unwrap_or(usize::MAX);
            let pb = pos.get(&b).copied().unwrap_or(usize::MAX);
            if pa > pb { a = if self.idom[a] < n { self.idom[a] } else { break a }; }
            else { b = if self.idom[b] < n { self.idom[b] } else { break b }; }
        }
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<MDiagnostic> { self.diagnostics }
}

// ─────────────────────────────────────────────────────────────────────────────
// UseDefCheck — every use dominated by its def
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that every use of an SSA variable is dominated by its definition.
#[derive(Debug, Default)]
pub struct UseDefCheck {
    diagnostics: Vec<MDiagnostic>,
}

impl UseDefCheck {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Check `func` given a precomputed [`DominanceVerifier`].
    pub fn check(&mut self, func: &MFunction, dom: &DominanceVerifier) {
        // Build a map: ssa_var → defining block id.
        let mut def_block: HashMap<SsaVar, usize> = HashMap::new();
        for block in &func.blocks {
            for insn in &block.instructions {
                for d in insn.definitions() {
                    def_block.insert(d, block.id);
                }
            }
        }

        // For every use, check that the defining block dominates the using block.
        for block in &func.blocks {
            for (idx, insn) in block.instructions.iter().enumerate() {
                // Skip phi uses (they reference predecessor blocks, not current block).
                if let MInsn::Assign(_, MExpr::Phi(_)) = insn { continue; }

                for used in insn.uses() {
                    if let Some(&def_b) = def_block.get(&used) {
                        if !dom.dominates(def_b, block.id) {
                            self.diagnostics.push(MDiagnostic::new(
                                MSeverity::Error,
                                "UseDefCheck",
                                format!(
                                    "Use of '{}' in bb{}:insn{} not dominated by definition in bb{}",
                                    used, block.id, idx, def_b
                                ),
                            ).at(block.id, idx));
                        }
                    } else {
                        // Undefined variable — might be a function parameter (version 0).
                        if used.version != 0 {
                            self.diagnostics.push(MDiagnostic::new(
                                MSeverity::Error,
                                "UseDefCheck",
                                format!("Use of undefined SSA variable '{used}'"),
                            ).at(block.id, idx));
                        }
                    }
                }
            }
        }
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<MDiagnostic> { self.diagnostics }

    #[must_use]
    pub fn error_count(&self) -> usize {
        self.diagnostics.iter().filter(|d| d.severity >= MSeverity::Error).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilVerificationReport
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated MLIL verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlilVerificationReport {
    pub function_name: String,
    pub diagnostics: Vec<MDiagnostic>,
    pub passed: bool,
}

impl MlilVerificationReport {
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.diagnostics.iter().filter(|d| d.severity >= MSeverity::Error).count()
    }

    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.diagnostics.iter().filter(|d| d.severity == MSeverity::Warning).count()
    }

    #[must_use]
    pub fn by_pass(&self, pass: &str) -> Vec<&MDiagnostic> {
        self.diagnostics.iter().filter(|d| d.pass == pass).collect()
    }

    /// All distinct pass names that produced at least one diagnostic, in
    /// alphabetical order (uses a [`BTreeMap`] internally).
    #[must_use]
    pub fn passes_seen(&self) -> Vec<String> {
        let mut by: BTreeMap<String, usize> = BTreeMap::new();
        for d in &self.diagnostics {
            *by.entry(d.pass.clone()).or_insert(0) += 1;
        }
        by.into_keys().collect()
    }

    /// The set of distinct severities observed in the report.
    #[must_use]
    pub fn severities_seen(&self) -> HashSet<MSeverity> {
        self.diagnostics.iter().map(|d| d.severity).collect()
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "fn='{}' passed={} errors={} warnings={}",
            self.function_name, self.passed, self.error_count(), self.warning_count()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilVerification — top-level verifier
// ─────────────────────────────────────────────────────────────────────────────

/// Drives all MLIL SSA verification passes.
#[derive(Debug, Default)]
pub struct MlilVerification {
    pub enable_ssa_check: bool,
    pub enable_phi_check: bool,
    pub enable_use_def_check: bool,
    pub enable_dom_compute: bool,
}

impl MlilVerification {
    /// Create with all passes enabled.
    #[must_use]
    pub const fn all_passes() -> Self {
        Self {
            enable_ssa_check: true,
            enable_phi_check: true,
            enable_use_def_check: true,
            enable_dom_compute: true,
        }
    }

    /// Verify `func` and return a report.
    #[must_use] 
    pub fn verify(&self, func: &MFunction) -> MlilVerificationReport {
        let mut all_diags: Vec<MDiagnostic> = Vec::new();

        if self.enable_ssa_check {
            let mut sv = SsaVerifier::new();
            sv.check(func);
            all_diags.extend(sv.into_diagnostics());
        }

        if self.enable_phi_check {
            let mut pc = PhiConsistency::new();
            pc.check(func);
            all_diags.extend(pc.into_diagnostics());
        }

        let dom = if self.enable_dom_compute {
            let mut dv = DominanceVerifier::new();
            dv.compute(func);
            all_diags.extend(dv.diagnostics.clone()); // take errors from dom
            Some(dv)
        } else {
            None
        };

        if self.enable_use_def_check
            && let Some(ref dv) = dom {
                let mut ud = UseDefCheck::new();
                ud.check(func, dv);
                all_diags.extend(ud.into_diagnostics());
            }

        let has_error = all_diags.iter().any(|d| d.severity >= MSeverity::Error);
        MlilVerificationReport {
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

    fn make_valid_func() -> MFunction {
        let mut func = MFunction::new("valid_fn");
        let mut b = MBlock::new(0, 0x1000);
        let x1 = SsaVar::new("x", 1);
        b.instructions.push(MInsn::Assign(x1.clone(), MExpr::Const(42)));
        b.instructions.push(MInsn::Return(Some(MExpr::Var(x1))));
        func.add_block(b);
        func
    }

    // ── SsaVar ────────────────────────────────────────────────────────────────

    #[test]
    fn test_ssa_var_display() {
        let v = SsaVar::new("rax", 3);
        assert_eq!(v.to_string(), "rax#3");
    }

    #[test]
    fn test_ssa_var_equality() {
        let a = SsaVar::new("x", 1);
        let b = SsaVar::new("x", 1);
        assert_eq!(a, b);
    }

    #[test]
    fn test_ssa_var_version_distinguishes() {
        let a = SsaVar::new("x", 1);
        let b = SsaVar::new("x", 2);
        assert_ne!(a, b);
    }

    // ── MExpr uses ────────────────────────────────────────────────────────────

    #[test]
    fn test_mexpr_const_no_uses() {
        assert!(MExpr::Const(42).uses().is_empty());
    }

    #[test]
    fn test_mexpr_var_use() {
        let v = SsaVar::new("x", 1);
        let uses = MExpr::Var(v.clone()).uses();
        assert_eq!(uses, vec![v]);
    }

    #[test]
    fn test_mexpr_add_uses() {
        let x = SsaVar::new("x", 1);
        let y = SsaVar::new("y", 1);
        let e = MExpr::Add(Box::new(MExpr::Var(x.clone())), Box::new(MExpr::Var(y.clone())));
        let uses = e.uses();
        assert!(uses.contains(&x));
        assert!(uses.contains(&y));
    }

    #[test]
    fn test_mexpr_phi_uses() {
        let v1 = SsaVar::new("x", 1);
        let v2 = SsaVar::new("x", 2);
        let phi = MExpr::Phi(vec![v1.clone(), v2.clone()]);
        let uses = phi.uses();
        assert!(uses.contains(&v1));
        assert!(uses.contains(&v2));
    }

    #[test]
    fn test_mexpr_is_phi() {
        assert!(MExpr::Phi(vec![]).is_phi());
        assert!(!MExpr::Const(0).is_phi());
    }

    // ── MInsn ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_minsn_definitions_assign() {
        let v = SsaVar::new("x", 1);
        let insn = MInsn::Assign(v.clone(), MExpr::Const(0));
        assert_eq!(insn.definitions(), vec![v]);
    }

    #[test]
    fn test_minsn_definitions_goto() {
        let insn = MInsn::Goto(1);
        assert!(insn.definitions().is_empty());
    }

    #[test]
    fn test_minsn_uses_return() {
        let v = SsaVar::new("r", 1);
        let insn = MInsn::Return(Some(MExpr::Var(v.clone())));
        assert!(insn.uses().contains(&v));
    }

    // ── SsaVerifier ───────────────────────────────────────────────────────────

    #[test]
    fn test_ssa_verifier_valid() {
        let func = make_valid_func();
        let mut sv = SsaVerifier::new();
        sv.check(&func);
        assert_eq!(sv.error_count(), 0);
    }

    #[test]
    fn test_ssa_verifier_double_define() {
        let mut func = MFunction::new("f");
        let mut b = MBlock::new(0, 0x0);
        let x1 = SsaVar::new("x", 1);
        b.instructions.push(MInsn::Assign(x1.clone(), MExpr::Const(1)));
        b.instructions.push(MInsn::Assign(x1.clone(), MExpr::Const(2))); // double define
        b.instructions.push(MInsn::Return(None));
        func.add_block(b);
        let mut sv = SsaVerifier::new();
        sv.check(&func);
        assert!(sv.error_count() > 0);
    }

    // ── PhiConsistency ────────────────────────────────────────────────────────

    #[test]
    fn test_phi_consistency_valid_two_preds() {
        let mut func = MFunction::new("f");
        let mut b0 = MBlock::new(0, 0x0);
        b0.successors = vec![1];
        b0.instructions.push(MInsn::Goto(1));
        let mut b1 = MBlock::new(1, 0x10);
        b1.predecessors = vec![0, 2]; // two predecessors
        let phi_var = SsaVar::new("x", 3);
        b1.instructions.push(MInsn::Assign(
            phi_var,
            MExpr::Phi(vec![SsaVar::new("x", 1), SsaVar::new("x", 2)]), // 2 operands = 2 preds ✓
        ));
        b1.instructions.push(MInsn::Return(None));
        let mut b2 = MBlock::new(2, 0x20);
        b2.instructions.push(MInsn::Goto(1));
        func.add_block(b0);
        func.add_block(b1);
        func.add_block(b2);
        let mut pc = PhiConsistency::new();
        pc.check(&func);
        assert_eq!(pc.error_count(), 0);
    }

    #[test]
    fn test_phi_consistency_wrong_operand_count() {
        let mut func = MFunction::new("f");
        let mut b0 = MBlock::new(0, 0x0);
        b0.instructions.push(MInsn::Goto(1));
        let mut b1 = MBlock::new(1, 0x10);
        b1.predecessors = vec![0, 2]; // two predecessors
        let phi_var = SsaVar::new("x", 3);
        b1.instructions.push(MInsn::Assign(
            phi_var,
            MExpr::Phi(vec![SsaVar::new("x", 1)]), // only 1 operand — wrong!
        ));
        b1.instructions.push(MInsn::Return(None));
        let mut b2 = MBlock::new(2, 0x20);
        b2.instructions.push(MInsn::Goto(1));
        func.add_block(b0);
        func.add_block(b1);
        func.add_block(b2);
        let mut pc = PhiConsistency::new();
        pc.check(&func);
        assert!(pc.error_count() > 0);
    }

    // ── DominanceVerifier ─────────────────────────────────────────────────────

    #[test]
    fn test_dominance_single_block() {
        let func = make_valid_func();
        let mut dv = DominanceVerifier::new();
        dv.compute(&func);
        assert!(dv.dominates(0, 0));
    }

    #[test]
    fn test_dominance_two_blocks() {
        let mut func = MFunction::new("f");
        let mut b0 = MBlock::new(0, 0x0);
        b0.successors = vec![1];
        b0.instructions.push(MInsn::Goto(1));
        let mut b1 = MBlock::new(1, 0x10);
        b1.predecessors = vec![0];
        b1.instructions.push(MInsn::Return(None));
        func.add_block(b0);
        func.add_block(b1);
        let mut dv = DominanceVerifier::new();
        dv.compute(&func);
        assert!(dv.dominates(0, 1)); // entry dominates all
        assert!(!dv.dominates(1, 0)); // b1 does not dominate entry
    }

    // ── UseDefCheck ───────────────────────────────────────────────────────────

    #[test]
    fn test_use_def_valid() {
        let func = make_valid_func();
        let mut dv = DominanceVerifier::new();
        dv.compute(&func);
        let mut ud = UseDefCheck::new();
        ud.check(&func, &dv);
        assert_eq!(ud.error_count(), 0);
    }

    #[test]
    fn test_use_def_undefined_high_version() {
        let mut func = MFunction::new("f");
        let mut b = MBlock::new(0, 0x0);
        // Use x#5 without defining it anywhere
        b.instructions.push(MInsn::Return(Some(MExpr::Var(SsaVar::new("x", 5)))));
        func.add_block(b);
        let mut dv = DominanceVerifier::new();
        dv.compute(&func);
        let mut ud = UseDefCheck::new();
        ud.check(&func, &dv);
        assert!(ud.error_count() > 0);
    }

    // ── MlilVerification (top-level) ──────────────────────────────────────────

    #[test]
    fn test_mlil_verification_all_passes_valid() {
        let func = make_valid_func();
        let v = MlilVerification::all_passes();
        let rep = v.verify(&func);
        assert!(rep.passed, "Expected pass but got: {:?}", rep.diagnostics);
    }

    #[test]
    fn test_mlil_verification_detects_double_define() {
        let mut func = MFunction::new("f");
        let mut b = MBlock::new(0, 0x0);
        let x1 = SsaVar::new("x", 1);
        b.instructions.push(MInsn::Assign(x1.clone(), MExpr::Const(1)));
        b.instructions.push(MInsn::Assign(x1.clone(), MExpr::Const(2)));
        b.instructions.push(MInsn::Return(None));
        func.add_block(b);
        let v = MlilVerification::all_passes();
        let rep = v.verify(&func);
        assert!(!rep.passed);
    }

    #[test]
    fn test_mlil_report_summary() {
        let func = make_valid_func();
        let v = MlilVerification::all_passes();
        let rep = v.verify(&func);
        assert!(rep.summary().contains("passed=true"));
    }

    #[test]
    fn test_mlil_report_by_pass() {
        let mut func = MFunction::new("f");
        let mut b = MBlock::new(0, 0x0);
        let x1 = SsaVar::new("x", 1);
        b.instructions.push(MInsn::Assign(x1.clone(), MExpr::Const(1)));
        b.instructions.push(MInsn::Assign(x1.clone(), MExpr::Const(2)));
        b.instructions.push(MInsn::Return(None));
        func.add_block(b);
        let v = MlilVerification::all_passes();
        let rep = v.verify(&func);
        assert!(!rep.by_pass("SsaVerifier").is_empty());
    }

    #[test]
    fn test_mdiagnostic_display() {
        let d = MDiagnostic::new(MSeverity::Error, "SsaVerifier", "double define").at(1, 3);
        let s = d.display();
        assert!(s.contains("bb1:insn3"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(MSeverity::Fatal > MSeverity::Error);
        assert!(MSeverity::Error > MSeverity::Warning);
        assert!(MSeverity::Warning > MSeverity::Info);
    }
}
