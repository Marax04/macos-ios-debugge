//! SSA reconstruction — convert non-SSA LLIL to pruned SSA (MLIL).
//!
//! # Algorithm
//! Uses the Braun et al. (2013) online SSA construction algorithm, which
//! builds SSA form directly without computing the full dominance-frontier set
//! upfront.  Phi nodes are inserted on-the-fly and removed if they turn out
//! to be trivial (all operands identical).
//!
//! # Layer distinction
//! This module sits at the **LLIL→MLIL lifting boundary**.  It operates on
//! [`rustre_il_llil::LlilFunction`] input and produces a renamed
//! `LlilFunction` plus phi metadata that a subsequent lifting step converts
//! to [`crate::MlilInstruction::Phi`] nodes.
//!
//! The [`PhiNode`] type in this module uses `operands: Vec<SsaVar>` (no
//! predecessor-block tagging), which differs from [`crate::mlil_ssa::SsaPhiNode`]
//! that carries `sources: Vec<(u32, SsaVar)>`.  They serve different phases:
//! this module is the *construction* phase; `mlil_ssa` is the *analysis* phase
//! over already-lifted MLIL.
//!
//! # Steps
//! 1. Assign fresh SSA versions to every definition (`SetReg`).
//! 2. Rename uses by walking the dominator tree, propagating the current
//!    reaching definition down each branch.
//! 3. Insert phi nodes at join points (blocks with multiple predecessors)
//!    using the "seal block" protocol.
//! 4. Remove trivial phis (one operand, or all operands identical).
//! 5. Out-of-SSA translation: insert copies at phi predecessors, then delete
//!    phi nodes.
//! 6. Coalescing: eliminate copy instructions introduced by out-of-SSA.

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use std::collections::VecDeque;

use rustre_il_llil::{LlilBasicBlock, LlilExpr, LlilFunction, LlilInstruction, LlilRegister};

use crate::SsaVar;

// ─────────────────────────────────────────────────────────────────────────────
// PhiNode
// ─────────────────────────────────────────────────────────────────────────────

/// A phi node inserted at a block join point.
#[derive(Debug, Clone)]
pub struct PhiNode {
    /// The SSA variable defined by this phi.
    pub dest: SsaVar,
    /// One operand per predecessor block (in predecessor order).
    pub operands: Vec<SsaVar>,
    /// True if this phi has been identified as trivial and should be removed.
    pub trivial: bool,
}

impl PhiNode {
    /// Returns `true` if all operands are the same variable (trivial phi).
    #[must_use]
    pub fn is_trivial(&self) -> bool {
        match self.operands.as_slice() {
            [] | [_] => true,
            [first, rest @ ..] => rest.iter().all(|v| v == first),
        }
    }

    /// If trivial, returns the single representative operand.
    #[must_use]
    pub fn trivial_operand(&self) -> Option<&SsaVar> {
        if self.is_trivial() {
            self.operands.first()
        } else {
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SsaVersionCounter
// ─────────────────────────────────────────────────────────────────────────────

/// Monotonically increasing SSA version counter per variable name.
#[derive(Debug, Clone, Default)]
pub struct SsaVersionCounter {
    counters: HashMap<String, u32>,
}

impl SsaVersionCounter {
    /// Allocate the next SSA version for `name`.
    pub fn next(&mut self, name: &str) -> SsaVar {
        let v = self.counters.entry(name.to_owned()).or_insert(0);
        let version = *v;
        *v += 1;
        SsaVar::new(name, version)
    }

    /// Peek at the current version without allocating.
    #[must_use]
    pub fn current(&self, name: &str) -> u32 {
        self.counters.get(name).copied().unwrap_or(0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ReachingDef — per-block reaching definition state
// ─────────────────────────────────────────────────────────────────────────────

/// Current reaching definition for each original variable at a block exit.
#[derive(Debug, Clone, Default)]
pub struct ReachingDef {
    /// Map from original variable name → current SSA version at block exit.
    pub defs: HashMap<String, SsaVar>,
}

impl ReachingDef {
    /// Look up the reaching definition for `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SsaVar> {
        self.defs.get(name)
    }

    /// Set the reaching definition for `name`.
    pub fn set(&mut self, name: impl Into<String>, var: SsaVar) {
        self.defs.insert(name.into(), var);
    }

    /// Merge another reaching-def map into this one (union; first writer wins).
    pub fn merge(&mut self, other: &Self) {
        for (k, v) in &other.defs {
            self.defs.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SsaBuilder — the Braun online SSA constructor
// ─────────────────────────────────────────────────────────────────────────────

/// Constructs pruned SSA form from a non-SSA function using the Braun
/// algorithm.
pub struct SsaBuilder {
    /// Version counter.
    pub counters: SsaVersionCounter,
    /// Reaching definitions at the *entry* of each block.
    pub block_entry: Vec<ReachingDef>,
    /// Reaching definitions at the *exit* of each block.
    pub block_exit: Vec<ReachingDef>,
    /// Phi nodes for each block (block index → list of phis).
    pub phis: Vec<Vec<PhiNode>>,
    /// Set of blocks that have been "sealed" (all predecessors processed).
    sealed: HashSet<usize>,
    /// Number of blocks.
    n_blocks: usize,
}

impl SsaBuilder {
    /// Create a builder for a function with `n_blocks` basic blocks.
    #[must_use] 
    pub fn new(n_blocks: usize) -> Self {
        Self {
            counters: SsaVersionCounter::default(),
            block_entry: vec![ReachingDef::default(); n_blocks],
            block_exit: vec![ReachingDef::default(); n_blocks],
            phis: vec![vec![]; n_blocks],
            sealed: HashSet::new(),
            n_blocks,
        }
    }

    /// Seal block `b`: all predecessors have been processed.
    pub fn seal_block(&mut self, b: usize) {
        self.sealed.insert(b);
    }

    /// Seal all blocks (used after processing the entire function).
    pub fn seal_all(&mut self) {
        for b in 0..self.n_blocks {
            self.sealed.insert(b);
        }
    }

    /// Record a new definition of `orig_name` in block `b`.
    /// Returns the fresh SSA variable allocated.
    pub fn write_var(&mut self, orig_name: &str, b: usize) -> SsaVar {
        let ssa_var = self.counters.next(orig_name);
        self.block_exit[b].set(orig_name, ssa_var.clone());
        ssa_var
    }

    /// Look up the reaching definition of `orig_name` at the entry of block `b`.
    /// May insert phi nodes if the block has multiple predecessors.
    pub fn read_var(
        &mut self,
        orig_name: &str,
        b: usize,
        preds: &[Vec<usize>],
    ) -> SsaVar {
        // Chase single-predecessor chains iteratively to avoid stack overflow on
        // long linear paths (unbounded recursion risk).
        let mut cur = b;
        loop {
            if let Some(v) = self.block_exit[cur].get(orig_name) {
                return v.clone();
            }
            if preds[cur].len() == 1 {
                cur = preds[cur][0];
                continue;
            }
            break;
        }
        let b = cur;
        // Fast path: already defined in this block's exit.
        if let Some(v) = self.block_exit[b].get(orig_name) {
            return v.clone();
        }
        // Multiple predecessors: need a phi.
        if !self.sealed.contains(&b) {
            // Block not yet sealed; insert incomplete phi.
            let phi_var = self.counters.next(orig_name);
            self.phis[b].push(PhiNode {
                dest: phi_var.clone(),
                operands: vec![],
                trivial: false,
            });
            self.block_exit[b].set(orig_name, phi_var.clone());
            return phi_var;
        }
        // Sealed with multiple predecessors: collect phi operands.
        let phi_var = self.counters.next(orig_name);
        // Reserve the phi slot first to break cycles.
        let phi_idx = self.phis[b].len();
        self.phis[b].push(PhiNode {
            dest: phi_var.clone(),
            operands: vec![],
            trivial: false,
        });
        self.block_exit[b].set(orig_name, phi_var.clone());

        let pred_list = preds[b].clone();
        let operands: Vec<SsaVar> = pred_list
            .iter()
            .map(|&pred| self.read_var(orig_name, pred, preds))
            .collect();
        self.phis[b][phi_idx].operands = operands;

        // Simplify trivial phi.
        if self.phis[b][phi_idx].is_trivial() {
            let representative = self.phis[b][phi_idx]
                .operands
                .first()
                .cloned()
                .unwrap_or_else(|| phi_var.clone());
            self.phis[b][phi_idx].trivial = true;
            self.block_exit[b].set(orig_name, representative.clone());
            return representative;
        }

        phi_var
    }

    /// Collect all non-trivial phi nodes.
    #[must_use] 
    pub fn non_trivial_phis(&self) -> Vec<(usize, &PhiNode)> {
        self.phis
            .iter()
            .enumerate()
            .flat_map(|(b, phis)| {
                phis.iter()
                    .filter(|p| !p.trivial)
                    .map(move |p| (b, p))
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DominanceFrontier
// ─────────────────────────────────────────────────────────────────────────────

/// Dominance frontier for a CFG block.
///
/// The dominance frontier of block `n` is the set of blocks `y` such that
/// `n` dominates some predecessor of `y` but does not strictly dominate `y`.
#[derive(Debug, Clone, Default)]
pub struct DominanceFrontier {
    /// `df[n]` = set of blocks in the dominance frontier of `n`.
    pub df: Vec<HashSet<usize>>,
}

impl DominanceFrontier {
    /// Compute the dominance frontier for all blocks using the Cooper et al.
    /// algorithm (requires an already-computed `idom` array).
    #[must_use] 
    pub fn compute(n: usize, idom: &[usize], preds: &[Vec<usize>]) -> Self {
        let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); n];

        for b in 0..n {
            if preds[b].len() >= 2 {
                for &p in &preds[b] {
                    let mut runner = p;
                    while runner != idom[b] {
                        df[runner].insert(b);
                        if idom[runner] == runner {
                            break;
                        }
                        runner = idom[runner];
                    }
                }
            }
        }

        Self { df }
    }

    /// Returns the dominance frontier of block `n`.
    #[must_use] 
    pub fn frontier(&self, n: usize) -> &HashSet<usize> {
        &self.df[n]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PhiInsertion — minimal (pruned) phi placement
// ─────────────────────────────────────────────────────────────────────────────

/// Result of the phi-insertion phase.
#[derive(Debug, Clone, Default)]
pub struct PhiPlacement {
    /// For each block and variable name, a phi node is needed.
    pub needs_phi: HashMap<(usize, String), bool>,
}

impl PhiPlacement {
    /// Compute where phi nodes are needed for each defined variable using the
    /// standard iterative dominance-frontier algorithm.
    ///
    /// `def_sites[v]` = set of blocks where variable `v` is defined.
    #[must_use] 
    pub fn compute(
        def_sites: &HashMap<String, HashSet<usize>>,
        df: &DominanceFrontier,
        _n: usize,
    ) -> Self {
        let mut needs_phi: HashMap<(usize, String), bool> = HashMap::new();

        for (var, defs) in def_sites {
            // Work-list: blocks that define the variable.
            let mut worklist: VecDeque<usize> = defs.iter().copied().collect();
            let mut in_worklist: HashSet<usize> = defs.iter().copied().collect();

            while let Some(b) = worklist.pop_front() {
                for &y in df.frontier(b) {
                    let key = (y, var.clone());
                    if !needs_phi.contains_key(&key) {
                        needs_phi.insert(key, true);
                        // y now defines the variable (via phi), so add to worklist.
                        if !in_worklist.contains(&y) {
                            in_worklist.insert(y);
                            worklist.push_back(y);
                        }
                    }
                }
            }
        }

        Self { needs_phi }
    }

    /// Returns `true` if a phi is needed for `var` at block `b`.
    #[must_use] 
    pub fn phi_needed(&self, b: usize, var: &str) -> bool {
        self.needs_phi
            .get(&(b, var.to_owned()))
            .copied()
            .unwrap_or(false)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OutOfSsaTranslation
// ─────────────────────────────────────────────────────────────────────────────

/// Translates SSA form back to non-SSA by inserting copies at phi predecessors
/// and removing phi nodes (the standard "lost copy" / "swap" method).
#[derive(Debug, Clone, Default)]
pub struct OutOfSsaTranslation {
    /// Map from SSA variable to its representative (post-coalescing).
    pub coalesce_map: HashMap<SsaVar, SsaVar>,
}

impl OutOfSsaTranslation {
    /// Build the coalesce map from a set of phi nodes.
    ///
    /// For each phi node `d = φ(v0, v1, …)`, if the phi is non-trivial, the
    /// operands and dest are placed in the same coalesce class.  All members
    /// of a class map to the minimum-version member.
    #[must_use] 
    pub fn build(phis: &[(usize, &PhiNode)]) -> Self {
        let mut union_find: HashMap<SsaVar, SsaVar> = HashMap::new();

        for (_, phi) in phis {
            // Find the minimum-version variable in the class.
            let mut class: Vec<SsaVar> = std::iter::once(phi.dest.clone())
                .chain(phi.operands.iter().cloned())
                .collect();
            class.sort();
            let repr = class[0].clone();

            for var in class {
                union_find.insert(var, repr.clone());
            }
        }

        Self {
            coalesce_map: union_find,
        }
    }

    /// Look up the coalesced representative of `var`.
    #[must_use] 
    pub fn repr<'a>(&'a self, var: &'a SsaVar) -> &'a SsaVar {
        self.coalesce_map.get(var).unwrap_or(var)
    }

    /// Apply coalescing to an `LlilExpr`: replace every `RegisterRef` with the
    /// register corresponding to the coalesced representative.
    #[must_use] 
    pub fn apply_to_expr(&self, expr: LlilExpr) -> LlilExpr {
        match expr {
            LlilExpr::RegisterRef { reg, size } => {
                // Look for a coalesced representative using the register name.
                let name = reg.name();
                let ssa = SsaVar::new(&name, 0);
                let repr_name = self
                    .coalesce_map
                    .get(&ssa).map_or_else(|| name.clone(), |r| r.name.clone());
                LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(repr_name),
                    size,
                }
            }
            LlilExpr::Add { left, right, size } => LlilExpr::Add {
                left: Box::new(self.apply_to_expr(*left)),
                right: Box::new(self.apply_to_expr(*right)),
                size,
            },
            LlilExpr::Sub { left, right, size } => LlilExpr::Sub {
                left: Box::new(self.apply_to_expr(*left)),
                right: Box::new(self.apply_to_expr(*right)),
                size,
            },
            LlilExpr::Mul { left, right, size } => LlilExpr::Mul {
                left: Box::new(self.apply_to_expr(*left)),
                right: Box::new(self.apply_to_expr(*right)),
                size,
            },
            LlilExpr::Load { addr, size } => LlilExpr::Load {
                addr: Box::new(self.apply_to_expr(*addr)),
                size,
            },
            other => other,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SsaReconstructor — top-level entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Reconstructs pruned SSA form from a non-SSA LLIL function.
///
/// Call [`SsaReconstructor::build`] to obtain a renamed, phi-inserted function
/// in near-SSA form.  The output is a renamed `LlilFunction` with phi metadata
/// stored separately.  A subsequent MLIL-lifting step converts it to
/// [`crate::MlilInstruction::Phi`] nodes.
/// Registers treated as clobbered (redefined) by call/syscall instructions.
/// Windows x64 volatile registers; conservative for SSA correctness.
const CALL_CLOBBERED_REGS: &[&str] = &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"];

#[derive(Debug, Clone, Default)]
pub struct SsaReconstructor;

impl SsaReconstructor {
    /// Reconstruct SSA for `func`.  Returns the renamed function and the map
    /// of phi nodes per block.
    #[must_use] 
    pub fn build(func: &LlilFunction) -> (LlilFunction, Vec<Vec<PhiNode>>) {
        let n = func.blocks.len();
        if n == 0 {
            return (func.clone(), vec![]);
        }

        // Build predecessor list from block successors (by index, not address).
        let preds = block_predecessors(func, n);

        // Compute def sites for each register name.
        let mut def_sites: HashMap<String, HashSet<usize>> = HashMap::new();
        for (b, block) in func.blocks.iter().enumerate() {
            for ai in &block.instrs {
                let mut def_names: Vec<String> = Vec::new();
                match &ai.instr {
                    LlilInstruction::SetReg { dest, .. }
                    | LlilInstruction::Load { dest, .. }
                    | LlilInstruction::Pop { dest, .. } => def_names.push(dest.name()),
                    LlilInstruction::SetRegSplit { high, low, .. } => {
                        def_names.push(high.name());
                        def_names.push(low.name());
                    }
                    LlilInstruction::SetFlag { name, .. } => def_names.push(name.clone()),
                    LlilInstruction::Call(_)
                    | LlilInstruction::CallDest { .. }
                    | LlilInstruction::CondCall { .. }
                    | LlilInstruction::SysCall => {
                        def_names.extend(CALL_CLOBBERED_REGS.iter().map(|r| (*r).to_owned()));
                    }
                    _ => {}
                }
                for name in def_names {
                    def_sites.entry(name).or_default().insert(b);
                }
            }
        }

        // Build SSA using the Braun algorithm.
        let mut builder = SsaBuilder::new(n);
        builder.seal_all(); // Simplified: seal all blocks upfront.

        // Rename phase: walk each block in RPO and rename defs/uses.
        let rpo = reverse_post_order(func, n);
        let mut renamed_blocks: Vec<LlilBasicBlock> = func.blocks.clone();

        for &b in &rpo {
            let block = &func.blocks[b];
            let mut new_instrs = Vec::new();

            for ai in &block.instrs {
                let new_instr = match &ai.instr {
                    LlilInstruction::SetReg { dest, size, value } => {
                        // Rename uses in value.
                        let new_value = rename_expr_uses(value, b, &mut builder, &preds);
                        // Allocate new SSA version for the definition.
                        let new_dest_ssa = builder.write_var(&dest.name(), b);
                        LlilInstruction::SetReg {
                            dest: LlilRegister::Concrete(new_dest_ssa.to_string()),
                            size: *size,
                            value: new_value,
                        }
                    }
                    LlilInstruction::Load { dest, size, addr } => {
                        let new_addr = rename_expr_uses(addr, b, &mut builder, &preds);
                        let new_dest_ssa = builder.write_var(&dest.name(), b);
                        LlilInstruction::Load {
                            dest: LlilRegister::Concrete(new_dest_ssa.to_string()),
                            size: *size,
                            addr: new_addr,
                        }
                    }
                    LlilInstruction::Store { addr, size, value } => {
                        let new_addr = rename_expr_uses(addr, b, &mut builder, &preds);
                        let new_val = rename_expr_uses(value, b, &mut builder, &preds);
                        LlilInstruction::Store {
                            addr: new_addr,
                            size: *size,
                            value: new_val,
                        }
                    }
                    LlilInstruction::CondJump { cond, true_dest, false_dest } => {
                        let new_cond = rename_expr_uses(cond, b, &mut builder, &preds);
                        LlilInstruction::CondJump {
                            cond: new_cond,
                            true_dest: *true_dest,
                            false_dest: *false_dest,
                        }
                    }
                    LlilInstruction::SetRegSplit { high, low, src } => {
                        let new_src = rename_expr_uses(src, b, &mut builder, &preds);
                        let new_high = builder.write_var(&high.name(), b);
                        let new_low = builder.write_var(&low.name(), b);
                        LlilInstruction::SetRegSplit {
                            high: LlilRegister::Concrete(new_high.to_string()),
                            low: LlilRegister::Concrete(new_low.to_string()),
                            src: new_src,
                        }
                    }
                    LlilInstruction::Call(target) => {
                        let new_tgt = rename_expr_uses(target, b, &mut builder, &preds);
                        for r in CALL_CLOBBERED_REGS {
                            builder.write_var(r, b);
                        }
                        LlilInstruction::Call(new_tgt)
                    }
                    LlilInstruction::CallDest { dest } => {
                        let new_dest = rename_expr_uses(dest, b, &mut builder, &preds);
                        for r in CALL_CLOBBERED_REGS {
                            builder.write_var(r, b);
                        }
                        LlilInstruction::CallDest { dest: new_dest }
                    }
                    LlilInstruction::CondCall { cond, dest } => {
                        let new_cond = rename_expr_uses(cond, b, &mut builder, &preds);
                        let new_dest = rename_expr_uses(dest, b, &mut builder, &preds);
                        for r in CALL_CLOBBERED_REGS {
                            builder.write_var(r, b);
                        }
                        LlilInstruction::CondCall {
                            cond: new_cond,
                            dest: new_dest,
                        }
                    }
                    LlilInstruction::SysCall => {
                        for r in CALL_CLOBBERED_REGS {
                            builder.write_var(r, b);
                        }
                        LlilInstruction::SysCall
                    }
                    LlilInstruction::Jump(target) => {
                        let new_tgt = rename_expr_uses(target, b, &mut builder, &preds);
                        LlilInstruction::Jump(new_tgt)
                    }
                    LlilInstruction::Return { value } => {
                        let new_val = value
                            .as_ref()
                            .map(|v| rename_expr_uses(v, b, &mut builder, &preds));
                        LlilInstruction::Return { value: new_val }
                    }
                    LlilInstruction::SetFlag { name, src } => {
                        let new_src = rename_expr_uses(src, b, &mut builder, &preds);
                        // Record the flag definition so reaching-def state is
                        // correct; keep the architectural flag name in the
                        // instruction (flag reads are not SSA-renamed).
                        builder.write_var(name, b);
                        LlilInstruction::SetFlag {
                            name: name.clone(),
                            src: new_src,
                        }
                    }
                    other => other.clone(),
                };

                let mut new_ai = ai.clone();
                new_ai.instr = new_instr;
                new_instrs.push(new_ai);
            }

            renamed_blocks[b].instrs = new_instrs;
        }

        let phis = builder.phis;
        let mut out = func.clone();
        out.blocks = renamed_blocks;
        (out, phis)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Expression renaming helper
// ─────────────────────────────────────────────────────────────────────────────

fn rename_expr_uses(
    expr: &LlilExpr,
    b: usize,
    builder: &mut SsaBuilder,
    preds: &[Vec<usize>],
) -> LlilExpr {
    match expr {
        LlilExpr::RegisterRef { reg, size } => {
            let ssa = builder.read_var(&reg.name(), b, preds);
            LlilExpr::RegisterRef {
                reg: LlilRegister::Concrete(ssa.to_string()),
                size: *size,
            }
        }
        LlilExpr::Add { left, right, size } => LlilExpr::Add {
            left: Box::new(rename_expr_uses(left, b, builder, preds)),
            right: Box::new(rename_expr_uses(right, b, builder, preds)),
            size: *size,
        },
        LlilExpr::Sub { left, right, size } => LlilExpr::Sub {
            left: Box::new(rename_expr_uses(left, b, builder, preds)),
            right: Box::new(rename_expr_uses(right, b, builder, preds)),
            size: *size,
        },
        LlilExpr::Mul { left, right, size } => LlilExpr::Mul {
            left: Box::new(rename_expr_uses(left, b, builder, preds)),
            right: Box::new(rename_expr_uses(right, b, builder, preds)),
            size: *size,
        },
        LlilExpr::Load { addr, size } => LlilExpr::Load {
            addr: Box::new(rename_expr_uses(addr, b, builder, preds)),
            size: *size,
        },
        LlilExpr::AddT(l, r, s) => LlilExpr::AddT(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
            *s,
        ),
        LlilExpr::SubT(l, r, s) => LlilExpr::SubT(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
            *s,
        ),
        LlilExpr::And(l, r, s) => LlilExpr::And(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
            *s,
        ),
        LlilExpr::Or(l, r, s) => LlilExpr::Or(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
            *s,
        ),
        LlilExpr::Xor(l, r, s) => LlilExpr::Xor(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
            *s,
        ),
        LlilExpr::CmpEq(l, r) => LlilExpr::CmpEq(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
        ),
        LlilExpr::CmpNe(l, r) => LlilExpr::CmpNe(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
        ),
        LlilExpr::CmpSlt(l, r) => LlilExpr::CmpSlt(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
        ),
        LlilExpr::CmpUlt(l, r) => LlilExpr::CmpUlt(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
        ),
        LlilExpr::CmpSle(l, r) => LlilExpr::CmpSle(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
        ),
        LlilExpr::CmpUle(l, r) => LlilExpr::CmpUle(
            Box::new(rename_expr_uses(l, b, builder, preds)),
            Box::new(rename_expr_uses(r, b, builder, preds)),
        ),
        other => other.clone(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Build a predecessor list indexed by block index.
/// Uses block `successors` field (which stores addresses) converted back to
/// indices via the block `start` field.
fn block_predecessors(func: &LlilFunction, n: usize) -> Vec<Vec<usize>> {
    // Build address → block-index map.
    let addr_to_idx: HashMap<u64, usize> = func
        .blocks
        .iter()
        .enumerate()
        .map(|(i, b)| (b.start.0, i))
        .collect();

    let mut preds: Vec<Vec<usize>> = vec![vec![]; n];
    for (b, block) in func.blocks.iter().enumerate() {
        for succ_addr in &block.successors {
            if let Some(&s) = addr_to_idx.get(&succ_addr.0)
                && s < n {
                    preds[s].push(b);
                }
        }
    }
    preds
}

fn reverse_post_order(func: &LlilFunction, n: usize) -> Vec<usize> {
    let mut visited = vec![false; n];
    let mut post = Vec::new();
    dfs(0, func, &mut visited, &mut post);
    post.reverse();
    post
}

fn dfs(b: usize, func: &LlilFunction, visited: &mut Vec<bool>, post: &mut Vec<usize>) {
    if b >= func.blocks.len() || visited[b] {
        return;
    }
    visited[b] = true;
    // Iterate successors by address, convert to indices.
    let succs: Vec<usize> = func.blocks[b]
        .successors
        .iter()
        .filter_map(|a| func.blocks.iter().position(|bl| bl.start == *a))
        .collect();
    for s in succs {
        dfs(s, func, visited, post);
    }
    post.push(b);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phi_trivial_detection() {
        let x0 = SsaVar::new("x", 0);
        let phi = PhiNode {
            dest: SsaVar::new("x", 1),
            operands: vec![x0.clone(), x0.clone()],
            trivial: false,
        };
        assert!(phi.is_trivial());
        assert_eq!(phi.trivial_operand(), Some(&x0));
    }

    #[test]
    fn test_phi_nontrivial() {
        let phi = PhiNode {
            dest: SsaVar::new("x", 2),
            operands: vec![SsaVar::new("x", 0), SsaVar::new("x", 1)],
            trivial: false,
        };
        assert!(!phi.is_trivial());
    }

    #[test]
    fn test_version_counter() {
        let mut ctr = SsaVersionCounter::default();
        let v0 = ctr.next("x");
        let v1 = ctr.next("x");
        let v2 = ctr.next("y");
        assert_eq!(v0.version, 0);
        assert_eq!(v1.version, 1);
        assert_eq!(v2.version, 0);
    }

    #[test]
    fn test_dominance_frontier_simple() {
        // Diamond: 0→1, 0→2, 1→3, 2→3.
        let idom = vec![0, 0, 0, 0];
        let preds = vec![vec![], vec![0usize], vec![0usize], vec![1usize, 2usize]];
        let df = DominanceFrontier::compute(4, &idom, &preds);
        // Block 3 is in the frontier of both 1 and 2.
        assert!(df.frontier(1).contains(&3));
        assert!(df.frontier(2).contains(&3));
        // Entry has empty frontier.
        assert!(df.frontier(0).is_empty());
    }

    #[test]
    fn test_phi_placement_diamond() {
        let idom = vec![0, 0, 0, 0];
        let preds = vec![vec![], vec![0usize], vec![0usize], vec![1usize, 2usize]];
        let df = DominanceFrontier::compute(4, &idom, &preds);

        let mut def_sites: HashMap<String, HashSet<usize>> = HashMap::new();
        def_sites.insert("x".to_owned(), [1usize, 2usize].into_iter().collect());

        let placement = PhiPlacement::compute(&def_sites, &df, 4);
        // x should have a phi at block 3.
        assert!(placement.phi_needed(3, "x"));
        assert!(!placement.phi_needed(0, "x"));
    }

    #[test]
    fn test_setregsplit_setflag_and_call_are_def_sites() {
        use rustre_il_llil::{LlilAnnotatedInstr, Size};

        // Single block:
        //   SetRegSplit high=rdx low=rax <- const
        //   SetFlag zf <- const
        //   Call const            (clobbers rax et al.)
        //   SetReg rbx <- rax     (must read the post-call rax version)
        let instrs = vec![
            LlilAnnotatedInstr::from(LlilInstruction::SetRegSplit {
                high: LlilRegister::Concrete("rdx".into()),
                low: LlilRegister::Concrete("rax".into()),
                src: LlilExpr::Const { value: 5, size: Size::QWord },
            }),
            LlilAnnotatedInstr::from(LlilInstruction::SetFlag {
                name: "zf".into(),
                src: LlilExpr::Const { value: 0, size: Size::Byte },
            }),
            LlilAnnotatedInstr::from(LlilInstruction::Call(LlilExpr::Const {
                value: 0x4000,
                size: Size::QWord,
            })),
            LlilAnnotatedInstr::from(LlilInstruction::SetReg {
                dest: LlilRegister::Concrete("rbx".into()),
                size: Size::QWord,
                value: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                },
            }),
        ];
        let func = LlilFunction {
            blocks: vec![LlilBasicBlock { instrs, ..Default::default() }],
            ..Default::default()
        };

        let (renamed, _phis) = SsaReconstructor::build(&func);
        let b = &renamed.blocks[0];

        // SetRegSplit dests got fresh SSA versions.
        match &b.instrs[0].instr {
            LlilInstruction::SetRegSplit { high, low, .. } => {
                assert_eq!(high.name(), "rdx#0");
                assert_eq!(low.name(), "rax#0");
            }
            other => panic!("expected SetRegSplit, got {other:?}"),
        }

        // The rax use after the call reads the call-clobbered version (rax#1),
        // not the stale SetRegSplit definition (rax#0).
        match &b.instrs[3].instr {
            LlilInstruction::SetReg { value, .. } => match value {
                LlilExpr::RegisterRef { reg, .. } => assert_eq!(reg.name(), "rax#1"),
                other => panic!("expected RegisterRef, got {other:?}"),
            },
            other => panic!("expected SetReg, got {other:?}"),
        }
    }

    #[test]
    fn test_out_of_ssa_coalescing() {
        let x0 = SsaVar::new("x", 0);
        let x1 = SsaVar::new("x", 1);
        let x2 = SsaVar::new("x", 2);
        let phi = PhiNode {
            dest: x2.clone(),
            operands: vec![x0.clone(), x1.clone()],
            trivial: false,
        };
        let oos = OutOfSsaTranslation::build(&[(0, &phi)]);
        // x0 should be the representative (lowest version).
        assert_eq!(oos.repr(&x2), &x0);
        assert_eq!(oos.repr(&x1), &x0);
    }
}
