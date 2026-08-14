//! `mlil_ssa.rs` — SSA construction, def-use chains, dominance, and sparse
//! conditional constant propagation for MLIL.
//!
//! # Exported types
//! * [`MlilSsa`] — high-level SSA wrapper around an [`MlilFunction`]; owns
//!   def-use, dominance, and phi-node bookkeeping.
//! * [`SsaVar`] — re-exported from `lib.rs`; (name, version) pair.
//! * [`SsaPhiNode`] — an explicit phi-node record (not just `MlilInstruction::Phi`).
//! * [`SsaMemoryVersion`] — versioned memory state, modelling store effects.
//! * [`SsaDefUse`] — def-use / use-def chains for SSA variables.
//! * [`SsaDominance`] — dominance tree and dominance frontier.
//! * [`SsaConstProp`] — sparse constant propagation on the SSA graph.

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use std::collections::VecDeque;

use crate::{MlilExpr, MlilFunction, MlilInstruction, SsaVar};

// Re-export the SSA-adjacent MLIL types from this module so downstream callers
// have a single import surface for everything they need to traverse SSA form.
pub use crate::{MlilAnnotatedInstr, MlilBasicBlock, Size};
use rustre_core::address::Address;

// ─── SsaPhiNode ──────────────────────────────────────────────────────────────

/// An explicit record of a φ-node in SSA form.
///
/// During construction of full SSA every variable that is live across a
/// control-flow join point gets a φ-node whose operands are the reaching
/// definitions from each predecessor block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaPhiNode {
    /// The SSA variable defined by this φ.
    pub dest: SsaVar,
    /// One entry `(pred_block_id, source_ssa_var)` per predecessor.
    pub sources: Vec<(u32, SsaVar)>,
    /// The basic block this φ belongs to.
    pub block_id: u32,
}

impl SsaPhiNode {
    #[must_use] 
    pub const fn new(dest: SsaVar, block_id: u32) -> Self {
        Self {
            dest,
            sources: Vec::new(),
            block_id,
        }
    }

    pub fn add_source(&mut self, pred_id: u32, src: SsaVar) {
        self.sources.push((pred_id, src));
    }

    /// Returns `true` when all source variables are the same (trivial φ).
    #[must_use]
    pub fn is_trivial(&self) -> bool {
        if self.sources.is_empty() {
            return true;
        }
        let first = &self.sources[0].1;
        self.sources.iter().all(|(_, s)| s == first)
    }

    /// If trivial, return the unique source variable.
    #[must_use]
    pub fn trivial_source(&self) -> Option<&SsaVar> {
        if self.is_trivial() {
            self.sources.first().map(|(_, s)| s)
        } else {
            None
        }
    }
}

// ─── SsaMemoryVersion ────────────────────────────────────────────────────────

/// A versioned snapshot of memory state used for memory SSA.
///
/// Each store instruction increments the memory version; loads that alias a
/// store reference the version just before it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SsaMemoryVersion {
    pub version: u32,
    /// Block where this version was created (by a store or call).
    pub block_id: u32,
    /// Address of the defining instruction.
    pub def_addr: Option<Address>,
}

impl SsaMemoryVersion {
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            version: 0,
            block_id: 0,
            def_addr: None,
        }
    }

    #[must_use]
    pub const fn next(&self, block_id: u32, def_addr: Option<Address>) -> Self {
        Self {
            version: self.version.saturating_add(1),
            block_id,
            def_addr,
        }
    }

    #[must_use]
    pub const fn is_initial(&self) -> bool {
        self.version == 0
    }
}

// ─── SsaDefUse ───────────────────────────────────────────────────────────────

/// Def-use and use-def chains for all SSA variables in a function.
///
/// A variable is **defined** exactly once (SSA invariant).  It may be **used**
/// zero or more times.
#[derive(Debug, Default)]
pub struct SsaDefUse {
    /// Maps each SSA variable to the address where it is defined.
    pub defs: HashMap<SsaVar, Address>,
    /// Maps each SSA variable to all addresses where it is used.
    pub uses: HashMap<SsaVar, Vec<Address>>,
}

impl SsaDefUse {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build def-use chains by scanning every instruction in `func`.
    pub fn build(&mut self, func: &MlilFunction) {
        self.defs.clear();
        self.uses.clear();
        let mut used_vars = Vec::new();
        for block in &func.blocks {
            for ai in &block.instrs {
                if let Some(def) = ai.instr.defined_var() {
                    self.defs.insert(def.clone(), ai.address);
                }
                used_vars.clear();
                collect_used_vars_instr(&ai.instr, &mut used_vars);
                for v in used_vars.drain(..) {
                    self.uses.entry(v).or_default().push(ai.address);
                }
            }
        }
    }

    /// Returns the definition site of `var`, if any.
    #[must_use]
    pub fn def_of(&self, var: &SsaVar) -> Option<Address> {
        self.defs.get(var).copied()
    }

    /// Returns all use sites of `var`.
    #[must_use]
    pub fn uses_of(&self, var: &SsaVar) -> &[Address] {
        self.uses.get(var).map_or(&[], Vec::as_slice)
    }

    /// Returns `true` when `var` is never used after its definition ("dead").
    #[must_use]
    pub fn is_dead(&self, var: &SsaVar) -> bool {
        self.uses_of(var).is_empty()
    }

    /// Total number of defined variables.
    #[must_use]
    pub fn def_count(&self) -> usize {
        self.defs.len()
    }

    /// Returns all variables that are defined but never used.
    #[must_use]
    pub fn dead_vars(&self) -> Vec<&SsaVar> {
        self.defs.keys().filter(|v| self.is_dead(v)).collect()
    }
}

fn collect_used_vars_instr(instr: &MlilInstruction, out: &mut Vec<SsaVar>) {
    match instr {
        MlilInstruction::Assign { src, .. } => collect_used_vars_expr(src, out),
        MlilInstruction::Store { addr, src, .. } => {
            collect_used_vars_expr(addr, out);
            collect_used_vars_expr(src, out);
        }
        MlilInstruction::Jump { dest } => collect_used_vars_expr(dest, out),
        MlilInstruction::CondJump { cond, .. } => collect_used_vars_expr(cond, out),
        MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
            collect_used_vars_expr(dest, out);
            for a in args {
                collect_used_vars_expr(a, out);
            }
        }
        MlilInstruction::Ret { values } => {
            for v in values {
                collect_used_vars_expr(v, out);
            }
        }
        MlilInstruction::Phi { sources, .. } => out.extend(sources.iter().cloned()),
        MlilInstruction::SysCall { args, .. } => {
            for a in args {
                collect_used_vars_expr(a, out);
            }
        }
        _ => {}
    }
}

fn collect_used_vars_expr(expr: &MlilExpr, out: &mut Vec<SsaVar>) {
    match expr {
        MlilExpr::Var { var, .. } => out.push(var.clone()),
        MlilExpr::Load { addr, .. } => collect_used_vars_expr(addr, out),
        MlilExpr::Neg(e, _) | MlilExpr::Not(e, _) => collect_used_vars_expr(e, out),
        MlilExpr::ZeroExtend { expr: e, .. } | MlilExpr::SignExtend { expr: e, .. } => {
            collect_used_vars_expr(e, out);
        }
        MlilExpr::Add(l, r, _)
        | MlilExpr::Sub(l, r, _)
        | MlilExpr::Mul(l, r, _)
        | MlilExpr::DivU(l, r, _)
        | MlilExpr::DivS(l, r, _)
        | MlilExpr::And(l, r, _)
        | MlilExpr::Or(l, r, _)
        | MlilExpr::Xor(l, r, _)
        | MlilExpr::Shl(l, r, _)
        | MlilExpr::Shr(l, r, _)
        | MlilExpr::Sar(l, r, _)
        | MlilExpr::FAdd(l, r, _)
        | MlilExpr::FSub(l, r, _)
        | MlilExpr::FMul(l, r, _)
        | MlilExpr::FDiv(l, r, _)
        | MlilExpr::CmpEq(l, r)
        | MlilExpr::CmpNe(l, r)
        | MlilExpr::CmpSlt(l, r)
        | MlilExpr::CmpUlt(l, r)
        | MlilExpr::CmpSle(l, r)
        | MlilExpr::CmpUle(l, r) => {
            collect_used_vars_expr(l, out);
            collect_used_vars_expr(r, out);
        }
        MlilExpr::Call { dest, args, .. } => {
            collect_used_vars_expr(dest, out);
            for a in args {
                collect_used_vars_expr(a, out);
            }
        }
        _ => {}
    }
}

// ─── SsaDominance ────────────────────────────────────────────────────────────

/// Simple dominance tree and dominance frontier computation.
///
/// Uses the classic iterative algorithm suitable for small-to-medium CFGs.
#[derive(Debug, Default)]
pub struct SsaDominance {
    /// Maps `block_id` → immediate dominator `block_id`.
    /// The entry block maps to itself.
    pub idom: HashMap<u32, u32>,
    /// Maps `block_id` → set of blocks in its dominance frontier.
    pub frontier: HashMap<u32, HashSet<u32>>,
    /// Maps `block_id` → set of blocks dominated by it (dominator tree children).
    pub dom_tree: HashMap<u32, HashSet<u32>>,
}

impl SsaDominance {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute dominance information for `func`.
    ///
    /// Assumes the first block is the entry (block with the lowest id).
    pub fn compute(&mut self, func: &MlilFunction) {
        self.idom.clear();
        self.frontier.clear();
        self.dom_tree.clear();

        if func.blocks.is_empty() {
            return;
        }

        let entry_id = func.blocks[0].id;
        let block_ids: Vec<u32> = func.blocks.iter().map(|b| b.id).collect();

        // Initialise: entry dominates itself; all others → undefined (using u32::MAX).
        let undef: u32 = u32::MAX;
        let mut idom: HashMap<u32, u32> = HashMap::new();
        for &id in &block_ids {
            idom.insert(id, if id == entry_id { id } else { undef });
        }

        // Build predecessor map.
        let mut preds: HashMap<u32, Vec<u32>> = HashMap::new();
        for b in &func.blocks {
            for &succ in &b.successors {
                preds.entry(succ).or_default().push(b.id);
            }
        }

        // Iterative fix-point.
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &block_ids {
                if b == entry_id {
                    continue;
                }
                let predecessors = preds.get(&b).map_or(&[][..], Vec::as_slice);
                // Find a processed predecessor (not undef).
                let processed: Vec<u32> = predecessors
                    .iter()
                    .filter(|&&p| idom[&p] != undef)
                    .copied()
                    .collect();
                if processed.is_empty() {
                    continue;
                }
                let mut new_idom = processed[0];
                for &p in processed.iter().skip(1) {
                    new_idom = self.intersect(p, new_idom, &idom, &block_ids);
                }
                if idom[&b] != new_idom {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }
        self.idom = idom;

        // Build dom-tree children.
        for (&b, &d) in &self.idom {
            if b != d {
                self.dom_tree.entry(d).or_default().insert(b);
            }
        }

        // Compute dominance frontiers.
        for b in &func.blocks {
            let preds_b = preds.get(&b.id).map_or(&[][..], Vec::as_slice);
            if preds_b.len() >= 2 {
                let idom_b = match self.idom.get(&b.id) {
                    Some(&d) if d != u32::MAX => d,
                    _ => continue,
                };
                for &p in preds_b {
                    let mut runner = p;
                    while runner != idom_b {
                        self.frontier.entry(runner).or_default().insert(b.id);
                        match self.idom.get(&runner) {
                            Some(&d) if d != u32::MAX => runner = d,
                            _ => break,
                        }
                    }
                }
            }
        }
    }

    fn intersect(&self, mut b1: u32, mut b2: u32, idom: &HashMap<u32, u32>, order: &[u32]) -> u32 {
        // Use reverse-postorder position as the ordering.
        let pos = |id: u32| order.iter().position(|&x| x == id).unwrap_or(usize::MAX);
        while b1 != b2 {
            while pos(b1) > pos(b2) {
                b1 = idom[&b1];
            }
            while pos(b2) > pos(b1) {
                b2 = idom[&b2];
            }
        }
        b1
    }

    /// Returns `true` when `dom` dominates `n`.
    #[must_use]
    pub fn dominates(&self, dom: u32, n: u32) -> bool {
        if dom == n {
            return true;
        }
        let mut cur = n;
        loop {
            let parent = match self.idom.get(&cur) {
                Some(&p) => p,
                None => return false,
            };
            if parent == dom {
                return true;
            }
            if parent == cur {
                return false; // reached entry without finding dom
            }
            cur = parent;
        }
    }

    /// Returns the dominance frontier of block `id`.
    #[must_use]
    pub fn frontier_of(&self, id: u32) -> &HashSet<u32> {
        static EMPTY: std::sync::OnceLock<HashSet<u32>> = std::sync::OnceLock::new();
        self.frontier
            .get(&id)
            .unwrap_or(EMPTY.get_or_init(HashSet::new))
    }

    /// Iteratively compute the dominance frontier "plus" (DF+) of a set of blocks.
    /// Used for determining where φ-nodes must be placed.
    #[must_use]
    pub fn iterated_frontier(&self, initial: &HashSet<u32>) -> HashSet<u32> {
        // DF+(S) is the fixpoint of the dominance frontier over S — it does NOT
        // contain S itself, except where a member genuinely appears in some
        // block's frontier (a loop header in its own frontier, say).
        //
        // This used to start from `initial.clone()`, so every seed block was
        // reported as part of its own iterated frontier: the function returned
        // S ∪ DF+(S), contradicting both Cytron's definition and this method's
        // own doc comment above. φ-node placement driven by it would insert φs
        // in blocks that need none.
        //
        // Seeding `result` empty is still terminating: a block is pushed only
        // when it is newly inserted into `result`, so each is processed at most
        // once beyond the initial |S| pushes.
        let mut result = HashSet::default();
        let mut worklist: VecDeque<u32> = initial.iter().copied().collect();
        while let Some(n) = worklist.pop_front() {
            for &f in self.frontier_of(n) {
                if result.insert(f) {
                    worklist.push_back(f);
                }
            }
        }
        result
    }
}

// ─── SsaConstProp ────────────────────────────────────────────────────────────

/// Sparse conditional constant propagation over the SSA graph.
///
/// Propagates known constant values through assignments and φ-nodes.
/// Implements a simple worklist-based algorithm.
#[derive(Debug, Default)]
pub struct SsaConstProp {
    /// Maps SSA variable → known constant value (if determined).
    pub constants: HashMap<SsaVar, u64>,
    /// Variables that could not be resolved to a constant.
    pub non_constants: HashSet<SsaVar>,
}

impl SsaConstProp {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run constant propagation on `func`.
    ///
    /// Returns the number of variables resolved to constants.
    pub fn run(&mut self, func: &MlilFunction) -> usize {
        self.constants.clear();
        self.non_constants.clear();

        // First pass: seed with all direct `Assign { src: Const }`.
        let mut worklist: VecDeque<SsaVar> = VecDeque::new();
        for ai in func.all_instrs() {
            if let MlilInstruction::Assign {
                dest,
                src: MlilExpr::Const { value, .. },
                ..
            } = &ai.instr
            {
                self.constants.insert(dest.clone(), *value);
                worklist.push_back(dest.clone());
            }
        }

        // Count total SSA definitions to bound the worklist iterations.
        // Each variable can only be resolved once, so the worklist shrinks
        // monotonically — but cap at def_count to defend against bugs.
        let def_count = func.all_instrs().count();
        let max_iterations = def_count.saturating_mul(2).max(64);
        let mut iterations = 0usize;
        // Propagation: for each constant def, find uses and attempt to fold.
        while let Some(_var) = worklist.pop_front() {
            iterations += 1;
            if iterations > max_iterations {
                break;
            }
            for ai in func.all_instrs() {
                if let MlilInstruction::Assign { dest, src, .. } = &ai.instr {
                    if self.constants.contains_key(dest) || self.non_constants.contains(dest) {
                        continue;
                    }
                    if let Some(cv) = self.eval_expr(src) {
                        self.constants.insert(dest.clone(), cv);
                        worklist.push_back(dest.clone());
                    } else {
                        // Cannot resolve — try φ-nodes.
                    }
                }
                if let MlilInstruction::Phi { dest, sources } = &ai.instr {
                    if self.constants.contains_key(dest) || self.non_constants.contains(dest) {
                        continue;
                    }
                    let vals: Vec<Option<u64>> = sources
                        .iter()
                        .map(|s| self.constants.get(s).copied())
                        .collect();
                    if !vals.is_empty() && vals.iter().all(std::option::Option::is_some) {
                        let first = vals[0].unwrap_or(0);
                        if vals.iter().all(|v| v == &Some(first)) {
                            self.constants.insert(dest.clone(), first);
                            worklist.push_back(dest.clone());
                        } else {
                            self.non_constants.insert(dest.clone());
                        }
                    }
                }
            }
        }

        self.constants.len()
    }

    fn eval_expr(&self, expr: &MlilExpr) -> Option<u64> {
        match expr {
            MlilExpr::Const { value, .. } => Some(*value),
            MlilExpr::Var { var, .. } => self.constants.get(var).copied(),
            MlilExpr::Add(l, r, _) => {
                let lv = self.eval_expr(l)?;
                let rv = self.eval_expr(r)?;
                Some(lv.wrapping_add(rv))
            }
            MlilExpr::Sub(l, r, _) => {
                let lv = self.eval_expr(l)?;
                let rv = self.eval_expr(r)?;
                Some(lv.wrapping_sub(rv))
            }
            MlilExpr::Mul(l, r, _) => {
                let lv = self.eval_expr(l)?;
                let rv = self.eval_expr(r)?;
                Some(lv.wrapping_mul(rv))
            }
            MlilExpr::And(l, r, _) => {
                let lv = self.eval_expr(l)?;
                let rv = self.eval_expr(r)?;
                Some(lv & rv)
            }
            MlilExpr::Or(l, r, _) => {
                let lv = self.eval_expr(l)?;
                let rv = self.eval_expr(r)?;
                Some(lv | rv)
            }
            MlilExpr::Xor(l, r, _) => {
                let lv = self.eval_expr(l)?;
                let rv = self.eval_expr(r)?;
                Some(lv ^ rv)
            }
            MlilExpr::Shl(l, r, s) => {
                let lv = self.eval_expr(l)?;
                let rv = self.eval_expr(r)?;
                let bits = s.bits() as u64;
                let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                Some(if rv >= bits { 0 } else { (lv << rv) & mask })
            }
            MlilExpr::Shr(l, r, s) => {
                let lv = self.eval_expr(l)?;
                let rv = self.eval_expr(r)?;
                let bits = s.bits() as u64;
                let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                Some(if rv >= bits { 0 } else { (lv & mask) >> rv })
            }
            MlilExpr::Neg(e, _) => Some(self.eval_expr(e)?.wrapping_neg()),
            MlilExpr::Not(e, _) => Some(!self.eval_expr(e)?),
            MlilExpr::CmpEq(l, r) => Some(u64::from(self.eval_expr(l)? == self.eval_expr(r)?)),
            MlilExpr::CmpNe(l, r) => Some(u64::from(self.eval_expr(l)? != self.eval_expr(r)?)),
            _ => None,
        }
    }

    /// Look up the constant value of `var`.
    #[must_use]
    pub fn constant_of(&self, var: &SsaVar) -> Option<u64> {
        self.constants.get(var).copied()
    }

    /// Returns all variables known to be constant.
    #[must_use]
    pub fn all_constants(&self) -> Vec<(&SsaVar, u64)> {
        self.constants.iter().map(|(v, &c)| (v, c)).collect()
    }
}

// ─── MlilSsa ─────────────────────────────────────────────────────────────────

/// High-level SSA wrapper around an [`MlilFunction`].
///
/// Owns pre-computed def-use chains, dominance trees, phi-node records,
/// memory versions, and the results of constant propagation.
#[derive(Debug)]
pub struct MlilSsa {
    /// The underlying MLIL function (consumed during construction).
    pub func: MlilFunction,
    pub def_use: SsaDefUse,
    pub dominance: SsaDominance,
    pub phi_nodes: Vec<SsaPhiNode>,
    pub memory_versions: Vec<SsaMemoryVersion>,
    pub const_prop: SsaConstProp,
}

impl MlilSsa {
    /// Construct the full SSA structure for `func`.
    #[must_use]
    pub fn build(func: MlilFunction) -> Self {
        let mut def_use = SsaDefUse::new();
        def_use.build(&func);

        let mut dominance = SsaDominance::new();
        dominance.compute(&func);

        let phi_nodes = Self::extract_phi_nodes(&func);
        let memory_versions = Self::build_memory_versions(&func);

        let mut const_prop = SsaConstProp::new();
        const_prop.run(&func);

        Self {
            func,
            def_use,
            dominance,
            phi_nodes,
            memory_versions,
            const_prop,
        }
    }

    fn extract_phi_nodes(func: &MlilFunction) -> Vec<SsaPhiNode> {
        let mut nodes = Vec::new();
        for block in &func.blocks {
            for ai in &block.instrs {
                if let MlilInstruction::Phi { dest, sources } = &ai.instr {
                    let mut phi = SsaPhiNode::new(dest.clone(), block.id);
                    for (i, src) in sources.iter().enumerate() {
                        let pred_id = block.predecessors.get(i).copied().unwrap_or(u32::MAX);
                        phi.add_source(pred_id, src.clone());
                    }
                    nodes.push(phi);
                }
            }
        }
        nodes
    }

    fn build_memory_versions(func: &MlilFunction) -> Vec<SsaMemoryVersion> {
        let mut versions = vec![SsaMemoryVersion::initial()];
        let mut current = SsaMemoryVersion::initial();
        for block in &func.blocks {
            for ai in &block.instrs {
                let creates_new = matches!(
                    &ai.instr,
                    MlilInstruction::Store { .. }
                        | MlilInstruction::Call { .. }
                        | MlilInstruction::TailCall { .. }
                        | MlilInstruction::SysCall { .. }
                );
                if creates_new {
                    current = current.next(block.id, Some(ai.address));
                    versions.push(current.clone());
                }
            }
        }
        versions
    }

    /// Number of φ-nodes in this function.
    #[must_use]
    pub const fn phi_count(&self) -> usize {
        self.phi_nodes.len()
    }

    /// Returns all trivial φ-nodes (candidates for elimination).
    #[must_use]
    pub fn trivial_phis(&self) -> Vec<&SsaPhiNode> {
        self.phi_nodes.iter().filter(|p| p.is_trivial()).collect()
    }

    /// Returns the constant value of `var`, if known.
    #[must_use]
    pub fn constant_of(&self, var: &SsaVar) -> Option<u64> {
        self.const_prop.constant_of(var)
    }

    /// Returns `true` when `var` is dead (never used after definition).
    #[must_use]
    pub fn is_dead(&self, var: &SsaVar) -> bool {
        self.def_use.is_dead(var)
    }

    /// Returns the number of memory versions (stores + call sites + 1).
    #[must_use]
    pub const fn memory_version_count(&self) -> usize {
        self.memory_versions.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MlilAnnotatedInstr, MlilBasicBlock, MlilFunction};
    use rustre_core::address::Address;

    fn make_var(name: &str, ver: u32) -> SsaVar {
        SsaVar::new(name, ver)
    }

    fn addr(n: u64) -> Address {
        Address::new(n)
    }

    fn make_func_one_block(instrs: Vec<MlilInstruction>) -> MlilFunction {
        let ann: Vec<MlilAnnotatedInstr> = instrs
            .into_iter()
            .enumerate()
            .map(|(i, instr)| MlilAnnotatedInstr {
                address: addr(0x1000 + i as u64 * 4),
                instr,
            })
            .collect();
        let n = ann.len();
        let mut func = MlilFunction::new(addr(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr(0x1000),
            end: addr(0x1000 + n as u64 * 4),
            instrs: ann,
            predecessors: vec![],
            successors: vec![],
        });
        func
    }

    // SsaPhiNode tests ──────────────────────────────────────────────────────

    #[test]
    fn phi_node_trivial_all_same() {
        let mut phi = SsaPhiNode::new(make_var("x", 2), 1);
        phi.add_source(0, make_var("x", 1));
        phi.add_source(1, make_var("x", 1));
        assert!(phi.is_trivial());
        assert_eq!(phi.trivial_source(), Some(&make_var("x", 1)));
    }

    #[test]
    fn phi_node_not_trivial() {
        let mut phi = SsaPhiNode::new(make_var("x", 2), 1);
        phi.add_source(0, make_var("x", 0));
        phi.add_source(1, make_var("x", 1));
        assert!(!phi.is_trivial());
        assert!(phi.trivial_source().is_none());
    }

    #[test]
    fn phi_node_empty_is_trivial() {
        let phi = SsaPhiNode::new(make_var("x", 0), 0);
        assert!(phi.is_trivial());
    }

    #[test]
    fn phi_node_single_source_trivial() {
        let mut phi = SsaPhiNode::new(make_var("y", 1), 0);
        phi.add_source(0, make_var("y", 0));
        assert!(phi.is_trivial());
    }

    // SsaMemoryVersion tests ─────────────────────────────────────────────────

    #[test]
    fn mem_ver_initial_is_zero() {
        let v = SsaMemoryVersion::initial();
        assert_eq!(v.version, 0);
        assert!(v.is_initial());
    }

    #[test]
    fn mem_ver_increments() {
        let v = SsaMemoryVersion::initial();
        let v2 = v.next(1, Some(addr(0x1000)));
        assert_eq!(v2.version, 1);
        assert!(!v2.is_initial());
    }

    #[test]
    fn mem_ver_sequential() {
        let mut v = SsaMemoryVersion::initial();
        for i in 1..=5u32 {
            v = v.next(0, None);
            assert_eq!(v.version, i);
        }
    }

    // SsaDefUse tests ────────────────────────────────────────────────────────

    #[test]
    fn def_use_counts_defs() {
        let func = make_func_one_block(vec![
            MlilInstruction::Assign {
                dest: make_var("a", 1),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 42,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Assign {
                dest: make_var("b", 1),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 7,
                    size: Size::QWord,
                },
            },
        ]);
        let mut du = SsaDefUse::new();
        du.build(&func);
        assert_eq!(du.def_count(), 2);
    }

    #[test]
    fn def_use_dead_var() {
        let func = make_func_one_block(vec![MlilInstruction::Assign {
            dest: make_var("dead", 1),
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            },
        }]);
        let mut du = SsaDefUse::new();
        du.build(&func);
        assert!(du.is_dead(&make_var("dead", 1)));
        assert_eq!(du.dead_vars().len(), 1);
    }

    #[test]
    fn def_use_used_var() {
        let a = make_var("a", 1);
        let b = make_var("b", 1);
        let func = make_func_one_block(vec![
            MlilInstruction::Assign {
                dest: a.clone(),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 10,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Assign {
                dest: b,
                size: Size::QWord,
                src: MlilExpr::Var {
                    var: a.clone(),
                    size: Size::QWord,
                },
            },
        ]);
        let mut du = SsaDefUse::new();
        du.build(&func);
        assert!(!du.is_dead(&a));
        assert_eq!(du.uses_of(&a).len(), 1);
    }

    #[test]
    fn def_use_def_site() {
        let a = make_var("a", 1);
        let func = make_func_one_block(vec![MlilInstruction::Assign {
            dest: a.clone(),
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 1,
                size: Size::QWord,
            },
        }]);
        let mut du = SsaDefUse::new();
        du.build(&func);
        assert_eq!(du.def_of(&a), Some(addr(0x1000)));
    }

    // SsaDominance tests ─────────────────────────────────────────────────────

    #[test]
    fn dominance_single_block() {
        let func = make_func_one_block(vec![MlilInstruction::Nop]);
        let mut dom = SsaDominance::new();
        dom.compute(&func);
        assert!(dom.dominates(0, 0));
    }

    #[test]
    fn dominance_empty_func() {
        let func = MlilFunction::new(addr(0x1000));
        let mut dom = SsaDominance::new();
        dom.compute(&func);
        assert!(dom.idom.is_empty());
    }

    #[test]
    fn dominance_two_blocks() {
        let mut func = MlilFunction::new(addr(0x1000));
        func.blocks.push(MlilBasicBlock {
            id: 0,
            start: addr(0x1000),
            end: addr(0x1008),
            instrs: vec![],
            predecessors: vec![],
            successors: vec![1],
        });
        func.blocks.push(MlilBasicBlock {
            id: 1,
            start: addr(0x1008),
            end: addr(0x1010),
            instrs: vec![],
            predecessors: vec![0],
            successors: vec![],
        });
        let mut dom = SsaDominance::new();
        dom.compute(&func);
        assert!(dom.dominates(0, 1));
        assert!(!dom.dominates(1, 0));
    }

    #[test]
    fn dominance_self_dominates() {
        let func = make_func_one_block(vec![]);
        let mut dom = SsaDominance::new();
        dom.compute(&func);
        assert!(dom.dominates(0, 0));
    }

    // SsaConstProp tests ─────────────────────────────────────────────────────

    #[test]
    fn const_prop_literal() {
        let a = make_var("a", 1);
        let func = make_func_one_block(vec![MlilInstruction::Assign {
            dest: a.clone(),
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 99,
                size: Size::QWord,
            },
        }]);
        let mut cp = SsaConstProp::new();
        let count = cp.run(&func);
        assert_eq!(count, 1);
        assert_eq!(cp.constant_of(&a), Some(99));
    }

    #[test]
    fn const_prop_add_constants() {
        let a = make_var("a", 1);
        let b = make_var("b", 1);
        let c = make_var("c", 1);
        let func = make_func_one_block(vec![
            MlilInstruction::Assign {
                dest: a.clone(),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 10,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Assign {
                dest: b.clone(),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 20,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Assign {
                dest: c.clone(),
                size: Size::QWord,
                src: MlilExpr::Add(
                    Box::new(MlilExpr::Var {
                        var: a,
                        size: Size::QWord,
                    }),
                    Box::new(MlilExpr::Var {
                        var: b,
                        size: Size::QWord,
                    }),
                    Size::QWord,
                ),
            },
        ]);
        let mut cp = SsaConstProp::new();
        cp.run(&func);
        assert_eq!(cp.constant_of(&c), Some(30));
    }

    #[test]
    fn const_prop_unknown_load() {
        let a = make_var("a", 1);
        let func = make_func_one_block(vec![MlilInstruction::Assign {
            dest: a.clone(),
            size: Size::QWord,
            src: MlilExpr::Load {
                addr: Box::new(MlilExpr::Const {
                    value: 0x1000,
                    size: Size::QWord,
                }),
                size: Size::QWord,
            },
        }]);
        let mut cp = SsaConstProp::new();
        cp.run(&func);
        assert!(cp.constant_of(&a).is_none());
    }

    #[test]
    fn const_prop_neg() {
        let a = make_var("a", 1);
        let b = make_var("b", 1);
        let func = make_func_one_block(vec![
            MlilInstruction::Assign {
                dest: a.clone(),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 5,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Assign {
                dest: b.clone(),
                size: Size::QWord,
                src: MlilExpr::Neg(
                    Box::new(MlilExpr::Var {
                        var: a,
                        size: Size::QWord,
                    }),
                    Size::QWord,
                ),
            },
        ]);
        let mut cp = SsaConstProp::new();
        cp.run(&func);
        assert_eq!(cp.constant_of(&b), Some(5u64.wrapping_neg()));
    }

    // MlilSsa tests ──────────────────────────────────────────────────────────

    #[test]
    fn mlil_ssa_build_empty() {
        let func = MlilFunction::new(addr(0x1000));
        let ssa = MlilSsa::build(func);
        assert_eq!(ssa.phi_count(), 0);
        assert_eq!(ssa.memory_version_count(), 1); // initial version
    }

    #[test]
    fn mlil_ssa_build_with_phi() {
        let dest = make_var("x", 2);
        let func = make_func_one_block(vec![MlilInstruction::Phi {
            dest,
            sources: vec![make_var("x", 0), make_var("x", 1)],
        }]);
        let ssa = MlilSsa::build(func);
        assert_eq!(ssa.phi_count(), 1);
    }

    #[test]
    fn mlil_ssa_trivial_phis() {
        let dest = make_var("x", 2);
        let func = make_func_one_block(vec![MlilInstruction::Phi {
            dest,
            sources: vec![make_var("x", 1), make_var("x", 1)],
        }]);
        let ssa = MlilSsa::build(func);
        assert_eq!(ssa.trivial_phis().len(), 1);
    }

    #[test]
    fn mlil_ssa_memory_versions_increase_on_store() {
        let func = make_func_one_block(vec![
            MlilInstruction::Store {
                addr: MlilExpr::Const {
                    value: 0x100,
                    size: Size::QWord,
                },
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 0,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Store {
                addr: MlilExpr::Const {
                    value: 0x108,
                    size: Size::QWord,
                },
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 1,
                    size: Size::QWord,
                },
            },
        ]);
        let ssa = MlilSsa::build(func);
        assert_eq!(ssa.memory_version_count(), 3); // initial + 2 stores
    }

    #[test]
    fn mlil_ssa_is_dead_true() {
        let a = make_var("dead", 1);
        let func = make_func_one_block(vec![MlilInstruction::Assign {
            dest: a.clone(),
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 0,
                size: Size::QWord,
            },
        }]);
        let ssa = MlilSsa::build(func);
        assert!(ssa.is_dead(&a));
    }

    #[test]
    fn mlil_ssa_constant_of() {
        let a = make_var("a", 1);
        let func = make_func_one_block(vec![MlilInstruction::Assign {
            dest: a.clone(),
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 42,
                size: Size::QWord,
            },
        }]);
        let ssa = MlilSsa::build(func);
        assert_eq!(ssa.constant_of(&a), Some(42));
    }

    #[test]
    fn iterated_frontier_empty() {
        let dom = SsaDominance::new();
        let result = dom.iterated_frontier(&HashSet::new());
        assert!(result.is_empty());
    }

    #[test]
    fn const_prop_xor_self_is_zero() {
        let a = make_var("a", 1);
        let b = make_var("b", 1);
        let func = make_func_one_block(vec![
            MlilInstruction::Assign {
                dest: a.clone(),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 0xABCD,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Assign {
                dest: b.clone(),
                size: Size::QWord,
                src: MlilExpr::Xor(
                    Box::new(MlilExpr::Var {
                        var: a.clone(),
                        size: Size::QWord,
                    }),
                    Box::new(MlilExpr::Var {
                        var: a,
                        size: Size::QWord,
                    }),
                    Size::QWord,
                ),
            },
        ]);
        let mut cp = SsaConstProp::new();
        cp.run(&func);
        assert_eq!(cp.constant_of(&b), Some(0));
    }

    #[test]
    fn def_use_phi_sources_counted_as_uses() {
        let a = make_var("a", 1);
        let b = make_var("b", 1);
        let func = make_func_one_block(vec![
            MlilInstruction::Assign {
                dest: a.clone(),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 1,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Phi {
                dest: make_var("c", 1),
                sources: vec![a.clone(), b],
            },
        ]);
        let mut du = SsaDefUse::new();
        du.build(&func);
        // `a` is used in the phi.
        assert!(!du.is_dead(&a));
    }

    #[test]
    fn ssa_const_prop_shl() {
        let a = make_var("a", 1);
        let b = make_var("b", 1);
        let func = make_func_one_block(vec![
            MlilInstruction::Assign {
                dest: a.clone(),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 1,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Assign {
                dest: b.clone(),
                size: Size::QWord,
                src: MlilExpr::Shl(
                    Box::new(MlilExpr::Var {
                        var: a,
                        size: Size::QWord,
                    }),
                    Box::new(MlilExpr::Const {
                        value: 3,
                        size: Size::QWord,
                    }),
                    Size::QWord,
                ),
            },
        ]);
        let mut cp = SsaConstProp::new();
        cp.run(&func);
        assert_eq!(cp.constant_of(&b), Some(8));
    }

    #[test]
    fn ssa_const_prop_cmp_eq_true() {
        let a = make_var("a", 1);
        let b = make_var("b", 1);
        let func = make_func_one_block(vec![
            MlilInstruction::Assign {
                dest: a.clone(),
                size: Size::QWord,
                src: MlilExpr::Const {
                    value: 5,
                    size: Size::QWord,
                },
            },
            MlilInstruction::Assign {
                dest: b.clone(),
                size: Size::QWord,
                src: MlilExpr::CmpEq(
                    Box::new(MlilExpr::Var {
                        var: a,
                        size: Size::QWord,
                    }),
                    Box::new(MlilExpr::Const {
                        value: 5,
                        size: Size::QWord,
                    }),
                ),
            },
        ]);
        let mut cp = SsaConstProp::new();
        cp.run(&func);
        assert_eq!(cp.constant_of(&b), Some(1));
    }

    #[test]
    fn ssa_const_prop_all_constants_returns_list() {
        let a = make_var("a", 1);
        let func = make_func_one_block(vec![MlilInstruction::Assign {
            dest: a,
            size: Size::QWord,
            src: MlilExpr::Const {
                value: 99,
                size: Size::QWord,
            },
        }]);
        let mut cp = SsaConstProp::new();
        cp.run(&func);
        let all = cp.all_constants();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1, 99);
    }

    #[test]
    fn phi_node_multiple_sources() {
        let mut phi = SsaPhiNode::new(make_var("x", 3), 2);
        phi.add_source(0, make_var("x", 1));
        phi.add_source(1, make_var("x", 2));
        assert_eq!(phi.sources.len(), 2);
        assert!(!phi.is_trivial());
    }

    #[test]
    fn mlil_ssa_call_creates_memory_version() {
        let func = make_func_one_block(vec![MlilInstruction::Call {
            dest: MlilExpr::Const {
                value: 0xdeadbeef,
                size: Size::QWord,
            },
            args: vec![],
            ret_vars: vec![],
        }]);
        let ssa = MlilSsa::build(func);
        assert!(ssa.memory_version_count() > 1);
    }

    #[test]
    fn iterated_frontier_single_block() {
        let mut func = MlilFunction::new(addr(0x1000));
        func.blocks.push(crate::MlilBasicBlock {
            id: 0,
            start: addr(0x1000),
            end: addr(0x1010),
            instrs: vec![],
            predecessors: vec![],
            successors: vec![],
        });
        let mut dom = SsaDominance::new();
        dom.compute(&func);
        let mut init: HashSet<u32> = HashSet::default();
        init.insert(0u32);
        let result = dom.iterated_frontier(&init);
        // A single block has no frontier, so DF+({0}) is EMPTY.
        //
        // This assertion used to read `result.is_empty() || result.contains(&0)`
        // — accepting both the right answer and the wrong one, and so passing
        // either way. Its own comment already stated the correct expectation;
        // the disjunction was written around the defect (`iterated_frontier`
        // seeded its result with the input set, returning {0}) rather than
        // catching it. An assertion that accepts two opposite outcomes is worth
        // treating as a defect marker in itself.
        assert!(
            result.is_empty(),
            "DF+ of the entry of a single-block function must be empty, got {result:?}"
        );
    }

    #[test]
    fn ssa_def_use_empty_function_no_defs() {
        let func = MlilFunction::new(addr(0x1000));
        let mut du = SsaDefUse::new();
        du.build(&func);
        assert_eq!(du.def_count(), 0);
        assert!(du.dead_vars().is_empty());
    }
}
