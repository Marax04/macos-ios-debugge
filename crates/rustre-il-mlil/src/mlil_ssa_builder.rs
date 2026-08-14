//! MLIL SSA builder — converts a flat MLIL function into SSA form by computing
//! dominance frontiers, inserting phi nodes, and renaming variables.
//!
//! Algorithm: Cytron et al. "Efficiently computing static single assignment
//! form and the control dependence graph", TOPLAS 1991.
//!
//! # SSA variable type
//! This module re-uses [`crate::SsaVar`] (the crate-canonical SSA variable)
//! rather than defining its own copy.  The builder's simplified
//! [`MlilInstruction`] represents defs/uses as plain `String` base names;
//! versions are tracked internally via [`MlilSsaBuilder::version_counters`].

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

// Re-export the canonical SsaVar so downstream code that imports from this
// module still gets the right type.
pub use crate::SsaVar;

// ─────────────────────────────────────────────────────────────────────────────
// PhiNode
// ─────────────────────────────────────────────────────────────────────────────

/// A phi node at a join point in the CFG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhiNode {
    /// The variable defined by this phi.
    pub dest: SsaVar,
    /// The source variable from each predecessor block.
    /// `sources[i]` is the incoming value from predecessor `i`.
    pub sources: Vec<(u32 /* pred_block_id */, SsaVar)>,
    /// Block where this phi is inserted.
    pub block_id: u32,
}

impl PhiNode {
    /// Create a new phi node.
    #[must_use]
    pub const fn new(dest: SsaVar, block_id: u32) -> Self {
        Self { dest, sources: Vec::new(), block_id }
    }

    /// Add a source (predecessor block, incoming SSA variable).
    pub fn add_source(&mut self, pred: u32, var: SsaVar) {
        self.sources.push((pred, var));
    }

    /// Return `true` if this phi is trivial (all sources are the same variable).
    #[must_use]
    pub fn is_trivial(&self) -> bool {
        if self.sources.len() <= 1 {
            return true;
        }
        let first = &self.sources[0].1;
        self.sources.iter().all(|(_, s)| s == first)
    }

    /// Simplify a trivial phi to the single source variable (or to the dest
    /// if there are no sources).
    #[must_use]
    pub fn simplify(&self) -> Option<SsaVar> {
        if self.is_trivial() {
            self.sources.first().map(|(_, s)| s.clone())
        } else {
            None
        }
    }
}

impl fmt::Display for PhiNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = φ(", self.dest)?;
        for (i, (pred, src)) in self.sources.iter().enumerate() {
            if i > 0 { write!(f, ", ")?; }
            write!(f, "[B{pred}]{src}")?;
        }
        write!(f, ")")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilInstruction (minimal representation for the builder)
// ─────────────────────────────────────────────────────────────────────────────

/// A simplified MLIL instruction used as input to the SSA builder.
#[derive(Debug, Clone)]
pub struct MlilInstruction {
    /// Instruction address.
    pub addr: u64,
    /// Variables defined (written) by this instruction.
    pub defs: Vec<String>,
    /// Variables used (read) by this instruction.
    pub uses: Vec<String>,
    /// Raw pseudo-code string for printing.
    pub text: String,
}

impl MlilInstruction {
    /// Create a simple assignment instruction.
    #[must_use]
    pub fn assign(addr: u64, dest: impl Into<String>, src: impl Into<String>) -> Self {
        let dest = dest.into();
        let src = src.into();
        let text = format!("{dest} = {src}");
        Self {
            addr,
            defs: vec![dest],
            uses: vec![src],
            text,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A basic block in the MLIL CFG.
#[derive(Debug, Clone)]
pub struct MlilBlock {
    /// Block ID.
    pub id: u32,
    /// Instructions in this block.
    pub instructions: Vec<MlilInstruction>,
    /// Successor block IDs.
    pub successors: Vec<u32>,
    /// Predecessor block IDs (filled in by the builder).
    pub predecessors: Vec<u32>,
    /// Immediate dominator block ID (`u32::MAX` = no dominator / root).
    pub idom: u32,
    /// Dominance frontier set.
    pub df: HashSet<u32>,
    /// Phi nodes inserted at the start of this block.
    pub phis: Vec<PhiNode>,
}

impl MlilBlock {
    /// Create a new empty block.
    #[must_use]
    pub fn new(id: u32, successors: Vec<u32>) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            successors,
            predecessors: Vec::new(),
            idom: u32::MAX,
            df: HashSet::new(),
            phis: Vec::new(),
        }
    }

    /// Return all variables defined in this block (including phi destinations).
    #[must_use]
    pub fn defs(&self) -> Vec<String> {
        let mut defs: Vec<String> = self
            .instructions
            .iter()
            .flat_map(|i| i.defs.iter().cloned())
            .collect();
        defs.extend(self.phis.iter().map(|p| p.dest.name.clone()));
        defs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SsaFunction — output of the builder
// ─────────────────────────────────────────────────────────────────────────────

/// An MLIL function in SSA form.
#[derive(Debug)]
pub struct SsaFunction {
    /// All blocks in the function.
    pub blocks: Vec<MlilBlock>,
    /// All phi nodes, indexed by block ID.
    pub phi_map: BTreeMap<u32, Vec<PhiNode>>,
    /// SSA name for each (block, instruction index, variable) triple.
    /// Key: `(block_id, insn_index, base_name)`.
    pub ssa_names: HashMap<(u32, usize, String), SsaVar>,
    /// Entry block ID.
    pub entry: u32,
    /// Total phi nodes inserted.
    pub phi_count: usize,
    /// All live variables in the function.
    pub live_vars: HashSet<String>,
}

impl SsaFunction {
    /// Return all phi nodes across all blocks.
    #[must_use]
    pub fn all_phis(&self) -> Vec<&PhiNode> {
        self.phi_map.values().flatten().collect()
    }

    /// Return the block with the given ID.
    #[must_use]
    pub fn block(&self, id: u32) -> Option<&MlilBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Return `true` if this SSA function has any non-trivial phi nodes.
    #[must_use]
    pub fn has_nontrivial_phis(&self) -> bool {
        self.all_phis().iter().any(|p| !p.is_trivial())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MlilSsaBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds SSA form for an MLIL function.
#[derive(Debug)]
pub struct MlilSsaBuilder {
    blocks: Vec<MlilBlock>,
    entry: u32,
    /// Counter per base variable for version assignment.
    version_counters: HashMap<String, u32>,
    /// Rename stacks: base → stack of current SSA vars.
    rename_stack: HashMap<String, Vec<SsaVar>>,
    /// Collected SSA name mappings.
    ssa_names: HashMap<(u32, usize, String), SsaVar>,
    /// Phi nodes accumulated during construction.
    phi_map: BTreeMap<u32, Vec<PhiNode>>,
}

impl MlilSsaBuilder {
    /// Create a new builder from a list of blocks.
    ///
    /// Blocks must have their `id` and `successors` fields set.
    /// The `predecessors` field will be computed automatically.
    #[must_use]
    pub fn new(blocks: Vec<MlilBlock>, entry: u32) -> Self {
        Self {
            blocks,
            entry,
            version_counters: HashMap::new(),
            rename_stack: HashMap::new(),
            ssa_names: HashMap::new(),
            phi_map: BTreeMap::new(),
        }
    }

    /// Add an instruction to a block.
    pub fn add_instruction(&mut self, block_id: u32, insn: MlilInstruction) {
        if let Some(b) = self.blocks.iter_mut().find(|b| b.id == block_id) {
            b.instructions.push(insn);
        }
    }

    /// Build SSA form and return an [`SsaFunction`].
    #[must_use]
    pub fn build_ssa(mut self) -> SsaFunction {
        // Step 1: compute predecessors.
        self.compute_predecessors();

        // Step 2: compute dominators (simple Lengauer-Tarjan approximation
        //         using BFS order idom computation for small CFGs).
        self.compute_dominators();

        // Step 3: compute dominance frontiers.
        self.compute_dominance_frontiers();

        // Step 4: collect all live variables.
        let live_vars = self.collect_live_vars();

        // Step 5: insert phi nodes at dominance frontiers.
        self.insert_phi_nodes(&live_vars);

        // Step 6: rename variables (DFS traversal of dominator tree).
        self.rename_variables();

        let phi_count: usize = self.phi_map.values().map(std::vec::Vec::len).sum();

        SsaFunction {
            blocks: self.blocks,
            phi_map: self.phi_map,
            ssa_names: self.ssa_names,
            entry: self.entry,
            phi_count,
            live_vars,
        }
    }

    // ── Step 1: predecessors ──────────────────────────────────────────────

    fn compute_predecessors(&mut self) {
        let edges: Vec<(u32, u32)> = self
            .blocks
            .iter()
            .flat_map(|b| b.successors.iter().map(move |&s| (b.id, s)))
            .collect();
        for (src, dst) in edges {
            if let Some(b) = self.blocks.iter_mut().find(|b| b.id == dst)
                && !b.predecessors.contains(&src) {
                    b.predecessors.push(src);
                }
        }
    }

    // ── Step 2: dominators (simple iterative algorithm) ───────────────────

    fn compute_dominators(&mut self) {
        let n = self.blocks.len();
        if n == 0 {
            return;
        }

        // Map block ID → index.
        let id_to_idx: HashMap<u32, usize> = self
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.id, i))
            .collect();

        // BFS order from entry. Use `id_to_idx` to index into `self.blocks`
        // in O(1) per visit instead of the linear `find` scan.
        let mut order: Vec<u32> = Vec::new();
        let mut visited: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<u32> = VecDeque::new();
        queue.push_back(self.entry);
        while let Some(id) = queue.pop_front() {
            if visited.insert(id) {
                order.push(id);
                if let Some(&idx) = id_to_idx.get(&id)
                    && let Some(b) = self.blocks.get(idx) {
                        for &s in &b.successors {
                            queue.push_back(s);
                        }
                    }
            }
        }

        // Initialise: idom[entry] = entry, others = UNDEF (u32::MAX).
        let mut idom: HashMap<u32, u32> = HashMap::new();
        idom.insert(self.entry, self.entry);

        // Pre-compute O(1) position lookup for blocks in `order`.
        let order_pos: HashMap<u32, usize> = order
            .iter()
            .enumerate()
            .map(|(i, &id)| (id, i))
            .collect();

        let mut changed = true;
        while changed {
            changed = false;
            for &b_id in &order {
                if b_id == self.entry {
                    continue;
                }
                let preds: Vec<u32> = self
                    .blocks
                    .iter()
                    .find(|b| b.id == b_id)
                    .map(|b| b.predecessors.clone())
                    .unwrap_or_default();

                // Find the first processed predecessor.
                let new_idom_opt = preds
                    .iter()
                    .filter(|&&p| idom.contains_key(&p))
                    .copied()
                    .next();
                let mut new_idom = match new_idom_opt {
                    Some(v) => v,
                    None => continue,
                };

                for &p in &preds {
                    if p == new_idom {
                        continue;
                    }
                    if idom.contains_key(&p) {
                        // Intersect: walk up both chains.
                        let mut a = p;
                        let mut b = new_idom;
                        // Bound iterations to prevent infinite loops on malformed idom maps.
                        let mut limit = order.len().saturating_add(2);
                        while a != b && limit > 0 {
                            limit -= 1;
                            let pos_a = *order_pos.get(&a).unwrap_or(&usize::MAX);
                            let pos_b = *order_pos.get(&b).unwrap_or(&usize::MAX);
                            if pos_a > pos_b {
                                a = match idom.get(&a) {
                                    Some(&p) => p,
                                    None => break,
                                };
                            } else {
                                b = match idom.get(&b) {
                                    Some(&p) => p,
                                    None => break,
                                };
                            }
                        }
                        if a == b {
                            new_idom = a;
                        }
                    }
                }

                let current = idom.entry(b_id).or_insert(u32::MAX);
                if *current != new_idom {
                    *current = new_idom;
                    changed = true;
                }
            }
        }

        // Write back idom to blocks.
        for b in &mut self.blocks {
            b.idom = *idom.get(&b.id).unwrap_or(&u32::MAX);
        }
    }

    // ── Step 3: dominance frontiers ───────────────────────────────────────

    fn compute_dominance_frontiers(&mut self) {
        let block_ids: Vec<u32> = self.blocks.iter().map(|b| b.id).collect();
        let preds: HashMap<u32, Vec<u32>> = self
            .blocks
            .iter()
            .map(|b| (b.id, b.predecessors.clone()))
            .collect();
        let idoms: HashMap<u32, u32> = self
            .blocks
            .iter()
            .map(|b| (b.id, b.idom))
            .collect();

        // Pre-compute O(1) block-id to block-index lookup.
        let id_to_idx: HashMap<u32, usize> = self
            .blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (b.id, i))
            .collect();

        for &b_id in &block_ids {
            let b_preds = match preds.get(&b_id) {
                Some(p) if p.len() >= 2 => p.clone(),
                _ => continue,
            };
            for &pred in &b_preds {
                let mut runner = pred;
                let b_idom = *idoms.get(&b_id).unwrap_or(&u32::MAX);
                while runner != b_idom && runner != u32::MAX {
                    // Add b_id to runner's DF.
                    if let Some(&idx) = id_to_idx.get(&runner)
                        && let Some(blk) = self.blocks.get_mut(idx) {
                            blk.df.insert(b_id);
                        }
                    runner = *idoms.get(&runner).unwrap_or(&u32::MAX);
                }
            }
        }
    }

    // ── Step 4: collect live vars ─────────────────────────────────────────

    fn collect_live_vars(&self) -> HashSet<String> {
        let mut vars = HashSet::new();
        for b in &self.blocks {
            for i in &b.instructions {
                for v in &i.defs { vars.insert(v.clone()); }
                for v in &i.uses { vars.insert(v.clone()); }
            }
        }
        vars
    }

    // ── Step 5: phi insertion ─────────────────────────────────────────────

    fn insert_phi_nodes(&mut self, vars: &HashSet<String>) {
        for var in vars {
            // Find all blocks that define this variable.
            let def_blocks: Vec<u32> = self
                .blocks
                .iter()
                .filter(|b| b.instructions.iter().any(|i| i.defs.contains(var)))
                .map(|b| b.id)
                .collect();

            let mut worklist: VecDeque<u32> = def_blocks.into_iter().collect();
            let mut has_phi: HashSet<u32> = HashSet::new();

            while let Some(b_id) = worklist.pop_front() {
                let df: Vec<u32> = self
                    .blocks
                    .iter()
                    .find(|b| b.id == b_id)
                    .map(|b| b.df.iter().copied().collect())
                    .unwrap_or_default();

                for y in df {
                    if !has_phi.contains(&y) {
                        // Insert phi for var at block y.
                        let phi = PhiNode::new(SsaVar::initial(var.clone()), y);
                        self.phi_map.entry(y).or_default().push(phi);
                        has_phi.insert(y);
                        worklist.push_back(y);
                    }
                }
            }
        }
    }

    // ── Step 6: rename variables ──────────────────────────────────────────

    fn rename_variables(&mut self) {
        // Build dominator tree: parent → children.
        let mut dom_children: HashMap<u32, Vec<u32>> = HashMap::new();
        for b in &self.blocks {
            if b.idom != u32::MAX && b.idom != b.id {
                dom_children.entry(b.idom).or_default().push(b.id);
            }
        }

        let block_ids: Vec<u32> = self.blocks.iter().map(|b| b.id).collect();
        let mut visited: HashSet<u32> = HashSet::new();
        let mut stack: Vec<u32> = vec![self.entry];

        // Build a fast id → block-index lookup, mirroring `block_ids` order,
        // so successor scans below can avoid linear `find()` calls.
        let block_idx: HashMap<u32, usize> = block_ids
            .iter()
            .copied()
            .enumerate()
            .map(|(i, id)| (id, i))
            .collect();

        // DFS over dominator tree using explicit stack.
        while let Some(b_id) = stack.pop() {
            if !visited.insert(b_id) {
                continue;
            }
            // Rename phi dests in this block.
            // Collect bases first to avoid simultaneous mutable borrows.
            let phi_bases: Vec<String> = self
                .phi_map
                .get(&b_id)
                .map(|phis| phis.iter().map(|p| p.dest.name.clone()).collect())
                .unwrap_or_default();
            let new_dests: Vec<SsaVar> = phi_bases
                .iter()
                .map(|base| SsaVar::new(base.clone(), self.next_version(base)))
                .collect();
            if let Some(phis) = self.phi_map.get_mut(&b_id) {
                for (phi, new_dest) in phis.iter_mut().zip(new_dests.iter()) {
                    phi.dest = new_dest.clone();
                }
            }
            for new_dest in &new_dests {
                self.rename_stack
                    .entry(new_dest.name.clone())
                    .or_default()
                    .push(new_dest.clone());
            }
            // Rename instructions.
            if let Some(block_idx) = self.blocks.iter().position(|b| b.id == b_id) {
                let n_insns = self.blocks[block_idx].instructions.len();
                for insn_idx in 0..n_insns {
                    let insn = self.blocks[block_idx].instructions[insn_idx].clone();
                    // Uses: record current version.
                    for base in &insn.uses {
                        let cur = self.current_version(base);
                        self.ssa_names.insert((b_id, insn_idx, base.clone()), cur);
                    }
                    // Defs: new version.
                    for base in &insn.defs {
                        let ver = self.next_version(base);
                        let sv = SsaVar::new(base.clone(), ver);
                        self.ssa_names.insert((b_id, insn_idx, base.clone()), sv.clone());
                        self.rename_stack.entry(base.clone()).or_default().push(sv);
                    }
                }
            }
            // Fill phi sources in successors. O(1) lookup via `block_idx`.
            let succs: Vec<u32> = block_idx
                .get(&b_id)
                .and_then(|&i| self.blocks.get(i))
                .map(|b| b.successors.clone())
                .unwrap_or_default();
            for succ in &succs {
                // Collect (base, cur_version) pairs before mutably borrowing phi_map.
                let updates: Vec<SsaVar> = self
                    .phi_map
                    .get(succ)
                    .map(|phis| {
                        phis.iter()
                            .map(|phi| self.current_version(&phi.dest.name))
                            .collect()
                    })
                    .unwrap_or_default();
                if let Some(phis) = self.phi_map.get_mut(succ) {
                    for (phi, cur) in phis.iter_mut().zip(updates.into_iter()) {
                        phi.add_source(b_id, cur);
                    }
                }
            }
            // Push children onto DFS stack.
            if let Some(children) = dom_children.get(&b_id) {
                for &child in children {
                    stack.push(child);
                }
            }
        }
    }

    fn next_version(&mut self, base: &str) -> u32 {
        let v = self.version_counters.entry(base.to_string()).or_insert(0);
        *v += 1;
        *v
    }

    fn current_version(&self, base: &str) -> SsaVar {
        self.rename_stack
            .get(base)
            .and_then(|s| s.last().cloned())
            .unwrap_or_else(|| SsaVar::initial(base))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// build_ssa — public convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Build SSA form from a list of blocks with the given entry block ID.
#[must_use]
pub fn build_ssa(blocks: Vec<MlilBlock>, entry: u32) -> SsaFunction {
    MlilSsaBuilder::new(blocks, entry).build_ssa()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_cfg() -> Vec<MlilBlock> {
        let mut entry = MlilBlock::new(0, vec![1, 2]);
        entry.instructions.push(MlilInstruction::assign(0x100, "x", "1"));

        let mut left = MlilBlock::new(1, vec![3]);
        left.instructions.push(MlilInstruction::assign(0x200, "x", "2"));

        let mut right = MlilBlock::new(2, vec![3]);
        right.instructions.push(MlilInstruction::assign(0x300, "x", "3"));

        let mut join = MlilBlock::new(3, vec![]);
        join.instructions.push(MlilInstruction {
            addr: 0x400,
            defs: vec![],
            uses: vec!["x".into()],
            text: "use x".into(),
        });

        vec![entry, left, right, join]
    }

    #[test]
    fn phi_inserted_at_join() {
        let cfg = simple_cfg();
        let ssa = build_ssa(cfg, 0);
        // Block 3 (join) should have a phi for x.
        let phis = ssa.phi_map.get(&3);
        assert!(phis.is_some(), "expected phi at join block");
        let phi = phis.unwrap().iter().find(|p| p.dest.name == "x");
        assert!(phi.is_some(), "expected phi for x");
    }

    #[test]
    fn ssa_var_display() {
        let v = SsaVar::new("rax", 3);
        assert_eq!(v.to_string(), "rax#3");
    }

    #[test]
    fn phi_trivial() {
        let mut phi = PhiNode::new(SsaVar::new("x", 1), 5);
        phi.add_source(0, SsaVar::new("x", 1));
        phi.add_source(1, SsaVar::new("x", 1));
        assert!(phi.is_trivial());
        assert_eq!(phi.simplify().unwrap(), SsaVar::new("x", 1));
    }

    #[test]
    fn build_ssa_single_block() {
        let mut b = MlilBlock::new(0, vec![]);
        b.instructions.push(MlilInstruction::assign(0, "a", "1"));
        let ssa = build_ssa(vec![b], 0);
        assert_eq!(ssa.phi_count, 0);
    }
}
