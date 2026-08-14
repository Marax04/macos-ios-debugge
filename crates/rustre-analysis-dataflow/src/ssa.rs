//! `ssa` — SSA construction via the Cytron-Ferrante-Rosen-Wegman-Zadeck algorithm.
//!
//! Reference: Cytron, R. et al. (1991). "Efficiently computing static single
//! assignment form and the control dependence graph." ACM TOPLAS 13(4):451-490.
//!
//! The algorithm has two phases:
//! 1. Insert φ-nodes at iterated dominance frontiers for every variable.
//! 2. Rename all variable uses/definitions by walking the dominator tree.
//!
//! Audit note (dataflow-crate iteration 5): `SsaFunction`/`Var`/`SsaVar`/
//! `construct_ssa` are load-bearing *within* this crate — `constant_propagation`,
//! `def_use`, `du_chains`, `live_ranges`, and `value_range` all build on this
//! module's SSA IR. But grepping the whole workspace for
//! `rustre_analysis_dataflow::` usage shows none of those internal callers is
//! itself reached from outside this crate. `ssa_optimizer.rs` has its own,
//! *unrelated* `SsaFunction` type — don't confuse the two. This module is
//! real shared infrastructure, but the whole subgraph it anchors is
//! currently orphaned from the rest of the workspace.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::cfg_dom::{BBId, Cfg, DomTree};

// ── Variable model ─────────────────────────────────────────────────────────────

/// A program variable identified by name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Var(pub String);

impl Var {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// An SSA version: `Var` + version counter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SsaVar {
    pub base: Var,
    pub version: u32,
}

impl SsaVar {
    #[must_use]
    pub const fn new(base: Var, version: u32) -> Self {
        Self { base, version }
    }
}

impl std::fmt::Display for SsaVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}", self.base.0, self.version)
    }
}

// ── Instruction model ─────────────────────────────────────────────────────────

/// A simplified, mutable instruction inside a basic block.
/// `def` holds the variable written by this instruction (if any).
/// `uses` holds all variables read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub id: usize,
    pub def: Option<Var>,
    pub uses: Vec<Var>,
    // After SSA renaming these fields are populated.
    pub ssa_def: Option<SsaVar>,
    pub ssa_uses: Vec<SsaVar>,
}

impl Instruction {
    #[must_use]
    pub const fn new(id: usize, def: Option<Var>, uses: Vec<Var>) -> Self {
        Self {
            id,
            def,
            uses,
            ssa_def: None,
            ssa_uses: Vec::new(),
        }
    }
}

// ── φ-node ────────────────────────────────────────────────────────────────────

/// A φ-node at the entry of a basic block for one variable.
/// `args[i]` = SSA variable incoming from predecessor `i`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiNode {
    pub var: Var,
    pub result: Option<SsaVar>,
    /// One argument per predecessor of the containing block.
    pub args: Vec<Option<SsaVar>>,
}

impl PhiNode {
    #[must_use]
    pub fn new(var: Var, pred_count: usize) -> Self {
        Self {
            var,
            result: None,
            args: vec![None; pred_count],
        }
    }
}

// ── MlilFunction (SSA) ────────────────────────────────────────────────────────

/// A function in SSA form: a list of basic blocks, each with φ-nodes
/// followed by ordinary instructions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsaFunction {
    pub cfg: Cfg,
    pub blocks: Vec<BasicBlock>,
}

/// One basic block in the SSA function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BBId,
    pub phis: Vec<PhiNode>,
    pub instrs: Vec<Instruction>,
}

impl SsaFunction {
    /// Create an `SsaFunction` from a CFG and a per-block instruction list.
    #[must_use]
    pub fn new(cfg: Cfg, instrs_per_block: &[Vec<Instruction>]) -> Self {
        let n = cfg.len();
        let mut blocks: Vec<BasicBlock> = (0..n)
            .map(|i| BasicBlock {
                id: BBId(i),
                phis: Vec::new(),
                instrs: instrs_per_block.get(i).cloned().unwrap_or_default(),
            })
            .collect();
        // Ensure blocks has exactly n elements.
        blocks.truncate(n);
        Self { cfg, blocks }
    }

    /// Insert a φ-node for `var` at block `bb_id`.
    ///
    /// Does nothing if `bb_id` is out of range for this function's blocks/CFG
    /// (e.g. an adversarial or stale `BBId`), rather than panicking.
    pub fn insert_phi(&mut self, bb_id: BBId, var: Var) {
        let Some(pred_count) = self.cfg.pred.get(bb_id.0).map(Vec::len) else {
            return;
        };
        let Some(block) = self.blocks.get_mut(bb_id.0) else {
            return;
        };
        // Only insert if not already present.
        if !block.phis.iter().any(|p| p.var == var) {
            block.phis.push(PhiNode::new(var, pred_count));
        }
    }

    /// Collect all variables defined anywhere in the function.
    #[must_use]
    pub fn all_vars(&self) -> HashSet<Var> {
        let mut vars = HashSet::new();
        for block in &self.blocks {
            for phi in &block.phis {
                vars.insert(phi.var.clone());
            }
            for instr in &block.instrs {
                if let Some(ref v) = instr.def {
                    vars.insert(v.clone());
                }
            }
        }
        vars
    }

    /// For each variable, compute the set of basic blocks that contain a
    /// definition of that variable.
    #[must_use]
    pub fn def_sites(&self) -> HashMap<Var, HashSet<BBId>> {
        let mut map: HashMap<Var, HashSet<BBId>> = HashMap::new();
        for (bb_idx, block) in self.blocks.iter().enumerate() {
            let bb = BBId(bb_idx);
            for phi in &block.phis {
                map.entry(phi.var.clone()).or_default().insert(bb);
            }
            for instr in &block.instrs {
                if let Some(ref v) = instr.def {
                    map.entry(v.clone()).or_default().insert(bb);
                }
            }
        }
        map
    }
}

// ── Phase 1: φ-node insertion ─────────────────────────────────────────────────

/// Insert φ-nodes for all variables at the iterated dominance frontier of their
/// definition sites.
pub fn insert_phi_nodes(func: &mut SsaFunction, dom_tree: &DomTree) {
    let df = dom_tree.dominance_frontier(&func.cfg);
    let def_sites = func.def_sites();

    // Iterate variables and blocks in a deterministic order: `def_sites` and
    // its per-var `HashSet<BBId>` have unspecified (hash-seed-dependent)
    // iteration order, which would otherwise make the relative order of
    // φ-nodes pushed into each block's `phis` vector vary from run to run.
    let mut vars: Vec<&Var> = def_sites.keys().collect();
    vars.sort_by(|a, b| a.0.cmp(&b.0));

    for var in vars {
        let def_set = &def_sites[var];
        let mut sorted_defs: Vec<BBId> = def_set.iter().copied().collect();
        sorted_defs.sort_by_key(|b| b.0);
        let mut worklist: VecDeque<BBId> = sorted_defs.into();
        let mut phi_inserted: HashSet<BBId> = HashSet::new();

        while let Some(bb) = worklist.pop_front() {
            let mut frontier: Vec<BBId> = df[bb.0].iter().copied().collect();
            frontier.sort_by_key(|b| b.0);
            for y in frontier {
                if phi_inserted.insert(y) {
                    func.insert_phi(y, var.clone());
                    if !def_set.contains(&y) {
                        worklist.push_back(y);
                    }
                }
            }
        }
    }
}

// ── Phase 2: Variable renaming ─────────────────────────────────────────────────

/// Rename all variable references to SSA form by walking the dominator tree.
pub fn rename_variables(func: &mut SsaFunction, dom_tree: &DomTree) {
    let n = func.blocks.len();
    if n == 0 {
        return;
    }

    // Per-variable version counter and definition stack.
    let all_vars: Vec<Var> = func.all_vars().into_iter().collect();
    let mut counters: HashMap<Var, u32> = all_vars.iter().map(|v| (v.clone(), 0)).collect();
    let mut stacks: HashMap<Var, Vec<SsaVar>> = all_vars
        .iter()
        .map(|v| {
            // Push a version 0 placeholder so all uses are defined.
            let init = SsaVar::new(v.clone(), 0);
            counters.insert(v.clone(), 1);
            (v.clone(), vec![init])
        })
        .collect();

    // Entry node
    let entry = func.cfg.entry;

    // Recursive DFS over dominator tree (implemented iteratively).
    // Stack entry: (block_id, snapshot of counters/stacks to restore on pop).
    rename_block(func, entry, dom_tree, &mut counters, &mut stacks);
}

/// Rename one basic block and recursively rename all blocks it dominates.
fn rename_block(
    func: &mut SsaFunction,
    bb: BBId,
    dom_tree: &DomTree,
    counters: &mut HashMap<Var, u32>,
    stacks: &mut HashMap<Var, Vec<SsaVar>>,
) {
    enum Action {
        Enter(BBId),
        Restore(HashMap<Var, usize>),
    }

    let mut work: Vec<Action> = vec![Action::Enter(bb)];
    while let Some(action) = work.pop() {
        let bb = match action {
            Action::Enter(bb) => bb,
            Action::Restore(saved) => {
                // Restore stacks to saved depths.
                for (v, depth) in &saved {
                    if let Some(stack) = stacks.get_mut(v) {
                        stack.truncate(*depth);
                    }
                }
                continue;
            }
        };

    // Snapshot the stack tops so we can restore them after processing children.
    let saved: HashMap<Var, usize> = stacks.iter().map(|(v, s)| (v.clone(), s.len())).collect();

    // Rename φ-node definitions.
    for phi in &mut func.blocks[bb.0].phis {
        let v = phi.var.clone();
        let ver = counters[&v];
        *counters.get_mut(&v).unwrap() += 1;
        let ssa_v = SsaVar::new(v.clone(), ver);
        phi.result = Some(ssa_v.clone());
        stacks.entry(v).or_default().push(ssa_v);
    }

    // Rename instruction defs and uses.
    let instrs_len = func.blocks[bb.0].instrs.len();
    for i in 0..instrs_len {
        // Rename uses first (read current stack tops).
        let ssa_uses: Vec<SsaVar> = func.blocks[bb.0].instrs[i]
            .uses
            .iter()
            .map(|u| {
                stacks
                    .get(u)
                    .and_then(|s| s.last())
                    .cloned()
                    .unwrap_or_else(|| SsaVar::new(u.clone(), 0))
            })
            .collect();
        func.blocks[bb.0].instrs[i].ssa_uses = ssa_uses;

        // Rename def.
        if let Some(v) = func.blocks[bb.0].instrs[i].def.clone() {
            let ver = *counters.get(&v).unwrap_or(&0);
            *counters.entry(v.clone()).or_insert(0) += 1;
            let ssa_v = SsaVar::new(v.clone(), ver);
            func.blocks[bb.0].instrs[i].ssa_def = Some(ssa_v.clone());
            stacks.entry(v).or_default().push(ssa_v);
        }
    }

    // Fill φ-node arguments in successor blocks.
    for si in 0..func.cfg.succ[bb.0].len() {
        let succ = func.cfg.succ[bb.0][si];
        // Find the predecessor index of `bb` in `succ`'s predecessor list.
        let pred_idx = func.cfg.pred[succ.0]
            .iter()
            .position(|&p| p == bb)
            .expect("bb must be a predecessor of succ");

        for phi in &mut func.blocks[succ.0].phis {
            let top = stacks
                .get(&phi.var)
                .and_then(|s| s.last())
                .cloned()
                .unwrap_or_else(|| SsaVar::new(phi.var.clone(), 0));
            if pred_idx < phi.args.len() {
                phi.args[pred_idx] = Some(top);
            }
        }
    }

    // Process dominated children after restoring this block's stack snapshot.
    work.push(Action::Restore(saved));
    for child in dom_tree.children[bb.0].iter().rev().copied() {
        work.push(Action::Enter(child));
    }
    }
}

// ── construct_ssa ─────────────────────────────────────────────────────────────

/// Full SSA construction pipeline: insert φ-nodes then rename variables.
pub fn construct_ssa(func: &mut SsaFunction) {
    let dom_tree = crate::cfg_dom::lengauer_tarjan(&func.cfg, func.cfg.entry);
    insert_phi_nodes(func, &dom_tree);
    rename_variables(func, &dom_tree);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};

    fn v(name: &str) -> Var {
        Var::new(name)
    }

    fn linear_func(n: usize) -> SsaFunction {
        let succs: Vec<Vec<BBId>> = (0..n)
            .map(|i| if i + 1 < n { vec![BBId(i + 1)] } else { vec![] })
            .collect();
        let cfg = Cfg::new(n, succs, BBId(0), BBId(n - 1));
        let instrs: Vec<Vec<Instruction>> = (0..n)
            .map(|i| vec![Instruction::new(i, Some(v("x")), vec![])])
            .collect();
        SsaFunction::new(cfg, &instrs)
    }

    fn diamond_func() -> SsaFunction {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let block_instrs = vec![
            vec![Instruction::new(0, Some(v("x")), vec![])],
            vec![Instruction::new(1, Some(v("x")), vec![])],
            vec![Instruction::new(2, Some(v("x")), vec![])],
            vec![Instruction::new(3, None, vec![v("x")])],
        ];
        SsaFunction::new(cfg, &block_instrs)
    }

    #[test]
    fn test_all_vars() {
        let func = linear_func(3);
        let vars = func.all_vars();
        assert!(vars.contains(&v("x")));
    }

    #[test]
    fn test_def_sites() {
        let func = linear_func(3);
        let sites = func.def_sites();
        let x_sites = &sites[&v("x")];
        assert_eq!(x_sites.len(), 3); // defined in each block
    }

    #[test]
    fn test_phi_insertion_diamond() {
        let mut func = diamond_func();
        let dom_tree = crate::cfg_dom::lengauer_tarjan(&func.cfg, BBId(0));
        insert_phi_nodes(&mut func, &dom_tree);
        // Block 3 (join) should have a φ-node for x since both 1 and 2 define x.
        assert!(func.blocks[3].phis.iter().any(|p| p.var == v("x")));
    }

    #[test]
    fn test_ssa_renaming_linear() {
        let mut func = linear_func(3);
        construct_ssa(&mut func);

        // Each block should have a distinct SSA version.
        let versions: Vec<u32> = func
            .blocks
            .iter()
            .filter_map(|b| b.instrs.first())
            .filter_map(|i| i.ssa_def.as_ref())
            .map(|sv| sv.version)
            .collect();

        assert_eq!(versions.len(), 3);
        // All versions should be distinct (each is a new def of x).
        let unique: HashSet<u32> = versions.iter().copied().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn test_ssa_renaming_diamond() {
        let mut func = diamond_func();
        construct_ssa(&mut func);

        // Block 3's use of x should reference an SSA variable.
        let use_instr = &func.blocks[3].instrs[0];
        assert!(!use_instr.ssa_uses.is_empty());
    }

    #[test]
    fn test_phi_node_has_args_after_rename() {
        let mut func = diamond_func();
        construct_ssa(&mut func);

        for phi in &func.blocks[3].phis {
            // Both arms of the diamond should provide an argument.
            assert_eq!(phi.args.len(), 2);
            assert!(phi.args.iter().any(std::option::Option::is_some));
        }
    }

    #[test]
    fn test_ssa_var_display() {
        let sv = SsaVar::new(Var::new("foo"), 3);
        assert_eq!(sv.to_string(), "foo_3");
    }

    #[test]
    fn test_insert_phi_idempotent() {
        let mut func = diamond_func();
        let dom_tree = crate::cfg_dom::lengauer_tarjan(&func.cfg, BBId(0));
        insert_phi_nodes(&mut func, &dom_tree);
        let count_before = func.blocks[3].phis.len();
        insert_phi_nodes(&mut func, &dom_tree);
        let count_after = func.blocks[3].phis.len();
        assert_eq!(count_before, count_after);
    }

    #[test]
    fn test_phi_node_creation() {
        let phi = PhiNode::new(v("y"), 3);
        assert_eq!(phi.args.len(), 3);
        assert!(phi.result.is_none());
    }

    #[test]
    fn test_ssa_function_insert_phi() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let mut func = SsaFunction::new(cfg, &vec![vec![], vec![]]);
        func.insert_phi(BBId(1), v("z"));
        assert_eq!(func.blocks[1].phis.len(), 1);
        // Insert again — should not duplicate.
        func.insert_phi(BBId(1), v("z"));
        assert_eq!(func.blocks[1].phis.len(), 1);
    }

    #[test]
    fn test_insert_phi_out_of_range_is_noop_not_panic() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let mut func = SsaFunction::new(cfg, &vec![vec![], vec![]]);
        // BBId(99) is out of range for both `blocks` and `cfg.pred` — must not panic.
        func.insert_phi(BBId(99), v("z"));
        assert_eq!(func.blocks.len(), 2);
        assert!(func.blocks.iter().all(|b| b.phis.is_empty()));
    }
}

// ── SsaFunction extended API ──────────────────────────────────────────────────

impl SsaFunction {
    /// Iterate all SSA-renamed variable definitions in program order.
    /// Returns `(block_id, instr_index_or_-1_for_phi, SsaVar)` triples.
    #[must_use] 
    pub fn all_ssa_defs(&self) -> Vec<(BBId, i32, SsaVar)> {
        let mut out = Vec::with_capacity(self.phi_count() + self.instr_count());
        for (bi, block) in self.blocks.iter().enumerate() {
            let bb = BBId(bi);
            for phi in &block.phis {
                if let Some(ref sv) = phi.result {
                    out.push((bb, -1, sv.clone()));
                }
            }
            for (ii, instr) in block.instrs.iter().enumerate() {
                if let Some(ref sv) = instr.ssa_def {
                    out.push((bb, i32::try_from(ii).unwrap_or(i32::MAX), sv.clone()));
                }
            }
        }
        out
    }

    /// Iterate all SSA-renamed variable uses in program order.
    /// Returns `(block_id, instr_index, operand_index, SsaVar)` tuples.
    #[must_use] 
    pub fn all_ssa_uses(&self) -> Vec<(BBId, usize, usize, SsaVar)> {
        let mut out = Vec::with_capacity(self.instr_count());
        for (bi, block) in self.blocks.iter().enumerate() {
            let bb = BBId(bi);
            for (ii, instr) in block.instrs.iter().enumerate() {
                for (oi, sv) in instr.ssa_uses.iter().enumerate() {
                    out.push((bb, ii, oi, sv.clone()));
                }
            }
        }
        out
    }

    /// Return the number of φ-nodes across all blocks.
    #[must_use]
    pub fn phi_count(&self) -> usize {
        self.blocks.iter().map(|b| b.phis.len()).sum()
    }

    /// Return all variables that have a φ-node in any block.
    #[must_use]
    pub fn phi_vars(&self) -> HashSet<Var> {
        let mut set = HashSet::new();
        for block in &self.blocks {
            for phi in &block.phis {
                set.insert(phi.var.clone());
            }
        }
        set
    }

    /// Count the total number of instructions (excluding φ-nodes).
    #[must_use]
    pub fn instr_count(&self) -> usize {
        self.blocks.iter().map(|b| b.instrs.len()).sum()
    }

    /// Return a map from each SSA variable to its definition block.
    #[must_use]
    pub fn ssa_def_block(&self) -> HashMap<SsaVar, BBId> {
        let mut map = HashMap::new();
        for (bi, block) in self.blocks.iter().enumerate() {
            let bb = BBId(bi);
            for phi in &block.phis {
                if let Some(ref sv) = phi.result {
                    map.insert(sv.clone(), bb);
                }
            }
            for instr in &block.instrs {
                if let Some(ref sv) = instr.ssa_def {
                    map.insert(sv.clone(), bb);
                }
            }
        }
        map
    }

    /// Return all SSA variables used in block `bb`.
    #[must_use]
    pub fn used_in_block(&self, bb: BBId) -> HashSet<SsaVar> {
        let mut set = HashSet::new();
        if let Some(block) = self.blocks.get(bb.0) {
            for phi in &block.phis {
                for sv in phi.args.iter().flatten() {
                    set.insert(sv.clone());
                }
            }
            for instr in &block.instrs {
                for sv in &instr.ssa_uses {
                    set.insert(sv.clone());
                }
            }
        }
        set
    }

    /// Return all SSA variables defined in block `bb`.
    #[must_use]
    pub fn defined_in_block(&self, bb: BBId) -> HashSet<SsaVar> {
        let mut set = HashSet::new();
        if let Some(block) = self.blocks.get(bb.0) {
            for phi in &block.phis {
                if let Some(ref sv) = phi.result {
                    set.insert(sv.clone());
                }
            }
            for instr in &block.instrs {
                if let Some(ref sv) = instr.ssa_def {
                    set.insert(sv.clone());
                }
            }
        }
        set
    }

    /// Verify SSA form invariants.  Returns a list of violation strings.
    /// An empty list means the function is in valid SSA form.
    #[must_use]
    pub fn verify(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut seen_defs: HashMap<SsaVar, BBId> = HashMap::new();

        for (bi, block) in self.blocks.iter().enumerate() {
            let bb = BBId(bi);
            // Check φ-node definitions.
            for phi in &block.phis {
                if let Some(ref sv) = phi.result
                    && let Some(prev_bb) = seen_defs.insert(sv.clone(), bb) {
                        errors.push(format!(
                            "SSA violation: {} defined in both bb{} and bb{}",
                            sv, prev_bb.0, bi
                        ));
                    }
                // Check argument count matches predecessor count.
                let pred_count = self.cfg.pred[bi].len();
                if phi.args.len() != pred_count {
                    errors.push(format!(
                        "φ-node {} in bb{} has {} args but {} predecessors",
                        phi.var.0,
                        bi,
                        phi.args.len(),
                        pred_count
                    ));
                }
            }
            // Check instruction definitions.
            for instr in &block.instrs {
                if let Some(ref sv) = instr.ssa_def
                    && let Some(prev_bb) = seen_defs.insert(sv.clone(), bb) {
                        errors.push(format!(
                            "SSA violation: {} defined in both bb{} and bb{}",
                            sv, prev_bb.0, bi
                        ));
                    }
            }
        }
        errors
    }

    /// Compute the set of all reachable blocks from the CFG entry using BFS.
    #[must_use]
    pub fn reachable_blocks(&self) -> HashSet<BBId> {
        use std::collections::VecDeque;
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(self.cfg.entry);
        visited.insert(self.cfg.entry);
        while let Some(bb) = queue.pop_front() {
            for &succ in &self.cfg.succ[bb.0] {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
        visited
    }

    /// Remove all φ-nodes — converts SSA back to non-SSA form.
    /// Useful for testing or when lowering SSA for code generation.
    pub fn strip_phis(&mut self) {
        for block in &mut self.blocks {
            block.phis.clear();
        }
    }

    /// Count the maximum SSA version used for any base variable.
    #[must_use]
    pub fn max_ssa_version(&self) -> u32 {
        let mut max_ver = 0u32;
        for (_, _, sv) in self.all_ssa_defs() {
            max_ver = max_ver.max(sv.version);
        }
        max_ver
    }
}

// ── SsaVar utilities ──────────────────────────────────────────────────────────

impl SsaVar {
    /// Whether this SSA variable is the initial (version 0) placeholder.
    #[must_use]
    pub const fn is_initial(&self) -> bool {
        self.version == 0
    }

    /// Whether two SSA variables have the same base variable.
    #[must_use]
    pub fn same_base(&self, other: &Self) -> bool {
        self.base == other.base
    }
}

// ── PhiNode utilities ─────────────────────────────────────────────────────────

impl PhiNode {
    /// Whether all arguments have been filled in.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.args.iter().all(Option::is_some)
    }

    /// Number of non-None arguments.
    #[must_use]
    pub fn defined_arg_count(&self) -> usize {
        self.args.iter().filter(|a| a.is_some()).count()
    }

    /// Whether this φ-node has the same argument in all positions (trivial φ).
    #[must_use]
    pub fn is_trivial(&self) -> bool {
        let Some(first) = self.args.first().and_then(Option::as_ref) else { return false };
        self.args.iter().all(|a| a.as_ref() == Some(first))
    }
}

// ── Instruction utilities ─────────────────────────────────────────────────────

impl Instruction {
    /// Whether this instruction has been renamed to SSA form.
    #[must_use]
    pub const fn is_renamed(&self) -> bool {
        // A renamed instruction has ssa_uses matching uses, or an ssa_def if it has a def.
        if self.def.is_some() {
            self.ssa_def.is_some()
        } else {
            self.uses.len() == self.ssa_uses.len()
        }
    }
}

// ── Extended tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod ssa_extended_tests {
    use super::*;
    use crate::cfg_dom::{BBId, Cfg};

    fn v(name: &str) -> Var {
        Var::new(name)
    }

    fn diamond_func() -> SsaFunction {
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let block_instrs = vec![
            vec![Instruction::new(0, Some(v("x")), vec![])],
            vec![Instruction::new(1, Some(v("x")), vec![])],
            vec![Instruction::new(2, Some(v("x")), vec![])],
            vec![Instruction::new(3, None, vec![v("x")])],
        ];
        SsaFunction::new(cfg, &block_instrs)
    }

    #[test]
    fn phi_count_zero_before_construction() {
        let func = diamond_func();
        // Before SSA, no φ-nodes.
        assert_eq!(func.phi_count(), 0);
    }

    #[test]
    fn phi_count_after_construction() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        assert!(func.phi_count() >= 1);
    }

    #[test]
    fn all_ssa_defs_nonempty_after_construction() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        let defs = func.all_ssa_defs();
        assert!(!defs.is_empty());
    }

    #[test]
    fn all_ssa_uses_nonempty() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        let uses = func.all_ssa_uses();
        assert!(!uses.is_empty());
    }

    #[test]
    fn verify_valid_ssa_has_no_errors() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        let errors = func.verify();
        assert!(errors.is_empty(), "SSA verification failed: {errors:?}");
    }

    #[test]
    fn ssa_def_block_maps_all_defs() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        let map = func.ssa_def_block();
        // Should have at least one entry per non-empty block.
        assert!(!map.is_empty());
    }

    #[test]
    fn used_in_block_returns_uses() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        let uses = func.used_in_block(BBId(3));
        assert!(!uses.is_empty());
    }

    #[test]
    fn defined_in_block_returns_defs() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        let defs = func.defined_in_block(BBId(0));
        assert!(!defs.is_empty());
    }

    #[test]
    fn reachable_blocks_linear() {
        let n = 4;
        let succs: Vec<Vec<BBId>> = (0..n)
            .map(|i| if i + 1 < n { vec![BBId(i + 1)] } else { vec![] })
            .collect();
        let cfg = Cfg::new(n, succs, BBId(0), BBId(n - 1));
        let func = SsaFunction::new(cfg, &vec![vec![]; n]);
        let reachable = func.reachable_blocks();
        assert_eq!(reachable.len(), n);
    }

    #[test]
    fn strip_phis_clears_all() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        assert!(func.phi_count() >= 1);
        func.strip_phis();
        assert_eq!(func.phi_count(), 0);
    }

    #[test]
    fn max_ssa_version_grows_with_defs() {
        let n = 5;
        let succs: Vec<Vec<BBId>> = (0..n)
            .map(|i| if i + 1 < n { vec![BBId(i + 1)] } else { vec![] })
            .collect();
        let cfg = Cfg::new(n, succs, BBId(0), BBId(n - 1));
        let instrs: Vec<Vec<Instruction>> = (0..n)
            .map(|i| vec![Instruction::new(i, Some(Var::new("x")), vec![])])
            .collect();
        let mut func = SsaFunction::new(cfg, &instrs);
        construct_ssa(&mut func);
        // 5 definitions of x means max version should be >= 4.
        assert!(func.max_ssa_version() >= 4);
    }

    #[test]
    fn ssavar_same_base() {
        let a = SsaVar::new(Var::new("x"), 0);
        let b = SsaVar::new(Var::new("x"), 5);
        let c = SsaVar::new(Var::new("y"), 0);
        assert!(a.same_base(&b));
        assert!(!a.same_base(&c));
    }

    #[test]
    fn ssavar_is_initial() {
        let a = SsaVar::new(Var::new("x"), 0);
        let b = SsaVar::new(Var::new("x"), 1);
        assert!(a.is_initial());
        assert!(!b.is_initial());
    }

    #[test]
    fn phi_node_is_trivial() {
        let sv = SsaVar::new(Var::new("x"), 1);
        let mut phi = PhiNode::new(Var::new("x"), 3);
        phi.args = vec![Some(sv.clone()), Some(sv.clone()), Some(sv)];
        assert!(phi.is_trivial());
    }

    #[test]
    fn phi_node_not_trivial_when_different_args() {
        let sv1 = SsaVar::new(Var::new("x"), 1);
        let sv2 = SsaVar::new(Var::new("x"), 2);
        let mut phi = PhiNode::new(Var::new("x"), 2);
        phi.args = vec![Some(sv1), Some(sv2)];
        assert!(!phi.is_trivial());
    }

    #[test]
    fn phi_node_is_complete() {
        let sv = SsaVar::new(Var::new("x"), 1);
        let mut phi = PhiNode::new(Var::new("x"), 2);
        phi.args = vec![Some(sv.clone()), Some(sv)];
        assert!(phi.is_complete());
    }

    #[test]
    fn phi_node_incomplete_when_none_arg() {
        let sv = SsaVar::new(Var::new("x"), 1);
        let mut phi = PhiNode::new(Var::new("x"), 2);
        phi.args = vec![Some(sv), None];
        assert!(!phi.is_complete());
    }

    #[test]
    fn phi_node_defined_arg_count() {
        let sv = SsaVar::new(v("x"), 1);
        let mut phi = PhiNode::new(v("x"), 3);
        assert_eq!(phi.defined_arg_count(), 0);
        phi.args = vec![Some(sv.clone()), None, Some(sv)];
        assert_eq!(phi.defined_arg_count(), 2);
    }

    #[test]
    fn phi_vars_nonempty_after_ssa() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        let vars = func.phi_vars();
        assert!(!vars.is_empty());
    }

    #[test]
    fn instr_count_correct() {
        let func = diamond_func();
        assert_eq!(func.instr_count(), 4); // one instr per block
    }

    #[test]
    fn instruction_is_renamed_after_ssa() {
        let mut func = diamond_func();
        construct_ssa(&mut func);
        for block in &func.blocks {
            for instr in &block.instrs {
                assert!(instr.is_renamed(), "instruction not renamed: {instr:?}");
            }
        }
    }

    #[test]
    fn ssa_loop_cfg_construction() {
        // 0 → 1 → 2 → 1 (back edge), 2 → 3
        let succs = vec![vec![BBId(1)], vec![BBId(2)], vec![BBId(1), BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let instrs: Vec<Vec<Instruction>> = vec![
            vec![Instruction::new(0, Some(Var::new("i")), vec![])],
            vec![Instruction::new(
                1,
                Some(Var::new("i")),
                vec![Var::new("i")],
            )],
            vec![Instruction::new(
                2,
                Some(Var::new("i")),
                vec![Var::new("i")],
            )],
            vec![Instruction::new(3, None, vec![Var::new("i")])],
        ];
        let mut func = SsaFunction::new(cfg, &instrs);
        construct_ssa(&mut func);
        // Block 1 (loop header) should have a φ-node for i.
        assert!(func.blocks[1].phis.iter().any(|p| p.var == Var::new("i")));
        let errors = func.verify();
        assert!(errors.is_empty(), "loop SSA invalid: {errors:?}");
    }

    #[test]
    fn ssa_function_new_pads_missing_block_instrs() {
        // instrs_per_block shorter than the CFG's block count: missing
        // blocks must get empty instruction lists, not panic/truncate wrongly.
        let cfg = linear_cfg_helper(3);
        let instrs = vec![vec![Instruction::new(0, Some(v("x")), vec![])]]; // only block 0
        let func = SsaFunction::new(cfg, &instrs);
        assert_eq!(func.blocks.len(), 3);
        assert_eq!(func.blocks[0].instrs.len(), 1);
        assert!(func.blocks[1].instrs.is_empty());
        assert!(func.blocks[2].instrs.is_empty());
    }

    #[test]
    fn ssa_function_new_ignores_extra_block_instrs() {
        // instrs_per_block longer than the CFG's block count: extras must be
        // dropped, and the result must have exactly `n` blocks.
        let cfg = linear_cfg_helper(2);
        let instrs = vec![
            vec![Instruction::new(0, Some(v("x")), vec![])],
            vec![Instruction::new(1, Some(v("x")), vec![])],
            vec![Instruction::new(2, Some(v("x")), vec![])], // extra, out of range
        ];
        let func = SsaFunction::new(cfg, &instrs);
        assert_eq!(func.blocks.len(), 2);
    }

    fn linear_cfg_helper(n: usize) -> Cfg {
        let succs: Vec<Vec<BBId>> = (0..n)
            .map(|i| if i + 1 < n { vec![BBId(i + 1)] } else { vec![] })
            .collect();
        Cfg::new(n, succs, BBId(0), BBId(n - 1))
    }

    #[test]
    fn all_ssa_uses_operand_indices_are_correct() {
        let succs = vec![vec![BBId(1)], vec![]];
        let cfg = Cfg::new(2, succs, BBId(0), BBId(1));
        let instrs = vec![
            vec![
                Instruction::new(0, Some(v("x")), vec![]),
                Instruction::new(1, Some(v("y")), vec![]),
            ],
            vec![Instruction::new(2, None, vec![v("x"), v("y")])],
        ];
        let mut func = SsaFunction::new(cfg, &instrs);
        construct_ssa(&mut func);
        let uses = func.all_ssa_uses();
        // The two-use instruction in block 1 must contribute operand indices 0 and 1.
        let block1_uses: Vec<(usize, &SsaVar)> = uses
            .iter()
            .filter(|(bb, ii, _, _)| *bb == BBId(1) && *ii == 0)
            .map(|(_, _, oi, sv)| (*oi, sv))
            .collect();
        assert_eq!(block1_uses.len(), 2);
        assert!(block1_uses.iter().any(|(oi, _)| *oi == 0));
        assert!(block1_uses.iter().any(|(oi, _)| *oi == 1));
    }

    #[test]
    fn def_sites_empty_for_function_with_no_defs() {
        let cfg = linear_cfg_helper(2);
        let func = SsaFunction::new(cfg, &[vec![], vec![]]);
        assert!(func.def_sites().is_empty());
        assert!(func.all_vars().is_empty());
    }

    #[test]
    fn phi_node_is_trivial_false_for_empty_args() {
        let phi = PhiNode::new(v("x"), 0);
        assert!(!phi.is_trivial());
    }

    #[test]
    fn phi_node_is_trivial_false_when_any_arg_missing() {
        let sv = SsaVar::new(v("x"), 1);
        let mut phi = PhiNode::new(v("x"), 2);
        phi.args = vec![Some(sv), None];
        // First arg present but not all args equal Some(first) since one is None.
        assert!(!phi.is_trivial());
    }

    #[test]
    fn rename_variables_noop_on_empty_function() {
        let cfg = Cfg::new(0, vec![], BBId(0), BBId(0));
        let mut func = SsaFunction::new(cfg, &[]);
        let dom_tree = crate::cfg_dom::lengauer_tarjan(&func.cfg, BBId(0));
        // Must not panic on an empty function/CFG.
        rename_variables(&mut func, &dom_tree);
        assert!(func.blocks.is_empty());
    }

    #[test]
    fn ssa_multiple_variables() {
        let succs = vec![vec![BBId(1), BBId(2)], vec![BBId(3)], vec![BBId(3)], vec![]];
        let cfg = Cfg::new(4, succs, BBId(0), BBId(3));
        let instrs: Vec<Vec<Instruction>> = vec![
            vec![
                Instruction::new(0, Some(Var::new("x")), vec![]),
                Instruction::new(1, Some(Var::new("y")), vec![]),
            ],
            vec![Instruction::new(
                2,
                Some(Var::new("x")),
                vec![Var::new("x"), Var::new("y")],
            )],
            vec![Instruction::new(
                3,
                Some(Var::new("x")),
                vec![Var::new("x")],
            )],
            vec![Instruction::new(4, None, vec![Var::new("x")])],
        ];
        let mut func = SsaFunction::new(cfg, &instrs);
        construct_ssa(&mut func);
        let errors = func.verify();
        assert!(errors.is_empty(), "multi-var SSA invalid: {errors:?}");
        // Block 3 should have φ for x (defined in both 1 and 2).
        assert!(func.blocks[3].phis.iter().any(|p| p.var == Var::new("x")));
    }
}
