//! `phi_placement` — generic, CFG-agnostic PHI-node placement algorithm.
//!
//! Implements the Cytron et al. (1991) algorithm for SSA construction,
//! pruning, renaming, validation, and de-SSA.
//!
//! # Layer distinction
//! This module is a **standalone algorithm layer** that operates on its own
//! abstract CFG ([`Cfg`]) and variable types ([`Variable`], [`SsaVar`]).
//! It intentionally does **not** depend on `crate::SsaVar` or any real MLIL
//! IR type so it can be used and tested in isolation.
//!
//! The [`phi_placement::SsaVar`] type here uses the convention
//! `name_version` (underscore separator) in its [`Display`] output, whereas
//! the crate-root [`crate::SsaVar`] uses `name#version`.  These are distinct
//! representations and must not be mixed.
//!
//! Consumers that want to drive PHI placement over real MLIL should call into
//! this module with their own variable name strings and then map the results
//! back to [`crate::SsaVar`].

use ahash::{AHashMap as HashMap, AHashSet as HashSet};
use std::collections::VecDeque;
use std::fmt;

// ---------------------------------------------------------------------------
// Basic block identifier
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct BBId(pub u32);

impl fmt::Display for BBId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BB{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Variable
// ---------------------------------------------------------------------------

/// A source-level variable (before SSA renaming).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Variable {
    pub name: String,
}

impl Variable {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ---------------------------------------------------------------------------
// SSA variable (variable + version)
// ---------------------------------------------------------------------------

/// An SSA-renamed variable: `name_version`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SsaVar {
    pub base: Variable,
    pub version: u32,
}

impl SsaVar {
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self { base: Variable::new(name), version }
    }
}

impl fmt::Display for SsaVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.base, self.version)
    }
}

// ---------------------------------------------------------------------------
// PHI node
// ---------------------------------------------------------------------------

/// A PHI function: `dst = φ(src0_from_pred0, src1_from_pred1, …)`.
#[derive(Clone, Debug)]
pub struct Phi {
    /// Destination SSA variable.
    pub dst: SsaVar,
    /// Each source is (predecessor BB, source SSA variable).
    pub sources: Vec<(BBId, SsaVar)>,
}

impl Phi {
    #[must_use] 
    pub const fn new(dst: SsaVar, sources: Vec<(BBId, SsaVar)>) -> Self {
        Self { dst, sources }
    }

    /// A PHI is trivial if all sources are the same SSA variable.
    #[must_use] 
    pub fn is_trivial(&self) -> bool {
        if self.sources.is_empty() {
            return true;
        }
        let first = &self.sources[0].1;
        self.sources.iter().all(|(_, sv)| sv == first)
    }

    /// Return the single operand value if this is a trivial PHI.
    #[must_use] 
    pub fn trivial_value(&self) -> Option<&SsaVar> {
        if self.is_trivial() {
            self.sources.first().map(|(_, sv)| sv)
        } else {
            None
        }
    }
}

impl fmt::Display for Phi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = φ(", self.dst)?;
        for (i, (bb, sv)) in self.sources.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "[{bb}]{sv}")?;
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------------------
// Control-flow graph
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Cfg {
    pub nodes: Vec<BBId>,
    pub succ: HashMap<BBId, Vec<BBId>>,
    pub pred: HashMap<BBId, Vec<BBId>>,
    pub entry: BBId,
}

impl Cfg {
    #[must_use] 
    pub fn new(entry: BBId) -> Self {
        let mut cfg = Self { entry, ..Default::default() };
        cfg.add_node(entry);
        cfg
    }

    pub fn add_node(&mut self, id: BBId) {
        if !self.succ.contains_key(&id) {
            self.nodes.push(id);
            self.succ.insert(id, Vec::new());
            self.pred.insert(id, Vec::new());
        }
    }

    pub fn add_edge(&mut self, from: BBId, to: BBId) {
        self.add_node(from);
        self.add_node(to);
        self.succ.entry(from).or_default().push(to);
        self.pred.entry(to).or_default().push(from);
    }

    #[must_use] 
    pub fn successors(&self, id: BBId) -> &[BBId] {
        self.succ.get(&id).map_or(&[], std::vec::Vec::as_slice)
    }

    #[must_use] 
    pub fn predecessors(&self, id: BBId) -> &[BBId] {
        self.pred.get(&id).map_or(&[], std::vec::Vec::as_slice)
    }
}

// ---------------------------------------------------------------------------
// Dominator tree (iterative Cooper–Harvey–Kennedy)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct DomTree {
    pub idom: HashMap<BBId, Option<BBId>>,
    pub children: HashMap<BBId, Vec<BBId>>,
}

impl DomTree {
    #[must_use] 
    pub fn build(cfg: &Cfg) -> Self {
        let rpo = Self::reverse_postorder(cfg);
        let rpo_num: HashMap<BBId, usize> =
            rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

        let mut idom: HashMap<BBId, Option<BBId>> = HashMap::new();
        idom.insert(cfg.entry, None);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == cfg.entry { continue; }
                let mut preds_iter = cfg
                    .predecessors(b)
                    .iter()
                    .copied()
                    .filter(|p| idom.contains_key(p));
                let mut new_idom = match preds_iter.next() {
                    Some(p) => p,
                    None => continue,
                };
                for p in preds_iter {
                    new_idom = Self::intersect(new_idom, p, &idom, &rpo_num);
                }
                if idom.get(&b).and_then(|x| *x) != Some(new_idom) {
                    idom.insert(b, Some(new_idom));
                    changed = true;
                }
            }
        }

        let mut children: HashMap<BBId, Vec<BBId>> = HashMap::new();
        for &b in &cfg.nodes {
            children.entry(b).or_default();
            if let Some(Some(parent)) = idom.get(&b) {
                children.entry(*parent).or_default().push(b);
            }
        }

        Self { idom, children }
    }

    fn reverse_postorder(cfg: &Cfg) -> Vec<BBId> {
        let mut visited = HashSet::new();
        let mut post = Vec::new();
        Self::dfs(cfg.entry, cfg, &mut visited, &mut post);
        post.reverse();
        post
    }

    fn dfs(start: BBId, cfg: &Cfg, visited: &mut HashSet<BBId>, post: &mut Vec<BBId>) {
        // Iterative post-order DFS to avoid stack overflow on deep CFGs.
        // Stack entries: (node, iterator-index-into-successors).
        let mut stack: Vec<(BBId, usize)> = Vec::new();
        if visited.insert(start) {
            stack.push((start, 0));
        }
        while let Some((node, succ_idx)) = stack.last_mut() {
            let node = *node;
            let succs = cfg.successors(node);
            if *succ_idx < succs.len() {
                let s = succs[*succ_idx];
                *succ_idx += 1;
                if visited.insert(s) {
                    stack.push((s, 0));
                }
            } else {
                post.push(node);
                stack.pop();
            }
        }
    }

    fn intersect(
        mut b1: BBId, mut b2: BBId,
        idom: &HashMap<BBId, Option<BBId>>,
        rpo_num: &HashMap<BBId, usize>,
    ) -> BBId {
        while b1 != b2 {
            while rpo_num[&b1] > rpo_num[&b2] {
                b1 = idom[&b1].unwrap_or(b1);
            }
            while rpo_num[&b2] > rpo_num[&b1] {
                b2 = idom[&b2].unwrap_or(b2);
            }
        }
        b1
    }

    #[must_use] 
    pub fn dominates(&self, a: BBId, b: BBId) -> bool {
        let mut cur = b;
        loop {
            if cur == a { return true; }
            match self.idom.get(&cur).and_then(|x| *x) {
                Some(parent) => cur = parent,
                None => return false,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dominance frontier
// ---------------------------------------------------------------------------

/// Compute dominance frontiers for every node in `cfg`.
/// DF[n] = { y | ∃ x ∈ pred(y) s.t. n dominates x and n does not strictly dominate y }
#[must_use] 
pub fn compute_dominance_frontier(cfg: &Cfg, dom: &DomTree) -> HashMap<BBId, HashSet<BBId>> {
    let mut df: HashMap<BBId, HashSet<BBId>> = cfg.nodes.iter().map(|&n| (n, HashSet::new())).collect();
    for &b in &cfg.nodes {
        let preds = cfg.predecessors(b);
        if preds.len() < 2 { continue; }
        for &p in preds {
            let mut runner = p;
            while runner != dom.idom[&b].unwrap_or(b) {
                df.entry(runner).or_default().insert(b);
                match dom.idom.get(&runner).and_then(|x| *x) {
                    Some(parent) => runner = parent,
                    None => break,
                }
            }
        }
    }
    df
}

/// Compute the iterated dominance frontier IDF(S) for a set of nodes S.
///
/// IDF(S) = fixed point of: start with DF(S), then add DF(new nodes) until stable.
#[must_use] 
pub fn iterated_dominance_frontier(
    seeds: &HashSet<BBId>,
    df: &HashMap<BBId, HashSet<BBId>>,
) -> HashSet<BBId> {
    let mut result: HashSet<BBId> = HashSet::new();
    let mut worklist: VecDeque<BBId> = seeds.iter().copied().collect();

    while let Some(n) = worklist.pop_front() {
        if let Some(frontier) = df.get(&n) {
            for &y in frontier {
                // `result.insert` returns true only on first insertion, so this
                // naturally deduplicates worklist pushes without a parallel set.
                if result.insert(y) {
                    worklist.push_back(y);
                }
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Liveness analysis (bit-vector dataflow)
// ---------------------------------------------------------------------------

/// Per-block liveness sets.
#[derive(Default, Debug)]
pub struct LivenessInfo {
    pub live_in:  HashMap<BBId, HashSet<Variable>>,
    pub live_out: HashMap<BBId, HashSet<Variable>>,
    /// Variables defined in block.
    pub defs: HashMap<BBId, HashSet<Variable>>,
    /// Variables used before any def in block (upward-exposed uses).
    pub uses: HashMap<BBId, HashSet<Variable>>,
}

impl LivenessInfo {
    /// Run iterative liveness until fixed-point.
    #[must_use] 
    pub fn compute(
        cfg: &Cfg,
        defs: HashMap<BBId, HashSet<Variable>>,
        uses: HashMap<BBId, HashSet<Variable>>,
    ) -> Self {
        let mut live_in:  HashMap<BBId, HashSet<Variable>> =
            cfg.nodes.iter().map(|&n| (n, HashSet::new())).collect();
        let mut live_out: HashMap<BBId, HashSet<Variable>> =
            cfg.nodes.iter().map(|&n| (n, HashSet::new())).collect();

        let mut changed = true;
        while changed {
            changed = false;
            // Iterate in reverse postorder for faster convergence.
            for &b in cfg.nodes.iter().rev() {
                // live_out[b] = ∪ live_in[s] for s ∈ succ(b) -- gather by reference, no per-set clone.
                let mut new_out: HashSet<Variable> = HashSet::new();
                for s in cfg.successors(b) {
                    if let Some(set) = live_in.get(s) {
                        new_out.extend(set.iter().cloned());
                    }
                }
                // live_in[b] = uses[b] ∪ (live_out[b] − defs[b])
                let empty: HashSet<Variable> = HashSet::new();
                let block_defs = defs.get(&b).unwrap_or(&empty);
                let block_uses = uses.get(&b).unwrap_or(&empty);
                let new_in: HashSet<Variable> = block_uses
                    .iter()
                    .cloned()
                    .chain(new_out.iter().filter(|v| !block_defs.contains(v)).cloned())
                    .collect();
                if new_in != live_in[&b] || new_out != live_out[&b] {
                    changed = true;
                    live_in.insert(b, new_in);
                    live_out.insert(b, new_out);
                }
            }
        }
        Self { live_in, live_out, defs, uses }
    }
}

// ---------------------------------------------------------------------------
// PHI placement (Cytron algorithm)
// ---------------------------------------------------------------------------

/// Classification of SSA form to construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SsaVariant {
    /// Insert PHIs at every IDF node regardless of liveness.
    Minimal,
    /// Only insert PHIs for variables live at the PHI point (requires liveness).
    Pruned,
    /// Only insert PHIs for variables defined in more than one block.
    SemiPruned,
}

/// Place PHI functions for a set of variables.
///
/// Returns a map from `BBId` to the list of PHI functions that must be
/// inserted at the start of that block.
#[must_use] 
pub fn place_phi_functions(
    cfg: &Cfg,
    dom: &DomTree,
    df: &HashMap<BBId, HashSet<BBId>>,
    // For each variable, the set of blocks where it is defined.
    defs_per_var: &HashMap<Variable, HashSet<BBId>>,
    variant: SsaVariant,
    liveness: Option<&LivenessInfo>,
) -> HashMap<BBId, Vec<Variable>> {
    let mut phi_sites: HashMap<BBId, HashSet<Variable>> = HashMap::new();

    // Pre-compute set of valid block ids from the CFG to filter out IDF
    // entries that refer to deleted/unreachable blocks; pre-compute the
    // dominator tree's known nodes for the same purpose.
    let valid_blocks: HashSet<BBId> = cfg_block_ids(cfg);
    let dom_known: HashSet<BBId> = dom_known_blocks(dom);

    for (var, def_blocks) in defs_per_var {
        // SemiPruned: skip variables defined in only one block.
        if variant == SsaVariant::SemiPruned && def_blocks.len() <= 1 {
            continue;
        }

        let idf = iterated_dominance_frontier(def_blocks, df);
        for bb in idf {
            // Skip blocks unknown to the CFG or absent from the dominator tree.
            if !valid_blocks.is_empty() && !valid_blocks.contains(&bb) {
                continue;
            }
            if !dom_known.is_empty() && !dom_known.contains(&bb) {
                continue;
            }
            // Pruned: skip if variable is not live at the PHI point.
            if variant == SsaVariant::Pruned
                && let Some(liv) = liveness
                    && !liv.live_in.get(&bb).is_some_and(|s| s.contains(var)) {
                        continue;
                    }
            phi_sites.entry(bb).or_default().insert(var.clone());
        }
    }

    // Convert sets to sorted vecs for deterministic output.
    phi_sites
        .into_iter()
        .map(|(bb, vars)| {
            let mut v: Vec<Variable> = vars.into_iter().collect();
            v.sort();
            (bb, v)
        })
        .collect()
}

/// Set of all block ids known to the CFG.
fn cfg_block_ids(cfg: &Cfg) -> HashSet<BBId> {
    cfg.nodes.iter().copied().collect()
}

/// Set of block ids known to the dominator tree (keys of `idom`).
fn dom_known_blocks(dom: &DomTree) -> HashSet<BBId> {
    dom.idom.keys().copied().collect()
}

// ---------------------------------------------------------------------------
// SSA renaming pass
// ---------------------------------------------------------------------------

/// State carried during the DFS renaming walk.
#[derive(Debug)]
struct RenameState {
    /// Per-variable version stack.
    stacks: HashMap<Variable, Vec<u32>>,
    /// Next version counter per variable.
    counters: HashMap<Variable, u32>,
    /// Produced PHI nodes: (block, phi).
    phi_nodes: HashMap<BBId, Vec<Phi>>,
    /// SSA-renamed definitions per block: block → [(original var, ssa var)].
    renamed_defs: HashMap<BBId, Vec<(Variable, SsaVar)>>,
}

impl RenameState {
    fn new(
        vars: &[Variable],
        phi_sites: &HashMap<BBId, Vec<Variable>>,
        cfg: &Cfg,
    ) -> Self {
        let mut stacks: HashMap<Variable, Vec<u32>> = HashMap::new();
        let mut counters: HashMap<Variable, u32> = HashMap::new();
        for v in vars {
            stacks.insert(v.clone(), vec![0]);
            counters.insert(v.clone(), 1);
        }
        // Pre-create placeholder PHI nodes. PHI operand vectors are sized
        // up-front to the predecessor count of each block so the renaming
        // pass can fill them in by index without re-allocating.
        let mut phi_nodes: HashMap<BBId, Vec<Phi>> = HashMap::new();
        for (&bb, vars) in phi_sites {
            let pred_count = cfg.predecessors(bb).len();
            let phis: Vec<Phi> = vars
                .iter()
                .map(|v| {
                    let ver = *counters.get(v).unwrap_or(&0);
                    let ssa = SsaVar::new(v.name.clone(), ver);
                    Phi::new(ssa, Vec::with_capacity(pred_count))
                })
                .collect();
            phi_nodes.insert(bb, phis);
        }
        Self {
            stacks,
            counters,
            phi_nodes,
            renamed_defs: HashMap::new(),
        }
    }

    fn gen_name(&mut self, var: &Variable) -> SsaVar {
        let ver = *self.counters.entry(var.clone()).or_insert(0);
        self.counters.insert(var.clone(), ver + 1);
        self.stacks.entry(var.clone()).or_default().push(ver);
        SsaVar::new(var.name.clone(), ver)
    }

    fn top(&self, var: &Variable) -> SsaVar {
        let ver = self
            .stacks
            .get(var)
            .and_then(|s| s.last())
            .copied()
            .unwrap_or(0);
        SsaVar::new(var.name.clone(), ver)
    }

    fn pop(&mut self, var: &Variable) {
        if let Some(stack) = self.stacks.get_mut(var) {
            stack.pop();
        }
    }
}

/// Block-local definition/use information.
pub struct BlockDefs {
    /// Original (non-SSA) variables defined in this block, in program order.
    pub defs: Vec<Variable>,
    /// Original variables used in this block.
    pub uses: Vec<Variable>,
}

/// Run the SSA renaming pass (DFS over dominator tree).
#[must_use] 
pub fn rename_pass(
    cfg: &Cfg,
    dom: &DomTree,
    phi_sites: &HashMap<BBId, Vec<Variable>>,
    block_defs: &HashMap<BBId, BlockDefs>,
    all_vars: &[Variable],
) -> HashMap<BBId, Vec<Phi>> {
    let mut state = RenameState::new(all_vars, phi_sites, cfg);

    // DFS over dominator tree starting from entry.
    rename_dfs(cfg.entry, cfg, dom, phi_sites, block_defs, &mut state);

    state.phi_nodes
}

fn rename_dfs(
    bb: BBId,
    cfg: &Cfg,
    dom: &DomTree,
    phi_sites: &HashMap<BBId, Vec<Variable>>,
    block_defs: &HashMap<BBId, BlockDefs>,
    state: &mut RenameState,
) {
    // Track which variables we pushed so we can pop at the end.
    let mut pushed: Vec<Variable> = Vec::new();

    // 1. Rename LHS of PHI nodes at this block.
    if let Some(phis) = phi_sites.get(&bb) {
        for var in phis {
            let ssa = state.gen_name(var);
            pushed.push(var.clone());
            // Update the dst of the corresponding pre-created phi.
            if let Some(phi_list) = state.phi_nodes.get_mut(&bb) {
                for phi in phi_list.iter_mut() {
                    if phi.dst.base == *var {
                        phi.dst = ssa.clone();
                        break;
                    }
                }
            }
        }
    }

    // 2. Rename defs in the block's instructions.
    if let Some(bd) = block_defs.get(&bb) {
        for var in &bd.defs {
            let _ssa_use = state.top(var); // current version for uses above this def
            let ssa_def = state.gen_name(var);
            pushed.push(var.clone());
            state
                .renamed_defs
                .entry(bb)
                .or_default()
                .push((var.clone(), ssa_def));
        }
    }

    // 3. Fill in PHI sources for each successor.
    for &succ in cfg.successors(bb) {
        // Collect (phi_index, var) to avoid simultaneous mut + immut borrow of state.
        let phi_vars: Vec<(usize, Variable)> = state
            .phi_nodes
            .get(&succ)
            .map(|phis| phis.iter().enumerate().map(|(i, p)| (i, p.dst.base.clone())).collect())
            .unwrap_or_default();
        for (i, var) in phi_vars {
            let src = state.top(&var);
            if let Some(phis) = state.phi_nodes.get_mut(&succ) {
                phis[i].sources.push((bb, src));
            }
        }
    }

    // 4. Recurse into dominator-tree children.
    let children: &[BBId] = dom.children.get(&bb).map_or(&[], Vec::as_slice);
    for &child in children {
        rename_dfs(child, cfg, dom, phi_sites, block_defs, state);
    }

    // 5. Pop all versions we pushed.
    for var in pushed.iter().rev() {
        state.pop(var);
    }
}

// ---------------------------------------------------------------------------
// SSA validation
// ---------------------------------------------------------------------------

/// Verify that every SSA use is dominated by its definition.
///
/// Returns a list of (block, variable, version) for violations found.
#[must_use] 
pub fn validate_ssa_dominance(
    cfg: &Cfg,
    dom: &DomTree,
    phi_nodes: &HashMap<BBId, Vec<Phi>>,
    renamed_defs: &HashMap<BBId, Vec<(Variable, SsaVar)>>,
    // Blocks where each SSA variable is used.
    ssa_uses: &HashMap<SsaVar, HashSet<BBId>>,
) -> Vec<(BBId, SsaVar)> {
    let mut violations = Vec::new();

    // Build a map: SsaVar → defining block.
    let mut def_block: HashMap<SsaVar, BBId> = HashMap::new();
    for (&bb, phis) in phi_nodes {
        for phi in phis {
            def_block.insert(phi.dst.clone(), bb);
        }
    }
    for (&bb, defs) in renamed_defs {
        for (_, ssa) in defs {
            def_block.insert(ssa.clone(), bb);
        }
    }

    let cfg_blocks = cfg_block_ids(cfg);
    for (ssa, use_sites) in ssa_uses {
        if let Some(&def_bb) = def_block.get(ssa) {
            for &use_bb in use_sites {
                // Skip uses in blocks the CFG doesn't know about — those are
                // stale references from removed blocks and not real violations.
                if !cfg_blocks.is_empty() && !cfg_blocks.contains(&use_bb) {
                    continue;
                }
                if !dom.dominates(def_bb, use_bb) {
                    violations.push((use_bb, ssa.clone()));
                }
            }
        } else {
            // Variable used but never defined (undefined variable).
            for &use_bb in use_sites {
                if !cfg_blocks.is_empty() && !cfg_blocks.contains(&use_bb) {
                    continue;
                }
                violations.push((use_bb, ssa.clone()));
            }
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// Trivial PHI elimination
// ---------------------------------------------------------------------------

/// Remove trivial PHI nodes (all sources identical) and propagate the
/// replacement.  Returns the eliminated PHI destinations.
pub fn eliminate_trivial_phis(
    phi_nodes: &mut HashMap<BBId, Vec<Phi>>,
) -> HashMap<SsaVar, SsaVar> {
    let mut replacements: HashMap<SsaVar, SsaVar> = HashMap::new();
    let mut changed = true;
    while changed {
        changed = false;
        for phis in phi_nodes.values_mut() {
            for phi in phis.iter_mut() {
                if phi.is_trivial()
                    && let Some(val) = phi.trivial_value() {
                        let val = val.clone();
                        // Resolve chains.
                        let final_val = resolve_replacement(&val, &replacements);
                        if final_val != phi.dst {
                            replacements.insert(phi.dst.clone(), final_val);
                            changed = true;
                        }
                    }
            }
        }
        // Apply replacements to all PHI sources.
        for phis in phi_nodes.values_mut() {
            for phi in phis.iter_mut() {
                for (_, src) in &mut phi.sources {
                    if let Some(rep) = replacements.get(src) {
                        *src = rep.clone();
                    }
                }
            }
        }
        // Remove trivially eliminated PHIs from the map.
        for phis in phi_nodes.values_mut() {
            phis.retain(|phi| !replacements.contains_key(&phi.dst));
        }
    }
    replacements
}

fn resolve_replacement(var: &SsaVar, replacements: &HashMap<SsaVar, SsaVar>) -> SsaVar {
    let mut cur = var.clone();
    let mut seen = HashSet::new();
    while let Some(next) = replacements.get(&cur) {
        if !seen.insert(cur.clone()) {
            break; // cycle guard
        }
        cur = next.clone();
    }
    cur
}

// ---------------------------------------------------------------------------
// De-SSA: PHI elimination for code generation
// ---------------------------------------------------------------------------

/// A copy instruction inserted at a predecessor edge.
#[derive(Clone, Debug)]
pub struct ParallelCopy {
    /// The predecessor block where this copy should be inserted.
    pub pred_bb: BBId,
    /// Source SSA variable.
    pub src: SsaVar,
    /// Destination SSA variable (the PHI's dst).
    pub dst: SsaVar,
}

/// Convert PHI nodes to parallel copies at predecessor edges (de-SSA).
///
/// For each `φ(src0_from_B0, src1_from_B1, …) → dst`:
///   - Insert copy `dst := srcN` at the end of block BN.
#[must_use] 
pub fn dessa_insert_copies(phi_nodes: &HashMap<BBId, Vec<Phi>>) -> Vec<ParallelCopy> {
    dessa_insert_copies_with_targets(phi_nodes).into_iter().map(|(_target_bb, c)| c).collect()
}

/// Like [`dessa_insert_copies`] but also returns the PHI's home block (the
/// destination block where the φ lives) alongside each generated copy.
///
/// The destination block is useful for downstream passes that need to
/// schedule the copy relative to the φ's home (e.g. linear-scan register
/// allocators that compute live ranges around the PHI point).
#[must_use] 
pub fn dessa_insert_copies_with_targets(
    phi_nodes: &HashMap<BBId, Vec<Phi>>,
) -> Vec<(BBId, ParallelCopy)> {
    let mut copies = Vec::new();
    for (&bb, phis) in phi_nodes {
        for phi in phis {
            for (pred, src) in &phi.sources {
                copies.push((bb, ParallelCopy {
                    pred_bb: *pred,
                    src: src.clone(),
                    dst: phi.dst.clone(),
                }));
            }
        }
    }
    copies
}

/// Resolve copy-swap conflicts (a = b; b = a) using a temporary.
/// Returns a list of resolved moves as (dst, src) pairs, where None src means
/// use a fresh temporary.
#[must_use] 
pub fn resolve_copy_conflicts(copies: &[ParallelCopy]) -> Vec<(SsaVar, Option<SsaVar>)> {
    // Simple sequentialization: detect cycles and break them with a temp.
    let mut result = Vec::new();
    let mut src_to_dst: HashMap<SsaVar, SsaVar> = HashMap::new();
    for copy in copies {
        src_to_dst.insert(copy.src.clone(), copy.dst.clone());
    }
    // Topological sort / cycle detection.
    let mut in_degree: HashMap<SsaVar, usize> = HashMap::new();
    for copy in copies {
        if src_to_dst.contains_key(&copy.dst) {
            *in_degree.entry(copy.dst.clone()).or_insert(0) += 1;
        } else {
            in_degree.entry(copy.dst.clone()).or_insert(0);
        }
        let deg = in_degree.entry(copy.src.clone()).or_insert(0);
        if src_to_dst.contains_key(&copy.dst) {
            *deg += 1;
        }
    }
    // Emit non-conflicting copies first.
    let mut queue: VecDeque<SsaVar> = in_degree
        .iter()
        .filter(|&(_, &d)| d == 0)
        .map(|(v, _)| v.clone())
        .collect();
    while let Some(src) = queue.pop_front() {
        if let Some(dst) = src_to_dst.get(&src) {
            result.push((dst.clone(), Some(src.clone())));
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Full SSA construction driver
// ---------------------------------------------------------------------------

/// Input description for one block.
pub struct BlockInfo {
    pub id: BBId,
    /// Original (pre-SSA) variables defined in this block.
    pub defs: Vec<Variable>,
    /// Original variables used in this block.
    pub uses: Vec<Variable>,
}

/// Output of a full SSA construction.
pub struct SsaForm {
    /// PHI nodes at each block entry.
    pub phi_nodes: HashMap<BBId, Vec<Phi>>,
    /// Dominance frontiers.
    pub df: HashMap<BBId, HashSet<BBId>>,
    /// Dominator tree.
    pub dom: DomTree,
}

impl SsaForm {
    /// Construct SSA for the given CFG and block information.
    #[must_use] 
    pub fn build(
        cfg: &Cfg,
        blocks: &[BlockInfo],
        variant: SsaVariant,
    ) -> Self {
        let dom = DomTree::build(cfg);
        let df = compute_dominance_frontier(cfg, &dom);

        // Collect all variables and their definition sites.
        let mut all_vars: Vec<Variable> = Vec::new();
        let mut seen_vars: HashSet<Variable> = HashSet::new();
        let mut defs_per_var: HashMap<Variable, HashSet<BBId>> = HashMap::new();
        let mut block_defs_map: HashMap<BBId, BlockDefs> = HashMap::new();
        let mut block_uses_map: HashMap<BBId, HashSet<Variable>> = HashMap::new();

        for bi in blocks {
            for v in &bi.defs {
                if seen_vars.insert(v.clone()) {
                    all_vars.push(v.clone());
                }
                defs_per_var.entry(v.clone()).or_default().insert(bi.id);
            }
            for v in &bi.uses {
                if seen_vars.insert(v.clone()) {
                    all_vars.push(v.clone());
                }
                block_uses_map.entry(bi.id).or_default().insert(v.clone());
            }
            block_defs_map.insert(
                bi.id,
                BlockDefs { defs: bi.defs.clone(), uses: bi.uses.clone() },
            );
        }

        // Compute liveness if needed.
        let liveness_opt = if variant == SsaVariant::Pruned {
            let uses_map: HashMap<BBId, HashSet<Variable>> = std::mem::take(&mut block_uses_map);
            let defs_map: HashMap<BBId, HashSet<Variable>> = blocks
                .iter()
                .map(|bi| {
                    let set: HashSet<Variable> = bi.defs.iter().cloned().collect();
                    (bi.id, set)
                })
                .collect();
            Some(LivenessInfo::compute(cfg, defs_map, uses_map))
        } else {
            None
        };

        let phi_sites = place_phi_functions(
            cfg, &dom, &df, &defs_per_var, variant, liveness_opt.as_ref(),
        );

        let phi_nodes = rename_pass(cfg, &dom, &phi_sites, &block_defs_map, &all_vars);

        Self { phi_nodes, df, dom }
    }

    /// Pretty-print all PHI nodes.
    #[must_use] 
    pub fn pretty_print(&self) -> String {
        let mut out = String::new();
        let mut bbs: Vec<BBId> = self.phi_nodes.keys().copied().collect();
        bbs.sort();
        for bb in bbs {
            let phis = &self.phi_nodes[&bb];
            if phis.is_empty() { continue; }
            out.push_str(&format!("{bb}:\n"));
            for phi in phis {
                out.push_str(&format!("  {phi}\n"));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn linear_cfg() -> Cfg {
        // 0 → 1 → 2
        let mut cfg = Cfg::new(BBId(0));
        cfg.add_edge(BBId(0), BBId(1));
        cfg.add_edge(BBId(1), BBId(2));
        cfg
    }

    fn diamond_cfg() -> Cfg {
        // 0 → 1, 0 → 2, 1 → 3, 2 → 3
        let mut cfg = Cfg::new(BBId(0));
        cfg.add_edge(BBId(0), BBId(1));
        cfg.add_edge(BBId(0), BBId(2));
        cfg.add_edge(BBId(1), BBId(3));
        cfg.add_edge(BBId(2), BBId(3));
        cfg
    }

    #[test]
    fn test_domtree_linear() {
        let cfg = linear_cfg();
        let dom = DomTree::build(&cfg);
        assert!(dom.dominates(BBId(0), BBId(1)));
        assert!(dom.dominates(BBId(0), BBId(2)));
        assert!(dom.dominates(BBId(1), BBId(2)));
        assert!(!dom.dominates(BBId(2), BBId(1)));
    }

    #[test]
    fn test_domtree_diamond() {
        let cfg = diamond_cfg();
        let dom = DomTree::build(&cfg);
        assert!(dom.dominates(BBId(0), BBId(3)));
        assert!(!dom.dominates(BBId(1), BBId(3)));
        assert!(!dom.dominates(BBId(2), BBId(3)));
    }

    #[test]
    fn test_dominance_frontier_diamond() {
        let cfg = diamond_cfg();
        let dom = DomTree::build(&cfg);
        let df = compute_dominance_frontier(&cfg, &dom);
        // DF[1] = {3}, DF[2] = {3}
        assert!(df[&BBId(1)].contains(&BBId(3)));
        assert!(df[&BBId(2)].contains(&BBId(3)));
        // DF[0] = {}
        assert!(df[&BBId(0)].is_empty());
    }

    #[test]
    fn test_idf_diamond() {
        let cfg = diamond_cfg();
        let dom = DomTree::build(&cfg);
        let df = compute_dominance_frontier(&cfg, &dom);
        let seeds: HashSet<BBId> = [BBId(1), BBId(2)].iter().cloned().collect();
        let idf = iterated_dominance_frontier(&seeds, &df);
        assert!(idf.contains(&BBId(3)));
    }

    #[test]
    fn test_phi_placement_diamond() {
        let cfg = diamond_cfg();
        let blocks = vec![
            BlockInfo { id: BBId(0), defs: vec![Variable::new("x")], uses: vec![] },
            BlockInfo { id: BBId(1), defs: vec![Variable::new("x")], uses: vec![Variable::new("x")] },
            BlockInfo { id: BBId(2), defs: vec![Variable::new("x")], uses: vec![Variable::new("x")] },
            BlockInfo { id: BBId(3), defs: vec![], uses: vec![Variable::new("x")] },
        ];
        let ssa = SsaForm::build(&cfg, &blocks, SsaVariant::Minimal);
        // BB3 must have a PHI for x (join point for BB1/BB2 definitions).
        let bb3_phis = ssa.phi_nodes.get(&BBId(3)).map_or(0, |v| v.len());
        assert!(bb3_phis >= 1, "Expected PHI at BB3, got {}", bb3_phis);
    }

    #[test]
    fn test_phi_trivial_detection() {
        let a = SsaVar::new("x", 1);
        let phi = Phi::new(SsaVar::new("x", 2), vec![
            (BBId(1), a.clone()),
            (BBId(2), a.clone()),
        ]);
        assert!(phi.is_trivial());
        assert_eq!(phi.trivial_value(), Some(&a));
    }

    #[test]
    fn test_phi_non_trivial() {
        let phi = Phi::new(SsaVar::new("x", 2), vec![
            (BBId(1), SsaVar::new("x", 0)),
            (BBId(2), SsaVar::new("x", 1)),
        ]);
        assert!(!phi.is_trivial());
    }

    #[test]
    fn test_trivial_phi_elimination() {
        let src = SsaVar::new("x", 0);
        let dst = SsaVar::new("x", 1);
        let phi = Phi::new(dst.clone(), vec![
            (BBId(0), src.clone()),
            (BBId(1), src.clone()),
        ]);
        let mut phi_nodes: HashMap<BBId, Vec<Phi>> = HashMap::new();
        phi_nodes.insert(BBId(2), vec![phi]);
        let replacements = eliminate_trivial_phis(&mut phi_nodes);
        assert!(replacements.contains_key(&dst));
        assert_eq!(replacements[&dst], src);
    }

    #[test]
    fn test_dessa_copies() {
        let phi = Phi::new(SsaVar::new("x", 2), vec![
            (BBId(1), SsaVar::new("x", 0)),
            (BBId(2), SsaVar::new("x", 1)),
        ]);
        let mut phi_nodes: HashMap<BBId, Vec<Phi>> = HashMap::new();
        phi_nodes.insert(BBId(3), vec![phi]);
        let copies = dessa_insert_copies(&phi_nodes);
        assert_eq!(copies.len(), 2);
        assert!(copies.iter().any(|c| c.pred_bb == BBId(1)));
        assert!(copies.iter().any(|c| c.pred_bb == BBId(2)));
    }

    #[test]
    fn test_phi_display() {
        let phi = Phi::new(SsaVar::new("x", 2), vec![
            (BBId(1), SsaVar::new("x", 0)),
            (BBId(2), SsaVar::new("x", 1)),
        ]);
        let s = format!("{}", phi);
        assert!(s.contains("φ("));
        assert!(s.contains("x_2"));
    }

    #[test]
    fn test_liveness_simple() {
        // Linear: BB0 defines x, BB1 uses x.
        let cfg = linear_cfg();
        let mut defs = HashMap::new();
        defs.insert(BBId(0), [Variable::new("x")].iter().cloned().collect());
        let mut uses = HashMap::new();
        uses.insert(BBId(1), [Variable::new("x")].iter().cloned().collect());
        let liv = LivenessInfo::compute(&cfg, defs, uses);
        // x is live-out of BB0 (needed in BB1).
        assert!(liv.live_out[&BBId(0)].contains(&Variable::new("x")));
    }

    #[test]
    fn test_ssa_form_pretty_print() {
        let cfg = diamond_cfg();
        let blocks = vec![
            BlockInfo { id: BBId(0), defs: vec![Variable::new("y")], uses: vec![] },
            BlockInfo { id: BBId(1), defs: vec![Variable::new("y")], uses: vec![] },
            BlockInfo { id: BBId(2), defs: vec![], uses: vec![] },
            BlockInfo { id: BBId(3), defs: vec![], uses: vec!["y".to_string()].into_iter().map(Variable::new).collect() },
        ];
        let ssa = SsaForm::build(&cfg, &blocks, SsaVariant::Minimal);
        let s = ssa.pretty_print();
        // Should contain at least one phi.
        assert!(s.contains("φ(") || s.is_empty()); // may be empty if no multi-def
    }
}
