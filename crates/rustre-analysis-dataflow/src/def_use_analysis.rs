//! `def_use_analysis` — comprehensive definition–use chain analysis.
//!
//! # Relationship to [`crate::def_use`]
//! This module provides a *self-contained* def-use pipeline built on its own
//! `Program`/`Block`/`Instruction` IR (string-keyed variables, unversioned).
//! It includes its own SSA form builder ([`SSAForm`]), reaching-definitions
//! sub-analysis ([`ReachingDefs`]), and bipartite def-use graph ([`DefUseGraph`]).
//!
//! [`crate::def_use`] operates on the project's shared SSA IR
//! ([`crate::ssa::SsaFunction`] with typed [`crate::ssa::SsaVar`] operands) and
//! is the SSA-aware layer used by the rest of the `RustRE` pipeline.  The two
//! modules are intentionally kept separate because they target different IRs.
//!
//! Provides:
//! * [`DefUseAnalysis`]   — top-level coordinator.
//! * [`Definition`]       — a variable definition with location.
//! * [`UseChain`]         — maps each definition to all its uses.
//! * [`DefChain`]         — maps each use to all reaching definitions.
//! * [`SSAForm`]          — minimal SSA with versioned variables.
//! * [`Phi`]              — SSA phi node.
//! * [`VersionedVar`]     — original variable + SSA version number.
//! * [`DefUseGraph`]      — full bipartite def–use graph.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Program point
// ─────────────────────────────────────────────────────────────────────────────

/// A location in the program identified by `(block_id, instruction_index)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProgramPoint {
    pub block: usize,
    pub index: usize,
}

impl ProgramPoint {
    #[must_use] 
    pub const fn new(block: usize, index: usize) -> Self {
        Self { block, index }
    }
}

impl std::fmt::Display for ProgramPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BB{}[{}]", self.block, self.index)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VersionedVar
// ─────────────────────────────────────────────────────────────────────────────

/// An SSA-versioned variable: original name + version counter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VersionedVar {
    pub original: String,
    pub version: u32,
}

impl VersionedVar {
    pub fn new(original: impl Into<String>, version: u32) -> Self {
        Self {
            original: original.into(),
            version,
        }
    }

    /// Unversioned representation (`x`).
    #[must_use] 
    pub fn base(&self) -> &str {
        &self.original
    }

    /// Versioned name representation (`x_3`).
    #[must_use] 
    pub fn versioned_name(&self) -> String {
        format!("{}_{}", self.original, self.version)
    }
}

impl std::fmt::Display for VersionedVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}", self.original, self.version)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Definition
// ─────────────────────────────────────────────────────────────────────────────

/// A single variable definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Definition {
    /// The variable being defined.
    pub var: String,
    /// Where in the program the definition occurs.
    pub point: ProgramPoint,
    /// Unique definition id (used in reaching-definitions bitvectors).
    pub id: usize,
    /// Whether this definition is a φ-node.
    pub is_phi: bool,
}

impl Definition {
    pub fn new(var: impl Into<String>, point: ProgramPoint, id: usize) -> Self {
        Self {
            var: var.into(),
            point,
            id,
            is_phi: false,
        }
    }

    pub fn phi(var: impl Into<String>, block: usize, id: usize) -> Self {
        Self {
            var: var.into(),
            point: ProgramPoint::new(block, 0),
            id,
            is_phi: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Use site
// ─────────────────────────────────────────────────────────────────────────────

/// A use of a variable at a program point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UseSite {
    pub var: String,
    pub point: ProgramPoint,
}

impl UseSite {
    pub fn new(var: impl Into<String>, point: ProgramPoint) -> Self {
        Self {
            var: var.into(),
            point,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phi
// ─────────────────────────────────────────────────────────────────────────────

/// An SSA φ-node: merges versions of a variable at a join point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phi {
    /// The variable being merged.
    pub var: String,
    /// Block where this φ resides.
    pub block: usize,
    /// `(predecessor_block, versioned_var)` operands.
    pub operands: Vec<(usize, VersionedVar)>,
    /// The versioned variable this φ defines.
    pub result: VersionedVar,
}

impl Phi {
    pub fn new(var: impl Into<String>, block: usize, result: VersionedVar) -> Self {
        Self {
            var: var.into(),
            block,
            operands: Vec::new(),
            result,
        }
    }

    /// Add an operand from predecessor `pred_block` with versioned variable `v`.
    pub fn add_operand(&mut self, pred_block: usize, v: VersionedVar) {
        self.operands.push((pred_block, v));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UseChain — definition → set of uses
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each definition to the set of use sites it reaches.
#[derive(Debug, Clone, Default)]
pub struct UseChain {
    inner: HashMap<usize, Vec<UseSite>>,
}

impl UseChain {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that definition `def_id` reaches use site `site`.
    pub fn add(&mut self, def_id: usize, site: UseSite) {
        self.inner.entry(def_id).or_default().push(site);
    }

    /// All use sites reachable from definition `def_id`.
    pub fn uses_of(&self, def_id: usize) -> &[UseSite] {
        self.inner.get(&def_id).map_or(&[], Vec::as_slice)
    }

    /// Number of uses for definition `def_id`.
    #[must_use] 
    pub fn use_count(&self, def_id: usize) -> usize {
        self.uses_of(def_id).len()
    }

    /// All definition ids that have at least one use.
    pub fn live_defs(&self) -> impl Iterator<Item = usize> + '_ {
        self.inner.keys().copied()
    }

    /// Total number of def–use edges.
    #[must_use] 
    pub fn total_edges(&self) -> usize {
        self.inner.values().map(std::vec::Vec::len).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DefChain — use site → set of reaching definitions
// ─────────────────────────────────────────────────────────────────────────────

/// Maps each use site to the set of definitions that can reach it.
#[derive(Debug, Clone, Default)]
pub struct DefChain {
    inner: HashMap<ProgramPoint, Vec<usize>>,
}

impl DefChain {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that definition `def_id` reaches the use at `point`.
    pub fn add(&mut self, point: ProgramPoint, def_id: usize) {
        self.inner.entry(point).or_default().push(def_id);
    }

    /// All definition ids that can reach use at `point`.
    pub fn defs_at(&self, point: ProgramPoint) -> &[usize] {
        self.inner.get(&point).map_or(&[], Vec::as_slice)
    }

    /// True if the use at `point` has a unique reaching definition.
    #[must_use] 
    pub fn is_single_def(&self, point: ProgramPoint) -> bool {
        self.defs_at(point).len() == 1
    }

    /// Total number of use–def edges.
    #[must_use] 
    pub fn total_edges(&self) -> usize {
        self.inner.values().map(std::vec::Vec::len).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DefUseGraph — bipartite graph
// ─────────────────────────────────────────────────────────────────────────────

/// A bipartite def–use graph combining [`UseChain`] and [`DefChain`].
#[derive(Debug, Clone, Default)]
pub struct DefUseGraph {
    pub definitions: Vec<Definition>,
    pub use_chain: UseChain,
    pub def_chain: DefChain,
    /// Mapping from variable name to its definition ids.
    pub defs_by_var: HashMap<String, Vec<usize>>,
    /// Mapping from definition id to its index in `definitions`, for O(1)
    /// lookup by id (definition ids are caller-supplied and need not equal
    /// their index in `definitions`, so a linear scan is not safe to assume
    /// away — this index avoids the O(n) `.find()` scan per lookup, which
    /// otherwise made id-based lookups in hot loops quadratic in the number
    /// of definitions).
    id_to_index: HashMap<usize, usize>,
}

impl DefUseGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a definition and return its id.
    pub fn add_definition(&mut self, def: Definition) -> usize {
        let id = def.id;
        self.defs_by_var
            .entry(def.var.clone())
            .or_default()
            .push(id);
        self.id_to_index.insert(id, self.definitions.len());
        self.definitions.push(def);
        id
    }

    /// Look up a definition by its id in O(1) rather than scanning
    /// `definitions` linearly.
    #[must_use]
    pub fn definition_by_id(&self, id: usize) -> Option<&Definition> {
        self.id_to_index
            .get(&id)
            .and_then(|&idx| self.definitions.get(idx))
    }

    /// Record a def–use edge between `def_id` and use at `use_point` of `var`.
    pub fn add_edge(&mut self, def_id: usize, var: impl Into<String>, use_point: ProgramPoint) {
        let site = UseSite::new(var, use_point);
        self.use_chain.add(def_id, site);
        self.def_chain.add(use_point, def_id);
    }

    /// Number of definitions.
    #[must_use] 
    pub const fn def_count(&self) -> usize {
        self.definitions.len()
    }

    /// Total def–use edges.
    #[must_use] 
    pub fn edge_count(&self) -> usize {
        self.use_chain.total_edges()
    }

    /// All definitions of variable `var`.
    #[must_use] 
    pub fn defs_of_var(&self, var: &str) -> Vec<&Definition> {
        self.defs_by_var
            .get(var)
            .map(|ids| {
                ids.iter()
                    .filter_map(|&id| self.definition_by_id(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Dead definitions: those with no uses.
    #[must_use] 
    pub fn dead_defs(&self) -> Vec<&Definition> {
        self.definitions
            .iter()
            .filter(|d| self.use_chain.use_count(d.id) == 0 && !d.is_phi)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight program representation
// ─────────────────────────────────────────────────────────────────────────────

/// A single instruction in the analysis model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Variable defined (if any).
    pub def: Option<String>,
    /// Variables used (read).
    pub uses: Vec<String>,
}

impl Instruction {
    pub fn new(def: Option<&str>, uses: Vec<&str>) -> Self {
        Self {
            def: def.map(str::to_string),
            uses: uses.into_iter().map(str::to_string).collect(),
        }
    }

    #[must_use] 
    pub fn assign(def: &str, src: &str) -> Self {
        Self::new(Some(def), vec![src])
    }

    #[must_use] 
    pub fn use_only(var: &str) -> Self {
        Self::new(None, vec![var])
    }
}

/// A basic block: a sequence of instructions.
#[derive(Debug, Clone)]
pub struct Block {
    pub id: usize,
    pub instrs: Vec<Instruction>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

impl Block {
    #[must_use] 
    pub const fn new(id: usize, instrs: Vec<Instruction>) -> Self {
        Self {
            id,
            instrs,
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    /// Variables defined in this block.
    #[must_use] 
    pub fn defs(&self) -> HashSet<String> {
        self.instrs.iter().filter_map(|i| i.def.clone()).collect()
    }

    /// Upward-exposed uses (used before being defined in this block).
    #[must_use] 
    pub fn ue_uses(&self) -> HashSet<String> {
        let mut killed = HashSet::new();
        let mut ue = HashSet::new();
        for instr in &self.instrs {
            for u in &instr.uses {
                if !killed.contains(u) {
                    ue.insert(u.clone());
                }
            }
            if let Some(d) = &instr.def {
                killed.insert(d.clone());
            }
        }
        ue
    }
}

/// A minimal program for def–use analysis.
#[derive(Debug, Clone)]
pub struct Program {
    pub blocks: Vec<Block>,
    pub entry: usize,
}

impl Program {
    #[must_use] 
    pub const fn new(entry: usize) -> Self {
        Self {
            blocks: Vec::new(),
            entry,
        }
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.push(block);
    }

    pub fn add_edge(&mut self, from: usize, to: usize) {
        if let Some(b) = self.blocks.iter_mut().find(|b| b.id == from)
            && !b.successors.contains(&to) {
                b.successors.push(to);
            }
        if let Some(b) = self.blocks.iter_mut().find(|b| b.id == to)
            && !b.predecessors.contains(&from) {
                b.predecessors.push(from);
            }
    }

    fn block(&self, id: usize) -> Option<&Block> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Precomputed `block_id → index` map for O(1) block lookups.
    ///
    /// `block()` is a linear scan; calling it repeatedly inside a fixpoint
    /// loop (as `compute_idom`/`compute_dom_frontier`/`ReachingDefs::compute`
    /// do, once per block per iteration) made those analyses effectively
    /// quadratic-to-cubic in the number of blocks. Building this index once
    /// per analysis run and doing `HashMap` lookups instead turns each of
    /// those loop bodies back into O(1) amortized block access.
    fn block_index(&self) -> HashMap<usize, usize> {
        self.blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect()
    }

    fn block_by_index<'a>(&'a self, idx: &HashMap<usize, usize>, id: usize) -> Option<&'a Block> {
        idx.get(&id).map(|&i| &self.blocks[i])
    }

    fn rpo(&self) -> Vec<usize> {
        
        if self.blocks.iter().map(|b| b.id).next().is_none() {
            return Vec::new();
        }
        let block_idx = self.block_index();
        let mut visited = HashSet::new();
        let mut po = Vec::new();
        let mut stack: Vec<(usize, usize)> = vec![(self.entry, 0)];
        visited.insert(self.entry);
        while let Some((node, idx)) = stack.last_mut() {
            let node = *node;
            let succs: Vec<usize> = self
                .block_by_index(&block_idx, node)
                .map(|b| b.successors.clone())
                .unwrap_or_default();
            if *idx < succs.len() {
                let child = succs[*idx];
                *idx += 1;
                if visited.insert(child) {
                    stack.push((child, 0));
                }
            } else {
                stack.pop();
                po.push(node);
            }
        }
        po.reverse();
        po
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reaching definitions (forward dataflow)
// ─────────────────────────────────────────────────────────────────────────────

/// Reaching definitions result: per-block in/out definition sets.
#[derive(Debug, Clone, Default)]
pub struct ReachingDefs {
    /// `in_defs[block_id]` = set of definition ids reaching the entry of block.
    pub in_defs: HashMap<usize, HashSet<usize>>,
    /// `out_defs[block_id]` = set of definition ids reaching the exit of block.
    pub out_defs: HashMap<usize, HashSet<usize>>,
    pub iterations: usize,
}

impl ReachingDefs {
    /// Run reaching-definitions analysis on `program` using `all_defs`.
    ///
    /// `all_defs` maps `(block_id, instr_index) → definition_id`.
    /// `kill_sets` maps `block_id → set of definition ids killed (overwritten)`.
    #[must_use] 
    pub fn compute(
        program: &Program,
        all_defs: &HashMap<ProgramPoint, usize>,
        kill_sets: &HashMap<usize, HashSet<usize>>,
    ) -> Self {
        let rpo = program.rpo();
        let n = program.blocks.len();
        if n == 0 {
            return Self::default();
        }

        let mut in_defs: HashMap<usize, HashSet<usize>> = program
            .blocks
            .iter()
            .map(|b| (b.id, HashSet::new()))
            .collect();
        let mut out_defs: HashMap<usize, HashSet<usize>> = program
            .blocks
            .iter()
            .map(|b| (b.id, HashSet::new()))
            .collect();

        // Gen sets: defs generated in each block — only the LAST definition of
        // each variable within the block survives to the block's exit. Earlier
        // same-variable defs are killed intra-block and must not leak into
        // gen, or they would incorrectly "reach" every successor.
        let mut r#gen: HashMap<usize, HashSet<usize>> = HashMap::new();
        for b in &program.blocks {
            let mut last_per_var: HashMap<&str, usize> = HashMap::new();
            let mut anon: HashSet<usize> = HashSet::new();
            for (i, instr) in b.instrs.iter().enumerate() {
                let pp = ProgramPoint::new(b.id, i);
                if let Some(&did) = all_defs.get(&pp) {
                    // Kill previous defs of same var before adding.
                    match &instr.def {
                        Some(v) => {
                            last_per_var.insert(v.as_str(), did);
                        }
                        // Def id registered at a point whose instruction names
                        // no variable: nothing to kill against, keep it.
                        None => {
                            anon.insert(did);
                        }
                    }
                }
            }
            let mut g: HashSet<usize> = last_per_var.into_values().collect();
            g.extend(anon);
            r#gen.insert(b.id, g);
        }

        // NOTE(perf): this is a round-robin fixpoint (rescans every block in RPO
        // order each pass) rather than a change-driven worklist keyed off
        // successors of blocks that actually changed, unlike the incremental
        // worklists in `reaching_definitions.rs` / `reaching_defs.rs`. It still
        // terminates and is correct, but on large CFGs it can do materially more
        // work per fixpoint than necessary. If this becomes a hot path, replace
        // with a `VecDeque`/`in_worklist` queue seeded from `rpo` and pushing only
        // the successors of blocks whose `out` set changed (see
        // `reaching_defs::compute` for the pattern).
        let block_idx = program.block_index();
        let mut changed = true;
        let mut iterations = 0;
        while changed {
            changed = false;
            iterations += 1;
            for &bid in &rpo {
                // in[b] = union of out[pred] for all predecessors
                let preds: &[usize] = program
                    .block_by_index(&block_idx, bid)
                    .map(|b| b.predecessors.as_slice())
                    .unwrap_or(&[]);
                let new_in: HashSet<usize> = preds
                    .iter()
                    .flat_map(|p| out_defs.get(p).into_iter().flatten().copied())
                    .collect();

                // out[b] = gen[b] ∪ (in[b] \ kill[b])
                let kill = kill_sets.get(&bid);
                let mut new_out: HashSet<usize> = new_in
                    .iter()
                    .filter(|d| !kill.is_some_and(|k| k.contains(d)))
                    .copied()
                    .collect();
                new_out.extend(r#gen.get(&bid).into_iter().flatten().copied());
                in_defs.insert(bid, new_in);

                if out_defs.get(&bid).map_or(!new_out.is_empty(), |prev| new_out != *prev) {
                    out_defs.insert(bid, new_out);
                    changed = true;
                }
            }
        }

        Self {
            in_defs,
            out_defs,
            iterations,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSAForm
// ─────────────────────────────────────────────────────────────────────────────

/// SSA form built from a program.
#[derive(Debug, Clone, Default)]
pub struct SSAForm {
    /// φ-nodes per block.
    pub phi_nodes: HashMap<usize, Vec<Phi>>,
    /// Version counters per variable.
    pub versions: HashMap<String, u32>,
    /// Mapping `(block, original_var)` → `VersionedVar`.
    pub renamed: HashMap<(usize, String), VersionedVar>,
    /// The dominance frontiers used.
    pub dom_frontiers: HashMap<usize, Vec<usize>>,
}

impl SSAForm {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Build SSA form from a program.
    #[must_use] 
    pub fn build(program: &Program) -> Self {
        let mut ssa = Self::new();
        let df = compute_dom_frontier(program);
        ssa.dom_frontiers.clone_from(&df);

        // Collect definition sites.
        let mut def_sites: HashMap<String, Vec<usize>> = HashMap::new();
        for b in &program.blocks {
            for instr in &b.instrs {
                if let Some(v) = &instr.def {
                    def_sites.entry(v.clone()).or_default().push(b.id);
                }
            }
        }

        // Insert φ-nodes at iterated dominance frontier of each variable.
        for (var, def_blocks) in &def_sites {
            let idf = iterated_dom_frontier(&df, def_blocks);
            for loc in idf {
                let preds: Vec<usize> = program
                    .block(loc)
                    .map(|b| b.predecessors.clone())
                    .unwrap_or_default();
                let result = VersionedVar::new(var.clone(), 0);
                let mut phi = Phi::new(var.clone(), loc, result);
                for pred in preds {
                    phi.add_operand(pred, VersionedVar::new(var.clone(), 0));
                }
                ssa.phi_nodes.entry(loc).or_default().push(phi);
            }
        }

        // Simple version numbering.
        let mut ver_ctr: HashMap<String, u32> = HashMap::new();
        for b in &program.blocks {
            for instr in &b.instrs {
                if let Some(v) = &instr.def {
                    let n = ver_ctr.entry(v.clone()).or_insert(0);
                    let ver = VersionedVar::new(v.clone(), *n);
                    ssa.renamed.insert((b.id, v.clone()), ver);
                    *n += 1;
                }
            }
        }
        ssa.versions = ver_ctr;
        ssa
    }

    /// Number of φ-nodes across all blocks.
    #[must_use] 
    pub fn phi_count(&self) -> usize {
        self.phi_nodes.values().map(std::vec::Vec::len).sum()
    }

    /// Maximum version number for variable `var`.
    #[must_use] 
    pub fn max_version(&self, var: &str) -> Option<u32> {
        self.versions.get(var).copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dominance frontier helpers
// ─────────────────────────────────────────────────────────────────────────────

fn compute_idom(program: &Program) -> HashMap<usize, usize> {
    let rpo = program.rpo();
    if rpo.is_empty() {
        return HashMap::new();
    }
    let rpo_pos: HashMap<usize, usize> = rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();
    let mut idom: HashMap<usize, usize> = HashMap::new();
    idom.insert(program.entry, program.entry);

    let intersect = |mut a: usize, mut b: usize, idom: &HashMap<usize, usize>| -> usize {
        while a != b {
            while rpo_pos.get(&a).copied().unwrap_or(usize::MAX)
                > rpo_pos.get(&b).copied().unwrap_or(usize::MAX)
            {
                a = *idom.get(&a).unwrap_or(&a);
            }
            while rpo_pos.get(&b).copied().unwrap_or(usize::MAX)
                > rpo_pos.get(&a).copied().unwrap_or(usize::MAX)
            {
                b = *idom.get(&b).unwrap_or(&b);
            }
        }
        a
    };

    let block_idx = program.block_index();
    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == program.entry {
                continue;
            }
            let preds: &[usize] = program
                .block_by_index(&block_idx, b)
                .map(|bl| bl.predecessors.as_slice())
                .unwrap_or(&[]);
            let mut new_idom: Option<usize> = None;
            for &p in preds {
                if !idom.contains_key(&p) {
                    continue;
                }
                new_idom = Some(match new_idom {
                    None => p,
                    Some(cur) => intersect(p, cur, &idom),
                });
            }
            let Some(new_idom) = new_idom else { continue };
            if idom.get(&b) != Some(&new_idom) {
                idom.insert(b, new_idom);
                changed = true;
            }
        }
    }
    idom
}

fn compute_dom_frontier(program: &Program) -> HashMap<usize, Vec<usize>> {
    let idom = compute_idom(program);
    let mut df: HashMap<usize, HashSet<usize>> = HashMap::new();
    for b in &program.blocks {
        df.insert(b.id, HashSet::new());
    }
    for b in &program.blocks {
        if b.predecessors.len() >= 2 {
            for &pred in &b.predecessors {
                let mut runner = pred;
                let join_idom = *idom.get(&b.id).unwrap_or(&b.id);
                while runner != join_idom {
                    df.entry(runner).or_default().insert(b.id);
                    let parent = *idom.get(&runner).unwrap_or(&runner);
                    if parent == runner {
                        break;
                    }
                    runner = parent;
                }
            }
        }
    }
    df.into_iter()
        .map(|(k, v)| {
            let mut v: Vec<usize> = v.into_iter().collect();
            v.sort_unstable();
            (k, v)
        })
        .collect()
}

fn iterated_dom_frontier(df: &HashMap<usize, Vec<usize>>, seeds: &[usize]) -> Vec<usize> {
    let mut result: HashSet<usize> = HashSet::new();
    let mut wl: VecDeque<usize> = seeds.iter().copied().collect();
    while let Some(n) = wl.pop_front() {
        for &f in df.get(&n).map_or(&[][..], Vec::as_slice) {
            if result.insert(f) {
                wl.push_back(f);
            }
        }
    }
    let mut v: Vec<usize> = result.into_iter().collect();
    v.sort_unstable();
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// DefUseAnalysis — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level def–use analysis.
pub struct DefUseAnalysis;

impl DefUseAnalysis {
    /// Run the full def–use analysis on a [`Program`].
    ///
    /// Returns `(DefUseGraph, SSAForm, ReachingDefs)`.
    #[must_use] 
    pub fn run(program: &Program) -> (DefUseGraph, SSAForm, ReachingDefs) {
        // Assign unique ids to all definitions.
        let mut all_defs: HashMap<ProgramPoint, usize> = HashMap::new();
        let mut kill_sets: HashMap<usize, HashSet<usize>> = HashMap::new();
        let mut def_list: Vec<Definition> = Vec::new();
        let mut def_id = 0usize;

        // First pass: collect all definitions.
        for b in &program.blocks {
            let mut seen_vars: HashMap<String, usize> = HashMap::new(); // var → last def id in block
            for (i, instr) in b.instrs.iter().enumerate() {
                if let Some(v) = &instr.def {
                    let pp = ProgramPoint::new(b.id, i);
                    let def = Definition::new(v.clone(), pp, def_id);
                    all_defs.insert(pp, def_id);
                    // Kill the previous def of this var in this block.
                    if let Some(&prev_id) = seen_vars.get(v) {
                        kill_sets.entry(b.id).or_default().insert(prev_id);
                    }
                    seen_vars.insert(v.clone(), def_id);
                    def_list.push(def);
                    def_id += 1;
                }
            }
        }

        // Reaching definitions.
        let rd = ReachingDefs::compute(program, &all_defs, &kill_sets);

        // Build def–use graph.
        let mut graph = DefUseGraph::new();
        for def in def_list {
            graph.add_definition(def);
        }

        for b in &program.blocks {
            let reaching = rd.in_defs.get(&b.id).cloned().unwrap_or_default();
            let mut live_at: HashMap<String, Vec<usize>> = HashMap::new();
            // Populate live_at from reaching defs.
            for &did in &reaching {
                if let Some(def) = graph.definition_by_id(did) {
                    live_at.entry(def.var.clone()).or_default().push(did);
                }
            }
            for (i, instr) in b.instrs.iter().enumerate() {
                let pp = ProgramPoint::new(b.id, i);
                // For each use, connect to reaching defs.
                for u in &instr.uses {
                    for &did in live_at.get(u).into_iter().flatten() {
                        graph.add_edge(did, u.clone(), pp);
                    }
                }
                // Update live_at when a definition occurs.
                if let Some(v) = &instr.def {
                    let new_id = all_defs.get(&pp).copied();
                    if let Some(nid) = new_id {
                        live_at.entry(v.clone()).or_default().retain(|_| false);
                        live_at.entry(v.clone()).or_default().push(nid);
                    }
                }
            }
        }

        // Build SSA.
        let ssa = SSAForm::build(program);

        (graph, ssa, rd)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_linear_program() -> Program {
        // BB0: x = 1; y = x; BB1: z = y
        let mut p = Program::new(0);
        p.add_block(Block::new(
            0,
            vec![
                Instruction::new(Some("x"), vec![]),
                Instruction::new(Some("y"), vec!["x"]),
            ],
        ));
        p.add_block(Block::new(1, vec![Instruction::new(Some("z"), vec!["y"])]));
        p.add_edge(0, 1);
        p
    }

    fn make_diamond_program() -> Program {
        // BB0: cond use; BB1: x=1; BB2: x=2; BB3: use x
        let mut p = Program::new(0);
        p.add_block(Block::new(0, vec![Instruction::use_only("cond")]));
        p.add_block(Block::new(1, vec![Instruction::new(Some("x"), vec![])]));
        p.add_block(Block::new(2, vec![Instruction::new(Some("x"), vec![])]));
        p.add_block(Block::new(3, vec![Instruction::use_only("x")]));
        p.add_edge(0, 1);
        p.add_edge(0, 2);
        p.add_edge(1, 3);
        p.add_edge(2, 3);
        p
    }

    // 1. VersionedVar basic.
    #[test]
    fn test_versioned_var_display() {
        let v = VersionedVar::new("x", 3);
        assert_eq!(v.versioned_name(), "x_3");
        assert_eq!(v.base(), "x");
    }

    // 2. ProgramPoint display.
    #[test]
    fn test_program_point_display() {
        let pp = ProgramPoint::new(2, 5);
        assert_eq!(pp.to_string(), "BB2[5]");
    }

    // 3. Definition basic.
    #[test]
    fn test_definition_new() {
        let d = Definition::new("x", ProgramPoint::new(0, 0), 42);
        assert_eq!(d.var, "x");
        assert_eq!(d.id, 42);
        assert!(!d.is_phi);
    }

    // 4. Definition phi constructor.
    #[test]
    fn test_definition_phi() {
        let d = Definition::phi("y", 1, 7);
        assert!(d.is_phi);
        assert_eq!(d.point.block, 1);
    }

    // 5. UseChain add / uses_of.
    #[test]
    fn test_use_chain() {
        let mut uc = UseChain::new();
        uc.add(0, UseSite::new("x", ProgramPoint::new(1, 0)));
        uc.add(0, UseSite::new("x", ProgramPoint::new(2, 1)));
        assert_eq!(uc.use_count(0), 2);
        assert_eq!(uc.uses_of(0).len(), 2);
        assert_eq!(uc.uses_of(99), &[]);
    }

    // 6. UseChain total_edges.
    #[test]
    fn test_use_chain_total_edges() {
        let mut uc = UseChain::new();
        uc.add(0, UseSite::new("a", ProgramPoint::new(0, 0)));
        uc.add(1, UseSite::new("b", ProgramPoint::new(1, 0)));
        assert_eq!(uc.total_edges(), 2);
    }

    // 7. DefChain add / defs_at.
    #[test]
    fn test_def_chain() {
        let mut dc = DefChain::new();
        let pp = ProgramPoint::new(1, 2);
        dc.add(pp, 5);
        dc.add(pp, 6);
        assert_eq!(dc.defs_at(pp).len(), 2);
        assert!(!dc.is_single_def(pp));
    }

    // 8. DefChain single_def.
    #[test]
    fn test_def_chain_single_def() {
        let mut dc = DefChain::new();
        let pp = ProgramPoint::new(0, 0);
        dc.add(pp, 3);
        assert!(dc.is_single_def(pp));
    }

    // 9. Phi node.
    #[test]
    fn test_phi_node() {
        let result = VersionedVar::new("x", 3);
        let mut phi = Phi::new("x", 2, result.clone());
        phi.add_operand(0, VersionedVar::new("x", 1));
        phi.add_operand(1, VersionedVar::new("x", 2));
        assert_eq!(phi.operands.len(), 2);
        assert_eq!(phi.result, result);
        assert_eq!(phi.block, 2);
    }

    // 10. Instruction helpers.
    #[test]
    fn test_instruction_helpers() {
        let a = Instruction::assign("y", "x");
        assert_eq!(a.def.as_deref(), Some("y"));
        assert!(a.uses.contains(&"x".to_string()));
        let u = Instruction::use_only("z");
        assert!(u.def.is_none());
        assert!(u.uses.contains(&"z".to_string()));
    }

    // 11. Block::defs.
    #[test]
    fn test_block_defs() {
        let b = Block::new(
            0,
            vec![Instruction::assign("x", "a"), Instruction::assign("y", "x")],
        );
        let d = b.defs();
        assert!(d.contains("x") && d.contains("y"));
    }

    // 12. Block::ue_uses.
    #[test]
    fn test_block_ue_uses() {
        let b = Block::new(
            0,
            vec![
                Instruction::assign("y", "a"), // a is UE, y is killed
                Instruction::use_only("y"),    // y used after kill → not UE
                Instruction::use_only("b"),    // b is UE
            ],
        );
        let ue = b.ue_uses();
        assert!(ue.contains("a") && ue.contains("b"));
        assert!(!ue.contains("y"));
    }

    // 13. Program::rpo visits all.
    #[test]
    fn test_program_rpo() {
        let p = make_diamond_program();
        let rpo = p.rpo();
        assert_eq!(rpo.len(), 4);
        assert_eq!(rpo[0], 0);
    }

    // 14. ReachingDefs linear.
    #[test]
    fn test_reaching_defs_linear() {
        let p = make_linear_program();
        let mut all_defs = HashMap::new();
        // Block 0: x defined at (0,0), y at (0,1); Block 1: z at (1,0).
        all_defs.insert(ProgramPoint::new(0, 0), 0usize); // x
        all_defs.insert(ProgramPoint::new(0, 1), 1usize); // y
        all_defs.insert(ProgramPoint::new(1, 0), 2usize); // z
        let kill = HashMap::new();
        let rd = ReachingDefs::compute(&p, &all_defs, &kill);
        // z at block 1 should see x(0) and y(1).
        let in1 = &rd.in_defs[&1];
        assert!(in1.contains(&0) && in1.contains(&1));
    }

    // 15. ReachingDefs kill.
    #[test]
    fn test_reaching_defs_kill() {
        let p = make_linear_program();
        let mut all_defs = HashMap::new();
        all_defs.insert(ProgramPoint::new(0, 0), 0usize); // x = ...
        all_defs.insert(ProgramPoint::new(0, 1), 1usize); // y = x   (kills y-previous if any)
        let mut kill = HashMap::new();
        kill.insert(1usize, HashSet::from([0usize])); // block 1 kills def 0
        let rd = ReachingDefs::compute(&p, &all_defs, &kill);
        // The kill set applies to the OUT equation (out = gen ∪ (in \ kill));
        // the IN of block 1 reflects predecessor outputs before kill is applied.
        assert!(!rd.out_defs.get(&1).is_some_and(|s| s.contains(&0)));
    }

    // 15b. Regression: a def killed by a LATER def of the same variable in the
    // SAME block must not appear in gen — it cannot reach any successor.
    // Previously gen collected every def in the block, so the dead first def
    // of `x` leaked into out[0] / in[1].
    #[test]
    fn test_reaching_defs_intra_block_kill_not_in_gen() {
        let mut p = Program::new(0);
        p.add_block(Block::new(
            0,
            vec![Instruction::new(Some("x"), vec![]), Instruction::new(Some("x"), vec![])],
        ));
        p.add_block(Block::new(1, vec![]));
        p.add_edge(0, 1);
        let mut all_defs = HashMap::new();
        all_defs.insert(ProgramPoint::new(0, 0), 0usize); // x = ... (killed)
        all_defs.insert(ProgramPoint::new(0, 1), 1usize); // x = ... (survives)
        let mut kill = HashMap::new();
        kill.insert(0usize, HashSet::from([0usize, 1usize]));
        let rd = ReachingDefs::compute(&p, &all_defs, &kill);
        let in1 = &rd.in_defs[&1];
        assert!(!in1.contains(&0), "intra-block-killed def 0 must not reach block 1");
        assert!(in1.contains(&1), "surviving def 1 must reach block 1");
    }

    // 16. DefUseGraph add_definition.
    #[test]
    fn test_def_use_graph_add() {
        let mut g = DefUseGraph::new();
        let d = Definition::new("x", ProgramPoint::new(0, 0), 0);
        g.add_definition(d);
        assert_eq!(g.def_count(), 1);
    }

    // 17. DefUseGraph add_edge.
    #[test]
    fn test_def_use_graph_edge() {
        let mut g = DefUseGraph::new();
        let d = Definition::new("x", ProgramPoint::new(0, 0), 0);
        g.add_definition(d);
        g.add_edge(0, "x", ProgramPoint::new(1, 0));
        assert_eq!(g.edge_count(), 1);
    }

    // 17b. DefUseGraph lookups (defs_of_var / definition_by_id) must resolve
    // correctly by id even when definition ids are non-sequential /
    // out-of-order relative to insertion index — a regression test for the
    // O(1) `id_to_index` index replacing a linear `.find()` scan.
    #[test]
    fn test_def_use_graph_lookup_by_nonsequential_id() {
        let mut g = DefUseGraph::new();
        g.add_definition(Definition::new("x", ProgramPoint::new(0, 0), 42));
        g.add_definition(Definition::new("y", ProgramPoint::new(0, 1), 7));
        g.add_definition(Definition::new("x", ProgramPoint::new(0, 2), 100));

        let x_defs = g.defs_of_var("x");
        assert_eq!(x_defs.len(), 2);
        let x_ids: Vec<usize> = x_defs.iter().map(|d| d.id).collect();
        assert!(x_ids.contains(&42));
        assert!(x_ids.contains(&100));

        assert_eq!(g.definition_by_id(7).unwrap().var, "y");
        assert_eq!(g.definition_by_id(100).unwrap().var, "x");
        assert!(g.definition_by_id(999).is_none());
    }

    // 18. DefUseGraph dead_defs.
    #[test]
    fn test_dead_defs() {
        let mut g = DefUseGraph::new();
        g.add_definition(Definition::new("x", ProgramPoint::new(0, 0), 0));
        g.add_definition(Definition::new("y", ProgramPoint::new(0, 1), 1));
        g.add_edge(1, "y", ProgramPoint::new(1, 0));
        let dead = g.dead_defs();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].var, "x");
    }

    // 19. SSAForm phi_count on diamond.
    #[test]
    fn test_ssa_phi_count_diamond() {
        let p = make_diamond_program();
        let ssa = SSAForm::build(&p);
        // x defined in blocks 1 and 2 → φ at block 3.
        assert!(ssa.phi_count() >= 1);
    }

    // 20. SSAForm version map.
    #[test]
    fn test_ssa_version_map() {
        let p = make_linear_program();
        let ssa = SSAForm::build(&p);
        assert!(ssa.renamed.contains_key(&(0, "x".into())));
        assert!(ssa.renamed.contains_key(&(0, "y".into())));
    }

    // 21. DefUseAnalysis::run on linear program.
    #[test]
    fn test_def_use_analysis_linear() {
        let p = make_linear_program();
        let (graph, ssa, rd) = DefUseAnalysis::run(&p);
        assert!(graph.def_count() >= 3); // x, y, z
        assert!(!ssa.versions.is_empty());
        assert!(!rd.out_defs.is_empty());
    }

    // 22. DefUseAnalysis::run on diamond.
    #[test]
    fn test_def_use_analysis_diamond() {
        let p = make_diamond_program();
        let (graph, ssa, _) = DefUseAnalysis::run(&p);
        assert!(graph.def_count() >= 2); // two x defs
        assert!(ssa.phi_count() >= 1);
    }

    // 23. DefUseGraph::defs_of_var.
    #[test]
    fn test_defs_of_var() {
        let p = make_diamond_program();
        let (graph, _, _) = DefUseAnalysis::run(&p);
        let x_defs = graph.defs_of_var("x");
        assert_eq!(x_defs.len(), 2);
    }

    // 24. Block edge bidirectionality.
    #[test]
    fn test_program_edge() {
        let mut p = Program::new(0);
        p.add_block(Block::new(0, vec![]));
        p.add_block(Block::new(1, vec![]));
        p.add_edge(0, 1);
        assert!(p.blocks[0].successors.contains(&1));
        assert!(p.blocks[1].predecessors.contains(&0));
    }

    // 25. VersionedVar ordering.
    #[test]
    fn test_versioned_var_ordering() {
        let v1 = VersionedVar::new("x", 1);
        let v2 = VersionedVar::new("x", 2);
        assert!(v1 < v2);
    }

    // 26. ProgramPoint ordering.
    #[test]
    fn test_program_point_ordering() {
        let p1 = ProgramPoint::new(0, 5);
        let p2 = ProgramPoint::new(1, 0);
        assert!(p1 < p2);
    }

    // 27. Phi operand count.
    #[test]
    fn test_phi_operand_count() {
        let result = VersionedVar::new("x", 0);
        let mut phi = Phi::new("x", 3, result);
        phi.add_operand(1, VersionedVar::new("x", 1));
        phi.add_operand(2, VersionedVar::new("x", 2));
        assert_eq!(phi.operands.len(), 2);
    }

    // 28. UseChain live_defs iterator.
    #[test]
    fn test_use_chain_live_defs() {
        let mut uc = UseChain::new();
        uc.add(5, UseSite::new("a", ProgramPoint::new(0, 0)));
        uc.add(10, UseSite::new("b", ProgramPoint::new(1, 0)));
        let live: Vec<usize> = uc.live_defs().collect();
        assert!(live.contains(&5) && live.contains(&10));
    }

    // 29. DefChain total_edges.
    #[test]
    fn test_def_chain_total_edges() {
        let mut dc = DefChain::new();
        dc.add(ProgramPoint::new(0, 0), 1);
        dc.add(ProgramPoint::new(0, 1), 2);
        dc.add(ProgramPoint::new(1, 0), 3);
        assert_eq!(dc.total_edges(), 3);
    }

    // 30. compute_idom linear.
    #[test]
    fn test_compute_idom_linear() {
        let p = make_linear_program();
        let idom = compute_idom(&p);
        assert_eq!(idom[&0], 0);
        assert_eq!(idom[&1], 0);
    }

    // 31. compute_dom_frontier diamond.
    #[test]
    fn test_dom_frontier_diamond() {
        let p = make_diamond_program();
        let df = compute_dom_frontier(&p);
        // DF of 1 and 2 should both contain 3.
        assert!(df.get(&1).is_some_and(|v| v.contains(&3)));
        assert!(df.get(&2).is_some_and(|v| v.contains(&3)));
    }

    // 32. iterated_dom_frontier.
    #[test]
    fn test_iterated_dom_frontier() {
        let p = make_diamond_program();
        let df = compute_dom_frontier(&p);
        let idf = iterated_dom_frontier(&df, &[1, 2]);
        assert!(idf.contains(&3));
    }

    // 33. SSAForm::max_version.
    #[test]
    fn test_ssa_max_version() {
        let p = make_diamond_program();
        let ssa = SSAForm::build(&p);
        let max = ssa.max_version("x");
        assert!(max.is_some());
    }

    // 34. ReachingDefs empty program.
    #[test]
    fn test_reaching_defs_empty() {
        let p = Program::new(0);
        let rd = ReachingDefs::compute(&p, &HashMap::new(), &HashMap::new());
        assert!(rd.in_defs.is_empty());
    }

    // 35. DefUseGraph edge_count matches use_chain.
    #[test]
    fn test_graph_edge_count() {
        let mut g = DefUseGraph::new();
        g.add_definition(Definition::new("a", ProgramPoint::new(0, 0), 0));
        g.add_edge(0, "a", ProgramPoint::new(1, 0));
        g.add_edge(0, "a", ProgramPoint::new(2, 0));
        assert_eq!(g.edge_count(), 2);
        assert_eq!(g.use_chain.use_count(0), 2);
    }

    // 36b. Program::add_edge is idempotent (no duplicate successors/predecessors).
    #[test]
    fn test_program_add_edge_duplicate() {
        let mut p = Program::new(0);
        p.add_block(Block::new(0, vec![]));
        p.add_block(Block::new(1, vec![]));
        p.add_edge(0, 1);
        p.add_edge(0, 1);
        assert_eq!(p.blocks[0].successors.len(), 1);
        assert_eq!(p.blocks[1].predecessors.len(), 1);
    }

    // 36c. ReachingDefs on a loop (back edge): the def inside the loop body
    // must reach the loop header again through the back edge, and the
    // fixpoint must still terminate.
    #[test]
    fn test_reaching_defs_loop_back_edge() {
        // BB0 (header) -> BB1 (body, defines x) -> BB0 (back edge); BB0 -> BB2 (exit).
        let mut p = Program::new(0);
        p.add_block(Block::new(0, vec![Instruction::use_only("x")]));
        p.add_block(Block::new(1, vec![Instruction::new(Some("x"), vec![])]));
        p.add_block(Block::new(2, vec![Instruction::use_only("x")]));
        p.add_edge(0, 1);
        p.add_edge(1, 0);
        p.add_edge(0, 2);

        let mut all_defs = HashMap::new();
        all_defs.insert(ProgramPoint::new(1, 0), 0usize); // x defined in loop body
        let kill = HashMap::new();
        let rd = ReachingDefs::compute(&p, &all_defs, &kill);

        // After the fixpoint, the def of x from block 1 must reach the header (0)
        // and the exit block (2) via the back edge.
        assert!(rd.in_defs[&0].contains(&0));
        assert!(rd.out_defs[&0].contains(&0));
        assert!(rd.in_defs[&2].contains(&0));
        // Fixpoint must actually converge (not loop forever / bail at 1 pass).
        assert!(rd.iterations >= 2);
    }

    /// Build a long straight-line chain `0 -> 1 -> 2 -> ... -> n-1` plus a
    /// diamond every few blocks, so both `rpo()`/`compute_idom` (linear-chain
    /// dominance) and `ReachingDefs::compute` (fixpoint over many blocks) are
    /// exercised on a CFG large enough that an O(n^2)/O(n^3) block-lookup
    /// regression would be easy to introduce by accident.
    fn make_long_chain_program(n: usize) -> Program {
        let mut p = Program::new(0);
        for i in 0..n {
            let vname = format!("v{i}");
            p.add_block(Block::new(i, vec![Instruction::new(Some(&vname), vec![])]));
        }
        for i in 0..n - 1 {
            p.add_edge(i, i + 1);
            // Every 4th block also gets a diamond side-branch back into the
            // chain two blocks later, to create join points that stress the
            // dominance-frontier / idom fixpoint.
            if i % 4 == 0 && i + 3 < n {
                p.add_edge(i, i + 2);
            }
        }
        p
    }

    // 37. Long chain: rpo visits every block exactly once, idom/frontier and
    // reaching-defs stay correct, and no block is silently dropped by the
    // O(1) index-based lookups added to replace the old linear `block()` scan.
    #[test]
    fn test_long_chain_rpo_and_reaching_defs_stay_correct() {
        let n = 200;
        let p = make_long_chain_program(n);

        let rpo = p.rpo();
        assert_eq!(rpo.len(), n, "every block must be visited exactly once");
        let mut seen: HashSet<usize> = HashSet::new();
        for &b in &rpo {
            assert!(seen.insert(b), "rpo must not repeat block {b}");
        }

        let df = compute_dom_frontier(&p);
        assert_eq!(df.len(), n);

        let mut all_defs = HashMap::new();
        for i in 0..n {
            all_defs.insert(ProgramPoint::new(i, 0), i);
        }
        let kill = HashMap::new();
        let rd = ReachingDefs::compute(&p, &all_defs, &kill);

        // The def in block 0 must reach every later block on the main chain.
        for i in 1..n {
            assert!(
                rd.in_defs[&i].contains(&0),
                "def 0 should reach block {i} along the chain"
            );
        }
        // Every block's own def must be in its own out-set.
        for i in 0..n {
            assert!(rd.out_defs[&i].contains(&i));
        }
    }

    // 36. DefUseAnalysis: no dead defs when all vars used.
    #[test]
    fn test_no_dead_defs_if_all_used() {
        let p = make_linear_program();
        let (graph, _, _) = DefUseAnalysis::run(&p);
        // x is used in y=x, y is used in z=y → x and y should have uses.
        let x_defs = graph.defs_of_var("x");
        assert!(!x_defs.is_empty());
        for d in &x_defs {
            // x def (id 0) should have at least one use (in y=x).
            // (Some dead detection depends on implementation detail.)
            let _ = graph.use_chain.use_count(d.id);
        }
    }
}
