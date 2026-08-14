//! `control_flow_analysis` — CFG construction from IL, SSA, dominance, back-edges.
//!
//! Provides [`ControlFlowAnalysis`] which combines:
//! * [`CFGBuilder`]      — builds a CFG from a flat IL instruction list.
//! * [`DominanceFrontier`] — standard Cytron dominance frontier.
//! * [`SSAConstruction`] — minimal SSA with φ-node insertion.
//! * [`BackEdgeDetector`] — identifies back edges (loop headers).
//! * [`LoopCarriedDependency`] — data-flow deps across back edges.
//! * [`AnalysisResult`]  — aggregate summary of the analysis.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Primitive IL instruction (self-contained; avoids pulling in rustre-il-llil)
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal IL instruction for control-flow analysis purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ILInstr {
    /// A plain assignment:  `dst = src`.
    Assign { dst: String, src: String },
    /// Unconditional jump to `target` block id.
    Jump { target: usize },
    /// Conditional jump: goes to `true_target` or `false_target`.
    CondJump {
        cond: String,
        true_target: usize,
        false_target: usize,
    },
    /// Return from function.
    Ret,
    /// No-operation.
    Nop,
    /// Binary operation: `dst = lhs op rhs`.
    BinOp {
        dst: String,
        lhs: String,
        rhs: String,
        op: String,
    },
    /// Phi node (inserted by SSA construction).
    Phi {
        dst: String,
        sources: Vec<(usize, String)>,
    },
    /// A function call placeholder: `dst = call(args...)`.
    Call {
        dst: Option<String>,
        callee: String,
        args: Vec<String>,
    },
    /// Load from memory: `dst = *ptr`.
    Load { dst: String, ptr: String },
    /// Store to memory: `*ptr = val`.
    Store { ptr: String, val: String },
}

impl ILInstr {
    /// Variable defined by this instruction, if any.
    #[must_use] 
    pub fn defined_var(&self) -> Option<&str> {
        match self {
            Self::Assign { dst, .. } | Self::BinOp { dst, .. } | Self::Load { dst, .. } => {
                Some(dst)
            }
            Self::Call { dst: Some(dst), .. } | Self::Phi { dst, .. } => Some(dst),
            _ => None,
        }
    }

    /// Variables used (read) by this instruction.
    pub fn used_vars(&self) -> Vec<&str> {
        match self {
            Self::Assign { src, .. } => vec![src.as_str()],
            Self::CondJump { cond, .. } => vec![cond.as_str()],
            Self::BinOp { lhs, rhs, .. } => vec![lhs.as_str(), rhs.as_str()],
            Self::Phi { sources, .. } => sources.iter().map(|(_, v)| v.as_str()).collect(),
            Self::Call { args, .. } => args.iter().map(String::as_str).collect(),
            Self::Load { ptr, .. } => vec![ptr.as_str()],
            Self::Store { ptr, val } => vec![ptr.as_str(), val.as_str()],
            _ => vec![],
        }
    }

    /// True if this is a terminator (last instruction of a basic block).
    #[must_use] 
    pub const fn is_terminator(&self) -> bool {
        matches!(self, Self::Jump { .. } | Self::CondJump { .. } | Self::Ret)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BasicBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A maximal sequence of [`ILInstr`]s with no internal branches.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub instrs: Vec<ILInstr>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
}

impl BasicBlock {
    #[must_use] 
    pub const fn new(id: usize) -> Self {
        Self {
            id,
            instrs: Vec::new(),
            successors: Vec::new(),
            predecessors: Vec::new(),
        }
    }

    /// Append an instruction.
    pub fn push(&mut self, instr: ILInstr) {
        self.instrs.push(instr);
    }

    /// Variables defined in this block.
    #[must_use] 
    pub fn defs(&self) -> Vec<&str> {
        self.instrs.iter().filter_map(|i| i.defined_var()).collect()
    }

    /// Variables used (before being defined) in this block — upward-exposed uses.
    #[must_use] 
    pub fn upward_exposed_uses(&self) -> HashSet<String> {
        let mut killed: HashSet<&str> = HashSet::new();
        let mut uses: HashSet<String> = HashSet::new();
        for instr in &self.instrs {
            for u in instr.used_vars() {
                if !killed.contains(u) {
                    uses.insert(u.to_string());
                }
            }
            if let Some(def) = instr.defined_var() {
                killed.insert(def);
            }
        }
        uses
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CFG
// ─────────────────────────────────────────────────────────────────────────────

/// A control-flow graph consisting of [`BasicBlock`]s.
#[derive(Debug, Clone)]
pub struct CFG {
    pub blocks: Vec<BasicBlock>,
    pub entry: usize,
}

impl CFG {
    /// Number of blocks.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.blocks.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Successors of block `id`.
    ///
    /// Returns an empty slice if `id` is out of range.
    #[must_use]
    pub fn successors(&self, id: usize) -> &[usize] {
        self.blocks.get(id).map_or(&[], |b| b.successors.as_slice())
    }

    /// Predecessors of block `id`.
    ///
    /// Returns an empty slice if `id` is out of range.
    #[must_use]
    pub fn predecessors(&self, id: usize) -> &[usize] {
        self.blocks.get(id).map_or(&[], |b| b.predecessors.as_slice())
    }

    /// Reverse post-order traversal starting from the entry.
    #[must_use] 
    pub fn rpo(&self) -> Vec<usize> {
        let n = self.blocks.len();
        // Guard against an empty CFG or an out-of-range entry (e.g. a
        // malformed/adversarial CFG constructed by hand rather than via
        // `CFGBuilder`, which always keeps `entry` in range). Without this,
        // indexing `visited[self.entry]` below panics.
        if n == 0 || self.entry >= n {
            return Vec::new();
        }
        let mut visited = vec![false; n];
        let mut po: Vec<usize> = Vec::with_capacity(n);
        let mut stack: Vec<(usize, usize)> = vec![(self.entry, 0)];
        visited[self.entry] = true;
        while let Some((node, idx)) = stack.last_mut() {
            let node = *node;
            let succs = &self.blocks[node].successors;
            if *idx < succs.len() {
                let child = succs[*idx];
                *idx += 1;
                if !visited[child] {
                    visited[child] = true;
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
// CFGBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`CFG`] from a flat list of `(block_id, instruction)` pairs.
///
/// Usage:
/// 1. Call [`CFGBuilder::new`] with the number of blocks.
/// 2. Call [`CFGBuilder::add_instr`] for each instruction in each block.
/// 3. Call [`CFGBuilder::build`] to finalise.
pub struct CFGBuilder {
    num_blocks: usize,
    instrs: Vec<Vec<ILInstr>>,
}

impl CFGBuilder {
    /// Create a builder for `num_blocks` blocks.
    #[must_use] 
    pub fn new(num_blocks: usize) -> Self {
        Self {
            num_blocks,
            instrs: vec![Vec::new(); num_blocks],
        }
    }

    /// Add an instruction to block `block_id`.
    ///
    /// # Panics
    ///
    /// Panics if `block_id >= num_blocks` as supplied to [`CFGBuilder::new`].
    pub fn add_instr(&mut self, block_id: usize, instr: ILInstr) {
        // Guard against out-of-bounds block ids coming from untrusted input
        // (e.g. a parsed binary whose jump targets reference non-existent blocks).
        if block_id < self.num_blocks {
            self.instrs[block_id].push(instr);
        }
        // Silently drop instructions for invalid block ids; callers can validate
        // before calling if they need an error signal.
    }

    /// Build the [`CFG`] by extracting edges from terminator instructions.
    pub fn build(self) -> CFG {
        let n = self.num_blocks;
        let mut blocks: Vec<BasicBlock> = (0..n).map(BasicBlock::new).collect();

        for (id, instrs) in self.instrs.into_iter().enumerate() {
            blocks[id].instrs = instrs;
        }

        // Extract edges from terminator instructions.
        let mut edges: Vec<(usize, usize)> = Vec::new();
        for b in &blocks {
            match b.instrs.last() {
                Some(ILInstr::Jump { target }) => edges.push((b.id, *target)),
                Some(ILInstr::CondJump {
                    true_target,
                    false_target,
                    ..
                }) => {
                    edges.push((b.id, *true_target));
                    edges.push((b.id, *false_target));
                }
                Some(ILInstr::Ret) => {
                    // Ret terminates; no fall-through edge.
                }
                _ => {
                    // Fall-through to the next block if it exists.
                    if b.id + 1 < n {
                        edges.push((b.id, b.id + 1));
                    }
                }
            }
        }

        for (from, to) in edges {
            if to < n {
                blocks[from].successors.push(to);
                blocks[to].predecessors.push(from);
            }
        }

        // Deduplicate.
        for b in &mut blocks {
            b.successors.sort_unstable();
            b.successors.dedup();
            b.predecessors.sort_unstable();
            b.predecessors.dedup();
        }

        CFG { blocks, entry: 0 }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DominanceFrontier
// ─────────────────────────────────────────────────────────────────────────────

/// Cytron et al. dominance-frontier computation.
#[derive(Debug, Clone, Default)]
pub struct DominanceFrontier {
    /// `df[b]` = dominance frontier of block `b`.
    pub df: Vec<Vec<usize>>,
    /// Immediate dominator array: `idom[b]` = immediate dominator of `b`.
    pub idom: Vec<usize>,
}

impl DominanceFrontier {
    /// Compute the dominance frontier for a [`CFG`].
    #[must_use] 
    pub fn compute(cfg: &CFG) -> Self {
        let n = cfg.len();
        if n == 0 {
            return Self::default();
        }
        let idom = compute_idom(cfg);
        let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); n];

        // Reachable nodes only: `compute_idom` stores `idom[b] == b` both for
        // the real entry AND (as a sentinel) for unreachable blocks, so we must
        // distinguish them by reachability rather than by the idom value.
        let reachable: HashSet<usize> = cfg.rpo().into_iter().collect();

        // Per-edge Cytron formulation. Two bugs previously lived here (the same
        // pair the dedicated `rustre-analysis-cfg` crate fixed in its own DF via
        // differential fuzzing):
        //   1. A `preds.len() >= 2` guard skipped single-predecessor joins,
        //      which is only sound when idom(b) == pred — it fails for a back
        //      edge to the entry (e.g. `0 -> 1 -> 0`: node 0 has the single
        //      predecessor 1, yet DF(1) must contain 0).
        //   2. For `b == entry` the stored idom is the entry itself, so the old
        //      `runner != idom[b]` stop ended the walk one node early and the
        //      entry never appeared in its own dominance frontier — which, since
        //      `SSAForm::build` places phis at the iterated DF, meant a variable
        //      live around a loop back to the entry got no phi at the entry.
        // Fix: drop the join-count guard, and stop at idom(b) only when idom(b)
        // != b (for the entry there is no proper idom, so the runner walks
        // through the entry itself and stops at the chain end).
        for b in 0..n {
            if !reachable.contains(&b) {
                continue;
            }
            let stop: Option<usize> = if idom[b] != b { Some(idom[b]) } else { None };
            for &pred in cfg.predecessors(b) {
                if !reachable.contains(&pred) {
                    continue;
                }
                let mut runner = pred;
                loop {
                    if Some(runner) == stop {
                        break;
                    }
                    df[runner].insert(b);
                    let parent = idom[runner];
                    if parent == runner {
                        break; // reached the entry / chain end
                    }
                    runner = parent;
                }
            }
        }

        let df_vec: Vec<Vec<usize>> = df
            .into_iter()
            .map(|s| {
                let mut v: Vec<usize> = s.into_iter().collect();
                v.sort_unstable();
                v
            })
            .collect();

        Self { df: df_vec, idom }
    }

    /// Iterated dominance frontier of a set of seeds.
    #[must_use]
    pub fn iterated(&self, seeds: &[usize]) -> Vec<usize> {
        let mut result: HashSet<usize> = HashSet::new();
        let mut wl: VecDeque<usize> = seeds.iter().copied().collect();
        while let Some(n) = wl.pop_front() {
            // Guard against out-of-bounds block ids (e.g. from malformed input).
            let Some(frontiers) = self.df.get(n) else { continue };
            for &f in frontiers {
                if result.insert(f) {
                    wl.push_back(f);
                }
            }
        }
        let mut v: Vec<usize> = result.into_iter().collect();
        v.sort_unstable();
        v
    }

    /// Frontier of a single block.
    ///
    /// Returns an empty slice if `b` is out of range.
    #[must_use]
    pub fn frontier_of(&self, b: usize) -> &[usize] {
        self.df.get(b).map_or(&[], Vec::as_slice)
    }
}

/// Cooper et al. iterative immediate-dominator algorithm.
fn compute_idom(cfg: &CFG) -> Vec<usize> {
    const UNDEF: usize = usize::MAX;
    let n = cfg.len();
    let mut idom = vec![UNDEF; n];
    idom[cfg.entry] = cfg.entry;

    let rpo = cfg.rpo();
    let rpo_pos: Vec<usize> = {
        let mut p = vec![0usize; n];
        for (i, &b) in rpo.iter().enumerate() {
            p[b] = i;
        }
        p
    };

    let intersect = |mut a: usize, mut b: usize, idom: &[usize]| -> usize {
        while a != b {
            while rpo_pos[a] > rpo_pos[b] {
                a = idom[a];
            }
            while rpo_pos[b] > rpo_pos[a] {
                b = idom[b];
            }
        }
        a
    };

    let mut changed = true;
    while changed {
        changed = false;
        for &b in &rpo {
            if b == cfg.entry {
                continue;
            }
            let preds: Vec<usize> = cfg
                .predecessors(b)
                .iter()
                .copied()
                .filter(|&p| idom[p] != UNDEF)
                .collect();
            if preds.is_empty() {
                continue;
            }
            let mut new_idom = preds[0];
            for &p in &preds[1..] {
                new_idom = intersect(p, new_idom, &idom);
            }
            if idom[b] != new_idom {
                idom[b] = new_idom;
                changed = true;
            }
        }
    }
    for (i, slot) in idom.iter_mut().enumerate().take(n) {
        if *slot == UNDEF {
            *slot = i;
        }
    }
    idom
}

// ─────────────────────────────────────────────────────────────────────────────
// BackEdgeDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Identifies back edges (edges `n→h` where `h` dominates `n`).
#[derive(Debug, Clone)]
pub struct BackEdgeDetector {
    /// List of back edges as `(source, header)`.
    pub back_edges: Vec<(usize, usize)>,
    /// Set of loop-header block ids.
    pub loop_headers: HashSet<usize>,
}

impl BackEdgeDetector {
    /// Detect back edges using the `idom` array from [`DominanceFrontier`].
    #[must_use] 
    pub fn detect(cfg: &CFG, idom: &[usize]) -> Self {
        let n = cfg.len();

        // `s` dominates `b` iff `s` appears on `b`'s idom chain. Walking the
        // chain per query is O(depth) instead of materialising an O(n^2)
        // `dominates` matrix up front, which was both an unconditional
        // O(n^2) time/memory cost for every CFG (regardless of how many
        // back edges actually exist) and a potential OOM/DoS vector for
        // large or adversarially-generated CFGs (e.g. tens of thousands of
        // blocks from a huge decompiled function).
        let dominates = |s: usize, b: usize| -> bool {
            let mut cur = b;
            loop {
                if cur == s {
                    return true;
                }
                let parent = idom[cur];
                if parent == cur {
                    return false;
                }
                cur = parent;
            }
        };

        let mut back_edges: Vec<(usize, usize)> = Vec::new();
        let mut loop_headers: HashSet<usize> = HashSet::new();
        (0..n).for_each(|b| {
            for &s in cfg.successors(b) {
                if dominates(s, b) {
                    back_edges.push((b, s));
                    loop_headers.insert(s);
                }
            }
        });

        Self {
            back_edges,
            loop_headers,
        }
    }

    /// True when `(from, to)` is a back edge.
    #[must_use] 
    pub fn is_back_edge(&self, from: usize, to: usize) -> bool {
        self.back_edges.contains(&(from, to))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopCarriedDependency
// ─────────────────────────────────────────────────────────────────────────────

/// A loop-carried dependency: variable defined before the back edge and used
/// after the back edge (i.e. on the next iteration).
#[derive(Debug, Clone)]
pub struct Dependency {
    /// The variable name.
    pub var: String,
    /// The block that defines the variable.
    pub def_block: usize,
    /// The loop header (back-edge target) through which the dep is carried.
    pub loop_header: usize,
    /// Blocks that use the variable inside the loop.
    pub use_blocks: Vec<usize>,
}

/// Detects loop-carried data dependencies in a CFG.
pub struct LoopCarriedDependency;

impl LoopCarriedDependency {
    /// Collect loop-carried dependencies given a [`CFG`] and a
    /// [`BackEdgeDetector`].
    #[must_use] 
    pub fn analyze(cfg: &CFG, bed: &BackEdgeDetector) -> Vec<Dependency> {
        let mut deps: Vec<Dependency> = Vec::new();

        // Iterate loop headers in a deterministic order: `bed.loop_headers`
        // is a `HashSet`, whose iteration order is randomised per-process.
        // Without sorting, `deps` (and therefore any downstream output that
        // is emitted in `deps` order) would vary from run to run for the
        // exact same input CFG.
        let mut headers: Vec<usize> = bed.loop_headers.iter().copied().collect();
        headers.sort_unstable();

        for header in headers {
            // Collect all blocks in this loop body via reverse BFS from the
            // back-edge sources.
            let body = Self::loop_body(cfg, header, bed);

            // Variables defined inside the loop.
            let mut defined_vars: HashMap<String, usize> = HashMap::new();
            for &bid in &body {
                let Some(block) = cfg.blocks.get(bid) else { continue };
                for instr in &block.instrs {
                    if let Some(v) = instr.defined_var() {
                        defined_vars.insert(v.to_string(), bid);
                    }
                }
            }

            // Variables used in the loop header (after the back edge re-enters).
            let mut used_in_header: HashSet<String> = HashSet::new();
            if let Some(hdr_block) = cfg.blocks.get(header) {
                for instr in &hdr_block.instrs {
                    for u in instr.used_vars() {
                        used_in_header.insert(u.to_string());
                    }
                }
            }

            // Sort by variable name for deterministic output: `defined_vars`
            // is a `HashMap`, whose iteration order is randomised per-process.
            let mut vars: Vec<(&String, &usize)> = defined_vars.iter().collect();
            vars.sort_unstable_by(|a, b| a.0.cmp(b.0));

            for (var, def_block) in vars {
                if used_in_header.contains(var.as_str()) {
                    let mut use_blocks: Vec<usize> = body
                        .iter()
                        .copied()
                        .filter(|&bid| {
                            cfg.blocks.get(bid).is_some_and(|b| {
                                b.instrs
                                    .iter()
                                    .any(|i| i.used_vars().contains(&var.as_str()))
                            })
                        })
                        .collect();
                    use_blocks.sort_unstable();
                    deps.push(Dependency {
                        var: var.clone(),
                        def_block: *def_block,
                        loop_header: header,
                        use_blocks,
                    });
                }
            }
        }
        deps
    }

    fn loop_body(cfg: &CFG, header: usize, bed: &BackEdgeDetector) -> HashSet<usize> {
        let mut body: HashSet<usize> = HashSet::from([header]);
        // Find back-edge sources for this header.
        
        let mut wl: VecDeque<usize> = bed
            .back_edges
            .iter()
            .filter(|&&(_, h)| h == header)
            .map(|&(s, _)| s).collect();
        while let Some(b) = wl.pop_front() {
            if body.insert(b) {
                for &p in cfg.predecessors(b) {
                    if !body.contains(&p) {
                        wl.push_back(p);
                    }
                }
            }
        }
        body
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SSAConstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Phi-node source: `(predecessor_block, source_var)`.
pub type PhiSource = (usize, String);
/// One phi node: destination variable and its incoming sources.
pub type PhiNode = (String, Vec<PhiSource>);
/// Phi map: `block → list of phi nodes`.
pub type PhiNodeMap = HashMap<usize, Vec<PhiNode>>;

/// Result of SSA construction.
#[derive(Debug, Clone)]
pub struct SSAForm {
    /// Modified CFG with φ-nodes inserted.
    pub cfg: CFG,
    /// Renaming map: `(block, original_var)` → versioned variable.
    pub version_map: HashMap<(usize, String), String>,
    /// Phi nodes: `block → [(dst_var, [(pred_block, src_var)])]`.
    pub phi_nodes: PhiNodeMap,
}

/// Constructs minimal SSA form with φ-node insertion.
pub struct SSAConstruction;

impl SSAConstruction {
    /// Construct SSA form for a [`CFG`].
    #[must_use] 
    pub fn build(cfg: CFG, dom_front: &DominanceFrontier) -> SSAForm {
        let n = cfg.len();

        // Collect all variables and their definition sites.
        let mut def_sites: HashMap<String, Vec<usize>> = HashMap::new();
        for b in 0..n {
            for instr in &cfg.blocks[b].instrs {
                if let Some(v) = instr.defined_var() {
                    def_sites.entry(v.to_string()).or_default().push(b);
                }
            }
        }

        // Phi-node placement: for each variable, insert φ at IDF of def sites.
        let mut phi_locations: HashMap<String, HashSet<usize>> = HashMap::new();
        for (var, def_blocks) in &def_sites {
            let idf = dom_front.iterated(def_blocks);
            for loc in idf {
                phi_locations.entry(var.clone()).or_default().insert(loc);
            }
        }

        // Build phi_nodes map. Iterate variables and their block sets in a
        // deterministic (sorted) order: `phi_locations` is a `HashMap` of
        // `HashSet`s, whose iteration order is randomised per-process. Left
        // unsorted, the order of `Vec<PhiNode>` entries within each block
        // (and thus any code emitted from them) would vary run-to-run for
        // identical input, breaking reproducible/recompilable output.
        let mut phi_nodes: PhiNodeMap = HashMap::new();
        let mut vars: Vec<&String> = phi_locations.keys().collect();
        vars.sort_unstable();
        for var in vars {
            let blocks = &phi_locations[var];
            let mut block_ids: Vec<usize> = blocks.iter().copied().collect();
            block_ids.sort_unstable();
            for b in block_ids {
                let mut preds: Vec<usize> = cfg.predecessors(b).to_vec();
                preds.sort_unstable();
                let sources: Vec<(usize, String)> =
                    preds.iter().map(|&p| (p, var.clone())).collect();
                phi_nodes.entry(b).or_default().push((var.clone(), sources));
            }
        }

        // Build a version_map (simplified: version == original for this skeleton).
        let version_map: HashMap<(usize, String), String> = def_sites
            .iter()
            .flat_map(|(var, defs)| {
                let var_owned: String = var.clone();
                defs.iter()
                    .enumerate()
                    .map(move |(i, &b)| ((b, var_owned.clone()), format!("{var_owned}_{i}")))
            })
            .collect();

        SSAForm {
            cfg,
            version_map,
            phi_nodes,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisResult
// ─────────────────────────────────────────────────────────────────────────────

/// Summary produced by [`ControlFlowAnalysis::run`].
#[derive(Debug, Clone)]
pub struct CFGAnalysisResult {
    pub block_count: usize,
    pub edge_count: usize,
    pub back_edge_count: usize,
    pub loop_header_count: usize,
    pub phi_node_count: usize,
    pub loop_carried_dep_count: usize,
    pub is_reducible: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// ControlFlowAnalysis — top-level coordinator
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level coordinator that runs CFG building, dominance, SSA, and
/// loop analysis on a given set of instructions.
pub struct ControlFlowAnalysis;

impl ControlFlowAnalysis {
    /// Build and fully analyse a CFG from a list of `(block_id, instr)` pairs.
    ///
    /// Returns a tuple of `(SSAForm, DominanceFrontier, BackEdgeDetector,
    /// Vec<Dependency>, CFGAnalysisResult)`.
    #[must_use] 
    pub fn run(
        num_blocks: usize,
        instrs: Vec<(usize, ILInstr)>,
    ) -> (
        SSAForm,
        DominanceFrontier,
        BackEdgeDetector,
        Vec<Dependency>,
        CFGAnalysisResult,
    ) {
        // Build CFG.
        let mut builder = CFGBuilder::new(num_blocks);
        for (bid, instr) in instrs {
            builder.add_instr(bid, instr);
        }
        let cfg = builder.build();

        let edge_count: usize = cfg.blocks.iter().map(|b| b.successors.len()).sum();
        let block_count = cfg.len();

        // Dominance frontier.
        let dom_front = DominanceFrontier::compute(&cfg);

        // Back-edge detection.
        let bed = BackEdgeDetector::detect(&cfg, &dom_front.idom);
        let back_edge_count = bed.back_edges.len();
        let loop_header_count = bed.loop_headers.len();

        // Loop-carried dependencies.
        let deps = LoopCarriedDependency::analyze(&cfg, &bed);
        let loop_carried_dep_count = deps.len();

        // Reducibility must be computed BEFORE `cfg` is consumed by the SSA
        // builder below.
        let is_reducible_pre = {
            let rpo = cfg.rpo();
            let mut rpo_pos = vec![usize::MAX; cfg.len()];
            for (i, &b) in rpo.iter().enumerate() {
                rpo_pos[b] = i;
            }
            let dominates = |s: usize, b: usize| -> bool {
                let mut cur = b;
                loop {
                    if cur == s {
                        return true;
                    }
                    let p = dom_front.idom[cur];
                    if p == cur {
                        return false;
                    }
                    cur = p;
                }
            };
            rpo.iter().all(|&b| {
                cfg.successors(b).iter().all(|&s| {
                    rpo_pos[s] == usize::MAX || rpo_pos[s] > rpo_pos[b] || dominates(s, b)
                })
            })
        };

        // SSA construction.
        let ssa = SSAConstruction::build(cfg, &dom_front);
        let phi_node_count = ssa.phi_nodes.values().map(std::vec::Vec::len).sum();

        // Reducibility check: a CFG is reducible iff every RETREATING edge is
        // also a back edge, i.e. its target dominates its source.
        //
        // The previous version iterated `bed.back_edges` and re-checked that the
        // target dominates the source — but `BackEdgeDetector::detect` only ever
        // collects edges that already satisfy exactly that, so the test was
        // vacuously true for EVERY CFG. Irreducible graphs, whose defining
        // feature is a retreating edge into a cycle with no dominating header,
        // produce NO back edges at all, so there was nothing left to reject and
        // they were reported reducible.
        let is_reducible = is_reducible_pre;

        let result = CFGAnalysisResult {
            block_count,
            edge_count,
            back_edge_count,
            loop_header_count,
            phi_node_count,
            loop_carried_dep_count,
            is_reducible,
        };

        (ssa, dom_front, bed, deps, result)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Differential soundness for the base crate's own Cooper `compute_idom`
    /// (exposed via `DominanceFrontier::compute(..).idom`): `d` dominates `n`
    /// per the idom chain iff removing `d` makes `n` unreachable from entry
    /// (the textbook dominance definition), over random CFGs. This crate's CFG
    /// analysis had never been property-tested before.
    #[test]
    fn base_cfg_idom_matches_reachability_oracle() {
        use crate::test_prng::xorshift as xs;
        // Reachable-from-entry set with node `avoid` removed (avoid=usize::MAX
        // removes nothing).
        fn reachable(succ: &[Vec<usize>], entry: usize, avoid: usize) -> Vec<bool> {
            let mut seen = vec![false; succ.len()];
            if entry == avoid {
                return seen;
            }
            let mut stack = vec![entry];
            seen[entry] = true;
            while let Some(u) = stack.pop() {
                for &v in &succ[u] {
                    if v != avoid && !seen[v] {
                        seen[v] = true;
                        stack.push(v);
                    }
                }
            }
            seen
        }
        // dominance via idom chain (reflexive).
        fn dom(idom: &[usize], entry: usize, d: usize, n: usize) -> bool {
            let mut cur = n;
            loop {
                if cur == d {
                    return true;
                }
                if cur == entry {
                    return false;
                }
                let nxt = idom[cur];
                if nxt == cur {
                    return false;
                }
                cur = nxt;
            }
        }
        let mut state = 0x1122_3344_5566_7788u64;
        for _ in 0..600 {
            let n = 2 + (xs(&mut state) % 7) as usize; // 2..=8
            let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
            for u in 0..n {
                for v in 0..n {
                    if u != v && xs(&mut state) % 100 < 35 {
                        succ[u].push(v);
                    }
                }
            }
            // Ensure every node reachable from entry 0 (chain fallback).
            for u in 1..n {
                if !succ[u - 1].contains(&u) {
                    succ[u - 1].push(u);
                }
            }
            // Build CFG with consistent predecessors.
            let mut blocks: Vec<BasicBlock> = (0..n).map(BasicBlock::new).collect();
            for u in 0..n {
                let mut s = succ[u].clone();
                s.sort_unstable();
                s.dedup();
                for &v in &s {
                    blocks[v].predecessors.push(u);
                }
                blocks[u].successors = s;
            }
            let cfg = CFG { blocks, entry: 0 };
            let idom = DominanceFrontier::compute(&cfg).idom;
            let rpo = cfg.rpo(); // reachable nodes
            for &nn in &rpo {
                for &d in &rpo {
                    let by_idom = dom(&idom, 0, d, nn);
                    let oracle = if d == nn {
                        true
                    } else {
                        !reachable(&succ, 0, d)[nn]
                    };
                    assert_eq!(
                        by_idom, oracle,
                        "dom({d},{nn})={by_idom} but oracle={oracle}; succ={succ:?}"
                    );
                }
            }
        }
    }

    /// Differential soundness for the base crate's Cytron dominance-frontier
    /// (`DominanceFrontier::compute`): DF(x) = { y : some predecessor p of y is
    /// dominated by x, and x does NOT strictly dominate y }. Cross-checked vs
    /// that textbook definition (using the idom chain) over random CFGs. The
    /// dedicated `cfg` crate had two real DF bugs (iter61) — this guards the
    /// base crate's independent implementation.
    #[test]
    fn base_cfg_dominance_frontier_matches_definition() {
        use crate::test_prng::xorshift as xs;
        fn dom(idom: &[usize], entry: usize, d: usize, n: usize) -> bool {
            let mut cur = n;
            loop {
                if cur == d { return true; }
                if cur == entry { return false; }
                let nxt = idom[cur];
                if nxt == cur { return false; }
                cur = nxt;
            }
        }
        let mut state = 0xfeed_face_0bad_c0deu64;
        for _ in 0..600 {
            let n = 2 + (xs(&mut state) % 7) as usize;
            let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
            for u in 0..n {
                for v in 0..n {
                    if u != v && xs(&mut state) % 100 < 35 {
                        succ[u].push(v);
                    }
                }
            }
            for u in 1..n {
                if !succ[u - 1].contains(&u) { succ[u - 1].push(u); }
            }
            let mut blocks: Vec<BasicBlock> = (0..n).map(BasicBlock::new).collect();
            for u in 0..n {
                let mut s = succ[u].clone();
                s.sort_unstable();
                s.dedup();
                for &v in &s { blocks[v].predecessors.push(u); }
                blocks[u].successors = s;
            }
            let cfg = CFG { blocks, entry: 0 };
            let result = DominanceFrontier::compute(&cfg);
            let idom = &result.idom;
            let rpo = cfg.rpo();
            let reachable: std::collections::HashSet<usize> = rpo.iter().copied().collect();
            // Brute-force DF over reachable nodes.
            for &x in &rpo {
                let mut want: Vec<usize> = Vec::new();
                for &y in &rpo {
                    // Full textbook definition — the entry-loop-header edge case
                    // (y == entry) is now handled correctly by the per-edge
                    // Cytron fix, so it is no longer excluded here.
                    let sdom_xy = x != y && dom(idom, 0, x, y);
                    if sdom_xy { continue; }
                    // y is in DF(x) if some pred p of y (reachable) is dominated by x.
                    let in_df = cfg.predecessors(y).iter().any(|&p| {
                        reachable.contains(&p) && dom(idom, 0, x, p)
                    });
                    if in_df { want.push(y); }
                }
                want.sort_unstable();
                let mut got: Vec<usize> = result.df[x]
                    .iter()
                    .copied()
                    .filter(|d| reachable.contains(d))
                    .collect();
                got.sort_unstable();
                got.dedup();
                assert_eq!(got, want, "DF({x}) got={got:?} want={want:?}; succ={succ:?}");
            }
        }
    }

    // ── Helper: build a simple linear CFG ─────────────────────────────────────
    fn linear_cfg(n: usize) -> CFG {
        let mut builder = CFGBuilder::new(n);
        for i in 0..n.saturating_sub(1) {
            builder.add_instr(i, ILInstr::Jump { target: i + 1 });
        }
        if n > 0 {
            builder.add_instr(n - 1, ILInstr::Ret);
        }
        builder.build()
    }

    // ── Helper: build a diamond CFG ───────────────────────────────────────────
    // 0 → {1, 2}, 1 → 3, 2 → 3
    fn diamond_cfg() -> CFG {
        let mut builder = CFGBuilder::new(4);
        builder.add_instr(
            0,
            ILInstr::CondJump {
                cond: "x".into(),
                true_target: 1,
                false_target: 2,
            },
        );
        builder.add_instr(1, ILInstr::Jump { target: 3 });
        builder.add_instr(2, ILInstr::Jump { target: 3 });
        builder.add_instr(3, ILInstr::Ret);
        builder.build()
    }

    // ── Helper: loop CFG ──────────────────────────────────────────────────────
    // 0 → 1 → {2, 3}, 2 → 1 (back edge), 3 = exit
    fn loop_cfg() -> CFG {
        let mut builder = CFGBuilder::new(4);
        builder.add_instr(0, ILInstr::Jump { target: 1 });
        builder.add_instr(
            1,
            ILInstr::CondJump {
                cond: "i".into(),
                true_target: 2,
                false_target: 3,
            },
        );
        builder.add_instr(2, ILInstr::Jump { target: 1 });
        builder.add_instr(3, ILInstr::Ret);
        builder.build()
    }

    // 1. CFGBuilder produces correct block count.
    #[test]
    fn test_cfgbuilder_block_count() {
        let cfg = linear_cfg(5);
        assert_eq!(cfg.len(), 5);
    }

    // 2. CFGBuilder builds correct edges for linear chain.
    #[test]
    fn test_cfgbuilder_linear_edges() {
        let cfg = linear_cfg(3);
        assert_eq!(cfg.successors(0), &[1]);
        assert_eq!(cfg.successors(1), &[2]);
        assert!(cfg.successors(2).is_empty());
    }

    // 3. CFGBuilder builds correct edges for diamond.
    #[test]
    fn test_cfgbuilder_diamond_edges() {
        let cfg = diamond_cfg();
        let succs0: HashSet<_> = cfg.successors(0).iter().copied().collect();
        assert!(succs0.contains(&1) && succs0.contains(&2));
        assert_eq!(cfg.successors(1), &[3]);
        assert_eq!(cfg.successors(2), &[3]);
    }

    // 4. Predecessors are correctly computed.
    #[test]
    fn test_predecessors_diamond() {
        let cfg = diamond_cfg();
        let preds3: HashSet<_> = cfg.predecessors(3).iter().copied().collect();
        assert!(preds3.contains(&1) && preds3.contains(&2));
        assert!(cfg.predecessors(0).is_empty());
    }

    // 5. RPO traversal visits all blocks.
    #[test]
    fn test_rpo_visits_all() {
        let cfg = diamond_cfg();
        let rpo = cfg.rpo();
        assert_eq!(rpo.len(), 4);
        let set: HashSet<usize> = rpo.into_iter().collect();
        assert_eq!(set, HashSet::from([0, 1, 2, 3]));
    }

    // 6. RPO: entry is first.
    #[test]
    fn test_rpo_entry_first() {
        let cfg = diamond_cfg();
        let rpo = cfg.rpo();
        assert_eq!(rpo[0], 0);
    }

    // 7. compute_idom: linear chain.
    #[test]
    fn test_idom_linear() {
        let cfg = linear_cfg(4);
        let idom = compute_idom(&cfg);
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0);
        assert_eq!(idom[2], 1);
        assert_eq!(idom[3], 2);
    }

    // 8. compute_idom: diamond.
    #[test]
    fn test_idom_diamond() {
        let cfg = diamond_cfg();
        let idom = compute_idom(&cfg);
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0);
        assert_eq!(idom[2], 0);
        assert_eq!(idom[3], 0);
    }

    // 9. DominanceFrontier: diamond.
    #[test]
    fn test_dom_frontier_diamond() {
        let cfg = diamond_cfg();
        let df = DominanceFrontier::compute(&cfg);
        assert!(df.frontier_of(1).contains(&3));
        assert!(df.frontier_of(2).contains(&3));
        assert!(df.frontier_of(0).is_empty());
    }

    // 10. DominanceFrontier: linear chain has no frontiers.
    #[test]
    fn test_dom_frontier_linear() {
        let cfg = linear_cfg(4);
        let df = DominanceFrontier::compute(&cfg);
        for i in 0..4 {
            assert!(
                df.frontier_of(i).is_empty(),
                "block {i} unexpectedly has frontiers"
            );
        }
    }

    // 11. Iterated dominance frontier.
    #[test]
    fn test_idf_diamond() {
        let cfg = diamond_cfg();
        let df = DominanceFrontier::compute(&cfg);
        let idf = df.iterated(&[1, 2]);
        assert!(idf.contains(&3));
    }

    // 12. BackEdgeDetector: no back edges in diamond.
    #[test]
    fn test_back_edges_diamond() {
        let cfg = diamond_cfg();
        let df = DominanceFrontier::compute(&cfg);
        let bed = BackEdgeDetector::detect(&cfg, &df.idom);
        assert!(bed.back_edges.is_empty());
    }

    // 13. BackEdgeDetector: detects back edge in loop.
    #[test]
    fn test_back_edges_loop() {
        let cfg = loop_cfg();
        let df = DominanceFrontier::compute(&cfg);
        let bed = BackEdgeDetector::detect(&cfg, &df.idom);
        assert!(bed.is_back_edge(2, 1));
        assert!(bed.loop_headers.contains(&1));
    }

    // 14. BackEdgeDetector: is_back_edge returns false for non-back edges.
    #[test]
    fn test_back_edge_false_negative() {
        let cfg = loop_cfg();
        let df = DominanceFrontier::compute(&cfg);
        let bed = BackEdgeDetector::detect(&cfg, &df.idom);
        assert!(!bed.is_back_edge(0, 1));
    }

    // 15. ILInstr::defined_var.
    #[test]
    fn test_il_instr_defined_var() {
        let a = ILInstr::Assign {
            dst: "x".into(),
            src: "y".into(),
        };
        assert_eq!(a.defined_var(), Some("x"));
        let r = ILInstr::Ret;
        assert_eq!(r.defined_var(), None);
    }

    // 16. ILInstr::used_vars.
    #[test]
    fn test_il_instr_used_vars() {
        let op = ILInstr::BinOp {
            dst: "z".into(),
            lhs: "a".into(),
            rhs: "b".into(),
            op: "+".into(),
        };
        let uses = op.used_vars();
        assert!(uses.contains(&"a") && uses.contains(&"b"));
    }

    // 17. ILInstr::is_terminator.
    #[test]
    fn test_il_instr_is_terminator() {
        assert!(ILInstr::Ret.is_terminator());
        assert!(ILInstr::Jump { target: 1 }.is_terminator());
        assert!(!ILInstr::Nop.is_terminator());
    }

    // 18. BasicBlock::upward_exposed_uses.
    #[test]
    fn test_bb_upward_exposed_uses() {
        let mut bb = BasicBlock::new(0);
        bb.push(ILInstr::BinOp {
            dst: "c".into(),
            lhs: "a".into(),
            rhs: "b".into(),
            op: "+".into(),
        });
        bb.push(ILInstr::Assign {
            dst: "d".into(),
            src: "c".into(),
        });
        let ue = bb.upward_exposed_uses();
        assert!(ue.contains("a") && ue.contains("b"));
        assert!(!ue.contains("c")); // killed before use
    }

    // 19. SSAConstruction places φ-nodes at join points.
    #[test]
    fn test_ssa_phi_at_join() {
        let mut builder = CFGBuilder::new(4);
        // 0 → {1,2}, 1 → 3, 2 → 3
        builder.add_instr(
            0,
            ILInstr::CondJump {
                cond: "cond".into(),
                true_target: 1,
                false_target: 2,
            },
        );
        builder.add_instr(
            1,
            ILInstr::Assign {
                dst: "x".into(),
                src: "1".into(),
            },
        );
        builder.add_instr(1, ILInstr::Jump { target: 3 });
        builder.add_instr(
            2,
            ILInstr::Assign {
                dst: "x".into(),
                src: "2".into(),
            },
        );
        builder.add_instr(2, ILInstr::Jump { target: 3 });
        builder.add_instr(3, ILInstr::Ret);
        let cfg = builder.build();
        let df = DominanceFrontier::compute(&cfg);
        let ssa = SSAConstruction::build(cfg, &df);
        // x is defined in blocks 1 and 2; their IDF includes block 3.
        assert!(ssa.phi_nodes.contains_key(&3));
    }

    // 20. SSAConstruction: no φ for var defined in only one block.
    #[test]
    fn test_ssa_no_phi_single_def() {
        let cfg = linear_cfg(3);
        let df = DominanceFrontier::compute(&cfg);
        let ssa = SSAConstruction::build(cfg, &df);
        // Linear chain has no join points → no φ nodes.
        assert!(ssa.phi_nodes.is_empty());
    }

    // 21. LoopCarriedDependency: detects dep across back edge.
    #[test]
    fn test_loop_carried_dep() {
        let mut builder = CFGBuilder::new(3);
        builder.add_instr(0, ILInstr::Jump { target: 1 });
        // Block 1 defines `i`, uses it
        builder.add_instr(
            1,
            ILInstr::BinOp {
                dst: "i".into(),
                lhs: "i".into(),
                rhs: "1".into(),
                op: "+".into(),
            },
        );
        builder.add_instr(
            1,
            ILInstr::CondJump {
                cond: "cond".into(),
                true_target: 2,
                false_target: 1,
            },
        );
        builder.add_instr(2, ILInstr::Ret);
        let cfg = builder.build();
        let df = DominanceFrontier::compute(&cfg);
        let bed = BackEdgeDetector::detect(&cfg, &df.idom);
        let deps = LoopCarriedDependency::analyze(&cfg, &bed);
        assert!(!deps.is_empty());
        assert!(deps.iter().any(|d| d.var == "i"));
    }

    // 22. ControlFlowAnalysis::run on diamond.
    #[test]
    fn test_analysis_run_diamond() {
        let instrs = vec![
            (
                0,
                ILInstr::CondJump {
                    cond: "c".into(),
                    true_target: 1,
                    false_target: 2,
                },
            ),
            (1, ILInstr::Jump { target: 3 }),
            (2, ILInstr::Jump { target: 3 }),
            (3, ILInstr::Ret),
        ];
        let (ssa, df, bed, deps, result) = ControlFlowAnalysis::run(4, instrs);
        assert_eq!(result.block_count, 4);
        assert_eq!(result.back_edge_count, 0);
        assert!(result.is_reducible);
        assert_eq!(ssa.cfg.len(), 4);
        let _ = (df, bed, deps);
    }

    // 23. ControlFlowAnalysis::run on loop.
    #[test]
    fn test_analysis_run_loop() {
        let instrs = vec![
            (0, ILInstr::Jump { target: 1 }),
            (
                1,
                ILInstr::CondJump {
                    cond: "i".into(),
                    true_target: 2,
                    false_target: 3,
                },
            ),
            (2, ILInstr::Jump { target: 1 }),
            (3, ILInstr::Ret),
        ];
        let (_, _, bed, _, result) = ControlFlowAnalysis::run(4, instrs);
        assert_eq!(result.back_edge_count, 1);
        assert_eq!(result.loop_header_count, 1);
        assert!(bed.loop_headers.contains(&1));
    }

    // 24. CFG is_empty on empty.
    #[test]
    fn test_cfg_is_empty() {
        let builder = CFGBuilder::new(0);
        let cfg = builder.build();
        assert!(cfg.is_empty());
    }

    // 25. CFGBuilder: nop instruction is not a terminator.
    #[test]
    fn test_nop_fallthrough() {
        let mut builder = CFGBuilder::new(2);
        builder.add_instr(0, ILInstr::Nop);
        builder.add_instr(1, ILInstr::Ret);
        let cfg = builder.build();
        assert_eq!(cfg.successors(0), &[1]);
    }

    // 26. SSAForm has version_map entries.
    #[test]
    fn test_ssa_version_map() {
        let instrs = vec![
            (
                0,
                ILInstr::Assign {
                    dst: "x".into(),
                    src: "0".into(),
                },
            ),
            (0, ILInstr::Ret),
        ];
        let (ssa, _, _, _, _) = ControlFlowAnalysis::run(1, instrs);
        // x defined in block 0 should appear in version_map.
        assert!(ssa.version_map.contains_key(&(0, "x".into())));
    }

    // 27. BackEdgeDetector: two nested loops.
    #[test]
    fn test_nested_loop_back_edges() {
        // 0→1, 1→2, 2→3, 3→2 (inner back), 3→4, 4→1 (outer back), 4→5(exit)
        let mut builder = CFGBuilder::new(6);
        builder.add_instr(0, ILInstr::Jump { target: 1 });
        builder.add_instr(1, ILInstr::Jump { target: 2 });
        builder.add_instr(2, ILInstr::Jump { target: 3 });
        builder.add_instr(
            3,
            ILInstr::CondJump {
                cond: "j".into(),
                true_target: 2,
                false_target: 4,
            },
        );
        builder.add_instr(
            4,
            ILInstr::CondJump {
                cond: "i".into(),
                true_target: 1,
                false_target: 5,
            },
        );
        builder.add_instr(5, ILInstr::Ret);
        let cfg = builder.build();
        let df = DominanceFrontier::compute(&cfg);
        let bed = BackEdgeDetector::detect(&cfg, &df.idom);
        assert!(bed.back_edges.len() >= 2);
    }

    // 28. ILInstr::Phi used_vars.
    #[test]
    fn test_phi_used_vars() {
        let phi = ILInstr::Phi {
            dst: "x".into(),
            sources: vec![(0, "a".into()), (1, "b".into())],
        };
        let uses = phi.used_vars();
        assert!(uses.contains(&"a") && uses.contains(&"b"));
    }

    // 29. ILInstr::Call with dst.
    #[test]
    fn test_call_defined_var() {
        let call = ILInstr::Call {
            dst: Some("ret".into()),
            callee: "foo".into(),
            args: vec![],
        };
        assert_eq!(call.defined_var(), Some("ret"));
    }

    // 30. ILInstr::Load / Store.
    #[test]
    fn test_load_store_vars() {
        let ld = ILInstr::Load {
            dst: "v".into(),
            ptr: "p".into(),
        };
        assert_eq!(ld.defined_var(), Some("v"));
        assert!(ld.used_vars().contains(&"p"));
        let st = ILInstr::Store {
            ptr: "p".into(),
            val: "v".into(),
        };
        assert_eq!(st.defined_var(), None);
        assert!(st.used_vars().contains(&"p") && st.used_vars().contains(&"v"));
    }

    // 31. DominanceFrontier: empty CFG.
    #[test]
    fn test_dom_frontier_empty() {
        let builder = CFGBuilder::new(0);
        let cfg = builder.build();
        let df = DominanceFrontier::compute(&cfg);
        assert!(df.df.is_empty());
    }

    // 32. CFGAnalysisResult: edge_count correct.
    #[test]
    fn test_edge_count() {
        let instrs = vec![
            (
                0,
                ILInstr::CondJump {
                    cond: "c".into(),
                    true_target: 1,
                    false_target: 2,
                },
            ),
            (1, ILInstr::Ret),
            (2, ILInstr::Ret),
        ];
        let (_, _, _, _, result) = ControlFlowAnalysis::run(3, instrs);
        assert_eq!(result.edge_count, 2);
    }

    // 33. SSA phi_node_count on diamond with variable.
    #[test]
    fn test_phi_node_count() {
        let instrs = vec![
            (
                0,
                ILInstr::CondJump {
                    cond: "c".into(),
                    true_target: 1,
                    false_target: 2,
                },
            ),
            (
                1,
                ILInstr::Assign {
                    dst: "v".into(),
                    src: "10".into(),
                },
            ),
            (1, ILInstr::Jump { target: 3 }),
            (
                2,
                ILInstr::Assign {
                    dst: "v".into(),
                    src: "20".into(),
                },
            ),
            (2, ILInstr::Jump { target: 3 }),
            (3, ILInstr::Ret),
        ];
        let (_, _, _, _, result) = ControlFlowAnalysis::run(4, instrs);
        assert!(result.phi_node_count >= 1);
    }

    // 34. Reducibility: irreducible CFG has no back edges in idom tree.
    #[test]
    fn test_reducibility_flag() {
        // Diamond is trivially reducible.
        let instrs = vec![
            (
                0,
                ILInstr::CondJump {
                    cond: "c".into(),
                    true_target: 1,
                    false_target: 2,
                },
            ),
            (1, ILInstr::Ret),
            (2, ILInstr::Ret),
        ];
        let (_, _, _, _, result) = ControlFlowAnalysis::run(3, instrs);
        assert!(result.is_reducible);
    }

    // 35. LoopCarriedDependency: no deps in acyclic CFG.
    #[test]
    fn test_no_loop_deps_acyclic() {
        let instrs = vec![
            (
                0,
                ILInstr::Assign {
                    dst: "x".into(),
                    src: "1".into(),
                },
            ),
            (0, ILInstr::Ret),
        ];
        let (_, _, bed, deps, _) = ControlFlowAnalysis::run(1, instrs);
        assert!(bed.back_edges.is_empty());
        assert!(deps.is_empty());
    }

    // 36. BasicBlock::defs collects defined vars.
    #[test]
    fn test_bb_defs() {
        let mut bb = BasicBlock::new(0);
        bb.push(ILInstr::Assign {
            dst: "a".into(),
            src: "0".into(),
        });
        bb.push(ILInstr::Assign {
            dst: "b".into(),
            src: "a".into(),
        });
        let defs = bb.defs();
        assert!(defs.contains(&"a") && defs.contains(&"b"));
    }

    // 37. Regression: CFG::rpo() must not panic on an empty CFG (previously
    // indexed `visited[self.entry]` on a zero-length vec).
    #[test]
    fn test_rpo_empty_cfg_no_panic() {
        let cfg = CFG {
            blocks: Vec::new(),
            entry: 0,
        };
        assert_eq!(cfg.rpo(), Vec::<usize>::new());
    }

    // 38. Regression: CFG::rpo() must not panic when `entry` is out of range
    // for the block list (a malformed/adversarial CFG built by hand).
    #[test]
    fn test_rpo_out_of_range_entry_no_panic() {
        let cfg = CFG {
            blocks: vec![BasicBlock::new(0)],
            entry: 5,
        };
        assert_eq!(cfg.rpo(), Vec::<usize>::new());
    }

    // 39. Regression: LoopCarriedDependency::analyze produces a
    // deterministic (sorted) order of dependencies, independent of HashMap
    // iteration order, so re-running the analysis on identical input always
    // yields identical output ordering.
    #[test]
    fn test_loop_carried_dep_deterministic_order() {
        let mut builder = CFGBuilder::new(3);
        builder.add_instr(0, ILInstr::Jump { target: 1 });
        builder.add_instr(
            1,
            ILInstr::BinOp {
                dst: "z".into(),
                lhs: "z".into(),
                rhs: "1".into(),
                op: "+".into(),
            },
        );
        builder.add_instr(
            1,
            ILInstr::BinOp {
                dst: "a".into(),
                lhs: "a".into(),
                rhs: "1".into(),
                op: "+".into(),
            },
        );
        builder.add_instr(
            1,
            ILInstr::CondJump {
                cond: "cond".into(),
                true_target: 2,
                false_target: 1,
            },
        );
        builder.add_instr(2, ILInstr::Ret);
        let cfg = builder.build();
        let df = DominanceFrontier::compute(&cfg);
        let bed = BackEdgeDetector::detect(&cfg, &df.idom);
        let deps = LoopCarriedDependency::analyze(&cfg, &bed);
        let vars: Vec<&str> = deps.iter().map(|d| d.var.as_str()).collect();
        let mut sorted_vars = vars.clone();
        sorted_vars.sort_unstable();
        assert_eq!(vars, sorted_vars, "deps must be sorted by variable name");
    }

    // 40. Regression: SSAConstruction::build produces a deterministic
    // (sorted) phi-node order per block, independent of HashMap iteration
    // order.
    #[test]
    fn test_ssa_phi_nodes_deterministic_order() {
        // 0 -> {1,2}, 1 -> 3, 2 -> 3; both blocks 1 and 2 define "z" and "a"
        // so block 3 gets phi nodes for both variables.
        let mut builder = CFGBuilder::new(4);
        builder.add_instr(
            0,
            ILInstr::CondJump {
                cond: "c".into(),
                true_target: 1,
                false_target: 2,
            },
        );
        builder.add_instr(
            1,
            ILInstr::Assign {
                dst: "z".into(),
                src: "1".into(),
            },
        );
        builder.add_instr(
            1,
            ILInstr::Assign {
                dst: "a".into(),
                src: "1".into(),
            },
        );
        builder.add_instr(1, ILInstr::Jump { target: 3 });
        builder.add_instr(
            2,
            ILInstr::Assign {
                dst: "z".into(),
                src: "2".into(),
            },
        );
        builder.add_instr(
            2,
            ILInstr::Assign {
                dst: "a".into(),
                src: "2".into(),
            },
        );
        builder.add_instr(2, ILInstr::Jump { target: 3 });
        builder.add_instr(3, ILInstr::Ret);
        let cfg = builder.build();
        let df = DominanceFrontier::compute(&cfg);
        let ssa = SSAConstruction::build(cfg, &df);
        let phis = ssa.phi_nodes.get(&3).expect("phi nodes at block 3");
        let names: Vec<&str> = phis.iter().map(|(v, _)| v.as_str()).collect();
        let mut sorted_names = names.clone();
        sorted_names.sort_unstable();
        assert_eq!(names, sorted_names, "phi nodes must be sorted by variable name");
    }

    // 41. Regression: BackEdgeDetector::detect (now chain-walk based instead
    // of an O(n^2) matrix) still finds back edges correctly on a larger
    // linear-with-loop CFG.
    #[test]
    fn test_back_edge_detect_large_linear_loop() {
        let n = 200;
        let mut builder = CFGBuilder::new(n);
        for i in 0..n - 1 {
            builder.add_instr(i, ILInstr::Jump { target: i + 1 });
        }
        // Back edge from last block to block 1.
        builder.add_instr(
            n - 1,
            ILInstr::CondJump {
                cond: "c".into(),
                true_target: 1,
                false_target: 0, // irrelevant target, just needs a terminator
            },
        );
        let cfg = builder.build();
        let df = DominanceFrontier::compute(&cfg);
        let bed = BackEdgeDetector::detect(&cfg, &df.idom);
        assert!(bed.is_back_edge(n - 1, 1));
        assert!(bed.loop_headers.contains(&1));
    }
}
