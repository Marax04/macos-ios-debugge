// loop_analysis.rs — Loop analysis and natural loop detection for RustRE
//
// Implements:
//   - Natural loop detection via back-edge analysis
//   - LoopTree: nested loop hierarchy
//   - Loop classification (while, do-while, for, infinite)
//   - Induction variable detection
//   - Loop bounds / trip-count inference
//   - Reducibility check
//
// # Relationship to `cfg_loop_analyzer`
//
// This module is **IL-agnostic and self-contained**: it defines its own
// lightweight `Cfg` / `BasicBlock` types (using `BBId = u32` integers) so
// that it can be used independently of the main `ControlFlowGraph` in
// `lib.rs`.  It additionally provides induction-variable detection, loop
// bounds inference, vectorisation assessment, and loop-invariant detection —
// features not present in `cfg_loop_analyzer`.
//
// [`cfg_loop_analyzer`](super::cfg_loop_analyzer) is **integrated with the
// crate's `ControlFlowGraph`**: it receives a `&ControlFlowGraph`, reuses the
// pre-computed `DominatorTree` stored on that struct, and produces a
// `LoopNest` with richer per-loop metadata (`exit_sources`, `LoopMetrics`,
// `LoopQuery`).  Prefer `CfgLoopAnalyzer` when you already have a
// `ControlFlowGraph`; use this module when you need the extended analysis
// passes (IV detection, trip-count, vectorisation) or when operating on a
// foreign CFG representation.

pub use std::collections::BTreeMap;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// Basic types
// ---------------------------------------------------------------------------

pub type BBId = u32;
pub type Addr = u64;

// ---------------------------------------------------------------------------
// Natural loop
// ---------------------------------------------------------------------------

/// A natural loop identified in the CFG.
///
/// A natural loop has a single entry point (the header) and a set of
/// back-edges whose target is the header. The loop body contains all
/// nodes from which the header is reachable in the reverse CFG without
/// passing through the header's dominators.
#[derive(Clone, Debug)]
pub struct NaturalLoop {
    /// The loop header — the single entry point.
    pub header: BBId,
    /// All nodes in the loop body (including header).
    pub body: BTreeSet<BBId>,
    /// Back-edges: (latch → header). A loop may have multiple latches.
    pub back_edges: Vec<(BBId, BBId)>,
    /// Latch nodes: the sources of back-edges.
    pub latches: Vec<BBId>,
    /// Exit nodes: successors of body nodes that are outside the loop.
    pub exit_nodes: Vec<BBId>,
    /// Pre-header node: the unique predecessor of the header outside the loop (if exists).
    pub pre_header: Option<BBId>,
    /// Nesting depth (0 = outermost).
    pub depth: usize,
}

impl NaturalLoop {
    #[must_use]
    pub fn new(header: BBId, back_edges: Vec<(BBId, BBId)>) -> Self {
        let latches: Vec<BBId> = back_edges.iter().map(|(src, _)| *src).collect();
        let mut body = BTreeSet::new();
        body.insert(header);
        Self {
            header,
            body,
            back_edges,
            latches,
            exit_nodes: Vec::new(),
            pre_header: None,
            depth: 0,
        }
    }

    /// True if `bb` is in the loop body.
    #[must_use]
    pub fn contains(&self, bb: BBId) -> bool {
        self.body.contains(&bb)
    }

    /// True if `edge` (from, to) is a back-edge of this loop.
    #[must_use]
    pub fn is_back_edge(&self, from: BBId, to: BBId) -> bool {
        self.back_edges.contains(&(from, to))
    }

    /// True if this loop is a sub-loop of `other`.
    #[must_use]
    pub fn is_nested_in(&self, other: &Self) -> bool {
        self.header != other.header && other.body.contains(&self.header)
    }
}

// ---------------------------------------------------------------------------
// Loop tree
// ---------------------------------------------------------------------------

/// A node in the loop tree, wrapping a `NaturalLoop`.
#[derive(Clone, Debug)]
pub struct LoopNode {
    pub loop_info: NaturalLoop,
    /// Indices into the owning `LoopTree::loops` vec for child loops.
    pub children: Vec<usize>,
    /// Index of the parent loop node, if any.
    pub parent: Option<usize>,
}

/// Hierarchical nesting of all loops in a function.
#[derive(Default)]
pub struct LoopTree {
    /// All loops (including nested), stored flat.
    pub loops: Vec<LoopNode>,
    /// Indices of top-level (outermost) loops.
    pub roots: Vec<usize>,
    /// `BBId` → index of the innermost loop that contains it.
    pub bb_to_loop: HashMap<BBId, usize>,
}

impl LoopTree {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Find all natural loops in `cfg`, build the loop tree.
    #[must_use]
    pub fn build(cfg: &Cfg) -> Self {
        let loops = find_natural_loops(cfg);
        let mut tree = Self::new();

        // Insert all loops as nodes.
        for lp in loops {
            tree.loops.push(LoopNode {
                loop_info: lp,
                children: Vec::new(),
                parent: None,
            });
        }

        // Build parent/child relationships.
        let n = tree.loops.len();
        for i in 0..n {
            let mut innermost_parent: Option<usize> = None;
            let mut innermost_size = usize::MAX;
            for j in 0..n {
                if i == j {
                    continue;
                }
                if tree.loops[i]
                    .loop_info
                    .is_nested_in(&tree.loops[j].loop_info)
                {
                    let size = tree.loops[j].loop_info.body.len();
                    if size < innermost_size {
                        innermost_size = size;
                        innermost_parent = Some(j);
                    }
                }
            }
            tree.loops[i].parent = innermost_parent;
        }

        // Add children.
        for i in 0..n {
            if let Some(parent_idx) = tree.loops[i].parent {
                tree.loops[parent_idx].children.push(i);
            } else {
                tree.roots.push(i);
            }
        }

        // Set depths.
        let mut depths: Vec<usize> = vec![0; n];
        for root in &tree.roots {
            tree.set_depths(*root, 0, &mut depths);
        }
        for (i, d) in depths.into_iter().enumerate() {
            tree.loops[i].loop_info.depth = d;
        }

        // Build bb_to_loop (innermost loop for each BB).
        for (i, node) in tree.loops.iter().enumerate() {
            for &bb in &node.loop_info.body {
                let entry = tree.bb_to_loop.entry(bb).or_insert(i);
                // Prefer inner loop (smaller body).
                if tree.loops[i].loop_info.body.len() < tree.loops[*entry].loop_info.body.len() {
                    *entry = i;
                }
            }
        }

        tree
    }

    // Iterative (explicit-stack) rather than recursive: a recursive walk
    // pushes one Rust stack frame per forest level, which overflows the
    // stack on adversarially deep loop-nesting forests.
    fn set_depths(&self, idx: usize, depth: usize, depths: &mut Vec<usize>) {
        let mut stack: Vec<(usize, usize)> = vec![(idx, depth)];
        while let Some((i, d)) = stack.pop() {
            depths[i] = d;
            for &child in &self.loops[i].children {
                stack.push((child, d + 1));
            }
        }
    }

    /// Return the innermost loop containing `bb`, if any.
    #[must_use]
    pub fn innermost_loop(&self, bb: BBId) -> Option<&NaturalLoop> {
        self.bb_to_loop.get(&bb).map(|&i| &self.loops[i].loop_info)
    }

    /// Total number of loops.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.loops.len()
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all loops.
    pub fn all_loops(&self) -> impl Iterator<Item = &NaturalLoop> {
        self.loops.iter().map(|n| &n.loop_info)
    }

    /// Print the loop tree.
    pub fn print(&self) {
        for root in &self.roots {
            self.print_node(*root, 0);
        }
    }

    fn print_node(&self, idx: usize, indent: usize) {
        let node = &self.loops[idx];
        let prefix = "  ".repeat(indent);
        println!(
            "{}Loop (header=BB{}, body={:?}, depth={})",
            prefix, node.loop_info.header, node.loop_info.body, node.loop_info.depth
        );
        for &child in &node.children {
            self.print_node(child, indent + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// CFG representation (minimal, for loop analysis)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct BasicBlock {
    pub id: BBId,
    pub start_addr: Addr,
    pub end_addr: Addr,
    pub successors: Vec<BBId>,
    pub predecessors: Vec<BBId>,
    /// Instructions as (address, opaque string) — loop analysis is IL-agnostic.
    pub instructions: Vec<(Addr, String)>,
}

impl BasicBlock {
    #[must_use]
    pub fn new(id: BBId, start: Addr, end: Addr) -> Self {
        Self {
            id,
            start_addr: start,
            end_addr: end,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct Cfg {
    pub blocks: HashMap<BBId, BasicBlock>,
    pub entry: BBId,
}

impl Cfg {
    #[must_use]
    pub fn new(entry: BBId) -> Self {
        Self {
            blocks: HashMap::new(),
            entry,
        }
    }

    pub fn add_block(&mut self, bb: BasicBlock) {
        self.blocks.insert(bb.id, bb);
    }

    pub fn add_edge(&mut self, from: BBId, to: BBId) {
        if let Some(bb) = self.blocks.get_mut(&from) && !bb.successors.contains(&to) {
            bb.successors.push(to);
        }
        if let Some(bb) = self.blocks.get_mut(&to) && !bb.predecessors.contains(&from) {
            bb.predecessors.push(from);
        }
    }

    #[must_use]
    pub fn successors(&self, id: BBId) -> &[BBId] {
        self.blocks
            .get(&id)
            .map(|bb| bb.successors.as_slice())
            .unwrap_or(&[])
    }

    #[must_use]
    pub fn predecessors(&self, id: BBId) -> &[BBId] {
        self.blocks
            .get(&id)
            .map(|bb| bb.predecessors.as_slice())
            .unwrap_or(&[])
    }

    pub fn all_ids(&self) -> impl Iterator<Item = BBId> + '_ {
        self.blocks.keys().copied()
    }
}

// ---------------------------------------------------------------------------
// Dominator analysis
// ---------------------------------------------------------------------------

/// Computes the immediate dominator for each node using the iterative algorithm
/// (Cooper et al., "A Simple, Fast Dominance Algorithm", 2001).
pub struct DominatorTree {
    /// idom[n] = immediate dominator of n, or n itself if n == entry.
    pub idom: HashMap<BBId, BBId>,
    /// `dom_children`[n] = nodes immediately dominated by n.
    pub dom_children: HashMap<BBId, Vec<BBId>>,
    /// RPO order.
    pub rpo: Vec<BBId>,
    pub rpo_index: HashMap<BBId, usize>,
}

impl DominatorTree {
    #[must_use]
    pub fn build(cfg: &Cfg) -> Self {
        let rpo = reverse_post_order(cfg);
        let rpo_index: HashMap<BBId, usize> =
            rpo.iter().enumerate().map(|(i, &id)| (id, i)).collect();

        let undefined: BBId = u32::MAX;
        let mut idom: HashMap<BBId, BBId> = HashMap::new();
        debug_assert_ne!(
            cfg.entry, undefined,
            "CFG entry must not collide with UNDEFINED sentinel"
        );

        // Entry dominates itself.
        idom.insert(cfg.entry, cfg.entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == cfg.entry {
                    continue;
                }

                let preds = cfg.predecessors(b);
                let mut new_idom = preds
                    .iter()
                    .find(|&&p| idom.contains_key(&p))
                    .copied()
                    .unwrap_or(b);

                for &p in preds {
                    if p == new_idom {
                        continue;
                    }
                    if idom.contains_key(&p) {
                        new_idom = Self::intersect(p, new_idom, &idom, &rpo_index);
                    }
                }

                let old = idom.get(&b).copied();
                if old != Some(new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }

        let mut dom_children: HashMap<BBId, Vec<BBId>> = HashMap::new();
        for &n in &rpo {
            dom_children.entry(n).or_default();
            if let Some(&id) = idom.get(&n) && id != n {
                dom_children.entry(id).or_default().push(n);
            }
        }

        Self {
            idom,
            dom_children,
            rpo,
            rpo_index,
        }
    }

    fn intersect(
        mut b1: BBId,
        mut b2: BBId,
        idom: &HashMap<BBId, BBId>,
        rpo_index: &HashMap<BBId, usize>,
    ) -> BBId {
        loop {
            let ri1 = rpo_index.get(&b1).copied().unwrap_or(usize::MAX);
            let ri2 = rpo_index.get(&b2).copied().unwrap_or(usize::MAX);
            if b1 == b2 {
                return b1;
            }
            if ri1 > ri2 {
                b1 = *idom.get(&b1).unwrap_or(&b1);
            } else {
                b2 = *idom.get(&b2).unwrap_or(&b2);
            }
        }
    }

    /// True if `a` dominates `b`.
    #[must_use]
    pub fn dominates(&self, a: BBId, b: BBId) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        loop {
            let parent = *self.idom.get(&cur).unwrap_or(&cur);
            if parent == a {
                return true;
            }
            if parent == cur {
                return false;
            } // reached entry
            cur = parent;
        }
    }

    /// Return all nodes dominated by `a` (inclusive).
    #[must_use]
    pub fn dominated_by(&self, a: BBId) -> HashSet<BBId> {
        let mut result = HashSet::new();
        let mut stack = vec![a];
        while let Some(n) = stack.pop() {
            result.insert(n);
            if let Some(children) = self.dom_children.get(&n) {
                stack.extend(children);
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Reverse post-order
// ---------------------------------------------------------------------------

#[must_use]
pub fn reverse_post_order(cfg: &Cfg) -> Vec<BBId> {
    let mut visited = HashSet::new();
    let mut post_order = Vec::new();
    dfs_post(cfg.entry, cfg, &mut visited, &mut post_order);
    post_order.reverse();
    post_order
}

// Iterative (explicit-stack) rather than recursive: a recursive DFS pushes
// one Rust stack frame per node on the current path, which overflows the
// stack on adversarially deep/long CFGs (e.g. a long linear chain or a
// pathological cyclic graph). Each stack entry tracks the next successor
// index still to visit so we can resume where a "recursive call" would have
// returned.
fn dfs_post(start: BBId, cfg: &Cfg, visited: &mut HashSet<BBId>, order: &mut Vec<BBId>) {
    if !visited.insert(start) {
        return;
    }
    let mut stack: Vec<(BBId, usize)> = vec![(start, 0)];
    while let Some((node, idx)) = stack.last_mut() {
        let succs = cfg.successors(*node);
        if *idx < succs.len() {
            let succ = succs[*idx];
            *idx += 1;
            if visited.insert(succ) {
                stack.push((succ, 0));
            }
        } else {
            order.push(*node);
            stack.pop();
        }
    }
}

// ---------------------------------------------------------------------------
// Natural loop detection
// ---------------------------------------------------------------------------

/// Find all natural loops in `cfg`.
///
/// Algorithm:
/// 1. Compute dominators.
/// 2. Identify back-edges: (n → d) where d dominates n.
/// 3. For each back-edge, compute the natural loop via backward reachability
///    from the latch to the header (without crossing the header's dominators).
#[must_use]
pub fn find_natural_loops(cfg: &Cfg) -> Vec<NaturalLoop> {
    let dom = DominatorTree::build(cfg);
    let back_edges = find_back_edges(cfg, &dom);
    let mut loops: Vec<NaturalLoop> = Vec::new();

    // Group back-edges by header. Use a `BTreeMap` (not `HashMap`) so
    // iteration below visits headers in a deterministic order: `HashMap`
    // iteration order is randomized per-process, which would otherwise leak
    // into the order of `loops` for headers with equal-sized bodies (the
    // `sort_by` below is stable but ties on `body.len()` fall through to
    // insertion order) and make decompiler output non-reproducible across
    // runs on the same input.
    let mut header_to_back_edges: BTreeMap<BBId, Vec<(BBId, BBId)>> = BTreeMap::new();
    for (src, dst) in back_edges {
        header_to_back_edges
            .entry(dst)
            .or_default()
            .push((src, dst));
    }

    for (header, edges) in header_to_back_edges {
        let mut lp = NaturalLoop::new(header, edges.clone());
        // Compute body via backward BFS from latches, stopping at header.
        for (latch, _) in &edges {
            compute_loop_body(*latch, header, cfg, &mut lp.body);
        }
        // Compute exit nodes.
        lp.exit_nodes = compute_exit_nodes(&lp, cfg);
        // Compute pre-header.
        lp.pre_header = find_pre_header(&lp, cfg);
        loops.push(lp);
    }

    // Sort by body size (outer loops have larger bodies → descending), then
    // by header id to keep the order fully deterministic when two loops have
    // equal-sized bodies.
    loops.sort_by(|a, b| b.body.len().cmp(&a.body.len()).then(a.header.cmp(&b.header)));
    loops
}

/// Identify all back-edges: (n → d) where d dom n.
fn find_back_edges(cfg: &Cfg, dom: &DominatorTree) -> Vec<(BBId, BBId)> {
    let mut back_edges = Vec::new();
    for (&src, bb) in &cfg.blocks {
        for &dst in &bb.successors {
            if dom.dominates(dst, src) {
                back_edges.push((src, dst));
            }
        }
    }
    back_edges
}

/// Backward BFS from `start` to `header`, collecting all nodes in the loop body.
fn compute_loop_body(start: BBId, header: BBId, cfg: &Cfg, body: &mut BTreeSet<BBId>) {
    let mut queue: VecDeque<BBId> = VecDeque::new();
    if body.insert(start) {
        queue.push_back(start);
    }
    while let Some(node) = queue.pop_front() {
        if node == header {
            continue;
        }
        for &pred in cfg.predecessors(node) {
            if body.insert(pred) {
                queue.push_back(pred);
            }
        }
    }
}

/// Compute exit nodes: successors of body nodes that are outside the body.
fn compute_exit_nodes(lp: &NaturalLoop, cfg: &Cfg) -> Vec<BBId> {
    let mut exits = Vec::new();
    for &bb in &lp.body {
        for &succ in cfg.successors(bb) {
            if !lp.body.contains(&succ) && !exits.contains(&succ) {
                exits.push(succ);
            }
        }
    }
    exits
}

/// Find the pre-header: unique predecessor of header not in the loop.
fn find_pre_header(lp: &NaturalLoop, cfg: &Cfg) -> Option<BBId> {
    let preds: Vec<BBId> = cfg
        .predecessors(lp.header)
        .iter()
        .filter(|&&p| !lp.body.contains(&p))
        .copied()
        .collect();
    if preds.len() == 1 {
        Some(preds[0])
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Loop classifier
// ---------------------------------------------------------------------------

/// Loop shape classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopKind {
    /// while (cond) { ... } — condition checked in header.
    While,
    /// do { ... } while (cond) — condition checked in latch.
    DoWhile,
    /// for (init; cond; inc) { ... } — induction variable with bounds check.
    For,
    /// while (true) { ... } — no exit edges from loop body.
    Infinite,
    /// Not yet classified.
    Unknown,
}

impl fmt::Display for LoopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::While => write!(f, "while"),
            Self::DoWhile => write!(f, "do-while"),
            Self::For => write!(f, "for"),
            Self::Infinite => write!(f, "infinite"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Context provided to the classifier (IL-agnostic hooks).
pub struct LoopClassifierCtx<'a> {
    pub cfg: &'a Cfg,
    /// For each BB, whether it ends in a conditional branch.
    pub is_conditional: &'a dyn Fn(BBId) -> bool,
    /// For each conditional branch, what is the variable being checked.
    pub branch_var: &'a dyn Fn(BBId) -> Option<String>,
    /// For each BB, check if it increments an induction variable.
    pub increments_var: &'a dyn Fn(BBId) -> Option<(String, i64)>,
}

/// Classifies a single natural loop.
pub struct LoopClassifier<'a> {
    ctx: &'a LoopClassifierCtx<'a>,
}

impl<'a> LoopClassifier<'a> {
    #[must_use]
    pub const fn new(ctx: &'a LoopClassifierCtx<'a>) -> Self {
        LoopClassifier { ctx }
    }

    #[must_use]
    pub fn classify(&self, lp: &NaturalLoop) -> LoopKind {
        // Infinite loop: no exit edges.
        if lp.exit_nodes.is_empty() {
            return LoopKind::Infinite;
        }

        // Check if header has a conditional branch that exits the loop.
        let header_is_cond = (self.ctx.is_conditional)(lp.header);
        let header_exits = self
            .ctx
            .cfg
            .successors(lp.header)
            .iter()
            .any(|&s| !lp.body.contains(&s));

        // Check if any latch has a conditional branch back to header.
        let latch_is_cond = lp.latches.iter().any(|&l| (self.ctx.is_conditional)(l));
        let latch_exits = lp.latches.iter().any(|&l| {
            self.ctx
                .cfg
                .successors(l)
                .iter()
                .any(|&s| !lp.body.contains(&s))
        });

        // For loop: header has condition and there is an induction variable.
        let has_iv = self.detect_induction_variable(lp).is_some();

        if header_is_cond && header_exits && has_iv {
            return LoopKind::For;
        }
        if header_is_cond && header_exits {
            return LoopKind::While;
        }
        if latch_is_cond && latch_exits {
            return LoopKind::DoWhile;
        }
        LoopKind::Unknown
    }

    /// Try to find an induction variable in the loop.
    #[must_use]
    pub fn detect_induction_variable(&self, lp: &NaturalLoop) -> Option<InductionVariable> {
        for &latch in &lp.latches {
            if let Some((var, step)) = (self.ctx.increments_var)(latch) {
                // Induction variable detected in latch.
                return Some(InductionVariable {
                    name: var,
                    init: None,
                    step,
                    bound: None,
                    is_ascending: step > 0,
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Induction variable
// ---------------------------------------------------------------------------

/// A detected induction variable within a loop.
#[derive(Clone, Debug)]
pub struct InductionVariable {
    /// Name (or register identifier) of the induction variable.
    pub name: String,
    /// Initial value (if known).
    pub init: Option<i64>,
    /// Step per iteration (positive = ascending, negative = descending).
    pub step: i64,
    /// Loop bound (the limit used in the exit condition).
    pub bound: Option<i64>,
    /// True if step > 0.
    pub is_ascending: bool,
}

impl InductionVariable {
    /// Compute the trip count (number of iterations), if both init and bound
    /// are known and the step is non-zero.
    #[must_use]
    pub fn trip_count(&self) -> Option<u64> {
        let init = self.init?;
        let bound = self.bound?;
        if self.step == 0 {
            return None;
        }
        // Delegate to the single correct implementation instead of repeating
        // the formula. The copy that used to live here divided with TRUNCATION
        // (`(bound - init) / step`), which undercounts whenever the span is not
        // a multiple of the step: `for (i = 0; i < 5; i += 2)` runs 3 times
        // (0, 2, 4) but was reported as 2. The iteration count is
        // ceil((bound - init) / step), which `trip_count_for_loop` computes as
        // `(bound - init - 1) / step + 1` — in i128, so the subtraction cannot
        // overflow either.
        let magnitude = self.step.saturating_abs();
        let step = if self.is_ascending { magnitude } else { -magnitude };
        LoopBoundsInference::trip_count_for_loop(init, bound, step)
    }
}

// ---------------------------------------------------------------------------
// Loop bounds inference
// ---------------------------------------------------------------------------

/// Infers loop bounds from induction variables and branch conditions.
pub struct LoopBoundsInference;

impl LoopBoundsInference {
    /// Given an induction variable and a branch condition of the form
    /// `iv < bound`, `iv <= bound`, `iv != bound`, etc., refine the
    /// induction variable with the bound.
    ///
    /// `bound_val` is derived from a disassembled compare immediate and may be
    /// adversarial (e.g. `i64::MAX`/`i64::MIN`), so the +/-1 adjustment for
    /// `Le`/`Ge`/`Eq` uses saturating arithmetic rather than plain `+`/`-` to
    /// avoid an overflow panic (debug) or silent wraparound (release).
    pub const fn infer_from_condition(iv: &mut InductionVariable, cmp_op: BoundCmpOp, bound_val: i64) {
        iv.bound = Some(match cmp_op {
            BoundCmpOp::Lt => bound_val,
            BoundCmpOp::Le => bound_val.saturating_add(1),
            BoundCmpOp::Gt => bound_val,
            BoundCmpOp::Ge => bound_val.saturating_sub(1),
            BoundCmpOp::Ne => bound_val,
            BoundCmpOp::Eq => bound_val.saturating_add(1),
        });
    }

    /// Try to infer the trip count for a known for-loop pattern:
    /// `for (i = init; i < bound; i += step)`.
    ///
    /// `init`/`bound`/`step` come from induction-variable analysis over
    /// (potentially adversarial) disassembly, so intermediate differences can
    /// approach the `i64` extremes (e.g. `bound == i64::MAX`,
    /// `init == i64::MIN`). The computation is done in `i128` to avoid an
    /// overflow panic/wraparound that plain `i64` subtraction would hit.
    #[must_use]
    pub const fn trip_count_for_loop(init: i64, bound: i64, step: i64) -> Option<u64> {
        if step == 0 {
            return None;
        }
        if step > 0 {
            if bound <= init {
                return Some(0);
            }
            let diff = (bound as i128) - (init as i128) - 1;
            let count = diff / (step as i128) + 1;
            Some(count as u64)
        } else {
            if bound >= init {
                return Some(0);
            }
            let diff = (init as i128) - (bound as i128) - 1;
            let count = diff / -(step as i128) + 1;
            Some(count as u64)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundCmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Ne,
    Eq,
}

// ---------------------------------------------------------------------------
// Reducibility check
// ---------------------------------------------------------------------------

/// Check whether the CFG is reducible.
///
/// A CFG is reducible iff all back-edges in any DFS tree are "retreating edges"
/// (i.e., the back-edge target dominates the source).
/// Equivalently: no "cross-edges" to ancestors outside the dominator tree.
#[must_use]
pub fn is_reducible(cfg: &Cfg) -> bool {
    let dom = DominatorTree::build(cfg);
    // A CFG is reducible iff every back-edge (n→d) has d dominating n.
    //
    // `dfs_back_edges` performs a *single* DFS over the whole CFG (O(V+E))
    // and returns the complete set of DFS back-edges. The previous
    // implementation ran a fresh DFS from the entry for *every* CFG edge via
    // `is_dfs_back_edge`, which is O(E · (V+E)) — far worse than the O(V·E)
    // pattern this audit targets.
    let dfs_backs = dfs_back_edges(cfg);
    for (&src, bb) in &cfg.blocks {
        for &dst in &bb.successors {
            // Is this edge a back-edge (dst is an ancestor in DFS)?
            if dfs_backs.contains(&(src, dst)) && !dom.dominates(dst, src) {
                // It's a back-edge: for reducibility, dst must dominate src.
                return false;
            }
        }
    }
    true
}

/// Find all DFS back-edges (`from → to` where `to` is on the current DFS
/// stack when `from` is visited) via a single iterative DFS from `cfg.entry`.
fn dfs_back_edges(cfg: &Cfg) -> HashSet<(BBId, BBId)> {
    let mut visited: HashSet<BBId> = HashSet::new();
    let mut on_stack: HashSet<BBId> = HashSet::new();
    let mut back_edges: HashSet<(BBId, BBId)> = HashSet::new();

    // Reducibility must be judged against a DFS forest rooted at the CFG's
    // actual entry, not an arbitrary HashMap-iteration-order root — starting
    // elsewhere can build a spanning forest that misclassifies edges as
    // cross/back edges relative to a tree the entry never anchors, making
    // this test's outcome depend on hash iteration order.
    for &start in std::iter::once(&cfg.entry).chain(cfg.blocks.keys()) {
        if visited.contains(&start) {
            continue;
        }
        // Stack frame: (node, child_index).
        let mut stack: Vec<(BBId, usize)> = vec![(start, 0)];
        visited.insert(start);
        on_stack.insert(start);

        while let Some((node, ci)) = stack.last_mut() {
            let node = *node;
            let children = cfg.successors(node);
            if *ci < children.len() {
                let child = children[*ci];
                *ci += 1;
                if on_stack.contains(&child) {
                    back_edges.insert((node, child));
                } else if visited.insert(child) {
                    on_stack.insert(child);
                    stack.push((child, 0));
                }
            } else {
                stack.pop();
                on_stack.remove(&node);
            }
        }
    }

    back_edges
}

// ---------------------------------------------------------------------------
// Loop analysis result
// ---------------------------------------------------------------------------

/// Full loop analysis result for a function.
#[derive(Default)]
pub struct LoopAnalysisResult {
    pub tree: LoopTree,
    pub loop_kinds: HashMap<BBId, LoopKind>,
    pub induction_vars: HashMap<BBId, Vec<InductionVariable>>,
    pub trip_counts: HashMap<BBId, u64>,
    pub is_reducible: bool,
}

impl LoopAnalysisResult {
    /// Compute loop analysis for a CFG.
    #[must_use]
    pub fn compute(cfg: &Cfg) -> Self {
        let tree = LoopTree::build(cfg);
        let reducible = is_reducible(cfg);

        Self {
            tree,
            loop_kinds: HashMap::new(),
            induction_vars: HashMap::new(),
            trip_counts: HashMap::new(),
            is_reducible: reducible,
        }
    }

    /// Print a summary.
    pub fn print_summary(&self) {
        println!("=== Loop Analysis Result ===");
        println!("Total loops: {}", self.tree.len());
        println!("Reducible CFG: {}", self.is_reducible);
        for lp in self.tree.all_loops() {
            let kind = self
                .loop_kinds
                .get(&lp.header)
                .copied()
                .unwrap_or(LoopKind::Unknown);
            let trip = self.trip_counts.get(&lp.header);
            print!(
                "  Loop header=BB{} kind={} body={:?} exits={:?}",
                lp.header, kind, lp.body, lp.exit_nodes
            );
            if let Some(t) = trip {
                print!(" trip_count={t}");
            }
            println!();
        }
    }
}

// ---------------------------------------------------------------------------
// Loop simplifications
// ---------------------------------------------------------------------------

/// Represents a loop invariant computation (move outside the loop).
#[derive(Clone, Debug)]
pub struct LoopInvariant {
    pub bb: BBId,
    pub insn_addr: Addr,
    pub reason: String,
}

/// Identifies loop-invariant instructions within a loop.
///
/// An instruction is loop-invariant if all its operands are loop-invariant
/// (either constant or defined outside the loop).
pub struct LoopInvariantDetector<'a> {
    pub lp: &'a NaturalLoop,
    /// For each instruction address, set of defining basic blocks of its operands.
    pub operand_defs: &'a dyn Fn(Addr) -> Vec<BBId>,
}

impl<'a> LoopInvariantDetector<'a> {
    pub fn new(lp: &'a NaturalLoop, operand_defs: &'a dyn Fn(Addr) -> Vec<BBId>) -> Self {
        LoopInvariantDetector { lp, operand_defs }
    }

    #[must_use]
    pub fn find_invariants(&self, cfg: &Cfg) -> Vec<LoopInvariant> {
        let mut invariants = Vec::new();
        for &bb in &self.lp.body {
            if let Some(block) = cfg.blocks.get(&bb) {
                for (addr, _) in &block.instructions {
                    let defs = (self.operand_defs)(*addr);
                    let is_invariant = defs.iter().all(|def_bb| !self.lp.body.contains(def_bb));
                    if is_invariant {
                        invariants.push(LoopInvariant {
                            bb,
                            insn_addr: *addr,
                            reason: "operands defined outside loop".into(),
                        });
                    }
                }
            }
        }
        invariants
    }
}

// ---------------------------------------------------------------------------
// Strength reduction candidate
// ---------------------------------------------------------------------------

/// An opportunity for strength reduction in a loop.
#[derive(Clone, Debug)]
pub struct StrengthReductionCandidate {
    pub insn_addr: Addr,
    pub iv_name: String,
    pub multiplier: i64,
    pub description: String,
}

// ---------------------------------------------------------------------------
// Loop unroll estimation
// ---------------------------------------------------------------------------

/// Estimate whether a loop is worth unrolling.
#[derive(Clone, Debug)]
pub struct UnrollEstimate {
    pub header: BBId,
    pub should_unroll: bool,
    pub suggested_factor: usize,
    pub reason: String,
}

impl UnrollEstimate {
    #[must_use]
    pub fn evaluate(lp: &NaturalLoop, trip_count: Option<u64>, body_size: usize) -> Self {
        const UNROLL_THRESHOLD_BODY_SIZE: usize = 8;
        const UNROLL_THRESHOLD_TRIP_COUNT: u64 = 16;
        const UNROLL_FACTOR: usize = 4;

        if let Some(tc) = trip_count && tc <= UNROLL_THRESHOLD_TRIP_COUNT && body_size <= UNROLL_THRESHOLD_BODY_SIZE {
            return Self {
                header: lp.header,
                should_unroll: true,
                suggested_factor: tc.min(UNROLL_FACTOR as u64) as usize,
                reason: format!("small loop: trip_count={tc}, body_size={body_size}"),
            };
        }
        Self {
            header: lp.header,
            should_unroll: false,
            suggested_factor: 1,
            reason: "not profitable".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Vectorisation potential
// ---------------------------------------------------------------------------

/// Assesses whether a loop body could be auto-vectorised.
#[derive(Clone, Debug)]
pub struct VectorizationAssessment {
    pub header: BBId,
    pub vectorizable: bool,
    pub vector_width: usize, // suggested SIMD width in elements
    pub blocking_reasons: Vec<String>,
}

impl VectorizationAssessment {
    #[must_use]
    pub fn assess(
        lp: &NaturalLoop,
        has_loop_carried_dep: bool,
        iv: Option<&InductionVariable>,
    ) -> Self {
        let mut blocking = Vec::new();
        if has_loop_carried_dep {
            blocking.push("loop-carried dependency".into());
        }
        if iv.map_or(0, |i| i.step) != 1 {
            blocking.push("non-unit stride induction variable".into());
        }
        let vectorizable = blocking.is_empty() && iv.is_some();
        Self {
            header: lp.header,
            vectorizable,
            vector_width: if vectorizable { 4 } else { 1 },
            blocking_reasons: blocking,
        }
    }
}

// ---------------------------------------------------------------------------
// Dominance frontier (needed for SSA construction, useful for loop exits)
// ---------------------------------------------------------------------------

/// Computes the dominance frontier of each node.
/// DF(x) = { y | ∃ pred(y) that x dominates, but x does not strictly dominate y }
pub struct DominanceFrontier {
    pub frontier: HashMap<BBId, HashSet<BBId>>,
}

impl DominanceFrontier {
    #[must_use]
    pub fn build(cfg: &Cfg, dom: &DominatorTree) -> Self {
        let mut frontier: HashMap<BBId, HashSet<BBId>> = HashMap::new();
        for &id in cfg.blocks.keys() {
            frontier.insert(id, HashSet::new());
        }
        // Per-edge formulation of Cytron et al.: for every CFG edge
        // `pred -> bb`, walk from `pred` up the dominator tree adding `bb`
        // to each node's frontier, stopping at idom(bb) (exclusive).
        //
        // Two bugs fixed here (found by
        // soundness_fuzz::dominance_frontier_matches_definition_fuzz):
        // 1. The old `predecessors.len() >= 2` guard skipped single-pred
        //    joins entirely. That is only sound when idom(bb) == pred, which
        //    fails for back edges to the entry (e.g. `0 -> 1 -> 0`: node 0
        //    has the single predecessor 1, yet DF(1) must contain 0).
        // 2. For `bb == entry` the stored idom is the entry itself, so the
        //    old stop condition `runner != idom(bb)` ended the walk one node
        //    early and the entry never appeared in its own frontier
        //    (DF(0) = {0} for `0 -> 1 -> 0` came out empty).
        for (&bb, block) in &cfg.blocks {
            if !dom.idom.contains_key(&bb) {
                continue; // unreachable join: not modeled by the dominator tree
            }
            // Stop node: idom(bb), exclusive. For the entry node there is no
            // proper idom (it is stored as its own idom), so the walk runs
            // through the entry itself and stops at the chain's end.
            let stop: Option<BBId> = match dom.idom.get(&bb) {
                Some(&id) if id != bb => Some(id),
                _ => None,
            };
            for &pred in &block.predecessors {
                if !dom.idom.contains_key(&pred) {
                    continue; // unreachable predecessor: not modeled
                }
                let mut runner = pred;
                loop {
                    if Some(runner) == stop {
                        break;
                    }
                    frontier.entry(runner).or_default().insert(bb);
                    let parent = *dom.idom.get(&runner).unwrap_or(&runner);
                    if parent == runner {
                        break; // reached the entry
                    }
                    runner = parent;
                }
            }
        }
        Self { frontier }
    }

    #[must_use]
    pub fn get(&self, bb: BBId) -> &HashSet<BBId> {
        static EMPTY: std::sync::OnceLock<HashSet<BBId>> = std::sync::OnceLock::new();
        self.frontier
            .get(&bb)
            .unwrap_or_else(|| EMPTY.get_or_init(HashSet::new))
    }
}

// ---------------------------------------------------------------------------
// Cycle detection (alternative reducibility via Tarjan)
// ---------------------------------------------------------------------------

/// Returns true if the CFG has irreducible control flow (non-natural loops).
///
/// Method: recursive SCC refinement (the loop-nesting decomposition used by
/// Havlak-style analyses). Each non-trivial SCC must have a single header —
/// an entry node that dominates every other entry of the SCC. If it does,
/// the header is removed and the remainder of the SCC is re-examined, so
/// that irreducible loops *nested inside* a single-entry outer loop are also
/// detected.
///
/// The previous implementation only inspected the top-level SCCs, so a CFG
/// like `0 -> 1, 1 -> {2, 3}, 2 <-> 3, 2 -> 1` — whose outer SCC {1,2,3} has
/// the single entry 1, but which contains the irreducible sub-loop {2,3}
/// entered at both 2 and 3 — was misreported as reducible (found by
/// `soundness_fuzz::reducibility_implementations_agree_fuzz`, which
/// cross-checks this function against the T1/T2 structural reduction).
#[must_use]
pub fn has_irreducible_control_flow(cfg: &Cfg) -> bool {
    let dom = DominatorTree::build(cfg);

    // Tarjan over an induced subgraph.
    fn sccs_in_subgraph(cfg: &Cfg, sub: &HashSet<BBId>) -> Vec<Vec<BBId>> {
        let mut s = Cfg::new(cfg.entry);
        for &id in sub {
            s.add_block(BasicBlock::new(id, 0, 0));
        }
        for &id in sub {
            for &t in cfg.successors(id) {
                if sub.contains(&t) {
                    s.add_edge(id, t);
                }
            }
        }
        tarjan_sccs(&s)
    }

    let mut worklist: Vec<HashSet<BBId>> = vec![cfg.blocks.keys().copied().collect()];
    while let Some(sub) = worklist.pop() {
        for scc in sccs_in_subgraph(cfg, &sub) {
            // Trivial SCC: a single node without a self-loop.
            if scc.len() == 1 && !cfg.successors(scc[0]).contains(&scc[0]) {
                continue;
            }
            let scc_set: HashSet<BBId> = scc.iter().copied().collect();
            // Entries: nodes with a predecessor outside the SCC (in the full
            // graph — at nested levels this includes previously removed
            // headers). The function entry is implicitly an entry of any SCC
            // containing it, even without an external predecessor.
            let mut entries: Vec<BBId> = scc
                .iter()
                .copied()
                .filter(|&n| cfg.predecessors(n).iter().any(|&p| !scc_set.contains(&p)))
                .collect();
            if scc_set.contains(&cfg.entry) && !entries.contains(&cfg.entry) {
                entries.push(cfg.entry);
            }
            // The header is an entry that dominates all other entries.
            let header = entries
                .iter()
                .copied()
                .find(|&h| entries.iter().all(|&other| dom.dominates(h, other)));
            match header {
                None if !entries.is_empty() => return true, // multi-entry loop
                _ => {
                    // Single-header (or unreachable) SCC: peel the header and
                    // re-examine the interior for nested irreducibility.
                    let peel = header.unwrap_or(scc[0]);
                    let mut inner = scc_set;
                    inner.remove(&peel);
                    if inner.len() > 1 {
                        worklist.push(inner);
                    }
                }
            }
        }
    }
    false
}

/// Tarjan's SCC algorithm.
#[must_use]
pub fn tarjan_sccs(cfg: &Cfg) -> Vec<Vec<BBId>> {
    let ids: Vec<BBId> = cfg.blocks.keys().copied().collect();
    let index_map: HashMap<BBId, usize> = ids.iter().enumerate().map(|(i, &id)| (id, i)).collect();
    let n = ids.len();

    let mut index = vec![0usize; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut visited = vec![false; n];
    let mut stack: Vec<BBId> = Vec::new();
    let mut result: Vec<Vec<BBId>> = Vec::new();
    let mut counter = 0usize;

    fn strong(
        v: usize,
        ids: &[BBId],
        index_map: &HashMap<BBId, usize>,
        cfg: &Cfg,
        idx: &mut Vec<usize>,
        low: &mut Vec<usize>,
        on_stack: &mut Vec<bool>,
        stack: &mut Vec<BBId>,
        result: &mut Vec<Vec<BBId>>,
        counter: &mut usize,
        visited: &mut Vec<bool>,
    ) {
        idx[v] = *counter;
        low[v] = *counter;
        *counter += 1;
        visited[v] = true;
        on_stack[v] = true;
        stack.push(ids[v]);

        for &succ in cfg.successors(ids[v]) {
            if let Some(&w) = index_map.get(&succ) {
                if !visited[w] {
                    strong(
                        w, ids, index_map, cfg, idx, low, on_stack, stack, result, counter, visited,
                    );
                    low[v] = low[v].min(low[w]);
                } else if on_stack[w] {
                    low[v] = low[v].min(idx[w]);
                }
            }
        }

        if low[v] == idx[v] {
            let mut scc = Vec::new();
            loop {
                let w = match stack.pop() {
                    Some(w) => w,
                    None => break,
                };
                if let Some(&wi) = index_map.get(&w) {
                    on_stack[wi] = false;
                    scc.push(w);
                }
                if w == ids[v] {
                    break;
                }
            }
            result.push(scc);
        }
    }

    for i in 0..n {
        if !visited[i] {
            strong(
                i,
                &ids,
                &index_map,
                cfg,
                &mut index,
                &mut low,
                &mut on_stack,
                &mut stack,
                &mut result,
                &mut counter,
                &mut visited,
            );
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Loop depth map
// ---------------------------------------------------------------------------

/// Returns a map: `BBId` → nesting depth (0 = not in a loop, 1 = outermost, etc.)
#[must_use]
pub fn compute_loop_depths(tree: &LoopTree, cfg: &Cfg) -> HashMap<BBId, usize> {
    let mut depth_map: HashMap<BBId, usize> = HashMap::new();
    for &id in cfg.blocks.keys() {
        depth_map.insert(id, 0);
    }
    for lp_node in &tree.loops {
        let lp = &lp_node.loop_info;
        for &bb in &lp.body {
            let d = depth_map.entry(bb).or_insert(0);
            *d = (*d).max(lp.depth + 1);
        }
    }
    depth_map
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a simple while-loop CFG:
    //   0 (entry) → 1 (header/cond) → 2 (body) → 1 (back), 1 → 3 (exit)
    fn simple_while_cfg() -> Cfg {
        let mut cfg = Cfg::new(0);
        for i in 0..4 {
            cfg.add_block(BasicBlock::new(i, u64::from(i) * 4, u64::from(i) * 4 + 4));
        }
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2); // enter body
        cfg.add_edge(1, 3); // exit loop
        cfg.add_edge(2, 1); // back-edge
        cfg
    }

    // Helper: build a do-while CFG:
    //   0 → 1 (body) → 2 (latch/cond) → 1 (back), 2 → 3 (exit)
    fn simple_do_while_cfg() -> Cfg {
        let mut cfg = Cfg::new(0);
        for i in 0..4 {
            cfg.add_block(BasicBlock::new(i, u64::from(i) * 4, u64::from(i) * 4 + 4));
        }
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1); // back-edge
        cfg.add_edge(2, 3); // exit
        cfg
    }

    // Helper: nested loops CFG.
    fn nested_loops_cfg() -> Cfg {
        let mut cfg = Cfg::new(0);
        for i in 0..6 {
            cfg.add_block(BasicBlock::new(i, u64::from(i) * 4, u64::from(i) * 4 + 4));
        }
        // Outer loop: 1 (header) ← 4 (latch)
        // Inner loop: 2 (header) ← 3 (latch)
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 3);
        cfg.add_edge(3, 2); // inner back-edge
        cfg.add_edge(3, 4);
        cfg.add_edge(4, 1); // outer back-edge
        cfg.add_edge(1, 5); // exit outer
        cfg
    }

    #[test]
    fn test_dominator_tree_entry_dominates_all() {
        let cfg = simple_while_cfg();
        let dom = DominatorTree::build(&cfg);
        for &id in cfg.blocks.keys() {
            assert!(dom.dominates(0, id), "entry should dominate BB{}", id);
        }
    }

    #[test]
    fn test_dominator_tree_header_dominates_body() {
        let cfg = simple_while_cfg();
        let dom = DominatorTree::build(&cfg);
        assert!(dom.dominates(1, 2));
        assert!(!dom.dominates(2, 1));
    }

    #[test]
    fn test_find_natural_loops_while() {
        let cfg = simple_while_cfg();
        let loops = find_natural_loops(&cfg);
        assert_eq!(loops.len(), 1);
        let lp = &loops[0];
        assert_eq!(lp.header, 1);
        assert!(lp.body.contains(&1));
        assert!(lp.body.contains(&2));
        assert!(!lp.body.contains(&3));
    }

    #[test]
    fn test_find_natural_loops_do_while() {
        let cfg = simple_do_while_cfg();
        let loops = find_natural_loops(&cfg);
        assert_eq!(loops.len(), 1);
        let lp = &loops[0];
        assert_eq!(lp.header, 1);
        assert!(lp.body.contains(&1));
        assert!(lp.body.contains(&2));
    }

    #[test]
    fn test_exit_nodes_while() {
        let cfg = simple_while_cfg();
        let loops = find_natural_loops(&cfg);
        let lp = &loops[0];
        assert!(lp.exit_nodes.contains(&3));
    }

    #[test]
    fn test_nested_loops() {
        let cfg = nested_loops_cfg();
        let loops = find_natural_loops(&cfg);
        // Should find 2 loops: inner (header=2) and outer (header=1).
        assert_eq!(loops.len(), 2);
        let outer = loops.iter().find(|l| l.header == 1).unwrap();
        let inner = loops.iter().find(|l| l.header == 2).unwrap();
        assert!(inner.is_nested_in(outer));
        assert!(!outer.is_nested_in(inner));
    }

    #[test]
    fn test_loop_tree_depth() {
        let cfg = nested_loops_cfg();
        let tree = LoopTree::build(&cfg);
        assert_eq!(tree.len(), 2);
        // Find the inner and outer loop depths.
        let depths: Vec<usize> = tree.all_loops().map(|l| l.depth).collect();
        assert!(depths.contains(&0)); // outer loop at depth 0
        assert!(depths.contains(&1)); // inner loop at depth 1
    }

    #[test]
    fn test_loop_tree_innermost() {
        let cfg = nested_loops_cfg();
        let tree = LoopTree::build(&cfg);
        // BB3 is the inner latch; it should be in the inner loop (header=2).
        if let Some(lp) = tree.innermost_loop(3) {
            assert_eq!(lp.header, 2);
        }
    }

    #[test]
    fn test_reducible_cfg() {
        let cfg = simple_while_cfg();
        assert!(is_reducible(&cfg));
    }

    #[test]
    fn test_induction_variable_trip_count() {
        let iv = InductionVariable {
            name: "i".into(),
            init: Some(0),
            step: 1,
            bound: Some(10),
            is_ascending: true,
        };
        assert_eq!(iv.trip_count(), Some(10));
    }

    #[test]
    fn test_induction_variable_descending() {
        let iv = InductionVariable {
            name: "i".into(),
            init: Some(10),
            step: -1,
            bound: Some(0),
            is_ascending: false,
        };
        assert_eq!(iv.trip_count(), Some(10));
    }

    #[test]
    fn test_induction_variable_zero_step() {
        let iv = InductionVariable {
            name: "i".into(),
            init: Some(0),
            step: 0,
            bound: Some(10),
            is_ascending: true,
        };
        assert_eq!(iv.trip_count(), None);
    }

    #[test]
    fn test_loop_bounds_inference() {
        let mut iv = InductionVariable {
            name: "i".into(),
            init: Some(0),
            step: 1,
            bound: None,
            is_ascending: true,
        };
        LoopBoundsInference::infer_from_condition(&mut iv, BoundCmpOp::Lt, 100);
        assert_eq!(iv.bound, Some(100));
        assert_eq!(iv.trip_count(), Some(100));
    }

    #[test]
    fn test_trip_count_for_loop() {
        assert_eq!(LoopBoundsInference::trip_count_for_loop(0, 10, 1), Some(10));
        assert_eq!(LoopBoundsInference::trip_count_for_loop(0, 10, 2), Some(5));
        assert_eq!(
            LoopBoundsInference::trip_count_for_loop(10, 0, -1),
            Some(10)
        );
        assert_eq!(LoopBoundsInference::trip_count_for_loop(0, 0, 1), Some(0));
    }

    /// Regression test: adversarial/malformed disassembly can yield compare
    /// immediates at the `i64` extremes. `infer_from_condition` must not
    /// panic (debug) or silently wrap (release) when adjusting the bound by
    /// +/-1 for `Le`/`Ge`/`Eq`.
    #[test]
    fn test_loop_bounds_inference_extreme_bound_no_overflow() {
        let mut iv = InductionVariable {
            name: "i".into(),
            init: Some(0),
            step: 1,
            bound: None,
            is_ascending: true,
        };
        LoopBoundsInference::infer_from_condition(&mut iv, BoundCmpOp::Le, i64::MAX);
        assert_eq!(iv.bound, Some(i64::MAX));

        LoopBoundsInference::infer_from_condition(&mut iv, BoundCmpOp::Eq, i64::MAX);
        assert_eq!(iv.bound, Some(i64::MAX));

        LoopBoundsInference::infer_from_condition(&mut iv, BoundCmpOp::Ge, i64::MIN);
        assert_eq!(iv.bound, Some(i64::MIN));
    }

    /// Regression test: `trip_count_for_loop` must not overflow/panic when
    /// `init`/`bound` are near the `i64` extremes (values derived from
    /// possibly-malformed disassembly).
    #[test]
    fn test_trip_count_for_loop_extreme_values_no_overflow() {
        // bound - init would overflow i64 subtraction directly.
        assert_eq!(
            LoopBoundsInference::trip_count_for_loop(i64::MIN, i64::MAX, 1),
            Some(u64::MAX)
        );
        assert_eq!(
            LoopBoundsInference::trip_count_for_loop(i64::MAX, i64::MIN, -1),
            Some(u64::MAX)
        );
        // step == i64::MIN: negating it directly would overflow.
        assert_eq!(
            LoopBoundsInference::trip_count_for_loop(10, 0, i64::MIN),
            Some(1)
        );
        assert_eq!(LoopBoundsInference::trip_count_for_loop(0, 10, 1), Some(10));
    }

    #[test]
    fn reverse_post_order_deep_chain_no_stack_overflow() {
        // `dfs_post` used to be plain recursion (one Rust stack frame per
        // node on the path); a long linear chain would blow the stack.
        // Regression test for the iterative rewrite.
        let n: u32 = 200_000;
        let mut cfg = Cfg::new(0);
        for i in 0..=n {
            cfg.add_block(BasicBlock::new(i, u64::from(i) * 4, u64::from(i) * 4 + 4));
        }
        for i in 0..n {
            cfg.add_edge(i, i + 1);
        }
        let rpo = reverse_post_order(&cfg);
        assert_eq!(rpo.len() as u32, n + 1);
        assert_eq!(rpo[0], 0);
        assert_eq!(rpo[rpo.len() - 1], n);
    }

    #[test]
    fn test_unroll_estimate_small_loop() {
        let mut cfg = Cfg::new(0);
        cfg.add_block(BasicBlock::new(0, 0, 4));
        cfg.add_block(BasicBlock::new(1, 4, 8));
        cfg.add_edge(0, 1);
        let loops = find_natural_loops(&cfg);
        if loops.is_empty() {
            // No loop in this trivial CFG — that's fine.
            return;
        }
        let lp = &loops[0];
        let est = UnrollEstimate::evaluate(lp, Some(4), 3);
        assert!(est.should_unroll);
    }

    #[test]
    fn test_tarjan_sccs_simple() {
        let cfg = simple_while_cfg();
        let sccs = tarjan_sccs(&cfg);
        // The loop BB1→BB2→BB1 forms an SCC of size 2.
        let has_scc_size_2 = sccs.iter().any(|s| s.len() >= 2);
        assert!(has_scc_size_2);
    }

    #[test]
    fn test_has_irreducible_false() {
        let cfg = simple_while_cfg();
        assert!(!has_irreducible_control_flow(&cfg));
    }

    #[test]
    fn test_loop_depth_map() {
        let cfg = nested_loops_cfg();
        let tree = LoopTree::build(&cfg);
        let depths = compute_loop_depths(&tree, &cfg);
        // BB3 is in both inner and outer loops → should be max depth.
        let max_depth = depths.values().copied().max().unwrap_or(0);
        assert!(max_depth >= 2, "expected depth >= 2, got {}", max_depth);
    }

    #[test]
    fn test_dominance_frontier_empty_for_entry() {
        let cfg = simple_while_cfg();
        let dom = DominatorTree::build(&cfg);
        let df = DominanceFrontier::build(&cfg, &dom);
        // The entry strictly dominates every reachable node, so nothing can be
        // in its dominance frontier — DF(entry) is EMPTY, which is exactly what
        // this test's name claims.
        //
        // The assertion here used to be `df.get(0).is_empty() ||
        // !df.get(0).is_empty()` — literally `X || !X`, true by construction, as
        // its own trailing comment ("just check no panic") conceded. It could
        // not fail for any input, so the property in the test's name was never
        // actually checked. Calling `df.get(0)` at all is enough to cover the
        // no-panic case.
        assert!(
            df.get(0).is_empty(),
            "entry strictly dominates all reachable nodes, so DF(entry) must be \
             empty, got {:?}",
            df.get(0)
        );
    }

    #[test]
    fn test_dominance_frontier_back_edge_to_entry() {
        // Regression (found by soundness_fuzz): 0 <-> 1. Node 0 (entry) has
        // the single predecessor 1, so the old `preds >= 2` guard skipped the
        // join entirely, and the old stop condition ended the runner walk
        // before the entry. Correct: DF(0) = DF(1) = {0}.
        let mut cfg = Cfg::new(0);
        cfg.add_block(BasicBlock::new(0, 0, 4));
        cfg.add_block(BasicBlock::new(1, 4, 8));
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 0);
        let dom = DominatorTree::build(&cfg);
        let df = DominanceFrontier::build(&cfg, &dom);
        assert_eq!(df.get(0), &HashSet::from([0]));
        assert_eq!(df.get(1), &HashSet::from([0]));
    }

    #[test]
    fn test_has_irreducible_nested_inside_single_entry_scc() {
        // Regression (found by soundness_fuzz): outer SCC {1,2,3} has the
        // single entry 1, but the inner sub-loop 2 <-> 3 is entered at both
        // 2 and 3 (from 1), so the CFG is irreducible. The old top-level-SCC
        // check reported it as reducible.
        //   0 -> 1, 1 -> 2, 1 -> 3, 2 -> 3, 3 -> 2, 2 -> 1
        let mut cfg = Cfg::new(0);
        for i in 0..4 {
            cfg.add_block(BasicBlock::new(i, u64::from(i) * 4, u64::from(i) * 4 + 4));
        }
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);
        cfg.add_edge(3, 2);
        cfg.add_edge(2, 1);
        assert!(has_irreducible_control_flow(&cfg));
        // Cross-check: the DFS back-edge dominance test agrees.
        assert!(!is_reducible(&cfg));
    }

    #[test]
    fn test_has_irreducible_false_for_entry_scc_nested_reducible() {
        // Entry participates in the outer SCC ({0,1} via 1 -> 0) and the
        // inner loop 1 <-> 2 is single-entry: fully reducible.
        //   0 -> 1, 1 -> 0, 1 -> 2, 2 -> 1
        let mut cfg = Cfg::new(0);
        for i in 0..3 {
            cfg.add_block(BasicBlock::new(i, u64::from(i) * 4, u64::from(i) * 4 + 4));
        }
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 0);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1);
        assert!(!has_irreducible_control_flow(&cfg));
        assert!(is_reducible(&cfg));
    }

    #[test]
    fn test_pre_header_detection() {
        let cfg = simple_while_cfg();
        let loops = find_natural_loops(&cfg);
        let lp = &loops[0];
        // BB0 is the unique predecessor of BB1 outside the loop.
        assert_eq!(lp.pre_header, Some(0));
    }

    #[test]
    fn test_latch_detection() {
        let cfg = simple_while_cfg();
        let loops = find_natural_loops(&cfg);
        let lp = &loops[0];
        assert!(lp.latches.contains(&2)); // BB2 is the latch
    }

    #[test]
    fn test_reverse_post_order_simple() {
        let cfg = simple_while_cfg();
        let rpo = reverse_post_order(&cfg);
        // Entry should be first.
        assert_eq!(rpo[0], 0);
    }

    // Regression test: `LoopTree::set_depths` used to recurse one Rust stack
    // frame per forest nesting level, which overflows the stack on
    // adversarially deep loop-nesting forests (e.g. a generated/pathological
    // binary with tens of thousands of sequentially nested loops). Build a
    // long children chain directly (bypassing the O(n^2) natural-loop
    // discovery in `LoopTree::build`, which is not the code path under test)
    // and confirm the iterative version handles it without overflowing.
    #[test]
    fn test_loop_tree_set_depths_deep_chain_no_stack_overflow() {
        const DEPTH: usize = 200_000;
        let mut tree = LoopTree::new();
        for i in 0..DEPTH {
            let loop_info = NaturalLoop::new(i as u32, vec![]);
            tree.loops.push(LoopNode {
                loop_info,
                children: if i + 1 < DEPTH { vec![i + 1] } else { vec![] },
                parent: if i == 0 { None } else { Some(i - 1) },
            });
        }
        tree.roots.push(0);

        let mut depths: Vec<usize> = vec![0; DEPTH];
        tree.set_depths(0, 0, &mut depths);

        assert_eq!(depths[0], 0);
        assert_eq!(depths[DEPTH - 1], DEPTH - 1);
    }

}
