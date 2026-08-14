//! `cfg_algorithms` — Advanced CFG analysis algorithms.
//!
//! Provides dominator trees (Cooper et al.'s iterative RPO dataflow
//! algorithm — see [`DominatorTree::compute`]), post-dominator trees, natural-loop
//! detection, loop nesting trees, irreducible-CFG detection, control dependence
//! graphs, and structural analysis (interval/region identification).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgAlgoError {
    InvalidEntry(String),
    // Not currently constructed by any algorithm in this module (all lookups
    // degrade gracefully to empty slices/None instead of erroring) — kept
    // for API compatibility with downstream callers who match on it.
    NodeNotFound(u64),
    EmptyCfg,
    IrreducibleCfg,
    /// A real CFG node uses the reserved sentinel ID (`u64::MAX`) that
    /// [`PostDominatorTree::compute`] needs for its synthetic virtual-exit
    /// node, which would otherwise silently merge with (and corrupt the
    /// analysis of) that real node.
    ReservedNodeId(u64),
}

impl fmt::Display for CfgAlgoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntry(s) => write!(f, "invalid entry: {s}"),
            Self::NodeNotFound(n) => write!(f, "node not found: {n:#x}"),
            Self::EmptyCfg => write!(f, "empty CFG"),
            Self::IrreducibleCfg => write!(f, "CFG is irreducible"),
            Self::ReservedNodeId(n) => write!(
                f,
                "node id {n:#x} collides with the reserved virtual-exit sentinel"
            ),
        }
    }
}

impl std::error::Error for CfgAlgoError {}

// ─── CfgNode / SimpleCfg ─────────────────────────────────────────────────────

/// A minimal CFG node used for algorithm inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgNode {
    pub id: u64,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
}

/// A simple adjacency-list CFG used as input to the algorithms.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SimpleCfg {
    pub nodes: HashMap<u64, CfgNode>,
    pub entry: u64,
}

impl SimpleCfg {
    #[must_use]
    pub fn new(entry: u64) -> Self {
        Self {
            nodes: HashMap::new(),
            entry,
        }
    }

    /// Add a node (idempotent).
    pub fn add_node(&mut self, id: u64) {
        self.nodes.entry(id).or_insert_with(|| CfgNode {
            id,
            successors: Vec::new(),
            predecessors: Vec::new(),
        });
    }

    /// Add a directed edge.
    pub fn add_edge(&mut self, from: u64, to: u64) {
        self.add_node(from);
        self.add_node(to);
        let from_node = self.nodes.get_mut(&from).unwrap();
        if !from_node.successors.contains(&to) {
            from_node.successors.push(to);
        }
        let to_node = self.nodes.get_mut(&to).unwrap();
        if !to_node.predecessors.contains(&from) {
            to_node.predecessors.push(from);
        }
    }

    /// Reverse the CFG (swap edges) for post-dominator computation.
    #[must_use]
    pub fn reverse(&self) -> Self {
        let mut rev = Self::new(self.entry);
        for node in self.nodes.values() {
            rev.add_node(node.id);
        }
        for node in self.nodes.values() {
            for &succ in &node.successors {
                rev.add_edge(succ, node.id);
            }
        }
        rev
    }

    /// Depth-first post-order traversal from entry.
    ///
    /// Implemented iteratively (explicit stack) rather than recursively: a
    /// recursive walk would push one stack frame per CFG node on the path
    /// from the entry, which risks a native stack overflow on large,
    /// deeply-chained functions (e.g. long linear blocks or deep loop
    /// nests) — those are exactly the inputs this crate processes.
    #[must_use]
    pub fn dfs_postorder(&self, entry: u64) -> Vec<u64> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        // Each frame: (node, next successor index to visit).
        let mut stack: Vec<(u64, usize)> = Vec::new();

        if visited.insert(entry) {
            stack.push((entry, 0));
        }

        while let Some(&(node, idx)) = stack.last() {
            let successors = self
                .nodes
                .get(&node)
                .map(|n| n.successors.as_slice())
                .unwrap_or(&[]);
            if idx < successors.len() {
                let succ = successors[idx];
                stack.last_mut().unwrap().1 += 1;
                if visited.insert(succ) {
                    stack.push((succ, 0));
                }
            } else {
                order.push(node);
                stack.pop();
            }
        }

        order
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ─── DominatorTree ───────────────────────────────────────────────────────────

/// Dominator tree computed by the Lengauer-Tarjan algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DominatorTree {
    /// Maps each node ID to its immediate dominator ID.
    pub idom: HashMap<u64, Option<u64>>,
    /// DFS pre-order numbers.
    pub preorder: HashMap<u64, usize>,
    /// Nodes in DFS pre-order.
    pub dfs_order: Vec<u64>,
}

impl DominatorTree {
    /// Compute the dominator tree.
    ///
    /// Despite the module doc's mention of Lengauer-Tarjan, this uses
    /// Cooper, Harvey & Kennedy's iterative reverse-post-order dataflow
    /// algorithm ("A Simple, Fast Dominance Algorithm"), which converges to
    /// the same unique idom assignment and is simpler to implement
    /// iteratively (avoiding recursion-depth issues on deep CFGs).
    pub fn compute(cfg: &SimpleCfg) -> Result<Self, CfgAlgoError> {
        if cfg.nodes.is_empty() {
            return Err(CfgAlgoError::EmptyCfg);
        }
        if !cfg.nodes.contains_key(&cfg.entry) {
            return Err(CfgAlgoError::InvalidEntry(format!("{:#x}", cfg.entry)));
        }

        // Simple iterative dataflow dominator computation (Cooper et al.).
        let dfs_order = cfg.dfs_postorder(cfg.entry);
        if dfs_order.is_empty() {
            return Err(CfgAlgoError::EmptyCfg);
        }
        // Assign reverse post-order numbers.
        let rpo: Vec<u64> = dfs_order.iter().rev().copied().collect();
        let mut rpo_num: HashMap<u64, usize> = HashMap::with_capacity(rpo.len());
        for (i, &n) in rpo.iter().enumerate() {
            rpo_num.insert(n, i);
        }

        let mut idom: HashMap<u64, u64> = HashMap::new();
        idom.insert(cfg.entry, cfg.entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == cfg.entry {
                    continue;
                }
                let preds: &[u64] = cfg
                    .nodes
                    .get(&b)
                    .map(|n| n.predecessors.as_slice())
                    .unwrap_or(&[]);
                let mut new_idom: Option<u64> = None;
                for &p in preds {
                    if !idom.contains_key(&p) {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(cur) => Self::intersect(cur, p, &idom, &rpo_num),
                    });
                }
                if let Some(new) = new_idom {
                    let old = idom.get(&b).copied();
                    if old != Some(new) {
                        idom.insert(b, new);
                        changed = true;
                    }
                }
            }
        }

        let mut preorder = HashMap::with_capacity(rpo.len());
        for (i, &n) in rpo.iter().enumerate() {
            preorder.insert(n, i);
        }

        let idom_opt: HashMap<u64, Option<u64>> = idom
            .into_iter()
            .map(|(k, v)| (k, if k == cfg.entry { None } else { Some(v) }))
            .collect();

        Ok(Self {
            idom: idom_opt,
            preorder,
            dfs_order,
        })
    }

    fn intersect(
        mut b1: u64,
        mut b2: u64,
        idom: &HashMap<u64, u64>,
        rpo_num: &HashMap<u64, usize>,
    ) -> u64 {
        while b1 != b2 {
            while rpo_num.get(&b1).copied().unwrap_or(usize::MAX)
                > rpo_num.get(&b2).copied().unwrap_or(usize::MAX)
            {
                b1 = *idom.get(&b1).unwrap_or(&b1);
            }
            while rpo_num.get(&b2).copied().unwrap_or(usize::MAX)
                > rpo_num.get(&b1).copied().unwrap_or(usize::MAX)
            {
                b2 = *idom.get(&b2).unwrap_or(&b2);
            }
        }
        b1
    }

    /// Returns `true` if `a` strictly dominates `b`.
    #[must_use]
    pub fn strictly_dominates(&self, a: u64, b: u64) -> bool {
        if a == b {
            return false;
        }
        let mut cur = b;
        loop {
            match self.idom.get(&cur).and_then(|x| *x) {
                None => return false,
                Some(d) if d == a => return true,
                Some(d) if d == cur => return false, // reached root
                Some(d) => cur = d,
            }
        }
    }

    /// Returns `true` if `a` dominates `b` (including a==b).
    #[must_use]
    pub fn dominates(&self, a: u64, b: u64) -> bool {
        a == b || self.strictly_dominates(a, b)
    }

    /// Children of a node in the dominator tree.
    #[must_use]
    pub fn children(&self, node: u64) -> Vec<u64> {
        self.idom
            .iter()
            .filter_map(|(&n, &idom)| {
                if idom == Some(node) && n != node {
                    Some(n)
                } else {
                    None
                }
            })
            .collect()
    }
}

// ─── PostDominatorTree ───────────────────────────────────────────────────────

/// Post-dominator tree: computed on the reversed CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostDominatorTree {
    pub inner: DominatorTree,
    /// The virtual exit node used for merging multiple exit nodes.
    pub virtual_exit: u64,
}

impl PostDominatorTree {
    /// Compute the post-dominator tree.
    ///
    /// A virtual exit node is created that all natural exit nodes connect to.
    pub fn compute(cfg: &SimpleCfg) -> Result<Self, CfgAlgoError> {
        let virtual_exit = u64::MAX;
        if cfg.nodes.contains_key(&virtual_exit) {
            // A real node already occupies the sentinel ID: reusing it would
            // silently merge the synthetic virtual-exit node with that real
            // node (same HashMap entry), corrupting the post-dominator
            // computation instead of panicking — much harder to notice.
            return Err(CfgAlgoError::ReservedNodeId(virtual_exit));
        }

        // Find exit nodes (nodes with no successors).
        let exit_nodes: Vec<u64> = cfg
            .nodes
            .values()
            .filter(|n| n.successors.is_empty())
            .map(|n| n.id)
            .collect();

        let mut rev = cfg.reverse();
        rev.add_node(virtual_exit);
        rev.entry = virtual_exit;
        for &exit in &exit_nodes {
            rev.add_edge(virtual_exit, exit);
        }

        let inner = DominatorTree::compute(&rev)?;
        Ok(Self {
            inner,
            virtual_exit,
        })
    }

    /// Returns `true` if `a` post-dominates `b`.
    #[must_use]
    pub fn post_dominates(&self, a: u64, b: u64) -> bool {
        self.inner.dominates(a, b)
    }
}

// ─── NaturalLoop ─────────────────────────────────────────────────────────────

/// A natural loop in the CFG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaturalLoop {
    /// Loop header (the dominator of all nodes in the loop).
    pub header: u64,
    /// The back-edge tail node.
    pub back_edge_tail: u64,
    /// All nodes in the loop body (including header).
    pub body: HashSet<u64>,
    /// Depth within a nesting structure (0 = outermost).
    pub depth: usize,
}

impl NaturalLoop {
    /// Construct a natural loop given its header and back-edge tail, using the CFG.
    #[must_use]
    pub fn build(header: u64, tail: u64, cfg: &SimpleCfg) -> Self {
        let mut body = HashSet::new();
        body.insert(header);
        body.insert(tail);
        // BFS backwards from tail, stopping at header.
        let mut queue = VecDeque::new();
        if tail != header {
            queue.push_back(tail);
        }
        while let Some(node) = queue.pop_front() {
            if let Some(n) = cfg.nodes.get(&node) {
                for &pred in &n.predecessors {
                    if body.insert(pred) && pred != header {
                        queue.push_back(pred);
                    }
                }
            }
        }
        Self {
            header,
            back_edge_tail: tail,
            body,
            depth: 0,
        }
    }

    #[must_use]
    pub fn contains(&self, node: u64) -> bool {
        self.body.contains(&node)
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.body.len()
    }

    /// Returns true if `other` is strictly nested inside this loop.
    #[must_use]
    pub fn contains_loop(&self, other: &Self) -> bool {
        other.header != self.header && self.body.contains(&other.header)
    }
}

/// Detect all natural loops in a CFG using back-edge detection.
#[must_use]
pub fn find_natural_loops(cfg: &SimpleCfg, dom: &DominatorTree) -> Vec<NaturalLoop> {
    let mut loops = Vec::new();
    // A back edge is an edge (a → b) where b dominates a.
    for node in cfg.nodes.values() {
        for &succ in &node.successors {
            if dom.dominates(succ, node.id) {
                // succ is a loop header; node.id is the back-edge tail.
                let natural_loop = NaturalLoop::build(succ, node.id, cfg);
                loops.push(natural_loop);
            }
        }
    }
    loops
}

// ─── LoopNestingTree ─────────────────────────────────────────────────────────

/// A tree representing the nesting relationship between loops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopNestingTree {
    pub loops: Vec<NaturalLoop>,
    /// Parent loop index for each loop (-1 = no parent).
    pub parent: Vec<Option<usize>>,
}

impl LoopNestingTree {
    /// Build the nesting tree from a set of natural loops.
    #[must_use]
    pub fn build(mut loops: Vec<NaturalLoop>) -> Self {
        let n = loops.len();
        let mut parent: Vec<Option<usize>> = vec![None; n];

        // For each loop, find its innermost enclosing loop.
        for i in 0..n {
            let mut smallest_encloser: Option<(usize, usize)> = None; // (index, size)
            for j in 0..n {
                if i == j {
                    continue;
                }
                if loops[j].contains_loop(&loops[i]) {
                    let size = loops[j].size();
                    if smallest_encloser.is_none_or(|(_, s)| size < s) {
                        smallest_encloser = Some((j, size));
                    }
                }
            }
            parent[i] = smallest_encloser.map(|(j, _)| j);
        }

        // Assign depths.
        for i in 0..n {
            let mut depth = 0usize;
            let mut cur = parent[i];
            while let Some(p) = cur {
                depth += 1;
                cur = parent[p];
            }
            loops[i].depth = depth;
        }

        Self { loops, parent }
    }

    /// Return loops at a given depth.
    #[must_use]
    pub fn at_depth(&self, depth: usize) -> Vec<&NaturalLoop> {
        self.loops.iter().filter(|l| l.depth == depth).collect()
    }

    /// Maximum nesting depth.
    #[must_use]
    pub fn max_depth(&self) -> usize {
        self.loops.iter().map(|l| l.depth).max().unwrap_or(0)
    }
}

// ─── IrreducibleCfg ──────────────────────────────────────────────────────────

/// Checks whether a CFG is irreducible using Tarjan's T1/T2 reduction rules.
pub struct IrreducibleCfgDetector;

impl IrreducibleCfgDetector {
    /// Returns `true` if the CFG contains an irreducible subgraph.
    ///
    /// Uses a single whole-graph Tarjan SCC pass to classify edges cheaply:
    /// an edge `node -> succ` can only be part of a "cycle without
    /// dominance" (and thus signal irreducibility) if `node` and `succ`
    /// lie in the *same* strongly connected component of the CFG. Edges
    /// crossing SCC boundaries (or touching trivial, non-looping SCCs) are
    /// rejected in O(1) without any per-edge DFS. Only edges within a
    /// nontrivial SCC pay for a bounded reachability search, and that
    /// search is restricted to the SCC's own nodes rather than the whole
    /// graph.
    #[must_use]
    pub fn is_irreducible(cfg: &SimpleCfg, dom: &DominatorTree) -> bool {
        let scc_id = Self::compute_scc_ids(cfg);

        for node in cfg.nodes.values() {
            for &succ in &node.successors {
                // Cross or forward edge where succ dominates node → back edge (ok).
                let is_back_edge = dom.dominates(succ, node.id);
                if is_back_edge {
                    continue;
                }
                // A cycle back to `node.id` can only exist if `succ` and
                // `node.id` are in the same SCC of the whole CFG.
                if scc_id.get(&succ) != scc_id.get(&node.id) {
                    continue;
                }
                if Self::has_cycle_without_dom(succ, node.id, cfg, dom, &scc_id) {
                    // Check if there's a path from succ back to node NOT through a dominator.
                    return true;
                }
            }
        }
        false
    }

    /// Computes a strongly-connected-component id for every node in `cfg`
    /// using an iterative Tarjan's algorithm (single O(V+E) pass).
    fn compute_scc_ids(cfg: &SimpleCfg) -> HashMap<u64, u32> {
        let mut index_counter: u32 = 0;
        let mut indices: HashMap<u64, u32> = HashMap::new();
        let mut lowlink: HashMap<u64, u32> = HashMap::new();
        let mut on_stack: HashSet<u64> = HashSet::new();
        let mut stack: Vec<u64> = Vec::new();
        let mut scc_id: HashMap<u64, u32> = HashMap::new();
        let mut next_scc: u32 = 0;

        // Explicit call-stack based Tarjan to avoid recursion-depth issues on
        // large CFGs. `call_stack` mirrors the recursive call chain exactly
        // (unlike a flat work-list, so lowlink propagation to the direct
        // parent is unambiguous): each frame is (node, next successor index).
        let mut call_stack: Vec<(u64, usize)> = Vec::new();

        for &root in cfg.nodes.keys() {
            if indices.contains_key(&root) {
                continue;
            }
            indices.insert(root, index_counter);
            lowlink.insert(root, index_counter);
            index_counter += 1;
            stack.push(root);
            on_stack.insert(root);
            call_stack.push((root, 0));

            while let Some(&(v, succ_idx)) = call_stack.last() {
                let successors = cfg
                    .nodes
                    .get(&v)
                    .map(|n| n.successors.as_slice())
                    .unwrap_or(&[]);
                if succ_idx < successors.len() {
                    let w = successors[succ_idx];
                    call_stack.last_mut().unwrap().1 += 1;
                    if !indices.contains_key(&w) {
                        indices.insert(w, index_counter);
                        lowlink.insert(w, index_counter);
                        index_counter += 1;
                        stack.push(w);
                        on_stack.insert(w);
                        call_stack.push((w, 0));
                    } else if on_stack.contains(&w) {
                        let w_idx = indices[&w];
                        let v_low = lowlink[&v];
                        if w_idx < v_low {
                            lowlink.insert(v, w_idx);
                        }
                    }
                } else {
                    // Finished visiting all successors of v.
                    call_stack.pop();
                    if lowlink[&v] == indices[&v] {
                        loop {
                            let w = stack.pop().expect("non-empty SCC stack");
                            on_stack.remove(&w);
                            scc_id.insert(w, next_scc);
                            if w == v {
                                break;
                            }
                        }
                        next_scc += 1;
                    }
                    if let Some(&(parent, _)) = call_stack.last() {
                        let v_low = lowlink[&v];
                        let p_low = lowlink[&parent];
                        if v_low < p_low {
                            lowlink.insert(parent, v_low);
                        }
                    }
                }
            }
        }

        scc_id
    }

    fn has_cycle_without_dom(
        start: u64,
        target: u64,
        cfg: &SimpleCfg,
        dom: &DominatorTree,
        scc_id: &HashMap<u64, u32>,
    ) -> bool {
        // Restrict the search to nodes within the same SCC as `target`,
        // since anything outside it cannot reach back to `target`.
        let target_scc = scc_id.get(&target);
        let mut visited = HashSet::new();
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            if node == target {
                return true;
            }
            if !visited.insert(node) {
                continue;
            }
            if let Some(n) = cfg.nodes.get(&node) {
                for &succ in &n.successors {
                    if scc_id.get(&succ) != target_scc {
                        continue;
                    }
                    // Never walk *into* an edge that is itself a back edge
                    // (i.e. `succ` dominates `node`). Such an edge is the
                    // loop's own legitimate re-entry through its single
                    // dominating header, already accounted for by the
                    // caller's back-edge check; following it here would
                    // just rediscover that same reducible cycle and falsely
                    // report irreducibility for an ordinary single-entry
                    // natural loop (e.g. a plain `while` loop reached via a
                    // forward edge into the header).
                    if dom.dominates(succ, node) {
                        continue;
                    }
                    // Any other edge is fair game: the textbook criterion is
                    // "a cycle survives once *back edges* are deleted", so
                    // the search must be allowed to walk every non-back
                    // edge. This used to additionally skip edges where
                    // `node` strictly dominates `succ` (i.e. dominator-tree
                    // edges), but an irreducible cycle can legitimately pass
                    // through such forward edges — e.g. 0→3→4→2→6→1→3 with
                    // 3 dominating 4 and 4 dominating 2 — so that extra
                    // filter caused false negatives (found by
                    // soundness_fuzz::reducibility_implementations_agree_fuzz).
                    stack.push(succ);
                }
            }
        }
        false
    }
}

// ─── ControlDependenceGraph ───────────────────────────────────────────────────

/// An edge in the control dependence graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdgEdge {
    pub from: u64,
    pub to: u64,
    pub label: bool, // true = control falls through to `to` if `from`'s condition is true.
}

/// The control dependence graph (CDG).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ControlDependenceGraph {
    pub edges: Vec<CdgEdge>,
    /// Control dependences per node: node → set of controlling nodes.
    pub dependences: HashMap<u64, Vec<u64>>,
}

impl ControlDependenceGraph {
    /// Build the CDG from a post-dominator tree.
    ///
    /// Node Y is control-dependent on X if:
    /// 1. There exists an edge X → Z in the CFG.
    /// 2. Y post-dominates Z.
    /// 3. Y does not strictly post-dominate X.
    ///
    /// Rather than testing every node `y` against `post_dominates` (an
    /// `O(V)` walk up the post-dominator tree per candidate, giving
    /// `O(E * V^2)` overall for dense-ish CFGs), walk from `z` up the
    /// post-dominator tree only as far as `idom(x)` (exclusive): every node
    /// on that path post-dominates `z` and, by construction, does not
    /// strictly post-dominate `x`. This is `O(E * depth)` instead.
    #[must_use]
    pub fn build(cfg: &SimpleCfg, pdt: &PostDominatorTree) -> Self {
        let mut edges = Vec::new();
        let mut dependences: HashMap<u64, Vec<u64>> = HashMap::new();

        for x in cfg.nodes.values() {
            for &z in &x.successors {
                // Stop walking once we reach the immediate post-dominator of
                // x (which strictly post-dominates x, so is excluded), or
                // once we run off the top of the tree.
                let stop_at = pdt.inner.idom.get(&x.id).copied().flatten();
                let mut y = z;
                loop {
                    if Some(y) == stop_at {
                        break;
                    }
                    edges.push(CdgEdge {
                        from: x.id,
                        to: y,
                        label: true,
                    });
                    dependences.entry(y).or_default().push(x.id);

                    match pdt.inner.idom.get(&y).copied().flatten() {
                        Some(next) if next != y => y = next,
                        _ => break,
                    }
                }
            }
        }
        Self { edges, dependences }
    }

    /// Return nodes that `node` is control-dependent on.
    #[must_use]
    pub fn controllers_of(&self, node: u64) -> &[u64] {
        self.dependences
            .get(&node)
            .map(std::vec::Vec::as_slice)
            .unwrap_or(&[])
    }

    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ─── StructuralAnalysis ───────────────────────────────────────────────────────

/// Region type in structural analysis.
///
/// Note: `Sequential`, `Loop`, and `Switch` are never constructed by
/// [`StructuralAnalysis::analyze`] today (it only emits `WhileLoop`/
/// `DoWhileLoop`/`Unstructured` for loop regions and `IfThen`/`IfThenElse`
/// for branch regions) — they exist for API/serialization compatibility with
/// downstream consumers but currently represent unimplemented detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionKind {
    Sequential,
    IfThen,
    IfThenElse,
    Loop,
    /// Natural loop with a single header.
    WhileLoop,
    DoWhileLoop,
    Switch,
    Unstructured,
}

/// A region identified during structural analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: usize,
    pub kind: RegionKind,
    pub header: u64,
    pub nodes: HashSet<u64>,
    pub exits: Vec<u64>,
}

/// Structural analysis on a CFG.
pub struct StructuralAnalysis;

impl StructuralAnalysis {
    /// Identify regions in the CFG.
    #[must_use]
    pub fn analyze(cfg: &SimpleCfg, loops: &[NaturalLoop]) -> Vec<Region> {
        let mut regions = Vec::new();
        let mut region_id = 0;

        // Mark loop regions.
        for lp in loops {
            // `lp.body` is a `HashSet`, so its iteration order is
            // nondeterministic across runs on the same input. Walk the
            // body in sorted node-id order (and de-dup/sort the collected
            // exits) so the resulting `exits` list — and hence the
            // `Region` it feeds into — is stable and reproducible.
            let mut body_sorted: Vec<u64> = lp.body.iter().copied().collect();
            body_sorted.sort_unstable();
            let mut exits: Vec<u64> = body_sorted
                .iter()
                .flat_map(|&n| {
                    cfg.nodes
                        .get(&n)
                        .map(|node| {
                            node.successors
                                .iter()
                                .filter(|&&s| !lp.body.contains(&s))
                                .copied()
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .collect();
            exits.sort_unstable();
            exits.dedup();

            // Classify loop kind.
            let header_preds_in_loop: Vec<u64> = cfg
                .nodes
                .get(&lp.header)
                .map(|n| {
                    n.predecessors
                        .iter()
                        .filter(|&&p| lp.body.contains(&p))
                        .copied()
                        .collect()
                })
                .unwrap_or_default();

            let kind = if header_preds_in_loop.is_empty() {
                RegionKind::Unstructured
            } else if lp.header == lp.back_edge_tail {
                RegionKind::DoWhileLoop
            } else {
                RegionKind::WhileLoop
            };

            regions.push(Region {
                id: region_id,
                kind,
                header: lp.header,
                nodes: lp.body.clone(),
                exits,
            });
            region_id += 1;
        }

        // Mark if-then / if-then-else regions based on branch structure.
        //
        // `cfg.nodes` is a `HashMap`, so `.values()` iterates in an
        // unspecified, run-dependent order; walking it directly made the
        // order (and therefore the `id`s) of the emitted if/if-else
        // regions nondeterministic across otherwise-identical runs on the
        // same CFG. Sort by node id first for reproducible output.
        let mut node_ids: Vec<u64> = cfg.nodes.keys().copied().collect();
        node_ids.sort_unstable();
        for id in node_ids {
            let node = &cfg.nodes[&id];
            if node.successors.len() == 2 {
                let t = node.successors[0];
                let f = node.successors[1];
                // Check if they converge at the same node.
                let t_succs: HashSet<u64> = cfg
                    .nodes
                    .get(&t)
                    .map(|n| n.successors.iter().copied().collect())
                    .unwrap_or_default();
                let f_succs: HashSet<u64> = cfg
                    .nodes
                    .get(&f)
                    .map(|n| n.successors.iter().copied().collect())
                    .unwrap_or_default();
                // `HashSet::intersection` yields items in an unspecified
                // order, so picking `common[0]` below (as the chosen join
                // node) was nondeterministic whenever the branches share
                // more than one common successor. Sort for a stable,
                // reproducible choice.
                let mut common: Vec<u64> = t_succs.intersection(&f_succs).copied().collect();
                common.sort_unstable();

                if common.is_empty() {
                    // If-then (one branch goes directly to the other's successor).
                    let mut nodes = HashSet::new();
                    nodes.insert(node.id);
                    nodes.insert(t);
                    regions.push(Region {
                        id: region_id,
                        kind: RegionKind::IfThen,
                        header: node.id,
                        nodes,
                        exits: vec![f],
                    });
                    region_id += 1;
                } else {
                    let join = common[0];
                    let mut nodes = HashSet::new();
                    nodes.insert(node.id);
                    nodes.insert(t);
                    nodes.insert(f);
                    regions.push(Region {
                        id: region_id,
                        kind: RegionKind::IfThenElse,
                        header: node.id,
                        nodes,
                        exits: vec![join],
                    });
                    region_id += 1;
                }
            }
        }
        regions
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a simple linear CFG: 0 → 1 → 2 → 3.
    fn linear_cfg() -> SimpleCfg {
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 3);
        cfg
    }

    /// Build a simple loop CFG: 0 → 1 → 2 → 1 (back edge), 2 → 3.
    fn loop_cfg() -> SimpleCfg {
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1); // back edge
        cfg.add_edge(2, 3);
        cfg
    }

    /// Diamond CFG: 0 → {1, 2}, {1, 2} → 3.
    fn diamond_cfg() -> SimpleCfg {
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);
        cfg
    }

    #[test]
    fn dominator_tree_linear() {
        let cfg = linear_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(dom.strictly_dominates(0, 1));
        assert!(dom.strictly_dominates(1, 2));
        assert!(dom.strictly_dominates(0, 3));
    }

    #[test]
    fn dominator_tree_diamond() {
        let cfg = diamond_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        // 0 dominates 1, 2, 3.
        assert!(dom.strictly_dominates(0, 1));
        assert!(dom.strictly_dominates(0, 2));
        assert!(dom.strictly_dominates(0, 3));
        // 1 does not dominate 3 (2 is an alternative path).
        assert!(!dom.strictly_dominates(1, 3));
    }

    #[test]
    fn dominator_tree_dominates_self() {
        let cfg = linear_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(dom.dominates(0, 0));
    }

    #[test]
    fn irreducible_detector_linear_is_reducible() {
        let cfg = linear_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(!IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn irreducible_detector_natural_loop_is_reducible() {
        // A plain single-entry `while`-style loop (0 → 1 → 2 → 1 back edge,
        // 2 → 3 exit) is textbook-reducible: it has exactly one header (1)
        // dominating the whole loop body, and no alternate path reaches the
        // body from outside except through that header.
        //
        // This was previously misflagged as irreducible: the forward edge
        // 1 → 2 triggered a reachability search from 2 back to 1 that
        // walked straight through the loop's own back edge (2 → 1),
        // "discovering" the very cycle that back edge already accounts
        // for. Excluding edges that are themselves back edges (target
        // dominates source) from that search fixes the false positive.
        let cfg = loop_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(!IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn irreducible_detector_diamond_is_reducible() {
        let cfg = diamond_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(!IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    /// Classic irreducible CFG: two headers (1, 2) each reachable from the
    /// entry and each other, with neither dominating the other. Entry 0 →
    /// {1, 2}; 1 → 2; 2 → 1. Neither 1 nor 2 dominates the other, so the
    /// 1↔2 cycle has no single dominating header ⇒ irreducible.
    fn multi_entry_loop_cfg() -> SimpleCfg {
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1);
        cfg
    }

    #[test]
    fn irreducible_detector_detects_multi_entry_loop() {
        let cfg = multi_entry_loop_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn irreducible_detector_disjoint_sccs_no_cross_contamination() {
        // Two independent simple loops hanging off a shared entry: neither
        // loop's nodes are in the other's SCC. The important property for
        // this rewrite is that the O(1) SCC-membership pre-filter yields
        // exactly the same verdict as the unfiltered per-edge DFS would
        // (i.e. it must not introduce cross-component false
        // positives/negatives), which we pin here against the
        // known-consistent single-loop result.
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1); // loop A back edge
        cfg.add_edge(0, 3);
        cfg.add_edge(3, 4);
        cfg.add_edge(4, 3); // loop B back edge
        let dom = DominatorTree::compute(&cfg).unwrap();
        let combined = IrreducibleCfgDetector::is_irreducible(&cfg, &dom);
        // Must match what a single isolated loop (loop_cfg-style) reports,
        // since the two loops here are structurally identical and
        // independent — no cross-SCC leakage should change the verdict.
        assert_eq!(combined, IrreducibleCfgDetector::is_irreducible(&loop_cfg(), &dom_for_loop_cfg()));
    }

    fn dom_for_loop_cfg() -> DominatorTree {
        DominatorTree::compute(&loop_cfg()).unwrap()
    }

    // --- Handwritten corpus of known-reducible CFGs (regression for the
    // back-edge self-reachability false positive) ---

    #[test]
    fn irreducible_detector_self_loop_is_reducible() {
        // 0 → 1 → 1 (self loop) → 2. A self loop is trivially reducible:
        // its only header is 1, dominating itself.
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 1);
        cfg.add_edge(1, 2);
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(!IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn irreducible_detector_nested_loop_is_reducible() {
        // Outer loop 1↔3 (via 2), inner loop 2 self-contained via 2↔2? use a
        // classic nested-loop shape instead:
        // 0 → 1 → 2 → 3 → 2 (inner back edge) ; 3 → 1 (outer back edge) ; 3 → 4 (exit)
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 3);
        cfg.add_edge(3, 2); // inner back edge
        cfg.add_edge(3, 1); // outer back edge
        cfg.add_edge(3, 4); // exit
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(!IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn irreducible_detector_if_inside_loop_is_reducible() {
        // Loop header 1 with an if/else diamond (2, 3) inside the body,
        // merging at 4, which loops back to 1; 1 → 5 exits the loop.
        // 0 → 1 → {2, 3} → 4 → 1 (back edge); 1 → 5.
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 4);
        cfg.add_edge(3, 4);
        cfg.add_edge(4, 1); // back edge
        cfg.add_edge(1, 5); // exit
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(!IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn irreducible_detector_loop_with_early_exit_is_reducible() {
        // Loop with a break: 0 → 1 → 2 → 1 (back edge); 2 → 3 (break exit);
        // 1 → 3 (loop-condition exit). Two distinct exits from the loop,
        // still single-entry (via 1) and thus reducible.
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1); // back edge
        cfg.add_edge(2, 3); // break exit
        cfg.add_edge(1, 3); // loop-condition exit
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(!IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn irreducible_detector_still_flags_true_irreducible_loop() {
        // Sanity check that the fix does not silently disable detection:
        // the classic two-header 1↔2 loop with independent entries 0→1 and
        // 0→2 must still be reported irreducible.
        let cfg = multi_entry_loop_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn dominator_tree_loop() {
        let cfg = loop_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        // 1 dominates 2 (only path to 2 is through 1).
        assert!(dom.strictly_dominates(1, 2));
    }

    #[test]
    fn dominator_tree_children() {
        let cfg = linear_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        let children_of_0 = dom.children(0);
        assert!(!children_of_0.is_empty());
    }

    #[test]
    fn dominator_tree_empty_cfg_error() {
        let cfg = SimpleCfg::new(0);
        let result = DominatorTree::compute(&cfg);
        assert!(matches!(result, Err(CfgAlgoError::EmptyCfg)));
    }

    // Coverage gap: a node registered in the CFG (e.g. via `add_node`, or
    // dead code never reached from `entry`) but unreachable from `entry` gets
    // no `idom` entry at all. `strictly_dominates`/`dominates`/`children`
    // must degrade gracefully (no panic, no false "dominates" claim) instead
    // of assuming every node the caller queries about was visited.
    #[test]
    fn dominator_tree_disconnected_node_is_handled_gracefully() {
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        // Node 99 is disconnected: reachable from nothing, reaches nothing.
        cfg.add_node(99);

        let dom = DominatorTree::compute(&cfg).unwrap();

        // The disconnected node never appears in the reverse-post-order walk
        // from `entry`, so it must not get an idom entry.
        assert!(!dom.idom.contains_key(&99));

        // Queries involving the disconnected node must resolve without
        // panicking, and must not spuriously claim a dominance relationship.
        assert!(!dom.dominates(0, 99));
        assert!(!dom.strictly_dominates(0, 99));
        assert!(!dom.dominates(99, 0));
        assert!(!dom.strictly_dominates(99, 0));
        assert!(dom.children(99).is_empty());

        // The reachable part of the graph is unaffected.
        assert!(dom.dominates(0, 1));
    }

    #[test]
    fn post_dominator_tree_linear() {
        let cfg = linear_cfg();
        let pdt = PostDominatorTree::compute(&cfg).unwrap();
        // In a linear cfg, node 3 post-dominates all others.
        assert!(pdt.post_dominates(3, 0));
        assert!(pdt.post_dominates(3, 1));
        assert!(pdt.post_dominates(3, 2));
    }

    #[test]
    fn natural_loop_build() {
        let cfg = loop_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        let loops = find_natural_loops(&cfg, &dom);
        assert!(!loops.is_empty());
        // Loop header should be 1 (target of back edge 2 → 1).
        let lp = loops.iter().find(|l| l.header == 1).unwrap();
        assert!(lp.body.contains(&1));
        assert!(lp.body.contains(&2));
    }

    #[test]
    fn natural_loop_no_loop_linear() {
        let cfg = linear_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        let loops = find_natural_loops(&cfg, &dom);
        assert!(loops.is_empty());
    }

    #[test]
    fn loop_nesting_tree_build() {
        let outer = NaturalLoop {
            header: 0,
            back_edge_tail: 5,
            body: [0, 1, 2, 3, 4, 5].iter().copied().collect(),
            depth: 0,
        };
        let inner = NaturalLoop {
            header: 2,
            back_edge_tail: 3,
            body: [2, 3].iter().copied().collect(),
            depth: 0,
        };
        let tree = LoopNestingTree::build(vec![outer, inner]);
        assert!(tree.max_depth() >= 1);
    }

    #[test]
    fn loop_nesting_at_depth() {
        let outer = NaturalLoop {
            header: 0,
            back_edge_tail: 5,
            body: [0, 1, 2, 3, 4, 5].iter().copied().collect(),
            depth: 0,
        };
        let inner = NaturalLoop {
            header: 2,
            back_edge_tail: 3,
            body: [2, 3].iter().copied().collect(),
            depth: 0,
        };
        let tree = LoopNestingTree::build(vec![outer, inner]);
        let depth_0 = tree.at_depth(0);
        assert!(!depth_0.is_empty());
    }

    #[test]
    fn irreducible_cfg_linear_is_reducible() {
        let cfg = linear_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(!IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn simple_cfg_reverse() {
        let cfg = linear_cfg();
        let rev = cfg.reverse();
        // Original has 0→1; reversed should have 1→0.
        assert!(rev.nodes[&1].successors.contains(&0));
    }

    #[test]
    fn simple_cfg_node_count() {
        let cfg = linear_cfg();
        assert_eq!(cfg.node_count(), 4);
    }

    #[test]
    fn control_dependence_graph_diamond() {
        let cfg = diamond_cfg();
        let pdt = PostDominatorTree::compute(&cfg).unwrap();
        let cdg = ControlDependenceGraph::build(&cfg, &pdt);
        // Node 1 and 2 should be control-dependent on node 0.
        // (CDG may include more edges depending on post-dom resolution.)
        let _ = cdg.edge_count(); // Just ensure no panic.
    }

    /// A CFG with a genuine control-dependent region: 0 branches to {1,2},
    /// both converge at 3, and 1 additionally branches to {4,5} converging
    /// back at 3. Nodes 4 and 5 should be control-dependent on 1 but not on
    /// 0 (since 1 does not post-dominate 0, but the join for 1's branch is
    /// still reached unconditionally once 1 executes... more precisely we
    /// check the direct diamond dependences that must hold regardless of
    /// exact post-dominator resolution): 1 and 2 are control-dependent on 0.
    #[test]
    fn control_dependence_graph_diamond_dependences() {
        let cfg = diamond_cfg();
        let pdt = PostDominatorTree::compute(&cfg).unwrap();
        let cdg = ControlDependenceGraph::build(&cfg, &pdt);
        assert!(cdg.controllers_of(1).contains(&0));
        assert!(cdg.controllers_of(2).contains(&0));
        // The merge node 3 is not control-dependent on the branch at 0
        // (it is reached on every path from 0).
        assert!(!cdg.controllers_of(3).contains(&0));
    }

    #[test]
    fn structural_analysis_loop_region() {
        let cfg = loop_cfg();
        let dom = DominatorTree::compute(&cfg).unwrap();
        let loops = find_natural_loops(&cfg, &dom);
        let regions = StructuralAnalysis::analyze(&cfg, &loops);
        assert!(!regions.is_empty());
        assert!(
            regions
                .iter()
                .any(|r| matches!(r.kind, RegionKind::WhileLoop | RegionKind::DoWhileLoop))
        );
    }

    #[test]
    fn structural_analysis_if_then() {
        // 0 → {1, 2}; 1 → 2 (one branch falls straight into the other's
        // target instead of a shared join): classic if-then with no else.
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 2);
        let regions = StructuralAnalysis::analyze(&cfg, &[]);
        let region = regions
            .iter()
            .find(|r| r.kind == RegionKind::IfThen)
            .expect("expected an IfThen region");
        assert_eq!(region.header, 0);
        assert!(region.nodes.contains(&1));
        assert_eq!(region.exits, vec![2]);
    }

    #[test]
    fn natural_loop_contains_loop_nesting() {
        let outer = NaturalLoop {
            header: 0,
            back_edge_tail: 5,
            body: [0, 1, 2, 3, 4, 5].iter().copied().collect(),
            depth: 0,
        };
        let inner = NaturalLoop {
            header: 2,
            back_edge_tail: 3,
            body: [2, 3].iter().copied().collect(),
            depth: 0,
        };
        assert!(outer.contains_loop(&inner));
        assert!(!inner.contains_loop(&outer));
        // A loop never "contains" itself under this definition.
        assert!(!outer.contains_loop(&outer));
    }

    #[test]
    fn loop_nesting_tree_parent_indices() {
        let outer = NaturalLoop {
            header: 0,
            back_edge_tail: 5,
            body: [0, 1, 2, 3, 4, 5].iter().copied().collect(),
            depth: 0,
        };
        let inner = NaturalLoop {
            header: 2,
            back_edge_tail: 3,
            body: [2, 3].iter().copied().collect(),
            depth: 0,
        };
        // outer at index 0, inner at index 1.
        let tree = LoopNestingTree::build(vec![outer, inner]);
        assert_eq!(tree.parent[0], None); // outer has no parent
        assert_eq!(tree.parent[1], Some(0)); // inner's parent is outer
        assert_eq!(tree.loops[0].depth, 0);
        assert_eq!(tree.loops[1].depth, 1);
    }

    #[test]
    fn control_dependence_graph_edge_fields() {
        let cfg = diamond_cfg();
        let pdt = PostDominatorTree::compute(&cfg).unwrap();
        let cdg = ControlDependenceGraph::build(&cfg, &pdt);
        // Every recorded edge from 0 must carry label == true (per the
        // documented convention) and point at a node actually control-
        // dependent on 0.
        for e in &cdg.edges {
            if e.from == 0 {
                assert!(e.label);
                assert!(cdg.controllers_of(e.to).contains(&0));
            }
        }
    }

    #[test]
    fn structural_analysis_if_then_else() {
        let cfg = diamond_cfg();
        let regions = StructuralAnalysis::analyze(&cfg, &[]);
        assert!(regions.iter().any(|r| r.kind == RegionKind::IfThenElse));
    }

    /// `StructuralAnalysis::analyze` walks `cfg.nodes` (a `HashMap`) and
    /// picks a join node out of a `HashSet` intersection. Both are
    /// iteration-order-dependent collections, so without sorting, the
    /// assigned `Region::id`s and the chosen if/else join node could vary
    /// from run to run on the exact same CFG. Run the analysis many times
    /// on a CFG with several branches (including one with two common
    /// successors) and require byte-identical output every time.
    #[test]
    fn structural_analysis_is_deterministic() {
        let mut cfg = SimpleCfg::new(0);
        // Several independent diamonds so `cfg.nodes` has many entries
        // whose HashMap iteration order could otherwise leak into `id`s.
        for base in [0u64, 10, 20, 30, 40] {
            cfg.add_edge(base, base + 1);
            cfg.add_edge(base, base + 2);
            cfg.add_edge(base + 1, base + 3);
            cfg.add_edge(base + 2, base + 3);
        }
        // A branch whose two arms share *two* common successors, so the
        // `common` HashSet-intersection join-node pick is exercised too.
        cfg.add_edge(100, 101);
        cfg.add_edge(100, 102);
        cfg.add_edge(101, 103);
        cfg.add_edge(101, 104);
        cfg.add_edge(102, 103);
        cfg.add_edge(102, 104);

        let first = StructuralAnalysis::analyze(&cfg, &[]);
        for _ in 0..25 {
            let again = StructuralAnalysis::analyze(&cfg, &[]);
            assert_eq!(again.len(), first.len());
            for (a, b) in again.iter().zip(first.iter()) {
                assert_eq!(a.id, b.id);
                assert_eq!(a.kind, b.kind);
                assert_eq!(a.header, b.header);
                assert_eq!(a.exits, b.exits);
            }
        }
    }

    #[test]
    fn natural_loop_contains() {
        let lp = NaturalLoop {
            header: 1,
            back_edge_tail: 2,
            body: [1, 2].iter().copied().collect(),
            depth: 0,
        };
        assert!(lp.contains(1));
        assert!(lp.contains(2));
        assert!(!lp.contains(99));
    }

    #[test]
    fn natural_loop_size() {
        let lp = NaturalLoop {
            header: 1,
            back_edge_tail: 2,
            body: [1, 2, 3].iter().copied().collect(),
            depth: 0,
        };
        assert_eq!(lp.size(), 3);
    }

    #[test]
    fn cfg_algo_error_display() {
        let e = CfgAlgoError::NodeNotFound(0xDEAD);
        assert!(e.to_string().contains("dead"));
    }

    #[test]
    fn dfs_postorder_visits_all() {
        let cfg = diamond_cfg();
        let order = cfg.dfs_postorder(0);
        assert_eq!(order.len(), 4);
    }

    /// `dfs_postorder` must be safe on very deep linear chains: it used to
    /// recurse one native stack frame per node, which overflows the stack
    /// well before this size on default thread stacks. The iterative
    /// version should handle it without crashing and produce a correct
    /// post-order (entry last).
    #[test]
    fn dfs_postorder_deep_chain_no_stack_overflow() {
        let n: u64 = 200_000;
        let mut cfg = SimpleCfg::new(0);
        for i in 0..n {
            cfg.add_edge(i, i + 1);
        }
        let order = cfg.dfs_postorder(0);
        assert_eq!(order.len() as u64, n + 1);
        // Post-order: deepest node first, entry last.
        assert_eq!(order[0], n);
        assert_eq!(order[order.len() - 1], 0);
    }

    /// Also exercise `DominatorTree::compute` (which calls `dfs_postorder`
    /// internally) on a deep chain, since that's the real hot path.
    #[test]
    fn dominator_tree_deep_chain_no_stack_overflow() {
        let n: u64 = 100_000;
        let mut cfg = SimpleCfg::new(0);
        for i in 0..n {
            cfg.add_edge(i, i + 1);
        }
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(dom.strictly_dominates(0, n));
    }

    #[test]
    fn post_dominator_tree_empty_cfg_ok() {
        // No real nodes at all: only the synthetic virtual-exit node exists,
        // so this must succeed (not panic / not EmptyCfg) rather than being
        // treated like `DominatorTree::compute` on an empty CFG.
        let cfg = SimpleCfg::new(0);
        let pdt = PostDominatorTree::compute(&cfg).unwrap();
        assert_eq!(pdt.inner.dfs_order, vec![u64::MAX]);
    }

    #[test]
    fn post_dominator_tree_rejects_reserved_node_id() {
        // A node legitimately using the u64::MAX sentinel must be rejected
        // rather than silently merged with the synthetic virtual-exit node
        // (see `CfgAlgoError::ReservedNodeId`).
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, u64::MAX);
        let result = PostDominatorTree::compute(&cfg);
        assert!(matches!(
            result,
            Err(CfgAlgoError::ReservedNodeId(n)) if n == u64::MAX
        ));
    }

    #[test]
    fn cfg_algo_error_reserved_node_id_display() {
        let e = CfgAlgoError::ReservedNodeId(u64::MAX);
        assert!(e.to_string().contains("reserved"));
    }

    #[test]
    fn simple_cfg_add_edge_bidirectional() {
        let mut cfg = SimpleCfg::new(0);
        cfg.add_edge(0, 1);
        assert!(cfg.nodes[&0].successors.contains(&1));
        assert!(cfg.nodes[&1].predecessors.contains(&0));
    }

    // --- Reference-definition fuzz check for `IrreducibleCfgDetector` ---
    //
    // The textbook definition: a flow graph is reducible iff, after deleting
    // every back edge (an edge `a -> b` where `b` dominates `a`), the
    // remaining graph is acyclic. This reference implementation is
    // deliberately naive (`O(V*E)`-ish, full-graph DFS) so it is a trustworthy
    // oracle independent of the SCC-based fast path under test.
    fn reference_is_irreducible(cfg: &SimpleCfg, dom: &DominatorTree) -> bool {
        // Build the graph with back edges removed.
        let mut succs: HashMap<u64, Vec<u64>> = HashMap::new();
        for node in cfg.nodes.values() {
            let kept: Vec<u64> = node
                .successors
                .iter()
                .copied()
                .filter(|&s| !dom.dominates(s, node.id))
                .collect();
            succs.insert(node.id, kept);
        }
        // DFS-based cycle detection (white/gray/black) over the filtered graph.
        #[derive(Clone, Copy, PartialEq)]
        enum Color {
            White,
            Gray,
            Black,
        }
        let mut color: HashMap<u64, Color> = cfg.nodes.keys().map(|&n| (n, Color::White)).collect();
        for &start in cfg.nodes.keys() {
            if color[&start] != Color::White {
                continue;
            }
            // Explicit stack DFS: (node, next child index).
            let mut stack: Vec<(u64, usize)> = vec![(start, 0)];
            color.insert(start, Color::Gray);
            while let Some(&(node, idx)) = stack.last() {
                let children = succs.get(&node).map(Vec::as_slice).unwrap_or(&[]);
                if idx < children.len() {
                    let child = children[idx];
                    stack.last_mut().unwrap().1 += 1;
                    match color.get(&child).copied().unwrap_or(Color::White) {
                        Color::White => {
                            color.insert(child, Color::Gray);
                            stack.push((child, 0));
                        }
                        Color::Gray => return true, // back edge in filtered graph => cycle
                        Color::Black => {}
                    }
                } else {
                    color.insert(node, Color::Black);
                    stack.pop();
                }
            }
        }
        false
    }

    use crate::test_prng::Xorshift;

    /// Brute-force reference dominance check: `a` dominates `b` iff every
    /// path from `entry` to `b` passes through `a`, which we test directly
    /// by deleting `a` from the graph (unless `a == b`) and checking whether
    /// `b` is still reachable from `entry`.
    fn reference_dominates(cfg: &SimpleCfg, entry: u64, a: u64, b: u64) -> bool {
        if a == b {
            return true;
        }
        if !cfg.nodes.contains_key(&b) {
            return false;
        }
        let mut visited = HashSet::new();
        let mut stack = vec![entry];
        while let Some(node) = stack.pop() {
            if node == a || !visited.insert(node) {
                continue;
            }
            if let Some(n) = cfg.nodes.get(&node) {
                for &succ in &n.successors {
                    stack.push(succ);
                }
            }
        }
        // `b` is dominated by `a` iff it is unreachable from entry once `a`
        // is removed, but only among nodes actually reachable from entry in
        // the first place (otherwise every node "dominates" unreachable
        // nodes vacuously, which the reachable-only DominatorTree doesn't
        // model).
        let mut all_reachable = HashSet::new();
        let mut stack2 = vec![entry];
        while let Some(node) = stack2.pop() {
            if !all_reachable.insert(node) {
                continue;
            }
            if let Some(n) = cfg.nodes.get(&node) {
                for &succ in &n.successors {
                    stack2.push(succ);
                }
            }
        }
        all_reachable.contains(&b) && !visited.contains(&b)
    }

    #[test]
    fn dominator_tree_matches_reference_definition_fuzz() {
        let mut rng = Xorshift(0xD1B54A32D192ED03);
        for trial in 0..500 {
            let n_nodes = 3 + (rng.range(6) as usize);
            let mut cfg = SimpleCfg::new(0);
            for i in 0..n_nodes as u64 {
                cfg.add_node(i);
            }
            let n_edges = n_nodes + (rng.range(n_nodes as u64 + 2) as usize);
            for _ in 0..n_edges {
                let from = rng.range(n_nodes as u64);
                let to = rng.range(n_nodes as u64);
                cfg.add_edge(from, to);
            }
            let Ok(dom) = DominatorTree::compute(&cfg) else {
                continue;
            };
            for &a in cfg.nodes.keys() {
                for &b in cfg.nodes.keys() {
                    let expected = reference_dominates(&cfg, cfg.entry, a, b);
                    let actual = dom.dominates(a, b);
                    assert_eq!(
                        actual, expected,
                        "trial {trial}: dominates({a},{b}) mismatch on cfg {:?}",
                        cfg.nodes
                    );
                }
            }
        }
    }

    /// Brute-force reference post-dominance check: `a` post-dominates `b` iff
    /// every path from `b` to any exit node (no successors) passes through
    /// `a`. Tested directly by deleting `a` and checking whether `b` can
    /// still reach an exit. Restricted to nodes that can reach an exit at
    /// all — nodes trapped in an infinite loop are unreachable from the
    /// virtual exit in the reversed graph and the reachable-only tree does
    /// not model them (mirrors `reference_dominates`).
    fn reference_post_dominates(cfg: &SimpleCfg, a: u64, b: u64) -> bool {
        if a == b {
            return true;
        }
        let exits: HashSet<u64> = cfg
            .nodes
            .values()
            .filter(|n| n.successors.is_empty())
            .map(|n| n.id)
            .collect();
        // Forward reachability from `b`, optionally with `a` deleted.
        let can_reach_exit = |start: u64, skip: Option<u64>| -> bool {
            let mut visited = HashSet::new();
            let mut stack = vec![start];
            while let Some(node) = stack.pop() {
                if Some(node) == skip || !visited.insert(node) {
                    continue;
                }
                if exits.contains(&node) {
                    return true;
                }
                if let Some(n) = cfg.nodes.get(&node) {
                    for &succ in &n.successors {
                        stack.push(succ);
                    }
                }
            }
            false
        };
        // Only meaningful when `b` can reach an exit in the first place.
        can_reach_exit(b, None) && !can_reach_exit(b, Some(a))
    }

    #[test]
    fn post_dominator_tree_matches_reference_definition_fuzz() {
        let mut rng = Xorshift(0xC0FFEE123456789B);
        for trial in 0..500 {
            let n_nodes = 3 + (rng.range(6) as usize);
            let mut cfg = SimpleCfg::new(0);
            for i in 0..n_nodes as u64 {
                cfg.add_node(i);
            }
            let n_edges = n_nodes + (rng.range(n_nodes as u64 + 2) as usize);
            for _ in 0..n_edges {
                let from = rng.range(n_nodes as u64);
                let to = rng.range(n_nodes as u64);
                cfg.add_edge(from, to);
            }
            let Ok(pdt) = PostDominatorTree::compute(&cfg) else {
                continue;
            };
            for &a in cfg.nodes.keys() {
                for &b in cfg.nodes.keys() {
                    let expected = reference_post_dominates(&cfg, a, b);
                    let actual = pdt.post_dominates(a, b);
                    assert_eq!(
                        actual, expected,
                        "trial {trial}: post_dominates({a},{b}) mismatch on cfg {:?}",
                        cfg.nodes
                    );
                }
            }
        }
    }

    #[test]
    fn irreducible_detector_cycle_through_dominator_tree_edges() {
        // Regression (found by soundness_fuzz::
        // reducibility_implementations_agree_fuzz): the multi-entry cycle
        // 3 → 4 → 2 → 6 → 1 → 3 is entered at both 3 and 6 (from entry 0),
        // so the CFG is irreducible — but the cycle passes through the
        // dominator-tree edges 3→4 and 4→2, which the detector's cycle
        // search used to refuse to traverse, misreporting the CFG as
        // reducible.
        let mut cfg = SimpleCfg::new(0);
        for i in [0u64, 1, 2, 3, 4, 6] {
            cfg.add_node(i);
        }
        for (f, t) in [
            (0u64, 3u64),
            (0, 6),
            (1, 3),
            (2, 6),
            (3, 4),
            (4, 2),
            (6, 1),
        ] {
            cfg.add_edge(f, t);
        }
        let dom = DominatorTree::compute(&cfg).unwrap();
        assert!(reference_is_irreducible(&cfg, &dom));
        assert!(IrreducibleCfgDetector::is_irreducible(&cfg, &dom));
    }

    #[test]
    fn irreducible_detector_matches_reference_definition_fuzz() {
        let mut rng = Xorshift(0x9E3779B97F4A7C15);
        for trial in 0..500 {
            let n_nodes = 3 + (rng.range(6) as usize); // 3..=8 nodes
            let mut cfg = SimpleCfg::new(0);
            for i in 0..n_nodes as u64 {
                cfg.add_node(i);
            }
            // Random edges, biased toward a connected-ish graph.
            let n_edges = n_nodes + (rng.range(n_nodes as u64 + 2) as usize);
            for _ in 0..n_edges {
                let from = rng.range(n_nodes as u64);
                let to = rng.range(n_nodes as u64);
                cfg.add_edge(from, to);
            }
            let Ok(dom) = DominatorTree::compute(&cfg) else {
                continue;
            };
            let expected = reference_is_irreducible(&cfg, &dom);
            let actual = IrreducibleCfgDetector::is_irreducible(&cfg, &dom);
            assert_eq!(
                actual, expected,
                "trial {trial}: mismatch on cfg {:?} (entry {})",
                cfg.nodes, cfg.entry
            );
        }
    }
}
