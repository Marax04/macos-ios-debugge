// loop_structurer.rs — Loop structuring for control-flow reconstruction
// Detects natural loops, classifies them (while/do-while/for/infinite),
// extracts headers, bodies, and latches, and produces structured loop nodes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use crate::structural_regions::{Cfg, CfgEdge, NodeId, compute_idoms, find_back_edges, compute_rpo};

// ── Loop Classification ───────────────────────────────────────────────────────

/// Classification of a structured loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoopKind {
    /// `while (cond) { body }` — condition tested before body.
    While,
    /// `do { body } while (cond)` — condition tested after body.
    DoWhile,
    /// `for (init; cond; step) { body }` — syntactic sugar over while.
    For,
    /// Infinite loop: `while(true)` / `loop {}` — no natural exit.
    Infinite,
    /// Loop with multiple exit points (not reducible to a standard form).
    MultiExit,
}

impl fmt::Display for LoopKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::While => write!(f, "while"),
            Self::DoWhile => write!(f, "do-while"),
            Self::For => write!(f, "for"),
            Self::Infinite => write!(f, "infinite"),
            Self::MultiExit => write!(f, "multi-exit"),
        }
    }
}

// ── LoopHeader ────────────────────────────────────────────────────────────────

/// Identifies the loop header node and its properties.
#[derive(Debug, Clone)]
pub struct LoopHeader {
    pub node: NodeId,
    /// Nodes that are latches (back-edge sources pointing to this header).
    pub latches: Vec<NodeId>,
    /// For while/for loops: the condition-exit successor (outside the loop).
    pub exit_successor: Option<NodeId>,
    /// For while/for loops: the body-entry successor (inside the loop).
    pub body_entry: Option<NodeId>,
    /// Number of in-loop predecessors (excluding back-edges from outside).
    pub in_loop_pred_count: u32,
}

impl LoopHeader {
    #[must_use] 
    pub const fn new(node: NodeId) -> Self {
        Self {
            node,
            latches: Vec::new(),
            exit_successor: None,
            body_entry: None,
            in_loop_pred_count: 0,
        }
    }

    /// Whether this header has a structured exit condition (while/for style).
    #[must_use] 
    pub const fn has_exit_condition(&self) -> bool { self.exit_successor.is_some() }

    /// Add a latch node.
    pub fn add_latch(&mut self, latch: NodeId) { self.latches.push(latch); }
}

// ── LoopBody ──────────────────────────────────────────────────────────────────

/// The set of nodes belonging to a loop's body.
#[derive(Debug, Clone)]
pub struct LoopBody {
    /// All nodes inside the loop (including header).
    pub nodes: HashSet<NodeId>,
    /// Internal back-edges (latch→header).
    pub back_edges: Vec<CfgEdge>,
    /// Edges leaving the loop body to external nodes (exit edges).
    pub exit_edges: Vec<CfgEdge>,
    /// Nodes from which exit edges emanate.
    pub exit_nodes: Vec<NodeId>,
}

impl LoopBody {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            nodes: HashSet::new(),
            back_edges: Vec::new(),
            exit_edges: Vec::new(),
            exit_nodes: Vec::new(),
        }
    }

    #[must_use] 
    pub fn contains(&self, n: NodeId) -> bool { self.nodes.contains(&n) }

    #[must_use] 
    pub fn node_count(&self) -> usize { self.nodes.len() }

    #[must_use] 
    pub const fn exit_count(&self) -> usize { self.exit_edges.len() }

    #[must_use] 
    pub const fn is_single_exit(&self) -> bool { self.exit_edges.len() == 1 }
}

impl Default for LoopBody {
    fn default() -> Self { Self::new() }
}

// ── Loop ─────────────────────────────────────────────────────────────────────

/// A complete description of a detected loop in the CFG.
#[derive(Debug, Clone)]
pub struct Loop {
    pub id: u32,
    pub kind: LoopKind,
    pub header: LoopHeader,
    pub body: LoopBody,
    /// The single loop-exit destination (for while/do-while), if any.
    pub exit: Option<NodeId>,
    /// The induction variable, if identified (name).
    pub induction_var: Option<String>,
    /// Depth of nesting (0 = outermost).
    pub depth: u32,
    /// ID of the enclosing (parent) loop, if nested.
    pub parent_loop: Option<u32>,
    /// IDs of loops directly nested inside this one.
    pub nested_loops: Vec<u32>,
}

impl Loop {
    #[must_use] 
    pub fn new(id: u32, kind: LoopKind, header: LoopHeader, body: LoopBody) -> Self {
        let exit = if body.exit_edges.len() == 1 {
            Some(body.exit_edges[0].dst)
        } else {
            None
        };
        Self {
            id, kind, header, body, exit,
            induction_var: None,
            depth: 0,
            parent_loop: None,
            nested_loops: Vec::new(),
        }
    }

    #[must_use] 
    pub const fn is_natural(&self) -> bool {
        matches!(self.kind, LoopKind::While | LoopKind::DoWhile | LoopKind::For | LoopKind::Infinite)
    }

    #[must_use] 
    pub fn node_count(&self) -> usize { self.body.node_count() }

    #[must_use] 
    pub fn contains(&self, n: NodeId) -> bool { self.body.contains(n) }
}

// ── LoopStructurer ────────────────────────────────────────────────────────────

/// Main loop structuring engine.
pub struct LoopStructurer {
    cfg: Cfg,
    idom: HashMap<NodeId, NodeId>,
    back_edges: Vec<CfgEdge>,
    loops: Vec<Loop>,
    next_id: u32,
}

impl LoopStructurer {
    #[must_use] 
    pub fn new(cfg: Cfg) -> Self {
        let idom = compute_idoms(&cfg);
        let back_edges = find_back_edges(&cfg);
        Self { cfg, idom, back_edges, loops: Vec::new(), next_id: 0 }
    }

    const fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Return the immediate dominator of `node`, if any.
    ///
    /// Exposes the cached idom map (built once in [`Self::new`]) so external
    /// callers can answer dominance queries without recomputing it.
    #[must_use]
    pub fn idom_of(&self, node: NodeId) -> Option<NodeId> {
        self.idom.get(&node).copied()
    }

    /// Borrow the full immediate-dominator map.
    #[must_use]
    pub const fn idom_map(&self) -> &HashMap<NodeId, NodeId> {
        &self.idom
    }

    /// Run full loop structuring and return all detected loops.
    pub fn structure(&mut self) -> &[Loop] {
        let rpo = compute_rpo(&self.cfg, self.cfg.entry);

        // Group back-edges by their target (header)
        let mut header_latches: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        for e in &self.back_edges {
            header_latches.entry(e.dst).or_default().push(e.src);
        }

        // Process headers in RPO order
        let headers: Vec<NodeId> = rpo.iter()
            .filter(|&&n| header_latches.contains_key(&n))
            .copied()
            .collect();

        for hdr in headers {
            let latches = header_latches[&hdr].clone();
            let lp = self.build_loop(hdr, &latches);
            self.loops.push(lp);
        }

        // Assign nesting depth and parent
        self.assign_nesting();

        &self.loops
    }

    fn build_loop(&mut self, header: NodeId, latches: &[NodeId]) -> Loop {
        // Collect body nodes via backwards reachability from latches to header
        let body_nodes = self.collect_body(header, latches);

        // Build header info
        let mut lhdr = LoopHeader::new(header);
        for &l in latches { lhdr.add_latch(l); }

        // Determine header successors that are inside vs outside the loop
        let succs = self.cfg.successors(header).to_vec();
        let outside: Vec<NodeId> = succs.iter().copied().filter(|&s| !body_nodes.contains(&s)).collect();
        let inside: Vec<NodeId> = succs.iter().copied().filter(|&s| body_nodes.contains(&s)).collect();

        if let Some(&ext) = outside.first() {
            lhdr.exit_successor = Some(ext);
        }
        if let Some(&ent) = inside.first() {
            lhdr.body_entry = Some(ent);
        }

        // Build body struct
        let mut body = LoopBody::new();
        body.nodes.clone_from(&body_nodes);

        // Back edges
        for &l in latches {
            body.back_edges.push(CfgEdge::new(l, header));
        }

        // Exit edges: edges from body to outside
        for &n in &body_nodes {
            for &s in self.cfg.successors(n) {
                if !body_nodes.contains(&s) {
                    body.exit_edges.push(CfgEdge::new(n, s));
                    if !body.exit_nodes.contains(&n) {
                        body.exit_nodes.push(n);
                    }
                }
            }
        }

        // Classify loop kind
        let kind = self.classify(header, &lhdr, &body);

        let id = self.alloc_id();
        Loop::new(id, kind, lhdr, body)
    }

    fn collect_body(&self, header: NodeId, latches: &[NodeId]) -> HashSet<NodeId> {
        let mut body = HashSet::new();
        body.insert(header);
        let mut worklist: VecDeque<NodeId> = latches.iter().copied().collect();
        while let Some(n) = worklist.pop_front() {
            if body.insert(n) {
                for &p in self.cfg.predecessors(n) {
                    if !body.contains(&p) {
                        worklist.push_back(p);
                    }
                }
            }
        }
        body
    }

    fn classify(&self, header: NodeId, lhdr: &LoopHeader, body: &LoopBody) -> LoopKind {
        let succs = self.cfg.successors(header).to_vec();

        // Infinite: header has no exit successor from the loop
        if lhdr.exit_successor.is_none() && body.exit_edges.is_empty() {
            return LoopKind::Infinite;
        }

        // Multi-exit: more than one exit
        if body.exit_edges.len() > 1 {
            return LoopKind::MultiExit;
        }

        // While: header has 2 succs, one inside one outside
        if succs.len() == 2 && lhdr.exit_successor.is_some() && lhdr.body_entry.is_some() {
            return LoopKind::While;
        }

        // DoWhile: single latch that has 2 succs (one back to header, one out)
        if lhdr.latches.len() == 1 {
            let latch = lhdr.latches[0];
            let latch_succs = self.cfg.successors(latch).to_vec();
            if latch_succs.len() == 2
                
                && latch_succs.iter()
                    .copied()
                    .filter(|&s| !body.contains(s) || s == header).count() >= 1 {
                    return LoopKind::DoWhile;
                }
        }

        // Default to While if any exit at header
        if lhdr.exit_successor.is_some() {
            return LoopKind::While;
        }

        LoopKind::MultiExit
    }

    fn assign_nesting(&mut self) {
        // For each loop, count how many other loops strictly contain it
        let ids_and_bodies: Vec<(u32, HashSet<NodeId>)> = self.loops.iter()
            .map(|l| (l.id, l.body.nodes.clone()))
            .collect();

        for i in 0..self.loops.len() {
            let hdr = self.loops[i].header.node;
            let mut depth = 0u32;
            let mut parent_id: Option<u32> = None;
            let mut parent_size = u32::MAX;

            for (j, (jid, jbody)) in ids_and_bodies.iter().enumerate() {
                if i != j && jbody.contains(&hdr) {
                    depth += 1;
                    let sz = u32::try_from(jbody.len()).unwrap_or(u32::MAX);
                    if sz < parent_size {
                        parent_size = sz;
                        parent_id = Some(*jid);
                    }
                }
            }

            self.loops[i].depth = depth;
            self.loops[i].parent_loop = parent_id;
        }

        // Build nested_loops
        let parent_map: Vec<(u32, Option<u32>)> = self.loops.iter()
            .map(|l| (l.id, l.parent_loop))
            .collect();

        for (id, parent) in &parent_map {
            if let Some(pid) = parent
                && let Some(parent_loop) = self.loops.iter_mut().find(|l| l.id == *pid)
                    && !parent_loop.nested_loops.contains(id) {
                        parent_loop.nested_loops.push(*id);
                    }
        }
    }

    #[must_use] 
    pub fn loops(&self) -> &[Loop] { &self.loops }

    #[must_use] 
    pub const fn cfg(&self) -> &Cfg { &self.cfg }

    /// Find the innermost loop containing node `n`.
    #[must_use] 
    pub fn loop_for(&self, n: NodeId) -> Option<&Loop> {
        self.loops.iter()
            .filter(|l| l.contains(n))
            .max_by_key(|l| l.depth)
    }

    /// Return all loop headers in the CFG.
    #[must_use] 
    pub fn loop_headers(&self) -> Vec<NodeId> {
        self.loops.iter().map(|l| l.header.node).collect()
    }

    /// Return a summary of all loops.
    #[must_use] 
    pub fn loop_summary(&self) -> Vec<LoopSummary> {
        self.loops.iter().map(|l| LoopSummary {
            id: l.id,
            kind: l.kind,
            header: l.header.node,
            node_count: l.node_count(),
            depth: l.depth,
            exit: l.exit,
        }).collect()
    }
}

/// Compact summary of a loop for reporting.
#[derive(Debug, Clone)]
pub struct LoopSummary {
    pub id: u32,
    pub kind: LoopKind,
    pub header: NodeId,
    pub node_count: usize,
    pub depth: u32,
    pub exit: Option<NodeId>,
}

impl fmt::Display for LoopSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Loop#{} [{}] header={} nodes={} depth={}",
            self.id, self.kind, self.header, self.node_count, self.depth
        )
    }
}

// ── Induction Variable Analysis ───────────────────────────────────────────────

/// A simple induction variable pattern (linear: i = i + stride).
#[derive(Debug, Clone)]
pub struct InductionVar {
    pub name: String,
    pub initial: i64,
    pub stride: i64,
    pub limit: Option<i64>,
    pub inclusive: bool,
}

impl InductionVar {
    pub fn new(name: impl Into<String>, initial: i64, stride: i64) -> Self {
        Self { name: name.into(), initial, stride, limit: None, inclusive: false }
    }

    #[must_use] 
    pub const fn with_limit(mut self, limit: i64, inclusive: bool) -> Self {
        self.limit = Some(limit);
        self.inclusive = inclusive;
        self
    }

    /// Estimated iteration count (None if infinite or unknown).
    #[must_use] 
    pub fn iteration_count(&self) -> Option<u64> {
        let limit = self.limit?;
        // Use checked arithmetic to avoid overflow / panic on i64::MIN.
        let diff = limit.checked_sub(self.initial)?;
        let abs_diff = diff.checked_abs()?; // returns None for i64::MIN
        let range: i64 = if self.inclusive {
            abs_diff.checked_add(1)?
        } else {
            abs_diff
        };
        if self.stride == 0 { return None; }
        let abs_stride = u64::try_from(self.stride.checked_abs()?).ok()?;
        let range_u64 = u64::try_from(range).ok()?; // abs_diff >= 0, so try_from succeeds
        // ceiling division: (range + stride - 1) / stride
        let iters = range_u64.checked_add(abs_stride - 1)? / abs_stride;
        Some(iters)
    }
}

/// Identifies potential induction variables in a loop body.
/// This is a stub that performs simple pattern matching on node labels.
pub struct InductionVarAnalyzer;

impl InductionVarAnalyzer {
    #[must_use] 
    pub fn analyze_loop(lp: &Loop, labels: &HashMap<NodeId, String>) -> Vec<InductionVar> {
        let mut vars = Vec::new();
        // Stub: look for nodes labeled "i = i + N" or similar
        for &n in &lp.body.nodes {
            if let Some(label) = labels.get(&n)
                && label.contains("= ") && label.contains(" + ") {
                    // Heuristic: extract variable name
                    let parts: Vec<&str> = label.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        let varname = parts[0].trim().to_string();
                        if !varname.is_empty() {
                            let iv = InductionVar::new(varname, 0, 1);
                            vars.push(iv);
                        }
                    }
                }
        }
        vars
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn while_loop_cfg() -> Cfg {
        // 0(entry) -> 1(header) -> 2(body) -> 1 (back)
        //                       -> 3(exit)
        let mut cfg = Cfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 1);
        cfg
    }

    fn do_while_cfg() -> Cfg {
        // 0 -> 1(body) -> 2(check) -> 1 (back)
        //                           -> 3 (exit)
        let mut cfg = Cfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1);
        cfg.add_edge(2, 3);
        cfg
    }

    fn nested_loop_cfg() -> Cfg {
        // outer: 0 -> 1 -> 2 -> 3 -> 1 (outer back), 3 -> 4
        // inner: 2 -> ... never mind, simple nest
        // 0 -> 1 -> 2 -> 3 -> 2 (inner back)
        //                -> 4 -> 1 (outer back)
        //                -> 5 (exit)
        let mut cfg = Cfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 3);
        cfg.add_edge(3, 2); // inner back edge
        cfg.add_edge(3, 4);
        cfg.add_edge(4, 1); // outer back edge
        cfg.add_edge(4, 5); // outer exit
        cfg
    }

    #[test]
    fn test_while_loop_detection() {
        let cfg = while_loop_cfg();
        let mut ls = LoopStructurer::new(cfg);
        let loops = ls.structure();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].kind, LoopKind::While);
        assert_eq!(loops[0].header.node, 1);
    }

    #[test]
    fn test_do_while_detection() {
        let cfg = do_while_cfg();
        let mut ls = LoopStructurer::new(cfg);
        let loops = ls.structure();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].kind, LoopKind::DoWhile);
    }

    #[test]
    fn test_nested_loop_depth() {
        let cfg = nested_loop_cfg();
        let mut ls = LoopStructurer::new(cfg);
        let loops = ls.structure();
        assert!(loops.len() >= 2);
        let max_depth = loops.iter().map(|l| l.depth).max().unwrap_or(0);
        assert!(max_depth >= 1);
    }

    #[test]
    fn test_loop_body_contains_header() {
        let cfg = while_loop_cfg();
        let mut ls = LoopStructurer::new(cfg);
        let loops = ls.structure();
        let lp = &loops[0];
        assert!(lp.body.contains(lp.header.node));
    }

    #[test]
    fn test_loop_exit_edge() {
        let cfg = while_loop_cfg();
        let mut ls = LoopStructurer::new(cfg);
        let loops = ls.structure();
        let lp = &loops[0];
        assert!(lp.exit.is_some());
        assert_eq!(lp.exit, Some(3));
    }

    #[test]
    fn test_loop_summary() {
        let cfg = while_loop_cfg();
        let mut ls = LoopStructurer::new(cfg);
        ls.structure();
        let summaries = ls.loop_summary();
        assert_eq!(summaries.len(), 1);
        assert!(format!("{}", summaries[0]).contains("while"));
    }

    #[test]
    fn test_no_loops() {
        let mut cfg = Cfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        let mut ls = LoopStructurer::new(cfg);
        let loops = ls.structure();
        assert!(loops.is_empty());
    }

    #[test]
    fn test_loop_for_node() {
        let cfg = while_loop_cfg();
        let mut ls = LoopStructurer::new(cfg);
        ls.structure();
        // Node 2 should be inside the loop
        let lp = ls.loop_for(2);
        assert!(lp.is_some());
    }

    #[test]
    fn test_induction_var() {
        let iv = InductionVar::new("i", 0, 1).with_limit(10, false);
        assert_eq!(iv.iteration_count(), Some(10));
    }

    #[test]
    fn test_loop_kind_display() {
        assert_eq!(format!("{}", LoopKind::While), "while");
        assert_eq!(format!("{}", LoopKind::DoWhile), "do-while");
        assert_eq!(format!("{}", LoopKind::Infinite), "infinite");
    }

    #[test]
    fn test_loop_body_default() {
        let b = LoopBody::default();
        assert_eq!(b.node_count(), 0);
        assert!(!b.is_single_exit());
    }
}
