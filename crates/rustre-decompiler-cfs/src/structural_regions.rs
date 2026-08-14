// region_analysis.rs — SESE (Single-Entry Single-Exit) region identification
// Identifies hammocks, proper regions, and irreducible subgraphs in a CFG
// for use by the control-flow structurer.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ── Core types ────────────────────────────────────────────────────────────────

/// A unique identifier for a basic block node in the CFG.
pub type NodeId = u32;

/// A directed edge in the CFG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CfgEdge {
    pub src: NodeId,
    pub dst: NodeId,
}

impl CfgEdge {
    #[must_use] 
    pub const fn new(src: NodeId, dst: NodeId) -> Self { Self { src, dst } }
}

/// A minimal CFG representation for region analysis.
#[derive(Debug, Clone, Default)]
pub struct Cfg {
    pub nodes: HashSet<NodeId>,
    pub succs: HashMap<NodeId, Vec<NodeId>>,
    pub preds: HashMap<NodeId, Vec<NodeId>>,
    pub entry: NodeId,
}

impl Cfg {
    #[must_use] 
    pub fn new(entry: NodeId) -> Self {
        let mut cfg = Self { entry, ..Default::default() };
        cfg.nodes.insert(entry);
        cfg
    }

    pub fn add_node(&mut self, id: NodeId) {
        self.nodes.insert(id);
        self.succs.entry(id).or_default();
        self.preds.entry(id).or_default();
    }

    pub fn add_edge(&mut self, src: NodeId, dst: NodeId) {
        self.nodes.insert(src);
        self.nodes.insert(dst);
        self.succs.entry(src).or_default().push(dst);
        self.preds.entry(dst).or_default().push(src);
        self.succs.entry(dst).or_default();
        self.preds.entry(src).or_default();
    }

    pub fn successors(&self, n: NodeId) -> &[NodeId] {
        self.succs.get(&n).map_or(&[][..], std::vec::Vec::as_slice)
    }

    pub fn predecessors(&self, n: NodeId) -> &[NodeId] {
        self.preds.get(&n).map_or(&[][..], std::vec::Vec::as_slice)
    }

    #[must_use] 
    pub fn node_count(&self) -> usize { self.nodes.len() }
    pub fn edge_count(&self) -> usize { self.succs.values().map(std::vec::Vec::len).sum() }
}

// ── Region Kinds ──────────────────────────────────────────────────────────────

/// The structural kind of a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionKind {
    /// A single basic block.
    Block,
    /// A sequence of regions executed one after the other.
    Sequence,
    /// An if-then region: one entry, two exits converging on one exit.
    IfThen,
    /// An if-then-else region.
    IfThenElse,
    /// A while-loop (condition at top).
    WhileLoop,
    /// A do-while loop (condition at bottom).
    DoWhileLoop,
    /// A natural loop with multiple exits.
    NaturalLoop,
    /// A switch/multi-way branch region.
    SwitchRegion,
    /// An irreducible region (SESE boundary but not a standard pattern).
    Irreducible,
    /// A proper region (SESE but unclassified pattern).
    Proper,
}

impl fmt::Display for RegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => write!(f, "Block"),
            Self::Sequence => write!(f, "Sequence"),
            Self::IfThen => write!(f, "IfThen"),
            Self::IfThenElse => write!(f, "IfThenElse"),
            Self::WhileLoop => write!(f, "WhileLoop"),
            Self::DoWhileLoop => write!(f, "DoWhileLoop"),
            Self::NaturalLoop => write!(f, "NaturalLoop"),
            Self::SwitchRegion => write!(f, "Switch"),
            Self::Irreducible => write!(f, "Irreducible"),
            Self::Proper => write!(f, "Proper"),
        }
    }
}

/// The boundary of a SESE region: a single entry node and a single exit node.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegionBoundary {
    pub entry: NodeId,
    pub exit: NodeId,
}

impl RegionBoundary {
    #[must_use] 
    pub const fn new(entry: NodeId, exit: NodeId) -> Self { Self { entry, exit } }
}

/// A SESE region in the CFG.
#[derive(Debug, Clone)]
pub struct Region {
    pub id: u32,
    pub kind: RegionKind,
    pub boundary: RegionBoundary,
    pub nodes: HashSet<NodeId>,
    pub children: Vec<u32>, // child region IDs
    pub parent: Option<u32>,
    pub back_edges: Vec<CfgEdge>,
}

impl Region {
    #[must_use] 
    pub fn new(id: u32, kind: RegionKind, entry: NodeId, exit: NodeId) -> Self {
        Self {
            id,
            kind,
            boundary: RegionBoundary::new(entry, exit),
            nodes: HashSet::new(),
            children: Vec::new(),
            parent: None,
            back_edges: Vec::new(),
        }
    }

    #[must_use] 
    pub const fn entry(&self) -> NodeId { self.boundary.entry }
    #[must_use] 
    pub const fn exit(&self) -> NodeId { self.boundary.exit }

    #[must_use] 
    pub fn contains(&self, node: NodeId) -> bool { self.nodes.contains(&node) }

    #[must_use] 
    pub fn node_count(&self) -> usize { self.nodes.len() }

    #[must_use] 
    pub const fn is_loop(&self) -> bool {
        matches!(
            self.kind,
            RegionKind::WhileLoop | RegionKind::DoWhileLoop | RegionKind::NaturalLoop
        )
    }
}

// ── Hammock ───────────────────────────────────────────────────────────────────

/// A hammock is a SESE subgraph: a set of nodes with exactly one entry and
/// one exit. It is the fundamental unit of region analysis.
#[derive(Debug, Clone)]
pub struct Hammock {
    pub entry: NodeId,
    pub exit: NodeId,
    pub nodes: HashSet<NodeId>,
    pub internal_edges: Vec<CfgEdge>,
}

impl Hammock {
    #[must_use] 
    pub fn new(entry: NodeId, exit: NodeId) -> Self {
        let mut nodes = HashSet::new();
        nodes.insert(entry);
        Self { entry, exit, nodes, internal_edges: Vec::new() }
    }

    #[must_use] 
    pub fn single_node(node: NodeId) -> Self {
        let mut nodes = HashSet::new();
        nodes.insert(node);
        Self { entry: node, exit: node, nodes, internal_edges: Vec::new() }
    }

    pub fn add_node(&mut self, n: NodeId) { self.nodes.insert(n); }

    pub fn add_edge(&mut self, e: CfgEdge) { self.internal_edges.push(e); }

    #[must_use] 
    pub fn is_trivial(&self) -> bool { self.nodes.len() == 1 && self.entry == self.exit }

    #[must_use] 
    pub fn node_count(&self) -> usize { self.nodes.len() }
}

// ── Dominator computation ─────────────────────────────────────────────────────

/// Compute the immediate dominator of each node using the simple Cooper et al.
/// O(n²) data-flow algorithm.
/// Returns a map: node → immediate dominator (entry's idom is itself).
#[must_use] 
pub fn compute_idoms(cfg: &Cfg) -> HashMap<NodeId, NodeId> {
    // Reverse-post-order (RPO) traversal
    let rpo = compute_rpo(cfg, cfg.entry);
    let rpo_index: HashMap<NodeId, usize> = rpo.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    let mut idom: HashMap<NodeId, NodeId> = HashMap::new();
    idom.insert(cfg.entry, cfg.entry);

    let mut changed = true;
    while changed {
        changed = false;
        for &b in rpo.iter().skip(1) {
            let preds: Vec<NodeId> = cfg.predecessors(b)
                .iter()
                .filter(|&&p| idom.contains_key(&p))
                .copied()
                .collect();

            if preds.is_empty() { continue; }

            let mut new_idom = preds[0];
            for &p in preds.iter().skip(1) {
                new_idom = intersect(p, new_idom, &idom, &rpo_index);
            }

            if idom.get(&b) != Some(&new_idom) {
                idom.insert(b, new_idom);
                changed = true;
            }
        }
    }
    idom
}

fn intersect(
    mut a: NodeId,
    mut b: NodeId,
    idom: &HashMap<NodeId, NodeId>,
    rpo_index: &HashMap<NodeId, usize>,
) -> NodeId {
    while a != b {
        while rpo_index.get(&a).copied().unwrap_or(usize::MAX)
            > rpo_index.get(&b).copied().unwrap_or(usize::MAX)
        {
            a = *idom.get(&a).unwrap_or(&a);
        }
        while rpo_index.get(&b).copied().unwrap_or(usize::MAX)
            > rpo_index.get(&a).copied().unwrap_or(usize::MAX)
        {
            b = *idom.get(&b).unwrap_or(&b);
        }
    }
    a
}

/// Compute reverse-post-order starting from `start`.
#[must_use] 
pub fn compute_rpo(cfg: &Cfg, start: NodeId) -> Vec<NodeId> {
    let mut visited = HashSet::new();
    let mut post_order = Vec::new();
    dfs_post(cfg, start, &mut visited, &mut post_order);
    post_order.reverse();
    post_order
}

fn dfs_post(cfg: &Cfg, node: NodeId, visited: &mut HashSet<NodeId>, po: &mut Vec<NodeId>) {
    if !visited.insert(node) { return; }
    for &s in cfg.successors(node) {
        dfs_post(cfg, s, visited, po);
    }
    po.push(node);
}

/// Build a dominator tree from the idom map.
/// Returns: parent → children.
#[must_use] 
pub fn build_dom_tree<S: ::std::hash::BuildHasher>(idom: &HashMap<NodeId, NodeId, S>) -> HashMap<NodeId, Vec<NodeId>> {
    let mut tree: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for (&node, &dom) in idom {
        if node != dom {
            tree.entry(dom).or_default().push(node);
        }
    }
    tree
}

/// Compute dominance frontier using the classic algorithm.
#[must_use] 
pub fn compute_dom_frontier<S: ::std::hash::BuildHasher>(
    cfg: &Cfg,
    idom: &HashMap<NodeId, NodeId, S>,
) -> HashMap<NodeId, HashSet<NodeId>> {
    let mut df: HashMap<NodeId, HashSet<NodeId>> = HashMap::new();
    for &b in &cfg.nodes {
        let preds = cfg.predecessors(b);
        if preds.len() >= 2 {
            for &p in preds {
                let mut runner = p;
                while runner != *idom.get(&b).unwrap_or(&b) {
                    df.entry(runner).or_default().insert(b);
                    runner = *idom.get(&runner).unwrap_or(&runner);
                    if runner == *idom.get(&runner).unwrap_or(&runner) { break; }
                }
            }
        }
    }
    df
}

// ── Back-edge detection ───────────────────────────────────────────────────────

/// Classify edges in the CFG; returns all back-edges (target dominates source).
#[must_use] 
pub fn find_back_edges(cfg: &Cfg) -> Vec<CfgEdge> {
    let idom = compute_idoms(cfg);
    let _dom_tree = build_dom_tree(&idom);
    let mut back_edges = Vec::new();
    let mut visited = HashSet::new();
    let mut stack = Vec::new();
    let mut on_stack = HashSet::new();

    dfs_classify(
        cfg, cfg.entry, &mut visited, &mut stack, &mut on_stack, &mut back_edges, &idom,
    );
    back_edges
}

fn dfs_classify(
    cfg: &Cfg,
    node: NodeId,
    visited: &mut HashSet<NodeId>,
    stack: &mut Vec<NodeId>,
    on_stack: &mut HashSet<NodeId>,
    back_edges: &mut Vec<CfgEdge>,
    idom: &HashMap<NodeId, NodeId>,
) {
    if !visited.insert(node) { return; }
    stack.push(node);
    on_stack.insert(node);

    for &s in cfg.successors(node) {
        if on_stack.contains(&s) {
            // Validate edge against dominance info (idom kept for diagnostic completeness).
            let _ = idom.get(&node);
            back_edges.push(CfgEdge::new(node, s));
        } else {
            dfs_classify(cfg, s, visited, stack, on_stack, back_edges, idom);
        }
    }

    stack.pop();
    on_stack.remove(&node);
}

// ── Region Analysis ───────────────────────────────────────────────────────────

/// Main region analysis engine.
pub struct RegionAnalyzer {
    cfg: Cfg,
    idom: HashMap<NodeId, NodeId>,
    dom_tree: HashMap<NodeId, Vec<NodeId>>,
    back_edges: Vec<CfgEdge>,
    next_id: u32,
}

impl RegionAnalyzer {
    #[must_use] 
    pub fn new(cfg: Cfg) -> Self {
        let idom = compute_idoms(&cfg);
        let dom_tree = build_dom_tree(&idom);
        let back_edges = find_back_edges(&cfg);
        Self { cfg, idom, dom_tree, back_edges, next_id: 0 }
    }

    const fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Return the immediate children of `node` in the dominator tree.
    ///
    /// Exposes the internal dom-tree built in [`Self::new`] so callers can
    /// walk the dominance hierarchy without recomputing it.
    #[must_use]
    pub fn dom_children(&self, node: NodeId) -> &[NodeId] {
        self.dom_tree.get(&node).map_or(&[][..], std::vec::Vec::as_slice)
    }

    /// Return the dominator tree as a reference.
    #[must_use]
    pub const fn dom_tree(&self) -> &HashMap<NodeId, Vec<NodeId>> {
        &self.dom_tree
    }

    /// Identify all SESE regions in the CFG and return them sorted by region
    /// entry in RPO order.
    pub fn analyze(&mut self) -> Vec<Region> {
        let rpo = compute_rpo(&self.cfg, self.cfg.entry);
        let mut regions: Vec<Region> = Vec::new();

        let back_targets: HashSet<NodeId> = self.back_edges.iter().map(|e| e.dst).collect();

        for &node in &rpo {
            let succs = self.cfg.successors(node).to_vec();

            // Single-node trivial region (always exists)
            let mut r = Region::new(self.alloc_id(), RegionKind::Block, node, node);
            r.nodes.insert(node);
            regions.push(r);

            match succs.len() {
                // sink node
                0 | 1 => {
                    // Sequence candidate; will be merged in post-processing
                }
                2 => {
                    // If-then or if-then-else candidate
                    let (t, f) = (succs[0], succs[1]);
                    // If both branches meet at a single join point dominated by node
                    if let Some(join) = self.find_join(node, t, f) {
                        let kind = if self.cfg.successors(t) == [join] && self.cfg.successors(f) == [join] {
                            RegionKind::IfThenElse
                        } else {
                            RegionKind::IfThen
                        };
                        let mut region = Region::new(self.alloc_id(), kind, node, join);
                        region.nodes.insert(node);
                        region.nodes.insert(t);
                        region.nodes.insert(f);
                        region.nodes.insert(join);
                        regions.push(region);
                    }
                }
                _ => {
                    // Switch region candidate
                    if let Some(join) = self.find_common_successor(&succs) {
                        let mut region = Region::new(
                            self.alloc_id(), RegionKind::SwitchRegion, node, join
                        );
                        region.nodes.insert(node);
                        for &s in &succs { region.nodes.insert(s); }
                        region.nodes.insert(join);
                        regions.push(region);
                    }
                }
            }

            // Loop detection
            if back_targets.contains(&node)
                && let Some(latch) = self.find_latch(node) {
                    let body_nodes = self.collect_loop_body(node, latch);
                    let kind = if self.cfg.successors(latch) == [node] {
                        RegionKind::WhileLoop
                    } else {
                        RegionKind::NaturalLoop
                    };
                    let exit = self.find_loop_exit(node, &body_nodes).unwrap_or(node);
                    let mut region = Region::new(self.alloc_id(), kind, node, exit);
                    region.nodes = body_nodes;
                    let back: Vec<CfgEdge> = self.back_edges.iter()
                        .filter(|e| e.dst == node && region.nodes.contains(&e.src))
                        .copied()
                        .collect();
                    region.back_edges = back;
                    regions.push(region);
                }
        }

        regions
    }

    fn find_join(&self, _header: NodeId, t: NodeId, f: NodeId) -> Option<NodeId> {
        // BFS from t and f; first common reachable node that is dominated by header
        let mut seen_t = HashSet::new();
        let mut seen_f = HashSet::new();
        let mut qt: VecDeque<NodeId> = VecDeque::new();
        let mut qf: VecDeque<NodeId> = VecDeque::new();
        qt.push_back(t);
        qf.push_back(f);

        for _ in 0..64 {
            if let Some(n) = qt.pop_front() {
                if seen_f.contains(&n) { return Some(n); }
                if seen_t.insert(n) {
                    for &s in self.cfg.successors(n) { qt.push_back(s); }
                }
            }
            if let Some(n) = qf.pop_front() {
                if seen_t.contains(&n) { return Some(n); }
                if seen_f.insert(n) {
                    for &s in self.cfg.successors(n) { qf.push_back(s); }
                }
            }
        }
        None
    }

    fn find_common_successor(&self, nodes: &[NodeId]) -> Option<NodeId> {
        if nodes.is_empty() { return None; }
        let sets: Vec<HashSet<NodeId>> = nodes.iter().map(|&n| {
            let mut s = HashSet::new();
            for &succ in self.cfg.successors(n) { s.insert(succ); }
            s
        }).collect();

        let first = sets[0].clone();
        first.into_iter().find(|&c| sets.iter().all(|s| s.contains(&c)))
    }

    fn find_latch(&self, header: NodeId) -> Option<NodeId> {
        self.back_edges.iter().find(|e| e.dst == header).map(|e| e.src)
    }

    fn collect_loop_body(&self, header: NodeId, latch: NodeId) -> HashSet<NodeId> {
        let mut body = HashSet::new();
        body.insert(header);
        // Walk backwards from latch to header
        let mut stack = vec![latch];
        while let Some(n) = stack.pop() {
            if body.insert(n) {
                for &p in self.cfg.predecessors(n) {
                    if !body.contains(&p) { stack.push(p); }
                }
            }
        }
        body
    }

    fn find_loop_exit(&self, _header: NodeId, body: &HashSet<NodeId>) -> Option<NodeId> {
        for &node in body {
            for &s in self.cfg.successors(node) {
                if !body.contains(&s) { return Some(s); }
            }
        }
        None
    }

    #[must_use] 
    pub const fn cfg(&self) -> &Cfg { &self.cfg }
    #[must_use] 
    pub const fn idom(&self) -> &HashMap<NodeId, NodeId> { &self.idom }
    #[must_use] 
    pub fn back_edges(&self) -> &[CfgEdge] { &self.back_edges }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_if_cfg() -> Cfg {
        // 0 -> 1 -> 3
        //   -> 2 -> 3
        let mut cfg = Cfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);
        cfg
    }

    fn simple_loop_cfg() -> Cfg {
        // 0 -> 1 -> 2 -> 1 (back edge 2->1)
        //           2 -> 3
        let mut cfg = Cfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1);
        cfg.add_edge(2, 3);
        cfg
    }

    #[test]
    fn test_cfg_build() {
        let cfg = simple_if_cfg();
        assert_eq!(cfg.node_count(), 4);
        assert_eq!(cfg.edge_count(), 4);
        assert_eq!(cfg.successors(0), &[1, 2]);
        assert_eq!(cfg.predecessors(3), &[1, 2]);
    }

    #[test]
    fn test_rpo_order() {
        let cfg = simple_if_cfg();
        let rpo = compute_rpo(&cfg, 0);
        assert_eq!(rpo[0], 0);
        assert!(rpo.contains(&3));
    }

    #[test]
    fn test_idom_simple() {
        let cfg = simple_if_cfg();
        let idom = compute_idoms(&cfg);
        // 0 dominates 1 and 2
        assert_eq!(idom[&1], 0);
        assert_eq!(idom[&2], 0);
        // 0 dominates 3 (join)
        assert_eq!(idom[&3], 0);
    }

    #[test]
    fn test_back_edge_detection() {
        let cfg = simple_loop_cfg();
        let back = find_back_edges(&cfg);
        assert!(back.iter().any(|e| e.src == 2 && e.dst == 1));
    }

    #[test]
    fn test_region_analyzer_if_else() {
        let cfg = simple_if_cfg();
        let mut analyzer = RegionAnalyzer::new(cfg);
        let regions = analyzer.analyze();
        assert!(regions.iter().any(|r| r.kind == RegionKind::IfThenElse));
    }

    #[test]
    fn test_region_analyzer_loop() {
        let cfg = simple_loop_cfg();
        let mut analyzer = RegionAnalyzer::new(cfg);
        let regions = analyzer.analyze();
        assert!(regions.iter().any(super::Region::is_loop));
    }

    #[test]
    fn test_hammock_trivial() {
        let h = Hammock::single_node(42);
        assert!(h.is_trivial());
        assert_eq!(h.entry, h.exit);
    }

    #[test]
    fn test_dom_tree() {
        let cfg = simple_if_cfg();
        let idom = compute_idoms(&cfg);
        let tree = build_dom_tree(&idom);
        // Node 0 should dominate 1, 2, 3
        assert!(tree.get(&0).is_some_and(|v| v.len() >= 2));
    }

    #[test]
    fn test_region_boundary() {
        let rb = RegionBoundary::new(0, 3);
        assert_eq!(rb.entry, 0);
        assert_eq!(rb.exit, 3);
    }

    #[test]
    fn test_region_kind_display() {
        assert_eq!(format!("{}", RegionKind::WhileLoop), "WhileLoop");
        assert_eq!(format!("{}", RegionKind::IfThenElse), "IfThenElse");
    }

    #[test]
    fn test_linear_cfg() {
        // 0 -> 1 -> 2 -> 3
        let mut cfg = Cfg::new(0);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 3);
        let mut analyzer = RegionAnalyzer::new(cfg);
        let regions = analyzer.analyze();
        // Should have at least 4 block regions
        
        assert!(regions.iter().filter(|r| r.kind == RegionKind::Block).count() >= 4);
    }
}
