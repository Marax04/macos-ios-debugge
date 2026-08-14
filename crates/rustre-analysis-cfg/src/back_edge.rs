//! Back-edge detection and classification for CFGs.
//!
//! A *back edge* is an edge `from → to` where `to` dominates `from` in the
//! dominator tree.  Back edges are the defining characteristic of loops.
//!
//! This module provides:
//! - [`BackEdge`]: a classified back-edge record.
//! - [`BackEdgeSet`]: the complete set of back edges in a CFG.
//! - [`BackEdgeKind`]: whether a back edge is natural (single loop header) or
//!   part of an irreducible region (multiple entry points).
//! - DFS coloring helpers used to cross-check dominator-based detection.

use crate::{CfgEdge, DominatorTree};
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet};

// ─────────────────────────────────────────────────────────────────────────────
// BackEdgeKind
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of a back edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackEdgeKind {
    /// Natural back edge: `to` strictly dominates `from`, so the loop has a
    /// single entry header.
    Natural,
    /// Irreducible back edge: `to` does *not* strictly dominate `from`, meaning
    /// the loop is irreducible (multiple entry points).
    Irreducible,
    /// Self-loop: `from == to`.
    SelfLoop,
}

impl BackEdgeKind {
    /// Whether this back edge forms part of a natural (reducible) loop.
    #[must_use]
    pub const fn is_natural(self) -> bool {
        matches!(self, Self::Natural | Self::SelfLoop)
    }

    /// Whether this back edge indicates an irreducible CFG structure.
    #[must_use]
    pub fn is_irreducible(self) -> bool {
        self == Self::Irreducible
    }

    /// Short textual tag for display / serialization.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Natural => "natural",
            Self::Irreducible => "irreducible",
            Self::SelfLoop => "self_loop",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BackEdge
// ─────────────────────────────────────────────────────────────────────────────

/// A single classified back edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BackEdge {
    /// Source of the back edge (the "latch" block).
    pub from: Address,
    /// Target of the back edge (the loop header).
    pub to: Address,
    /// Classification.
    pub kind: BackEdgeKind,
    /// Whether the target block (`to`) was also identified as a loop header by
    /// the dominator tree (i.e. `dom.dominates(to, from)` is true).
    pub dom_based: bool,
}

impl BackEdge {
    /// Whether this edge is a self-loop (`from == to`).
    #[must_use]
    pub fn is_self_loop(&self) -> bool {
        self.from == self.to
    }

    /// The loop header targeted by this back edge.
    #[must_use]
    pub const fn header(&self) -> Address {
        self.to
    }

    /// The latch block (block that closes the loop).
    #[must_use]
    pub const fn latch(&self) -> Address {
        self.from
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BackEdgeSet
// ─────────────────────────────────────────────────────────────────────────────

/// The complete set of back edges in a CFG, with classification.
#[derive(Debug, Clone, Default)]
pub struct BackEdgeSet {
    /// All back edges found.
    pub edges: Vec<BackEdge>,
    /// Maps a loop header address to the indices in `edges` for all back edges
    /// targeting it.
    pub by_header: HashMap<Address, Vec<usize>>,
    /// Whether any irreducible back edges are present.
    pub has_irreducible: bool,
}

impl BackEdgeSet {
    /// Build a `BackEdgeSet` from a CFG.
    ///
    /// Uses the provided dominator tree for dominator-based classification.
    /// Also runs DFS coloring independently to cross-validate (a DFS "back"
    /// edge that is *not* dominator-based is irreducible).
    #[must_use]
    pub fn compute(blocks: &[Address], edges: &[CfgEdge], dom: &DominatorTree) -> Self {
        // DFS back edges.
        let dfs_backs = dfs_back_edges(blocks, edges);

        let mut result = Vec::new();
        let mut by_header: HashMap<Address, Vec<usize>> = HashMap::new();
        let mut has_irreducible = false;

        for e in edges {
            let is_dom_back = dom.dominates(e.to, e.from);
            let is_dfs_back = dfs_backs.contains(&(e.from, e.to));

            if !is_dom_back && !is_dfs_back {
                continue; // Not a back edge by either criterion.
            }

            let kind = if e.from == e.to {
                BackEdgeKind::SelfLoop
            } else if is_dom_back {
                BackEdgeKind::Natural
            } else {
                // DFS back edge but not dominator-based → irreducible.
                has_irreducible = true;
                BackEdgeKind::Irreducible
            };

            let idx = result.len();
            by_header.entry(e.to).or_default().push(idx);
            result.push(BackEdge {
                from: e.from,
                to: e.to,
                kind,
                dom_based: is_dom_back,
            });
        }

        Self {
            edges: result,
            by_header,
            has_irreducible,
        }
    }

    /// All back edges targeting `header`.
    #[must_use]
    pub fn edges_to_header(&self, header: Address) -> Vec<&BackEdge> {
        self.by_header
            .get(&header)
            .map(|indices| indices.iter().map(|&i| &self.edges[i]).collect())
            .unwrap_or_default()
    }

    /// All natural back edges (single-entry loops).
    #[must_use]
    pub fn natural_edges(&self) -> Vec<&BackEdge> {
        self.edges.iter().filter(|e| e.kind.is_natural()).collect()
    }

    /// All irreducible back edges.
    #[must_use]
    pub fn irreducible_edges(&self) -> Vec<&BackEdge> {
        self.edges
            .iter()
            .filter(|e| e.kind.is_irreducible())
            .collect()
    }

    /// All self-loop edges.
    #[must_use]
    pub fn self_loops(&self) -> Vec<&BackEdge> {
        self.edges.iter().filter(|e| e.is_self_loop()).collect()
    }

    /// Number of distinct loop headers (back-edge targets).
    #[must_use]
    pub fn header_count(&self) -> usize {
        self.by_header.len()
    }

    /// Total number of back edges.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.edges.len()
    }

    /// Whether there are no back edges (acyclic CFG).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Whether the CFG is reducible (no irreducible back edges).
    #[must_use]
    pub const fn is_reducible(&self) -> bool {
        !self.has_irreducible
    }

    /// All unique loop header addresses.
    #[must_use]
    pub fn headers(&self) -> Vec<Address> {
        let mut h: Vec<Address> = self.by_header.keys().copied().collect();
        h.sort_by_key(|a| a.as_u64());
        h
    }

    /// For the given header, return the list of latch blocks.
    #[must_use]
    pub fn latches_of(&self, header: Address) -> Vec<Address> {
        self.edges_to_header(header)
            .into_iter()
            .map(|e| e.from)
            .collect()
    }

    /// Number of back edges targeting `header` (multi-latch count).
    #[must_use]
    pub fn latch_count(&self, header: Address) -> usize {
        self.by_header.get(&header).map_or(0, Vec::len)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DFS back-edge detection
// ─────────────────────────────────────────────────────────────────────────────

/// Find back edges via DFS coloring.
///
/// An edge `u → v` is a back edge iff `v` is an ancestor of `u` in the DFS
/// tree (i.e. `v` is on the current DFS stack when `u` is processed).
///
/// Returns the set of `(from, to)` pairs that are DFS back edges.
///
/// **Precondition:** `blocks[0]` must be the CFG entry. DFS roots are taken in
/// `blocks` order, so the DFS spanning forest — and therefore which retreating
/// edges are reported — depends on that order. Passing a slice whose first
/// element is not the entry can root the forest at the wrong node and misreport
/// retreating edges (hence irreducibility). All in-crate callers pass an
/// entry-first slice; the differential fuzz test in `soundness_fuzz.rs`
/// validates that contract, not violations of it.
#[must_use]
pub fn dfs_back_edges(blocks: &[Address], edges: &[CfgEdge]) -> HashSet<(Address, Address)> {
    if blocks.is_empty() {
        return HashSet::new();
    }

    // Build adjacency.
    let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
    for &b in blocks {
        adj.entry(b).or_default();
    }
    for e in edges {
        adj.entry(e.from).or_default().push(e.to);
    }

    let mut visited: HashSet<Address> = HashSet::new();
    let mut on_stack: HashSet<Address> = HashSet::new();
    let mut back_edges: HashSet<(Address, Address)> = HashSet::new();

    // Iterative DFS to avoid stack overflow.
    for &start in blocks {
        if visited.contains(&start) {
            continue;
        }
        // Stack frame: (node, child_index).
        let mut stack: Vec<(Address, usize)> = vec![(start, 0)];
        visited.insert(start);
        on_stack.insert(start);

        while let Some((node, ci)) = stack.last_mut() {
            let node = *node;
            let children: Vec<Address> = adj.get(&node).cloned().unwrap_or_default();
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

// ─────────────────────────────────────────────────────────────────────────────
// LoopHeader identification
// ─────────────────────────────────────────────────────────────────────────────

/// Returns all addresses that are loop headers (targets of at least one
/// natural back edge) in the given CFG.
///
/// A block `h` is a loop header iff there exists an edge `l → h` where
/// `h` dominates `l` in the dominator tree.
#[must_use]
pub fn find_loop_headers(edges: &[CfgEdge], dom: &DominatorTree) -> Vec<Address> {
    let mut headers: HashSet<Address> = HashSet::new();
    for e in edges {
        if dom.dominates(e.to, e.from) {
            headers.insert(e.to);
        }
    }
    let mut v: Vec<Address> = headers.into_iter().collect();
    v.sort_by_key(|a| a.as_u64());
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// BackEdgeAnnotator — annotates edges with their back-edge status
// ─────────────────────────────────────────────────────────────────────────────

/// Annotates each CFG edge with its DFS classification (tree, forward, cross,
/// or back edge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfsEdgeKind {
    /// DFS tree edge.
    Tree,
    /// Forward edge (to a descendant not reached via tree).
    Forward,
    /// Cross edge (to an already-completed DFS subtree).
    Cross,
    /// Back edge (to an ancestor still on the DFS stack).
    Back,
}

/// Maps each CFG edge `(from, to)` to its [`DfsEdgeKind`].
#[must_use]
pub fn classify_dfs_edges(
    blocks: &[Address],
    edges: &[CfgEdge],
) -> HashMap<(Address, Address), DfsEdgeKind> {
    if blocks.is_empty() {
        return HashMap::new();
    }

    let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
    for &b in blocks {
        adj.entry(b).or_default();
    }
    for e in edges {
        adj.entry(e.from).or_default().push(e.to);
    }

    // DFS state.
    let mut color: HashMap<Address, u8> = HashMap::new(); // 0=white, 1=gray, 2=black
    let mut classification: HashMap<(Address, Address), DfsEdgeKind> = HashMap::new();
    let mut disc: HashMap<Address, u32> = HashMap::new();
    let mut disc_counter = 0u32;

    for &start in blocks {
        if color.get(&start).copied().unwrap_or(0) != 0 {
            continue;
        }
        let mut stack: Vec<(Address, usize)> = vec![(start, 0)];
        color.insert(start, 1); // gray
        disc.insert(start, disc_counter);
        disc_counter += 1;

        while let Some((node, ci)) = stack.last_mut() {
            let node = *node;
            let children: Vec<Address> = adj.get(&node).cloned().unwrap_or_default();
            if *ci < children.len() {
                let child = children[*ci];
                *ci += 1;
                let child_color = color.get(&child).copied().unwrap_or(0);
                let edge = (node, child);
                match child_color {
                    0 => {
                        // White — tree edge.
                        color.insert(child, 1);
                        disc.insert(child, disc_counter);
                        disc_counter += 1;
                        classification.insert(edge, DfsEdgeKind::Tree);
                        stack.push((child, 0));
                    }
                    1 => {
                        // Gray — back edge.
                        classification.insert(edge, DfsEdgeKind::Back);
                    }
                    _ => {
                        // Black — forward or cross.
                        let d_node = disc.get(&node).copied().unwrap_or(u32::MAX);
                        let d_child = disc.get(&child).copied().unwrap_or(u32::MAX);
                        if d_node < d_child {
                            classification.insert(edge, DfsEdgeKind::Forward);
                        } else {
                            classification.insert(edge, DfsEdgeKind::Cross);
                        }
                    }
                }
            } else {
                color.insert(node, 2); // black
                stack.pop();
            }
        }
    }

    classification
}

// ─────────────────────────────────────────────────────────────────────────────
// BackEdgeStats — aggregate statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics about back edges in a CFG.
#[derive(Debug, Clone, Default)]
pub struct BackEdgeStats {
    pub total: usize,
    pub natural: usize,
    pub irreducible: usize,
    pub self_loops: usize,
    pub distinct_headers: usize,
    pub max_latches_per_header: usize,
}

impl BackEdgeStats {
    /// Compute statistics from a [`BackEdgeSet`].
    #[must_use]
    pub fn compute(set: &BackEdgeSet) -> Self {
        let max_latches = set.by_header.values().map(std::vec::Vec::len).max().unwrap_or(0);

        Self {
            total: set.edges.len(),
            natural: set.natural_edges().len(),
            irreducible: set.irreducible_edges().len(),
            self_loops: set.self_loops().len(),
            distinct_headers: set.header_count(),
            max_latches_per_header: max_latches,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicBlock, DominatorTree, EdgeKind};

    fn a(n: u64) -> Address {
        Address::new(n)
    }

    fn make_dom_cfg(
        block_addrs: &[u64],
        raw_edges: &[(u64, u64)],
        entry: u64,
    ) -> (Vec<Address>, Vec<CfgEdge>, DominatorTree) {
        let blocks_map: std::collections::HashMap<Address, BasicBlock> = block_addrs
            .iter()
            .map(|&n| {
                let addr = a(n);
                (
                    addr,
                    BasicBlock {
                        start: addr,
                        end: addr,
                        instructions: vec![],
                    },
                )
            })
            .collect();
        let edges: Vec<CfgEdge> = raw_edges
            .iter()
            .map(|&(f, t)| CfgEdge {
                from: a(f),
                to: a(t),
                kind: EdgeKind::Unconditional,
            })
            .collect();
        let dom = DominatorTree::compute(&blocks_map, &edges, a(entry));
        let blocks_vec: Vec<Address> = block_addrs.iter().map(|&n| a(n)).collect();
        (blocks_vec, edges, dom)
    }

    // ── BackEdgeKind ──────────────────────────────────────────────────────

    #[test]
    fn back_edge_kind_natural_is_natural() {
        assert!(BackEdgeKind::Natural.is_natural());
        assert!(BackEdgeKind::SelfLoop.is_natural());
        assert!(!BackEdgeKind::Irreducible.is_natural());
    }

    #[test]
    fn back_edge_kind_tags() {
        assert_eq!(BackEdgeKind::Natural.tag(), "natural");
        assert_eq!(BackEdgeKind::SelfLoop.tag(), "self_loop");
        assert_eq!(BackEdgeKind::Irreducible.tag(), "irreducible");
    }

    // ── dfs_back_edges ────────────────────────────────────────────────────

    #[test]
    fn dfs_back_linear_no_backs() {
        let blocks = vec![a(0), a(1), a(2)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
        ];
        let backs = dfs_back_edges(&blocks, &edges);
        assert!(backs.is_empty());
    }

    #[test]
    fn dfs_back_simple_loop() {
        let blocks = vec![a(0), a(1), a(2), a(3)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(3),
                kind: EdgeKind::Unconditional,
            },
        ];
        let backs = dfs_back_edges(&blocks, &edges);
        assert!(backs.contains(&(a(2), a(1))));
    }

    #[test]
    fn dfs_back_self_loop() {
        let blocks = vec![a(0), a(1)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
        ];
        let backs = dfs_back_edges(&blocks, &edges);
        assert!(backs.contains(&(a(1), a(1))));
    }

    // ── BackEdgeSet::compute ──────────────────────────────────────────────

    #[test]
    fn back_edge_set_empty_on_acyclic() {
        let (blocks, edges, dom) = make_dom_cfg(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        assert!(set.is_empty());
        assert!(set.is_reducible());
    }

    #[test]
    fn back_edge_set_simple_while() {
        let (blocks, edges, dom) =
            make_dom_cfg(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        assert_eq!(set.len(), 1);
        assert!(set.is_reducible());
        let be = &set.edges[0];
        assert_eq!(be.from, a(2));
        assert_eq!(be.to, a(1));
        assert_eq!(be.kind, BackEdgeKind::Natural);
    }

    #[test]
    fn back_edge_set_headers() {
        let (blocks, edges, dom) =
            make_dom_cfg(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        let headers = set.headers();
        assert!(headers.contains(&a(1)));
    }

    #[test]
    fn back_edge_set_latch_count() {
        // Two latches to header 1: edges 2→1 and 3→1.
        let (blocks, edges, dom) = make_dom_cfg(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (1, 3), (2, 1), (3, 1), (1, 4)],
            0,
        );
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        assert_eq!(set.latch_count(a(1)), 2);
    }

    #[test]
    fn back_edge_set_nested_loops() {
        let (blocks, edges, dom) = make_dom_cfg(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        assert_eq!(set.len(), 2);
        assert!(set.is_reducible());
        let h2 = set.edges_to_header(a(2));
        let h1 = set.edges_to_header(a(1));
        assert_eq!(h2.len(), 1);
        assert_eq!(h1.len(), 1);
    }

    // ── find_loop_headers ─────────────────────────────────────────────────

    #[test]
    fn find_loop_headers_simple() {
        let (_, edges, dom) = make_dom_cfg(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let headers = find_loop_headers(&edges, &dom);
        assert!(headers.contains(&a(1)));
        assert!(!headers.contains(&a(0)));
    }

    #[test]
    fn find_loop_headers_no_loops() {
        let (_, edges, dom) = make_dom_cfg(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let headers = find_loop_headers(&edges, &dom);
        assert!(headers.is_empty());
    }

    // ── classify_dfs_edges ────────────────────────────────────────────────

    #[test]
    fn dfs_edge_classification_linear() {
        let blocks = vec![a(0), a(1), a(2)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
        ];
        let cls = classify_dfs_edges(&blocks, &edges);
        assert_eq!(cls[&(a(0), a(1))], DfsEdgeKind::Tree);
        assert_eq!(cls[&(a(1), a(2))], DfsEdgeKind::Tree);
    }

    #[test]
    fn dfs_edge_classification_back_edge() {
        let blocks = vec![a(0), a(1), a(2)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
        ];
        let cls = classify_dfs_edges(&blocks, &edges);
        assert_eq!(cls[&(a(2), a(1))], DfsEdgeKind::Back);
    }

    // ── BackEdgeStats ─────────────────────────────────────────────────────

    #[test]
    fn back_edge_stats_simple() {
        let (blocks, edges, dom) =
            make_dom_cfg(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 1), (1, 3)], 0);
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        let stats = BackEdgeStats::compute(&set);
        assert_eq!(stats.total, 1);
        assert_eq!(stats.natural, 1);
        assert_eq!(stats.irreducible, 0);
        assert_eq!(stats.distinct_headers, 1);
        assert_eq!(stats.max_latches_per_header, 1);
    }

    #[test]
    fn back_edge_stats_self_loop() {
        let blocks = vec![a(0), a(1)];
        let edges_list = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
        ];
        let blocks_map: std::collections::HashMap<Address, BasicBlock> = blocks
            .iter()
            .map(|&addr| {
                (
                    addr,
                    BasicBlock {
                        start: addr,
                        end: addr,
                        instructions: vec![],
                    },
                )
            })
            .collect();
        let dom = DominatorTree::compute(&blocks_map, &edges_list, a(0));
        let set = BackEdgeSet::compute(&blocks, &edges_list, &dom);
        let stats = BackEdgeStats::compute(&set);
        assert_eq!(stats.self_loops, 1);
    }

    #[test]
    fn back_edge_natural_edges_filter() {
        let (blocks, edges, dom) = make_dom_cfg(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (2, 3), (3, 2), (3, 1), (1, 4)],
            0,
        );
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        assert_eq!(set.natural_edges().len(), set.len());
        assert!(set.irreducible_edges().is_empty());
    }

    #[test]
    fn back_edge_latches_of_header() {
        let (blocks, edges, dom) = make_dom_cfg(
            &[0, 1, 2, 3, 4],
            &[(0, 1), (1, 2), (1, 3), (2, 1), (3, 1), (1, 4)],
            0,
        );
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        let latches = set.latches_of(a(1));
        assert_eq!(latches.len(), 2);
        assert!(latches.contains(&a(2)));
        assert!(latches.contains(&a(3)));
    }

    #[test]
    fn dfs_back_empty() {
        let backs = dfs_back_edges(&[], &[]);
        assert!(backs.is_empty());
    }

    // ── BackEdgeKind::is_irreducible ─────────────────────────────────────

    #[test]
    fn back_edge_kind_is_irreducible() {
        assert!(BackEdgeKind::Irreducible.is_irreducible());
        assert!(!BackEdgeKind::Natural.is_irreducible());
        assert!(!BackEdgeKind::SelfLoop.is_irreducible());
    }

    // ── BackEdge accessors ────────────────────────────────────────────────

    #[test]
    fn back_edge_accessors() {
        let be = BackEdge {
            from: a(2),
            to: a(1),
            kind: BackEdgeKind::Natural,
            dom_based: true,
        };
        assert!(!be.is_self_loop());
        assert_eq!(be.header(), a(1));
        assert_eq!(be.latch(), a(2));

        let self_loop = BackEdge {
            from: a(5),
            to: a(5),
            kind: BackEdgeKind::SelfLoop,
            dom_based: true,
        };
        assert!(self_loop.is_self_loop());
    }

    // ── edges_to_header for missing header ───────────────────────────────

    #[test]
    fn edges_to_header_missing_returns_empty() {
        let (blocks, edges, dom) = make_dom_cfg(&[0, 1, 2], &[(0, 1), (1, 2)], 0);
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        assert!(set.edges_to_header(a(99)).is_empty());
        assert_eq!(set.latch_count(a(99)), 0);
        assert!(set.latches_of(a(99)).is_empty());
    }

    // ── irreducible loop detection ────────────────────────────────────────

    #[test]
    fn back_edge_set_irreducible_loop() {
        // Classic irreducible graph: entry branches into a 2-node cycle with
        // two distinct entry points (1 and 2), neither dominates the other.
        //   0 -> 1, 0 -> 2, 1 -> 2, 2 -> 1
        let (blocks, edges, dom) = make_dom_cfg(&[0, 1, 2], &[(0, 1), (0, 2), (1, 2), (2, 1)], 0);
        let set = BackEdgeSet::compute(&blocks, &edges, &dom);
        assert!(set.has_irreducible);
        assert!(!set.is_reducible());
        assert!(!set.irreducible_edges().is_empty());
        for e in set.irreducible_edges() {
            assert_eq!(e.kind, BackEdgeKind::Irreducible);
            assert!(!e.dom_based);
        }
    }

    // ── classify_dfs_edges: forward and cross edges ──────────────────────

    #[test]
    fn dfs_edge_classification_forward() {
        // 0->1 (tree), 1->2 (tree), 0->2 (forward: 2 already visited when
        // 0's second child is processed, and disc(0) < disc(2)).
        let blocks = vec![a(0), a(1), a(2)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(1),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(0),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
        ];
        let cls = classify_dfs_edges(&blocks, &edges);
        assert_eq!(cls[&(a(0), a(2))], DfsEdgeKind::Forward);
    }

    #[test]
    fn dfs_edge_classification_cross() {
        // 0->1 (tree), 0->2 (tree), 2->1 (cross: 1 already black,
        // disc(2) > disc(1)).
        let blocks = vec![a(0), a(1), a(2)];
        let edges = vec![
            CfgEdge {
                from: a(0),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(0),
                to: a(2),
                kind: EdgeKind::Unconditional,
            },
            CfgEdge {
                from: a(2),
                to: a(1),
                kind: EdgeKind::Unconditional,
            },
        ];
        let cls = classify_dfs_edges(&blocks, &edges);
        assert_eq!(cls[&(a(2), a(1))], DfsEdgeKind::Cross);
    }
}
