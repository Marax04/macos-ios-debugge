//! Path queries on the CFG: find all simple paths between two blocks,
//! bounded by a maximum depth / path length.
//!
//! Two main APIs are provided:
//!
//! - [`find_all_paths`]: return every simple path from `src` to `dst` in the
//!   CFG, up to `max_depth` edges.  A "simple path" visits each block at most
//!   once, preventing infinite loops in cyclic CFGs.
//!
//! - [`PathQuery`]: a reusable, stateful query object that caches the adjacency
//!   list and can answer multiple queries efficiently.
//!
//! Because the number of simple paths can be exponential in cyclic CFGs, the
//! `max_depth` bound is *mandatory*.

use crate::CfgEdge;
use rustre_core::address::Address;
use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// PathResult — a single discovered path
// ─────────────────────────────────────────────────────────────────────────────

/// A sequence of block addresses forming one simple path through the CFG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    /// Ordered sequence of block start addresses, starting at `src` and ending
    /// at `dst`.
    pub nodes: Vec<Address>,
}

impl Path {
    /// Length of the path in *edges* (= number of nodes − 1).
    #[must_use]
    pub const fn edge_len(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }

    /// Number of blocks in the path.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Whether `addr` appears in the path.
    #[must_use]
    pub fn contains(&self, addr: Address) -> bool {
        self.nodes.contains(&addr)
    }

    /// Source address (first node).
    #[must_use]
    pub fn src(&self) -> Option<Address> {
        self.nodes.first().copied()
    }

    /// Destination address (last node).
    #[must_use]
    pub fn dst(&self) -> Option<Address> {
        self.nodes.last().copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// find_all_paths — free function
// ─────────────────────────────────────────────────────────────────────────────

/// Find all simple paths from `src` to `dst` in the CFG, each at most
/// `max_depth` edges long.
///
/// A path is *simple* when each block appears at most once on it, preventing
/// infinite traversal through loops.
///
/// Returns an empty `Vec` when:
/// - `src == dst` and there is no cycle back to `src` within `max_depth` --
///   this function only ever returns paths of at least one edge, so the
///   degenerate zero-edge path `[src]` is never included even when
///   `src == dst`. (Contrast with [`PathQuery::shortest_path`], which does
///   return the trivial single-node path for `src == dst`.)
/// - No path of length ≤ `max_depth` exists.
/// - `max_depth == 0` (no edges can be traversed).
///
/// The maximum number of paths returned is capped at `max_paths` to prevent
/// combinatorial explosion.  When the cap is reached the function returns the
/// paths found so far.
#[must_use]
pub fn find_all_paths(
    edges: &[CfgEdge],
    src: Address,
    dst: Address,
    max_depth: usize,
    max_paths: usize,
) -> Vec<Path> {
    if max_paths == 0 || max_depth == 0 {
        return Vec::new();
    }

    // Build adjacency.
    let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
    for e in edges {
        adj.entry(e.from).or_default().push(e.to);
    }

    let mut results = Vec::new();

    // DFS with an explicit stack to avoid recursion.
    // Each stack frame: (current_node, current_path, visited_set).
    // Using a stack of (node, child_index, path_so_far, visited).
    struct Frame {
        node: Address,
        child_idx: usize,
        path: Vec<Address>,
        visited: HashSet<Address>,
    }

    let mut stack: Vec<Frame> = Vec::new();
    let mut initial_visited = HashSet::new();
    initial_visited.insert(src);
    stack.push(Frame {
        node: src,
        child_idx: 0,
        path: vec![src],
        visited: initial_visited,
    });

    while let Some(frame) = stack.last_mut() {
        if results.len() >= max_paths {
            break;
        }

        let node = frame.node;
        let children = adj.get(&node).map(Vec::as_slice).unwrap_or(&[]);

        if frame.child_idx >= children.len() {
            stack.pop();
            continue;
        }

        let child = children[frame.child_idx];
        frame.child_idx += 1;

        if frame.path.len() > max_depth {
            continue;
        }

        if child == dst {
            let mut p = frame.path.clone();
            p.push(dst);
            results.push(Path { nodes: p });
        } else if !frame.visited.contains(&child) && frame.path.len() < max_depth {
            let mut new_path = frame.path.clone();
            new_path.push(child);
            let mut new_visited = frame.visited.clone();
            new_visited.insert(child);
            stack.push(Frame {
                node: child,
                child_idx: 0,
                path: new_path,
                visited: new_visited,
            });
        }
    }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// PathQuery — reusable query object
// ─────────────────────────────────────────────────────────────────────────────

/// A stateful query object for path queries on a fixed CFG.
///
/// The adjacency list is built once in [`PathQuery::new`] and reused across
/// multiple calls to [`find_paths`], [`exists_path`], and [`shortest_path`].
pub struct PathQuery {
    adj: HashMap<Address, Vec<Address>>,
    /// Reverse adjacency (`to` → `from`s), precomputed once in [`PathQuery::new`]
    /// so that repeated [`PathQuery::can_reach`] / [`PathQuery::can_reach_bounded`]
    /// calls by batch callers don't each pay an O(edges) rebuild.
    rev: HashMap<Address, Vec<Address>>,
    /// Default maximum path depth applied when none is specified.
    pub default_max_depth: usize,
    /// Default cap on the number of paths returned.
    pub default_max_paths: usize,
}

impl PathQuery {
    /// Build a `PathQuery` from a list of CFG edges.
    ///
    /// `default_max_depth` limits the edge-length of paths searched.
    /// `default_max_paths` caps the number of paths returned per query.
    #[must_use]
    pub fn new(edges: &[CfgEdge], default_max_depth: usize, default_max_paths: usize) -> Self {
        let mut adj: HashMap<Address, Vec<Address>> = HashMap::new();
        let mut rev: HashMap<Address, Vec<Address>> = HashMap::new();
        for e in edges {
            adj.entry(e.from).or_default().push(e.to);
            rev.entry(e.to).or_default().push(e.from);
        }
        Self {
            adj,
            rev,
            default_max_depth,
            default_max_paths,
        }
    }

    /// Find all simple paths from `src` to `dst` within the configured bounds.
    #[must_use]
    pub fn find_paths(&self, src: Address, dst: Address) -> Vec<Path> {
        self.find_paths_bounded(src, dst, self.default_max_depth, self.default_max_paths)
    }

    /// Find all simple paths with explicit bounds.
    #[must_use]
    pub fn find_paths_bounded(
        &self,
        src: Address,
        dst: Address,
        max_depth: usize,
        max_paths: usize,
    ) -> Vec<Path> {
        if max_paths == 0 || max_depth == 0 {
            return Vec::new();
        }

        let mut results = Vec::new();

        struct Frame {
            node: Address,
            child_idx: usize,
            path: Vec<Address>,
            visited: HashSet<Address>,
        }

        let mut stack = Vec::new();
        let mut init_visited = HashSet::new();
        init_visited.insert(src);
        stack.push(Frame {
            node: src,
            child_idx: 0,
            path: vec![src],
            visited: init_visited,
        });

        while let Some(frame) = stack.last_mut() {
            if results.len() >= max_paths {
                break;
            }

            let node = frame.node;
            let children = self.adj.get(&node).map(Vec::as_slice).unwrap_or(&[]);

            if frame.child_idx >= children.len() {
                stack.pop();
                continue;
            }

            let child = children[frame.child_idx];
            frame.child_idx += 1;

            if frame.path.len() > max_depth {
                continue;
            }

            if child == dst {
                let mut p = frame.path.clone();
                p.push(dst);
                results.push(Path { nodes: p });
            } else if !frame.visited.contains(&child) && frame.path.len() < max_depth {
                let mut new_path = frame.path.clone();
                new_path.push(child);
                let mut new_visited = frame.visited.clone();
                new_visited.insert(child);
                stack.push(Frame {
                    node: child,
                    child_idx: 0,
                    path: new_path,
                    visited: new_visited,
                });
            }
        }

        results
    }

    /// Return `true` if any path from `src` to `dst` exists within `max_depth`
    /// edges.  More efficient than `find_paths` because it stops at the first
    /// hit.
    #[must_use]
    pub fn exists_path(&self, src: Address, dst: Address) -> bool {
        if src == dst {
            return true;
        }
        self.exists_path_bounded(src, dst, self.default_max_depth)
    }

    /// Bounded reachability check.
    #[must_use]
    pub fn exists_path_bounded(&self, src: Address, dst: Address, max_depth: usize) -> bool {
        // BFS up to `max_depth` layers.
        let mut visited: HashSet<Address> = HashSet::new();
        let mut queue: VecDeque<(Address, usize)> = VecDeque::new();
        queue.push_back((src, 0));
        visited.insert(src);

        while let Some((node, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            for &child in self.adj.get(&node).into_iter().flatten() {
                if child == dst {
                    return true;
                }
                if visited.insert(child) {
                    queue.push_back((child, depth + 1));
                }
            }
        }
        false
    }

    /// Shortest simple path from `src` to `dst` (by edge count) using BFS.
    ///
    /// Returns `None` if no path is reachable within `default_max_depth` edges.
    #[must_use]
    pub fn shortest_path(&self, src: Address, dst: Address) -> Option<Path> {
        self.shortest_path_bounded(src, dst, self.default_max_depth)
    }

    /// Shortest path with an explicit depth bound.
    #[must_use]
    pub fn shortest_path_bounded(
        &self,
        src: Address,
        dst: Address,
        max_depth: usize,
    ) -> Option<Path> {
        if src == dst {
            return Some(Path { nodes: vec![src] });
        }

        // BFS tracking predecessor for path reconstruction.
        let mut pred: HashMap<Address, Address> = HashMap::new();
        let mut visited: HashSet<Address> = HashSet::new();
        let mut queue: VecDeque<(Address, usize)> = VecDeque::new();
        queue.push_back((src, 0));
        visited.insert(src);
        let mut found = false;

        'outer: while let Some((node, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            for &child in self.adj.get(&node).into_iter().flatten() {
                if visited.insert(child) {
                    pred.insert(child, node);
                    if child == dst {
                        found = true;
                        break 'outer;
                    }
                    queue.push_back((child, depth + 1));
                }
            }
        }

        if !found {
            return None;
        }

        // Reconstruct path.
        let mut path = vec![dst];
        let mut cur = dst;
        while cur != src {
            cur = *pred.get(&cur)?;
            path.push(cur);
        }
        path.reverse();
        Some(Path { nodes: path })
    }

    /// BFS distances from `src` to all reachable blocks within `max_depth`.
    ///
    /// Returns a map from address to minimum edge-distance.
    #[must_use]
    pub fn bfs_distances(&self, src: Address) -> HashMap<Address, usize> {
        self.bfs_distances_bounded(src, self.default_max_depth)
    }

    /// BFS distances with explicit depth bound.
    #[must_use]
    pub fn bfs_distances_bounded(&self, src: Address, max_depth: usize) -> HashMap<Address, usize> {
        let mut dist: HashMap<Address, usize> = HashMap::new();
        let mut queue: VecDeque<(Address, usize)> = VecDeque::new();
        dist.insert(src, 0);
        queue.push_back((src, 0));

        while let Some((node, d)) = queue.pop_front() {
            if d >= max_depth {
                continue;
            }
            for &child in self.adj.get(&node).into_iter().flatten() {
                if let std::collections::hash_map::Entry::Vacant(e) = dist.entry(child) {
                    e.insert(d + 1);
                    queue.push_back((child, d + 1));
                }
            }
        }

        dist
    }

    /// All nodes reachable from `src` within `default_max_depth` edges.
    #[must_use]
    pub fn reachable(&self, src: Address) -> HashSet<Address> {
        self.bfs_distances(src).into_keys().collect()
    }

    /// All nodes that can reach `dst` within `default_max_depth` edges
    /// (reverse reachability).
    #[must_use]
    pub fn can_reach(&self, dst: Address) -> HashSet<Address> {
        self.can_reach_bounded(dst, self.default_max_depth)
    }

    /// Reverse reachability with an explicit depth bound.
    #[must_use]
    pub fn can_reach_bounded(&self, dst: Address, max_depth: usize) -> HashSet<Address> {
        let mut visited: HashSet<Address> = HashSet::new();
        let mut queue: VecDeque<(Address, usize)> = VecDeque::new();
        visited.insert(dst);
        queue.push_back((dst, 0));
        while let Some((node, d)) = queue.pop_front() {
            if d >= max_depth {
                continue;
            }
            for &pred in self.rev.get(&node).into_iter().flatten() {
                if visited.insert(pred) {
                    queue.push_back((pred, d + 1));
                }
            }
        }
        visited
    }

    /// Successor nodes of `addr` (direct neighbours).
    #[must_use]
    pub fn successors(&self, addr: Address) -> Vec<Address> {
        self.adj.get(&addr).cloned().unwrap_or_default()
    }

    /// Number of nodes for which adjacency information is stored.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.adj.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PathFilter — predicate-based filtering over a set of paths
// ─────────────────────────────────────────────────────────────────────────────

/// Filters a slice of [`Path`] values based on structural criteria.
pub struct PathFilter {
    /// Only accept paths that visit at least one of these addresses.
    must_visit: Option<HashSet<Address>>,
    /// Reject paths that visit any of these addresses.
    must_avoid: Option<HashSet<Address>>,
    /// Minimum path length in edges.
    min_edges: usize,
    /// Maximum path length in edges.
    max_edges: Option<usize>,
}

impl PathFilter {
    /// Create an empty (pass-all) filter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            must_visit: None,
            must_avoid: None,
            min_edges: 0,
            max_edges: None,
        }
    }

    /// Require that the path visits at least one address in `addrs`.
    #[must_use]
    pub fn must_visit_any(mut self, addrs: impl IntoIterator<Item = Address>) -> Self {
        self.must_visit = Some(addrs.into_iter().collect());
        self
    }

    /// Require that the path does not visit any address in `addrs`.
    #[must_use]
    pub fn must_avoid_all(mut self, addrs: impl IntoIterator<Item = Address>) -> Self {
        self.must_avoid = Some(addrs.into_iter().collect());
        self
    }

    /// Minimum edge count.
    #[must_use]
    pub const fn with_min_edges(mut self, n: usize) -> Self {
        self.min_edges = n;
        self
    }

    /// Maximum edge count.
    #[must_use]
    pub const fn with_max_edges(mut self, n: usize) -> Self {
        self.max_edges = Some(n);
        self
    }

    /// Return `true` if `path` passes all filter conditions.
    #[must_use]
    pub fn matches(&self, path: &Path) -> bool {
        let elen = path.edge_len();
        if elen < self.min_edges {
            return false;
        }
        if let Some(max) = self.max_edges && elen > max {
            return false;
        }
        if let Some(ref must) = self.must_visit && !path.nodes.iter().any(|n| must.contains(n)) {
            return false;
        }
        if let Some(ref avoid) = self.must_avoid && path.nodes.iter().any(|n| avoid.contains(n)) {
            return false;
        }
        true
    }

    /// Filter a slice of paths, returning those that match.
    #[must_use]
    pub fn apply<'a>(&self, paths: &'a [Path]) -> Vec<&'a Path> {
        paths.iter().filter(|p| self.matches(p)).collect()
    }
}

impl Default for PathFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EdgeKind;

    fn a(n: u64) -> Address {
        Address::new(n)
    }

    fn edge(f: u64, t: u64) -> CfgEdge {
        CfgEdge {
            from: a(f),
            to: a(t),
            kind: EdgeKind::Unconditional,
        }
    }

    // ── find_all_paths ────────────────────────────────────────────────────

    #[test]
    fn paths_linear_chain() {
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
        let paths = find_all_paths(&edges, a(0), a(3), 10, 100);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].nodes, vec![a(0), a(1), a(2), a(3)]);
    }

    #[test]
    fn paths_diamond_two_paths() {
        // 0→1, 0→2, 1→3, 2→3
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3), edge(2, 3)];
        let paths = find_all_paths(&edges, a(0), a(3), 10, 100);
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn paths_with_loop_bounded() {
        // 0→1→2→1 (loop), 1→3
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 1), edge(1, 3)];
        // max_depth=3 should find: 0→1→3 (len=2)
        let paths = find_all_paths(&edges, a(0), a(3), 5, 100);
        assert!(!paths.is_empty());
        let p = &paths[0];
        assert!(p.src() == Some(a(0)));
        assert!(p.dst() == Some(a(3)));
    }

    #[test]
    fn paths_no_path_returns_empty() {
        let edges = vec![edge(0, 1)];
        let paths = find_all_paths(&edges, a(0), a(99), 10, 100);
        assert!(paths.is_empty());
    }

    #[test]
    fn paths_max_depth_zero_returns_empty() {
        let edges = vec![edge(0, 1)];
        let paths = find_all_paths(&edges, a(0), a(1), 0, 100);
        assert!(paths.is_empty());
    }

    #[test]
    fn paths_max_paths_caps_results() {
        // 0→1→3, 0→2→3 — two paths but cap at 1.
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3), edge(2, 3)];
        let paths = find_all_paths(&edges, a(0), a(3), 10, 1);
        assert_eq!(paths.len(), 1);
    }

    // ── PathQuery ─────────────────────────────────────────────────────────

    #[test]
    fn query_shortest_path_linear() {
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
        let q = PathQuery::new(&edges, 20, 100);
        let sp = q.shortest_path(a(0), a(3)).unwrap();
        assert_eq!(sp.edge_len(), 3);
        assert_eq!(sp.nodes, vec![a(0), a(1), a(2), a(3)]);
    }

    #[test]
    fn query_shortest_path_multiple_routes() {
        // 0→1→3 (len 2), 0→2→3 (len 2), 0→1→2→3 (len 3).
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3), edge(2, 3), edge(1, 2)];
        let q = PathQuery::new(&edges, 20, 100);
        let sp = q.shortest_path(a(0), a(3)).unwrap();
        assert_eq!(sp.edge_len(), 2);
    }

    #[test]
    fn query_shortest_path_no_route() {
        let edges = vec![edge(0, 1)];
        let q = PathQuery::new(&edges, 10, 100);
        assert!(q.shortest_path(a(0), a(99)).is_none());
    }

    #[test]
    fn query_shortest_path_self() {
        let edges: Vec<CfgEdge> = vec![];
        let q = PathQuery::new(&edges, 10, 100);
        let sp = q.shortest_path(a(5), a(5)).unwrap();
        assert_eq!(sp.nodes, vec![a(5)]);
    }

    #[test]
    fn query_exists_path_true() {
        let edges = vec![edge(0, 1), edge(1, 2)];
        let q = PathQuery::new(&edges, 10, 100);
        assert!(q.exists_path(a(0), a(2)));
    }

    #[test]
    fn query_exists_path_false() {
        let edges = vec![edge(0, 1)];
        let q = PathQuery::new(&edges, 10, 100);
        assert!(!q.exists_path(a(0), a(99)));
    }

    #[test]
    fn query_exists_path_self() {
        let q = PathQuery::new(&[], 10, 100);
        assert!(q.exists_path(a(7), a(7)));
    }

    #[test]
    fn query_bfs_distances() {
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
        let q = PathQuery::new(&edges, 20, 100);
        let dists = q.bfs_distances(a(0));
        assert_eq!(dists[&a(0)], 0);
        assert_eq!(dists[&a(1)], 1);
        assert_eq!(dists[&a(3)], 3);
    }

    #[test]
    fn query_reachable_includes_all() {
        let edges = vec![edge(0, 1), edge(1, 2)];
        let q = PathQuery::new(&edges, 10, 100);
        let r = q.reachable(a(0));
        assert!(r.contains(&a(0)));
        assert!(r.contains(&a(1)));
        assert!(r.contains(&a(2)));
    }

    #[test]
    fn query_can_reach_reverse() {
        let edges = vec![edge(0, 1), edge(1, 2)];
        let q = PathQuery::new(&edges, 10, 100);
        let pred = q.can_reach(a(2));
        assert!(pred.contains(&a(0)));
        assert!(pred.contains(&a(1)));
        assert!(pred.contains(&a(2)));
    }

    #[test]
    fn query_successors() {
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3)];
        let q = PathQuery::new(&edges, 10, 100);
        let s = q.successors(a(0));
        assert_eq!(s.len(), 2);
        assert!(s.contains(&a(1)));
        assert!(s.contains(&a(2)));
    }

    // ── PathFilter ────────────────────────────────────────────────────────

    #[test]
    fn path_filter_must_visit() {
        let p1 = Path {
            nodes: vec![a(0), a(1), a(3)],
        };
        let p2 = Path {
            nodes: vec![a(0), a(2), a(3)],
        };
        let filter = PathFilter::new().must_visit_any([a(1)]);
        assert!(filter.matches(&p1));
        assert!(!filter.matches(&p2));
    }

    #[test]
    fn path_filter_must_avoid() {
        let p1 = Path {
            nodes: vec![a(0), a(1), a(3)],
        };
        let p2 = Path {
            nodes: vec![a(0), a(2), a(3)],
        };
        let filter = PathFilter::new().must_avoid_all([a(2)]);
        assert!(filter.matches(&p1));
        assert!(!filter.matches(&p2));
    }

    #[test]
    fn path_filter_min_max_edges() {
        let p_short = Path {
            nodes: vec![a(0), a(1)],
        }; // 1 edge
        let p_long = Path {
            nodes: vec![a(0), a(1), a(2), a(3)],
        }; // 3 edges
        let filter = PathFilter::new().with_min_edges(2).with_max_edges(4);
        assert!(!filter.matches(&p_short));
        assert!(filter.matches(&p_long));
    }

    #[test]
    fn path_filter_apply() {
        let paths = vec![
            Path {
                nodes: vec![a(0), a(1), a(3)],
            },
            Path {
                nodes: vec![a(0), a(2), a(3)],
            },
        ];
        let filter = PathFilter::new().must_visit_any([a(1)]);
        let matched = filter.apply(&paths);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].nodes[1], a(1));
    }

    // ── Path helpers ──────────────────────────────────────────────────────

    #[test]
    fn path_edge_len_and_node_count() {
        let p = Path {
            nodes: vec![a(0), a(1), a(2), a(3)],
        };
        assert_eq!(p.edge_len(), 3);
        assert_eq!(p.node_count(), 4);
    }

    #[test]
    fn path_contains() {
        let p = Path {
            nodes: vec![a(0), a(5), a(10)],
        };
        assert!(p.contains(a(5)));
        assert!(!p.contains(a(3)));
    }

    #[test]
    fn path_src_and_dst() {
        let p = Path {
            nodes: vec![a(0), a(1), a(2)],
        };
        assert_eq!(p.src(), Some(a(0)));
        assert_eq!(p.dst(), Some(a(2)));
    }

    #[test]
    fn paths_empty_graph() {
        let paths = find_all_paths(&[], a(0), a(1), 10, 100);
        assert!(paths.is_empty());
    }

    #[test]
    fn query_find_paths_bounded_depth() {
        // Linear: 0→1→2→3→4.  Ask for paths of max length 2.
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3), edge(3, 4)];
        let q = PathQuery::new(&edges, 20, 100);
        // Direct path 0→1→2→4 length 3 — not found at depth 2.
        let found = q.find_paths_bounded(a(0), a(4), 2, 100);
        assert!(found.is_empty());
        // At depth 4 the path is found.
        let found2 = q.find_paths_bounded(a(0), a(4), 4, 100);
        assert_eq!(found2.len(), 1);
    }

    #[test]
    fn paths_src_equals_dst_no_self_loop_returns_empty() {
        // src == dst with no cycle back to src: the trivial zero-edge path
        // is deliberately excluded (see doc comment on find_all_paths).
        let edges = vec![edge(0, 1), edge(1, 2)];
        let paths = find_all_paths(&edges, a(0), a(0), 10, 100);
        assert!(paths.is_empty());
    }

    #[test]
    fn paths_src_equals_dst_self_loop_found() {
        // A genuine self-loop 0->0 should surface as a length-1 path.
        let edges = vec![edge(0, 0), edge(0, 1)];
        let paths = find_all_paths(&edges, a(0), a(0), 10, 100);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].nodes, vec![a(0), a(0)]);
    }

    #[test]
    fn paths_self_loop_only_cfg() {
        // A CFG consisting of a single block with only a self-loop edge:
        // src == dst == that block, dst unreachable via any other route.
        let edges = vec![edge(5, 5)];
        let paths = find_all_paths(&edges, a(5), a(5), 3, 10);
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn query_disconnected_components_not_reachable() {
        // Two disjoint chains: 0->1 and 10->11. Neither can reach the other.
        let edges = vec![edge(0, 1), edge(10, 11)];
        let q = PathQuery::new(&edges, 10, 100);
        assert!(!q.exists_path(a(0), a(11)));
        assert!(q.shortest_path(a(0), a(11)).is_none());
        let r = q.reachable(a(0));
        assert!(r.contains(&a(1)));
        assert!(!r.contains(&a(10)));
        assert!(!r.contains(&a(11)));
    }

    #[test]
    fn query_single_block_no_edges() {
        // A single-block CFG has no edges at all.
        let edges: Vec<CfgEdge> = vec![];
        let q = PathQuery::new(&edges, 10, 100);
        assert_eq!(q.node_count(), 0);
        assert!(q.successors(a(0)).is_empty());
        assert!(q.exists_path(a(0), a(0)));
        assert!(!q.exists_path(a(0), a(1)));
        assert_eq!(q.bfs_distances(a(0)).len(), 1);
        assert_eq!(q.reachable(a(0)).len(), 1);
    }

    #[test]
    fn query_max_depth_zero_bounded_variants() {
        let edges = vec![edge(0, 1)];
        let q = PathQuery::new(&edges, 10, 100);
        assert!(q.find_paths_bounded(a(0), a(1), 0, 100).is_empty());
        assert!(!q.exists_path_bounded(a(0), a(1), 0));
        assert!(q.shortest_path_bounded(a(0), a(1), 0).is_none());
    }

    #[test]
    fn query_find_paths_uses_defaults() {
        // `find_paths` (no explicit bounds) must behave the same as
        // `find_paths_bounded` with the configured defaults.
        let edges = vec![edge(0, 1), edge(0, 2), edge(1, 3), edge(2, 3)];
        let q = PathQuery::new(&edges, 10, 100);
        let via_default = q.find_paths(a(0), a(3));
        let via_bounded = q.find_paths_bounded(a(0), a(3), 10, 100);
        assert_eq!(via_default, via_bounded);
        assert_eq!(via_default.len(), 2);
    }

    #[test]
    fn path_filter_default_matches_everything() {
        let filter = PathFilter::default();
        let p = Path {
            nodes: vec![a(0), a(1)],
        };
        assert!(filter.matches(&p));
    }

    #[test]
    fn query_node_count() {
        let edges = vec![edge(0, 1), edge(1, 2), edge(2, 3)];
        let q = PathQuery::new(&edges, 10, 100);
        // adj has entries for 0, 1, 2 (each has at least one outgoing edge).
        assert_eq!(q.node_count(), 3);
    }
}
