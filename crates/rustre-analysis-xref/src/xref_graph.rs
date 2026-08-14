//! Extended xref graph with hub-node detection, isolation analysis, and
//! BFS neighbourhood extraction.
//!
//! Builds on the existing `XrefDatabase` types but provides an independent
//! petgraph-style adjacency-list representation with typed edges, suitable
//! for graph-metric analysis (in-degree, out-degree, clustering, etc.).

use std::collections::{HashMap, HashSet, VecDeque};

// ---------------------------------------------------------------------------
// XrefNode
// ---------------------------------------------------------------------------

/// A node in the extended xref graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct XrefNode {
    /// Raw numeric address.
    pub address: u64,
    /// Optional symbol or label name.
    pub name: Option<String>,
}

impl XrefNode {
    /// Create a node with just an address.
    #[must_use]
    pub const fn new(address: u64) -> Self {
        Self {
            address,
            name: None,
        }
    }

    /// Create a named node.
    #[must_use]
    pub fn named(address: u64, name: impl Into<String>) -> Self {
        Self {
            address,
            name: Some(name.into()),
        }
    }

    /// Display name: symbol name if present, else `0x{address:x}`.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.as_ref().map_or_else(|| format!("{:#x}", self.address), Clone::clone)
    }
}

impl std::fmt::Display for XrefNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// XrefEdgeType
// ---------------------------------------------------------------------------

/// The semantic type of an edge in the xref graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefEdgeType {
    /// Direct CALL instruction.
    Call,
    /// JMP / branch.
    Jump,
    /// Data read.
    DataRead,
    /// Data write.
    DataWrite,
    /// Address-of reference (LEA / MOV-imm).
    DataAddress,
    /// Import thunk.
    Import,
    /// String literal reference.
    StringRef,
    /// Generic / unknown.
    Other,
}

impl std::fmt::Display for XrefEdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::DataRead => "data-read",
            Self::DataWrite => "data-write",
            Self::DataAddress => "data-addr",
            Self::Import => "import",
            Self::StringRef => "string-ref",
            Self::Other => "other",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// XrefEdge
// ---------------------------------------------------------------------------

/// A directed edge in the xref graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefEdge {
    /// Edge semantic type.
    pub edge_type: XrefEdgeType,
    /// Number of times this edge has been observed.
    pub count: u64,
    /// Optional human-readable label (e.g. import name).
    pub label: Option<String>,
}

impl XrefEdge {
    /// Create a new edge.
    #[must_use]
    pub const fn new(edge_type: XrefEdgeType) -> Self {
        Self {
            edge_type,
            count: 1,
            label: None,
        }
    }

    /// Create an edge with a specific count.
    #[must_use]
    pub const fn with_count(mut self, count: u64) -> Self {
        self.count = count;
        self
    }

    /// Attach a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Increment the edge observation count.
    pub const fn inc(&mut self) {
        self.count += 1;
    }
}

impl std::fmt::Display for XrefEdge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(lbl) = &self.label {
            write!(f, "{}×{} [{}]", self.edge_type, self.count, lbl)
        } else {
            write!(f, "{}×{}", self.edge_type, self.count)
        }
    }
}

// ---------------------------------------------------------------------------
// XrefGraph
// ---------------------------------------------------------------------------

/// Extended xref graph backed by an adjacency list of `(to_addr, XrefEdge)`.
///
/// Supports:
/// - Adding nodes and directed edges
/// - Hub-node detection (high in-degree)
/// - Isolated-node detection (no edges)
/// - BFS neighbourhood extraction
pub struct XrefGraph {
    /// addr → `XrefNode`
    nodes: HashMap<u64, XrefNode>,
    /// `from_addr` → list of `(to_addr, edge)`
    adj_out: HashMap<u64, Vec<(u64, XrefEdge)>>,
    /// `to_addr` → list of `from_addrs` (reverse index for in-degree)
    adj_in: HashMap<u64, Vec<u64>>,
}

impl XrefGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            adj_out: HashMap::new(),
            adj_in: HashMap::new(),
        }
    }

    /// Add a node.  If the address is already present, update the name if `node.name` is `Some`.
    pub fn add_node(&mut self, node: XrefNode) {
        let addr = node.address;
        let entry = self
            .nodes
            .entry(addr)
            .or_insert_with(|| XrefNode::new(addr));
        if node.name.is_some() {
            entry.name = node.name;
        }
    }

    /// Add a directed edge from `from` to `to`.
    /// If the nodes do not exist they are created automatically.
    pub fn add_edge(&mut self, from: u64, to: u64, edge: XrefEdge) {
        self.nodes
            .entry(from)
            .or_insert_with(|| XrefNode::new(from));
        self.nodes.entry(to).or_insert_with(|| XrefNode::new(to));
        self.adj_out.entry(from).or_default().push((to, edge));
        self.adj_in.entry(to).or_default().push(from);
    }

    /// Convenience: add a CALL edge.
    pub fn add_call(&mut self, from: u64, to: u64) {
        self.add_edge(from, to, XrefEdge::new(XrefEdgeType::Call));
    }

    /// Convenience: add a JUMP edge.
    pub fn add_jump(&mut self, from: u64, to: u64) {
        self.add_edge(from, to, XrefEdge::new(XrefEdgeType::Jump));
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Total number of directed edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.adj_out.values().map(std::vec::Vec::len).sum()
    }

    /// In-degree of `addr` (number of incoming edges).
    #[must_use]
    pub fn in_degree(&self, addr: u64) -> usize {
        self.adj_in.get(&addr).map_or(0, std::vec::Vec::len)
    }

    /// Out-degree of `addr` (number of outgoing edges).
    #[must_use]
    pub fn out_degree(&self, addr: u64) -> usize {
        self.adj_out.get(&addr).map_or(0, std::vec::Vec::len)
    }

    /// Whether the graph contains a node for `addr`.
    #[must_use]
    pub fn contains(&self, addr: u64) -> bool {
        self.nodes.contains_key(&addr)
    }

    /// Get a node reference by address.
    #[must_use]
    pub fn node(&self, addr: u64) -> Option<&XrefNode> {
        self.nodes.get(&addr)
    }

    /// All node addresses in the graph (order unspecified).
    #[must_use]
    pub fn all_addresses(&self) -> Vec<u64> {
        self.nodes.keys().copied().collect()
    }

    // ── Hub and Isolated Node Detection ──────────────────────────────────────

    /// Find all "hub" nodes: nodes whose in-degree is ≥ `min_in_degree`.
    ///
    /// Returns a `Vec` of `(address, in_degree)` sorted by in-degree descending.
    #[must_use]
    pub fn find_hub_nodes(&self, min_in_degree: usize) -> Vec<(u64, usize)> {
        let mut hubs: Vec<(u64, usize)> = self
            .nodes
            .keys()
            .filter_map(|&addr| {
                let deg = self.in_degree(addr);
                if deg >= min_in_degree {
                    Some((addr, deg))
                } else {
                    None
                }
            })
            .collect();
        hubs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        hubs
    }

    /// Find all isolated nodes: nodes with no incoming *and* no outgoing edges.
    #[must_use]
    pub fn find_isolated_nodes(&self) -> Vec<u64> {
        let mut isolated: Vec<u64> = self
            .nodes
            .keys()
            .filter(|&&addr| self.in_degree(addr) == 0 && self.out_degree(addr) == 0)
            .copied()
            .collect();
        isolated.sort_unstable();
        isolated
    }

    /// Find nodes that are referenced (have incoming edges) but have no outgoing
    /// edges — i.e. potential leaf functions.
    #[must_use]
    pub fn find_leaf_nodes(&self) -> Vec<u64> {
        let mut leaves: Vec<u64> = self
            .nodes
            .keys()
            .filter(|&&addr| self.in_degree(addr) > 0 && self.out_degree(addr) == 0)
            .copied()
            .collect();
        leaves.sort_unstable();
        leaves
    }

    // ── BFS Neighbourhood ─────────────────────────────────────────────────────

    /// Extract the BFS neighbourhood of `center` up to `radius` hops.
    ///
    /// Returns a new `XrefGraph` containing only the subgraph induced by
    /// the nodes within `radius` hops (following outgoing edges) of `center`.
    #[must_use]
    pub fn subgraph_around(&self, center: u64, radius: usize) -> Self {
        let mut sub = Self::new();
        if !self.contains(center) {
            return sub;
        }
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
        queue.push_back((center, 0));
        visited.insert(center);

        while let Some((addr, depth)) = queue.pop_front() {
            // Add node to subgraph
            if let Some(node) = self.node(addr) {
                sub.add_node(node.clone());
            }
            if depth < radius {
                // Outgoing neighbours.
                if let Some(out_edges) = self.adj_out.get(&addr) {
                    for (to, _edge) in out_edges {
                        if visited.insert(*to) {
                            queue.push_back((*to, depth + 1));
                        }
                    }
                }
                // Incoming neighbours (the neighbourhood is followed both
                // ways). `adj_in[addr]` records one entry per inbound edge, so
                // the same `from` can appear several times; only the distinct
                // addresses matter for traversal.
                if let Some(in_addrs) = self.adj_in.get(&addr) {
                    let unique_froms: HashSet<u64> = in_addrs.iter().copied().collect();
                    for from in unique_froms {
                        if visited.insert(from) {
                            if let Some(node) = self.node(from) {
                                sub.add_node(node.clone());
                            }
                            queue.push_back((from, depth + 1));
                        }
                    }
                }
            }
        }

        // Copy the edges in a SECOND pass, once the node set is known.
        //
        // Doing it during the traversal copied every edge whose two endpoints
        // both got dequeued TWICE — once by the source's outgoing pass and
        // again by the target's incoming pass — so `edge_count`, `in_degree`
        // and `out_degree` all came out inflated (a 4-edge graph produced a
        // 6-edge "subgraph"). Walking the visited set afterwards yields the
        // induced subgraph the doc-comment promises, with each edge copied
        // exactly once, and cannot re-introduce the double-add no matter how
        // the traversal is later changed.
        for &from in &visited {
            if let Some(out_edges) = self.adj_out.get(&from) {
                for (to, edge) in out_edges {
                    if visited.contains(to) {
                        sub.add_edge(from, *to, edge.clone());
                    }
                }
            }
        }
        sub
    }

    /// BFS distances from `start` to all reachable nodes (following outgoing edges).
    #[must_use]
    pub fn bfs_distances(&self, start: u64) -> HashMap<u64, usize> {
        let mut dist: HashMap<u64, usize> = HashMap::new();
        let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
        dist.insert(start, 0);
        queue.push_back((start, 0));

        while let Some((addr, d)) = queue.pop_front() {
            if let Some(out) = self.adj_out.get(&addr) {
                for (to, _) in out {
                    if !dist.contains_key(to) {
                        dist.insert(*to, d + 1);
                        queue.push_back((*to, d + 1));
                    }
                }
            }
        }
        dist
    }

    /// Whether `target` is reachable from `source` via outgoing edges.
    #[must_use]
    pub fn is_reachable(&self, source: u64, target: u64) -> bool {
        if source == target {
            return true;
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(source);
        visited.insert(source);
        while let Some(cur) = queue.pop_front() {
            if let Some(out) = self.adj_out.get(&cur) {
                for (to, _) in out {
                    if *to == target {
                        return true;
                    }
                    if visited.insert(*to) {
                        queue.push_back(*to);
                    }
                }
            }
        }
        false
    }

    // ── Graph Metrics ─────────────────────────────────────────────────────────

    /// Compute the top-N nodes by in-degree.
    #[must_use]
    pub fn top_by_in_degree(&self, n: usize) -> Vec<(u64, usize)> {
        let mut hubs = self.find_hub_nodes(0);
        hubs.truncate(n);
        hubs
    }

    /// Compute the top-N nodes by out-degree.
    #[must_use]
    pub fn top_by_out_degree(&self, n: usize) -> Vec<(u64, usize)> {
        let mut nodes: Vec<(u64, usize)> = self
            .nodes
            .keys()
            .map(|&addr| (addr, self.out_degree(addr)))
            .collect();
        nodes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        nodes.truncate(n);
        nodes
    }

    /// Export the graph as DOT (Graphviz) format.
    #[must_use]
    pub fn to_dot(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("digraph xref {\n  rankdir=LR;\n  node [shape=box];\n");
        for (&from, edges) in &self.adj_out {
            let from_name = self
                .node(from).map_or_else(|| format!("{from:#x}"), XrefNode::display_name);
            for (to, edge) in edges {
                let to_name = self
                    .node(*to).map_or_else(|| format!("{to:#x}"), XrefNode::display_name);
                let _ = writeln!(out, "  \"{from_name}\" -> \"{to_name}\" [label=\"{}\"];", edge.edge_type);
            }
        }
        out.push_str("}\n");
        out
    }
}

impl Default for XrefGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for XrefGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "XrefGraph {{ nodes: {}, edges: {} }}",
            self.node_count(),
            self.edge_count()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_graph() -> XrefGraph {
        let mut g = XrefGraph::new();
        // hub: 0x100 is called by 0x200, 0x300, 0x400
        g.add_call(0x200, 0x100);
        g.add_call(0x300, 0x100);
        g.add_call(0x400, 0x100);
        // 0x200 also calls 0x500
        g.add_call(0x200, 0x500);
        // isolated: 0x999 has no edges
        g.add_node(XrefNode::new(0x999));
        g
    }

    #[test]
    fn test_node_count() {
        let g = build_graph();
        // 0x100, 0x200, 0x300, 0x400, 0x500, 0x999
        assert_eq!(g.node_count(), 6);
    }

    #[test]
    fn test_edge_count() {
        let g = build_graph();
        assert_eq!(g.edge_count(), 4);
    }

    #[test]
    fn test_in_degree() {
        let g = build_graph();
        assert_eq!(g.in_degree(0x100), 3);
        assert_eq!(g.in_degree(0x200), 0);
    }

    #[test]
    fn test_out_degree() {
        let g = build_graph();
        assert_eq!(g.out_degree(0x200), 2);
        assert_eq!(g.out_degree(0x100), 0);
    }

    #[test]
    fn test_find_hub_nodes_threshold() {
        let g = build_graph();
        let hubs = g.find_hub_nodes(2);
        assert_eq!(hubs.len(), 1);
        assert_eq!(hubs[0].0, 0x100);
        assert_eq!(hubs[0].1, 3);
    }

    #[test]
    fn test_find_hub_nodes_zero_threshold() {
        let g = build_graph();
        let hubs = g.find_hub_nodes(0);
        // All nodes qualify
        assert_eq!(hubs.len(), 6);
    }

    #[test]
    fn test_find_isolated_nodes() {
        let g = build_graph();
        let isolated = g.find_isolated_nodes();
        assert_eq!(isolated, vec![0x999]);
    }

    #[test]
    fn test_find_leaf_nodes() {
        let g = build_graph();
        let leaves = g.find_leaf_nodes();
        // 0x100 has in-degree 3 but out-degree 0 — it's a leaf
        // 0x500 has in-degree 1 but out-degree 0 — also a leaf
        assert!(leaves.contains(&0x100));
        assert!(leaves.contains(&0x500));
    }

    #[test]
    fn test_subgraph_around_radius_1() {
        let g = build_graph();
        let sub = g.subgraph_around(0x200, 1);
        // Should include 0x200, its out-neighbours 0x100 and 0x500,
        // and 0x200 has no in-edges so only 3 nodes at most
        assert!(sub.contains(0x200));
        assert!(sub.contains(0x100));
        assert!(sub.contains(0x500));
    }

    #[test]
    fn test_subgraph_around_non_existent_center() {
        let g = build_graph();
        let sub = g.subgraph_around(0xdead, 2);
        assert_eq!(sub.node_count(), 0);
    }

    #[test]
    fn test_is_reachable_direct() {
        let g = build_graph();
        assert!(g.is_reachable(0x200, 0x100));
        assert!(g.is_reachable(0x200, 0x500));
    }

    #[test]
    fn test_is_reachable_self() {
        let g = build_graph();
        assert!(g.is_reachable(0x100, 0x100));
    }

    #[test]
    fn test_is_not_reachable() {
        let g = build_graph();
        // 0x100 has no outgoing edges
        assert!(!g.is_reachable(0x100, 0x200));
    }

    #[test]
    fn test_bfs_distances() {
        let g = build_graph();
        let dist = g.bfs_distances(0x200);
        assert_eq!(dist[&0x200], 0);
        assert_eq!(dist[&0x100], 1);
        assert_eq!(dist[&0x500], 1);
    }

    #[test]
    fn test_top_by_in_degree() {
        let g = build_graph();
        let top = g.top_by_in_degree(1);
        assert_eq!(top[0].0, 0x100);
    }

    #[test]
    fn test_top_by_out_degree() {
        let g = build_graph();
        let top = g.top_by_out_degree(1);
        assert_eq!(top[0].0, 0x200);
    }

    #[test]
    fn test_xref_node_display_name() {
        let n = XrefNode::named(0x1000, "malloc");
        assert_eq!(n.display_name(), "malloc");
        let n2 = XrefNode::new(0x2000);
        assert_eq!(n2.display_name(), "0x2000");
    }

    #[test]
    fn test_xref_edge_display() {
        let e = XrefEdge::new(XrefEdgeType::Call)
            .with_count(5)
            .with_label("malloc");
        let s = e.to_string();
        assert!(s.contains("call"));
        assert!(s.contains('5'));
        assert!(s.contains("malloc"));
    }

    #[test]
    fn test_to_dot_contains_edges() {
        let mut g = XrefGraph::new();
        g.add_node(XrefNode::named(0x100, "foo"));
        g.add_node(XrefNode::named(0x200, "bar"));
        g.add_call(0x200, 0x100);
        let dot = g.to_dot();
        assert!(dot.contains("->"));
        assert!(dot.contains("call"));
    }

    #[test]
    fn test_named_node_update() {
        let mut g = XrefGraph::new();
        g.add_node(XrefNode::new(0x100));
        g.add_node(XrefNode::named(0x100, "renamed"));
        assert_eq!(g.node(0x100).unwrap().name, Some("renamed".to_string()));
    }

    #[test]
    fn test_all_addresses() {
        let g = build_graph();
        let mut addrs = g.all_addresses();
        addrs.sort_unstable();
        assert_eq!(addrs, vec![0x100, 0x200, 0x300, 0x400, 0x500, 0x999]);
    }

    #[test]
    fn test_add_jump() {
        let mut g = XrefGraph::new();
        g.add_jump(0x10, 0x20);
        assert_eq!(g.out_degree(0x10), 1);
        assert_eq!(g.in_degree(0x20), 1);
        let dot = g.to_dot();
        assert!(dot.contains("jump"));
    }

    #[test]
    fn test_contains() {
        let g = build_graph();
        assert!(g.contains(0x100));
        assert!(!g.contains(0xDEADBEEF));
    }

    #[test]
    fn test_default_and_debug() {
        let g = XrefGraph::default();
        assert_eq!(g.node_count(), 0);
        let s = format!("{g:?}");
        assert!(s.contains("nodes: 0"));
    }

    /// Regression test: `subgraph_around` must carry over the actual edge data
    /// for inbound edges into the center node, not just the node itself.
    /// Previously `find_hub_nodes`-style callers of `subgraph_around` on a
    /// heavily-called node (a "hub") would get a subgraph with all the right
    /// nodes but zero edges into the center.
    #[test]
    fn test_subgraph_around_includes_incoming_edges() {
        let g = build_graph();
        // 0x100 is called by 0x200, 0x300, 0x400 (in-degree 3, out-degree 0).
        let sub = g.subgraph_around(0x100, 1);
        assert!(sub.contains(0x100));
        assert!(sub.contains(0x200));
        assert!(sub.contains(0x300));
        assert!(sub.contains(0x400));
        // The 3 inbound call edges must be present in the induced subgraph.
        assert_eq!(sub.edge_count(), 3);
        assert_eq!(sub.in_degree(0x100), 3);
    }

    /// Regression test: when a node has *multiple* distinct edges to the same
    /// target (e.g. both a call and a jump, or two calls recorded from the
    /// same call-site parsing pass), `subgraph_around` must copy each real
    /// edge exactly once, not once per occurrence of `from` in the reverse
    /// adjacency list `adj_in[to]` (which has one entry per inbound edge and
    /// therefore repeats `from`).
    #[test]
    fn test_subgraph_around_does_not_multiply_duplicate_incoming_edges() {
        let mut g = XrefGraph::new();
        // 0x200 -> 0x100 twice: once as a call, once as a jump. This makes
        // adj_in[0x100] == [0x200, 0x200] (two entries for the same `from`).
        g.add_call(0x200, 0x100);
        g.add_jump(0x200, 0x100);
        assert_eq!(g.edge_count(), 2);

        let sub = g.subgraph_around(0x100, 1);
        // The two real edges must be copied exactly twice total, not
        // 2 (edges) * 2 (duplicate `from` entries) = 4.
        assert_eq!(sub.edge_count(), 2);
    }

    #[test]
    fn test_subgraph_around_radius_zero() {
        let g = build_graph();
        let sub = g.subgraph_around(0x200, 0);
        // Only the center node itself, no edges traversed.
        assert_eq!(sub.node_count(), 1);
        assert_eq!(sub.edge_count(), 0);
        assert!(sub.contains(0x200));
    }
}
