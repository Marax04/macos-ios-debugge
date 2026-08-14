//! Cross-reference call graph backed by petgraph.
//!
//! Builds a directed graph where nodes are addresses (u64) and edges carry
//! `XrefEdge` metadata (kind, call-site offset, optional target name).

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// XrefKind
// ---------------------------------------------------------------------------

/// The type of a cross-reference edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefKind {
    /// Direct call instruction (CALL rel32, BL, etc.).
    DirectCall,
    /// Indirect call via register or memory operand.
    IndirectCall,
    /// Unconditional jump.
    Jump,
    /// Conditional branch (edge weight: taken/not-taken implied by CFG).
    ConditionalBranch,
    /// Data read (code reads data at the target address).
    DataRead,
    /// Data write.
    DataWrite,
    /// Code references data address (e.g., load address of a global).
    CodeToData,
    /// Data item contains a pointer to a code address.
    DataToCode,
    /// Tail call (jump to a different function).
    TailCall,
    /// Return from function (edges from return sites to call sites).
    Return,
}

impl fmt::Display for XrefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectCall       => write!(f, "direct_call"),
            Self::IndirectCall     => write!(f, "indirect_call"),
            Self::Jump             => write!(f, "jump"),
            Self::ConditionalBranch => write!(f, "cond_branch"),
            Self::DataRead         => write!(f, "data_read"),
            Self::DataWrite        => write!(f, "data_write"),
            Self::CodeToData       => write!(f, "code_to_data"),
            Self::DataToCode       => write!(f, "data_to_code"),
            Self::TailCall         => write!(f, "tail_call"),
            Self::Return           => write!(f, "return"),
        }
    }
}

// ---------------------------------------------------------------------------
// XrefEdge
// ---------------------------------------------------------------------------

/// Metadata attached to a cross-reference edge.
#[derive(Debug, Clone)]
pub struct XrefEdge {
    /// Type of cross-reference.
    pub kind: XrefKind,
    /// Address of the instruction that generates this xref.
    pub site: u64,
    /// Confidence in [0, 100] (100 = certain, lower = heuristic).
    pub confidence: u8,
    /// Optional human-readable label.
    pub label: Option<String>,
}

impl XrefEdge {
    #[must_use] 
    pub const fn new(kind: XrefKind, site: u64) -> Self {
        Self { kind, site, confidence: 100, label: None }
    }

    #[must_use] 
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }

    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    #[must_use] 
    pub const fn is_call(&self) -> bool {
        matches!(self.kind, XrefKind::DirectCall | XrefKind::IndirectCall | XrefKind::TailCall)
    }

    #[must_use] 
    pub const fn is_data_ref(&self) -> bool {
        matches!(self.kind, XrefKind::DataRead | XrefKind::DataWrite | XrefKind::CodeToData | XrefKind::DataToCode)
    }
}

// ---------------------------------------------------------------------------
// XrefGraph
// ---------------------------------------------------------------------------

/// Errors that can occur when manipulating the xref graph.
#[derive(Debug)]
pub enum XrefGraphError {
    NodeNotFound { address: u64 },
    EdgeAlreadyExists { from: u64, to: u64, kind: XrefKind },
    CycleDetected,
}

impl fmt::Display for XrefGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeNotFound { address } =>
                write!(f, "node not found for address 0x{address:016X}"),
            Self::EdgeAlreadyExists { from, to, kind } =>
                write!(f, "edge {kind} already exists: 0x{from:X} → 0x{to:X}"),
            Self::CycleDetected =>
                write!(f, "cycle detected in graph"),
        }
    }
}

impl std::error::Error for XrefGraphError {}

/// The cross-reference graph node — one per unique address.
#[derive(Debug, Clone)]
pub struct XrefNode {
    /// The virtual address this node represents.
    pub address: u64,
    /// Optional name (function name, label, etc.).
    pub name: Option<String>,
    /// Whether this address is known to be a function entry point.
    pub is_function: bool,
    /// Whether this address is known to be a data symbol.
    pub is_data: bool,
}

impl XrefNode {
    #[must_use] 
    pub const fn new(address: u64) -> Self {
        Self { address, name: None, is_function: false, is_data: false }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use] 
    pub const fn as_function(mut self) -> Self {
        self.is_function = true;
        self
    }

    #[must_use] 
    pub const fn as_data(mut self) -> Self {
        self.is_data = true;
        self
    }
}

/// A petgraph-backed cross-reference graph.
pub struct XrefCallGraph {
    graph: DiGraph<XrefNode, XrefEdge>,
    /// Maps address → `NodeIndex` for O(1) lookup.
    addr_to_node: HashMap<u64, NodeIndex>,
}

impl XrefCallGraph {
    /// Create an empty graph.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            addr_to_node: HashMap::new(),
        }
    }

    /// Add a node for `address` if one does not already exist.
    /// Returns the `NodeIndex`.
    pub fn get_or_insert_node(&mut self, address: u64) -> NodeIndex {
        if let Some(&ni) = self.addr_to_node.get(&address) {
            return ni;
        }
        let ni = self.graph.add_node(XrefNode::new(address));
        self.addr_to_node.insert(address, ni);
        ni
    }

    /// Add a node with full metadata.  If a node already exists for `address`,
    /// the metadata is merged (name wins over None, flags are OR-ed).
    pub fn add_node(&mut self, node: XrefNode) -> NodeIndex {
        if let Some(&ni) = self.addr_to_node.get(&node.address) {
            let existing = &mut self.graph[ni];
            if existing.name.is_none() && node.name.is_some() {
                existing.name = node.name;
            }
            existing.is_function |= node.is_function;
            existing.is_data     |= node.is_data;
            return ni;
        }
        let addr = node.address;
        let ni = self.graph.add_node(node);
        self.addr_to_node.insert(addr, ni);
        ni
    }

    /// Add a cross-reference edge from `from_addr` to `to_addr`.
    /// Both nodes are created if they do not exist.
    pub fn add_xref(&mut self, from_addr: u64, to_addr: u64, edge: XrefEdge) {
        let from = self.get_or_insert_node(from_addr);
        let to   = self.get_or_insert_node(to_addr);
        self.graph.add_edge(from, to, edge);
    }

    /// Return the `NodeIndex` for an address, or None if absent.
    #[must_use] 
    pub fn node_for(&self, address: u64) -> Option<NodeIndex> {
        self.addr_to_node.get(&address).copied()
    }

    /// Return all outgoing xrefs from `address`.
    #[must_use] 
    pub fn xrefs_from(&self, address: u64) -> Vec<(u64, &XrefEdge)> {
        let Some(ni) = self.node_for(address) else { return vec![] };
        self.graph.edges_directed(ni, Direction::Outgoing)
            .map(|e| (self.graph[e.target()].address, e.weight()))
            .collect()
    }

    /// Return all incoming xrefs to `address`.
    #[must_use] 
    pub fn xrefs_to(&self, address: u64) -> Vec<(u64, &XrefEdge)> {
        let Some(ni) = self.node_for(address) else { return vec![] };
        self.graph.edges_directed(ni, Direction::Incoming)
            .map(|e| (self.graph[e.source()].address, e.weight()))
            .collect()
    }

    /// Return all direct callers of `address`.
    #[must_use] 
    pub fn callers_of(&self, address: u64) -> Vec<u64> {
        self.xrefs_to(address)
            .into_iter()
            .filter(|(_, e)| e.is_call())
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Return all callees (functions called from) `address`.
    #[must_use] 
    pub fn callees_of(&self, address: u64) -> Vec<u64> {
        self.xrefs_from(address)
            .into_iter()
            .filter(|(_, e)| e.is_call())
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Compute the in-degree (number of incoming edges) for `address`.
    #[must_use] 
    pub fn in_degree(&self, address: u64) -> usize {
        let Some(ni) = self.node_for(address) else { return 0 };
        self.graph.edges_directed(ni, Direction::Incoming).count()
    }

    /// Compute the out-degree (number of outgoing edges) for `address`.
    #[must_use] 
    pub fn out_degree(&self, address: u64) -> usize {
        let Some(ni) = self.node_for(address) else { return 0 };
        self.graph.edges_directed(ni, Direction::Outgoing).count()
    }

    /// Return all function entry-point nodes.
    #[must_use] 
    pub fn function_nodes(&self) -> Vec<&XrefNode> {
        self.graph.node_weights().filter(|n| n.is_function).collect()
    }

    /// Return all data nodes.
    #[must_use] 
    pub fn data_nodes(&self) -> Vec<&XrefNode> {
        self.graph.node_weights().filter(|n| n.is_data).collect()
    }

    /// Find all nodes that have no incoming call edges (potential root functions).
    #[must_use] 
    pub fn root_functions(&self) -> Vec<u64> {
        self.graph.node_indices()
            .filter(|&ni| {
                let node = &self.graph[ni];
                if !node.is_function { return false; }
                self.graph.edges_directed(ni, Direction::Incoming)
                    .all(|e| !e.weight().is_call())
            })
            .map(|ni| self.graph[ni].address)
            .collect()
    }

    /// Compute the strongly-connected components using Tarjan's algorithm via petgraph.
    /// Returns a list of SCCs (each is a Vec of addresses).
    #[must_use] 
    pub fn strongly_connected_components(&self) -> Vec<Vec<u64>> {
        let sccs = petgraph::algo::tarjan_scc(&self.graph);
        sccs.into_iter()
            .map(|scc| scc.into_iter().map(|ni| self.graph[ni].address).collect())
            .collect()
    }

    /// Returns true if the graph contains a cycle reachable from `start`.
    #[must_use] 
    pub fn has_cycle(&self) -> bool {
        petgraph::algo::is_cyclic_directed(&self.graph)
    }

    /// Return count of (nodes, edges).
    #[must_use] 
    pub fn stats(&self) -> (usize, usize) {
        (self.graph.node_count(), self.graph.edge_count())
    }

    /// Find all addresses reachable from `start` via outgoing call edges (BFS).
    #[must_use] 
    pub fn reachable_from(&self, start: u64) -> Vec<u64> {
        let Some(start_ni) = self.node_for(start) else { return vec![] };
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start_ni);
        visited.insert(start_ni);
        while let Some(ni) = queue.pop_front() {
            for edge in self.graph.edges_directed(ni, Direction::Outgoing) {
                if edge.weight().is_call() {
                    let target = edge.target();
                    if visited.insert(target) {
                        queue.push_back(target);
                    }
                }
            }
        }
        visited.remove(&start_ni);
        // `visited` is a `HashSet`, so its iteration order is not stable
        // across runs/processes; sort by address for deterministic output
        // (mirrors the same fix applied elsewhere in this crate, e.g.
        // `GlobalCallGraph`/`DataXrefDatabase`).
        let mut out: Vec<u64> = visited.into_iter().map(|ni| self.graph[ni].address).collect();
        out.sort_unstable();
        out
    }

    /// Remove all edges with confidence below `min_confidence`.
    pub fn prune_low_confidence(&mut self, min_confidence: u8) {
        let mut to_remove = Vec::new();
        for ei in self.graph.edge_indices() {
            if self.graph[ei].confidence < min_confidence {
                to_remove.push(ei);
            }
        }
        for ei in to_remove.into_iter().rev() {
            self.graph.remove_edge(ei);
        }
    }

    /// Return the node metadata for a given address.
    #[must_use] 
    pub fn node_info(&self, address: u64) -> Option<&XrefNode> {
        self.node_for(address).map(|ni| &self.graph[ni])
    }
}

impl Default for XrefCallGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_graph() -> XrefCallGraph {
        let mut g = XrefCallGraph::new();
        // main → foo (direct call)
        g.add_xref(0x1000, 0x2000, XrefEdge::new(XrefKind::DirectCall, 0x1005));
        // main → bar (direct call)
        g.add_xref(0x1000, 0x3000, XrefEdge::new(XrefKind::DirectCall, 0x1010));
        // foo → bar (direct call)
        g.add_xref(0x2000, 0x3000, XrefEdge::new(XrefKind::DirectCall, 0x2010));
        // bar → bar (recursive)
        g.add_xref(0x3000, 0x3000, XrefEdge::new(XrefKind::DirectCall, 0x3020));
        g
    }

    #[test]
    fn node_count_after_adds() {
        let g = make_graph();
        let (nodes, edges) = g.stats();
        assert_eq!(nodes, 3); // main, foo, bar
        assert_eq!(edges, 4);
    }

    #[test]
    fn callers_of() {
        let g = make_graph();
        let mut callers = g.callers_of(0x3000);
        callers.sort();
        assert_eq!(callers, vec![0x1000, 0x2000, 0x3000]);
    }

    #[test]
    fn callees_of() {
        let g = make_graph();
        let mut callees = g.callees_of(0x1000);
        callees.sort();
        assert_eq!(callees, vec![0x2000, 0x3000]);
    }

    #[test]
    fn in_degree_out_degree() {
        let g = make_graph();
        assert_eq!(g.in_degree(0x1000), 0);   // main has no callers
        assert_eq!(g.out_degree(0x1000), 2);   // main calls foo+bar
        assert_eq!(g.in_degree(0x3000), 3);    // bar called by main, foo, bar(recursive)
    }

    #[test]
    fn has_cycle_true() {
        let g = make_graph();
        assert!(g.has_cycle()); // bar calls itself
    }

    #[test]
    fn no_cycle_linear() {
        let mut g = XrefCallGraph::new();
        g.add_xref(0x1, 0x2, XrefEdge::new(XrefKind::DirectCall, 0x1));
        g.add_xref(0x2, 0x3, XrefEdge::new(XrefKind::DirectCall, 0x2));
        assert!(!g.has_cycle());
    }

    #[test]
    fn reachable_from_main() {
        let g = make_graph();
        let mut reachable = g.reachable_from(0x1000);
        reachable.sort();
        assert!(reachable.contains(&0x2000));
        assert!(reachable.contains(&0x3000));
    }

    #[test]
    fn add_node_merges_metadata() {
        let mut g = XrefCallGraph::new();
        g.add_node(XrefNode::new(0x1000));
        g.add_node(XrefNode::new(0x1000).with_name("main").as_function());
        let info = g.node_info(0x1000).unwrap();
        assert_eq!(info.name.as_deref(), Some("main"));
        assert!(info.is_function);
    }

    #[test]
    fn xref_edge_flags() {
        let e = XrefEdge::new(XrefKind::DataRead, 0x5000);
        assert!(e.is_data_ref());
        assert!(!e.is_call());

        let e2 = XrefEdge::new(XrefKind::TailCall, 0x6000);
        assert!(e2.is_call());
    }

    #[test]
    fn prune_low_confidence() {
        let mut g = XrefCallGraph::new();
        g.add_xref(0x1, 0x2, XrefEdge::new(XrefKind::DirectCall, 0x1).with_confidence(90));
        g.add_xref(0x1, 0x3, XrefEdge::new(XrefKind::IndirectCall, 0x2).with_confidence(30));
        assert_eq!(g.stats().1, 2);
        g.prune_low_confidence(50);
        assert_eq!(g.stats().1, 1);
    }

    #[test]
    fn root_functions() {
        let mut g = XrefCallGraph::new();
        g.add_node(XrefNode::new(0x1000).as_function());
        g.add_node(XrefNode::new(0x2000).as_function());
        g.add_xref(0x1000, 0x2000, XrefEdge::new(XrefKind::DirectCall, 0x1005));
        let roots = g.root_functions();
        assert_eq!(roots, vec![0x1000]);
    }

    #[test]
    fn strongly_connected_components_single() {
        let mut g = XrefCallGraph::new();
        g.add_xref(0xA, 0xB, XrefEdge::new(XrefKind::DirectCall, 0xA));
        g.add_xref(0xB, 0xA, XrefEdge::new(XrefKind::DirectCall, 0xB));
        let sccs = g.strongly_connected_components();
        // One SCC with both addresses
        let big: Vec<_> = sccs.into_iter().filter(|s| s.len() > 1).collect();
        assert_eq!(big.len(), 1);
        let mut scc = big[0].clone();
        scc.sort();
        assert_eq!(scc, vec![0xA, 0xB]);
    }
}
