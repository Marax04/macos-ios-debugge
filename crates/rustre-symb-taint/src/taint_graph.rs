//! `taint_graph` — Petgraph-based taint flow graph.
//!
//! Models taint propagation as a directed graph where nodes are data locations
//! and edges are the operations that carried taint between them.  Provides BFS
//! reachability, path enumeration, source/sink marking, and graph statistics.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use petgraph::algo;
use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

use crate::{PropagationOp, TaintId, TaintLocation, TaintSource, taint_bits};

// ─── TaintNodeData ────────────────────────────────────────────────────────────

/// Data stored at each node in the taint flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintNodeData {
    /// The data location this node represents.
    pub location: TaintLocation,
    /// Cumulative taint bitmask accumulated at this node.
    pub taint_mask: TaintId,
    /// Whether this node is a known taint source.
    pub is_source: bool,
    /// Whether this node is a known dangerous sink.
    pub is_sink: bool,
    /// Whether taint at this node has been sanitized.
    pub sanitized: bool,
    /// Original taint source, if this is a source node.
    pub source_kind: Option<TaintSource>,
    /// Instruction address that created this node (best-effort).
    pub creation_addr: u64,
    /// Depth from the nearest source node (populated by BFS; `u32::MAX` = unreachable).
    pub depth_from_source: u32,
}

impl TaintNodeData {
    /// Create a plain (non-source, non-sink) node.
    #[must_use]
    pub fn new(location: TaintLocation, taint_mask: TaintId) -> Self {
        Self {
            location,
            taint_mask,
            is_source: false,
            is_sink: false,
            sanitized: false,
            source_kind: None,
            creation_addr: 0,
            depth_from_source: u32::MAX,
        }
    }

    /// Create a source node.
    #[must_use]
    pub fn source(location: TaintLocation, source: TaintSource, taint_mask: TaintId) -> Self {
        Self {
            location,
            taint_mask,
            is_source: true,
            is_sink: false,
            sanitized: false,
            source_kind: Some(source),
            creation_addr: 0,
            depth_from_source: 0,
        }
    }

    /// Create a sink node.
    #[must_use]
    pub fn sink(location: TaintLocation, taint_mask: TaintId) -> Self {
        Self {
            location,
            taint_mask,
            is_source: false,
            is_sink: true,
            sanitized: false,
            source_kind: None,
            creation_addr: 0,
            depth_from_source: u32::MAX,
        }
    }

    /// Returns `true` if this node carries any taint.
    #[must_use]
    pub fn is_tainted(&self) -> bool {
        !self.sanitized && taint_bits::is_tainted(self.taint_mask)
    }
}

impl fmt::Display for TaintNodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = if self.is_source { "SRC" } else if self.is_sink { "SINK" } else { "" };
        write!(f, "{} mask={:#x} {flags}", self.location, self.taint_mask)
    }
}

// ─── TaintEdgeData ────────────────────────────────────────────────────────────

/// Data stored on each edge in the taint flow graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintEdgeData {
    /// The operation that propagated taint along this edge.
    pub operation: PropagationOp,
    /// Instruction address where the propagation occurred.
    pub instruction_addr: u64,
    /// Taint bits carried by this edge.
    pub carried_taint: TaintId,
}

impl TaintEdgeData {
    /// Create a new edge data record.
    #[must_use]
    pub const fn new(op: PropagationOp, addr: u64, taint: TaintId) -> Self {
        Self {
            operation: op,
            instruction_addr: addr,
            carried_taint: taint,
        }
    }
}

impl fmt::Display for TaintEdgeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} @ 0x{:x} taint={:#x}",
            self.operation, self.instruction_addr, self.carried_taint
        )
    }
}

// ─── TaintFlow ────────────────────────────────────────────────────────────────

/// A single taint flow: source location → sink location through a sequence of
/// propagation steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFlow {
    /// Source location.
    pub source: TaintLocation,
    /// Sink location.
    pub sink: TaintLocation,
    /// Sequence of `(location, instruction_address)` pairs forming the path.
    pub path: Vec<(TaintLocation, u64)>,
    /// Cumulative taint mask carried along the path.
    pub taint_mask: TaintId,
}

impl TaintFlow {
    /// Create a new flow.
    #[must_use]
    pub fn new(
        source: TaintLocation,
        sink: TaintLocation,
        path: Vec<(TaintLocation, u64)>,
        taint_mask: TaintId,
    ) -> Self {
        Self {
            source,
            sink,
            path,
            taint_mask,
        }
    }

    /// Length of the path (number of hops).
    #[must_use]
    pub fn hop_count(&self) -> usize {
        self.path.len().saturating_sub(1)
    }

    /// Returns `true` if the path is a direct source-to-sink connection (no intermediate nodes).
    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.path.len() <= 2
    }
}

impl fmt::Display for TaintFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} → {} ({} hops, taint={:#x})",
            self.source,
            self.sink,
            self.hop_count(),
            self.taint_mask,
        )
    }
}

// ─── TaintGraph ───────────────────────────────────────────────────────────────

/// A directed taint-flow graph backed by `petgraph`.
///
/// Each node is a [`TaintLocation`] (register, memory address, variable, …) and
/// each edge records the [`PropagationOp`] that caused taint to flow.
pub struct TaintGraph {
    /// The underlying directed graph.
    pub graph: DiGraph<TaintNodeData, TaintEdgeData>,
    /// Location → node index mapping for fast lookup.
    node_map: HashMap<TaintLocation, NodeIndex>,
}

impl TaintGraph {
    /// Create an empty taint graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_map: HashMap::new(),
        }
    }

    // ── Node management ───────────────────────────────────────────────────────

    /// Add or retrieve the node for `location`.  If the node already exists,
    /// the taint mask is OR-ed with `taint_mask`.
    pub fn add_node(&mut self, data: TaintNodeData) -> NodeIndex {
        let loc = data.location.clone();
        if let Some(&idx) = self.node_map.get(&loc) {
            // Merge taint.
            if let Some(n) = self.graph.node_weight_mut(idx) {
                n.taint_mask |= data.taint_mask;
            }
            return idx;
        }
        let idx = self.graph.add_node(data);
        self.node_map.insert(loc, idx);
        idx
    }

    /// Ensure a node exists for `location`, creating one with zero taint if absent.
    pub fn ensure_node(&mut self, location: TaintLocation) -> NodeIndex {
        if let Some(&idx) = self.node_map.get(&location) {
            return idx;
        }
        let data = TaintNodeData::new(location.clone(), taint_bits::NONE);
        let idx = self.graph.add_node(data);
        self.node_map.insert(location, idx);
        idx
    }

    /// Get the node index for a location, if it exists.
    #[must_use]
    pub fn node_index(&self, location: &TaintLocation) -> Option<NodeIndex> {
        self.node_map.get(location).copied()
    }

    /// Get node data by location.
    #[must_use]
    pub fn node_data(&self, location: &TaintLocation) -> Option<&TaintNodeData> {
        let idx = self.node_map.get(location)?;
        self.graph.node_weight(*idx)
    }

    /// Mark a node as a taint source.
    pub fn mark_source(&mut self, location: &TaintLocation, source: TaintSource, taint: TaintId) {
        let idx = self.ensure_node(location.clone());
        if let Some(n) = self.graph.node_weight_mut(idx) {
            n.is_source = true;
            n.taint_mask |= taint;
            n.source_kind = Some(source);
            n.depth_from_source = 0;
        }
    }

    /// Mark a node as a dangerous sink.
    pub fn mark_sink(&mut self, location: &TaintLocation) {
        let idx = self.ensure_node(location.clone());
        if let Some(n) = self.graph.node_weight_mut(idx) {
            n.is_sink = true;
        }
    }

    /// Mark a node as sanitized.
    pub fn sanitize(&mut self, location: &TaintLocation) {
        if let Some(&idx) = self.node_map.get(location) {
            if let Some(n) = self.graph.node_weight_mut(idx) {
                n.sanitized = true;
            }
        }
    }

    // ── Edge management ───────────────────────────────────────────────────────

    /// Add a directed edge from `from` to `to` carrying the given taint.
    /// Both nodes are created if they do not exist.
    pub fn add_edge(
        &mut self,
        from: &TaintLocation,
        to: &TaintLocation,
        op: PropagationOp,
        addr: u64,
        taint: TaintId,
    ) -> EdgeIndex {
        let from_idx = self.ensure_node(from.clone());
        let to_idx = self.ensure_node(to.clone());
        // Propagate taint to destination.
        if let Some(n) = self.graph.node_weight_mut(to_idx) {
            n.taint_mask |= taint;
        }
        self.graph
            .add_edge(from_idx, to_idx, TaintEdgeData::new(op, addr, taint))
    }

    // ── Reachability ──────────────────────────────────────────────────────────

    /// Returns `true` if there is a directed path from `source` to `sink`.
    #[must_use]
    pub fn has_path(&self, source: &TaintLocation, sink: &TaintLocation) -> bool {
        let src_idx = match self.node_map.get(source) {
            Some(&i) => i,
            None => return false,
        };
        let snk_idx = match self.node_map.get(sink) {
            Some(&i) => i,
            None => return false,
        };
        algo::has_path_connecting(&self.graph, src_idx, snk_idx, None)
    }

    /// BFS forward from `source`; returns all reachable locations.
    #[must_use]
    pub fn reachable_from(&self, source: &TaintLocation) -> Vec<TaintLocation> {
        let start = match self.node_map.get(source) {
            Some(&i) => i,
            None => return vec![],
        };
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<NodeIndex> = VecDeque::new();
        queue.push_back(start);
        while let Some(n) = queue.pop_front() {
            if !visited.insert(n) {
                continue;
            }
            for e in self.graph.edges(n) {
                queue.push_back(e.target());
            }
        }
        visited
            .iter()
            .filter_map(|&idx| self.graph.node_weight(idx))
            .map(|n| n.location.clone())
            .collect()
    }

    /// BFS backward from `sink`; returns all locations that can reach `sink`.
    #[must_use]
    pub fn predecessors_of(&self, sink: &TaintLocation) -> Vec<TaintLocation> {
        let target = match self.node_map.get(sink) {
            Some(&i) => i,
            None => return vec![],
        };
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<NodeIndex> = VecDeque::new();
        queue.push_back(target);
        // Traverse incoming edges using the reversed graph view.
        while let Some(n) = queue.pop_front() {
            if !visited.insert(n) {
                continue;
            }
            for e in self.graph.edges_directed(n, petgraph::Direction::Incoming) {
                queue.push_back(e.source());
            }
        }
        visited
            .iter()
            .filter(|&&idx| idx != target)
            .filter_map(|&idx| self.graph.node_weight(idx))
            .map(|n| n.location.clone())
            .collect()
    }

    // ── Path enumeration ──────────────────────────────────────────────────────

    /// Find one shortest path from `source` to `sink` using BFS.
    ///
    /// Returns `None` if no path exists.
    #[must_use]
    pub fn shortest_path(
        &self,
        source: &TaintLocation,
        sink: &TaintLocation,
    ) -> Option<TaintFlow> {
        let src_idx = *self.node_map.get(source)?;
        let snk_idx = *self.node_map.get(sink)?;

        // BFS to find path.
        let mut parent: HashMap<NodeIndex, NodeIndex> = HashMap::new();
        let mut queue: VecDeque<NodeIndex> = VecDeque::new();
        queue.push_back(src_idx);
        parent.insert(src_idx, src_idx);

        while let Some(n) = queue.pop_front() {
            if n == snk_idx {
                break;
            }
            for e in self.graph.edges(n) {
                let t = e.target();
                if !parent.contains_key(&t) {
                    parent.insert(t, n);
                    queue.push_back(t);
                }
            }
        }

        if !parent.contains_key(&snk_idx) {
            return None;
        }

        // Reconstruct path.
        let mut path_nodes = vec![snk_idx];
        let mut cur = snk_idx;
        while cur != src_idx {
            cur = *parent.get(&cur)?;
            path_nodes.push(cur);
        }
        path_nodes.reverse();

        let taint_mask = self
            .graph
            .node_weight(snk_idx)
            .map_or(taint_bits::NONE, |n| n.taint_mask);

        let path: Vec<(TaintLocation, u64)> = path_nodes
            .iter()
            .filter_map(|&idx| self.graph.node_weight(idx))
            .map(|n| (n.location.clone(), n.creation_addr))
            .collect();

        Some(TaintFlow::new(
            source.clone(),
            sink.clone(),
            path,
            taint_mask,
        ))
    }

    // ── Source / sink queries ─────────────────────────────────────────────────

    /// All source nodes in the graph.
    #[must_use]
    pub fn source_nodes(&self) -> Vec<&TaintNodeData> {
        self.graph
            .node_weights()
            .filter(|n| n.is_source)
            .collect()
    }

    /// All sink nodes in the graph.
    #[must_use]
    pub fn sink_nodes(&self) -> Vec<&TaintNodeData> {
        self.graph
            .node_weights()
            .filter(|n| n.is_sink)
            .collect()
    }

    /// Find all flows from any source to any sink.
    #[must_use]
    pub fn source_to_sink_flows(&self) -> Vec<TaintFlow> {
        let sources: Vec<TaintLocation> = self
            .source_nodes()
            .iter()
            .map(|n| n.location.clone())
            .collect();
        let sinks: Vec<TaintLocation> = self
            .sink_nodes()
            .iter()
            .map(|n| n.location.clone())
            .collect();

        let mut flows = Vec::new();
        for src in &sources {
            for snk in &sinks {
                if let Some(flow) = self.shortest_path(src, snk) {
                    flows.push(flow);
                }
            }
        }
        flows
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Returns `true` if the graph is a DAG (no cycles).
    #[must_use]
    pub fn is_dag(&self) -> bool {
        !algo::is_cyclic_directed(&self.graph)
    }

    /// Number of tainted (non-sanitized) nodes.
    #[must_use]
    pub fn tainted_node_count(&self) -> usize {
        self.graph.node_weights().filter(|n| n.is_tainted()).count()
    }

    /// All tainted locations.
    #[must_use]
    pub fn tainted_locations(&self) -> Vec<TaintLocation> {
        self.graph
            .node_weights()
            .filter(|n| n.is_tainted())
            .map(|n| n.location.clone())
            .collect()
    }

    /// Compute BFS depth from all source nodes and store in each node's
    /// `depth_from_source` field.
    pub fn compute_depths(&mut self) {
        // Collect source indices first.
        let sources: Vec<NodeIndex> = self
            .graph
            .node_indices()
            .filter(|&idx| {
                self.graph
                    .node_weight(idx)
                    .is_some_and(|n| n.is_source)
            })
            .collect();

        let mut depth_map: HashMap<NodeIndex, u32> = HashMap::new();
        let mut queue: VecDeque<(NodeIndex, u32)> = VecDeque::new();

        for src in sources {
            depth_map.insert(src, 0);
            queue.push_back((src, 0));
        }

        while let Some((n, d)) = queue.pop_front() {
            for e in self.graph.edges(n) {
                let t = e.target();
                if !depth_map.contains_key(&t) {
                    let next_d = d.saturating_add(1);
                    depth_map.insert(t, next_d);
                    queue.push_back((t, next_d));
                }
            }
        }

        for (idx, depth) in depth_map {
            if let Some(n) = self.graph.node_weight_mut(idx) {
                n.depth_from_source = depth;
            }
        }
    }
}

impl Default for TaintGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TaintGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TaintGraph(nodes={} edges={} sources={} sinks={})",
            self.node_count(),
            self.edge_count(),
            self.source_nodes().len(),
            self.sink_nodes().len(),
        )
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TaintLocation, TaintSource, taint_bits};

    fn reg(name: &str) -> TaintLocation {
        TaintLocation::Register(name.to_owned())
    }
    fn mem(addr: u64) -> TaintLocation {
        TaintLocation::Memory(addr)
    }

    #[test]
    fn test_taint_graph_new_empty() {
        let g = TaintGraph::new();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn test_add_node() {
        let mut g = TaintGraph::new();
        let data = TaintNodeData::new(reg("rax"), taint_bits::USER_INPUT);
        g.add_node(data);
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn test_add_node_merges_taint() {
        let mut g = TaintGraph::new();
        g.add_node(TaintNodeData::new(reg("rax"), taint_bits::USER_INPUT));
        g.add_node(TaintNodeData::new(reg("rax"), taint_bits::NETWORK));
        // Still one node, taint is merged.
        assert_eq!(g.node_count(), 1);
        let data = g.node_data(&reg("rax")).unwrap();
        assert!(taint_bits::has_bit(data.taint_mask, taint_bits::USER_INPUT));
        assert!(taint_bits::has_bit(data.taint_mask, taint_bits::NETWORK));
    }

    #[test]
    fn test_add_edge_creates_nodes() {
        let mut g = TaintGraph::new();
        g.add_edge(
            &reg("rax"),
            &mem(0x1000),
            PropagationOp::Store,
            0x401000,
            taint_bits::USER_INPUT,
        );
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_has_path_true() {
        let mut g = TaintGraph::new();
        g.add_edge(&reg("rax"), &reg("rbx"), PropagationOp::Assign, 0x100, taint_bits::FILE);
        g.add_edge(&reg("rbx"), &mem(0x2000), PropagationOp::Store, 0x104, taint_bits::FILE);
        assert!(g.has_path(&reg("rax"), &mem(0x2000)));
    }

    #[test]
    fn test_has_path_false() {
        let mut g = TaintGraph::new();
        g.add_edge(&reg("rax"), &reg("rbx"), PropagationOp::Assign, 0x100, taint_bits::FILE);
        // No path rax → rcx
        let _ = g.ensure_node(reg("rcx"));
        assert!(!g.has_path(&reg("rax"), &reg("rcx")));
    }

    #[test]
    fn test_has_path_nonexistent_node() {
        let g = TaintGraph::new();
        assert!(!g.has_path(&reg("rax"), &mem(0x1000)));
    }

    #[test]
    fn test_reachable_from() {
        let mut g = TaintGraph::new();
        g.add_edge(&reg("rax"), &reg("rbx"), PropagationOp::Assign, 0x100, 1);
        g.add_edge(&reg("rbx"), &mem(0x1000), PropagationOp::Store, 0x104, 1);
        let reach = g.reachable_from(&reg("rax"));
        assert!(reach.contains(&reg("rbx")));
        assert!(reach.contains(&mem(0x1000)));
    }

    #[test]
    fn test_reachable_from_unknown() {
        let g = TaintGraph::new();
        assert!(g.reachable_from(&reg("rdi")).is_empty());
    }

    #[test]
    fn test_predecessors_of() {
        let mut g = TaintGraph::new();
        g.add_edge(&reg("rax"), &reg("rbx"), PropagationOp::Assign, 0x100, 1);
        g.add_edge(&reg("rcx"), &reg("rbx"), PropagationOp::Assign, 0x104, 1);
        let preds = g.predecessors_of(&reg("rbx"));
        assert!(preds.contains(&reg("rax")));
        assert!(preds.contains(&reg("rcx")));
    }

    #[test]
    fn test_shortest_path() {
        let mut g = TaintGraph::new();
        g.add_edge(&reg("rax"), &reg("rbx"), PropagationOp::Assign, 0x100, taint_bits::NETWORK);
        g.add_edge(&reg("rbx"), &mem(0x1000), PropagationOp::Store, 0x104, taint_bits::NETWORK);
        let flow = g.shortest_path(&reg("rax"), &mem(0x1000)).unwrap();
        assert_eq!(flow.hop_count(), 2);
    }

    #[test]
    fn test_shortest_path_no_path() {
        let mut g = TaintGraph::new();
        g.ensure_node(reg("rax"));
        g.ensure_node(mem(0x1000));
        assert!(g.shortest_path(&reg("rax"), &mem(0x1000)).is_none());
    }

    #[test]
    fn test_mark_source_and_query() {
        let mut g = TaintGraph::new();
        g.mark_source(&reg("rdi"), TaintSource::UserInput, taint_bits::USER_INPUT);
        assert_eq!(g.source_nodes().len(), 1);
        assert!(g.node_data(&reg("rdi")).unwrap().is_source);
    }

    #[test]
    fn test_mark_sink() {
        let mut g = TaintGraph::new();
        g.mark_sink(&mem(0xDEAD));
        assert_eq!(g.sink_nodes().len(), 1);
    }

    #[test]
    fn test_sanitize() {
        let mut g = TaintGraph::new();
        g.add_node(TaintNodeData::new(reg("rax"), taint_bits::FILE));
        g.sanitize(&reg("rax"));
        assert!(!g.node_data(&reg("rax")).unwrap().is_tainted());
    }

    #[test]
    fn test_source_to_sink_flows() {
        let mut g = TaintGraph::new();
        g.mark_source(&reg("rax"), TaintSource::UserInput, taint_bits::USER_INPUT);
        g.mark_sink(&mem(0xBEEF));
        g.add_edge(&reg("rax"), &mem(0xBEEF), PropagationOp::Store, 0x100, taint_bits::USER_INPUT);
        let flows = g.source_to_sink_flows();
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn test_is_dag_true() {
        let mut g = TaintGraph::new();
        g.add_edge(&reg("a"), &reg("b"), PropagationOp::Assign, 0, 1);
        g.add_edge(&reg("b"), &reg("c"), PropagationOp::Assign, 0, 1);
        assert!(g.is_dag());
    }

    #[test]
    fn test_tainted_node_count() {
        let mut g = TaintGraph::new();
        g.add_node(TaintNodeData::new(reg("rax"), taint_bits::USER_INPUT));
        g.add_node(TaintNodeData::new(reg("rbx"), taint_bits::NONE));
        assert_eq!(g.tainted_node_count(), 1);
    }

    #[test]
    fn test_compute_depths() {
        let mut g = TaintGraph::new();
        g.mark_source(&reg("rax"), TaintSource::UserInput, taint_bits::USER_INPUT);
        g.add_edge(&reg("rax"), &reg("rbx"), PropagationOp::Assign, 0x100, taint_bits::USER_INPUT);
        g.add_edge(&reg("rbx"), &mem(0x1000), PropagationOp::Store, 0x104, taint_bits::USER_INPUT);
        g.compute_depths();
        assert_eq!(g.node_data(&reg("rax")).unwrap().depth_from_source, 0);
        assert_eq!(g.node_data(&reg("rbx")).unwrap().depth_from_source, 1);
        assert_eq!(g.node_data(&mem(0x1000)).unwrap().depth_from_source, 2);
    }

    #[test]
    fn test_taint_node_data_is_tainted() {
        let n = TaintNodeData::new(reg("rax"), taint_bits::NETWORK);
        assert!(n.is_tainted());
        let clean = TaintNodeData::new(reg("rbx"), taint_bits::NONE);
        assert!(!clean.is_tainted());
    }

    #[test]
    fn test_taint_node_display() {
        let n = TaintNodeData::new(reg("rax"), taint_bits::USER_INPUT);
        assert!(!n.to_string().is_empty());
    }

    #[test]
    fn test_taint_edge_display() {
        let e = TaintEdgeData::new(PropagationOp::Load, 0x1000, taint_bits::FILE);
        assert!(e.to_string().contains("0x1000"));
    }

    #[test]
    fn test_taint_flow_display() {
        let flow = TaintFlow::new(reg("rax"), mem(0x1000), vec![], taint_bits::USER_INPUT);
        assert!(!flow.to_string().is_empty());
    }

    #[test]
    fn test_taint_flow_is_direct() {
        let flow = TaintFlow::new(
            reg("rax"),
            mem(0x1000),
            vec![(reg("rax"), 0), (mem(0x1000), 0)],
            1,
        );
        assert!(flow.is_direct());
    }

    #[test]
    fn test_graph_debug() {
        let g = TaintGraph::new();
        assert!(!format!("{g:?}").is_empty());
    }

    #[test]
    fn test_tainted_locations() {
        let mut g = TaintGraph::new();
        g.add_node(TaintNodeData::new(reg("rax"), taint_bits::FILE));
        let locs = g.tainted_locations();
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0], reg("rax"));
    }
}
