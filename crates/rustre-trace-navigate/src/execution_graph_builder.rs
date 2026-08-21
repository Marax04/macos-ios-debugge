//! Execution graph builder.
//!
//! Constructs a directed graph of observed control-flow transitions from a
//! recorded execution trace.  Each node is a unique instruction address;
//! each edge is a control-flow transition with traversal statistics.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use crate::trace_search_engine::TraceEntry;

// ---------------------------------------------------------------------------
// EdgeType
// ---------------------------------------------------------------------------

/// The kind of control-flow edge between two addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EdgeType {
    /// Sequential fall-through (address + `instruction_size` → next address).
    Fall,
    /// Unconditional or conditional jump.
    Jump,
    /// CALL instruction.
    Call,
    /// RET instruction.
    Return,
    /// Exception / interrupt handler dispatch.
    Exception,
}

impl EdgeType {
    /// Returns a Graphviz style string for this edge type.
    #[must_use]
    pub const fn graphviz_style(&self) -> &'static str {
        match self {
            Self::Fall => "style=solid color=black",
            Self::Jump => "style=dashed color=blue",
            Self::Call => "style=bold color=green",
            Self::Return => "style=dotted color=red",
            Self::Exception => "style=bold color=orange",
        }
    }
}

// ---------------------------------------------------------------------------
// ExecNode
// ---------------------------------------------------------------------------

/// A node in the execution graph (one unique instruction address).
#[derive(Debug, Clone)]
pub struct ExecNode {
    /// The instruction address.
    pub address: u64,
    /// Number of times this address was executed.
    pub visit_count: u32,
    /// Cumulative time spent at this address (sum of observation durations).
    pub total_time_ns: u64,
    /// Average time per visit.
    pub avg_time_ns: f64,
    /// Whether this node is considered "hot" (top 10 % by visit count).
    pub is_hot: bool,
    /// Disassembly of the first observed execution.
    pub disasm: String,
}

impl ExecNode {
    fn new(address: u64, disasm: &str) -> Self {
        Self {
            address,
            visit_count: 0,
            total_time_ns: 0,
            avg_time_ns: 0.0,
            is_hot: false,
            disasm: disasm.to_owned(),
        }
    }

    fn record_visit(&mut self, duration_ns: u64) {
        self.visit_count = self.visit_count.saturating_add(1);
        self.total_time_ns = self.total_time_ns.saturating_add(duration_ns);
        self.avg_time_ns = f64::from(u32::try_from(self.total_time_ns).unwrap_or(u32::MAX)) / f64::from(self.visit_count);
    }
}

// ---------------------------------------------------------------------------
// ExecEdge
// ---------------------------------------------------------------------------

/// A directed edge in the execution graph.
#[derive(Debug, Clone)]
pub struct ExecEdge {
    /// Source address.
    pub from: u64,
    /// Destination address.
    pub to: u64,
    /// Number of times this edge was traversed.
    pub traversal_count: u32,
    /// Type of the edge.
    pub edge_type: EdgeType,
}

impl ExecEdge {
    const fn new(from: u64, to: u64, edge_type: EdgeType) -> Self {
        Self {
            from,
            to,
            traversal_count: 1,
            edge_type,
        }
    }
}

// ---------------------------------------------------------------------------
// ExecutionGraph
// ---------------------------------------------------------------------------

/// A directed graph derived from an execution trace.
#[derive(Debug, Clone)]
pub struct ExecutionGraph {
    /// All nodes, keyed by address.
    pub nodes: HashMap<u64, ExecNode>,
    /// All edges.
    pub edges: Vec<ExecEdge>,
}

impl ExecutionGraph {
    /// Create an empty execution graph.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }

    /// Returns the number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns all successor addresses for `from`.
    #[must_use]
    pub fn successors(&self, from: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|e| e.from == from)
            .map(|e| e.to)
            .collect()
    }

    /// Returns all predecessor addresses for `to`.
    #[must_use]
    pub fn predecessors(&self, to: u64) -> Vec<u64> {
        self.edges
            .iter()
            .filter(|e| e.to == to)
            .map(|e| e.from)
            .collect()
    }

    /// Returns the edge between `from` and `to`, if it exists.
    #[must_use]
    pub fn edge(&self, from: u64, to: u64) -> Option<&ExecEdge> {
        self.edges.iter().find(|e| e.from == from && e.to == to)
    }

    /// Returns nodes sorted by `visit_count` descending.
    #[must_use]
    pub fn nodes_by_hotness(&self) -> Vec<&ExecNode> {
        let mut nodes: Vec<&ExecNode> = self.nodes.values().collect();
        nodes.sort_by_key(|b| std::cmp::Reverse(b.visit_count));
        nodes
    }

    /// Export the graph as a Graphviz DOT string.
    #[must_use]
    pub fn export_to_graphviz(&self) -> String {
        let mut dot = String::from("digraph execution_graph {\n");
        dot.push_str("  rankdir=TB;\n");
        dot.push_str("  node [shape=box fontname=Courier];\n\n");

        // Nodes
        for node in self.nodes.values() {
            let color = if node.is_hot { "red" } else { "black" };
            let label = format!(
                "0x{:x}\\n{}\\n×{}",
                node.address,
                node.disasm.replace('"', "'"),
                node.visit_count
            );
            let _ = writeln!(dot, "  n{:x} [label=\"{}\" color=\"{}\"];", node.address, label, color);
        }

        dot.push('\n');

        // Edges
        for edge in &self.edges {
            let style = edge.edge_type.graphviz_style();
            let _ = writeln!(dot, "  n{:x} -> n{:x} [label=\"×{}\" {}];", edge.from, edge.to, edge.traversal_count, style);
        }

        dot.push_str("}\n");
        dot
    }
}

impl Default for ExecutionGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExecutionGraphBuilder
// ---------------------------------------------------------------------------

/// Constructs an `ExecutionGraph` from a sequence of `TraceEntry` objects.
pub struct ExecutionGraphBuilder {
    /// Heuristic: address gaps larger than this are classified as JUMP/CALL.
    pub jump_threshold: u64,
}

impl ExecutionGraphBuilder {
    /// Create a builder with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            jump_threshold: 32,
        }
    }

    /// Build an `ExecutionGraph` from a slice of trace entries.
    #[must_use]
    pub fn build_from_trace(&self, entries: &[TraceEntry]) -> ExecutionGraph {
        let mut graph = ExecutionGraph::new();
        let mut edge_counts: HashMap<(u64, u64, u8), u32> = HashMap::new();

        for (i, entry) in entries.iter().enumerate() {
            // Create or update node
            let node = graph
                .nodes
                .entry(entry.address)
                .or_insert_with(|| ExecNode::new(entry.address, &entry.disasm));

            // Estimate duration from next entry's timestamp
            let duration = if i + 1 < entries.len() {
                entries[i + 1]
                    .timestamp_ns
                    .saturating_sub(entry.timestamp_ns)
            } else {
                0
            };
            node.record_visit(duration);

            // Create edge from previous entry
            if i > 0 {
                let prev = &entries[i - 1];
                let edge_type = self.classify_edge(prev, entry);
                let et_u8 = edge_type_to_u8(&edge_type);
                let counter = edge_counts
                    .entry((prev.address, entry.address, et_u8))
                    .or_insert(0);
                *counter += 1;
            }
        }

        // Convert edge_counts into ExecEdge list
        // First, collect all unique edges
        let mut edge_map: HashMap<(u64, u64, u8), ExecEdge> = HashMap::new();
        for (i, entry) in entries.iter().enumerate() {
            if i > 0 {
                let prev = &entries[i - 1];
                let edge_type = self.classify_edge(prev, entry);
                let et_u8 = edge_type_to_u8(&edge_type);
                let key = (prev.address, entry.address, et_u8);
                edge_map
                    .entry(key)
                    .or_insert_with(|| ExecEdge::new(prev.address, entry.address, edge_type.clone()))
                    .traversal_count = *edge_counts.get(&key).unwrap_or(&1);
            }
        }
        graph.edges = edge_map.into_values().collect();

        self.compute_hotness(&mut graph);
        graph
    }

    /// Classify the edge type between two consecutive trace entries.
    fn classify_edge(&self, prev: &TraceEntry, next: &TraceEntry) -> EdgeType {
        let mnemonic = prev.mnemonic().to_lowercase();
        if mnemonic == "call" || mnemonic == "callq" {
            return EdgeType::Call;
        }
        if mnemonic == "ret" || mnemonic == "retq" || mnemonic == "retn" {
            return EdgeType::Return;
        }
        if mnemonic.starts_with("int") || mnemonic == "syscall" || mnemonic == "sysenter" {
            return EdgeType::Exception;
        }
        // If addresses are far apart, treat it as a jump
        let delta = next.address.abs_diff(prev.address);
        if delta > self.jump_threshold {
            EdgeType::Jump
        } else {
            EdgeType::Fall
        }
    }

    /// Mark the top 10 % of nodes by visit count as "hot".
    pub fn compute_hotness(&self, graph: &mut ExecutionGraph) {
        if graph.nodes.is_empty() {
            return;
        }
        let mut counts: Vec<u32> = graph.nodes.values().map(|n| n.visit_count).collect();
        counts.sort_unstable_by(|a, b| b.cmp(a));
        let top_10_idx = (counts.len() / 10).max(1) - 1;
        let threshold = counts[top_10_idx.min(counts.len() - 1)];
        for node in graph.nodes.values_mut() {
            node.is_hot = node.visit_count >= threshold && threshold > 0;
        }
    }

    /// Find strongly-connected components using Kosaraju's algorithm.
    ///
    /// Returns a list of SCCs (each a set of addresses).  SCCs with more than
    /// one node represent loops.
    #[must_use]
    pub fn find_loops(&self, graph: &ExecutionGraph) -> Vec<HashSet<u64>> {
        let addresses: Vec<u64> = graph.nodes.keys().copied().collect();
        if addresses.is_empty() {
            return Vec::new();
        }

        // Build adjacency maps
        let mut forward: HashMap<u64, Vec<u64>> = HashMap::new();
        let mut backward: HashMap<u64, Vec<u64>> = HashMap::new();
        for edge in &graph.edges {
            forward.entry(edge.from).or_default().push(edge.to);
            backward.entry(edge.to).or_default().push(edge.from);
        }

        // Pass 1: DFS post-order on forward graph
        let mut visited: HashSet<u64> = HashSet::new();
        let mut finish_order: Vec<u64> = Vec::new();
        for &start in &addresses {
            if !visited.contains(&start) {
                dfs_iterative(&forward, start, &mut visited, &mut finish_order);
            }
        }

        // Pass 2: DFS on reversed graph in reverse finish order
        let mut visited2: HashSet<u64> = HashSet::new();
        let mut sccs: Vec<HashSet<u64>> = Vec::new();
        for &start in finish_order.iter().rev() {
            if !visited2.contains(&start) {
                let mut component: HashSet<u64> = HashSet::new();
                dfs_iterative_collect(&backward, start, &mut visited2, &mut component);
                sccs.push(component);
            }
        }
        sccs
    }

    /// Find sequences of addresses that repeat with at least `min_frequency`.
    ///
    /// Uses a sliding-window approach over the raw trace to find repeated
    /// n-grams of addresses.
    #[must_use]
    pub fn find_frequent_paths(
        &self,
        entries: &[TraceEntry],
        min_frequency: u32,
    ) -> Vec<Vec<u64>> {
        if entries.len() < 2 {
            return Vec::new();
        }

        let addrs: Vec<u64> = entries.iter().map(|e| e.address).collect();
        let mut results: Vec<Vec<u64>> = Vec::new();

        // Search for windows of length 2 to 6
        for window_size in 2..=6usize {
            if window_size >= addrs.len() {
                break;
            }
            let mut counts: HashMap<Vec<u64>, u32> = HashMap::new();
            for w in addrs.windows(window_size) {
                *counts.entry(w.to_vec()).or_insert(0) += 1;
            }
            for (path, freq) in counts {
                if freq >= min_frequency
                    && !results.iter().any(|r| r == &path) {
                        results.push(path);
                    }
            }
        }

        // Sort by path length descending, then by address
        results.sort_by(|a, b| b.len().cmp(&a.len()).then(a[0].cmp(&b[0])));
        results
    }
}

impl Default for ExecutionGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const fn edge_type_to_u8(et: &EdgeType) -> u8 {
    match et {
        EdgeType::Fall => 0,
        EdgeType::Jump => 1,
        EdgeType::Call => 2,
        EdgeType::Return => 3,
        EdgeType::Exception => 4,
    }
}

fn dfs_iterative(
    adj: &HashMap<u64, Vec<u64>>,
    start: u64,
    visited: &mut HashSet<u64>,
    finish_order: &mut Vec<u64>,
) {
    let mut stack: Vec<(u64, usize)> = vec![(start, 0)];
    visited.insert(start);
    while let Some((node, child_idx)) = stack.last_mut() {
        let node = *node;
        let neighbors = adj.get(&node).map_or(&[][..], std::vec::Vec::as_slice);
        if *child_idx < neighbors.len() {
            let next = neighbors[*child_idx];
            *child_idx += 1;
            if visited.insert(next) {
                stack.push((next, 0));
            }
        } else {
            finish_order.push(node);
            stack.pop();
        }
    }
}

fn dfs_iterative_collect(
    adj: &HashMap<u64, Vec<u64>>,
    start: u64,
    visited: &mut HashSet<u64>,
    component: &mut HashSet<u64>,
) {
    let mut queue: VecDeque<u64> = VecDeque::new();
    queue.push_back(start);
    visited.insert(start);
    component.insert(start);
    while let Some(node) = queue.pop_front() {
        if let Some(neighbors) = adj.get(&node) {
            for &next in neighbors {
                if visited.insert(next) {
                    component.insert(next);
                    queue.push_back(next);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: u64, addr: u64, disasm: &str) -> TraceEntry {
        TraceEntry::new(ts, 1, addr, disasm)
    }

    fn linear_trace() -> Vec<TraceEntry> {
        vec![
            entry(100, 0x1000, "push rbp"),
            entry(200, 0x1001, "mov rbp, rsp"),
            entry(300, 0x1003, "sub rsp, 0x20"),
            entry(400, 0x1007, "mov eax, 1"),
            entry(500, 0x100b, "ret"),
        ]
    }

    fn loop_trace() -> Vec<TraceEntry> {
        // A → B → C → B → C → B → C → D (loop B→C×3)
        vec![
            entry(100, 0xA000, "push rbp"),
            entry(200, 0xB000, "cmp eax, 0"),
            entry(300, 0xC000, "dec eax"),
            entry(400, 0xB000, "cmp eax, 0"),
            entry(500, 0xC000, "dec eax"),
            entry(600, 0xB000, "cmp eax, 0"),
            entry(700, 0xC000, "dec eax"),
            entry(800, 0xD000, "ret"),
        ]
    }

    #[test]
    fn test_build_linear_nodes() {
        let builder = ExecutionGraphBuilder::new();
        let trace = linear_trace();
        let graph = builder.build_from_trace(&trace);
        assert_eq!(graph.node_count(), 5);
    }

    #[test]
    fn test_build_linear_edges() {
        let builder = ExecutionGraphBuilder::new();
        let trace = linear_trace();
        let graph = builder.build_from_trace(&trace);
        assert!(graph.edge_count() >= 4);
    }

    #[test]
    fn test_visit_counts() {
        let builder = ExecutionGraphBuilder::new();
        let trace = loop_trace();
        let graph = builder.build_from_trace(&trace);
        let b_node = graph.nodes.get(&0xB000).unwrap();
        assert_eq!(b_node.visit_count, 3);
    }

    #[test]
    fn test_hotness_marking() {
        let builder = ExecutionGraphBuilder::new();
        let trace = loop_trace();
        let graph = builder.build_from_trace(&trace);
        let hot_nodes: Vec<_> = graph.nodes.values().filter(|n| n.is_hot).collect();
        // At least one node should be hot
        assert!(!hot_nodes.is_empty());
    }

    #[test]
    fn test_edge_type_call() {
        let builder = ExecutionGraphBuilder::new();
        let from = entry(0, 0x1000, "call VirtualAlloc");
        let to = entry(100, 0x007f_f800, "push rbp");
        let et = builder.classify_edge(&from, &to);
        assert_eq!(et, EdgeType::Call);
    }

    #[test]
    fn test_edge_type_ret() {
        let builder = ExecutionGraphBuilder::new();
        let from = entry(0, 0x1000, "ret");
        let to = entry(100, 0x2000, "mov eax, 0");
        let et = builder.classify_edge(&from, &to);
        assert_eq!(et, EdgeType::Return);
    }

    #[test]
    fn test_edge_type_fall() {
        let builder = ExecutionGraphBuilder::new();
        let from = entry(0, 0x1000, "mov eax, 1");
        let to = entry(100, 0x1004, "add eax, 2");
        let et = builder.classify_edge(&from, &to);
        assert_eq!(et, EdgeType::Fall);
    }

    #[test]
    fn test_edge_type_jump() {
        let builder = ExecutionGraphBuilder::new();
        let from = entry(0, 0x1000, "jmp somewhere");
        let to = entry(100, 0x5000, "mov eax, 1");
        let et = builder.classify_edge(&from, &to);
        assert_eq!(et, EdgeType::Jump);
    }

    #[test]
    fn test_find_loops() {
        let builder = ExecutionGraphBuilder::new();
        let trace = loop_trace();
        let graph = builder.build_from_trace(&trace);
        let sccs = builder.find_loops(&graph);
        let multi_node_sccs: Vec<_> = sccs.iter().filter(|s| s.len() > 1).collect();
        assert!(!multi_node_sccs.is_empty(), "should find loop between B and C");
    }

    #[test]
    fn test_find_frequent_paths() {
        let builder = ExecutionGraphBuilder::new();
        let trace = loop_trace();
        let paths = builder.find_frequent_paths(&trace, 2);
        // B→C should appear at least twice
        assert!(!paths.is_empty());
        let bc_path = vec![0xB000u64, 0xC000u64];
        assert!(paths.iter().any(|p| p == &bc_path));
    }

    #[test]
    fn test_successors() {
        let builder = ExecutionGraphBuilder::new();
        let graph = builder.build_from_trace(&linear_trace());
        let succ = graph.successors(0x1000);
        assert!(!succ.is_empty());
    }

    #[test]
    fn test_predecessors() {
        let builder = ExecutionGraphBuilder::new();
        let graph = builder.build_from_trace(&linear_trace());
        let pred = graph.predecessors(0x1001);
        assert!(pred.contains(&0x1000));
    }

    #[test]
    fn test_export_to_graphviz_contains_digraph() {
        let builder = ExecutionGraphBuilder::new();
        let graph = builder.build_from_trace(&linear_trace());
        let dot = graph.export_to_graphviz();
        assert!(dot.contains("digraph execution_graph"));
    }

    #[test]
    fn test_nodes_by_hotness_sorted() {
        let builder = ExecutionGraphBuilder::new();
        let graph = builder.build_from_trace(&loop_trace());
        let nodes = graph.nodes_by_hotness();
        if nodes.len() >= 2 {
            assert!(nodes[0].visit_count >= nodes[1].visit_count);
        }
    }

    #[test]
    fn test_empty_trace() {
        let builder = ExecutionGraphBuilder::new();
        let graph = builder.build_from_trace(&[]);
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }
}
