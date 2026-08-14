//! `data_flow_xrefs` — inter-function data dependency graph.
//!
//! Tracks how values flow between functions via return values, global variables,
//! and heap allocations.  Builds a directed `DataDependencyGraph` and can produce
//! full propagation chains for any (source, sink) pair.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// DataSource

/// A source of data values in the binary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DataSource {
    /// Function return value — the value returned by the function at `addr`.
    ReturnValue { func_addr: u64 },
    /// Global / static variable at a fixed address.
    Global { addr: u64, name: Option<String> },
    /// Heap allocation site (call to malloc/new/etc.) at `call_addr`.
    HeapAlloc { call_addr: u64 },
    /// Function argument at position `arg_idx` (0-based).
    Argument { func_addr: u64, arg_idx: usize },
    /// Stack local variable identified by frame offset.
    StackLocal { func_addr: u64, offset: i32 },
    /// Imported function (its return value is foreign data).
    Import { name: String },
    /// Literal / immediate constant baked into the instruction stream.
    Constant { value: u64 },
}

impl fmt::Display for DataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReturnValue { func_addr } => write!(f, "ret({func_addr:#x})"),
            Self::Global { addr, name } => {
                if let Some(n) = name { write!(f, "global({n}, {addr:#x})") }
                else { write!(f, "global({addr:#x})") }
            }
            Self::HeapAlloc { call_addr } => write!(f, "heap@{call_addr:#x}"),
            Self::Argument { func_addr, arg_idx } => {
                write!(f, "arg{arg_idx}@{func_addr:#x}")
            }
            Self::StackLocal { func_addr, offset } => {
                write!(f, "local[{offset}]@{func_addr:#x}")
            }
            Self::Import { name } => write!(f, "import({name})"),
            Self::Constant { value } => write!(f, "const({value:#x})"),
        }
    }
}

// ---------------------------------------------------------------------------
// DataSink

/// A sink where data values are consumed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DataSink {
    /// Passed as argument to a callee function.
    CallArgument { call_site: u64, callee: u64, arg_idx: usize },
    /// Stored to a global variable.
    GlobalStore { addr: u64 },
    /// Stored to the heap (pointer + offset).
    HeapStore { site: u64 },
    /// Returned from the containing function.
    Return { func_addr: u64 },
    /// Used in a branch condition (taint-sensitive branch).
    BranchCondition { branch_addr: u64 },
    /// Passed to an indirect call (function pointer).
    IndirectCall { call_site: u64 },
}

impl fmt::Display for DataSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CallArgument { call_site, callee, arg_idx } => {
                write!(f, "arg{arg_idx}->callee({callee:#x})@{call_site:#x}")
            }
            Self::GlobalStore { addr } => write!(f, "store->global({addr:#x})"),
            Self::HeapStore { site } => write!(f, "store->heap@{site:#x}"),
            Self::Return { func_addr } => write!(f, "return@{func_addr:#x}"),
            Self::BranchCondition { branch_addr } => write!(f, "branch@{branch_addr:#x}"),
            Self::IndirectCall { call_site } => write!(f, "icall@{call_site:#x}"),
        }
    }
}

// ---------------------------------------------------------------------------
// DataFlowEdge

/// A directed data-flow edge from a source to a sink, tagged with the
/// function address where the flow was observed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataFlowEdge {
    pub source: DataSource,
    pub sink: DataSink,
    /// Function that contains this flow.
    pub in_func: u64,
    /// The instruction address where the transfer occurs.
    pub insn_addr: u64,
    /// Confidence score 0-100.
    pub confidence: u8,
}

impl DataFlowEdge {
    #[must_use] 
    pub const fn new(source: DataSource, sink: DataSink, in_func: u64, insn_addr: u64) -> Self {
        Self { source, sink, in_func, insn_addr, confidence: 100 }
    }

    #[must_use] 
    pub fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c.min(100);
        self
    }
}

impl fmt::Display for DataFlowEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}%] {} -> {} (fn={:#x}, insn={:#x})",
            self.confidence, self.source, self.sink, self.in_func, self.insn_addr)
    }
}

// ---------------------------------------------------------------------------
// PropagationChain

/// An ordered sequence of data-flow edges forming a path from a root source
/// to a final sink.
#[derive(Debug, Clone)]
pub struct PropagationChain {
    pub edges: Vec<DataFlowEdge>,
}

impl PropagationChain {
    #[must_use] 
    pub const fn new() -> Self { Self { edges: Vec::new() } }

    pub fn push(&mut self, edge: DataFlowEdge) { self.edges.push(edge); }

    #[must_use] 
    pub const fn len(&self) -> usize { self.edges.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.edges.is_empty() }

    /// The root source of this chain (first edge's source).
    #[must_use] 
    pub fn root(&self) -> Option<&DataSource> {
        self.edges.first().map(|e| &e.source)
    }

    /// The final sink of this chain (last edge's sink).
    #[must_use] 
    pub fn terminal(&self) -> Option<&DataSink> {
        self.edges.last().map(|e| &e.sink)
    }

    /// Minimum confidence along the chain.
    #[must_use] 
    pub fn min_confidence(&self) -> u8 {
        self.edges.iter().map(|e| e.confidence).min().unwrap_or(0)
    }

    /// Functions visited along the chain (in order).
    #[must_use] 
    pub fn functions(&self) -> Vec<u64> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for e in &self.edges {
            if seen.insert(e.in_func) { out.push(e.in_func); }
        }
        out
    }
}

impl Default for PropagationChain {
    fn default() -> Self { Self::new() }
}

impl fmt::Display for PropagationChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, edge) in self.edges.iter().enumerate() {
            writeln!(f, "  [{i}] {edge}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DataDependencyGraph

/// Node identifier within the graph: an index into the flat node list.
type NodeId = usize;

/// A node in the dependency graph (a data source or intermediate variable).
#[derive(Debug, Clone)]
struct DdgNode {
    /// The canonical source this node represents.
    source: DataSource,
    /// Indices of edges that originate from this node.
    out_edges: Vec<usize>,
}

/// An edge in the dependency graph.
#[derive(Debug, Clone)]
struct DdgEdge {
    from: NodeId,
    to: NodeId,
    flow: DataFlowEdge,
}

/// Directed data dependency graph across function boundaries.
///
/// Nodes are data sources; edges are data-flow edges connecting them.
/// The graph supports BFS-based chain finding from any source.
#[derive(Debug, Clone)]
pub struct DataDependencyGraph {
    nodes: Vec<DdgNode>,
    edges: Vec<DdgEdge>,
    source_to_node: HashMap<DataSourceKey, NodeId>,
}

/// A hashable key that identifies a `DataSource`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DataSourceKey {
    ReturnValue(u64),
    Global(u64),
    HeapAlloc(u64),
    Argument(u64, usize),
    StackLocal(u64, i32),
    Import(String),
    Constant(u64),
}

impl DataSourceKey {
    fn from_source(s: &DataSource) -> Self {
        match s {
            DataSource::ReturnValue { func_addr } => Self::ReturnValue(*func_addr),
            DataSource::Global { addr, .. } => Self::Global(*addr),
            DataSource::HeapAlloc { call_addr } => Self::HeapAlloc(*call_addr),
            DataSource::Argument { func_addr, arg_idx } => Self::Argument(*func_addr, *arg_idx),
            DataSource::StackLocal { func_addr, offset } => Self::StackLocal(*func_addr, *offset),
            DataSource::Import { name } => Self::Import(name.clone()),
            DataSource::Constant { value } => Self::Constant(*value),
        }
    }
}

impl DataDependencyGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            source_to_node: HashMap::new(),
        }
    }

    fn get_or_create_node(&mut self, src: DataSource) -> NodeId {
        let key = DataSourceKey::from_source(&src);
        if let Some(&id) = self.source_to_node.get(&key) {
            return id;
        }
        let id = self.nodes.len();
        self.nodes.push(DdgNode { source: src, out_edges: Vec::new() });
        self.source_to_node.insert(key, id);
        id
    }

    /// Add a data-flow edge to the graph.
    ///
    /// The edge's sink is used to synthesise a destination source (`ReturnValue`
    /// / Global / etc.) so that chains can be followed across functions.
    pub fn add_edge(&mut self, edge: DataFlowEdge) {
        let from_src = edge.source.clone();
        let from_id = self.get_or_create_node(from_src);

        // Synthesise a destination node based on the sink type.
        let to_src = match &edge.sink {
            DataSink::Return { func_addr } => {
                DataSource::ReturnValue { func_addr: *func_addr }
            }
            DataSink::CallArgument { callee, arg_idx, .. } => {
                DataSource::Argument { func_addr: *callee, arg_idx: *arg_idx }
            }
            DataSink::GlobalStore { addr } => {
                DataSource::Global { addr: *addr, name: None }
            }
            DataSink::HeapStore { site } => {
                DataSource::HeapAlloc { call_addr: *site }
            }
            DataSink::BranchCondition { branch_addr } => {
                DataSource::StackLocal { func_addr: *branch_addr, offset: 0 }
            }
            DataSink::IndirectCall { call_site } => {
                DataSource::HeapAlloc { call_addr: *call_site }
            }
        };

        let to_id = self.get_or_create_node(to_src);
        let edge_idx = self.edges.len();
        self.edges.push(DdgEdge { from: from_id, to: to_id, flow: edge });
        self.nodes[from_id].out_edges.push(edge_idx);
    }

    /// BFS to find all propagation chains from `source` up to `max_depth` hops.
    ///
    /// The data-flow graph can contain cycles (e.g. a loop that repeatedly
    /// stores back into the same global, or a source reachable from itself
    /// through a chain of calls). Each in-flight path tracks the set of
    /// node ids it has already visited and refuses to step onto one of them
    /// again — without this guard, a cycle turns the search into an
    /// exponential (bounded only by `max_depth`, which callers may pass as
    /// a very large or effectively "unlimited" value) blow-up of
    /// ever-repeating chains instead of terminating quickly once the cycle
    /// is detected.
    #[must_use]
    pub fn chains_from(&self, source: &DataSource, max_depth: usize) -> Vec<PropagationChain> {
        let key = DataSourceKey::from_source(source);
        let Some(&start_id) = self.source_to_node.get(&key) else { return Vec::new() };

        let mut results = Vec::new();
        // BFS state: (node_id, accumulated_chain, nodes visited on this path)
        let mut queue: VecDeque<(NodeId, PropagationChain, HashSet<NodeId>)> = VecDeque::new();
        let mut start_visited = HashSet::new();
        start_visited.insert(start_id);
        queue.push_back((start_id, PropagationChain::new(), start_visited));

        while let Some((node_id, chain, visited)) = queue.pop_front() {
            if chain.len() >= max_depth {
                if !chain.is_empty() { results.push(chain); }
                continue;
            }
            let node = &self.nodes[node_id];
            if node.out_edges.is_empty() {
                if !chain.is_empty() { results.push(chain); }
                continue;
            }
            let mut extended_any = false;
            for &eidx in &node.out_edges {
                let edge = &self.edges[eidx];
                // Skip edges that would revisit a node already on this path
                // (cycle) — prevents unbounded/exponential path growth.
                if visited.contains(&edge.to) {
                    continue;
                }
                let mut new_chain = chain.clone();
                new_chain.push(edge.flow.clone());
                let mut new_visited = visited.clone();
                new_visited.insert(edge.to);
                queue.push_back((edge.to, new_chain, new_visited));
                extended_any = true;
            }
            if !extended_any && !chain.is_empty() {
                // All outgoing edges led back into the path (pure cycle) —
                // record the chain up to this point instead of dropping it.
                results.push(chain);
            }
        }
        results
    }

    /// Find all chains from `source` that eventually reach `sink` (by sink address match).
    #[must_use] 
    pub fn chains_to_sink(&self, source: &DataSource, sink_addr: u64, max_depth: usize) -> Vec<PropagationChain> {
        let all = self.chains_from(source, max_depth);
        all.into_iter().filter(|c| {
            c.edges.iter().any(|e| e.insn_addr == sink_addr)
        }).collect()
    }

    /// Return all data sources that flow into `sink_func` as arguments or returns.
    #[must_use] 
    pub fn sources_reaching_func(&self, sink_func: u64) -> Vec<DataSource> {
        let mut out = Vec::new();
        for edge in &self.edges {
            let reaches = match &edge.flow.sink {
                DataSink::CallArgument { callee, .. } => *callee == sink_func,
                DataSink::Return { func_addr } => *func_addr == sink_func,
                DataSink::GlobalStore { .. }
                | DataSink::HeapStore { .. }
                | DataSink::BranchCondition { .. }
                | DataSink::IndirectCall { .. } => false,
            };
            if reaches {
                out.push(edge.flow.source.clone());
            }
        }
        out
    }

    /// Number of nodes in the graph.
    #[must_use] 
    pub const fn node_count(&self) -> usize { self.nodes.len() }
    /// Number of edges in the graph.
    #[must_use] 
    pub const fn edge_count(&self) -> usize { self.edges.len() }

    /// Return the [`DataSource`] backing the node at `node_id`, if any.
    ///
    /// Together with [`Self::edge_endpoints`] this lets external callers walk
    /// the graph without exposing the private node/edge structs.
    #[must_use]
    pub fn node_source(&self, node_id: usize) -> Option<&DataSource> {
        self.nodes.get(node_id).map(|n| &n.source)
    }

    /// Return the `(from_node, to_node)` endpoints of the edge at `edge_id`.
    #[must_use]
    pub fn edge_endpoints(&self, edge_id: usize) -> Option<(usize, usize)> {
        self.edges.get(edge_id).map(|e| (e.from, e.to))
    }

    /// Iterator over `(from_source, to_source)` pairs for every edge.
    ///
    /// Skips edges whose endpoints have somehow been removed from the node
    /// table (should never happen in practice but kept defensive).
    pub fn edge_source_pairs(&self) -> impl Iterator<Item = (&DataSource, &DataSource)> + '_ {
        self.edges.iter().filter_map(move |e| {
            let f = self.nodes.get(e.from).map(|n| &n.source)?;
            let t = self.nodes.get(e.to).map(|n| &n.source)?;
            Some((f, t))
        })
    }

    /// Statistics string.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!("DataDependencyGraph: {} nodes, {} edges", self.node_count(), self.edge_count())
    }
}

impl Default for DataDependencyGraph {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    fn make_graph() -> DataDependencyGraph {
        let mut g = DataDependencyGraph::new();
        // import("malloc") --heap alloc--> heapAlloc@0x1010
        // retval(0x1000) --arg0->callee(0x2000)--> arg0@0x2000
        // arg0@0x2000 --return--> retval(0x2000)

        let e1 = DataFlowEdge::new(
            DataSource::Import { name: "malloc".into() },
            DataSink::HeapStore { site: 0x1010 },
            0x1000, 0x1010,
        );
        let e2 = DataFlowEdge::new(
            DataSource::ReturnValue { func_addr: 0x1000 },
            DataSink::CallArgument { call_site: 0x2050, callee: 0x2000, arg_idx: 0 },
            0x1050, 0x2050,
        );
        let e3 = DataFlowEdge::new(
            DataSource::Argument { func_addr: 0x2000, arg_idx: 0 },
            DataSink::Return { func_addr: 0x2000 },
            0x2000, 0x2080,
        );
        g.add_edge(e1);
        g.add_edge(e2);
        g.add_edge(e3);
        g
    }

    #[test]
    fn test_node_edge_count() {
        let g = make_graph();
        assert_eq!(g.edge_count(), 3);
        assert!(g.node_count() >= 3);
    }

    #[test]
    fn test_chains_from_import() {
        let g = make_graph();
        let src = DataSource::Import { name: "malloc".into() };
        let chains = g.chains_from(&src, 5);
        assert!(!chains.is_empty());
    }

    #[test]
    fn test_chains_from_cycle_terminates_and_is_bounded() {
        // Build a 2-node cycle: Argument@0x2000 --Return--> ReturnValue(0x2000)
        // --CallArgument(callee=0x2000)--> Argument@0x2000 (same node as start).
        let mut g = DataDependencyGraph::new();
        let e_out = DataFlowEdge::new(
            DataSource::Argument { func_addr: 0x2000, arg_idx: 0 },
            DataSink::Return { func_addr: 0x2000 },
            0x2000, 0x2080,
        );
        let e_back = DataFlowEdge::new(
            DataSource::ReturnValue { func_addr: 0x2000 },
            DataSink::CallArgument { call_site: 0x2090, callee: 0x2000, arg_idx: 0 },
            0x2090, 0x2090,
        );
        g.add_edge(e_out);
        g.add_edge(e_back);

        let src = DataSource::Argument { func_addr: 0x2000, arg_idx: 0 };
        // A max_depth far larger than the cycle length: without cycle
        // detection this would try to enumerate an exponentially (here,
        // effectively unboundedly) growing number of repeating chains and
        // never return in reasonable time/memory. With the per-path
        // visited-node guard it must terminate immediately and produce a
        // chain no longer than the cycle itself.
        let chains = g.chains_from(&src, 1_000_000);
        assert!(!chains.is_empty());
        for chain in &chains {
            assert!(chain.len() <= 2, "chain revisited a node in the cycle: len={}", chain.len());
        }
    }

    #[test]
    fn test_chains_from_retval() {
        let g = make_graph();
        let src = DataSource::ReturnValue { func_addr: 0x1000 };
        let chains = g.chains_from(&src, 5);
        // chain: retval(0x1000)->arg0@0x2000->retval(0x2000)
        assert!(!chains.is_empty());
        let longest = chains.iter().max_by_key(|c| c.len()).unwrap();
        assert!(longest.len() >= 1);
    }

    #[test]
    fn test_sources_reaching_func() {
        let g = make_graph();
        let srcs = g.sources_reaching_func(0x2000);
        assert!(!srcs.is_empty());
    }

    #[test]
    fn test_propagation_chain_functions() {
        let g = make_graph();
        let src = DataSource::ReturnValue { func_addr: 0x1000 };
        let chains = g.chains_from(&src, 5);
        for c in &chains {
            let fns = c.functions();
            assert!(!fns.is_empty());
        }
    }
}
