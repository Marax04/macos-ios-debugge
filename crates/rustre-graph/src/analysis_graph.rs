//! Full analysis graph over a binary view.
//!
//! Provides [`AnalysisGraph`], [`FunctionNode`], [`CallEdge`], [`DataFlowEdge`],
//! [`TypeEdge`], [`GraphQuery`] (Cypher-like DSL), and [`GraphExport`]
//! (DOT/JSON/Gephi formats).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fmt::Write;

// ─────────────────────────────────────────────────────────────────────────────
// Node and edge ID types
// ─────────────────────────────────────────────────────────────────────────────

/// Opaque node identifier in the analysis graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u64);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "N{}", self.0)
    }
}

/// Opaque edge identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EdgeId(pub u64);

impl fmt::Display for EdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "E{}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionNode
// ─────────────────────────────────────────────────────────────────────────────

/// Node representing a function in the analysis graph.
#[derive(Debug, Clone)]
pub struct FunctionNode {
    pub id: NodeId,
    pub address: u64,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub is_external: bool,
    pub is_thunk: bool,
    /// True if this function is the program entry point.
    pub is_entry: bool,
    pub calling_conv: Option<String>,
    pub prototype: Option<String>,
    /// Arbitrary key-value annotations.
    pub annotations: HashMap<String, String>,
}

impl FunctionNode {
    #[must_use]
    pub fn new(id: NodeId, address: u64) -> Self {
        Self {
            id,
            address,
            name: None,
            size: None,
            is_external: false,
            is_thunk: false,
            is_entry: false,
            calling_conv: None,
            prototype: None,
            annotations: HashMap::default(),
        }
    }
 #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("fn_{:#x}", self.address))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DataNode — represents a data variable / global
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DataNode {
    pub id: NodeId,
    pub address: u64,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub type_name: Option<String>,
}

impl DataNode {
    #[must_use]
    pub const fn new(id: NodeId, address: u64) -> Self {
        Self {
            id,
            address,
            name: None,
            size: None,
            type_name: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeKind
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum NodeKind {
    Function(FunctionNode),
    Data(DataNode),
}

impl NodeKind {
    #[must_use]
    pub const fn id(&self) -> NodeId {
        match self {
            Self::Function(f) => f.id,
            Self::Data(d) => d.id,
        }
    }

    #[must_use]
    pub const fn address(&self) -> u64 {
        match self {
            Self::Function(f) => f.address,
            Self::Data(d) => d.address,
        }
    }

    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Function(f) => f.name.as_deref(),
            Self::Data(d) => d.name.as_deref(),
        }
    }

    #[must_use]
    pub const fn as_function(&self) -> Option<&FunctionNode> {
        if let Self::Function(f) = self {
            Some(f)
        } else {
            None
        }
    }
 #[must_use]
    pub const fn as_data(&self) -> Option<&DataNode> {
        if let Self::Data(d) = self {
            Some(d)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Function(_) => "Function",
            Self::Data(_) => "Data",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edges
// ─────────────────────────────────────────────────────────────────────────────

/// A call edge from one function to another.
#[derive(Debug, Clone)]
pub struct CallEdge {
    pub id: EdgeId,
    pub from: NodeId,
    pub to: NodeId,
    /// Address of the call site.
    pub call_site: u64,
    /// True if the target is computed at runtime (indirect call).
    pub is_indirect: bool,
    /// True if this is a tail call.
    pub is_tail_call: bool,
    /// Estimated call frequency (loop-count / profiling weight).
    pub weight: f64,
}

impl CallEdge {
    #[must_use]
    pub const fn new(id: EdgeId, from: NodeId, to: NodeId, call_site: u64) -> Self {
        Self {
            id,
            from,
            to,
            call_site,
            is_indirect: false,
            is_tail_call: false,
            weight: 1.0,
        }
    }
}

/// A data-flow edge: one node reads/writes data used by another.
#[derive(Debug, Clone)]
pub struct DataFlowEdge {
    pub id: EdgeId,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: DataFlowKind,
    pub variable: Option<String>,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFlowKind {
    Read,
    Write,
    ReadWrite,
    Address,
}

impl fmt::Display for DataFlowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "rw",
            Self::Address => "addr",
        };
        write!(f, "{s}")
    }
}

/// A type-relationship edge (e.g., function returns/takes a given type).
#[derive(Debug, Clone)]
pub struct TypeEdge {
    pub id: EdgeId,
    pub from: NodeId,
    pub to: NodeId,
    pub kind: TypeEdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeEdgeKind {
    Returns,
    TakesParam,
    FieldOf,
    Inherits,
    CastsTo,
}

impl fmt::Display for TypeEdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Returns => "returns",
            Self::TakesParam => "takes_param",
            Self::FieldOf => "field_of",
            Self::Inherits => "inherits",
            Self::CastsTo => "casts_to",
        };
        write!(f, "{s}")
    }
}

/// Generic edge kind.
#[derive(Debug, Clone)]
pub enum EdgeKind {
    Call(CallEdge),
    DataFlow(DataFlowEdge),
    Type(TypeEdge),
}

impl EdgeKind {
    #[must_use]
    pub const fn id(&self) -> EdgeId {
        match self {
            Self::Call(e) => e.id,
            Self::DataFlow(e) => e.id,
            Self::Type(e) => e.id,
        }
    }

    #[must_use]
    pub const fn from_node(&self) -> NodeId {
        match self {
            Self::Call(e) => e.from,
            Self::DataFlow(e) => e.from,
            Self::Type(e) => e.from,
        }
    }

    #[must_use]
    pub const fn to_node(&self) -> NodeId {
        match self {
            Self::Call(e) => e.to,
            Self::DataFlow(e) => e.to,
            Self::Type(e) => e.to,
        }
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Call(_) => "CALL",
            Self::DataFlow(_) => "DATA_FLOW",
            Self::Type(_) => "TYPE",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisGraph
// ─────────────────────────────────────────────────────────────────────────────

/// The central analysis graph.
///
/// Nodes represent functions and data; edges represent calls, data flows,
/// and type relationships.
#[derive(Debug, Default)]
pub struct AnalysisGraph {
    nodes: HashMap<NodeId, NodeKind>,
    edges: HashMap<EdgeId, EdgeKind>,
    /// Out-edges indexed by source node.
    adjacency: HashMap<NodeId, Vec<EdgeId>>,
    /// In-edges indexed by destination node.
    reverse_adjacency: HashMap<NodeId, Vec<EdgeId>>,
    /// Address → node id index.
    addr_index: HashMap<u64, NodeId>,
    next_node: u64,
    next_edge: u64,
}

impl AnalysisGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Node management ───────────────────────────────────────────────────────

    const fn alloc_node_id(&mut self) -> NodeId {
        let id = NodeId(self.next_node);
        self.next_node += 1;
        id
    }

    const fn alloc_edge_id(&mut self) -> EdgeId {
        let id = EdgeId(self.next_edge);
        self.next_edge += 1;
        id
    }

    /// Add a function node, returning its [`NodeId`].
    pub fn add_function(&mut self, address: u64, name: Option<&str>) -> NodeId {
        if let Some(&existing) = self.addr_index.get(&address) {
            return existing;
        }
        let id = self.alloc_node_id();
        let mut node = FunctionNode::new(id, address);
        if let Some(n) = name {
            node.name = Some(n.to_owned());
        }
        self.addr_index.insert(address, id);
        self.nodes.insert(id, NodeKind::Function(node));
        id
    }

    /// Add a data node, returning its [`NodeId`].
    pub fn add_data(&mut self, address: u64, name: Option<&str>) -> NodeId {
        if let Some(&existing) = self.addr_index.get(&address) {
            return existing;
        }
        let id = self.alloc_node_id();
        let mut node = DataNode::new(id, address);
        if let Some(n) = name {
            node.name = Some(n.to_owned());
        }
        self.addr_index.insert(address, id);
        self.nodes.insert(id, NodeKind::Data(node));
        id
    }

    /// Look up a node by id.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&NodeKind> {
        self.nodes.get(&id)
    }

    /// Look up a node by virtual address.
    #[must_use]
    pub fn node_at_address(&self, addr: u64) -> Option<&NodeKind> {
        self.addr_index.get(&addr).and_then(|id| self.nodes.get(id))
    }

    /// Total number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// All node IDs.
    pub fn nodes(&self) -> impl Iterator<Item = (&NodeId, &NodeKind)> {
        self.nodes.iter()
    }

    /// All function nodes.
    pub fn function_nodes(&self) -> impl Iterator<Item = &FunctionNode> {
        self.nodes.values().filter_map(|n| n.as_function())
    }

    /// Look up a function node by its node id.
    #[must_use]
    pub fn get_function_node(&self, id: NodeId) -> Option<&FunctionNode> {
        self.nodes.get(&id).and_then(|n| n.as_function())
    }

    // ── Edge management ───────────────────────────────────────────────────────

    fn register_edge(&mut self, id: EdgeId, from: NodeId, to: NodeId, kind: EdgeKind) {
        self.adjacency.entry(from).or_default().push(id);
        self.reverse_adjacency.entry(to).or_default().push(id);
        self.edges.insert(id, kind);
    }

    /// Add a call edge between two nodes.
    pub fn add_call_edge(&mut self, from: NodeId, to: NodeId, call_site: u64) -> EdgeId {
        let id = self.alloc_edge_id();
        let edge = CallEdge::new(id, from, to, call_site);
        self.register_edge(id, from, to, EdgeKind::Call(edge));
        id
    }

    /// Add a data-flow edge.
    pub fn add_data_flow_edge(
        &mut self,
        from: NodeId,
        to: NodeId,
        kind: DataFlowKind,
        variable: Option<String>,
        address: Option<u64>,
    ) -> EdgeId {
        let eid = self.alloc_edge_id();
        let edge = DataFlowEdge {
            id: eid,
            from,
            to,
            kind,
            variable,
            address,
        };
        self.register_edge(eid, from, to, EdgeKind::DataFlow(edge));
        eid
    }

    /// Add a type edge.
    pub fn add_type_edge(&mut self, from: NodeId, to: NodeId, kind: TypeEdgeKind) -> EdgeId {
        let eid = self.alloc_edge_id();
        let edge = TypeEdge {
            id: eid,
            from,
            to,
            kind,
        };
        self.register_edge(eid, from, to, EdgeKind::Type(edge));
        eid
    }

    /// Total number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// All edges from a node (outgoing).
    #[must_use]
    pub fn edges_from(&self, id: NodeId) -> Vec<&EdgeKind> {
        self.adjacency
            .get(&id)
            .map(|ids| ids.iter().filter_map(|eid| self.edges.get(eid)).collect())
            .unwrap_or_default()
    }

    /// All edges to a node (incoming).
    #[must_use]
    pub fn edges_to(&self, id: NodeId) -> Vec<&EdgeKind> {
        self.reverse_adjacency
            .get(&id)
            .map(|ids| ids.iter().filter_map(|eid| self.edges.get(eid)).collect())
            .unwrap_or_default()
    }

    /// All call edges from a node.
    #[must_use]
    pub fn callees_of(&self, id: NodeId) -> Vec<NodeId> {
        self.edges_from(id)
            .into_iter()
            .filter_map(|e| {
                if let EdgeKind::Call(c) = e {
                    Some(c.to)
                } else {
                    None
                }
            })
            .collect()
    }

    /// All callers of a node (via call edges).
    #[must_use]
    pub fn callers_of(&self, id: NodeId) -> Vec<NodeId> {
        self.edges_to(id)
            .into_iter()
            .filter_map(|e| {
                if let EdgeKind::Call(c) = e {
                    Some(c.from)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Number of outgoing call edges (out-degree in the call graph).
    #[must_use]
    pub fn call_out_degree(&self, id: NodeId) -> usize {
        self.callees_of(id).len()
    }

    /// Number of incoming call edges (in-degree in the call graph).
    #[must_use]
    pub fn call_in_degree(&self, id: NodeId) -> usize {
        self.callers_of(id).len()
    }

    // ── Traversals ─────────────────────────────────────────────────────────────

    /// BFS traversal from `start`, returning nodes in visit order.
    #[must_use]
    pub fn bfs(&self, start: NodeId) -> Vec<NodeId> {
        let n = self.nodes.len();
        let mut visited = HashSet::with_capacity(n);
        let mut queue = VecDeque::new();
        let mut result = Vec::with_capacity(n);
        if !self.nodes.contains_key(&start) {
            return result;
        }
        queue.push_back(start);
        visited.insert(start);
        while let Some(n) = queue.pop_front() {
            result.push(n);
            for callee in self.callees_of(n) {
                if visited.insert(callee) {
                    queue.push_back(callee);
                }
            }
        }
        result
    }

    /// DFS traversal from `start`, returning nodes in visit order.
    #[must_use]
    pub fn dfs(&self, start: NodeId) -> Vec<NodeId> {
        // Iterative DFS to avoid stack overflow on large/deep graphs.
        let n = self.nodes.len();
        let mut visited = HashSet::with_capacity(n);
        let mut result = Vec::with_capacity(n);
        if !self.nodes.contains_key(&start) {
            return result;
        }
        let mut stack = vec![start];
        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }
            result.push(node);
            // Push in reverse order so the first callee is processed first.
            let callees = self.callees_of(node);
            for callee in callees.into_iter().rev() {
                if !visited.contains(&callee) {
                    stack.push(callee);
                }
            }
        }
        result
    }

    // dfs_recurse removed: replaced by iterative dfs above.

    /// Returns all nodes reachable from `start` via call edges.
    #[must_use]
    pub fn reachable_functions(&self, start: NodeId) -> HashSet<NodeId> {
        self.bfs(start).into_iter().collect()
    }

    /// Identify strongly-connected components via Kosaraju's algorithm.
    ///
    /// Returns a list of SCCs, each being a vec of node ids.
    #[must_use]
    pub fn strongly_connected_components(&self) -> Vec<Vec<NodeId>> {
        // Step 1: post-order DFS on original graph.
        let node_count = self.nodes.len();
        let mut visited = HashSet::with_capacity(node_count);
        let mut finish_order = Vec::with_capacity(node_count);
        for &n in self.nodes.keys() {
            if !visited.contains(&n) {
                self.kosaraju_dfs1(n, &mut visited, &mut finish_order);
            }
        }
        // Step 2: DFS on transposed graph in reverse finish order.
        let mut visited2 = HashSet::with_capacity(node_count);
        let mut sccs = Vec::new();
        for n in finish_order.into_iter().rev() {
            if !visited2.contains(&n) {
                let mut scc = Vec::new();
                self.kosaraju_dfs2(n, &mut visited2, &mut scc);
                sccs.push(scc);
            }
        }
        sccs
    }

    fn kosaraju_dfs1(&self, start: NodeId, visited: &mut HashSet<NodeId>, order: &mut Vec<NodeId>) {
        // Iterative post-order DFS to avoid stack overflow on large graphs.
        // Stack entries: (node, iterator index into callees).
        let mut stack: Vec<(NodeId, Vec<NodeId>, usize)> = Vec::new();
        if !visited.insert(start) {
            return;
        }
        let callees = self.callees_of(start);
        stack.push((start, callees, 0));
        loop {
            let done = match stack.last_mut() {
                None => break,
                Some((node, neighbors, idx)) => {
                    if *idx < neighbors.len() {
                        let next = neighbors[*idx];
                        *idx += 1;
                        if visited.insert(next) {
                            let callees = self.callees_of(next);
                            stack.push((next, callees, 0));
                        }
                        false
                    } else {
                        order.push(*node);
                        true
                    }
                }
            };
            if done {
                stack.pop();
            }
        }
    }

    fn kosaraju_dfs2(&self, start: NodeId, visited: &mut HashSet<NodeId>, scc: &mut Vec<NodeId>) {
        // Iterative DFS on the transposed graph to avoid stack overflow.
        let mut stack = vec![start];
        if !visited.insert(start) {
            return;
        }
        while let Some(n) = stack.pop() {
            scc.push(n);
            for caller in self.callers_of(n) {
                if visited.insert(caller) {
                    stack.push(caller);
                }
            }
        }
    }

    /// Find all functions in cycles (mutual recursion).
    #[must_use]
    pub fn recursive_functions(&self) -> HashSet<NodeId> {
        self.strongly_connected_components()
            .into_iter()
            .filter(|scc| {
                scc.len() > 1 || (scc.len() == 1 && self.callees_of(scc[0]).contains(&scc[0]))
            })
            .flatten()
            .collect()
    }

    /// Compute out-degree histogram for the call graph.
    #[must_use]
    pub fn out_degree_histogram(&self) -> HashMap<usize, usize> {
        let mut hist = HashMap::default();
        for &id in self.nodes.keys() {
            let deg = self.call_out_degree(id);
            *hist.entry(deg).or_insert(0) += 1;
        }
        hist
    }

    /// Find "leaf" functions (no callees).
    #[must_use]
    pub fn leaf_functions(&self) -> Vec<NodeId> {
        self.nodes
            .keys()
            .filter(|&&n| {
                self.nodes
                    .get(&n)
                    .is_some_and(|k| matches!(k, NodeKind::Function(_)))
                    && self.call_out_degree(n) == 0
            })
            .copied()
            .collect()
    }

    /// Find "root" functions (no callers).
    #[must_use]
    pub fn root_functions(&self) -> Vec<NodeId> {
        self.nodes
            .keys()
            .filter(|&&n| {
                self.nodes
                    .get(&n)
                    .is_some_and(|k| matches!(k, NodeKind::Function(_)))
                    && self.call_in_degree(n) == 0
            })
            .copied()
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphQuery — simple Cypher-like query DSL
// ─────────────────────────────────────────────────────────────────────────────

/// Predicate used by [`GraphQuery`].
#[derive(Debug, Clone)]
pub enum NodePredicate {
    /// Match any node.
    Any,
    /// Match by node label.
    Label(String),
    /// Match by name (exact).
    Name(String),
    /// Match by name prefix.
    NamePrefix(String),
    /// Match functions that are external.
    IsExternal,
    /// Match functions that are thunks.
    IsThunk,
    /// Match nodes with a given annotation key.
    HasAnnotation(String),
}

impl NodePredicate {
    #[must_use]
    pub fn matches(&self, node: &NodeKind) -> bool {
        match self {
            Self::Any => true,
            Self::Label(l) => node.label() == l.as_str(),
            Self::Name(n) => node.name() == Some(n.as_str()),
            Self::NamePrefix(pfx) => node
                .name()
                .is_some_and(|s| s.starts_with(pfx.as_str())),
            Self::IsExternal => node.as_function().is_some_and(|f| f.is_external),
            Self::IsThunk => node.as_function().is_some_and(|f| f.is_thunk),
            Self::HasAnnotation(key) => node
                .as_function()
                .is_some_and(|f| f.annotations.contains_key(key.as_str())),
        }
    }
}

/// Edge filter for queries.
#[derive(Debug, Clone, Copy)]
pub enum EdgeFilter {
    Any,
    Call,
    DataFlow,
    Type,
}

/// A simple graph query that matches (`source_pred`) --`edge_filter`--> (`target_pred`).
#[derive(Debug, Clone)]
pub struct GraphQuery {
    pub source: NodePredicate,
    pub edge_filter: EdgeFilter,
    pub target: NodePredicate,
    pub limit: Option<usize>,
}

impl GraphQuery {
    #[must_use]
    pub const fn new(source: NodePredicate, edge_filter: EdgeFilter, target: NodePredicate) -> Self {
        Self {
            source,
            edge_filter,
            target,
            limit: None,
        }
    }

    #[must_use]
    pub const fn with_limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Return all node ids whose address falls within `[start, end)`.
    #[must_use]
    pub fn nodes_in_address_range(graph: &AnalysisGraph, start: u64, end: u64) -> Vec<NodeId> {
        graph
            .nodes()
            .filter_map(|(id, node)| {
                let addr = node.address();
                if addr >= start && addr < end {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Execute this query on a graph, returning matching (source, edge, target) triples.
    #[must_use]
    pub fn execute(&self, graph: &AnalysisGraph) -> Vec<(NodeId, EdgeId, NodeId)> {
        let mut results = Vec::new();
        for (&src_id, src_node) in graph.nodes() {
            if !self.source.matches(src_node) {
                continue;
            }
            for edge in graph.edges_from(src_id) {
                let ok = match self.edge_filter {
                    EdgeFilter::Any => true,
                    EdgeFilter::Call => matches!(edge, EdgeKind::Call(_)),
                    EdgeFilter::DataFlow => matches!(edge, EdgeKind::DataFlow(_)),
                    EdgeFilter::Type => matches!(edge, EdgeKind::Type(_)),
                };
                if !ok {
                    continue;
                }
                let tgt_id = edge.to_node();
                if let Some(tgt_node) = graph.node(tgt_id)
                    && self.target.matches(tgt_node) {
                        results.push((src_id, edge.id(), tgt_id));
                        if let Some(lim) = self.limit
                            && results.len() >= lim {
                                return results;
                            }
                    }
            }
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphExport
// ─────────────────────────────────────────────────────────────────────────────

/// Supported export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Dot,
    Json,
    Gephi, // GEXF-like JSON
}

/// Exports the graph to various interchange formats.
pub struct GraphExport;

impl GraphExport {
    /// Export only the call graph to DOT notation.
    pub fn to_dot_callgraph(graph: &AnalysisGraph) -> String {
        let mut s = "digraph callgraph {\n".to_string();
        s.push_str("  rankdir=LR;\n");
        s.push_str("  node [shape=box];\n");
        for (_, node) in graph.nodes() {
            let label = node
                .name().map_or_else(|| format!("{:#x}", node.address()), str::to_owned);
            writeln!(s, "  {} [label=\"{}\"];", node.id().0, label).unwrap();
        }
        for edge in graph.edges.values() {
            if let EdgeKind::Call(c) = edge {
                writeln!(s, "  {} -> {};", c.from.0, c.to.0).unwrap();
            }
        }
        s.push_str("}\n");
        s
    }

    /// Export the full graph to DOT (all edge kinds).
    pub fn to_dot_full(graph: &AnalysisGraph) -> String {
        let mut s = "digraph analysis {\n".to_string();
        s.push_str("  rankdir=LR;\n");
        for (_, node) in graph.nodes() {
            let label = node
                .name().map_or_else(|| format!("{:#x}", node.address()), str::to_owned);
            let color = match node {
                NodeKind::Function(_) => "lightblue",
                NodeKind::Data(_) => "lightyellow",
            };
            writeln!(s, "  {} [label=\"{}\", style=filled, fillcolor=\"{}\"];",
                node.id().0,
                label,
                color
            ).unwrap();
        }
        for edge in graph.edges.values() {
            let (from, to, color) = match edge {
                EdgeKind::Call(c) => (c.from.0, c.to.0, "black"),
                EdgeKind::DataFlow(d) => (d.from.0, d.to.0, "blue"),
                EdgeKind::Type(t) => (t.from.0, t.to.0, "green"),
            };
            writeln!(s, "  {} -> {} [color=\"{}\", label=\"{}\"];",
                from,
                to,
                color,
                edge.label()
            ).unwrap();
        }
        s.push_str("}\n");
        s
    }

    /// Escape a value for use inside a JSON string literal.
    ///
    /// Node *names* come from the analysed binary — demangled symbols and paths
    /// — so quotes and backslashes are ordinary content. (The `label` fields
    /// next to them are `&'static str` kind tags, so they are safe as they are.)
    /// The previous inline escaping substituted `"` but not `\`, which is worse
    /// than none at all for a value ending in a backslash: `a\` became `a\"`,
    /// turning the closing quote into an escaped character and swallowing the
    /// rest of the document. The order matters — backslash first, or the
    /// escapes we add get escaped in turn. `to_gephi_json` escaped nothing.
    ///
    /// RFC 8259 also requires every character below U+0020 to be escaped, so
    /// tabs and stray control bytes are emitted in `\u00XX` form rather than
    /// passed through raw.
    ///
    /// Same job as `json_escape` in `rustre-graph::graph_export`.
    fn json_string(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for c in value.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out
    }

    /// Export the graph as a JSON object with `nodes` and `edges` arrays.
    #[must_use]
    pub fn to_json(graph: &AnalysisGraph) -> String {
        let mut s = "{\n  \"nodes\": [\n".to_string();
        let nodes: Vec<String> = graph
            .nodes()
            .map(|(_, n)| {
                let name = n
                    .name()
                    .map_or("null".to_string(), |v| format!("\"{}\"", Self::json_string(v)));
                format!(
                    "    {{\"id\": {}, \"address\": \"{:#x}\", \"label\": \"{}\", \"name\": {}}}",
                    n.id().0,
                    n.address(),
                    n.label(),
                    name
                )
            })
            .collect();
        s.push_str(&nodes.join(",\n"));
        s.push_str("\n  ],\n  \"edges\": [\n");
        let edges: Vec<String> = graph
            .edges
            .values()
            .map(|e| {
                format!(
                    "    {{\"id\": {}, \"from\": {}, \"to\": {}, \"type\": \"{}\"}}",
                    e.id().0,
                    e.from_node().0,
                    e.to_node().0,
                    e.label()
                )
            })
            .collect();
        s.push_str(&edges.join(",\n"));
        s.push_str("\n  ]\n}\n");
        s
    }

    /// Export the graph in a Gephi-compatible GEXF-like JSON.
    #[must_use]
    pub fn to_gephi_json(graph: &AnalysisGraph) -> String {
        // Minimal Gephi JSON format: { "graph": { "nodes": [...], "edges": [...] } }
        let mut s = "{\n  \"graph\": {\n    \"nodes\": [\n".to_string();
        let nodes: Vec<String> = graph
            .nodes()
            .map(|(_, n)| {
                let label = n
                    .name().map_or_else(|| format!("{:#x}", n.address()), str::to_owned);
                format!(
                    "      {{\"id\": \"{}\", \"label\": \"{}\"}}",
                    n.id().0,
                    Self::json_string(&label)
                )
            })
            .collect();
        s.push_str(&nodes.join(",\n"));
        s.push_str("\n    ],\n    \"edges\": [\n");
        let edges: Vec<String> = graph
            .edges
            .values()
            .enumerate()
            .map(|(i, e)| {
                format!(
                    "      {{\"id\": \"{}\", \"source\": \"{}\", \"target\": \"{}\"}}",
                    i,
                    e.from_node().0,
                    e.to_node().0
                )
            })
            .collect();
        s.push_str(&edges.join(",\n"));
        s.push_str("\n    ]\n  }\n}\n");
        s
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_graph() -> AnalysisGraph {
        AnalysisGraph::new()
    }

    // ── NodeId / EdgeId ───────────────────────────────────────────────────────

    #[test]
    fn node_id_display() {
        assert_eq!(NodeId(5).to_string(), "N5");
    }

    #[test]
    fn edge_id_display() {
        assert_eq!(EdgeId(3).to_string(), "E3");
    }

    // ── AnalysisGraph — node management ──────────────────────────────────────

    #[test]
    fn add_function_returns_stable_id() {
        let mut g = make_graph();
        let id1 = g.add_function(0x1000, Some("main"));
        let id2 = g.add_function(0x1000, Some("main"));
        assert_eq!(id1, id2);
    }

    #[test]
    fn add_function_increments_count() {
        let mut g = make_graph();
        g.add_function(0x1000, Some("a"));
        g.add_function(0x2000, Some("b"));
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn node_at_address() {
        let mut g = make_graph();
        g.add_function(0x0040_1000, Some("main"));
        assert!(g.node_at_address(0x0040_1000).is_some());
        assert!(g.node_at_address(0xDEAD).is_none());
    }

    #[test]
    fn add_data_node() {
        let mut g = make_graph();
        let id = g.add_data(0x5000, Some("global_buf"));
        let node = g.node(id).unwrap();
        assert_eq!(node.label(), "Data");
        assert_eq!(node.name(), Some("global_buf"));
    }

    #[test]
    fn function_node_display_name_fallback() {
        // `0x0040_1234` is a Rust *literal*: the underscores are source-level
        // digit separators and the leading zeros are not part of the value, so
        // at runtime this is simply 0x401234. No formatting can bring back
        // punctuation that never existed — `{:#x}` prints "0x401234".
        let node = FunctionNode::new(NodeId(0), 0x0040_1234);
        assert_eq!(node.display_name(), "fn_0x401234");
    }

    #[test]
    fn function_node_with_name() {
        let node = FunctionNode::new(NodeId(0), 0x0040_1234).with_name("foo");
        assert_eq!(node.display_name(), "foo");
    }

    // ── Edge management ───────────────────────────────────────────────────────

    #[test]
    fn add_call_edge() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, Some("a"));
        let b = g.add_function(0x2000, Some("b"));
        g.add_call_edge(a, b, 0x1010);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn callees_of() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, Some("a"));
        let b = g.add_function(0x2000, Some("b"));
        let c = g.add_function(0x3000, Some("c"));
        g.add_call_edge(a, b, 0x1010);
        g.add_call_edge(a, c, 0x1020);
        let callees = g.callees_of(a);
        assert_eq!(callees.len(), 2);
    }

    #[test]
    fn callers_of() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        let c = g.add_function(0x3000, None);
        g.add_call_edge(a, c, 0x1050);
        g.add_call_edge(b, c, 0x2050);
        assert_eq!(g.callers_of(c).len(), 2);
    }

    #[test]
    fn call_in_out_degree() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        g.add_call_edge(a, b, 0x1000);
        assert_eq!(g.call_out_degree(a), 1);
        assert_eq!(g.call_in_degree(b), 1);
        assert_eq!(g.call_in_degree(a), 0);
    }

    #[test]
    fn add_data_flow_edge() {
        let mut g = make_graph();
        let f = g.add_function(0x1000, None);
        let d = g.add_data(0x5000, Some("buf"));
        g.add_data_flow_edge(f, d, DataFlowKind::Write, Some("buf".into()), Some(0x5000));
        let edges = g.edges_from(f);
        assert_eq!(edges.len(), 1);
        assert!(matches!(edges[0], EdgeKind::DataFlow(_)));
    }

    #[test]
    fn add_type_edge() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        g.add_type_edge(a, b, TypeEdgeKind::Returns);
        assert!(matches!(g.edges_from(a)[0], EdgeKind::Type(_)));
    }

    // ── Traversals ────────────────────────────────────────────────────────────

    #[test]
    fn bfs_single_node() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let visited = g.bfs(a);
        assert_eq!(visited, vec![a]);
    }

    #[test]
    fn bfs_chain() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        let c = g.add_function(0x3000, None);
        g.add_call_edge(a, b, 0x1010);
        g.add_call_edge(b, c, 0x2010);
        let visited = g.bfs(a);
        assert_eq!(visited.len(), 3);
        assert_eq!(visited[0], a);
    }

    #[test]
    fn dfs_chain() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        g.add_call_edge(a, b, 0x1010);
        let visited = g.dfs(a);
        assert_eq!(visited.len(), 2);
    }

    #[test]
    fn bfs_unknown_node_returns_empty() {
        let g = make_graph();
        assert!(g.bfs(NodeId(99999)).is_empty());
    }

    #[test]
    fn reachable_functions() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        let c = g.add_function(0x3000, None);
        let isolated = g.add_function(0x9000, None);
        g.add_call_edge(a, b, 0x1010);
        g.add_call_edge(b, c, 0x2010);
        let reachable = g.reachable_functions(a);
        assert!(reachable.contains(&a));
        assert!(reachable.contains(&b));
        assert!(reachable.contains(&c));
        assert!(!reachable.contains(&isolated));
    }

    // ── SCC ──────────────────────────────────────────────────────────────────

    #[test]
    fn scc_no_cycles() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        g.add_call_edge(a, b, 0x1010);
        let sccs = g.strongly_connected_components();
        // Each node in its own SCC.
        assert!(sccs.iter().all(|scc| scc.len() == 1));
    }

    #[test]
    fn scc_with_cycle() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        g.add_call_edge(a, b, 0x1010);
        g.add_call_edge(b, a, 0x2010); // cycle
        let sccs = g.strongly_connected_components();
        let cycle_scc = sccs.iter().find(|scc| scc.len() == 2);
        assert!(cycle_scc.is_some());
    }

    #[test]
    fn recursive_functions_detected() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, Some("fact"));
        g.add_call_edge(a, a, 0x1050); // self-call
        let rec = g.recursive_functions();
        assert!(rec.contains(&a));
    }

    // ── leaf / root functions ─────────────────────────────────────────────────

    #[test]
    fn leaf_functions() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        g.add_call_edge(a, b, 0x1010);
        let leaves = g.leaf_functions();
        assert!(leaves.contains(&b));
        assert!(!leaves.contains(&a));
    }

    #[test]
    fn root_functions() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        g.add_call_edge(a, b, 0x1010);
        let roots = g.root_functions();
        assert!(roots.contains(&a));
        assert!(!roots.contains(&b));
    }

    // ── out-degree histogram ──────────────────────────────────────────────────

    #[test]
    fn out_degree_histogram() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        let c = g.add_function(0x3000, None);
        g.add_call_edge(a, b, 0x1010);
        g.add_call_edge(a, c, 0x1020);
        let hist = g.out_degree_histogram();
        assert_eq!(hist.get(&2), Some(&1)); // a has degree 2
        assert!(hist.contains_key(&0)); // b and c have degree 0
    }

    // ── GraphQuery ────────────────────────────────────────────────────────────

    #[test]
    fn graph_query_any_to_any() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, Some("main"));
        let b = g.add_function(0x2000, Some("foo"));
        g.add_call_edge(a, b, 0x1010);
        let q = GraphQuery::new(NodePredicate::Any, EdgeFilter::Call, NodePredicate::Any);
        let results = q.execute(&g);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn graph_query_name_match() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, Some("main"));
        let b = g.add_function(0x2000, Some("printf"));
        g.add_call_edge(a, b, 0x1010);
        let q = GraphQuery::new(
            NodePredicate::Name("main".into()),
            EdgeFilter::Call,
            NodePredicate::Any,
        );
        let results = q.execute(&g);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, a);
    }

    #[test]
    fn graph_query_name_prefix() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, Some("std_malloc"));
        let b = g.add_function(0x2000, Some("std_free"));
        g.add_call_edge(a, b, 0x1010);
        let q = GraphQuery::new(
            NodePredicate::NamePrefix("std_".into()),
            EdgeFilter::Any,
            NodePredicate::Any,
        );
        let results = q.execute(&g);
        assert!(!results.is_empty());
    }

    #[test]
    fn graph_query_with_limit() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, None);
        let b = g.add_function(0x2000, None);
        let c = g.add_function(0x3000, None);
        g.add_call_edge(a, b, 0x1010);
        g.add_call_edge(a, c, 0x1020);
        let q =
            GraphQuery::new(NodePredicate::Any, EdgeFilter::Call, NodePredicate::Any).with_limit(1);
        let results = q.execute(&g);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn graph_query_data_flow_filter() {
        let mut g = make_graph();
        let f = g.add_function(0x1000, None);
        let d = g.add_data(0x5000, None);
        let f2 = g.add_function(0x2000, None);
        g.add_call_edge(f, f2, 0x1010);
        g.add_data_flow_edge(f, d, DataFlowKind::Read, None, None);
        let q = GraphQuery::new(NodePredicate::Any, EdgeFilter::DataFlow, NodePredicate::Any);
        let results = q.execute(&g);
        assert_eq!(results.len(), 1);
    }

    // ── GraphExport ───────────────────────────────────────────────────────────

    #[test]
    fn export_dot_callgraph_contains_digraph() {
        let g = make_graph();
        let dot = GraphExport::to_dot_callgraph(&g);
        assert!(dot.contains("digraph"));
    }

    #[test]
    fn export_dot_full_contains_all_nodes() {
        let mut g = make_graph();
        g.add_function(0x1000, Some("main"));
        let dot = GraphExport::to_dot_full(&g);
        assert!(dot.contains("main"));
    }

    #[test]
    fn export_json_valid_structure() {
        let mut g = make_graph();
        g.add_function(0x1000, Some("main"));
        let json = GraphExport::to_json(&g);
        assert!(json.contains("\"nodes\""));
        assert!(json.contains("\"edges\""));
    }

    /// A symbol name that ends in a backslash used to swallow the closing quote:
    /// escaping `"` without escaping `\` first turns `a\` into `a\"`, so the
    /// delimiter becomes an escaped character and the document runs on. The
    /// Gephi exporter escaped nothing at all.
    #[test]
    fn export_json_escapes_backslashes_and_quotes_in_names() {
        let mut g = make_graph();
        g.add_function(0x1000, Some(r"ns::fn<\>\"));
        g.add_function(0x2000, Some("say \"hi\"\tnow"));

        for json in [GraphExport::to_json(&g), GraphExport::to_gephi_json(&g)] {
            // Count the quotes that actually delimit strings: an escaped quote
            // is preceded by an odd number of backslashes and must not count.
            let bytes: Vec<char> = json.chars().collect();
            let mut delimiters = 0usize;
            for (i, &c) in bytes.iter().enumerate() {
                if c != '"' {
                    continue;
                }
                let mut backslashes = 0usize;
                let mut j = i;
                while j > 0 && bytes[j - 1] == '\\' {
                    backslashes += 1;
                    j -= 1;
                }
                if backslashes % 2 == 0 {
                    delimiters += 1;
                }
            }
            assert_eq!(
                delimiters % 2,
                0,
                "unbalanced string delimiters — a value escaped the quoting: {json}"
            );
            // A raw tab inside a string literal is invalid JSON (RFC 8259).
            assert!(!json.contains('\t'), "raw control character in output: {json}");
        }
    }

    #[test]
    fn export_gephi_json_structure() {
        let g = make_graph();
        let gephi = GraphExport::to_gephi_json(&g);
        assert!(gephi.contains("\"graph\""));
        assert!(gephi.contains("\"nodes\""));
    }

    #[test]
    fn export_dot_includes_edge() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, Some("a"));
        let b = g.add_function(0x2000, Some("b"));
        g.add_call_edge(a, b, 0x1010);
        let dot = GraphExport::to_dot_callgraph(&g);
        assert!(dot.contains("->"));
    }

    // ── DataFlowKind / TypeEdgeKind display ───────────────────────────────────

    #[test]
    fn data_flow_kind_display() {
        assert_eq!(DataFlowKind::Read.to_string(), "read");
        assert_eq!(DataFlowKind::Write.to_string(), "write");
        assert_eq!(DataFlowKind::ReadWrite.to_string(), "rw");
        assert_eq!(DataFlowKind::Address.to_string(), "addr");
    }

    #[test]
    fn type_edge_kind_display() {
        assert_eq!(TypeEdgeKind::Returns.to_string(), "returns");
        assert_eq!(TypeEdgeKind::TakesParam.to_string(), "takes_param");
        assert_eq!(TypeEdgeKind::Inherits.to_string(), "inherits");
    }

    // ── EdgeKind helpers ──────────────────────────────────────────────────────

    #[test]
    fn edge_kind_label() {
        let call = EdgeKind::Call(CallEdge::new(EdgeId(0), NodeId(1), NodeId(2), 0x1000));
        assert_eq!(call.label(), "CALL");
        let df = EdgeKind::DataFlow(DataFlowEdge {
            id: EdgeId(1),
            from: NodeId(1),
            to: NodeId(2),
            kind: DataFlowKind::Read,
            variable: None,
            address: None,
        });
        assert_eq!(df.label(), "DATA_FLOW");
    }

    #[test]
    fn call_edge_properties() {
        let e = CallEdge::new(EdgeId(0), NodeId(1), NodeId(2), 0x1234);
        assert_eq!(e.call_site, 0x1234);
        assert!(!e.is_indirect);
        assert!(!e.is_tail_call);
        assert_eq!(e.weight, 1.0);
    }

    // ── Extra coverage tests ──────────────────────────────────────────────────

    #[test]
    fn analysis_graph_node_count_after_multiple_adds() {
        let mut g = make_graph();
        for i in 0..10u64 {
            g.add_function(0x1000 + i * 0x100, Some(&format!("fn_{i}")));
        }
        assert_eq!(g.node_count(), 10);
    }

    #[test]
    fn analysis_graph_callee_lookup() {
        let mut g = make_graph();
        let caller = g.add_function(0x1000, Some("caller"));
        let callee = g.add_function(0x2000, Some("callee"));
        g.add_call_edge(caller, callee, 0x1010);
        let callees = g.callees_of(caller);
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0], callee);
    }

    #[test]
    fn analysis_graph_caller_lookup() {
        let mut g = make_graph();
        let caller = g.add_function(0x1000, Some("caller"));
        let callee = g.add_function(0x2000, Some("callee"));
        g.add_call_edge(caller, callee, 0x1010);
        let callers = g.callers_of(callee);
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0], caller);
    }

    #[test]
    fn graph_export_json_valid() {
        let mut g = make_graph();
        let a = g.add_function(0x1000, Some("alpha"));
        let b = g.add_function(0x2000, Some("beta"));
        g.add_call_edge(a, b, 0x1050);
        let json = GraphExport::to_json(&g);
        assert!(json.contains("alpha"));
        assert!(json.contains("beta"));
    }

    #[test]
    fn graph_query_nodes_by_address_range() {
        let mut g = make_graph();
        g.add_function(0x1000, Some("f1"));
        g.add_function(0x2000, Some("f2"));
        g.add_function(0x3000, Some("f3"));
        let results = GraphQuery::nodes_in_address_range(&g, 0x1000, 0x2500);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn function_node_is_entry_flag() {
        let mut g = make_graph();
        let id = g.add_function(0x0040_0000, Some("entry_point"));
        if let Some(node) = g.get_function_node(id) {
            // Default should not be entry
            assert!(!node.is_entry);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphMetrics — centrality and connectivity statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Degree-centrality and basic connectivity metrics for a call graph.
#[derive(Debug, Clone)]
pub struct GraphMetrics {
    /// In-degree (number of callers) for each node.
    pub in_degree: std::collections::HashMap<NodeId, usize>,
    /// Out-degree (number of callees) for each node.
    pub out_degree: std::collections::HashMap<NodeId, usize>,
    /// Sink nodes (no callees).
    pub sinks: Vec<NodeId>,
    /// Source nodes (no callers).
    pub sources: Vec<NodeId>,
    /// Total number of nodes.
    pub node_count: usize,
    /// Total number of call edges.
    pub edge_count: usize,
}

impl GraphMetrics {
    /// Compute metrics for the given `AnalysisGraph`.
    #[must_use]
    pub fn compute(g: &AnalysisGraph) -> Self {
        let mut in_degree: std::collections::HashMap<NodeId, usize> =
            std::collections::HashMap::default();
        let mut out_degree: std::collections::HashMap<NodeId, usize> =
            std::collections::HashMap::default();

        // Initialise all nodes at degree 0.
        for &id in g.nodes.keys() {
            in_degree.entry(id).or_insert(0);
            out_degree.entry(id).or_insert(0);
        }

        let mut edge_count = 0usize;
        for edge in g.edges.values() {
            if let EdgeKind::Call(ce) = edge {
                *out_degree.entry(ce.from).or_insert(0) += 1;
                *in_degree.entry(ce.to).or_insert(0) += 1;
                edge_count += 1;
            }
        }

        let sinks: Vec<NodeId> = out_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();
        let sources: Vec<NodeId> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();

        Self {
            in_degree,
            out_degree,
            sinks,
            sources,
            node_count: g.nodes.len(),
            edge_count,
        }
    }

    /// Average out-degree (fan-out).
    #[must_use]
    pub fn avg_out_degree(&self) -> f64 {
        if self.node_count == 0 {
            return 0.0;
        }
        let total: usize = self.out_degree.values().sum();
        total as f64 / self.node_count as f64
    }

    /// Average in-degree (fan-in).
    #[must_use]
    pub fn avg_in_degree(&self) -> f64 {
        if self.node_count == 0 {
            return 0.0;
        }
        let total: usize = self.in_degree.values().sum();
        total as f64 / self.node_count as f64
    }

    /// The node with the highest in-degree (most-called function).
    #[must_use]
    pub fn hottest_callee(&self) -> Option<NodeId> {
        self.in_degree
            .iter()
            .max_by_key(|&(_, &d)| d)
            .map(|(&id, _)| id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SCCFinder — strongly connected components (Kosaraju's algorithm)
// ─────────────────────────────────────────────────────────────────────────────

/// Finds strongly connected components (SCCs) in the call graph.
///
/// Each SCC with more than one node indicates a (mutual) recursion group.
pub struct SCCFinder;

impl SCCFinder {
    /// Compute SCCs using Kosaraju's two-pass DFS.
    ///
    /// Returns a list of components; each component is a list of `NodeId`s.
    /// Components with a single node and no self-edge are non-recursive.
    #[must_use]
    pub fn compute(g: &AnalysisGraph) -> Vec<Vec<NodeId>> {
        let nodes: Vec<NodeId> = g.nodes.keys().copied().collect();
        if nodes.is_empty() {
            return vec![];
        }

        // Build adjacency from call edges.
        let mut adj: std::collections::HashMap<NodeId, Vec<NodeId>> =
            std::collections::HashMap::default();
        let mut radj: std::collections::HashMap<NodeId, Vec<NodeId>> =
            std::collections::HashMap::default();
        for &id in &nodes {
            adj.entry(id).or_default();
            radj.entry(id).or_default();
        }
        for edge in g.edges.values() {
            if let EdgeKind::Call(ce) = edge {
                adj.entry(ce.from).or_default().push(ce.to);
                radj.entry(ce.to).or_default().push(ce.from);
            }
        }

        // Pass 1: DFS on original graph, push in finish order.
        let mut visited: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
        let mut finish_order: Vec<NodeId> = Vec::new();
        for &start in &nodes {
            if !visited.contains(&start) {
                Self::dfs_finish(&adj, start, &mut visited, &mut finish_order);
            }
        }

        // Pass 2: DFS on reversed graph in reverse finish order → each DFS tree = one SCC.
        let mut visited2: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
        let mut sccs: Vec<Vec<NodeId>> = Vec::new();
        for &start in finish_order.iter().rev() {
            if !visited2.contains(&start) {
                let mut component = Vec::new();
                Self::dfs_collect(&radj, start, &mut visited2, &mut component);
                sccs.push(component);
            }
        }
        sccs
    }

    fn dfs_finish(
        adj: &std::collections::HashMap<NodeId, Vec<NodeId>>,
        start: NodeId,
        visited: &mut std::collections::HashSet<NodeId>,
        finish_order: &mut Vec<NodeId>,
    ) {
        let mut stack: Vec<(NodeId, usize)> = vec![(start, 0)];
        visited.insert(start);
        while let Some((node, idx)) = stack.last_mut() {
            let node = *node;
            let neighbors: &[NodeId] = adj.get(&node).map_or(&[], |v| v.as_slice());
            if *idx < neighbors.len() {
                let next = neighbors[*idx];
                *idx += 1;
                if visited.insert(next) {
                    stack.push((next, 0));
                }
            } else {
                stack.pop();
                finish_order.push(node);
            }
        }
    }

    fn dfs_collect(
        radj: &std::collections::HashMap<NodeId, Vec<NodeId>>,
        start: NodeId,
        visited: &mut std::collections::HashSet<NodeId>,
        component: &mut Vec<NodeId>,
    ) {
        let mut stack = vec![start];
        visited.insert(start);
        while let Some(node) = stack.pop() {
            component.push(node);
            if let Some(neighbors) = radj.get(&node) {
                for &next in neighbors {
                    if visited.insert(next) {
                        stack.push(next);
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests for GraphMetrics and SCCFinder
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod extended_graph_tests {
    use super::*;

    fn graph_with_calls() -> AnalysisGraph {
        let mut g = AnalysisGraph::new();
        let a = g.add_function(0x1000, Some("a"));
        let b = g.add_function(0x2000, Some("b"));
        let c = g.add_function(0x3000, Some("c"));
        g.add_call_edge(a, b, 0x1010);
        g.add_call_edge(a, c, 0x1020);
        g.add_call_edge(b, c, 0x2010);
        g
    }

    #[test]
    fn metrics_node_and_edge_count() {
        let g = graph_with_calls();
        let m = GraphMetrics::compute(&g);
        assert_eq!(m.node_count, 3);
        assert_eq!(m.edge_count, 3);
    }

    #[test]
    fn metrics_sinks_and_sources() {
        let g = graph_with_calls();
        let m = GraphMetrics::compute(&g);
        // c has no callees → sink; a has no callers → source.
        assert!(!m.sinks.is_empty());
        assert!(!m.sources.is_empty());
    }

    #[test]
    fn metrics_avg_out_degree() {
        let g = graph_with_calls();
        let m = GraphMetrics::compute(&g);
        // a:2, b:1, c:0 → avg = 1.0
        assert!((m.avg_out_degree() - 1.0).abs() < 0.01);
    }

    #[test]
    fn metrics_avg_in_degree() {
        let g = graph_with_calls();
        let m = GraphMetrics::compute(&g);
        // a:0, b:1, c:2 → avg = 1.0
        assert!((m.avg_in_degree() - 1.0).abs() < 0.01);
    }

    #[test]
    fn metrics_hottest_callee() {
        let g = graph_with_calls();
        let m = GraphMetrics::compute(&g);
        // c is called by both a and b → in_degree=2.
        let hot = m.hottest_callee().unwrap();
        assert_eq!(m.in_degree[&hot], 2);
    }

    #[test]
    fn scc_no_cycles() {
        let g = graph_with_calls();
        let sccs = SCCFinder::compute(&g);
        // No cycles → each SCC has exactly one node.
        assert_eq!(sccs.len(), 3);
        for scc in &sccs {
            assert_eq!(scc.len(), 1);
        }
    }

    #[test]
    fn scc_with_cycle() {
        let mut g = AnalysisGraph::new();
        let a = g.add_function(0x1000, Some("a"));
        let b = g.add_function(0x2000, Some("b"));
        g.add_call_edge(a, b, 0x1010);
        g.add_call_edge(b, a, 0x2010); // back-edge
        let sccs = SCCFinder::compute(&g);
        // Should find one SCC with both a and b.
        let big_scc: Vec<_> = sccs.iter().filter(|s| s.len() > 1).collect();
        assert_eq!(big_scc.len(), 1);
        assert_eq!(big_scc[0].len(), 2);
    }

    #[test]
    fn scc_self_loop() {
        let mut g = AnalysisGraph::new();
        let a = g.add_function(0x1000, Some("recursive"));
        g.add_call_edge(a, a, 0x1010); // self-call
        let sccs = SCCFinder::compute(&g);
        // Self-loop → one SCC containing just `a`.
        assert_eq!(sccs.len(), 1);
    }

    #[test]
    fn scc_empty_graph() {
        let g = AnalysisGraph::new();
        let sccs = SCCFinder::compute(&g);
        assert!(sccs.is_empty());
    }
}
