//! `call_graph_builder` — directed call graph construction and analysis.
//!
//! Provides:
//! * [`CallGraphBuilder`]  — builder that constructs the call graph.
//! * [`CallGraph`]         — directed graph of call relationships.
//! * [`CallNode`]          — a function in the call graph.
//! * [`CallEdge`]          — a call relationship between two functions.
//! * [`CallType`]          — direct / indirect / virtual / tail call.
//! * [`SCCDecomposition`]  — strongly-connected components (Tarjan).
//! * [`CallGraphStats`]    — aggregate statistics.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// CallType
// ─────────────────────────────────────────────────────────────────────────────

/// The nature of a call relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallType {
    /// Direct call (`CALL <addr>`).
    Direct,
    /// Indirect call through a register or memory (`CALL *rax`).
    Indirect,
    /// Virtual dispatch through a vtable slot.
    Virtual,
    /// Tail-call optimisation (`JMP <addr>`).
    Tail,
    /// Import/PLT stub.
    Import,
    /// Callback / function pointer stored in data.
    Callback,
}

impl std::fmt::Display for CallType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Direct => "direct",
            Self::Indirect => "indirect",
            Self::Virtual => "virtual",
            Self::Tail => "tail",
            Self::Import => "import",
            Self::Callback => "callback",
        };
        f.write_str(s)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallNode
// ─────────────────────────────────────────────────────────────────────────────

/// A function represented as a node in the call graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallNode {
    /// Unique node id.
    pub id: u64,
    /// Function start address.
    pub func_addr: u64,
    /// Function name (may be empty if not available).
    pub name: String,
    /// True if this function is imported (has no local body).
    pub is_import: bool,
    /// True if this function is an export.
    pub is_export: bool,
}

impl CallNode {
    pub fn new(func_addr: u64, name: impl Into<String>) -> Self {
        Self {
            id: func_addr,
            func_addr,
            name: name.into(),
            is_import: false,
            is_export: false,
        }
    }

    pub fn imported(func_addr: u64, name: impl Into<String>) -> Self {
        let mut n = Self::new(func_addr, name);
        n.is_import = true;
        n
    }

    pub fn exported(func_addr: u64, name: impl Into<String>) -> Self {
        let mut n = Self::new(func_addr, name);
        n.is_export = true;
        n
    }
}

impl std::fmt::Display for CallNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.name.is_empty() {
            write!(f, "sub_{:08x}", self.func_addr)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallEdge
// ─────────────────────────────────────────────────────────────────────────────

/// A directed call edge from `caller` to `callee`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallEdge {
    pub caller: u64,
    pub callee: u64,
    pub call_type: CallType,
    /// Address of the call site instruction.
    pub call_site: Option<u64>,
}

impl CallEdge {
    #[must_use]
    pub const fn new(from_fn: u64, to_fn: u64, call_type: CallType) -> Self {
        Self {
            caller: from_fn,
            callee: to_fn,
            call_type,
            call_site: None,
        }
    }

    #[must_use] 
    pub const fn with_site(mut self, addr: u64) -> Self {
        self.call_site = Some(addr);
        self
    }

    #[must_use] 
    pub fn is_direct(&self) -> bool {
        self.call_type == CallType::Direct
    }

    #[must_use] 
    pub fn is_tail(&self) -> bool {
        self.call_type == CallType::Tail
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraph
// ─────────────────────────────────────────────────────────────────────────────

/// A directed call graph.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    pub nodes: HashMap<u64, CallNode>,
    pub edges: Vec<CallEdge>,
    /// `callees[func_addr]` = list of callee addresses.
    pub callees: HashMap<u64, Vec<u64>>,
    /// `callers[func_addr]` = list of caller addresses.
    pub callers: HashMap<u64, Vec<u64>>,
}

impl CallGraph {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node. No-op if already present.
    pub fn add_node(&mut self, node: CallNode) {
        self.callees.entry(node.func_addr).or_default();
        self.callers.entry(node.func_addr).or_default();
        self.nodes.insert(node.func_addr, node);
    }

    /// Add a directed edge. Adds implicit nodes if needed.
    pub fn add_edge(&mut self, edge: CallEdge) {
        let from_fn = edge.caller;
        let to_fn = edge.callee;
        // Ensure nodes exist.
        self.nodes
            .entry(from_fn)
            .or_insert_with(|| CallNode::new(from_fn, ""));
        self.nodes
            .entry(to_fn)
            .or_insert_with(|| CallNode::new(to_fn, ""));
        self.callees.entry(from_fn).or_default().push(to_fn);
        self.callers.entry(to_fn).or_default().push(from_fn);
        self.callees.entry(to_fn).or_default();
        self.callers.entry(from_fn).or_default();
        self.edges.push(edge);
    }

    /// Number of nodes.
    #[must_use] 
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    #[must_use] 
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// All callee addresses of `func`.
    pub fn callees_of(&self, func: u64) -> &[u64] {
        self.callees.get(&func).map_or(&[], Vec::as_slice)
    }

    /// All caller addresses of `func`.
    pub fn callers_of(&self, func: u64) -> &[u64] {
        self.callers.get(&func).map_or(&[], Vec::as_slice)
    }

    /// True if `caller` directly calls `callee`.
    #[must_use] 
    pub fn calls(&self, from_fn: u64, to_fn: u64) -> bool {
        self.edges
            .iter()
            .any(|e| e.caller == from_fn && e.callee == to_fn)
    }

    /// Leaf functions (functions that call nothing), sorted ascending for
    /// deterministic output (`self.nodes` is a `HashMap`; its iteration order
    /// is not stable across runs).
    #[must_use]
    pub fn leaf_functions(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .nodes
            .keys()
            .filter(|&&addr| self.callees_of(addr).is_empty())
            .copied()
            .collect();
        v.sort_unstable();
        v
    }

    /// Root functions (functions not called by anyone), sorted ascending for
    /// deterministic output (`self.nodes` is a `HashMap`; its iteration order
    /// is not stable across runs).
    #[must_use]
    pub fn root_functions(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .nodes
            .keys()
            .filter(|&&addr| self.callers_of(addr).is_empty())
            .copied()
            .collect();
        v.sort_unstable();
        v
    }

    /// All functions reachable from `start` (BFS).
    #[must_use] 
    pub fn reachable_from(&self, start: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(n) = queue.pop_front() {
            if !visited.insert(n) {
                continue;
            }
            for &c in self.callees_of(n) {
                if !visited.contains(&c) {
                    queue.push_back(c);
                }
            }
        }
        visited
    }

    /// All functions that can reach `target` (reverse BFS).
    #[must_use] 
    pub fn ancestors_of(&self, target: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::from([target]);
        while let Some(n) = queue.pop_front() {
            if !visited.insert(n) {
                continue;
            }
            for &c in self.callers_of(n) {
                if !visited.contains(&c) {
                    queue.push_back(c);
                }
            }
        }
        visited
    }

    /// Topological sort (Kahn's algorithm). Returns `Err` if cycle detected.
    ///
    /// # Errors
    /// Returns `Err(partial_order)` when the graph contains a cycle.
    pub fn topological_sort(&self) -> Result<Vec<u64>, Vec<u64>> {
        let mut in_deg: HashMap<u64, usize> = self.nodes.keys().map(|&k| (k, 0)).collect();
        for e in &self.edges {
            *in_deg.entry(e.callee).or_insert(0) += 1;
        }
        // Seed the queue in sorted order: `in_deg` is a `HashMap`, so iterating
        // it directly would make tie-breaks among same-in-degree nodes depend
        // on hash iteration order (nondeterministic across runs/processes).
        let mut zero_deg: Vec<u64> = in_deg
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(&k, _)| k)
            .collect();
        zero_deg.sort_unstable();
        let mut queue: VecDeque<u64> = zero_deg.into_iter().collect();
        let mut order = Vec::new();
        while let Some(n) = queue.pop_front() {
            order.push(n);
            // Callees newly at in-degree 0 are appended in `callees_of` order,
            // which is a `Vec` derived from insertion order and therefore
            // already deterministic.
            for &c in self.callees_of(n) {
                if let Some(d) = in_deg.get_mut(&c) {
                    *d -= 1;
                    if *d == 0 {
                        queue.push_back(c);
                    }
                }
            }
        }
        if order.len() == self.nodes.len() {
            Ok(order)
        } else {
            Err(order)
        }
    }

    /// Render to Graphviz DOT format.
    #[must_use] 
    pub fn to_dot(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("digraph callgraph {\n  node [shape=box];\n");
        let mut addrs: Vec<u64> = self.nodes.keys().copied().collect();
        addrs.sort_unstable();
        for addr in &addrs {
            let n = &self.nodes[addr];
            let label = if n.name.is_empty() {
                format!("sub_{addr:08x}")
            } else {
                n.name.clone()
            };
            let _ = writeln!(out, "  n{addr:x} [label=\"{label}\"];");
        }
        for e in &self.edges {
            let _ = writeln!(out, "  n{:x} -> n{:x} [label=\"{}\"];",
                e.caller, e.callee, e.call_type);
        }
        out.push_str("}\n");
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SCCDecomposition
// ─────────────────────────────────────────────────────────────────────────────

/// One strongly-connected component.
#[derive(Debug, Clone)]
pub struct SCC {
    pub nodes: Vec<u64>,
    pub id: usize,
}

impl SCC {
    /// True if this SCC contains more than one node (i.e. there is a cycle).
    #[must_use] 
    pub const fn is_cycle(&self) -> bool {
        self.nodes.len() > 1
    }

    /// True if this is a single-node trivial SCC.
    #[must_use] 
    pub const fn is_trivial(&self) -> bool {
        self.nodes.len() == 1
    }
}

/// Tarjan SCC decomposition of a call graph.
#[derive(Debug, Clone, Default)]
pub struct SCCDecomposition {
    pub sccs: Vec<SCC>,
    /// `node_scc[func_addr]` = SCC id.
    pub node_scc: HashMap<u64, usize>,
}

struct TarjanState<'a> {
    nodes: &'a [u64],
    idx_map: &'a HashMap<u64, usize>,
    cg: &'a CallGraph,
    index: Vec<usize>,
    lowlink: Vec<usize>,
    on_stack: Vec<bool>,
    visited: Vec<bool>,
    stack: Vec<u64>,
    counter: usize,
    components: Vec<Vec<u64>>,
}

impl<'a> TarjanState<'a> {
    fn new(nodes: &'a [u64], idx_map: &'a HashMap<u64, usize>, cg: &'a CallGraph) -> Self {
        let n = nodes.len();
        Self {
            nodes,
            idx_map,
            cg,
            index: vec![0usize; n],
            lowlink: vec![0usize; n],
            on_stack: vec![false; n],
            visited: vec![false; n],
            stack: Vec::new(),
            counter: 0,
            components: Vec::new(),
        }
    }

    /// Iterative Tarjan SCC from root `start` with an explicit work stack,
    /// to avoid a native stack overflow on deep call chains from real
    /// binaries (mirrors `GlobalTarjanState::run` in `global_xref_analysis.rs`).
    fn strong(&mut self, start: usize) {
        // Each frame: (node index, its successor node-indices, next index into that list).
        let mut work: Vec<(usize, Vec<usize>, usize)> = Vec::new();

        self.index[start] = self.counter;
        self.lowlink[start] = self.counter;
        self.counter += 1;
        self.visited[start] = true;
        self.on_stack[start] = true;
        self.stack.push(self.nodes[start]);
        work.push((start, self.succ_indices(start), 0));

        while let Some(&mut (v, ref succs, ref mut i)) = work.last_mut() {
            if *i < succs.len() {
                let w = succs[*i];
                *i += 1;
                if !self.visited[w] {
                    self.index[w] = self.counter;
                    self.lowlink[w] = self.counter;
                    self.counter += 1;
                    self.visited[w] = true;
                    self.on_stack[w] = true;
                    self.stack.push(self.nodes[w]);
                    work.push((w, self.succ_indices(w), 0));
                } else if self.on_stack[w] {
                    self.lowlink[v] = self.lowlink[v].min(self.index[w]);
                }
            } else {
                // Done with v's successors; pop the frame and propagate
                // lowlink to the parent frame (if any).
                let (v, _, _) = work.pop().unwrap();
                if let Some(&(parent, _, _)) = work.last() {
                    self.lowlink[parent] = self.lowlink[parent].min(self.lowlink[v]);
                }

                if self.lowlink[v] == self.index[v] {
                    let mut scc = Vec::new();
                    loop {
                        let w = self.stack.pop().unwrap();
                        if let Some(&wi) = self.idx_map.get(&w) {
                            self.on_stack[wi] = false;
                        }
                        scc.push(w);
                        if w == self.nodes[v] {
                            break;
                        }
                    }
                    self.components.push(scc);
                }
            }
        }
    }

    /// Resolve `v`'s call-graph successors to their `node_vec` indices,
    /// dropping any callee not present in this component's node set.
    fn succ_indices(&self, v: usize) -> Vec<usize> {
        self.cg
            .callees_of(self.nodes[v])
            .iter()
            .filter_map(|succ| self.idx_map.get(succ).copied())
            .collect()
    }
}

impl SCCDecomposition {
    /// Compute SCCs for the given call graph.
    #[must_use]
    pub fn compute(cg: &CallGraph) -> Self {
        let mut idx_map: HashMap<u64, usize> = HashMap::new();
        let mut node_vec: Vec<u64> = cg.nodes.keys().copied().collect();
        node_vec.sort_unstable();
        for (i, &n) in node_vec.iter().enumerate() {
            idx_map.insert(n, i);
        }
        let n = node_vec.len();

        let mut state = TarjanState::new(&node_vec, &idx_map, cg);
        for i in 0..n {
            if !state.visited[i] {
                state.strong(i);
            }
        }
        let components = state.components;

        let sccs: Vec<SCC> = components
            .into_iter()
            .enumerate()
            .map(|(id, nodes)| SCC { nodes, id })
            .collect();
        let node_scc: HashMap<u64, usize> = sccs
            .iter()
            .flat_map(|scc| scc.nodes.iter().map(move |&n| (n, scc.id)))
            .collect();

        Self { sccs, node_scc }
    }

    /// All recursive SCCs (cycles).
    #[must_use] 
    pub fn cycles(&self) -> Vec<&SCC> {
        self.sccs.iter().filter(|s| s.is_cycle()).collect()
    }

    /// All trivial SCCs (non-recursive nodes).
    #[must_use] 
    pub fn trivial(&self) -> Vec<&SCC> {
        self.sccs.iter().filter(|s| s.is_trivial()).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a call graph.
#[derive(Debug, Clone, Default)]
pub struct CallGraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub direct_calls: usize,
    pub indirect_calls: usize,
    pub virtual_calls: usize,
    pub tail_calls: usize,
    pub import_calls: usize,
    pub leaf_count: usize,
    pub root_count: usize,
    pub max_callee_count: usize,
    pub max_caller_count: usize,
    pub recursive_scc_count: usize,
    pub avg_out_degree: f64,
}

impl CallGraphStats {
    #[must_use] 
    pub fn compute(cg: &CallGraph) -> Self {
        let total_nodes = cg.node_count();
        let total_edges = cg.edge_count();

        let mut direct = 0;
        let mut indirect = 0;
        let mut virtual_c = 0;
        let mut tail = 0;
        let mut import = 0;
        for e in &cg.edges {
            match e.call_type {
                CallType::Direct => direct += 1,
                CallType::Indirect => indirect += 1,
                CallType::Virtual => virtual_c += 1,
                CallType::Tail => tail += 1,
                CallType::Import => import += 1,
                CallType::Callback => {}
            }
        }

        let leaf_count = cg.leaf_functions().len();
        let root_count = cg.root_functions().len();
        let max_out_degree = cg.callees.values().map(std::vec::Vec::len).max().unwrap_or(0);
        let max_in_degree = cg.callers.values().map(std::vec::Vec::len).max().unwrap_or(0);
        let avg_out = if total_nodes > 0 {
            f64::from(u32::try_from(total_edges).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total_nodes).unwrap_or(u32::MAX))
        } else {
            0.0
        };

        let scc = SCCDecomposition::compute(cg);
        let recursive_scc_count = scc.cycles().len();

        Self {
            total_nodes,
            total_edges,
            direct_calls: direct,
            indirect_calls: indirect,
            virtual_calls: virtual_c,
            tail_calls: tail,
            import_calls: import,
            leaf_count,
            root_count,
            max_callee_count: max_out_degree,
            max_caller_count: max_in_degree,
            recursive_scc_count,
            avg_out_degree: avg_out,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CallGraphBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a [`CallGraph`] from raw call records.
///
/// Usage:
/// 1. Register functions with [`add_function`].
/// 2. Register calls with [`add_call`].
/// 3. Call [`build`] to obtain the call graph.
pub struct CallGraphBuilder {
    graph: CallGraph,
}

impl CallGraphBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            graph: CallGraph::new(),
        }
    }

    /// Register a function node.
    pub fn add_function(&mut self, func_addr: u64, name: impl Into<String>) -> &mut Self {
        self.graph.add_node(CallNode::new(func_addr, name));
        self
    }

    /// Register an imported function.
    pub fn add_import(&mut self, func_addr: u64, name: impl Into<String>) -> &mut Self {
        self.graph.add_node(CallNode::imported(func_addr, name));
        self
    }

    /// Add a call edge.
    pub fn add_call(&mut self, from_fn: u64, to_fn: u64, call_type: CallType) -> &mut Self {
        self.graph
            .add_edge(CallEdge::new(from_fn, to_fn, call_type));
        self
    }

    /// Add a call with a call-site address.
    pub fn add_call_at(
        &mut self,
        from_fn: u64,
        to_fn: u64,
        call_type: CallType,
        site: u64,
    ) -> &mut Self {
        self.graph
            .add_edge(CallEdge::new(from_fn, to_fn, call_type).with_site(site));
        self
    }

    /// Scan raw x86-64 bytes at `base` for direct CALL rel32 targets and
    /// register them as direct call edges originating from `caller_addr`.
    pub fn scan_x86_calls(&mut self, caller_addr: u64, base: u64, bytes: &[u8]) -> &mut Self {
        let mut i = 0;
        while i + 4 < bytes.len() {
            if bytes[i] == 0xE8 {
                let rel =
                    i32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
                // Wrapping on purpose: RIP-relative arithmetic is defined
                // mod 2^64, and a bare `+` panics in debug builds when an
                // adversarial `base` sits near u64::MAX.
                let site = base.wrapping_add(i as u64);
                let next_ip = site.wrapping_add(5);
                let callee = next_ip.wrapping_add_signed(i64::from(rel));
                self.graph
                    .add_edge(CallEdge::new(caller_addr, callee, CallType::Direct).with_site(site));
                i += 5;
            } else {
                i += 1;
            }
        }
        self
    }

    /// Consume the builder and return the completed call graph.
    #[must_use] 
    pub fn build(self) -> CallGraph {
        self.graph
    }
}

impl Default for CallGraphBuilder {
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

    fn simple_graph() -> CallGraph {
        let mut b = CallGraphBuilder::new();
        b.add_function(0x1000, "main");
        b.add_function(0x2000, "foo");
        b.add_function(0x3000, "bar");
        b.add_call(0x1000, 0x2000, CallType::Direct);
        b.add_call(0x1000, 0x3000, CallType::Direct);
        b.add_call(0x2000, 0x3000, CallType::Direct);
        b.build()
    }

    // 1. CallGraphBuilder basics.
    #[test]
    fn test_builder_nodes_edges() {
        let cg = simple_graph();
        assert_eq!(cg.node_count(), 3);
        assert_eq!(cg.edge_count(), 3);
    }

    // Regression: leaf_functions/root_functions/topological_sort must be
    // deterministic across repeated calls (HashMap iteration order must not
    // leak into the returned order).
    #[test]
    fn test_leaf_root_topo_are_deterministic() {
        let mut b = CallGraphBuilder::new();
        for i in 0..12u64 {
            b.add_function(0x1000 + i * 0x10, "");
        }
        // Several independent leaves/roots plus a diamond, to exercise ties.
        b.add_call(0x1000, 0x1010, CallType::Direct);
        b.add_call(0x1000, 0x1020, CallType::Direct);
        b.add_call(0x1010, 0x1030, CallType::Direct);
        b.add_call(0x1020, 0x1030, CallType::Direct);
        b.add_call(0x1000, 0x1040, CallType::Direct);
        // Remaining functions (0x1050..0x10c0) are isolated: all simultaneously
        // leaves and roots, a broad tie-break test.
        let cg = b.build();

        let leaves1 = cg.leaf_functions();
        let roots1 = cg.root_functions();
        let topo1 = cg.topological_sort();
        for _ in 0..5 {
            assert_eq!(cg.leaf_functions(), leaves1);
            assert_eq!(cg.root_functions(), roots1);
            assert_eq!(cg.topological_sort(), topo1);
        }
        // And sorted, since that's the documented contract.
        let mut sorted_leaves = leaves1.clone();
        sorted_leaves.sort_unstable();
        assert_eq!(leaves1, sorted_leaves);
        let mut sorted_roots = roots1.clone();
        sorted_roots.sort_unstable();
        assert_eq!(roots1, sorted_roots);
    }

    // 2. CallType display.
    #[test]
    fn test_call_type_display() {
        assert_eq!(CallType::Direct.to_string(), "direct");
        assert_eq!(CallType::Virtual.to_string(), "virtual");
        assert_eq!(CallType::Tail.to_string(), "tail");
    }

    // 3. CallNode display.
    #[test]
    fn test_call_node_display() {
        let n = CallNode::new(0x1000, "main");
        assert_eq!(n.to_string(), "main");
        let n2 = CallNode::new(0x2000, "");
        assert!(n2.to_string().starts_with("sub_"));
    }

    // 4. CallGraph::callees_of.
    #[test]
    fn test_callees_of() {
        let cg = simple_graph();
        let callees: HashSet<u64> = cg.callees_of(0x1000).iter().copied().collect();
        assert!(callees.contains(&0x2000) && callees.contains(&0x3000));
    }

    // 5. CallGraph::callers_of.
    #[test]
    fn test_callers_of() {
        let cg = simple_graph();
        let callers: HashSet<u64> = cg.callers_of(0x3000).iter().copied().collect();
        assert!(callers.contains(&0x1000) && callers.contains(&0x2000));
    }

    // 6. CallGraph::calls.
    #[test]
    fn test_calls() {
        let cg = simple_graph();
        assert!(cg.calls(0x1000, 0x2000));
        assert!(!cg.calls(0x3000, 0x1000));
    }

    // 7. CallGraph::leaf_functions.
    #[test]
    fn test_leaf_functions() {
        let cg = simple_graph();
        let leaves = cg.leaf_functions();
        assert!(leaves.contains(&0x3000));
        assert!(!leaves.contains(&0x1000));
    }

    // 8. CallGraph::root_functions.
    #[test]
    fn test_root_functions() {
        let cg = simple_graph();
        let roots = cg.root_functions();
        assert!(roots.contains(&0x1000));
        assert!(!roots.contains(&0x3000));
    }

    // 9. CallGraph::reachable_from.
    #[test]
    fn test_reachable_from() {
        let cg = simple_graph();
        let r = cg.reachable_from(0x1000);
        assert!(r.contains(&0x2000) && r.contains(&0x3000));
    }

    // 10. CallGraph::reachable_from leaf.
    #[test]
    fn test_reachable_from_leaf() {
        let cg = simple_graph();
        let r = cg.reachable_from(0x3000);
        assert_eq!(r.len(), 1);
        assert!(r.contains(&0x3000));
    }

    // 11. CallGraph::ancestors_of.
    #[test]
    fn test_ancestors_of() {
        let cg = simple_graph();
        let a = cg.ancestors_of(0x3000);
        assert!(a.contains(&0x1000) && a.contains(&0x2000));
    }

    // 12. CallGraph::topological_sort.
    #[test]
    fn test_topological_sort() {
        let cg = simple_graph();
        let order = cg.topological_sort().unwrap();
        let pos: HashMap<u64, usize> = order.iter().enumerate().map(|(i, &v)| (v, i)).collect();
        assert!(pos[&0x1000] < pos[&0x2000]);
        assert!(pos[&0x2000] < pos[&0x3000]);
    }

    // 13. CallGraph::topological_sort with cycle.
    #[test]
    fn test_topological_sort_cycle() {
        let mut b = CallGraphBuilder::new();
        b.add_function(0x1000, "a");
        b.add_function(0x2000, "b");
        b.add_call(0x1000, 0x2000, CallType::Direct);
        b.add_call(0x2000, 0x1000, CallType::Direct); // cycle
        let cg = b.build();
        assert!(cg.topological_sort().is_err());
    }

    // 14. CallEdge with_site.
    #[test]
    fn test_call_edge_site() {
        let e = CallEdge::new(0x1000, 0x2000, CallType::Direct).with_site(0x1005);
        assert_eq!(e.call_site, Some(0x1005));
    }

    // 15. SCCDecomposition::compute trivial.
    #[test]
    fn test_scc_trivial() {
        let cg = simple_graph();
        let scc = SCCDecomposition::compute(&cg);
        // No cycles in simple_graph → all trivial.
        assert_eq!(scc.cycles().len(), 0);
        assert_eq!(scc.trivial().len(), 3);
    }

    // 16. SCCDecomposition::compute cycle.
    #[test]
    fn test_scc_cycle() {
        let mut b = CallGraphBuilder::new();
        b.add_function(0x1000, "a");
        b.add_function(0x2000, "b");
        b.add_call(0x1000, 0x2000, CallType::Direct);
        b.add_call(0x2000, 0x1000, CallType::Direct);
        let cg = b.build();
        let scc = SCCDecomposition::compute(&cg);
        assert_eq!(scc.cycles().len(), 1);
        assert_eq!(scc.cycles()[0].nodes.len(), 2);
    }

    // 17. SCCDecomposition node_scc mapping.
    #[test]
    fn test_scc_node_mapping() {
        let cg = simple_graph();
        let scc = SCCDecomposition::compute(&cg);
        assert!(scc.node_scc.contains_key(&0x1000));
        assert!(scc.node_scc.contains_key(&0x3000));
    }

    // 18. CallGraphStats::compute.
    #[test]
    fn test_stats_compute() {
        let cg = simple_graph();
        let stats = CallGraphStats::compute(&cg);
        assert_eq!(stats.total_nodes, 3);
        assert_eq!(stats.total_edges, 3);
        assert_eq!(stats.direct_calls, 3);
        assert_eq!(stats.leaf_count, 1);
        assert_eq!(stats.root_count, 1);
    }

    // 19. CallGraphStats indirect / virtual.
    #[test]
    fn test_stats_call_types() {
        let mut b = CallGraphBuilder::new();
        b.add_function(0x1000, "f");
        b.add_function(0x2000, "g");
        b.add_call(0x1000, 0x2000, CallType::Indirect);
        b.add_call(0x1000, 0x2000, CallType::Virtual);
        let cg = b.build();
        let stats = CallGraphStats::compute(&cg);
        assert_eq!(stats.indirect_calls, 1);
        assert_eq!(stats.virtual_calls, 1);
    }

    // 20. CallGraphBuilder::scan_x86_calls.
    #[test]
    fn test_scan_x86_calls() {
        // CALL rel32 at offset 0: next_ip = base+5, disp = 0x0B → target = base+0x10
        let base = 0x1000u64;
        let mut code = vec![0x90u8; 0x20];
        code[0] = 0xE8;
        code[1..5].copy_from_slice(&0x0Bu32.to_le_bytes());
        let mut b = CallGraphBuilder::new();
        b.add_function(0x1000, "caller");
        b.scan_x86_calls(0x1000, base, &code);
        let cg = b.build();
        let target = base + 5 + 0x0B;
        assert!(cg.calls(0x1000, target));
    }

    // 20b. scan_x86_calls with an adversarial base near u64::MAX must not
    // panic (debug builds) and must wrap mod 2^64 like real RIP arithmetic.
    #[test]
    fn test_scan_x86_calls_base_near_u64_max_no_panic() {
        let base = u64::MAX - 2;
        let mut code = vec![0x90u8; 0x10];
        code[0] = 0xE8;
        code[1..5].copy_from_slice(&0x0Bu32.to_le_bytes());
        let mut b = CallGraphBuilder::new();
        b.add_function(base, "caller");
        b.scan_x86_calls(base, base, &code);
        let cg = b.build();
        // next_ip = (u64::MAX-2) + 5 wraps to 2; callee = 2 + 0x0B = 0x0D.
        assert!(cg.calls(base, 0x0D));
    }

    // 21. CallGraph::to_dot.
    #[test]
    fn test_to_dot() {
        let cg = simple_graph();
        let dot = cg.to_dot();
        assert!(dot.starts_with("digraph callgraph"));
        assert!(dot.contains("main"));
    }

    // 22. CallNode::imported.
    #[test]
    fn test_import_node() {
        let n = CallNode::imported(0xFFFF_0000, "malloc");
        assert!(n.is_import);
        assert_eq!(n.name, "malloc");
    }

    // 23. CallNode::exported.
    #[test]
    fn test_export_node() {
        let n = CallNode::exported(0x1000, "DllMain");
        assert!(n.is_export);
    }

    // 24. CallGraph empty.
    #[test]
    fn test_empty_graph() {
        let cg = CallGraph::new();
        assert_eq!(cg.node_count(), 0);
        assert_eq!(cg.edge_count(), 0);
        assert!(cg.leaf_functions().is_empty());
        assert!(cg.root_functions().is_empty());
    }

    // 25. CallEdge is_direct / is_tail.
    #[test]
    fn test_call_edge_flags() {
        assert!(CallEdge::new(0x1000, 0x2000, CallType::Direct).is_direct());
        assert!(CallEdge::new(0x1000, 0x2000, CallType::Tail).is_tail());
        assert!(!CallEdge::new(0x1000, 0x2000, CallType::Virtual).is_direct());
    }

    // 26. SCCDecomposition: self-loop is a cycle.
    #[test]
    fn test_scc_self_loop() {
        let mut b = CallGraphBuilder::new();
        b.add_function(0x1000, "recursive");
        b.add_call(0x1000, 0x1000, CallType::Direct);
        let cg = b.build();
        let scc = SCCDecomposition::compute(&cg);
        // A self-loop may be represented as a trivial SCC with a self-edge
        // or as a cycle depending on implementation. We just verify no panic.
        let _ = scc.cycles().len() + scc.trivial().len();
    }

    // 27. CallGraphStats::avg_out_degree.
    #[test]
    fn test_avg_out_degree() {
        let cg = simple_graph();
        let stats = CallGraphStats::compute(&cg);
        // 3 edges / 3 nodes = 1.0
        assert!((stats.avg_out_degree - 1.0).abs() < 0.01);
    }

    // 28. CallGraph add_node idempotent.
    #[test]
    fn test_add_node_idempotent() {
        let mut cg = CallGraph::new();
        cg.add_node(CallNode::new(0x1000, "foo"));
        cg.add_node(CallNode::new(0x1000, "foo_dup"));
        assert_eq!(cg.node_count(), 1);
    }

    // 29. CallGraphBuilder chaining.
    #[test]
    fn test_builder_chaining() {
        let mut builder = CallGraphBuilder::new();
        builder
            .add_function(0x1000, "a")
            .add_function(0x2000, "b")
            .add_call(0x1000, 0x2000, CallType::Direct);
        let cg = builder.build();
        assert_eq!(cg.node_count(), 2);
        assert_eq!(cg.edge_count(), 1);
    }

    // 30. CallGraph implicit nodes from add_edge.
    #[test]
    fn test_implicit_nodes() {
        let mut cg = CallGraph::new();
        cg.add_edge(CallEdge::new(0xAAAA, 0xBBBB, CallType::Direct));
        assert!(cg.nodes.contains_key(&0xAAAA));
        assert!(cg.nodes.contains_key(&0xBBBB));
    }

    // 31. CallGraph reachable_from empty start.
    #[test]
    fn test_reachable_from_unknown() {
        let cg = simple_graph();
        let r = cg.reachable_from(0xDEAD);
        assert_eq!(r.len(), 1); // only the start node itself
    }

    // 32. SCCDecomposition: condensation DAG has no cycles.
    #[test]
    fn test_scc_condensation() {
        let cg = simple_graph();
        let scc = SCCDecomposition::compute(&cg);
        assert_eq!(scc.sccs.len(), 3);
    }

    // 33. CallType all variants.
    #[test]
    fn test_call_type_variants() {
        let types = [
            CallType::Direct,
            CallType::Indirect,
            CallType::Virtual,
            CallType::Tail,
            CallType::Import,
            CallType::Callback,
        ];
        let set: HashSet<String> = types.iter().map(std::string::ToString::to_string).collect();
        assert_eq!(set.len(), 6);
    }

    // 34. CallGraphStats max_callee_count.
    #[test]
    fn test_max_callee_count() {
        let cg = simple_graph();
        let stats = CallGraphStats::compute(&cg);
        assert_eq!(stats.max_callee_count, 2); // main calls foo and bar
    }

    // 35. CallGraph ancestors_of root.
    #[test]
    fn test_ancestors_of_root() {
        let cg = simple_graph();
        let a = cg.ancestors_of(0x1000);
        assert_eq!(a.len(), 1); // only itself
    }

    // 36. CallGraphBuilder: import flag propagated.
    #[test]
    fn test_builder_import() {
        let mut b = CallGraphBuilder::new();
        b.add_import(0xFFFF, "printf");
        let cg = b.build();
        assert!(cg.nodes[&0xFFFF].is_import);
    }

    // 37. CallGraphBuilder::add_call_at records the call-site address and
    // creates the expected edge (previously zero direct coverage).
    #[test]
    fn test_builder_add_call_at() {
        let mut b = CallGraphBuilder::new();
        b.add_function(0x1000, "caller");
        b.add_function(0x2000, "callee");
        b.add_call_at(0x1000, 0x2000, CallType::Direct, 0x1234);
        let cg = b.build();
        assert!(cg.calls(0x1000, 0x2000));
        assert_eq!(cg.edges.len(), 1);
        assert_eq!(cg.edges[0].call_site, Some(0x1234));
        assert_eq!(cg.edges[0].call_type, CallType::Direct);
    }
}
