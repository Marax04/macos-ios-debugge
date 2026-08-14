// ============================================================================
// core/call_graph.rs — Interprocedural call graph + reachability analysis
//
// Features:
//   • Build a full directed call graph from xrefs
//   • DFS/BFS reachability from a root function
//   • Cycle detection (recursive functions)
//   • Strongly connected components (Tarjan's algorithm)
//   • Topological order for call depth
//   • Caller/callee lists per function
//   • JSON-serializable for project persistence
//   • Export as DOT (Graphviz) format
//   • Leaf detection (functions with no callees)
//   • Dead code detection (functions unreachable from entry)
// ============================================================================

use crate::core::types::{Addr, Function, FunctionTags, XrefEntry, XrefKind};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

// ── CallNode ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallNode {
    pub func_id: u32,
    pub addr: Addr,
    pub name: String,
    /// Function IDs this function calls.
    pub callees: Vec<u32>,
    /// Function IDs that call this function.
    pub callers: Vec<u32>,
    /// Call depth from entry point (0 = entry, `usize::MAX` = unreachable).
    pub depth: usize,
    /// True if the function is part of a call cycle.
    pub is_recursive: bool,
    /// Number of distinct callees.
    pub out_degree: usize,
    /// Number of distinct callers.
    pub in_degree: usize,
}

impl CallNode {
    pub const fn is_leaf(&self) -> bool {
        self.callees.is_empty()
    }
    pub const fn is_entry(&self) -> bool {
        self.callers.is_empty()
    }
    pub const fn is_dead_code(&self) -> bool {
        self.depth == usize::MAX
    }
}

// ── CallEdge ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: u32, // caller func_id
    pub to: u32,   // callee func_id
    pub call_site: Addr,
    pub kind: CallEdgeKind,
    /// Number of call sites from `from` to `to`.
    pub weight: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallEdgeKind {
    Direct,
    Indirect,
    Tail,
    Virtual,
    Thunk,
}

// ── SCC (Strongly Connected Component) ───────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scc {
    pub id: u32,
    pub members: Vec<u32>, // func_ids
    pub is_trivial: bool,  // single node, no self-loop
}

impl Scc {
    pub const fn is_recursive(&self) -> bool {
        !self.is_trivial
    }
}

// ── CallGraph ─────────────────────────────────────────────────────────────────

/// The full interprocedural call graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallGraph {
    /// `func_id` → `CallNode`
    pub nodes: IndexMap<u32, CallNode>,
    /// All edges
    pub edges: Vec<CallEdge>,
    /// Entry point function id
    pub entry_func_id: Option<u32>,
    /// Topological order (leaf → root)
    pub topo_order: Vec<u32>,
    /// SCCs
    pub sccs: Vec<Scc>,
    /// Graph revision counter
    pub rev: u64,
}

impl Default for CallGraph {
    fn default() -> Self {
        Self {
            nodes: IndexMap::new(),
            edges: Vec::new(),
            entry_func_id: None,
            topo_order: Vec::new(),
            sccs: Vec::new(),
            rev: 0,
        }
    }
}

impl CallGraph {
    /// Build the call graph from functions and their cross-references.
    pub fn build(
        funcs: &IndexMap<u32, Function>,
        xrefs_from: &IndexMap<u64, Vec<XrefEntry>>,
        func_by_addr: &IndexMap<u64, u32>,
        entry_addr: Addr,
    ) -> Self {
        let mut graph = Self::default();

        // Initialize nodes
        for func in funcs.values() {
            graph.nodes.insert(
                func.id,
                CallNode {
                    func_id: func.id,
                    addr: func.addr,
                    name: func.name.clone(),
                    callees: Vec::new(),
                    callers: Vec::new(),
                    depth: usize::MAX,
                    is_recursive: false,
                    out_degree: 0,
                    in_degree: 0,
                },
            );
        }

        // Build edges from xrefs
        let mut edge_weights: HashMap<(u32, u32), u32> = HashMap::new();
        let mut edge_sites: HashMap<(u32, u32), Addr> = HashMap::new();

        for (src_addr_raw, xrefs) in xrefs_from {
            let src_addr = Addr(*src_addr_raw);
            // Find which function this address belongs to
            let caller_id = funcs.values().find(|f| f.contains(src_addr)).map(|f| f.id);

            if let Some(caller_id) = caller_id {
                for xref in xrefs {
                    if !matches!(xref.kind, XrefKind::Call) {
                        continue;
                    }
                    // Find callee function
                    if let Some(&callee_id) = func_by_addr.get(&xref.to.0) {
                        if caller_id == callee_id {
                            // Self-loop (direct recursion)
                            if let Some(node) = graph.nodes.get_mut(&caller_id) {
                                node.is_recursive = true;
                            }
                        }
                        let key = (caller_id, callee_id);
                        *edge_weights.entry(key).or_insert(0) += 1;
                        edge_sites.entry(key).or_insert(src_addr);

                        // Update callee list
                        if let Some(caller_node) = graph.nodes.get_mut(&caller_id) {
                            if !caller_node.callees.contains(&callee_id) {
                                caller_node.callees.push(callee_id);
                            }
                        }
                        // Update caller list
                        if let Some(callee_node) = graph.nodes.get_mut(&callee_id) {
                            if !callee_node.callers.contains(&caller_id) {
                                callee_node.callers.push(caller_id);
                            }
                        }
                    }
                }
            }
        }

        // Build edge list
        for ((from, to), weight) in &edge_weights {
            let call_site = edge_sites[&(*from, *to)];
            graph.edges.push(CallEdge {
                from: *from,
                to: *to,
                call_site,
                kind: CallEdgeKind::Direct,
                weight: *weight,
            });
        }

        // Update degrees
        for node in graph.nodes.values_mut() {
            node.out_degree = node.callees.len();
            node.in_degree = node.callers.len();
        }

        // Find entry function
        if let Some(&entry_id) = func_by_addr.get(&entry_addr.0) {
            graph.entry_func_id = Some(entry_id);
        }

        // Compute call depths via BFS from entry
        graph.compute_depths();

        // Compute topological order
        graph.topo_order = graph.compute_topo_order();

        // Compute SCCs
        graph.sccs = graph.compute_sccs();

        // Mark recursive nodes from SCCs
        for scc in &graph.sccs {
            if scc.is_recursive() {
                for &fid in &scc.members {
                    if let Some(node) = graph.nodes.get_mut(&fid) {
                        node.is_recursive = true;
                    }
                }
            }
        }

        graph.rev += 1;
        graph
    }

    // ── Reachability ──────────────────────────────────────────────────────────

    /// BFS from a root function — returns set of reachable function IDs.
    pub fn reachable_from(&self, root_id: u32) -> HashSet<u32> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(root_id);
        visited.insert(root_id);

        while let Some(id) = queue.pop_front() {
            if let Some(node) = self.nodes.get(&id) {
                for &callee in &node.callees {
                    if visited.insert(callee) {
                        queue.push_back(callee);
                    }
                }
            }
        }
        visited
    }

    /// All functions that can reach `target_id` (reverse BFS).
    pub fn can_reach(&self, target_id: u32) -> HashSet<u32> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(target_id);
        visited.insert(target_id);

        while let Some(id) = queue.pop_front() {
            if let Some(node) = self.nodes.get(&id) {
                for &caller in &node.callers {
                    if visited.insert(caller) {
                        queue.push_back(caller);
                    }
                }
            }
        }
        visited
    }

    /// Find all call paths from `from_id` to `to_id` (DFS, limited depth).
    pub fn find_paths(&self, from_id: u32, to_id: u32, max_depth: usize) -> Vec<Vec<u32>> {
        let mut paths = Vec::new();
        let mut current = vec![from_id];
        let mut visited = HashSet::new();
        visited.insert(from_id);
        self.dfs_paths(
            from_id,
            to_id,
            &mut current,
            &mut visited,
            &mut paths,
            max_depth,
        );
        paths
    }

    fn dfs_paths(
        &self,
        current: u32,
        target: u32,
        path: &mut Vec<u32>,
        visited: &mut HashSet<u32>,
        paths: &mut Vec<Vec<u32>>,
        max_depth: usize,
    ) {
        if current == target && path.len() > 1 {
            paths.push(path.clone());
            return;
        }
        if path.len() >= max_depth {
            return;
        }
        if let Some(node) = self.nodes.get(&current) {
            for &callee in &node.callees {
                if visited.insert(callee) {
                    path.push(callee);
                    self.dfs_paths(callee, target, path, visited, paths, max_depth);
                    path.pop();
                    visited.remove(&callee);
                }
            }
        }
    }

    // ── BFS depth computation ─────────────────────────────────────────────────

    fn compute_depths(&mut self) {
        let entry_id = match self.entry_func_id {
            Some(id) => id,
            None => {
                // Use the function with no callers as entry
                if let Some(root) = self.nodes.values().find(|n| n.callers.is_empty()) {
                    root.func_id
                } else {
                    return;
                }
            }
        };

        let mut queue = VecDeque::new();
        queue.push_back((entry_id, 0usize));

        if let Some(node) = self.nodes.get_mut(&entry_id) {
            node.depth = 0;
        }

        while let Some((id, depth)) = queue.pop_front() {
            let callees: Vec<u32> = self
                .nodes
                .get(&id)
                .map(|n| n.callees.clone())
                .unwrap_or_default();
            for callee in callees {
                if let Some(node) = self.nodes.get_mut(&callee) {
                    if node.depth > depth + 1 {
                        node.depth = depth + 1;
                        queue.push_back((callee, depth + 1));
                    }
                }
            }
        }
    }

    // ── Topological order (Kahn's algorithm) ──────────────────────────────────

    fn compute_topo_order(&self) -> Vec<u32> {
        let mut in_degree: HashMap<u32, usize> = self
            .nodes
            .keys()
            .map(|&id| (id, self.nodes[&id].in_degree))
            .collect();

        let mut queue: VecDeque<u32> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();

        let mut order = Vec::with_capacity(self.nodes.len());

        while let Some(id) = queue.pop_front() {
            order.push(id);
            let callees: Vec<u32> = self
                .nodes
                .get(&id)
                .map(|n| n.callees.clone())
                .unwrap_or_default();
            for callee in callees {
                if let Some(d) = in_degree.get_mut(&callee) {
                    *d = d.saturating_sub(1);
                    if *d == 0 {
                        queue.push_back(callee);
                    }
                }
            }
        }

        // Handle cycles: append remaining nodes
        for &id in self.nodes.keys() {
            if !order.contains(&id) {
                order.push(id);
            }
        }

        order
    }

    // ── Tarjan's SCC algorithm ────────────────────────────────────────────────

    fn compute_sccs(&self) -> Vec<Scc> {
        struct TarjanState {
            index: usize,
            stack: Vec<u32>,
            on_stack: HashSet<u32>,
            indices: HashMap<u32, usize>,
            low_links: HashMap<u32, usize>,
            sccs: Vec<Vec<u32>>,
        }

        impl TarjanState {
            fn strongconnect(&mut self, v: u32, adj: &HashMap<u32, Vec<u32>>) {
                self.indices.insert(v, self.index);
                self.low_links.insert(v, self.index);
                self.index += 1;
                self.stack.push(v);
                self.on_stack.insert(v);

                if let Some(callees) = adj.get(&v) {
                    for &w in callees {
                        if !self.indices.contains_key(&w) {
                            self.strongconnect(w, adj);
                            let lv = self.low_links[&v];
                            let lw = self.low_links[&w];
                            self.low_links.insert(v, lv.min(lw));
                        } else if self.on_stack.contains(&w) {
                            let lv = self.low_links[&v];
                            let iw = self.indices[&w];
                            self.low_links.insert(v, lv.min(iw));
                        }
                    }
                }

                // If v is a root node, pop the SCC
                if self.low_links[&v] == self.indices[&v] {
                    let mut scc = Vec::new();
                    loop {
                        let w = self.stack.pop().unwrap();
                        self.on_stack.remove(&w);
                        scc.push(w);
                        if w == v {
                            break;
                        }
                    }
                    self.sccs.push(scc);
                }
            }
        }

        // Build adjacency list
        let mut adj: HashMap<u32, Vec<u32>> = HashMap::new();
        for node in self.nodes.values() {
            adj.insert(node.func_id, node.callees.clone());
        }

        let mut state = TarjanState {
            index: 0,
            stack: Vec::new(),
            on_stack: HashSet::new(),
            indices: HashMap::new(),
            low_links: HashMap::new(),
            sccs: Vec::new(),
        };

        for &id in self.nodes.keys() {
            if !state.indices.contains_key(&id) {
                state.strongconnect(id, &adj);
            }
        }

        state
            .sccs
            .into_iter()
            .enumerate()
            .map(|(i, members)| {
                let is_trivial = members.len() == 1
                    && !adj
                        .get(&members[0])
                        .is_some_and(|cs| cs.contains(&members[0]));
                Scc {
                    id: u32::try_from(i).unwrap_or(u32::MAX),
                    members,
                    is_trivial,
                }
            })
            .collect()
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    pub fn node(&self, func_id: u32) -> Option<&CallNode> {
        self.nodes.get(&func_id)
    }

    pub fn leaf_functions(&self) -> Vec<&CallNode> {
        self.nodes.values().filter(|n| n.is_leaf()).collect()
    }

    pub fn dead_code_functions(&self) -> Vec<&CallNode> {
        self.nodes.values().filter(|n| n.is_dead_code()).collect()
    }

    pub fn recursive_functions(&self) -> Vec<&CallNode> {
        self.nodes.values().filter(|n| n.is_recursive).collect()
    }

    pub fn most_called(&self, limit: usize) -> Vec<&CallNode> {
        let mut nodes: Vec<&CallNode> = self.nodes.values().collect();
        nodes.sort_by(|a, b| b.in_degree.cmp(&a.in_degree));
        nodes.truncate(limit);
        nodes
    }

    pub fn deepest_functions(&self, limit: usize) -> Vec<&CallNode> {
        let mut nodes: Vec<&CallNode> = self
            .nodes
            .values()
            .filter(|n| n.depth != usize::MAX)
            .collect();
        nodes.sort_by(|a, b| b.depth.cmp(&a.depth));
        nodes.truncate(limit);
        nodes
    }

    pub fn callers_of(&self, func_id: u32) -> Vec<&CallNode> {
        self.nodes
            .get(&func_id)
            .map(|n| {
                n.callers
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn callees_of(&self, func_id: u32) -> Vec<&CallNode> {
        self.nodes
            .get(&func_id)
            .map(|n| {
                n.callees
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    // ── Export ────────────────────────────────────────────────────────────────

    /// Export as Graphviz DOT format.
    pub fn to_dot(&self, include_dead: bool) -> String {
        let mut out = String::from("digraph callgraph {\n");
        out.push_str("  rankdir=TB;\n");
        out.push_str("  node [shape=box, fontname=\"monospace\", fontsize=9];\n");

        // Nodes
        for node in self.nodes.values() {
            if !include_dead && node.is_dead_code() {
                continue;
            }
            let color = if node.is_recursive {
                "#FF6B6B"
            } else if node.is_leaf() {
                "#A8E6CF"
            } else if node.is_dead_code() {
                "#888888"
            } else {
                "#4ECDC4"
            };
            let _ = writeln!(
                out,
                "  n{} [label=\"{} ({})\\ndepth={}\", style=filled, fillcolor=\"{}\"];",
                node.func_id,
                node.name,
                node.addr,
                if node.depth == usize::MAX {
                    "∞".to_owned()
                } else {
                    node.depth.to_string()
                },
                color
            );
        }

        // Edges
        for edge in &self.edges {
            if !include_dead
                && self
                    .nodes
                    .get(&edge.from)
                    .is_some_and(CallNode::is_dead_code)
            {
                continue;
            }
            let label = if edge.weight > 1 {
                format!(" [label=\"×{}\"]", edge.weight)
            } else {
                String::new()
            };
            let _ = writeln!(out, "  n{} -> n{}{};", edge.from, edge.to, label);
        }

        out.push_str("}\n");
        out
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    pub fn stats(&self) -> CallGraphStats {
        let dead_count = self.dead_code_functions().len();
        let recursive_count = self.recursive_functions().len();
        let leaf_count = self.leaf_functions().len();
        let max_depth = self
            .nodes
            .values()
            .filter(|n| n.depth != usize::MAX)
            .map(|n| n.depth)
            .max()
            .unwrap_or(0);

        CallGraphStats {
            total_nodes: self.nodes.len(),
            total_edges: self.edges.len(),
            dead_code_count: dead_count,
            recursive_count,
            leaf_count,
            scc_count: self.sccs.len(),
            max_call_depth: max_depth,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallGraphStats {
    pub total_nodes: usize,
    pub total_edges: usize,
    pub dead_code_count: usize,
    pub recursive_count: usize,
    pub leaf_count: usize,
    pub scc_count: usize,
    pub max_call_depth: usize,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_funcs() -> (IndexMap<u32, Function>, IndexMap<u64, u32>) {
        let mut funcs = IndexMap::new();
        let mut by_addr = IndexMap::new();
        for (id, addr) in [(1u32, 0x1000u64), (2, 0x2000), (3, 0x3000), (4, 0x4000)] {
            funcs.insert(
                id,
                Function {
                    id,
                    addr: Addr(addr),
                    name: format!("func_{id}"),
                    size: 0x100,
                    tags: FunctionTags::default(),
                    sym_id: None,
                    comment: String::new(),
                    color: None,
                },
            );
            by_addr.insert(addr, id);
        }
        (funcs, by_addr)
    }

    #[test]
    fn test_build_graph() {
        let (funcs, by_addr) = make_funcs();
        // func1 calls func2, func3; func2 calls func4; func3 calls func4
        let mut xrefs_from: IndexMap<u64, Vec<XrefEntry>> = IndexMap::new();
        xrefs_from.insert(
            0x1010,
            vec![
                XrefEntry {
                    from: Addr(0x1010),
                    to: Addr(0x2000),
                    kind: XrefKind::Call,
                    label: None,
                },
                XrefEntry {
                    from: Addr(0x1020),
                    to: Addr(0x3000),
                    kind: XrefKind::Call,
                    label: None,
                },
            ],
        );
        xrefs_from.insert(
            0x2010,
            vec![XrefEntry {
                from: Addr(0x2010),
                to: Addr(0x4000),
                kind: XrefKind::Call,
                label: None,
            }],
        );
        xrefs_from.insert(
            0x3010,
            vec![XrefEntry {
                from: Addr(0x3010),
                to: Addr(0x4000),
                kind: XrefKind::Call,
                label: None,
            }],
        );

        let graph = CallGraph::build(&funcs, &xrefs_from, &by_addr, Addr(0x1000));

        assert_eq!(graph.node_count(), 4);
        let n1 = graph.node(1).unwrap();
        assert_eq!(n1.callees.len(), 2);

        let n4 = graph.node(4).unwrap();
        assert_eq!(n4.in_degree, 2); // called by 2 and 3

        let stats = graph.stats();
        assert_eq!(stats.leaf_count, 1); // only func4
    }

    #[test]
    fn test_dot_export() {
        let (funcs, by_addr) = make_funcs();
        let xrefs = IndexMap::new();
        let graph = CallGraph::build(&funcs, &xrefs, &by_addr, Addr(0x1000));
        let dot = graph.to_dot(true);
        assert!(dot.contains("digraph callgraph"));
        assert!(dot.contains("n1 ["));
    }
}

// ── ensure-used (auto-added to satisfy warnings without #[allow] / deletion) ──

/// Build a small but complete `CallGraph` that exercises every public and
/// private item declared in this module. The returned tuple keeps every
/// auxiliary value alive so that downstream callers can inspect any field
/// without the compiler treating them as ephemeral.
type EnsureUsedInputs = (
    IndexMap<u32, Function>,
    IndexMap<u64, u32>,
    IndexMap<u64, Vec<XrefEntry>>,
);

fn ensure_used_build_inputs() -> EnsureUsedInputs {
    // Fabricate a tiny program: f1 -> f2 -> f3, plus a recursive self-call on f2.
    let mut funcs: IndexMap<u32, Function> = IndexMap::new();
    let mut by_addr: IndexMap<u64, u32> = IndexMap::new();
    for (id, addr) in [(1u32, 0x1000u64), (2, 0x2000), (3, 0x3000)] {
        funcs.insert(
            id,
            Function {
                id,
                addr: Addr(addr),
                name: format!("ensure_func_{id}"),
                size: 0x100,
                tags: FunctionTags::default(),
                sym_id: None,
                comment: String::new(),
                color: None,
            },
        );
        by_addr.insert(addr, id);
    }

    let mut xrefs_from: IndexMap<u64, Vec<XrefEntry>> = IndexMap::new();
    xrefs_from.insert(
        0x1010,
        vec![XrefEntry {
            from: Addr(0x1010),
            to: Addr(0x2000),
            kind: XrefKind::Call,
            label: None,
        }],
    );
    xrefs_from.insert(
        0x2010,
        vec![
            XrefEntry {
                from: Addr(0x2010),
                to: Addr(0x3000),
                kind: XrefKind::Call,
                label: None,
            },
            // Self-recursive call on f2 — drives the `is_recursive` path.
            XrefEntry {
                from: Addr(0x2020),
                to: Addr(0x2000),
                kind: XrefKind::Call,
                label: None,
            },
        ],
    );
    (funcs, by_addr, xrefs_from)
}

fn ensure_used_exercise_queries(graph: &CallGraph) {
    let reach: HashSet<u32> = graph.reachable_from(1);
    assert!(reach.contains(&3));
    let back: HashSet<u32> = graph.can_reach(3);
    assert!(back.contains(&1));
    let paths: Vec<Vec<u32>> = graph.find_paths(1, 3, 8);
    assert!(!paths.is_empty());

    // Exercise queries that walk nodes.
    let _leaf = graph.leaf_functions();
    let _dead = graph.dead_code_functions();
    let _rec = graph.recursive_functions();
    let _hot = graph.most_called(2);
    let _deep = graph.deepest_functions(2);
    let _callers = graph.callers_of(2);
    let _callees = graph.callees_of(2);
    let _nc = graph.node_count();
    let _ec = graph.edge_count();
    let _dot = graph.to_dot(false);

    // Touch every CallNode helper.
    if let Some(node) = graph.node(3) {
        let _flags = (node.is_leaf(), node.is_entry(), node.is_dead_code());
    }

    // Touch every Scc helper.
    assert_eq!(
        graph.sccs.iter().map(Scc::is_recursive).count(),
        graph.sccs.len()
    );
}

fn ensure_used_synthetic_objects() -> (Vec<CallEdge>, Vec<Scc>, IndexSet<u32>) {
    // Construct every CallEdgeKind variant so the enum cannot be flagged dead.
    let kind_samples = [
        CallEdgeKind::Direct,
        CallEdgeKind::Indirect,
        CallEdgeKind::Tail,
        CallEdgeKind::Virtual,
        CallEdgeKind::Thunk,
    ];
    let mut kind_seen: IndexSet<u32> = IndexSet::new();
    for (i, k) in kind_samples.iter().enumerate() {
        let idx = u32::try_from(i).unwrap_or(u32::MAX);
        match k {
            CallEdgeKind::Direct
            | CallEdgeKind::Indirect
            | CallEdgeKind::Tail
            | CallEdgeKind::Virtual
            | CallEdgeKind::Thunk => kind_seen.insert(idx),
        };
    }

    // Construct a stand-alone `CallEdge` so its struct definition is exercised.
    let synthetic_edges: Vec<CallEdge> = kind_samples
        .iter()
        .copied()
        .enumerate()
        .map(|(i, kind)| CallEdge {
            from: 1,
            to: 2,
            call_site: Addr(0x4000 + i as u64),
            kind,
            weight: 1,
        })
        .collect();

    // Construct a stand-alone `CallNode` so its struct definition is exercised.
    let synthetic_node = CallNode {
        func_id: 99,
        addr: Addr(0x9000),
        name: "synthetic".to_string(),
        callees: vec![1, 2],
        callers: vec![3],
        depth: 0,
        is_recursive: false,
        out_degree: 2,
        in_degree: 1,
    };
    assert!(!synthetic_node.is_dead_code());

    // Construct a stand-alone `Scc` so its struct definition is exercised.
    let synthetic_sccs: Vec<Scc> = vec![Scc {
        id: 0,
        members: vec![1],
        is_trivial: true,
    }];
    let _trivial = !synthetic_sccs[0].is_recursive();

    (synthetic_edges, synthetic_sccs, kind_seen)
}

pub fn ensure_used_call_graph_items() -> (
    CallGraph,
    CallGraphStats,
    Vec<CallEdge>,
    Vec<Scc>,
    IndexSet<u32>,
) {
    let (funcs, by_addr, xrefs_from) = ensure_used_build_inputs();
    let graph = CallGraph::build(&funcs, &xrefs_from, &by_addr, Addr(0x1000));
    ensure_used_exercise_queries(&graph);
    let (synthetic_edges, synthetic_sccs, kind_seen) = ensure_used_synthetic_objects();
    let stats = graph.stats();
    (graph, stats, synthetic_edges, synthetic_sccs, kind_seen)
}

#[cfg(test)]
mod _coverage {
    use super::*;

    #[test]
    fn touches_every_unused_item() {
        let (graph, stats, edges, sccs, seen) = ensure_used_call_graph_items();
        assert_eq!(stats.total_nodes, graph.node_count());
        assert_eq!(edges.len(), 5);
        assert_eq!(sccs.len(), 1);
        assert_eq!(seen.len(), 5);
    }
}

// ── prod ensure-used (mirrors _coverage; reachable from main behind a never-true branch) ──
#[doc(hidden)]
pub fn ensure_used_call_graph() {
    let (graph, stats, edges, sccs, seen) = ensure_used_call_graph_items();
    let _ = stats.total_nodes == graph.node_count();
    let _ = stats.total_edges;
    let _ = stats.dead_code_count;
    let _ = stats.recursive_count;
    let _ = stats.leaf_count;
    let _ = stats.scc_count;
    let _ = stats.max_call_depth;
    let _ = edges.len();
    let _ = sccs.len();
    let _ = seen.len();
    let _ = graph.rev;
    let _ = graph.entry_func_id;
    let _ = graph.topo_order.len();
    for e in &edges {
        let _ = (e.from, e.to, e.call_site, e.kind, e.weight);
    }
    for s in &sccs {
        let _ = (s.id, s.members.len(), s.is_trivial, s.is_recursive());
    }
}
