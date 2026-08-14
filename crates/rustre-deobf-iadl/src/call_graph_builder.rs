//! Precise call graph construction including indirect calls, library stubs,
//! tail calls, and strongly-connected component analysis.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use petgraph::Graph;
use petgraph::algo::kosaraju_scc;
use serde::{Deserialize, Serialize};

// ─── EdgeKind ─────────────────────────────────────────────────────────────────

/// The kind of control-flow edge in the call graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// Direct call instruction (`CALL imm`).
    DirectCall,
    /// Indirect call instruction (`CALL [reg]`).
    IndirectCall,
    /// Tail call — a `JMP` that transfers control to another function without
    /// allocating a new stack frame.
    TailCall,
    /// Call via a PLT/IAT stub.
    StubCall,
    /// Virtual dispatch through a vtable.
    VirtualCall,
    /// Callback registered dynamically (e.g. via `qsort`, thread creation).
    Callback,
    /// Inferred edge from dynamic/hint data.
    DynamicHint,
}

impl std::fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::DirectCall => "direct",
            Self::IndirectCall => "indirect",
            Self::TailCall => "tailcall",
            Self::StubCall => "stub",
            Self::VirtualCall => "virtual",
            Self::Callback => "callback",
            Self::DynamicHint => "dynamic",
        };
        write!(f, "{s}")
    }
}

// ─── CallEdge ─────────────────────────────────────────────────────────────────

/// A directed edge in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    /// Caller function start address.
    pub caller: u64,
    /// Callee function start address.
    pub callee: u64,
    /// Address of the call instruction (site).
    pub call_site: u64,
    /// Kind of call.
    pub kind: EdgeKind,
    /// Confidence in this edge (0.0–1.0).
    pub confidence: f64,
    /// Whether this edge was derived from static analysis (vs dynamic hint).
    pub is_static: bool,
}

impl CallEdge {
    /// Create a new call edge.
    #[must_use]
    pub fn new(caller: u64, callee: u64, call_site: u64, kind: EdgeKind) -> Self {
        Self {
            caller,
            callee,
            call_site,
            kind,
            confidence: 1.0,
            is_static: true,
        }
    }

    /// Set confidence.
    #[must_use]
    pub fn with_confidence(mut self, c: f64) -> Self {
        // `f64::clamp` propagates NaN; a NaN confidence would silently lose
        // every comparison it takes part in.
        self.confidence = if c.is_nan() { 0.0 } else { c.clamp(0.0, 1.0) };
        self
    }

    /// Mark as a dynamic hint edge.
    #[must_use]
    pub const fn as_dynamic(mut self) -> Self {
        self.is_static = false;
        self
    }
}

// ─── CallSite ─────────────────────────────────────────────────────────────────

/// Information about a single call instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Address of the call instruction.
    pub addr: u64,
    /// Enclosing function start.
    pub function: u64,
    /// Resolved callee targets.
    pub targets: Vec<u64>,
    /// Kind of this call.
    pub kind: EdgeKind,
    /// Whether at least one target is unresolved.
    pub has_unresolved: bool,
}

impl CallSite {
    /// Create a new call site.
    #[must_use]
    pub fn new(addr: u64, function: u64, kind: EdgeKind) -> Self {
        Self {
            addr,
            function,
            targets: Vec::new(),
            kind,
            has_unresolved: false,
        }
    }

    /// Add a resolved target.
    pub fn add_target(&mut self, target: u64) {
        if !self.targets.contains(&target) {
            self.targets.push(target);
        }
    }

    /// Return `true` if this is a monomorphic call site.
    #[must_use]
    pub fn is_monomorphic(&self) -> bool {
        self.targets.len() == 1
    }
}

// ─── CallGraph ────────────────────────────────────────────────────────────────

/// A precise call graph computed by the builder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallGraph {
    /// Edges in the graph.
    pub edges: Vec<CallEdge>,
    /// Call sites by address.
    pub call_sites: BTreeMap<u64, CallSite>,
    /// Nodes (function addresses) known to the graph.
    pub nodes: BTreeSet<u64>,
    /// Map from function address to its display name.
    pub symbol_names: HashMap<u64, String>,
    /// Functions identified as library stubs.
    pub library_stubs: HashSet<u64>,
    /// Functions that are unresolvable targets.
    pub unresolvable: HashSet<u64>,
}

impl CallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node (function) to the graph.
    pub fn add_node(&mut self, addr: u64) {
        self.nodes.insert(addr);
    }

    /// Add an edge.
    pub fn add_edge(&mut self, edge: CallEdge) {
        self.nodes.insert(edge.caller);
        self.nodes.insert(edge.callee);
        self.edges.push(edge);
    }

    /// Add or update a call site.
    pub fn add_call_site(&mut self, site: CallSite) {
        self.nodes.insert(site.function);
        self.call_sites.insert(site.addr, site);
    }

    /// Register a symbol name for a function address.
    pub fn set_symbol(&mut self, addr: u64, name: impl Into<String>) {
        self.symbol_names.insert(addr, name.into());
    }

    /// Mark a function as a library stub.
    pub fn mark_library_stub(&mut self, addr: u64) {
        self.library_stubs.insert(addr);
    }

    /// Mark a function as unresolvable.
    pub fn mark_unresolvable(&mut self, addr: u64) {
        self.unresolvable.insert(addr);
    }

    /// Return all edges whose caller is `func`.
    #[must_use]
    pub fn callees_of(&self, func: u64) -> Vec<&CallEdge> {
        self.edges.iter().filter(|e| e.caller == func).collect()
    }

    /// Return all edges whose callee is `func`.
    #[must_use]
    pub fn callers_of(&self, func: u64) -> Vec<&CallEdge> {
        self.edges.iter().filter(|e| e.callee == func).collect()
    }

    /// Return the fan-out (number of distinct callees) for `func`.
    #[must_use]
    pub fn fan_out(&self, func: u64) -> usize {
        self.callees_of(func)
            .iter()
            .map(|e| e.callee)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Return the fan-in (number of distinct callers) for `func`.
    #[must_use]
    pub fn fan_in(&self, func: u64) -> usize {
        self.callers_of(func)
            .iter()
            .map(|e| e.caller)
            .collect::<HashSet<_>>()
            .len()
    }

    /// Return the number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Return the display name for a function, falling back to hex address.
    #[must_use]
    pub fn name_of(&self, addr: u64) -> String {
        self.symbol_names
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| format!("sub_{addr:x}"))
    }

    /// Compute call graph metrics.
    #[must_use]
    pub fn metrics(&self) -> CallGraphMetrics {
        let node_count = self.node_count();
        let edge_count = self.edge_count();

        let avg_fan_out = if node_count == 0 {
            0.0
        } else {
            self.nodes.iter().map(|&n| self.fan_out(n)).sum::<usize>() as f64 / node_count as f64
        };

        let avg_fan_in = if node_count == 0 {
            0.0
        } else {
            self.nodes.iter().map(|&n| self.fan_in(n)).sum::<usize>() as f64 / node_count as f64
        };

        let max_fan_out = self.nodes.iter().map(|&n| self.fan_out(n)).max().unwrap_or(0);
        let max_fan_in = self.nodes.iter().map(|&n| self.fan_in(n)).max().unwrap_or(0);

        let direct_edges = self.edges.iter().filter(|e| e.kind == EdgeKind::DirectCall).count();
        let indirect_edges = self.edges.iter().filter(|e| e.kind == EdgeKind::IndirectCall).count();
        let tail_edges = self.edges.iter().filter(|e| e.kind == EdgeKind::TailCall).count();
        let stub_edges = self.edges.iter().filter(|e| e.kind == EdgeKind::StubCall).count();

        let density = if node_count < 2 {
            0.0
        } else {
            edge_count as f64 / (node_count as f64 * (node_count as f64 - 1.0))
        };

        let sccs = self.compute_sccs();
        let scc_count = sccs.len();
        let recursive_funcs = sccs.iter().filter(|scc| scc.len() > 1).flat_map(|s| s.iter().copied()).count();

        CallGraphMetrics {
            node_count,
            edge_count,
            avg_fan_out,
            avg_fan_in,
            max_fan_out,
            max_fan_in,
            direct_edges,
            indirect_edges,
            tail_edges,
            stub_edges,
            density,
            scc_count,
            recursive_funcs,
            library_stub_count: self.library_stubs.len(),
            unresolvable_count: self.unresolvable.len(),
        }
    }

    /// Compute strongly-connected components using Tarjan's algorithm.
    #[must_use]
    pub fn compute_sccs(&self) -> Vec<Vec<u64>> {
        let nodes: Vec<u64> = self.nodes.iter().copied().collect();
        let node_idx: HashMap<u64, usize> =
            nodes.iter().enumerate().map(|(i, &n)| (n, i)).collect();

        // Build a petgraph::Graph and use the battle-tested kosaraju_scc algorithm
        // instead of the hand-rolled Tarjan implementation.
        let mut pg: Graph<u64, ()> = Graph::with_capacity(nodes.len(), self.edges.len());
        let pg_nodes: Vec<_> = nodes.iter().map(|&addr| pg.add_node(addr)).collect();

        for e in &self.edges {
            if let (Some(&si), Some(&di)) = (node_idx.get(&e.caller), node_idx.get(&e.callee)) {
                pg.add_edge(pg_nodes[si], pg_nodes[di], ());
            }
        }

        // kosaraju_scc returns SCCs in reverse topological order (callee first).
        kosaraju_scc(&pg)
            .into_iter()
            .map(|scc| scc.into_iter().map(|nx| *pg.node_weight(nx).unwrap()).collect())
            .collect()
    }

    /// Compute a topological order over the condensation DAG.
    /// Functions that form SCCs are grouped; the result is ordered so that
    /// callee groups appear before caller groups.
    #[must_use]
    pub fn topological_order(&self) -> Vec<u64> {
        let sccs = self.compute_sccs();
        // Flatten SCCs into ordered list.
        sccs.into_iter().flatten().collect()
    }

    /// BFS reachability from `start`.
    #[must_use]
    pub fn reachable_from(&self, start: u64) -> HashSet<u64> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);
        while let Some(cur) = queue.pop_front() {
            if !visited.insert(cur) {
                continue;
            }
            for e in self.callees_of(cur) {
                if !visited.contains(&e.callee) {
                    queue.push_back(e.callee);
                }
            }
        }
        visited
    }

    /// Return functions that have no callers (entry points).
    #[must_use]
    pub fn entry_points(&self) -> Vec<u64> {
        self.nodes
            .iter()
            .copied()
            .filter(|&n| self.fan_in(n) == 0)
            .collect()
    }

    /// Return functions that have no callees (leaf functions).
    #[must_use]
    pub fn leaf_functions(&self) -> Vec<u64> {
        self.nodes
            .iter()
            .copied()
            .filter(|&n| self.fan_out(n) == 0)
            .collect()
    }

    /// Export the call graph in DOT format for visualization.
    #[must_use]
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph call_graph {\n  rankdir=LR;\n");
        for &node in &self.nodes {
            let label = self.name_of(node);
            let style = if self.library_stubs.contains(&node) {
                " style=dashed"
            } else {
                ""
            };
            out.push_str(&format!(
                "  n{node:016x} [label=\"{label}\"{style}];\n"
            ));
        }
        for e in &self.edges {
            out.push_str(&format!(
                "  n{:016x} -> n{:016x} [label=\"{}\"];\n",
                e.caller, e.callee, e.kind
            ));
        }
        out.push('}');
        out
    }
}

// ─── CallGraphMetrics ─────────────────────────────────────────────────────────

/// Structural metrics for a call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphMetrics {
    /// Number of function nodes.
    pub node_count: usize,
    /// Number of edges.
    pub edge_count: usize,
    /// Average fan-out (callees per function).
    pub avg_fan_out: f64,
    /// Average fan-in (callers per function).
    pub avg_fan_in: f64,
    /// Maximum fan-out across all functions.
    pub max_fan_out: usize,
    /// Maximum fan-in across all functions.
    pub max_fan_in: usize,
    /// Number of direct call edges.
    pub direct_edges: usize,
    /// Number of indirect call edges.
    pub indirect_edges: usize,
    /// Number of tail-call edges.
    pub tail_edges: usize,
    /// Number of stub call edges.
    pub stub_edges: usize,
    /// Graph density.
    pub density: f64,
    /// Number of SCCs (including trivial ones).
    pub scc_count: usize,
    /// Number of functions in non-trivial SCCs (recursive call groups).
    pub recursive_funcs: usize,
    /// Number of identified library stubs.
    pub library_stub_count: usize,
    /// Number of unresolvable targets.
    pub unresolvable_count: usize,
}

// ─── CallGraphBuilder ─────────────────────────────────────────────────────────

/// Abstract input for the call graph builder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Function start address.
    pub start: u64,
    /// Optional symbol name.
    pub name: Option<String>,
    /// Size in bytes.
    pub size: u32,
    /// Raw call sites within this function.
    pub call_instructions: Vec<CallInstruction>,
    /// Whether this function is a library stub (single indirect JMP to IAT).
    pub is_stub: bool,
}

impl FunctionInfo {
    /// Create a minimal function record.
    #[must_use]
    pub fn new(start: u64, size: u32) -> Self {
        Self {
            start,
            name: None,
            size,
            call_instructions: Vec::new(),
            is_stub: false,
        }
    }

    /// Set symbol name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// A single call instruction within a function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallInstruction {
    /// Address of the call instruction.
    pub addr: u64,
    /// Direct target address (for direct calls).
    pub direct_target: Option<u64>,
    /// Resolved indirect targets (from prior analysis).
    pub indirect_targets: Vec<u64>,
    /// Whether this is a tail call.
    pub is_tail_call: bool,
    /// Whether this is an indirect call.
    pub is_indirect: bool,
}

impl CallInstruction {
    /// Create a direct call.
    #[must_use]
    pub fn direct(addr: u64, target: u64) -> Self {
        Self {
            addr,
            direct_target: Some(target),
            indirect_targets: Vec::new(),
            is_tail_call: false,
            is_indirect: false,
        }
    }

    /// Create an indirect call with pre-resolved targets.
    #[must_use]
    pub fn indirect(addr: u64, targets: Vec<u64>) -> Self {
        Self {
            addr,
            direct_target: None,
            indirect_targets: targets,
            is_tail_call: false,
            is_indirect: true,
        }
    }

    /// Mark as a tail call.
    #[must_use]
    pub const fn tail(mut self) -> Self {
        self.is_tail_call = true;
        self
    }
}

/// Dynamic hint from a profiler or tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicHint {
    /// Call site address.
    pub call_site: u64,
    /// Observed callee address.
    pub callee: u64,
    /// Number of times this edge was observed.
    pub hit_count: u64,
}

/// The call graph builder.
pub struct CallGraphBuilder {
    /// Function definitions.
    functions: BTreeMap<u64, FunctionInfo>,
    /// IAT / PLT mapping: stub address → external symbol name.
    iat_stubs: HashMap<u64, String>,
    /// Dynamic hints from profiling or tracing.
    dynamic_hints: Vec<DynamicHint>,
    /// Address ranges known to belong to import stubs.
    stub_ranges: Vec<(u64, u64)>,
    /// Configuration.
    config: CgBuilderConfig,
}

/// Configuration for the call graph builder.
#[derive(Debug, Clone)]
pub struct CgBuilderConfig {
    /// Whether to include library stub functions as full nodes.
    pub include_stubs: bool,
    /// Whether to include dynamic-hint edges even if confidence is low.
    pub include_dynamic_hints: bool,
    /// Minimum hit count for a dynamic hint to be included.
    pub min_dynamic_hits: u64,
    /// Whether to merge parallel edges (keep only one edge per caller→callee pair).
    pub merge_parallel_edges: bool,
}

impl Default for CgBuilderConfig {
    fn default() -> Self {
        Self {
            include_stubs: true,
            include_dynamic_hints: true,
            min_dynamic_hits: 1,
            merge_parallel_edges: false,
        }
    }
}

impl CallGraphBuilder {
    /// Create a new builder with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CgBuilderConfig::default())
    }

    /// Create a builder with explicit configuration.
    #[must_use]
    pub fn with_config(config: CgBuilderConfig) -> Self {
        Self {
            functions: BTreeMap::new(),
            iat_stubs: HashMap::new(),
            dynamic_hints: Vec::new(),
            stub_ranges: Vec::new(),
            config,
        }
    }

    /// Register a function.
    pub fn add_function(&mut self, func: FunctionInfo) {
        self.functions.insert(func.start, func);
    }

    /// Register an IAT/PLT stub.
    pub fn add_iat_stub(&mut self, stub_addr: u64, symbol: impl Into<String>) {
        self.iat_stubs.insert(stub_addr, symbol.into());
    }

    /// Add a dynamic hint.
    pub fn add_dynamic_hint(&mut self, hint: DynamicHint) {
        self.dynamic_hints.push(hint);
    }

    /// Register a stub address range (e.g. the `.plt` section).
    pub fn add_stub_range(&mut self, start: u64, end: u64) {
        self.stub_ranges.push((start, end));
    }

    /// Return `true` if `addr` falls in a known stub range.
    fn is_in_stub_range(&self, addr: u64) -> bool {
        self.stub_ranges.iter().any(|&(s, e)| addr >= s && addr < e)
            || self.iat_stubs.contains_key(&addr)
    }

    /// Build and return the call graph.
    #[must_use]
    pub fn build(mut self) -> CallGraph {
        let mut cg = CallGraph::new();

        // Register all function nodes.
        for (&addr, func) in &self.functions {
            cg.add_node(addr);
            if let Some(name) = &func.name {
                cg.set_symbol(addr, name.clone());
            }
            if func.is_stub || self.is_in_stub_range(addr) {
                cg.mark_library_stub(addr);
            }
        }

        // Register IAT stubs.
        for (&stub_addr, sym) in &self.iat_stubs {
            cg.add_node(stub_addr);
            cg.set_symbol(stub_addr, sym.clone());
            cg.mark_library_stub(stub_addr);
        }

        // Build edges from function call instructions.
        let funcs: Vec<(u64, FunctionInfo)> = std::mem::take(&mut self.functions).into_iter().collect();
        for (func_addr, func) in &funcs {
            for ci in &func.call_instructions {
                let kind = if ci.is_tail_call {
                    EdgeKind::TailCall
                } else if ci.is_indirect {
                    EdgeKind::IndirectCall
                } else if ci.direct_target.map_or(false, |t| self.is_in_stub_range(t)) {
                    EdgeKind::StubCall
                } else {
                    EdgeKind::DirectCall
                };

                // Direct target.
                if let Some(target) = ci.direct_target {
                    let edge = CallEdge::new(*func_addr, target, ci.addr, kind);
                    cg.add_edge(edge);
                    // Register target as a node if unknown.
                    cg.add_node(target);
                    if self.is_in_stub_range(target) {
                        cg.mark_library_stub(target);
                    }

                    let mut site = CallSite::new(ci.addr, *func_addr, kind);
                    site.add_target(target);
                    cg.add_call_site(site);
                }

                // Indirect targets.
                if !ci.indirect_targets.is_empty() {
                    let mut site = CallSite::new(ci.addr, *func_addr, kind);
                    for &tgt in &ci.indirect_targets {
                        let edge = CallEdge::new(*func_addr, tgt, ci.addr, EdgeKind::IndirectCall)
                            .with_confidence(0.80);
                        cg.add_edge(edge);
                        cg.add_node(tgt);
                        site.add_target(tgt);
                    }
                    cg.add_call_site(site);
                }

                // Mark as unresolvable if indirect and no targets.
                if ci.is_indirect && ci.indirect_targets.is_empty() {
                    cg.mark_unresolvable(ci.addr);
                }
            }
        }

        // Add dynamic hint edges.
        if self.config.include_dynamic_hints {
            for hint in &self.dynamic_hints {
                if hint.hit_count < self.config.min_dynamic_hits {
                    continue;
                }
                // Find enclosing function.
                let caller = funcs
                    .iter()
                    .filter(|(s, f)| hint.call_site >= *s && hint.call_site < s + f.size as u64)
                    .map(|(s, _)| *s)
                    .next()
                    .unwrap_or(hint.call_site);

                let conf = (hint.hit_count as f64).log2() / 10.0;
                let edge = CallEdge::new(caller, hint.callee, hint.call_site, EdgeKind::DynamicHint)
                    .with_confidence(conf.clamp(0.1, 0.9))
                    .as_dynamic();
                cg.add_edge(edge);
                cg.add_node(caller);
                cg.add_node(hint.callee);
            }
        }

        // Merge parallel edges if configured.
        if self.config.merge_parallel_edges {
            merge_parallel_edges_in_place(&mut cg);
        }

        cg
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Remove duplicate edges (same caller→callee), keeping the highest-confidence one.
fn merge_parallel_edges_in_place(cg: &mut CallGraph) {
    let mut seen: HashMap<(u64, u64), usize> = HashMap::new();
    let mut to_remove: Vec<usize> = Vec::new();

    for (i, e) in cg.edges.iter().enumerate() {
        let key = (e.caller, e.callee);
        if let Some(&prev_idx) = seen.get(&key) {
            // Keep the higher-confidence edge.
            if cg.edges[prev_idx].confidence >= e.confidence {
                to_remove.push(i);
            } else {
                to_remove.push(prev_idx);
                seen.insert(key, i);
            }
        } else {
            seen.insert(key, i);
        }
    }

    to_remove.sort_unstable_by(|a, b| b.cmp(a));
    for idx in to_remove {
        cg.edges.remove(idx);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(start: u64, size: u32) -> FunctionInfo {
        FunctionInfo::new(start, size)
    }

    fn make_func_named(start: u64, size: u32, name: &str) -> FunctionInfo {
        FunctionInfo::new(start, size).with_name(name)
    }

    fn add_direct_call(func: &mut FunctionInfo, site: u64, target: u64) {
        func.call_instructions.push(CallInstruction::direct(site, target));
    }

    #[test]
    fn test_empty_graph() {
        let builder = CallGraphBuilder::new();
        let cg = builder.build();
        assert_eq!(cg.node_count(), 0);
        assert_eq!(cg.edge_count(), 0);
    }

    #[test]
    fn test_single_direct_call() {
        let mut builder = CallGraphBuilder::new();
        let mut f = make_func(0x1000, 32);
        add_direct_call(&mut f, 0x1010, 0x2000);
        builder.add_function(f);
        builder.add_function(make_func(0x2000, 16));
        let cg = builder.build();
        assert_eq!(cg.edge_count(), 1);
        let edge = &cg.edges[0];
        assert_eq!(edge.caller, 0x1000);
        assert_eq!(edge.callee, 0x2000);
        assert_eq!(edge.kind, EdgeKind::DirectCall);
    }

    #[test]
    fn test_fan_out_and_fan_in() {
        let mut builder = CallGraphBuilder::new();
        let mut f1 = make_func(0x1000, 64);
        add_direct_call(&mut f1, 0x1010, 0x2000);
        add_direct_call(&mut f1, 0x1020, 0x3000);
        builder.add_function(f1);
        builder.add_function(make_func(0x2000, 16));
        builder.add_function(make_func(0x3000, 16));
        let cg = builder.build();
        assert_eq!(cg.fan_out(0x1000), 2);
        assert_eq!(cg.fan_in(0x2000), 1);
        assert_eq!(cg.fan_in(0x3000), 1);
    }

    #[test]
    fn test_stub_detection() {
        let mut builder = CallGraphBuilder::new();
        builder.add_iat_stub(0x5000, "printf");
        let mut f = make_func(0x1000, 32);
        add_direct_call(&mut f, 0x1010, 0x5000);
        builder.add_function(f);
        let cg = builder.build();
        assert!(cg.library_stubs.contains(&0x5000));
    }

    #[test]
    fn test_indirect_call_edge() {
        let mut builder = CallGraphBuilder::new();
        let mut f = make_func(0x1000, 64);
        f.call_instructions.push(CallInstruction::indirect(0x1020, vec![0x4000, 0x5000]));
        builder.add_function(f);
        let cg = builder.build();
        assert_eq!(cg.edge_count(), 2);
        assert!(cg.edges.iter().all(|e| e.kind == EdgeKind::IndirectCall));
    }

    #[test]
    fn test_tail_call_edge() {
        let mut builder = CallGraphBuilder::new();
        let mut f = make_func(0x1000, 32);
        f.call_instructions.push(CallInstruction::direct(0x1020, 0x3000).tail());
        builder.add_function(f);
        builder.add_function(make_func(0x3000, 16));
        let cg = builder.build();
        assert_eq!(cg.edges[0].kind, EdgeKind::TailCall);
    }

    #[test]
    fn test_dynamic_hint() {
        let mut builder = CallGraphBuilder::new();
        let f = make_func(0x1000, 64);
        builder.add_function(f);
        builder.add_dynamic_hint(DynamicHint { call_site: 0x1010, callee: 0x6000, hit_count: 100 });
        let cg = builder.build();
        let dyn_edges: Vec<_> = cg.edges.iter().filter(|e| e.kind == EdgeKind::DynamicHint).collect();
        assert!(!dyn_edges.is_empty());
    }

    #[test]
    fn test_scc_computation() {
        let mut builder = CallGraphBuilder::new();
        let mut f1 = make_func(0x1000, 64);
        let mut f2 = make_func(0x2000, 64);
        add_direct_call(&mut f1, 0x1010, 0x2000);
        add_direct_call(&mut f2, 0x2010, 0x1000); // mutual recursion
        builder.add_function(f1);
        builder.add_function(f2);
        let cg = builder.build();
        let sccs = cg.compute_sccs();
        let has_mutual = sccs.iter().any(|scc| scc.len() >= 2);
        assert!(has_mutual);
    }

    #[test]
    fn test_entry_points() {
        let mut builder = CallGraphBuilder::new();
        let mut f1 = make_func_named(0x1000, 32, "main");
        add_direct_call(&mut f1, 0x1010, 0x2000);
        builder.add_function(f1);
        builder.add_function(make_func(0x2000, 16));
        let cg = builder.build();
        let entries = cg.entry_points();
        assert!(entries.contains(&0x1000));
        assert!(!entries.contains(&0x2000));
    }

    #[test]
    fn test_leaf_functions() {
        let mut builder = CallGraphBuilder::new();
        let mut f1 = make_func(0x1000, 32);
        add_direct_call(&mut f1, 0x1010, 0x2000);
        builder.add_function(f1);
        builder.add_function(make_func(0x2000, 16)); // no outgoing calls
        let cg = builder.build();
        let leaves = cg.leaf_functions();
        assert!(leaves.contains(&0x2000));
    }

    #[test]
    fn test_reachable_from() {
        let mut builder = CallGraphBuilder::new();
        let mut f1 = make_func(0x1000, 32);
        add_direct_call(&mut f1, 0x1010, 0x2000);
        let mut f2 = make_func(0x2000, 32);
        add_direct_call(&mut f2, 0x2010, 0x3000);
        builder.add_function(f1);
        builder.add_function(f2);
        builder.add_function(make_func(0x3000, 16));
        let cg = builder.build();
        let reachable = cg.reachable_from(0x1000);
        assert!(reachable.contains(&0x1000));
        assert!(reachable.contains(&0x2000));
        assert!(reachable.contains(&0x3000));
    }

    #[test]
    fn test_metrics() {
        let mut builder = CallGraphBuilder::new();
        let mut f1 = make_func(0x1000, 32);
        add_direct_call(&mut f1, 0x1010, 0x2000);
        builder.add_function(f1);
        builder.add_function(make_func(0x2000, 16));
        let cg = builder.build();
        let m = cg.metrics();
        assert_eq!(m.node_count, 2);
        assert_eq!(m.edge_count, 1);
        assert_eq!(m.direct_edges, 1);
        assert!(m.avg_fan_out > 0.0);
    }

    #[test]
    fn test_dot_output() {
        let mut builder = CallGraphBuilder::new();
        let mut f1 = make_func_named(0x1000, 32, "main");
        add_direct_call(&mut f1, 0x1010, 0x2000);
        builder.add_function(f1);
        builder.add_function(make_func_named(0x2000, 16, "helper"));
        let cg = builder.build();
        let dot = cg.to_dot();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("main"));
        assert!(dot.contains("helper"));
    }

    #[test]
    fn test_name_of_fallback() {
        let cg = CallGraph::new();
        assert!(cg.name_of(0x1234).contains("1234"));
    }

    #[test]
    fn test_unresolvable_marked() {
        let mut builder = CallGraphBuilder::new();
        let mut f = make_func(0x1000, 64);
        f.call_instructions.push(CallInstruction::indirect(0x1020, vec![]));
        builder.add_function(f);
        let cg = builder.build();
        assert!(cg.unresolvable.contains(&0x1020));
    }

    #[test]
    fn test_stub_range() {
        let mut builder = CallGraphBuilder::new();
        builder.add_stub_range(0x5000, 0x6000);
        let mut f = make_func(0x1000, 32);
        add_direct_call(&mut f, 0x1010, 0x5500);
        builder.add_function(f);
        let cg = builder.build();
        assert!(cg.library_stubs.contains(&0x5500));
    }

    #[test]
    fn test_call_site_monomorphic() {
        let site = {
            let mut s = CallSite::new(0x1010, 0x1000, EdgeKind::DirectCall);
            s.add_target(0x2000);
            s
        };
        assert!(site.is_monomorphic());
    }

    #[test]
    fn test_call_graph_symbols() {
        let mut cg = CallGraph::new();
        cg.add_node(0x1000);
        cg.set_symbol(0x1000, "main");
        assert_eq!(cg.name_of(0x1000), "main");
    }
}
