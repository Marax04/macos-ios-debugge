// lua_function_graph.rs — Build function call graph from Lua/LuaJIT bytecode.
// Tracks CALL/TAILCALL opcodes, proto references via CLOSURE/FNEW, upvalue
// chains, and computes reachability, dominators, and strongly-connected
// components (SCCs).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

// ── Node types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeKind {
    Proto,          // function prototype defined in this module
    CFunction,      // C function (upvalue-imported)
    GlobalRef,      // reference via GGET/global table
    UpvalueRef,     // upvalue closure
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    pub kind: NodeKind,
    pub index: u32,        // proto index or arbitrary ID for C/globals
    pub name: Option<String>,
}

impl NodeId {
    #[must_use]
    pub const fn proto(index: u32, name: Option<String>) -> Self {
        Self { kind: NodeKind::Proto, index, name }
    }

    #[must_use]
    pub fn global(name: &str) -> Self {
        // Hash the name for a stable index
        let h = fnv_hash(name.as_bytes());
        Self { kind: NodeKind::GlobalRef, index: u32::try_from(h).unwrap_or(u32::MAX), name: Some(name.to_owned()) }
    }

    #[must_use]
    pub fn display_name(&self) -> String {
        self.name.as_ref().map_or_else(|| format!("<proto#{}>", self.index), Clone::clone)
    }
}

fn fnv_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;
    let mut hash = FNV_OFFSET;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ── Call edge ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller: u32,          // proto index
    pub callee: u32,          // proto index or synthetic global ID
    pub call_pc: u32,         // instruction offset in caller
    pub is_tail: bool,
    pub is_method: bool,
    pub edge_kind: EdgeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    Direct,      // CALL/CALLT to known proto
    Closure,     // FNEW/CLOSURE creating a child proto
    Global,      // GGET-based call
    Upvalue,     // upvalue call
    Indirect,    // dynamic call, target unknown
}

// ── Upvalue reference ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpvalRef {
    pub proto_id: u32,
    pub upval_index: u8,
    pub captured_from_proto: Option<u32>,
    pub captured_reg: Option<u8>,
    pub name: Option<String>,
}

// ── Function graph ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionGraph {
    /// All proto nodes (`proto_id` → `NodeId`)
    pub nodes: BTreeMap<u32, NodeId>,
    /// All call edges
    pub edges: Vec<CallEdge>,
    /// Adjacency list: `caller` → `[callee]`
    pub adj_out: HashMap<u32, Vec<u32>>,
    /// Reverse adjacency: `callee` → `[caller]`
    pub adj_in: HashMap<u32, Vec<u32>>,
    /// Upvalue chains
    pub upval_refs: Vec<UpvalRef>,
    /// Strongly connected components (each SCC is a vec of proto IDs)
    pub sccs: Vec<Vec<u32>>,
    /// Dominator tree: `proto_id` → immediate dominator `proto_id`
    pub idom: HashMap<u32, u32>,
    /// Reachability from root: set of reachable proto IDs
    pub reachable: HashSet<u32>,
    pub root_proto: Option<u32>,
}

impl FunctionGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a proto node.
    pub fn add_proto(&mut self, id: u32, name: Option<String>) {
        self.nodes.insert(id, NodeId::proto(id, name));
        self.adj_out.entry(id).or_default();
        self.adj_in.entry(id).or_default();
    }

    /// Add a call edge.
    pub fn add_edge(&mut self, edge: CallEdge) {
        let caller = edge.caller;
        let callee_id = edge.callee;
        self.adj_out.entry(caller).or_default().push(callee_id);
        self.adj_in.entry(callee_id).or_default().push(caller);
        self.edges.push(edge);
    }

    /// Compute reachability from the root proto using BFS.
    pub fn compute_reachability(&mut self) {
        let Some(root) = self.root_proto else { return };
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(root);
        visited.insert(root);
        while let Some(node) = queue.pop_front() {
            if let Some(succs) = self.adj_out.get(&node) {
                for &succ in succs {
                    if visited.insert(succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
        self.reachable = visited;
    }

    /// Compute SCCs using Tarjan's algorithm.
    ///
    /// # Panics
    ///
    /// Panics if internal graph invariants are violated (should never occur with
    /// graphs constructed via `add_proto`/`add_edge`).
    pub fn compute_sccs(&mut self) {
        #[derive(Debug)]
        enum Action {
            Visit(u32),
            Process(u32, u32), // node, child
        }

        let nodes: Vec<u32> = self.nodes.keys().copied().collect();
        let mut index_counter = 0u32;
        let mut stack: Vec<u32> = Vec::new();
        let mut on_stack: HashSet<u32> = HashSet::new();
        let mut index: HashMap<u32, u32> = HashMap::new();
        let mut lowlink: HashMap<u32, u32> = HashMap::new();
        let mut sccs: Vec<Vec<u32>> = Vec::new();

        let adj_out = self.adj_out.clone();
        let mut work_stack: Vec<Action> = Vec::new();
        let mut child_iters: HashMap<u32, usize> = HashMap::new();

        for &start in &nodes {
            if index.contains_key(&start) {
                continue;
            }
            work_stack.push(Action::Visit(start));
            while let Some(action) = work_stack.last() {
                match action {
                    Action::Visit(v) => {
                        let v = *v;
                        work_stack.pop();
                        if index.contains_key(&v) {
                            continue;
                        }
                        index.insert(v, index_counter);
                        lowlink.insert(v, index_counter);
                        index_counter += 1;
                        stack.push(v);
                        on_stack.insert(v);
                        child_iters.insert(v, 0);
                        work_stack.push(Action::Process(v, 0));
                    }
                    Action::Process(v, ci_arg) => {
                        let v = *v;
                        let ci_arg = *ci_arg;
                        work_stack.pop();
                        let children: Vec<u32> = adj_out.get(&v).cloned().unwrap_or_default();
                        // Prefer the explicit child cursor carried by the Action;
                        // fall back to the auxiliary map for the initial Visit→Process
                        // transition which seeds the map with 0.
                        let ci = ci_arg as usize;
                        debug_assert_eq!(ci, *child_iters.get(&v).unwrap_or(&0));
                        if ci < children.len() {
                            *child_iters.entry(v).or_default() += 1;
                            work_stack.push(Action::Process(v, u32::try_from(ci + 1).unwrap_or(u32::MAX)));
                            let w = children[ci];
                            if !index.contains_key(&w) {
                                work_stack.push(Action::Visit(w));
                            } else if on_stack.contains(&w) {
                                let wl = *lowlink.get(&w).unwrap_or(&u32::MAX);
                                let vl = lowlink.entry(v).or_insert(u32::MAX);
                                if wl < *vl { *vl = wl; }
                            }
                        } else {
                            // All children processed — check SCC root
                            let vi = *index.get(&v).unwrap();
                            let vl = *lowlink.get(&v).unwrap();
                            if vl == vi {
                                let mut scc = Vec::new();
                                while let Some(&top) = stack.last() {
                                    stack.pop();
                                    on_stack.remove(&top);
                                    scc.push(top);
                                    if top == v { break; }
                                }
                                sccs.push(scc);
                            }
                            // Propagate lowlink to parent
                            if let Some(&parent) = work_stack.last().and_then(|a| {
                                if let Action::Process(p, _) = a { Some(p) } else { None }
                            }) {
                                let vl_val = *lowlink.get(&v).unwrap_or(&u32::MAX);
                                let pl = lowlink.entry(parent).or_insert(u32::MAX);
                                if vl_val < *pl { *pl = vl_val; }
                            }
                        }
                    }
                }
            }
        }

        self.sccs = sccs;
    }

    /// Find all recursive functions (in non-trivial SCCs).
    #[must_use]
    pub fn recursive_protos(&self) -> Vec<u32> {
        self.sccs
            .iter()
            .filter(|scc| scc.len() > 1 || (scc.len() == 1 && self.has_self_loop(scc[0])))
            .flatten()
            .copied()
            .collect()
    }

    fn has_self_loop(&self, node: u32) -> bool {
        self.adj_out
            .get(&node)
            .is_some_and(|succs| succs.contains(&node))
    }

    /// Callees of a given proto.
    #[must_use]
    pub fn callees(&self, proto_id: u32) -> Vec<u32> {
        self.adj_out.get(&proto_id).cloned().unwrap_or_default()
    }

    /// Callers of a given proto.
    #[must_use]
    pub fn callers(&self, proto_id: u32) -> Vec<u32> {
        self.adj_in.get(&proto_id).cloned().unwrap_or_default()
    }

    /// Total edge count.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Return the n most-called protos (by in-degree).
    #[must_use]
    pub fn top_callees(&self, n: usize) -> Vec<(u32, usize)> {
        let mut in_deg: Vec<(u32, usize)> = self
            .adj_in
            .iter()
            .map(|(&id, callers)| (id, callers.len()))
            .collect();
        in_deg.sort_by(|a, b| b.1.cmp(&a.1));
        in_deg.truncate(n);
        in_deg
    }

    /// Return unreachable protos (not reachable from root).
    #[must_use]
    pub fn unreachable_protos(&self) -> Vec<u32> {
        if self.reachable.is_empty() {
            return vec![];
        }
        self.nodes
            .keys()
            .filter(|&&id| !self.reachable.contains(&id))
            .copied()
            .collect()
    }

    /// Compute dominator tree using simple iterative algorithm (Cooper et al.).
    ///
    /// # Panics
    ///
    /// Panics if internal graph invariants are violated (should never occur with
    /// graphs constructed via `add_proto`/`add_edge`).
    pub fn compute_dominators(&mut self) {
        let Some(root) = self.root_proto else { return };

        // BFS ordering
        let mut order: Vec<u32> = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(root);
        while let Some(n) = queue.pop_front() {
            if visited.insert(n) {
                order.push(n);
                if let Some(succs) = self.adj_out.get(&n) {
                    for &s in succs { queue.push_back(s); }
                }
            }
        }

        let order_idx: HashMap<u32, usize> = order.iter().enumerate().map(|(i, &n)| (n, i)).collect();
        let mut idom: HashMap<u32, u32> = HashMap::new();
        idom.insert(root, root);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in order.iter().skip(1) {
                let preds: Vec<u32> = self.adj_in.get(&b).cloned().unwrap_or_default();
                let processed: Vec<u32> = preds.iter().filter(|&&p| idom.contains_key(&p)).copied().collect();
                if processed.is_empty() { continue; }

                let mut new_idom = *processed.iter().min_by_key(|&p| order_idx.get(p).unwrap_or(&usize::MAX)).unwrap();
                for &p in &processed {
                    if p != new_idom && idom.contains_key(&p) {
                        new_idom = intersect(new_idom, p, &idom, &order_idx);
                    }
                }
                if idom.get(&b) != Some(&new_idom) {
                    idom.insert(b, new_idom);
                    changed = true;
                }
            }
        }
        idom.remove(&root);
        self.idom = idom;
    }

    /// Return stats.
    #[must_use]
    pub fn stats(&self) -> GraphStats {
        GraphStats {
            node_count: self.nodes.len(),
            edge_count: self.edges.len(),
            scc_count: self.sccs.len(),
            recursive_count: self.recursive_protos().len(),
            reachable_count: self.reachable.len(),
            unreachable_count: self.unreachable_protos().len(),
            tail_call_count: self.edges.iter().filter(|e| e.is_tail).count(),
            closure_count: self.edges.iter().filter(|e| e.edge_kind == EdgeKind::Closure).count(),
        }
    }
}

fn intersect(mut a: u32, mut b: u32, idom: &HashMap<u32, u32>, order: &HashMap<u32, usize>) -> u32 {
    while a != b {
        let oa = order.get(&a).copied().unwrap_or(usize::MAX);
        let ob = order.get(&b).copied().unwrap_or(usize::MAX);
        if oa > ob {
            a = *idom.get(&a).unwrap_or(&a);
        } else {
            b = *idom.get(&b).unwrap_or(&b);
        }
    }
    a
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub scc_count: usize,
    pub recursive_count: usize,
    pub reachable_count: usize,
    pub unreachable_count: usize,
    pub tail_call_count: usize,
    pub closure_count: usize,
}

// ── Graph builder from JitDump ────────────────────────────────────────────────

/// `LuaJIT` 2.x opcode IDs for call/closure detection.
/// These are approximate positions in the opcode table.
pub const LJX_FNEW: u8 = 0x32; // FNEW (approx)
pub const LJX_CALL: u8 = 0x41;
pub const LJX_CALLM: u8 = 0x40;
pub const LJX_CALLMT: u8 = 0x42;
pub const LJX_CALLT: u8 = 0x43;
pub const LJX_GGET: u8 = 0x35;
pub const LJX_UGET: u8 = 0x2C;

/// Returns `true` if `op` is one of the `LuaJIT` call-family opcodes
/// (`CALL`, `CALLM`, `CALLT`, `CALLMT`).
#[must_use]
pub const fn is_ljx_call_op(op: u8) -> bool {
    matches!(op, LJX_CALL | LJX_CALLM | LJX_CALLMT | LJX_CALLT)
}

/// Returns `true` if `op` is a `LuaJIT` global/upvalue load (`GGET`/`UGET`).
#[must_use]
pub const fn is_ljx_global_or_upval_load(op: u8) -> bool {
    matches!(op, LJX_GGET | LJX_UGET)
}

pub struct JitGraphBuilder<'a> {
    dump: &'a crate::luajit_loader::JitDump,
}

impl<'a> JitGraphBuilder<'a> {
    #[must_use]
    pub const fn new(dump: &'a crate::luajit_loader::JitDump) -> Self {
        Self { dump }
    }

    #[must_use]
    pub fn build(&self) -> FunctionGraph {
        let mut graph = FunctionGraph::new();

        // Add all proto nodes
        for proto in &self.dump.protos {
            graph.add_proto(proto.id, proto.name.clone());
        }
        graph.root_proto = self.dump.root_proto_id;

        // Scan instructions for FNEW (closure creation) and CALL variants
        for proto in &self.dump.protos {
            for (pc, instr) in proto.instructions.iter().enumerate() {
                let op = instr.op;
                let pc = u32::try_from(pc).unwrap_or(u32::MAX);

                if op == LJX_FNEW || crate::luajit_loader::opcode_name(op) == "FNEW" {
                    // FNEW A, D: create closure from proto table[D]
                    let child_id = u32::from(instr.d);
                    if child_id < u32::try_from(self.dump.protos.len()).unwrap_or(u32::MAX) {
                        graph.add_edge(CallEdge {
                            caller: proto.id,
                            callee: child_id,
                            call_pc: pc,
                            is_tail: false,
                            is_method: false,
                            edge_kind: EdgeKind::Closure,
                        });
                    }
                } else if crate::luajit_loader::is_call_op(op) {
                    let is_tail = matches!(
                        crate::luajit_loader::opcode_name(op),
                        "CALLMT" | "CALLT"
                    );
                    // A = base register — we can't always resolve to a specific proto
                    // so emit an indirect edge unless we can trace it
                    graph.add_edge(CallEdge {
                        caller: proto.id,
                        callee: u32::MAX, // unknown
                        call_pc: pc,
                        is_tail,
                        is_method: false,
                        edge_kind: EdgeKind::Indirect,
                    });
                } else if crate::luajit_loader::opcode_name(op) == "GGET" {
                    // GGET A, D: load global string constant at KGC[D]
                    // emit a global reference edge
                    let kgc_idx = instr.d as usize;
                    if let Some(crate::luajit_loader::KgcConst::Str(name)) =
                        proto.kgc.get(kgc_idx)
                    {
                        let global_id = u32::try_from(fnv_hash(name.as_bytes())).unwrap_or(u32::MAX);
                        graph.nodes.entry(global_id).or_insert_with(|| NodeId::global(name));
                        graph.adj_out.entry(global_id).or_default();
                        graph.adj_in.entry(global_id).or_default();
                        graph.add_edge(CallEdge {
                            caller: proto.id,
                            callee: global_id,
                            call_pc: pc,
                            is_tail: false,
                            is_method: false,
                            edge_kind: EdgeKind::Global,
                        });
                    }
                }
            }

            // Upvalue references
            for (idx, uv) in proto.upvalues.iter().enumerate() {
                if uv.on_stack {
                    graph.upval_refs.push(UpvalRef {
                        proto_id: proto.id,
                        upval_index: u8::try_from(idx).unwrap_or(u8::MAX),
                        captured_from_proto: proto.parent_id,
                        captured_reg: Some(uv.idx),
                        name: proto.debug_upval_names.get(idx).cloned(),
                    });
                }
            }
        }

        // Remove placeholder indirect edges with callee = u32::MAX
        // (keep only resolved edges for clean graph; indirect edges are still tracked)
        // Actually, keep all — callers can filter by EdgeKind

        graph.compute_reachability();
        graph.compute_sccs();
        graph
    }
}

// ── Standard Lua graph builder ────────────────────────────────────────────────

/// Standard Lua 5.x opcodes for CLOSURE and CALL.
/// These vary by Lua version; we use 5.1 opcodes by default.
pub mod lua51_ops {
    pub const CLOSURE: u8 = 36;
    pub const CALL: u8 = 28;
    pub const TAILCALL: u8 = 29;
    pub const RETURN: u8 = 30;
    pub const GETGLOBAL: u8 = 5;
    pub const SETGLOBAL: u8 = 7;

    /// Returns `true` if `op` is `RETURN`.
    #[must_use]
    pub const fn is_return(op: u8) -> bool {
        op == RETURN
    }

    /// Returns `true` if `op` writes a global (`SETGLOBAL`).
    #[must_use]
    pub const fn is_setglobal(op: u8) -> bool {
        op == SETGLOBAL
    }
}

/// Minimal Lua 5.x instruction representation for graph building.
#[derive(Debug, Clone, Copy)]
pub struct Lua5Instr {
    pub op: u8,
    pub a: u32,
    pub bx: u32,
    pub sbx: i32,
    pub b: u32,
    pub c: u32,
}

impl Lua5Instr {
    const fn from_u32(v: u32) -> Self {
        let op = (v & 0x3F) as u8;
        let a = (v >> 6) & 0xFF;
        let b = (v >> 23) & 0x1FF;
        let c = (v >> 14) & 0x1FF;
        let bx = (v >> 14) & 0x3FFFF;
        let sbx = bx.cast_signed() - 131_071;
        Self { op, a, bx, sbx, b, c }
    }
}

/// `(proto_id, parent_id, instructions_u32, constants_str)` entry for [`build_lua5_graph`].
pub type ProtoEntry = (u32, Option<u32>, Vec<u32>, Vec<Option<String>>);

/// Build a call graph for standard Lua 5.x bytecode given a proto tree.
/// Each proto is represented as `(proto_id, parent_id, instructions_u32, constants_str)`.
#[must_use]
pub fn build_lua5_graph(
    protos: &[ProtoEntry],
    root_id: Option<u32>,
) -> FunctionGraph {
    let mut graph = FunctionGraph::new();

    for (id, _, _, _) in protos {
        graph.add_proto(*id, None);
    }
    graph.root_proto = root_id;

    for (id, _parent_id, instrs, constants) in protos {
        for (pc, &raw) in instrs.iter().enumerate() {
            let instr = Lua5Instr::from_u32(raw);
            let pc = u32::try_from(pc).unwrap_or(u32::MAX);

            match instr.op {
                op if op == lua51_ops::CLOSURE => {
                    // Bx = proto index in function table
                    let child_id = instr.bx;
                    if protos.iter().any(|(pid, _, _, _)| *pid == child_id) {
                        graph.add_edge(CallEdge {
                            caller: *id,
                            callee: child_id,
                            call_pc: pc,
                            is_tail: false,
                            is_method: false,
                            edge_kind: EdgeKind::Closure,
                        });
                    }
                }
                op if op == lua51_ops::CALL => {
                    graph.add_edge(CallEdge {
                        caller: *id,
                        callee: u32::MAX,
                        call_pc: pc,
                        is_tail: false,
                        is_method: false,
                        edge_kind: EdgeKind::Indirect,
                    });
                }
                op if op == lua51_ops::TAILCALL => {
                    graph.add_edge(CallEdge {
                        caller: *id,
                        callee: u32::MAX,
                        call_pc: pc,
                        is_tail: true,
                        is_method: false,
                        edge_kind: EdgeKind::Indirect,
                    });
                }
                op if op == lua51_ops::GETGLOBAL => {
                    // Bx = constant index → string name
                    if let Some(Some(name)) = constants.get(instr.bx as usize) {
                        let global_id = u32::try_from(fnv_hash(name.as_bytes())).unwrap_or(u32::MAX);
                        graph.nodes.entry(global_id).or_insert_with(|| NodeId::global(name));
                        graph.adj_out.entry(global_id).or_default();
                        graph.adj_in.entry(global_id).or_default();
                        graph.add_edge(CallEdge {
                            caller: *id,
                            callee: global_id,
                            call_pc: pc,
                            is_tail: false,
                            is_method: false,
                            edge_kind: EdgeKind::Global,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    graph.compute_reachability();
    graph.compute_sccs();
    graph
}

// ── Serialization helpers ─────────────────────────────────────────────────────

/// Export the call graph as a DOT digraph for visualization.
#[must_use]
pub fn graph_to_dot(graph: &FunctionGraph) -> String {
    let mut out = String::from("digraph luacallgraph {\n  rankdir=LR;\n");
    for (&id, node) in &graph.nodes {
        let label = node.display_name().replace('"', "'");
        let color = if graph.reachable.contains(&id) { "lightblue" } else { "gray" };
        writeln!(out, "  n{id} [label=\"{label}\", style=filled, fillcolor={color}];").unwrap();
    }
    for edge in &graph.edges {
        if edge.callee == u32::MAX { continue; }
        let style = match edge.edge_kind {
            EdgeKind::Closure => "dashed",
            EdgeKind::Global | EdgeKind::Upvalue => "dotted",
            _ => "solid",
        };
        let tail_label = if edge.is_tail { " [tail]" } else { "" };
        let (caller, callee_id, call_pc) = (edge.caller, edge.callee, edge.call_pc);
        writeln!(out, "  n{caller} -> n{callee_id} [style={style}, label=\"pc={call_pc}{tail_label}\"];").unwrap();
    }
    out.push_str("}\n");
    out
}

/// Export as JSON for programmatic consumption.
///
/// # Errors
///
/// Returns an error if JSON serialization fails.
pub fn graph_to_json(graph: &FunctionGraph) -> Result<String> {
    Ok(serde_json::to_string_pretty(graph)?)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_two_node_graph() -> FunctionGraph {
        let mut g = FunctionGraph::new();
        g.add_proto(0, Some("main".to_owned()));
        g.add_proto(1, Some("helper".to_owned()));
        g.root_proto = Some(0);
        g.add_edge(CallEdge {
            caller: 0,
            callee: 1,
            call_pc: 5,
            is_tail: false,
            is_method: false,
            edge_kind: EdgeKind::Direct,
        });
        g.compute_reachability();
        g.compute_sccs();
        g
    }

    #[test]
    fn test_reachability() {
        let g = simple_two_node_graph();
        assert!(g.reachable.contains(&0));
        assert!(g.reachable.contains(&1));
    }

    #[test]
    fn test_callees() {
        let g = simple_two_node_graph();
        assert_eq!(g.callees(0), vec![1]);
    }

    #[test]
    fn test_callers() {
        let g = simple_two_node_graph();
        assert_eq!(g.callers(1), vec![0]);
    }

    #[test]
    fn test_edge_count() {
        let g = simple_two_node_graph();
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn test_self_loop_detection() {
        let mut g = FunctionGraph::new();
        g.add_proto(0, None);
        g.root_proto = Some(0);
        g.add_edge(CallEdge {
            caller: 0, callee: 0, call_pc: 3,
            is_tail: true, is_method: false,
            edge_kind: EdgeKind::Direct,
        });
        g.compute_sccs();
        let rec = g.recursive_protos();
        assert!(rec.contains(&0));
    }

    #[test]
    fn test_node_display_name() {
        let node = NodeId::proto(42, Some("fib".to_owned()));
        assert_eq!(node.display_name(), "fib");

        let anon = NodeId::proto(7, None);
        assert_eq!(anon.display_name(), "<proto#7>");
    }

    #[test]
    fn test_dot_output() {
        let g = simple_two_node_graph();
        let dot = graph_to_dot(&g);
        assert!(dot.contains("digraph"));
        assert!(dot.contains("main"));
        assert!(dot.contains("helper"));
    }

    #[test]
    fn test_stats() {
        let g = simple_two_node_graph();
        let stats = g.stats();
        assert_eq!(stats.node_count, 2);
        assert_eq!(stats.edge_count, 1);
    }

    #[test]
    fn test_top_callees() {
        let g = simple_two_node_graph();
        let top = g.top_callees(5);
        assert!(!top.is_empty());
        assert_eq!(top[0].0, 1); // node 1 is called once
    }

    #[test]
    fn test_lua5_graph_empty() {
        let graph = build_lua5_graph(&[], None);
        assert_eq!(graph.edge_count(), 0);
        assert_eq!(graph.nodes.len(), 0);
    }

    #[test]
    fn test_fnv_hash_deterministic() {
        let h1 = fnv_hash(b"hello");
        let h2 = fnv_hash(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(fnv_hash(b"hello"), fnv_hash(b"world"));
    }
}
