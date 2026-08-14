// cil_call_graph.rs — Build a call graph from CIL method bodies

use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cil_decoder::{DecodedCilInstr, Opcode};

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CallGraphError {
    #[error("method token {0:#x} not found in resolver")]
    UnknownToken(u32),
    #[error("circular dependency while resolving {0}")]
    Circular(String),
    #[error("decode error: {0}")]
    Decode(String),
}

// ─── Method signature / identity ─────────────────────────────────────────────

/// A fully-qualified method signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MethodSig {
    /// Declaring type (e.g. "System.Console").
    pub declaring_type: String,
    /// Method name (e.g. "WriteLine").
    pub name: String,
    /// Return type as a string (e.g. "void", "int32").
    pub return_type: String,
    /// Parameter types in order.
    pub param_types: Vec<String>,
    /// True if this is an instance method (has `this`).
    pub is_instance: bool,
    /// True if this is a virtual method.
    pub is_virtual: bool,
    /// True if this is generic.
    pub is_generic: bool,
    /// Number of generic parameters (0 if non-generic).
    pub generic_param_count: u8,
}

impl MethodSig {
    pub fn new(declaring_type: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            declaring_type: declaring_type.into(),
            name: name.into(),
            return_type: "void".to_string(),
            param_types: vec![],
            is_instance: false,
            is_virtual: false,
            is_generic: false,
            generic_param_count: 0,
        }
    }

    /// Display as `DeclaringType::Name(params) -> ReturnType`.
    pub fn display(&self) -> String {
        let params = self.param_types.join(", ");
        format!(
            "{}::{}({}) -> {}",
            self.declaring_type, self.name, params, self.return_type
        )
    }
}

// ─── Call site ───────────────────────────────────────────────────────────────

/// One call instruction within a method body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    /// Byte offset of the call instruction.
    pub offset: u32,
    /// The raw metadata token operand (MethodDef/MethodRef/MemberRef).
    pub token: u32,
    /// Resolved method signature (None if token could not be resolved).
    pub target: Option<MethodSig>,
    /// Kind of call.
    pub call_kind: CallKind,
    /// True if the call was a tail call (prefixed with `tail.`).
    pub is_tail: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallKind {
    /// `call` — direct call.
    Direct,
    /// `callvirt` — virtual dispatch.
    Virtual,
    /// `calli` — indirect call through function pointer.
    Indirect,
    /// `newobj` — constructor call.
    NewObj,
    /// `ldftn` / `ldvirtftn` — take function pointer without calling.
    FunctionPointer,
}

// ─── Call graph node ─────────────────────────────────────────────────────────

/// One node in the call graph — represents a single method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    /// Unique node identifier (auto-assigned).
    pub id: usize,
    /// Method signature for this node.
    pub sig: MethodSig,
    /// Metadata token for this method (MethodDef).
    pub token: u32,
    /// All call sites within this method's body.
    pub call_sites: Vec<CallSite>,
    /// Set of node IDs this method directly calls.
    pub callees: HashSet<usize>,
    /// Set of node IDs that directly call this method.
    pub callers: HashSet<usize>,
    /// True if this method is a root (has no callers in the graph).
    pub is_root: bool,
    /// True if this method is a leaf (makes no calls to methods in the graph).
    pub is_leaf: bool,
    /// Approximate depth from the nearest root (BFS distance).
    pub depth_from_root: Option<u32>,
}

impl CallGraphNode {
    pub fn new(id: usize, sig: MethodSig, token: u32) -> Self {
        Self {
            id,
            sig,
            token,
            call_sites: vec![],
            callees: HashSet::new(),
            callers: HashSet::new(),
            is_root: true,
            is_leaf: true,
            depth_from_root: None,
        }
    }

    pub fn callee_count(&self) -> usize {
        self.callees.len()
    }

    pub fn caller_count(&self) -> usize {
        self.callers.len()
    }

    /// All call sites targeting a specific node ID.
    pub fn call_sites_to(&self, target_id: usize) -> Vec<&CallSite> {
        self.call_sites
            .iter()
            .filter(|cs| {
                cs.target
                    .as_ref()
                    .map(|_| self.callees.contains(&target_id))
                    .unwrap_or(false)
            })
            .collect()
    }
}

// ─── Call graph ──────────────────────────────────────────────────────────────

/// Full inter-procedural call graph for a CIL assembly (or module).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CilCallGraph {
    pub nodes: Vec<CallGraphNode>,
    /// Map from metadata token → node index.
    #[serde(skip)]
    pub token_to_node: HashMap<u32, usize>,
    /// Map from display signature → node index.
    #[serde(skip)]
    pub sig_to_node: HashMap<String, usize>,
    /// Unresolved call tokens encountered during construction.
    pub unresolved_tokens: Vec<u32>,
    /// Virtual call sites that could not be devirtualised.
    pub unresolved_virtual_calls: Vec<CallSite>,
}

impl CilCallGraph {
    pub fn new() -> Self {
        Self {
            nodes: vec![],
            token_to_node: HashMap::new(),
            sig_to_node: HashMap::new(),
            unresolved_tokens: vec![],
            unresolved_virtual_calls: vec![],
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.nodes.iter().map(|n| n.callees.len()).sum()
    }

    pub fn root_nodes(&self) -> Vec<&CallGraphNode> {
        self.nodes.iter().filter(|n| n.is_root).collect()
    }

    pub fn leaf_nodes(&self) -> Vec<&CallGraphNode> {
        self.nodes.iter().filter(|n| n.is_leaf).collect()
    }

    /// Nodes that are both root and leaf (isolated).
    pub fn isolated_nodes(&self) -> Vec<&CallGraphNode> {
        self.nodes
            .iter()
            .filter(|n| n.is_root && n.is_leaf)
            .collect()
    }

    pub fn node_by_token(&self, token: u32) -> Option<&CallGraphNode> {
        self.token_to_node.get(&token).and_then(|&i| self.nodes.get(i))
    }

    pub fn node_by_sig(&self, sig: &str) -> Option<&CallGraphNode> {
        self.sig_to_node.get(sig).and_then(|&i| self.nodes.get(i))
    }

    /// BFS reachability: all nodes reachable from `start_id` (inclusive).
    pub fn reachable_from(&self, start_id: usize) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_id);
        while let Some(id) = queue.pop_front() {
            if visited.insert(id) {
                for &callee in &self.nodes[id].callees {
                    queue.push_back(callee);
                }
            }
        }
        visited
    }

    /// Reverse reachability: all nodes from which `target_id` is reachable.
    pub fn can_reach(&self, target_id: usize) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(target_id);
        while let Some(id) = queue.pop_front() {
            if visited.insert(id) {
                for &caller in &self.nodes[id].callers {
                    queue.push_back(caller);
                }
            }
        }
        visited
    }

    /// Depth-first post-order traversal from entry nodes.
    pub fn post_order(&self) -> Vec<usize> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        for root in self.root_nodes().iter().map(|n| n.id).collect::<Vec<_>>() {
            self.dfs_post(root, &mut visited, &mut order);
        }
        // Also visit any unvisited nodes (not reachable from roots).
        for i in 0..self.nodes.len() {
            if !visited.contains(&i) {
                self.dfs_post(i, &mut visited, &mut order);
            }
        }
        order
    }

    fn dfs_post(&self, id: usize, visited: &mut HashSet<usize>, out: &mut Vec<usize>) {
        if !visited.insert(id) {
            return;
        }
        for &callee in &self.nodes[id].callees {
            self.dfs_post(callee, visited, out);
        }
        out.push(id);
    }

    /// Detect strongly connected components (Tarjan's SCC).
    pub fn sccs(&self) -> Vec<Vec<usize>> {
        let n = self.nodes.len();
        let mut index_counter = 0u32;
        let mut stack: Vec<usize> = Vec::new();
        let mut on_stack = vec![false; n];
        let mut index = vec![u32::MAX; n];
        let mut lowlink = vec![0u32; n];
        let mut result: Vec<Vec<usize>> = Vec::new();

        for start in 0..n {
            if index[start] == u32::MAX {
                strongconnect(
                    start,
                    &self.nodes,
                    &mut index_counter,
                    &mut stack,
                    &mut on_stack,
                    &mut index,
                    &mut lowlink,
                    &mut result,
                );
            }
        }
        result
    }

    /// Returns only SCCs with more than one node (i.e., mutually recursive groups).
    pub fn recursive_groups(&self) -> Vec<Vec<usize>> {
        self.sccs().into_iter().filter(|scc| scc.len() > 1).collect()
    }

    /// Compute call depth from roots (BFS).
    pub fn compute_depths(&mut self) {
        let roots: Vec<usize> = self.nodes.iter().filter(|n| n.is_root).map(|n| n.id).collect();
        let mut queue: VecDeque<(usize, u32)> = roots.into_iter().map(|id| (id, 0)).collect();
        let mut visited = HashSet::new();
        while let Some((id, depth)) = queue.pop_front() {
            if !visited.insert(id) {
                continue;
            }
            self.nodes[id].depth_from_root = Some(depth);
            let callees: Vec<usize> = self.nodes[id].callees.iter().copied().collect();
            for callee in callees {
                queue.push_back((callee, depth + 1));
            }
        }
    }

    /// Maximum call depth observed (after `compute_depths`).
    pub fn max_depth(&self) -> Option<u32> {
        self.nodes.iter().filter_map(|n| n.depth_from_root).max()
    }
}

impl Default for CilCallGraph {
    fn default() -> Self {
        Self::new()
    }
}

// Tarjan helper.
#[allow(clippy::too_many_arguments)]
fn strongconnect(
    v: usize,
    nodes: &[CallGraphNode],
    counter: &mut u32,
    stack: &mut Vec<usize>,
    on_stack: &mut Vec<bool>,
    index: &mut Vec<u32>,
    lowlink: &mut Vec<u32>,
    result: &mut Vec<Vec<usize>>,
) {
    index[v] = *counter;
    lowlink[v] = *counter;
    *counter += 1;
    stack.push(v);
    on_stack[v] = true;

    for &w in &nodes[v].callees {
        if index[w] == u32::MAX {
            strongconnect(w, nodes, counter, stack, on_stack, index, lowlink, result);
            lowlink[v] = lowlink[v].min(lowlink[w]);
        } else if on_stack[w] {
            lowlink[v] = lowlink[v].min(index[w]);
        }
    }

    if lowlink[v] == index[v] {
        let mut scc = Vec::new();
        loop {
            let w = stack.pop().unwrap();
            on_stack[w] = false;
            scc.push(w);
            if w == v {
                break;
            }
        }
        result.push(scc);
    }
}

// ─── Call graph builder ───────────────────────────────────────────────────────

/// Resolves a method token to a `MethodSig`.
pub trait TokenResolver {
    fn resolve(&self, token: u32) -> Option<MethodSig>;
}

/// Simple HashMap-backed resolver for testing.
pub struct MapResolver(pub HashMap<u32, MethodSig>);

impl TokenResolver for MapResolver {
    fn resolve(&self, token: u32) -> Option<MethodSig> {
        self.0.get(&token).cloned()
    }
}

/// Builds a `CilCallGraph` by analysing CIL instruction streams.
pub struct CallGraphBuilder<R: TokenResolver> {
    resolver: R,
    graph: CilCallGraph,
    /// Whether to attempt CHA-based devirtualisation.
    devirtualize: bool,
    /// Type hierarchy for CHA (type name → list of subtypes).
    type_hierarchy: HashMap<String, Vec<String>>,
}

impl<R: TokenResolver> CallGraphBuilder<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            graph: CilCallGraph::new(),
            devirtualize: false,
            type_hierarchy: HashMap::new(),
        }
    }

    pub fn with_devirtualization(mut self, hierarchy: HashMap<String, Vec<String>>) -> Self {
        self.devirtualize = true;
        self.type_hierarchy = hierarchy;
        self
    }

    /// Register a method without processing its body.
    pub fn add_method(&mut self, sig: MethodSig, token: u32) -> usize {
        let key = sig.display();
        if let Some(&id) = self.graph.sig_to_node.get(&key) {
            return id;
        }
        let id = self.graph.nodes.len();
        self.graph.nodes.push(CallGraphNode::new(id, sig, token));
        self.graph.token_to_node.insert(token, id);
        self.graph.sig_to_node.insert(key, id);
        id
    }

    /// Process one method body: scan `instrs` for call instructions and wire edges.
    pub fn process_method(
        &mut self,
        caller_token: u32,
        instrs: &[DecodedCilInstr],
    ) -> Result<(), CallGraphError> {
        let caller_id = match self.graph.token_to_node.get(&caller_token) {
            Some(&id) => id,
            None => return Err(CallGraphError::UnknownToken(caller_token)),
        };

        let mut tail_prefix = false;

        for instr in instrs {
            let call_kind = match instr.opcode {
                Opcode::Tailprefix => {
                    tail_prefix = true;
                    continue;
                }
                Opcode::Call => CallKind::Direct,
                Opcode::Callvirt => CallKind::Virtual,
                Opcode::Calli => CallKind::Indirect,
                Opcode::Newobj => CallKind::NewObj,
                Opcode::Ldftn | Opcode::Ldvirtftn => CallKind::FunctionPointer,
                _ => {
                    tail_prefix = false;
                    continue;
                }
            };

            let is_tail = tail_prefix;
            tail_prefix = false;

            let token = match instr.method_token() {
                Some(t) => t,
                None => {
                    // `calli` uses a signature token, not a method token.
                    let site = CallSite {
                        offset: instr.offset,
                        token: 0,
                        target: None,
                        call_kind,
                        is_tail,
                    };
                    self.graph.nodes[caller_id].call_sites.push(site);
                    continue;
                }
            };

            let resolved = self.resolver.resolve(token);
            if resolved.is_none() {
                self.graph.unresolved_tokens.push(token);
            }

            let target_id = resolved.as_ref().map(|sig| {
                let key = sig.display();
                if let Some(&id) = self.graph.sig_to_node.get(&key) {
                    id
                } else {
                    let id = self.graph.nodes.len();
                    self.graph
                        .nodes
                        .push(CallGraphNode::new(id, sig.clone(), token));
                    self.graph.token_to_node.insert(token, id);
                    self.graph.sig_to_node.insert(key, id);
                    id
                }
            });

            // For virtual calls, attempt CHA devirtualisation.
            let virtual_targets: Vec<usize> = if call_kind == CallKind::Virtual
                && self.devirtualize
            {
                if let Some(ref sig) = resolved {
                    if let Some(subtypes) = self.type_hierarchy.get(&sig.declaring_type) {
                        subtypes
                            .iter()
                            .filter_map(|sub| {
                                let mut subsig = sig.clone();
                                subsig.declaring_type = sub.clone();
                                let key = subsig.display();
                                self.graph.sig_to_node.get(&key).copied()
                            })
                            .collect()
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            let site = CallSite {
                offset: instr.offset,
                token,
                target: resolved,
                call_kind,
                is_tail,
            };

            if let Some(tid) = target_id {
                self.graph.nodes[caller_id].callees.insert(tid);
                self.graph.nodes[tid].callers.insert(caller_id);
                self.graph.nodes[tid].is_root = false;
                self.graph.nodes[caller_id].is_leaf = false;
            } else if call_kind == CallKind::Virtual {
                self.graph.unresolved_virtual_calls.push(site.clone());
            }

            // Wire additional virtual targets from CHA.
            for vid in virtual_targets {
                self.graph.nodes[caller_id].callees.insert(vid);
                self.graph.nodes[vid].callers.insert(caller_id);
                self.graph.nodes[vid].is_root = false;
                self.graph.nodes[caller_id].is_leaf = false;
            }

            self.graph.nodes[caller_id].call_sites.push(site);
        }

        Ok(())
    }

    pub fn finish(mut self) -> CilCallGraph {
        self.graph.compute_depths();
        self.graph
    }
}

// ─── Graph statistics ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub root_count: usize,
    pub leaf_count: usize,
    pub isolated_count: usize,
    pub recursive_group_count: usize,
    pub max_callers: usize,
    pub max_callees: usize,
    pub max_depth: Option<u32>,
    pub unresolved_token_count: usize,
    pub unresolved_virtual_count: usize,
}

impl CallGraphStats {
    pub fn from(cg: &CilCallGraph) -> Self {
        Self {
            node_count: cg.node_count(),
            edge_count: cg.edge_count(),
            root_count: cg.root_nodes().len(),
            leaf_count: cg.leaf_nodes().len(),
            isolated_count: cg.isolated_nodes().len(),
            recursive_group_count: cg.recursive_groups().len(),
            max_callers: cg.nodes.iter().map(|n| n.caller_count()).max().unwrap_or(0),
            max_callees: cg.nodes.iter().map(|n| n.callee_count()).max().unwrap_or(0),
            max_depth: cg.max_depth(),
            unresolved_token_count: cg.unresolved_tokens.len(),
            unresolved_virtual_count: cg.unresolved_virtual_calls.len(),
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cil_decoder::{DecodedCilInstr, Opcode, Operand};

    fn make_sig(ty: &str, name: &str) -> MethodSig {
        MethodSig::new(ty, name)
    }

    fn call_instr(offset: u32, token: u32) -> DecodedCilInstr {
        DecodedCilInstr {
            offset,
            size: 5,
            opcode: Opcode::Call,
            operand: Operand::MethodToken(token),
        }
    }

    fn callvirt_instr(offset: u32, token: u32) -> DecodedCilInstr {
        DecodedCilInstr {
            offset,
            size: 5,
            opcode: Opcode::Callvirt,
            operand: Operand::MethodToken(token),
        }
    }

    fn ret_instr() -> DecodedCilInstr {
        DecodedCilInstr { offset: 99, size: 1, opcode: Opcode::Ret, operand: Operand::None }
    }

    fn builder_with_two_methods() -> CallGraphBuilder<MapResolver> {
        let mut map = HashMap::new();
        map.insert(0x0A00_0001u32, make_sig("Foo", "Bar"));
        map.insert(0x0A00_0002u32, make_sig("Foo", "Baz"));
        let resolver = MapResolver(map);
        let mut b = CallGraphBuilder::new(resolver);
        b.add_method(make_sig("Main", "Run"), 0x0600_0001);
        b.add_method(make_sig("Foo", "Bar"), 0x0A00_0001);
        b.add_method(make_sig("Foo", "Baz"), 0x0A00_0002);
        b
    }

    #[test]
    fn test_add_method() {
        let b = builder_with_two_methods();
        let cg = b.finish();
        assert_eq!(cg.node_count(), 3);
    }

    #[test]
    fn test_process_method_wires_edge() {
        let mut b = builder_with_two_methods();
        let instrs = vec![call_instr(0, 0x0A00_0001), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        let caller = cg.node_by_token(0x0600_0001).unwrap();
        let callee = cg.node_by_token(0x0A00_0001).unwrap();
        assert!(caller.callees.contains(&callee.id));
        assert!(callee.callers.contains(&caller.id));
    }

    #[test]
    fn test_root_and_leaf_flags() {
        let mut b = builder_with_two_methods();
        let instrs = vec![call_instr(0, 0x0A00_0001), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        let main = cg.node_by_token(0x0600_0001).unwrap();
        let bar = cg.node_by_token(0x0A00_0001).unwrap();
        assert!(main.is_root);
        assert!(!main.is_leaf);
        assert!(!bar.is_root);
        assert!(bar.is_leaf);
    }

    #[test]
    fn test_reachable_from() {
        let mut b = builder_with_two_methods();
        let instrs = vec![call_instr(0, 0x0A00_0001), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        let main_id = cg.node_by_token(0x0600_0001).unwrap().id;
        let reachable = cg.reachable_from(main_id);
        assert!(reachable.len() >= 2);
    }

    #[test]
    fn test_can_reach() {
        let mut b = builder_with_two_methods();
        let instrs = vec![call_instr(0, 0x0A00_0001), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        let bar_id = cg.node_by_token(0x0A00_0001).unwrap().id;
        let callers = cg.can_reach(bar_id);
        let main_id = cg.node_by_token(0x0600_0001).unwrap().id;
        assert!(callers.contains(&main_id));
    }

    #[test]
    fn test_unresolved_token_recorded() {
        let map = HashMap::new();
        let resolver = MapResolver(map);
        let mut b = CallGraphBuilder::new(resolver);
        b.add_method(make_sig("X", "Y"), 0x0600_0001);
        let instrs = vec![call_instr(0, 0xDEAD_BEEF), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        assert!(!cg.unresolved_tokens.is_empty());
    }

    #[test]
    fn test_scc_single_nodes() {
        let mut b = builder_with_two_methods();
        let instrs = vec![call_instr(0, 0x0A00_0001), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        let sccs = cg.sccs();
        // No recursion, each node in its own SCC.
        assert_eq!(sccs.len(), cg.node_count());
    }

    #[test]
    fn test_recursive_group() {
        let mut map = HashMap::new();
        map.insert(0x0A00_0001u32, make_sig("A", "F"));
        map.insert(0x0A00_0002u32, make_sig("B", "G"));
        let resolver = MapResolver(map);
        let mut b = CallGraphBuilder::new(resolver);
        b.add_method(make_sig("A", "F"), 0x0A00_0001);
        b.add_method(make_sig("B", "G"), 0x0A00_0002);
        // A calls B, B calls A — mutual recursion.
        b.process_method(0x0A00_0001, &[call_instr(0, 0x0A00_0002), ret_instr()])
            .unwrap();
        b.process_method(0x0A00_0002, &[call_instr(0, 0x0A00_0001), ret_instr()])
            .unwrap();
        let cg = b.finish();
        let rec = cg.recursive_groups();
        assert!(!rec.is_empty());
    }

    #[test]
    fn test_stats() {
        let mut b = builder_with_two_methods();
        let instrs = vec![call_instr(0, 0x0A00_0001), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        let stats = CallGraphStats::from(&cg);
        assert_eq!(stats.node_count, 3);
        assert!(stats.edge_count >= 1);
    }

    #[test]
    fn test_method_sig_display() {
        let mut sig = make_sig("System.Console", "WriteLine");
        sig.param_types = vec!["string".to_string()];
        sig.return_type = "void".to_string();
        let d = sig.display();
        assert!(d.contains("System.Console"));
        assert!(d.contains("WriteLine"));
    }

    #[test]
    fn test_post_order_covers_all_nodes() {
        let mut b = builder_with_two_methods();
        let instrs = vec![call_instr(0, 0x0A00_0001), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        let po = cg.post_order();
        assert_eq!(po.len(), cg.node_count());
    }

    #[test]
    fn test_isolated_nodes() {
        let map = HashMap::new();
        let resolver = MapResolver(map);
        let mut b = CallGraphBuilder::new(resolver);
        b.add_method(make_sig("X", "Standalone"), 0x0600_0001);
        let cg = b.finish();
        assert_eq!(cg.isolated_nodes().len(), 1);
    }

    #[test]
    fn test_virtual_call_unresolved_tracked() {
        let map = HashMap::new();
        let resolver = MapResolver(map);
        let mut b = CallGraphBuilder::new(resolver);
        b.add_method(make_sig("Caller", "M"), 0x0600_0001);
        let instrs = vec![callvirt_instr(0, 0xDEAD_0001), ret_instr()];
        b.process_method(0x0600_0001, &instrs).unwrap();
        let cg = b.finish();
        assert!(!cg.unresolved_virtual_calls.is_empty());
    }
}
