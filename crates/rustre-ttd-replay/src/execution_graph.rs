//! Build and analyze an execution graph from a TTD trace.
//!
//! Nodes are basic-block entry addresses; edges are transitions (fall-through,
//! taken branch, call, return). Annotated with execution counts from the trace.
//! Includes loop detection and a dominance tree computed over actual execution.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use rustre_ttd::{EventKind, TracePosition, TtdTrace};

// ─── ExecEdgeKind ─────────────────────────────────────────────────────────────

/// The kind of a transition edge in the execution graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecEdgeKind {
    /// Sequential fall-through between blocks.
    FallThrough,
    /// Branch taken.
    Branch,
    /// Function call edge.
    Call,
    /// Return from function.
    Return,
    /// Exception / signal delivery.
    Exception,
}

impl fmt::Display for ExecEdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FallThrough => write!(f, "fallthrough"),
            Self::Branch => write!(f, "branch"),
            Self::Call => write!(f, "call"),
            Self::Return => write!(f, "return"),
            Self::Exception => write!(f, "exception"),
        }
    }
}

// ─── ExecEdge ─────────────────────────────────────────────────────────────────

/// A directed edge between two basic-block nodes in the execution graph.
#[derive(Debug, Clone)]
pub struct ExecEdge {
    /// Source node (block entry address).
    pub from: u64,
    /// Destination node (block entry address).
    pub to: u64,
    /// Number of times this transition occurred.
    pub count: u64,
    /// Semantic classification of the transition.
    pub kind: ExecEdgeKind,
    /// First trace position where this edge was observed.
    pub first_seen: TracePosition,
    /// Last trace position where this edge was observed.
    pub last_seen: TracePosition,
}

impl ExecEdge {
    #[must_use]
    pub const fn new(
        from: u64,
        to: u64,
        kind: ExecEdgeKind,
        first_seen: TracePosition,
    ) -> Self {
        Self {
            from,
            to,
            count: 1,
            kind,
            first_seen,
            last_seen: first_seen,
        }
    }
}

impl fmt::Display for ExecEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExecEdge {{ {:#x} --[{}]--> {:#x} × {} }}",
            self.from, self.kind, self.to, self.count
        )
    }
}

// ─── LoopExec ─────────────────────────────────────────────────────────────────

/// A detected loop in the execution graph (a back-edge and its iteration count).
#[derive(Debug, Clone)]
pub struct LoopExec {
    /// The header node of the loop (dominates all other nodes in the loop).
    pub header: u64,
    /// The node that has the back-edge to `header`.
    pub tail: u64,
    /// Number of times the loop body executed (number of back-edge traversals).
    pub iteration_count: u64,
    /// Set of node addresses that belong to the loop body.
    pub body_nodes: Vec<u64>,
    /// Trace position where the loop was first entered.
    pub first_entry: TracePosition,
}

impl fmt::Display for LoopExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Loop {{ header={:#x}, tail={:#x}, iters={}, body_size={} }}",
            self.header,
            self.tail,
            self.iteration_count,
            self.body_nodes.len()
        )
    }
}

// ─── ExecNode ─────────────────────────────────────────────────────────────────

/// A node in the execution graph representing a basic block.
#[derive(Debug, Clone)]
pub struct ExecNode {
    /// Entry address of the basic block.
    pub address: u64,
    /// Number of times this block was entered.
    pub exec_count: u64,
    /// Incoming edge source addresses.
    pub predecessors: Vec<u64>,
    /// Outgoing edge destination addresses.
    pub successors: Vec<u64>,
    /// First trace position where this node was entered.
    pub first_seen: TracePosition,
    /// Last trace position where this node was entered.
    pub last_seen: TracePosition,
    /// Whether this node is a function entry.
    pub is_call_target: bool,
    /// Whether this node is a return site.
    pub is_return_site: bool,
}

impl ExecNode {
    #[must_use]
    pub const fn new(address: u64, first_seen: TracePosition) -> Self {
        Self {
            address,
            exec_count: 1,
            predecessors: Vec::new(),
            successors: Vec::new(),
            first_seen,
            last_seen: first_seen,
            is_call_target: false,
            is_return_site: false,
        }
    }

    /// Return the ratio of executions of this node relative to `total`.
    #[must_use]
    pub fn exec_ratio(&self, total: u64) -> f64 {
        if total == 0 {
            0.0
        } else {
            self.exec_count as f64 / total as f64
        }
    }
}

impl fmt::Display for ExecNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExecNode {{ addr={:#x}, count={}, preds={}, succs={} }}",
            self.address,
            self.exec_count,
            self.predecessors.len(),
            self.successors.len()
        )
    }
}

// ─── ExecDominator ────────────────────────────────────────────────────────────

/// Entry in the dominance tree.
#[derive(Debug, Clone)]
pub struct ExecDominator {
    /// Node address.
    pub node: u64,
    /// Immediate dominator (None for the root / entry node).
    pub idom: Option<u64>,
    /// Children in the dominator tree.
    pub children: Vec<u64>,
    /// RPO (reverse post-order) number assigned during computation.
    pub rpo: u32,
}

impl fmt::Display for ExecDominator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExecDominator {{ node={:#x}, idom={:?} }}",
            self.node,
            self.idom.map(|a| format!("{a:#x}"))
        )
    }
}

// ─── ExecGraph ────────────────────────────────────────────────────────────────

/// Execution graph built from a TTD trace.
pub struct ExecGraph {
    /// Map from block address to node.
    pub nodes: BTreeMap<u64, ExecNode>,
    /// Map from (from, to) to edge.
    pub edges: HashMap<(u64, u64), ExecEdge>,
    /// Detected loops, sorted by header address.
    pub loops: Vec<LoopExec>,
    /// Dominance tree (computed lazily, or via `compute_dominators()`).
    pub dominators: BTreeMap<u64, ExecDominator>,
    /// The entry node address (first node seen in the trace).
    pub entry: u64,
    /// Total execution event count.
    pub total_transitions: u64,
}

impl ExecGraph {
    /// Build the execution graph from a TTD trace.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn build(trace: &TtdTrace) -> Self {
        let events = trace.all_events();
        let mut nodes: BTreeMap<u64, ExecNode> = BTreeMap::new();
        let mut edges: HashMap<(u64, u64), ExecEdge> = HashMap::new();
        let mut entry: u64 = 0;
        let mut total_transitions: u64 = 0;
        let mut found_entry = false;

        for event in &events {
            match &event.kind {
                EventKind::Call { from, to } => {
                    if !found_entry {
                        entry = *from;
                        found_entry = true;
                    }
                    // Ensure both nodes exist.
                    let from_node = nodes.entry(*from).or_insert_with(|| ExecNode::new(*from, event.position));
                    from_node.exec_count = from_node.exec_count.saturating_add(1);
                    from_node.last_seen = event.position;

                    let to_node = nodes.entry(*to).or_insert_with(|| ExecNode::new(*to, event.position));
                    to_node.exec_count = to_node.exec_count.saturating_add(1);
                    to_node.last_seen = event.position;
                    to_node.is_call_target = true;

                    // Add/update edge.
                    let edge = edges.entry((*from, *to)).or_insert_with(|| {
                        ExecEdge::new(*from, *to, ExecEdgeKind::Call, event.position)
                    });
                    edge.count += 1;
                    edge.last_seen = event.position;

                    // Predecessor/successor lists.
                    let from_node = nodes.get_mut(from).unwrap();
                    if !from_node.successors.contains(to) {
                        from_node.successors.push(*to);
                    }
                    let to_node = nodes.get_mut(to).unwrap();
                    if !to_node.predecessors.contains(from) {
                        to_node.predecessors.push(*from);
                    }
                    total_transitions += 1;
                }
                EventKind::Return { from, to } => {
                    let from_node = nodes.entry(*from).or_insert_with(|| ExecNode::new(*from, event.position));
                    from_node.exec_count = from_node.exec_count.saturating_add(1);
                    from_node.last_seen = event.position;
                    from_node.is_return_site = true;

                    let to_node = nodes.entry(*to).or_insert_with(|| ExecNode::new(*to, event.position));
                    to_node.exec_count = to_node.exec_count.saturating_add(1);
                    to_node.last_seen = event.position;

                    let edge = edges.entry((*from, *to)).or_insert_with(|| {
                        ExecEdge::new(*from, *to, ExecEdgeKind::Return, event.position)
                    });
                    edge.count += 1;
                    edge.last_seen = event.position;

                    let from_node = nodes.get_mut(from).unwrap();
                    if !from_node.successors.contains(to) {
                        from_node.successors.push(*to);
                    }
                    let to_node = nodes.get_mut(to).unwrap();
                    if !to_node.predecessors.contains(from) {
                        to_node.predecessors.push(*from);
                    }
                    total_transitions += 1;
                }
                EventKind::Exception { addr, .. } => {
                    let node = nodes.entry(*addr).or_insert_with(|| ExecNode::new(*addr, event.position));
                    node.exec_count = node.exec_count.saturating_add(1);
                    node.last_seen = event.position;
                }
                _ => {}
            }
        }

        let mut graph = Self {
            nodes,
            edges,
            loops: Vec::new(),
            dominators: BTreeMap::new(),
            entry,
            total_transitions,
        };
        graph.detect_loops();
        graph
    }

    // ── Node / edge accessors ─────────────────────────────────────────────────

    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    #[must_use]
    pub fn node(&self, addr: u64) -> Option<&ExecNode> {
        self.nodes.get(&addr)
    }

    #[must_use]
    pub fn edge(&self, from: u64, to: u64) -> Option<&ExecEdge> {
        self.edges.get(&(from, to))
    }

    /// Return the top-N hottest nodes by execution count.
    #[must_use]
    pub fn hot_nodes(&self, n: usize) -> Vec<&ExecNode> {
        let mut ns: Vec<&ExecNode> = self.nodes.values().collect();
        ns.sort_by(|a, b| b.exec_count.cmp(&a.exec_count));
        ns.truncate(n);
        ns
    }

    /// Return edges of a specific kind.
    #[must_use]
    pub fn edges_of_kind(&self, kind: ExecEdgeKind) -> Vec<&ExecEdge> {
        self.edges.values().filter(|e| e.kind == kind).collect()
    }

    // ── Loop detection (back-edge DFS) ────────────────────────────────────────

    fn detect_loops(&mut self) {
        // Simple DFS-based back-edge detection.
        let entry = self.entry;
        if !self.nodes.contains_key(&entry) {
            return;
        }

        let mut visited: HashSet<u64> = HashSet::new();
        let mut on_stack: HashSet<u64> = HashSet::new();
        let mut loops: Vec<LoopExec> = Vec::new();

        Self::dfs_loops(
            entry,
            &self.nodes,
            &self.edges,
            &mut visited,
            &mut on_stack,
            &mut loops,
        );

        self.loops = loops;
    }

    fn dfs_loops(
        node: u64,
        nodes: &BTreeMap<u64, ExecNode>,
        edges: &HashMap<(u64, u64), ExecEdge>,
        visited: &mut HashSet<u64>,
        on_stack: &mut HashSet<u64>,
        loops: &mut Vec<LoopExec>,
    ) {
        if visited.contains(&node) {
            return;
        }
        visited.insert(node);
        on_stack.insert(node);

        let succs: Vec<u64> = nodes
            .get(&node)
            .map(|n| n.successors.clone())
            .unwrap_or_default();

        for succ in succs {
            if on_stack.contains(&succ) {
                // Back-edge found: node → succ (succ is loop header)
                let edge = edges.get(&(node, succ));
                let iters = edge.map_or(0, |e| e.count);
                let first_entry = edge.map_or(TracePosition::start(), |e| e.first_seen);

                // Find body nodes (all nodes from succ to node via the loop).
                let body = Self::find_loop_body(succ, node, nodes);

                loops.push(LoopExec {
                    header: succ,
                    tail: node,
                    iteration_count: iters,
                    body_nodes: body,
                    first_entry,
                });
            } else if !visited.contains(&succ) {
                Self::dfs_loops(succ, nodes, edges, visited, on_stack, loops);
            }
        }
        on_stack.remove(&node);
    }

    fn find_loop_body(header: u64, tail: u64, nodes: &BTreeMap<u64, ExecNode>) -> Vec<u64> {
        // BFS backward from tail to header to find all nodes in the loop.
        let mut body: BTreeSet<u64> = BTreeSet::new();
        body.insert(header);
        body.insert(tail);
        let mut worklist = vec![tail];
        while let Some(node) = worklist.pop() {
            if let Some(n) = nodes.get(&node) {
                for &pred in &n.predecessors {
                    if body.insert(pred) {
                        worklist.push(pred);
                    }
                }
            }
        }
        body.into_iter().collect()
    }

    // ── Dominance tree computation (simple iterative algorithm) ───────────────

    /// Compute the dominance tree for the graph and store it in `self.dominators`.
    pub fn compute_dominators(&mut self) {
        if self.nodes.is_empty() {
            return;
        }

        // Compute RPO order via DFS from entry.
        let order = self.rpo_order();
        if order.is_empty() {
            return;
        }

        let n = order.len();
        let index: HashMap<u64, usize> = order.iter().enumerate().map(|(i, &a)| (a, i)).collect();

        // Cooper et al. simple iterative dominators.
        let mut idom: Vec<Option<usize>> = vec![None; n];
        idom[0] = Some(0); // entry dominates itself

        let mut changed = true;
        while changed {
            changed = false;
            for i in 1..n {
                let node = order[i];
                let preds: Vec<u64> = self
                    .nodes
                    .get(&node)
                    .map(|nd| nd.predecessors.clone())
                    .unwrap_or_default();

                // Filter to preds that have already been processed.
                let mut new_idom: Option<usize> = None;
                for pred in &preds {
                    if let Some(&pred_idx) = index.get(pred)
                        && idom[pred_idx].is_some() {
                            new_idom = new_idom.map_or(Some(pred_idx), |d| Some(Self::intersect(d, pred_idx, &idom)));
                        }
                }
                if let Some(d) = new_idom
                    && idom[i] != Some(d) {
                        idom[i] = Some(d);
                        changed = true;
                    }
            }
        }

        // Build ExecDominator structs.
        let mut doms: BTreeMap<u64, ExecDominator> = BTreeMap::new();
        for (i, &addr) in order.iter().enumerate() {
            let idom_addr = if i == 0 {
                None
            } else {
                idom[i].map(|d| order[d])
            };
            doms.insert(
                addr,
                ExecDominator {
                    node: addr,
                    idom: idom_addr,
                    children: Vec::new(),
                    rpo: u32::try_from(i).unwrap_or(u32::MAX),
                },
            );
        }
        // Populate children.
        let entries: Vec<(u64, Option<u64>)> = doms
            .values()
            .map(|d| (d.node, d.idom))
            .collect();
        for (node, idom_opt) in entries {
            if let Some(parent) = idom_opt
                && let Some(p) = doms.get_mut(&parent) {
                    p.children.push(node);
                }
        }
        self.dominators = doms;
    }

    fn intersect(mut a: usize, mut b: usize, idom: &[Option<usize>]) -> usize {
        loop {
            if a == b {
                return a;
            }
            while a > b {
                if let Some(ia) = idom[a] {
                    a = ia;
                } else {
                    return b;
                }
            }
            while b > a {
                if let Some(ib) = idom[b] {
                    b = ib;
                } else {
                    return a;
                }
            }
        }
    }

    fn rpo_order(&self) -> Vec<u64> {
        let entry = self.entry;
        if !self.nodes.contains_key(&entry) {
            return self.nodes.keys().copied().collect();
        }
        let mut visited = HashSet::new();
        let mut post = Vec::new();
        let mut stack: Vec<(u64, bool)> = vec![(entry, false)];
        while let Some((node, processed)) = stack.pop() {
            if processed {
                post.push(node);
                continue;
            }
            if visited.contains(&node) {
                continue;
            }
            visited.insert(node);
            stack.push((node, true));
            let succs: Vec<u64> = self
                .nodes
                .get(&node)
                .map(|n| n.successors.clone())
                .unwrap_or_default();
            for succ in succs.into_iter().rev() {
                if !visited.contains(&succ) {
                    stack.push((succ, false));
                }
            }
        }
        post.reverse();
        post
    }

    // ── Query helpers ─────────────────────────────────────────────────────────

    /// Return whether `dom` dominates `node` in the computed dominator tree.
    #[must_use]
    pub fn dominates(&self, dom: u64, node: u64) -> bool {
        if dom == node {
            return true;
        }
        let mut cur = node;
        loop {
            match self.dominators.get(&cur).and_then(|d| d.idom) {
                None => return false,
                Some(parent) => {
                    if parent == dom {
                        return true;
                    }
                    if parent == cur {
                        return false;
                    }
                    cur = parent;
                }
            }
        }
    }

    /// Return all loop headers.
    #[must_use]
    pub fn loop_headers(&self) -> Vec<u64> {
        let mut headers: Vec<u64> = self.loops.iter().map(|l| l.header).collect();
        headers.sort_unstable();
        headers.dedup();
        headers
    }

    /// Return the total count of all loop iterations across all detected loops.
    #[must_use]
    pub fn total_loop_iterations(&self) -> u64 {
        self.loops.iter().map(|l| l.iteration_count).sum()
    }

    /// Return unreachable nodes (nodes with no predecessors except the entry).
    #[must_use]
    pub fn unreachable_nodes(&self) -> Vec<u64> {
        self.nodes
            .keys()
            .copied()
            .filter(|&addr| {
                addr != self.entry
                    && self
                        .nodes
                        .get(&addr)
                        .is_none_or(|n| n.predecessors.is_empty())
            })
            .collect()
    }

    /// Compute the average execution count across all nodes.
    #[must_use]
    pub fn average_exec_count(&self) -> f64 {
        if self.nodes.is_empty() {
            return 0.0;
        }
        let total: u64 = self.nodes.values().map(|n| n.exec_count).sum();
        total as f64 / self.nodes.len() as f64
    }

    /// Find all call targets (nodes marked as call targets).
    #[must_use]
    pub fn call_targets(&self) -> Vec<u64> {
        self.nodes
            .values()
            .filter(|n| n.is_call_target)
            .map(|n| n.address)
            .collect()
    }

    /// Return the most frequent call edge (caller, callee, count).
    #[must_use]
    pub fn hottest_call(&self) -> Option<(u64, u64, u64)> {
        self.edges
            .values()
            .filter(|e| e.kind == ExecEdgeKind::Call)
            .max_by_key(|e| e.count)
            .map(|e| (e.from, e.to, e.count))
    }

    /// Serialize the graph to a simple DOT format.
    #[must_use]
    pub fn to_dot(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("digraph exec {\n");
        out.push_str("  rankdir=TB;\n");
        for (addr, node) in &self.nodes {
            let color = if node.is_call_target { "lightblue" } else { "white" };
            let _ = writeln!(out, "  n{addr:x} [label=\"{addr:#x}\\n×{}\", style=filled, fillcolor={color}];", node.exec_count);
        }
        for ((from, to), edge) in &self.edges {
            let style = match edge.kind {
                ExecEdgeKind::Call => "bold",
                ExecEdgeKind::Return => "dashed",
                _ => "solid",
            };
            let _ = writeln!(out, "  n{from:x} -> n{to:x} [label=\"×{}\", style={style}];", edge.count);
        }
        out.push('}');
        out
    }
}

impl fmt::Debug for ExecGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecGraph")
            .field("nodes", &self.nodes.len())
            .field("edges", &self.edges.len())
            .field("loops", &self.loops.len())
            .field("entry", &format!("{:#x}", self.entry))
            .finish_non_exhaustive()
    }
}

// ─── ExecGraphStats ───────────────────────────────────────────────────────────

/// Summary statistics about an execution graph.
#[derive(Debug, Clone)]
pub struct ExecGraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub loop_count: usize,
    pub total_loop_iterations: u64,
    pub call_edge_count: usize,
    pub return_edge_count: usize,
    pub hottest_node_addr: Option<u64>,
    pub hottest_node_count: u64,
    pub average_exec_count: f64,
    pub unreachable_count: usize,
}

impl ExecGraphStats {
    #[must_use]
    pub fn compute(graph: &ExecGraph) -> Self {
        let hottest = graph.hot_nodes(1).into_iter().next();
        Self {
            node_count: graph.node_count(),
            edge_count: graph.edge_count(),
            loop_count: graph.loops.len(),
            total_loop_iterations: graph.total_loop_iterations(),
            call_edge_count: graph.edges_of_kind(ExecEdgeKind::Call).len(),
            return_edge_count: graph.edges_of_kind(ExecEdgeKind::Return).len(),
            hottest_node_addr: hottest.map(|n| n.address),
            hottest_node_count: hottest.map_or(0, |n| n.exec_count),
            average_exec_count: graph.average_exec_count(),
            unreachable_count: graph.unreachable_nodes().len(),
        }
    }
}

impl fmt::Display for ExecGraphStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExecGraphStats {{ nodes={}, edges={}, loops={}, loop_iters={}, avg_exec={:.1} }}",
            self.node_count,
            self.edge_count,
            self.loop_count,
            self.total_loop_iterations,
            self.average_exec_count,
        )
    }
}

// ─── CriticalPath ─────────────────────────────────────────────────────────────

/// A path through the execution graph weighted by execution count.
#[derive(Debug, Clone)]
pub struct CriticalPath {
    /// Sequence of node addresses on the path.
    pub nodes: Vec<u64>,
    /// Total execution weight along the path.
    pub total_weight: u64,
}

impl CriticalPath {
    /// Find the critical (hottest) path from `start` to any sink node.
    #[must_use]
    pub fn find(graph: &ExecGraph, start: u64) -> Option<Self> {
        if graph.nodes.is_empty() {
            return None;
        }
        // Greedy: always pick the successor with the highest edge count.
        let mut path = vec![start];
        let mut weight = graph.nodes.get(&start).map_or(0, |n| n.exec_count);
        let mut visited: HashSet<u64> = HashSet::new();
        visited.insert(start);

        let mut current = start;
        loop {
            let succs = graph
                .nodes
                .get(&current)
                .map(|n| n.successors.clone())
                .unwrap_or_default();
            let best = succs
                .iter()
                .filter(|&&s| !visited.contains(&s))
                .max_by_key(|&&s| {
                    graph.edge(current, s).map_or(0, |e| e.count)
                });
            match best {
                None => break,
                Some(&next) => {
                    weight += graph.edge(current, next).map_or(0, |e| e.count);
                    path.push(next);
                    visited.insert(next);
                    current = next;
                }
            }
        }

        Some(Self {
            nodes: path,
            total_weight: weight,
        })
    }
}

impl fmt::Display for CriticalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CriticalPath {{ len={}, weight={} }}", self.nodes.len(), self.total_weight)
    }
}

// ─── ExecGraphBuilder ─────────────────────────────────────────────────────────

/// Streaming builder for `ExecGraph` that processes events incrementally.
pub struct ExecGraphBuilder {
    nodes: BTreeMap<u64, ExecNode>,
    edges: HashMap<(u64, u64), ExecEdge>,
    entry: Option<u64>,
    total_transitions: u64,
    event_count: usize,
}

impl ExecGraphBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: HashMap::new(),
            entry: None,
            total_transitions: 0,
            event_count: 0,
        }
    }

    /// Feed a single event into the builder.
    pub fn feed(&mut self, pos: TracePosition, kind: &EventKind) {
        self.event_count += 1;
        match kind {
            EventKind::Call { from, to } => {
                if self.entry.is_none() {
                    self.entry = Some(*from);
                }
                self.touch_node(*from, pos, false, false);
                self.touch_node(*to, pos, true, false);
                self.touch_edge(*from, *to, ExecEdgeKind::Call, pos);
                self.total_transitions += 1;
            }
            EventKind::Return { from, to } => {
                self.touch_node(*from, pos, false, true);
                self.touch_node(*to, pos, false, false);
                self.touch_edge(*from, *to, ExecEdgeKind::Return, pos);
                self.total_transitions += 1;
            }
            _ => {}
        }
    }

    fn touch_node(&mut self, addr: u64, pos: TracePosition, is_call_target: bool, is_return: bool) {
        let node = self
            .nodes
            .entry(addr)
            .or_insert_with(|| ExecNode::new(addr, pos));
        node.exec_count += 1;
        node.last_seen = pos;
        if is_call_target {
            node.is_call_target = true;
        }
        if is_return {
            node.is_return_site = true;
        }
    }

    fn touch_edge(&mut self, from: u64, to: u64, kind: ExecEdgeKind, pos: TracePosition) {
        let edge = self
            .edges
            .entry((from, to))
            .or_insert_with(|| ExecEdge::new(from, to, kind, pos));
        edge.count += 1;
        edge.last_seen = pos;

        let from_node = self.nodes.entry(from).or_insert_with(|| ExecNode::new(from, pos));
        if !from_node.successors.contains(&to) {
            from_node.successors.push(to);
        }
        let to_node = self.nodes.entry(to).or_insert_with(|| ExecNode::new(to, pos));
        if !to_node.predecessors.contains(&from) {
            to_node.predecessors.push(from);
        }
    }

    /// Finalize and return the completed `ExecGraph`.
    #[must_use]
    pub fn finish(self) -> ExecGraph {
        let mut graph = ExecGraph {
            nodes: self.nodes,
            edges: self.edges,
            loops: Vec::new(),
            dominators: BTreeMap::new(),
            entry: self.entry.unwrap_or(0),
            total_transitions: self.total_transitions,
        };
        graph.detect_loops();
        graph
    }

    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.event_count
    }
}

impl Default for ExecGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}
