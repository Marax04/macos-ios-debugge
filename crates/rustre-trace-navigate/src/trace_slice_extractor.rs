//! Execution slice extraction from traces.
//!
//! Extracts execution slices based on variable/address criteria, supporting
//! backward and forward program slicing. Produces `SliceNode` and `SliceGraph`
//! using petgraph.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde::{Deserialize, Serialize};

use crate::{Address, AccessKind, EntryKind, ExecutionTrace, MemAccessIndex, RegId, TraceEntry};

// ─── SliceCriterion ──────────────────────────────────────────────────────────

/// The criterion that anchors a program slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SliceCriterion {
    /// Slice from all instructions that read or write the given memory address.
    MemoryAddress {
        addr: Address,
        kind: CriterionAccessKind,
    },
    /// Slice from all instructions that produce or consume the given register.
    Register { reg_id: RegId },
    /// Slice from a specific trace index.
    TraceIndex { idx: usize },
    /// Slice from all CALL instructions to a specific target.
    CallTarget { target: Address },
    /// Slice from all instructions at a specific PC.
    Pc { pc: Address },
}

/// Whether to match reads, writes, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CriterionAccessKind {
    Read,
    Write,
    ReadWrite,
}

// ─── SliceDirection ───────────────────────────────────────────────────────────

/// Direction of the slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliceDirection {
    /// Backward: find all instructions that could have affected the criterion.
    Backward,
    /// Forward: find all instructions that the criterion could affect.
    Forward,
    /// Both directions from the criterion.
    Both,
}

// ─── SliceNode ────────────────────────────────────────────────────────────────

/// A node in the slice graph representing one trace entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceNode {
    /// Trace index.
    pub idx: usize,
    /// Program counter.
    pub pc: Address,
    /// Thread ID.
    pub tid: u32,
    /// Human-readable disassembly.
    pub disasm: String,
    /// True if this is one of the criterion (seed) nodes.
    pub is_seed: bool,
    /// Depth from the nearest seed (steps in the dependency graph).
    pub depth: u32,
    /// Memory writes at this instruction.
    pub mem_writes: Vec<(Address, Vec<u8>)>,
    /// Registers defined at this instruction (values written).
    pub reg_defs: Vec<(RegId, u64)>,
}

impl SliceNode {
    fn from_entry(entry: &TraceEntry, is_seed: bool, depth: u32) -> Self {
        Self {
            idx: entry.idx,
            pc: entry.pc,
            tid: entry.tid,
            disasm: entry.disasm.clone(),
            is_seed,
            depth,
            mem_writes: entry.mem_writes.clone(),
            reg_defs: entry.reg_snapshot.clone(),
        }
    }
}

// ─── SliceEdgeKind ────────────────────────────────────────────────────────────

/// The kind of dependency edge between two slice nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliceEdgeKind {
    /// Data dependency via a memory address.
    MemoryDep,
    /// Data dependency via a register.
    RegisterDep,
    /// Control dependency (one instruction controls whether another executes).
    ControlDep,
    /// Direct succession (instruction B immediately follows A in the trace).
    Sequential,
}

// ─── SliceGraph ───────────────────────────────────────────────────────────────

/// A petgraph-backed directed graph of slice nodes.
pub struct SliceGraph {
    /// The underlying directed graph.
    pub graph: DiGraph<SliceNode, SliceEdgeKind>,
    /// Map from trace index to node index.
    pub idx_to_node: HashMap<usize, NodeIndex>,
    /// The seed trace indices.
    pub seeds: Vec<usize>,
    /// Slice direction used when building.
    pub direction: SliceDirection,
    /// Dependency edges discovered before both endpoints existed.
    ///
    /// The traversal records an edge to a producer at the moment that producer
    /// is ENQUEUED, but its node is only created when the worklist reaches it.
    /// `add_dep_edge` needs both endpoints, so those edges were silently
    /// dropped — the slice came out with the right nodes and NO edges at all,
    /// which is precisely the information a dependency slice exists to carry.
    pending_edges: Vec<(usize, usize, SliceEdgeKind)>,
}

impl SliceGraph {
    fn new(direction: SliceDirection) -> Self {
        Self {
            graph: DiGraph::new(),
            idx_to_node: HashMap::new(),
            seeds: Vec::new(),
            direction,
            pending_edges: Vec::new(),
        }
    }

    /// Add a node for a trace entry, or return the existing node index.
    fn add_node(&mut self, entry: &TraceEntry, is_seed: bool, depth: u32) -> NodeIndex {
        if let Some(&ni) = self.idx_to_node.get(&entry.idx) {
            return ni;
        }
        let node = SliceNode::from_entry(entry, is_seed, depth);
        let ni = self.graph.add_node(node);
        self.idx_to_node.insert(entry.idx, ni);
        ni
    }

    /// Add a directed edge between two trace indices if both exist as nodes.
    fn add_dep_edge(&mut self, from_idx: usize, to_idx: usize, kind: SliceEdgeKind) {
        if let (Some(&ni_from), Some(&ni_to)) = (
            self.idx_to_node.get(&from_idx),
            self.idx_to_node.get(&to_idx),
        ) {
            // Avoid duplicate edges
            if !self.graph.contains_edge(ni_from, ni_to) {
                self.graph.add_edge(ni_from, ni_to, kind);
            }
        } else {
            // One endpoint has not been visited yet — the producer is only
            // enqueued at this point. Remember the edge and add it once the
            // traversal has created every node.
            self.pending_edges.push((from_idx, to_idx, kind));
        }
    }

    /// Add every edge that was discovered before its endpoints existed.
    ///
    /// Must run after the traversal has finished creating nodes.
    fn flush_pending_edges(&mut self) {
        for (from_idx, to_idx, kind) in std::mem::take(&mut self.pending_edges) {
            if let (Some(&ni_from), Some(&ni_to)) = (
                self.idx_to_node.get(&from_idx),
                self.idx_to_node.get(&to_idx),
            ) && !self.graph.contains_edge(ni_from, ni_to)
            {
                self.graph.add_edge(ni_from, ni_to, kind);
            }
        }
    }

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

    /// All trace indices in the slice, sorted ascending.
    #[must_use]
    pub fn trace_indices(&self) -> Vec<usize> {
        let mut idxs: Vec<usize> = self.idx_to_node.keys().copied().collect();
        idxs.sort_unstable();
        idxs
    }

    /// Return the nodes sorted by trace index.
    #[must_use]
    pub fn nodes_in_order(&self) -> Vec<&SliceNode> {
        let mut idxs: Vec<usize> = self.idx_to_node.keys().copied().collect();
        idxs.sort_unstable();
        idxs
            .iter()
            .filter_map(|i| self.idx_to_node.get(i).and_then(|ni| self.graph.node_weight(*ni)))
            .collect()
    }

    /// Strongly-connected component count (using petgraph Kosaraju).
    #[must_use]
    pub fn scc_count(&self) -> usize {
        petgraph::algo::kosaraju_scc(&self.graph).len()
    }

    /// Return ancestors of the given trace index in the slice graph.
    #[must_use]
    pub fn ancestors(&self, idx: usize) -> Vec<usize> {
        let Some(&ni) = self.idx_to_node.get(&idx) else {
            return Vec::new();
        };
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(ni);
        while let Some(n) = queue.pop_front() {
            for pred in self.graph.neighbors_directed(n, Direction::Incoming) {
                if visited.insert(pred) {
                    queue.push_back(pred);
                }
            }
        }
        visited
            .iter()
            .filter_map(|n| self.graph.node_weight(*n).map(|node| node.idx))
            .collect()
    }
}

// ─── TraceSliceExtractor ──────────────────────────────────────────────────────

/// Extracts program slices from execution traces.
pub struct TraceSliceExtractor {
    /// Maximum BFS depth when building the slice graph.
    pub max_depth: u32,
    /// Maximum number of nodes in the slice graph.
    pub max_nodes: usize,
    /// Whether to follow memory dependencies through the slice.
    pub follow_memory_deps: bool,
    /// Whether to follow register dependencies through the slice.
    pub follow_register_deps: bool,
}

impl TraceSliceExtractor {
    /// Create a new extractor with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_depth: 50,
            max_nodes: 100_000,
            follow_memory_deps: true,
            follow_register_deps: true,
        }
    }

    /// Extract a slice from the trace using the given criterion and direction.
    #[must_use]
    pub fn extract(
        &self,
        trace: &ExecutionTrace,
        criterion: &SliceCriterion,
        direction: SliceDirection,
    ) -> SliceGraph {
        let mem_index = MemAccessIndex::build(trace);
        let seed_indices = Self::find_seeds(trace, criterion, &mem_index);
        let mut graph = SliceGraph::new(direction);
        graph.seeds.clone_from(&seed_indices);

        match direction {
            SliceDirection::Backward => {
                self.build_backward(trace, &seed_indices, &mem_index, &mut graph);
            }
            SliceDirection::Forward => {
                self.build_forward(trace, &seed_indices, &mem_index, &mut graph);
            }
            SliceDirection::Both => {
                self.build_backward(trace, &seed_indices, &mem_index, &mut graph);
                self.build_forward(trace, &seed_indices, &mem_index, &mut graph);
            }
        }

        // Every node exists now: add the edges whose endpoints were still
        // missing when the traversal discovered them.
        graph.flush_pending_edges();

        graph
    }

    /// Find the seed trace indices satisfying the criterion.
    fn find_seeds(
        trace: &ExecutionTrace,
        criterion: &SliceCriterion,
        mem_index: &MemAccessIndex,
    ) -> Vec<usize> {
        match criterion {
            SliceCriterion::TraceIndex { idx } => vec![*idx],
            SliceCriterion::Pc { pc } => {
                trace.entries.iter().filter(|e| e.pc == *pc).map(|e| e.idx).collect()
            }
            SliceCriterion::MemoryAddress { addr, kind } => {
                let accesses = mem_index.accesses(*addr);
                accesses
                    .iter()
                    .filter(|(_, ak, _)| match kind {
                        CriterionAccessKind::Read => *ak == AccessKind::Read,
                        CriterionAccessKind::Write => *ak == AccessKind::Write,
                        CriterionAccessKind::ReadWrite => true,
                    })
                    .map(|(i, _, _)| *i)
                    .collect()
            }
            SliceCriterion::Register { reg_id } => trace
                .entries
                .iter()
                .filter(|e| e.reg_snapshot.iter().any(|(r, _)| r == reg_id))
                .map(|e| e.idx)
                .collect(),
            SliceCriterion::CallTarget { target } => trace
                .entries
                .iter()
                .filter(|e| matches!(e.kind, EntryKind::Call { target: t, .. } if t == *target))
                .map(|e| e.idx)
                .collect(),
        }
    }

    /// Build a backward slice: from seeds, follow data producers going earlier.
    fn build_backward(
        &self,
        trace: &ExecutionTrace,
        seeds: &[usize],
        mem_index: &MemAccessIndex,
        graph: &mut SliceGraph,
    ) {
        // Build a register def map: reg_id -> sorted list of (trace_idx, value)
        let mut reg_def_map: HashMap<RegId, Vec<(usize, u64)>> = HashMap::new();
        for entry in &trace.entries {
            for (reg, val) in &entry.reg_snapshot {
                reg_def_map.entry(*reg).or_default().push((entry.idx, *val));
            }
        }

        let mut worklist: VecDeque<(usize, u32)> = seeds.iter().map(|&i| (i, 0)).collect();
        let mut visited: HashSet<usize> = seeds.iter().copied().collect();

        while let Some((idx, depth)) = worklist.pop_front() {
            if graph.node_count() >= self.max_nodes {
                break;
            }
            let Some(entry) = trace.get(idx) else {
                continue;
            };
            let is_seed = seeds.contains(&idx);
            graph.add_node(entry, is_seed, depth);

            if depth >= self.max_depth {
                continue;
            }

            // Find producers via memory reads
            if self.follow_memory_deps {
                for (addr, _) in &entry.mem_reads {
                    // Find the most recent write before this idx
                    if let Some(write_idx) = mem_index
                        .writes(*addr)
                        .into_iter()
                        .rev()
                        .find(|(i, _)| *i < idx)
                        .map(|(i, _)| i)
                    {
                        if visited.insert(write_idx) {
                            worklist.push_back((write_idx, depth + 1));
                        }
                        graph.add_dep_edge(write_idx, idx, SliceEdgeKind::MemoryDep);
                    }
                }
            }

            // Find producers via register uses
            if self.follow_register_deps {
                // The registers "used" are those in the snapshot — find their last
                // definition before this index.
                for (reg, _) in &entry.reg_snapshot {
                    if let Some(hist) = reg_def_map.get(reg)
                        && let Some(&(def_idx, _)) = hist.iter().rev().find(|(i, _)| *i < idx) {
                            if visited.insert(def_idx) {
                                worklist.push_back((def_idx, depth + 1));
                            }
                            graph.add_dep_edge(def_idx, idx, SliceEdgeKind::RegisterDep);
                        }
                }
            }
        }
    }

    /// Build a forward slice: from seeds, follow data consumers going later.
    fn build_forward(
        &self,
        trace: &ExecutionTrace,
        seeds: &[usize],
        _mem_index: &MemAccessIndex,
        graph: &mut SliceGraph,
    ) {
        // Build a map: addr -> list of read trace indices
        let mut mem_read_map: BTreeMap<Address, Vec<usize>> = BTreeMap::new();
        for entry in &trace.entries {
            for (addr, _) in &entry.mem_reads {
                mem_read_map.entry(*addr).or_default().push(entry.idx);
            }
        }

        // Register use map: reg_id -> list of (trace_idx) where it was read
        let mut reg_use_map: HashMap<RegId, Vec<usize>> = HashMap::new();
        for entry in &trace.entries {
            for (reg, _) in &entry.reg_snapshot {
                reg_use_map.entry(*reg).or_default().push(entry.idx);
            }
        }

        let mut worklist: VecDeque<(usize, u32)> = seeds.iter().map(|&i| (i, 0)).collect();
        let mut visited: HashSet<usize> = seeds.iter().copied().collect();

        while let Some((idx, depth)) = worklist.pop_front() {
            if graph.node_count() >= self.max_nodes {
                break;
            }
            let Some(entry) = trace.get(idx) else {
                continue;
            };
            let is_seed = seeds.contains(&idx);
            graph.add_node(entry, is_seed, depth);

            if depth >= self.max_depth {
                continue;
            }

            // Find consumers of memory writes from this instruction
            if self.follow_memory_deps {
                for (addr, _) in &entry.mem_writes {
                    if let Some(readers) = mem_read_map.get(addr) {
                        for &read_idx in readers {
                            if read_idx > idx {
                                if visited.insert(read_idx) {
                                    worklist.push_back((read_idx, depth + 1));
                                }
                                graph.add_dep_edge(idx, read_idx, SliceEdgeKind::MemoryDep);
                            }
                        }
                    }
                }
            }

            // Find consumers of registers defined at this instruction
            if self.follow_register_deps {
                for (reg, _) in &entry.reg_snapshot {
                    if let Some(users) = reg_use_map.get(reg) {
                        for &use_idx in users {
                            if use_idx > idx {
                                if visited.insert(use_idx) {
                                    worklist.push_back((use_idx, depth + 1));
                                }
                                graph.add_dep_edge(idx, use_idx, SliceEdgeKind::RegisterDep);
                                break; // Only follow to next use
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Default for TraceSliceExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SliceStats ───────────────────────────────────────────────────────────────

/// Statistics about a slice graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub seed_count: usize,
    pub max_depth: u32,
    pub mean_depth: f64,
    pub memory_dep_edges: usize,
    pub register_dep_edges: usize,
    pub scc_count: usize,
}

impl SliceStats {
    /// Compute statistics for a slice graph.
    #[must_use]
    pub fn compute(graph: &SliceGraph) -> Self {
        let node_count = graph.node_count();
        let edge_count = graph.edge_count();
        let seed_count = graph.seeds.len();

        let (max_depth, depth_sum) = graph
            .graph
            .node_weights()
            .fold((0u32, 0u64), |(max, sum): (u32, u64), n| {
                (max.max(n.depth), sum + u64::from(n.depth))
            });
        let mean_depth = if node_count > 0 {
            f64::from(u32::try_from(depth_sum).unwrap_or(u32::MAX)) / f64::from(u32::try_from(node_count).unwrap_or(u32::MAX))
        } else {
            0.0
        };

        let memory_dep_edges = graph
            .graph
            .edge_weights()
            .filter(|&&e| e == SliceEdgeKind::MemoryDep)
            .count();
        let register_dep_edges = graph
            .graph
            .edge_weights()
            .filter(|&&e| e == SliceEdgeKind::RegisterDep)
            .count();

        let scc_count = graph.scc_count();

        Self {
            node_count,
            edge_count,
            seed_count,
            max_depth,
            mean_depth,
            memory_dep_edges,
            register_dep_edges,
            scc_count,
        }
    }
}

// ─── VariableTainter ──────────────────────────────────────────────────────────

/// Simple taint tracker: given an initial set of tainted addresses, propagate
/// taint through the trace to find all instructions that produce tainted values.
pub struct VariableTainter {
    tainted_addrs: HashSet<Address>,
    tainted_regs: HashSet<RegId>,
}

impl VariableTainter {
    /// Create a taint tracker with the given initial tainted memory addresses.
    #[must_use]
    pub fn new(initial_addrs: impl IntoIterator<Item = Address>) -> Self {
        Self {
            tainted_addrs: initial_addrs.into_iter().collect(),
            tainted_regs: HashSet::new(),
        }
    }

    /// Mark a register as initially tainted.
    pub fn taint_register(&mut self, reg: RegId) {
        self.tainted_regs.insert(reg);
    }

    /// Run taint propagation through the trace (forward pass).
    /// Returns the set of tainted trace indices.
    #[must_use]
    pub fn propagate(&mut self, trace: &ExecutionTrace) -> HashSet<usize> {
        let mut tainted_indices = HashSet::new();

        for entry in &trace.entries {
            let mut is_tainted = false;

            // Check if any memory read comes from a tainted address
            for (addr, _) in &entry.mem_reads {
                if self.tainted_addrs.contains(addr) {
                    is_tainted = true;
                    break;
                }
            }

            // Check if any register snapshot value is from a tainted reg
            if !is_tainted {
                for (reg, _) in &entry.reg_snapshot {
                    if self.tainted_regs.contains(reg) {
                        is_tainted = true;
                        break;
                    }
                }
            }

            if is_tainted {
                tainted_indices.insert(entry.idx);
                // Propagate: any memory written is now tainted
                for (addr, _) in &entry.mem_writes {
                    self.tainted_addrs.insert(*addr);
                }
                // Propagate to all registers in the snapshot
                for (reg, _) in &entry.reg_snapshot {
                    self.tainted_regs.insert(*reg);
                }
            }
        }

        tainted_indices
    }

    /// Return the current set of tainted addresses.
    #[must_use]
    pub const fn tainted_addresses(&self) -> &HashSet<Address> {
        &self.tainted_addrs
    }

    /// Return the current set of tainted registers.
    #[must_use]
    pub const fn tainted_registers(&self) -> &HashSet<RegId> {
        &self.tainted_regs
    }
}
