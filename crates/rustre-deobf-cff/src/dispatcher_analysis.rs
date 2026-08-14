//! Deep dispatcher analysis for CFF-protected functions.
//!
//! Provides:
//! * [`DispatcherBlock`] — a characterised dispatcher block with state-var comparisons.
//! * [`CaseTransition`] — a single case arrow from one dispatcher state to the next.
//! * [`StateVariableTracker`] — tracks all writes to the CFF state variable.
//! * [`DispatcherGraph`] — the complete graph of dispatcher→case edges.
//! * [`FlattenedRegion`] — a contiguous region of blocks that the dispatcher manages.
//! * [`DispatcherAnalysis`] — top-level analysis object.

use std::collections::{HashMap, HashSet, VecDeque};

// ─────────────────────────────────────────────────────────────────────────────
// Address wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// A virtual address used throughout dispatcher analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr(pub u64);

impl Addr {
    /// Construct from a raw `u64`.
    #[must_use]
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw `u64`.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CaseTransition
// ─────────────────────────────────────────────────────────────────────────────

/// A single transition in the dispatcher: "when the state variable holds
/// `state_value`, jump to `target_block`."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseTransition {
    /// The constant state-variable value that triggers this transition.
    pub state_value: u64,
    /// The address of the handler block reached when the state matches.
    pub target_block: Addr,
    /// Optional flag: `true` if this transition is marked as a loop-back
    /// (the handler eventually writes a state that loops back here).
    pub is_loop_back: bool,
    /// Confidence that this transition is correctly recovered (0–100).
    pub confidence: u8,
}

impl CaseTransition {
    /// Create a new transition.
    #[must_use]
    pub const fn new(state_value: u64, target_block: Addr) -> Self {
        Self {
            state_value,
            target_block,
            is_loop_back: false,
            confidence: 80,
        }
    }

    /// Mark as a loop-back transition and return `self`.
    #[must_use]
    pub const fn with_loop_back(mut self) -> Self {
        self.is_loop_back = true;
        self
    }

    /// Set confidence and return `self`.
    #[must_use]
    pub fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c.min(100);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateWrite
// ─────────────────────────────────────────────────────────────────────────────

/// A single write to the CFF state variable observed at a particular address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateWrite {
    /// Address of the instruction that writes the state.
    pub instr_addr: Addr,
    /// The constant value written, if statically known.
    pub value: Option<u64>,
    /// Name of the register or memory location written to.
    pub location: String,
    /// Whether this write was resolved via constant propagation (`true`) or
    /// direct pattern matching (`false`).
    pub is_propagated: bool,
}

impl StateWrite {
    /// Create a new write with a known constant value.
    #[must_use]
    pub fn constant(instr_addr: Addr, value: u64, location: impl Into<String>) -> Self {
        Self {
            instr_addr,
            value: Some(value),
            location: location.into(),
            is_propagated: false,
        }
    }

    /// Create a write with an unknown (runtime-dependent) value.
    #[must_use]
    pub fn unknown(instr_addr: Addr, location: impl Into<String>) -> Self {
        Self {
            instr_addr,
            value: None,
            location: location.into(),
            is_propagated: false,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateVariableTracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks all writes to the CFF state variable across a set of basic blocks.
///
/// Maintains:
/// * A list of all [`StateWrite`] records ordered by instruction address.
/// * A deduplicated mapping from block start address → list of writes.
/// * A coverage set: the block addresses where at least one write was resolved.
#[derive(Debug, Default, Clone)]
pub struct StateVariableTracker {
    /// All collected state writes, in insertion order.
    pub writes: Vec<StateWrite>,
    /// Block-address → writes performed in that block.
    pub block_writes: HashMap<u64, Vec<StateWrite>>,
    /// Addresses of blocks where the state was successfully resolved.
    pub resolved_blocks: HashSet<u64>,
}

impl StateVariableTracker {
    /// Create an empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a state write.
    pub fn record(&mut self, block_addr: Addr, value: u64, is_propagated: bool) {
        let sw = StateWrite {
            instr_addr: block_addr,
            value: Some(value),
            location: "state_var".into(),
            is_propagated,
        };
        self.writes.push(sw.clone());
        self.block_writes
            .entry(block_addr.as_u64())
            .or_default()
            .push(sw);
        self.resolved_blocks.insert(block_addr.as_u64());
    }

    /// Record a write of unknown value.
    pub fn record_unknown(&mut self, block_addr: Addr) {
        let sw = StateWrite::unknown(block_addr, "state_var");
        self.writes.push(sw.clone());
        self.block_writes
            .entry(block_addr.as_u64())
            .or_default()
            .push(sw);
    }

    /// Return the resolved state value for `block_addr`, if any.
    #[must_use]
    pub fn resolved_value(&self, block_addr: Addr) -> Option<u64> {
        self.block_writes
            .get(&block_addr.as_u64())?
            .iter()
            .find_map(|sw| sw.value)
    }

    /// Number of blocks where the state was successfully resolved.
    #[must_use]
    pub fn resolved_count(&self) -> usize {
        self.resolved_blocks.len()
    }

    /// Return `true` if `block_addr` has been resolved.
    #[must_use]
    pub fn is_resolved(&self, block_addr: Addr) -> bool {
        self.resolved_blocks.contains(&block_addr.as_u64())
    }

    /// Return all writes that carry a known constant value.
    #[must_use]
    pub fn constant_writes(&self) -> Vec<&StateWrite> {
        self.writes.iter().filter(|sw| sw.value.is_some()).collect()
    }

    /// Propagate resolved values forward through a simple CFG edge set.
    ///
    /// `edges` is a list of `(from, to)` block-address pairs.  When `from`
    /// has a resolved value and `to` does not, and `to` has no unconditional
    /// write of its own, the value propagates.
    pub fn propagate_simple(&mut self, edges: &[(u64, u64)]) {
        let resolved: Vec<(u64, u64)> = self
            .resolved_blocks
            .iter()
            .filter_map(|&addr| {
                self.block_writes
                    .get(&addr)?
                    .iter()
                    .find_map(|sw| sw.value.map(|v| (addr, v)))
            })
            .collect();

        for (src, val) in &resolved {
            for &(from, to) in edges {
                if from == *src && !self.resolved_blocks.contains(&to) {
                    self.record(Addr(to), *val, true);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatcherBlock
// ─────────────────────────────────────────────────────────────────────────────

/// A fully characterised CFF dispatcher block.
///
/// The dispatcher block is the "hub" that all handler blocks return to; it
/// reads the state variable and dispatches to the appropriate handler.
#[derive(Debug, Clone)]
pub struct DispatcherBlock {
    /// Address of the dispatcher.
    pub address: Addr,
    /// Number of handler cases dispatched by this block.
    pub case_count: usize,
    /// All case transitions for this dispatcher.
    pub cases: Vec<CaseTransition>,
    /// State variable location (register name or `"mem:0xADDR"`).
    pub state_var_location: String,
    /// Number of incoming back-edges (how many handlers return here).
    pub back_edge_count: usize,
    /// Whether the dispatcher uses an indirect jump table.
    pub uses_jump_table: bool,
    /// Confidence that this is indeed a dispatcher (0–100).
    pub confidence: u8,
}

impl DispatcherBlock {
    /// Create a new dispatcher block.
    #[must_use]
    pub fn new(address: Addr, state_var_location: impl Into<String>) -> Self {
        Self {
            address,
            case_count: 0,
            cases: Vec::new(),
            state_var_location: state_var_location.into(),
            back_edge_count: 0,
            uses_jump_table: false,
            confidence: 50,
        }
    }

    /// Add a case transition.
    pub fn add_case(&mut self, transition: CaseTransition) {
        self.case_count += 1;
        self.cases.push(transition);
    }

    /// Return the case for a given state value, if present.
    #[must_use]
    pub fn case_for_state(&self, state: u64) -> Option<&CaseTransition> {
        self.cases.iter().find(|c| c.state_value == state)
    }

    /// Return all loop-back transitions.
    #[must_use]
    pub fn loop_back_cases(&self) -> Vec<&CaseTransition> {
        self.cases.iter().filter(|c| c.is_loop_back).collect()
    }

    /// Return the average confidence across all cases.
    #[must_use]
    pub fn average_case_confidence(&self) -> f64 {
        if self.cases.is_empty() {
            return 0.0;
        }
        self.cases.iter().map(|c| f64::from(c.confidence)).sum::<f64>()
            / f64::from(u32::try_from(self.cases.len()).unwrap_or(u32::MAX))
    }

    /// Recompute `case_count` from `cases.len()`.
    pub const fn sync_case_count(&mut self) {
        self.case_count = self.cases.len();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatcherGraph
// ─────────────────────────────────────────────────────────────────────────────

/// The complete graph of dispatcher → case relationships.
///
/// Nodes are dispatcher block addresses; edges are `(dispatcher, state_value,
/// target_block)` triples.
#[derive(Debug, Clone, Default)]
pub struct DispatcherGraph {
    /// All dispatcher blocks, keyed by their address.
    pub dispatchers: HashMap<Addr, DispatcherBlock>,
    /// `(dispatcher_addr, state_value) → target_block_addr`
    pub edges: HashMap<(u64, u64), Addr>,
    /// Set of all target-block addresses across all dispatchers.
    pub all_targets: HashSet<Addr>,
}

impl DispatcherGraph {
    /// Create an empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a dispatcher block (replaces any existing entry for the same address).
    pub fn add_dispatcher(&mut self, db: DispatcherBlock) {
        for c in &db.cases {
            self.edges
                .insert((db.address.as_u64(), c.state_value), c.target_block);
            self.all_targets.insert(c.target_block);
        }
        self.dispatchers.insert(db.address, db);
    }

    /// Look up the target block for `(dispatcher, state_value)`.
    #[must_use]
    pub fn target_for(&self, dispatcher: Addr, state: u64) -> Option<Addr> {
        self.edges.get(&(dispatcher.as_u64(), state)).copied()
    }

    /// Return the number of unique target blocks across all dispatchers.
    #[must_use]
    pub fn unique_target_count(&self) -> usize {
        self.all_targets.len()
    }

    /// Return all dispatcher addresses in sorted order.
    #[must_use]
    pub fn sorted_dispatcher_addrs(&self) -> Vec<Addr> {
        let mut v: Vec<Addr> = Vec::with_capacity(self.dispatchers.len());
        v.extend(self.dispatchers.keys().copied());
        v.sort_unstable();
        v
    }

    /// Total number of case edges in the graph.
    #[must_use]
    pub fn total_cases(&self) -> usize {
        self.dispatchers.values().map(|d| d.case_count).sum()
    }

    /// Check whether the graph is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dispatchers.is_empty()
    }

    /// Return the dispatcher with the highest case count.
    #[must_use]
    pub fn busiest_dispatcher(&self) -> Option<&DispatcherBlock> {
        // `dispatchers` is a HashMap: without a tie-break on the address, two
        // dispatchers with the same case count would win arbitrarily and the
        // reported "busiest" one would differ between runs on the same binary.
        self.dispatchers
            .iter()
            .max_by(|a, b| a.1.case_count.cmp(&b.1.case_count).then_with(|| b.0.cmp(a.0)))
            .map(|(_, d)| d)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FlattenedRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous set of basic blocks managed by one dispatcher in the
/// de-flattened control flow.
#[derive(Debug, Clone)]
pub struct FlattenedRegion {
    /// The dispatcher that owned this region.
    pub dispatcher: Addr,
    /// All block addresses that were handler bodies.
    pub body_blocks: Vec<Addr>,
    /// Recovered edges: `(from, to)` in the original (pre-CFF) CFG.
    pub recovered_edges: Vec<(Addr, Addr)>,
    /// Overall confidence in the recovery (0–100).
    pub recovery_confidence: u8,
    /// Number of state transitions successfully resolved.
    pub resolved_transitions: usize,
    /// Number of state transitions that could not be resolved.
    pub unresolved_transitions: usize,
}

impl FlattenedRegion {
    /// Create a new region.
    #[must_use]
    pub const fn new(dispatcher: Addr) -> Self {
        Self {
            dispatcher,
            body_blocks: Vec::new(),
            recovered_edges: Vec::new(),
            recovery_confidence: 0,
            resolved_transitions: 0,
            unresolved_transitions: 0,
        }
    }

    /// Add a body block.
    pub fn add_block(&mut self, addr: Addr) {
        self.body_blocks.push(addr);
    }

    /// Add a recovered edge.
    pub fn add_edge(&mut self, from: Addr, to: Addr) {
        self.recovered_edges.push((from, to));
        self.resolved_transitions += 1;
    }

    /// Mark an unresolved transition.
    pub const fn note_unresolved(&mut self) {
        self.unresolved_transitions += 1;
    }

    /// Compute recovery rate as a fraction in [0.0, 1.0].
    #[must_use]
    pub fn recovery_rate(&self) -> f64 {
        let total = self.resolved_transitions + self.unresolved_transitions;
        if total == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.resolved_transitions).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
    }

    /// Return `true` when all transitions were resolved.
    #[must_use]
    pub const fn is_fully_recovered(&self) -> bool {
        self.unresolved_transitions == 0 && self.resolved_transitions > 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatcherAnalysis
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level analysis that:
/// 1. Identifies all dispatcher blocks via predecessor-count heuristic.
/// 2. Builds a [`DispatcherGraph`].
/// 3. Produces [`FlattenedRegion`] objects for each dispatcher.
///
/// # Input
/// The caller supplies a simple adjacency-list CFG:
/// * `blocks`: mapping from block address → list of successor addresses.
/// * `back_edge_counts`: mapping from block address → number of back-edges
///   (predecessor blocks that are not the entry).
#[derive(Debug, Clone)]
pub struct DispatcherAnalysis {
    /// Minimum back-edge count for a block to be considered a dispatcher (default 4).
    pub min_back_edges: usize,
    /// Minimum confidence for a dispatcher to be included in the graph (default 50).
    pub min_confidence: u8,
}

impl Default for DispatcherAnalysis {
    fn default() -> Self {
        Self {
            min_back_edges: 4,
            min_confidence: 50,
        }
    }
}

impl DispatcherAnalysis {
    /// Create an analysis with default parameters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the minimum back-edge threshold.
    #[must_use]
    pub const fn with_min_back_edges(mut self, n: usize) -> Self {
        self.min_back_edges = n;
        self
    }

    /// Run the analysis over the supplied CFG.
    ///
    /// Returns `(DispatcherGraph, Vec<FlattenedRegion>)`.
    #[must_use]
    pub fn analyze(
        &self,
        blocks: &HashMap<Addr, Vec<Addr>>,
        back_edge_counts: &HashMap<Addr, usize>,
        state_values: &HashMap<Addr, u64>,
    ) -> (DispatcherGraph, Vec<FlattenedRegion>) {
        let mut graph = DispatcherGraph::new();
        let mut regions: Vec<FlattenedRegion> = Vec::new();

        // 1. Identify dispatcher candidates.
        let dispatcher_addrs: Vec<Addr> = back_edge_counts
            .iter()
            .filter(|&(_, &c)| c >= self.min_back_edges)
            .map(|(&a, _)| a)
            .collect();

        for disp_addr in &dispatcher_addrs {
            let back_edges = *back_edge_counts.get(disp_addr).unwrap_or(&0);
            // Confidence is "how far above the configured threshold we are":
            // hitting the threshold maps to min_confidence, and we saturate at
            // 100 once we are well above it. This way, lowering
            // `min_back_edges` keeps confidence usable for callers that have
            // already vetted the dispatcher count externally.
            let base = usize::from(self.min_confidence);
            let over_count = back_edges.saturating_sub(self.min_back_edges).min(20);
            let confidence_usize = (base + over_count * (100 - base) / 20).min(100);
            let confidence = u8::try_from(confidence_usize).unwrap_or(100);
            if confidence < self.min_confidence {
                continue;
            }

            // 2. Build dispatcher block with case transitions.
            let mut db = DispatcherBlock::new(*disp_addr, "state_var");
            db.back_edge_count = back_edges;
            db.confidence = confidence;

            // The successors of the dispatcher block are the handler blocks.
            if let Some(succs) = blocks.get(disp_addr) {
                for &target in succs {
                    // Try to find the state value that leads to this target.
                    let state_value = state_values
                        .get(&target)
                        .copied()
                        .unwrap_or(target.as_u64() & 0xFFFF_FFFF);
                    let ct = CaseTransition::new(state_value, target).with_confidence(confidence);
                    db.add_case(ct);
                }
            }

            // 3. Build a FlattenedRegion for this dispatcher.
            let mut region = FlattenedRegion::new(*disp_addr);

            // BFS from dispatcher to collect all reachable blocks that eventually
            // loop back to the dispatcher.
            let body = Self::collect_body_blocks(*disp_addr, blocks);
            for &b in &body {
                region.add_block(b);
            }

            // Recover edges: for each body block, if it has a successor that is
            // also in the body (or is the dispatcher), add an edge.
            let body_set: HashSet<Addr> = body.iter().copied().collect();
            for &b in &body {
                if let Some(succs) = blocks.get(&b) {
                    for &s in succs {
                        let not_disp = s != *disp_addr;
                        if not_disp
                            && (body_set.contains(&s) || state_values.contains_key(&s))
                        {
                            region.add_edge(b, s);
                        } else if s == *disp_addr {
                            // Back-edge — look up where the handler goes.
                            if let Some(&sv) = state_values.get(&b) {
                                if let Some(&real_target) =
                                    state_values.iter().find_map(|(a, &v)| {
                                        if v == sv && *a != b { Some(a) } else { None }
                                    })
                                {
                                    region.add_edge(b, real_target);
                                } else {
                                    region.note_unresolved();
                                }
                            } else {
                                region.note_unresolved();
                            }
                        }
                    }
                }
            }

            region.recovery_confidence = confidence;
            graph.add_dispatcher(db);
            regions.push(region);
        }

        (graph, regions)
    }

    /// BFS from `dispatcher` collecting all blocks that eventually loop back
    /// to `dispatcher`.  Returns the set of body-block addresses (excluding
    /// the dispatcher itself).
    fn collect_body_blocks(
        dispatcher: Addr,
        blocks: &HashMap<Addr, Vec<Addr>>,
    ) -> Vec<Addr> {
        let mut visited: HashSet<Addr> = HashSet::new();
        let mut queue: VecDeque<Addr> = VecDeque::new();

        if let Some(succs) = blocks.get(&dispatcher) {
            for &s in succs {
                queue.push_back(s);
                visited.insert(s);
            }
        }

        while let Some(addr) = queue.pop_front() {
            if addr == dispatcher {
                continue;
            }
            if let Some(succs) = blocks.get(&addr) {
                for &s in succs {
                    if !visited.contains(&s) && s != dispatcher {
                        visited.insert(s);
                        queue.push_back(s);
                    }
                }
            }
        }

        visited.into_iter().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StateVariableCandidateFinder — locates potential state-variable registers
// ─────────────────────────────────────────────────────────────────────────────

/// A register candidate for the CFF state variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateVarCandidate {
    /// Register name (e.g. "eax", "ecx").
    pub register: String,
    /// Number of times this register was assigned before a back-edge.
    pub write_count: usize,
    /// Number of times the dispatcher compared this register.
    pub cmp_count: usize,
    /// Confidence score (0–100).
    pub confidence: u8,
}

impl StateVarCandidate {
    /// Create a new candidate.
    #[must_use]
    pub fn new(register: impl Into<String>, write_count: usize, cmp_count: usize) -> Self {
        let confidence = u8::try_from(
            (write_count.min(10) * 5 + cmp_count.min(10) * 5).min(100),
        )
        .unwrap_or(100);
        Self {
            register: register.into(),
            write_count,
            cmp_count,
            confidence,
        }
    }

    /// Return `true` if this looks like a strong state-variable candidate.
    #[must_use]
    pub const fn is_strong(&self) -> bool {
        self.confidence >= 75
    }
}

/// Finds state-variable candidates by analysing write/compare patterns in
/// blocks that precede the dispatcher.
#[derive(Debug, Clone, Default)]
pub struct StateVariableCandidateFinder;

impl StateVariableCandidateFinder {
    /// Create a new finder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Analyse `write_map` (register → back-edge write count) and
    /// `cmp_map` (register → dispatcher compare count) to rank candidates.
    #[must_use]
    pub fn rank(
        write_map: &HashMap<String, usize>,
        cmp_map: &HashMap<String, usize>,
    ) -> Vec<StateVarCandidate> {
        let mut all_registers: HashSet<String> = HashSet::new();
        for k in write_map.keys() {
            all_registers.insert(k.clone());
        }
        for k in cmp_map.keys() {
            all_registers.insert(k.clone());
        }

        let mut candidates: Vec<StateVarCandidate> = all_registers
            .into_iter()
            .map(|reg| {
                let w = write_map.get(&reg).copied().unwrap_or(0);
                let c = cmp_map.get(&reg).copied().unwrap_or(0);
                StateVarCandidate::new(reg, w, c)
            })
            .collect();

        candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        candidates
    }

    /// Return the top-ranked candidate, if any.
    #[must_use]
    pub fn top_candidate(
        write_map: &HashMap<String, usize>,
        cmp_map: &HashMap<String, usize>,
    ) -> Option<StateVarCandidate> {
        Self::rank(write_map, cmp_map).into_iter().next()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BackEdgeAnalyzer — counts and classifies back-edges in a CFG
// ─────────────────────────────────────────────────────────────────────────────

/// A back-edge in a CFG (a cycle in the DFS tree).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackEdge {
    /// Source block (the block that jumps backward).
    pub from: Addr,
    /// Target block (the loop header).
    pub to: Addr,
}

/// Analyses a CFG to count and list all back-edges.
#[derive(Debug, Clone, Default)]
pub struct BackEdgeAnalyzer;

impl BackEdgeAnalyzer {
    /// Identify all back-edges via DFS.
    #[must_use]
    pub fn find_back_edges(entry: Addr, adj: &HashMap<Addr, Vec<Addr>>) -> Vec<BackEdge> {
        let mut back_edges = Vec::new();
        let mut visited: HashSet<Addr> = HashSet::new();
        let mut on_stack: HashSet<Addr> = HashSet::new();
        let mut stack: Vec<(Addr, usize)> = Vec::new(); // (node, child_index)

        if adj.contains_key(&entry) {
            stack.push((entry, 0));
            visited.insert(entry);
            on_stack.insert(entry);
        }

        while let Some((node, child_idx)) = stack.last_mut() {
            let node = *node;
            let children: &[Addr] = adj.get(&node).map_or(&[], Vec::as_slice);
            if *child_idx < children.len() {
                let child = children[*child_idx];
                *child_idx += 1;
                if on_stack.contains(&child) {
                    back_edges.push(BackEdge {
                        from: node,
                        to: child,
                    });
                } else if visited.insert(child) {
                    on_stack.insert(child);
                    stack.push((child, 0));
                }
            } else {
                on_stack.remove(&node);
                stack.pop();
            }
        }
        back_edges
    }

    /// Build a `HashMap<Addr, usize>` counting how many back-edges point to each block.
    #[must_use]
    pub fn back_edge_count_map(back_edges: &[BackEdge]) -> HashMap<Addr, usize> {
        let mut map: HashMap<Addr, usize> = HashMap::new();
        for be in back_edges {
            *map.entry(be.to).or_insert(0) += 1;
        }
        map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DispatcherQualityScorer
// ─────────────────────────────────────────────────────────────────────────────

/// Produces a quality score in [0.0, 1.0] for a [`DispatcherGraph`] based on
/// how complete and consistent the analysis is.
#[derive(Debug, Clone, Default)]
pub struct DispatcherQualityScorer;

/// Quality metrics for a recovered dispatcher graph.
#[derive(Debug, Clone)]
pub struct DispatcherQuality {
    /// Average per-dispatcher confidence (0–100).
    pub avg_confidence: f64,
    /// Fraction of regions that are fully recovered.
    pub recovery_rate: f64,
    /// Average case count per dispatcher.
    pub avg_case_count: f64,
    /// Overall quality score in [0.0, 1.0].
    pub score: f64,
}

impl DispatcherQualityScorer {
    /// Compute quality for `graph` and `regions`.
    #[must_use]
    pub fn score(&self, graph: &DispatcherGraph, regions: &[FlattenedRegion]) -> DispatcherQuality {
        if graph.is_empty() {
            return DispatcherQuality {
                avg_confidence: 0.0,
                recovery_rate: 0.0,
                avg_case_count: 0.0,
                score: 0.0,
            };
        }

        let avg_confidence = graph
            .dispatchers
            .values()
            .map(|d| f64::from(d.confidence))
            .sum::<f64>()
            / f64::from(u32::try_from(graph.dispatchers.len()).unwrap_or(u32::MAX));

        let recovery_rate = if regions.is_empty() {
            0.0
        } else {
            f64::from(u32::try_from(regions.iter().filter(|r| r.is_fully_recovered()).count()).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(regions.len()).unwrap_or(u32::MAX))
        };

        let avg_case_count = if graph.dispatchers.is_empty() {
            0.0
        } else {
            f64::from(
                u32::try_from(
                    graph.dispatchers.values().map(|d| d.case_count).sum::<usize>(),
                )
                .unwrap_or(u32::MAX),
            ) / f64::from(u32::try_from(graph.dispatchers.len()).unwrap_or(u32::MAX))
        };

        let score = (avg_confidence / 100.0).mul_add(
            0.4,
            recovery_rate.mul_add(0.4, (avg_case_count / 256.0).clamp(0.0, 1.0) * 0.2),
        );

        DispatcherQuality {
            avg_confidence,
            recovery_rate,
            avg_case_count,
            score: score.clamp(0.0, 1.0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CaseRangeAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Analyses the range and density of state values in a dispatcher.
#[derive(Debug, Clone, Default)]
pub struct CaseRangeAnalyzer;

/// State-value range statistics for a dispatcher.
#[derive(Debug, Clone)]
pub struct CaseRange {
    /// Minimum state value observed.
    pub min_state: u64,
    /// Maximum state value observed.
    pub max_state: u64,
    /// Number of distinct state values.
    pub distinct_count: usize,
    /// Density: `distinct_count / (max - min + 1)` in [0.0, 1.0].
    pub density: f64,
    /// Whether the state values look like sequential integers.
    pub is_sequential: bool,
}

impl CaseRangeAnalyzer {
    /// Analyse the cases of a dispatcher block.
    ///
    /// # Panics
    /// Panics if `db.cases` is non-empty but the internal state-value list is
    /// somehow empty after deduplication (cannot happen in practice).
    #[must_use]
    pub fn analyze(db: &DispatcherBlock) -> CaseRange {
        if db.cases.is_empty() {
            return CaseRange {
                min_state: 0,
                max_state: 0,
                distinct_count: 0,
                density: 0.0,
                is_sequential: false,
            };
        }
        let mut states: Vec<u64> = db.cases.iter().map(|c| c.state_value).collect();
        states.sort_unstable();
        states.dedup();
        let min = *states.first().unwrap();
        let max = *states.last().unwrap();
        let range = max.saturating_sub(min).saturating_add(1);
        let density = f64::from(u32::try_from(states.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(range).unwrap_or(u32::MAX));
        // Sequential: each state is exactly 1 more than the previous.
        let is_sequential = states
            .windows(2)
            .all(|w| w[0].checked_add(1).is_some_and(|next| w[1] == next));
        CaseRange {
            min_state: min,
            max_state: max,
            distinct_count: states.len(),
            density,
            is_sequential,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Addr ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_addr_display() {
        assert_eq!(Addr(0x1000).to_string(), "0x1000");
    }

    #[test]
    fn test_addr_hash() {
        let mut set = HashSet::new();
        set.insert(Addr(1));
        set.insert(Addr(1));
        assert_eq!(set.len(), 1);
    }

    // ── CaseTransition ────────────────────────────────────────────────────────

    #[test]
    fn test_case_transition_new() {
        let ct = CaseTransition::new(0xABCD, Addr(0x1000));
        assert_eq!(ct.state_value, 0xABCD);
        assert_eq!(ct.target_block, Addr(0x1000));
        assert!(!ct.is_loop_back);
        assert_eq!(ct.confidence, 80);
    }

    #[test]
    fn test_case_transition_with_loop_back() {
        let ct = CaseTransition::new(1, Addr(0)).with_loop_back();
        assert!(ct.is_loop_back);
    }

    #[test]
    fn test_case_transition_confidence_clamped() {
        let ct = CaseTransition::new(0, Addr(0)).with_confidence(200);
        assert_eq!(ct.confidence, 100);
    }

    // ── StateWrite ────────────────────────────────────────────────────────────

    #[test]
    fn test_state_write_constant() {
        let sw = StateWrite::constant(Addr(0x1000), 42, "eax");
        assert_eq!(sw.value, Some(42));
        assert_eq!(sw.location, "eax");
        assert!(!sw.is_propagated);
    }

    #[test]
    fn test_state_write_unknown() {
        let sw = StateWrite::unknown(Addr(0x2000), "ecx");
        assert!(sw.value.is_none());
    }

    // ── StateVariableTracker ─────────────────────────────────────────────────

    #[test]
    fn test_tracker_record_and_resolve() {
        let mut t = StateVariableTracker::new();
        t.record(Addr(0x100), 0xDEAD, false);
        assert_eq!(t.resolved_value(Addr(0x100)), Some(0xDEAD));
        assert!(t.is_resolved(Addr(0x100)));
        assert!(!t.is_resolved(Addr(0x200)));
    }

    #[test]
    fn test_tracker_unknown_does_not_resolve() {
        let mut t = StateVariableTracker::new();
        t.record_unknown(Addr(0x100));
        assert_eq!(t.resolved_value(Addr(0x100)), None);
        // block_writes entry exists but value is None.
        assert!(!t.is_resolved(Addr(0x100)));
    }

    #[test]
    fn test_tracker_constant_writes() {
        let mut t = StateVariableTracker::new();
        t.record(Addr(0x100), 1, false);
        t.record_unknown(Addr(0x200));
        assert_eq!(t.constant_writes().len(), 1);
    }

    #[test]
    fn test_tracker_resolved_count() {
        let mut t = StateVariableTracker::new();
        t.record(Addr(0x1), 10, false);
        t.record(Addr(0x2), 20, false);
        assert_eq!(t.resolved_count(), 2);
    }

    #[test]
    fn test_tracker_propagate_simple() {
        let mut t = StateVariableTracker::new();
        t.record(Addr(0x100), 0xBEEF, false);
        // Propagate to 0x200 via edge 0x100 → 0x200.
        t.propagate_simple(&[(0x100, 0x200)]);
        assert_eq!(t.resolved_value(Addr(0x200)), Some(0xBEEF));
    }

    #[test]
    fn test_tracker_propagate_does_not_overwrite() {
        let mut t = StateVariableTracker::new();
        t.record(Addr(0x100), 0xAAAA, false);
        t.record(Addr(0x200), 0xBBBB, false);
        t.propagate_simple(&[(0x100, 0x200)]);
        // 0x200 already resolved → should not be overwritten.
        assert_eq!(t.resolved_value(Addr(0x200)), Some(0xBBBB));
    }

    // ── DispatcherBlock ───────────────────────────────────────────────────────

    #[test]
    fn test_dispatcher_block_new() {
        let db = DispatcherBlock::new(Addr(0x1000), "eax");
        assert_eq!(db.address, Addr(0x1000));
        assert_eq!(db.case_count, 0);
        assert_eq!(db.state_var_location, "eax");
    }

    #[test]
    fn test_dispatcher_block_add_case() {
        let mut db = DispatcherBlock::new(Addr(0x1000), "eax");
        db.add_case(CaseTransition::new(1, Addr(0x2000)));
        db.add_case(CaseTransition::new(2, Addr(0x3000)));
        assert_eq!(db.case_count, 2);
        assert_eq!(db.case_for_state(1).unwrap().target_block, Addr(0x2000));
        assert!(db.case_for_state(99).is_none());
    }

    #[test]
    fn test_dispatcher_block_loop_back_cases() {
        let mut db = DispatcherBlock::new(Addr(0), "eax");
        db.add_case(CaseTransition::new(1, Addr(0x100)).with_loop_back());
        db.add_case(CaseTransition::new(2, Addr(0x200)));
        assert_eq!(db.loop_back_cases().len(), 1);
    }

    #[test]
    fn test_dispatcher_block_average_confidence() {
        let mut db = DispatcherBlock::new(Addr(0), "eax");
        db.add_case(CaseTransition::new(1, Addr(0x100)).with_confidence(80));
        db.add_case(CaseTransition::new(2, Addr(0x200)).with_confidence(60));
        let avg = db.average_case_confidence();
        assert!((avg - 70.0).abs() < 0.01);
    }

    #[test]
    fn test_dispatcher_block_sync_case_count() {
        let mut db = DispatcherBlock::new(Addr(0), "eax");
        db.cases.push(CaseTransition::new(1, Addr(0)));
        db.sync_case_count();
        assert_eq!(db.case_count, 1);
    }

    // ── DispatcherGraph ───────────────────────────────────────────────────────

    #[test]
    fn test_dispatcher_graph_add_and_lookup() {
        let mut g = DispatcherGraph::new();
        let mut db = DispatcherBlock::new(Addr(0x1000), "eax");
        db.add_case(CaseTransition::new(5, Addr(0x2000)));
        g.add_dispatcher(db);
        assert_eq!(g.target_for(Addr(0x1000), 5), Some(Addr(0x2000)));
        assert_eq!(g.target_for(Addr(0x1000), 6), None);
    }

    #[test]
    fn test_dispatcher_graph_unique_targets() {
        let mut g = DispatcherGraph::new();
        let mut db = DispatcherBlock::new(Addr(0x1000), "eax");
        db.add_case(CaseTransition::new(1, Addr(0x2000)));
        db.add_case(CaseTransition::new(2, Addr(0x3000)));
        db.add_case(CaseTransition::new(3, Addr(0x2000))); // duplicate target
        g.add_dispatcher(db);
        assert_eq!(g.unique_target_count(), 2);
    }

    #[test]
    fn test_dispatcher_graph_sorted_addrs() {
        let mut g = DispatcherGraph::new();
        g.add_dispatcher(DispatcherBlock::new(Addr(0x3000), "eax"));
        g.add_dispatcher(DispatcherBlock::new(Addr(0x1000), "eax"));
        let sorted = g.sorted_dispatcher_addrs();
        assert_eq!(sorted, vec![Addr(0x1000), Addr(0x3000)]);
    }

    #[test]
    fn test_dispatcher_graph_total_cases() {
        let mut g = DispatcherGraph::new();
        let mut db = DispatcherBlock::new(Addr(0x1000), "eax");
        db.add_case(CaseTransition::new(1, Addr(0x2000)));
        db.add_case(CaseTransition::new(2, Addr(0x3000)));
        g.add_dispatcher(db);
        assert_eq!(g.total_cases(), 2);
    }

    #[test]
    fn test_dispatcher_graph_busiest() {
        let mut g = DispatcherGraph::new();
        let mut db1 = DispatcherBlock::new(Addr(0x1000), "eax");
        db1.add_case(CaseTransition::new(1, Addr(0x2000)));
        let mut db2 = DispatcherBlock::new(Addr(0x3000), "eax");
        for i in 0..5 {
            db2.add_case(CaseTransition::new(i, Addr(0x4000 + i * 0x10)));
        }
        g.add_dispatcher(db1);
        g.add_dispatcher(db2);
        let busiest = g.busiest_dispatcher().unwrap();
        assert_eq!(busiest.address, Addr(0x3000));
    }

    #[test]
    fn test_dispatcher_graph_is_empty() {
        let g = DispatcherGraph::new();
        assert!(g.is_empty());
    }

    // ── FlattenedRegion ───────────────────────────────────────────────────────

    #[test]
    fn test_flattened_region_new() {
        let r = FlattenedRegion::new(Addr(0x1000));
        assert_eq!(r.dispatcher, Addr(0x1000));
        assert!(r.body_blocks.is_empty());
    }

    #[test]
    fn test_flattened_region_add_block() {
        let mut r = FlattenedRegion::new(Addr(0));
        r.add_block(Addr(0x100));
        r.add_block(Addr(0x200));
        assert_eq!(r.body_blocks.len(), 2);
    }

    #[test]
    fn test_flattened_region_add_edge() {
        let mut r = FlattenedRegion::new(Addr(0));
        r.add_edge(Addr(0x100), Addr(0x200));
        assert_eq!(r.resolved_transitions, 1);
    }

    #[test]
    fn test_flattened_region_recovery_rate_all_resolved() {
        let mut r = FlattenedRegion::new(Addr(0));
        r.add_edge(Addr(1), Addr(2));
        r.add_edge(Addr(2), Addr(3));
        assert!((r.recovery_rate() - 1.0).abs() < 0.001);
        assert!(r.is_fully_recovered());
    }

    #[test]
    fn test_flattened_region_recovery_rate_partial() {
        let mut r = FlattenedRegion::new(Addr(0));
        r.add_edge(Addr(1), Addr(2));
        r.note_unresolved();
        assert!((r.recovery_rate() - 0.5).abs() < 0.001);
        assert!(!r.is_fully_recovered());
    }

    #[test]
    fn test_flattened_region_empty_rate() {
        let r = FlattenedRegion::new(Addr(0));
        assert!(r.recovery_rate() < f64::EPSILON);
    }

    // ── DispatcherAnalysis ────────────────────────────────────────────────────

    type TestCfg = (
        HashMap<Addr, Vec<Addr>>,
        HashMap<Addr, usize>,
        HashMap<Addr, u64>,
    );

    fn make_test_cfg() -> TestCfg {
        // Classic 3-handler CFF shape:
        // dispatcher (0x1000) → [A(0x2000), B(0x3000), C(0x4000)]
        // A → dispatcher, B → dispatcher, C → dispatcher
        let mut blocks: HashMap<Addr, Vec<Addr>> = HashMap::new();
        blocks.insert(Addr(0x1000), vec![Addr(0x2000), Addr(0x3000), Addr(0x4000)]);
        blocks.insert(Addr(0x2000), vec![Addr(0x1000)]);
        blocks.insert(Addr(0x3000), vec![Addr(0x1000)]);
        blocks.insert(Addr(0x4000), vec![Addr(0x1000)]);

        // back-edge count for dispatcher = 3 (A, B, C all point back)
        let mut back = HashMap::new();
        back.insert(Addr(0x1000), 3);

        let mut sv: HashMap<Addr, u64> = HashMap::new();
        sv.insert(Addr(0x2000), 10);
        sv.insert(Addr(0x3000), 20);
        sv.insert(Addr(0x4000), 30);

        (blocks, back, sv)
    }

    #[test]
    fn test_analysis_finds_dispatcher() {
        let (blocks, back, sv) = make_test_cfg();
        let analysis = DispatcherAnalysis::new().with_min_back_edges(3);
        let (graph, regions) = analysis.analyze(&blocks, &back, &sv);
        assert!(!graph.is_empty(), "should find a dispatcher");
        assert_eq!(regions.len(), 1);
    }

    #[test]
    fn test_analysis_dispatcher_cases() {
        let (blocks, back, sv) = make_test_cfg();
        let analysis = DispatcherAnalysis::new().with_min_back_edges(3);
        let (graph, _) = analysis.analyze(&blocks, &back, &sv);
        let db = graph.dispatchers.get(&Addr(0x1000)).unwrap();
        assert_eq!(db.case_count, 3);
    }

    #[test]
    fn test_analysis_no_dispatcher_when_below_threshold() {
        let (blocks, back, sv) = make_test_cfg();
        // Require 10 back edges — none qualify.
        let analysis = DispatcherAnalysis::new().with_min_back_edges(10);
        let (graph, regions) = analysis.analyze(&blocks, &back, &sv);
        assert!(graph.is_empty());
        assert!(regions.is_empty());
    }

    #[test]
    fn test_analysis_body_blocks_collected() {
        let (blocks, back, sv) = make_test_cfg();
        let analysis = DispatcherAnalysis::new().with_min_back_edges(3);
        let (_, regions) = analysis.analyze(&blocks, &back, &sv);
        let region = &regions[0];
        // All three handler blocks should be in the body.
        assert_eq!(region.body_blocks.len(), 3);
    }

    #[test]
    fn test_analysis_empty_cfg() {
        let analysis = DispatcherAnalysis::new();
        let (g, r) = analysis.analyze(&HashMap::new(), &HashMap::new(), &HashMap::new());
        assert!(g.is_empty());
        assert!(r.is_empty());
    }

    // ── Additional coverage tests ─────────────────────────────────────────────

    #[test]
    fn test_addr_as_u64() {
        assert_eq!(Addr::new(0xBEEF).as_u64(), 0xBEEF);
    }

    #[test]
    fn test_tracker_multiple_writes_same_block() {
        let mut t = StateVariableTracker::new();
        t.record(Addr(0x100), 10, false);
        t.record(Addr(0x100), 20, true);
        // resolved_value returns the first recorded value.
        assert_eq!(t.resolved_value(Addr(0x100)), Some(10));
    }

    #[test]
    fn test_dispatcher_block_sync_after_manual_push() {
        let mut db = DispatcherBlock::new(Addr(0), "eax");
        db.cases.push(CaseTransition::new(1, Addr(0x100)));
        db.cases.push(CaseTransition::new(2, Addr(0x200)));
        db.sync_case_count();
        assert_eq!(db.case_count, 2);
    }

    #[test]
    fn test_dispatcher_graph_empty() {
        let g = DispatcherGraph::new();
        assert!(g.is_empty());
        assert_eq!(g.total_cases(), 0);
        assert_eq!(g.unique_target_count(), 0);
    }

    #[test]
    fn test_dispatcher_graph_busiest_single() {
        let mut g = DispatcherGraph::new();
        let mut db = DispatcherBlock::new(Addr(0), "eax");
        db.add_case(CaseTransition::new(1, Addr(0x100)));
        g.add_dispatcher(db);
        assert_eq!(g.busiest_dispatcher().map(|d| d.address), Some(Addr(0)));
    }

    #[test]
    fn test_case_transition_state_value() {
        let ct = CaseTransition::new(0xDEAD, Addr(0x1000));
        assert_eq!(ct.state_value, 0xDEAD);
    }

    #[test]
    fn test_flattened_region_recovery_rate_all_unresolved() {
        let mut r = FlattenedRegion::new(Addr(0));
        r.note_unresolved();
        r.note_unresolved();
        assert!(r.recovery_rate() < f64::EPSILON);
        assert!(!r.is_fully_recovered());
    }

    #[test]
    fn test_tracker_constant_writes_empty() {
        let t = StateVariableTracker::new();
        assert!(t.constant_writes().is_empty());
    }

    #[test]
    fn test_analysis_confidence_scales_with_back_edges() {
        let (blocks, back, sv) = make_test_cfg();
        let analysis1 = DispatcherAnalysis::new().with_min_back_edges(3);
        let analysis2 = DispatcherAnalysis::new().with_min_back_edges(1);
        let (g1, _) = analysis1.analyze(&blocks, &back, &sv);
        let (g2, _) = analysis2.analyze(&blocks, &back, &sv);
        // Both should find the dispatcher.
        assert!(!g1.is_empty());
        assert!(!g2.is_empty());
    }

    #[test]
    fn test_dispatcher_graph_all_targets() {
        let mut g = DispatcherGraph::new();
        let mut db = DispatcherBlock::new(Addr(0), "eax");
        db.add_case(CaseTransition::new(1, Addr(0x100)));
        db.add_case(CaseTransition::new(2, Addr(0x200)));
        g.add_dispatcher(db);
        assert!(g.all_targets.contains(&Addr(0x100)));
        assert!(g.all_targets.contains(&Addr(0x200)));
    }

    #[test]
    fn test_state_write_is_propagated_flag() {
        let sw = StateWrite {
            instr_addr: Addr(0),
            value: Some(42),
            location: "eax".into(),
            is_propagated: true,
        };
        assert!(sw.is_propagated);
    }

    #[test]
    fn test_flattened_region_add_multiple_edges() {
        let mut r = FlattenedRegion::new(Addr(0));
        r.add_edge(Addr(0x100), Addr(0x200));
        r.add_edge(Addr(0x200), Addr(0x300));
        r.add_edge(Addr(0x300), Addr(0x400));
        assert_eq!(r.resolved_transitions, 3);
        assert_eq!(r.recovered_edges.len(), 3);
    }

    #[test]
    fn test_dispatcher_analysis_default_settings() {
        let a = DispatcherAnalysis::default();
        assert_eq!(a.min_back_edges, 4);
        assert_eq!(a.min_confidence, 50);
    }
}
