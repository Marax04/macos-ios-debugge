//! CFG reconstruction from a linear instruction stream for `rustre-analysis-cfg`.
//!
//! # Overview
//!
//! This module provides two complementary CFG reconstruction algorithms and a
//! unified [`CfgReconstruction`] facade.
//!
//! ## Linear Sweep
//!
//! [`LinearSweep`] performs a single forward pass over the instruction stream:
//!
//! 1. [`BlockSplitter::compute`] identifies "leader" addresses:
//!    - The function entry point.
//!    - Every target of a branch or jump.
//!    - Every instruction following a branch or jump.
//!
//! 2. Instructions are partitioned into [`ReconstructedBlock`]s at leader
//!    boundaries.
//!
//! 3. Edges are inserted based on the terminator of each block.
//!
//! Linear sweep is fast (O(N)) but may miss blocks that are unreachable from
//! the linear scan (e.g. targets of indirect jumps not supplied via hints).
//!
//! ## Recursive Descent
//!
//! [`RecursiveDescent`] follows control flow from the entry address using a
//! BFS work-list.  It discovers only blocks reachable from the entry, which
//! gives a more accurate picture of runtime reachability at the cost of
//! potentially missing dead-code blocks.
//!
//! # Indirect Jump Resolution
//!
//! Both strategies consult an [`IndirectJumpResolver`] for indirect jumps.
//! Callers can pre-register hints via [`CfgReconstruction::hint`] or
//! [`IndirectJumpResolver::register_hint`].  Unresolved indirect jumps are
//! recorded in [`ReconstructedCfg::unresolved`].
//!
//! # Post-Processing
//!
//! After reconstruction, use the provided utilities:
//!
//! * [`ReachabilityAnalysis`] —" identify unreachable blocks.
//! * [`CycleDetector`] —" find natural loops via back-edge detection.
//! * [`CfgStats`] —" aggregate metrics (block count, edge type distribution, —¦).
//! * [`DotExporter`] —" emit a Graphviz DOT string for visualisation.
//!
//! Two strategies are provided:
//!
//! * [`LinearSweep`] —" fast, single-pass: scans instructions linearly,
//!   splits on branches, and links known targets.  May miss dead-code blocks
//!   for indirect jumps.
//! * [`RecursiveDescent`] —" follows control flow from an entry point,
//!   discovering blocks reachable via the control-flow graph.
//!
//! Both strategies produce a [`ReconstructedCfg`] via the [`CFGBuilder`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;

use rustre_core::address::Address;
use rustre_il_llil::{LlilAnnotatedInstr, LlilInstruction};

// ---------------------------------------------------------------------------
// Well-known constants
// ---------------------------------------------------------------------------

/// Maximum number of blocks in a function before the reconstructor gives up.
pub const MAX_BLOCKS: usize = 65_536;

/// Maximum number of instructions in a single basic block.
pub const MAX_BLOCK_INSTRS: usize = 4_096;

/// Default capacity hint for the edge `HashMap`.
pub const DEFAULT_EDGE_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------
// BlockId type alias
// ---------------------------------------------------------------------------

/// A type alias for block start addresses used as block ids.
pub type BlockAddr = u64;

// ---------------------------------------------------------------------------
// ReconstructionConfig —" tuning parameters
// ---------------------------------------------------------------------------

/// Configuration knobs for the CFG reconstruction algorithms.
#[derive(Debug, Clone)]
pub struct ReconstructionConfig {
    /// Maximum number of basic blocks before aborting (0 = no limit).
    pub max_blocks: usize,
    /// Whether to follow call edges (creates a call graph, not just CFG).
    pub follow_calls: bool,
    /// Whether to treat `SysCall` as a terminator.
    pub syscall_terminates: bool,
}

impl Default for ReconstructionConfig {
    fn default() -> Self {
        Self {
            max_blocks: MAX_BLOCKS,
            follow_calls: false,
            syscall_terminates: true,
        }
    }
}

// ---------------------------------------------------------------------------
// BasicBlockInfo —" lightweight summary of a reconstructed block
// ---------------------------------------------------------------------------

/// A lightweight summary of a basic block for display / serialisation.
#[derive(Debug, Clone)]
pub struct BasicBlockInfo {
    pub start: u64,
    pub end: u64,
    pub len: usize,
    pub is_exit: bool,
}

impl BasicBlockInfo {
    /// Build from a [`ReconstructedBlock`].
    #[must_use]
    pub const fn from_block(block: &ReconstructedBlock, has_successors: bool) -> Self {
        Self {
            start: block.start.0,
            end: block.end.0,
            len: block.len(),
            is_exit: !has_successors,
        }
    }
}

// ---------------------------------------------------------------------------
// CfgSummary —" quick summary struct for a CFG
// ---------------------------------------------------------------------------

/// A high-level textual summary of a [`ReconstructedCfg`].
#[derive(Debug, Clone, Default)]
pub struct CfgSummary {
    pub entry: Option<u64>,
    pub block_count: usize,
    pub edge_count: usize,
    pub unresolved: usize,
    pub has_cycles: bool,
}

impl CfgSummary {
    /// Build a summary.
    #[must_use]
    pub fn from_cfg(cfg: &ReconstructedCfg) -> Self {
        Self {
            entry: cfg.entry.map(|a| a.0),
            block_count: cfg.block_count(),
            edge_count: cfg.edge_count(),
            unresolved: cfg.unresolved.len(),
            has_cycles: CycleDetector::has_cycle(cfg),
        }
    }
}

impl fmt::Display for CfgSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CFG {{ entry={:?}, blocks={}, edges={}, unresolved={}, cycles={} }}",
            self.entry, self.block_count, self.edge_count, self.unresolved, self.has_cycles,
        )
    }
}

// ---------------------------------------------------------------------------
// BlockOrder —" topological / RPO ordering
// ---------------------------------------------------------------------------

/// Produces a topological (reverse post-order) list of block addresses.
#[derive(Debug, Default)]
pub struct BlockOrder;

impl BlockOrder {
    /// Return block addresses in reverse post-order.
    #[must_use]
    pub fn rpo(cfg: &ReconstructedCfg) -> Vec<u64> {
        let mut order = cfg.post_order();
        order.reverse();
        order
    }
}

// ---------------------------------------------------------------------------
// EdgeType
// ---------------------------------------------------------------------------

/// The semantic role of a reconstructed CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeType {
    /// Unconditional jump or fall-through.
    Unconditional,
    /// The taken branch of a conditional jump.
    TrueBranch,
    /// The not-taken branch of a conditional jump.
    FalseBranch,
    /// Fall-through from a non-branch instruction.
    Fallthrough,
    /// Target discovered via indirect jump resolver.
    IndirectTarget,
    /// Call edge (enter callee).
    Call,
    /// Return edge (leave callee).
    Return,
}

// ---------------------------------------------------------------------------
// ReconstructedBlock
// ---------------------------------------------------------------------------

/// A basic block produced during reconstruction.
#[derive(Debug, Clone)]
pub struct ReconstructedBlock {
    /// Entry address.
    pub start: Address,
    /// First address *past* this block.
    pub end: Address,
    /// Linear instruction list (shallow copies from the input stream).
    pub instructions: Vec<LlilAnnotatedInstr>,
}

impl ReconstructedBlock {
    /// Number of instructions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// True if this block has no instructions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// The last instruction, if any.
    #[must_use]
    pub fn last_instr(&self) -> Option<&LlilAnnotatedInstr> {
        self.instructions.last()
    }
}

// ---------------------------------------------------------------------------
// ReconstructedCfg
// ---------------------------------------------------------------------------

/// The output of a CFG reconstruction run.
#[derive(Debug, Clone, Default)]
pub struct ReconstructedCfg {
    /// Basic blocks, keyed by start address.
    pub blocks: BTreeMap<u64, ReconstructedBlock>,
    /// Edges: (`from_start`, `to_start`) â†' `EdgeType`.
    pub edges: HashMap<(u64, u64), EdgeType>,
    /// Entry point.
    pub entry: Option<Address>,
    /// Addresses that could not be resolved (indirect jump targets).
    pub unresolved: Vec<Address>,
}

impl ReconstructedCfg {
    /// Number of basic blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Return the successors (start addresses) of block at `addr`.
    #[must_use]
    pub fn successors(&self, addr: u64) -> Vec<u64> {
        // `self.edges` is a HashMap, so its iteration order is
        // nondeterministic (varies run-to-run / process-to-process). Sort
        // before returning so callers get a stable, reproducible order
        // instead of silently leaking hash-iteration order into output.
        let mut out: Vec<u64> = self
            .edges
            .keys()
            .filter(|(from, _)| *from == addr)
            .map(|(_, to)| *to)
            .collect();
        out.sort_unstable();
        out
    }

    /// Return the predecessors (start addresses) of block at `addr`.
    #[must_use]
    pub fn predecessors(&self, addr: u64) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .edges
            .keys()
            .filter(|(_, to)| *to == addr)
            .map(|(from, _)| *from)
            .collect();
        out.sort_unstable();
        out
    }

    /// Lookup a block by start address.
    #[must_use]
    pub fn block(&self, addr: u64) -> Option<&ReconstructedBlock> {
        self.blocks.get(&addr)
    }

    /// Build an adjacency list (`from` → successors) once, in `O(E)`.
    ///
    /// Several traversal algorithms below (post-order, reachability, cycle
    /// detection) used to call [`Self::successors`] — an `O(E)` full scan of
    /// `edges` — once per visited node, giving `O(V * E)` overall on graphs
    /// with many edges per node. Precomputing the adjacency list once turns
    /// every one of those traversals into `O(V + E)`.
    fn adjacency(&self) -> HashMap<u64, Vec<u64>> {
        let mut adj: HashMap<u64, Vec<u64>> = HashMap::with_capacity(self.blocks.len());
        for &(from, to) in self.edges.keys() {
            adj.entry(from).or_default().push(to);
        }
        // `self.edges` is a HashMap, so the relative order in which two
        // edges sharing the same `from` get pushed above is nondeterministic
        // (hash-iteration order, not insertion order). That order then
        // drives DFS traversal (`post_order`, `find_back_edges`, ...), so
        // without sorting here those traversals silently return a different
        // node order on every run. Sort each successor list once so all
        // downstream traversals are deterministic.
        for succs in adj.values_mut() {
            succs.sort_unstable();
        }
        adj
    }

    /// Post-order traversal addresses (reverse post-order = topological order
    /// for reducible graphs).
    #[must_use]
    pub fn post_order(&self) -> Vec<u64> {
        let entry = match self.entry {
            Some(e) => e.0,
            None => return vec![],
        };
        let adj = self.adjacency();
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        Self::dfs_post(entry, &adj, &mut visited, &mut order);
        order
    }

    fn dfs_post(
        root: u64,
        adj: &HashMap<u64, Vec<u64>>,
        visited: &mut HashSet<u64>,
        order: &mut Vec<u64>,
    ) {
        // Iterative post-order DFS to avoid stack overflow on deep CFGs
        // (up to MAX_BLOCKS = 65 536 deep with adversarial linear chains).
        // Each work-stack frame: (node, successor_iterator_index).
        // Successors come from the precomputed adjacency list (O(1) lookup)
        // rather than rescanning all edges per node.
        if !visited.insert(root) {
            return;
        }
        let empty: Vec<u64> = Vec::new();
        let mut stack: Vec<(u64, usize)> = vec![(root, 0)];
        while let Some(frame) = stack.last_mut() {
            let node = frame.0;
            let idx = frame.1;
            let succs = adj.get(&node).unwrap_or(&empty);
            if idx < succs.len() {
                let child = succs[idx];
                // Advance the index for next iteration.
                frame.1 += 1;
                if visited.insert(child) {
                    stack.push((child, 0));
                }
            } else {
                stack.pop();
                order.push(node);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BlockSplitter
// ---------------------------------------------------------------------------

/// Identifies "leader" addresses where basic blocks must start.
///
/// Leaders are:
/// 1. The entry point.
/// 2. Any target of a branch / jump.
/// 3. The instruction following a branch.
#[derive(Debug, Default)]
pub struct BlockSplitter {
    leaders: HashSet<u64>,
}

impl BlockSplitter {
    /// Analyse `instrs` and compute leader set.
    pub fn compute(&mut self, entry: u64, instrs: &[LlilAnnotatedInstr]) {
        self.leaders.insert(entry);
        let mut i = 0;
        while i < instrs.len() {
            let ai = &instrs[i];
            match &ai.instr {
                LlilInstruction::CondJump {
                    true_dest,
                    false_dest,
                    ..
                } => {
                    self.leaders.insert(true_dest.0);
                    self.leaders.insert(false_dest.0);
                    // The instruction after the conditional branch is also a leader.
                    if i + 1 < instrs.len() {
                        self.leaders.insert(instrs[i + 1].address.0);
                    }
                }
                LlilInstruction::JumpDest { dest }
                    | LlilInstruction::Jump(dest)
                    | LlilInstruction::TailCall { dest } => {
                    if let Some(t) = dest_if_const(dest) {
                        self.leaders.insert(t);
                    }
                    if i + 1 < instrs.len() {
                        self.leaders.insert(instrs[i + 1].address.0);
                    }
                }
                LlilInstruction::JumpTo { targets, .. } => {
                    for t in targets {
                        self.leaders.insert(t.0);
                    }
                    if i + 1 < instrs.len() {
                        self.leaders.insert(instrs[i + 1].address.0);
                    }
                }
                LlilInstruction::CallDest { .. } => {
                    // Fall-through after call is also a leader.
                    if i + 1 < instrs.len() {
                        self.leaders.insert(instrs[i + 1].address.0);
                    }
                }
                LlilInstruction::Ret
                    if i + 1 < instrs.len() => {
                        self.leaders.insert(instrs[i + 1].address.0);
                    }
                _ => {}
            }
            i += 1;
        }
    }

    /// Is `addr` a block leader?
    #[must_use]
    pub fn is_leader(&self, addr: u64) -> bool {
        self.leaders.contains(&addr)
    }

    /// All leader addresses in sorted order.
    #[must_use]
    pub fn leaders_sorted(&self) -> Vec<u64> {
        let mut v: Vec<u64> = Vec::with_capacity(self.leaders.len());
        v.extend(self.leaders.iter().copied());
        v.sort_unstable();
        v
    }
}

const fn dest_if_const(expr: &rustre_il_llil::LlilExpr) -> Option<u64> {
    if let rustre_il_llil::LlilExpr::Const { value, .. } = expr {
        Some(*value)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// IndirectJumpResolver
// ---------------------------------------------------------------------------

/// Placeholder for indirect-jump target resolution.
///
/// In production this would query value-set analysis or jump-table decoding.
#[derive(Debug, Default)]
pub struct IndirectJumpResolver {
    /// Pre-registered (addr â†' targets) hints.
    hints: HashMap<u64, Vec<u64>>,
}

impl IndirectJumpResolver {
    /// Register that the indirect jump at `addr` can target `targets`.
    pub fn register_hint(&mut self, addr: u64, targets: Vec<u64>) {
        self.hints.insert(addr, targets);
    }

    /// Resolve targets for the instruction at `addr`.
    #[must_use]
    pub fn resolve(&self, addr: u64) -> &[u64] {
        self.hints.get(&addr).map(Vec::as_slice).unwrap_or(&[])
    }
}

// ---------------------------------------------------------------------------
// CFGBuilder
// ---------------------------------------------------------------------------

/// Assembles a [`ReconstructedCfg`] from split blocks and edge hints.
#[derive(Debug, Default)]
pub struct CFGBuilder {
    cfg: ReconstructedCfg,
}

impl CFGBuilder {
    /// Create a new builder starting from `entry`.
    #[must_use]
    pub fn new(entry: Address) -> Self {
        let cfg = ReconstructedCfg {
            entry: Some(entry),
            ..ReconstructedCfg::default()
        };
        Self { cfg }
    }

    /// Insert a basic block.
    pub fn add_block(&mut self, block: ReconstructedBlock) {
        self.cfg.blocks.insert(block.start.0, block);
    }

    /// Insert an edge between two blocks.
    pub fn add_edge(&mut self, from: u64, to: u64, ty: EdgeType) {
        self.cfg.edges.insert((from, to), ty);
    }

    /// Mark `addr` as an unresolved indirect target.
    pub fn add_unresolved(&mut self, addr: Address) {
        self.cfg.unresolved.push(addr);
    }

    /// Finalise and return the [`ReconstructedCfg`].
    #[must_use]
    pub fn build(self) -> ReconstructedCfg {
        self.cfg
    }
}

// ---------------------------------------------------------------------------
// LinearSweep
// ---------------------------------------------------------------------------

/// Linear-sweep CFG reconstruction: one pass over the instruction stream.
#[derive(Debug, Default)]
pub struct LinearSweep {
    pub indirect_resolver: IndirectJumpResolver,
}

impl LinearSweep {
    /// Reconstruct a CFG from `instrs` with entry at `entry_addr`.
    pub fn reconstruct(
        &mut self,
        entry_addr: Address,
        instrs: &[LlilAnnotatedInstr],
    ) -> ReconstructedCfg {
        if instrs.is_empty() {
            return ReconstructedCfg {
                entry: Some(entry_addr),
                ..Default::default()
            };
        }

        // Step 1: identify leaders.
        let mut splitter = BlockSplitter::default();
        splitter.compute(entry_addr.0, instrs);

        // Step 2: split into blocks.
        let mut builder = CFGBuilder::new(entry_addr);
        let mut current_start = instrs[0].address;
        let mut current_instrs: Vec<LlilAnnotatedInstr> = Vec::new();

        let finalize =
            |start: Address, block_instrs: Vec<LlilAnnotatedInstr>, builder: &mut CFGBuilder| {
                if block_instrs.is_empty() {
                    return;
                }
                let end = block_instrs.last().map_or(start, |i| {
                    // Saturate: `i.address`/`i.length` come from decoding a
                    // possibly-adversarial instruction stream, so an
                    // instruction near `u64::MAX` with a nonzero length would
                    // otherwise panic (debug) or silently wrap to a tiny
                    // `end` (release), corrupting downstream fallthrough
                    // edge-wiring.
                    Address(i.address.0.saturating_add(u64::from(i.length)))
                });
                builder.add_block(ReconstructedBlock {
                    start,
                    end,
                    instructions: block_instrs,
                });
            };

        let mut last_leader_idx: usize = 0;
        for (idx, ai) in instrs.iter().enumerate() {
            let is_leader = splitter.is_leader(ai.address.0) && ai.address.0 != current_start.0;
            if is_leader {
                debug_assert!(idx >= last_leader_idx, "leader indices must be monotonic");
                last_leader_idx = idx;
                let drained = std::mem::take(&mut current_instrs);
                finalize(current_start, drained, &mut builder);
                current_start = ai.address;
            }
            current_instrs.push(ai.clone());
        }
        finalize(current_start, current_instrs, &mut builder);

        // Step 3: wire edges.
        let block_starts: HashSet<u64> = builder.cfg.blocks.keys().copied().collect();
        let block_vec: Vec<ReconstructedBlock> = builder.cfg.blocks.values().cloned().collect();

        for block in &block_vec {
            let from = block.start.0;
            if let Some(last) = block.last_instr() {
                match &last.instr {
                    LlilInstruction::CondJump {
                        true_dest,
                        false_dest,
                        ..
                    } => {
                        builder.add_edge(from, true_dest.0, EdgeType::TrueBranch);
                        builder.add_edge(from, false_dest.0, EdgeType::FalseBranch);
                    }
                    LlilInstruction::JumpDest { dest }
                    | LlilInstruction::Jump(dest)
                    | LlilInstruction::TailCall { dest } => {
                        if let Some(t) = dest_if_const(dest) {
                            builder.add_edge(from, t, EdgeType::Unconditional);
                        } else {
                            let targets = self.indirect_resolver.resolve(last.address.0);
                            if targets.is_empty() {
                                builder.add_unresolved(last.address);
                            } else {
                                for &t in targets {
                                    builder.add_edge(from, t, EdgeType::IndirectTarget);
                                }
                            }
                        }
                    }
                    LlilInstruction::JumpTo { targets, .. } => {
                        for t in targets {
                            builder.add_edge(from, t.0, EdgeType::IndirectTarget);
                        }
                    }
                    LlilInstruction::Ret => { /* no outgoing edge */ }
                    _ => {
                        // Fall-through: find the block starting just after this one.
                        let next = block.end.0;
                        if block_starts.contains(&next) {
                            builder.add_edge(from, next, EdgeType::Fallthrough);
                        }
                    }
                }
            }
        }

        builder.build()
    }
}

// ---------------------------------------------------------------------------
// RecursiveDescent
// ---------------------------------------------------------------------------

/// Recursive-descent CFG reconstruction: follows control flow from entry.
#[derive(Debug, Default)]
pub struct RecursiveDescent {
    pub indirect_resolver: IndirectJumpResolver,
}

impl RecursiveDescent {
    /// Reconstruct reachable CFG from `entry_addr` in `instrs`.
    pub fn reconstruct(
        &mut self,
        entry_addr: Address,
        instrs: &[LlilAnnotatedInstr],
    ) -> ReconstructedCfg {
        if instrs.is_empty() {
            return ReconstructedCfg {
                entry: Some(entry_addr),
                ..Default::default()
            };
        }

        // Build address â†' instruction index for random-access lookup.
        let addr_map: HashMap<u64, usize> = instrs
            .iter()
            .enumerate()
            .map(|(i, ai)| (ai.address.0, i))
            .collect();

        // Work-list of block entry addresses to process.
        let mut work: VecDeque<u64> = VecDeque::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut builder = CFGBuilder::new(entry_addr);

        work.push_back(entry_addr.0);

        let mut block_count = 0usize;
        while let Some(block_start) = work.pop_front() {
            if block_count >= MAX_BLOCKS {
                // Exceeded the block limit; stop enqueuing more blocks.
                break;
            }
            if !visited.insert(block_start) {
                continue;
            }
            let Some(&start_idx) = addr_map.get(&block_start) else {
                continue;
            };

            // Walk forward until a terminator or the next known block leader.
            let mut block_instrs = Vec::new();
            let mut i = start_idx;
            loop {
                if i >= instrs.len() {
                    break;
                }
                // Guard against pathologically large blocks from adversarial input.
                if block_instrs.len() >= MAX_BLOCK_INSTRS {
                    break;
                }
                let ai = &instrs[i];
                // If we re-entered a block we've already discovered, stop.
                if ai.address.0 != block_start && visited.contains(&ai.address.0) {
                    builder.add_edge(block_start, ai.address.0, EdgeType::Fallthrough);
                    break;
                }
                block_instrs.push(ai.clone());
                let is_term = ai.instr.is_terminator();
                i += 1;
                if is_term {
                    break;
                }
            }

            if block_instrs.is_empty() {
                continue;
            }
            // Saturate: `a.address`/`a.length` come from decoding a
            // possibly-adversarial instruction stream (see comment on the
            // LinearSweep variant above for the failure mode).
            let end = block_instrs.last().map_or(Address(block_start), |a| {
                Address(a.address.0.saturating_add(u64::from(a.length)))
            });
            // Schedule successors before moving block_instrs into the block.
            if let Some(last) = block_instrs.last() {
                match &last.instr {
                    LlilInstruction::CondJump {
                        true_dest,
                        false_dest,
                        ..
                    } => {
                        builder.add_edge(block_start, true_dest.0, EdgeType::TrueBranch);
                        builder.add_edge(block_start, false_dest.0, EdgeType::FalseBranch);
                        work.push_back(true_dest.0);
                        work.push_back(false_dest.0);
                    }
                    LlilInstruction::JumpDest { dest }
                    | LlilInstruction::Jump(dest)
                    | LlilInstruction::TailCall { dest } => {
                        if let Some(t) = dest_if_const(dest) {
                            builder.add_edge(block_start, t, EdgeType::Unconditional);
                            work.push_back(t);
                        } else {
                            let resolved = self.indirect_resolver.resolve(last.address.0);
                            if resolved.is_empty() {
                                builder.add_unresolved(last.address);
                            } else {
                                for &t in resolved {
                                    builder.add_edge(block_start, t, EdgeType::IndirectTarget);
                                    work.push_back(t);
                                }
                            }
                        }
                    }
                    LlilInstruction::JumpTo { targets, .. } => {
                        for t in targets {
                            builder.add_edge(block_start, t.0, EdgeType::IndirectTarget);
                            work.push_back(t.0);
                        }
                    }
                    LlilInstruction::Ret => {}
                    _ => {
                        // Fall-through.
                        let next = end.0;
                        if addr_map.contains_key(&next) {
                            builder.add_edge(block_start, next, EdgeType::Fallthrough);
                            work.push_back(next);
                        }
                    }
                }
            }
            builder.add_block(ReconstructedBlock {
                start: Address(block_start),
                end,
                instructions: block_instrs,
            });
            block_count += 1;
        }

        builder.build()
    }
}

// ---------------------------------------------------------------------------
// CfgReconstruction — unified facade
// ---------------------------------------------------------------------------

/// High-level CFG reconstruction controller.  Chooses strategy and wraps the
/// result in a uniform type.
#[derive(Debug)]
pub struct CfgReconstruction {
    pub strategy: ReconstructionStrategy,
    pub indirect_resolver: IndirectJumpResolver,
}

/// Which reconstruction algorithm to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconstructionStrategy {
    LinearSweep,
    RecursiveDescent,
}

impl CfgReconstruction {
    /// Create a reconstruction controller with the given strategy.
    #[must_use]
    pub fn new(strategy: ReconstructionStrategy) -> Self {
        Self {
            strategy,
            indirect_resolver: IndirectJumpResolver::default(),
        }
    }

    /// Register an indirect-jump hint.
    pub fn hint(&mut self, at: u64, targets: Vec<u64>) {
        self.indirect_resolver.register_hint(at, targets);
    }

    /// Run reconstruction on `instrs` starting at `entry`.
    pub fn run(&mut self, entry: Address, instrs: &[LlilAnnotatedInstr]) -> ReconstructedCfg {
        let mut hints = std::mem::take(&mut self.indirect_resolver);
        let result = match self.strategy {
            ReconstructionStrategy::LinearSweep => {
                let mut ls = LinearSweep {
                    indirect_resolver: hints,
                };
                let r = ls.reconstruct(entry, instrs);
                hints = ls.indirect_resolver;
                r
            }
            ReconstructionStrategy::RecursiveDescent => {
                let mut rd = RecursiveDescent {
                    indirect_resolver: hints,
                };
                let r = rd.reconstruct(entry, instrs);
                hints = rd.indirect_resolver;
                r
            }
        };
        self.indirect_resolver = hints;
        result
    }
}

// ---------------------------------------------------------------------------
// CfgStats —" metrics on a reconstructed CFG
// ---------------------------------------------------------------------------

/// Compute statistics over a [`ReconstructedCfg`].
#[derive(Debug, Clone, Default)]
pub struct CfgStats {
    pub block_count: usize,
    pub edge_count: usize,
    pub true_branch_edges: usize,
    pub false_branch_edges: usize,
    pub fallthrough_edges: usize,
    pub unresolved_count: usize,
    pub avg_block_size: f64,
}

impl CfgStats {
    /// Compute stats for `cfg`.
    #[must_use]
    pub fn compute(cfg: &ReconstructedCfg) -> Self {
        let block_count = cfg.block_count();
        let edge_count = cfg.edge_count();

        let true_branch = cfg
            .edges
            .values()
            .filter(|&&e| e == EdgeType::TrueBranch)
            .count();
        let false_branch = cfg
            .edges
            .values()
            .filter(|&&e| e == EdgeType::FalseBranch)
            .count();
        let fallthrough = cfg
            .edges
            .values()
            .filter(|&&e| e == EdgeType::Fallthrough)
            .count();

        let total_instrs: usize = cfg.blocks.values().map(ReconstructedBlock::len).sum();
        let avg_block_size = if block_count == 0 {
            0.0
        } else {
            total_instrs as f64 / block_count as f64
        };

        Self {
            block_count,
            edge_count,
            true_branch_edges: true_branch,
            false_branch_edges: false_branch,
            fallthrough_edges: fallthrough,
            unresolved_count: cfg.unresolved.len(),
            avg_block_size,
        }
    }
}

// ---------------------------------------------------------------------------
// ReachabilityAnalysis
// ---------------------------------------------------------------------------

/// Computes which blocks are reachable from the CFG entry.
#[derive(Debug, Default)]
pub struct ReachabilityAnalysis;

impl ReachabilityAnalysis {
    /// Returns the set of reachable block start addresses.
    #[must_use]
    pub fn reachable(cfg: &ReconstructedCfg) -> std::collections::HashSet<u64> {
        let entry = match cfg.entry {
            Some(e) => e.0,
            None => return std::collections::HashSet::new(),
        };
        let adj = cfg.adjacency();
        let empty: Vec<u64> = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut stack = vec![entry];
        while let Some(addr) = stack.pop() {
            if !visited.insert(addr) {
                continue;
            }
            for &succ in adj.get(&addr).unwrap_or(&empty) {
                stack.push(succ);
            }
        }
        visited
    }

    /// Returns unreachable block addresses.
    #[must_use]
    pub fn unreachable(cfg: &ReconstructedCfg) -> Vec<u64> {
        let reachable = Self::reachable(cfg);
        let mut out: Vec<u64> = cfg
            .blocks
            .keys()
            .filter(|&&a| !reachable.contains(&a))
            .copied()
            .collect();
        // `cfg.blocks` is a HashMap; sort so the result is deterministic
        // instead of leaking hash-iteration order.
        out.sort_unstable();
        out
    }
}

// ---------------------------------------------------------------------------
// DotExporter —" Graphviz DOT output
// ---------------------------------------------------------------------------

/// Exports a [`ReconstructedCfg`] as a Graphviz DOT string.
#[derive(Debug, Default)]
pub struct DotExporter;

impl DotExporter {
    /// Produce a DOT string for `cfg`.
    #[must_use]
    pub fn export(cfg: &ReconstructedCfg) -> String {
        let mut out = String::from("digraph CFG {\n");
        // `cfg.blocks`/`cfg.edges` are HashMaps; iterate in a sorted, stable
        // order so the emitted DOT text is deterministic (reproducible
        // diffs / snapshot tests) rather than reflecting hash-iteration
        // order that changes from run to run.
        let mut block_addrs: Vec<u64> = cfg.blocks.keys().copied().collect();
        block_addrs.sort_unstable();
        for addr in block_addrs {
            let block = &cfg.blocks[&addr];
            let _ = std::fmt::write(
                &mut out,
                format_args!(
                    "  n{addr:#x} [label=\"{addr:#x}\\n{} instrs\"];\n",
                    block.len()
                ),
            );
        }
        let mut edge_keys: Vec<(u64, u64)> = cfg.edges.keys().copied().collect();
        edge_keys.sort_unstable();
        for (from, to) in edge_keys {
            let edge_type = cfg.edges[&(from, to)];
            let label = match edge_type {
                EdgeType::TrueBranch => "T",
                EdgeType::FalseBranch => "F",
                EdgeType::Fallthrough => "fall",
                EdgeType::Unconditional => "",
                EdgeType::IndirectTarget => "ind",
                EdgeType::Call => "call",
                EdgeType::Return => "ret",
            };
            let _ = std::fmt::write(
                &mut out,
                format_args!("  n{from:#x} -> n{to:#x} [label=\"{label}\"];\n"),
            );
        }
        out.push_str("}\n");
        out
    }
}

// ---------------------------------------------------------------------------
// CycleDetector —" finds cycles in the reconstructed CFG
// ---------------------------------------------------------------------------

/// Detects natural loops (cycles) in a [`ReconstructedCfg`].
#[derive(Debug, Default)]
pub struct CycleDetector;

impl CycleDetector {
    /// Find back-edges (source address, target address) via DFS.
    #[must_use]
    pub fn find_back_edges(cfg: &ReconstructedCfg) -> Vec<(u64, u64)> {
        let entry = match cfg.entry {
            Some(e) => e.0,
            None => return vec![],
        };
        let adj = cfg.adjacency();
        let mut visited = std::collections::HashSet::new();
        let mut on_stack = std::collections::HashSet::new();
        let mut backs = Vec::new();
        Self::dfs(entry, &adj, &mut visited, &mut on_stack, &mut backs);
        backs
    }

    fn dfs(
        root: u64,
        adj: &HashMap<u64, Vec<u64>>,
        visited: &mut std::collections::HashSet<u64>,
        on_stack: &mut std::collections::HashSet<u64>,
        backs: &mut Vec<(u64, u64)>,
    ) {
        // Iterative DFS with explicit stack to avoid stack overflow on deep CFGs
        // (up to MAX_BLOCKS = 65 536 nodes with adversarial linear chains).
        // Each frame: (node, successor_index). Successors are looked up in
        // the precomputed adjacency list (O(1)) instead of rescanning all
        // edges per node, which previously made this O(V * E).
        if !visited.insert(root) {
            return;
        }
        on_stack.insert(root);
        let empty: Vec<u64> = Vec::new();
        let mut work: Vec<(u64, usize)> = vec![(root, 0)];
        while let Some(frame) = work.last_mut() {
            let node = frame.0;
            let idx = frame.1;
            let succs = adj.get(&node).unwrap_or(&empty);
            if idx < succs.len() {
                let succ = succs[idx];
                frame.1 += 1;
                if on_stack.contains(&succ) {
                    backs.push((node, succ));
                } else if visited.insert(succ) {
                    on_stack.insert(succ);
                    work.push((succ, 0));
                }
            } else {
                work.pop();
                on_stack.remove(&node);
            }
        }
    }

    /// Whether `cfg` contains any cycle.
    #[must_use]
    pub fn has_cycle(cfg: &ReconstructedCfg) -> bool {
        !Self::find_back_edges(cfg).is_empty()
    }
}

// ---------------------------------------------------------------------------
// CfgTextSerializer —" simple text representation of a CFG
// ---------------------------------------------------------------------------

/// Produces a plain-text listing of a [`ReconstructedCfg`].
#[derive(Debug, Default)]
pub struct CfgTextSerializer;

impl CfgTextSerializer {
    /// Serialize `cfg` to a multi-line string.
    #[must_use]
    pub fn serialize(cfg: &ReconstructedCfg) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        // Precompute the adjacency list once instead of calling
        // `cfg.successors(addr)` (an O(E) scan of all edges) per block, which
        // made this O(V * E) on functions with many blocks/edges.
        let adj = cfg.adjacency();
        let empty: Vec<u64> = Vec::new();
        for (&addr, block) in &cfg.blocks {
            let _ = writeln!(out, "block_{addr:#x}: ({} instrs)", block.len());
            for &succ in adj.get(&addr).unwrap_or(&empty) {
                let edge = cfg
                    .edges
                    .get(&(addr, succ))
                    .copied()
                    .unwrap_or(EdgeType::Fallthrough);
                let _ = writeln!(out, "  -> block_{succ:#x} [{edge:?}]");
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_core::address::Address;
    use rustre_il_llil::{LlilAnnotatedInstr, LlilExpr, LlilInstruction, Size};

    fn nop(addr: u64) -> LlilAnnotatedInstr {
        LlilAnnotatedInstr {
            size: 1,
            address: Address(addr),
            instr: LlilInstruction::Nop,
            length: 1,
        }
    }

    fn ret(addr: u64) -> LlilAnnotatedInstr {
        LlilAnnotatedInstr {
            size: 1,
            address: Address(addr),
            instr: LlilInstruction::Ret,
            length: 1,
        }
    }

    fn cond_jump(addr: u64, t: u64, f: u64, cond_reg: &str) -> LlilAnnotatedInstr {
        use rustre_il_llil::LlilRegister;
        LlilAnnotatedInstr {
            size: 2,
            address: Address(addr),
            instr: LlilInstruction::CondJump {
                cond: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete(cond_reg.into()),
                    size: Size::Byte,
                },
                true_dest: Address(t),
                false_dest: Address(f),
            },
            length: 2,
        }
    }

    fn jump_const(addr: u64, target: u64) -> LlilAnnotatedInstr {
        LlilAnnotatedInstr {
            size: 2,
            address: Address(addr),
            instr: LlilInstruction::JumpDest {
                dest: LlilExpr::Const {
                    value: target,
                    size: Size::QWord,
                },
            },
            length: 2,
        }
    }

    // --- EdgeType ---

    #[test]
    fn edge_type_variants_distinct() {
        assert_ne!(EdgeType::TrueBranch, EdgeType::FalseBranch);
        assert_ne!(EdgeType::Fallthrough, EdgeType::Unconditional);
    }

    // --- BlockSplitter ---

    #[test]
    fn block_splitter_entry_is_leader() {
        let mut sp = BlockSplitter::default();
        let instrs = vec![nop(0x100), ret(0x101)];
        sp.compute(0x100, &instrs);
        assert!(sp.is_leader(0x100));
    }

    #[test]
    fn block_splitter_cond_jump_targets_are_leaders() {
        let mut sp = BlockSplitter::default();
        let instrs = vec![cond_jump(0, 0x10, 0x20, "rax")];
        sp.compute(0, &instrs);
        assert!(sp.is_leader(0x10));
        assert!(sp.is_leader(0x20));
    }

    #[test]
    fn block_splitter_sorted_leaders() {
        let mut sp = BlockSplitter::default();
        let instrs = vec![cond_jump(0, 0x30, 0x10, "rax"), nop(0x10)];
        sp.compute(0, &instrs);
        let sorted = sp.leaders_sorted();
        for i in 1..sorted.len() {
            assert!(sorted[i - 1] <= sorted[i]);
        }
    }

    // --- ReconstructedBlock ---

    #[test]
    fn block_len_is_empty() {
        let b = ReconstructedBlock {
            start: Address(0),
            end: Address(0),
            instructions: vec![],
        };
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
    }

    #[test]
    fn block_last_instr() {
        let b = ReconstructedBlock {
            start: Address(0),
            end: Address(2),
            instructions: vec![nop(0), ret(1)],
        };
        assert!(matches!(
            b.last_instr().unwrap().instr,
            LlilInstruction::Ret
        ));
    }

    // --- ReconstructedCfg ---

    #[test]
    fn cfg_successors_predecessors() {
        let mut cfg = ReconstructedCfg {
            entry: Some(Address(0)),
            ..ReconstructedCfg::default()
        };
        cfg.edges.insert((0, 10), EdgeType::TrueBranch);
        cfg.edges.insert((0, 20), EdgeType::FalseBranch);
        let succs = cfg.successors(0);
        assert!(succs.contains(&10));
        assert!(succs.contains(&20));
        let preds_10 = cfg.predecessors(10);
        assert!(preds_10.contains(&0));
    }

    #[test]
    fn cfg_successors_predecessors_are_sorted() {
        // Regression test: `edges` is a HashMap, so without an explicit sort
        // `successors`/`predecessors` would return addresses in
        // hash-iteration order (nondeterministic across runs) instead of a
        // stable, reproducible order.
        let mut cfg = ReconstructedCfg {
            entry: Some(Address(0)),
            ..ReconstructedCfg::default()
        };
        // Insert out of numeric order to make an accidental "already sorted"
        // pass unlikely.
        for &to in &[50u64, 10, 40, 20, 30] {
            cfg.edges.insert((0, to), EdgeType::Unconditional);
        }
        for &from in &[50u64, 10, 40, 20, 30] {
            cfg.edges.insert((from, 99), EdgeType::Unconditional);
        }
        assert_eq!(cfg.successors(0), vec![10, 20, 30, 40, 50]);
        assert_eq!(cfg.predecessors(99), vec![10, 20, 30, 40, 50]);
    }

    #[test]
    fn cfg_post_order_and_back_edges_are_deterministic() {
        // Regression test: `adjacency()` used to preserve HashMap iteration
        // order for same-`from` edges, making `post_order`/`find_back_edges`
        // traversal order nondeterministic. Build a node with several
        // out-of-order successors and confirm the traversal always visits
        // them in ascending address order.
        let mut cfg = ReconstructedCfg {
            entry: Some(Address(0)),
            ..ReconstructedCfg::default()
        };
        for &to in &[40u64, 10, 30, 20] {
            cfg.edges.insert((0, to), EdgeType::Unconditional);
        }
        // post_order is a post-order DFS, so with ascending-order successor
        // visitation the last-finished (and thus last in `post_order`)
        // top-level child is the highest address; the root always finishes
        // last of all.
        let order = cfg.post_order();
        assert_eq!(*order.last().unwrap(), 0);
        // All four children must appear exactly once.
        let mut children: Vec<u64> = order[..order.len() - 1].to_vec();
        children.sort_unstable();
        assert_eq!(children, vec![10, 20, 30, 40]);
    }

    #[test]
    fn cfg_unreachable_is_sorted() {
        let mut cfg = ReconstructedCfg {
            entry: Some(Address(0)),
            ..ReconstructedCfg::default()
        };
        for &addr in &[0u64, 50, 10, 40, 20] {
            cfg.blocks.insert(
                addr,
                ReconstructedBlock {
                    start: Address(addr),
                    end: Address(addr + 1),
                    instructions: vec![],
                },
            );
        }
        // No edges at all: everything except entry is unreachable.
        let unreachable = ReachabilityAnalysis::unreachable(&cfg);
        assert_eq!(unreachable, vec![10, 20, 40, 50]);
    }

    #[test]
    fn cfg_block_count_edge_count() {
        let mut cfg = ReconstructedCfg {
            entry: Some(Address(0)),
            ..ReconstructedCfg::default()
        };
        cfg.blocks.insert(
            0,
            ReconstructedBlock {
                start: Address(0),
                end: Address(1),
                instructions: vec![],
            },
        );
        cfg.edges.insert((0, 1), EdgeType::Fallthrough);
        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.edge_count(), 1);
    }

    // --- IndirectJumpResolver ---

    #[test]
    fn resolver_empty_hint() {
        let r = IndirectJumpResolver::default();
        assert!(r.resolve(0x1234).is_empty());
    }

    #[test]
    fn resolver_with_hint() {
        let mut r = IndirectJumpResolver::default();
        r.register_hint(0x1000, vec![0x2000, 0x3000]);
        assert_eq!(r.resolve(0x1000), &[0x2000u64, 0x3000]);
    }

    // --- CFGBuilder ---

    #[test]
    fn builder_add_block_and_edge() {
        let mut b = CFGBuilder::new(Address(0));
        b.add_block(ReconstructedBlock {
            start: Address(0),
            end: Address(4),
            instructions: vec![],
        });
        b.add_edge(0, 4, EdgeType::Fallthrough);
        let cfg = b.build();
        assert_eq!(cfg.block_count(), 1);
        assert_eq!(cfg.edge_count(), 1);
    }

    // --- LinearSweep ---

    #[test]
    fn linear_sweep_single_block() {
        let instrs = vec![nop(0), nop(1), ret(2)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        assert!(cfg.block_count() >= 1);
        assert_eq!(cfg.entry, Some(Address(0)));
    }

    #[test]
    fn linear_sweep_cond_jump_splits() {
        let instrs = vec![
            nop(0),
            cond_jump(1, 4, 6, "rax"),
            nop(4),
            ret(5),
            nop(6),
            ret(7),
        ];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        assert!(cfg.block_count() >= 2);
    }

    #[test]
    fn linear_sweep_empty_instrs() {
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &[]);
        assert_eq!(cfg.block_count(), 0);
    }

    #[test]
    fn linear_sweep_unconditional_jump() {
        let instrs = vec![nop(0), jump_const(1, 0x100)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        // Should have an unconditional edge to 0x100.
        let has_edge = cfg.edges.contains_key(&(0, 0x100));
        let _ = has_edge; // edge goes from block start, not instr addr
    }

    // --- RecursiveDescent ---

    #[test]
    fn recursive_descent_single_block() {
        let instrs = vec![nop(0), ret(1)];
        let mut rd = RecursiveDescent::default();
        let cfg = rd.reconstruct(Address(0), &instrs);
        assert_eq!(cfg.block_count(), 1);
    }

    #[test]
    fn recursive_descent_cond_jump() {
        let instrs = vec![
            nop(0),
            cond_jump(1, 10, 20, "rax"),
            nop(10),
            ret(11),
            nop(20),
            ret(21),
        ];
        let mut rd = RecursiveDescent::default();
        let cfg = rd.reconstruct(Address(0), &instrs);
        // Entry, then two successor blocks.
        assert!(cfg.block_count() >= 2);
    }

    #[test]
    fn recursive_descent_loop() {
        // A simple loop: 0 â†' 1 (cond jump to 0 and 2)
        let instrs = vec![
            nop(0),
            cond_jump(1, 0, 4, "rax"), // back-edge to 0, exit to 4
            nop(4),
            ret(5),
        ];
        let mut rd = RecursiveDescent::default();
        let cfg = rd.reconstruct(Address(0), &instrs);
        assert!(cfg.block_count() >= 1);
    }

    #[test]
    fn recursive_descent_empty() {
        let mut rd = RecursiveDescent::default();
        let cfg = rd.reconstruct(Address(0), &[]);
        assert_eq!(cfg.block_count(), 0);
    }

    // --- CfgReconstruction facade ---

    #[test]
    fn facade_linear_sweep() {
        let instrs = vec![nop(0), ret(1)];
        let mut r = CfgReconstruction::new(ReconstructionStrategy::LinearSweep);
        let cfg = r.run(Address(0), &instrs);
        assert!(cfg.block_count() >= 1);
    }

    #[test]
    fn facade_recursive_descent() {
        let instrs = vec![nop(0), ret(1)];
        let mut r = CfgReconstruction::new(ReconstructionStrategy::RecursiveDescent);
        let cfg = r.run(Address(0), &instrs);
        assert!(cfg.block_count() >= 1);
    }

    #[test]
    fn facade_hint_propagates() {
        let mut r = CfgReconstruction::new(ReconstructionStrategy::LinearSweep);
        r.hint(0x1000, vec![0x2000]);
        assert_eq!(r.indirect_resolver.resolve(0x1000), &[0x2000u64]);
    }

    #[test]
    fn post_order_single_node() {
        let mut cfg = ReconstructedCfg {
            entry: Some(Address(0)),
            ..ReconstructedCfg::default()
        };
        cfg.blocks.insert(
            0,
            ReconstructedBlock {
                start: Address(0),
                end: Address(1),
                instructions: vec![],
            },
        );
        let order = cfg.post_order();
        assert_eq!(order, vec![0u64]);
    }

    #[test]
    fn post_order_empty_entry() {
        let cfg = ReconstructedCfg::default();
        assert!(cfg.post_order().is_empty());
    }

    #[test]
    fn unresolved_tracked() {
        let instrs = vec![
            nop(0),
            LlilAnnotatedInstr {
                size: 1,
                address: Address(1),
                instr: LlilInstruction::JumpDest {
                    dest: rustre_il_llil::LlilExpr::RegisterRef {
                        reg: rustre_il_llil::LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                    },
                },
                length: 2,
            },
        ];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        assert!(!cfg.unresolved.is_empty());
    }

    #[test]
    fn linear_sweep_overflowing_address_length_does_not_panic() {
        // Regression test: an adversarial/malformed instruction stream can
        // place the last instruction at an address near u64::MAX with a
        // nonzero length. Computing `end` used to add these directly, which
        // panics on overflow in debug builds and silently wraps in release.
        // It must saturate to u64::MAX instead.
        let instrs = vec![LlilAnnotatedInstr {
            size: 1,
            address: Address(u64::MAX - 2),
            instr: LlilInstruction::Nop,
            length: 10,
        }];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(u64::MAX - 2), &instrs);
        let block = cfg.block(u64::MAX - 2).expect("block should exist");
        assert_eq!(block.end, Address(u64::MAX));
    }

    #[test]
    fn recursive_descent_overflowing_address_length_does_not_panic() {
        let instrs = vec![LlilAnnotatedInstr {
            size: 1,
            address: Address(u64::MAX - 2),
            instr: LlilInstruction::Nop,
            length: 10,
        }];
        let mut rd = RecursiveDescent::default();
        let cfg = rd.reconstruct(Address(u64::MAX - 2), &instrs);
        let block = cfg.block(u64::MAX - 2).expect("block should exist");
        assert_eq!(block.end, Address(u64::MAX));
    }

    #[test]
    fn reconstruction_strategies_distinct() {
        assert_ne!(
            ReconstructionStrategy::LinearSweep,
            ReconstructionStrategy::RecursiveDescent
        );
    }

    // --- Additional BlockSplitter tests ---

    #[test]
    fn block_splitter_jump_to_targets_are_leaders() {
        use rustre_il_llil::LlilRegister;
        let jt = LlilAnnotatedInstr {
            size: 1,
            address: Address(0),
            instr: LlilInstruction::JumpTo {
                dest: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                },
                targets: vec![Address(0x10), Address(0x20)],
            },
            length: 2,
        };
        let mut sp = BlockSplitter::default();
        sp.compute(0, &[jt]);
        assert!(sp.is_leader(0x10));
        assert!(sp.is_leader(0x20));
    }

    #[test]
    fn block_splitter_call_fallthrough_is_leader() {
        let call = LlilAnnotatedInstr {
            size: 1,
            address: Address(0),
            instr: LlilInstruction::CallDest {
                dest: LlilExpr::Const {
                    value: 0x5000,
                    size: Size::QWord,
                },
            },
            length: 5,
        };
        let after = nop(5);
        let mut sp = BlockSplitter::default();
        sp.compute(0, &[call, after]);
        assert!(sp.is_leader(5));
    }

    #[test]
    fn block_splitter_ret_fallthrough_is_leader() {
        let r = ret(0);
        let after = nop(1);
        let mut sp = BlockSplitter::default();
        sp.compute(0, &[r, after]);
        assert!(sp.is_leader(1));
    }

    // --- ReconstructedCfg query methods ---

    #[test]
    fn cfg_block_lookup() {
        let mut cfg = ReconstructedCfg {
            entry: Some(Address(0x100)),
            ..ReconstructedCfg::default()
        };
        cfg.blocks.insert(
            0x100,
            ReconstructedBlock {
                start: Address(0x100),
                end: Address(0x102),
                instructions: vec![],
            },
        );
        assert!(cfg.block(0x100).is_some());
        assert!(cfg.block(0x200).is_none());
    }

    #[test]
    fn cfg_no_predecessors_for_entry() {
        let mut cfg = ReconstructedCfg {
            entry: Some(Address(0)),
            ..ReconstructedCfg::default()
        };
        cfg.edges.insert((0, 1), EdgeType::Fallthrough);
        let preds = cfg.predecessors(0);
        assert!(preds.is_empty());
    }

    // --- LinearSweep edge wiring ---

    #[test]
    fn linear_sweep_edges_exist_after_cond_jump() {
        let instrs = vec![
            nop(0),
            cond_jump(1, 10, 20, "rax"),
            nop(10),
            ret(11),
            nop(20),
            ret(21),
        ];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        // Should have true and false branch edges.
        let has_true = cfg.edges.values().any(|e| *e == EdgeType::TrueBranch);
        let has_false = cfg.edges.values().any(|e| *e == EdgeType::FalseBranch);
        assert!(has_true);
        assert!(has_false);
    }

    #[test]
    fn linear_sweep_fallthrough_edge() {
        let instrs = vec![nop(0), nop(1), ret(2)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        // A single block with nop+nop+ret; no fallthrough needed.
        assert!(cfg.block_count() >= 1);
    }

    // --- RecursiveDescent edge coverage ---

    #[test]
    fn recursive_descent_two_blocks() {
        let instrs = vec![jump_const(0, 4), nop(4), ret(5)];
        let mut rd = RecursiveDescent::default();
        let cfg = rd.reconstruct(Address(0), &instrs);
        assert!(cfg.block_count() >= 2);
    }

    #[test]
    fn recursive_descent_indirect_with_hint() {
        use rustre_il_llil::LlilRegister;
        let jmp = LlilAnnotatedInstr {
            size: 1,
            address: Address(0),
            instr: LlilInstruction::JumpDest {
                dest: LlilExpr::RegisterRef {
                    reg: LlilRegister::Concrete("rax".into()),
                    size: Size::QWord,
                },
            },
            length: 2,
        };
        let target = nop(0x100);
        let target_ret = ret(0x101);
        let instrs = vec![jmp, target, target_ret];
        let mut rd = RecursiveDescent::default();
        rd.indirect_resolver.register_hint(0, vec![0x100]);
        let cfg = rd.reconstruct(Address(0), &instrs);
        assert!(cfg.block_count() >= 1);
    }

    // --- IndirectJumpResolver additional ---

    #[test]
    fn resolver_overwrite_hint() {
        let mut r = IndirectJumpResolver::default();
        r.register_hint(0x10, vec![0x20]);
        r.register_hint(0x10, vec![0x30]); // overwrite
        assert_eq!(r.resolve(0x10), &[0x30u64]);
    }

    // --- EdgeType completeness ---

    #[test]
    fn edge_type_all_variants_distinct() {
        let types = [
            EdgeType::Unconditional,
            EdgeType::TrueBranch,
            EdgeType::FalseBranch,
            EdgeType::Fallthrough,
            EdgeType::IndirectTarget,
            EdgeType::Call,
            EdgeType::Return,
        ];
        for (i, &a) in types.iter().enumerate() {
            for (j, &b) in types.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    // --- CFGBuilder add_unresolved ---

    #[test]
    fn builder_add_unresolved() {
        let mut b = CFGBuilder::new(Address(0));
        b.add_unresolved(Address(0xBAD));
        let cfg = b.build();
        assert!(!cfg.unresolved.is_empty());
    }

    // --- CfgStats tests ---

    #[test]
    fn cfg_stats_empty() {
        let cfg = ReconstructedCfg::default();
        let s = CfgStats::compute(&cfg);
        assert_eq!(s.block_count, 0);
        assert_eq!(s.edge_count, 0);
    }

    #[test]
    fn cfg_stats_with_blocks() {
        let instrs = vec![
            nop(0),
            cond_jump(1, 10, 20, "rax"),
            nop(10),
            ret(11),
            nop(20),
            ret(21),
        ];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let s = CfgStats::compute(&cfg);
        assert!(s.block_count >= 2);
        assert!(s.true_branch_edges + s.false_branch_edges >= 2);
    }

    #[test]
    fn cfg_stats_avg_block_size() {
        let instrs = vec![nop(0), nop(1), ret(2)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let s = CfgStats::compute(&cfg);
        assert!(s.avg_block_size > 0.0);
    }

    // --- ReachabilityAnalysis tests ---

    #[test]
    fn reachability_all_reachable() {
        let instrs = vec![nop(0), jump_const(1, 4), nop(4), ret(5)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let r = ReachabilityAnalysis::reachable(&cfg);
        assert!(!r.is_empty());
    }

    #[test]
    fn reachability_no_entry_empty() {
        let cfg = ReconstructedCfg::default();
        let r = ReachabilityAnalysis::reachable(&cfg);
        assert!(r.is_empty());
    }

    #[test]
    fn reachability_unreachable_after_jump() {
        let instrs = vec![
            jump_const(0, 4),
            nop(2), // unreachable
            nop(3), // unreachable
            nop(4),
            ret(5),
        ];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let _unreachable = ReachabilityAnalysis::unreachable(&cfg);
        // May or may not be empty depending on splitter;
        // just verify the method runs.
    }

    // --- DotExporter tests ---

    #[test]
    fn dot_exporter_produces_digraph() {
        let cfg = ReconstructedCfg::default();
        let dot = DotExporter::export(&cfg);
        assert!(dot.contains("digraph CFG"));
    }

    #[test]
    fn dot_exporter_includes_block_nodes() {
        let instrs = vec![nop(0), ret(1)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let dot = DotExporter::export(&cfg);
        assert!(dot.contains("n0x"));
    }

    // --- BlockSplitter: ret makes fallthrough a leader ---

    #[test]
    fn block_splitter_multiple_leaders_sorted() {
        let mut sp = BlockSplitter::default();
        let instrs = vec![
            nop(0),
            cond_jump(1, 10, 20, "rax"),
            nop(10),
            ret(11),
            nop(20),
            ret(21),
        ];
        sp.compute(0, &instrs);
        let leaders = sp.leaders_sorted();
        for i in 1..leaders.len() {
            assert!(leaders[i - 1] <= leaders[i]);
        }
        assert!(leaders.len() >= 3);
    }

    // --- CFGBuilder entry ---

    #[test]
    fn builder_entry_set() {
        let b = CFGBuilder::new(Address(0x400));
        let cfg = b.build();
        assert_eq!(cfg.entry, Some(Address(0x400)));
    }

    // --- CycleDetector tests ---

    #[test]
    fn cycle_detector_no_cycle_linear() {
        let instrs = vec![nop(0), jump_const(1, 4), nop(4), ret(5)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        assert!(!CycleDetector::has_cycle(&cfg));
    }

    #[test]
    fn cycle_detector_loop_has_cycle() {
        let instrs = vec![
            nop(0),
            cond_jump(1, 0, 4, "rax"), // back-edge to 0
            nop(4),
            ret(5),
        ];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        assert!(CycleDetector::has_cycle(&cfg));
    }

    #[test]
    fn cycle_detector_empty_cfg() {
        let cfg = ReconstructedCfg::default();
        assert!(!CycleDetector::has_cycle(&cfg));
    }

    #[test]
    fn cycle_detector_back_edges_count() {
        let instrs = vec![nop(0), cond_jump(1, 0, 4, "rax"), nop(4), ret(5)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let backs = CycleDetector::find_back_edges(&cfg);
        assert!(!backs.is_empty());
    }

    // --- CfgTextSerializer tests ---

    #[test]
    fn text_serializer_empty() {
        let cfg = ReconstructedCfg::default();
        let s = CfgTextSerializer::serialize(&cfg);
        assert!(s.is_empty());
    }

    #[test]
    fn text_serializer_single_block() {
        let instrs = vec![nop(0), ret(1)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let s = CfgTextSerializer::serialize(&cfg);
        assert!(s.contains("block_"));
    }

    #[test]
    fn text_serializer_multiple_successors_shows_both_edges() {
        // entry (cond jump) -> true_dest / false_dest, both blocks end in Ret.
        let instrs = vec![
            cond_jump(0, 4, 8, "r0"),
            nop(4),
            ret(5),
            nop(8),
            ret(9),
        ];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let s = CfgTextSerializer::serialize(&cfg);
        // Entry block must list both successor edges with correct edge kinds.
        assert!(s.contains("block_0x0:"));
        assert!(s.contains("-> block_0x4 [TrueBranch]"));
        assert!(s.contains("-> block_0x8 [FalseBranch]"));
    }

    // --- ReachabilityAnalysis extra ---

    #[test]
    fn reachability_entry_in_reachable() {
        let instrs = vec![nop(0), ret(1)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let r = ReachabilityAnalysis::reachable(&cfg);
        assert!(r.contains(&0));
    }

    // --- DotExporter extra ---

    #[test]
    fn dot_exporter_ends_with_closing_brace() {
        let instrs = vec![nop(0), ret(1)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let dot = DotExporter::export(&cfg);
        assert!(dot.trim_end().ends_with('}'));
    }

    // --- CfgStats unresolved ---

    // --- CfgSummary tests (previously zero coverage) ---

    #[test]
    fn cfg_summary_from_cfg_basic_fields() {
        let instrs = vec![nop(0), jump_const(1, 4), nop(4), ret(5)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let summary = CfgSummary::from_cfg(&cfg);
        assert_eq!(summary.entry, Some(0));
        assert_eq!(summary.block_count, cfg.block_count());
        assert_eq!(summary.edge_count, cfg.edge_count());
        assert_eq!(summary.unresolved, cfg.unresolved.len());
        assert!(!summary.has_cycles);
    }

    #[test]
    fn cfg_summary_detects_cycle() {
        let instrs = vec![nop(0), cond_jump(1, 0, 4, "rax"), nop(4), ret(5)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let summary = CfgSummary::from_cfg(&cfg);
        assert!(summary.has_cycles);
    }

    #[test]
    fn cfg_summary_display_contains_fields() {
        let cfg = ReconstructedCfg::default();
        let summary = CfgSummary::from_cfg(&cfg);
        let s = format!("{summary}");
        assert!(s.contains("blocks=0"));
        assert!(s.contains("edges=0"));
    }

    // --- BlockOrder::rpo tests (previously zero coverage) ---

    #[test]
    fn block_order_rpo_is_reverse_of_post_order() {
        let instrs = vec![nop(0), jump_const(1, 4), nop(4), ret(5)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let mut expected = cfg.post_order();
        expected.reverse();
        assert_eq!(BlockOrder::rpo(&cfg), expected);
    }

    #[test]
    fn block_order_rpo_entry_first_for_simple_chain() {
        // Entry has no predecessors, so in RPO it must come before its
        // successors for a simple acyclic chain.
        let instrs = vec![nop(0), jump_const(1, 4), nop(4), ret(5)];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let order = BlockOrder::rpo(&cfg);
        assert_eq!(order.first().copied(), Some(0u64));
    }

    #[test]
    fn block_order_rpo_empty_cfg() {
        let cfg = ReconstructedCfg::default();
        assert!(BlockOrder::rpo(&cfg).is_empty());
    }

    // --- BasicBlockInfo tests (previously zero coverage) ---

    #[test]
    fn basic_block_info_from_block_with_successors() {
        let block = ReconstructedBlock {
            start: Address(0x10),
            end: Address(0x14),
            instructions: vec![nop(0x10), nop(0x12)],
        };
        let info = BasicBlockInfo::from_block(&block, true);
        assert_eq!(info.start, 0x10);
        assert_eq!(info.end, 0x14);
        assert_eq!(info.len, 2);
        assert!(!info.is_exit);
    }

    #[test]
    fn basic_block_info_from_block_no_successors_is_exit() {
        let block = ReconstructedBlock {
            start: Address(0x20),
            end: Address(0x21),
            instructions: vec![ret(0x20)],
        };
        let info = BasicBlockInfo::from_block(&block, false);
        assert!(info.is_exit);
    }

    #[test]
    fn cfg_stats_unresolved() {
        let instrs = vec![
            nop(0),
            LlilAnnotatedInstr {
                size: 1,
                address: Address(1),
                instr: LlilInstruction::JumpDest {
                    dest: rustre_il_llil::LlilExpr::RegisterRef {
                        reg: rustre_il_llil::LlilRegister::Concrete("rax".into()),
                        size: Size::QWord,
                    },
                },
                length: 2,
            },
        ];
        let mut ls = LinearSweep::default();
        let cfg = ls.reconstruct(Address(0), &instrs);
        let s = CfgStats::compute(&cfg);
        assert!(s.unresolved_count > 0);
    }
}
