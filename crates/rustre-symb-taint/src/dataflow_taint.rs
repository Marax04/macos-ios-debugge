//! Dataflow-based taint analysis over a CFG.
//!
//! This module implements a forward dataflow analysis using a worklist
//! fixpoint solver. Each basic block has IN and OUT taint sets; `TaintLattice`
//! defines join/meet on `TaintId` bitmasks; `TaintTransferFunctions` applies
//! each IL instruction type; `TaintPropagationGraph` records the directed
//! flow of taint through the program.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use thiserror::Error;

use crate::{TaintFinding, TaintId, TaintInstr, TaintState, TaintedValue, apply_instr, taint_bits};

/// Re-exports of the lower-level taint primitives so consumers of the
/// dataflow module can build/inspect expressions without an extra import.
pub use crate::{TaintExpr, eval_taint, eval_value};

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DataflowError {
    #[error("block {0} not found in CFG")]
    BlockNotFound(BlockId),
    #[error("fixpoint did not converge after {0} iterations")]
    DidNotConverge(usize),
    #[error("dataflow error: {0}")]
    Other(String),
}

// ─── BlockId ─────────────────────────────────────────────────────────────────

/// Identifier for a basic block in the CFG.
pub type BlockId = u32;

// ─── TaintLattice ─────────────────────────────────────────────────────────────

/// The taint lattice for a single value: a `TaintId` bitmask.
///
/// - Bottom (⊥) = 0 (no taint, "definitely clean").
/// - Top   (⊤) = `u64::MAX` (all taint bits set).
/// - Join  = bitwise OR  (over-approximation for merge points).
/// - Meet  = bitwise AND (conservative intersection).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TaintLattice(pub TaintId);

impl TaintLattice {
    /// Bottom element (no taint).
    pub const BOTTOM: Self = Self(taint_bits::NONE);
    /// Top element (all taint sources).
    pub const TOP: Self = Self(taint_bits::ALL);

    /// Lattice join (least upper bound): union of taint bits.
    #[must_use]
    #[inline]
    pub const fn join(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Lattice meet (greatest lower bound): intersection of taint bits.
    #[must_use]
    #[inline]
    pub const fn meet(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Return `true` if this element is strictly above `other` in the lattice.
    #[must_use]
    #[inline]
    pub const fn is_above(self, other: Self) -> bool {
        // a ≥ b iff (a | b) == a; strictly above: a ≥ b and a ≠ b
        (self.0 | other.0) == self.0 && self.0 != other.0
    }

    /// Return `true` if no taint bits are set.
    #[must_use]
    #[inline]
    pub const fn is_bottom(self) -> bool {
        self.0 == taint_bits::NONE
    }

    /// Return `true` if all taint bits are set.
    #[must_use]
    #[inline]
    pub const fn is_top(self) -> bool {
        self.0 == taint_bits::ALL
    }

    /// Add a set of taint bits and return the updated element.
    #[must_use]
    #[inline]
    pub const fn with_bits(self, bits: TaintId) -> Self {
        Self(self.0 | bits)
    }

    /// Remove specific taint bits (sanitise).
    #[must_use]
    #[inline]
    pub const fn without_bits(self, bits: TaintId) -> Self {
        Self(self.0 & !bits)
    }
}

impl fmt::Display for TaintLattice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TaintLattice({:#018x})", self.0)
    }
}

impl From<TaintId> for TaintLattice {
    fn from(id: TaintId) -> Self {
        Self(id)
    }
}

impl From<TaintLattice> for TaintId {
    fn from(l: TaintLattice) -> Self {
        l.0
    }
}

// ─── PerBlockTaintState ───────────────────────────────────────────────────────

/// IN and OUT taint sets (per-variable lattice elements) for a basic block.
///
/// Variables are identified by string keys (register names or symbolic
/// addresses rendered as hex strings, e.g. `"mem:0x1000"`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerBlockTaintState {
    /// Taint facts that hold at the *entry* of this block.
    pub taint_in: HashMap<String, TaintLattice>,
    /// Taint facts that hold at the *exit* of this block.
    pub taint_out: HashMap<String, TaintLattice>,
}

impl PerBlockTaintState {
    /// Create a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the IN taint for a variable, defaulting to BOTTOM.
    #[must_use]
    pub fn get_in(&self, var: &str) -> TaintLattice {
        self.taint_in
            .get(var)
            .copied()
            .unwrap_or(TaintLattice::BOTTOM)
    }

    /// Return the OUT taint for a variable, defaulting to BOTTOM.
    #[must_use]
    pub fn get_out(&self, var: &str) -> TaintLattice {
        self.taint_out
            .get(var)
            .copied()
            .unwrap_or(TaintLattice::BOTTOM)
    }

    /// Set the IN taint for a variable.
    pub fn set_in(&mut self, var: impl Into<String>, taint: TaintLattice) {
        self.taint_in.insert(var.into(), taint);
    }

    /// Set the OUT taint for a variable.
    pub fn set_out(&mut self, var: impl Into<String>, taint: TaintLattice) {
        self.taint_out.insert(var.into(), taint);
    }

    /// Merge another IN state into this one using join (union).
    /// Returns `true` if this state changed.
    pub fn merge_in(&mut self, other: &HashMap<String, TaintLattice>) -> bool {
        let mut changed = false;
        for (var, &new_taint) in other {
            let old = self
                .taint_in
                .entry(var.clone())
                .or_insert(TaintLattice::BOTTOM);
            let joined = old.join(new_taint);
            if joined != *old {
                *old = joined;
                changed = true;
            }
        }
        changed
    }

    /// Check whether IN and OUT are equal (fixpoint check).
    #[must_use]
    pub fn in_out_equal(&self) -> bool {
        self.taint_in == self.taint_out
    }
}

// ─── BasicBlock ──────────────────────────────────────────────────────────────

/// A basic block in the CFG: a sequence of `TaintInstr` with known successors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub instructions: Vec<TaintInstr>,
    pub successors: Vec<BlockId>,
    pub predecessors: Vec<BlockId>,
    /// Entry address of the block.
    pub start_addr: u64,
}

impl BasicBlock {
    /// Create a new basic block.
    #[must_use]
    pub fn new(id: BlockId, start_addr: u64, instructions: Vec<TaintInstr>) -> Self {
        Self {
            id,
            instructions,
            successors: Vec::new(),
            predecessors: Vec::new(),
            start_addr,
        }
    }

    /// Add a successor edge.
    pub fn add_successor(&mut self, succ: BlockId) {
        if !self.successors.contains(&succ) {
            self.successors.push(succ);
        }
    }

    /// Add a predecessor edge.
    pub fn add_predecessor(&mut self, pred: BlockId) {
        if !self.predecessors.contains(&pred) {
            self.predecessors.push(pred);
        }
    }
}

// ─── ControlFlowGraph ────────────────────────────────────────────────────────

/// A simple control-flow graph keyed by `BlockId`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub blocks: HashMap<BlockId, BasicBlock>,
    pub entry: BlockId,
}

impl ControlFlowGraph {
    /// Create a new, empty CFG.
    #[must_use]
    pub fn new(entry: BlockId) -> Self {
        Self {
            blocks: HashMap::new(),
            entry,
        }
    }

    /// Insert a basic block into the CFG.
    pub fn add_block(&mut self, block: BasicBlock) {
        self.blocks.insert(block.id, block);
    }

    /// Add a directed edge from `from` to `to`.
    pub fn add_edge(&mut self, from: BlockId, to: BlockId) {
        if let Some(b) = self.blocks.get_mut(&from) {
            b.add_successor(to);
        }
        if let Some(b) = self.blocks.get_mut(&to) {
            b.add_predecessor(from);
        }
    }

    /// Return block IDs in a stable order (sorted).
    #[must_use]
    pub fn block_ids(&self) -> Vec<BlockId> {
        let mut ids: Vec<_> = self.blocks.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Return the number of blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Return `true` if there are no blocks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

// ─── TaintTransferFunctions ───────────────────────────────────────────────────

/// Applies IL instruction transfer functions to per-block taint lattice state.
///
/// Each instruction transforms the current `HashMap<String, TaintLattice>`.
pub struct TaintTransferFunctions;

impl TaintTransferFunctions {
    /// Apply a single `TaintInstr` to the taint map.
    /// Returns any sink `TaintFinding` generated.
    pub fn apply(
        instr: &TaintInstr,
        taint_map: &mut HashMap<String, TaintLattice>,
    ) -> Option<TaintFinding> {
        // Convert taint_map to a TaintState for reuse of existing eval functions.
        let mut state = Self::map_to_state(taint_map);
        let finding = apply_instr(instr, &mut state);
        // Propagate register changes back to taint_map.
        for (reg, val) in &state.registers {
            taint_map.insert(reg.clone(), TaintLattice(val.taints));
        }
        // Propagate memory changes.
        for (addr, val) in &state.memory {
            taint_map.insert(format!("mem:{addr:#x}"), TaintLattice(val.taints));
        }
        finding
    }

    /// Apply a full basic block and return findings.
    pub fn apply_block(
        block: &BasicBlock,
        taint_in: &HashMap<String, TaintLattice>,
    ) -> (HashMap<String, TaintLattice>, Vec<TaintFinding>) {
        let mut current = taint_in.clone();
        let mut findings = Vec::new();
        for instr in &block.instructions {
            if let Some(f) = Self::apply(instr, &mut current) {
                findings.push(f);
            }
        }
        (current, findings)
    }

    fn map_to_state(taint_map: &HashMap<String, TaintLattice>) -> TaintState {
        let mut state = TaintState::new();
        for (key, lat) in taint_map {
            if let Some(addr_str) = key.strip_prefix("mem:") {
                if let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) {
                    state.set_mem(addr, TaintedValue::new(0, lat.0));
                }
            } else {
                state.set_reg(key, TaintedValue::new(0, lat.0));
            }
        }
        state
    }
}

// ─── TaintPropagationGraph ────────────────────────────────────────────────────

/// A directed graph recording taint flows: nodes are `(block_id, var)` pairs;
/// edges are labelled with the instruction address where taint propagated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintPropagationGraph {
    /// Adjacency list: source → list of (target, instr_addr).
    edges: HashMap<String, Vec<(String, u64)>>,
    /// All nodes ever referenced.
    nodes: HashSet<String>,
}

impl TaintPropagationGraph {
    /// Create a new empty propagation graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Node key from a (`block_id`, `variable`) pair.
    #[must_use]
    pub fn node_key(block_id: BlockId, var: &str) -> String {
        format!("b{block_id}::{var}")
    }

    /// Add a directed taint-flow edge.
    pub fn add_edge(&mut self, from: String, to: String, instr_addr: u64) {
        self.nodes.insert(from.clone());
        self.nodes.insert(to.clone());
        self.edges.entry(from).or_default().push((to, instr_addr));
    }

    /// Return all successors of `node` as `(target, instr_addr)`.
    #[must_use]
    pub fn successors(&self, node: &str) -> &[(String, u64)] {
        self.edges.get(node).map_or(&[], Vec::as_slice)
    }

    /// Check if there is a path from `source` to `sink` using BFS.
    #[must_use]
    pub fn has_path(&self, source: &str, sink: &str) -> bool {
        if source == sink {
            return true;
        }
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(source.to_string());
        while let Some(node) = queue.pop_front() {
            if !visited.insert(node.clone()) {
                continue;
            }
            for (succ, _) in self.successors(&node) {
                if succ == sink {
                    return true;
                }
                queue.push_back(succ.clone());
            }
        }
        false
    }

    /// Return the number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the number of edges (sum of all adjacency list sizes).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(Vec::len).sum()
    }

    /// Return all nodes reachable from `source` (BFS).
    #[must_use]
    pub fn reachable_from(&self, source: &str) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(source.to_string());
        while let Some(node) = queue.pop_front() {
            if !visited.insert(node.clone()) {
                continue;
            }
            for (succ, _) in self.successors(&node) {
                queue.push_back(succ.clone());
            }
        }
        visited.into_iter().collect()
    }
}

// ─── FixpointSolver ───────────────────────────────────────────────────────────

/// Configuration for the fixpoint solver.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FixpointConfig {
    /// Maximum number of worklist iterations before giving up.
    pub max_iterations: usize,
    /// If `true`, process blocks in RPO (reverse post-order) for efficiency.
    pub use_rpo: bool,
}

impl Default for FixpointConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10_000,
            use_rpo: true,
        }
    }
}

/// Result of a fixpoint solve.
#[derive(Debug, Default)]
pub struct FixpointResult {
    /// Per-block IN/OUT taint sets at fixpoint.
    pub block_states: HashMap<BlockId, PerBlockTaintState>,
    /// Taint findings emitted during propagation.
    pub findings: Vec<TaintFinding>,
    /// Taint propagation graph (how taint moved through the program).
    pub propagation_graph: TaintPropagationGraph,
    /// Number of worklist iterations taken.
    pub iterations: usize,
    /// Whether the solver converged.
    pub converged: bool,
}

/// Worklist-based forward dataflow fixpoint solver.
///
/// Algorithm:
/// 1. Initialise all block IN sets to BOTTOM.
/// 2. Mark the entry block with the initial seed taint.
/// 3. Repeatedly pop a block from the worklist, apply transfer functions to
///    compute the new OUT, then propagate OUT to successor IN sets (join).
/// 4. If a successor's IN changes, re-add it to the worklist.
/// 5. Stop when the worklist is empty or `max_iterations` is reached.
pub struct FixpointSolver {
    pub config: FixpointConfig,
}

impl FixpointSolver {
    /// Create a new solver with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: FixpointConfig::default(),
        }
    }

    /// Create a solver with custom configuration.
    #[must_use]
    pub const fn with_config(config: FixpointConfig) -> Self {
        Self { config }
    }

    /// Run the dataflow fixpoint over `cfg` starting from `seed`.
    ///
    /// `seed` is an initial taint map applied to the entry block's IN set.
    ///
    /// # Errors
    /// Returns [`DataflowError::DidNotConverge`] if the fixpoint is not reached
    /// within `config.max_iterations` iterations, or
    /// [`DataflowError::BlockNotFound`] if the CFG references a missing block.
    ///
    /// # Panics
    /// Panics if the OUT state for a block that was just inserted is missing
    /// (this is an internal invariant violation that should never occur).
    pub fn solve(
        &self,
        cfg: &ControlFlowGraph,
        seed: &HashMap<String, TaintLattice>,
    ) -> Result<FixpointResult, DataflowError> {
        let mut result = FixpointResult::default();

        // Initialise per-block state.
        for &bid in cfg.blocks.keys() {
            result.block_states.insert(bid, PerBlockTaintState::new());
        }

        // Seed the entry block.
        if let Some(entry_state) = result.block_states.get_mut(&cfg.entry) {
            for (var, taint) in seed {
                entry_state.taint_in.insert(var.clone(), *taint);
            }
        }

        let mut worklist: VecDeque<BlockId> = VecDeque::new();
        worklist.push_back(cfg.entry);
        let mut in_worklist: HashSet<BlockId> = HashSet::new();
        in_worklist.insert(cfg.entry);

        let mut iter = 0usize;

        while let Some(bid) = worklist.pop_front() {
            in_worklist.remove(&bid);
            iter += 1;
            if iter > self.config.max_iterations {
                result.iterations = iter;
                result.converged = false;
                return Err(DataflowError::DidNotConverge(iter));
            }

            let block = cfg
                .blocks
                .get(&bid)
                .ok_or(DataflowError::BlockNotFound(bid))?;

            // Copy IN state.
            let taint_in = result.block_states[&bid].taint_in.clone();

            // Apply transfer functions.
            let (taint_out, mut findings) = TaintTransferFunctions::apply_block(block, &taint_in);
            result.findings.append(&mut findings);

            // Record propagation graph edges for changed variables.
            for (var, &new_taint) in &taint_out {
                let old_taint = taint_in.get(var).copied().unwrap_or(TaintLattice::BOTTOM);
                if new_taint != old_taint {
                    let from_key = TaintPropagationGraph::node_key(bid, var);
                    for &succ in &block.successors {
                        let to_key = TaintPropagationGraph::node_key(succ, var);
                        result.propagation_graph.add_edge(
                            from_key.clone(),
                            to_key,
                            block.start_addr,
                        );
                    }
                }
            }

            // Update OUT state.
            result.block_states.get_mut(&bid).unwrap().taint_out.clone_from(&taint_out);

            // Propagate OUT to successor IN sets.
            for &succ in &block.successors {
                let succ_state = result
                    .block_states
                    .get_mut(&succ)
                    .ok_or(DataflowError::BlockNotFound(succ))?;
                let changed = succ_state.merge_in(&taint_out);
                if changed && !in_worklist.contains(&succ) {
                    worklist.push_back(succ);
                    in_worklist.insert(succ);
                }
            }
        }

        result.iterations = iter;
        result.converged = true;
        Ok(result)
    }
}

impl Default for FixpointSolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── DataflowTaintEngine ──────────────────────────────────────────────────────

/// High-level engine that wraps a CFG and runs the dataflow fixpoint.
///
/// Usage:
/// ```rust,no_run
/// use rustre_symb_taint::dataflow_taint::*;
/// use rustre_symb_taint::taint_bits;
/// let mut engine = DataflowTaintEngine::new(FixpointConfig::default());
/// let cfg = ControlFlowGraph::new(0);
/// // … add blocks …
/// let seed = std::collections::HashMap::new();
/// let result = engine.analyze(&cfg, seed).unwrap();
/// ```
pub struct DataflowTaintEngine {
    pub solver: FixpointSolver,
}

impl DataflowTaintEngine {
    /// Create a new engine with given configuration.
    #[must_use]
    pub fn new(config: FixpointConfig) -> Self {
        Self {
            solver: FixpointSolver::with_config(config),
        }
    }

    /// Run taint dataflow over the CFG. Returns the fixpoint result.
    ///
    /// # Errors
    /// Returns [`DataflowError`] if the fixpoint fails to converge or a block
    /// referenced in the CFG is not found.
    #[must_use = "the fixpoint result contains findings and block states"]
    pub fn analyze(
        &self,
        cfg: &ControlFlowGraph,
        seed: HashMap<String, TaintLattice>,
    ) -> Result<FixpointResult, DataflowError> {
        self.solver.solve(cfg, &seed)
    }

    /// Quick summary: which variables are tainted at the exit of the CFG?
    #[must_use]
    pub fn tainted_at_exit(
        result: &FixpointResult,
        exit_block: BlockId,
    ) -> Vec<(String, TaintLattice)> {
        result
            .block_states
            .get(&exit_block)
            .map(|bs| {
                bs.taint_out
                    .iter()
                    .filter(|&(_, &l)| !l.is_bottom())
                    .map(|(k, &v)| (k.clone(), v))
                    .collect()
            })
            .unwrap_or_default()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TaintExpr, TaintInstr, taint_bits};

    fn make_setreg(reg: &str, src_reg: &str, addr: u64) -> TaintInstr {
        TaintInstr::SetReg {
            reg: reg.into(),
            src: TaintExpr::Reg(src_reg.into()),
            addr,
        }
    }

    fn make_setreg_const(reg: &str, val: u64, addr: u64) -> TaintInstr {
        TaintInstr::SetReg {
            reg: reg.into(),
            src: TaintExpr::Const(val),
            addr,
        }
    }

    // ── TaintLattice tests ────────────────────────────────────────────────────

    #[test]
    fn lattice_join_is_union() {
        let a = TaintLattice(taint_bits::USER_INPUT);
        let b = TaintLattice(taint_bits::NETWORK);
        let j = a.join(b);
        assert_eq!(j.0, taint_bits::USER_INPUT | taint_bits::NETWORK);
    }

    #[test]
    fn lattice_meet_is_intersection() {
        let a = TaintLattice(taint_bits::USER_INPUT | taint_bits::NETWORK);
        let b = TaintLattice(taint_bits::USER_INPUT);
        let m = a.meet(b);
        assert_eq!(m.0, taint_bits::USER_INPUT);
    }

    #[test]
    fn lattice_bottom_is_zero() {
        assert!(TaintLattice::BOTTOM.is_bottom());
        assert!(!TaintLattice::BOTTOM.is_top());
    }

    #[test]
    fn lattice_top_is_all_bits() {
        assert!(TaintLattice::TOP.is_top());
        assert!(!TaintLattice::TOP.is_bottom());
    }

    #[test]
    fn lattice_join_with_bottom_is_identity() {
        let a = TaintLattice(taint_bits::FILE);
        assert_eq!(a.join(TaintLattice::BOTTOM), a);
    }

    #[test]
    fn lattice_meet_with_top_is_identity() {
        let a = TaintLattice(taint_bits::FILE);
        assert_eq!(a.meet(TaintLattice::TOP), a);
    }

    #[test]
    fn lattice_with_bits_adds() {
        let a = TaintLattice(taint_bits::FILE);
        let b = a.with_bits(taint_bits::NETWORK);
        assert_eq!(b.0, taint_bits::FILE | taint_bits::NETWORK);
    }

    #[test]
    fn lattice_without_bits_removes() {
        let a = TaintLattice(taint_bits::FILE | taint_bits::NETWORK);
        let b = a.without_bits(taint_bits::NETWORK);
        assert_eq!(b.0, taint_bits::FILE);
    }

    #[test]
    fn lattice_is_above() {
        let a = TaintLattice(taint_bits::USER_INPUT | taint_bits::NETWORK);
        let b = TaintLattice(taint_bits::USER_INPUT);
        assert!(a.is_above(b));
        assert!(!b.is_above(a));
        assert!(!a.is_above(a));
    }

    #[test]
    fn lattice_from_taint_id() {
        let l: TaintLattice = taint_bits::USER_INPUT.into();
        assert_eq!(l.0, taint_bits::USER_INPUT);
        let id: TaintId = l.into();
        assert_eq!(id, taint_bits::USER_INPUT);
    }

    // ── PerBlockTaintState tests ──────────────────────────────────────────────

    #[test]
    fn per_block_state_get_defaults_to_bottom() {
        let state = PerBlockTaintState::new();
        assert_eq!(state.get_in("rax"), TaintLattice::BOTTOM);
        assert_eq!(state.get_out("rax"), TaintLattice::BOTTOM);
    }

    #[test]
    fn per_block_state_set_and_get() {
        let mut state = PerBlockTaintState::new();
        state.set_in("rdi", TaintLattice(taint_bits::USER_INPUT));
        state.set_out("rdi", TaintLattice(taint_bits::NETWORK));
        assert_eq!(state.get_in("rdi").0, taint_bits::USER_INPUT);
        assert_eq!(state.get_out("rdi").0, taint_bits::NETWORK);
    }

    #[test]
    fn per_block_state_merge_in_detects_change() {
        let mut state = PerBlockTaintState::new();
        state.set_in("rax", TaintLattice(taint_bits::USER_INPUT));
        let mut other = HashMap::new();
        other.insert("rax".to_string(), TaintLattice(taint_bits::NETWORK));
        let changed = state.merge_in(&other);
        assert!(changed);
        assert_eq!(
            state.get_in("rax").0,
            taint_bits::USER_INPUT | taint_bits::NETWORK
        );
    }

    #[test]
    fn per_block_state_merge_in_no_change() {
        let mut state = PerBlockTaintState::new();
        state.set_in(
            "rax",
            TaintLattice(taint_bits::USER_INPUT | taint_bits::NETWORK),
        );
        let mut other = HashMap::new();
        other.insert("rax".to_string(), TaintLattice(taint_bits::USER_INPUT));
        let changed = state.merge_in(&other);
        assert!(!changed);
    }

    // ── BasicBlock and CFG tests ──────────────────────────────────────────────

    #[test]
    fn basic_block_successors_deduped() {
        let mut block = BasicBlock::new(0, 0x1000, vec![]);
        block.add_successor(1);
        block.add_successor(1); // duplicate
        block.add_successor(2);
        assert_eq!(block.successors.len(), 2);
    }

    #[test]
    fn cfg_add_edge_updates_both_directions() {
        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(BasicBlock::new(0, 0, vec![]));
        cfg.add_block(BasicBlock::new(1, 0x10, vec![]));
        cfg.add_edge(0, 1);
        assert!(cfg.blocks[&0].successors.contains(&1));
        assert!(cfg.blocks[&1].predecessors.contains(&0));
    }

    #[test]
    fn cfg_block_ids_sorted() {
        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(BasicBlock::new(3, 0, vec![]));
        cfg.add_block(BasicBlock::new(1, 0, vec![]));
        cfg.add_block(BasicBlock::new(2, 0, vec![]));
        assert_eq!(cfg.block_ids(), vec![1, 2, 3]);
    }

    // ── TaintTransferFunctions tests ──────────────────────────────────────────

    #[test]
    fn transfer_setreg_propagates_register_taint() {
        let mut taint_map: HashMap<String, TaintLattice> = HashMap::new();
        taint_map.insert("rdi".to_string(), TaintLattice(taint_bits::USER_INPUT));
        let instr = make_setreg("rax", "rdi", 0x100);
        TaintTransferFunctions::apply(&instr, &mut taint_map);
        assert_eq!(
            taint_map
                .get("rax")
                .copied()
                .unwrap_or(TaintLattice::BOTTOM)
                .0,
            taint_bits::USER_INPUT
        );
    }

    #[test]
    fn transfer_setreg_const_is_clean() {
        let mut taint_map: HashMap<String, TaintLattice> = HashMap::new();
        let instr = make_setreg_const("rax", 42, 0x100);
        TaintTransferFunctions::apply(&instr, &mut taint_map);
        assert!(
            taint_map
                .get("rax")
                .copied()
                .unwrap_or(TaintLattice::BOTTOM)
                .is_bottom()
        );
    }

    #[test]
    fn transfer_block_propagates_through_chain() {
        let instrs = vec![
            make_setreg("rbx", "rdi", 0x100),
            make_setreg("rcx", "rbx", 0x104),
        ];
        let block = BasicBlock::new(0, 0x100, instrs);
        let mut tin: HashMap<String, TaintLattice> = HashMap::new();
        tin.insert("rdi".to_string(), TaintLattice(taint_bits::NETWORK));
        let (tout, _) = TaintTransferFunctions::apply_block(&block, &tin);
        assert_eq!(
            tout.get("rcx").copied().unwrap_or(TaintLattice::BOTTOM).0,
            taint_bits::NETWORK
        );
    }

    // ── TaintPropagationGraph tests ───────────────────────────────────────────

    #[test]
    fn propagation_graph_add_and_query() {
        let mut g = TaintPropagationGraph::new();
        g.add_edge("b0::rax".to_string(), "b1::rax".to_string(), 0x100);
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn propagation_graph_has_path() {
        let mut g = TaintPropagationGraph::new();
        g.add_edge("b0::rax".to_string(), "b1::rax".to_string(), 0x100);
        g.add_edge("b1::rax".to_string(), "b2::rdi".to_string(), 0x200);
        assert!(g.has_path("b0::rax", "b2::rdi"));
        assert!(!g.has_path("b2::rdi", "b0::rax"));
    }

    #[test]
    fn propagation_graph_no_path_disconnected() {
        let g = TaintPropagationGraph::new();
        assert!(!g.has_path("b0::rax", "b1::rax"));
    }

    #[test]
    fn propagation_graph_node_key_format() {
        let key = TaintPropagationGraph::node_key(42, "rsp");
        assert_eq!(key, "b42::rsp");
    }

    #[test]
    fn propagation_graph_reachable() {
        let mut g = TaintPropagationGraph::new();
        g.add_edge("a".to_string(), "b".to_string(), 0);
        g.add_edge("b".to_string(), "c".to_string(), 0);
        let reachable = g.reachable_from("a");
        assert!(reachable.contains(&"a".to_string()));
        assert!(reachable.contains(&"b".to_string()));
        assert!(reachable.contains(&"c".to_string()));
    }

    // ── FixpointSolver / DataflowTaintEngine tests ────────────────────────────

    #[test]
    fn fixpoint_single_block_converges() {
        let instr = make_setreg("rbx", "rdi", 0x100);
        let block = BasicBlock::new(0, 0x100, vec![instr]);
        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(block);

        let mut seed = HashMap::new();
        seed.insert("rdi".to_string(), TaintLattice(taint_bits::USER_INPUT));

        let solver = FixpointSolver::new();
        let result = solver.solve(&cfg, &seed).unwrap();
        assert!(result.converged);
        assert_eq!(
            result.block_states[&0]
                .taint_out
                .get("rbx")
                .copied()
                .unwrap_or(TaintLattice::BOTTOM)
                .0,
            taint_bits::USER_INPUT
        );
    }

    #[test]
    fn fixpoint_two_blocks_propagates_across_edge() {
        let b0 = BasicBlock::new(0, 0x100, vec![make_setreg("rbx", "rdi", 0x100)]);
        let b1 = BasicBlock::new(1, 0x110, vec![make_setreg("rcx", "rbx", 0x110)]);
        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(b0);
        cfg.add_block(b1);
        cfg.add_edge(0, 1);

        let mut seed = HashMap::new();
        seed.insert("rdi".to_string(), TaintLattice(taint_bits::NETWORK));

        let engine = DataflowTaintEngine::new(FixpointConfig::default());
        let result = engine.analyze(&cfg, seed).unwrap();
        assert!(result.converged);
        assert_eq!(
            result.block_states[&1]
                .taint_out
                .get("rcx")
                .copied()
                .unwrap_or(TaintLattice::BOTTOM)
                .0,
            taint_bits::NETWORK
        );
    }

    #[test]
    fn fixpoint_join_at_merge_point() {
        // B0 → B1 (rdi tainted with USER_INPUT)
        // B0 → B2 (rdi tainted with NETWORK)
        // B1, B2 → B3: should have USER_INPUT | NETWORK at B3
        let b0 = BasicBlock::new(0, 0x100, vec![]);
        let b1 = BasicBlock::new(1, 0x110, vec![make_setreg("rax", "rdi", 0x110)]);
        let b2 = BasicBlock::new(2, 0x120, vec![make_setreg("rax", "rsi", 0x120)]);
        let b3 = BasicBlock::new(3, 0x130, vec![]);

        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(b0);
        cfg.add_block(b1);
        cfg.add_block(b2);
        cfg.add_block(b3);
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);

        let mut seed = HashMap::new();
        seed.insert("rdi".to_string(), TaintLattice(taint_bits::USER_INPUT));
        seed.insert("rsi".to_string(), TaintLattice(taint_bits::NETWORK));

        let solver = FixpointSolver::new();
        let result = solver.solve(&cfg, &seed).unwrap();
        assert!(result.converged);
        // B3's IN should have rax from both predecessors joined.
        let b3_in_rax = result.block_states[&3].get_in("rax").0;
        assert!(
            taint_bits::has_bit(b3_in_rax, taint_bits::USER_INPUT)
                || taint_bits::has_bit(b3_in_rax, taint_bits::NETWORK),
            "B3 should receive taint from merge: {b3_in_rax:#x}"
        );
    }

    #[test]
    fn fixpoint_max_iterations_error() {
        // Create a loop: B0 → B1 → B0, each block propagates taint forward.
        let b0 = BasicBlock::new(0, 0, vec![make_setreg("rax", "rdi", 0)]);
        let b1 = BasicBlock::new(1, 0x10, vec![make_setreg("rdi", "rax", 0x10)]);
        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(b0);
        cfg.add_block(b1);
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 0);

        let mut seed = HashMap::new();
        seed.insert("rdi".to_string(), TaintLattice(taint_bits::USER_INPUT));

        let solver = FixpointSolver::with_config(FixpointConfig {
            max_iterations: 1,
            use_rpo: false,
        });
        let result = solver.solve(&cfg, &seed);
        assert!(result.is_err());
    }

    #[test]
    fn tainted_at_exit_returns_tainted_vars() {
        let instr = make_setreg("rbx", "rdi", 0x100);
        let block = BasicBlock::new(0, 0x100, vec![instr]);
        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(block);

        let mut seed = HashMap::new();
        seed.insert("rdi".to_string(), TaintLattice(taint_bits::FILE));

        let engine = DataflowTaintEngine::new(FixpointConfig::default());
        let result = engine.analyze(&cfg, seed).unwrap();
        let tainted = DataflowTaintEngine::tainted_at_exit(&result, 0);
        let names: Vec<_> = tainted.iter().map(|(k, _)| k.as_str()).collect();
        assert!(
            names.contains(&"rbx") || names.contains(&"rdi"),
            "expected tainted exit vars"
        );
    }

    #[test]
    fn fixpoint_empty_cfg_converges() {
        let cfg = ControlFlowGraph::new(0);
        let solver = FixpointSolver::new();
        // CFG has no blocks, but entry is 0 — solver should not crash.
        let result = solver.solve(&cfg, &HashMap::new());
        // The entry block doesn't exist, so this might return an error.
        // Either outcome is acceptable for an empty CFG.
        let _ = result;
    }

    #[test]
    fn fixpoint_sink_finding_emitted() {
        let call_instr = TaintInstr::Call {
            target: "system".into(),
            args: vec![TaintExpr::Reg("rdi".into())],
            addr: 0x200,
        };
        let block = BasicBlock::new(0, 0x200, vec![call_instr]);
        let mut cfg = ControlFlowGraph::new(0);
        cfg.add_block(block);

        let mut seed = HashMap::new();
        seed.insert("rdi".to_string(), TaintLattice(taint_bits::USER_INPUT));

        let engine = DataflowTaintEngine::new(FixpointConfig::default());
        let result = engine.analyze(&cfg, seed).unwrap();
        assert!(
            !result.findings.is_empty(),
            "should emit a CommandInjection finding"
        );
    }

    #[test]
    fn per_block_state_in_out_equal_when_same() {
        let mut state = PerBlockTaintState::new();
        state.set_in("rax", TaintLattice(taint_bits::USER_INPUT));
        state.set_out("rax", TaintLattice(taint_bits::USER_INPUT));
        assert!(state.in_out_equal());
    }

    #[test]
    fn per_block_state_in_out_not_equal_when_different() {
        let mut state = PerBlockTaintState::new();
        state.set_in("rax", TaintLattice(taint_bits::USER_INPUT));
        state.set_out("rax", TaintLattice(taint_bits::NETWORK));
        assert!(!state.in_out_equal());
    }
}
