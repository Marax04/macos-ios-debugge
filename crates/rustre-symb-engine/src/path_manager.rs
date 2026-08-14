//! Symbolic execution path management.
//!
//! Provides [`PathManager`] which maintains a worklist of [`PathState`]s,
//! supports DFS/BFS/random exploration orders, prunes infeasible or
//! over-deep paths, and checks feasibility before enqueuing.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{ExecutorConfig, ExplorationStrategy};
use rustre_symb::SymExpr;

/// Re-exports of the lower-level symbolic primitives so path-manager users
/// can directly construct or inspect state without an extra import.
pub use rustre_symb::{SymbolicError, SymbolicState};

// ─── PathState ────────────────────────────────────────────────────────────────

/// The full symbolic state of one execution path.
#[derive(Debug, Clone)]
pub struct PathState {
    /// Current program counter.
    pub pc: u64,
    /// Exploration depth (number of steps from entry).
    pub depth: u32,
    /// Symbolic register file (name → expr).
    pub registers: HashMap<String, SymExpr>,
    /// Path constraints accumulated so far.
    pub constraints: Vec<SymExpr>,
    /// Whether this path is known to be infeasible.
    pub infeasible: bool,
    /// Unique identifier for this path.
    pub id: u64,
    /// Parent path ID (`None` for the root).
    pub parent_id: Option<u64>,
}

impl PathState {
    /// Create a new path state at `pc` with the given depth.
    #[must_use]
    pub fn new(id: u64, pc: u64, depth: u32, parent_id: Option<u64>) -> Self {
        Self {
            pc,
            depth,
            registers: HashMap::new(),
            constraints: Vec::new(),
            infeasible: false,
            id,
            parent_id,
        }
    }

    /// Add a constraint to this path.
    pub fn add_constraint(&mut self, expr: SymExpr) {
        self.constraints.push(expr);
    }

    /// Set a register to a symbolic expression.
    pub fn set_reg(&mut self, name: impl Into<String>, expr: SymExpr) {
        self.registers.insert(name.into(), expr);
    }

    /// Get the symbolic value of a register, or `None`.
    #[must_use]
    pub fn get_reg(&self, name: &str) -> Option<&SymExpr> {
        self.registers.get(name)
    }

    /// Mark this path as infeasible.
    pub const fn mark_infeasible(&mut self) {
        self.infeasible = true;
    }

    /// Return `true` if this path has any constraints.
    #[must_use]
    pub const fn has_constraints(&self) -> bool {
        !self.constraints.is_empty()
    }

    /// Number of constraints.
    #[must_use]
    pub const fn constraint_count(&self) -> usize {
        self.constraints.len()
    }

    /// Advance the program counter.
    pub const fn advance(&mut self, new_pc: u64) {
        self.pc = new_pc;
        self.depth += 1;
    }

    /// Fork this path into two branches at `branch_pc` / `fall_pc`, adding the
    /// appropriate branch condition constraints.
    #[must_use]
    pub fn fork(
        &self,
        taken_id: u64,
        not_taken_id: u64,
        branch_pc: u64,
        fallthrough_pc: u64,
        cond: SymExpr,
    ) -> (Self, Self) {
        let mut taken = self.clone();
        taken.id = taken_id;
        taken.parent_id = Some(self.id);
        taken.pc = branch_pc;
        taken.depth += 1;
        taken.add_constraint(cond.clone());

        let mut not_taken = self.clone();
        not_taken.id = not_taken_id;
        not_taken.parent_id = Some(self.id);
        not_taken.pc = fallthrough_pc;
        not_taken.depth += 1;
        not_taken.add_constraint(SymExpr::BoolNot(Box::new(cond)));

        (taken, not_taken)
    }
}

// ─── PathQueue ────────────────────────────────────────────────────────────────

/// Strategy-aware queue of [`PathState`]s.
#[derive(Debug, Default)]
pub struct PathQueue {
    deque: VecDeque<PathState>,
    strategy: ExplorationStrategy,
}

impl PathQueue {
    #[must_use]
    pub fn new(strategy: ExplorationStrategy) -> Self {
        Self {
            strategy,
            ..Default::default()
        }
    }

    /// Push a path onto the worklist.
    pub fn push(&mut self, state: PathState) {
        self.deque.push_back(state);
    }

    /// Pop the next path according to the strategy.
    pub fn pop(&mut self) -> Option<PathState> {
        match self.strategy {
            ExplorationStrategy::Dfs => self.deque.pop_back(),
            ExplorationStrategy::Bfs
            | ExplorationStrategy::CoverageGuided
            | ExplorationStrategy::RandomWalk => self.deque.pop_front(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.deque.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    /// Retain only paths that satisfy the predicate.
    pub fn retain<F: FnMut(&PathState) -> bool>(&mut self, f: F) {
        self.deque.retain(f);
    }

    /// Change the exploration strategy.
    pub const fn set_strategy(&mut self, s: ExplorationStrategy) {
        self.strategy = s;
    }

    /// Peek at the front item without removing it.
    #[must_use]
    pub fn peek_front(&self) -> Option<&PathState> {
        self.deque.front()
    }
}

// ─── PathPruner ───────────────────────────────────────────────────────────────

/// Pruning policy for the path worklist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPruner {
    /// Maximum exploration depth.  Paths deeper than this are dropped.
    pub max_depth: u32,
    /// Maximum number of loop iterations at a given back-edge before pruning.
    pub loop_bound: u32,
    /// Count of paths pruned by depth limit.
    pub depth_pruned: u64,
    /// Count of paths pruned by loop bound.
    pub loop_pruned: u64,
    /// Visit counts per PC (for loop detection).
    pc_visits: HashMap<u64, u32>,
}

impl PathPruner {
    #[must_use]
    pub fn new(max_depth: u32, loop_bound: u32) -> Self {
        Self {
            max_depth,
            loop_bound,
            depth_pruned: 0,
            loop_pruned: 0,
            pc_visits: HashMap::new(),
        }
    }

    /// Return `true` if `state` should be dropped.
    pub fn should_prune(&mut self, state: &PathState) -> bool {
        if state.depth > self.max_depth {
            self.depth_pruned += 1;
            return true;
        }
        let visits = self.pc_visits.entry(state.pc).or_insert(0);
        *visits = visits.saturating_add(1);
        if *visits > self.loop_bound {
            self.loop_pruned += 1;
            return true;
        }
        false
    }

    /// Reset all visit counters.
    pub fn reset_visits(&mut self) {
        self.pc_visits.clear();
    }
}

// ─── FeasibilityCheck ─────────────────────────────────────────────────────────

/// Lightweight feasibility checker.
///
/// In production this would invoke an SMT solver.  Here we use a conservative
/// heuristic: a path is considered infeasible only if it has been explicitly
/// marked so via `mark_infeasible`.
#[derive(Debug, Default, Clone)]
pub struct FeasibilityCheck {
    /// Number of checks performed.
    pub checks: u64,
    /// Number of paths reported infeasible.
    pub infeasible_count: u64,
}

impl FeasibilityCheck {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `state` is feasible.  Returns `true` if it might be.
    pub const fn is_feasible(&mut self, state: &PathState) -> bool {
        self.checks += 1;
        if state.infeasible {
            self.infeasible_count += 1;
            return false;
        }
        // Conservative: assume feasible unless marked otherwise.
        true
    }
}

// ─── PathManager ─────────────────────────────────────────────────────────────

/// Manages the collection of live symbolic paths.
///
/// Combines a [`PathQueue`], a [`PathPruner`], and a [`FeasibilityCheck`] to
/// provide a unified worklist API.
#[derive(Debug)]
pub struct PathManager {
    queue: PathQueue,
    pruner: PathPruner,
    feasibility: FeasibilityCheck,
    /// Total paths ever enqueued.
    total_enqueued: u64,
    /// Next path ID.
    next_id: u64,
    /// Visited (pc, depth) pairs for coverage tracking.
    visited: HashSet<(u64, u32)>,
    /// Config reference (cloned).
    pub config: ExecutorConfig,
}

impl PathManager {
    /// Create a new manager from an [`ExecutorConfig`].
    #[must_use]
    pub fn new(config: ExecutorConfig) -> Self {
        Self {
            queue: PathQueue::new(config.strategy),
            pruner: PathPruner::new(config.max_depth, 10),
            feasibility: FeasibilityCheck::new(),
            total_enqueued: 0,
            next_id: 0,
            visited: HashSet::new(),
            config,
        }
    }

    /// Allocate a new path ID.
    pub const fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Enqueue a new path state.  Returns `false` if it was rejected (too many
    /// states, infeasible, or pruned).
    pub fn enqueue(&mut self, state: PathState) -> bool {
        if self.queue.len() >= self.config.max_states {
            return false;
        }
        if self.pruner.should_prune(&state) {
            return false;
        }
        if !self.feasibility.is_feasible(&state) {
            return false;
        }
        self.visited.insert((state.pc, state.depth));
        self.total_enqueued += 1;
        self.queue.push(state);
        true
    }

    /// Dequeue the next path.
    pub fn dequeue(&mut self) -> Option<PathState> {
        self.queue.pop()
    }

    /// Whether the worklist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Current worklist size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Total paths enqueued (ever).
    #[must_use]
    pub const fn total_enqueued(&self) -> u64 {
        self.total_enqueued
    }

    /// Remove all paths that are marked infeasible.
    pub fn prune_infeasible(&mut self) {
        self.queue.retain(|s| !s.infeasible);
    }

    /// Return coverage: number of (pc, depth) pairs visited.
    #[must_use]
    pub fn coverage(&self) -> usize {
        self.visited.len()
    }

    /// Stats from the pruner.
    #[must_use]
    pub const fn depth_pruned(&self) -> u64 {
        self.pruner.depth_pruned
    }

    #[must_use]
    pub const fn loop_pruned(&self) -> u64 {
        self.pruner.loop_pruned
    }

    /// Feasibility check stats.
    #[must_use]
    pub const fn feasibility_checks(&self) -> u64 {
        self.feasibility.checks
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_symb::SymExpr;

    fn default_config() -> ExecutorConfig {
        ExecutorConfig::default()
    }

    fn make_state(id: u64, pc: u64, depth: u32) -> PathState {
        PathState::new(id, pc, depth, None)
    }

    // --- PathState ---

    #[test]
    fn path_state_add_constraint() {
        let mut s = make_state(0, 0x1000, 0);
        assert!(!s.has_constraints());
        s.add_constraint(SymExpr::constant(1, 1));
        assert!(s.has_constraints());
        assert_eq!(s.constraint_count(), 1);
    }

    #[test]
    fn path_state_set_get_reg() {
        let mut s = make_state(0, 0, 0);
        s.set_reg("rax", SymExpr::constant(64, 42));
        assert!(s.get_reg("rax").is_some());
        assert!(s.get_reg("rbx").is_none());
    }

    #[test]
    fn path_state_advance() {
        let mut s = make_state(0, 0x1000, 3);
        s.advance(0x1002);
        assert_eq!(s.pc, 0x1002);
        assert_eq!(s.depth, 4);
    }

    #[test]
    fn path_state_mark_infeasible() {
        let mut s = make_state(0, 0, 0);
        assert!(!s.infeasible);
        s.mark_infeasible();
        assert!(s.infeasible);
    }

    #[test]
    fn path_state_fork_produces_two_children() {
        let s = make_state(0, 0x1000, 0);
        let cond = SymExpr::constant(1, 1);
        let (taken, not_taken) = s.fork(1, 2, 0x2000, 0x1002, cond);
        assert_eq!(taken.id, 1);
        assert_eq!(taken.pc, 0x2000);
        assert_eq!(not_taken.id, 2);
        assert_eq!(not_taken.pc, 0x1002);
        assert_eq!(taken.depth, 1);
    }

    #[test]
    fn path_state_fork_preserves_parent_id() {
        let s = make_state(42, 0, 0);
        let cond = SymExpr::constant(1, 0);
        let (taken, _) = s.fork(100, 101, 0, 0, cond);
        assert_eq!(taken.parent_id, Some(42));
    }

    // --- PathQueue ---

    #[test]
    fn queue_dfs_lifo() {
        let mut q = PathQueue::new(ExplorationStrategy::Dfs);
        q.push(make_state(0, 0xA, 0));
        q.push(make_state(1, 0xB, 0));
        assert_eq!(q.pop().unwrap().pc, 0xB); // LIFO
    }

    #[test]
    fn queue_bfs_fifo() {
        let mut q = PathQueue::new(ExplorationStrategy::Bfs);
        q.push(make_state(0, 0xA, 0));
        q.push(make_state(1, 0xB, 0));
        assert_eq!(q.pop().unwrap().pc, 0xA); // FIFO
    }

    #[test]
    fn queue_empty_pop_none() {
        let mut q = PathQueue::new(ExplorationStrategy::Dfs);
        assert!(q.pop().is_none());
    }

    #[test]
    fn queue_retain() {
        let mut q = PathQueue::new(ExplorationStrategy::Dfs);
        q.push(make_state(0, 0xA, 5));
        q.push(make_state(1, 0xB, 1));
        q.retain(|s| s.depth < 3);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn queue_set_strategy() {
        let mut q = PathQueue::new(ExplorationStrategy::Dfs);
        q.set_strategy(ExplorationStrategy::Bfs);
        q.push(make_state(0, 0xA, 0));
        q.push(make_state(1, 0xB, 0));
        assert_eq!(q.pop().unwrap().pc, 0xA);
    }

    // --- PathPruner ---

    #[test]
    fn pruner_depth_limit() {
        let mut p = PathPruner::new(5, 100);
        let s = make_state(0, 0, 6);
        assert!(p.should_prune(&s));
        assert_eq!(p.depth_pruned, 1);
    }

    #[test]
    fn pruner_loop_bound() {
        let mut p = PathPruner::new(1000, 2);
        let s = make_state(0, 0x1000, 0);
        assert!(!p.should_prune(&s)); // visit 1
        assert!(!p.should_prune(&s)); // visit 2
        assert!(p.should_prune(&s)); // visit 3 → prune
        assert_eq!(p.loop_pruned, 1);
    }

    #[test]
    fn pruner_reset_visits() {
        let mut p = PathPruner::new(1000, 1);
        let s = make_state(0, 0x1000, 0);
        p.should_prune(&s);
        p.reset_visits();
        assert!(!p.should_prune(&s)); // visit count reset
    }

    // --- FeasibilityCheck ---

    #[test]
    fn feasibility_feasible_by_default() {
        let mut fc = FeasibilityCheck::new();
        let s = make_state(0, 0, 0);
        assert!(fc.is_feasible(&s));
        assert_eq!(fc.checks, 1);
    }

    #[test]
    fn feasibility_infeasible_when_marked() {
        let mut fc = FeasibilityCheck::new();
        let mut s = make_state(0, 0, 0);
        s.mark_infeasible();
        assert!(!fc.is_feasible(&s));
        assert_eq!(fc.infeasible_count, 1);
    }

    // --- PathManager ---

    #[test]
    fn path_manager_enqueue_dequeue() {
        let mut pm = PathManager::new(default_config());
        let s = make_state(0, 0x1000, 0);
        assert!(pm.enqueue(s));
        assert!(!pm.is_empty());
        assert!(pm.dequeue().is_some());
        assert!(pm.is_empty());
    }

    #[test]
    fn path_manager_rejects_over_max_states() {
        let mut cfg = default_config();
        cfg.max_states = 2;
        let mut pm = PathManager::new(cfg);
        assert!(pm.enqueue(make_state(0, 0, 0)));
        assert!(pm.enqueue(make_state(1, 1, 0)));
        assert!(!pm.enqueue(make_state(2, 2, 0))); // over limit
    }

    #[test]
    fn path_manager_rejects_infeasible() {
        let mut pm = PathManager::new(default_config());
        let mut s = make_state(0, 0, 0);
        s.mark_infeasible();
        assert!(!pm.enqueue(s));
    }

    #[test]
    fn path_manager_total_enqueued() {
        let mut pm = PathManager::new(default_config());
        pm.enqueue(make_state(0, 0, 0));
        pm.enqueue(make_state(1, 1, 0));
        assert_eq!(pm.total_enqueued(), 2);
    }

    #[test]
    fn path_manager_alloc_id_monotone() {
        let mut pm = PathManager::new(default_config());
        let a = pm.alloc_id();
        let b = pm.alloc_id();
        assert_eq!(b, a + 1);
    }

    #[test]
    fn path_manager_prune_infeasible() {
        let mut pm = PathManager::new(default_config());
        let mut bad = make_state(0, 0, 0);
        bad.mark_infeasible();
        // Directly push without enqueue to bypass the check
        pm.queue.push(bad);
        pm.queue.push(make_state(1, 1, 0));
        pm.prune_infeasible();
        assert_eq!(pm.len(), 1);
    }

    #[test]
    fn path_manager_coverage_tracks_unique_visits() {
        let mut pm = PathManager::new(default_config());
        pm.enqueue(make_state(0, 0xA, 0));
        pm.enqueue(make_state(1, 0xB, 0));
        pm.enqueue(make_state(2, 0xA, 0)); // same (pc=0xA, depth=0) — not counted twice
        assert_eq!(pm.coverage(), 2);
    }
}
