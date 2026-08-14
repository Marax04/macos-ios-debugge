//! `path_explosion` — **Runtime** path explosion mitigation (hard limits, worklist, loop bounds).
//!
//! Large programs can generate an exponential number of symbolic execution
//! paths. This module provides:
//! - [`StateLimit`]: hard cap on active states
//! - [`DepthLimit`]: maximum exploration depth
//! - [`LoopBound`]: loop iteration bounds
//! - [`PrioritizationQueue`]: priority-ordered state worklist
//! - [`PathSelector`]: composable path-selection policies
//!
//! # Relationship to [`explosion_mitigation`](crate::explosion_mitigation)
//!
//! These modules are **not duplicates** — they address different aspects:
//!
//! | Module | Focus |
//! |--------|-------|
//! | **`path_explosion`** (this file) | Runtime guards: hard state/depth caps, loop-count tracking, worklist management |
//! | [`explosion_mitigation`](crate::explosion_mitigation) | Higher-level policies: loop-bound inference from back-edges, state merging/abstraction, function-summary caching, subsumption detection |

use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap};
use std::fmt;

use crate::{SymbolicError, SymbolicState};

/// Convert a `u64` to `f64`, saturating any value above 2^53 to that boundary
/// (the largest integer exactly representable in `f64`).
///
/// Used for ratio statistics where the absolute magnitude beyond 2^53 carries
/// no meaningful precision anyway.
///
/// This is the canonical copy; [`explosion_mitigation`](crate::explosion_mitigation)
/// imports it from here to avoid duplication.
#[inline]
pub(crate) fn u64_to_f64_lossy(v: u64) -> f64 {
    // 2^53 — the largest integer with an exact `f64` representation.
    const F64_INT_BOUND: u64 = 1u64 << 53;
    // 2^32, expressed as f64 by composing two f64-exact halves.
    const TWO_POW_32: f64 = 4_294_967_296.0;
    // 2^53 as an f64 literal (exactly representable).
    const F64_BOUND_AS_F64: f64 = 9_007_199_254_740_992.0;
    if v <= F64_INT_BOUND {
        u32::try_from(v).map_or_else(
            |_| {
                let hi = u32::try_from(v >> 32).unwrap_or(0);
                let lo = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(0);
                f64::from(hi).mul_add(TWO_POW_32, f64::from(lo))
            },
            f64::from,
        )
    } else {
        F64_BOUND_AS_F64
    }
}

// ---------------------------------------------------------------------------
// StateLimit
// ---------------------------------------------------------------------------

/// Hard cap on the number of simultaneously active symbolic states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateLimit {
    /// Maximum allowed active states.
    pub max_states: usize,
    /// Action to take when the limit is exceeded.
    pub action: LimitAction,
}

/// Action to take when a state limit is exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LimitAction {
    /// Drop the newest (least explored) states.
    DropNewest,
    /// Drop the deepest states (most explored depth).
    DropDeepest,
    /// Return an error.
    Error,
}

impl StateLimit {
    /// Create a new state limit.
    #[must_use]
    pub const fn new(max_states: usize, action: LimitAction) -> Self {
        Self { max_states, action }
    }

    /// Apply the limit to a state worklist in-place.
    ///
    /// # Errors
    ///
    /// Returns [`SymbolicError::StateExplosion`] if `action` is [`LimitAction::Error`]
    /// and the limit is exceeded.
    pub fn enforce(&self, states: &mut Vec<SymbolicState>) -> Result<(), SymbolicError> {
        if states.len() <= self.max_states {
            return Ok(());
        }
        match self.action {
            LimitAction::DropNewest => {
                states.truncate(self.max_states);
            }
            LimitAction::DropDeepest => {
                // Sort by depth ascending (keep shallowest)
                states.sort_by_key(|s| s.depth);
                states.truncate(self.max_states);
            }
            LimitAction::Error => {
                return Err(SymbolicError::StateExplosion(states.len()));
            }
        }
        Ok(())
    }

    /// Return `true` if the given count exceeds the limit.
    #[must_use]
    pub const fn is_exceeded(&self, count: usize) -> bool {
        count > self.max_states
    }
}

impl fmt::Display for StateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StateLimit(max={}, action={:?})",
            self.max_states, self.action
        )
    }
}

// ---------------------------------------------------------------------------
// DepthLimit
// ---------------------------------------------------------------------------

/// Maximum exploration depth in the symbolic execution tree.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DepthLimit {
    /// Maximum depth allowed.
    pub max_depth: u32,
}

impl DepthLimit {
    /// Create a new depth limit.
    #[must_use]
    pub const fn new(max_depth: u32) -> Self {
        Self { max_depth }
    }

    /// Return `true` if the given state has reached the depth limit.
    #[must_use]
    pub const fn is_exceeded(&self, state: &SymbolicState) -> bool {
        state.depth >= self.max_depth
    }

    /// Filter out states that exceed the depth limit.
    pub fn filter_states(&self, states: &mut Vec<SymbolicState>) {
        states.retain(|s| s.depth < self.max_depth);
    }
}

impl fmt::Display for DepthLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DepthLimit({})", self.max_depth)
    }
}

// ---------------------------------------------------------------------------
// LoopBound
// ---------------------------------------------------------------------------

/// Tracks loop iteration counts to prevent infinite loops in symbolic execution.
#[derive(Debug, Clone)]
pub struct LoopBound {
    /// Maximum iterations permitted per loop back-edge.
    pub max_iterations: u32,
    /// Back-edge address → iteration count for each active state.
    counters: HashMap<u64, u32>,
}

impl LoopBound {
    /// Create a new loop bound tracker.
    #[must_use]
    pub fn new(max_iterations: u32) -> Self {
        Self {
            max_iterations,
            counters: HashMap::new(),
        }
    }

    /// Record one iteration of the loop with back-edge at `address`.
    ///
    /// Returns `true` if the loop should continue, `false` if the bound is hit.
    pub fn record_iteration(&mut self, address: u64) -> bool {
        let count = self.counters.entry(address).or_insert(0);
        *count += 1;
        *count <= self.max_iterations
    }

    /// Reset iteration counts for a specific back-edge (when leaving a loop).
    pub fn reset(&mut self, address: u64) {
        self.counters.remove(&address);
    }

    /// Reset all tracked counters.
    pub fn reset_all(&mut self) {
        self.counters.clear();
    }

    /// Return the current iteration count for the given back-edge address.
    #[must_use]
    pub fn iteration_count(&self, address: u64) -> u32 {
        self.counters.get(&address).copied().unwrap_or(0)
    }

    /// Return all tracked back-edges with their iteration counts.
    #[must_use]
    pub const fn all_counts(&self) -> &HashMap<u64, u32> {
        &self.counters
    }
}

// ---------------------------------------------------------------------------
// Priority-ordered state worklist
// ---------------------------------------------------------------------------

/// Priority assigned to a symbolic state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatePriority {
    /// States that have not been explored yet (highest priority).
    New = 100,
    /// States near a security-sensitive sink.
    NearSink = 80,
    /// States with fewer path constraints (less complex).
    LessConstrained = 60,
    /// Default exploration priority.
    Normal = 40,
    /// Deeply-nested states with many constraints (deprioritised).
    Deep = 20,
}

/// A symbolic state with an associated priority.
#[derive(Debug)]
struct PrioritisedState {
    state: SymbolicState,
    priority: u32,
    seq: u64, // tie-breaking FIFO sequence
}

impl PartialEq for PrioritisedState {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.seq == other.seq
    }
}

impl Eq for PrioritisedState {}

impl PartialOrd for PrioritisedState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritisedState {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // BinaryHeap is a max-heap: elements comparing as *greater* are popped first.
        // We want higher priority to be popped first, so higher priority → greater ordering.
        // For tie-breaking (FIFO), lower seq (earlier insertion) → greater ordering.
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

/// A priority queue worklist for symbolic execution states.
///
/// States with higher [`StatePriority`] are explored first.
pub struct PrioritizationQueue {
    heap: BinaryHeap<PrioritisedState>,
    seq: u64,
}

impl PrioritizationQueue {
    /// Create an empty queue.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            seq: 0,
        }
    }

    /// Push a state with an associated priority.
    pub fn push(&mut self, state: SymbolicState, priority: StatePriority) {
        self.seq += 1;
        self.heap.push(PrioritisedState {
            state,
            priority: priority as u32,
            seq: self.seq,
        });
    }

    /// Pop the highest-priority state.
    #[must_use]
    pub fn pop(&mut self) -> Option<SymbolicState> {
        self.heap.pop().map(|ps| ps.state)
    }

    /// Return the number of states in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Return `true` if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Drain all states into a `Vec`, ordered by priority (highest first).
    #[must_use]
    pub fn drain_ordered(mut self) -> Vec<SymbolicState> {
        let mut v = Vec::with_capacity(self.heap.len());
        while let Some(ps) = self.heap.pop() {
            v.push(ps.state);
        }
        v
    }
}

impl Default for PrioritizationQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PrioritizationQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrioritizationQueue")
            .field("len", &self.heap.len())
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// PathSelector
// ---------------------------------------------------------------------------

/// Policy for selecting which state to explore next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathSelectionPolicy {
    /// Depth-first search — deepest state first.
    DepthFirst,
    /// Breadth-first search — shallowest state first.
    BreadthFirst,
    /// Random selection for coverage diversity.
    Random,
    /// Prioritise states with fewer path constraints.
    MinConstraints,
    /// Prioritise states closest to a target address.
    TargetDirected { target_addr: u64 },
}

/// Selects the next state to explore from a worklist.
pub struct PathSelector {
    /// The selection policy to use.
    pub policy: PathSelectionPolicy,
}

impl PathSelector {
    /// Create a path selector with the given policy.
    #[must_use]
    pub const fn new(policy: PathSelectionPolicy) -> Self {
        Self { policy }
    }

    /// Select and remove one state from `worklist` according to the policy.
    ///
    /// Returns `None` if the worklist is empty.
    #[must_use]
    pub fn select(&self, worklist: &mut Vec<SymbolicState>) -> Option<SymbolicState> {
        if worklist.is_empty() {
            return None;
        }
        let idx = match self.policy {
            PathSelectionPolicy::DepthFirst => {
                // Pick the state with the greatest depth
                worklist
                    .iter()
                    .enumerate()
                    .max_by_key(|(_, s)| s.depth)
                    .map_or(0, |(i, _)| i)
            }
            PathSelectionPolicy::BreadthFirst => {
                // Pick the state with the smallest depth
                worklist
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| s.depth)
                    .map_or(0, |(i, _)| i)
            }
            PathSelectionPolicy::MinConstraints => {
                // Pick the state with the fewest path constraints
                worklist
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| s.path_condition.len())
                    .map_or(0, |(i, _)| i)
            }
            PathSelectionPolicy::Random => {
                // Use a simple pseudo-random selection based on list length
                worklist.len() / 2
            }
            PathSelectionPolicy::TargetDirected { target_addr } => {
                // Prefer states whose PC is closest to the target
                worklist
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, s)| s.pc.abs_diff(target_addr))
                    .map_or(0, |(i, _)| i)
            }
        };
        Some(worklist.swap_remove(idx))
    }
}

impl fmt::Display for PathSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PathSelector({:?})", self.policy)
    }
}

// ---------------------------------------------------------------------------
// ExplorationStats
// ---------------------------------------------------------------------------

/// Statistics collected during symbolic exploration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExplorationStats {
    /// Total states explored.
    pub states_explored: u64,
    /// States abandoned (depth/limit exceeded).
    pub states_abandoned: u64,
    /// States found to be infeasible.
    pub infeasible_states: u64,
    /// Maximum depth reached.
    pub max_depth_reached: u32,
    /// Total branches encountered.
    pub branches_encountered: u64,
    /// Branches that were both true and false (real forks).
    pub real_forks: u64,
}

impl ExplorationStats {
    /// Create zeroed statistics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one explored state at the given depth.
    pub const fn record_state(&mut self, depth: u32) {
        self.states_explored += 1;
        if depth > self.max_depth_reached {
            self.max_depth_reached = depth;
        }
    }

    /// Record an abandoned state.
    pub const fn record_abandoned(&mut self) {
        self.states_abandoned += 1;
    }

    /// Record an infeasible path.
    pub const fn record_infeasible(&mut self) {
        self.infeasible_states += 1;
    }

    /// Record a branch, specifying whether both paths were taken.
    pub const fn record_branch(&mut self, both_taken: bool) {
        self.branches_encountered += 1;
        if both_taken {
            self.real_forks += 1;
        }
    }

    /// Fraction of branches that produced real forks, or 0 if none.
    #[must_use]
    pub fn fork_ratio(&self) -> f64 {
        if self.branches_encountered == 0 {
            0.0
        } else {
            u64_to_f64_lossy(self.real_forks) / u64_to_f64_lossy(self.branches_encountered)
        }
    }
}

impl fmt::Display for ExplorationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Explored={} Abandoned={} Infeasible={} MaxDepth={} Forks={}/{} ({:.0}%)",
            self.states_explored,
            self.states_abandoned,
            self.infeasible_states,
            self.max_depth_reached,
            self.real_forks,
            self.branches_encountered,
            self.fork_ratio() * 100.0,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SymbolicState;

    fn make_state(depth: u32, pc: u64) -> SymbolicState {
        let mut s = SymbolicState::new();
        s.depth = depth;
        s.pc = pc;
        s
    }

    // ---- StateLimit ----

    #[test]
    fn test_state_limit_not_exceeded() {
        let limit = StateLimit::new(5, LimitAction::DropNewest);
        let mut states = vec![make_state(0, 0), make_state(1, 0)];
        limit.enforce(&mut states).unwrap();
        assert_eq!(states.len(), 2);
    }

    #[test]
    fn test_state_limit_drop_newest() {
        let limit = StateLimit::new(2, LimitAction::DropNewest);
        let mut states = vec![make_state(0, 0), make_state(1, 0), make_state(2, 0)];
        limit.enforce(&mut states).unwrap();
        assert_eq!(states.len(), 2);
    }

    #[test]
    fn test_state_limit_drop_deepest() {
        let limit = StateLimit::new(2, LimitAction::DropDeepest);
        let mut states = vec![make_state(5, 0), make_state(1, 0), make_state(3, 0)];
        limit.enforce(&mut states).unwrap();
        assert_eq!(states.len(), 2);
        assert!(states.iter().all(|s| s.depth <= 3));
    }

    #[test]
    fn test_state_limit_error() {
        let limit = StateLimit::new(1, LimitAction::Error);
        let mut states = vec![make_state(0, 0), make_state(1, 0)];
        let r = limit.enforce(&mut states);
        assert!(r.is_err());
    }

    #[test]
    fn test_state_limit_is_exceeded() {
        let limit = StateLimit::new(3, LimitAction::DropNewest);
        assert!(!limit.is_exceeded(3));
        assert!(limit.is_exceeded(4));
    }

    #[test]
    fn test_state_limit_display() {
        let limit = StateLimit::new(100, LimitAction::DropNewest);
        let s = limit.to_string();
        assert!(s.contains("100"));
    }

    // ---- DepthLimit ----

    #[test]
    fn test_depth_limit_not_exceeded() {
        let dl = DepthLimit::new(10);
        let s = make_state(9, 0);
        assert!(!dl.is_exceeded(&s));
    }

    #[test]
    fn test_depth_limit_exceeded() {
        let dl = DepthLimit::new(10);
        let s = make_state(10, 0);
        assert!(dl.is_exceeded(&s));
    }

    #[test]
    fn test_depth_limit_filter() {
        let dl = DepthLimit::new(5);
        let mut states = vec![make_state(4, 0), make_state(5, 0), make_state(6, 0)];
        dl.filter_states(&mut states);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].depth, 4);
    }

    #[test]
    fn test_depth_limit_display() {
        let dl = DepthLimit::new(20);
        assert!(dl.to_string().contains("20"));
    }

    // ---- LoopBound ----

    #[test]
    fn test_loop_bound_allows_below_max() {
        let mut lb = LoopBound::new(3);
        assert!(lb.record_iteration(0x1000));
        assert!(lb.record_iteration(0x1000));
        assert!(lb.record_iteration(0x1000));
    }

    #[test]
    fn test_loop_bound_rejects_above_max() {
        let mut lb = LoopBound::new(2);
        lb.record_iteration(0x1000);
        lb.record_iteration(0x1000);
        assert!(!lb.record_iteration(0x1000));
    }

    #[test]
    fn test_loop_bound_reset() {
        let mut lb = LoopBound::new(1);
        lb.record_iteration(0x1000);
        lb.reset(0x1000);
        assert!(lb.record_iteration(0x1000));
    }

    #[test]
    fn test_loop_bound_reset_all() {
        let mut lb = LoopBound::new(1);
        lb.record_iteration(0x1000);
        lb.record_iteration(0x2000);
        lb.reset_all();
        assert_eq!(lb.iteration_count(0x1000), 0);
    }

    #[test]
    fn test_loop_bound_iteration_count() {
        let mut lb = LoopBound::new(10);
        lb.record_iteration(0x4000);
        lb.record_iteration(0x4000);
        assert_eq!(lb.iteration_count(0x4000), 2);
    }

    // ---- PrioritizationQueue ----

    #[test]
    fn test_priority_queue_empty() {
        let q = PrioritizationQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn test_priority_queue_push_pop() {
        let mut q = PrioritizationQueue::new();
        // Push Normal-priority state with depth=1, then New-priority state with depth=3
        q.push(make_state(1, 0), StatePriority::Normal);
        q.push(make_state(3, 0), StatePriority::New);
        let s = q.pop().unwrap();
        // New (priority=100) > Normal (priority=40) — New state should come first
        assert_eq!(s.depth, 3);
    }

    #[test]
    fn test_priority_queue_len() {
        let mut q = PrioritizationQueue::new();
        q.push(make_state(0, 0), StatePriority::Normal);
        q.push(make_state(1, 0), StatePriority::Deep);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn test_priority_queue_drain_ordered() {
        let mut q = PrioritizationQueue::new();
        // depth=10 → Deep priority (20), depth=20 → New priority (100), depth=5 → Normal priority (40)
        q.push(make_state(10, 0), StatePriority::Deep);
        q.push(make_state(20, 0), StatePriority::New);
        q.push(make_state(5, 0), StatePriority::Normal);
        let drained = q.drain_ordered();
        assert_eq!(drained.len(), 3);
        // First should be the New priority (depth=20)
        assert_eq!(drained[0].depth, 20);
    }

    #[test]
    fn test_priority_queue_debug() {
        let q = PrioritizationQueue::new();
        let s = format!("{q:?}");
        assert!(s.contains("PrioritizationQueue"));
    }

    // ---- PathSelector ----

    #[test]
    fn test_path_selector_depth_first() {
        let sel = PathSelector::new(PathSelectionPolicy::DepthFirst);
        let mut states = vec![make_state(1, 0), make_state(5, 0), make_state(3, 0)];
        let s = sel.select(&mut states).unwrap();
        assert_eq!(s.depth, 5);
    }

    #[test]
    fn test_path_selector_breadth_first() {
        let sel = PathSelector::new(PathSelectionPolicy::BreadthFirst);
        let mut states = vec![make_state(3, 0), make_state(1, 0), make_state(5, 0)];
        let s = sel.select(&mut states).unwrap();
        assert_eq!(s.depth, 1);
    }

    #[test]
    fn test_path_selector_empty_returns_none() {
        let sel = PathSelector::new(PathSelectionPolicy::DepthFirst);
        let mut states: Vec<SymbolicState> = Vec::new();
        assert!(sel.select(&mut states).is_none());
    }

    #[test]
    fn test_path_selector_min_constraints() {
        let sel = PathSelector::new(PathSelectionPolicy::MinConstraints);
        let s0 = {
            let mut s = make_state(0, 0);
            s.path_condition.push(crate::SymExpr::ConstBool(true));
            s.path_condition.push(crate::SymExpr::ConstBool(true));
            s
        };
        let s1 = make_state(0, 0); // 0 constraints
        let mut states = vec![s0, s1];
        let selected = sel.select(&mut states).unwrap();
        assert_eq!(selected.path_condition.len(), 0);
    }

    #[test]
    fn test_path_selector_target_directed() {
        let sel = PathSelector::new(PathSelectionPolicy::TargetDirected {
            target_addr: 0x2000,
        });
        let mut states = vec![make_state(0, 0x1000), make_state(0, 0x2001)];
        let s = sel.select(&mut states).unwrap();
        assert_eq!(s.pc, 0x2001); // closest to target
    }

    #[test]
    fn test_path_selector_display() {
        let sel = PathSelector::new(PathSelectionPolicy::BreadthFirst);
        let s = sel.to_string();
        assert!(s.contains("PathSelector"));
    }

    // ---- ExplorationStats ----

    #[test]
    fn test_exploration_stats_default() {
        let stats = ExplorationStats::new();
        assert_eq!(stats.states_explored, 0);
        assert!((stats.fork_ratio()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_exploration_stats_record_state() {
        let mut stats = ExplorationStats::new();
        stats.record_state(5);
        stats.record_state(10);
        assert_eq!(stats.states_explored, 2);
        assert_eq!(stats.max_depth_reached, 10);
    }

    #[test]
    fn test_exploration_stats_record_abandoned() {
        let mut stats = ExplorationStats::new();
        stats.record_abandoned();
        assert_eq!(stats.states_abandoned, 1);
    }

    #[test]
    fn test_exploration_stats_record_infeasible() {
        let mut stats = ExplorationStats::new();
        stats.record_infeasible();
        assert_eq!(stats.infeasible_states, 1);
    }

    #[test]
    fn test_exploration_stats_fork_ratio() {
        let mut stats = ExplorationStats::new();
        stats.record_branch(true);
        stats.record_branch(true);
        stats.record_branch(false);
        assert!((stats.fork_ratio() - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_exploration_stats_display() {
        let mut stats = ExplorationStats::new();
        stats.record_state(3);
        let s = stats.to_string();
        assert!(s.contains("Explored=1"));
    }

    #[test]
    fn test_exploration_stats_serialization() {
        let mut stats = ExplorationStats::new();
        stats.record_state(5);
        let json = serde_json::to_string(&stats).unwrap();
        let decoded: ExplorationStats = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.states_explored, 1);
    }
}
