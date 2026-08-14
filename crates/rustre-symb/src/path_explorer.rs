//! `path_explorer` — Path exploration strategies for symbolic execution.
//!
//! Provides DFS, BFS, and random/heuristic path traversal over the symbolic
//! state space, with built-in path-explosion mitigation:
//! - Merge identical symbolic states (state deduplication)
//! - Configurable depth limit
//! - Per-address loop bound enforcement
//! - Path count tracking and hard limits

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{SymExpr, SymbolicState};

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ExplorationError {
    #[error("path explosion: too many paths ({0})")]
    PathExplosion(usize),
    #[error("depth limit exceeded ({limit}) at pc {pc:#x}")]
    DepthLimitExceeded { limit: u32, pc: u64 },
    #[error("loop bound exceeded: address {addr:#x} visited {count} times")]
    LoopBoundExceeded { addr: u64, count: u32 },
    #[error("no paths remaining in the work queue")]
    ExhaustedQueue,
    #[error("exploration already complete")]
    AlreadyComplete,
}

// ─── ExplorationStrategy ──────────────────────────────────────────────────────

/// Which order to pick the next path from the work queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ExplorationStrategy {
    /// Depth-first search: always pick the most recently added path.
    #[default]
    Dfs,
    /// Breadth-first search: always pick the oldest path.
    Bfs,
    /// Random: pick a path using a simple PRNG (reproducible with a seed).
    Random { seed: u64 },
    /// Heuristic: prefer paths whose PC has been visited least often
    /// (coverage-guided).
    CoverageGuided,
    /// Interleave DFS within BFS rounds of fixed depth.
    InterleavedDfsBfs { bfs_round_depth: u32 },
}

impl fmt::Display for ExplorationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dfs => write!(f, "DFS"),
            Self::Bfs => write!(f, "BFS"),
            Self::Random { seed } => write!(f, "Random(seed={seed})"),
            Self::CoverageGuided => write!(f, "CoverageGuided"),
            Self::InterleavedDfsBfs { bfs_round_depth } => {
                write!(f, "InterleavedDfsBfs(round_depth={bfs_round_depth})")
            }
        }
    }
}

// ─── ExplorationConfig ────────────────────────────────────────────────────────

/// Configuration knobs for path exploration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationConfig {
    /// Maximum depth (number of state forks) before pruning a path.
    pub max_depth: u32,
    /// Maximum number of times any single address may appear in a path's
    /// execution history before the loop is considered infinite and pruned.
    pub loop_bound: u32,
    /// Hard limit on the total number of live paths in the queue.
    pub max_live_paths: usize,
    /// Hard limit on the total number of paths explored (including completed
    /// and pruned).
    pub max_total_paths: usize,
    /// Whether to merge states with identical path-condition fingerprints.
    pub merge_identical_states: bool,
    /// Whether to deduplicate paths by (pc, `path_cond_hash`) before enqueueing.
    pub dedup_paths: bool,
    /// Strategy to use.
    pub strategy: ExplorationStrategy,
}

impl Default for ExplorationConfig {
    fn default() -> Self {
        Self {
            max_depth: 128,
            loop_bound: 8,
            max_live_paths: 4096,
            max_total_paths: 65536,
            merge_identical_states: true,
            dedup_paths: true,
            strategy: ExplorationStrategy::Dfs,
        }
    }
}

impl ExplorationConfig {
    /// Create a config suitable for quick, shallow analysis.
    #[must_use]
    pub fn shallow() -> Self {
        Self {
            max_depth: 16,
            loop_bound: 2,
            max_live_paths: 256,
            max_total_paths: 2048,
            ..Default::default()
        }
    }

    /// Create a config for deep, exhaustive analysis (expensive).
    #[must_use]
    pub fn deep() -> Self {
        Self {
            max_depth: 512,
            loop_bound: 32,
            max_live_paths: 32768,
            max_total_paths: 524_288,
            ..Default::default()
        }
    }

    /// Set the strategy and return `self` for builder-style configuration.
    #[must_use]
    pub const fn with_strategy(mut self, strategy: ExplorationStrategy) -> Self {
        self.strategy = strategy;
        self
    }
}

// ─── PathState ────────────────────────────────────────────────────────────────

/// A single path in the exploration: holds a snapshot of the symbolic state
/// together with per-path bookkeeping.
#[derive(Debug, Clone)]
pub struct PathState {
    /// The symbolic execution state at this point.
    pub state: SymbolicState,
    /// Addresses visited along this path (for loop-bound enforcement).
    pub visit_counts: HashMap<u64, u32>,
    /// Ordinal identifier assigned by the explorer.
    pub path_id: u64,
    /// Whether this path has been marked as completed (reached a terminal).
    pub is_terminal: bool,
    /// Optional human-readable tag (e.g. "error path").
    pub tag: Option<String>,
}

impl PathState {
    /// Create a new `PathState` from an initial symbolic state.
    #[must_use]
    pub fn new(state: SymbolicState, path_id: u64) -> Self {
        let mut visit_counts = HashMap::new();
        visit_counts.insert(state.pc, 1);
        Self {
            state,
            visit_counts,
            path_id,
            is_terminal: false,
            tag: None,
        }
    }

    /// Record a visit to `addr` and return the new visit count.
    pub fn record_visit(&mut self, addr: u64) -> u32 {
        let count = self.visit_counts.entry(addr).or_insert(0);
        *count += 1;
        *count
    }

    /// Return the visit count for `addr`.
    #[must_use]
    pub fn visit_count(&self, addr: u64) -> u32 {
        self.visit_counts.get(&addr).copied().unwrap_or(0)
    }

    /// Return `true` if the path condition is satisfiable (lightweight check).
    #[must_use]
    pub fn is_feasible(&self) -> bool {
        self.state.is_satisfiable()
    }

    /// Compute a cheap fingerprint of (pc, `path_condition` length) for dedup.
    #[must_use]
    pub const fn fingerprint(&self) -> (u64, usize) {
        (self.state.pc, self.state.path_condition.len())
    }

    /// Fork this `PathState` into two children with opposite branch conditions.
    #[must_use]
    pub fn fork_on(&self, cond: SymExpr, next_id: u64) -> (Self, Self) {
        let (true_state, false_state) = self.state.fork_pair(cond);
        let mut true_path = Self {
            state: true_state,
            visit_counts: self.visit_counts.clone(),
            path_id: next_id,
            is_terminal: false,
            tag: self.tag.clone(),
        };
        let mut false_path = Self {
            state: false_state,
            visit_counts: self.visit_counts.clone(),
            path_id: next_id + 1,
            is_terminal: false,
            tag: self.tag.clone(),
        };
        true_path.record_visit(true_path.state.pc);
        false_path.record_visit(false_path.state.pc);
        (true_path, false_path)
    }
}

// ─── ExplorationStats ─────────────────────────────────────────────────────────

/// Cumulative statistics gathered during exploration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExplorationStats {
    /// Total paths enqueued (including those later pruned).
    pub paths_enqueued: u64,
    /// Total paths completed (reached a terminal instruction).
    pub paths_completed: u64,
    /// Total paths pruned by depth / loop / explosion mitigations.
    pub paths_pruned: u64,
    /// Total paths merged due to identical state detection.
    pub paths_merged: u64,
    /// Total paths discarded as infeasible (unsatisfiable path condition).
    pub paths_infeasible: u64,
    /// Maximum depth reached across all explored paths.
    pub max_depth_reached: u32,
    /// Total symbolic instructions stepped (aggregated across all paths).
    pub total_steps: u64,
    /// Number of distinct PC values reached.
    pub distinct_pcs: usize,
}

impl ExplorationStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one enqueued path.
    pub const fn record_enqueue(&mut self) {
        self.paths_enqueued += 1;
    }

    /// Record one completed path.
    pub fn record_complete(&mut self, depth: u32) {
        self.paths_completed += 1;
        self.max_depth_reached = self.max_depth_reached.max(depth);
    }

    /// Record one pruned path.
    pub const fn record_prune(&mut self) {
        self.paths_pruned += 1;
    }

    /// Record a merged path.
    pub const fn record_merge(&mut self) {
        self.paths_merged += 1;
    }

    /// Record an infeasible path.
    pub const fn record_infeasible(&mut self) {
        self.paths_infeasible += 1;
    }

    /// Record `n` symbolic steps.
    pub const fn record_steps(&mut self, n: u64) {
        self.total_steps += n;
    }

    /// Return the total number of live + completed + pruned paths.
    #[must_use]
    pub const fn total_paths(&self) -> u64 {
        self.paths_enqueued
    }
}

impl fmt::Display for ExplorationStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExplorationStats {{ enqueued={}, completed={}, pruned={}, merged={}, \
             infeasible={}, max_depth={}, steps={} }}",
            self.paths_enqueued,
            self.paths_completed,
            self.paths_pruned,
            self.paths_merged,
            self.paths_infeasible,
            self.max_depth_reached,
            self.total_steps,
        )
    }
}

// ─── PathQueue ────────────────────────────────────────────────────────────────

/// Internal work queue that implements the chosen [`ExplorationStrategy`].
#[derive(Debug)]
struct PathQueue {
    /// DFS / Random storage (stack semantics).
    stack: Vec<PathState>,
    /// BFS storage (queue semantics).
    deque: VecDeque<PathState>,
    /// Strategy in effect.
    strategy: ExplorationStrategy,
    /// Simple xorshift PRNG state (for Random strategy).
    rng: u64,
    /// Track of fingerprints already in the queue (for dedup).
    fingerprints: HashSet<(u64, usize)>,
    /// Coverage counts: pc → number of times a path started at that pc.
    coverage: HashMap<u64, u64>,
}

impl PathQueue {
    fn new(strategy: ExplorationStrategy) -> Self {
        let seed = match strategy {
            ExplorationStrategy::Random { seed } => seed,
            _ => 0x517c_c1b7_2722_0a95_u64,
        };
        Self {
            stack: Vec::new(),
            deque: VecDeque::new(),
            strategy,
            rng: seed,
            fingerprints: HashSet::new(),
            coverage: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        match self.strategy {
            ExplorationStrategy::Bfs
            | ExplorationStrategy::CoverageGuided
            | ExplorationStrategy::InterleavedDfsBfs { .. } => self.deque.len(),
            _ => self.stack.len(),
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&mut self, path: PathState, dedup: bool) -> bool {
        if dedup {
            let fp = path.fingerprint();
            if !self.fingerprints.insert(fp) {
                return false; // duplicate
            }
        }
        *self.coverage.entry(path.state.pc).or_insert(0) += 1;
        match self.strategy {
            ExplorationStrategy::Bfs
            | ExplorationStrategy::CoverageGuided
            | ExplorationStrategy::InterleavedDfsBfs { .. } => {
                self.deque.push_back(path);
            }
            _ => {
                self.stack.push(path);
            }
        }
        true
    }

    fn pop(&mut self) -> Option<PathState> {
        match self.strategy {
            ExplorationStrategy::Dfs => self.stack.pop(),
            ExplorationStrategy::Bfs => self.deque.pop_front(),
            ExplorationStrategy::Random { .. } => {
                if self.stack.is_empty() {
                    return None;
                }
                let idx = usize::try_from(self.xorshift()).unwrap_or(usize::MAX) % self.stack.len();
                Some(self.stack.swap_remove(idx))
            }
            ExplorationStrategy::CoverageGuided => {
                // Pick the path whose PC has the lowest visit count in coverage.
                if self.deque.is_empty() {
                    return None;
                }
                let best_idx = self
                    .deque
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, p)| {
                        self.coverage.get(&p.state.pc).copied().unwrap_or(u64::MAX)
                    })
                    .map_or(0, |(i, _)| i);
                self.deque.remove(best_idx)
            }
            ExplorationStrategy::InterleavedDfsBfs { bfs_round_depth } => {
                // Pop front when depth ≤ bfs_round_depth, else pop back.
                let front_depth = self.deque.front().map_or(0, |p| p.state.depth);
                if front_depth <= bfs_round_depth {
                    self.deque.pop_front()
                } else {
                    self.deque.pop_back()
                }
            }
        }
    }

    const fn xorshift(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }
}

// ─── MergeKey ─────────────────────────────────────────────────────────────────

/// Key used for state merging: two states with the same key are candidates for
/// structural merging via [`SymbolicState::merge`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MergeKey {
    pc: u64,
    depth: u32,
}

impl MergeKey {
    const fn from_state(state: &SymbolicState) -> Self {
        Self {
            pc: state.pc,
            depth: state.depth,
        }
    }
}

// ─── PathExplorer ─────────────────────────────────────────────────────────────

/// High-level path explorer.
///
/// Feed initial states with [`PathExplorer::push_initial`], then call
/// [`PathExplorer::next_path`] in a loop to retrieve paths one by one.
/// After each step, push successor states back with [`PathExplorer::push`].
///
/// ```no_run
/// use rustre_symb::{SymbolicState, path_explorer::{PathExplorer, ExplorationConfig}};
///
/// let config = ExplorationConfig::default();
/// let mut explorer = PathExplorer::new(config);
/// let init = SymbolicState::new();
/// explorer.push_initial(init);
///
/// while let Ok(mut path) = explorer.next_path() {
///     // ... step the symbolic engine ...
///     // push successors back:
///     // explorer.push(successor_path_state)?;
/// }
/// ```
pub struct PathExplorer {
    config: ExplorationConfig,
    queue: PathQueue,
    stats: ExplorationStats,
    /// States awaiting merge: `MergeKey` → first candidate.
    merge_pending: HashMap<MergeKey, PathState>,
    /// Monotonically increasing path-id counter.
    next_path_id: u64,
    /// Set of (pc, depth) pairs seen; used for dedup across iterations.
    seen: HashSet<(u64, u32)>,
    /// Whether the explorer has been fully drained.
    complete: bool,
}

impl PathExplorer {
    /// Create a new explorer with the given configuration.
    #[must_use]
    pub fn new(config: ExplorationConfig) -> Self {
        let strategy = config.strategy;
        Self {
            config,
            queue: PathQueue::new(strategy),
            stats: ExplorationStats::new(),
            merge_pending: HashMap::new(),
            next_path_id: 0,
            seen: HashSet::new(),
            complete: false,
        }
    }

    /// Push an initial state into the explorer.
    pub fn push_initial(&mut self, state: SymbolicState) {
        let id = self.alloc_id();
        let path = PathState::new(state, id);
        self.enqueue(path);
    }

    /// Enqueue a `PathState` (successor of a previously explored path).
    ///
    /// Returns `Ok(true)` if enqueued, `Ok(false)` if deduplicated/dropped,
    /// or an error if limits are exceeded.
    ///
    /// # Errors
    ///
    /// Returns [`ExplorationError::PathExplosion`] if the live-path or total-path
    /// limits would be exceeded.
    pub fn push(&mut self, path: PathState) -> Result<bool, ExplorationError> {
        // Depth limit check.
        if path.state.depth > self.config.max_depth {
            self.stats.record_prune();
            return Ok(false);
        }
        // Infeasibility check.
        if !path.is_feasible() {
            self.stats.record_infeasible();
            return Ok(false);
        }
        // Live-path limit.
        if self.queue.len() >= self.config.max_live_paths {
            return Err(ExplorationError::PathExplosion(self.queue.len()));
        }
        // Total-path limit.
        if self.stats.paths_enqueued >= self.config.max_total_paths as u64 {
            return Err(ExplorationError::PathExplosion(
                usize::try_from(self.stats.paths_enqueued).unwrap_or(usize::MAX),
            ));
        }
        // Optionally merge with a pending state at the same (pc, depth).
        // Clone here so `path` is still available if `try_merge` returns
        // `None` (the merge attempt consumes its argument).
        if self.config.merge_identical_states {
            let path_for_merge = path.clone();
            if let Some(existing) = self.try_merge(path_for_merge) {
                self.stats.record_merge();
                // Re-enqueue the merged result.
                self.enqueue(existing);
                return Ok(true);
            }
        }
        Ok(self.enqueue(path))
    }

    /// Retrieve the next path to explore.
    ///
    /// # Errors
    ///
    /// Returns [`ExplorationError::AlreadyComplete`] if the explorer has been
    /// marked complete, or [`ExplorationError::ExhaustedQueue`] if no more paths
    /// remain to be explored.
    pub fn next_path(&mut self) -> Result<PathState, ExplorationError> {
        if self.complete {
            return Err(ExplorationError::AlreadyComplete);
        }
        // Drain the merge-pending table into the queue first.
        let pending: Vec<PathState> = self.merge_pending.drain().map(|(_, v)| v).collect();
        for p in pending {
            self.enqueue(p);
        }
        self.queue.pop().ok_or(ExplorationError::ExhaustedQueue)
    }

    /// Check whether the loop-bound has been exceeded for `addr` in `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ExplorationError::LoopBoundExceeded`] if `addr` has been visited
    /// more than [`ExplorationConfig::loop_bound`] times along `path`.
    pub fn check_loop_bound(&self, path: &PathState, addr: u64) -> Result<(), ExplorationError> {
        let count = path.visit_count(addr);
        if count > self.config.loop_bound {
            Err(ExplorationError::LoopBoundExceeded { addr, count })
        } else {
            Ok(())
        }
    }

    /// Mark a path as completed (reached a terminal).
    pub fn complete_path(&mut self, path: &PathState) {
        self.stats.record_complete(path.state.depth);
    }

    /// Return a reference to the current exploration statistics.
    #[must_use]
    pub const fn stats(&self) -> &ExplorationStats {
        &self.stats
    }

    /// Return a mutable reference to the current exploration statistics.
    pub const fn stats_mut(&mut self) -> &mut ExplorationStats {
        &mut self.stats
    }

    /// Return the number of paths currently in the queue.
    #[must_use]
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Return `true` if there are no more paths to explore.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.merge_pending.is_empty()
    }

    /// Return the configuration.
    #[must_use]
    pub const fn config(&self) -> &ExplorationConfig {
        &self.config
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    const fn alloc_id(&mut self) -> u64 {
        let id = self.next_path_id;
        self.next_path_id += 1;
        id
    }

    fn enqueue(&mut self, path: PathState) -> bool {
        self.stats.record_enqueue();
        self.seen.insert((path.state.pc, path.state.depth));
        self.queue.push(path, self.config.dedup_paths)
    }

    /// Try to merge `path` with a pending state at the same key.
    /// Returns the merged state if successful, or re-inserts `path` as pending
    /// and returns `None`.
    fn try_merge(&mut self, path: PathState) -> Option<PathState> {
        let key = MergeKey::from_state(&path.state);
        if let Some(existing) = self.merge_pending.remove(&key) {
            // Merge the two states.
            let cond = existing
                .state
                .path_condition
                .last()
                .cloned()
                .unwrap_or(SymExpr::ConstBool(true));
            let merged_state = SymbolicState::merge(existing.state, path.state, &cond);
            let merged_id = self.alloc_id();
            Some(PathState {
                state: merged_state,
                visit_counts: HashMap::new(),
                path_id: merged_id,
                is_terminal: false,
                tag: None,
            })
        } else {
            self.merge_pending.insert(key, path);
            None
        }
    }
}

// ─── PathExplorerBuilder ──────────────────────────────────────────────────────

/// Builder for [`PathExplorer`].
#[derive(Debug, Default)]
pub struct PathExplorerBuilder {
    config: ExplorationConfig,
    initial_states: Vec<SymbolicState>,
}

impl PathExplorerBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_config(mut self, config: ExplorationConfig) -> Self {
        self.config = config;
        self
    }

    #[must_use]
    pub const fn with_strategy(mut self, strategy: ExplorationStrategy) -> Self {
        self.config.strategy = strategy;
        self
    }

    #[must_use]
    pub const fn max_depth(mut self, d: u32) -> Self {
        self.config.max_depth = d;
        self
    }

    #[must_use]
    pub const fn loop_bound(mut self, b: u32) -> Self {
        self.config.loop_bound = b;
        self
    }

    #[must_use]
    pub const fn max_live_paths(mut self, n: usize) -> Self {
        self.config.max_live_paths = n;
        self
    }

    #[must_use]
    pub fn add_initial_state(mut self, state: SymbolicState) -> Self {
        self.initial_states.push(state);
        self
    }

    #[must_use]
    pub fn build(self) -> PathExplorer {
        let mut explorer = PathExplorer::new(self.config);
        for state in self.initial_states {
            explorer.push_initial(state);
        }
        explorer
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state_at(pc: u64) -> SymbolicState {
        let mut s = SymbolicState::new();
        s.pc = pc;
        s
    }

    #[test]
    fn test_explorer_basic_dfs() {
        let config = ExplorationConfig {
            strategy: ExplorationStrategy::Dfs,
            dedup_paths: false,
            ..Default::default()
        };
        let mut explorer = PathExplorer::new(config);
        explorer.push_initial(make_state_at(0x1000));
        explorer.push_initial(make_state_at(0x2000));

        let p1 = explorer.next_path().unwrap();
        // DFS pops from end — last pushed = 0x2000
        assert_eq!(p1.state.pc, 0x2000);
        let p2 = explorer.next_path().unwrap();
        assert_eq!(p2.state.pc, 0x1000);
        assert!(explorer.next_path().is_err());
    }

    #[test]
    fn test_explorer_basic_bfs() {
        let config = ExplorationConfig {
            strategy: ExplorationStrategy::Bfs,
            dedup_paths: false,
            ..Default::default()
        };
        let mut explorer = PathExplorer::new(config);
        explorer.push_initial(make_state_at(0x1000));
        explorer.push_initial(make_state_at(0x2000));

        let p1 = explorer.next_path().unwrap();
        // BFS pops from front — first pushed = 0x1000
        assert_eq!(p1.state.pc, 0x1000);
        let p2 = explorer.next_path().unwrap();
        assert_eq!(p2.state.pc, 0x2000);
    }

    #[test]
    fn test_depth_limit_prunes() {
        let config = ExplorationConfig {
            max_depth: 2,
            dedup_paths: false,
            ..Default::default()
        };
        let mut explorer = PathExplorer::new(config);
        let mut s = make_state_at(0x1000);
        s.depth = 3; // already over limit
        let path = PathState::new(s, 0);
        let ok = explorer.push(path).unwrap();
        assert!(!ok, "path over depth limit should be rejected");
        assert_eq!(explorer.stats().paths_pruned, 1);
    }

    #[test]
    fn test_infeasible_path_dropped() {
        let config = ExplorationConfig {
            dedup_paths: false,
            ..Default::default()
        };
        let mut explorer = PathExplorer::new(config);
        let mut s = make_state_at(0x1000);
        // Make it infeasible.
        s.path_condition.push(SymExpr::ConstBool(false));
        let path = PathState::new(s, 0);
        let ok = explorer.push(path).unwrap();
        assert!(!ok);
        assert_eq!(explorer.stats().paths_infeasible, 1);
    }

    #[test]
    fn test_loop_bound_check() {
        let config = ExplorationConfig {
            loop_bound: 3,
            ..Default::default()
        };
        let explorer = PathExplorer::new(config);
        let mut path = PathState::new(make_state_at(0x1000), 0);
        // Simulate visiting 0x1000 four times.
        for _ in 0..4 {
            path.record_visit(0x1000);
        }
        // Now visit count is 5 (initial 1 in new + 4 here).
        assert!(explorer.check_loop_bound(&path, 0x1000).is_err());
    }

    #[test]
    fn test_explorer_builder() {
        let explorer = PathExplorerBuilder::new()
            .max_depth(64)
            .loop_bound(4)
            .with_strategy(ExplorationStrategy::Bfs)
            .add_initial_state(make_state_at(0xDEAD))
            .build();
        assert_eq!(explorer.config().max_depth, 64);
        assert_eq!(explorer.config().loop_bound, 4);
        assert_eq!(explorer.queue_len(), 1);
    }

    #[test]
    fn test_path_state_fork_on() {
        let state = make_state_at(0x1000);
        let path = PathState::new(state, 0);
        let (t_path, f_path) = path.fork_on(SymExpr::ConstBool(true), 1);
        assert_eq!(t_path.path_id, 1);
        assert_eq!(f_path.path_id, 2);
        // true branch last condition is ConstBool(true).
        assert_eq!(
            t_path.state.path_condition.last(),
            Some(&SymExpr::ConstBool(true))
        );
        // false branch last condition is BoolNot(ConstBool(true)).
        assert!(matches!(
            f_path.state.path_condition.last(),
            Some(SymExpr::BoolNot(_))
        ));
    }

    #[test]
    fn test_exploration_stats_display() {
        let stats = ExplorationStats::default();
        let s = stats.to_string();
        assert!(s.contains("ExplorationStats"));
    }

    #[test]
    fn test_complete_and_stats() {
        let config = ExplorationConfig {
            dedup_paths: false,
            ..Default::default()
        };
        let mut explorer = PathExplorer::new(config);
        explorer.push_initial(make_state_at(0x100));
        let path = explorer.next_path().unwrap();
        explorer.complete_path(&path);
        assert_eq!(explorer.stats().paths_completed, 1);
    }

    #[test]
    fn test_exploration_config_shallow() {
        let c = ExplorationConfig::shallow();
        assert_eq!(c.max_depth, 16);
        assert_eq!(c.loop_bound, 2);
    }

    #[test]
    fn test_exploration_config_deep() {
        let c = ExplorationConfig::deep();
        assert_eq!(c.max_depth, 512);
    }

    #[test]
    fn test_exploration_strategy_display() {
        assert_eq!(ExplorationStrategy::Dfs.to_string(), "DFS");
        assert_eq!(ExplorationStrategy::Bfs.to_string(), "BFS");
        assert!(
            ExplorationStrategy::Random { seed: 42 }
                .to_string()
                .contains("seed=42")
        );
    }

    #[test]
    fn test_path_state_visit_count() {
        let state = make_state_at(0x500);
        let mut path = PathState::new(state, 0);
        assert_eq!(path.visit_count(0x500), 1); // initial from new()
        path.record_visit(0x500);
        assert_eq!(path.visit_count(0x500), 2);
        assert_eq!(path.visit_count(0x600), 0);
    }

    #[test]
    fn test_is_empty_after_drain() {
        let mut explorer = PathExplorer::new(ExplorationConfig::default());
        explorer.push_initial(make_state_at(0x10));
        assert!(!explorer.is_empty());
        let _p = explorer.next_path().unwrap();
        assert!(explorer.is_empty());
    }
}
