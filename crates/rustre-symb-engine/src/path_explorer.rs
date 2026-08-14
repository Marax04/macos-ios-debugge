//! Symbolic path exploration: BFS/DFS over execution paths with configurable
//! path limits and branch condition tracking.

use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── ExplorationStrategy ─────────────────────────────────────────────────────

/// Which search order to use when exploring paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExplorationStrategy {
    /// Breadth-first search: explore all paths to depth N before N+1.
    Bfs,
    /// Depth-first search: follow one path as deep as possible first.
    Dfs,
    /// Interleaved: alternate between BFS and DFS on successive steps.
    Interleaved,
    /// Priority-driven: prefer paths with a lower cost (requires cost fn).
    Priority,
}

impl fmt::Display for ExplorationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bfs => write!(f, "BFS"),
            Self::Dfs => write!(f, "DFS"),
            Self::Interleaved => write!(f, "Interleaved"),
            Self::Priority => write!(f, "Priority"),
        }
    }
}

// ─── BranchCondition ─────────────────────────────────────────────────────────

/// A symbolic boolean constraint added at a branch point.
///
/// In a real symbolic executor this would be an SMT expression.  Here it is
/// represented as a printable string that the caller constructs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BranchCondition {
    /// The branch address (program counter of the conditional jump).
    pub address: u64,
    /// `true` = taken branch, `false` = not-taken branch.
    pub taken: bool,
    /// Human-readable or serialised SMT constraint string.
    pub constraint: String,
}

impl BranchCondition {
    /// Create a new `BranchCondition`.
    #[must_use]
    pub fn new(address: u64, taken: bool, constraint: impl Into<String>) -> Self {
        Self {
            address,
            taken,
            constraint: constraint.into(),
        }
    }

    /// Negate the condition (flip `taken` and negate the constraint string).
    #[must_use]
    pub fn negate(&self) -> Self {
        Self {
            address: self.address,
            taken: !self.taken,
            constraint: format!("NOT({})", self.constraint),
        }
    }
}

impl fmt::Display for BranchCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let taken = if self.taken { "taken" } else { "not-taken" };
        write!(f, "@{:#x}[{taken}]: {}", self.address, self.constraint)
    }
}

// ─── PathState ────────────────────────────────────────────────────────────────

/// The state of one symbolic execution path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathState {
    /// Unique identifier for this path (assigned by the explorer).
    pub id: u64,
    /// Current program counter.
    pub pc: u64,
    /// Path conditions accumulated so far (conjunction of `BranchCondition`s).
    pub conditions: Vec<BranchCondition>,
    /// Exploration depth (number of branches taken on this path).
    pub depth: u32,
    /// Estimated cost (lower = prefer in Priority mode).
    pub cost: u64,
    /// Whether this path has reached a terminal point.
    pub terminated: bool,
    /// Optional reason for termination.
    pub termination_reason: Option<String>,
    /// Opaque symbolic state payload (left to the caller).
    pub payload: Vec<u8>,
}

impl PathState {
    /// Create a new path state starting at `pc`.
    #[must_use]
    pub const fn new(id: u64, pc: u64) -> Self {
        Self {
            id,
            pc,
            conditions: Vec::new(),
            depth: 0,
            cost: 0,
            terminated: false,
            termination_reason: None,
            payload: Vec::new(),
        }
    }

    /// Fork this path into a taken and not-taken branch.
    ///
    /// Returns `(taken_state, not_taken_state)` with new IDs.
    #[must_use]
    pub fn fork(&self, next_id_taken: u64, next_id_not_taken: u64, cond: &BranchCondition) -> (Self, Self) {
        let mut taken = self.clone();
        taken.id = next_id_taken;
        taken.depth = self.depth.saturating_add(1);
        taken.conditions.push(cond.clone());

        let mut not_taken = self.clone();
        not_taken.id = next_id_not_taken;
        not_taken.depth = self.depth.saturating_add(1);
        not_taken.conditions.push(cond.negate());

        (taken, not_taken)
    }

    /// Terminate this path with a reason string.
    pub fn terminate(&mut self, reason: impl Into<String>) {
        self.terminated = true;
        self.termination_reason = Some(reason.into());
    }

    /// Return a condensed "fingerprint" for loop detection: `conditions` sorted
    /// and hashed into a `BTreeSet`.  Two paths with the same fingerprint
    /// would follow the same set of branches.
    #[must_use]
    pub fn condition_fingerprint(&self) -> BTreeSet<(u64, bool)> {
        self.conditions
            .iter()
            .map(|c| (c.address, c.taken))
            .collect()
    }
}

impl fmt::Display for PathState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Path[{}] pc={:#x} depth={} conds={} terminated={}",
            self.id,
            self.pc,
            self.depth,
            self.conditions.len(),
            self.terminated
        )
    }
}

// ─── ExplorationLimits ────────────────────────────────────────────────────────

/// Hard limits for the path explorer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorationLimits {
    /// Maximum number of live (non-terminated) paths at any time.
    pub max_live_paths: usize,
    /// Maximum branch depth per path before it is force-terminated.
    pub max_depth: u32,
    /// Maximum total number of forks performed across all paths.
    pub max_total_forks: u64,
    /// Maximum number of paths to return in a single `step_n` call.
    pub max_returned_per_step: usize,
}

impl Default for ExplorationLimits {
    fn default() -> Self {
        Self {
            max_live_paths: 256,
            max_depth: 64,
            max_total_forks: 1_000_000,
            max_returned_per_step: 64,
        }
    }
}

// ─── ExplorationStats ─────────────────────────────────────────────────────────

/// Statistics gathered by the `PathExplorer`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExplorationStats {
    /// Total paths ever created (including already terminated).
    pub total_paths_created: u64,
    /// Total forks performed.
    pub total_forks: u64,
    /// Paths terminated because `max_depth` was hit.
    pub depth_limit_terminations: u64,
    /// Paths terminated because the live-path pool was full.
    pub overflow_terminations: u64,
    /// Paths explicitly terminated by the caller.
    pub explicit_terminations: u64,
    /// Currently live (non-terminated) path count.
    pub live_path_count: usize,
}

// ─── PathExplorer ─────────────────────────────────────────────────────────────

/// Symbolic path explorer supporting BFS, DFS, and priority-guided strategies.
///
/// The explorer maintains a worklist of `PathState`s and a pool of completed
/// (terminated) paths.  At each step the caller provides a callback that
/// decides whether to fork (and with what constraint) or terminate a path.
#[derive(Debug)]
pub struct PathExplorer {
    /// Active exploration strategy.
    pub strategy: ExplorationStrategy,
    /// Hard limits.
    pub limits: ExplorationLimits,
    /// Monotonically increasing path ID counter.
    next_id: u64,
    /// BFS/priority worklist.
    bfs_queue: VecDeque<PathState>,
    /// DFS worklist (used as a stack).
    dfs_stack: Vec<PathState>,
    /// Terminated paths.
    terminated: Vec<PathState>,
    /// Aggregate statistics.
    pub stats: ExplorationStats,
    /// Toggle for interleaved mode.
    interleaved_toggle: bool,
}

impl PathExplorer {
    /// Create a new `PathExplorer` with the given strategy and limits.
    #[must_use]
    pub fn new(strategy: ExplorationStrategy, limits: ExplorationLimits) -> Self {
        Self {
            strategy,
            limits,
            next_id: 0,
            bfs_queue: VecDeque::new(),
            dfs_stack: Vec::new(),
            terminated: Vec::new(),
            stats: ExplorationStats::default(),
            interleaved_toggle: false,
        }
    }

    /// Seed the explorer with an initial path starting at `pc`.
    pub fn seed(&mut self, pc: u64) -> u64 {
        let id = self.alloc_id();
        let state = PathState::new(id, pc);
        self.push_live(state);
        self.stats.total_paths_created += 1;
        id
    }

    /// Return the number of currently live paths.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.bfs_queue.len() + self.dfs_stack.len()
    }

    /// Return `true` if no live paths remain.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.live_count() == 0
    }

    /// Pop the next live path according to the active strategy.
    pub fn pop_next(&mut self) -> Option<PathState> {
        if self.strategy == ExplorationStrategy::Interleaved {
            // Alternate which structure is preferred, then fall back to the
            // other one if the preferred is empty. The toggle must only express
            // a PREFERENCE: letting it gate reachability meant that after an
            // odd number of pushes it pointed at the empty structure and
            // `pop_next` reported exhaustion while live paths were still queued.
            let prefer_bfs = self.interleaved_toggle;
            self.interleaved_toggle = !self.interleaved_toggle;
            return if prefer_bfs {
                self.bfs_queue.pop_front().or_else(|| self.dfs_stack.pop())
            } else {
                self.dfs_stack.pop().or_else(|| self.bfs_queue.pop_front())
            };
        }
        match self.effective_strategy() {
            ExplorationStrategy::Bfs | ExplorationStrategy::Priority => {
                self.bfs_queue.pop_front()
            }
            ExplorationStrategy::Dfs => self.dfs_stack.pop(),
            ExplorationStrategy::Interleaved => unreachable!(),
        }
    }

    /// Fork `state` into two children.  Both children inherit `state`'s
    /// conditions; the taken child gets `cond`, the not-taken gets `NOT(cond)`.
    ///
    /// Returns `(taken_id, not_taken_id)`.  May force-terminate one or both
    /// children if limits are exceeded.
    pub fn fork(&mut self, state: &PathState, cond: &BranchCondition) -> (u64, u64) {
        let id_taken = self.alloc_id();
        let id_not_taken = self.alloc_id();
        let (mut taken, mut not_taken) = state.fork(id_taken, id_not_taken, cond);

        self.stats.total_forks += 1;
        self.stats.total_paths_created += 2;

        // Depth limit check.
        if taken.depth >= self.limits.max_depth {
            taken.terminate("depth_limit");
            self.stats.depth_limit_terminations += 1;
            self.push_terminated(taken);

            not_taken.terminate("depth_limit");
            self.stats.depth_limit_terminations += 1;
            self.push_terminated(not_taken);
            return (id_taken, id_not_taken);
        }

        // Live path pool overflow.
        let live = self.live_count();
        if live + 2 > self.limits.max_live_paths {
            taken.terminate("path_overflow");
            self.stats.overflow_terminations += 1;
            self.push_terminated(taken);

            not_taken.terminate("path_overflow");
            self.stats.overflow_terminations += 1;
            self.push_terminated(not_taken);
        } else {
            self.push_live(taken);
            self.push_live(not_taken);
        }

        (id_taken, id_not_taken)
    }

    /// Explicitly terminate `state` and move it to the completed pool.
    pub fn terminate(&mut self, mut state: PathState, reason: impl Into<String>) {
        state.terminate(reason);
        self.stats.explicit_terminations += 1;
        self.push_terminated(state);
    }

    /// Push a terminated state back (e.g. after processing by caller).
    pub fn push_terminated(&mut self, state: PathState) {
        self.terminated.push(state);
    }

    /// Return all terminated paths.
    #[must_use]
    pub fn terminated_paths(&self) -> &[PathState] {
        &self.terminated
    }

    /// Drain terminated paths and return them.
    pub fn drain_terminated(&mut self) -> Vec<PathState> {
        std::mem::take(&mut self.terminated)
    }

    /// Update `stats.live_path_count` to the current live count.
    pub fn refresh_stats(&mut self) {
        self.stats.live_path_count = self.live_count();
    }

    /// Run a batch step: pop up to `n` paths, call `step_fn` for each, and
    /// re-enqueue or terminate based on the result.
    ///
    /// `step_fn` receives a mutable path reference.  If it sets
    /// `state.terminated = true`, the state is moved to the terminated pool.
    /// Otherwise it is re-enqueued as a live path.
    ///
    /// Returns the number of paths processed.
    pub fn step_n<F>(&mut self, n: usize, mut step_fn: F) -> usize
    where
        F: FnMut(&mut PathState, &mut Self) -> StepAction,
    {
        let count = n.min(self.limits.max_returned_per_step);
        let mut processed = 0;
        let mut to_process: Vec<PathState> = Vec::with_capacity(count);

        for _ in 0..count {
            match self.pop_next() {
                Some(s) => to_process.push(s),
                None => break,
            }
        }

        // Temporarily take `self` apart so we can pass `&mut self` to step_fn
        // while also holding `state`.  We do this by processing outside the
        // loop and re-inserting after.
        for mut state in to_process {
            let action = step_fn(&mut state, self);
            match action {
                StepAction::Continue => {
                    if state.terminated {
                        self.push_terminated(state);
                    } else {
                        self.push_live(state);
                    }
                }
                StepAction::Terminate(reason) => {
                    state.terminate(reason);
                    self.stats.explicit_terminations += 1;
                    self.push_terminated(state);
                }
                StepAction::Fork(cond) => {
                    let _ = self.fork(&state, &cond);
                    // The original state is discarded; its children are enqueued.
                }
                StepAction::Requeue => {
                    self.push_live(state);
                }
            }
            processed += 1;
        }
        self.refresh_stats();
        processed
    }

    // ── private ──────────────────────────────────────────────────────────────

    const fn alloc_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    const fn effective_strategy(&self) -> ExplorationStrategy {
        match self.strategy {
            ExplorationStrategy::Interleaved => {
                if self.interleaved_toggle {
                    ExplorationStrategy::Bfs
                } else {
                    ExplorationStrategy::Dfs
                }
            }
            s => s,
        }
    }

    fn push_live(&mut self, state: PathState) {
        match self.effective_strategy() {
            ExplorationStrategy::Bfs | ExplorationStrategy::Priority => {
                // Priority: insert in cost order (ascending).
                if self.strategy == ExplorationStrategy::Priority {
                    let pos = self.bfs_queue.partition_point(|s| s.cost <= state.cost);
                    self.bfs_queue.insert(pos, state);
                } else {
                    self.bfs_queue.push_back(state);
                }
            }
            ExplorationStrategy::Dfs => self.dfs_stack.push(state),
            ExplorationStrategy::Interleaved => {
                // Alternate.
                if self.interleaved_toggle {
                    self.bfs_queue.push_back(state);
                } else {
                    self.dfs_stack.push(state);
                }
                // Toggle is flipped after each push_live call when strategy is Interleaved.
            }
        }
        // Toggle interleaved flag.
        if self.strategy == ExplorationStrategy::Interleaved {
            self.interleaved_toggle = !self.interleaved_toggle;
        }
    }
}

/// Action returned by the step function in `step_n`.
pub enum StepAction {
    /// Continue executing this path; re-enqueue it.
    Continue,
    /// Terminate the path with a reason string.
    Terminate(String),
    /// Fork the path on the given condition.
    Fork(BranchCondition),
    /// Re-enqueue the path without modification.
    Requeue,
}

// ─── path_limit_reached helper ────────────────────────────────────────────────

/// Return `true` if `state.depth` has reached or exceeded `limit`.
#[must_use]
pub const fn path_limit_reached(state: &PathState, limit: u32) -> bool {
    state.depth >= limit
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cond(addr: u64, taken: bool) -> BranchCondition {
        BranchCondition::new(addr, taken, format!("cond@{addr:#x}"))
    }

    #[test]
    fn test_seed_creates_live_path() {
        let mut explorer = PathExplorer::new(
            ExplorationStrategy::Bfs,
            ExplorationLimits::default(),
        );
        explorer.seed(0x1000);
        assert_eq!(explorer.live_count(), 1);
    }

    #[test]
    fn test_fork_creates_two_children() {
        let mut explorer = PathExplorer::new(
            ExplorationStrategy::Bfs,
            ExplorationLimits::default(),
        );
        let _root_id = explorer.seed(0x1000);
        let root = explorer.pop_next().unwrap();
        explorer.fork(&root, &make_cond(0x1000, true));
        assert_eq!(explorer.live_count(), 2);
    }

    #[test]
    fn test_dfs_pops_last_pushed() {
        let mut explorer = PathExplorer::new(
            ExplorationStrategy::Dfs,
            ExplorationLimits::default(),
        );
        explorer.seed(0x100);
        explorer.seed(0x200);
        // DFS pops the last pushed first.
        let p = explorer.pop_next().unwrap();
        assert_eq!(p.pc, 0x200);
    }

    #[test]
    fn test_bfs_pops_first_pushed() {
        let mut explorer = PathExplorer::new(
            ExplorationStrategy::Bfs,
            ExplorationLimits::default(),
        );
        explorer.seed(0x100);
        explorer.seed(0x200);
        let p = explorer.pop_next().unwrap();
        assert_eq!(p.pc, 0x100);
    }

    #[test]
    fn test_depth_limit_terminates_children() {
        let limits = ExplorationLimits {
            max_depth: 2,
            ..Default::default()
        };
        let mut explorer = PathExplorer::new(ExplorationStrategy::Bfs, limits);
        explorer.seed(0x0);
        // Pop and fork repeatedly to hit the depth limit.
        for _ in 0..3 {
            if let Some(s) = explorer.pop_next() {
                explorer.fork(&s, &make_cond(0x0, true));
            }
        }
        // Some paths should be terminated due to depth limit.
        assert!(!explorer.terminated_paths().is_empty());
    }

    #[test]
    fn test_path_fork_conditions() {
        let s = PathState::new(1, 0x500);
        let (taken, not_taken) = s.fork(2, 3, &make_cond(0x500, true));
        assert!(taken.conditions.last().unwrap().taken);
        assert!(!not_taken.conditions.last().unwrap().taken);
    }

    #[test]
    fn test_condition_negate() {
        let c = make_cond(0x1234, true);
        let neg = c.negate();
        assert!(!neg.taken);
        assert!(neg.constraint.starts_with("NOT("));
    }

    #[test]
    fn test_path_limit_reached() {
        let mut s = PathState::new(1, 0);
        s.depth = 10;
        assert!(path_limit_reached(&s, 10));
        assert!(!path_limit_reached(&s, 11));
    }

    #[test]
    fn test_exhausted_after_drain() {
        let mut explorer = PathExplorer::new(
            ExplorationStrategy::Bfs,
            ExplorationLimits::default(),
        );
        explorer.seed(0x0);
        let s = explorer.pop_next().unwrap();
        explorer.terminate(s, "done");
        assert!(explorer.is_exhausted());
    }

    #[test]
    fn test_step_n_terminates_via_action() {
        let mut explorer = PathExplorer::new(
            ExplorationStrategy::Bfs,
            ExplorationLimits::default(),
        );
        explorer.seed(0x0);
        explorer.step_n(1, |_state, _exp| {
            StepAction::Terminate("test".to_owned())
        });
        assert_eq!(explorer.terminated_paths().len(), 1);
    }
}
