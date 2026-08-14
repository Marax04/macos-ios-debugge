//! Symbolic state manager with fork, merge, lazy clone, GC, snapshot/restore,
//! and similarity detection.
//!
//! Provides [`SymStateManager`] — a worklist that goes beyond the simple
//! [`StateManager`] in `lib.rs`:
//!
//! - **Fork on branch**: splits one state into two successors (taken / not-taken).
//! - **Merge with phi-join**: joins two states at a common join point by
//!   introducing `Ite` expressions for diverging register values.
//! - **Lazy cloning (copy-on-write)**: states share an [`Arc`]-wrapped base;
//!   a state is only deeply cloned when it is actually mutated.
//! - **State GC**: prune states whose path condition is trivially unsatisfiable.
//! - **Snapshot / restore**: save state, continue exploring, then roll back.
//! - **Similarity detection**: detect states that are structurally equivalent
//!   (up to renaming) to avoid redundant exploration (loop detection).

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::Arc;

use parking_lot;

use serde::{Deserialize, Serialize};

use rustre_symb::{SymExpr, SymbolicState};

use crate::ExplorationStrategy;

// ─── State ID ─────────────────────────────────────────────────────────────────

pub type StateId = u64;

// ─── SharedState — copy-on-write wrapper ─────────────────────────────────────

/// A lazily-cloned symbolic state.
///
/// [`Arc::make_mut`] ensures a deep copy only when a mutation is performed
/// while there is more than one reference to the inner state.
#[derive(Debug, Clone)]
pub struct SharedState {
    inner: Arc<SymbolicState>,
    pub id: StateId,
    pub parent_id: Option<StateId>,
    /// Exploration depth (instruction count since root).
    pub depth: u32,
    /// Whether this state is on the "taken" side of a branch fork.
    pub branch_taken: Option<bool>,
}

impl SharedState {
    #[must_use]
    pub fn new(id: StateId, state: SymbolicState) -> Self {
        Self {
            inner: Arc::new(state),
            id,
            parent_id: None,
            depth: 0,
            branch_taken: None,
        }
    }

    /// Borrow the state immutably.
    #[must_use]
    pub fn get(&self) -> &SymbolicState {
        &self.inner
    }

    /// Obtain a mutable reference, cloning the inner state if it is shared.
    pub fn get_mut(&mut self) -> &mut SymbolicState {
        Arc::make_mut(&mut self.inner)
    }

    /// Return the number of strong references to the inner state.
    #[must_use]
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Structural hash of the state (registers + path condition length).
    #[must_use]
    pub fn structural_hash(&self) -> u64 {
        let mut h = DefaultHasher::new();
        // Hash register names + expressions.
        let mut regs: Vec<(&String, &SymExpr)> = self.inner.registers.iter().collect();
        regs.sort_by_key(|(k, _)| *k);
        for (name, expr) in regs {
            name.hash(&mut h);
            expr.hash(&mut h);
        }
        self.inner.path_condition.len().hash(&mut h);
        h.finish()
    }
}

// ─── Fork result ──────────────────────────────────────────────────────────────

/// The two successors produced by forking a state at a branch.
pub struct ForkResult {
    pub taken: SharedState,
    pub not_taken: SharedState,
}

// ─── Merge result ─────────────────────────────────────────────────────────────

/// The merged state produced by phi-joining two states at a join point.
pub struct MergeResult {
    pub merged: SharedState,
    /// Number of registers that diverged and required `Ite` nodes.
    pub phi_count: usize,
}

// ─── Snapshot ─────────────────────────────────────────────────────────────────

/// A saved snapshot of a state (for backtracking).
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub snapshot_id: u64,
    pub state_id: StateId,
    pub state: Arc<SymbolicState>,
    pub depth: u32,
}

// ─── State statistics ─────────────────────────────────────────────────────────

/// Counters maintained by [`SymStateManager`].
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StateManagerStats {
    pub total_forked: u64,
    pub total_merged: u64,
    pub total_pruned: u64,
    pub total_snapshots: u64,
    pub total_restores: u64,
    pub similarity_hits: u64,
}

// ─── SymStateManager ─────────────────────────────────────────────────────────

/// Full-featured symbolic state manager.
pub struct SymStateManager {
    worklist: VecDeque<SharedState>,
    /// All states ever created (for lineage tracing).
    all_states: HashMap<StateId, SharedState>,
    next_id: StateId,
    next_snapshot_id: u64,
    snapshots: HashMap<u64, Snapshot>,
    stats: StateManagerStats,
    /// Structural hashes of states we have already explored.
    seen_hashes: HashSet<u64>,
    /// Strategy used by `pop`.
    strategy: ExplorationStrategy,
    /// Maximum worklist size (0 = unlimited).
    max_states: usize,
}

impl SymStateManager {
    #[must_use]
    pub fn new(strategy: ExplorationStrategy, max_states: usize) -> Self {
        Self {
            worklist: VecDeque::new(),
            all_states: HashMap::new(),
            next_id: 1,
            next_snapshot_id: 1,
            snapshots: HashMap::new(),
            stats: StateManagerStats::default(),
            seen_hashes: HashSet::new(),
            strategy,
            max_states,
        }
    }

    const fn alloc_id(&mut self) -> StateId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    // ─── Push / pop ───────────────────────────────────────────────────────

    /// Enqueue a state for exploration.
    ///
    /// Returns `false` and drops the state if the worklist is at capacity.
    pub fn push(&mut self, state: SharedState) -> bool {
        if self.max_states > 0 && self.worklist.len() >= self.max_states {
            self.stats.total_pruned += 1;
            return false;
        }
        self.worklist.push_back(state);
        true
    }

    /// Dequeue the next state according to the exploration strategy.
    pub fn pop(&mut self) -> Option<SharedState> {
        match self.strategy {
            ExplorationStrategy::Dfs => self.worklist.pop_back(),
            ExplorationStrategy::Bfs
            | ExplorationStrategy::CoverageGuided
            | ExplorationStrategy::RandomWalk => self.worklist.pop_front(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.worklist.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.worklist.is_empty()
    }

    // ─── Fork ─────────────────────────────────────────────────────────────

    /// Fork `state` into two successors at a conditional branch.
    ///
    /// - `taken_cond`: the symbolic condition for the taken path.
    /// - `not_taken_cond`: the symbolic condition for the not-taken path.
    ///
    /// Each successor gets the condition added to its path constraint.
    pub fn fork(
        &mut self,
        state: &SharedState,
        taken_cond: SymExpr,
        not_taken_cond: SymExpr,
    ) -> ForkResult {
        let taken_id = self.alloc_id();
        let not_taken_id = self.alloc_id();

        // Taken branch: clone and add the taken condition.
        let mut taken_inner = state.get().clone();
        taken_inner.path_condition.push(taken_cond);
        let taken = SharedState {
            inner: Arc::new(taken_inner),
            id: taken_id,
            parent_id: Some(state.id),
            depth: state.depth + 1,
            branch_taken: Some(true),
        };

        // Not-taken branch: clone and add the negated condition.
        let mut not_taken_inner = state.get().clone();
        not_taken_inner.path_condition.push(not_taken_cond);
        let not_taken = SharedState {
            inner: Arc::new(not_taken_inner),
            id: not_taken_id,
            parent_id: Some(state.id),
            depth: state.depth + 1,
            branch_taken: Some(false),
        };

        self.stats.total_forked += 1;
        ForkResult { taken, not_taken }
    }

    // ─── Merge (phi-join) ─────────────────────────────────────────────────

    /// Merge two states at a common join point using phi-functions.
    ///
    /// For each register that differs between `a` and `b`, introduce an
    /// `Ite(branch_cond, a_val, b_val)` expression in the merged state.
    ///
    /// `branch_cond` should be the condition that led to `a` (i.e. the
    /// condition under which `a.val` holds).
    pub fn merge(
        &mut self,
        a: &SharedState,
        b: &SharedState,
        branch_cond: &SymExpr,
    ) -> MergeResult {
        let merged_id = self.alloc_id();

        let state_a = a.get();
        let state_b = b.get();

        // Start from state_a and merge registers that differ.
        let mut merged_state = state_a.clone();
        let mut phi_count = 0;

        // Collect all register names from both states.
        let all_regs: HashSet<&String> = state_a
            .registers
            .keys()
            .chain(state_b.registers.keys())
            .collect();

        for reg in all_regs {
            let val_a = state_a.registers.get(reg);
            let val_b = state_b.registers.get(reg);
            match (val_a, val_b) {
                (Some(a_expr), Some(b_expr)) if a_expr != b_expr => {
                    // Introduce phi: Ite(branch_cond, a_val, b_val)
                    let phi = SymExpr::Ite {
                        cond: Box::new(branch_cond.clone()),
                        then_: Box::new(a_expr.clone()),
                        else_: Box::new(b_expr.clone()),
                    };
                    merged_state.registers.insert(reg.clone(), phi);
                    phi_count += 1;
                }
                (None, Some(b_expr)) => {
                    // Register only in b: keep it (undefined in a → use b).
                    merged_state.registers.insert(reg.clone(), b_expr.clone());
                }
                _ => { /* same or only in a — keep a's value */ }
            }
        }

        // Merge path conditions: take the disjunction of the two.
        if state_a.path_condition != state_b.path_condition {
            let pc_a = build_conjunction(&state_a.path_condition);
            let pc_b = build_conjunction(&state_b.path_condition);
            merged_state.path_condition = match (pc_a, pc_b) {
                (Some(a), Some(b)) => vec![SymExpr::BoolOr(Box::new(a), Box::new(b))],
                (Some(a), None) => vec![a],
                (None, Some(b)) => vec![b],
                (None, None) => vec![],
            };
        }

        self.stats.total_merged += 1;

        let merged = SharedState {
            inner: Arc::new(merged_state),
            id: merged_id,
            parent_id: None,
            depth: a.depth.max(b.depth),
            branch_taken: None,
        };

        MergeResult { merged, phi_count }
    }

    // ─── GC: prune infeasible states ──────────────────────────────────────

    /// Remove states whose path condition is trivially `false`.
    pub fn prune_infeasible(&mut self) {
        let before = self.worklist.len();
        self.worklist.retain(|s| {
            let infeasible = s.get().path_condition.iter().any(|c| {
                matches!(c, SymExpr::ConstBool(false))
            });
            !infeasible
        });
        let pruned = before - self.worklist.len();
        self.stats.total_pruned += pruned as u64;
    }

    // ─── Snapshot / restore ───────────────────────────────────────────────

    /// Take a snapshot of `state` and return the snapshot ID.
    pub fn snapshot(&mut self, state: &SharedState) -> u64 {
        let snap_id = self.next_snapshot_id;
        self.next_snapshot_id += 1;
        self.snapshots.insert(
            snap_id,
            Snapshot {
                snapshot_id: snap_id,
                state_id: state.id,
                state: state.inner.clone(),
                depth: state.depth,
            },
        );
        self.stats.total_snapshots += 1;
        snap_id
    }

    /// Restore a previously snapshotted state.
    pub fn restore(&mut self, snap_id: u64) -> Option<SharedState> {
        let (state_clone, state_id, depth) = {
            let snap = self.snapshots.get(&snap_id)?;
            (snap.state.clone(), snap.state_id, snap.depth)
        };
        let restored_id = self.alloc_id();
        let restored = SharedState {
            inner: state_clone,
            id: restored_id,
            parent_id: Some(state_id),
            depth,
            branch_taken: None,
        };
        self.stats.total_restores += 1;
        Some(restored)
    }

    /// Delete a snapshot.
    pub fn drop_snapshot(&mut self, snap_id: u64) {
        self.snapshots.remove(&snap_id);
    }

    // ─── Similarity detection (loop detection) ────────────────────────────

    /// Return `true` if a state with the same structural hash has already
    /// been explored (potential loop).
    pub fn is_similar_to_seen(&mut self, state: &SharedState) -> bool {
        let h = state.structural_hash();
        if self.seen_hashes.contains(&h) {
            self.stats.similarity_hits += 1;
            true
        } else {
            self.seen_hashes.insert(h);
            false
        }
    }

    /// Clear the set of seen hashes (reset similarity detection).
    pub fn reset_similarity_table(&mut self) {
        self.seen_hashes.clear();
    }

    // ─── State archiving ─────────────────────────────────────────────────

    /// Archive a state so it can be retrieved later by ID.
    pub fn archive(&mut self, state: SharedState) {
        self.all_states.insert(state.id, state);
    }

    /// Retrieve an archived state by ID.
    #[must_use]
    pub fn get_archived(&self, id: StateId) -> Option<&SharedState> {
        self.all_states.get(&id)
    }

    // ─── Statistics ───────────────────────────────────────────────────────

    #[must_use]
    pub const fn stats(&self) -> &StateManagerStats {
        &self.stats
    }

    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Create a fresh [`SharedState`] wrapping the given [`SymbolicState`].
    pub fn wrap(&mut self, state: SymbolicState) -> SharedState {
        let id = self.alloc_id();
        SharedState::new(id, state)
    }
}

// ─── Helper ───────────────────────────────────────────────────────────────────

fn build_conjunction(conjuncts: &[SymExpr]) -> Option<SymExpr> {
    let mut it = conjuncts.iter().cloned();
    let first = it.next()?;
    Some(it.fold(first, |acc, c| SymExpr::BoolAnd(Box::new(acc), Box::new(c))))
}

// ─── Priority queue variant for heuristic exploration ────────────────────────

/// A state with an associated priority score (higher = explore first).
#[derive(Debug, Clone)]
pub struct PrioritizedState {
    pub state: SharedState,
    pub priority: i64,
}

impl PartialEq for PrioritizedState {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}
impl Eq for PrioritizedState {}
impl PartialOrd for PrioritizedState {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for PrioritizedState {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

/// Priority heuristics for selecting interesting states.
pub mod heuristics {
    use super::{HashSet, SharedState, SymExpr};

    /// Score that rewards states closer to a set of target addresses.
    #[must_use]
    pub fn distance_to_targets<S: std::hash::BuildHasher>(
        state: &SharedState,
        targets: &HashSet<u64, S>,
    ) -> i64 {
        let pc = state
            .get()
            .registers
            .get("rip")
            .and_then(SymExpr::as_const_u64)
            .unwrap_or(0);

        if targets.contains(&pc) {
            return 1000;
        }

        // Simple: reward states that have fewer path conditions (less constrained).
        let depth_penalty = i64::from(state.depth);
        let pc_len = i64::try_from(state.get().path_condition.len()).unwrap_or(i64::MAX);
        100 - depth_penalty - pc_len
    }

    /// Score that rewards states with uncovered branches.
    #[must_use]
    pub fn coverage_guided<S: std::hash::BuildHasher>(
        state: &SharedState,
        covered: &HashSet<u64, S>,
    ) -> i64 {
        let pc = state
            .get()
            .registers
            .get("rip")
            .and_then(SymExpr::as_const_u64)
            .unwrap_or(0);

        (if covered.contains(&pc) { 0i64 } else { 50i64 }) - i64::from(state.depth)
    }
}

// ─── Thread-safe worklist ─────────────────────────────────────────────────────

/// A thread-safe worklist of [`SharedState`]s backed by a [`parking_lot::Mutex`].
///
/// Suitable for parallel path exploration where multiple threads may push or
/// pop states concurrently.  Uses `parking_lot::Mutex` rather than
/// `std::sync::Mutex` for lower overhead and guaranteed absence of poisoning.
pub struct ThreadSafeWorklist {
    inner: parking_lot::Mutex<VecDeque<SharedState>>,
}

impl ThreadSafeWorklist {
    /// Create an empty worklist.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(VecDeque::new()),
        }
    }

    /// Push a state onto the back of the worklist.
    pub fn push(&self, state: SharedState) {
        self.inner.lock().push_back(state);
    }

    /// Pop a state from the front (BFS order).
    pub fn pop_front(&self) -> Option<SharedState> {
        self.inner.lock().pop_front()
    }

    /// Pop a state from the back (DFS order).
    pub fn pop_back(&self) -> Option<SharedState> {
        self.inner.lock().pop_back()
    }

    /// Return the current number of states in the worklist.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Return `true` if the worklist is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl Default for ThreadSafeWorklist {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_symb::SymType;

    fn empty_state() -> SymbolicState {
        SymbolicState::default()
    }

    fn manager() -> SymStateManager {
        SymStateManager::new(ExplorationStrategy::Dfs, 1024)
    }

    #[test]
    fn test_wrap_and_push_pop() {
        let mut mgr = manager();
        let s = mgr.wrap(empty_state());
        let id = s.id;
        mgr.push(s);
        let popped = mgr.pop().unwrap();
        assert_eq!(popped.id, id);
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_fork() {
        let mut mgr = manager();
        let s = mgr.wrap(empty_state());
        let cond = SymExpr::Var { name: "c".into(), ty: SymType::Bool };
        let not_cond = SymExpr::BoolNot(Box::new(cond.clone()));
        let fork = mgr.fork(&s, cond.clone(), not_cond);

        assert_eq!(fork.taken.branch_taken, Some(true));
        assert_eq!(fork.not_taken.branch_taken, Some(false));
        assert!(fork.taken.get().path_condition.contains(&cond));
        assert_eq!(mgr.stats().total_forked, 1);
    }

    #[test]
    fn test_merge_phi() {
        let mut mgr = manager();
        let mut state_a_inner = empty_state();
        state_a_inner.registers.insert(
            "rax".into(),
            SymExpr::ConstBv { val: 1, width: 64 },
        );
        let mut state_b_inner_alt = empty_state();
        state_b_inner_alt.registers.insert(
            "rax".into(),
            SymExpr::ConstBv { val: 2, width: 64 },
        );

        let a = mgr.wrap(state_a_inner);
        let b = mgr.wrap(state_b_inner_alt);
        let cond = SymExpr::Var { name: "branch".into(), ty: SymType::Bool };
        let result = mgr.merge(&a, &b, &cond);

        assert_eq!(result.phi_count, 1);
        let merged_rax = result.merged.get().registers.get("rax").unwrap();
        assert!(matches!(merged_rax, SymExpr::Ite { .. }));
    }

    #[test]
    fn test_snapshot_restore() {
        let mut mgr = manager();
        let mut s = mgr.wrap(empty_state());
        let snap_id = mgr.snapshot(&s);

        // Mutate the state.
        s.get_mut()
            .registers
            .insert("rax".into(), SymExpr::ConstBv { val: 99, width: 64 });

        let restored = mgr.restore(snap_id).unwrap();
        assert!(!restored.get().registers.contains_key("rax"));
        assert_eq!(mgr.stats().total_restores, 1);
    }

    #[test]
    fn test_prune_infeasible() {
        let mut mgr = manager();
        let mut s = mgr.wrap(empty_state());
        s.get_mut().path_condition.push(SymExpr::ConstBool(false));
        mgr.push(s);
        let wrapped = mgr.wrap(empty_state());
        mgr.push(wrapped);
        assert_eq!(mgr.len(), 2);
        mgr.prune_infeasible();
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_similarity_detection() {
        let mut mgr = manager();
        let s1 = mgr.wrap(empty_state());
        let duplicate = mgr.wrap(empty_state()); // same structure
        assert!(!mgr.is_similar_to_seen(&s1));
        assert!(mgr.is_similar_to_seen(&duplicate));
    }

    #[test]
    fn test_max_states_cap() {
        let mut mgr = SymStateManager::new(ExplorationStrategy::Dfs, 2);
        let w1 = mgr.wrap(empty_state());
        assert!(mgr.push(w1));
        let w2 = mgr.wrap(empty_state());
        assert!(mgr.push(w2));
        let w3 = mgr.wrap(empty_state());
        assert!(!mgr.push(w3));
        assert_eq!(mgr.stats().total_pruned, 1);
    }
}
