//! Symbolic state merging.
//!
//! Merges equivalent symbolic execution paths at join points to prevent
//! state-space explosion.  Two states are merge-candidates if they share the
//! same program counter and a compatible constraint hash.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Re-export of [`HashSet`] for callers building merge-key collections
/// without an extra import.
pub use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Re-export of [`crate::ExplorationStrategy`] so merger consumers can wire
/// their own exploration policy without depending on the crate root.
pub use crate::ExplorationStrategy;
use rustre_symb::{SymExpr, SymbolicState};

// ─── MergeKey ─────────────────────────────────────────────────────────────────

/// The key used to identify merge-compatible states.
///
/// Two states are merge-compatible iff their `MergeKey` is identical.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MergeKey {
    /// Program counter.
    pub pc: u64,
    /// Hash of the accumulated path constraints.
    pub constraint_hash: u64,
}

impl MergeKey {
    #[must_use]
    pub const fn new(pc: u64, constraint_hash: u64) -> Self {
        Self {
            pc,
            constraint_hash,
        }
    }

    /// Compute the constraint hash for a slice of expressions.
    ///
    /// Hashes the structural content of each [`SymExpr`] tree directly
    /// (using the derived `Hash` impl) so that two semantically identical
    /// expression trees always produce the same hash, regardless of internal
    /// bookkeeping details that may differ in `Debug` output.
    #[must_use]
    pub fn hash_constraints(constraints: &[SymExpr]) -> u64 {
        let mut hasher = DefaultHasher::new();
        for c in constraints {
            c.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Build a `MergeKey` from a PC and a slice of constraints.
    #[must_use]
    pub fn from_state(pc: u64, constraints: &[SymExpr]) -> Self {
        Self::new(pc, Self::hash_constraints(constraints))
    }
}

impl std::fmt::Display for MergeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pc={:#x} ch={:#016x}", self.pc, self.constraint_hash)
    }
}

// ─── MergeCandidate ───────────────────────────────────────────────────────────

/// A symbolic state waiting to be merged.
#[derive(Debug, Clone)]
pub struct MergeCandidate {
    /// Merge key.
    pub key: MergeKey,
    /// Symbolic state.
    pub state: SymbolicState,
    /// Depth at which this candidate was created.
    pub depth: u32,
    /// Sequential arrival order (for FIFO / LIFO tie-breaking).
    pub arrival: u64,
}

impl MergeCandidate {
    #[must_use]
    pub const fn new(key: MergeKey, state: SymbolicState, depth: u32, arrival: u64) -> Self {
        Self {
            key,
            state,
            depth,
            arrival,
        }
    }
}

// ─── JoinPoint ────────────────────────────────────────────────────────────────

/// Records the outcome of a merge operation at a specific PC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinPoint {
    /// PC where the merge occurred.
    pub pc: u64,
    /// Number of states that were merged into one.
    pub merged_count: usize,
    /// Merge key used.
    pub key: MergeKey,
    /// Depth of the surviving state.
    pub depth: u32,
}

// ─── MergeHistory ─────────────────────────────────────────────────────────────

/// Tracks all past merge operations.
#[derive(Debug, Default)]
pub struct MergeHistory {
    records: Vec<JoinPoint>,
    /// Total states eliminated by merging.
    pub total_eliminated: usize,
}

impl MergeHistory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a merge.
    pub fn record(&mut self, jp: JoinPoint) {
        self.total_eliminated += jp.merged_count.saturating_sub(1);
        self.records.push(jp);
    }

    /// All join points, in merge order.
    #[must_use]
    pub fn records(&self) -> &[JoinPoint] {
        &self.records
    }

    /// Number of merge operations performed.
    #[must_use]
    pub const fn merge_count(&self) -> usize {
        self.records.len()
    }

    /// All PCs at which merges have occurred.
    #[must_use]
    pub fn merged_pcs(&self) -> Vec<u64> {
        let mut seen = Vec::new();
        for r in &self.records {
            if !seen.contains(&r.pc) {
                seen.push(r.pc);
            }
        }
        seen
    }
}

// ─── MergedState ──────────────────────────────────────────────────────────────

/// The result of merging two or more compatible symbolic states.
#[derive(Debug, Clone)]
pub struct MergedState {
    /// PC of the merged state.
    pub pc: u64,
    /// The merged symbolic state (simplified by combining constraints).
    pub state: SymbolicState,
    /// Number of source states that were merged.
    pub source_count: usize,
    /// Depth of the deepest merged state.
    pub depth: u32,
    /// The merge key.
    pub key: MergeKey,
}

impl MergedState {
    #[must_use]
    pub const fn new(
        pc: u64,
        state: SymbolicState,
        source_count: usize,
        depth: u32,
        key: MergeKey,
    ) -> Self {
        Self {
            pc,
            state,
            source_count,
            depth,
            key,
        }
    }
}

// ─── StateMerger ──────────────────────────────────────────────────────────────

/// Accumulates [`MergeCandidate`]s and merges them when the bucket is full.
#[derive(Debug, Default)]
pub struct StateMerger {
    /// Candidates grouped by [`MergeKey`].
    buckets: HashMap<MergeKey, Vec<MergeCandidate>>,
    /// History of merge operations.
    pub history: MergeHistory,
    /// Minimum number of candidates in a bucket before a merge is triggered.
    pub min_merge_count: usize,
    /// Maximum bucket size before forced merge.
    pub max_bucket_size: usize,
    /// Total candidates submitted.
    total_submitted: u64,
    /// Next arrival counter.
    next_arrival: u64,
    /// Whether merging is enabled.
    pub enabled: bool,
}

impl StateMerger {
    /// Create a new merger.
    #[must_use]
    pub fn new(min_merge_count: usize, max_bucket_size: usize) -> Self {
        Self {
            min_merge_count,
            max_bucket_size,
            enabled: true,
            ..Default::default()
        }
    }

    /// Submit a state for potential merging.  Returns a merged state if a merge
    /// was triggered, or `None` if the state was merely queued.
    pub fn submit(
        &mut self,
        pc: u64,
        state: SymbolicState,
        depth: u32,
        constraints: &[SymExpr],
    ) -> Option<MergedState> {
        if !self.enabled {
            return None;
        }
        let key = MergeKey::from_state(pc, constraints);
        let arrival = self.next_arrival;
        self.next_arrival += 1;
        self.total_submitted += 1;

        let candidate = MergeCandidate::new(key.clone(), state, depth, arrival);
        let bucket = self.buckets.entry(key.clone()).or_default();
        bucket.push(candidate);

        if bucket.len() >= self.max_bucket_size || (bucket.len() >= self.min_merge_count) {
            return self.merge_bucket(&key);
        }
        None
    }

    /// Force a merge for `key` if there are at least 2 candidates.
    pub fn force_merge(&mut self, key: &MergeKey) -> Option<MergedState> {
        if self.buckets.get(key).map_or(0, Vec::len) < 2 {
            return None;
        }
        self.merge_bucket(key)
    }

    fn merge_bucket(&mut self, key: &MergeKey) -> Option<MergedState> {
        let candidates = self.buckets.remove(key)?;
        if candidates.is_empty() {
            return None;
        }

        let source_count = candidates.len();
        let depth = candidates.iter().map(|c| c.depth).max().unwrap_or(0);

        // "Merge" by taking the first state and disjunctively combining
        // the others' constraints (simplified: just keep the first state,
        // record the merge, and note how many were merged).
        let first = candidates.into_iter().next().unwrap();
        let merged = MergedState::new(first.key.pc, first.state, source_count, depth, key.clone());

        let jp = JoinPoint {
            pc: merged.pc,
            merged_count: source_count,
            key: key.clone(),
            depth,
        };
        self.history.record(jp);
        Some(merged)
    }

    /// Flush all buckets with at least one candidate.
    pub fn flush_all(&mut self) -> Vec<MergedState> {
        let keys: Vec<MergeKey> = self.buckets.keys().cloned().collect();
        let mut results = Vec::new();
        for key in keys {
            if let Some(bucket) = self.buckets.get(&key)
                && !bucket.is_empty()
                    && let Some(m) = self.merge_bucket(&key) {
                        results.push(m);
                    }
        }
        results
    }

    /// Number of pending candidates across all buckets.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.buckets.values().map(Vec::len).sum()
    }

    /// Number of distinct merge keys currently pending.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Total candidates submitted.
    #[must_use]
    pub const fn total_submitted(&self) -> u64 {
        self.total_submitted
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_symb::{SymExpr, SymbolicState};

    fn make_state() -> SymbolicState {
        SymbolicState::new()
    }

    // --- MergeKey ---

    #[test]
    fn merge_key_same_pc_same_constraints_equal() {
        let c1 = vec![SymExpr::constant(8, 1)];
        let c2 = vec![SymExpr::constant(8, 1)];
        let k1 = MergeKey::from_state(0x1000, &c1);
        let k2 = MergeKey::from_state(0x1000, &c2);
        assert_eq!(k1, k2);
    }

    #[test]
    fn merge_key_different_pc_not_equal() {
        let k1 = MergeKey::from_state(0x1000, &[]);
        let k2 = MergeKey::from_state(0x2000, &[]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn merge_key_empty_constraints_stable() {
        let k = MergeKey::from_state(0, &[]);
        assert_eq!(k.constraint_hash, MergeKey::hash_constraints(&[]));
    }

    #[test]
    fn merge_key_display_contains_pc() {
        let k = MergeKey::new(0x1234, 0);
        let s = k.to_string();
        assert!(s.contains("0x1234"));
    }

    #[test]
    fn merge_key_hash_constraints_varies_with_content() {
        let h1 = MergeKey::hash_constraints(&[SymExpr::constant(8, 1)]);
        let h2 = MergeKey::hash_constraints(&[SymExpr::constant(8, 2)]);
        // Different constant values → different repr → different hash (almost always)
        // This is a probabilistic check; collision is astronomically unlikely.
        assert_ne!(h1, h2);
    }

    // --- MergeCandidate ---

    #[test]
    fn merge_candidate_fields() {
        let key = MergeKey::new(0, 0);
        let c = MergeCandidate::new(key.clone(), make_state(), 3, 7);
        assert_eq!(c.depth, 3);
        assert_eq!(c.arrival, 7);
        assert_eq!(c.key, key);
    }

    // --- JoinPoint ---

    #[test]
    fn join_point_fields() {
        let jp = JoinPoint {
            pc: 0x1000,
            merged_count: 4,
            key: MergeKey::new(0x1000, 0),
            depth: 5,
        };
        assert_eq!(jp.merged_count, 4);
    }

    // --- MergeHistory ---

    #[test]
    fn history_record_increments() {
        let mut h = MergeHistory::new();
        let jp = JoinPoint {
            pc: 0,
            merged_count: 3,
            key: MergeKey::new(0, 0),
            depth: 0,
        };
        h.record(jp);
        assert_eq!(h.merge_count(), 1);
        assert_eq!(h.total_eliminated, 2); // merged 3, eliminated 2
    }

    #[test]
    fn history_merged_pcs_deduped() {
        let mut h = MergeHistory::new();
        for _ in 0..3 {
            let jp = JoinPoint {
                pc: 0x1000,
                merged_count: 2,
                key: MergeKey::new(0x1000, 0),
                depth: 0,
            };
            h.record(jp);
        }
        assert_eq!(h.merged_pcs().len(), 1);
    }

    #[test]
    fn history_multiple_pcs() {
        let mut h = MergeHistory::new();
        for pc in [0x1000u64, 0x2000, 0x3000] {
            h.record(JoinPoint {
                pc,
                merged_count: 2,
                key: MergeKey::new(pc, 0),
                depth: 0,
            });
        }
        assert_eq!(h.merged_pcs().len(), 3);
    }

    // --- MergedState ---

    #[test]
    fn merged_state_fields() {
        let key = MergeKey::new(0x1000, 0);
        let m = MergedState::new(0x1000, make_state(), 5, 10, key);
        assert_eq!(m.source_count, 5);
        assert_eq!(m.depth, 10);
    }

    // --- StateMerger ---

    #[test]
    fn merger_submit_below_threshold_returns_none() {
        let mut sm = StateMerger::new(3, 10);
        let r = sm.submit(0x1000, make_state(), 0, &[]);
        assert!(r.is_none());
        assert_eq!(sm.pending_count(), 1);
    }

    #[test]
    fn merger_submit_at_threshold_triggers_merge() {
        let mut sm = StateMerger::new(2, 10);
        sm.submit(0x1000, make_state(), 0, &[]);
        let r = sm.submit(0x1000, make_state(), 1, &[]);
        assert!(r.is_some());
        let m = r.unwrap();
        assert_eq!(m.source_count, 2);
        assert_eq!(m.pc, 0x1000);
    }

    #[test]
    fn merger_force_merge() {
        let mut sm = StateMerger::new(5, 20);
        let key = MergeKey::from_state(0xABCD, &[]);
        sm.submit(0xABCD, make_state(), 0, &[]);
        sm.submit(0xABCD, make_state(), 1, &[]);
        let r = sm.force_merge(&key);
        assert!(r.is_some());
        assert_eq!(sm.pending_count(), 0);
    }

    #[test]
    fn merger_force_merge_single_candidate_returns_none() {
        let mut sm = StateMerger::new(5, 20);
        let key = MergeKey::from_state(0x1000, &[]);
        sm.submit(0x1000, make_state(), 0, &[]);
        assert!(sm.force_merge(&key).is_none());
    }

    #[test]
    fn merger_flush_all_drains_buckets() {
        let mut sm = StateMerger::new(100, 100);
        sm.submit(0xA, make_state(), 0, &[]);
        sm.submit(0xB, make_state(), 0, &[SymExpr::constant(8, 1)]);
        let _results = sm.flush_all();
        // Each bucket has 1 candidate — flush returns them all.
        assert_eq!(sm.pending_count(), 0);
    }

    #[test]
    fn merger_disabled_returns_none() {
        let mut sm = StateMerger::new(1, 1);
        sm.enabled = false;
        let r = sm.submit(0, make_state(), 0, &[]);
        assert!(r.is_none());
    }

    #[test]
    fn merger_history_updated_on_merge() {
        let mut sm = StateMerger::new(2, 10);
        sm.submit(0x1000, make_state(), 0, &[]);
        sm.submit(0x1000, make_state(), 1, &[]);
        assert_eq!(sm.history.merge_count(), 1);
        assert_eq!(sm.history.total_eliminated, 1);
    }

    #[test]
    fn merger_total_submitted() {
        let mut sm = StateMerger::new(10, 10);
        for _ in 0..5 {
            sm.submit(0, make_state(), 0, &[]);
        }
        assert_eq!(sm.total_submitted(), 5);
    }

    #[test]
    fn merger_different_keys_separate_buckets() {
        let mut sm = StateMerger::new(100, 100);
        sm.submit(0x1000, make_state(), 0, &[]);
        sm.submit(0x2000, make_state(), 0, &[]);
        assert_eq!(sm.bucket_count(), 2);
    }

    #[test]
    fn merger_max_bucket_forced_merge() {
        let mut sm = StateMerger::new(100, 3); // force merge at size 3
        sm.submit(0x1000, make_state(), 0, &[]);
        sm.submit(0x1000, make_state(), 1, &[]);
        let r = sm.submit(0x1000, make_state(), 2, &[]);
        assert!(r.is_some());
        assert_eq!(r.unwrap().source_count, 3);
    }
}
