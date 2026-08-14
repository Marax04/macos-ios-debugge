//! `recognition_session` — FLIRT recognition session management.
//!
//! Provides:
//! * [`RecognitionSession`] — manages a single recognition run
//! * [`MatchQueue`] — priority queue of pending match candidates
//! * [`BatchApply`] — applies a batch of matches to an analysis context
//! * [`ConflictLog`] — records address conflicts from overlapping matches
//! * [`AppliedSymbols`] — final symbol map produced by a session
//! * [`RecognitionStats`] — session statistics
//! * [`AutoApply`] — automatic, threshold-based symbol application

use std::cmp::Ordering;

use crate::casts::usize_to_f64;
pub use std::collections::BinaryHeap;
use std::collections::HashSet;

// Use AHashMap (randomised hash) for all maps keyed by attacker-controlled
// data (function addresses from binary input, function names from .sig/.pat
// files) to prevent hash-collision DoS.
use ahash::AHashMap as HashMap;

use serde::{Deserialize, Serialize};

pub use crate::FlirtError;

// ─── MatchCandidate ───────────────────────────────────────────────────────────

/// A single pending match candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCandidate {
    /// Virtual address where the function was matched.
    pub address: u64,
    /// Proposed symbol name from the FLIRT pattern.
    pub name: String,
    /// Library name this match came from.
    pub library: String,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// Whether the CRC check passed for this match.
    pub crc_ok: bool,
}

impl MatchCandidate {
    /// Returns `true` if this is a high-confidence match.
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.crc_ok && self.confidence >= 0.8
    }
}

impl PartialEq for MatchCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.name == other.name
    }
}

impl Eq for MatchCandidate {}

impl PartialOrd for MatchCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MatchCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher confidence = higher priority.
        self.confidence
            .partial_cmp(&other.confidence)
            .unwrap_or(Ordering::Equal)
    }
}

// ─── MatchQueue ───────────────────────────────────────────────────────────────

/// A priority queue of [`MatchCandidate`] ordered by confidence (highest first).
#[derive(Debug, Default, Clone)]
pub struct MatchQueue {
    heap: Vec<MatchCandidate>,
}

impl MatchQueue {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a candidate onto the queue.
    pub fn push(&mut self, candidate: MatchCandidate) {
        self.heap.push(candidate);
        // Keep sorted by descending confidence
        self.heap.sort_by(|a, b| b.cmp(a));
    }

    /// Pop the highest-confidence candidate.
    #[must_use]
    pub fn pop(&mut self) -> Option<MatchCandidate> {
        if self.heap.is_empty() {
            None
        } else {
            Some(self.heap.remove(0))
        }
    }

    /// Returns the number of candidates in the queue.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.heap.len()
    }

    /// Returns `true` if the queue is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Peek at the highest-confidence candidate without removing it.
    #[must_use]
    pub fn peek(&self) -> Option<&MatchCandidate> {
        self.heap.first()
    }

    /// Drain all candidates with confidence >= `threshold`.
    #[must_use]
    pub fn drain_above(&mut self, threshold: f64) -> Vec<MatchCandidate> {
        let mut result = Vec::new();
        self.heap.retain(|c| {
            if c.confidence >= threshold {
                result.push(c.clone());
                false
            } else {
                true
            }
        });
        result
    }
}

// ─── ConflictLog ─────────────────────────────────────────────────────────────

/// Records address conflicts where multiple different names were proposed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConflictLog {
    /// Conflicts: `address → Vec<(name, confidence)>`
    pub entries: HashMap<u64, Vec<(String, f64)>>,
}

impl ConflictLog {
    /// Create an empty conflict log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a conflict at `address` between `existing_name` and `new_name`.
    pub fn record(
        &mut self,
        address: u64,
        existing_name: &str,
        existing_conf: f64,
        new_name: &str,
        new_conf: f64,
    ) {
        let entry = self.entries.entry(address).or_default();
        if entry.is_empty() {
            entry.push((existing_name.to_string(), existing_conf));
        }
        if !entry.iter().any(|(n, _)| n == new_name) {
            entry.push((new_name.to_string(), new_conf));
        }
    }

    /// Returns `true` if there are no conflicts.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total number of conflicting addresses.
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.entries.len()
    }

    /// Return the best candidate for a conflicting address (highest confidence).
    #[must_use]
    pub fn resolve_best(&self, address: u64) -> Option<&str> {
        self.entries.get(&address).and_then(|v| {
            v.iter()
                .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(Ordering::Equal))
                .map(|(n, _)| n.as_str())
        })
    }
}

// ─── AppliedSymbols ───────────────────────────────────────────────────────────

/// The final map of address → symbol name produced by a recognition session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppliedSymbols {
    /// Accepted symbols: `address → (name, confidence)`.
    pub accepted: HashMap<u64, (String, f64)>,
    /// Total number of high-confidence symbols.
    pub high_confidence_count: usize,
}

impl AppliedSymbols {
    /// Create an empty symbol map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol.
    pub fn insert(&mut self, address: u64, name: impl Into<String>, confidence: f64) {
        if confidence >= 0.8 {
            self.high_confidence_count += 1;
        }
        self.accepted.insert(address, (name.into(), confidence));
    }

    /// Look up the symbol name at `address`.
    #[must_use]
    pub fn name_at(&self, address: u64) -> Option<&str> {
        self.accepted.get(&address).map(|(n, _)| n.as_str())
    }

    /// Returns the confidence score for the symbol at `address`.
    #[must_use]
    pub fn confidence_at(&self, address: u64) -> Option<f64> {
        self.accepted.get(&address).map(|(_, c)| *c)
    }

    /// Total number of accepted symbols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    /// Returns `true` if no symbols have been applied.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
    }
}

// ─── RecognitionStats ────────────────────────────────────────────────────────

/// Statistics produced by a recognition session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecognitionStats {
    /// Number of functions scanned.
    pub functions_scanned: usize,
    /// Number of candidates generated.
    pub candidates_generated: usize,
    /// Number of symbols applied.
    pub symbols_applied: usize,
    /// Number of conflicts recorded.
    pub conflicts: usize,
    /// Symbols applied with high confidence (CRC verified, confidence ≥ 0.8).
    pub high_confidence_applied: usize,
    /// Libraries that contributed matches.
    pub matched_libraries: HashSet<String>,
}

impl RecognitionStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply rate = `symbols_applied` / `candidates_generated` (0.0 if no candidates).
    #[must_use]
    pub fn apply_rate(&self) -> f64 {
        if self.candidates_generated == 0 {
            0.0
        } else {
            usize_to_f64(self.symbols_applied) / usize_to_f64(self.candidates_generated)
        }
    }
}

// ─── BatchApply ───────────────────────────────────────────────────────────────

/// Applies a batch of [`MatchCandidate`] values, resolving conflicts.
#[derive(Debug, Clone)]
pub struct BatchApply {
    /// Minimum confidence threshold to apply a symbol.
    pub min_confidence: f64,
    /// Whether to prefer high-confidence matches when conflicts occur.
    pub prefer_high_confidence: bool,
}

/// Delegates to [`BatchApply::new`].
///
/// BUG FIX: this used to be `#[derive(Default)]`, which set
/// `min_confidence` to 0 while `new()` sets it to 0.5. A threshold of zero is
/// not a neutral default — it silently disables the check it guards.
impl Default for BatchApply {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchApply {
    /// Create with default threshold of 0.5.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_confidence: 0.5,
            prefer_high_confidence: true,
        }
    }

    /// Set the minimum confidence threshold.
    #[must_use]
    pub const fn with_threshold(mut self, threshold: f64) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Apply a batch of candidates, populating `symbols` and `conflicts`.
    pub fn apply(
        &self,
        candidates: &[MatchCandidate],
        symbols: &mut AppliedSymbols,
        conflicts: &mut ConflictLog,
    ) {
        for c in candidates {
            if c.confidence < self.min_confidence {
                continue;
            }
            if let Some((existing_name, existing_conf)) = symbols.accepted.get(&c.address).cloned()
            {
                if existing_name != c.name {
                    conflicts.record(
                        c.address,
                        &existing_name,
                        existing_conf,
                        &c.name,
                        c.confidence,
                    );
                    if self.prefer_high_confidence && c.confidence > existing_conf {
                        symbols.insert(c.address, c.name.clone(), c.confidence);
                    }
                }
            } else {
                symbols.insert(c.address, c.name.clone(), c.confidence);
            }
        }
    }
}

// ─── AutoApply ────────────────────────────────────────────────────────────────

/// Automatic, threshold-based symbol application that drains a [`MatchQueue`].
#[derive(Debug, Clone)]
pub struct AutoApply {
    /// High-confidence threshold — applied immediately.
    pub high_threshold: f64,
    /// Low-confidence threshold — applied if no conflict.
    pub low_threshold: f64,
    /// Maximum number of symbols to apply in one run.
    pub max_apply: usize,
}

impl Default for AutoApply {
    fn default() -> Self {
        Self {
            high_threshold: 0.8,
            low_threshold: 0.5,
            max_apply: usize::MAX,
        }
    }
}

impl AutoApply {
    /// Create with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain candidates from `queue` and apply them to `symbols`.
    ///
    /// Returns the number of symbols applied.
    pub fn run(
        &self,
        queue: &mut MatchQueue,
        symbols: &mut AppliedSymbols,
        conflicts: &mut ConflictLog,
    ) -> usize {
        let mut applied = 0usize;

        while applied < self.max_apply {
            let Some(candidate) = queue.pop() else { break };

            if candidate.confidence < self.low_threshold {
                // Re-push and stop — remaining candidates are below threshold.
                queue.push(candidate);
                break;
            }

            if let Some((existing_name, existing_conf)) =
                symbols.accepted.get(&candidate.address).cloned()
            {
                if existing_name != candidate.name {
                    conflicts.record(
                        candidate.address,
                        &existing_name,
                        existing_conf,
                        &candidate.name,
                        candidate.confidence,
                    );
                    if candidate.confidence > existing_conf {
                        symbols.insert(
                            candidate.address,
                            candidate.name.clone(),
                            candidate.confidence,
                        );
                        applied += 1;
                    }
                }
            } else {
                symbols.insert(
                    candidate.address,
                    candidate.name.clone(),
                    candidate.confidence,
                );
                applied += 1;
            }
        }

        applied
    }
}

// ─── RecognitionSession ───────────────────────────────────────────────────────

/// Manages a single FLIRT recognition run.
///
/// Aggregates match candidates, applies them through [`BatchApply`] or
/// [`AutoApply`], and produces [`AppliedSymbols`] and [`RecognitionStats`].
#[derive(Debug, Default)]
pub struct RecognitionSession {
    /// Pending candidates.
    queue: MatchQueue,
    /// Applied symbols.
    pub symbols: AppliedSymbols,
    /// Conflict log.
    pub conflicts: ConflictLog,
    /// Session statistics.
    pub stats: RecognitionStats,
    /// Batch applier configuration.
    batch_applier: BatchApply,
    /// Auto applier configuration.
    auto_applier: AutoApply,
}

impl RecognitionSession {
    /// Create a new session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a match candidate to the session queue.
    pub fn add_candidate(&mut self, candidate: MatchCandidate) {
        self.stats.candidates_generated += 1;
        self.stats
            .matched_libraries
            .insert(candidate.library.clone());
        self.queue.push(candidate);
    }

    /// Add multiple candidates at once.
    pub fn add_candidates(&mut self, candidates: Vec<MatchCandidate>) {
        for c in candidates {
            self.add_candidate(c);
        }
    }

    /// Apply all queued candidates using the batch applier.
    pub fn apply_batch(&mut self) {
        let candidates: Vec<MatchCandidate> = self.queue.heap.drain(..).collect();
        let prev_count = self.symbols.len();
        self.batch_applier
            .apply(&candidates, &mut self.symbols, &mut self.conflicts);
        let applied = self.symbols.len() - prev_count;
        self.stats.symbols_applied += applied;
        self.stats.conflicts = self.conflicts.conflict_count();
        self.stats.high_confidence_applied = self.symbols.high_confidence_count;
    }

    /// Apply candidates using the auto applier (drains the queue).
    pub fn apply_auto(&mut self) {
        let applied =
            self.auto_applier
                .run(&mut self.queue, &mut self.symbols, &mut self.conflicts);
        self.stats.symbols_applied += applied;
        self.stats.conflicts = self.conflicts.conflict_count();
        self.stats.high_confidence_applied = self.symbols.high_confidence_count;
    }

    /// Returns `true` if there are pending candidates.
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Returns the number of pending candidates.
    #[must_use]
    pub const fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Finalize the session and return statistics.
    #[must_use]
    pub fn finalize(mut self) -> (AppliedSymbols, ConflictLog, RecognitionStats) {
        // Apply any remaining candidates.
        if !self.queue.is_empty() {
            self.apply_batch();
        }
        (self.symbols, self.conflicts, self.stats)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(addr: u64, name: &str, conf: f64) -> MatchCandidate {
        MatchCandidate {
            address: addr,
            name: name.to_string(),
            library: "libtest.a".to_string(),
            confidence: conf,
            crc_ok: conf >= 0.8,
        }
    }

    // ── MatchCandidate ────────────────────────────────────────────────────────

    #[test]
    fn test_candidate_is_high_confidence() {
        let c = make_candidate(0x1000, "foo", 0.9);
        assert!(c.is_high_confidence());
    }

    #[test]
    fn test_candidate_is_not_high_confidence_low_score() {
        let c = make_candidate(0x1000, "foo", 0.6);
        assert!(!c.is_high_confidence());
    }

    #[test]
    fn test_candidate_is_not_high_confidence_no_crc() {
        let mut c = make_candidate(0x1000, "foo", 0.9);
        c.crc_ok = false;
        assert!(!c.is_high_confidence());
    }

    #[test]
    fn test_candidate_ordering() {
        let a = make_candidate(0x1000, "a", 0.9);
        let b = make_candidate(0x2000, "b", 0.5);
        assert!(a > b);
    }

    // ── MatchQueue ────────────────────────────────────────────────────────────

    #[test]
    fn test_match_queue_push_pop() {
        let mut q = MatchQueue::new();
        q.push(make_candidate(0x1000, "foo", 0.7));
        q.push(make_candidate(0x2000, "bar", 0.9));
        let top = q.pop().unwrap();
        assert_eq!(top.name, "bar"); // highest confidence first
    }

    #[test]
    fn test_match_queue_len() {
        let mut q = MatchQueue::new();
        q.push(make_candidate(0x1000, "a", 0.8));
        assert_eq!(q.len(), 1);
        let _ = q.pop();
        assert!(q.is_empty());
    }

    #[test]
    fn test_match_queue_peek() {
        let mut q = MatchQueue::new();
        q.push(make_candidate(0x1000, "a", 0.5));
        q.push(make_candidate(0x2000, "b", 0.9));
        assert_eq!(q.peek().unwrap().name, "b");
    }

    #[test]
    fn test_match_queue_drain_above() {
        let mut q = MatchQueue::new();
        q.push(make_candidate(0x1000, "a", 0.5));
        q.push(make_candidate(0x2000, "b", 0.9));
        q.push(make_candidate(0x3000, "c", 0.85));
        let drained = q.drain_above(0.8);
        assert_eq!(drained.len(), 2);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn test_match_queue_empty_pop() {
        let mut q = MatchQueue::new();
        assert!(q.pop().is_none());
    }

    // ── ConflictLog ───────────────────────────────────────────────────────────

    #[test]
    fn test_conflict_log_is_clean_initially() {
        let log = ConflictLog::new();
        assert!(log.is_clean());
    }

    #[test]
    fn test_conflict_log_record() {
        let mut log = ConflictLog::new();
        log.record(0x1000, "foo", 0.9, "bar", 0.8);
        assert_eq!(log.conflict_count(), 1);
        assert!(!log.is_clean());
    }

    #[test]
    fn test_conflict_log_no_duplicate_names() {
        let mut log = ConflictLog::new();
        log.record(0x1000, "foo", 0.9, "bar", 0.8);
        log.record(0x1000, "foo", 0.9, "bar", 0.8); // duplicate
        assert_eq!(log.entries[&0x1000].len(), 2); // original + bar
    }

    #[test]
    fn test_conflict_log_resolve_best() {
        let mut log = ConflictLog::new();
        log.record(0x1000, "low", 0.3, "high", 0.9);
        assert_eq!(log.resolve_best(0x1000), Some("high"));
    }

    #[test]
    fn test_conflict_log_resolve_missing() {
        let log = ConflictLog::new();
        assert!(log.resolve_best(0xDEAD).is_none());
    }

    // ── AppliedSymbols ────────────────────────────────────────────────────────

    #[test]
    fn test_applied_symbols_insert_and_lookup() {
        let mut s = AppliedSymbols::new();
        s.insert(0x1000, "malloc", 0.95);
        assert_eq!(s.name_at(0x1000), Some("malloc"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_applied_symbols_high_confidence_count() {
        let mut s = AppliedSymbols::new();
        s.insert(0x1000, "a", 0.9);
        s.insert(0x2000, "b", 0.4);
        assert_eq!(s.high_confidence_count, 1);
    }

    #[test]
    fn test_applied_symbols_confidence_at() {
        let mut s = AppliedSymbols::new();
        s.insert(0x1000, "foo", 0.75);
        assert!((s.confidence_at(0x1000).unwrap() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn test_applied_symbols_is_empty() {
        let s = AppliedSymbols::new();
        assert!(s.is_empty());
    }

    #[test]
    fn test_applied_symbols_serialization() {
        let mut s = AppliedSymbols::new();
        s.insert(0x1000, "f", 0.9);
        let j = serde_json::to_string(&s).unwrap();
        let d: AppliedSymbols = serde_json::from_str(&j).unwrap();
        assert_eq!(d.len(), 1);
    }

    // ── RecognitionStats ──────────────────────────────────────────────────────

    #[test]
    fn test_recognition_stats_apply_rate_zero_candidates() {
        let s = RecognitionStats::new();
        assert!((s.apply_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_recognition_stats_apply_rate() {
        let mut s = RecognitionStats::new();
        s.candidates_generated = 10;
        s.symbols_applied = 8;
        assert!((s.apply_rate() - 0.8).abs() < f64::EPSILON);
    }

    // ── BatchApply ────────────────────────────────────────────────────────────

    #[test]
    fn test_batch_apply_basic() {
        let ba = BatchApply::new();
        let candidates = vec![make_candidate(0x1000, "malloc", 0.9)];
        let mut symbols = AppliedSymbols::new();
        let mut conflicts = ConflictLog::new();
        ba.apply(&candidates, &mut symbols, &mut conflicts);
        assert_eq!(symbols.len(), 1);
    }

    #[test]
    fn test_batch_apply_below_threshold_skipped() {
        let ba = BatchApply::new().with_threshold(0.8);
        let candidates = vec![make_candidate(0x1000, "foo", 0.5)];
        let mut symbols = AppliedSymbols::new();
        let mut conflicts = ConflictLog::new();
        ba.apply(&candidates, &mut symbols, &mut conflicts);
        assert_eq!(symbols.len(), 0);
    }

    #[test]
    fn test_batch_apply_conflict_recorded() {
        let ba = BatchApply::new();
        let mut symbols = AppliedSymbols::new();
        symbols.insert(0x1000, "foo", 0.7);
        let candidates = vec![make_candidate(0x1000, "bar", 0.9)];
        let mut conflicts = ConflictLog::new();
        ba.apply(&candidates, &mut symbols, &mut conflicts);
        assert!(!conflicts.is_clean());
    }

    // ── AutoApply ─────────────────────────────────────────────────────────────

    #[test]
    fn test_auto_apply_basic() {
        let aa = AutoApply::new();
        let mut q = MatchQueue::new();
        q.push(make_candidate(0x1000, "foo", 0.9));
        q.push(make_candidate(0x2000, "bar", 0.85));
        let mut symbols = AppliedSymbols::new();
        let mut conflicts = ConflictLog::new();
        let applied = aa.run(&mut q, &mut symbols, &mut conflicts);
        assert_eq!(applied, 2);
    }

    #[test]
    fn test_auto_apply_stops_at_low_threshold() {
        let aa = AutoApply::new();
        let mut q = MatchQueue::new();
        q.push(make_candidate(0x1000, "foo", 0.9));
        q.push(make_candidate(0x2000, "bar", 0.3)); // below threshold
        let mut symbols = AppliedSymbols::new();
        let mut conflicts = ConflictLog::new();
        let applied = aa.run(&mut q, &mut symbols, &mut conflicts);
        assert_eq!(applied, 1);
        assert_eq!(q.len(), 1); // low-conf one left in queue
    }

    #[test]
    fn test_auto_apply_max_apply() {
        let mut aa = AutoApply::new();
        aa.max_apply = 2;
        let mut q = MatchQueue::new();
        for i in 0..5 {
            q.push(make_candidate(0x1000 + i, "f", 0.9));
        }
        let mut symbols = AppliedSymbols::new();
        let mut conflicts = ConflictLog::new();
        let applied = aa.run(&mut q, &mut symbols, &mut conflicts);
        assert_eq!(applied, 2);
    }

    // ── RecognitionSession ────────────────────────────────────────────────────

    #[test]
    fn test_session_add_candidate() {
        let mut session = RecognitionSession::new();
        session.add_candidate(make_candidate(0x1000, "malloc", 0.9));
        assert_eq!(session.pending_count(), 1);
        assert_eq!(session.stats.candidates_generated, 1);
    }

    #[test]
    fn test_session_add_multiple_candidates() {
        let mut session = RecognitionSession::new();
        session.add_candidates(vec![
            make_candidate(0x1000, "malloc", 0.9),
            make_candidate(0x2000, "free", 0.85),
        ]);
        assert_eq!(session.pending_count(), 2);
    }

    #[test]
    fn test_session_apply_batch() {
        let mut session = RecognitionSession::new();
        session.add_candidate(make_candidate(0x1000, "foo", 0.9));
        session.apply_batch();
        assert_eq!(session.symbols.len(), 1);
        assert!(!session.has_pending());
    }

    #[test]
    fn test_session_apply_auto() {
        let mut session = RecognitionSession::new();
        session.add_candidate(make_candidate(0x1000, "bar", 0.8));
        session.apply_auto();
        assert_eq!(session.symbols.len(), 1);
    }

    #[test]
    fn test_session_finalize() {
        let mut session = RecognitionSession::new();
        session.add_candidate(make_candidate(0x1000, "baz", 0.9));
        let (symbols, conflicts, stats) = session.finalize();
        assert_eq!(symbols.len(), 1);
        assert!(conflicts.is_clean());
        assert!(stats.symbols_applied > 0);
    }

    #[test]
    fn test_session_stats_matched_libraries() {
        let mut session = RecognitionSession::new();
        session.add_candidate(make_candidate(0x1000, "foo", 0.9));
        assert!(session.stats.matched_libraries.contains("libtest.a"));
    }

    #[test]
    fn test_session_conflict_recorded() {
        let mut session = RecognitionSession::new();
        session.add_candidate(make_candidate(0x1000, "foo", 0.7));
        session.add_candidate(make_candidate(0x1000, "bar", 0.9));
        session.apply_batch();
        assert!(!session.conflicts.is_clean());
    }
}
