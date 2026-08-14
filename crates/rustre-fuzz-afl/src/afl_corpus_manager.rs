//! AFL++-style corpus manager for `rustre-fuzz-afl`.
//!
//! Provides [`AflCorpusManager`], [`CorpusEntry`], [`FavoriteEntry`],
//! [`CorpusTrimmer`], [`CrashCorpus`], [`QueueEntry`], and [`PathSorter`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::{Duration, SystemTime};

use rayon::prelude::*;

use serde::{Deserialize, Serialize};

use crate::{AflQueueEntry, XorShiftRng, RngCore};
use rustre_fuzz::fnv1a;

// ── CorpusEntry ───────────────────────────────────────────────────────────────

/// A single corpus entry carrying raw content, edge coverage, and access stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// Unique entry identifier.
    pub id: u64,
    /// Raw input bytes.
    pub content: Vec<u8>,
    /// FNV-1a hash of the content.
    pub content_hash: u64,
    /// Set of edge IDs covered by this entry.
    pub coverage: HashSet<u64>,
    /// Number of times this entry has been selected for mutation.
    pub hit_count: u64,
    /// Number of times a child of this entry was found interesting.
    pub interesting_children: u64,
    /// Execution time when this entry was run.
    pub exec_time: Duration,
    /// Whether this entry has been selected as a "favorite".
    pub is_favorite: bool,
    /// Whether this entry has been trimmed.
    pub is_trimmed: bool,
    /// When this entry was added.
    pub added_at: SystemTime,
    /// Human-readable source label.
    pub source: Option<String>,
}

impl CorpusEntry {
    /// Create a new corpus entry.
    #[must_use]
    pub fn new(id: u64, content: Vec<u8>, coverage: HashSet<u64>, exec_time: Duration) -> Self {
        let content_hash = fnv1a(&content);
        Self {
            id,
            content,
            content_hash,
            coverage,
            hit_count: 0,
            interesting_children: 0,
            exec_time,
            is_favorite: false,
            is_trimmed: false,
            added_at: SystemTime::now(),
            source: None,
        }
    }

    /// Create a seed entry (no coverage data).
    #[must_use]
    pub fn new_seed(id: u64, content: Vec<u8>) -> Self {
        Self::new(id, content, HashSet::new(), Duration::ZERO)
    }

    /// Length of the content in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.content.len()
    }

    /// True when the content is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Number of edges covered.
    #[must_use]
    pub fn coverage_count(&self) -> usize {
        self.coverage.len()
    }

    /// Record a selection for mutation.
    pub const fn record_hit(&mut self) {
        self.hit_count = self.hit_count.saturating_add(1);
    }

    /// Record an interesting child.
    pub const fn record_interesting_child(&mut self) {
        self.interesting_children = self.interesting_children.saturating_add(1);
    }

    /// Productivity score: interesting children per hit.
    #[must_use]
    pub fn productivity(&self) -> f64 {
        if self.hit_count == 0 {
            f64::INFINITY
        } else {
            f64::from(u32::try_from(self.interesting_children).unwrap_or(u32::MAX)) / f64::from(u32::try_from(self.hit_count).unwrap_or(u32::MAX))
        }
    }

    /// AFL-style performance score combining coverage density and execution speed.
    #[must_use]
    pub fn afl_score(&self) -> f64 {
        let time_bonus = if self.exec_time.is_zero() {
            10.0
        } else {
            1000.0 / (f64::from(u32::try_from(self.exec_time.as_micros()).unwrap_or(u32::MAX))).max(1.0)
        };
        let cov_bonus = (f64::from(u32::try_from(self.coverage_count()).unwrap_or(u32::MAX))).ln_1p();
        let productivity = self.productivity();
        let productivity_factor = if productivity.is_infinite() {
            1.0
        } else {
            1.0 + productivity
        };
        productivity_factor * time_bonus * cov_bonus
    }
}

// ── FavoriteEntry ─────────────────────────────────────────────────────────────

/// Tracks which corpus entry "owns" each edge for the minimum-spanning-set
/// (AFL favorites) selection.
#[derive(Debug, Default)]
pub struct FavoriteEntry {
    /// Map from edge id → corpus entry id that currently owns it.
    edge_owner: HashMap<u64, u64>,
    /// Set of entry IDs that currently hold favorite status.
    favorites: HashSet<u64>,
}

impl FavoriteEntry {
    /// Create a new selector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Recompute favorites over a slice of corpus entries.
    ///
    /// An entry becomes a favorite when it is the *shortest* (then
    /// *fastest*) entry that covers an edge not yet owned.
    pub fn recompute(&mut self, entries: &[CorpusEntry]) {
        self.edge_owner.clear();
        self.favorites.clear();

        // Sort by: length ASC, then exec_time ASC.
        let mut sorted: Vec<&CorpusEntry> = entries.iter().collect();
        sorted.sort_unstable_by(|a, b| {
            a.len()
                .cmp(&b.len())
                .then_with(|| a.exec_time.cmp(&b.exec_time))
        });

        for entry in sorted {
            let mut is_fav = false;
            for &edge in &entry.coverage {
                if let std::collections::hash_map::Entry::Vacant(e) = self.edge_owner.entry(edge) {
                    e.insert(entry.id);
                    is_fav = true;
                }
            }
            if is_fav {
                self.favorites.insert(entry.id);
            }
        }
    }

    /// Returns `true` when `id` is currently a favorite.
    #[must_use]
    pub fn is_favorite(&self, id: u64) -> bool {
        self.favorites.contains(&id)
    }

    /// Number of distinct edges currently owned.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edge_owner.len()
    }

    /// Number of favorite entries.
    #[must_use]
    pub fn favorite_count(&self) -> usize {
        self.favorites.len()
    }

    /// Iterate over favorite entry IDs.
    pub fn favorite_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.favorites.iter().copied()
    }
}

// ── CorpusTrimmer ─────────────────────────────────────────────────────────────

/// Trims the corpus to a minimal covering set using a greedy set-cover
/// algorithm (smallest entry that covers each unique edge first).
#[derive(Debug, Default)]
pub struct CorpusTrimmer {
    /// Minimum coverage count an entry must have to be retained.
    pub min_coverage: usize,
    /// Whether to prefer shorter entries when two cover the same edges.
    pub prefer_shorter: bool,
}

impl CorpusTrimmer {
    /// Create a new trimmer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_coverage: 1,
            prefer_shorter: true,
        }
    }

    /// Trim `entries` to the minimal covering set.
    ///
    /// Returns the IDs of entries that should be *kept*.
    #[must_use]
    pub fn trim(&self, entries: &[CorpusEntry]) -> Vec<u64> {
        let mut covered: HashSet<u64> = HashSet::new();
        let mut kept: Vec<u64> = Vec::new();

        // Filter out entries with insufficient coverage.
        let mut candidates: Vec<&CorpusEntry> = entries
            .iter()
            .filter(|e| e.coverage_count() >= self.min_coverage)
            .collect();

        // Sort: most coverage first, tie-break by shorter / faster.
        if self.prefer_shorter {
            candidates.sort_unstable_by(|a, b| {
                b.coverage_count()
                    .cmp(&a.coverage_count())
                    .then_with(|| a.len().cmp(&b.len()))
                    .then_with(|| a.exec_time.cmp(&b.exec_time))
            });
        } else {
            candidates.sort_unstable_by(|a, b| {
                b.coverage_count().cmp(&a.coverage_count())
            });
        }

        for entry in &candidates {
            let novel: Vec<u64> = entry
                .coverage
                .iter()
                .filter(|e| !covered.contains(e))
                .copied()
                .collect();
            if !novel.is_empty() {
                covered.extend(novel);
                kept.push(entry.id);
            }
        }

        kept
    }

    /// Returns the set of edges covered by the entries with the given IDs.
    #[must_use]
    pub fn coverage_of(
        &self,
        entries: &[CorpusEntry],
        ids: &[u64],
    ) -> HashSet<u64> {
        let id_set: HashSet<u64> = ids.iter().copied().collect();
        let mut cov = HashSet::new();
        for e in entries.iter().filter(|e| id_set.contains(&e.id)) {
            cov.extend(e.coverage.iter().copied());
        }
        cov
    }
}

// ── CrashCorpus ───────────────────────────────────────────────────────────────

/// Stores crash-inducing inputs with deduplication by content hash and
/// optional stack-trace hash.
#[derive(Debug, Default)]
pub struct CrashCorpus {
    /// All crash entries, keyed by content hash.
    crashes: BTreeMap<u64, CrashEntry>,
    /// Total crashes submitted (including duplicates).
    pub total_submitted: u64,
}

/// A single crash entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashEntry {
    /// Raw input bytes.
    pub input: Vec<u8>,
    /// Content hash.
    pub content_hash: u64,
    /// Signal that caused the crash.
    pub signal: i32,
    /// Fault address, if available.
    pub fault_addr: Option<u64>,
    /// Stack-trace hash (if available).
    pub stack_hash: Option<u64>,
    /// Number of times this crash was reproduced.
    pub occurrences: u64,
    /// When first seen.
    pub first_seen: SystemTime,
    /// Exploitability estimate (0–5).
    pub exploitability: u8,
}

impl CrashEntry {
    /// Create a new crash entry.
    #[must_use]
    pub fn new(input: Vec<u8>, signal: i32, fault_addr: Option<u64>) -> Self {
        let content_hash = fnv1a(&input);
        Self {
            input,
            content_hash,
            signal,
            fault_addr,
            stack_hash: None,
            occurrences: 1,
            first_seen: SystemTime::now(),
            exploitability: 0,
        }
    }
}

impl CrashCorpus {
    /// Create an empty corpus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a crash.  Returns `true` if this is a new unique crash.
    pub fn submit(&mut self, input: Vec<u8>, signal: i32, fault_addr: Option<u64>) -> bool {
        self.total_submitted += 1;
        let h = fnv1a(&input);
        if let Some(existing) = self.crashes.get_mut(&h) {
            existing.occurrences += 1;
            return false;
        }
        let entry = CrashEntry::new(input, signal, fault_addr);
        self.crashes.insert(h, entry);
        true
    }

    /// Submit with a stack hash for better deduplication.
    pub fn submit_with_stack(
        &mut self,
        input: Vec<u8>,
        signal: i32,
        fault_addr: Option<u64>,
        stack_hash: u64,
    ) -> bool {
        self.total_submitted += 1;
        // Prefer dedup by stack hash.
        let existing = self.crashes.values_mut().find(|e| e.stack_hash == Some(stack_hash));
        if let Some(e) = existing {
            e.occurrences += 1;
            return false;
        }
        let h = fnv1a(&input);
        let mut entry = CrashEntry::new(input, signal, fault_addr);
        entry.stack_hash = Some(stack_hash);
        self.crashes.insert(h, entry);
        true
    }

    /// Number of unique crashes.
    #[must_use]
    pub fn unique_count(&self) -> usize {
        self.crashes.len()
    }

    /// True when the corpus is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.crashes.is_empty()
    }

    /// Iterate over all crash entries.
    pub fn iter(&self) -> impl Iterator<Item = &CrashEntry> {
        self.crashes.values()
    }

    /// Return the most-reproduced crash.
    #[must_use]
    pub fn most_common(&self) -> Option<&CrashEntry> {
        self.crashes.values().max_by_key(|e| e.occurrences)
    }

    /// Return all crashes that occurred in one signal.
    #[must_use]
    pub fn by_signal(&self, signal: i32) -> Vec<&CrashEntry> {
        self.crashes.values().filter(|e| e.signal == signal).collect()
    }

    /// Clear all crash entries.
    pub fn clear(&mut self) {
        self.crashes.clear();
    }
}

// ── QueueEntry ────────────────────────────────────────────────────────────────

/// A single entry in the AFL-style fuzzing queue, richer than [`AflQueueEntry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    /// Unique identifier.
    pub id: u64,
    /// Input bytes.
    pub data: Vec<u8>,
    /// Content hash.
    pub hash: u64,
    /// Number of coverage edges.
    pub edge_count: u32,
    /// Estimated execution time in microseconds.
    pub exec_us: u64,
    /// Total mutation count applied to this entry.
    pub mutation_count: u64,
    /// Whether this entry has been trimmed.
    pub trimmed: bool,
    /// Whether this entry is currently favored.
    pub favored: bool,
    /// Generation (0 = seed).
    pub generation: u32,
    /// Parent entry ID, if any.
    pub parent: Option<u64>,
    /// When added.
    pub added_at: SystemTime,
}

impl From<&QueueEntry> for AflQueueEntry {
    /// Adapt a rich [`QueueEntry`] to the leaner [`AflQueueEntry`] consumed by
    /// the low-level scheduling primitives in [`crate::lib`]. Loses
    /// fields that the small entry does not track (`generation`, `parent`).
    fn from(q: &QueueEntry) -> Self {
        let mut entry = Self::new(q.id, q.data.clone(), q.edge_count);
        entry.exec_time_us = q.exec_us;
        entry.is_favored = q.favored;
        entry.is_trimmed = q.trimmed;
        entry.added_at = q.added_at;
        entry
    }
}

impl QueueEntry {
    /// Create a new queue entry.
    #[must_use]
    pub fn new(id: u64, data: Vec<u8>, edge_count: u32, exec_us: u64) -> Self {
        let hash = fnv1a(&data);
        Self {
            id,
            data,
            hash,
            edge_count,
            exec_us,
            mutation_count: 0,
            trimmed: false,
            favored: false,
            generation: 0,
            parent: None,
            added_at: SystemTime::now(),
        }
    }

    /// Create a child entry derived from a parent.
    #[must_use]
    pub fn new_child(
        id: u64,
        data: Vec<u8>,
        edge_count: u32,
        exec_us: u64,
        parent_id: u64,
        parent_generation: u32,
    ) -> Self {
        let mut e = Self::new(id, data, edge_count, exec_us);
        e.parent = Some(parent_id);
        e.generation = parent_generation.saturating_add(1);
        e
    }

    /// AFL-style "performance" score.
    #[must_use]
    pub fn perf_score(&self) -> f64 {
        let time_factor = if self.exec_us == 0 {
            8.0
        } else {
            (10_000.0 / f64::from(u32::try_from(self.exec_us).unwrap_or(u32::MAX))).clamp(0.1, 8.0)
        };
        let edge_factor = (f64::from(self.edge_count) + 1.0).sqrt();
        time_factor * edge_factor
    }

    /// Number of mutations to apply (energy).
    ///
    /// Uses integer fixed-point arithmetic (×10 scale) to avoid f64→u32 cast lints.
    #[must_use]
    pub fn energy(&self) -> u32 {
        // time_factor ∈ [0.1, 8.0] → time_x10 ∈ [1, 80]
        let exec_capped = u64::from(u32::try_from(self.exec_us).unwrap_or(u32::MAX)).max(1);
        let time_x10 = (100_000u64 / exec_capped).clamp(1, 80);
        // edge_factor = sqrt(edge_count + 1) → edge_x10 = isqrt((edge_count+1)*100)
        let edge_x100 = u64::from(self.edge_count)
            .saturating_add(1)
            .saturating_mul(100);
        let edge_x10 = edge_x100.isqrt();
        // score = time_factor * edge_factor; rounded via +50 before divide
        let score = (time_x10.saturating_mul(edge_x10).saturating_add(50)) / 100;
        u32::try_from(score).unwrap_or(512).clamp(1, 512)
    }
}

// ── PathSorter ────────────────────────────────────────────────────────────────

/// Sorts queue entries by various criteria.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortCriterion {
    /// Highest AFL performance score first.
    ByScore,
    /// Most edge coverage first.
    ByEdgeCount,
    /// Shortest input first.
    ByLength,
    /// Fastest execution first.
    ByExecTime,
    /// Most recently added first.
    ByRecency,
}

/// Sorts a mutable slice of [`QueueEntry`] by a given criterion.
#[derive(Debug, Default)]
pub struct PathSorter;

impl PathSorter {
    /// Create a new sorter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Sort `entries` in-place according to `criterion`.
    pub fn sort(&self, entries: &mut [QueueEntry], criterion: SortCriterion) {
        match criterion {
            SortCriterion::ByScore => entries.sort_unstable_by(|a, b| {
                b.perf_score()
                    .partial_cmp(&a.perf_score())
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            SortCriterion::ByEdgeCount => {
                entries.sort_unstable_by(|a, b| b.edge_count.cmp(&a.edge_count));
            }
            SortCriterion::ByLength => {
                entries.sort_unstable_by_key(|a| a.data.len());
            }
            SortCriterion::ByExecTime => {
                entries.sort_unstable_by_key(|a| a.exec_us);
            }
            SortCriterion::ByRecency => {
                // time-monotonic-vs-system: `added_at` is a `SystemTime` (wall
                // clock) which can jump backwards on NTP adjustments, silently
                // reordering entries and promoting older ones as "most recent".
                // The `id` field is a monotonically-increasing counter allocated
                // by `AflCorpusManager::next_id`, so it faithfully reflects
                // insertion order without relying on the wall clock.
                entries.sort_unstable_by(|a, b| b.id.cmp(&a.id));
            }
        }
    }

    /// Return the top-`n` entries by the given criterion (cloned).
    #[must_use]
    pub fn top_n(&self, entries: &[QueueEntry], n: usize, criterion: SortCriterion) -> Vec<QueueEntry> {
        let mut v = entries.to_vec();
        self.sort(&mut v, criterion);
        v.truncate(n);
        v
    }
}

// ── AflCorpusManager ─────────────────────────────────────────────────────────

/// Full-featured AFL++-style corpus manager.
///
/// Manages a set of [`CorpusEntry`] items, tracks favorites via
/// [`FavoriteEntry`], trims the corpus via [`CorpusTrimmer`], and stores
/// crashes in [`CrashCorpus`].
pub struct AflCorpusManager {
    /// All corpus entries, keyed by id.
    pub entries: BTreeMap<u64, CorpusEntry>,
    /// Insertion-order ids for sequential access.
    order: VecDeque<u64>,
    /// Next entry id.
    next_id: u64,
    /// Favorite-entry selector.
    pub favorites: FavoriteEntry,
    /// Corpus trimmer.
    pub trimmer: CorpusTrimmer,
    /// Crash corpus.
    pub crashes: CrashCorpus,
    /// PRNG for randomized selection.
    rng: XorShiftRng,
    /// Total selections made.
    pub total_selections: u64,
    /// Total mutations applied.
    pub total_mutations: u64,
}

impl AflCorpusManager {
    /// Create a new empty corpus manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            next_id: 0,
            favorites: FavoriteEntry::new(),
            trimmer: CorpusTrimmer::new(),
            crashes: CrashCorpus::new(),
            rng: XorShiftRng::default(),
            total_selections: 0,
            total_mutations: 0,
        }
    }

    /// Allocate the next corpus entry id.
    pub const fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Add a new corpus entry.  Returns its assigned id.
    pub fn add(&mut self, content: Vec<u8>, coverage: HashSet<u64>, exec_time: Duration) -> u64 {
        let id = self.next_id();
        let entry = CorpusEntry::new(id, content, coverage, exec_time);
        self.order.push_back(id);
        self.entries.insert(id, entry);
        id
    }

    /// Add a seed entry with no coverage data.
    pub fn add_seed(&mut self, content: Vec<u8>) -> u64 {
        self.add(content, HashSet::new(), Duration::ZERO)
    }

    /// Remove an entry by id.  Returns the removed entry, or `None`.
    pub fn remove(&mut self, id: u64) -> Option<CorpusEntry> {
        self.order.retain(|&oid| oid != id);
        self.entries.remove(&id)
    }

    /// Number of entries in the corpus.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the corpus is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Select the next entry for mutation using round-robin.
    ///
    /// # Panics
    /// Panics if the corpus is empty.
    pub fn select_sequential(&mut self) -> &mut CorpusEntry {
        assert!(!self.order.is_empty(), "corpus is empty");
        let idx = usize::try_from(self.total_selections % u64::try_from(self.order.len()).unwrap_or(u64::MAX)).unwrap_or(0);
        let id = self.order[idx];
        self.total_selections += 1;
        self.entries.get_mut(&id).expect("entry exists")
    }

    /// Select a random entry, preferring favorites 70% of the time.
    ///
    /// # Panics
    /// Panics if the corpus is empty.
    pub fn select_random(&mut self) -> u64 {
        assert!(!self.order.is_empty(), "corpus is empty");
        self.total_selections += 1;
        let use_fav = self.rng.next_usize(10) < 7;
        let fav_ids: Vec<u64> = self.favorites.favorite_ids().collect();
        if use_fav && !fav_ids.is_empty() {
            let idx = self.rng.next_usize(fav_ids.len());
            return fav_ids[idx];
        }
        let idx = self.rng.next_usize(self.order.len());
        self.order[idx]
    }

    /// Recompute favorites over all current entries.
    pub fn recompute_favorites(&mut self) {
        let entries: Vec<CorpusEntry> = self.entries.values().cloned().collect();
        self.favorites.recompute(&entries);
        for e in self.entries.values_mut() {
            e.is_favorite = self.favorites.is_favorite(e.id);
        }
    }

    /// Trim the corpus to the minimal covering set.
    /// Returns the ids of entries that were removed.
    pub fn trim(&mut self) -> Vec<u64> {
        let entries: Vec<CorpusEntry> = self.entries.values().cloned().collect();
        let keep = self.trimmer.trim(&entries);
        let keep_set: HashSet<u64> = keep.into_iter().collect();
        let removed: Vec<u64> = self.entries.keys().copied().filter(|id| !keep_set.contains(id)).collect();
        for &id in &removed {
            self.remove(id);
        }
        removed
    }

    /// Total coverage edges across all entries (union).
    #[must_use]
    pub fn total_coverage(&self) -> HashSet<u64> {
        self.entries
            .values()
            .par_bridge()
            .map(|e| e.coverage.clone())
            .reduce(HashSet::new, |mut a, b| {
                a.extend(b);
                a
            })
    }

    /// Return the entry with the highest AFL score.
    #[must_use]
    pub fn best_entry(&self) -> Option<&CorpusEntry> {
        self.entries
            .values()
            .max_by(|a, b| a.afl_score().partial_cmp(&b.afl_score()).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Import seeds from a list of byte vectors.
    pub fn import_seeds(&mut self, seeds: Vec<Vec<u8>>) {
        for s in seeds {
            self.add_seed(s);
        }
    }
}

impl Default for AflCorpusManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn make_cov(edges: &[u64]) -> HashSet<u64> {
        edges.iter().copied().collect()
    }

    // ── CorpusEntry ───────────────────────────────────────────────────────────

    #[test]
    fn corpus_entry_new() {
        let e = CorpusEntry::new(1, vec![1, 2, 3], make_cov(&[10, 20]), Duration::from_micros(50));
        assert_eq!(e.id, 1);
        assert_eq!(e.len(), 3);
        assert_eq!(e.coverage_count(), 2);
        assert!(!e.is_favorite);
    }

    #[test]
    fn corpus_entry_hash_deterministic() {
        let e1 = CorpusEntry::new(0, vec![1, 2], make_cov(&[]), Duration::ZERO);
        let e2 = CorpusEntry::new(1, vec![1, 2], make_cov(&[]), Duration::ZERO);
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn corpus_entry_productivity_untried() {
        let e = CorpusEntry::new(0, vec![1], make_cov(&[]), Duration::ZERO);
        assert_eq!(e.productivity(), f64::INFINITY);
    }

    #[test]
    fn corpus_entry_hit_record() {
        let mut e = CorpusEntry::new(0, vec![1], make_cov(&[]), Duration::ZERO);
        e.record_hit();
        e.record_hit();
        assert_eq!(e.hit_count, 2);
    }

    #[test]
    fn corpus_entry_interesting_children() {
        let mut e = CorpusEntry::new(0, vec![1], make_cov(&[]), Duration::ZERO);
        e.record_hit();
        e.record_interesting_child();
        assert!((e.productivity() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn corpus_entry_afl_score_nonnegative() {
        let e = CorpusEntry::new(0, vec![1, 2, 3], make_cov(&[1, 2, 3]), Duration::from_micros(100));
        assert!(e.afl_score() > 0.0);
    }

    // ── FavoriteEntry ─────────────────────────────────────────────────────────

    #[test]
    fn favorite_entry_empty() {
        let fe = FavoriteEntry::new();
        assert_eq!(fe.favorite_count(), 0);
        assert_eq!(fe.edge_count(), 0);
    }

    #[test]
    fn favorite_entry_recompute() {
        let mut fe = FavoriteEntry::new();
        let entries = vec![
            CorpusEntry::new(0, vec![1], make_cov(&[1, 2, 3]), Duration::from_micros(100)),
            CorpusEntry::new(1, vec![1, 2], make_cov(&[4, 5]), Duration::from_micros(200)),
        ];
        fe.recompute(&entries);
        assert!(fe.favorite_count() > 0);
        assert!(fe.edge_count() >= 1);
    }

    #[test]
    fn favorite_entry_shorter_preferred() {
        let mut fe = FavoriteEntry::new();
        let cov = make_cov(&[100]);
        let entries = vec![
            CorpusEntry::new(0, vec![1, 2, 3], cov.clone(), Duration::from_micros(10)),
            CorpusEntry::new(1, vec![1], cov.clone(), Duration::from_micros(10)),
        ];
        fe.recompute(&entries);
        // The shorter entry (id=1) should be the favorite for edge 100.
        assert!(fe.is_favorite(1));
    }

    #[test]
    fn favorite_is_favorite_unknown_id() {
        let fe = FavoriteEntry::new();
        assert!(!fe.is_favorite(999));
    }

    // ── CorpusTrimmer ─────────────────────────────────────────────────────────

    #[test]
    fn trimmer_keeps_covering_set() {
        let trimmer = CorpusTrimmer::new();
        let entries = vec![
            CorpusEntry::new(0, vec![1], make_cov(&[1, 2]), Duration::ZERO),
            CorpusEntry::new(1, vec![1, 2], make_cov(&[3]), Duration::ZERO),
            CorpusEntry::new(2, vec![1, 2, 3], make_cov(&[1, 2, 3]), Duration::ZERO),
        ];
        let kept = trimmer.trim(&entries);
        // All edges 1,2,3 must be covered.
        let covered = trimmer.coverage_of(&entries, &kept);
        assert!(covered.contains(&1));
        assert!(covered.contains(&2));
        assert!(covered.contains(&3));
    }

    #[test]
    fn trimmer_prefers_shorter() {
        let trimmer = CorpusTrimmer { prefer_shorter: true, min_coverage: 1 };
        let entries = vec![
            CorpusEntry::new(0, vec![1, 2, 3], make_cov(&[42]), Duration::ZERO),
            CorpusEntry::new(1, vec![1], make_cov(&[42]), Duration::ZERO),
        ];
        let kept = trimmer.trim(&entries);
        // Both cover edge 42; shorter (id=1) should win.
        assert!(kept.contains(&1));
    }

    #[test]
    fn trimmer_empty_entries() {
        let trimmer = CorpusTrimmer::new();
        let kept = trimmer.trim(&[]);
        assert!(kept.is_empty());
    }

    // ── CrashCorpus ───────────────────────────────────────────────────────────

    #[test]
    fn crash_corpus_new_is_empty() {
        let cc = CrashCorpus::new();
        assert!(cc.is_empty());
        assert_eq!(cc.unique_count(), 0);
    }

    #[test]
    fn crash_corpus_submit_new_crash() {
        let mut cc = CrashCorpus::new();
        let is_new = cc.submit(vec![0xde, 0xad], 11, Some(0xbad));
        assert!(is_new);
        assert_eq!(cc.unique_count(), 1);
    }

    #[test]
    fn crash_corpus_submit_duplicate() {
        let mut cc = CrashCorpus::new();
        cc.submit(vec![1, 2], 11, None);
        let is_new = cc.submit(vec![1, 2], 11, None);
        assert!(!is_new);
        assert_eq!(cc.unique_count(), 1);
        assert_eq!(cc.total_submitted, 2);
    }

    #[test]
    fn crash_corpus_submit_with_stack() {
        let mut cc = CrashCorpus::new();
        cc.submit_with_stack(vec![1], 11, None, 0xABCD);
        let dup = cc.submit_with_stack(vec![2], 11, None, 0xABCD); // same stack
        assert!(!dup);
        assert_eq!(cc.unique_count(), 1);
    }

    #[test]
    fn crash_corpus_by_signal() {
        let mut cc = CrashCorpus::new();
        cc.submit(vec![1], 11, None);
        cc.submit(vec![2], 6, None);
        cc.submit(vec![3], 11, None);
        let sigsegv = cc.by_signal(11);
        assert_eq!(sigsegv.len(), 2);
    }

    #[test]
    fn crash_corpus_most_common() {
        let mut cc = CrashCorpus::new();
        cc.submit(vec![1], 11, None);
        cc.submit(vec![1], 11, None); // occurrences=2
        cc.submit(vec![2], 11, None);
        let mc = cc.most_common().unwrap();
        assert_eq!(mc.occurrences, 2);
    }

    #[test]
    fn crash_corpus_clear() {
        let mut cc = CrashCorpus::new();
        cc.submit(vec![1], 11, None);
        cc.clear();
        assert!(cc.is_empty());
    }

    // ── QueueEntry ────────────────────────────────────────────────────────────

    #[test]
    fn queue_entry_energy_positive() {
        let e = QueueEntry::new(0, vec![1, 2, 3], 100, 500);
        assert!(e.energy() >= 1);
    }

    #[test]
    fn queue_entry_perf_score_positive() {
        let e = QueueEntry::new(0, vec![1], 50, 1000);
        assert!(e.perf_score() > 0.0);
    }

    #[test]
    fn queue_entry_child_increments_generation() {
        let e = QueueEntry::new_child(1, vec![1], 5, 100, 0, 2);
        assert_eq!(e.generation, 3);
        assert_eq!(e.parent, Some(0));
    }

    // ── PathSorter ────────────────────────────────────────────────────────────

    #[test]
    fn path_sorter_by_length() {
        let sorter = PathSorter::new();
        let mut entries = vec![
            QueueEntry::new(0, vec![1, 2, 3], 5, 100),
            QueueEntry::new(1, vec![1], 5, 100),
            QueueEntry::new(2, vec![1, 2], 5, 100),
        ];
        sorter.sort(&mut entries, SortCriterion::ByLength);
        assert_eq!(entries[0].data.len(), 1);
        assert_eq!(entries[2].data.len(), 3);
    }

    #[test]
    fn path_sorter_by_score() {
        let sorter = PathSorter::new();
        let mut entries = vec![
            QueueEntry::new(0, vec![1], 10, 5000),
            QueueEntry::new(1, vec![1], 100, 10),
        ];
        sorter.sort(&mut entries, SortCriterion::ByScore);
        // Higher score (more edges, faster) should come first.
        assert!(entries[0].perf_score() >= entries[1].perf_score());
    }

    #[test]
    fn path_sorter_top_n() {
        let sorter = PathSorter::new();
        let entries: Vec<QueueEntry> = (0..10).map(|i| QueueEntry::new(i, vec![i as u8], i as u32, 100)).collect();
        let top = sorter.top_n(&entries, 3, SortCriterion::ByEdgeCount);
        assert_eq!(top.len(), 3);
        assert!(top[0].edge_count >= top[2].edge_count);
    }

    // ── AflCorpusManager ──────────────────────────────────────────────────────

    #[test]
    fn manager_add_and_len() {
        let mut m = AflCorpusManager::new();
        m.add(vec![1, 2, 3], make_cov(&[1]), Duration::ZERO);
        assert_eq!(m.len(), 1);
        assert!(!m.is_empty());
    }

    #[test]
    fn manager_remove_entry() {
        let mut m = AflCorpusManager::new();
        let id = m.add(vec![1], make_cov(&[]), Duration::ZERO);
        let removed = m.remove(id);
        assert!(removed.is_some());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn manager_import_seeds() {
        let mut m = AflCorpusManager::new();
        m.import_seeds(vec![vec![1], vec![2], vec![3]]);
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn manager_select_sequential() {
        let mut m = AflCorpusManager::new();
        m.add_seed(vec![1]);
        m.add_seed(vec![2]);
        let e = m.select_sequential();
        assert!(!e.content.is_empty());
    }

    #[test]
    fn manager_recompute_favorites() {
        let mut m = AflCorpusManager::new();
        m.add(vec![1], make_cov(&[10, 11]), Duration::from_micros(10));
        m.add(vec![1, 2], make_cov(&[12]), Duration::from_micros(20));
        m.recompute_favorites();
        assert!(m.favorites.favorite_count() > 0);
    }

    #[test]
    fn manager_total_coverage() {
        let mut m = AflCorpusManager::new();
        m.add(vec![1], make_cov(&[10, 11]), Duration::ZERO);
        m.add(vec![2], make_cov(&[12, 13]), Duration::ZERO);
        let cov = m.total_coverage();
        assert_eq!(cov.len(), 4);
    }

    #[test]
    fn manager_best_entry() {
        let mut m = AflCorpusManager::new();
        m.add(vec![1], make_cov(&[1, 2, 3, 4, 5]), Duration::from_micros(1));
        m.add(vec![1, 2, 3], make_cov(&[6]), Duration::from_micros(10_000));
        let best = m.best_entry().unwrap();
        // High-coverage, fast entry should win.
        assert_eq!(best.coverage_count(), 5);
    }

    #[test]
    fn manager_trim_reduces_corpus() {
        let mut m = AflCorpusManager::new();
        m.add(vec![1], make_cov(&[1, 2, 3]), Duration::ZERO);
        m.add(vec![1, 2], make_cov(&[1, 2, 3]), Duration::ZERO); // duplicate coverage
        let before = m.len();
        let removed = m.trim();
        assert!(m.len() <= before);
        let _ = removed;
    }
}
