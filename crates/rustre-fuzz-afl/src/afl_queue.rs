/// AFL++ fuzzing queue with prioritization and the favor system.
///
/// The queue holds every test case that produced new coverage. Each entry is
/// assigned a "score" used to decide which inputs to fuzz next (the "favor"
/// system). Entries with smaller input size and shorter execution time are
/// preferred. This module provides:
///
/// - `QueueEntry` — metadata for one test case
/// - `FavorAlgorithm` — scoring strategy variants
/// - `AflQueue` — the full queue with cycling, skipping, and statistics
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::time::Duration;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueueError {
    #[error("queue is empty")]
    Empty,
    #[error("entry id {0} not found")]
    EntryNotFound(u64),
    #[error("cycle limit {0} reached")]
    CycleLimitReached(u64),
    #[error("duplicate entry id {0}")]
    DuplicateId(u64),
}

// ---------------------------------------------------------------------------
// QueueEntry
// ---------------------------------------------------------------------------

/// Metadata for a single fuzzing queue entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueEntry {
    /// Unique monotonically increasing ID.
    pub id: u64,
    /// The input bytes.
    pub input: Vec<u8>,
    /// Execution time of the first run that produced this entry.
    pub exec_us: u64,
    /// Number of edges covered by this input (from the bitmap).
    pub bitmap_size: usize,
    /// Number of times this entry has been fuzzed.
    pub fuzz_count: u64,
    /// Number of new coverage bits discovered via this entry.
    pub new_cov: usize,
    /// Whether this entry is marked as a "favored" entry for the current cycle.
    pub favored: bool,
    /// Whether this entry has been trimmed to minimal size.
    pub trimmed: bool,
    /// Optional human-readable label (e.g. crash-inducing description).
    pub label: Option<String>,
    /// Depth in the mutation tree (0 = seed, 1 = direct child, …).
    pub depth: u32,
    /// Parent entry ID, if this was mutated from another entry.
    pub parent_id: Option<u64>,
}

impl QueueEntry {
    #[must_use] 
    pub const fn new(id: u64, input: Vec<u8>, exec_us: u64, bitmap_size: usize) -> Self {
        Self {
            id,
            input,
            exec_us,
            bitmap_size,
            fuzz_count: 0,
            new_cov: 0,
            favored: false,
            trimmed: false,
            label: None,
            depth: 0,
            parent_id: None,
        }
    }

    /// Score used for the favor algorithm: lower is better.
    /// Based on AFL's `calculate_score` but simplified.
    #[must_use] 
    pub fn raw_score(&self) -> f64 {
        if self.bitmap_size == 0 || self.exec_us == 0 {
            return f64::MAX;
        }
        f64::from(u32::try_from(self.exec_us).unwrap_or(u32::MAX))
            * f64::from(u32::try_from(self.input.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.bitmap_size).unwrap_or(u32::MAX))
    }
}

// ---------------------------------------------------------------------------
// FavorAlgorithm
// ---------------------------------------------------------------------------

/// Strategy used to select and mark favored entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum FavorAlgorithm {
    /// Classic AFL: prefer inputs with smaller size × execution time per coverage bit.
    #[default]
    Classic,
    /// Prefer entries with the most new unique edges.
    MaxNewEdges,
    /// Prefer entries at the shallowest depth in the mutation tree.
    ShallowDepth,
    /// Round-robin: no preference, cycle through all entries equally.
    RoundRobin,
}


// ---------------------------------------------------------------------------
// Internal scored entry for the priority queue
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ScoredEntry {
    score: u64, // integer score for BinaryHeap (lower = higher priority)
    id: u64,
}

impl PartialEq for ScoredEntry {
    fn eq(&self, other: &Self) -> bool { self.score == other.score }
}
impl Eq for ScoredEntry {}
impl PartialOrd for ScoredEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for ScoredEntry {
    // min-heap: lower score = higher priority
    fn cmp(&self, other: &Self) -> Ordering { other.score.cmp(&self.score) }
}

// ---------------------------------------------------------------------------
// QueueConfig
// ---------------------------------------------------------------------------

/// Configuration for the AFL queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    /// Maximum number of entries in the queue (0 = unlimited).
    pub max_entries: usize,
    /// How many consecutive unfavored entries to skip before forcing one.
    pub skip_ratio: u32,
    /// Favor algorithm to use.
    pub favor_algorithm: FavorAlgorithm,
    /// If `true`, once `max_entries` is reached, evict the lowest-scored entry.
    pub evict_on_overflow: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_entries: 0,
            skip_ratio: 9,
            favor_algorithm: FavorAlgorithm::Classic,
            evict_on_overflow: false,
        }
    }
}

// ---------------------------------------------------------------------------
// AflQueue — the main queue
// ---------------------------------------------------------------------------

/// AFL fuzzing queue.
///
/// Entries are kept in insertion order for cycling; a secondary priority queue
/// drives the favor selection pass.
pub struct AflQueue {
    config: QueueConfig,
    /// All entries keyed by ID.
    entries: HashMap<u64, QueueEntry>,
    /// Insertion-order IDs for deterministic cycling.
    order: VecDeque<u64>,
    /// Current cycle cursor (index into `order`).
    cursor: usize,
    /// Monotonically increasing ID counter.
    next_id: u64,
    /// How many full cycles have completed.
    cycle_count: u64,
    /// Stats.
    stats: QueueStats,
    /// Skip counter for unfavored entries.
    skip_counter: u32,
}

/// Runtime statistics for the queue.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub total_entries: u64,
    pub favored_entries: u64,
    pub total_fuzz_rounds: u64,
    pub skipped_unfavored: u64,
    pub evictions: u64,
    pub cycles_completed: u64,
}

impl AflQueue {
    #[must_use] 
    pub fn new(config: QueueConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            order: VecDeque::new(),
            cursor: 0,
            next_id: 0,
            cycle_count: 0,
            stats: QueueStats::default(),
            skip_counter: 0,
        }
    }

    // ------------------------------------------------------------------
    // Adding entries
    // ------------------------------------------------------------------

    /// Add a new entry to the queue. Returns the assigned ID.
    ///
    /// # Errors
    /// Returns [`QueueError::DuplicateId`] if the auto-assigned ID already exists,
    /// or [`QueueError`] from eviction on overflow.
    pub fn push(&mut self, mut entry: QueueEntry) -> Result<u64, QueueError> {
        let id = self.next_id;
        if self.entries.contains_key(&id) {
            return Err(QueueError::DuplicateId(id));
        }
        entry.id = id;
        self.next_id += 1;

        // Overflow eviction.
        if self.config.max_entries > 0
            && self.entries.len() >= self.config.max_entries
            && self.config.evict_on_overflow
        {
            self.evict_worst()?;
        }

        self.order.push_back(id);
        self.entries.insert(id, entry);
        self.stats.total_entries += 1;
        Ok(id)
    }

    /// Convenience: build and push a new entry, returning its ID.
    ///
    /// # Errors
    /// Returns [`QueueError`] if the push fails (duplicate ID or eviction error).
    pub fn add(
        &mut self,
        input: Vec<u8>,
        exec_us: u64,
        bitmap_size: usize,
    ) -> Result<u64, QueueError> {
        let entry = QueueEntry::new(0, input, exec_us, bitmap_size);
        self.push(entry)
    }

    // ------------------------------------------------------------------
    // Favor pass
    // ------------------------------------------------------------------

    /// Re-compute the favored flag for all entries according to the configured algorithm.
    pub fn update_favored(&mut self) {
        // Clear all favored flags first.
        for entry in self.entries.values_mut() {
            entry.favored = false;
        }

        match self.config.favor_algorithm {
            FavorAlgorithm::Classic => self.favor_classic(),
            FavorAlgorithm::MaxNewEdges => self.favor_max_new_edges(),
            FavorAlgorithm::ShallowDepth => self.favor_shallow_depth(),
            FavorAlgorithm::RoundRobin => {
                // All entries are equally favored in round-robin mode.
                for entry in self.entries.values_mut() {
                    entry.favored = true;
                }
            }
        }

        self.stats.favored_entries =
            self.entries.values().filter(|e| e.favored).count() as u64;
    }

    fn favor_classic(&mut self) {
        // Build a min-score priority queue.
        // Score = exec_us * input_len * 1_000_000 / bitmap_size (integer, scaled).
        // Use u128 arithmetic to avoid f64→u64 cast lints.
        let mut heap: BinaryHeap<ScoredEntry> = BinaryHeap::new();
        for entry in self.entries.values() {
            let score = {
                let eu = u128::from(u32::try_from(entry.exec_us).unwrap_or(u32::MAX));
                let ln = u128::from(u32::try_from(entry.input.len()).unwrap_or(u32::MAX));
                let bm = u128::from(u32::try_from(entry.bitmap_size).unwrap_or(u32::MAX)).max(1);
                if eu == 0 || bm == 0 {
                    u64::MAX
                } else {
                    u64::try_from(eu.saturating_mul(ln).saturating_mul(1_000_000u128) / bm)
                        .unwrap_or(u64::MAX)
                }
            };
            heap.push(ScoredEntry { score, id: entry.id });
        }

        // Mark top 30% as favored (minimum 1).
        let n_favor = (self.entries.len() * 3).div_ceil(10).max(1);
        let mut marked = 0;
        while let Some(se) = heap.pop() {
            if marked >= n_favor { break; }
            if let Some(e) = self.entries.get_mut(&se.id) {
                e.favored = true;
                marked += 1;
            }
        }
    }

    fn favor_max_new_edges(&mut self) {
        // Sort IDs by new_cov descending.
        let mut sorted: Vec<(u64, usize)> = self
            .entries
            .iter()
            .map(|(&id, e)| (id, e.new_cov))
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        let n_favor = (self.entries.len() * 3).div_ceil(10).max(1);
        for (id, _) in sorted.into_iter().take(n_favor) {
            if let Some(e) = self.entries.get_mut(&id) {
                e.favored = true;
            }
        }
    }

    fn favor_shallow_depth(&mut self) {
        let mut sorted: Vec<(u64, u32)> = self
            .entries
            .iter()
            .map(|(&id, e)| (id, e.depth))
            .collect();
        sorted.sort_by_key(|&(_, d)| d);
        let n_favor = (self.entries.len() * 3).div_ceil(10).max(1);
        for (id, _) in sorted.into_iter().take(n_favor) {
            if let Some(e) = self.entries.get_mut(&id) {
                e.favored = true;
            }
        }
    }

    // ------------------------------------------------------------------
    // Cycling
    // ------------------------------------------------------------------

    /// Get the next entry to fuzz, advancing the cursor. Applies the skip-ratio
    /// heuristic for unfavored entries. Returns `None` when the queue is exhausted
    /// for this cycle (call `finish_cycle()` to wrap around).
    pub fn advance(&mut self) -> Option<&mut QueueEntry> {
        if self.order.is_empty() {
            return None;
        }

        let mut found_id = None;
        while self.cursor < self.order.len() {
            let id = self.order[self.cursor];
            self.cursor += 1;

            let favored = self.entries.get(&id).is_some_and(|e| e.favored);
            if !favored {
                self.skip_counter += 1;
                if self.skip_counter < self.config.skip_ratio {
                    self.stats.skipped_unfavored += 1;
                    continue;
                }
                self.skip_counter = 0;
            }

            if self.entries.contains_key(&id) {
                found_id = Some(id);
                break;
            }
        }

        if let Some(id) = found_id
            && let Some(entry) = self.entries.get_mut(&id) {
                entry.fuzz_count += 1;
                self.stats.total_fuzz_rounds += 1;
                return Some(entry);
            }
        None
    }

    /// Wrap the cursor to start a new cycle. Returns the new cycle count.
    pub const fn finish_cycle(&mut self) -> u64 {
        self.cursor = 0;
        self.skip_counter = 0;
        self.cycle_count += 1;
        self.stats.cycles_completed += 1;
        self.cycle_count
    }

    /// Current cycle count (number of full cycles completed).
    #[must_use] 
    pub const fn cycle_count(&self) -> u64 {
        self.cycle_count
    }

    // ------------------------------------------------------------------
    // Access
    // ------------------------------------------------------------------

    #[must_use] 
    pub fn get(&self, id: u64) -> Option<&QueueEntry> {
        self.entries.get(&id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut QueueEntry> {
        self.entries.get_mut(&id)
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use] 
    pub const fn stats(&self) -> &QueueStats {
        &self.stats
    }

    /// Iterate all entries in insertion order.
    pub fn iter_ordered(&self) -> impl Iterator<Item = &QueueEntry> {
        self.order.iter().filter_map(|id| self.entries.get(id))
    }

    /// Collect favored entry IDs.
    #[must_use] 
    pub fn favored_ids(&self) -> Vec<u64> {
        self.entries
            .values()
            .filter(|e| e.favored)
            .map(|e| e.id)
            .collect()
    }

    // ------------------------------------------------------------------
    // Eviction
    // ------------------------------------------------------------------

    /// Evict the entry with the worst (highest) score.
    ///
    /// # Errors
    /// Returns [`QueueError::EntryNotFound`] if the entry was already removed.
    fn evict_worst(&mut self) -> Result<(), QueueError> {
        let worst_id = self
            .entries
            .iter()
            .max_by(|(_, a), (_, b)| a.raw_score().partial_cmp(&b.raw_score()).unwrap_or(Ordering::Equal))
            .map(|(&id, _)| id);

        if let Some(id) = worst_id {
            self.remove(id)?;
            self.stats.evictions += 1;
        }
        Ok(())
    }

    /// Remove an entry from the queue.
    ///
    /// # Errors
    ///
    /// Returns [`QueueError::EntryNotFound`] if `id` is not in the queue.
    pub fn remove(&mut self, id: u64) -> Result<(), QueueError> {
        if self.entries.remove(&id).is_none() {
            return Err(QueueError::EntryNotFound(id));
        }
        self.order.retain(|&x| x != id);
        // Adjust cursor if needed.
        if self.cursor > 0 {
            self.cursor = self.cursor.min(self.order.len());
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Corpus metrics
    // ------------------------------------------------------------------

    /// Mean execution time across all entries.
    #[must_use] 
    pub fn mean_exec_us(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.entries.values().map(|e| e.exec_us).sum();
        f64::from(u32::try_from(sum).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.entries.len()).unwrap_or(u32::MAX))
    }

    /// Total input bytes across all entries.
    #[must_use] 
    pub fn total_corpus_bytes(&self) -> usize {
        self.entries.values().map(|e| e.input.len()).sum()
    }

    /// Estimated time per cycle as a `Duration`.
    #[must_use] 
    pub fn estimated_cycle_time(&self) -> Duration {
        let total_us: u64 = self.entries.values().map(|e| e.exec_us).sum();
        Duration::from_micros(total_us)
    }

    /// Find the entry with the highest `new_cov` value.
    #[must_use] 
    pub fn top_coverage_entry(&self) -> Option<&QueueEntry> {
        self.entries.values().max_by_key(|e| e.new_cov)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_queue() -> AflQueue {
        AflQueue::new(QueueConfig::default())
    }

    #[test]
    fn test_push_and_len() {
        let mut q = make_queue();
        q.add(vec![0u8; 10], 100, 50).unwrap();
        q.add(vec![1u8; 20], 200, 30).unwrap();
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn test_cycling() {
        // Add 3 entries; all round-robin favored
        let mut cfg = QueueConfig::default();
        cfg.favor_algorithm = FavorAlgorithm::RoundRobin;
        let mut q = AflQueue::new(cfg);
        q.add(vec![0], 100, 10).unwrap();
        q.add(vec![1], 100, 10).unwrap();
        q.add(vec![2], 100, 10).unwrap();
        q.update_favored();
        let mut seen = Vec::new();
        while let Some(e) = q.advance() {
            seen.push(e.id);
        }
        assert_eq!(seen.len(), 3);
        assert_eq!(q.finish_cycle(), 1);
    }

    #[test]
    fn test_favor_classic_marks_top_30_pct() {
        let mut q = make_queue();
        for i in 0..10u64 {
            let mut e = QueueEntry::new(0, vec![0u8; (i + 1) as usize], i * 10 + 1, 10);
            e.bitmap_size = 10 + i as usize;
            q.push(e).unwrap();
        }
        q.update_favored();
        let favored = q.favored_ids().len();
        assert!(favored >= 1);
        assert!(favored <= 4); // 30% of 10 = 3, ceil = 3
    }

    #[test]
    fn test_eviction_on_overflow() {
        let cfg = QueueConfig {
            max_entries: 3,
            evict_on_overflow: true,
            ..Default::default()
        };
        let mut q = AflQueue::new(cfg);
        q.add(vec![0], 1000, 1).unwrap(); // worst score
        q.add(vec![0], 10, 100).unwrap();
        q.add(vec![0], 5, 200).unwrap();
        // Adding a 4th should evict the worst
        q.add(vec![0], 8, 150).unwrap();
        assert_eq!(q.len(), 3);
        assert_eq!(q.stats().evictions, 1);
    }

    #[test]
    fn test_remove_entry() {
        let mut q = make_queue();
        let id = q.add(vec![0], 100, 5).unwrap();
        q.remove(id).unwrap();
        assert!(q.is_empty());
    }

    #[test]
    fn test_cycle_count_increments() {
        let mut q = make_queue();
        q.add(vec![0], 100, 5).unwrap();
        assert_eq!(q.cycle_count(), 0);
        q.finish_cycle();
        assert_eq!(q.cycle_count(), 1);
    }

    #[test]
    fn test_top_coverage_entry() {
        let mut q = make_queue();
        let mut e1 = QueueEntry::new(0, vec![0], 100, 10);
        e1.new_cov = 5;
        let mut e2 = QueueEntry::new(0, vec![1], 100, 10);
        e2.new_cov = 15;
        q.push(e1).unwrap();
        q.push(e2).unwrap();
        let top = q.top_coverage_entry().unwrap();
        assert_eq!(top.new_cov, 15);
    }

    #[test]
    fn test_mean_exec_us() {
        let mut q = make_queue();
        q.add(vec![0], 100, 10).unwrap();
        q.add(vec![1], 200, 10).unwrap();
        assert!((q.mean_exec_us() - 150.0).abs() < 1e-9);
    }

    #[test]
    fn test_estimated_cycle_time() {
        let mut q = make_queue();
        q.add(vec![0], 1_000_000, 10).unwrap(); // 1 second in micros
        let t = q.estimated_cycle_time();
        assert_eq!(t.as_secs(), 1);
    }
}
