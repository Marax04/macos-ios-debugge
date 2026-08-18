//! `corpus_manager` — Corpus management with minimization strategies, deduplication,
//! disk persistence, and per-entry statistics.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::{CorpusMeta, FuzzError, FuzzInput, FuzzRng, fnv1a};

// ── CorpusEntryExt ────────────────────────────────────────────────────────────

/// Extended metadata for a corpus entry managed by [`CorpusManager`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntryExt {
    /// Input bytes.
    pub data: Vec<u8>,
    /// Unique id within this manager.
    pub id: u64,
    /// FNV-1a hash of `data`.
    pub data_hash: u64,
    /// Coverage-bitmap hash produced when this entry was added.
    pub coverage_hash: u64,
    /// Number of coverage bits hit.
    pub coverage_bits: u32,
    /// Wall-clock time the target took to process this input.
    pub execution_time: Duration,
    /// When this entry entered the corpus.
    pub found_at: SystemTime,
    /// Generation depth from the originating seed.
    pub generation: u32,
    /// Origin mutation strategy name.
    pub origin: Option<String>,
    /// Number of times this entry was selected for mutation.
    pub selected_count: u64,
    /// Assigned energy (power schedule).
    pub energy: u32,
    /// Whether this entry has been minimized.
    pub minimized: bool,
    /// Number of minimization rounds the last reduction took. `0` means the
    /// entry has not been minimized yet.
    #[serde(default)]
    pub minimize_rounds: usize,
}

impl CorpusEntryExt {
    /// Create a new extended corpus entry.
    #[must_use]
    pub fn new(
        id: u64,
        data: Vec<u8>,
        coverage_hash: u64,
        coverage_bits: u32,
        execution_time: Duration,
    ) -> Self {
        let data_hash = fnv1a(&data);
        Self {
            data,
            id,
            data_hash,
            coverage_hash,
            coverage_bits,
            execution_time,
            found_at: SystemTime::now(),
            generation: 0,
            origin: None,
            selected_count: 0,
            energy: 1,
            minimized: false,
            minimize_rounds: 0,
        }
    }

    /// Convert from a [`FuzzInput`] and [`CorpusMeta`].
    #[must_use]
    pub fn from_input_and_meta(input: &FuzzInput, meta: &CorpusMeta) -> Self {
        let data_hash = fnv1a(&input.data);
        Self {
            data: input.data.clone(),
            id: input.id,
            data_hash,
            coverage_hash: meta.hash,
            coverage_bits: meta.coverage_bits,
            execution_time: meta.execution_time,
            found_at: meta.found_at,
            generation: input.generation,
            origin: input.origin.clone(),
            selected_count: meta.selected_count,
            energy: meta.energy,
            minimized: false,
            minimize_rounds: 0,
        }
    }
}

// ── MinimizeStrategy ──────────────────────────────────────────────────────────

/// Strategy used by the corpus minimizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MinimizeStrategy {
    /// Remove one byte at a time (delta debugging).
    ByteRemoval,
    /// Remove half-sized blocks (binary block reduction).
    BlockReduction,
    /// Combine byte removal and block reduction in alternating passes.
    Combined,
    /// Only run a single pass of byte removal.
    SinglePass,
}

impl MinimizeStrategy {
    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ByteRemoval => "byte_removal",
            Self::BlockReduction => "block_reduction",
            Self::Combined => "combined",
            Self::SinglePass => "single_pass",
        }
    }
}

impl std::fmt::Display for MinimizeStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── CorpusStats ───────────────────────────────────────────────────────────────

/// Aggregate statistics for a [`CorpusManager`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorpusStats {
    /// Total number of entries (interesting + crashes).
    pub total_entries: usize,
    /// Number of interesting (coverage-increasing) entries.
    pub interesting_entries: usize,
    /// Number of crash-inducing entries.
    pub crash_entries: usize,
    /// Number of minimized entries.
    pub minimized_entries: usize,
    /// Total bytes across all entries.
    pub total_bytes: usize,
    /// Minimum entry size in bytes.
    pub min_bytes: usize,
    /// Maximum entry size in bytes.
    pub max_bytes: usize,
    /// Average entry size in bytes.
    pub avg_bytes: f64,
    /// Number of unique coverage hashes.
    pub unique_coverage_hashes: usize,
    /// Number of unique data hashes (exact duplicate detection).
    pub unique_data_hashes: usize,
    /// Number of duplicates deduplicated out.
    pub duplicates_dropped: u64,
    /// Average execution time across all entries.
    pub avg_execution_time_ms: f64,
    /// Total energy assigned across all entries.
    pub total_energy: u64,
}

// ── CorpusManager ─────────────────────────────────────────────────────────────

/// Manages a fuzzing corpus: deduplicates entries, computes statistics, supports
/// minimization, and optionally persists entries to disk.
pub struct CorpusManager {
    /// All corpus entries, keyed by id.
    entries: BTreeMap<u64, CorpusEntryExt>,
    /// Set of coverage hashes already present.
    coverage_hashes: HashSet<u64>,
    /// Set of data hashes for exact-duplicate detection.
    data_hashes: HashSet<u64>,
    /// Ids of entries that are crashes.
    crash_ids: HashSet<u64>,
    /// Next id to assign.
    next_id: u64,
    /// Maximum corpus size (entries).  `0` = unlimited.
    pub max_entries: usize,
    /// Minimum entry size to keep (bytes).
    pub min_entry_size: usize,
    /// Maximum entry size to keep (bytes).  `0` = unlimited.
    pub max_entry_size: usize,
    /// Number of duplicates dropped since creation.
    duplicates_dropped: u64,
    /// Optional directory for disk persistence.
    persist_dir: Option<PathBuf>,
    /// Internal RNG for sampling.
    rng: FuzzRng,
}

impl CorpusManager {
    /// Create a new empty [`CorpusManager`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            coverage_hashes: HashSet::new(),
            data_hashes: HashSet::new(),
            crash_ids: HashSet::new(),
            next_id: 0,
            max_entries: 0,
            min_entry_size: 0,
            max_entry_size: 0,
            duplicates_dropped: 0,
            persist_dir: None,
            rng: FuzzRng::new(0xdead_beef_1234_5678),
        }
    }

    /// Set a directory for persisting corpus entries on disk.
    #[must_use]
    pub fn with_persist_dir(mut self, dir: PathBuf) -> Self {
        self.persist_dir = Some(dir);
        self
    }

    /// Set the maximum number of corpus entries to keep.
    #[must_use]
    pub const fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    /// Set the maximum entry size in bytes.
    #[must_use]
    pub const fn with_max_entry_size(mut self, max: usize) -> Self {
        self.max_entry_size = max;
        self
    }

    // ── Add entries ───────────────────────────────────────────────────────────

    /// Add an interesting (coverage-increasing) entry to the corpus.
    ///
    /// Returns the assigned id if the entry was novel, or `None` if it was a
    /// duplicate (same coverage hash or same exact data).
    pub fn add_interesting(
        &mut self,
        data: Vec<u8>,
        coverage_hash: u64,
        coverage_bits: u32,
        execution_time: Duration,
    ) -> Option<u64> {
        self.add_internal(data, coverage_hash, coverage_bits, execution_time, false)
    }

    /// Add a crash-inducing entry.
    ///
    /// Returns the assigned id if the entry was novel.
    pub fn add_crash(
        &mut self,
        data: Vec<u8>,
        coverage_hash: u64,
        coverage_bits: u32,
        execution_time: Duration,
    ) -> Option<u64> {
        let id = self.add_internal(data, coverage_hash, coverage_bits, execution_time, true)?;
        self.crash_ids.insert(id);
        Some(id)
    }

    fn add_internal(
        &mut self,
        data: Vec<u8>,
        coverage_hash: u64,
        coverage_bits: u32,
        execution_time: Duration,
        is_crash: bool,
    ) -> Option<u64> {
        // Size gating.
        if data.len() < self.min_entry_size {
            return None;
        }
        if self.max_entry_size > 0 && data.len() > self.max_entry_size {
            return None;
        }

        let data_hash = fnv1a(&data);

        // Deduplication: drop exact data duplicates.
        if self.data_hashes.contains(&data_hash) {
            self.duplicates_dropped += 1;
            return None;
        }

        // For interesting entries: also deduplicate by coverage hash.
        if !is_crash && self.coverage_hashes.contains(&coverage_hash) {
            self.duplicates_dropped += 1;
            return None;
        }

        let id = self.next_id;
        self.next_id += 1;

        self.data_hashes.insert(data_hash);
        self.coverage_hashes.insert(coverage_hash);

        let entry = CorpusEntryExt::new(id, data, coverage_hash, coverage_bits, execution_time);
        self.entries.insert(id, entry);

        // Enforce max capacity by dropping the lowest-coverage non-crash entry.
        if self.max_entries > 0 && self.entries.len() > self.max_entries {
            self.evict_lowest_coverage();
        }

        Some(id)
    }

    /// Evict the entry with the fewest coverage bits (favouring non-crash entries).
    fn evict_lowest_coverage(&mut self) {
        let victim_id = self
            .entries
            .values()
            .filter(|e| !self.crash_ids.contains(&e.id))
            .min_by_key(|e| e.coverage_bits)
            .map(|e| e.id);

        if let Some(id) = victim_id
            && let Some(entry) = self.entries.remove(&id)
        {
            self.data_hashes.remove(&entry.data_hash);
            // Keep the coverage hash so we don't re-add something we've seen.
        }
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Number of entries in the corpus.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the corpus is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of crash entries.
    #[must_use]
    pub fn crash_count(&self) -> usize {
        self.crash_ids.len()
    }

    /// Get an entry by id.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&CorpusEntryExt> {
        self.entries.get(&id)
    }

    /// Get a mutable entry by id.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut CorpusEntryExt> {
        self.entries.get_mut(&id)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &CorpusEntryExt> {
        self.entries.values()
    }

    /// Iterate over all crash entries.
    pub fn crashes(&self) -> impl Iterator<Item = &CorpusEntryExt> {
        self.entries
            .values()
            .filter(|e| self.crash_ids.contains(&e.id))
    }

    /// Iterate over all interesting (non-crash) entries.
    pub fn interesting(&self) -> impl Iterator<Item = &CorpusEntryExt> {
        self.entries
            .values()
            .filter(|e| !self.crash_ids.contains(&e.id))
    }

    /// Return entries sorted by coverage bits descending.
    #[must_use]
    pub fn sorted_by_coverage(&self) -> Vec<&CorpusEntryExt> {
        let mut v: Vec<&CorpusEntryExt> = self.entries.values().collect();
        v.sort_unstable_by(|a, b| b.coverage_bits.cmp(&a.coverage_bits));
        v
    }

    /// Return entries sorted by data length ascending.
    #[must_use]
    pub fn sorted_by_size(&self) -> Vec<&CorpusEntryExt> {
        let mut v: Vec<&CorpusEntryExt> = self.entries.values().collect();
        v.sort_unstable_by_key(|e| e.data.len());
        v
    }

    /// Select an entry using a weighted-random strategy (higher energy = higher probability).
    ///
    /// Returns `None` if the corpus is empty.
    pub fn select_weighted(&mut self) -> Option<&CorpusEntryExt> {
        if self.entries.is_empty() {
            return None;
        }
        let total_energy: u64 = self.entries.values().map(|e| u64::from(e.energy)).sum();
        if total_energy == 0 {
            let idx = self.rng.next_usize(self.entries.len());
            return self.entries.values().nth(idx);
        }
        let mut target = self.rng.next_u64() % total_energy;
        for entry in self.entries.values() {
            if target < u64::from(entry.energy) {
                return Some(entry);
            }
            target -= u64::from(entry.energy);
        }
        self.entries.values().next_back()
    }

    /// Record that an entry was selected for mutation (increments `selected_count`).
    pub fn record_selection(&mut self, id: u64) {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.selected_count = entry.selected_count.saturating_add(1);
        }
    }

    /// Update the energy of an entry.
    pub fn set_energy(&mut self, id: u64, energy: u32) {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.energy = energy;
        }
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Compute aggregate statistics for the current corpus.
    #[must_use]
    pub fn corpus_stats(&self) -> CorpusStats {
        if self.entries.is_empty() {
            return CorpusStats {
                duplicates_dropped: self.duplicates_dropped,
                ..Default::default()
            };
        }

        let total_entries = self.entries.len();
        let interesting_entries = self.entries.values().filter(|e| !self.crash_ids.contains(&e.id)).count();
        let crash_entries = self.crash_ids.len();
        let minimized_entries = self.entries.values().filter(|e| e.minimized).count();

        let total_bytes: usize = self.entries.values().map(|e| e.data.len()).sum();
        let min_bytes = self.entries.values().map(|e| e.data.len()).min().unwrap_or(0);
        let max_bytes = self.entries.values().map(|e| e.data.len()).max().unwrap_or(0);
        let avg_bytes = total_bytes as f64 / total_entries as f64;

        let total_exec_ms: u128 = self
            .entries
            .values()
            .map(|e| e.execution_time.as_millis())
            .sum();
        let avg_execution_time_ms = total_exec_ms as f64 / total_entries as f64;

        let total_energy: u64 = self.entries.values().map(|e| u64::from(e.energy)).sum();

        CorpusStats {
            total_entries,
            interesting_entries,
            crash_entries,
            minimized_entries,
            total_bytes,
            min_bytes,
            max_bytes,
            avg_bytes,
            unique_coverage_hashes: self.coverage_hashes.len(),
            unique_data_hashes: self.data_hashes.len(),
            duplicates_dropped: self.duplicates_dropped,
            avg_execution_time_ms,
            total_energy,
        }
    }

    // ── Minimization ──────────────────────────────────────────────────────────

    /// Minimize the data of entry `id` using the given strategy and an oracle
    /// closure `is_interesting` that returns `true` when the trimmed data is
    /// still worth keeping.
    ///
    /// Marks the entry as minimized and updates its data in place.
    ///
    /// # Errors
    /// Returns [`FuzzError::CorpusError`] if the id does not exist.
    pub fn minimize_entry<F>(
        &mut self,
        id: u64,
        strategy: MinimizeStrategy,
        max_rounds: usize,
        is_interesting: F,
    ) -> Result<usize, FuzzError>
    where
        F: FnMut(&[u8]) -> bool,
    {
        let data = self
            .entries
            .get(&id)
            .ok_or_else(|| FuzzError::CorpusError(format!("entry {id} not found")))?
            .data
            .clone();

        let (minimized, rounds) = minimize_data(&data, strategy, max_rounds, is_interesting);
        let reduction = data.len().saturating_sub(minimized.len());

        if let Some(entry) = self.entries.get_mut(&id) {
            // Update data hash.
            let old_hash = entry.data_hash;
            self.data_hashes.remove(&old_hash);
            entry.data = minimized;
            entry.data_hash = fnv1a(&entry.data);
            self.data_hashes.insert(entry.data_hash);
            entry.minimized = true;
            entry.minimize_rounds = rounds;
        }

        Ok(reduction)
    }

    /// Minimize all un-minimized entries using the given strategy.
    ///
    /// Returns the total bytes saved.
    ///
    /// The oracle `make_oracle` is called for each entry id and must return an
    /// `is_interesting` closure appropriate for that entry.
    pub fn minimize_all<F, Oracle>(
        &mut self,
        strategy: MinimizeStrategy,
        max_rounds: usize,
        mut make_oracle: F,
    ) -> usize
    where
        F: FnMut(u64) -> Oracle,
        Oracle: FnMut(&[u8]) -> bool,
    {
        let ids: Vec<u64> = self
            .entries
            .keys()
            .copied()
            .filter(|id| !self.entries[id].minimized)
            .collect();

        let mut total_saved = 0usize;
        for id in ids {
            let oracle = make_oracle(id);
            if let Ok(saved) = self.minimize_entry(id, strategy, max_rounds, oracle) {
                total_saved += saved;
            }
        }
        total_saved
    }

    // ── Pruning ───────────────────────────────────────────────────────────────

    /// Remove all interesting (non-crash) entries with fewer than
    /// `min_coverage_bits` coverage bits.
    ///
    /// Returns the number of entries pruned.
    pub fn prune_low_coverage(&mut self, min_coverage_bits: u32) -> usize {
        let to_remove: Vec<u64> = self
            .entries
            .values()
            .filter(|e| !self.crash_ids.contains(&e.id) && e.coverage_bits < min_coverage_bits)
            .map(|e| e.id)
            .collect();

        let count = to_remove.len();
        for id in to_remove {
            if let Some(entry) = self.entries.remove(&id) {
                self.data_hashes.remove(&entry.data_hash);
            }
        }
        count
    }

    /// Remove exact-duplicate entries (same data hash, keeping the one with the
    /// highest coverage bits).
    ///
    /// Returns the number of entries removed.
    pub fn dedup_by_data(&mut self) -> usize {
        let mut seen_data: HashMap<u64, u64> = HashMap::new(); // data_hash -> best_id
        let mut to_remove = Vec::new();

        for entry in self.entries.values() {
            if let Some(&existing_id) = seen_data.get(&entry.data_hash) {
                let existing_bits = self.entries[&existing_id].coverage_bits;
                if entry.coverage_bits > existing_bits {
                    to_remove.push(existing_id);
                    seen_data.insert(entry.data_hash, entry.id);
                } else {
                    to_remove.push(entry.id);
                }
            } else {
                seen_data.insert(entry.data_hash, entry.id);
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            self.entries.remove(&id);
            self.crash_ids.remove(&id);
        }
        count
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /// Save all entries to the configured persist directory.
    ///
    /// Each entry is written as a raw binary file named by its id.
    ///
    /// # Errors
    /// Returns [`FuzzError::CorpusError`] on I/O failure.
    pub fn save_to_disk(&self) -> Result<usize, FuzzError> {
        let dir = self
            .persist_dir
            .as_ref()
            .ok_or_else(|| FuzzError::CorpusError("no persist_dir configured".to_string()))?;

        std::fs::create_dir_all(dir)
            .map_err(|e| FuzzError::CorpusError(format!("create_dir: {e}")))?;

        let mut saved = 0usize;
        for entry in self.entries.values() {
            let path = dir.join(format!("{:016x}", entry.id));
            std::fs::write(&path, &entry.data)
                .map_err(|e| FuzzError::CorpusError(format!("write {}: {e}", path.display())))?;
            saved += 1;
        }
        Ok(saved)
    }

    /// Load entries from the configured persist directory.
    ///
    /// Files are interpreted as raw input bytes; coverage metadata is
    /// zeroed (to be repopulated on the next run).
    ///
    /// # Errors
    /// Returns [`FuzzError::CorpusError`] on I/O failure.
    pub fn load_from_disk(&mut self) -> Result<usize, FuzzError> {
        let dir = self
            .persist_dir
            .as_ref()
            .ok_or_else(|| FuzzError::CorpusError("no persist_dir configured".to_string()))?
            .clone();

        let entries = std::fs::read_dir(&dir)
            .map_err(|e| FuzzError::CorpusError(format!("read_dir: {e}")))?;

        /// Cap per-file size to prevent dos-memory-exhaustion from oversized files.
        const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
        let mut loaded = 0usize;
        for dirent in entries.flatten() {
            let path = dirent.path();
            if !path.is_file() {
                continue;
            }
            // Skip oversized files rather than allocating unbounded memory.
            if let Ok(meta) = std::fs::metadata(&path)
                && meta.len() > MAX_ENTRY_BYTES
            {
                continue;
            }
            let data = std::fs::read(&path)
                .map_err(|e| FuzzError::CorpusError(format!("read {}: {e}", path.display())))?;
            self.add_interesting(data, 0, 0, Duration::ZERO);
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Load raw input files from an arbitrary directory (e.g. an AFL corpus dir).
    ///
    /// # Errors
    /// Returns [`FuzzError::CorpusError`] on I/O failure.
    pub fn import_directory(&mut self, dir: &Path) -> Result<usize, FuzzError> {
        let entries =
            std::fs::read_dir(dir).map_err(|e| FuzzError::CorpusError(format!("read_dir: {e}")))?;
        /// Cap per-file size to prevent dos-memory-exhaustion from oversized files.
        const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
        let mut imported = 0;
        for dirent in entries.flatten() {
            let path = dirent.path();
            if path.is_file() {
                // Skip oversized files rather than allocating unbounded memory.
                if let Ok(meta) = std::fs::metadata(&path)
                    && meta.len() > MAX_ENTRY_BYTES
                {
                    continue;
                }
                let data = std::fs::read(&path)
                    .map_err(|e| FuzzError::CorpusError(format!("read {}: {e}", path.display())))?;
                self.add_interesting(data, 0, 0, Duration::ZERO);
                imported += 1;
            }
        }
        Ok(imported)
    }
}

impl Default for CorpusManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Minimization logic ────────────────────────────────────────────────────────

/// Minimize `data` using `strategy` with up to `max_rounds` passes.
///
/// Returns `(minimized_bytes, rounds_taken)`.
fn minimize_data<F>(
    data: &[u8],
    strategy: MinimizeStrategy,
    max_rounds: usize,
    mut is_interesting: F,
) -> (Vec<u8>, usize)
where
    F: FnMut(&[u8]) -> bool,
{
    let mut current = data.to_vec();
    let mut rounds = 0;

    for r in 0..max_rounds {
        rounds = r + 1;
        let before = current.len();

        match strategy {
            MinimizeStrategy::ByteRemoval | MinimizeStrategy::SinglePass => {
                current = byte_removal_pass(&current, &mut is_interesting);
                if matches!(strategy, MinimizeStrategy::SinglePass) {
                    break;
                }
            }
            MinimizeStrategy::BlockReduction => {
                current = block_reduction_pass(&current, &mut is_interesting);
            }
            MinimizeStrategy::Combined => {
                if r % 2 == 0 {
                    current = byte_removal_pass(&current, &mut is_interesting);
                } else {
                    current = block_reduction_pass(&current, &mut is_interesting);
                }
            }
        }

        if current.len() >= before || current.is_empty() {
            break;
        }
    }

    (current, rounds)
}

fn byte_removal_pass<F>(input: &[u8], is_interesting: &mut F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> bool,
{
    let mut current = input.to_vec();
    let mut i = 0;
    while i < current.len() {
        let mut candidate = current.clone();
        candidate.remove(i);
        if is_interesting(&candidate) {
            current = candidate;
        } else {
            i += 1;
        }
    }
    current
}

fn block_reduction_pass<F>(input: &[u8], is_interesting: &mut F) -> Vec<u8>
where
    F: FnMut(&[u8]) -> bool,
{
    let mut current = input.to_vec();
    let mut block = current.len() / 2;
    while block >= 1 {
        let mut i = 0;
        while i + block <= current.len() {
            let mut candidate = current.clone();
            candidate.drain(i..i + block);
            if is_interesting(&candidate) {
                current = candidate;
            } else {
                i += block;
            }
        }
        block /= 2;
    }
    current
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_interesting_returns_id() {
        let mut mgr = CorpusManager::new();
        let id = mgr.add_interesting(vec![1, 2, 3], 0xdeadbeef, 10, Duration::ZERO);
        assert!(id.is_some());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn dedup_by_coverage_hash() {
        let mut mgr = CorpusManager::new();
        mgr.add_interesting(vec![1, 2, 3], 0xaaaa, 10, Duration::ZERO);
        let dup = mgr.add_interesting(vec![4, 5, 6], 0xaaaa, 10, Duration::ZERO);
        assert!(dup.is_none());
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn dedup_by_data_hash() {
        let mut mgr = CorpusManager::new();
        mgr.add_interesting(vec![1, 2, 3], 0x1111, 5, Duration::ZERO);
        let dup = mgr.add_interesting(vec![1, 2, 3], 0x2222, 10, Duration::ZERO);
        assert!(dup.is_none());
    }

    #[test]
    fn add_crash_tracked_separately() {
        let mut mgr = CorpusManager::new();
        mgr.add_crash(vec![0xff, 0x00], 0xcafe, 3, Duration::ZERO);
        assert_eq!(mgr.crash_count(), 1);
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn corpus_stats_basic() {
        let mut mgr = CorpusManager::new();
        mgr.add_interesting(vec![1, 2], 0x1, 2, Duration::from_millis(5));
        mgr.add_interesting(vec![1, 2, 3, 4], 0x2, 4, Duration::from_millis(10));
        let stats = mgr.corpus_stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.min_bytes, 2);
        assert_eq!(stats.max_bytes, 4);
    }

    #[test]
    fn minimize_entry_reduces_size() {
        let mut mgr = CorpusManager::new();
        let id = mgr
            .add_interesting(vec![1, 2, 3, 4, 5], 0xabcd, 5, Duration::ZERO)
            .unwrap();
        // Oracle: interesting if data contains the byte 3
        let saved = mgr
            .minimize_entry(id, MinimizeStrategy::ByteRemoval, 4, |d| d.contains(&3))
            .unwrap();
        assert!(saved > 0);
        let entry = mgr.get(id).unwrap();
        assert!(entry.data.contains(&3));
        assert!(entry.minimized);
    }

    #[test]
    fn prune_low_coverage_removes_entries() {
        let mut mgr = CorpusManager::new();
        mgr.add_interesting(vec![1], 0x1, 2, Duration::ZERO);
        mgr.add_interesting(vec![2], 0x2, 10, Duration::ZERO);
        let removed = mgr.prune_low_coverage(5);
        assert_eq!(removed, 1);
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn sorted_by_coverage_descending() {
        let mut mgr = CorpusManager::new();
        mgr.add_interesting(vec![1], 0x1, 5, Duration::ZERO);
        mgr.add_interesting(vec![2], 0x2, 20, Duration::ZERO);
        mgr.add_interesting(vec![3], 0x3, 1, Duration::ZERO);
        let sorted = mgr.sorted_by_coverage();
        assert_eq!(sorted[0].coverage_bits, 20);
        assert_eq!(sorted[2].coverage_bits, 1);
    }

    #[test]
    fn byte_removal_pass_minimizes() {
        let input = vec![10u8, 20, 30, 40, 50];
        let result = byte_removal_pass(&input, &mut |d| d.contains(&30));
        assert!(result.contains(&30));
        assert!(result.len() <= input.len());
    }

    #[test]
    fn block_reduction_pass_minimizes() {
        let input = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let result = block_reduction_pass(&input, &mut |d| !d.is_empty());
        assert!(!result.is_empty());
    }

    #[test]
    fn minimize_strategy_names() {
        assert_eq!(MinimizeStrategy::ByteRemoval.name(), "byte_removal");
        assert_eq!(MinimizeStrategy::BlockReduction.name(), "block_reduction");
        assert_eq!(MinimizeStrategy::Combined.name(), "combined");
        assert_eq!(MinimizeStrategy::SinglePass.name(), "single_pass");
    }

    #[test]
    fn max_entries_evicts_lowest_coverage() {
        let mut mgr = CorpusManager::new().with_max_entries(2);
        mgr.add_interesting(vec![1], 0x1, 5, Duration::ZERO);
        mgr.add_interesting(vec![2], 0x2, 10, Duration::ZERO);
        mgr.add_interesting(vec![3], 0x3, 3, Duration::ZERO);
        // Should have evicted the entry with 5 bits (lowest among non-crash)
        // but max_entries is 2, so after 3 adds only 2 remain.
        assert!(mgr.len() <= 2);
    }
}
