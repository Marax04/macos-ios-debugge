//! Corpus minimization for coverage-guided fuzzing.
//!
//! Given a set of test-cases each annotated with the set of edges (or basic-blocks)
//! that they cover, this module computes a minimal sub-corpus that covers the same
//! total edge set.  The algorithm is a standard greedy set-cover approximation:
//! iteratively select the test-case that contributes the most *new* coverage until
//! no further uncovered edges remain.
//!
//! Additionally provides:
//! - Exact deduplication (two inputs with identical coverage sets are identical).
//! - Weighted minimization (prefer shorter inputs / lower execution time).
//! - Incremental minimization: add a new batch of inputs to an already-minimized
//!   corpus without reprocessing everything.
//! - Export of the minimized corpus as a JSON manifest.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use rayon::prelude::*;

use crate::{CovError, CoverageRun};

// ─── Edge identifier ──────────────────────────────────────────────────────────

/// Compact representation of a covered edge.
/// For `DRcov` entries: `(module_id << 32) | (offset as u32)`.
/// For sancov PC-guards: the raw PC value.
pub type EdgeId = u64;

// ─── CorpusEntry ─────────────────────────────────────────────────────────────

/// A single corpus entry with its coverage fingerprint and file metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// Unique identifier (usually the SHA-256 hex of the input bytes).
    pub id: String,
    /// Path to the input file on disk.
    pub path: PathBuf,
    /// Size of the input in bytes.
    pub size_bytes: u64,
    /// Execution time recorded during coverage collection, if known.
    pub exec_time_us: Option<u64>,
    /// Set of edge IDs covered by this input.
    pub edges: HashSet<EdgeId>,
    /// Arbitrary key-value tags (e.g. `"crash"`, `"interesting"`).
    pub tags: HashMap<String, String>,
    /// Whether this entry is retained in the minimized corpus.
    pub retained: bool,
    /// The edges this entry contributed uniquely (only valid after minimization).
    pub unique_edges: HashSet<EdgeId>,
}

impl CorpusEntry {
    /// Create a new corpus entry from a [`CoverageRun`].
    #[must_use] 
    pub fn from_coverage_run(run: &CoverageRun, path: PathBuf) -> Self {
        let edges: HashSet<EdgeId> = run
            .bb_hits
            .keys()
            .copied()
            .collect();
        Self {
            id: run.name.clone(),
            path,
            size_bytes: 0,
            exec_time_us: None,
            edges,
            tags: HashMap::new(),
            retained: false,
            unique_edges: HashSet::new(),
        }
    }

    /// Create a corpus entry directly from an edge set.
    pub fn from_edges(
        id: impl Into<String>,
        path: PathBuf,
        edges: HashSet<EdgeId>,
        size_bytes: u64,
        exec_time_us: Option<u64>,
    ) -> Self {
        Self {
            id: id.into(),
            path,
            size_bytes,
            exec_time_us,
            edges,
            tags: HashMap::new(),
            retained: false,
            unique_edges: HashSet::new(),
        }
    }

    /// Coverage cardinality.
    #[must_use] 
    pub fn coverage_count(&self) -> usize {
        self.edges.len()
    }

    /// How many edges in this entry are not in `already_covered`.
    #[must_use] 
    pub fn new_edges_over(&self, already_covered: &HashSet<EdgeId>) -> usize {
        self.edges.difference(already_covered).count()
    }

    /// A score combining new edge count, size (prefer small) and speed (prefer fast).
    /// Higher is better.
    #[must_use] 
    pub fn greedy_score(
        &self,
        already_covered: &HashSet<EdgeId>,
        weight_size: f64,
        weight_time: f64,
    ) -> f64 {
        let new = crate::casts::usize_to_f64(self.new_edges_over(already_covered));
        if new == 0.0 {
            return 0.0;
        }
        let size_penalty = if self.size_bytes > 0 {
            weight_size * crate::casts::u64_to_f64(self.size_bytes).ln()
        } else {
            0.0
        };
        let time_penalty = self.exec_time_us.map_or(0.0, |t| weight_time * crate::casts::u64_to_f64(t).ln_1p());
        new - size_penalty - time_penalty
    }
}

// ─── MinimizerConfig ─────────────────────────────────────────────────────────

/// Configuration for the greedy minimizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizerConfig {
    /// Weight applied to log(size) in the greedy score.  0.0 = ignore size.
    pub size_weight: f64,
    /// Weight applied to `log1p(exec_time_us)` in the greedy score.  0.0 = ignore time.
    pub time_weight: f64,
    /// If true, deduplicate entries with identical edge sets before minimization.
    pub dedup_identical: bool,
    /// If true, always retain entries tagged with `"crash"`.
    pub keep_crashes: bool,
    /// Maximum corpus size (0 = unlimited).
    pub max_corpus_size: usize,
    /// Minimum coverage percentage (0–100) that the minimized corpus must retain
    /// relative to the full corpus.  Allows a small loss for a large size reduction.
    pub min_coverage_pct: f64,
}

impl Default for MinimizerConfig {
    fn default() -> Self {
        Self {
            size_weight: 0.05,
            time_weight: 0.02,
            dedup_identical: true,
            keep_crashes: true,
            max_corpus_size: 0,
            min_coverage_pct: 100.0,
        }
    }
}

// ─── MinimizationResult ──────────────────────────────────────────────────────

/// Statistics and output of a minimization run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinimizationResult {
    /// Total entries in the original corpus.
    pub original_count: usize,
    /// Entries retained.
    pub retained_count: usize,
    /// Entries removed.
    pub removed_count: usize,
    /// Total unique edges across the full corpus.
    pub total_edges: usize,
    /// Edges covered by the minimized corpus.
    pub retained_edges: usize,
    /// Coverage retention percentage (0–100).
    pub coverage_pct: f64,
    /// IDs of retained entries in selection order.
    pub retained_ids: Vec<String>,
    /// IDs of removed entries.
    pub removed_ids: Vec<String>,
    /// Wall-clock time for the minimization pass.
    pub elapsed_ms: u64,
    /// Entries removed in the dedup phase (identical coverage).
    pub dedup_removed: usize,
    /// Number of edges in the *original* corpus that were covered by exactly
    /// one entry. These are the entries the minimizer had no choice but to
    /// keep; reporting the count lets callers gauge how irreducible the
    /// corpus was.
    #[serde(default)]
    pub unique_edges: usize,
}

impl MinimizationResult {
    /// Size reduction ratio (0 = no reduction, 1 = everything removed).
    #[must_use] 
    pub fn size_reduction(&self) -> f64 {
        if self.original_count == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.removed_count) / crate::casts::usize_to_f64(self.original_count)
    }
}

// ─── EdgeCoverageIndex ───────────────────────────────────────────────────────

/// Inverted index: edge → list of corpus entry indices that cover it.
/// Used to accelerate incremental updates.
struct EdgeCoverageIndex {
    /// `edge_id` → Vec<`entry_index`>
    edge_to_entries: HashMap<EdgeId, Vec<usize>>,
    /// Total unique edges tracked.
    all_edges: HashSet<EdgeId>,
}

impl EdgeCoverageIndex {
    fn build(entries: &[CorpusEntry]) -> Self {
        let mut edge_to_entries: HashMap<EdgeId, Vec<usize>> = HashMap::new();
        let mut all_edges = HashSet::new();
        for (i, entry) in entries.iter().enumerate() {
            for &e in &entry.edges {
                edge_to_entries.entry(e).or_default().push(i);
                all_edges.insert(e);
            }
        }
        Self {
            edge_to_entries,
            all_edges,
        }
    }

    fn all_edge_count(&self) -> usize {
        self.all_edges.len()
    }

    /// Number of corpus entries covering `edge`, or `0` if the edge is not
    /// tracked. Used by the minimizer's diagnostic reports to surface the
    /// least-redundant edges.
    fn entries_covering(&self, edge: EdgeId) -> usize {
        self.edge_to_entries.get(&edge).map_or(0, Vec::len)
    }

    /// Iterate over `(edge, coverage_count)` pairs. Returned in arbitrary
    /// order; callers that need a deterministic order should sort the result.
    fn edge_coverage_iter(&self) -> impl Iterator<Item = (EdgeId, usize)> + '_ {
        self.edge_to_entries.iter().map(|(&e, v)| (e, v.len()))
    }
}

// ─── CorpusMinimizer ─────────────────────────────────────────────────────────

/// Main minimizer.
pub struct CorpusMinimizer {
    config: MinimizerConfig,
    /// Working copy of all entries (mutable during minimization).
    entries: Vec<CorpusEntry>,
}

impl CorpusMinimizer {
    /// Create a new minimizer from a vector of corpus entries.
    #[must_use] 
    pub const fn new(entries: Vec<CorpusEntry>, config: MinimizerConfig) -> Self {
        Self { config, entries }
    }

    /// Add more entries to the corpus (for incremental use).
    pub fn add_entries(&mut self, new_entries: Vec<CorpusEntry>) {
        self.entries.extend(new_entries);
    }

    /// Total number of entries.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the corpus is empty.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Run the greedy set-cover minimization.
    ///
    /// Returns a [`MinimizationResult`] and mutates `self.entries` so that
    /// `retained == true` on the selected subset.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn minimize(&mut self) -> MinimizationResult {
        let start = Instant::now();

        // --- Phase 1: dedup identical coverage sets ---
        let dedup_removed = if self.config.dedup_identical {
            self.dedup_by_coverage()
        } else {
            0
        };

        let original_count = self.entries.len();

        // --- Phase 2: always retain crashes ---
        let mut covered: HashSet<EdgeId> = HashSet::new();
        if self.config.keep_crashes {
            for entry in &mut self.entries {
                if entry.tags.get("crash").is_some_and(|v| v == "true") {
                    entry.retained = true;
                    covered.extend(entry.edges.iter().copied());
                }
            }
        }

        // --- Phase 3: build inverted index ---
        let index = EdgeCoverageIndex::build(&self.entries);
        let total_edges = index.all_edge_count();

        // Required edges to cover (respecting min_coverage_pct)
        let target_edges = crate::casts::f64_to_usize(
            (crate::casts::usize_to_f64(total_edges) * self.config.min_coverage_pct / 100.0).ceil(),
        );

        // --- Phase 4: greedy selection ---
        let retained_ids = self.greedy_select(&mut covered, target_edges);

        // Mark non-retained entries.
        let removed_ids: Vec<String> = self
            .entries
            .iter()
            .filter(|e| !e.retained)
            .map(|e| e.id.clone())
            .collect();

        let retained_count = retained_ids.len();
        let removed_count = original_count - retained_count;
        let retained_edges = covered.len();
        let coverage_pct = if total_edges > 0 {
            crate::casts::usize_to_f64(retained_edges) / crate::casts::usize_to_f64(total_edges) * 100.0
        } else {
            100.0
        };

        // Count edges that have exactly one covering entry in the original
        // corpus, using the inverted index built above.
        let unique_edges = index
            .edge_coverage_iter()
            .filter(|&(edge, _)| index.entries_covering(edge) == 1)
            .count();

        MinimizationResult {
            original_count,
            retained_count,
            removed_count,
            total_edges,
            retained_edges,
            coverage_pct,
            retained_ids,
            removed_ids,
            elapsed_ms: crate::casts::u128_to_u64(start.elapsed().as_millis()),
            dedup_removed,
            unique_edges,
        }
    }

    /// Return an iterator over retained entries (after calling `minimize`).
    pub fn retained_entries(&self) -> impl Iterator<Item = &CorpusEntry> {
        self.entries.iter().filter(|e| e.retained)
    }

    /// Return an iterator over removed entries.
    pub fn removed_entries(&self) -> impl Iterator<Item = &CorpusEntry> {
        self.entries.iter().filter(|e| !e.retained)
    }

    /// Consume the minimizer and return only retained entries.
    #[must_use] 
    pub fn into_retained(self) -> Vec<CorpusEntry> {
        self.entries.into_iter().filter(|e| e.retained).collect()
    }

    /// Greedy entry-selection phase of [`minimize`]. Pops the best-scoring
    /// entry from a max-heap, re-scores it against the current `covered` set,
    /// and either selects it or re-inserts it with the updated score. Returns
    /// the ordered list of selected entry IDs.
    fn greedy_select(&mut self, covered: &mut HashSet<EdgeId>, target_edges: usize) -> Vec<String> {
        let sw = self.config.size_weight;
        let tw = self.config.time_weight;
        let covered_ref: &HashSet<EdgeId> = covered;
        let mut heap_entries: BinaryHeap<HeapItem> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.retained)
            .par_bridge()
            .map(|(i, e)| HeapItem {
                score: OrderedF64(e.greedy_score(covered_ref, sw, tw)),
                idx: i,
                generation: 0,
            })
            .collect::<Vec<_>>()
            .into_iter()
            .collect();

        let mut generation: u64 = 0;
        let mut entry_generation: Vec<u64> = vec![0; self.entries.len()];
        let mut retained_ids: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.retained)
            .map(|e| e.id.clone())
            .collect();
        let max_size = if self.config.max_corpus_size > 0 {
            self.config.max_corpus_size
        } else {
            usize::MAX
        };

        while covered.len() < target_edges && !heap_entries.is_empty() {
            if retained_ids.len() >= max_size {
                break;
            }
            let item = heap_entries.pop().unwrap();
            if item.generation < entry_generation[item.idx] {
                continue;
            }
            let entry = &self.entries[item.idx];
            if entry.retained {
                continue;
            }
            let fresh_score = entry.greedy_score(covered, sw, tw);
            if (fresh_score - item.score.0).abs() > 1e-9 {
                let new_generation = generation;
                entry_generation[item.idx] = new_generation;
                heap_entries.push(HeapItem {
                    score: OrderedF64(fresh_score),
                    idx: item.idx,
                    generation: new_generation,
                });
                continue;
            }
            if fresh_score <= 0.0 {
                break;
            }
            let new_edges: HashSet<EdgeId> = self.entries[item.idx]
                .edges
                .difference(covered)
                .copied()
                .collect();
            covered.extend(new_edges.iter().copied());
            generation += 1;
            self.entries[item.idx].retained = true;
            self.entries[item.idx].unique_edges = new_edges;
            retained_ids.push(self.entries[item.idx].id.clone());
        }
        retained_ids
    }

    /// Export a JSON manifest of the minimized corpus.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn export_manifest(&self) -> Result<String, serde_json::Error> {
        let manifest: Vec<&CorpusEntry> = self.retained_entries().collect();
        serde_json::to_string_pretty(&manifest)
    }

    /// Compute total unique edges across all entries.
    #[must_use] 
    pub fn total_unique_edges(&self) -> usize {
        let mut all: HashSet<EdgeId> = HashSet::new();
        for e in &self.entries {
            all.extend(e.edges.iter().copied());
        }
        all.len()
    }

    // ─── Internal ────────────────────────────────────────────────────────────

    /// Remove entries with identical edge sets (keep the smallest/fastest one).
    /// Returns the number of removed entries.
    fn dedup_by_coverage(&mut self) -> usize {
        // Fingerprint: sorted vec of edges → use as HashMap key.
        let mut fingerprint_map: HashMap<Vec<EdgeId>, usize> = HashMap::new();
        let mut to_remove: HashSet<usize> = HashSet::new();

        for (i, entry) in self.entries.iter().enumerate() {
            let mut fp: Vec<EdgeId> = entry.edges.iter().copied().collect();
            fp.sort_unstable();

            match fingerprint_map.get(&fp) {
                None => {
                    fingerprint_map.insert(fp, i);
                }
                Some(&existing_idx) => {
                    // Keep the smaller / faster one.
                    let existing = &self.entries[existing_idx];
                    let prefer_new = match (entry.exec_time_us, existing.exec_time_us) {
                        (Some(t_new), Some(t_old)) => t_new < t_old,
                        _ => entry.size_bytes < existing.size_bytes,
                    };
                    if prefer_new {
                        to_remove.insert(existing_idx);
                        fingerprint_map.insert(fp, i);
                    } else {
                        to_remove.insert(i);
                    }
                }
            }
        }

        let removed = to_remove.len();
        // Remove in reverse-index order to preserve indices.
        let mut sorted: Vec<usize> = to_remove.into_iter().collect();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        for idx in sorted {
            self.entries.remove(idx);
        }
        removed
    }
}

// ─── HeapItem (for greedy priority queue) ────────────────────────────────────

#[derive(Debug, Clone)]
struct HeapItem {
    score: OrderedF64,
    idx: usize,
    generation: u64,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score && self.idx == other.idx
    }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .partial_cmp(&other.score)
            .unwrap_or(Ordering::Equal)
    }
}

/// f64 wrapper that implements `Ord` (NaN handled as equal).
#[derive(Debug, Clone, Copy)]
struct OrderedF64(f64);
impl PartialEq for OrderedF64 {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}
impl Eq for OrderedF64 {}
impl PartialOrd for OrderedF64 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for OrderedF64 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.partial_cmp(&other.0).unwrap_or(Ordering::Equal)
    }
}

// ─── IncrementalMinimizer ─────────────────────────────────────────────────────

/// Wraps [`CorpusMinimizer`] to support incremental batch additions.
///
/// Maintains the current covered-edge set and the minimized corpus.  When new
/// entries arrive, only those that contribute new coverage are added; the rest
/// are discarded immediately without re-running the full minimization.
pub struct IncrementalMinimizer {
    config: MinimizerConfig,
    /// The current minimized corpus.
    corpus: Vec<CorpusEntry>,
    /// All edges covered by `corpus`.
    covered: HashSet<EdgeId>,
    /// Total entries processed (including rejected ones).
    total_seen: usize,
    /// Total entries rejected.
    total_rejected: usize,
}

impl IncrementalMinimizer {
    /// Create an empty incremental minimizer.
    #[must_use] 
    pub fn new(config: MinimizerConfig) -> Self {
        Self {
            config,
            corpus: Vec::new(),
            covered: HashSet::new(),
            total_seen: 0,
            total_rejected: 0,
        }
    }

    /// Process a batch of new entries.  Returns the number accepted.
    pub fn process_batch(&mut self, batch: Vec<CorpusEntry>) -> usize {
        self.total_seen += batch.len();
        let sw = self.config.size_weight;
        let tw = self.config.time_weight;
        let mut accepted = 0;

        // Sort batch by descending score relative to current coverage (parallel).
        let covered_ref = &self.covered;
        let mut scored: Vec<(f64, CorpusEntry)> = batch
            .into_par_iter()
            .map(|e| {
                let score = e.greedy_score(covered_ref, sw, tw);
                (score, e)
            })
            .collect();
        scored.sort_unstable_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal));

        for (score, mut entry) in scored {
            if score <= 0.0 {
                self.total_rejected += 1;
                continue;
            }
            // Recompute with latest covered (batch ordering may have shifted).
            let new_edges: HashSet<EdgeId> =
                entry.edges.difference(&self.covered).copied().collect();
            if new_edges.is_empty() {
                self.total_rejected += 1;
                continue;
            }
            self.covered.extend(new_edges.iter().copied());
            entry.retained = true;
            entry.unique_edges = new_edges;
            self.corpus.push(entry);
            accepted += 1;

            if self.config.max_corpus_size > 0
                && self.corpus.len() >= self.config.max_corpus_size
            {
                break;
            }
        }
        accepted
    }

    /// Process a single entry.  Returns true if accepted.
    pub fn process_entry(&mut self, entry: CorpusEntry) -> bool {
        self.process_batch(vec![entry]) > 0
    }

    /// Number of entries in the current minimized corpus.
    #[must_use] 
    pub const fn corpus_size(&self) -> usize {
        self.corpus.len()
    }

    /// Total unique edges covered.
    #[must_use] 
    pub fn covered_edges(&self) -> usize {
        self.covered.len()
    }

    /// Rejection rate (0–1).
    #[must_use] 
    pub fn rejection_rate(&self) -> f64 {
        if self.total_seen == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.total_rejected) / crate::casts::usize_to_f64(self.total_seen)
    }

    /// Borrow the current minimized corpus.
    #[must_use] 
    pub fn corpus(&self) -> &[CorpusEntry] {
        &self.corpus
    }

    /// Export the corpus as a JSON manifest.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn export_manifest(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.corpus)
    }

    /// Run a full re-minimization pass on the current corpus (expensive).
    pub fn reoptimize(&mut self) -> MinimizationResult {
        let entries = std::mem::take(&mut self.corpus);
        // Reset retained flags.
        let entries: Vec<CorpusEntry> = entries
            .into_iter()
            .map(|mut e| {
                e.retained = false;
                e.unique_edges = HashSet::new();
                e
            })
            .collect();
        let mut minimizer = CorpusMinimizer::new(entries, self.config.clone());
        let result = minimizer.minimize();
        let (retained, _): (Vec<_>, Vec<_>) =
            minimizer.entries.into_iter().partition(|e| e.retained);
        self.corpus = retained;
        // Rebuild covered set.
        self.covered.clear();
        for entry in &self.corpus {
            self.covered.extend(entry.edges.iter().copied());
        }
        result
    }
}

// ─── CoverageContributionReport ──────────────────────────────────────────────

/// Per-entry contribution statistics (useful for understanding corpus health).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionReport {
    pub entry_id: String,
    pub path: PathBuf,
    pub total_edges: usize,
    pub unique_edges: usize,
    pub shared_edges: usize,
    /// Fraction of this entry's edges that are unique to it.
    pub uniqueness_ratio: f64,
    /// Fraction of total corpus edges covered by this entry.
    pub coverage_fraction: f64,
}

/// Generate a contribution report for every entry in a minimized corpus.
#[must_use] 
pub fn contribution_report(
    entries: &[CorpusEntry],
    total_corpus_edges: usize,
) -> Vec<ContributionReport> {
    // Count how many entries cover each edge.
    let mut edge_frequency: HashMap<EdgeId, usize> = HashMap::new();
    for entry in entries {
        for &e in &entry.edges {
            *edge_frequency.entry(e).or_insert(0) += 1;
        }
    }

    entries
        .par_iter()
        .map(|entry| {
            let unique_edges = entry.edges.iter().filter(|e| edge_frequency[e] == 1).count();
            let shared_edges = entry.edges.len() - unique_edges;
            let uniqueness_ratio = if entry.edges.is_empty() {
                0.0
            } else {
                crate::casts::usize_to_f64(unique_edges) / crate::casts::usize_to_f64(entry.edges.len())
            };
            let coverage_fraction = if total_corpus_edges > 0 {
                crate::casts::usize_to_f64(entry.edges.len()) / crate::casts::usize_to_f64(total_corpus_edges)
            } else {
                0.0
            };
            ContributionReport {
                entry_id: entry.id.clone(),
                path: entry.path.clone(),
                total_edges: entry.edges.len(),
                unique_edges,
                shared_edges,
                uniqueness_ratio,
                coverage_fraction,
            }
        })
        .collect()
}

// ─── Utility helpers ─────────────────────────────────────────────────────────

/// Load a corpus manifest JSON file produced by [`CorpusMinimizer::export_manifest`].
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn load_manifest(path: &Path) -> Result<Vec<CorpusEntry>, CovError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| CovError::Io(e.to_string()))?;
    let entries: Vec<CorpusEntry> = serde_json::from_str(&data)
        .map_err(|e| CovError::Parse(e.to_string()))?;
    Ok(entries)
}

/// Save a corpus manifest.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn save_manifest(entries: &[CorpusEntry], path: &Path) -> Result<(), CovError> {
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| CovError::Parse(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| CovError::Io(e.to_string()))
}

/// Quick corpus statistics without running minimization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusStats {
    pub total_entries: usize,
    pub total_edges: usize,
    pub avg_edges_per_entry: f64,
    pub median_edges: usize,
    pub min_edges: usize,
    pub max_edges: usize,
    pub total_size_bytes: u64,
    pub avg_size_bytes: f64,
    /// Estimated redundancy: fraction of edges that are covered by >1 entry.
    pub redundancy_ratio: f64,
}

/// Compute quick statistics for a corpus.
#[must_use] 
pub fn corpus_stats(entries: &[CorpusEntry]) -> CorpusStats {
    if entries.is_empty() {
        return CorpusStats {
            total_entries: 0,
            total_edges: 0,
            avg_edges_per_entry: 0.0,
            median_edges: 0,
            min_edges: 0,
            max_edges: 0,
            total_size_bytes: 0,
            avg_size_bytes: 0.0,
            redundancy_ratio: 0.0,
        };
    }

    let mut edge_freq: HashMap<EdgeId, usize> = HashMap::new();
    for entry in entries {
        for &e in &entry.edges {
            *edge_freq.entry(e).or_insert(0) += 1;
        }
    }
    let total_edges = edge_freq.len();
    let redundant = edge_freq.values().filter(|&&c| c > 1).count();
    let redundancy_ratio = if total_edges > 0 {
        crate::casts::usize_to_f64(redundant) / crate::casts::usize_to_f64(total_edges)
    } else {
        0.0
    };

    let mut counts: Vec<usize> = entries.iter().map(|e| e.edges.len()).collect();
    counts.sort_unstable();
    let median_edges = counts[counts.len() / 2];
    let min_edges = *counts.first().unwrap_or(&0);
    let max_edges = *counts.last().unwrap_or(&0);
    let total_size_bytes: u64 = entries.iter().map(|e| e.size_bytes).sum();

    CorpusStats {
        total_entries: entries.len(),
        total_edges,
        avg_edges_per_entry: crate::casts::usize_to_f64(counts.iter().sum::<usize>()) / crate::casts::usize_to_f64(counts.len()),
        median_edges,
        min_edges,
        max_edges,
        total_size_bytes,
        avg_size_bytes: crate::casts::u64_to_f64(total_size_bytes) / crate::casts::usize_to_f64(entries.len()),
        redundancy_ratio,
    }
}

// ─── CovError extensions needed ──────────────────────────────────────────────
// (These variants must exist in the parent lib.rs CovError enum; here we just
// reference them via `crate::CovError`.)

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(id: &str, edges: &[u64]) -> CorpusEntry {
        CorpusEntry::from_edges(
            id,
            PathBuf::from(format!("/corpus/{id}")),
            edges.iter().copied().collect(),
            id.len() as u64 * 100,
            Some(1000),
        )
    }

    #[test]
    fn test_greedy_selects_best() {
        let entries = vec![
            make_entry("a", &[1, 2, 3, 4]),
            make_entry("b", &[5, 6, 7, 8]),
            make_entry("c", &[1, 5]),   // subset of a+b
            make_entry("d", &[9, 10]),  // unique
        ];
        let mut m = CorpusMinimizer::new(entries, MinimizerConfig::default());
        let result = m.minimize();
        assert!(result.retained_count <= 3, "c should be dropped as redundant");
        assert_eq!(result.retained_edges, 10);
    }

    #[test]
    fn test_dedup_removes_identical() {
        let entries = vec![
            make_entry("a", &[1, 2, 3]),
            make_entry("b", &[1, 2, 3]), // identical to a
            make_entry("c", &[4, 5, 6]),
        ];
        let mut m = CorpusMinimizer::new(
            entries,
            MinimizerConfig { dedup_identical: true, ..Default::default() },
        );
        let result = m.minimize();
        assert_eq!(result.dedup_removed, 1);
        assert_eq!(result.retained_count, 2);
    }

    #[test]
    fn test_incremental_minimizer() {
        let mut inc = IncrementalMinimizer::new(MinimizerConfig::default());
        let batch1 = vec![make_entry("a", &[1, 2, 3]), make_entry("b", &[4, 5, 6])];
        let accepted = inc.process_batch(batch1);
        assert_eq!(accepted, 2);

        // Add a fully redundant entry.
        let redundant = make_entry("c", &[1, 4]);
        assert!(!inc.process_entry(redundant));

        // Add a genuinely new entry.
        let novel = make_entry("d", &[7, 8, 9]);
        assert!(inc.process_entry(novel));
        assert_eq!(inc.corpus_size(), 3);
        assert_eq!(inc.covered_edges(), 9);
    }

    #[test]
    fn test_corpus_stats() {
        let entries = vec![
            make_entry("a", &[1, 2, 3]),
            make_entry("b", &[2, 3, 4]),
            make_entry("c", &[5, 6]),
        ];
        let stats = corpus_stats(&entries);
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.total_edges, 6);
        assert!(stats.redundancy_ratio > 0.0); // edges 2,3 are shared
    }

    #[test]
    fn test_contribution_report() {
        let entries = vec![
            make_entry("a", &[1, 2, 3]),
            make_entry("b", &[3, 4, 5]), // edge 3 shared
        ];
        let report = contribution_report(&entries, 5);
        assert_eq!(report.len(), 2);
        // edge 3 is shared so unique_edges < total_edges for both
        let a = report.iter().find(|r| r.entry_id == "a").unwrap();
        assert_eq!(a.shared_edges, 1);
    }
}
