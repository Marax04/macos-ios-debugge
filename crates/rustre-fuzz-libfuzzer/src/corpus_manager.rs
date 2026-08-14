//! `rustre-fuzz-libfuzzer` — corpus management subsystem.
//!
//! Provides a complete corpus management pipeline for libFuzzer-style in-process
//! fuzzing: unique entry tracking, statistics, merging, shrinking, crash corpus
//! isolation, and export.
//!
//! # Structs
//! - [`CorpusEntry`]   — a single corpus element with metadata
//! - [`CorpusStats`]   — summary statistics over the whole corpus
//! - [`CorpusMerge`]   — merges two or more corpora into one
//! - [`CorpusShrink`]  — minimises the corpus to a minimal covering set
//! - [`CrashCorpus`]   — isolated crash-only corpus
//! - [`CorpusExport`]  — serialises the corpus to various formats
//! - [`CorpusManager`] — top-level coordinator

use std::collections::HashSet;
pub use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_fuzz::fnv1a;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the corpus management subsystem.
#[derive(Debug, Error)]
pub enum CorpusManagerError {
    #[error("entry not found: {0}")]
    NotFound(u64),
    #[error("duplicate entry: hash {0:#x}")]
    Duplicate(u64),
    #[error("io error: {0}")]
    Io(String),
    #[error("export error: {0}")]
    Export(String),
    #[error("merge error: {0}")]
    Merge(String),
    #[error("shrink error: {0}")]
    Shrink(String),
    #[error("empty corpus")]
    Empty,
    #[error("serialization error: {0}")]
    Serialization(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// EntryKind
// ─────────────────────────────────────────────────────────────────────────────

/// Whether a corpus entry came from a seed, mutation, or crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    /// Initial seed input.
    Seed,
    /// Mutation-derived interesting input.
    Interesting,
    /// Input that caused a crash (stored separately).
    Crash,
    /// Input that caused a hang / timeout.
    Hang,
    /// Entry imported from an external corpus.
    Imported,
}

impl std::fmt::Display for EntryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Seed => write!(f, "seed"),
            Self::Interesting => write!(f, "interesting"),
            Self::Crash => write!(f, "crash"),
            Self::Hang => write!(f, "hang"),
            Self::Imported => write!(f, "imported"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CorpusEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single corpus element with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// Unique id within the corpus.
    pub id: u64,
    /// Raw input bytes.
    pub data: Vec<u8>,
    /// FNV-1a hash of the data.
    pub hash: u64,
    /// Coverage bits hit by this entry.
    pub coverage_bits: u32,
    /// Set of edge hashes covered by this entry.
    pub edges: Vec<u64>,
    /// Average execution time in nanoseconds.
    pub exec_time_ns: u64,
    /// When this entry was added.
    pub added_at: SystemTime,
    /// Kind of entry.
    pub kind: EntryKind,
    /// Times this entry has been selected for mutation.
    pub selected_count: u64,
    /// Times a child of this entry was interesting.
    pub interesting_children: u64,
    /// Whether this entry is "favored" (minimal cover set).
    pub is_favored: bool,
    /// Whether this entry has been minimised.
    pub is_minimised: bool,
    /// Optional label.
    pub label: Option<String>,
}

impl CorpusEntry {
    /// Create a new entry.
    #[must_use]
    pub fn new(id: u64, data: Vec<u8>, coverage_bits: u32, exec_time_ns: u64) -> Self {
        let hash = fnv1a(&data);
        Self {
            id,
            data,
            hash,
            coverage_bits,
            edges: Vec::new(),
            exec_time_ns,
            added_at: SystemTime::now(),
            kind: EntryKind::Interesting,
            selected_count: 0,
            interesting_children: 0,
            is_favored: false,
            is_minimised: false,
            label: None,
        }
    }

    /// Create a seed entry.
    #[must_use]
    pub fn seed(id: u64, data: Vec<u8>) -> Self {
        let mut e = Self::new(id, data, 0, 0);
        e.kind = EntryKind::Seed;
        e
    }

    /// Score for power scheduling (higher = more mutations).
    #[must_use]
    pub fn score(&self) -> f64 {
        if self.selected_count == 0 {
            return f64::MAX;
        }
        let ir = (self.interesting_children as f64) / (self.selected_count as f64);
        let time_factor = if self.exec_time_ns == 0 {
            1.0
        } else {
            1_000_000_000.0 / (self.exec_time_ns as f64)
        };
        (1.0 + ir) * time_factor.min(100.0) * (f64::from(self.coverage_bits) + 1.0)
    }

    /// Mark as selected.
    pub const fn select(&mut self) {
        self.selected_count += 1;
    }

    /// Mark that a child was interesting.
    pub const fn child_interesting(&mut self) {
        self.interesting_children += 1;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CorpusStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics over a corpus.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorpusStats {
    pub total_entries: usize,
    pub total_bytes: u64,
    pub avg_entry_size: f64,
    pub max_entry_size: usize,
    pub min_entry_size: usize,
    pub avg_coverage_bits: f64,
    pub total_coverage_bits: u64,
    pub unique_edge_count: usize,
    pub favored_count: usize,
    pub seed_count: usize,
    pub crash_count: usize,
    pub hang_count: usize,
    pub avg_exec_time_ns: f64,
}

impl CorpusStats {
    /// Compute statistics from a slice of entries.
    #[must_use]
    pub fn compute(entries: &[CorpusEntry]) -> Self {
        if entries.is_empty() {
            return Self::default();
        }
        let total_entries = entries.len();
        let total_bytes: u64 = entries.iter().map(|e| e.data.len() as u64).sum();
        let max_entry_size = entries.iter().map(|e| e.data.len()).max().unwrap_or(0);
        let min_entry_size = entries.iter().map(|e| e.data.len()).min().unwrap_or(0);
        let total_coverage_bits: u64 = entries.iter().map(|e| u64::from(e.coverage_bits)).sum();
        let favored_count = entries.iter().filter(|e| e.is_favored).count();
        let seed_count = entries.iter().filter(|e| e.kind == EntryKind::Seed).count();
        let crash_count = entries
            .iter()
            .filter(|e| e.kind == EntryKind::Crash)
            .count();
        let hang_count = entries.iter().filter(|e| e.kind == EntryKind::Hang).count();
        let mut unique_edges: HashSet<u64> = HashSet::new();
        for e in entries {
            unique_edges.extend(e.edges.iter());
        }
        let total_exec: u64 = entries.iter().map(|e| e.exec_time_ns).sum();
        Self {
            total_entries,
            total_bytes,
            avg_entry_size: (total_bytes) as f64 / (total_entries) as f64,
            max_entry_size,
            min_entry_size,
            avg_coverage_bits: (total_coverage_bits) as f64 / (total_entries) as f64,
            total_coverage_bits,
            unique_edge_count: unique_edges.len(),
            favored_count,
            seed_count,
            crash_count,
            hang_count,
            avg_exec_time_ns: (total_exec) as f64 / (total_entries) as f64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CorpusMerge
// ─────────────────────────────────────────────────────────────────────────────

/// Merges two or more corpora into one, deduplicating by data hash.
#[derive(Debug, Default)]
pub struct CorpusMerge {
    /// Merged result.
    pub merged: Vec<CorpusEntry>,
    seen: HashSet<u64>,
    pub dedup_count: usize,
    pub accepted_count: usize,
    next_id: u64,
}

impl CorpusMerge {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge in a single entry. Returns `true` if novel.
    pub fn add(&mut self, entry: CorpusEntry) -> bool {
        if self.seen.contains(&entry.hash) {
            self.dedup_count += 1;
            return false;
        }
        self.seen.insert(entry.hash);
        let mut e = entry;
        e.id = self.next_id;
        self.next_id += 1;
        self.merged.push(e);
        self.accepted_count += 1;
        true
    }

    /// Merge an entire slice.  Returns count of novel entries added.
    pub fn merge_all(&mut self, entries: &[CorpusEntry]) -> usize {
        let mut added = 0;
        for e in entries {
            if self.add(e.clone()) {
                added += 1;
            }
        }
        added
    }

    /// Deduplication ratio.
    #[must_use]
    pub fn dedup_ratio(&self) -> f64 {
        let total = self.dedup_count + self.accepted_count;
        if total == 0 {
            return 0.0;
        }
        (self.dedup_count as f64) / (total as f64)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.merged.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.merged.is_empty()
    }

    #[must_use]
    pub fn into_entries(self) -> Vec<CorpusEntry> {
        self.merged
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CorpusShrink
// ─────────────────────────────────────────────────────────────────────────────

/// Minimises the corpus to the smallest set that covers all observed edges.
#[derive(Debug, Default)]
pub struct CorpusShrink {
    pub selected: Vec<CorpusEntry>,
    pub pruned_count: usize,
    pub original_size: usize,
}

impl CorpusShrink {
    /// Shrink `entries` to a minimal edge-covering subset.
    #[must_use]
    pub fn shrink(entries: &[CorpusEntry]) -> Self {
        let mut result = Self {
            original_size: entries.len(),
            ..Default::default()
        };
        let (with_edges, without_edges): (Vec<&CorpusEntry>, Vec<&CorpusEntry>) =
            entries.iter().partition(|e| !e.edges.is_empty());
        for e in &without_edges {
            result.selected.push((*e).clone());
        }
        let all_edges: HashSet<u64> = with_edges
            .iter()
            .flat_map(|e| e.edges.iter().copied())
            .collect();
        let mut covered: HashSet<u64> = HashSet::new();
        while covered.len() < all_edges.len() {
            let best = with_edges
                .iter()
                .max_by_key(|e| e.edges.iter().filter(|ed| !covered.contains(ed)).count());
            if let Some(e) = best {
                let new: Vec<u64> = e
                    .edges
                    .iter()
                    .filter(|ed| !covered.contains(ed))
                    .copied()
                    .collect();
                if new.is_empty() {
                    break;
                }
                covered.extend(new);
                result.selected.push((*e).clone());
            } else {
                break;
            }
        }
        result.pruned_count = entries.len() - result.selected.len();
        result
    }

    #[must_use]
    pub fn shrink_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        (self.pruned_count as f64) / (self.original_size as f64)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.selected.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CrashCorpus
// ─────────────────────────────────────────────────────────────────────────────

/// An isolated corpus of crash-inducing inputs.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CrashCorpus {
    entries: Vec<CorpusEntry>,
    seen_hashes: HashSet<u64>,
    next_id: u64,
    pub total_submitted: u64,
}

impl CrashCorpus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a crash entry.  Returns `true` if novel.
    pub fn add(&mut self, data: Vec<u8>, coverage_bits: u32, exec_time_ns: u64) -> bool {
        self.total_submitted += 1;
        let hash = fnv1a(&data);
        if self.seen_hashes.contains(&hash) {
            return false;
        }
        self.seen_hashes.insert(hash);
        let mut e = CorpusEntry::new(self.next_id, data, coverage_bits, exec_time_ns);
        self.next_id += 1;
        e.kind = EntryKind::Crash;
        self.entries.push(e);
        true
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn entries(&self) -> &[CorpusEntry] {
        &self.entries
    }

    #[must_use]
    pub fn by_coverage(&self) -> Vec<&CorpusEntry> {
        let mut v: Vec<&CorpusEntry> = self.entries.iter().collect();
        v.sort_unstable_by(|a, b| b.coverage_bits.cmp(&a.coverage_bits));
        v
    }

    #[must_use]
    pub fn duplicate_rate(&self) -> f64 {
        if self.total_submitted == 0 {
            return 0.0;
        }
        let unique = self.len() as u64;
        ((self.total_submitted - unique) as f64) / (self.total_submitted as f64)
    }

    pub fn prune(&mut self, min_coverage_bits: u32) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|e| e.coverage_bits >= min_coverage_bits);
        before - self.entries.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExportFormat
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    RawBinary,
    JsonMetadata,
    JsonBytesOnly,
    LibFuzzerSeedDir,
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawBinary => write!(f, "raw-binary"),
            Self::JsonMetadata => write!(f, "json-metadata"),
            Self::JsonBytesOnly => write!(f, "json-bytes"),
            Self::LibFuzzerSeedDir => write!(f, "libfuzzer-seed-dir"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ExportedEntry
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedEntry {
    pub filename: String,
    pub data: Vec<u8>,
    pub metadata: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// CorpusExport
// ─────────────────────────────────────────────────────────────────────────────

pub struct CorpusExport;

impl CorpusExport {
    pub fn export(
        entries: &[CorpusEntry],
        format: ExportFormat,
    ) -> Result<Vec<ExportedEntry>, CorpusManagerError> {
        match format {
            ExportFormat::RawBinary | ExportFormat::LibFuzzerSeedDir => Ok(entries
                .iter()
                .map(|e| ExportedEntry {
                    filename: format!("{:06}", e.id),
                    data: e.data.clone(),
                    metadata: None,
                })
                .collect()),
            ExportFormat::JsonBytesOnly => {
                let payload: Vec<&Vec<u8>> = entries.iter().map(|e| &e.data).collect();
                let json = serde_json::to_string(&payload)
                    .map_err(|e| CorpusManagerError::Export(e.to_string()))?;
                Ok(vec![ExportedEntry {
                    filename: "corpus.json".to_string(),
                    data: json.into_bytes(),
                    metadata: None,
                }])
            }
            ExportFormat::JsonMetadata => {
                let json = serde_json::to_string_pretty(entries)
                    .map_err(|e| CorpusManagerError::Export(e.to_string()))?;
                Ok(vec![ExportedEntry {
                    filename: "corpus_metadata.json".to_string(),
                    data: json.into_bytes(),
                    metadata: None,
                }])
            }
        }
    }

    #[must_use]
    pub fn total_bytes(exported: &[ExportedEntry]) -> u64 {
        exported.iter().map(|e| e.data.len() as u64).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CorpusManager
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level corpus management coordinator.
pub struct CorpusManager {
    entries: Vec<CorpusEntry>,
    seen_hashes: HashSet<u64>,
    next_id: u64,
    pub crashes: CrashCorpus,
    pub root: PathBuf,
    pub max_entries: usize,
    pub total_added: u64,
}

impl CorpusManager {
    #[must_use]
    pub fn new(dir: &Path) -> Self {
        Self {
            entries: Vec::new(),
            seen_hashes: HashSet::new(),
            next_id: 1,
            crashes: CrashCorpus::new(),
            root: dir.to_path_buf(),
            max_entries: 0,
            total_added: 0,
        }
    }

    #[must_use]
    pub fn with_max_entries(dir: &Path, max: usize) -> Self {
        let mut m = Self::new(dir);
        m.max_entries = max;
        m
    }

    pub fn add(&mut self, data: Vec<u8>, coverage_bits: u32, exec_time_ns: u64) -> bool {
        let hash = fnv1a(&data);
        if self.seen_hashes.contains(&hash) {
            return false;
        }
        self.seen_hashes.insert(hash);
        let id = self.next_id;
        self.next_id += 1;
        self.entries
            .push(CorpusEntry::new(id, data, coverage_bits, exec_time_ns));
        self.total_added += 1;
        if self.max_entries > 0 && self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
        true
    }

    pub fn add_seed(&mut self, data: Vec<u8>) {
        let hash = fnv1a(&data);
        if self.seen_hashes.contains(&hash) {
            return;
        }
        self.seen_hashes.insert(hash);
        let id = self.next_id;
        self.next_id += 1;
        self.entries.push(CorpusEntry::seed(id, data));
        self.total_added += 1;
    }

    pub fn add_crash(&mut self, data: Vec<u8>, coverage_bits: u32, exec_time_ns: u64) -> bool {
        self.crashes.add(data, coverage_bits, exec_time_ns)
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn entries(&self) -> &[CorpusEntry] {
        &self.entries
    }

    #[must_use]
    pub fn select_best(&self) -> Option<&CorpusEntry> {
        self.entries.iter().max_by(|a, b| {
            a.score()
                .partial_cmp(&b.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    #[must_use]
    pub fn select_rr(&self, n: u64) -> Option<&CorpusEntry> {
        if self.entries.is_empty() {
            return None;
        }
        Some(&self.entries[(n as usize) % self.entries.len()])
    }

    #[must_use]
    pub fn stats(&self) -> CorpusStats {
        CorpusStats::compute(&self.entries)
    }

    pub fn merge_from(&mut self, external: &[CorpusEntry]) -> usize {
        let mut added = 0;
        for e in external {
            if self.add(e.data.clone(), e.coverage_bits, e.exec_time_ns) {
                added += 1;
            }
        }
        added
    }

    pub fn shrink(&mut self) -> usize {
        let result = CorpusShrink::shrink(&self.entries);
        let pruned = result.pruned_count;
        self.entries = result.selected;
        pruned
    }

    pub fn export(&self, format: ExportFormat) -> Result<Vec<ExportedEntry>, CorpusManagerError> {
        CorpusExport::export(&self.entries, format)
    }

    pub fn compute_favorites(&mut self) {
        let mut covered_bits: HashSet<u32> = HashSet::new();
        let mut indices: Vec<usize> = (0..self.entries.len()).collect();
        indices.sort_unstable_by(|&a, &b| {
            self.entries[b]
                .coverage_bits
                .cmp(&self.entries[a].coverage_bits)
        });
        for i in 0..self.entries.len() {
            self.entries[i].is_favored = false;
        }
        for idx in indices {
            let bits = self.entries[idx].coverage_bits;
            if bits == 0 {
                continue;
            }
            if covered_bits.insert(bits) {
                self.entries[idx].is_favored = true;
            }
        }
    }

    pub fn prune(&mut self, min_bits: u32) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|e| e.coverage_bits >= min_bits || e.kind == EntryKind::Seed);
        before - self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.seen_hashes.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn mgr() -> CorpusManager {
        CorpusManager::new(Path::new("/tmp"))
    }

    // ── CorpusEntry ───────────────────────────────────────────────────────────

    #[test]
    fn entry_new() {
        let e = CorpusEntry::new(1, vec![1, 2, 3], 10, 1000);
        assert_eq!(e.id, 1);
        assert_eq!(e.coverage_bits, 10);
        assert_eq!(e.kind, EntryKind::Interesting);
    }

    #[test]
    fn entry_seed_kind() {
        let e = CorpusEntry::seed(1, vec![0xAA]);
        assert_eq!(e.kind, EntryKind::Seed);
    }

    #[test]
    fn entry_score_untried() {
        let e = CorpusEntry::new(1, vec![1], 10, 100);
        assert_eq!(e.score(), f64::MAX);
    }

    #[test]
    fn entry_score_tried() {
        let mut e = CorpusEntry::new(1, vec![1], 10, 100);
        e.selected_count = 5;
        e.interesting_children = 2;
        assert!(e.score() > 0.0 && e.score().is_finite());
    }

    #[test]
    fn entry_select_increments() {
        let mut e = CorpusEntry::new(1, vec![1], 10, 100);
        e.select();
        e.select();
        assert_eq!(e.selected_count, 2);
    }

    #[test]
    fn entry_kind_display() {
        assert_eq!(EntryKind::Seed.to_string(), "seed");
        assert_eq!(EntryKind::Interesting.to_string(), "interesting");
        assert_eq!(EntryKind::Crash.to_string(), "crash");
        assert_eq!(EntryKind::Hang.to_string(), "hang");
        assert_eq!(EntryKind::Imported.to_string(), "imported");
    }

    // ── CorpusStats ───────────────────────────────────────────────────────────

    #[test]
    fn stats_empty() {
        let s = CorpusStats::compute(&[]);
        assert_eq!(s.total_entries, 0);
    }

    #[test]
    fn stats_two_entries() {
        let e1 = CorpusEntry::new(1, vec![1, 2], 10, 100);
        let e2 = CorpusEntry::new(2, vec![3, 4, 5], 20, 200);
        let s = CorpusStats::compute(&[e1, e2]);
        assert_eq!(s.total_entries, 2);
        assert_eq!(s.total_bytes, 5);
        assert!((s.avg_coverage_bits - 15.0).abs() < 1e-9);
    }

    #[test]
    fn stats_seed_count() {
        let e1 = CorpusEntry::seed(1, vec![1]);
        let e2 = CorpusEntry::new(2, vec![2], 5, 100);
        let s = CorpusStats::compute(&[e1, e2]);
        assert_eq!(s.seed_count, 1);
    }

    #[test]
    fn stats_max_min_entry_size() {
        let e1 = CorpusEntry::new(1, vec![1], 5, 100);
        let e2 = CorpusEntry::new(2, vec![1, 2, 3, 4], 5, 100);
        let s = CorpusStats::compute(&[e1, e2]);
        assert_eq!(s.max_entry_size, 4);
        assert_eq!(s.min_entry_size, 1);
    }

    // ── CorpusMerge ───────────────────────────────────────────────────────────

    #[test]
    fn merge_two_unique() {
        let mut m = CorpusMerge::new();
        assert!(m.add(CorpusEntry::new(1, vec![1], 5, 100)));
        assert!(m.add(CorpusEntry::new(2, vec![2], 5, 100)));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn merge_duplicate() {
        let mut m = CorpusMerge::new();
        let e = CorpusEntry::new(1, vec![1], 5, 100);
        m.add(e.clone());
        assert!(!m.add(e));
        assert_eq!(m.dedup_count, 1);
    }

    #[test]
    fn merge_all_counts() {
        let mut m = CorpusMerge::new();
        let added = m.merge_all(&[
            CorpusEntry::new(1, vec![1], 5, 100),
            CorpusEntry::new(2, vec![2], 5, 100),
            CorpusEntry::new(3, vec![1], 5, 100), // dup
        ]);
        assert_eq!(added, 2);
        assert_eq!(m.dedup_count, 1);
    }

    #[test]
    fn merge_dedup_ratio() {
        let mut m = CorpusMerge::new();
        m.merge_all(&[
            CorpusEntry::new(1, vec![1], 5, 100),
            CorpusEntry::new(2, vec![1], 5, 100),
        ]);
        assert!((m.dedup_ratio() - 0.5).abs() < 1e-9);
    }

    // ── CorpusShrink ──────────────────────────────────────────────────────────

    #[test]
    fn shrink_no_edges_keeps_all() {
        let entries = vec![
            CorpusEntry::new(1, vec![1], 5, 100),
            CorpusEntry::new(2, vec![2], 5, 100),
        ];
        let result = CorpusShrink::shrink(&entries);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn shrink_with_edges_reduces_redundant() {
        let mut e1 = CorpusEntry::new(1, vec![1], 10, 100);
        e1.edges = vec![0x1, 0x2, 0x3];
        let mut e2 = CorpusEntry::new(2, vec![2], 8, 100);
        e2.edges = vec![0x1, 0x2]; // subset
        let mut e3 = CorpusEntry::new(3, vec![3], 6, 100);
        e3.edges = vec![0x4]; // unique edge
        let result = CorpusShrink::shrink(&[e1, e2, e3]);
        assert!(result.len() <= 3);
    }

    #[test]
    fn shrink_ratio_non_negative() {
        let mut e1 = CorpusEntry::new(1, vec![1], 10, 100);
        e1.edges = vec![0x1, 0x2];
        let mut e2 = CorpusEntry::new(2, vec![2], 8, 100);
        e2.edges = vec![0x1];
        let result = CorpusShrink::shrink(&[e1, e2]);
        assert!(result.shrink_ratio() >= 0.0);
    }

    // ── CrashCorpus ───────────────────────────────────────────────────────────

    #[test]
    fn crash_corpus_add_novel() {
        let mut cc = CrashCorpus::new();
        assert!(cc.add(vec![0xCC], 5, 1000));
        assert_eq!(cc.len(), 1);
    }

    #[test]
    fn crash_corpus_add_dup() {
        let mut cc = CrashCorpus::new();
        cc.add(vec![0xCC], 5, 1000);
        assert!(!cc.add(vec![0xCC], 5, 1000));
        assert_eq!(cc.len(), 1);
        assert_eq!(cc.total_submitted, 2);
    }

    #[test]
    fn crash_corpus_prune() {
        let mut cc = CrashCorpus::new();
        cc.add(vec![1], 1, 100);
        cc.add(vec![2], 10, 100);
        let pruned = cc.prune(5);
        assert_eq!(pruned, 1);
        assert_eq!(cc.len(), 1);
    }

    #[test]
    fn crash_corpus_duplicate_rate() {
        let mut cc = CrashCorpus::new();
        cc.add(vec![1], 5, 100);
        cc.add(vec![1], 5, 100);
        assert!((cc.duplicate_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn crash_corpus_by_coverage() {
        let mut cc = CrashCorpus::new();
        cc.add(vec![1], 5, 100);
        cc.add(vec![2], 20, 100);
        let sorted = cc.by_coverage();
        assert!(sorted[0].coverage_bits >= sorted[1].coverage_bits);
    }

    // ── CorpusExport ──────────────────────────────────────────────────────────

    #[test]
    fn export_raw_binary() {
        let entries = vec![CorpusEntry::new(1, vec![0xDE, 0xAD], 5, 100)];
        let exported = CorpusExport::export(&entries, ExportFormat::RawBinary).unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].data, vec![0xDE, 0xAD]);
    }

    #[test]
    fn export_json_bytes_only() {
        let entries = vec![CorpusEntry::new(1, vec![1, 2], 5, 100)];
        let exported = CorpusExport::export(&entries, ExportFormat::JsonBytesOnly).unwrap();
        assert_eq!(exported.len(), 1);
        assert!(
            std::str::from_utf8(&exported[0].data)
                .unwrap()
                .contains('[')
        );
    }

    #[test]
    fn export_json_metadata() {
        let entries = vec![CorpusEntry::new(1, vec![1], 5, 100)];
        let exported = CorpusExport::export(&entries, ExportFormat::JsonMetadata).unwrap();
        assert_eq!(exported.len(), 1);
        let json = std::str::from_utf8(&exported[0].data).unwrap();
        assert!(json.contains("coverage_bits"));
    }

    #[test]
    fn export_total_bytes() {
        let entries = vec![CorpusEntry::new(1, vec![1, 2, 3], 5, 100)];
        let exported = CorpusExport::export(&entries, ExportFormat::RawBinary).unwrap();
        assert_eq!(CorpusExport::total_bytes(&exported), 3);
    }

    // ── CorpusManager ─────────────────────────────────────────────────────────

    #[test]
    fn manager_add_novel() {
        let mut m = mgr();
        assert!(m.add(vec![1, 2], 10, 100));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn manager_add_duplicate() {
        let mut m = mgr();
        m.add(vec![1], 10, 100);
        assert!(!m.add(vec![1], 10, 100));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn manager_add_seed_kind() {
        let mut m = mgr();
        m.add_seed(vec![0xAA]);
        assert_eq!(m.entries[0].kind, EntryKind::Seed);
    }

    #[test]
    fn manager_add_crash() {
        let mut m = mgr();
        assert!(m.add_crash(vec![0xCC], 5, 100));
        assert_eq!(m.crashes.len(), 1);
    }

    #[test]
    fn manager_stats() {
        let mut m = mgr();
        m.add(vec![1], 10, 100);
        m.add(vec![2], 20, 200);
        let s = m.stats();
        assert_eq!(s.total_entries, 2);
    }

    #[test]
    fn manager_merge_from() {
        let mut m = mgr();
        let external = vec![
            CorpusEntry::new(1, vec![1], 5, 100),
            CorpusEntry::new(2, vec![2], 10, 200),
        ];
        let added = m.merge_from(&external);
        assert_eq!(added, 2);
    }

    #[test]
    fn manager_select_best() {
        let mut m = mgr();
        m.add(vec![1], 5, 100);
        m.add(vec![2], 20, 100);
        assert!(m.select_best().is_some());
    }

    #[test]
    fn manager_select_rr() {
        let mut m = mgr();
        m.add(vec![1], 5, 100);
        m.add(vec![2], 5, 100);
        let e0 = m.select_rr(0).unwrap();
        let e1 = m.select_rr(1).unwrap();
        assert_ne!(e0.hash, e1.hash);
    }

    #[test]
    fn manager_compute_favorites() {
        let mut m = mgr();
        m.add(vec![1], 10, 100);
        m.add(vec![2], 10, 100);
        m.add(vec![3], 20, 100);
        m.compute_favorites();
        let fav = m.entries.iter().filter(|e| e.is_favored).count();
        assert!(fav >= 1);
    }

    #[test]
    fn manager_prune() {
        let mut m = mgr();
        m.add(vec![1], 1, 100);
        m.add(vec![2], 20, 100);
        let removed = m.prune(10);
        assert_eq!(removed, 1);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn manager_prune_keeps_seeds() {
        let mut m = mgr();
        m.add_seed(vec![0xAA]);
        m.add(vec![1], 1, 100);
        m.prune(10);
        assert!(m.entries.iter().any(|e| e.kind == EntryKind::Seed));
    }

    #[test]
    fn manager_clear() {
        let mut m = mgr();
        m.add(vec![1], 5, 100);
        m.clear();
        assert!(m.is_empty());
    }

    #[test]
    fn manager_max_entries_eviction() {
        let mut m = CorpusManager::with_max_entries(Path::new("/tmp"), 2);
        m.add(vec![1], 5, 100);
        m.add(vec![2], 5, 100);
        m.add(vec![3], 5, 100);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn manager_export_raw() {
        let mut m = mgr();
        m.add(vec![0xDE, 0xAD], 10, 100);
        let exported = m.export(ExportFormat::RawBinary).unwrap();
        assert_eq!(exported.len(), 1);
    }
}
