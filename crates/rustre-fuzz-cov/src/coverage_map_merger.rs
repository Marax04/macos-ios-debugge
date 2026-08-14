//! Coverage map merging for the `RustRE` fuzzing suite.
//!
//! Merges multiple AFL/SanitizerCoverage bitmaps into a single aggregate map,
//! computes per-edge hit statistics, and supports incremental updates.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::CovError;

// ─── RawBitmap ────────────────────────────────────────────────────────────────

/// A raw coverage bitmap (bytes, one per edge).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawBitmap {
    /// Bitmap data.
    pub data: Vec<u8>,
    /// Label identifying the source of this bitmap.
    pub label: String,
    /// Optional source file path.
    pub source_path: Option<PathBuf>,
}

impl RawBitmap {
    /// Create from raw data.
    #[must_use]
    pub fn new(data: Vec<u8>, label: impl Into<String>) -> Self {
        Self { data, label: label.into(), source_path: None }
    }

    /// Create from a file.
    ///
    /// # Errors
    /// Returns `CovError::Io` if the file cannot be read.
    pub fn from_file(path: &Path) -> Result<Self, CovError> {
        let data = std::fs::read(path).map_err(|e| CovError::Io(e.to_string()))?;
        let label = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        Ok(Self { data, label, source_path: Some(path.to_path_buf()) })
    }

    /// Number of non-zero bytes (hit edges).
    #[must_use]
    pub fn hit_count(&self) -> usize {
        self.data.iter().filter(|&&b| b != 0).count()
    }

    /// FNV-1a hash of bitmap data.
    #[must_use]
    pub fn hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.data {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
}

// ─── EdgeStats ────────────────────────────────────────────────────────────────

/// Per-edge hit statistics collected during merging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeStats {
    /// Edge index.
    pub index: u32,
    /// Maximum raw hit count seen across all merged bitmaps.
    pub max_hits: u8,
    /// Number of bitmaps that hit this edge.
    pub hit_by: usize,
    /// First time this edge appeared (index into the ordered merge sequence).
    pub first_seen_at: usize,
}

// ─── MergeResult ─────────────────────────────────────────────────────────────

/// Result of merging multiple coverage bitmaps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeResult {
    /// The merged bitmap (union, max per byte).
    pub bitmap: Vec<u8>,
    /// Total number of hit edges in the merged bitmap.
    pub total_edges_hit: usize,
    /// Total number of edges across the full bitmap.
    pub total_edges: usize,
    /// Per-edge statistics (only for edges that were hit by at least one bitmap).
    pub edge_stats: HashMap<u32, EdgeStats>,
    /// Number of bitmaps merged.
    pub num_sources: usize,
    /// Cumulative edge discovery per bitmap (how many new edges each added).
    pub new_edges_per_source: Vec<usize>,
    /// Labels of merged sources.
    pub source_labels: Vec<String>,
}

impl MergeResult {
    /// Coverage percentage [0.0, 100.0].
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        if self.total_edges == 0 { return 0.0; }
        crate::casts::usize_to_f64(self.total_edges_hit) / crate::casts::usize_to_f64(self.total_edges) * 100.0
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Merged {} bitmaps: {}/{} edges hit ({:.2}%)",
            self.num_sources,
            self.total_edges_hit,
            self.total_edges,
            self.coverage_pct(),
        )
    }

    /// Return the set of edges (indices) hit by every single source.
    #[must_use]
    pub fn universal_edges(&self) -> Vec<u32> {
        let n = self.num_sources;
        self.edge_stats.iter()
            .filter(|(_, s)| s.hit_by == n)
            .map(|(idx, _)| *idx)
            .collect()
    }

    /// Return the set of edges only hit by exactly one source (rare).
    #[must_use]
    pub fn unique_edges(&self) -> Vec<u32> {
        self.edge_stats.iter()
            .filter(|(_, s)| s.hit_by == 1)
            .map(|(idx, _)| *idx)
            .collect()
    }
}

// ─── CoverageMapMerger ───────────────────────────────────────────────────────

/// Merges multiple coverage bitmaps and tracks per-edge statistics.
pub struct CoverageMapMerger {
    /// Current merged bitmap.
    merged: Vec<u8>,
    /// Per-edge statistics.
    edge_stats: HashMap<u32, EdgeStats>,
    /// Source labels.
    source_labels: Vec<String>,
    /// New edges added by each source.
    new_edges_per_source: Vec<usize>,
    /// Number of bitmaps merged so far.
    merge_count: usize,
}

impl CoverageMapMerger {
    /// Create a new merger with a bitmap size hint.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            merged: vec![0u8; capacity],
            edge_stats: HashMap::new(),
            source_labels: Vec::new(),
            new_edges_per_source: Vec::new(),
            merge_count: 0,
        }
    }

    /// Create a merger without a size hint (grows as needed).
    #[must_use]
    pub fn empty() -> Self {
        Self::new(0)
    }

    /// Merge a single bitmap into the accumulator.
    pub fn merge_bitmap(&mut self, bitmap: &RawBitmap) {
        // Extend the merged bitmap if needed.
        if bitmap.data.len() > self.merged.len() {
            self.merged.resize(bitmap.data.len(), 0);
        }

        let mut new_edges = 0usize;
        let seq = self.merge_count;

        for (i, &b) in bitmap.data.iter().enumerate() {
            if b == 0 { continue; }
            let was_zero = self.merged[i] == 0;
            if b > self.merged[i] {
                self.merged[i] = b;
            }
            if was_zero {
                new_edges += 1;
                self.edge_stats.insert(crate::casts::usize_to_u32(i), EdgeStats {
                    index: crate::casts::usize_to_u32(i),
                    max_hits: b,
                    hit_by: 1,
                    first_seen_at: seq,
                });
            } else if let Some(es) = self.edge_stats.get_mut(&crate::casts::usize_to_u32(i)) {
                es.hit_by += 1;
                if b > es.max_hits { es.max_hits = b; }
            }
        }

        self.source_labels.push(bitmap.label.clone());
        self.new_edges_per_source.push(new_edges);
        self.merge_count += 1;
    }

    /// Finalise and return the merge result.
    #[must_use]
    pub fn finish(self) -> MergeResult {
        let total_edges_hit = self.merged.iter().filter(|&&b| b != 0).count();
        MergeResult {
            total_edges: self.merged.len(),
            bitmap: self.merged,
            total_edges_hit,
            edge_stats: self.edge_stats,
            num_sources: self.merge_count,
            new_edges_per_source: self.new_edges_per_source,
            source_labels: self.source_labels,
        }
    }

    /// Merge bitmaps from a directory of raw bitmap files.
    ///
    /// # Errors
    /// Returns `CovError::Io` if the directory cannot be read.
    pub fn merge_dir(dir: &Path) -> Result<MergeResult, CovError> {
        let mut merger = Self::empty();
        let rd = std::fs::read_dir(dir).map_err(|e| CovError::Io(e.to_string()))?;
        for entry in rd.flatten() {
            let path = entry.path();
            if !path.is_file() { continue; }
            if let Ok(bm) = RawBitmap::from_file(&path) {
                merger.merge_bitmap(&bm);
            }
        }
        Ok(merger.finish())
    }
}

// ─── merge_many ──────────────────────────────────────────────────────────────

/// Merge a slice of bitmaps into a single `MergeResult`.
#[must_use]
pub fn merge_many(bitmaps: &[RawBitmap]) -> MergeResult {
    let capacity = bitmaps.iter().map(|b| b.data.len()).max().unwrap_or(0);
    let mut merger = CoverageMapMerger::new(capacity);
    for bm in bitmaps {
        merger.merge_bitmap(bm);
    }
    merger.finish()
}

// ─── DiffReport ──────────────────────────────────────────────────────────────

/// Comparison between two merge results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeDiffReport {
    /// Edges in `a` not in `b`.
    pub only_in_a: Vec<u32>,
    /// Edges in `b` not in `a`.
    pub only_in_b: Vec<u32>,
    /// Edges in both.
    pub in_both: usize,
    /// Jaccard similarity.
    pub jaccard: f64,
}

impl MergeDiffReport {
    /// Compute diff between two merge results.
    #[must_use]
    pub fn diff(a: &MergeResult, b: &MergeResult) -> Self {
        let len = a.bitmap.len().max(b.bitmap.len());
        let mut only_in_a = Vec::new();
        let mut only_in_b = Vec::new();
        let mut in_both = 0usize;

        for i in 0..len {
            let av = a.bitmap.get(i).copied().unwrap_or(0) != 0;
            let bv = b.bitmap.get(i).copied().unwrap_or(0) != 0;
            match (av, bv) {
                (true, false) => only_in_a.push(crate::casts::usize_to_u32(i)),
                (false, true) => only_in_b.push(crate::casts::usize_to_u32(i)),
                (true, true) => in_both += 1,
                _ => {}
            }
        }

        let union = only_in_a.len() + only_in_b.len() + in_both;
        let jaccard = if union == 0 { 1.0 } else { crate::casts::usize_to_f64(in_both) / crate::casts::usize_to_f64(union) };

        Self { only_in_a, only_in_b, in_both, jaccard }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bm(data: Vec<u8>, label: &str) -> RawBitmap {
        RawBitmap::new(data, label)
    }

    #[test]
    fn merge_two_bitmaps() {
        let a = bm(vec![0, 1, 0, 2], "a");
        let b = bm(vec![3, 0, 0, 1], "b");
        let result = merge_many(&[a, b]);
        assert_eq!(result.bitmap, vec![3, 1, 0, 2]);
        assert_eq!(result.total_edges_hit, 3);
    }

    #[test]
    fn new_edges_tracking() {
        let a = bm(vec![1, 0, 0], "a");
        let b = bm(vec![0, 1, 0], "b");
        let result = merge_many(&[a, b]);
        assert_eq!(result.new_edges_per_source[0], 1);
        assert_eq!(result.new_edges_per_source[1], 1);
    }

    #[test]
    fn coverage_pct() {
        let a = bm(vec![1, 1, 0, 0], "a");
        let r = merge_many(&[a]);
        assert!((r.coverage_pct() - 50.0).abs() < 0.1);
    }

    #[test]
    fn unique_edges() {
        let a = bm(vec![1, 0, 1], "a");
        let b = bm(vec![0, 1, 1], "b");
        let r = merge_many(&[a, b]);
        let unique = r.unique_edges();
        assert_eq!(unique.len(), 2); // edge 0 (only a) and edge 1 (only b)
    }

    #[test]
    fn universal_edges() {
        let a = bm(vec![1, 1, 0], "a");
        let b = bm(vec![2, 1, 0], "b");
        let r = merge_many(&[a, b]);
        let universal = r.universal_edges();
        assert!(universal.contains(&0));
        assert!(universal.contains(&1));
    }

    #[test]
    fn merge_empty_input() {
        let r = merge_many(&[]);
        assert_eq!(r.num_sources, 0);
        assert_eq!(r.total_edges_hit, 0);
    }

    #[test]
    fn bitmap_hash_deterministic() {
        let b = bm(vec![1, 2, 3], "h");
        assert_eq!(b.hash(), b.hash());
    }

    #[test]
    fn diff_report() {
        let a = merge_many(&[bm(vec![1, 0, 1], "a")]);
        let b = merge_many(&[bm(vec![0, 1, 1], "b")]);
        let diff = MergeDiffReport::diff(&a, &b);
        assert_eq!(diff.in_both, 1);
        assert_eq!(diff.only_in_a.len(), 1);
        assert_eq!(diff.only_in_b.len(), 1);
    }

    #[test]
    fn merge_dir_nonexistent() {
        let r = CoverageMapMerger::merge_dir(Path::new("/nonexistent_path_99999"));
        assert!(r.is_err());
    }

    #[test]
    fn edge_stats_max_hits() {
        let a = bm(vec![1, 5, 0], "a");
        let b = bm(vec![3, 2, 0], "b");
        let r = merge_many(&[a, b]);
        assert_eq!(r.edge_stats[&0].max_hits, 3);
        assert_eq!(r.edge_stats[&1].max_hits, 5);
    }
}
