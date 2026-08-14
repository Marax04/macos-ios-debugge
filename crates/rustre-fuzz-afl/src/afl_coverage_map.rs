//! AFL coverage bitmap analysis.
//!
//! Reads, merges, and analyses the 64 KiB shared-memory coverage bitmaps
//! written by AFL++ instrumentation.  No external crates required.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Default AFL bitmap size: 2^16 bytes.
pub const AFL_MAP_SIZE: usize = 65536;

// ─── MapEntry ─────────────────────────────────────────────────────────────────

/// A single edge (AFL bucket) that was hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapEntry {
    /// Index into the 64 KiB bitmap.
    pub index: u32,
    /// Raw hit-count byte value (AFL bucketized: 1,2,3,4,8,16,32,128).
    pub hits: u8,
}

impl MapEntry {
    /// Convert a raw AFL hit-count to the normalized bucket value.
    ///
    /// AFL uses a log-scale bucketing to avoid treating e.g. 100 hits vs 99
    /// hits as a new coverage discovery.
    #[must_use]
    pub const fn bucket(raw: u8) -> u8 {
        match raw {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            4..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            32..=127 => 64,
            _ => 128,
        }
    }

    /// Returns `true` if this edge was hit at least once.
    #[must_use]
    pub const fn is_hit(self) -> bool {
        self.hits != 0
    }
}

// ─── BitmapStats ──────────────────────────────────────────────────────────────

/// Statistics over a single AFL coverage bitmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitmapStats {
    /// Total bitmap size (bytes).
    pub map_size: usize,
    /// Number of non-zero edges.
    pub edges_hit: usize,
    /// Total edge hit counts (sum of all bytes).
    pub total_hits: u64,
    /// Percentage of bitmap that is non-zero.
    pub coverage_percent: f64,
    /// Maximum hit-count byte in the bitmap.
    pub max_hits: u8,
    /// Number of edges at each bucket level (`bucket_value` → count).
    pub bucket_distribution: HashMap<u8, usize>,
    /// Path this bitmap was loaded from (if known).
    pub source_path: Option<PathBuf>,
}

impl BitmapStats {
    /// Compute statistics from a raw bitmap slice.
    #[must_use]
    pub fn from_bitmap(bitmap: &[u8], source: Option<PathBuf>) -> Self {
        let mut edges_hit = 0usize;
        let mut total_hits = 0u64;
        let mut max_hits = 0u8;
        let mut bucket_distribution: HashMap<u8, usize> = HashMap::new();
        for &b in bitmap {
            if b != 0 {
                edges_hit += 1;
                total_hits += u64::from(b);
                if b > max_hits { max_hits = b; }
                *bucket_distribution.entry(MapEntry::bucket(b)).or_insert(0) += 1;
            }
        }
        let coverage_percent = if bitmap.is_empty() {
            0.0
        } else {
            f64::from(u32::try_from(edges_hit).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(bitmap.len()).unwrap_or(u32::MAX))
                * 100.0
        };
        Self {
            map_size: bitmap.len(),
            edges_hit,
            total_hits,
            coverage_percent,
            max_hits,
            bucket_distribution,
            source_path: source,
        }
    }

    /// One-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "edges={} ({:.2}%) total_hits={} max={}",
            self.edges_hit, self.coverage_percent, self.total_hits, self.max_hits,
        )
    }
}

// ─── AflCoverageMap ───────────────────────────────────────────────────────────

/// Wrapper around a raw AFL coverage bitmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AflCoverageMap {
    /// Raw 64 KiB bitmap (or smaller for custom builds).
    pub bitmap: Vec<u8>,
    /// Identifier string (e.g. the input filename that produced this map).
    pub label: String,
}

impl AflCoverageMap {
    /// Create from a raw bitmap with a label.
    #[must_use]
    pub fn new(bitmap: Vec<u8>, label: impl Into<String>) -> Self {
        Self { bitmap, label: label.into() }
    }

    /// Create an all-zero map of the default AFL size.
    #[must_use]
    pub fn zeroed() -> Self {
        Self::new(vec![0u8; AFL_MAP_SIZE], "zero".to_string())
    }

    /// Load from a file (reads raw bytes).
    ///
    /// # Errors
    /// Returns `std::io::Error` if the file cannot be read.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bitmap = std::fs::read(path)?;
        let label = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        Ok(Self::new(bitmap, label))
    }

    /// Number of non-zero edges.
    #[must_use]
    pub fn edges_hit(&self) -> usize {
        self.bitmap.iter().filter(|&&b| b != 0).count()
    }

    /// Compute detailed statistics.
    #[must_use]
    pub fn stats(&self) -> BitmapStats {
        BitmapStats::from_bitmap(&self.bitmap, None)
    }

    /// Return all hit entries (index + hits).
    #[must_use]
    pub fn hit_entries(&self) -> Vec<MapEntry> {
        self.bitmap
            .iter()
            .enumerate()
            .filter(|(_, b)| **b != 0)
            .map(|(i, b)| MapEntry { index: u32::try_from(i).unwrap_or(u32::MAX), hits: *b })
            .collect()
    }

    /// Merge another map into `self` by OR-ing hit counts (keeps higher value).
    pub fn merge_in(&mut self, other: &Self) {
        let len = self.bitmap.len().min(other.bitmap.len());
        for i in 0..len {
            if other.bitmap[i] > self.bitmap[i] {
                self.bitmap[i] = other.bitmap[i];
            }
        }
    }

    /// Return a new map that is the union (max per byte) of `self` and `other`.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let len = self.bitmap.len().max(other.bitmap.len());
        let mut out = vec![0u8; len];
        for (i, elem) in out.iter_mut().enumerate() {
            let a = self.bitmap.get(i).copied().unwrap_or(0);
            let b = other.bitmap.get(i).copied().unwrap_or(0);
            *elem = a.max(b);
        }
        Self::new(out, format!("{}+{}", self.label, other.label))
    }

    /// Edges present in `self` but NOT in `other`.
    #[must_use]
    pub fn new_edges_vs(&self, other: &Self) -> Vec<MapEntry> {
        self.bitmap
            .iter()
            .enumerate()
            .filter(|(i, b)| **b != 0 && other.bitmap.get(*i).copied().unwrap_or(0) == 0)
            .map(|(i, b)| MapEntry { index: u32::try_from(i).unwrap_or(u32::MAX), hits: *b })
            .collect()
    }

    /// Bucketed copy: replace each byte with its AFL bucket value.
    #[must_use]
    pub fn bucketed(&self) -> Self {
        let bm: Vec<u8> = self.bitmap.iter().map(|&b| MapEntry::bucket(b)).collect();
        Self::new(bm, format!("{}_bucketed", self.label))
    }

    /// XOR distance from another map (sum of abs differences).
    #[must_use]
    pub fn distance(&self, other: &Self) -> u64 {
        let len = self.bitmap.len().min(other.bitmap.len());
        self.bitmap[..len]
            .iter()
            .zip(other.bitmap[..len].iter())
            .map(|(&a, &b)| u64::from(a.abs_diff(b)))
            .sum()
    }

    /// FNV-1a hash of the bitmap (for deduplication).
    #[must_use]
    pub fn bitmap_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.bitmap {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
}

// ─── merge_maps ───────────────────────────────────────────────────────────────

/// Merge multiple maps into a single union map.
///
/// Each byte position takes the maximum value across all input maps.
#[must_use]
pub fn merge_maps(maps: &[AflCoverageMap]) -> AflCoverageMap {
    if maps.is_empty() {
        return AflCoverageMap::zeroed();
    }
    let max_len = maps.iter().map(|m| m.bitmap.len()).max().unwrap_or(AFL_MAP_SIZE);
    let mut out = vec![0u8; max_len];
    for map in maps {
        for (i, &b) in map.bitmap.iter().enumerate() {
            if b > out[i] {
                out[i] = b;
            }
        }
    }
    AflCoverageMap::new(out, "merged".to_string())
}

// ─── MapComparisonReport ─────────────────────────────────────────────────────

/// Comparison report between two coverage maps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapComparisonReport {
    /// Label for map A.
    pub label_a: String,
    /// Label for map B.
    pub label_b: String,
    /// Edges in A not in B.
    pub only_in_a: Vec<MapEntry>,
    /// Edges in B not in A.
    pub only_in_b: Vec<MapEntry>,
    /// Edges in both.
    pub in_both: usize,
    /// Total edges in A.
    pub total_a: usize,
    /// Total edges in B.
    pub total_b: usize,
    /// XOR distance.
    pub distance: u64,
    /// Jaccard similarity [0.0, 1.0].
    pub jaccard: f64,
}

impl MapComparisonReport {
    /// Build a comparison between two maps.
    #[must_use]
    pub fn compare(a: &AflCoverageMap, b: &AflCoverageMap) -> Self {
        let only_in_a = a.new_edges_vs(b);
        let only_in_b = b.new_edges_vs(a);
        let total_a = a.edges_hit();
        let total_b = b.edges_hit();
        let in_both = if total_a + total_b == 0 {
            0
        } else {
            // |A ∩ B| = |A| + |B| - |A ∪ B|
            let union = a.union(b).edges_hit();
            total_a + total_b - union
        };
        let union_size = in_both + only_in_a.len() + only_in_b.len();
        let jaccard = if union_size == 0 {
            1.0
        } else {
            f64::from(u32::try_from(in_both).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(union_size).unwrap_or(u32::MAX))
        };
        Self {
            label_a: a.label.clone(),
            label_b: b.label.clone(),
            only_in_a,
            only_in_b,
            in_both,
            total_a,
            total_b,
            distance: a.distance(b),
            jaccard,
        }
    }
}

// ─── CoverageMapDatabase ──────────────────────────────────────────────────────

/// An in-memory database of coverage maps keyed by label.
#[derive(Debug, Default)]
pub struct CoverageMapDatabase {
    maps: HashMap<String, AflCoverageMap>,
}

impl CoverageMapDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a map.
    pub fn insert(&mut self, map: AflCoverageMap) {
        self.maps.insert(map.label.clone(), map);
    }

    /// Get by label.
    #[must_use]
    pub fn get(&self, label: &str) -> Option<&AflCoverageMap> {
        self.maps.get(label)
    }

    /// Number of maps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.maps.len()
    }

    /// Returns `true` if no maps stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
    }

    /// All labels.
    #[must_use]
    pub fn labels(&self) -> Vec<&str> {
        self.maps.keys().map(std::string::String::as_str).collect()
    }

    /// Merge all stored maps into a single union map.
    #[must_use]
    pub fn global_union(&self) -> AflCoverageMap {
        let all: Vec<AflCoverageMap> = self.maps.values().cloned().collect();
        merge_maps(&all)
    }

    /// Remove duplicate maps (same bitmap hash).
    pub fn deduplicate(&mut self) {
        let mut seen: HashMap<u64, String> = HashMap::new();
        let mut to_remove = Vec::new();
        for (label, map) in &self.maps {
            let h = map.bitmap_hash();
            if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(h) {
                e.insert(label.clone());
            } else {
                to_remove.push(label.clone());
            }
        }
        for label in to_remove {
            self.maps.remove(&label);
        }
    }

    /// Load all raw bitmap files from `dir`.
    ///
    /// # Errors
    /// Returns `std::io::Error` if the directory cannot be read.
    pub fn load_dir(&mut self, dir: &Path) -> std::io::Result<usize> {
        let mut count = 0;
        for entry in std::fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Ok(m) = AflCoverageMap::load(&path) { self.insert(m); count += 1; }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(bytes: Vec<u8>, label: &str) -> AflCoverageMap {
        AflCoverageMap::new(bytes, label)
    }

    #[test]
    fn bucket_values() {
        assert_eq!(MapEntry::bucket(0), 0);
        assert_eq!(MapEntry::bucket(1), 1);
        assert_eq!(MapEntry::bucket(2), 2);
        assert_eq!(MapEntry::bucket(5), 8);
        assert_eq!(MapEntry::bucket(255), 128);
    }

    #[test]
    fn edges_hit_count() {
        let m = make_map(vec![0, 1, 0, 2, 0], "test");
        assert_eq!(m.edges_hit(), 2);
    }

    #[test]
    fn union_takes_max() {
        let a = make_map(vec![0, 5, 10], "a");
        let b = make_map(vec![3, 2, 15], "b");
        let u = a.union(&b);
        assert_eq!(u.bitmap, vec![3, 5, 15]);
    }

    #[test]
    fn new_edges_vs() {
        let a = make_map(vec![1, 0, 1], "a");
        let b = make_map(vec![0, 0, 1], "b");
        let new_in_a = a.new_edges_vs(&b);
        assert_eq!(new_in_a.len(), 1);
        assert_eq!(new_in_a[0].index, 0);
    }

    #[test]
    fn merge_maps_union() {
        let a = make_map(vec![0, 5], "a");
        let b = make_map(vec![3, 1], "b");
        let merged = merge_maps(&[a, b]);
        assert_eq!(merged.bitmap, vec![3, 5]);
    }

    #[test]
    fn merge_empty() {
        let m = merge_maps(&[]);
        assert_eq!(m.bitmap.len(), AFL_MAP_SIZE);
    }

    #[test]
    fn bitmap_stats() {
        let m = make_map(vec![0, 1, 2, 0, 255], "s");
        let stats = m.stats();
        assert_eq!(stats.edges_hit, 3);
        assert_eq!(stats.max_hits, 255);
    }

    #[test]
    fn bitmap_hash_deterministic() {
        let m = make_map(vec![1, 2, 3], "h");
        assert_eq!(m.bitmap_hash(), m.bitmap_hash());
    }

    #[test]
    fn jaccard_identical() {
        let a = make_map(vec![1, 0, 1], "a");
        let b = make_map(vec![1, 0, 1], "b");
        let report = MapComparisonReport::compare(&a, &b);
        assert!((report.jaccard - 1.0).abs() < 1e-6);
    }

    #[test]
    fn database_dedup() {
        let mut db = CoverageMapDatabase::new();
        db.insert(make_map(vec![1, 2, 3], "x"));
        db.insert(make_map(vec![1, 2, 3], "y"));
        db.deduplicate();
        assert_eq!(db.len(), 1);
    }
}
