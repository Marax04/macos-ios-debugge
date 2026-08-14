/// AFL++ coverage bitmap implementation.
///
/// The bitmap is the core feedback mechanism in AFL: a 64 KiB shared memory
/// region where each byte represents the "hit count" of a specific (`prev_loc`, `cur_loc`)
/// edge. This module provides:
///
/// - `AflBitmap` — the live coverage bitmap, updated during fuzzing
/// - `VirginBits` — tracks which edges have never been seen before
/// - `BitmapStats` — per-run statistics derived from the bitmap
/// - `has_new_coverage()` — fast check for interesting inputs
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard AFL bitmap size: 64 KiB = 65536 bytes.
pub const BITMAP_SIZE: usize = 1 << 16;

/// AFL hit-count buckets: raw counts are mapped to these bucket values.
/// This is the standard AFL bucketing scheme.
const BUCKET_TABLE: [u8; 256] = {
    let mut t = [0u8; 256];
    // 0 → 0
    t[0] = 0;
    // 1 → 1
    t[1] = 1;
    // 2 → 2
    t[2] = 2;
    // 3 → 4
    t[3] = 4;
    // 4..=7 → 8
    let mut i = 4usize;
    while i <= 7 { t[i] = 8; i += 1; }
    // 8..=15 → 16
    let mut i = 8usize;
    while i <= 15 { t[i] = 16; i += 1; }
    // 16..=31 → 32
    let mut i = 16usize;
    while i <= 31 { t[i] = 32; i += 1; }
    // 32..=127 → 64
    let mut i = 32usize;
    while i <= 127 { t[i] = 64; i += 1; }
    // 128..=255 → 128
    let mut i = 128usize;
    while i <= 255 { t[i] = 128; i += 1; }
    t
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitmapError {
    #[error("bitmap index {0} out of range (max {BITMAP_SIZE})")]
    IndexOutOfRange(usize),
    #[error("bitmap sizes differ: {0} vs {1}")]
    SizeMismatch(usize, usize),
    #[error("virgin bits and bitmap sizes differ")]
    VirginSizeMismatch,
}

// ---------------------------------------------------------------------------
// AflBitmap — the live coverage bitmap
// ---------------------------------------------------------------------------

/// The AFL coverage bitmap.
///
/// Internally stores raw byte counts per edge. The `classify_counts()` method
/// applies bucket normalization before comparison with virgin bits.
#[derive(Clone, Serialize, Deserialize)]
pub struct AflBitmap {
    data: Vec<u8>,
    /// Count of edges with non-zero hit count.
    populated: usize,
}

impl std::fmt::Debug for AflBitmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AflBitmap")
            .field("size", &self.data.len())
            .field("populated_edges", &self.populated)
            .finish()
    }
}

impl AflBitmap {
    /// Create a new zeroed bitmap of size `BITMAP_SIZE`.
    #[must_use] 
    pub fn new() -> Self {
        Self { data: vec![0u8; BITMAP_SIZE], populated: 0 }
    }

    /// Create a bitmap from raw bytes (must be exactly `BITMAP_SIZE` bytes).
    ///
    /// # Errors
    /// Returns [`BitmapError::SizeMismatch`] if the input is not exactly `BITMAP_SIZE` bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, BitmapError> {
        if bytes.len() != BITMAP_SIZE {
            return Err(BitmapError::SizeMismatch(bytes.len(), BITMAP_SIZE));
        }
        let populated = bytes.iter().filter(|&&b| b != 0).count();
        Ok(Self { data: bytes, populated })
    }

    /// Increment the hit count for edge `idx`.
    ///
    /// # Errors
    /// Returns [`BitmapError::IndexOutOfRange`] if `idx >= BITMAP_SIZE`.
    pub fn hit(&mut self, idx: usize) -> Result<(), BitmapError> {
        let cell = self.data.get_mut(idx).ok_or(BitmapError::IndexOutOfRange(idx))?;
        if *cell == 0 {
            self.populated += 1;
        }
        *cell = cell.saturating_add(1);
        Ok(())
    }

    /// Set a specific edge to `val`.
    ///
    /// # Errors
    /// Returns [`BitmapError::IndexOutOfRange`] if `idx >= BITMAP_SIZE`.
    pub fn set(&mut self, idx: usize, val: u8) -> Result<(), BitmapError> {
        let cell = self.data.get_mut(idx).ok_or(BitmapError::IndexOutOfRange(idx))?;
        let was_zero = *cell == 0;
        *cell = val;
        match (was_zero, val == 0) {
            (true, false) => self.populated += 1,
            (false, true) => self.populated = self.populated.saturating_sub(1),
            _ => {}
        }
        Ok(())
    }

    /// Read the raw hit count for edge `idx`.
    ///
    /// # Errors
    /// Returns [`BitmapError::IndexOutOfRange`] if `idx >= BITMAP_SIZE`.
    pub fn get(&self, idx: usize) -> Result<u8, BitmapError> {
        self.data.get(idx).copied().ok_or(BitmapError::IndexOutOfRange(idx))
    }

    /// Return a bucketed (normalized) copy of this bitmap.
    #[must_use] 
    pub fn classify_counts(&self) -> Self {
        let classified: Vec<u8> = self.data.iter().map(|&b| BUCKET_TABLE[b as usize]).collect();
        let populated = classified.iter().filter(|&&b| b != 0).count();
        Self { data: classified, populated }
    }

    /// Clear the entire bitmap.
    pub fn clear(&mut self) {
        self.data.fill(0);
        self.populated = 0;
    }

    /// Number of edges with non-zero hit counts.
    #[must_use] 
    pub const fn populated_edges(&self) -> usize {
        self.populated
    }

    /// Raw byte slice.
    #[must_use] 
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Compute a 32-bit hash of the non-zero edges (useful for dedup).
    #[must_use] 
    pub fn hash32(&self) -> u32 {
        let mut h = 0x811c_9dc5_u32;
        for (i, &v) in self.data.iter().enumerate() {
            if v != 0 {
                h ^= u32::try_from(i).unwrap_or(u32::MAX);
                h = h.wrapping_mul(0x0100_0193);
                h ^= u32::from(v);
                h = h.wrapping_mul(0x0100_0193);
            }
        }
        h
    }

    /// OR-merge another bitmap into this one (used for corpus-wide coverage).
    pub fn merge_or(&mut self, other: &Self) {
        debug_assert_eq!(self.data.len(), other.data.len());
        self.populated = 0;
        for (a, &b) in self.data.iter_mut().zip(other.data.iter()) {
            *a |= b;
            if *a != 0 { self.populated += 1; }
        }
    }

    /// Count edges that are set in `self` but not in `other`.
    #[must_use] 
    pub fn new_edges_vs(&self, other: &Self) -> usize {
        self.data.iter().zip(other.data.iter()).filter(|&(&a, &b)| a != 0 && b == 0).count()
    }

    /// Build a frequency map: hit-count bucket → number of edges.
    #[must_use] 
    pub fn bucket_histogram(&self) -> HashMap<u8, usize> {
        let mut map: HashMap<u8, usize> = HashMap::new();
        for &v in &self.data {
            let bucket = BUCKET_TABLE[v as usize];
            *map.entry(bucket).or_insert(0) += 1;
        }
        map
    }
}

impl Default for AflBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// VirginBits — tracks unseen edges across the entire fuzzing campaign
// ---------------------------------------------------------------------------

/// Tracks which edges have never been seen in any previous run.
///
/// A bit value of `0xFF` means the edge is "virgin" (never hit). After each run
/// the virgin bits are `ANDed` with the NOT of the run's bitmap — any newly hit
/// edges are "consumed."
#[derive(Clone, Serialize, Deserialize)]
pub struct VirginBits {
    data: Vec<u8>,
    /// How many edges remain virgin.
    virgin_count: usize,
}

impl std::fmt::Debug for VirginBits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirginBits")
            .field("size", &self.data.len())
            .field("virgin_count", &self.virgin_count)
            .finish()
    }
}

impl VirginBits {
    /// Create a fresh virgin-bits map (all `0xFF`).
    #[must_use] 
    pub fn new() -> Self {
        let data = vec![0xFFu8; BITMAP_SIZE];
        Self { data, virgin_count: BITMAP_SIZE }
    }

    /// Update virgin bits with a new run's classified bitmap.
    /// Returns the number of newly discovered edges.
    ///
    /// # Errors
    /// Returns [`BitmapError::VirginSizeMismatch`] if bitmap sizes differ.
    pub fn update(&mut self, run_bitmap: &AflBitmap) -> Result<usize, BitmapError> {
        if run_bitmap.data.len() != self.data.len() {
            return Err(BitmapError::VirginSizeMismatch);
        }
        let mut new_edges = 0usize;
        for (v, &r) in self.data.iter_mut().zip(run_bitmap.data.iter()) {
            if r != 0 && *v != 0 {
                let before = *v;
                *v &= !r;
                if before == 0xFF && *v != 0xFF {
                    new_edges += 1;
                    self.virgin_count = self.virgin_count.saturating_sub(1);
                }
            }
        }
        Ok(new_edges)
    }

    /// Number of edges that are still virgin (never hit).
    #[must_use] 
    pub const fn virgin_count(&self) -> usize {
        self.virgin_count
    }

    /// Number of edges that have been seen at least once.
    #[must_use] 
    pub const fn seen_count(&self) -> usize {
        BITMAP_SIZE - self.virgin_count
    }

    /// Check whether a specific edge is still virgin.
    #[must_use] 
    pub fn is_virgin(&self, idx: usize) -> bool {
        self.data.get(idx).copied().unwrap_or(0) == 0xFF
    }

    /// Reset all bits to virgin state.
    pub fn reset(&mut self) {
        self.data.fill(0xFF);
        self.virgin_count = BITMAP_SIZE;
    }

    #[must_use] 
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Collect all edges that were newly seen after calling `update`.
    /// This is a separate pass — call *before* `update` if you need the list.
    #[must_use] 
    pub fn new_edges_in(&self, run_bitmap: &AflBitmap) -> Vec<usize> {
        self.data
            .iter()
            .zip(run_bitmap.data.iter())
            .enumerate()
            .filter(|&(_, (&v, &r))| r != 0 && v == 0xFF)
            .map(|(i, _)| i)
            .collect()
    }
}

impl Default for VirginBits {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BitmapStats — per-run statistics
// ---------------------------------------------------------------------------

/// Statistics derived from comparing a run's bitmap against the virgin map.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BitmapStats {
    /// Total non-zero edges in this run.
    pub edges_hit: usize,
    /// Edges hit for the first time in this run.
    pub new_edges: usize,
    /// Edges where the bucket changed (same edge, higher/lower hit count).
    pub bucket_changes: usize,
    /// 32-bit hash of the classified bitmap.
    pub bitmap_hash: u32,
    /// Percentage of the full bitmap covered.
    pub coverage_pct: f64,
}

impl BitmapStats {
    /// Compute stats for `run` given the current `virgin` state.
    ///
    /// NOTE: This does NOT mutate `virgin` — call `virgin.update()` separately if desired.
    ///
    /// # Errors
    /// Returns [`BitmapError::VirginSizeMismatch`] if bitmap sizes differ.
    pub fn compute(run: &AflBitmap, virgin: &VirginBits) -> Result<Self, BitmapError> {
        if run.data.len() != virgin.data.len() {
            return Err(BitmapError::VirginSizeMismatch);
        }
        let classified = run.classify_counts();
        let edges_hit = classified.populated_edges();
        let new_edges = virgin.new_edges_in(&classified).len();
        let bitmap_hash = classified.hash32();

        // Bucket changes: edges where virgin still has some bits set (i.e. bucket changed)
        // but the edge was already seen (virgin != 0xFF).
        let bucket_changes = run
            .data
            .iter()
            .zip(virgin.data.iter())
            .filter(|&(&r, &v)| r != 0 && v != 0 && v != 0xFF)
            .count();

        let coverage_pct = f64::from(u32::try_from(edges_hit).unwrap_or(u32::MAX)) / f64::from(u32::try_from(BITMAP_SIZE).unwrap_or(u32::MAX)) * 100.0;

        Ok(Self { edges_hit, new_edges, bucket_changes, bitmap_hash, coverage_pct })
    }

    /// Returns `true` if this run is "interesting" — has new edges or new bucket transitions.
    #[must_use] 
    pub const fn is_interesting(&self) -> bool {
        self.new_edges > 0 || self.bucket_changes > 0
    }
}

// ---------------------------------------------------------------------------
// has_new_coverage — fast public API
// ---------------------------------------------------------------------------

/// Fast check: does `run_bitmap` contain any edge not yet present in `virgin`?
///
/// This mirrors AFL's inner loop hot path.
#[must_use] 
pub fn has_new_coverage(run_bitmap: &AflBitmap, virgin: &VirginBits) -> bool {
    run_bitmap
        .data
        .iter()
        .zip(virgin.data.iter())
        .any(|(&r, &v)| r != 0 && v == 0xFF)
}

// ---------------------------------------------------------------------------
// Bitmap distance
// ---------------------------------------------------------------------------

/// Compute the Hamming distance (differing bytes) between two bitmaps.
#[must_use] 
pub fn hamming_distance(a: &AflBitmap, b: &AflBitmap) -> usize {
    a.data.iter().zip(b.data.iter()).filter(|&(&x, &y)| x != y).count()
}

/// Compute the Jaccard similarity between the non-zero edge sets of two bitmaps.
#[must_use] 
pub fn jaccard_similarity(a: &AflBitmap, b: &AflBitmap) -> f64 {
    let intersection = a
        .data
        .iter()
        .zip(b.data.iter())
        .filter(|&(&x, &y)| x != 0 && y != 0)
        .count();
    let union = a
        .data
        .iter()
        .zip(b.data.iter())
        .filter(|&(&x, &y)| x != 0 || y != 0)
        .count();
    if union == 0 { 1.0 } else { f64::from(u32::try_from(intersection).unwrap_or(u32::MAX)) / f64::from(u32::try_from(union).unwrap_or(u32::MAX)) }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_hit_and_get() {
        let mut bm = AflBitmap::new();
        assert_eq!(bm.get(0).unwrap(), 0);
        bm.hit(0).unwrap();
        bm.hit(0).unwrap();
        assert_eq!(bm.get(0).unwrap(), 2);
        assert_eq!(bm.populated_edges(), 1);
    }

    #[test]
    fn test_classify_counts_bucketing() {
        let mut bm = AflBitmap::new();
        bm.set(0, 3).unwrap(); // bucket 4
        bm.set(1, 10).unwrap(); // bucket 16
        let classified = bm.classify_counts();
        assert_eq!(classified.get(0).unwrap(), 4);
        assert_eq!(classified.get(1).unwrap(), 16);
    }

    #[test]
    fn test_virgin_bits_update() {
        let mut bm = AflBitmap::new();
        bm.hit(5).unwrap();
        bm.hit(100).unwrap();
        let classified = bm.classify_counts();
        let mut virgin = VirginBits::new();
        let new_edges = virgin.update(&classified).unwrap();
        assert_eq!(new_edges, 2);
        assert!(!virgin.is_virgin(5));
        assert!(!virgin.is_virgin(100));
        assert!(virgin.is_virgin(6));
    }

    #[test]
    fn test_has_new_coverage_true() {
        let mut bm = AflBitmap::new();
        bm.hit(42).unwrap();
        let virgin = VirginBits::new();
        assert!(has_new_coverage(&bm, &virgin));
    }

    #[test]
    fn test_has_new_coverage_false_after_update() {
        let mut bm = AflBitmap::new();
        bm.hit(42).unwrap();
        let classified = bm.classify_counts();
        let mut virgin = VirginBits::new();
        virgin.update(&classified).unwrap();
        assert!(!has_new_coverage(&classified, &virgin));
    }

    #[test]
    fn test_bitmap_stats_interesting() {
        let mut bm = AflBitmap::new();
        bm.hit(1).unwrap();
        let classified = bm.classify_counts();
        let virgin = VirginBits::new();
        let stats = BitmapStats::compute(&classified, &virgin).unwrap();
        assert!(stats.is_interesting());
        assert_eq!(stats.new_edges, 1);
    }

    #[test]
    fn test_merge_or() {
        let mut a = AflBitmap::new();
        a.hit(10).unwrap();
        let mut b = AflBitmap::new();
        b.hit(20).unwrap();
        a.merge_or(&b);
        assert_ne!(a.get(10).unwrap(), 0);
        assert_ne!(a.get(20).unwrap(), 0);
    }

    #[test]
    fn test_hash32_stability() {
        let mut bm = AflBitmap::new();
        bm.hit(7).unwrap();
        let h1 = bm.hash32();
        let h2 = bm.hash32();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hamming_distance() {
        let mut a = AflBitmap::new();
        a.hit(0).unwrap();
        let b = AflBitmap::new();
        assert!(hamming_distance(&a, &b) > 0);
    }

    #[test]
    fn test_jaccard_identical() {
        let mut a = AflBitmap::new();
        a.hit(1).unwrap();
        let b = a.clone();
        assert!((jaccard_similarity(&a, &b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_bucket_histogram() {
        let mut bm = AflBitmap::new();
        bm.set(0, 1).unwrap();
        bm.set(1, 3).unwrap();
        let hist = bm.bucket_histogram();
        assert_eq!(hist.get(&1), Some(&1));
        assert_eq!(hist.get(&4), Some(&1));
    }
}
