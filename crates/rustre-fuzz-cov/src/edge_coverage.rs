//! Edge-level coverage tracking for `rustre-fuzz-cov`.
//!
//! Provides [`EdgeCoverage`], [`EdgeId`], [`EdgeBitmap`] (64 K bits),
//! [`EdgeFrequency`], [`NewEdgeDetector`], [`EdgeStatistics`], and
//! [`CoverageProfile`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

// ── EdgeId ────────────────────────────────────────────────────────────────────

/// A unique identifier for a control-flow edge.
///
/// Computed as `src_pc XOR dst_pc` shifted by 1 to give AFL-style edge hashing,
/// then masked to 16 bits so it indexes directly into a 64 K-bit bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EdgeId(pub u16);

impl EdgeId {
    /// Construct an [`EdgeId`] from source and destination program counters.
    ///
    /// Uses the standard AFL formula: `(src >> 1) XOR dst`, masked to 16 bits.
    #[must_use]
    pub const fn from_pcs(src_pc: u64, dst_pc: u64) -> Self {
        // Mask to low 16 bits (AFL formula). `as u16` would truncate; instead
        // round-trip through `to_le_bytes` to get the low two bytes losslessly.
        let raw = (src_pc >> 1) ^ dst_pc;
        let bytes = raw.to_le_bytes();
        let v = u16::from_le_bytes([bytes[0], bytes[1]]);
        Self(v)
    }

    /// Raw 16-bit value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Index into the [`EdgeBitmap`] byte array: `id / 8`.
    #[must_use]
    pub const fn byte_index(self) -> usize {
        (self.0 as usize) / 8
    }

    /// Bit index within the byte: `id % 8`.
    #[must_use]
    pub const fn bit_index(self) -> u8 {
        (self.0 % 8) as u8
    }

    /// The bitmask for this edge within its byte: `1 << bit_index`.
    #[must_use]
    pub const fn mask(self) -> u8 {
        1u8 << self.bit_index()
    }
}

impl std::fmt::Display for EdgeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "edge#{}", self.0)
    }
}

// ── EdgeBitmap ────────────────────────────────────────────────────────────────

/// A compact 64 K-bit (8 192-byte) bitmap tracking which edges have been hit.
///
/// Each bit position corresponds to an [`EdgeId`] value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeBitmap {
    /// 8 192 bytes = 65 536 bits.
    bytes: Vec<u8>,
}

impl EdgeBitmap {
    /// Size of the bitmap in bits (2^16 = 65 536).
    pub const BITS: usize = 65_536;
    /// Size of the bitmap in bytes (8 192).
    pub const BYTES: usize = Self::BITS / 8;

    /// Create a zeroed bitmap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes: vec![0u8; Self::BYTES],
        }
    }

    /// Create from raw bytes (must be exactly 8 192 bytes).
    ///
    /// # Panics
    /// Panics if `bytes.len() != 8192`.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        assert_eq!(bytes.len(), Self::BYTES, "EdgeBitmap requires exactly {} bytes", Self::BYTES);
        Self { bytes }
    }

    /// Set the bit for `edge_id`.
    pub fn set(&mut self, edge: EdgeId) {
        self.bytes[edge.byte_index()] |= edge.mask();
    }

    /// Clear the bit for `edge_id`.
    pub fn clear(&mut self, edge: EdgeId) {
        self.bytes[edge.byte_index()] &= !edge.mask();
    }

    /// Returns `true` if the bit for `edge_id` is set.
    #[must_use]
    pub fn is_set(&self, edge: EdgeId) -> bool {
        self.bytes[edge.byte_index()] & edge.mask() != 0
    }

    /// Count the total number of set bits.
    #[must_use]
    pub fn count_set(&self) -> u32 {
        self.bytes.iter().map(|b| b.count_ones()).sum()
    }

    /// OR-merge `other` into `self`.  Returns the number of newly set bits.
    pub fn merge(&mut self, other: &Self) -> u32 {
        let mut newly_set = 0u32;
        for (a, b) in self.bytes.iter_mut().zip(other.bytes.iter()) {
            let novel = *b & !(*a);
            newly_set += novel.count_ones();
            *a |= *b;
        }
        newly_set
    }

    /// Returns `true` if `other` would set any new bits not currently in `self`.
    #[must_use]
    pub fn has_new_bits(&self, other: &Self) -> bool {
        self.bytes.iter().zip(other.bytes.iter()).any(|(&a, &b)| b & !a != 0)
    }

    /// Compute the FNV-1a hash of the bitmap.
    #[must_use]
    pub fn hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in &self.bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// Reset all bits.
    pub fn reset(&mut self) {
        self.bytes.iter_mut().for_each(|b| *b = 0);
    }

    /// Return all set [`EdgeId`]s.
    #[must_use]
    pub fn set_edges(&self) -> Vec<EdgeId> {
        let mut edges = Vec::new();
        for (byte_idx, &byte) in self.bytes.iter().enumerate() {
            for bit in 0..8u8 {
                if (byte >> bit) & 1 == 1 {
                    let raw = u16::try_from(byte_idx * 8 + bit as usize).unwrap_or(u16::MAX);
                    edges.push(EdgeId(raw));
                }
            }
        }
        edges
    }

    /// Raw byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Default for EdgeBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// ── EdgeFrequency ─────────────────────────────────────────────────────────────

/// Tracks per-edge hit counts (AFL-style "bucketed" counts).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeFrequency {
    /// Raw hit counts per edge (sparse: only non-zero edges).
    counts: HashMap<EdgeId, u64>,
}

impl EdgeFrequency {
    /// Create an empty frequency table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one hit for `edge`.
    pub fn record(&mut self, edge: EdgeId) {
        *self.counts.entry(edge).or_insert(0) += 1;
    }

    /// Record `n` hits for `edge`.
    pub fn record_n(&mut self, edge: EdgeId, n: u64) {
        *self.counts.entry(edge).or_insert(0) += n;
    }

    /// Hit count for `edge` (0 if never hit).
    #[must_use]
    pub fn count(&self, edge: EdgeId) -> u64 {
        self.counts.get(&edge).copied().unwrap_or(0)
    }

    /// Number of distinct edges hit at least once.
    #[must_use]
    pub fn distinct_edges(&self) -> usize {
        self.counts.len()
    }

    /// Total hits across all edges.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Top-`n` edges by hit count (descending).
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(EdgeId, u64)> {
        let mut v: Vec<(EdgeId, u64)> = self.counts.iter().map(|(&e, &c)| (e, c)).collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// AFL-style bucketing for a count: 1→1, 2→2, 3–4→4, 5–8→8, …
    #[must_use]
    pub const fn bucket(count: u64) -> u8 {
        match count {
            0 => 0,
            1 => 1,
            2 => 2,
            3..=4 => 4,
            5..=8 => 8,
            9..=16 => 16,
            17..=32 => 32,
            33..=128 => 64,
            _ => 128,
        }
    }

    /// Return a bucketed version of this frequency map.
    #[must_use]
    pub fn bucketed(&self) -> HashMap<EdgeId, u8> {
        self.counts
            .iter()
            .map(|(&e, &c)| (e, Self::bucket(c)))
            .collect()
    }

    /// Merge another frequency map into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&e, &c) in &other.counts {
            *self.counts.entry(e).or_insert(0) += c;
        }
    }

    /// Reset all counts.
    pub fn reset(&mut self) {
        self.counts.clear();
    }
}

// ── NewEdgeDetector ───────────────────────────────────────────────────────────

/// Detects when a new edge is observed for the first time.
#[derive(Debug, Default)]
pub struct NewEdgeDetector {
    /// Set of all previously seen edges.
    seen: HashSet<EdgeId>,
    /// Total new-edge discoveries.
    pub total_new: u64,
}

impl NewEdgeDetector {
    /// Create a new detector with no known edges.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check `bitmap` against the known set.  Returns the list of newly
    /// discovered edges and updates the internal set.
    pub fn check(&mut self, bitmap: &EdgeBitmap) -> Vec<EdgeId> {
        let mut new_edges = Vec::new();
        for edge in bitmap.set_edges() {
            if self.seen.insert(edge) {
                new_edges.push(edge);
                self.total_new += 1;
            }
        }
        new_edges
    }

    /// Number of edges in the known set.
    #[must_use]
    pub fn known_count(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` if `edge` has been seen before.
    #[must_use]
    pub fn is_known(&self, edge: EdgeId) -> bool {
        self.seen.contains(&edge)
    }

    /// Reset the known set.
    pub fn reset(&mut self) {
        self.seen.clear();
        self.total_new = 0;
    }

    /// Seed the detector with a set of pre-known edges.
    pub fn seed(&mut self, edges: impl IntoIterator<Item = EdgeId>) {
        for e in edges {
            self.seen.insert(e);
        }
    }
}

// ── EdgeStatistics ────────────────────────────────────────────────────────────

/// Aggregate statistics over edge coverage across multiple runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeStatistics {
    /// Total number of runs counted.
    pub run_count: u64,
    /// Number of distinct edges ever seen.
    pub total_distinct_edges: u64,
    /// Edges seen in every run (intersection size).
    pub always_hit_edges: u64,
    /// Edges seen in exactly one run.
    pub singleton_edges: u64,
    /// Maximum edges seen in a single run.
    pub max_edges_per_run: u64,
    /// Minimum edges seen in a single run (excluding empty runs).
    pub min_edges_per_run: u64,
    /// Total edge hits across all runs.
    pub total_hits: u64,
    /// Per-edge hit counts aggregated.
    pub per_edge_counts: BTreeMap<u16, u64>,
}

impl EdgeStatistics {
    /// Create empty statistics.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a single run's bitmap.
    pub fn record_run(&mut self, bitmap: &EdgeBitmap) {
        let edges = bitmap.set_edges();
        let count = edges.len() as u64;
        self.run_count += 1;
        self.total_hits += count;
        if count > self.max_edges_per_run {
            self.max_edges_per_run = count;
        }
        if (self.run_count == 1 || count < self.min_edges_per_run)
            && count > 0 {
                self.min_edges_per_run = count;
            }
        for e in edges {
            let c = self.per_edge_counts.entry(e.0).or_insert(0);
            *c += 1;
        }
        // Update derived fields.
        self.total_distinct_edges = self.per_edge_counts.len() as u64;
        self.always_hit_edges = self
            .per_edge_counts
            .values()
            .filter(|&&c| c == self.run_count)
            .count() as u64;
        self.singleton_edges = self
            .per_edge_counts
            .values()
            .filter(|&&c| c == 1)
            .count() as u64;
    }

    /// Average edges per run.
    #[must_use]
    pub fn avg_edges(&self) -> f64 {
        if self.run_count == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.total_hits) / crate::casts::u64_to_f64(self.run_count)
        }
    }

    /// Hit frequency for a specific edge.
    #[must_use]
    pub fn hit_frequency(&self, edge: EdgeId) -> f64 {
        if self.run_count == 0 {
            return 0.0;
        }
        let hits = self.per_edge_counts.get(&edge.0).copied().unwrap_or(0);
        crate::casts::u64_to_f64(hits) / crate::casts::u64_to_f64(self.run_count)
    }
}

// ── CoverageProfile ───────────────────────────────────────────────────────────

/// A complete coverage profile for a single execution, combining bitmap,
/// frequency, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageProfile {
    /// The edge hit bitmap.
    pub bitmap: EdgeBitmap,
    /// Per-edge hit frequencies.
    pub frequency: EdgeFrequency,
    /// Input hash that produced this profile.
    pub input_hash: u64,
    /// Execution time.
    pub exec_time: Duration,
    /// When this profile was recorded.
    pub recorded_at: SystemTime,
    /// Human-readable label.
    pub label: Option<String>,
}

impl CoverageProfile {
    /// Create a new profile.
    #[must_use]
    pub fn new(
        bitmap: EdgeBitmap,
        frequency: EdgeFrequency,
        input_hash: u64,
        exec_time: Duration,
    ) -> Self {
        Self {
            bitmap,
            frequency,
            input_hash,
            exec_time,
            recorded_at: SystemTime::now(),
            label: None,
        }
    }

    /// Number of distinct edges hit.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.bitmap.count_set() as usize
    }

    /// Hash of the bitmap (for deduplication).
    #[must_use]
    pub fn bitmap_hash(&self) -> u64 {
        self.bitmap.hash()
    }

    /// Whether this profile has new edges compared to `baseline`.
    #[must_use]
    pub fn is_interesting_vs(&self, baseline: &EdgeBitmap) -> bool {
        baseline.has_new_bits(&self.bitmap)
    }

    /// Jaccard similarity with another profile.
    #[must_use]
    pub fn jaccard(&self, other: &Self) -> f64 {
        let a: HashSet<EdgeId> = self.bitmap.set_edges().into_iter().collect();
        let b: HashSet<EdgeId> = other.bitmap.set_edges().into_iter().collect();
        let intersection = a.intersection(&b).count();
        let union = a.union(&b).count();
        if union == 0 {
            1.0
        } else {
            crate::casts::usize_to_f64(intersection) / crate::casts::usize_to_f64(union)
        }
    }

    /// Set the profile label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

// ── EdgeCoverage ──────────────────────────────────────────────────────────────

/// Top-level edge-coverage manager combining bitmap, frequency tracking,
/// new-edge detection, and statistics.
pub struct EdgeCoverage {
    /// Global accumulated bitmap (OR of all runs).
    pub global_bitmap: EdgeBitmap,
    /// Per-edge hit frequencies across all runs.
    pub frequency: EdgeFrequency,
    /// New-edge detector.
    pub detector: NewEdgeDetector,
    /// Aggregate statistics.
    pub statistics: EdgeStatistics,
    /// All profiles recorded so far.
    pub profiles: Vec<CoverageProfile>,
    /// Maximum number of profiles to keep (0 = unlimited).
    pub max_profiles: usize,
}

impl EdgeCoverage {
    /// Create a new edge-coverage manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            global_bitmap: EdgeBitmap::new(),
            frequency: EdgeFrequency::new(),
            detector: NewEdgeDetector::new(),
            statistics: EdgeStatistics::new(),
            profiles: Vec::new(),
            max_profiles: 0,
        }
    }

    /// Create with a profile retention cap.
    #[must_use]
    pub fn with_profile_cap(max_profiles: usize) -> Self {
        let mut e = Self::new();
        e.max_profiles = max_profiles;
        e
    }

    /// Record a single run given a raw bitmap and hit-frequency table.
    ///
    /// Returns the list of newly discovered edges.
    pub fn record_run(
        &mut self,
        bitmap: EdgeBitmap,
        frequency: EdgeFrequency,
        input_hash: u64,
        exec_time: Duration,
    ) -> Vec<EdgeId> {
        let new_edges = self.detector.check(&bitmap);
        self.global_bitmap.merge(&bitmap);
        self.frequency.merge(&frequency);
        self.statistics.record_run(&bitmap);

        let profile = CoverageProfile::new(bitmap, frequency, input_hash, exec_time);
        if self.max_profiles == 0 || self.profiles.len() < self.max_profiles {
            self.profiles.push(profile);
        }

        new_edges
    }

    /// Record a simple bitmap (no per-edge frequency).
    pub fn record_bitmap(&mut self, bitmap: EdgeBitmap, input_hash: u64) -> Vec<EdgeId> {
        self.record_run(bitmap, EdgeFrequency::new(), input_hash, Duration::ZERO)
    }

    /// Number of distinct edges in the global bitmap.
    #[must_use]
    pub fn global_edge_count(&self) -> u32 {
        self.global_bitmap.count_set()
    }

    /// Total new edges discovered across all runs.
    #[must_use]
    pub const fn total_new_edges(&self) -> u64 {
        self.detector.total_new
    }

    /// Total runs recorded.
    #[must_use]
    pub const fn run_count(&self) -> u64 {
        self.statistics.run_count
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.global_bitmap.reset();
        self.frequency.reset();
        self.detector.reset();
        self.statistics = EdgeStatistics::new();
        self.profiles.clear();
    }

    /// Return the top-`n` hottest edges by frequency.
    #[must_use]
    pub fn hottest_edges(&self, n: usize) -> Vec<(EdgeId, u64)> {
        self.frequency.top_n(n)
    }

    /// Build a summary string for logging.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "runs={} global_edges={} new_edges={} avg_edges={:.1}",
            self.run_count(),
            self.global_edge_count(),
            self.total_new_edges(),
            self.statistics.avg_edges(),
        )
    }
}

impl Default for EdgeCoverage {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EdgeId ────────────────────────────────────────────────────────────────

    #[test]
    fn edge_id_from_pcs_deterministic() {
        let a = EdgeId::from_pcs(0x1000, 0x2000);
        let b = EdgeId::from_pcs(0x1000, 0x2000);
        assert_eq!(a, b);
    }

    #[test]
    fn edge_id_from_different_pcs_differ() {
        let a = EdgeId::from_pcs(0x1000, 0x2000);
        let b = EdgeId::from_pcs(0x2000, 0x1000);
        assert_ne!(a, b);
    }

    #[test]
    fn edge_id_byte_and_bit_index() {
        let e = EdgeId(0);
        assert_eq!(e.byte_index(), 0);
        assert_eq!(e.bit_index(), 0);
        let e2 = EdgeId(8);
        assert_eq!(e2.byte_index(), 1);
        assert_eq!(e2.bit_index(), 0);
    }

    #[test]
    fn edge_id_mask() {
        let e = EdgeId(3); // bit 3 in byte 0
        assert_eq!(e.mask(), 1 << 3);
    }

    #[test]
    fn edge_id_display() {
        let s = format!("{}", EdgeId(42));
        assert!(s.contains("42"));
    }

    // ── EdgeBitmap ────────────────────────────────────────────────────────────

    #[test]
    fn edge_bitmap_new_all_zero() {
        let bm = EdgeBitmap::new();
        assert_eq!(bm.count_set(), 0);
        assert_eq!(bm.as_bytes().len(), EdgeBitmap::BYTES);
    }

    #[test]
    fn edge_bitmap_set_and_is_set() {
        let mut bm = EdgeBitmap::new();
        let e = EdgeId(100);
        bm.set(e);
        assert!(bm.is_set(e));
        assert!(!bm.is_set(EdgeId(101)));
    }

    #[test]
    fn edge_bitmap_clear() {
        let mut bm = EdgeBitmap::new();
        let e = EdgeId(50);
        bm.set(e);
        bm.clear(e);
        assert!(!bm.is_set(e));
    }

    #[test]
    fn edge_bitmap_count_set() {
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(0));
        bm.set(EdgeId(1));
        bm.set(EdgeId(2));
        assert_eq!(bm.count_set(), 3);
    }

    #[test]
    fn edge_bitmap_merge_returns_newly_set() {
        let mut a = EdgeBitmap::new();
        let mut b = EdgeBitmap::new();
        b.set(EdgeId(10));
        b.set(EdgeId(20));
        let new = a.merge(&b);
        assert_eq!(new, 2);
    }

    #[test]
    fn edge_bitmap_merge_idempotent() {
        let mut a = EdgeBitmap::new();
        let mut b = EdgeBitmap::new();
        b.set(EdgeId(5));
        a.merge(&b);
        let new2 = a.merge(&b);
        assert_eq!(new2, 0);
    }

    #[test]
    fn edge_bitmap_has_new_bits() {
        let mut a = EdgeBitmap::new();
        let mut b = EdgeBitmap::new();
        b.set(EdgeId(7));
        assert!(a.has_new_bits(&b));
        a.merge(&b);
        assert!(!a.has_new_bits(&b));
    }

    #[test]
    fn edge_bitmap_hash_changes_after_set() {
        let mut bm = EdgeBitmap::new();
        let h1 = bm.hash();
        bm.set(EdgeId(1000));
        let h2 = bm.hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn edge_bitmap_reset_clears() {
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(999));
        bm.reset();
        assert_eq!(bm.count_set(), 0);
    }

    #[test]
    fn edge_bitmap_set_edges() {
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(0));
        bm.set(EdgeId(8));
        bm.set(EdgeId(16));
        let edges = bm.set_edges();
        assert_eq!(edges.len(), 3);
    }

    // ── EdgeFrequency ─────────────────────────────────────────────────────────

    #[test]
    fn edge_frequency_record_and_count() {
        let mut ef = EdgeFrequency::new();
        let e = EdgeId(1);
        ef.record(e);
        ef.record(e);
        assert_eq!(ef.count(e), 2);
    }

    #[test]
    fn edge_frequency_count_unrecorded() {
        let ef = EdgeFrequency::new();
        assert_eq!(ef.count(EdgeId(42)), 0);
    }

    #[test]
    fn edge_frequency_total_hits() {
        let mut ef = EdgeFrequency::new();
        ef.record_n(EdgeId(1), 5);
        ef.record_n(EdgeId(2), 3);
        assert_eq!(ef.total_hits(), 8);
    }

    #[test]
    fn edge_frequency_bucket_values() {
        assert_eq!(EdgeFrequency::bucket(0), 0);
        assert_eq!(EdgeFrequency::bucket(1), 1);
        assert_eq!(EdgeFrequency::bucket(3), 4);
        assert_eq!(EdgeFrequency::bucket(255), 128);
    }

    #[test]
    fn edge_frequency_top_n() {
        let mut ef = EdgeFrequency::new();
        ef.record_n(EdgeId(1), 10);
        ef.record_n(EdgeId(2), 5);
        ef.record_n(EdgeId(3), 1);
        let top = ef.top_n(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].1, 10);
    }

    #[test]
    fn edge_frequency_merge() {
        let mut a = EdgeFrequency::new();
        let mut b = EdgeFrequency::new();
        a.record_n(EdgeId(1), 3);
        b.record_n(EdgeId(1), 4);
        a.merge(&b);
        assert_eq!(a.count(EdgeId(1)), 7);
    }

    // ── NewEdgeDetector ───────────────────────────────────────────────────────

    #[test]
    fn new_edge_detector_empty_bitmap() {
        let mut det = NewEdgeDetector::new();
        let bm = EdgeBitmap::new();
        let new = det.check(&bm);
        assert!(new.is_empty());
    }

    #[test]
    fn new_edge_detector_first_hit() {
        let mut det = NewEdgeDetector::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(42));
        let new = det.check(&bm);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0], EdgeId(42));
    }

    #[test]
    fn new_edge_detector_no_repeat() {
        let mut det = NewEdgeDetector::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(7));
        det.check(&bm);
        let new2 = det.check(&bm);
        assert!(new2.is_empty());
    }

    #[test]
    fn new_edge_detector_is_known() {
        let mut det = NewEdgeDetector::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(99));
        det.check(&bm);
        assert!(det.is_known(EdgeId(99)));
        assert!(!det.is_known(EdgeId(100)));
    }

    #[test]
    fn new_edge_detector_seed() {
        let mut det = NewEdgeDetector::new();
        det.seed([EdgeId(1), EdgeId(2)]);
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(1));
        bm.set(EdgeId(3));
        let new = det.check(&bm);
        // EdgeId(1) already seeded; only EdgeId(3) is new.
        assert_eq!(new.len(), 1);
        assert_eq!(new[0], EdgeId(3));
    }

    #[test]
    fn new_edge_detector_reset() {
        let mut det = NewEdgeDetector::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(5));
        det.check(&bm);
        det.reset();
        assert_eq!(det.known_count(), 0);
        assert_eq!(det.total_new, 0);
    }

    // ── EdgeStatistics ────────────────────────────────────────────────────────

    #[test]
    fn edge_statistics_record_single_run() {
        let mut stats = EdgeStatistics::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(1));
        bm.set(EdgeId(2));
        stats.record_run(&bm);
        assert_eq!(stats.run_count, 1);
        assert_eq!(stats.total_distinct_edges, 2);
    }

    #[test]
    fn edge_statistics_avg_edges() {
        let mut stats = EdgeStatistics::new();
        let mut bm1 = EdgeBitmap::new();
        bm1.set(EdgeId(1));
        bm1.set(EdgeId(2));
        let mut bm2 = EdgeBitmap::new();
        bm2.set(EdgeId(3));
        bm2.set(EdgeId(4));
        stats.record_run(&bm1);
        stats.record_run(&bm2);
        assert!((stats.avg_edges() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn edge_statistics_always_hit() {
        let mut stats = EdgeStatistics::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(10));
        stats.record_run(&bm);
        stats.record_run(&bm);
        assert_eq!(stats.always_hit_edges, 1);
    }

    // ── CoverageProfile ───────────────────────────────────────────────────────

    #[test]
    fn coverage_profile_edge_count() {
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(1));
        bm.set(EdgeId(2));
        let prof = CoverageProfile::new(bm, EdgeFrequency::new(), 0, Duration::ZERO);
        assert_eq!(prof.edge_count(), 2);
    }

    #[test]
    fn coverage_profile_jaccard_identical() {
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(1));
        let p1 = CoverageProfile::new(bm.clone(), EdgeFrequency::new(), 0, Duration::ZERO);
        let p2 = CoverageProfile::new(bm, EdgeFrequency::new(), 0, Duration::ZERO);
        assert!((p1.jaccard(&p2) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn coverage_profile_jaccard_disjoint() {
        let mut bm1 = EdgeBitmap::new();
        bm1.set(EdgeId(1));
        let mut bm2 = EdgeBitmap::new();
        bm2.set(EdgeId(2));
        let p1 = CoverageProfile::new(bm1, EdgeFrequency::new(), 0, Duration::ZERO);
        let p2 = CoverageProfile::new(bm2, EdgeFrequency::new(), 0, Duration::ZERO);
        assert!((p1.jaccard(&p2)).abs() < 1e-9);
    }

    #[test]
    fn coverage_profile_interesting_vs() {
        let baseline = EdgeBitmap::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(50));
        let prof = CoverageProfile::new(bm, EdgeFrequency::new(), 0, Duration::ZERO);
        assert!(prof.is_interesting_vs(&baseline));
    }

    // ── EdgeCoverage ──────────────────────────────────────────────────────────

    #[test]
    fn edge_coverage_initial_state() {
        let ec = EdgeCoverage::new();
        assert_eq!(ec.global_edge_count(), 0);
        assert_eq!(ec.run_count(), 0);
    }

    #[test]
    fn edge_coverage_record_bitmap() {
        let mut ec = EdgeCoverage::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(10));
        ec.record_bitmap(bm, 0xABCD);
        assert_eq!(ec.global_edge_count(), 1);
        assert_eq!(ec.run_count(), 1);
        assert_eq!(ec.total_new_edges(), 1);
    }

    #[test]
    fn edge_coverage_record_run_frequency() {
        let mut ec = EdgeCoverage::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(3));
        let mut freq = EdgeFrequency::new();
        freq.record_n(EdgeId(3), 7);
        ec.record_run(bm, freq, 0, Duration::from_micros(100));
        assert_eq!(ec.frequency.count(EdgeId(3)), 7);
    }

    #[test]
    fn edge_coverage_new_edges_not_repeated() {
        let mut ec = EdgeCoverage::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(5));
        ec.record_bitmap(bm.clone(), 1);
        let new2 = ec.record_bitmap(bm, 2);
        assert!(new2.is_empty());
    }

    #[test]
    fn edge_coverage_summary_not_empty() {
        let ec = EdgeCoverage::new();
        assert!(!ec.summary().is_empty());
    }

    #[test]
    fn edge_coverage_reset() {
        let mut ec = EdgeCoverage::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(1));
        ec.record_bitmap(bm, 0);
        ec.reset();
        assert_eq!(ec.global_edge_count(), 0);
        assert_eq!(ec.run_count(), 0);
    }

    #[test]
    fn edge_coverage_hottest_edges() {
        let mut ec = EdgeCoverage::new();
        let mut bm = EdgeBitmap::new();
        bm.set(EdgeId(1));
        bm.set(EdgeId(2));
        let mut freq = EdgeFrequency::new();
        freq.record_n(EdgeId(1), 100);
        freq.record_n(EdgeId(2), 1);
        ec.record_run(bm, freq, 0, Duration::ZERO);
        let top = ec.hottest_edges(1);
        assert_eq!(top[0].0, EdgeId(1));
    }

    #[test]
    fn edge_coverage_profile_cap() {
        let mut ec = EdgeCoverage::with_profile_cap(3);
        for i in 0..10u16 {
            let mut bm = EdgeBitmap::new();
            bm.set(EdgeId(i));
            ec.record_bitmap(bm, u64::from(i));
        }
        assert_eq!(ec.profiles.len(), 3);
    }
}
