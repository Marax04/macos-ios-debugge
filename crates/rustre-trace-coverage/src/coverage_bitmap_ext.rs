//! Extended coverage bitmap management: AFL-style edge coverage bitmaps,
//! merge bitmaps, compute unique edges, bitmap normalization, population
//! count, compare bitmaps, serialize/deserialize.
//!
//! Complements the existing `coverage_bitmap` module with higher-level
//! types: `CoverageBitmap`, `BitmapStats`, `EdgeId`, `BitmapMerger`,
//! `CoverageComparison`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::CovError;

// ── EdgeId ────────────────────────────────────────────────────────────────────

/// A hashed edge identifier, as used in AFL bitmaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EdgeId(pub usize);

impl EdgeId {
    /// Compute the AFL-style edge ID from `prev_pc` and `cur_pc` given a
    /// bitmap of size `map_size`.
    #[must_use]
    pub fn from_pcs(prev_pc: u64, cur_pc: u64, map_size: usize) -> Self {
        // `prev ^ cur` is SYMMETRIC: a call `A -> B` and its return `B -> A`
        // collapse onto the same slot — exactly the pair a coverage map exists
        // to tell apart — and every self-edge hashes to 0, so a tight loop
        // anywhere in the program looks like the same edge.
        //
        // Shifting one side first breaks the symmetry; this is AFL's formula.
        let hash = crate::u64_to_usize_sat((prev_pc >> 1) ^ cur_pc);
        Self(if map_size > 0 { hash % map_size } else { hash })
    }

    /// Raw index.
    #[must_use]
    pub const fn index(self) -> usize { self.0 }
}

impl fmt::Display for EdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EdgeId({})", self.0)
    }
}

// ── BitmapStats ───────────────────────────────────────────────────────────────

/// Statistics derived from a `CoverageBitmap`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BitmapStats {
    /// Total size in bits.
    pub size_bits: usize,
    /// Total size in bytes.
    pub size_bytes: usize,
    /// Number of set bits (covered edges).
    pub set_bits: usize,
    /// Number of clear bits (uncovered edges).
    pub clear_bits: usize,
    /// Coverage ratio in [0.0, 1.0].
    pub coverage_ratio: f64,
}

impl BitmapStats {
    /// Compute stats from a `CoverageBitmap`.
    #[must_use]
    pub fn compute(bm: &CoverageBitmap) -> Self {
        let set = bm.popcount();
        let size_bits = bm.size();
        let size_bytes = bm.byte_len();
        let clear = size_bits.saturating_sub(set);
        let ratio = if size_bits == 0 { 1.0 } else { crate::usize_to_f64(set) / crate::usize_to_f64(size_bits) };
        Self { size_bits, size_bytes, set_bits: set, clear_bits: clear, coverage_ratio: ratio }
    }
}

impl fmt::Display for BitmapStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitmapStats: {}/{} bits set ({:.1}%)",
            self.set_bits, self.size_bits, self.coverage_ratio * 100.0)
    }
}

// ── CoverageBitmap ────────────────────────────────────────────────────────────

/// High-level AFL-style edge coverage bitmap.
///
/// Stores one bit per edge hash slot. Supports set/clear/test,
/// bitwise operations (OR/AND/XOR/diff), population count,
/// normalization, and binary serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageBitmap {
    /// Raw bytes (bits packed, LSB first within each byte).
    data: Vec<u8>,
    /// Logical size in bits.
    size: usize,
}

impl CoverageBitmap {
    /// Standard AFL bitmap size (64 KB = 524288 bits).
    pub const AFL_SIZE: usize = 64 * 1024 * 8;

    /// Create a zeroed bitmap of `size_bits` bits.
    #[must_use]
    pub fn new(size_bits: usize) -> Self {
        let bytes = Self::bytes_needed(size_bits);
        Self { data: vec![0u8; bytes], size: size_bits }
    }

    /// Create a standard AFL 64 KB bitmap.
    #[must_use]
    pub fn afl() -> Self { Self::new(Self::AFL_SIZE) }

    /// Create from raw bytes (each byte = 8 bits, LSB first).
    #[must_use]
    pub const fn from_bytes(data: Vec<u8>) -> Self {
        let size = data.len() * 8;
        Self { data, size }
    }

    /// Create from raw bytes with an explicit bit size.
    ///
    /// # Errors
    /// Returns `CovError::SizeMismatch` if `size_bits > data.len() * 8`.
    pub fn from_bytes_with_size(data: Vec<u8>, size_bits: usize) -> Result<Self, CovError> {
        let available = data.len() * 8;
        if size_bits > available {
            return Err(CovError::SizeMismatch { a: size_bits, b: available });
        }
        Ok(Self { data, size: size_bits })
    }

    const fn bytes_needed(bits: usize) -> usize {
        if bits == 0 { 0 } else { bits.div_ceil(8) }
    }

    /// Logical size in bits.
    #[must_use]
    pub const fn size(&self) -> usize { self.size }

    /// Storage size in bytes.
    #[must_use]
    pub const fn byte_len(&self) -> usize { self.data.len() }

    /// Set bit at `idx`. No-op if out of range.
    pub fn set(&mut self, idx: usize) {
        if idx < self.size { self.data[idx / 8] |= 1 << (idx % 8); }
    }

    /// Clear bit at `idx`.
    pub fn clear(&mut self, idx: usize) {
        if idx < self.size { self.data[idx / 8] &= !(1 << (idx % 8)); }
    }

    /// Toggle bit at `idx`.
    pub fn toggle(&mut self, idx: usize) {
        if idx < self.size { self.data[idx / 8] ^= 1 << (idx % 8); }
    }

    /// Test bit at `idx`. Returns `false` if out of range.
    #[must_use]
    pub fn test(&self, idx: usize) -> bool {
        if idx >= self.size { return false; }
        (self.data[idx / 8] >> (idx % 8)) & 1 == 1
    }

    /// Record a PC-pair edge (AFL hash).
    pub fn record_edge(&mut self, prev_pc: u64, cur_pc: u64) {
        if self.size > 0 {
            let id = EdgeId::from_pcs(prev_pc, cur_pc, self.size);
            self.set(id.0);
        }
    }

    /// Record by `EdgeId`.
    pub fn record_edge_id(&mut self, edge: EdgeId) { self.set(edge.0); }

    /// Population count (number of set bits).
    #[must_use]
    pub fn popcount(&self) -> usize {
        self.data.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// All set bit indices.
    #[must_use]
    pub fn set_indices(&self) -> Vec<usize> {
        (0..self.size).filter(|&i| self.test(i)).collect()
    }

    /// All clear bit indices.
    #[must_use]
    pub fn clear_indices(&self) -> Vec<usize> {
        (0..self.size).filter(|&i| !self.test(i)).collect()
    }

    /// Returns `true` if no bits are set.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.data.iter().all(|&b| b == 0) }

    /// Returns `true` if all bits are set.
    #[must_use]
    pub fn is_full(&self) -> bool {
        if self.size == 0 { return true; }
        let full_bytes = self.size / 8;
        let tail_bits = self.size % 8;
        for &b in &self.data[..full_bytes] {
            if b != 0xFF { return false; }
        }
        if tail_bits > 0 {
            let tail = self.data.get(full_bytes).copied().unwrap_or(0);
            let mask = (1u8 << tail_bits) - 1;
            if tail & mask != mask { return false; }
        }
        true
    }

    // ── Bitwise operations ────────────────────────────────────────────────

    /// Bitwise OR (union). Result has the maximum size.
    #[must_use]
    pub fn or(&self, other: &Self) -> Self {
        let size = self.size.max(other.size);
        let bytes = Self::bytes_needed(size);
        let mut result = vec![0u8; bytes];
        for (i, slot) in result.iter_mut().enumerate() {
            *slot = self.data.get(i).copied().unwrap_or(0)
                  | other.data.get(i).copied().unwrap_or(0);
        }
        Self { data: result, size }
    }

    /// Bitwise AND (intersection).
    #[must_use]
    pub fn and(&self, other: &Self) -> Self {
        let size = self.size.min(other.size);
        let bytes = Self::bytes_needed(size);
        let mut result = vec![0u8; bytes];
        for (i, slot) in result.iter_mut().enumerate() {
            *slot = self.data.get(i).copied().unwrap_or(0)
                  & other.data.get(i).copied().unwrap_or(0);
        }
        Self { data: result, size }
    }

    /// Bitwise XOR.
    #[must_use]
    pub fn xor(&self, other: &Self) -> Self {
        let size = self.size.max(other.size);
        let bytes = Self::bytes_needed(size);
        let mut result = vec![0u8; bytes];
        for (i, slot) in result.iter_mut().enumerate() {
            *slot = self.data.get(i).copied().unwrap_or(0)
                  ^ other.data.get(i).copied().unwrap_or(0);
        }
        Self { data: result, size }
    }

    /// Bits set in `self` but NOT in `other`.
    #[must_use]
    pub fn diff(&self, other: &Self) -> Self {
        let size = self.size;
        let bytes = Self::bytes_needed(size);
        let mut result = vec![0u8; bytes];
        for (i, slot) in result.iter_mut().enumerate() {
            *slot = self.data.get(i).copied().unwrap_or(0)
                  & !other.data.get(i).copied().unwrap_or(0);
        }
        Self { data: result, size }
    }

    /// In-place OR.
    pub fn or_assign(&mut self, other: &Self) {
        let need = Self::bytes_needed(other.size);
        if self.data.len() < need { self.data.resize(need, 0); }
        if other.size > self.size { self.size = other.size; }
        for (i, &b) in other.data.iter().enumerate() { self.data[i] |= b; }
    }

    // ── Normalization ─────────────────────────────────────────────────────

    /// Return a normalized copy (non-zero bytes become 0xFF).
    #[must_use]
    pub fn normalized(&self) -> Self {
        let data = self.data.iter().map(|&b| if b != 0 { 0xFF } else { 0 }).collect();
        Self { data, size: self.size }
    }

    /// Normalize in place.
    pub fn normalize_inplace(&mut self) {
        for b in &mut self.data { if *b != 0 { *b = 0xFF; } }
    }

    // ── Comparison ────────────────────────────────────────────────────────

    /// Number of unique edges in `self` not in `other`.
    #[must_use]
    pub fn new_coverage_vs(&self, baseline: &Self) -> usize {
        self.diff(baseline).popcount()
    }

    /// Jaccard similarity: `|A ∩ B| / |A ∪ B|`.
    #[must_use]
    pub fn jaccard(&self, other: &Self) -> f64 {
        let inter = self.and(other).popcount();
        let uni = self.or(other).popcount();
        if uni == 0 { 1.0 } else { crate::usize_to_f64(inter) / crate::usize_to_f64(uni) }
    }

    /// Hamming distance (number of differing bits).
    #[must_use]
    pub fn hamming_distance(&self, other: &Self) -> usize {
        self.xor(other).popcount()
    }

    // ── Serialization ─────────────────────────────────────────────────────

    /// Serialize: `size_bits: u64 LE` + raw bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.data.len());
        out.extend_from_slice(&(self.size as u64).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Deserialize from format produced by `to_bytes`.
    ///
    /// # Errors
    /// Returns `CovError::ParseError` on malformed input.
    ///
    /// # Panics
    /// Panics if the internal slice extraction fails (can only happen if `data.len() < 8`, which is checked first).
    pub fn from_serialized(data: &[u8]) -> Result<Self, CovError> {
        if data.len() < 8 {
            return Err(CovError::ParseError("bitmap too short".into()));
        }
        let size = crate::u64_to_usize_sat(u64::from_le_bytes(data[..8].try_into().unwrap()));
        let raw = data[8..].to_vec();
        let needed = Self::bytes_needed(size);
        if raw.len() < needed {
            return Err(CovError::SizeMismatch { a: raw.len(), b: needed });
        }
        Ok(Self { data: raw, size })
    }

    /// Raw bytes view.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] { &self.data }

    /// Compute statistics.
    #[must_use]
    pub fn stats(&self) -> BitmapStats { BitmapStats::compute(self) }
}

impl Default for CoverageBitmap {
    fn default() -> Self { Self::new(0) }
}

impl PartialEq for CoverageBitmap {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.data == other.data
    }
}

impl Eq for CoverageBitmap {}

// ── BitmapMerger ──────────────────────────────────────────────────────────────

/// Merges multiple bitmaps into one via cumulative OR.
#[derive(Debug, Default)]
pub struct BitmapMerger {
    accumulated: Option<CoverageBitmap>,
    count: usize,
}

impl BitmapMerger {
    /// Create a new merger.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Add a bitmap.
    pub fn add(&mut self, bm: &CoverageBitmap) {
        match &mut self.accumulated {
            Some(acc) => acc.or_assign(bm),
            None => self.accumulated = Some(bm.clone()),
        }
        self.count += 1;
    }

    /// Finalize and return the merged bitmap.
    #[must_use]
    pub fn finish(self) -> Option<CoverageBitmap> { self.accumulated }

    /// Number of bitmaps merged.
    #[must_use]
    pub const fn count(&self) -> usize { self.count }

    /// Current merged coverage (popcount).
    #[must_use]
    pub fn merged_coverage(&self) -> usize {
        self.accumulated.as_ref().map_or(0, CoverageBitmap::popcount)
    }
}

// ── CoverageComparison ────────────────────────────────────────────────────────

/// Detailed comparison between two bitmaps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageComparison {
    pub only_in_a: usize,
    pub only_in_b: usize,
    pub in_both: usize,
    pub jaccard: f64,
    pub hamming: usize,
    pub coverage_a: f64,
    pub coverage_b: f64,
}

impl CoverageComparison {
    /// Compute comparison between `a` and `b`.
    #[must_use]
    pub fn compute(a: &CoverageBitmap, b: &CoverageBitmap) -> Self {
        let only_in_a = a.diff(b).popcount();
        let only_in_b = b.diff(a).popcount();
        let in_both = a.and(b).popcount();
        let jaccard = a.jaccard(b);
        let hamming = a.hamming_distance(b);
        Self {
            only_in_a, only_in_b, in_both, jaccard, hamming,
            coverage_a: a.stats().coverage_ratio,
            coverage_b: b.stats().coverage_ratio,
        }
    }

    /// Net new edges in B vs A.
    #[must_use]
    pub const fn new_edges_in_b(&self) -> usize { self.only_in_b }

    /// Summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Comparison: only_in_a={} only_in_b={} shared={} jaccard={:.3} hamming={}",
            self.only_in_a, self.only_in_b, self.in_both, self.jaccard, self.hamming
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_test_clear() {
        let mut bm = CoverageBitmap::new(64);
        bm.set(0); bm.set(7); bm.set(63);
        assert!(bm.test(0) && bm.test(7) && bm.test(63));
        assert!(!bm.test(1));
        bm.clear(7);
        assert!(!bm.test(7));
    }

    #[test]
    fn test_popcount() {
        let mut bm = CoverageBitmap::new(16);
        bm.set(0); bm.set(1); bm.set(15);
        assert_eq!(bm.popcount(), 3);
    }

    #[test]
    fn test_or_and_diff() {
        let mut a = CoverageBitmap::new(8);
        let mut b = CoverageBitmap::new(8);
        a.set(0); a.set(1); b.set(1); b.set(2);
        let u = a.or(&b);
        assert!(u.test(0) && u.test(1) && u.test(2));
        let i = a.and(&b);
        assert!(!i.test(0) && i.test(1) && !i.test(2));
        let d = a.diff(&b);
        assert!(d.test(0) && !d.test(1));
    }

    #[test]
    fn test_jaccard_identical() {
        let mut a = CoverageBitmap::new(16);
        a.set(3); a.set(10);
        let b = a.clone();
        assert!((a.jaccard(&b) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_is_empty_is_full() {
        let mut bm = CoverageBitmap::new(4);
        assert!(bm.is_empty());
        bm.set(0); bm.set(1); bm.set(2); bm.set(3);
        assert!(bm.is_full());
    }

    #[test]
    fn test_serialization_round_trip() {
        let mut bm = CoverageBitmap::new(32);
        bm.set(0); bm.set(15); bm.set(31);
        let bytes = bm.to_bytes();
        let bm2 = CoverageBitmap::from_serialized(&bytes).unwrap();
        assert_eq!(bm, bm2);
    }

    #[test]
    fn test_bitmap_merger() {
        let mut m = BitmapMerger::new();
        let mut a = CoverageBitmap::new(8);
        let mut b = CoverageBitmap::new(8);
        a.set(0); b.set(1);
        m.add(&a); m.add(&b);
        let merged = m.finish().unwrap();
        assert!(merged.test(0) && merged.test(1));
    }

    #[test]
    fn test_edge_id_from_pcs() {
        // This test used to assert `id.0 == (0x1000 ^ 0x2000) % 65536`, i.e. it
        // re-implemented the formula under test inside its own assertion. Such
        // an oracle passes by construction and proves nothing: it pinned the
        // implementation while the property it was supposed to protect —
        // distinct edges landing in distinct slots — was violated, because XOR
        // is symmetric.
        //
        // Assert the property instead.
        let forward = EdgeId::from_pcs(0x1000, 0x2000, 65536);
        let back = EdgeId::from_pcs(0x2000, 0x1000, 65536);
        assert_ne!(
            forward.0, back.0,
            "a call and its return are different edges"
        );

        let self_a = EdgeId::from_pcs(0x1000, 0x1000, 65536);
        let self_b = EdgeId::from_pcs(0x9999, 0x9999, 65536);
        assert_ne!(self_a.0, self_b.0, "distinct self-edges are distinct");

        // Deterministic and inside the map.
        assert_eq!(forward.0, EdgeId::from_pcs(0x1000, 0x2000, 65536).0);
        assert!(forward.0 < 65536);
    }

    #[test]
    fn test_coverage_comparison() {
        let mut a = CoverageBitmap::new(16);
        let mut b = CoverageBitmap::new(16);
        a.set(0); a.set(1); b.set(1); b.set(2);
        let cmp = CoverageComparison::compute(&a, &b);
        assert_eq!(cmp.only_in_a, 1);
        assert_eq!(cmp.only_in_b, 1);
        assert_eq!(cmp.in_both, 1);
    }

    #[test]
    fn test_normalization() {
        let mut bm = CoverageBitmap::new(8);
        bm.data[0] = 0b0000_0011;
        let norm = bm.normalized();
        assert_eq!(norm.data[0], 0xFF);
    }

    #[test]
    fn test_bitmap_stats() {
        let mut bm = CoverageBitmap::new(100);
        bm.set(0); bm.set(50);
        let stats = bm.stats();
        assert_eq!(stats.set_bits, 2);
        assert_eq!(stats.size_bits, 100);
    }
}
