//! AFL-style 64k coverage bitmap — edge coverage tracking, hit counts,
//! new-bits detection, and bitmap comparison utilities.

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Number of slots in the coverage bitmap (64 KiB = 65 536 entries).
pub const BITMAP_SIZE: usize = 1 << 16;

/// `BITMAP_SIZE` as a `u32` (always fits; 65536 < 2^32).
const BITMAP_SIZE_U32: u32 = 65536;

/// Bitmask used to fold edge IDs into the bitmap index space.
pub const BITMAP_MASK: u64 = (BITMAP_SIZE as u64) - 1;

// ─── Edge ID ──────────────────────────────────────────────────────────────────

/// A control-flow edge represented as (previous block, current block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Edge {
    pub prev: u64,
    pub curr: u64,
}

impl Edge {
    #[must_use] 
    pub const fn new(prev: u64, curr: u64) -> Self {
        Self { prev, curr }
    }

    /// Compute the AFL-style bitmap slot for this edge.
    ///
    /// AFL uses: `cur_location ^ (prev_location >> 1)`, where both are
    /// randomized block IDs. We use a multiplicative hash over the pair.
    #[must_use] 
    pub const fn bitmap_slot(&self) -> usize {
        let h = self.prev.wrapping_mul(2_654_435_761)
            ^ self.curr.wrapping_mul(2_246_822_519);
        (h & BITMAP_MASK) as usize
    }

    /// Slot using AFL's classic XOR formula (requires pre-hashed block IDs).
    #[must_use] 
    pub const fn bitmap_slot_afl_classic(&self) -> usize {
        ((self.prev ^ (self.curr >> 1)) & BITMAP_MASK) as usize
    }
}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x} → {:#x}", self.prev, self.curr)
    }
}

// ─── Coverage bitmap ─────────────────────────────────────────────────────────

/// AFL-style 64k coverage bitmap tracking per-slot hit counts.
///
/// Each slot corresponds to one control-flow edge (derived from a (prev, curr)
/// block address pair). The hit count is stored as a saturating u8, clamped
/// at 255.
#[derive(Clone, Serialize, Deserialize)]
pub struct CoverageBitmap {
    /// Raw hit-count array indexed by slot.
    #[serde(serialize_with = "serialize_map", deserialize_with = "deserialize_map")]
    map: Box<[u8; BITMAP_SIZE]>,
    /// Total number of recorded hits across all slots.
    total_hits: u64,
    /// Number of non-zero slots (distinct edges seen).
    distinct_edges: u32,
}

fn serialize_map<S>(map: &[u8; BITMAP_SIZE], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_bytes(map.as_slice())
}

fn deserialize_map<'de, D>(deserializer: D) -> Result<Box<[u8; BITMAP_SIZE]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct MapVisitor;
    impl serde::de::Visitor<'_> for MapVisitor {
        type Value = Box<[u8; BITMAP_SIZE]>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte array of size 65536")
        }
        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if v.len() != BITMAP_SIZE {
                return Err(E::custom(format!("expected size {}, got {}", BITMAP_SIZE, v.len())));
            }
            let mut map: Box<[u8; BITMAP_SIZE]> = vec![0u8; BITMAP_SIZE]
                .into_boxed_slice()
                .try_into()
                .unwrap();
            map.copy_from_slice(v);
            Ok(map)
        }
    }
    deserializer.deserialize_bytes(MapVisitor)
}

impl CoverageBitmap {
    /// Create an empty bitmap.
    ///
    /// # Panics
    /// Panics if the fixed-size array conversion fails (should never happen at
    /// compile-time-known `BITMAP_SIZE`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: vec![0u8; BITMAP_SIZE].into_boxed_slice().try_into().unwrap(),
            total_hits: 0,
            distinct_edges: 0,
        }
    }

    /// Record a hit for the given edge.
    /// The hit count is saturating — it will not overflow past 255.
    pub fn record_edge(&mut self, edge: Edge) {
        let slot = edge.bitmap_slot();
        self.record_slot(slot);
    }

    /// Record a hit for a raw slot index (clamped to [0, `BITMAP_SIZE`)).
    pub fn record_slot(&mut self, slot: usize) {
        let slot = slot & (BITMAP_SIZE - 1);
        if self.map[slot] == 0 {
            self.distinct_edges += 1;
        }
        self.map[slot] = self.map[slot].saturating_add(1);
        self.total_hits += 1;
    }

    /// Record a block transition (`prev_block` → `curr_block`).
    pub fn record_transition(&mut self, prev: u64, curr: u64) {
        self.record_edge(Edge::new(prev, curr));
    }

    /// Get the raw hit count for a slot.
    #[must_use] 
    pub fn get(&self, slot: usize) -> u8 {
        self.map[slot & (BITMAP_SIZE - 1)]
    }

    /// Get the hit count for an edge.
    #[must_use] 
    pub fn hit_count(&self, edge: &Edge) -> u8 {
        self.map[edge.bitmap_slot()]
    }

    /// Returns true if the edge has been seen at least once.
    #[must_use] 
    pub fn is_covered(&self, edge: &Edge) -> bool {
        self.map[edge.bitmap_slot()] > 0
    }

    /// Returns the number of non-zero slots (distinct edges covered).
    #[must_use] 
    pub const fn distinct_edge_count(&self) -> u32 {
        self.distinct_edges
    }

    /// Returns the total number of recorded hits.
    #[must_use] 
    pub const fn total_hits(&self) -> u64 {
        self.total_hits
    }

    /// Returns the raw backing array.
    #[must_use] 
    pub fn raw(&self) -> &[u8; BITMAP_SIZE] {
        &self.map
    }

    /// Returns a mutable reference to the raw backing array.
    pub fn raw_mut(&mut self) -> &mut [u8; BITMAP_SIZE] {
        &mut self.map
    }

    /// Merge another bitmap into this one (union with saturating add).
    pub fn merge(&mut self, other: &Self) {
        for i in 0..BITMAP_SIZE {
            let was_zero = self.map[i] == 0;
            self.map[i] = self.map[i].saturating_add(other.map[i]);
            if was_zero && self.map[i] > 0 {
                self.distinct_edges += 1;
            }
            self.total_hits += u64::from(other.map[i]);
        }
    }

    /// Returns a new bitmap that is the union (saturating add) of both.
    #[must_use] 
    pub fn union(&self, other: &Self) -> Self {
        let mut out = self.clone();
        out.merge(other);
        out
    }

    /// Compute the set of new bits in `other` not present in `self`.
    /// Returns a bitmap with only the newly discovered edges set to 1.
    #[must_use] 
    pub fn new_bits(&self, other: &Self) -> Self {
        let mut diff = Self::new();
        for i in 0..BITMAP_SIZE {
            if other.map[i] > 0 && self.map[i] == 0 {
                diff.map[i] = 1;
                diff.distinct_edges += 1;
                diff.total_hits += 1;
            }
        }
        diff
    }

    /// Returns true if `other` contains at least one edge not in `self`.
    #[must_use] 
    pub fn has_new_bits(&self, other: &Self) -> bool {
        for i in 0..BITMAP_SIZE {
            if other.map[i] > 0 && self.map[i] == 0 {
                return true;
            }
        }
        false
    }

    /// Compute the Hamming distance (number of slots that differ) between
    /// this bitmap and another.
    #[must_use] 
    pub fn hamming_distance(&self, other: &Self) -> u32 {
        let mut dist = 0u32;
        for i in 0..BITMAP_SIZE {
            if self.map[i] != other.map[i] {
                dist += 1;
            }
        }
        dist
    }

    /// Compute the Jaccard similarity (intersection / union) of covered slots.
    #[must_use] 
    pub fn jaccard_similarity(&self, other: &Self) -> f64 {
        let mut intersection = 0u32;
        let mut union = 0u32;
        for i in 0..BITMAP_SIZE {
            let a = self.map[i] > 0;
            let b = other.map[i] > 0;
            if a || b {
                union += 1;
            }
            if a && b {
                intersection += 1;
            }
        }
        if union == 0 {
            1.0
        } else {
            f64::from(intersection) / f64::from(union)
        }
    }

    /// Reset the bitmap to all zeros.
    pub fn reset(&mut self) {
        self.map.iter_mut().for_each(|b| *b = 0);
        self.total_hits = 0;
        self.distinct_edges = 0;
    }

    /// Serialize the bitmap to a compact binary representation.
    /// Format: 4 bytes (little-endian `distinct_edges`), 8 bytes (`total_hits`),
    /// then 65536 bytes of raw data.
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + BITMAP_SIZE);
        out.extend_from_slice(&self.distinct_edges.to_le_bytes());
        out.extend_from_slice(&self.total_hits.to_le_bytes());
        out.extend_from_slice(self.map.as_slice());
        out
    }

    /// Deserialize from the compact binary format produced by `to_bytes`.
    ///
    /// # Panics
    /// Panics if the fixed-size array conversion fails (should never happen at
    /// compile-time-known `BITMAP_SIZE`).
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 4 + 8 + BITMAP_SIZE {
            return None;
        }
        let distinct_edges = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let total_hits = u64::from_le_bytes(data[4..12].try_into().ok()?);
        let mut map: Box<[u8; BITMAP_SIZE]> = vec![0u8; BITMAP_SIZE]
            .into_boxed_slice()
            .try_into()
            .unwrap();
        map.copy_from_slice(&data[12..12 + BITMAP_SIZE]);
        Some(Self {
            map,
            total_hits,
            distinct_edges,
        })
    }

    /// Compute a summary of the bitmap's coverage characteristics.
    #[must_use] 
    pub fn stats(&self) -> BitmapStats {
        let covered = self.distinct_edges;
        let max_slot = self
            .map
            .iter()
            .enumerate()
            .max_by_key(|&(_, &v)| v)
            .map_or(0, |(i, _)| i);
        let max_hits = self.map[max_slot];
        let mean_hits = if covered > 0 {
            crate::u64_to_f64(self.total_hits) / f64::from(covered)
        } else {
            0.0
        };
        let coverage_pct = f64::from(covered) / crate::usize_to_f64(BITMAP_SIZE) * 100.0;

        // Build hit bucket distribution (1, 2–3, 4–7, 8–15, 16–31, 32+)
        let mut buckets = [0u32; 6];
        for &v in self.map.iter() {
            let bucket = match v {
                0 => continue,
                1 => 0,
                2..=3 => 1,
                4..=7 => 2,
                8..=15 => 3,
                16..=31 => 4,
                _ => 5,
            };
            buckets[bucket] += 1;
        }

        BitmapStats {
            covered_slots: covered,
            total_slots: crate::usize_to_u32_sat(BITMAP_SIZE),
            coverage_pct,
            total_hits: self.total_hits,
            mean_hits_per_covered_slot: mean_hits,
            max_hits_in_any_slot: max_hits,
            hottest_slot: max_slot,
            hit_buckets: buckets,
        }
    }
}

impl Default for CoverageBitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CoverageBitmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoverageBitmap {{ distinct_edges: {}, total_hits: {} }}",
            self.distinct_edges, self.total_hits
        )
    }
}

// ─── Bitmap stats ─────────────────────────────────────────────────────────────

/// Summary statistics for a coverage bitmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitmapStats {
    /// Number of non-zero slots.
    pub covered_slots: u32,
    /// Total bitmap size.
    pub total_slots: u32,
    /// Coverage percentage (0.0–100.0).
    pub coverage_pct: f64,
    /// Total hit count across all slots.
    pub total_hits: u64,
    /// Mean hits per covered slot.
    pub mean_hits_per_covered_slot: f64,
    /// Maximum hits in any single slot.
    pub max_hits_in_any_slot: u8,
    /// Slot index with the most hits.
    pub hottest_slot: usize,
    /// Hit count distribution: [1, 2-3, 4-7, 8-15, 16-31, 32+]
    pub hit_buckets: [u32; 6],
}

// ─── Virgins bitmap ───────────────────────────────────────────────────────────

/// Tracks which slots have never been hit (AFL "`virgin_bits`" equivalent).
///
/// Initially all slots are "virgin" (unseen). When a new bitmap is observed,
/// virgins are cleared for newly covered slots.
pub struct VirginBitmap {
    virgin: Box<[u8; BITMAP_SIZE]>,
    remaining_virgin: u32,
}

impl VirginBitmap {
    /// Create a new virgin bitmap (all slots unexplored).
    ///
    /// # Panics
    /// Panics if the fixed-size array conversion fails (should never happen at
    /// compile-time-known `BITMAP_SIZE`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            virgin: vec![0xFFu8; BITMAP_SIZE].into_boxed_slice().try_into().unwrap(),
            remaining_virgin: crate::usize_to_u32_sat(BITMAP_SIZE),
        }
    }

    /// Update the virgin map given a new coverage bitmap.
    /// Returns the number of newly discovered slots (new interesting edges).
    pub fn update(&mut self, bitmap: &CoverageBitmap) -> u32 {
        let mut new_count = 0u32;
        let raw = bitmap.raw();
        for (v_slot, r_slot) in self.virgin.iter_mut().zip(raw.iter()) {
            if *r_slot != 0 && *v_slot != 0 {
                let prev = *v_slot;
                *v_slot &= !r_slot;
                if prev != *v_slot {
                    new_count += 1;
                    if self.remaining_virgin > 0 {
                        self.remaining_virgin -= 1;
                    }
                }
            }
        }
        new_count
    }

    #[must_use] 
    pub const fn remaining(&self) -> u32 {
        self.remaining_virgin
    }

    #[must_use] 
    pub fn is_virgin(&self, slot: usize) -> bool {
        self.virgin[slot & (BITMAP_SIZE - 1)] != 0
    }

    /// Returns the number of slots that have been discovered (not virgin).
    #[must_use]
    pub const fn discovered(&self) -> u32 {
        BITMAP_SIZE_U32 - self.remaining_virgin
    }
}

impl Default for VirginBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Block-level coverage ─────────────────────────────────────────────────────

/// Records which basic blocks (by address) have been visited and how many times.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockCoverageTracker {
    /// Map from block address to hit count.
    hits: std::collections::HashMap<u64, u32>,
}

impl BlockCoverageTracker {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            hits: std::collections::HashMap::new(),
        }
    }

    pub fn record(&mut self, addr: u64) {
        *self.hits.entry(addr).or_insert(0) += 1;
    }

    pub fn record_batch(&mut self, addrs: &[u64]) {
        for &a in addrs {
            self.record(a);
        }
    }

    #[must_use] 
    pub fn hit_count(&self, addr: u64) -> u32 {
        self.hits.get(&addr).copied().unwrap_or(0)
    }

    #[must_use] 
    pub fn is_covered(&self, addr: u64) -> bool {
        self.hits.contains_key(&addr)
    }

    pub fn covered_addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.hits.keys().copied()
    }

    #[must_use] 
    pub fn covered_count(&self) -> usize {
        self.hits.len()
    }

    pub fn merge(&mut self, other: &Self) {
        for (&addr, &count) in &other.hits {
            *self.hits.entry(addr).or_insert(0) += count;
        }
    }

    pub fn new_blocks_in<'a>(
        &self,
        other: &'a Self,
    ) -> impl Iterator<Item = u64> + 'a {
        let existing: std::collections::HashSet<u64> =
            self.hits.keys().copied().collect();
        other
            .hits
            .keys()
            .copied()
            .filter(move |a| !existing.contains(a))
    }

    #[must_use] 
    pub fn to_sorted_vec(&self) -> Vec<(u64, u32)> {
        let mut v: Vec<(u64, u32)> = self.hits.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by_key(|(a, _)| *a);
        v
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_edge() {
        let mut bm = CoverageBitmap::new();
        let e = Edge::new(0x1000, 0x2000);
        bm.record_edge(e);
        assert_eq!(bm.hit_count(&e), 1);
        assert!(bm.is_covered(&e));
        assert_eq!(bm.distinct_edge_count(), 1);
    }

    #[test]
    fn test_saturating_hit() {
        let mut bm = CoverageBitmap::new();
        let e = Edge::new(1, 2);
        let slot = e.bitmap_slot();
        for _ in 0..300 {
            bm.record_slot(slot);
        }
        assert_eq!(bm.get(slot), 255);
    }

    #[test]
    fn test_new_bits() {
        let mut a = CoverageBitmap::new();
        let mut b = CoverageBitmap::new();
        a.record_edge(Edge::new(0, 1));
        b.record_edge(Edge::new(0, 1));
        b.record_edge(Edge::new(2, 3));
        let diff = a.new_bits(&b);
        assert_eq!(diff.distinct_edge_count(), 1);
        assert!(a.has_new_bits(&b));
    }

    #[test]
    fn test_merge() {
        let mut a = CoverageBitmap::new();
        let mut b = CoverageBitmap::new();
        a.record_edge(Edge::new(0, 1));
        b.record_edge(Edge::new(2, 3));
        a.merge(&b);
        assert_eq!(a.distinct_edge_count(), 2);
    }

    #[test]
    fn test_jaccard_similarity() {
        let mut a = CoverageBitmap::new();
        let mut b = CoverageBitmap::new();
        a.record_edge(Edge::new(0, 1));
        b.record_edge(Edge::new(0, 1));
        let sim = a.jaccard_similarity(&b);
        assert!((sim - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_bytes_roundtrip() {
        let mut bm = CoverageBitmap::new();
        bm.record_edge(Edge::new(100, 200));
        bm.record_edge(Edge::new(300, 400));
        let bytes = bm.to_bytes();
        let bm2 = CoverageBitmap::from_bytes(&bytes).unwrap();
        assert_eq!(bm.distinct_edge_count(), bm2.distinct_edge_count());
        assert_eq!(bm.total_hits(), bm2.total_hits());
    }

    #[test]
    fn test_bitmap_stats() {
        let mut bm = CoverageBitmap::new();
        for i in 0..100u64 {
            bm.record_edge(Edge::new(i, i + 1));
        }
        let stats = bm.stats();
        assert!(stats.coverage_pct > 0.0);
        assert!(stats.covered_slots > 0);
    }

    #[test]
    fn test_virgin_bitmap() {
        let mut vb = VirginBitmap::new();
        let mut bm = CoverageBitmap::new();
        let e = Edge::new(10, 20);
        bm.record_edge(e);
        let new = vb.update(&bm);
        assert_eq!(new, 1);
        // Second update with same bitmap → no new bits
        let new2 = vb.update(&bm);
        assert_eq!(new2, 0);
    }

    #[test]
    fn test_block_tracker() {
        let mut tracker = BlockCoverageTracker::new();
        tracker.record(0x1000);
        tracker.record(0x1000);
        tracker.record(0x2000);
        assert_eq!(tracker.hit_count(0x1000), 2);
        assert_eq!(tracker.covered_count(), 2);
    }

    #[test]
    fn test_block_new_blocks() {
        let mut a = BlockCoverageTracker::new();
        let mut b = BlockCoverageTracker::new();
        a.record(0x1000);
        b.record(0x1000);
        b.record(0x3000);
        let new: Vec<u64> = a.new_blocks_in(&b).collect();
        assert_eq!(new, vec![0x3000]);
    }
}
