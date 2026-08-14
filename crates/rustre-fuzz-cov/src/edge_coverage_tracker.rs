//! Edge-level coverage tracker for the rustre fuzzing subsystem.
//!
//! This module complements [`block_coverage_tracker`] by tracking *transitions*
//! between basic blocks (edges in the control-flow graph).  Edge coverage is
//! more precise than block coverage: two inputs that cover the same blocks but
//! take different branches produce different edge traces.
//!
//! The representation mirrors AFL's approach: each edge is encoded as a 16-bit
//! index computed as `(prev_block_id * K + cur_block_id) % BITMAP_SIZE`.
//! The bitmap is a compact byte array where each byte saturates at 255.
//!
//! Key types:
//! - [`EdgeBitmap`] — the raw AFL-style coverage bitmap.
//! - [`CoveredEdge`] — metadata for a discovered edge.
//! - [`EdgeCoverageTracker`] — high-level tracker with per-run semantics.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default bitmap size (must be a power of two for the index mask to work).
pub const DEFAULT_EDGE_BITMAP_SIZE: usize = 65536;
/// Same value as `DEFAULT_EDGE_BITMAP_SIZE`, typed as `u32` for atomic storage.
pub const DEFAULT_EDGE_BITMAP_SIZE_U32: u32 = 65536;

/// Multiplier used when hashing edge (prev, cur) → index.
const HASH_MULT: u32 = 1_234_577;

// ---------------------------------------------------------------------------
// Edge identifier
// ---------------------------------------------------------------------------

/// A directed CFG edge identified by source and destination block IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeId {
    /// Source block (where the branch originates).
    pub from: u32,
    /// Destination block (target of the branch).
    pub to: u32,
}

impl EdgeId {
    /// Construct an edge ID.
    #[must_use] 
    pub const fn new(from: u32, to: u32) -> Self {
        Self { from, to }
    }

    /// Compute the AFL-style bitmap index for this edge.
    ///
    /// The index is `(from * HASH_MULT ^ to) % bitmap_size`.
    #[must_use] 
    pub const fn bitmap_index(&self, bitmap_size: usize) -> usize {
        let h = self.from.wrapping_mul(HASH_MULT) ^ self.to;
        (h as usize) % bitmap_size
    }
}

impl fmt::Display for EdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}→{}", self.from, self.to)
    }
}

// ---------------------------------------------------------------------------
// CoveredEdge
// ---------------------------------------------------------------------------

/// Metadata about a discovered CFG edge.
#[derive(Debug, Clone)]
pub struct CoveredEdge {
    /// The edge identifier.
    pub id: EdgeId,
    /// Total number of times this edge was taken across all runs.
    pub hit_count: u64,
    /// Index of the first run in which this edge was discovered.
    pub first_seen_run: u32,
    /// Bitmap slot index (may alias with other edges due to hashing).
    pub bitmap_slot: usize,
}

impl CoveredEdge {
    const fn new(id: EdgeId, run_index: u32, bitmap_size: usize) -> Self {
        Self {
            bitmap_slot: id.bitmap_index(bitmap_size),
            id,
            hit_count: 1,
            first_seen_run: run_index,
        }
    }
}

// ---------------------------------------------------------------------------
// EdgeBitmap
// ---------------------------------------------------------------------------

/// A compact AFL-style edge coverage bitmap.
///
/// Each byte corresponds to a bitmap slot.  Bytes saturate at 255.  Two
/// edges that hash to the same slot are indistinguishable (hash collision),
/// but with a 64 KB bitmap this is rare for typical programs.
#[derive(Debug, Clone)]
pub struct EdgeBitmap {
    data: Vec<u8>,
}

impl EdgeBitmap {
    /// Allocate a zeroed bitmap of `size` bytes.
    #[must_use] 
    pub fn new(size: usize) -> Self {
        Self { data: vec![0u8; size] }
    }

    /// Allocate a default-sized (64 KB) bitmap.
    #[must_use] 
    pub fn default_sized() -> Self {
        Self::new(DEFAULT_EDGE_BITMAP_SIZE)
    }

    /// Increment (saturating) the slot for edge `id`.
    #[inline]
    pub fn record(&mut self, id: EdgeId) {
        let idx = id.bitmap_index(self.data.len());
        let v = self.data[idx];
        self.data[idx] = v.saturating_add(1);
    }

    /// Increment a raw slot index (used by the C-ABI shim).
    #[inline]
    pub fn record_raw(&mut self, slot: usize) {
        if slot < self.data.len() {
            self.data[slot] = self.data[slot].saturating_add(1);
        }
    }

    /// Test whether any hit was recorded at the slot for `id`.
    #[must_use] 
    pub fn test(&self, id: EdgeId) -> bool {
        let idx = id.bitmap_index(self.data.len());
        self.data[idx] > 0
    }

    /// Number of non-zero slots (approximates number of covered edges).
    #[must_use] 
    pub fn covered_slots(&self) -> usize {
        self.data.iter().filter(|&&b| b > 0).count()
    }

    /// Total size in bytes.
    #[must_use] 
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    /// Compute a 64-bit hash of the bitmap content (for quick equality check).
    #[must_use] 
    pub fn content_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV offset
        for &b in &self.data {
            h = h.wrapping_mul(0x100_0000_01b3);
            h ^= u64::from(b);
        }
        h
    }

    /// Return a bitmap of *new* slots: set in `other` but zero in `self`.
    #[must_use] 
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn new_in(&self, other: &Self) -> Self {
        assert_eq!(self.data.len(), other.data.len(), "bitmap size mismatch");
        let data: Vec<u8> = self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(&a, &b)| if a == 0 && b > 0 { b } else { 0 })
            .collect();
        Self { data }
    }

    /// Merge `other` into `self` (element-wise saturating add).
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn merge_add(&mut self, other: &Self) {
        assert_eq!(self.data.len(), other.data.len());
        for (a, &b) in self.data.iter_mut().zip(other.data.iter()) {
            *a = a.saturating_add(b);
        }
    }

    /// Merge `other` into `self` (element-wise OR — treats any hit as 1).
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn merge_or(&mut self, other: &Self) {
        assert_eq!(self.data.len(), other.data.len());
        for (a, &b) in self.data.iter_mut().zip(other.data.iter()) {
            if b > 0 {
                *a = a.saturating_add(1);
            }
        }
    }

    /// Serialise to bytes: magic `ECOV` + 4-byte size LE + bitmap bytes.
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.data.len());
        out.extend_from_slice(b"ECOV");
        out.extend_from_slice(&crate::casts::usize_to_u32(self.data.len()).to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Deserialise from bytes written by [`to_bytes`].
    #[must_use] 
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 || &data[0..4] != b"ECOV" {
            return None;
        }
        let size = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
        if data.len() < 8 + size {
            return None;
        }
        Some(Self { data: data[8..8 + size].to_vec() })
    }

    /// Borrow the raw byte slice.
    #[must_use] 
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Check whether all slots are zero (no coverage recorded).
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    /// Reset all slots to zero.
    pub fn clear(&mut self) {
        self.data.iter_mut().for_each(|b| *b = 0);
    }
}

// ---------------------------------------------------------------------------
// EdgeCoverageTracker
// ---------------------------------------------------------------------------

/// Tracks edge coverage across multiple fuzzing runs.
///
/// Maintains an aggregate [`EdgeBitmap`] covering all runs plus per-run
/// snapshots.  Supports the concept of "has new edge since last check"
/// which is the primary signal used by the fuzzer to decide whether an
/// input is interesting.
///
/// ```text
/// let mut tracker = EdgeCoverageTracker::new(DEFAULT_EDGE_BITMAP_SIZE);
/// tracker.run_start();
/// tracker.record_edge(EdgeId::new(0, 1));
/// let new_edges = tracker.run_end();
/// println!("New edge slots: {}", new_edges.covered_slots());
/// ```
pub struct EdgeCoverageTracker {
    bitmap_size: usize,
    /// Aggregate bitmap across all runs (OR semantics).
    aggregate: EdgeBitmap,
    /// Bitmap for the current in-progress run.
    current_run: Option<EdgeBitmap>,
    /// Current run index.
    run_index: u32,
    /// Metadata about covered edges (keyed by `EdgeId`).
    covered: BTreeMap<(u32, u32), CoveredEdge>,
    /// Per-run new-slot counts.
    per_run_new: Vec<usize>,
    /// Per-run total hit counts.
    per_run_hits: Vec<u64>,
    /// Snapshot of aggregate at the last call to [`checkpoint`].
    checkpoint_bm: EdgeBitmap,
}

impl EdgeCoverageTracker {
    /// Create a new tracker with a bitmap of `bitmap_size` bytes.
    #[must_use] 
    pub fn new(bitmap_size: usize) -> Self {
        let size = if bitmap_size.is_power_of_two() {
            bitmap_size
        } else {
            bitmap_size.next_power_of_two()
        };
        let agg = EdgeBitmap::new(size);
        let ckpt = EdgeBitmap::new(size);
        Self {
            bitmap_size: size,
            aggregate: agg,
            current_run: None,
            run_index: 0,
            covered: BTreeMap::new(),
            per_run_new: Vec::new(),
            per_run_hits: Vec::new(),
            checkpoint_bm: ckpt,
        }
    }

    /// Start recording a new run.
    pub fn run_start(&mut self) {
        self.current_run = Some(EdgeBitmap::new(self.bitmap_size));
    }

    /// Record an edge hit in the current run.
    ///
    /// Also stores metadata for later [`coverage_report`] calls.
    pub fn record_edge(&mut self, id: EdgeId) {
        if let Some(ref mut bm) = self.current_run {
            bm.record(id);
        }
        let key = (id.from, id.to);
        self.covered.entry(key).or_insert_with(|| {
            CoveredEdge::new(id, self.run_index, self.bitmap_size)
        }).hit_count += 1;
    }

    /// Record a raw slot hit (from C-ABI shim).
    pub fn record_raw(&mut self, slot: usize) {
        if let Some(ref mut bm) = self.current_run {
            bm.record_raw(slot);
        }
    }

    /// Finalise the current run and return the newly covered [`EdgeBitmap`].
    ///
    /// Returns `None` if no run was started.
    pub fn run_end(&mut self) -> Option<EdgeBitmap> {
        let run_bm = self.current_run.take()?;
        let new_bm = self.aggregate.new_in(&run_bm);
        let new_slots = new_bm.covered_slots();
        let total_hits: u64 = run_bm.as_bytes().iter().map(|&b| u64::from(b)).sum();
        self.per_run_new.push(new_slots);
        self.per_run_hits.push(total_hits);
        self.aggregate.merge_or(&run_bm);
        self.run_index += 1;
        Some(new_bm)
    }

    /// Return `true` if `bm` contains any edge not yet in the aggregate.
    #[must_use] 
    pub fn new_edge_since_last(&self, bm: &EdgeBitmap) -> bool {
        let new = self.aggregate.new_in(bm);
        !new.is_empty()
    }

    /// Return `true` if `bm` has new coverage since the last [`checkpoint`].
    #[must_use] 
    pub fn new_since_checkpoint(&self, bm: &EdgeBitmap) -> bool {
        let new = self.checkpoint_bm.new_in(bm);
        !new.is_empty()
    }

    /// Save a checkpoint of current aggregate coverage.
    pub fn checkpoint(&mut self) {
        self.checkpoint_bm = self.aggregate.clone();
    }

    /// Merge an external bitmap into the aggregate.
    pub fn merge_external(&mut self, bm: &EdgeBitmap) {
        self.aggregate.merge_or(bm);
    }

    /// Number of completed runs.
    #[must_use] 
    pub const fn run_count(&self) -> u32 {
        self.run_index
    }

    /// Number of covered edge slots in the aggregate bitmap.
    #[must_use] 
    pub fn covered_slot_count(&self) -> usize {
        self.aggregate.covered_slots()
    }

    /// Coverage density: fraction of bitmap slots that are non-zero.
    #[must_use] 
    pub fn coverage_density(&self) -> f64 {
        crate::casts::usize_to_f64(self.aggregate.covered_slots()) / crate::casts::usize_to_f64(self.bitmap_size)
    }

    /// Access the aggregate bitmap.
    #[must_use] 
    pub const fn aggregate_bitmap(&self) -> &EdgeBitmap {
        &self.aggregate
    }

    /// Serialise the aggregate bitmap.
    #[must_use] 
    pub fn serialize_aggregate(&self) -> Vec<u8> {
        self.aggregate.to_bytes()
    }

    /// Load an aggregate bitmap from bytes.
    pub fn load_aggregate(&mut self, data: &[u8]) -> bool {
        if let Some(bm) = EdgeBitmap::from_bytes(data)
            && bm.size() == self.bitmap_size {
                self.aggregate = bm;
                return true;
            }
        false
    }

    /// Generate a coverage summary.
    #[must_use] 
    pub fn coverage_report(&self) -> EdgeCoverageReport {
        let mut top_edges: Vec<CoveredEdge> = self.covered.values().cloned().collect();
        top_edges.sort_by(|a, b| b.hit_count.cmp(&a.hit_count));

        EdgeCoverageReport {
            bitmap_size: self.bitmap_size,
            covered_slots: self.aggregate.covered_slots(),
            total_runs: self.run_index,
            per_run_new: self.per_run_new.clone(),
            per_run_hits: self.per_run_hits.clone(),
            top_edges: top_edges.into_iter().take(20).collect(),
            density: self.coverage_density(),
        }
    }

    /// Reset all state.
    pub fn reset(&mut self) {
        self.aggregate = EdgeBitmap::new(self.bitmap_size);
        self.checkpoint_bm = EdgeBitmap::new(self.bitmap_size);
        self.current_run = None;
        self.run_index = 0;
        self.covered.clear();
        self.per_run_new.clear();
        self.per_run_hits.clear();
    }

    /// Covered edge identifiers (only edges tracked via [`record_edge`]).
    #[must_use] 
    pub fn covered_edges(&self) -> HashSet<EdgeId> {
        self.covered.values().map(|e| e.id).collect()
    }
}

// ---------------------------------------------------------------------------
// EdgeCoverageReport
// ---------------------------------------------------------------------------

/// Summary of edge coverage for a fuzzing session.
#[derive(Debug, Clone)]
pub struct EdgeCoverageReport {
    /// Bitmap size in bytes.
    pub bitmap_size: usize,
    /// Number of non-zero slots in the aggregate.
    pub covered_slots: usize,
    /// Number of completed runs.
    pub total_runs: u32,
    /// Per-run count of newly covered slots.
    pub per_run_new: Vec<usize>,
    /// Per-run total edge-hit counts (sum of all bytes in run bitmap).
    pub per_run_hits: Vec<u64>,
    /// Top-20 hottest edges by hit count.
    pub top_edges: Vec<CoveredEdge>,
    /// Coverage density (`covered_slots` / `bitmap_size`).
    pub density: f64,
}

impl EdgeCoverageReport {
    /// One-line summary string.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "Edge coverage: {}/{} slots ({:.2}%) over {} runs",
            self.covered_slots,
            self.bitmap_size,
            self.density * 100.0,
            self.total_runs,
        )
    }
}

// ---------------------------------------------------------------------------
// Lock-free global edge bitmap (for C-ABI / shared-memory use)
// ---------------------------------------------------------------------------

/// Global edge bitmap used by the inline C-ABI shim.
///
/// In a real deployment this would typically be a shared-memory region
/// exported to the fuzz target via `__AFL_SHM_ID` or similar.
static GLOBAL_EDGE_BITMAP: std::sync::OnceLock<Vec<AtomicU8>> = std::sync::OnceLock::new();
static GLOBAL_EDGE_BM_SIZE: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(DEFAULT_EDGE_BITMAP_SIZE_U32);

/// Initialise the global edge bitmap.
///
/// Must be called once before any instrumented edge call.
pub fn global_edge_init(size: usize) {
    let sz = if size.is_power_of_two() { size } else { size.next_power_of_two() };
    GLOBAL_EDGE_BM_SIZE.store(crate::casts::usize_to_u32(sz), Ordering::SeqCst);
    let _ = GLOBAL_EDGE_BITMAP.set((0..sz).map(|_| AtomicU8::new(0)).collect());
}

/// Record an edge in the global bitmap (saturating increment).
pub fn global_record_edge(from: u32, to: u32) {
    let size = GLOBAL_EDGE_BM_SIZE.load(Ordering::Relaxed) as usize;
    let slot = EdgeId::new(from, to).bitmap_index(size);
    if let Some(bm) = GLOBAL_EDGE_BITMAP.get()
        && slot < bm.len() {
            let old = bm[slot].load(Ordering::Relaxed);
            let _ = bm[slot].compare_exchange(
                old,
                old.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
}

/// Drain the global edge bitmap into an [`EdgeBitmap`], clearing the global.
pub fn drain_global_edge_bitmap() -> EdgeBitmap {
    let size = GLOBAL_EDGE_BM_SIZE.load(Ordering::SeqCst) as usize;
    let mut bm = EdgeBitmap::new(size);
    if let Some(global) = GLOBAL_EDGE_BITMAP.get() {
        for (i, slot) in global.iter().enumerate() {
            let v = slot.swap(0, Ordering::AcqRel);
            if v > 0 && i < bm.data.len() {
                bm.data[i] = v;
            }
        }
    }
    bm
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_id_display() {
        let e = EdgeId::new(3, 7);
        assert_eq!(format!("{e}"), "3→7");
    }

    #[test]
    fn test_bitmap_record_test() {
        let mut bm = EdgeBitmap::new(256);
        let e = EdgeId::new(1, 2);
        bm.record(e);
        assert!(bm.test(e));
        assert!(!bm.test(EdgeId::new(99, 100)));
    }

    #[test]
    fn test_bitmap_new_in() {
        let mut base = EdgeBitmap::new(256);
        base.record(EdgeId::new(0, 1));
        let mut run = EdgeBitmap::new(256);
        run.record(EdgeId::new(0, 1));
        run.record(EdgeId::new(5, 6));
        let new = base.new_in(&run);
        assert!(!new.test(EdgeId::new(0, 1)));
        assert!(new.test(EdgeId::new(5, 6)));
    }

    #[test]
    fn test_bitmap_roundtrip() {
        let mut bm = EdgeBitmap::new(256);
        bm.record(EdgeId::new(10, 20));
        let bytes = bm.to_bytes();
        let bm2 = EdgeBitmap::from_bytes(&bytes).unwrap();
        assert!(bm2.test(EdgeId::new(10, 20)));
    }

    #[test]
    fn test_tracker_run_lifecycle() {
        let mut tracker = EdgeCoverageTracker::new(256);
        tracker.run_start();
        tracker.record_edge(EdgeId::new(0, 1));
        tracker.record_edge(EdgeId::new(1, 2));
        let new = tracker.run_end().unwrap();
        assert_eq!(new.covered_slots(), 2);
        assert_eq!(tracker.covered_slot_count(), 2);
    }

    #[test]
    fn test_tracker_new_edge_since_last() {
        let mut tracker = EdgeCoverageTracker::new(256);
        tracker.run_start();
        tracker.record_edge(EdgeId::new(0, 1));
        tracker.run_end();

        let mut candidate = EdgeBitmap::new(256);
        candidate.record(EdgeId::new(0, 1));
        assert!(!tracker.new_edge_since_last(&candidate));

        candidate.record(EdgeId::new(2, 3));
        assert!(tracker.new_edge_since_last(&candidate));
    }

    #[test]
    fn test_tracker_checkpoint() {
        let mut tracker = EdgeCoverageTracker::new(256);
        tracker.run_start();
        tracker.record_edge(EdgeId::new(0, 1));
        tracker.run_end();
        tracker.checkpoint();

        let mut candidate = EdgeBitmap::new(256);
        candidate.record(EdgeId::new(0, 1));
        assert!(!tracker.new_since_checkpoint(&candidate));

        candidate.record(EdgeId::new(5, 6));
        assert!(tracker.new_since_checkpoint(&candidate));
    }

    #[test]
    fn test_tracker_reset() {
        let mut tracker = EdgeCoverageTracker::new(256);
        tracker.run_start();
        tracker.record_edge(EdgeId::new(1, 2));
        tracker.run_end();
        tracker.reset();
        assert_eq!(tracker.covered_slot_count(), 0);
        assert_eq!(tracker.run_count(), 0);
    }

    #[test]
    fn test_coverage_density() {
        let mut tracker = EdgeCoverageTracker::new(1024);
        tracker.run_start();
        for i in 0u32..10 {
            tracker.record_edge(EdgeId::new(i, i + 1));
        }
        tracker.run_end();
        assert!(tracker.coverage_density() > 0.0);
        assert!(tracker.coverage_density() < 1.0);
    }

    #[test]
    fn test_content_hash_changes() {
        let mut a = EdgeBitmap::new(256);
        let h0 = a.content_hash();
        a.record(EdgeId::new(3, 4));
        let h1 = a.content_hash();
        assert_ne!(h0, h1);
    }
}
