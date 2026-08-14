//! Basic-block coverage tracker for the rustre fuzzing subsystem.
//!
//! This module maintains a compact bitmap of which basic blocks have been
//! executed during a fuzzing campaign.  Each block is identified by a
//! monotonically-assigned [`BlockCovId`].  Instrumentation stubs call
//! [`BlockCoverageTracker::mark`] (or the C-ABI shim
//! [`block_cov_mark_c`]) to flip the bit for a given block.
//!
//! The tracker supports:
//! - Per-run "has this block been newly covered?" queries.
//! - Merging coverage from multiple runs into an aggregate map.
//! - Serialisation to / deserialisation from a compact binary format
//!   (4-byte magic + 4-byte count + packed bytes).
//! - Generating human-readable [`CoverageReport`] summaries.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};

// ---------------------------------------------------------------------------
// Block identifier
// ---------------------------------------------------------------------------

/// Unique identifier for an instrumented basic block.
///
/// IDs are assigned at instrumentation time and are stable within a single
/// binary.  They are *not* necessarily dense — instrumentation may skip
/// blocks that are unreachable or uninteresting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockCovId(pub u32);

impl fmt::Display for BlockCovId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BB#{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// InstrumentedTarget
// ---------------------------------------------------------------------------

/// Metadata about an instrumented target binary / module.
#[derive(Debug, Clone)]
pub struct InstrumentedTarget {
    /// Human-readable name (e.g., the binary file name).
    pub name: String,
    /// Total number of instrumented blocks in this target.
    pub total_blocks: u32,
    /// Base virtual address of the target (0 if position-independent).
    pub base_address: u64,
    /// Mapping from block ID to its virtual address in the target.
    pub block_addresses: HashMap<BlockCovId, u64>,
    /// Optional mapping from block ID to source file + line.
    pub block_sources: HashMap<BlockCovId, (String, u32)>,
}

impl InstrumentedTarget {
    /// Create a new `InstrumentedTarget` with no address/source mappings.
    pub fn new(name: impl Into<String>, total_blocks: u32) -> Self {
        Self {
            name: name.into(),
            total_blocks,
            base_address: 0,
            block_addresses: HashMap::new(),
            block_sources: HashMap::new(),
        }
    }

    /// Register the virtual address for a given block.
    pub fn set_address(&mut self, id: BlockCovId, addr: u64) {
        self.block_addresses.insert(id, addr);
    }

    /// Register the source location for a given block.
    pub fn set_source(&mut self, id: BlockCovId, file: impl Into<String>, line: u32) {
        self.block_sources.insert(id, (file.into(), line));
    }

    /// Coverage percentage given a set of covered block IDs.
    #[must_use] 
    pub fn coverage_pct(&self, covered: &HashSet<BlockCovId>) -> f64 {
        if self.total_blocks == 0 {
            return 100.0;
        }
        let n = covered
            .iter()
            .filter(|id| id.0 < self.total_blocks)
            .count();
        crate::casts::usize_to_f64(n) / f64::from(self.total_blocks) * 100.0
    }
}

// ---------------------------------------------------------------------------
// CoveredBlock
// ---------------------------------------------------------------------------

/// Information about a single covered block.
#[derive(Debug, Clone)]
pub struct CoveredBlock {
    /// Block identifier.
    pub id: BlockCovId,
    /// Number of times this block was hit across all tracked runs.
    pub hit_count: u64,
    /// Index of the first run in which this block was covered (0-based).
    pub first_seen_run: u32,
    /// Virtual address of the block (if known).
    pub address: Option<u64>,
}

impl CoveredBlock {
    const fn new(id: BlockCovId, run_index: u32, address: Option<u64>) -> Self {
        Self { id, hit_count: 1, first_seen_run: run_index, address }
    }
}

// ---------------------------------------------------------------------------
// BlockCovBitmap
// ---------------------------------------------------------------------------

/// A raw bitmap covering up to `capacity` block IDs.
///
/// Stored as a `Vec<u8>` of ceil(capacity / 8) bytes.  The bit for block ID
/// `i` is at byte `i / 8`, bit `i % 8`.
#[derive(Debug, Clone)]
pub struct BlockCovBitmap {
    bits: Vec<u8>,
    capacity: u32,
}

impl BlockCovBitmap {
    /// Create a zeroed bitmap for `capacity` blocks.
    #[must_use] 
    pub fn new(capacity: u32) -> Self {
        let bytes = (capacity as usize).div_ceil(8);
        Self { bits: vec![0u8; bytes], capacity }
    }

    /// Set the bit for block `id`.
    pub fn set(&mut self, id: BlockCovId) {
        if id.0 < self.capacity {
            let byte = (id.0 / 8) as usize;
            let bit = id.0 % 8;
            self.bits[byte] |= 1u8 << bit;
        }
    }

    /// Test whether block `id` is set.
    #[must_use] 
    pub fn test(&self, id: BlockCovId) -> bool {
        if id.0 >= self.capacity {
            return false;
        }
        let byte = (id.0 / 8) as usize;
        let bit = id.0 % 8;
        (self.bits[byte] >> bit) & 1 == 1
    }

    /// Count the number of set bits.
    #[must_use] 
    pub fn popcount(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }

    /// Bitwise OR of two bitmaps of equal capacity into `self`.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn merge_or(&mut self, other: &Self) {
        assert_eq!(self.capacity, other.capacity, "bitmap capacity mismatch");
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= b;
        }
    }

    /// Bits set in `other` but not in `self` (new coverage).
    #[must_use] 
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn new_in(&self, other: &Self) -> Self {
        assert_eq!(self.capacity, other.capacity);
        let mut result = Self::new(self.capacity);
        for i in 0..self.bits.len() {
            result.bits[i] = other.bits[i] & !self.bits[i];
        }
        result
    }

    /// Capacity (number of bits).
    #[must_use] 
    pub const fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Serialise to bytes: 4-byte magic `BCOV`, 4-byte capacity LE, then bitmap bytes.
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.bits.len());
        out.extend_from_slice(b"BCOV");
        out.extend_from_slice(&self.capacity.to_le_bytes());
        out.extend_from_slice(&self.bits);
        out
    }

    /// Deserialise from bytes written by [`to_bytes`].
    #[must_use] 
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        if &data[0..4] != b"BCOV" {
            return None;
        }
        let capacity = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let expected_bytes = (capacity as usize).div_ceil(8);
        if data.len() < 8 + expected_bytes {
            return None;
        }
        Some(Self { bits: data[8..8 + expected_bytes].to_vec(), capacity })
    }

    /// Iterate over all set block IDs.
    pub fn iter_set(&self) -> impl Iterator<Item = BlockCovId> + '_ {
        (0..self.capacity).filter(move |&i| {
            let byte = (i / 8) as usize;
            let bit = i % 8;
            byte < self.bits.len() && (self.bits[byte] >> bit) & 1 == 1
        }).map(BlockCovId)
    }
}

// ---------------------------------------------------------------------------
// CoverageReport
// ---------------------------------------------------------------------------

/// A human-readable coverage report.
#[derive(Debug, Clone)]
pub struct CoverageReport {
    /// Target name.
    pub target: String,
    /// Number of blocks instrumented.
    pub total_blocks: u32,
    /// Number of blocks covered at least once.
    pub covered_blocks: u32,
    /// Coverage percentage (0.0–100.0).
    pub coverage_pct: f64,
    /// Number of distinct fuzzing runs contributing to coverage.
    pub run_count: u32,
    /// Top-N newly discovered blocks (sorted by `first_seen_run`).
    pub new_blocks: Vec<CoveredBlock>,
    /// Per-run block coverage counts.
    pub per_run_counts: Vec<u32>,
}

impl CoverageReport {
    /// Print a brief summary to a string.
    #[must_use] 
    pub fn summary(&self) -> String {
        format!(
            "Target: {} | Covered: {}/{} ({:.1}%) | Runs: {}",
            self.target,
            self.covered_blocks,
            self.total_blocks,
            self.coverage_pct,
            self.run_count,
        )
    }
}

// ---------------------------------------------------------------------------
// BlockCoverageTracker
// ---------------------------------------------------------------------------

/// The main block coverage tracker.
///
/// Tracks which blocks have been covered across multiple fuzzing runs.
/// Each call to [`run_start`] begins a new run; [`mark`] records a hit;
/// [`run_end`] finalises the run and returns newly covered blocks.
///
/// ```text
/// let mut tracker = BlockCoverageTracker::new(target);
/// tracker.run_start();
/// tracker.mark(BlockCovId(42));
/// let new_cov = tracker.run_end();
/// let report = tracker.coverage_report(10);
/// ```
pub struct BlockCoverageTracker {
    target: InstrumentedTarget,
    /// Aggregate coverage across all completed runs.
    aggregate: BlockCovBitmap,
    /// Bitmap for the current (in-progress) run.
    current_run: Option<BlockCovBitmap>,
    /// Current run index.
    run_index: u32,
    /// Per-covered-block metadata.
    covered: BTreeMap<BlockCovId, CoveredBlock>,
    /// Per-run hit counts.
    per_run_counts: Vec<u32>,
}

impl BlockCoverageTracker {
    /// Create a tracker for the given target.
    #[must_use] 
    pub fn new(target: InstrumentedTarget) -> Self {
        let cap = target.total_blocks;
        Self {
            aggregate: BlockCovBitmap::new(cap),
            target,
            current_run: None,
            run_index: 0,
            covered: BTreeMap::new(),
            per_run_counts: Vec::new(),
        }
    }

    /// Begin recording a new run.  Any previous in-progress run is discarded.
    pub fn run_start(&mut self) {
        self.current_run = Some(BlockCovBitmap::new(self.target.total_blocks));
    }

    /// Record a hit for block `id` in the current run.
    ///
    /// If no run is in progress the call is silently ignored.
    pub fn mark(&mut self, id: BlockCovId) {
        if let Some(ref mut bm) = self.current_run {
            bm.set(id);
        }
    }

    /// Mark multiple blocks at once.
    pub fn mark_many(&mut self, ids: impl IntoIterator<Item = BlockCovId>) {
        for id in ids {
            self.mark(id);
        }
    }

    /// Finalise the current run, merge into aggregate, and return a
    /// [`BlockCovBitmap`] containing the *newly* covered blocks
    /// (i.e., not seen in any previous run).
    ///
    /// Returns `None` if no run was started.
    pub fn run_end(&mut self) -> Option<BlockCovBitmap> {
        let run_bm = self.current_run.take()?;
        let new_bm = self.aggregate.new_in(&run_bm);
        let run_hits = run_bm.popcount();
        self.per_run_counts.push(run_hits);

        // Update covered metadata.
        for id in new_bm.iter_set() {
            let addr = self.target.block_addresses.get(&id).copied();
            self.covered.insert(id, CoveredBlock::new(id, self.run_index, addr));
        }
        // Increment hit counts for already-covered blocks.
        for id in run_bm.iter_set() {
            if let Some(cb) = self.covered.get_mut(&id) {
                cb.hit_count += 1;
            }
        }

        self.aggregate.merge_or(&run_bm);
        self.run_index += 1;
        Some(new_bm)
    }

    /// Directly merge an external bitmap into the aggregate (useful for
    /// importing coverage from a subprocess or shared-memory region).
    pub fn merge_bitmap(&mut self, bm: &BlockCovBitmap) {
        let new_bm = self.aggregate.new_in(bm);
        for id in new_bm.iter_set() {
            let addr = self.target.block_addresses.get(&id).copied();
            self.covered.insert(id, CoveredBlock::new(id, self.run_index, addr));
        }
        self.aggregate.merge_or(bm);
    }

    /// Return `true` if there is any new coverage in `bm` not yet seen.
    #[must_use] 
    pub fn has_new_coverage(&self, bm: &BlockCovBitmap) -> bool {
        let new = self.aggregate.new_in(bm);
        new.popcount() > 0
    }

    /// Number of completed runs.
    #[must_use] 
    pub const fn run_count(&self) -> u32 {
        self.run_index
    }

    /// Number of covered blocks.
    #[must_use] 
    pub fn covered_count(&self) -> u32 {
        self.aggregate.popcount()
    }

    /// Coverage percentage (0.0–100.0).
    #[must_use] 
    pub fn coverage_pct(&self) -> f64 {
        if self.target.total_blocks == 0 {
            return 100.0;
        }
        f64::from(self.covered_count()) / f64::from(self.target.total_blocks) * 100.0
    }

    /// Access the aggregate bitmap directly (read-only).
    #[must_use] 
    pub const fn aggregate_bitmap(&self) -> &BlockCovBitmap {
        &self.aggregate
    }

    /// Serialise the aggregate bitmap to bytes.
    #[must_use] 
    pub fn serialize_aggregate(&self) -> Vec<u8> {
        self.aggregate.to_bytes()
    }

    /// Replace the aggregate bitmap with one loaded from bytes.
    pub fn load_aggregate(&mut self, data: &[u8]) -> bool {
        if let Some(bm) = BlockCovBitmap::from_bytes(data)
            && bm.capacity() == self.target.total_blocks {
                self.aggregate = bm;
                return true;
            }
        false
    }

    /// Build a coverage report, including up to `max_new` newly-seen blocks.
    #[must_use] 
    pub fn coverage_report(&self, max_new: usize) -> CoverageReport {
        let mut new_blocks: Vec<CoveredBlock> = self.covered.values().cloned().collect();
        new_blocks.sort_by_key(|b| b.first_seen_run);
        new_blocks.truncate(max_new);

        CoverageReport {
            target: self.target.name.clone(),
            total_blocks: self.target.total_blocks,
            covered_blocks: self.covered_count(),
            coverage_pct: self.coverage_pct(),
            run_count: self.run_index,
            new_blocks,
            per_run_counts: self.per_run_counts.clone(),
        }
    }

    /// Reset all coverage (aggregate + per-run data).
    pub fn reset(&mut self) {
        self.aggregate = BlockCovBitmap::new(self.target.total_blocks);
        self.current_run = None;
        self.run_index = 0;
        self.covered.clear();
        self.per_run_counts.clear();
    }

    /// Return the set of covered block IDs.
    #[must_use] 
    pub fn covered_ids(&self) -> HashSet<BlockCovId> {
        self.aggregate.iter_set().collect()
    }

    /// Return the set of uncovered block IDs.
    pub fn uncovered_ids(&self) -> HashSet<BlockCovId> {
        (0..self.target.total_blocks)
            .map(BlockCovId)
            .filter(|id| !self.aggregate.test(*id))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// C-ABI shim for use from instrumented code
// ---------------------------------------------------------------------------

/// Thread-local slot count: how many block IDs are expected.
static GLOBAL_BLOCK_COUNT: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

/// A lock-free shared coverage array used by the C-ABI shim.
///
/// Each element is 0 (not hit) or 1 (hit).  Instrumentation code compiled
/// with `-fsanitize-coverage=trace-pc` will call [`block_cov_mark_c`].
static mut GLOBAL_COV_ARRAY: Vec<AtomicU8> = Vec::new();

/// Initialise the global coverage array for `count` blocks.
///
/// # Safety
/// Must be called before any instrumented code runs and before calling
/// [`block_cov_mark_c`].  Not thread-safe with concurrent calls to itself.
pub unsafe fn global_cov_init(count: u32) { unsafe {
    GLOBAL_BLOCK_COUNT.store(count, Ordering::SeqCst);
    GLOBAL_COV_ARRAY = (0..count).map(|_| AtomicU8::new(0)).collect();
}}

/// Mark block `id` as covered in the global coverage array.
///
/// # Safety
/// `global_cov_init` must have been called first.
pub unsafe fn block_cov_mark_c(id: u32) { unsafe {
    let count = GLOBAL_BLOCK_COUNT.load(Ordering::Relaxed);
    if id < count {
        GLOBAL_COV_ARRAY[id as usize].store(1, Ordering::Relaxed);
    }
}}

/// Drain the global coverage array into a [`BlockCovBitmap`].
///
/// # Safety
/// `global_cov_init` must have been called first.
pub unsafe fn drain_global_cov() -> BlockCovBitmap { unsafe {
    let count = GLOBAL_BLOCK_COUNT.load(Ordering::SeqCst);
    let mut bm = BlockCovBitmap::new(count);
    for i in 0..count {
        if GLOBAL_COV_ARRAY[i as usize].swap(0, Ordering::AcqRel) != 0 {
            bm.set(BlockCovId(i));
        }
    }
    bm
}}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target(n: u32) -> InstrumentedTarget {
        InstrumentedTarget::new("test_target", n)
    }

    #[test]
    fn test_bitmap_set_test() {
        let mut bm = BlockCovBitmap::new(64);
        bm.set(BlockCovId(0));
        bm.set(BlockCovId(7));
        bm.set(BlockCovId(63));
        assert!(bm.test(BlockCovId(0)));
        assert!(bm.test(BlockCovId(7)));
        assert!(bm.test(BlockCovId(63)));
        assert!(!bm.test(BlockCovId(1)));
        assert!(!bm.test(BlockCovId(64)));
    }

    #[test]
    fn test_bitmap_popcount() {
        let mut bm = BlockCovBitmap::new(100);
        for i in [0, 10, 20, 30, 40u32] {
            bm.set(BlockCovId(i));
        }
        assert_eq!(bm.popcount(), 5);
    }

    #[test]
    fn test_bitmap_merge_or() {
        let mut a = BlockCovBitmap::new(32);
        let mut b = BlockCovBitmap::new(32);
        a.set(BlockCovId(1));
        b.set(BlockCovId(2));
        a.merge_or(&b);
        assert!(a.test(BlockCovId(1)));
        assert!(a.test(BlockCovId(2)));
    }

    #[test]
    fn test_bitmap_new_in() {
        let mut base = BlockCovBitmap::new(32);
        base.set(BlockCovId(0));
        let mut run = BlockCovBitmap::new(32);
        run.set(BlockCovId(0));
        run.set(BlockCovId(5));
        let new = base.new_in(&run);
        assert!(!new.test(BlockCovId(0)));
        assert!(new.test(BlockCovId(5)));
    }

    #[test]
    fn test_bitmap_roundtrip() {
        let mut bm = BlockCovBitmap::new(128);
        bm.set(BlockCovId(15));
        bm.set(BlockCovId(127));
        let bytes = bm.to_bytes();
        let bm2 = BlockCovBitmap::from_bytes(&bytes).unwrap();
        assert!(bm2.test(BlockCovId(15)));
        assert!(bm2.test(BlockCovId(127)));
        assert_eq!(bm2.popcount(), 2);
    }

    #[test]
    fn test_tracker_run_lifecycle() {
        let mut tracker = BlockCoverageTracker::new(make_target(64));
        tracker.run_start();
        tracker.mark(BlockCovId(0));
        tracker.mark(BlockCovId(10));
        let new_cov = tracker.run_end().unwrap();
        assert_eq!(new_cov.popcount(), 2);
        assert_eq!(tracker.covered_count(), 2);
        assert_eq!(tracker.run_count(), 1);

        // Second run: one already seen, one new.
        tracker.run_start();
        tracker.mark(BlockCovId(0));
        tracker.mark(BlockCovId(20));
        let new_cov2 = tracker.run_end().unwrap();
        assert_eq!(new_cov2.popcount(), 1);
        assert!(new_cov2.test(BlockCovId(20)));
        assert_eq!(tracker.covered_count(), 3);
    }

    #[test]
    fn test_tracker_coverage_pct() {
        let mut tracker = BlockCoverageTracker::new(make_target(100));
        tracker.run_start();
        for i in 0..25 {
            tracker.mark(BlockCovId(i));
        }
        tracker.run_end();
        assert!((tracker.coverage_pct() - 25.0).abs() < 1e-9);
    }

    #[test]
    fn test_tracker_report() {
        let mut tracker = BlockCoverageTracker::new(make_target(50));
        tracker.run_start();
        tracker.mark(BlockCovId(3));
        tracker.mark(BlockCovId(7));
        tracker.run_end();
        let report = tracker.coverage_report(100);
        assert_eq!(report.covered_blocks, 2);
        assert_eq!(report.run_count, 1);
        assert!(!report.summary().is_empty());
    }

    #[test]
    fn test_tracker_reset() {
        let mut tracker = BlockCoverageTracker::new(make_target(32));
        tracker.run_start();
        tracker.mark(BlockCovId(1));
        tracker.run_end();
        tracker.reset();
        assert_eq!(tracker.covered_count(), 0);
        assert_eq!(tracker.run_count(), 0);
    }

    #[test]
    fn test_instrumented_target_coverage_pct() {
        let target = make_target(200);
        let mut covered = HashSet::new();
        for i in 0..50 {
            covered.insert(BlockCovId(i));
        }
        let pct = target.coverage_pct(&covered);
        assert!((pct - 25.0).abs() < 1e-9);
    }
}
