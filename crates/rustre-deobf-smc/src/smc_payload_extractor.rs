/// SMC payload extractor: reconstruct the final executable memory state from write traces.
///
/// This module applies recorded write events to a flat memory model, resolves overlapping
/// patches, identifies contiguous executable regions, and returns `ReconstructedCode` structs
/// ready for disassembly or further analysis.
use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtractorError {
    #[error("address {0:#x} overflows address space")]
    AddressOverflow(u64),
    #[error("no write events recorded")]
    NoEvents,
    #[error("region at {base:#x}+{size} exceeds maximum allowed size {max}")]
    RegionTooLarge { base: u64, size: usize, max: usize },
    #[error("conflicting patches at address {0:#x}: values {1:#x} and {2:#x}")]
    ConflictingPatch(u64, u8, u8),
}

// ---------------------------------------------------------------------------
// WritePatch — a single byte-level write to the memory model
// ---------------------------------------------------------------------------

/// A single byte-level write captured during SMC analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WritePatch {
    /// Address of the byte being written.
    pub addr: u64,
    /// Value written.
    pub value: u8,
    /// Program counter that performed the write.
    pub write_pc: u64,
    /// Logical timestamp (e.g. instruction count).
    pub timestamp: u64,
}

impl WritePatch {
    #[must_use] 
    pub const fn new(addr: u64, value: u8, write_pc: u64, timestamp: u64) -> Self {
        Self { addr, value, write_pc, timestamp }
    }
}

// ---------------------------------------------------------------------------
// MemorySnapshot — address → (latest_value, latest_timestamp)
// ---------------------------------------------------------------------------

/// Flat memory model built by applying write patches in timestamp order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Sorted map from address to (value, timestamp).
    cells: BTreeMap<u64, (u8, u64)>,
}

impl MemorySnapshot {
    #[must_use] 
    pub const fn new() -> Self {
        Self { cells: BTreeMap::new() }
    }

    /// Apply a patch. Later timestamps win; equal timestamps cause a conflict error
    /// only when the values differ.
    ///
    /// # Errors
    /// Returns [`ExtractorError::ConflictingPatch`] if two writes at the same timestamp disagree.
    pub fn apply(&mut self, patch: &WritePatch) -> Result<(), ExtractorError> {
        match self.cells.get(&patch.addr) {
            Some(&(existing_val, existing_ts)) => {
                if patch.timestamp > existing_ts {
                    self.cells.insert(patch.addr, (patch.value, patch.timestamp));
                } else if patch.timestamp == existing_ts && existing_val != patch.value {
                    return Err(ExtractorError::ConflictingPatch(
                        patch.addr,
                        existing_val,
                        patch.value,
                    ));
                }
                // earlier or equal-timestamp with same value → no-op
            }
            None => {
                self.cells.insert(patch.addr, (patch.value, patch.timestamp));
            }
        }
        Ok(())
    }

    /// Read a byte. Returns `None` if never written.
    #[must_use] 
    pub fn read(&self, addr: u64) -> Option<u8> {
        self.cells.get(&addr).map(|&(v, _)| v)
    }

    /// Number of cells written.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Iterate over (addr, value) pairs in address order.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.cells.iter().map(|(&a, &(v, _))| (a, v))
    }

    /// Collect all addresses that have been written.
    #[must_use] 
    pub fn written_addresses(&self) -> Vec<u64> {
        self.cells.keys().copied().collect()
    }

    /// Extract a contiguous byte slice starting at `base` of length `len`.
    /// Unwritten bytes within the range are filled with `fill`.
    #[must_use] 
    pub fn extract_range(&self, base: u64, len: usize, fill: u8) -> Vec<u8> {
        let mut out = vec![fill; len];
        for (i, cell) in out.iter_mut().enumerate() {
            let addr = base.wrapping_add(u64::try_from(i).unwrap_or(u64::MAX));
            if let Some(v) = self.cells.get(&addr).map(|&(v, _)| v) {
                *cell = v;
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// ReconstructedRegion — a contiguous block of reconstructed bytes
// ---------------------------------------------------------------------------

/// A contiguous reconstructed code/data region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedRegion {
    /// Base address of the region.
    pub base: u64,
    /// Reconstructed bytes (may contain fill bytes for gaps).
    pub bytes: Vec<u8>,
    /// Number of bytes that were actually written (non-fill).
    pub written_count: usize,
    /// Coverage ratio: `written_count / bytes.len()`.
    pub coverage: f64,
    /// Whether this region was also executed.
    pub was_executed: bool,
}

impl ReconstructedRegion {
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Byte at offset `off` from the base.
    #[must_use] 
    pub fn byte_at(&self, off: usize) -> Option<u8> {
        self.bytes.get(off).copied()
    }

    /// End address (exclusive).
    #[must_use] 
    pub const fn end(&self) -> u64 {
        self.base.wrapping_add(self.bytes.len() as u64)
    }
}

// ---------------------------------------------------------------------------
// ReconstructedCode — top-level result returned by the extractor
// ---------------------------------------------------------------------------

/// Complete reconstruction result from a set of write events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedCode {
    /// Individual contiguous regions.
    pub regions: Vec<ReconstructedRegion>,
    /// Total bytes written across all regions.
    pub total_written: usize,
    /// Total bytes spanned (written + fill) across all regions.
    pub total_spanned: usize,
    /// Number of write patches applied.
    pub patch_count: usize,
    /// Number of distinct write PCs observed.
    pub distinct_write_pcs: usize,
}

impl ReconstructedCode {
    /// Find the region containing `addr`, if any.
    #[must_use] 
    pub fn region_containing(&self, addr: u64) -> Option<&ReconstructedRegion> {
        self.regions.iter().find(|r| addr >= r.base && addr < r.end())
    }

    /// Read a byte from any region.
    #[must_use] 
    pub fn read_byte(&self, addr: u64) -> Option<u8> {
        let region = self.region_containing(addr)?;
        let off = usize::try_from(addr - region.base).unwrap_or(usize::MAX);
        region.bytes.get(off).copied()
    }

    /// Collect all executed regions.
    #[must_use] 
    pub fn executed_regions(&self) -> Vec<&ReconstructedRegion> {
        self.regions.iter().filter(|r| r.was_executed).collect()
    }
}

// ---------------------------------------------------------------------------
// ExtractorConfig
// ---------------------------------------------------------------------------

/// Configuration for `SmcPayloadExtractor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractorConfig {
    /// Maximum number of bytes per reconstructed region. Prevents OOM on bad data.
    pub max_region_bytes: usize,
    /// Gap threshold: addresses farther apart than this start a new region.
    pub gap_threshold: u64,
    /// Fill byte used for gaps within a region.
    pub fill_byte: u8,
    /// If `true`, conflict errors are demoted to warnings and the later write wins.
    pub ignore_conflicts: bool,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            max_region_bytes: 16 * 1024 * 1024, // 16 MiB
            gap_threshold: 64,
            fill_byte: 0xCC, // INT3 — visually obvious in disassembly
            ignore_conflicts: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ExtractorStats
// ---------------------------------------------------------------------------

/// Runtime statistics from an extraction run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractorStats {
    pub patches_applied: u64,
    pub patches_skipped_older: u64,
    pub conflicts_detected: u64,
    pub regions_produced: u64,
    pub executed_regions: u64,
    pub fill_bytes_inserted: u64,
}

// ---------------------------------------------------------------------------
// SmcPayloadExtractor — main engine
// ---------------------------------------------------------------------------

/// Reconstructs the final memory state from an ordered list of write patches.
///
/// Usage:
/// ```rust,ignore
/// let mut ext = SmcPayloadExtractor::new(ExtractorConfig::default());
/// for patch in patches { ext.add_patch(patch)?; }
/// ext.mark_executed(0xdeadbeef);
/// let code = ext.reconstruct()?;
/// ```
pub struct SmcPayloadExtractor {
    config: ExtractorConfig,
    snapshot: MemorySnapshot,
    executed_addrs: Vec<u64>,
    stats: ExtractorStats,
    write_pcs: HashMap<u64, u64>, // pc → call count
}

impl SmcPayloadExtractor {
    #[must_use] 
    pub fn new(config: ExtractorConfig) -> Self {
        Self {
            config,
            snapshot: MemorySnapshot::new(),
            executed_addrs: Vec::new(),
            stats: ExtractorStats::default(),
            write_pcs: HashMap::new(),
        }
    }

    /// Add a write patch to the memory model.
    ///
    /// # Errors
    /// Returns [`ExtractorError::ConflictingPatch`] if two writes at the same timestamp conflict
    /// and `config.ignore_conflicts` is false.
    pub fn add_patch(&mut self, patch: &WritePatch) -> Result<(), ExtractorError> {
        *self.write_pcs.entry(patch.write_pc).or_insert(0) += 1;
        match self.snapshot.apply(patch) {
            Ok(()) => {
                self.stats.patches_applied += 1;
            }
            Err(ExtractorError::ConflictingPatch(addr, v1, v2)) => {
                self.stats.conflicts_detected += 1;
                if self.config.ignore_conflicts {
                    // later write wins — force insert
                    self.snapshot
                        .cells
                        .insert(addr, (v2, patch.timestamp));
                } else {
                    return Err(ExtractorError::ConflictingPatch(addr, v1, v2));
                }
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Bulk-add patches from an iterator.
    ///
    /// # Errors
    /// Returns an error if any individual patch fails (see [`Self::add_patch`]).
    pub fn add_patches<I>(&mut self, patches: I) -> Result<(), ExtractorError>
    where
        I: IntoIterator<Item = WritePatch>,
    {
        for p in patches {
            self.add_patch(&p)?;
        }
        Ok(())
    }

    /// Record that a given address was executed (used to mark reconstructed regions).
    pub fn mark_executed(&mut self, addr: u64) {
        self.executed_addrs.push(addr);
    }

    /// Record a batch of executed addresses.
    pub fn mark_executed_batch(&mut self, addrs: &[u64]) {
        self.executed_addrs.extend_from_slice(addrs);
    }

    /// Access the underlying memory snapshot directly.
    #[must_use] 
    pub const fn snapshot(&self) -> &MemorySnapshot {
        &self.snapshot
    }

    /// Runtime statistics.
    #[must_use] 
    pub const fn stats(&self) -> &ExtractorStats {
        &self.stats
    }

    /// Number of distinct write PCs observed.
    #[must_use] 
    pub fn distinct_write_pcs(&self) -> usize {
        self.write_pcs.len()
    }

    /// Reconstruct all contiguous regions from the current memory snapshot.
    ///
    /// # Errors
    /// Returns [`ExtractorError::NoEvents`] if no patches have been applied.
    pub fn reconstruct(&mut self) -> Result<ReconstructedCode, ExtractorError> {
        if self.snapshot.is_empty() {
            return Err(ExtractorError::NoEvents);
        }

        // Build an executed address set for fast lookup.
        let executed_set: std::collections::HashSet<u64> =
            self.executed_addrs.iter().copied().collect();

        // Group addresses into contiguous regions.
        let addresses = self.snapshot.written_addresses(); // sorted ascending

        let mut region_ranges: Vec<(u64, u64)> = Vec::new(); // (base, end_exclusive)
        let mut current_base = addresses[0];
        let mut current_end = addresses[0] + 1;

        for &addr in &addresses[1..] {
            if addr.saturating_sub(current_end) > self.config.gap_threshold {
                region_ranges.push((current_base, current_end));
                current_base = addr;
            }
            current_end = addr + 1;
        }
        region_ranges.push((current_base, current_end));

        // Build each region.
        let mut regions = Vec::with_capacity(region_ranges.len());
        let mut total_written = 0usize;
        let mut total_spanned = 0usize;
        let mut executed_region_count = 0u64;

        for (base, end) in region_ranges {
            let size = usize::try_from(end - base).unwrap_or(usize::MAX);
            if size > self.config.max_region_bytes {
                return Err(ExtractorError::RegionTooLarge {
                    base,
                    size,
                    max: self.config.max_region_bytes,
                });
            }

            let bytes =
                self.snapshot.extract_range(base, size, self.config.fill_byte);

            // Count actually-written bytes.
            let written_count = (0..size)
                .filter(|&i| {
                    self.snapshot
                        .cells
                        .contains_key(&base.wrapping_add(u64::try_from(i).unwrap_or(u64::MAX)))
                })
                .count();

            let fill_count = size - written_count;
            self.stats.fill_bytes_inserted += u64::try_from(fill_count).unwrap_or(u64::MAX);

            // Check if any executed address falls within this region.
            let was_executed = executed_set.iter().any(|&ea| ea >= base && ea < end);
            if was_executed {
                executed_region_count += 1;
            }

            let coverage = if size == 0 { 0.0 } else { f64::from(u32::try_from(written_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(size).unwrap_or(u32::MAX)) };

            regions.push(ReconstructedRegion {
                base,
                bytes,
                written_count,
                coverage,
                was_executed,
            });

            total_written += written_count;
            total_spanned += size;
        }

        self.stats.regions_produced += u64::try_from(regions.len()).unwrap_or(u64::MAX);
        self.stats.executed_regions += executed_region_count;

        Ok(ReconstructedCode {
            regions,
            total_written,
            total_spanned,
            patch_count: usize::try_from(self.stats.patches_applied).unwrap_or(usize::MAX),
            distinct_write_pcs: self.write_pcs.len(),
        })
    }

    /// Reset the extractor, clearing all patches and executed addresses.
    pub fn clear(&mut self) {
        self.snapshot = MemorySnapshot::new();
        self.executed_addrs.clear();
        self.write_pcs.clear();
        self.stats = ExtractorStats::default();
    }

    /// Convenience: build an extractor from a slice of `(addr, value, write_pc, ts)` tuples.
    ///
    /// # Errors
    /// Returns an error if any patch application fails (see [`Self::add_patch`]).
    pub fn from_tuples(
        tuples: &[(u64, u8, u64, u64)],
        config: ExtractorConfig,
    ) -> Result<Self, ExtractorError> {
        let mut ext = Self::new(config);
        for &(addr, value, write_pc, ts) in tuples {
            ext.add_patch(&WritePatch::new(addr, value, write_pc, ts))?;
        }
        Ok(ext)
    }
}

// ---------------------------------------------------------------------------
// Region merger — merge two ReconstructedCode results (e.g. from two passes)
// ---------------------------------------------------------------------------

/// Merge two `ReconstructedCode` results into one, resolving overlaps by taking
/// the later-addressed byte from `b` when both `a` and `b` cover the same range.
#[must_use] 
pub fn merge_reconstructed(
    mut a: ReconstructedCode,
    b: ReconstructedCode,
) -> ReconstructedCode {
    // Build a combined snapshot from `a`, then overwrite with `b`.
    let mut snap = MemorySnapshot::new();
    let mut ts = 0u64;

    for region in &a.regions {
        for (i, &byte) in region.bytes.iter().enumerate() {
            let addr = region.base.wrapping_add(i as u64);
            let _ = snap.apply(&WritePatch::new(addr, byte, 0, ts));
            ts += 1;
        }
    }
    for region in &b.regions {
        for (i, &byte) in region.bytes.iter().enumerate() {
            let addr = region.base.wrapping_add(i as u64);
            let _ = snap.apply(&WritePatch::new(addr, byte, 1, ts));
            ts += 1;
        }
    }

    // Build a temporary extractor to reconstruct from merged snapshot.
    let mut ext = SmcPayloadExtractor::new(ExtractorConfig::default());
    ext.snapshot = snap;

    // Combine executed_addrs from both.
    let executed: Vec<u64> = a
        .regions
        .iter()
        .filter(|r| r.was_executed)
        .map(|r| r.base)
        .chain(
            b.regions
                .iter()
                .filter(|r| r.was_executed)
                .map(|r| r.base),
        )
        .collect();
    ext.mark_executed_batch(&executed);

    ext.reconstruct().unwrap_or_else(|_| {
        a.regions.extend(b.regions);
        a
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn p(addr: u64, value: u8, ts: u64) -> WritePatch {
        WritePatch::new(addr, value, 0x1000, ts)
    }

    #[test]
    fn test_memory_snapshot_apply_latest_wins() {
        let mut snap = MemorySnapshot::new();
        snap.apply(&p(0x100, 0xAA, 1)).unwrap();
        snap.apply(&p(0x100, 0xBB, 2)).unwrap();
        snap.apply(&p(0x100, 0xCC, 1)).unwrap(); // older → ignored
        assert_eq!(snap.read(0x100), Some(0xBB));
    }

    #[test]
    fn test_memory_snapshot_conflict() {
        let mut snap = MemorySnapshot::new();
        snap.apply(&p(0x200, 0x11, 5)).unwrap();
        let err = snap.apply(&WritePatch::new(0x200, 0x22, 0x2000, 5));
        assert!(matches!(err, Err(ExtractorError::ConflictingPatch(0x200, 0x11, 0x22))));
    }

    #[test]
    fn test_extract_range_with_fill() {
        let mut snap = MemorySnapshot::new();
        snap.apply(&p(0x300, 0xDE, 1)).unwrap();
        snap.apply(&p(0x302, 0xAD, 2)).unwrap();
        let bytes = snap.extract_range(0x300, 4, 0xFF);
        assert_eq!(bytes, vec![0xDE, 0xFF, 0xAD, 0xFF]);
    }

    #[test]
    fn test_reconstruct_single_region() {
        let patches = vec![
            p(0x1000, 0x55, 1),
            p(0x1001, 0x89, 2),
            p(0x1002, 0xE5, 3),
        ];
        let mut ext = SmcPayloadExtractor::new(ExtractorConfig::default());
        ext.add_patches(patches).unwrap();
        ext.mark_executed(0x1000);
        let code = ext.reconstruct().unwrap();
        assert_eq!(code.regions.len(), 1);
        assert_eq!(code.regions[0].base, 0x1000);
        assert_eq!(code.regions[0].bytes, vec![0x55, 0x89, 0xE5]);
        assert!(code.regions[0].was_executed);
    }

    #[test]
    fn test_reconstruct_multiple_regions() {
        let mut patches = Vec::new();
        for i in 0u64..4 {
            patches.push(p(0x1000 + i, i as u8, i + 1));
        }
        // Gap of 200 bytes → new region
        for i in 0u64..4 {
            patches.push(p(0x1100 + i, (0x10 + i) as u8, 10 + i));
        }
        let mut ext = SmcPayloadExtractor::new(ExtractorConfig::default());
        ext.add_patches(patches).unwrap();
        let code = ext.reconstruct().unwrap();
        assert_eq!(code.regions.len(), 2);
        assert_eq!(code.regions[0].base, 0x1000);
        assert_eq!(code.regions[1].base, 0x1100);
    }

    #[test]
    fn test_no_events_error() {
        let mut ext = SmcPayloadExtractor::new(ExtractorConfig::default());
        assert!(matches!(ext.reconstruct(), Err(ExtractorError::NoEvents)));
    }

    #[test]
    fn test_ignore_conflicts_flag() {
        let mut config = ExtractorConfig::default();
        config.ignore_conflicts = true;
        let mut ext = SmcPayloadExtractor::new(config);
        ext.add_patch(&WritePatch::new(0x500, 0xAA, 0, 7)).unwrap();
        ext.add_patch(&WritePatch::new(0x500, 0xBB, 0, 7)).unwrap(); // same ts, diff value
        // should succeed — later wins by insert order
        let code = ext.reconstruct().unwrap();
        assert_eq!(code.read_byte(0x500), Some(0xBB));
    }

    #[test]
    fn test_coverage_ratio() {
        let mut ext = SmcPayloadExtractor::new(ExtractorConfig::default());
        // Write bytes 0,2,4 in a range 0..5 → 3/5 coverage after gap fill
        ext.add_patch(&p(0x600, 0x01, 1)).unwrap();
        ext.add_patch(&p(0x602, 0x02, 2)).unwrap();
        ext.add_patch(&p(0x604, 0x03, 3)).unwrap();
        let code = ext.reconstruct().unwrap();
        assert_eq!(code.regions.len(), 1);
        let r = &code.regions[0];
        assert_eq!(r.written_count, 3);
        let size = r.len();
        assert_eq!(size, 5);
        assert!((r.coverage - 0.6).abs() < 1e-9);
    }

    #[test]
    fn test_merge_reconstructed() {
        let mut ext_a = SmcPayloadExtractor::new(ExtractorConfig::default());
        ext_a.add_patch(&p(0x700, 0x11, 1)).unwrap();
        ext_a.add_patch(&p(0x701, 0x22, 2)).unwrap();
        let code_a = ext_a.reconstruct().unwrap();

        let mut ext_b = SmcPayloadExtractor::new(ExtractorConfig::default());
        ext_b.add_patch(&p(0x702, 0x33, 3)).unwrap();
        ext_b.add_patch(&p(0x703, 0x44, 4)).unwrap();
        let code_b = ext_b.reconstruct().unwrap();

        let merged = merge_reconstructed(code_a, code_b);
        // All four bytes should be in a single region if gap is within threshold
        let total: usize = merged.regions.iter().map(|r| r.written_count).sum();
        assert_eq!(total, 4);
    }

    #[test]
    fn test_from_tuples() {
        let tuples: Vec<(u64, u8, u64, u64)> = vec![
            (0x800, 0xAB, 0x1000, 1),
            (0x801, 0xCD, 0x1000, 2),
        ];
        let mut ext =
            SmcPayloadExtractor::from_tuples(&tuples, ExtractorConfig::default()).unwrap();
        let code = ext.reconstruct().unwrap();
        assert_eq!(code.read_byte(0x800), Some(0xAB));
        assert_eq!(code.read_byte(0x801), Some(0xCD));
    }

    #[test]
    fn test_executed_regions_filter() {
        let mut ext = SmcPayloadExtractor::new(ExtractorConfig::default());
        ext.add_patch(&p(0x900, 0x90, 1)).unwrap();
        ext.add_patch(&p(0xB00, 0x90, 2)).unwrap();
        ext.mark_executed(0x900);
        let code = ext.reconstruct().unwrap();
        let exec = code.executed_regions();
        assert_eq!(exec.len(), 1);
        assert_eq!(exec[0].base, 0x900);
    }
}
