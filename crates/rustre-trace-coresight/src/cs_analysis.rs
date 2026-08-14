//! `CoreSight` / ETM analysis — function coverage from ETM, branch hotness,
//! and ETM timeline reconstruction.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CsAnalysisError {
    #[error("sync error: {0}")]
    SyncError(String),
    #[error("no trace data")]
    NoTraceData,
    #[error("function not found: 0x{0:08x}")]
    FunctionNotFound(u32),
    #[error("invalid atom packet byte 0x{0:02x}")]
    InvalidAtomPacket(u8),
}

// ─── ETM Coverage Block ───────────────────────────────────────────────────────

/// A basic block covered by ETM trace data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtmBlock {
    /// Start address.
    pub start: u32,
    /// End address (exclusive).
    pub end: u32,
    /// Hit count (merged from multiple trace runs).
    pub hit_count: u64,
    /// Whether this block contains a branch.
    pub has_branch: bool,
    /// Cycle count if available.
    pub cycles: Option<u32>,
}

impl EtmBlock {
    /// Create a new ETM block.
    #[must_use]
    pub const fn new(start: u32, end: u32) -> Self {
        Self {
            start,
            end,
            hit_count: 1,
            has_branch: false,
            cycles: None,
        }
    }

    /// Byte size.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.end.saturating_sub(self.start)
    }

    /// Merge another block's stats into this one.
    pub const fn merge(&mut self, other: &Self) {
        self.hit_count += other.hit_count;
    }
}

// ─── EtmCoverage ─────────────────────────────────────────────────────────────

/// Coverage data derived from ETM trace streams.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EtmCoverage {
    /// Basic blocks by start address.
    pub blocks: BTreeMap<u32, EtmBlock>,
    /// Total bytes covered.
    pub covered_bytes: u64,
    /// Total instructions executed.
    pub total_insns: u64,
}

impl EtmCoverage {
    /// Record a covered block.
    pub fn record_block(&mut self, start: u32, end: u32, cycles: Option<u32>) {
        let block = EtmBlock {
            start,
            end,
            hit_count: 1,
            has_branch: false,
            cycles,
        };
        if let Some(existing) = self.blocks.get_mut(&start) { existing.merge(&block) } else {
            self.covered_bytes += u64::from(block.size());
            self.blocks.insert(start, block);
        }
        self.total_insns += u64::from((end - start) / 4);
    }

    /// Number of distinct covered blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Whether a given address is covered.
    #[must_use]
    pub fn is_covered(&self, addr: u32) -> bool {
        self.blocks
            .range(..=addr)
            .next_back()
            .is_some_and(|(_, b)| addr >= b.start && addr < b.end)
    }
}

// ─── FunctionCoverage ─────────────────────────────────────────────────────────

/// ETM-derived coverage for a single function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionCoverage {
    pub func_addr: u32,
    pub func_size: u32,
    pub name: Option<String>,
    pub covered_bytes: u32,
    pub total_bytes: u32,
    pub covered_blocks: u32,
    pub total_blocks: u32,
    /// Number of times the function was entered.
    pub call_count: u64,
}

impl FunctionCoverage {
    /// Coverage percentage (0–100).
    #[must_use]
    pub fn coverage_pct(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        f64::from(self.covered_bytes) / f64::from(self.total_bytes) * 100.0
    }

    /// Whether function is fully covered.
    #[must_use]
    pub const fn is_fully_covered(&self) -> bool {
        self.covered_bytes >= self.total_bytes && self.total_bytes > 0
    }

    /// Whether function was completely uncovered.
    #[must_use]
    pub const fn is_uncovered(&self) -> bool {
        self.call_count == 0
    }
}

// ─── BranchHotness ───────────────────────────────────────────────────────────

/// Hotness information for a branch site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchHotness {
    pub branch_addr: u32,
    pub target_addr: u32,
    pub taken_count: u64,
    pub not_taken_count: u64,
}

impl BranchHotness {
    /// Taken ratio (0.0–1.0).
    #[must_use]
    pub fn taken_ratio(&self) -> f64 {
        let total = self.taken_count + self.not_taken_count;
        if total == 0 {
            0.0
        } else {
            {
                let ppm = u128::from(self.taken_count) * 1_000_000
                    / u128::from(total);
                f64::from(u32::try_from(ppm).unwrap_or(1_000_000)) * 1e-6
            }
        }
    }

    /// Total branch occurrences.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.taken_count + self.not_taken_count
    }

    /// Whether this branch is "hot" (total > threshold).
    #[must_use]
    pub const fn is_hot(&self, threshold: u64) -> bool {
        self.total() >= threshold
    }
}

// ─── EtmTimeline ─────────────────────────────────────────────────────────────

/// A single timeline event from ETM trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EtmEvent {
    /// PC reached this address.
    Pc(u32),
    /// Exception entry.
    Exception { number: u16 },
    /// Exception return.
    ExceptionReturn,
    /// Timestamp in nanoseconds.
    Timestamp(u64),
    /// Cycle count delta.
    CycleDelta(u32),
    /// Context ID change.
    ContextId(u32),
    /// Sync point.
    Sync,
}

/// Full ETM timeline of events.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct EtmTimeline {
    pub events: Vec<EtmEvent>,
    /// Total wall clock ns (if timestamps available).
    pub total_ns: u64,
    /// Number of exceptions captured.
    pub exception_count: u32,
}

impl EtmTimeline {
    /// Append an event.
    pub fn push(&mut self, ev: EtmEvent) {
        match &ev {
            EtmEvent::Timestamp(ns) => self.total_ns += ns,
            EtmEvent::Exception { .. } => self.exception_count += 1,
            _ => {}
        }
        self.events.push(ev);
    }

    /// All PC events.
    #[must_use]
    pub fn pc_events(&self) -> Vec<u32> {
        self.events
            .iter()
            .filter_map(|e| {
                if let EtmEvent::Pc(pc) = e {
                    Some(*pc)
                } else {
                    None
                }
            })
            .collect()
    }

    /// All exception events.
    #[must_use]
    pub fn exceptions(&self) -> Vec<u16> {
        self.events
            .iter()
            .filter_map(|e| {
                if let EtmEvent::Exception { number } = e {
                    Some(*number)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Unique PCs seen.
    #[must_use]
    pub fn unique_pcs(&self) -> HashSet<u32> {
        self.pc_events().into_iter().collect()
    }
}

// ─── CoreSightAnalysis ────────────────────────────────────────────────────────

/// Top-level CoreSight/ETM analysis object.
#[derive(Debug, Default)]
pub struct CoreSightAnalysis {
    pub coverage: EtmCoverage,
    pub timeline: EtmTimeline,
    /// Function coverage map: `func_addr` → `FunctionCoverage`.
    pub func_coverage: HashMap<u32, FunctionCoverage>,
    /// Branch hotness map: `branch_addr` → `BranchHotness`.
    pub branch_hotness: HashMap<u32, BranchHotness>,
}

impl CoreSightAnalysis {
    /// Create a new analysis context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record ETM coverage block.
    pub fn record_coverage(&mut self, start: u32, end: u32, cycles: Option<u32>) {
        self.coverage.record_block(start, end, cycles);
    }

    /// Record branch event.
    pub fn record_branch(&mut self, branch_addr: u32, target: u32, taken: bool) {
        let bh = self
            .branch_hotness
            .entry(branch_addr)
            .or_insert(BranchHotness {
                branch_addr,
                target_addr: target,
                taken_count: 0,
                not_taken_count: 0,
            });
        if taken {
            bh.taken_count += 1;
        } else {
            bh.not_taken_count += 1;
        }
    }

    /// Compute function coverage given function boundaries `(start, size, name)`.
    pub fn compute_function_coverage(&mut self, functions: &[(u32, u32, Option<String>)]) {
        for &(start, size, ref name) in functions {
            let end = start + size;
            // Single pass over the BTreeMap range — avoids three separate
            // tree traversals for covered_bytes / call_count / covered_blocks.
            let mut covered_bytes: u32 = 0;
            let mut call_count: u64 = 0;
            let mut covered_blocks: u32 = 0;
            for (_, b) in self.coverage.blocks.range(start..end) {
                let blk_start = b.start.max(start);
                let blk_end = b.end.min(end);
                covered_bytes = covered_bytes.saturating_add(blk_end.saturating_sub(blk_start));
                if b.hit_count > call_count {
                    call_count = b.hit_count;
                }
                covered_blocks += 1;
            }
            let fc = FunctionCoverage {
                func_addr: start,
                func_size: size,
                name: name.clone(),
                covered_bytes,
                total_bytes: size,
                covered_blocks,
                total_blocks: (size / 4).max(1),
                call_count,
            };
            self.func_coverage.insert(start, fc);
        }
    }

    /// Hot branches (taken ≥ threshold).
    #[must_use]
    pub fn hot_branches(&self, threshold: u64) -> Vec<&BranchHotness> {
        self.branch_hotness
            .values()
            .filter(|b| b.is_hot(threshold))
            .collect()
    }

    /// Fully covered functions.
    #[must_use]
    pub fn fully_covered_functions(&self) -> Vec<&FunctionCoverage> {
        self.func_coverage
            .values()
            .filter(|f| f.is_fully_covered())
            .collect()
    }

    /// Uncovered functions.
    #[must_use]
    pub fn uncovered_functions(&self) -> Vec<&FunctionCoverage> {
        self.func_coverage
            .values()
            .filter(|f| f.is_uncovered())
            .collect()
    }

    /// Overall coverage percentage.
    #[must_use]
    pub fn overall_coverage_pct(&self) -> f64 {
        if self.func_coverage.is_empty() {
            return 0.0;
        }
        let total_bytes: u32 = self.func_coverage.values().map(|f| f.total_bytes).sum();
        let covered: u32 = self.func_coverage.values().map(|f| f.covered_bytes).sum();
        if total_bytes == 0 {
            0.0
        } else {
            f64::from(covered) / f64::from(total_bytes) * 100.0
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EtmBlock ─────────────────────────────────────────────────────────────

    #[test]
    fn test_block_size() {
        let b = EtmBlock::new(0x1000, 0x1010);
        assert_eq!(b.size(), 0x10);
    }

    #[test]
    fn test_block_merge() {
        let mut a = EtmBlock::new(0x1000, 0x1010);
        let b = EtmBlock::new(0x1000, 0x1010);
        a.merge(&b);
        assert_eq!(a.hit_count, 2);
    }

    // ── EtmCoverage ──────────────────────────────────────────────────────────

    #[test]
    fn test_coverage_record_block() {
        let mut c = EtmCoverage::default();
        c.record_block(0x1000, 0x1010, None);
        assert_eq!(c.block_count(), 1);
    }

    #[test]
    fn test_coverage_is_covered() {
        let mut c = EtmCoverage::default();
        c.record_block(0x1000, 0x1010, None);
        assert!(c.is_covered(0x1008));
        assert!(!c.is_covered(0x2000));
    }

    #[test]
    fn test_coverage_merge_increases_hit_count() {
        let mut c = EtmCoverage::default();
        c.record_block(0x1000, 0x1010, None);
        c.record_block(0x1000, 0x1010, None);
        assert_eq!(c.blocks[&0x1000].hit_count, 2);
    }

    #[test]
    fn test_coverage_covered_bytes() {
        let mut c = EtmCoverage::default();
        c.record_block(0x1000, 0x1020, None);
        assert_eq!(c.covered_bytes, 0x20);
    }

    // ── FunctionCoverage ─────────────────────────────────────────────────────

    #[test]
    fn test_func_coverage_pct() {
        let fc = FunctionCoverage {
            func_addr: 0,
            func_size: 100,
            name: None,
            covered_bytes: 50,
            total_bytes: 100,
            covered_blocks: 2,
            total_blocks: 4,
            call_count: 1,
        };
        assert!((fc.coverage_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_func_fully_covered() {
        let fc = FunctionCoverage {
            func_addr: 0,
            func_size: 100,
            name: None,
            covered_bytes: 100,
            total_bytes: 100,
            covered_blocks: 4,
            total_blocks: 4,
            call_count: 5,
        };
        assert!(fc.is_fully_covered());
    }

    #[test]
    fn test_func_uncovered() {
        let fc = FunctionCoverage {
            func_addr: 0,
            func_size: 100,
            name: None,
            covered_bytes: 0,
            total_bytes: 100,
            covered_blocks: 0,
            total_blocks: 4,
            call_count: 0,
        };
        assert!(fc.is_uncovered());
    }

    // ── BranchHotness ────────────────────────────────────────────────────────

    #[test]
    fn test_branch_taken_ratio() {
        let b = BranchHotness {
            branch_addr: 0,
            target_addr: 0,
            taken_count: 3,
            not_taken_count: 1,
        };
        assert!((b.taken_ratio() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_branch_is_hot() {
        let b = BranchHotness {
            branch_addr: 0,
            target_addr: 0,
            taken_count: 100,
            not_taken_count: 100,
        };
        assert!(b.is_hot(50));
        assert!(!b.is_hot(1000));
    }

    #[test]
    fn test_branch_total() {
        let b = BranchHotness {
            branch_addr: 0,
            target_addr: 0,
            taken_count: 7,
            not_taken_count: 3,
        };
        assert_eq!(b.total(), 10);
    }

    // ── EtmTimeline ──────────────────────────────────────────────────────────

    #[test]
    fn test_timeline_pc_events() {
        let mut t = EtmTimeline::default();
        t.push(EtmEvent::Pc(0x1000));
        t.push(EtmEvent::Sync);
        t.push(EtmEvent::Pc(0x2000));
        let pcs = t.pc_events();
        assert_eq!(pcs, vec![0x1000, 0x2000]);
    }

    #[test]
    fn test_timeline_exceptions() {
        let mut t = EtmTimeline::default();
        t.push(EtmEvent::Exception { number: 15 });
        t.push(EtmEvent::ExceptionReturn);
        assert_eq!(t.exception_count, 1);
        assert_eq!(t.exceptions(), vec![15]);
    }

    #[test]
    fn test_timeline_total_ns() {
        let mut t = EtmTimeline::default();
        t.push(EtmEvent::Timestamp(1000));
        t.push(EtmEvent::Timestamp(500));
        assert_eq!(t.total_ns, 1500);
    }

    #[test]
    fn test_timeline_unique_pcs() {
        let mut t = EtmTimeline::default();
        t.push(EtmEvent::Pc(0x1000));
        t.push(EtmEvent::Pc(0x1000));
        t.push(EtmEvent::Pc(0x2000));
        assert_eq!(t.unique_pcs().len(), 2);
    }

    // ── CoreSightAnalysis ────────────────────────────────────────────────────

    #[test]
    fn test_analysis_record_coverage() {
        let mut a = CoreSightAnalysis::new();
        a.record_coverage(0x1000, 0x1010, None);
        assert_eq!(a.coverage.block_count(), 1);
    }

    #[test]
    fn test_analysis_record_branch() {
        let mut a = CoreSightAnalysis::new();
        a.record_branch(0x1000, 0x2000, true);
        a.record_branch(0x1000, 0x2000, false);
        let bh = &a.branch_hotness[&0x1000];
        assert_eq!(bh.taken_count, 1);
        assert_eq!(bh.not_taken_count, 1);
    }

    #[test]
    fn test_analysis_function_coverage() {
        let mut a = CoreSightAnalysis::new();
        a.record_coverage(0x1000, 0x1010, None);
        a.record_coverage(0x1010, 0x1020, None);
        a.compute_function_coverage(&[(0x1000, 0x20, Some("func_a".into()))]);
        let fc = &a.func_coverage[&0x1000];
        assert_eq!(fc.total_bytes, 0x20);
        assert!(fc.covered_bytes > 0);
    }

    #[test]
    fn test_analysis_fully_covered() {
        let mut a = CoreSightAnalysis::new();
        a.record_coverage(0x1000, 0x1020, Some(50));
        a.compute_function_coverage(&[(0x1000, 0x20, None)]);
        assert!(!a.fully_covered_functions().is_empty());
    }

    #[test]
    fn test_analysis_uncovered_function() {
        let mut a = CoreSightAnalysis::new();
        a.compute_function_coverage(&[(0x5000, 0x100, Some("uncovered".into()))]);
        assert!(!a.uncovered_functions().is_empty());
    }

    #[test]
    fn test_analysis_hot_branches() {
        let mut a = CoreSightAnalysis::new();
        for _ in 0..100 {
            a.record_branch(0x1000, 0x2000, true);
        }
        a.record_branch(0x3000, 0x4000, true);
        let hot = a.hot_branches(50);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].branch_addr, 0x1000);
    }

    // ── Additional coverage ─────────────────────────────────────────────────

    #[test]
    fn test_coverage_total_insns() {
        let mut c = EtmCoverage::default();
        c.record_block(0x1000, 0x1010, None); // 4 insns (0x10/4)
        assert_eq!(c.total_insns, 4);
    }

    #[test]
    fn test_etm_timeline_cycle_delta() {
        let mut t = EtmTimeline::default();
        t.push(EtmEvent::CycleDelta(50));
        assert_eq!(t.events.len(), 1);
    }

    #[test]
    fn test_branch_hotness_zero_total() {
        let b = BranchHotness {
            branch_addr: 0,
            target_addr: 0,
            taken_count: 0,
            not_taken_count: 0,
        };
        assert_eq!(b.taken_ratio(), 0.0);
    }

    #[test]
    fn test_function_coverage_zero_total() {
        let fc = FunctionCoverage::default();
        assert_eq!(fc.coverage_pct(), 0.0);
    }

    #[test]
    fn test_analysis_overall_coverage_pct_zero() {
        let a = CoreSightAnalysis::new();
        assert_eq!(a.overall_coverage_pct(), 0.0);
    }

    #[test]
    fn test_coverage_block_with_cycles() {
        let mut c = EtmCoverage::default();
        c.record_block(0x1000, 0x1010, Some(100));
        assert_eq!(c.blocks[&0x1000].cycles, Some(100));
    }

    #[test]
    fn test_analysis_overall_coverage_non_zero() {
        let mut a = CoreSightAnalysis::new();
        a.record_coverage(0x1000, 0x1020, None);
        a.compute_function_coverage(&[(0x1000, 0x20, None)]);
        assert!(a.overall_coverage_pct() > 0.0);
    }

    #[test]
    fn test_etm_timeline_exception_return() {
        let mut t = EtmTimeline::default();
        t.push(EtmEvent::ExceptionReturn);
        // exception_count should NOT increase for ExceptionReturn.
        assert_eq!(t.exception_count, 0);
    }
}
