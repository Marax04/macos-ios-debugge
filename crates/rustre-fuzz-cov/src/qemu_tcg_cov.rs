//! `qemu_tcg_cov` — QEMU TCG-based coverage collection.
//!
//! Provides a stub QEMU plugin interface, TCG basic-block execution records,
//! AFL-style edge bitmaps, and snapshot-based fuzzing integration.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── TbExecRecord ──────────────────────────────────────────────────────────────

/// A Translation Block (TB) execution record from QEMU TCG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TbExecRecord {
    /// Program counter of the first instruction in the TB.
    pub pc: u64,
    /// Size of the TB in bytes.
    pub size: u32,
    /// Number of times this TB was executed.
    pub count: u64,
    /// Optional index in the AFL edge bitmap (XOR of pc and `prev_pc`).
    pub bitmap_idx: Option<usize>,
}

impl TbExecRecord {
    /// Create a new record with a single execution.
    #[must_use]
    pub const fn new(pc: u64, size: u32) -> Self {
        Self {
            pc,
            size,
            count: 1,
            bitmap_idx: None,
        }
    }

    /// Create with bitmap index.
    #[must_use]
    pub const fn with_bitmap(pc: u64, size: u32, idx: usize) -> Self {
        Self {
            pc,
            size,
            count: 1,
            bitmap_idx: Some(idx),
        }
    }

    /// End address (exclusive).
    #[must_use]
    pub fn end_pc(&self) -> u64 {
        self.pc + u64::from(self.size)
    }

    /// Increment the execution count by `n`.
    pub const fn add_count(&mut self, n: u64) {
        self.count = self.count.saturating_add(n);
    }
}

// ── QemuPlugin ───────────────────────────────────────────────────────────────

/// Stub interface for a QEMU TCG plugin.
///
/// In a real implementation this would register callbacks via `qemu_plugin_*`
/// C FFI functions. Here it simulates the plugin state in Rust.
pub struct QemuPlugin {
    /// Registered TB exec callback (simulated).
    pub tb_exec_enabled: bool,
    /// Registered mem access callback.
    pub mem_access_enabled: bool,
    /// Plugin name.
    pub name: String,
    /// Plugin version.
    pub version: u32,
}

impl QemuPlugin {
    /// Create a new plugin stub.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            tb_exec_enabled: false,
            mem_access_enabled: false,
            name: name.into(),
            version: 1,
        }
    }

    /// Enable the TB exec callback.
    pub const fn enable_tb_exec(&mut self) {
        self.tb_exec_enabled = true;
    }

    /// Enable memory-access callbacks.
    pub const fn enable_mem_access(&mut self) {
        self.mem_access_enabled = true;
    }

    /// Simulate receiving a TB-exec event.
    pub fn on_tb_exec(&self, collector: &mut QemuCovCollector, pc: u64, size: u32) {
        if self.tb_exec_enabled {
            collector.record_tb(pc, size);
        }
    }
}

// ── QemuCovCollector ──────────────────────────────────────────────────────────

/// Collects QEMU TCG coverage using an AFL-style edge bitmap.
pub struct QemuCovCollector {
    /// TB execution records keyed by PC.
    pub tb_records: HashMap<u64, TbExecRecord>,
    /// AFL-style edge bitmap (64 KB by default).
    pub bitmap: Vec<u8>,
    /// Previous TB PC (for edge computation).
    prev_pc: u64,
    /// Total number of TB executions recorded.
    pub total_executions: u64,
}

const BITMAP_SIZE: usize = 65_536;

impl QemuCovCollector {
    /// Create a new collector with a 64 KB bitmap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tb_records: HashMap::new(),
            bitmap: vec![0u8; BITMAP_SIZE],
            prev_pc: 0,
            total_executions: 0,
        }
    }

    /// Create with a custom bitmap size.
    #[must_use]
    pub fn with_bitmap_size(size: usize) -> Self {
        Self {
            tb_records: HashMap::new(),
            bitmap: vec![0u8; size],
            prev_pc: 0,
            total_executions: 0,
        }
    }

    /// Record a TB execution at `pc` with the given `size`.
    pub fn record_tb(&mut self, pc: u64, size: u32) {
        self.total_executions += 1;

        // AFL edge: (prev_pc >> 1) XOR pc, masked to bitmap length.
        let edge = crate::casts::u64_to_usize((self.prev_pc >> 1) ^ pc) % self.bitmap.len().max(1);
        self.bitmap[edge] = self.bitmap[edge].saturating_add(1);

        let rec = self
            .tb_records
            .entry(pc)
            .or_insert_with(|| TbExecRecord::new(pc, size));
        rec.add_count(1);
        if rec.bitmap_idx.is_none() {
            rec.bitmap_idx = Some(edge);
        }

        self.prev_pc = pc;
    }

    /// Reset the bitmap and previous PC (for snapshot-fuzzing: new iteration).
    pub fn reset_bitmap(&mut self) {
        self.bitmap.iter_mut().for_each(|b| *b = 0);
        self.prev_pc = 0;
    }

    /// Number of unique TBs observed.
    #[must_use]
    pub fn unique_tbs(&self) -> usize {
        self.tb_records.len()
    }

    /// Number of bitmap slots with at least one hit.
    #[must_use]
    pub fn bitmap_coverage(&self) -> usize {
        self.bitmap.iter().filter(|&&b| b > 0).count()
    }

    /// Bitmap density (0.0–1.0).
    #[must_use]
    pub fn bitmap_density(&self) -> f64 {
        if self.bitmap.is_empty() {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.bitmap_coverage()) / crate::casts::usize_to_f64(self.bitmap.len())
    }

    /// Merge another collector's data into this one (OR-merge the bitmap).
    pub fn merge(&mut self, other: &Self) {
        let len = self.bitmap.len().min(other.bitmap.len());
        for i in 0..len {
            self.bitmap[i] = self.bitmap[i].saturating_add(other.bitmap[i]);
        }
        for (&pc, rec) in &other.tb_records {
            let entry = self
                .tb_records
                .entry(pc)
                .or_insert_with(|| TbExecRecord::new(pc, rec.size));
            entry.add_count(rec.count);
        }
        self.total_executions += other.total_executions;
    }

    /// Compute the number of new bitmap slots gained from `other` vs this
    /// collector's current state.
    #[must_use]
    pub fn new_bits_from(&self, other: &Self) -> usize {
        let len = self.bitmap.len().min(other.bitmap.len());
        (0..len)
            .filter(|&i| other.bitmap[i] > 0 && self.bitmap[i] == 0)
            .count()
    }

    /// Return the top-N most-executed TBs.
    #[must_use]
    pub fn hot_tbs(&self, n: usize) -> Vec<&TbExecRecord> {
        let mut sorted: Vec<_> = self.tb_records.values().collect();
        // Total order, and here it decides membership rather than presentation:
        // `tb_records` is a `HashMap` (iteration order randomised per process),
        // `sort_by` is stable, and the `take(n)` below cuts the list. Ranking on
        // `count` alone therefore let equally-executed blocks straddle the
        // cutoff, so *which* translation blocks appeared in the top-N changed
        // between runs, not merely their order within it.
        sorted.sort_by(|a, b| b.count.cmp(&a.count).then(a.pc.cmp(&b.pc)));
        sorted.into_iter().take(n).collect()
    }
}

impl Default for QemuCovCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ── QemuCovReport ─────────────────────────────────────────────────────────────

/// A snapshot coverage report from a QEMU run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QemuCovReport {
    /// Total unique TBs seen.
    pub unique_tbs: usize,
    /// Total executions.
    pub total_executions: u64,
    /// Bitmap coverage (slots hit / total slots).
    pub bitmap_density: f64,
    /// Top-5 most-executed TBs by PC.
    pub hot_tbs: Vec<(u64, u64)>,
    /// Start timestamp (simulated nanoseconds).
    pub start_ns: u64,
    /// End timestamp (simulated nanoseconds).
    pub end_ns: u64,
}

impl QemuCovReport {
    /// Build a report from a collector.
    #[must_use]
    pub fn from_collector(col: &QemuCovCollector) -> Self {
        let hot: Vec<(u64, u64)> = col.hot_tbs(5).iter().map(|r| (r.pc, r.count)).collect();
        Self {
            unique_tbs: col.unique_tbs(),
            total_executions: col.total_executions,
            bitmap_density: col.bitmap_density(),
            hot_tbs: hot,
            start_ns: 0,
            end_ns: 0,
        }
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "tbs={} execs={} bitmap_density={:.4}",
            self.unique_tbs, self.total_executions, self.bitmap_density
        )
    }
}

// ── SnapshotFuzzSession ───────────────────────────────────────────────────────

/// Manages snapshot-based fuzzing with QEMU TCG coverage.
pub struct SnapshotFuzzSession {
    pub collector: QemuCovCollector,
    pub plugin: QemuPlugin,
    /// Accumulated bitmaps from previous iterations (for coverage guidance).
    global_bitmap: Vec<u8>,
    pub iteration: u64,
}

impl SnapshotFuzzSession {
    /// Create a new session.
    #[must_use]
    pub fn new() -> Self {
        let mut plugin = QemuPlugin::new("snapshot_fuzz");
        plugin.enable_tb_exec();
        Self {
            collector: QemuCovCollector::new(),
            plugin,
            global_bitmap: vec![0u8; BITMAP_SIZE],
            iteration: 0,
        }
    }

    /// Simulate one fuzzing iteration: reset bitmap, execute TBs, report new bits.
    pub fn run_iteration(&mut self, tb_trace: &[(u64, u32)]) -> usize {
        self.collector.reset_bitmap();

        for &(pc, size) in tb_trace {
            self.plugin.on_tb_exec(&mut self.collector, pc, size);
        }

        // Count new bits.
        let new_bits = {
            let bitmap = &self.collector.bitmap;
            let len = self.global_bitmap.len().min(bitmap.len());
            
            (0..len)
                .filter(|&i| bitmap[i] > 0 && self.global_bitmap[i] == 0)
                .count()
        };

        // Merge into global.
        let len = self.global_bitmap.len().min(self.collector.bitmap.len());
        for i in 0..len {
            self.global_bitmap[i] = self.global_bitmap[i].saturating_add(self.collector.bitmap[i]);
        }

        self.iteration += 1;
        new_bits
    }

    /// Total global bitmap coverage.
    #[must_use]
    pub fn global_coverage(&self) -> usize {
        self.global_bitmap.iter().filter(|&&b| b > 0).count()
    }

    /// Build a report for the current iteration.
    #[must_use]
    pub fn report(&self) -> QemuCovReport {
        QemuCovReport::from_collector(&self.collector)
    }
}

impl Default for SnapshotFuzzSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tb_exec_record_new() {
        let r = TbExecRecord::new(0x1000, 32);
        assert_eq!(r.pc, 0x1000);
        assert_eq!(r.size, 32);
        assert_eq!(r.count, 1);
        assert_eq!(r.end_pc(), 0x1020);
    }

    #[test]
    fn test_tb_exec_record_with_bitmap() {
        let r = TbExecRecord::with_bitmap(0x2000, 16, 42);
        assert_eq!(r.bitmap_idx, Some(42));
    }

    #[test]
    fn test_tb_exec_record_add_count() {
        let mut r = TbExecRecord::new(0, 4);
        r.add_count(5);
        assert_eq!(r.count, 6);
    }

    #[test]
    fn test_qemu_plugin_enable() {
        let mut p = QemuPlugin::new("test");
        assert!(!p.tb_exec_enabled);
        p.enable_tb_exec();
        assert!(p.tb_exec_enabled);
    }

    #[test]
    fn test_qemu_plugin_disabled_no_record() {
        let p = QemuPlugin::new("x");
        let mut col = QemuCovCollector::new();
        p.on_tb_exec(&mut col, 0x1000, 16);
        assert_eq!(col.unique_tbs(), 0);
    }

    #[test]
    fn test_qemu_plugin_enabled_records() {
        let mut p = QemuPlugin::new("x");
        p.enable_tb_exec();
        let mut col = QemuCovCollector::new();
        p.on_tb_exec(&mut col, 0x1000, 16);
        assert_eq!(col.unique_tbs(), 1);
    }

    #[test]
    fn test_collector_record_single_tb() {
        let mut col = QemuCovCollector::new();
        col.record_tb(0x1000, 16);
        assert_eq!(col.unique_tbs(), 1);
        assert_eq!(col.total_executions, 1);
    }

    #[test]
    fn test_collector_bitmap_coverage() {
        let mut col = QemuCovCollector::new();
        col.record_tb(0x1000, 4);
        assert!(col.bitmap_coverage() > 0);
    }

    #[test]
    fn test_collector_reset_bitmap() {
        let mut col = QemuCovCollector::new();
        col.record_tb(0x1000, 4);
        assert!(col.bitmap_coverage() > 0);
        col.reset_bitmap();
        assert_eq!(col.bitmap_coverage(), 0);
        // TB records should be preserved
        assert_eq!(col.unique_tbs(), 1);
    }

    #[test]
    fn test_collector_merge() {
        let mut a = QemuCovCollector::with_bitmap_size(256);
        let mut b = QemuCovCollector::with_bitmap_size(256);
        a.record_tb(0x100, 4);
        b.record_tb(0x200, 4);
        a.merge(&b);
        assert_eq!(a.unique_tbs(), 2);
    }

    #[test]
    fn test_collector_new_bits_from() {
        let a = QemuCovCollector::with_bitmap_size(256);
        let mut b = QemuCovCollector::with_bitmap_size(256);
        b.record_tb(0x100, 4); // sets some bitmap bits
        let new = a.new_bits_from(&b);
        assert!(new > 0);
    }

    #[test]
    fn test_collector_hot_tbs() {
        let mut col = QemuCovCollector::new();
        for i in 0..10u64 {
            for _ in 0..=i {
                col.record_tb(i * 0x100, 4);
            }
        }
        let hot = col.hot_tbs(3);
        assert_eq!(hot.len(), 3);
        assert!(hot[0].count >= hot[1].count);
    }

    #[test]
    fn test_collector_bitmap_density() {
        let mut col = QemuCovCollector::with_bitmap_size(100);
        col.record_tb(0x100, 4);
        assert!(col.bitmap_density() > 0.0);
        assert!(col.bitmap_density() <= 1.0);
    }

    #[test]
    fn test_qemu_cov_report_from_collector() {
        let mut col = QemuCovCollector::new();
        col.record_tb(0x1000, 8);
        col.record_tb(0x2000, 8);
        let rep = QemuCovReport::from_collector(&col);
        assert_eq!(rep.unique_tbs, 2);
        assert_eq!(rep.total_executions, 2);
    }

    #[test]
    fn test_qemu_cov_report_summary() {
        let col = QemuCovCollector::new();
        let rep = QemuCovReport::from_collector(&col);
        let s = rep.summary();
        assert!(s.contains("tbs="));
    }

    #[test]
    fn test_snapshot_session_iteration() {
        let mut sess = SnapshotFuzzSession::new();
        let trace = vec![(0x1000u64, 16u32), (0x2000, 8)];
        let new_bits = sess.run_iteration(&trace);
        assert!(new_bits > 0);
        assert_eq!(sess.iteration, 1);
    }

    #[test]
    fn test_snapshot_session_global_coverage() {
        let mut sess = SnapshotFuzzSession::new();
        sess.run_iteration(&[(0x1000, 4), (0x2000, 4)]);
        let cov = sess.global_coverage();
        assert!(cov > 0);
    }

    #[test]
    fn test_snapshot_session_second_iter_fewer_new_bits() {
        let mut sess = SnapshotFuzzSession::new();
        let trace = vec![(0x1000u64, 4u32)];
        let new1 = sess.run_iteration(&trace);
        let new2 = sess.run_iteration(&trace);
        // Second iteration over same trace → 0 new bits.
        assert!(new1 > 0);
        assert_eq!(new2, 0);
    }

    #[test]
    fn test_snapshot_session_report() {
        let mut sess = SnapshotFuzzSession::new();
        sess.run_iteration(&[(0x3000, 4)]);
        let rep = sess.report();
        assert!(rep.total_executions > 0);
    }

    #[test]
    fn test_collector_default() {
        let col = QemuCovCollector::default();
        assert_eq!(col.bitmap.len(), BITMAP_SIZE);
        assert_eq!(col.unique_tbs(), 0);
    }

    #[test]
    fn test_tb_record_saturation() {
        let mut r = TbExecRecord::new(0, 0);
        r.count = u64::MAX;
        r.add_count(1);
        assert_eq!(r.count, u64::MAX);
    }
}
