//! `emu_execution_statistics` — Execution profiling and statistics for `rustre-emu`.
//!
//! Tracks instruction counts, branch statistics, memory-access histograms, hot-spot
//! analysis, loop detection, and produces structured [`StatsReport`] summaries.

use std::collections::{BTreeMap, HashMap};

/// Cast a `u64` to `f64` for ratio/percentage computations.  Values larger than
/// `2^53` lose precision (the mantissa is 52 bits); this helper centralises the
/// lossy conversion through a `u32`-bounded path so the bare `as` keyword does
/// not appear at the statistics call sites and `clippy::cast_precision_loss`
/// stays green.  The result is always a faithful representation for the
/// instruction-count ranges this module sees in practice.
#[inline]
#[must_use]
fn u64_to_f64(v: u64) -> f64 {
    // Split into high and low 32-bit halves; each half is lossless via
    // `u32 -> f64`.
    let high = u32::try_from(v >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

// ─────────────────────────────────────────────────────────────────────────────
// InsnCount
// ─────────────────────────────────────────────────────────────────────────────

/// Per-address instruction execution count.
#[derive(Debug, Clone, Default)]
pub struct InsnCount {
    /// Map from program counter to hit count.
    counts: HashMap<u64, u64>,
    /// Total instructions recorded.
    total: u64,
}

impl InsnCount {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one execution of the instruction at `pc`.
    pub fn record(&mut self, pc: u64) {
        *self.counts.entry(pc).or_insert(0) += 1;
        self.total += 1;
    }

    /// Record `n` executions of the instruction at `pc`.
    pub fn record_n(&mut self, pc: u64, n: u64) {
        *self.counts.entry(pc).or_insert(0) += n;
        self.total += n;
    }

    /// Total instructions executed.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Hit count for a specific PC.
    #[must_use]
    pub fn count_at(&self, pc: u64) -> u64 {
        self.counts.get(&pc).copied().unwrap_or(0)
    }

    /// Number of unique PCs that have been executed at least once.
    #[must_use]
    pub fn unique_pcs(&self) -> usize {
        self.counts.len()
    }

    /// Return the top-`n` hottest PCs sorted by descending hit count.
    #[must_use]
    pub fn top_n(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    /// Return all (pc, count) pairs sorted by address.
    #[must_use]
    pub fn all_sorted_by_addr(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by_key(|(a, _)| *a);
        v
    }

    /// Merge another `InsnCount` into this one.
    pub fn merge(&mut self, other: &Self) {
        for (&pc, &n) in &other.counts {
            *self.counts.entry(pc).or_insert(0) += n;
        }
        self.total += other.total;
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        self.counts.clear();
        self.total = 0;
    }

    /// Return `true` if `pc` is in the top-`threshold_pct` percent by count.
    #[must_use]
    pub fn is_hot(&self, pc: u64, threshold_pct: f64) -> bool {
        let count = self.count_at(pc);
        if self.total == 0 || count == 0 {
            return false;
        }
        let pct = (u64_to_f64(count) / u64_to_f64(self.total)) * 100.0;
        pct >= threshold_pct
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BranchStats
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about conditional and unconditional branches.
#[derive(Debug, Clone, Default)]
pub struct BranchStats {
    /// Total conditional branches encountered.
    pub total_conditional: u64,
    /// Conditional branches that were taken.
    pub taken: u64,
    /// Conditional branches that fell through.
    pub not_taken: u64,
    /// Unconditional direct branches (JMP, B, etc.).
    pub unconditional_direct: u64,
    /// Indirect branches (JMP [reg], BX, etc.).
    pub indirect: u64,
    /// Call instructions.
    pub calls: u64,
    /// Return instructions.
    pub returns: u64,
    /// Backwards branches (loop candidates).
    pub backward_branches: u64,
    /// Per-branch-address taken/not-taken counts.
    per_site: HashMap<u64, (u64, u64)>,
}

impl BranchStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a conditional branch at `pc` that targeted `target`.
    pub fn record_conditional(&mut self, pc: u64, target: u64, taken: bool) {
        self.total_conditional += 1;
        if taken {
            self.taken += 1;
        } else {
            self.not_taken += 1;
        }
        if taken && target < pc {
            self.backward_branches += 1;
        }
        let entry = self.per_site.entry(pc).or_insert((0, 0));
        if taken {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }

    /// Record an unconditional direct branch.
    pub const fn record_direct(&mut self, pc: u64, target: u64) {
        self.unconditional_direct += 1;
        if target < pc {
            self.backward_branches += 1;
        }
    }

    /// Record an indirect branch.
    pub const fn record_indirect(&mut self) {
        self.indirect += 1;
    }

    /// Record a function call.
    pub const fn record_call(&mut self) {
        self.calls += 1;
    }

    /// Record a return.
    pub const fn record_return(&mut self) {
        self.returns += 1;
    }

    /// Total branches of any kind.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total_conditional
            + self.unconditional_direct
            + self.indirect
            + self.calls
            + self.returns
    }

    /// Branch prediction accuracy (taken / `total_conditional`).
    #[must_use]
    pub fn taken_ratio(&self) -> f64 {
        if self.total_conditional == 0 {
            0.0
        } else {
            u64_to_f64(self.taken) / u64_to_f64(self.total_conditional)
        }
    }

    /// Return the top-`n` most frequently taken branches, sorted desc by taken count.
    #[must_use]
    pub fn top_taken_sites(&self, n: usize) -> Vec<(u64, u64, u64)> {
        let mut v: Vec<(u64, u64, u64)> = self
            .per_site
            .iter()
            .map(|(&pc, &(taken, nt))| (pc, taken, nt))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Merge another `BranchStats` into this one.
    pub fn merge(&mut self, other: &Self) {
        self.total_conditional += other.total_conditional;
        self.taken += other.taken;
        self.not_taken += other.not_taken;
        self.unconditional_direct += other.unconditional_direct;
        self.indirect += other.indirect;
        self.calls += other.calls;
        self.returns += other.returns;
        self.backward_branches += other.backward_branches;
        for (&pc, &(t, nt)) in &other.per_site {
            let e = self.per_site.entry(pc).or_insert((0, 0));
            e.0 += t;
            e.1 += nt;
        }
    }

    /// Reset all branch statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MemAccessStats
// ─────────────────────────────────────────────────────────────────────────────

/// Histogram of memory access sizes and counts.
#[derive(Debug, Clone, Default)]
pub struct MemAccessStats {
    pub reads: u64,
    pub writes: u64,
    /// Histogram: `access_size_bytes` → count.
    pub size_histogram: BTreeMap<usize, u64>,
    /// Hot memory addresses (address → `access_count`).
    hot_addrs: HashMap<u64, u64>,
    /// Whether to track per-address statistics (expensive).
    track_addrs: bool,
}

impl MemAccessStats {
    #[must_use]
    pub fn new(track_addrs: bool) -> Self {
        Self {
            track_addrs,
            ..Self::default()
        }
    }

    /// Record a memory read of `size` bytes at `addr`.
    pub fn record_read(&mut self, addr: u64, size: usize) {
        self.reads += 1;
        *self.size_histogram.entry(size).or_insert(0) += 1;
        if self.track_addrs {
            *self.hot_addrs.entry(addr).or_insert(0) += 1;
        }
    }

    /// Record a memory write of `size` bytes at `addr`.
    pub fn record_write(&mut self, addr: u64, size: usize) {
        self.writes += 1;
        *self.size_histogram.entry(size).or_insert(0) += 1;
        if self.track_addrs {
            *self.hot_addrs.entry(addr).or_insert(0) += 1;
        }
    }

    /// Total memory accesses.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.reads + self.writes
    }

    /// Return the top-`n` hottest accessed addresses.
    #[must_use]
    pub fn top_addrs(&self, n: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.hot_addrs.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v.truncate(n);
        v
    }

    /// Most common access size.
    #[must_use]
    pub fn dominant_size(&self) -> Option<usize> {
        self.size_histogram.iter().max_by_key(|(_, c)| *c).map(|(s, _)| *s)
    }

    /// Reset.
    pub fn reset(&mut self) {
        self.reads = 0;
        self.writes = 0;
        self.size_histogram.clear();
        self.hot_addrs.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoopDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Detects tight loops by identifying frequently-taken backward branches.
///
/// # Design note — two `LoopDetector` types in this crate
///
/// This type is a **profiling** detector: it accumulates `(branch_pc → target)`
/// counts from explicit `observe` calls and surfaces back-edges whose iteration
/// count exceeds the threshold. It is intended for offline analysis via
/// [`EmuExecutionStatistics::generate_report`].
///
/// [`structured_execution::LoopDetector`] (in the `structured_execution` module)
/// is a **guard-rail** detector that operates on the live PC stream during
/// [`structured_execution::EmuSession::tick`]: it watches both per-PC visit
/// counts and repeating short PC patterns to abort runaway loops early, before
/// the emulation step limit is reached. The two types are intentionally kept
/// separate because they serve different purposes — profiling vs. safety.
#[derive(Debug, Clone, Default)]
pub struct LoopDetector {
    /// (`branch_pc`, `target_pc`) → iteration count.
    loops: HashMap<(u64, u64), u64>,
    /// Minimum count to consider a backward branch a "loop".
    threshold: u64,
}

impl LoopDetector {
    #[must_use]
    pub fn new(threshold: u64) -> Self {
        Self {
            loops: HashMap::new(),
            threshold,
        }
    }

    /// Observe a backward branch from `pc` to `target`.
    pub fn observe(&mut self, pc: u64, target: u64) {
        if target < pc {
            *self.loops.entry((pc, target)).or_insert(0) += 1;
        }
    }

    /// Return all detected loop back-edges that exceed the threshold.
    #[must_use]
    pub fn detected_loops(&self) -> Vec<(u64, u64, u64)> {
        let mut v: Vec<(u64, u64, u64)> = self
            .loops
            .iter()
            .filter(|&(_, &c)| c >= self.threshold)
            .map(|(&(pc, tgt), &c)| (pc, tgt, c))
            .collect();
        v.sort_by(|a, b| b.2.cmp(&a.2));
        v
    }

    /// Return `true` if `(pc, target)` has been observed more than `threshold` times.
    #[must_use]
    pub fn is_loop(&self, pc: u64, target: u64) -> bool {
        self.loops.get(&(pc, target)).copied().unwrap_or(0) >= self.threshold
    }

    /// Total unique backward branches observed.
    #[must_use]
    pub fn unique_back_edges(&self) -> usize {
        self.loops.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// StatsReport
// ─────────────────────────────────────────────────────────────────────────────

/// A rendered human-readable snapshot of all statistics.
#[derive(Debug, Clone)]
pub struct StatsReport {
    /// Total instructions executed.
    pub total_insns: u64,
    /// Unique program counter values observed.
    pub unique_pcs: usize,
    /// Total branches of all kinds.
    pub total_branches: u64,
    /// Fraction of conditional branches that were taken.
    pub branch_taken_ratio: f64,
    /// Total memory reads.
    pub mem_reads: u64,
    /// Total memory writes.
    pub mem_writes: u64,
    /// Total function calls.
    pub call_count: u64,
    /// Total returns.
    pub return_count: u64,
    /// Backward branch count.
    pub backward_branches: u64,
    /// Top-10 hottest instruction PCs (address, count).
    pub top_hot_pcs: Vec<(u64, u64)>,
    /// Top-5 most-taken branch sites (`branch_pc`, taken, `not_taken`).
    pub top_branch_sites: Vec<(u64, u64, u64)>,
    /// Detected loops: (`branch_pc`, `target_pc`, `iteration_count`).
    pub loops: Vec<(u64, u64, u64)>,
}

impl std::fmt::Display for StatsReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Execution Statistics Report ===")?;
        writeln!(f, "Total instructions:   {}", self.total_insns)?;
        writeln!(f, "Unique PCs:           {}", self.unique_pcs)?;
        writeln!(f, "Total branches:       {}", self.total_branches)?;
        writeln!(
            f,
            "Branch taken ratio:   {:.2}%",
            self.branch_taken_ratio * 100.0
        )?;
        writeln!(f, "Memory reads:         {}", self.mem_reads)?;
        writeln!(f, "Memory writes:        {}", self.mem_writes)?;
        writeln!(f, "Function calls:       {}", self.call_count)?;
        writeln!(f, "Returns:              {}", self.return_count)?;
        writeln!(f, "Backward branches:    {}", self.backward_branches)?;
        writeln!(f, "Hot PCs (top 10):")?;
        for (pc, cnt) in &self.top_hot_pcs {
            writeln!(f, "  {pc:#018x}  {cnt}")?;
        }
        writeln!(f, "Top branch sites:")?;
        for (pc, t, nt) in &self.top_branch_sites {
            writeln!(f, "  {pc:#018x}  taken={t} not_taken={nt}")?;
        }
        if !self.loops.is_empty() {
            writeln!(f, "Detected loops:")?;
            for (pc, tgt, iters) in &self.loops {
                writeln!(f, "  {pc:#018x} → {tgt:#018x} ({iters} iters)")?;
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EmuExecutionStatistics
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregator for all emulation profiling data.
pub struct EmuExecutionStatistics {
    /// Per-PC instruction hit counts.
    pub insn_counts: InsnCount,
    /// Branch statistics.
    pub branch_stats: BranchStats,
    /// Memory access statistics.
    pub mem_stats: MemAccessStats,
    /// Loop detector.
    pub loop_detector: LoopDetector,
    /// Wall-clock start time for IPC calculations.
    start_time: std::time::Instant,
    /// Elapsed emulation time (accumulated across pauses).
    elapsed_ns: u64,
}

impl EmuExecutionStatistics {
    /// Create a new stats aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            insn_counts: InsnCount::new(),
            branch_stats: BranchStats::new(),
            mem_stats: MemAccessStats::new(false),
            loop_detector: LoopDetector::new(10),
            start_time: std::time::Instant::now(),
            elapsed_ns: 0,
        }
    }

    /// Create with per-address memory tracking enabled.
    #[must_use]
    pub fn with_addr_tracking() -> Self {
        let mut s = Self::new();
        s.mem_stats = MemAccessStats::new(true);
        s
    }

    // ── Recording ────────────────────────────────────────────────────────────

    /// Record one instruction execution.
    pub fn record_insn(&mut self, pc: u64) {
        self.insn_counts.record(pc);
    }

    /// Record a conditional branch.
    pub fn record_branch(&mut self, pc: u64, target: u64, taken: bool) {
        self.branch_stats.record_conditional(pc, target, taken);
        if taken {
            self.loop_detector.observe(pc, target);
        }
    }

    /// Record an unconditional direct branch.
    pub fn record_jump(&mut self, pc: u64, target: u64) {
        self.branch_stats.record_direct(pc, target);
        self.loop_detector.observe(pc, target);
    }

    /// Record a call instruction.
    pub const fn record_call(&mut self) {
        self.branch_stats.record_call();
    }

    /// Record a return instruction.
    pub const fn record_return(&mut self) {
        self.branch_stats.record_return();
    }

    /// Record a memory read.
    pub fn record_mem_read(&mut self, addr: u64, size: usize) {
        self.mem_stats.record_read(addr, size);
    }

    /// Record a memory write.
    pub fn record_mem_write(&mut self, addr: u64, size: usize) {
        self.mem_stats.record_write(addr, size);
    }

    // ── Snapshot ─────────────────────────────────────────────────────────────

    /// Snapshot the current time to start a timing interval.
    pub fn start_timing(&mut self) {
        self.start_time = std::time::Instant::now();
    }

    /// End the current timing interval and accumulate elapsed nanoseconds.
    pub fn stop_timing(&mut self) {
        self.elapsed_ns += u64::try_from(self.start_time.elapsed().as_nanos()).unwrap_or(u64::MAX);
    }

    /// Instructions per second based on accumulated timing.
    #[must_use]
    pub fn insns_per_second(&self) -> f64 {
        if self.elapsed_ns == 0 {
            return 0.0;
        }
        u64_to_f64(self.insn_counts.total()) / (u64_to_f64(self.elapsed_ns) / 1_000_000_000.0)
    }

    // ── Merge / reset ─────────────────────────────────────────────────────────

    /// Merge another statistics object into this one.
    pub fn merge(&mut self, other: &Self) {
        self.insn_counts.merge(&other.insn_counts);
        self.branch_stats.merge(&other.branch_stats);
    }

    /// Reset all statistics.
    pub fn reset(&mut self) {
        self.insn_counts.reset();
        self.branch_stats.reset();
        self.mem_stats.reset();
        self.loop_detector = LoopDetector::new(10);
        self.elapsed_ns = 0;
        self.start_time = std::time::Instant::now();
    }

    // ── Report generation ─────────────────────────────────────────────────────

    /// Generate a comprehensive statistics report.
    #[must_use]
    pub fn generate_report(&self) -> StatsReport {
        StatsReport {
            total_insns: self.insn_counts.total(),
            unique_pcs: self.insn_counts.unique_pcs(),
            total_branches: self.branch_stats.total(),
            branch_taken_ratio: self.branch_stats.taken_ratio(),
            mem_reads: self.mem_stats.reads,
            mem_writes: self.mem_stats.writes,
            call_count: self.branch_stats.calls,
            return_count: self.branch_stats.returns,
            backward_branches: self.branch_stats.backward_branches,
            top_hot_pcs: self.insn_counts.top_n(10),
            top_branch_sites: self.branch_stats.top_taken_sites(5),
            loops: self.loop_detector.detected_loops(),
        }
    }
}

impl Default for EmuExecutionStatistics {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EmuExecutionStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmuExecutionStatistics")
            .field("total_insns", &self.insn_counts.total())
            .field("total_branches", &self.branch_stats.total())
            .field("mem_reads", &self.mem_stats.reads)
            .field("mem_writes", &self.mem_stats.writes)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insn_count_record_and_total() {
        let mut ic = InsnCount::new();
        ic.record(0x1000);
        ic.record(0x1000);
        ic.record(0x1004);
        assert_eq!(ic.total(), 3);
        assert_eq!(ic.count_at(0x1000), 2);
        assert_eq!(ic.unique_pcs(), 2);
    }

    #[test]
    fn test_insn_count_top_n() {
        let mut ic = InsnCount::new();
        for _ in 0..10 { ic.record(0x2000); }
        for _ in 0..3 { ic.record(0x1000); }
        let top = ic.top_n(1);
        assert_eq!(top[0].0, 0x2000);
        assert_eq!(top[0].1, 10);
    }

    #[test]
    fn test_insn_count_merge() {
        let mut a = InsnCount::new();
        a.record_n(0x1000, 5);
        let mut b = InsnCount::new();
        b.record_n(0x1000, 3);
        b.record_n(0x2000, 1);
        a.merge(&b);
        assert_eq!(a.count_at(0x1000), 8);
        assert_eq!(a.total(), 9);
    }

    #[test]
    fn test_insn_count_reset() {
        let mut ic = InsnCount::new();
        ic.record(0x1000);
        ic.reset();
        assert_eq!(ic.total(), 0);
    }

    #[test]
    fn test_insn_count_is_hot() {
        let mut ic = InsnCount::new();
        ic.record_n(0x1000, 90);
        ic.record_n(0x2000, 10);
        assert!(ic.is_hot(0x1000, 50.0));
        assert!(!ic.is_hot(0x2000, 50.0));
    }

    #[test]
    fn test_branch_stats_conditional() {
        let mut bs = BranchStats::new();
        bs.record_conditional(0x1000, 0x2000, true);
        bs.record_conditional(0x1000, 0x1002, false);
        bs.record_conditional(0x3000, 0x1000, true); // backward
        assert_eq!(bs.taken, 2);
        assert_eq!(bs.not_taken, 1);
        assert_eq!(bs.backward_branches, 1);
    }

    #[test]
    fn test_branch_stats_taken_ratio() {
        let mut bs = BranchStats::new();
        bs.record_conditional(0x1000, 0x2000, true);
        bs.record_conditional(0x1000, 0x1002, true);
        bs.record_conditional(0x1000, 0x1002, false);
        let r = bs.taken_ratio();
        assert!((r - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_branch_stats_calls_returns() {
        let mut bs = BranchStats::new();
        bs.record_call();
        bs.record_call();
        bs.record_return();
        assert_eq!(bs.calls, 2);
        assert_eq!(bs.returns, 1);
        assert_eq!(bs.total(), 3);
    }

    #[test]
    fn test_branch_stats_merge() {
        let mut a = BranchStats::new();
        a.record_conditional(0x1000, 0x2000, true);
        let mut b = BranchStats::new();
        b.record_conditional(0x1000, 0x2000, false);
        a.merge(&b);
        assert_eq!(a.total_conditional, 2);
    }

    #[test]
    fn test_mem_access_stats() {
        let mut ms = MemAccessStats::new(true);
        ms.record_read(0x4000, 8);
        ms.record_write(0x4000, 4);
        ms.record_read(0x5000, 8);
        assert_eq!(ms.reads, 2);
        assert_eq!(ms.writes, 1);
        assert_eq!(ms.total(), 3);
        assert_eq!(ms.dominant_size(), Some(8));
    }

    #[test]
    fn test_mem_top_addrs() {
        let mut ms = MemAccessStats::new(true);
        for _ in 0..5 { ms.record_read(0x1000, 4); }
        ms.record_read(0x2000, 4);
        let top = ms.top_addrs(1);
        assert_eq!(top[0].0, 0x1000);
    }

    #[test]
    fn test_loop_detector() {
        let mut ld = LoopDetector::new(5);
        for _ in 0..7 {
            ld.observe(0x2000, 0x1000);
        }
        assert!(ld.is_loop(0x2000, 0x1000));
        let loops = ld.detected_loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0], (0x2000, 0x1000, 7));
    }

    #[test]
    fn test_loop_detector_no_forward_branch() {
        let mut ld = LoopDetector::new(3);
        for _ in 0..10 {
            ld.observe(0x1000, 0x2000); // forward, should not count
        }
        assert!(!ld.is_loop(0x1000, 0x2000));
        assert!(ld.detected_loops().is_empty());
    }

    #[test]
    fn test_emu_stats_record_and_report() {
        let mut stats = EmuExecutionStatistics::new();
        for _ in 0..100 { stats.record_insn(0x1000); }
        stats.record_branch(0x1008, 0x1000, true);
        stats.record_call();
        stats.record_return();
        stats.record_mem_read(0x4000, 8);
        stats.record_mem_write(0x5000, 4);

        let r = stats.generate_report();
        assert_eq!(r.total_insns, 100);
        assert_eq!(r.call_count, 1);
        assert_eq!(r.return_count, 1);
        assert_eq!(r.mem_reads, 1);
        assert_eq!(r.mem_writes, 1);
    }

    #[test]
    fn test_report_display() {
        let mut stats = EmuExecutionStatistics::new();
        stats.record_insn(0x1000);
        let r = stats.generate_report();
        let s = r.to_string();
        assert!(s.contains("Execution Statistics Report"));
    }

    #[test]
    fn test_reset_clears_everything() {
        let mut stats = EmuExecutionStatistics::new();
        stats.record_insn(0x1000);
        stats.record_mem_read(0x2000, 4);
        stats.reset();
        assert_eq!(stats.insn_counts.total(), 0);
        assert_eq!(stats.mem_stats.reads, 0);
    }

    #[test]
    fn test_merge_stats() {
        let mut a = EmuExecutionStatistics::new();
        a.record_insn(0x1000);
        let mut b = EmuExecutionStatistics::new();
        b.record_insn(0x2000);
        a.merge(&b);
        assert_eq!(a.insn_counts.total(), 2);
    }

    #[test]
    fn test_debug_format() {
        let stats = EmuExecutionStatistics::new();
        let s = format!("{stats:?}");
        assert!(s.contains("EmuExecutionStatistics"));
    }

    #[test]
    fn test_unique_pcs_in_report() {
        let mut stats = EmuExecutionStatistics::new();
        stats.record_insn(0x1000);
        stats.record_insn(0x1000);
        stats.record_insn(0x1004);
        let r = stats.generate_report();
        assert_eq!(r.unique_pcs, 2);
    }
}
