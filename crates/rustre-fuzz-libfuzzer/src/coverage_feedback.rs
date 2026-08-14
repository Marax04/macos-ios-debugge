//! Coverage feedback — `SanitizerCoverage` integration, PC-table decoding,
//! new coverage detection, branch tuples, and `CmpLog` operand tracking.
//!
//! This module interfaces with the `SanitizerCoverage` (sancov) instrumentation
//! injected by clang/LLVM to provide feedback to the fuzzer loop.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

// ─── PC-table entry ───────────────────────────────────────────────────────────

// Flags stored alongside each PC in the sancov PC-table. (The doc text is
// duplicated inside the `bitflags!` invocation below so rustdoc still picks
// it up — the outer `///` form is rejected because the macro does not
// re-emit it on its expansion.)
bitflags::bitflags! {
    /// Flags stored alongside each PC in the sancov PC-table.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct PcFlags: u64 {
        /// PC marks the entry point of a function.
        const FUNC_ENTRY   = 0x1;
        /// PC marks the entry of a basic block.
        const BB_ENTRY     = 0x2;
        /// PC marks both a function entry and a basic-block entry.
        const COMBINED     = 0x4;
    }
}

/// One entry in the `SanitizerCoverage` PC-table (`__sancov_pc_table`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcTableEntry {
    /// Instrumented program counter.
    pub pc: u64,
    /// PC flags (function entry, basic-block entry, etc.).
    pub flags: PcFlags,
}

/// Parse a raw PC-table from a byte slice.
/// The PC-table has alternating (pc, flags) pairs, each pointer-sized.
#[must_use] 
pub fn parse_pc_table(bytes: &[u8], pointer_size: u8) -> Vec<PcTableEntry> {
    let step = pointer_size as usize;
    if step != 4 && step != 8 { return Vec::new(); }
    let mut entries = Vec::new();
    let mut i = 0;
    while i + step * 2 <= bytes.len() {
        let pc = read_uint(bytes, i, step);
        let flags_raw = read_uint(bytes, i + step, step);
        entries.push(PcTableEntry {
            pc,
            flags: PcFlags::from_bits_truncate(flags_raw),
        });
        i += step * 2;
    }
    entries
}

fn read_uint(bytes: &[u8], offset: usize, size: usize) -> u64 {
    match size {
        4 => u64::from(u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))),
        8 => u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8])),
        _ => 0,
    }
}

// ─── Coverage map ─────────────────────────────────────────────────────────────

/// The inline 8-bit AFL-style coverage bitmap, shared between the harness
/// and the fuzzer engine.
///
/// In libFuzzer/sancov mode each (`src_pc` → `dst_pc`) edge is hashed to an index
/// into this table and its counter is incremented.
pub struct CoverageShm {
    /// The raw 64 KiB bitmap.
    bitmap: Vec<AtomicU8>,
}

impl CoverageShm {
    /// Allocate a fresh 64 KiB bitmap.
    #[must_use] 
    pub fn new() -> Arc<Self> {
        let bitmap = (0..65536).map(|_| AtomicU8::new(0)).collect();
        Arc::new(Self { bitmap })
    }

    /// Return the current value at index `idx`.
    #[must_use] 
    pub fn get(&self, idx: usize) -> u8 {
        self.bitmap.get(idx).map_or(0, |a| a.load(Ordering::Relaxed))
    }

    /// Set all bytes to zero.
    pub fn reset(&self) {
        for cell in &self.bitmap {
            cell.store(0, Ordering::Relaxed);
        }
    }

    /// Count the number of non-zero entries (hit edges).
    #[must_use] 
    pub fn count_edges(&self) -> usize {
        self.bitmap.iter().filter(|a| a.load(Ordering::Relaxed) != 0).count()
    }

    /// Snapshot the bitmap into a plain Vec<u8>.
    #[must_use] 
    pub fn snapshot(&self) -> Vec<u8> {
        self.bitmap.iter().map(|a| a.load(Ordering::Relaxed)).collect()
    }

    /// Merge `other_snapshot` into self (OR semantics).
    pub fn merge_or(&self, other_snapshot: &[u8]) {
        for (cell, &v) in self.bitmap.iter().zip(other_snapshot.iter()) {
            let cur = cell.load(Ordering::Relaxed);
            cell.store(cur | v, Ordering::Relaxed);
        }
    }

    #[must_use] 
    pub const fn size(&self) -> usize { self.bitmap.len() }
}

impl Default for CoverageShm {
    fn default() -> Self {
        let bitmap = (0..65536).map(|_| AtomicU8::new(0)).collect();
        Self { bitmap }
    }
}

// ─── New coverage detector ─────────────────────────────────────────────────────

/// Tracks aggregate corpus coverage across many runs.
#[derive(Debug)]
pub struct CoverageTracker {
    /// Bitmap of all edges ever seen (union of all runs).
    global: Vec<u8>,
    /// Per-run snapshots: `run_id` → snapshot.
    runs: Vec<(u64 /* run_id */, Vec<u8> /* snapshot */)>,
    /// Count of total distinct edges seen.
    total_edges: usize,
}

impl CoverageTracker {
    #[must_use] 
    pub fn new(bitmap_size: usize) -> Self {
        Self { global: vec![0u8; bitmap_size], runs: Vec::new(), total_edges: 0 }
    }

    /// Record a run's bitmap snapshot; returns (`new_edges`, `new_edge_indices`).
    pub fn record_run(&mut self, run_id: u64, snapshot: &[u8]) -> (usize, Vec<usize>) {
        let mut new_edges = 0usize;
        let mut new_indices = Vec::new();

        for (i, (&cur, &new)) in self.global.iter().zip(snapshot.iter()).enumerate() {
            if new != 0 && cur == 0 {
                new_edges += 1;
                new_indices.push(i);
            }
        }

        // Update global (OR)
        for (g, &s) in self.global.iter_mut().zip(snapshot.iter()) {
            *g |= s;
        }

        self.total_edges += new_edges;
        self.runs.push((run_id, snapshot.to_vec()));
        (new_edges, new_indices)
    }

    /// Check if a snapshot adds any new coverage vs. the current global.
    #[must_use] 
    pub fn has_new_coverage(&self, snapshot: &[u8]) -> bool {
        self.global.iter().zip(snapshot.iter()).any(|(&g, &s)| s != 0 && g == 0)
    }

    #[must_use] 
    pub const fn total_edges(&self) -> usize { self.total_edges }
    #[must_use] 
    pub const fn run_count(&self) -> usize { self.runs.len() }

    /// Compute coverage percentage given a known total number of edges.
    #[must_use] 
    pub fn coverage_pct(&self, total: usize) -> f64 {
        if total == 0 { return 0.0; }
        (self.total_edges as f64 / total as f64) * 100.0
    }
}

// ─── Branch tuple / edge hash ─────────────────────────────────────────────────

/// A (`src_pc`, `dst_pc`) branch tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BranchTuple {
    pub src: u64,
    pub dst: u64,
}

impl BranchTuple {
    #[must_use] 
    pub const fn new(src: u64, dst: u64) -> Self { Self { src, dst } }

    /// AFL-style edge hash: (src >> 1) XOR dst, masked to bitmap size.
    #[must_use] 
    pub const fn edge_index(&self, bitmap_size: usize) -> usize {
        let h = ((self.src >> 1) ^ self.dst) as usize;
        h % bitmap_size
    }
}

/// Track branch tuples observed across runs.
#[derive(Debug, Default)]
pub struct BranchTracker {
    seen: HashSet<BranchTuple>,
    per_run: Vec<(u64, Vec<BranchTuple>)>,
}

impl BranchTracker {
    pub fn record_run(&mut self, run_id: u64, tuples: Vec<BranchTuple>) -> usize {
        let mut new = 0usize;
        for t in &tuples {
            if self.seen.insert(*t) {
                new += 1;
            }
        }
        self.per_run.push((run_id, tuples));
        new
    }

    #[must_use] 
    pub fn total_unique_branches(&self) -> usize { self.seen.len() }
}

// ─── CmpLog (comparison operand feedback) ────────────────────────────────────

/// The type of a comparison operand captured by `CmpLog` instrumentation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CmpOperand {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Bytes(Vec<u8>),
}

impl CmpOperand {
    /// Return the raw bytes of this operand (for mutation feedback).
    #[must_use] 
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::U8(v) => vec![*v],
            Self::U16(v) => v.to_le_bytes().to_vec(),
            Self::U32(v) => v.to_le_bytes().to_vec(),
            Self::U64(v) => v.to_le_bytes().to_vec(),
            Self::Bytes(b) => b.clone(),
        }
    }
}

/// One captured comparison operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmpEntry {
    /// PC of the comparison instruction.
    pub pc: u64,
    pub lhs: CmpOperand,
    pub rhs: CmpOperand,
    /// How many times this comparison fired in this run.
    pub hit_count: u32,
}

/// Aggregates `CmpLog` entries across runs and suggests mutation candidates.
#[derive(Debug, Default)]
pub struct CmpLogAnalyzer {
    entries: Vec<CmpEntry>,
    /// Magic values extracted from comparisons (de-duplicated).
    magic_values: HashSet<Vec<u8>>,
}

impl CmpLogAnalyzer {
    pub fn record_entries(&mut self, entries: Vec<CmpEntry>) {
        for e in &entries {
            self.magic_values.insert(e.lhs.to_bytes());
            self.magic_values.insert(e.rhs.to_bytes());
        }
        self.entries.extend(entries);
    }

    /// Return bytes that frequently appear as comparison RHS — good for dictionary.
    #[must_use] 
    pub fn extract_interesting_bytes(&self) -> Vec<Vec<u8>> {
        self.magic_values.iter().cloned().collect()
    }

    /// Filter entries by PC range (e.g. inside a specific function).
    #[must_use] 
    pub fn entries_in_range(&self, lo: u64, hi: u64) -> Vec<&CmpEntry> {
        self.entries.iter().filter(|e| e.pc >= lo && e.pc <= hi).collect()
    }

    /// Return the top-N most-hit comparison sites.
    #[must_use] 
    pub fn top_hot_cmps(&self, n: usize) -> Vec<&CmpEntry> {
        let mut sorted: Vec<&CmpEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| b.hit_count.cmp(&a.hit_count));
        sorted.into_iter().take(n).collect()
    }

    #[must_use] 
    pub const fn total_entries(&self) -> usize { self.entries.len() }
}

// ─── AFL bitmap classifier ───────────────────────────────────────────────────

/// Bucket classification for AFL-style hit counts.
/// Maps raw count to power-of-two bucket to reduce noise.
#[inline]
#[must_use] 
pub const fn bucket_hit_count(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// Apply AFL bucketing to an entire bitmap snapshot.
#[must_use] 
pub fn bucket_bitmap(bitmap: &[u8]) -> Vec<u8> {
    bitmap.iter().map(|&b| bucket_hit_count(b)).collect()
}

/// Compare two bucketed bitmaps and return the number of edges that differ.
#[must_use] 
pub fn count_new_bits_bucketed(global: &[u8], current: &[u8]) -> usize {
    global.iter().zip(current.iter()).filter(|(g, c)| {
        let bc = bucket_hit_count(**c);
        bc != 0 && bc > **g
    }).count()
}

// ─── Coverage edge statistics ─────────────────────────────────────────────────

/// Statistics about a coverage bitmap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitmapStats {
    pub total_bits: usize,
    pub set_bits: usize,
    pub coverage_pct: f64,
    /// Estimated number of distinct "buckets" seen.
    pub distinct_buckets: usize,
    pub max_hit: u8,
    pub mean_hit: f64,
}

impl BitmapStats {
    #[must_use] 
    pub fn compute(bitmap: &[u8]) -> Self {
        let total_bits = bitmap.len();
        let set_bits = bitmap.iter().filter(|&&b| b != 0).count();
        let coverage_pct = if total_bits == 0 { 0.0 } else { (set_bits) as f64 / (total_bits) as f64 * 100.0 };
        let max_hit = bitmap.iter().copied().max().unwrap_or(0);
        let sum: u64 = bitmap.iter().map(|&b| u64::from(b)).sum();
        let mean_hit = if set_bits == 0 { 0.0 } else { (sum) as f64 / (set_bits) as f64 };

        // Count distinct non-zero values as a proxy for bucket diversity
        let mut vals = std::collections::HashSet::new();
        for &b in bitmap { if b != 0 { vals.insert(bucket_hit_count(b)); } }
        let distinct_buckets = vals.len();

        Self { total_bits, set_bits, coverage_pct, distinct_buckets, max_hit, mean_hit }
    }
}

impl std::fmt::Display for BitmapStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "edges: {}/{} ({:.1}%)  max_hit={}  mean_hit={:.2}  buckets={}",
            self.set_bits, self.total_bits, self.coverage_pct, self.max_hit, self.mean_hit, self.distinct_buckets)
    }
}

// ─── SanitizerCoverage PC guard integration ───────────────────────────────────

/// Represents a PC-guard instrumentation point installed by sancov.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcGuard {
    pub guard_id: u32,
    pub pc: u64,
    pub is_function_entry: bool,
    pub module: Option<String>,
}

/// A live PC-guard table: updated by the `__sanitizer_cov_trace_pc_guard` callback.
pub struct PcGuardTable {
    guards: Vec<PcGuard>,
    hit_counts: Vec<std::sync::atomic::AtomicU32>,
}

impl PcGuardTable {
    /// Allocate a table of `n` guards.
    #[must_use] 
    pub fn new(n: usize) -> Self {
        let guards = (0..n as u32).map(|i| PcGuard { guard_id: i, pc: 0, is_function_entry: false, module: None }).collect();
        let hit_counts = (0..n).map(|_| std::sync::atomic::AtomicU32::new(0)).collect();
        Self { guards, hit_counts }
    }

    /// Increment the hit count for guard `id`.
    pub fn hit(&self, id: u32) {
        if let Some(cnt) = self.hit_counts.get(id as usize) {
            cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Set the PC for guard `id` (called from `__sanitizer_cov_trace_pc_guard_init`).
    pub fn set_pc(&mut self, id: u32, pc: u64) {
        if let Some(g) = self.guards.get_mut(id as usize) { g.pc = pc; }
    }

    /// Number of guards with at least one hit.
    #[must_use] 
    pub fn covered_count(&self) -> usize {
        self.hit_counts.iter().filter(|c| c.load(std::sync::atomic::Ordering::Relaxed) > 0).count()
    }

    /// Snapshot guard hit counts into a `Vec`.
    #[must_use] 
    pub fn snapshot(&self) -> Vec<u32> {
        self.hit_counts.iter().map(|c| c.load(std::sync::atomic::Ordering::Relaxed)).collect()
    }

    /// Reset all hit counts.
    pub fn reset(&self) {
        for c in &self.hit_counts { c.store(0, std::sync::atomic::Ordering::Relaxed); }
    }

    /// Total number of guards.
    #[must_use] 
    pub const fn len(&self) -> usize { self.guards.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.guards.is_empty() }
}

// ─── Feedback aggregator ──────────────────────────────────────────────────────

/// Aggregates coverage feedback across the entire fuzzing session.
#[derive(Debug)]
pub struct FeedbackAggregator {
    pub tracker: CoverageTracker,
    pub branch_tracker: BranchTracker,
    pub cmplog: CmpLogAnalyzer,
    pub iteration_log: Vec<IterationFeedback>,
    total_execs: u64,
    total_new_coverage: usize,
}

impl FeedbackAggregator {
    #[must_use] 
    pub fn new(bitmap_size: usize) -> Self {
        Self {
            tracker: CoverageTracker::new(bitmap_size),
            branch_tracker: BranchTracker::default(),
            cmplog: CmpLogAnalyzer::default(),
            iteration_log: Vec::new(),
            total_execs: 0,
            total_new_coverage: 0,
        }
    }

    /// Record one fuzzer iteration.
    pub fn record_iteration(
        &mut self,
        run_id: u64,
        input: &[u8],
        bitmap_snapshot: &[u8],
        branches: Vec<BranchTuple>,
        cmp_entries: Vec<CmpEntry>,
        exec_time_us: u64,
        has_crash: bool,
    ) -> IterationFeedback {
        let input_hash = fnv1a_64(input);
        let input_len = input.len();
        let (new_edges, _) = self.tracker.record_run(run_id, bitmap_snapshot);
        let new_branches = self.branch_tracker.record_run(run_id, branches);
        self.cmplog.record_entries(cmp_entries);
        self.total_execs += 1;
        self.total_new_coverage += new_edges;

        let fb = IterationFeedback {
            run_id, input_hash, input_len, new_edges,
            total_edges_seen: self.tracker.total_edges(),
            new_branches, has_crash, exec_time_us,
        };
        self.iteration_log.push(fb.clone());
        fb
    }

    #[must_use] 
    pub const fn total_execs(&self) -> u64 { self.total_execs }
    #[must_use] 
    pub const fn total_coverage_gains(&self) -> usize { self.total_new_coverage }
    #[must_use] 
    pub fn execs_per_sec(&self, elapsed_secs: f64) -> f64 {
        if elapsed_secs == 0.0 { 0.0 } else { (self.total_execs) as f64 / elapsed_secs }
    }

    /// Generate a text stats summary.
    #[must_use] 
    pub fn stats_summary(&self, elapsed_secs: f64) -> String {
        let mut out = String::new();
        writeln!(out, "Fuzzer Coverage Stats").ok();
        writeln!(out, "  Total execs   : {}", self.total_execs).ok();
        writeln!(out, "  Exec/sec      : {:.0}", self.execs_per_sec(elapsed_secs)).ok();
        writeln!(out, "  Total edges   : {}", self.tracker.total_edges()).ok();
        writeln!(out, "  Coverage gains: {}", self.total_new_coverage).ok();
        writeln!(out, "  Unique branches: {}", self.branch_tracker.total_unique_branches()).ok();
        writeln!(out, "  CmpLog entries : {}", self.cmplog.total_entries()).ok();
        out
    }
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data { h ^= u64::from(b); h = h.wrapping_mul(0x0000_0100_0000_01b3); }
    h
}

// ─── Coverage feedback summary ────────────────────────────────────────────────

/// A combined feedback snapshot for one fuzzer iteration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IterationFeedback {
    pub run_id: u64,
    pub input_hash: u64,
    pub input_len: usize,
    pub new_edges: usize,
    pub total_edges_seen: usize,
    pub new_branches: usize,
    pub has_crash: bool,
    pub exec_time_us: u64,
}

impl std::fmt::Display for IterationFeedback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "run={} len={} new_edges={} total_edges={} new_branches={} crash={} time={}µs",
            self.run_id, self.input_len, self.new_edges, self.total_edges_seen,
            self.new_branches, self.has_crash, self.exec_time_us
        )
    }
}

// ─── Coverage-driven input selection ─────────────────────────────────────────

/// Seed selection policy for coverage-guided fuzzing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedSelectionPolicy {
    /// Round-robin across all seeds.
    RoundRobin,
    /// Prefer seeds that introduced the most new edges.
    MostNewEdges,
    /// Prefer the most recently added seeds (recency bias).
    Recency,
    /// Prefer seeds with the lowest execution time.
    Fastest,
}

/// Track seeds with their coverage contribution for selection.
pub struct SeedPool {
    pub seeds: Vec<SeedEntry>,
    policy: SeedSelectionPolicy,
    rr_index: usize,
}

/// One seed in the pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedEntry {
    pub id: u64,
    pub data_hash: u64,
    pub new_edges_at_discovery: usize,
    pub total_runs: u64,
    pub total_exec_us: u64,
    pub last_used_run: u64,
}

impl SeedEntry {
    #[must_use] 
    pub fn avg_exec_us(&self) -> f64 {
        if self.total_runs == 0 { 0.0 } else { (self.total_exec_us) as f64 / (self.total_runs) as f64 }
    }
}

impl SeedPool {
    #[must_use] 
    pub const fn new(policy: SeedSelectionPolicy) -> Self {
        Self { seeds: Vec::new(), policy, rr_index: 0 }
    }

    pub fn add(&mut self, id: u64, data_hash: u64, new_edges: usize) {
        self.seeds.push(SeedEntry { id, data_hash, new_edges_at_discovery: new_edges, total_runs: 0, total_exec_us: 0, last_used_run: 0 });
    }

    pub fn update_seed(&mut self, id: u64, run_id: u64, exec_us: u64) {
        if let Some(s) = self.seeds.iter_mut().find(|s| s.id == id) {
            s.total_runs += 1;
            s.total_exec_us += exec_us;
            s.last_used_run = run_id;
        }
    }

    /// Select the next seed according to the policy.
    pub fn select_next(&mut self) -> Option<u64> {
        if self.seeds.is_empty() { return None; }
        match self.policy {
            SeedSelectionPolicy::RoundRobin => {
                let id = self.seeds[self.rr_index % self.seeds.len()].id;
                self.rr_index += 1;
                Some(id)
            }
            SeedSelectionPolicy::MostNewEdges => {
                self.seeds.iter().max_by_key(|s| s.new_edges_at_discovery).map(|s| s.id)
            }
            SeedSelectionPolicy::Recency => {
                self.seeds.iter().max_by_key(|s| s.last_used_run).map(|s| s.id)
            }
            SeedSelectionPolicy::Fastest => {
                self.seeds.iter()
                    .filter(|s| s.total_runs > 0)
                    .min_by(|a, b| a.avg_exec_us().partial_cmp(&b.avg_exec_us()).unwrap_or(std::cmp::Ordering::Equal))
                    .or_else(|| self.seeds.first())
                    .map(|s| s.id)
            }
        }
    }

    #[must_use] 
    pub const fn len(&self) -> usize { self.seeds.len() }
    #[must_use] 
    pub const fn is_empty(&self) -> bool { self.seeds.is_empty() }
}

// ─── Coverage-guided minimizer ────────────────────────────────────────────────

/// Minimizes a corpus to the smallest set of seeds that preserves full coverage.
pub struct CorpusMinimizer;

impl CorpusMinimizer {
    /// Greedy set-cover minimization: repeatedly select the seed that covers
    /// the most currently uncovered edges.
    #[must_use] 
    pub fn minimize<'a>(
        _seeds: &'a [(u64, Vec<u8>)],
        coverage: &'a [(u64, Vec<usize>)], // (seed_id, edge_indices)
        total_edges: usize,
    ) -> Vec<u64> {
        let mut covered: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut selected: Vec<u64> = Vec::new();
        let mut remaining: Vec<&(u64, Vec<usize>)> = coverage.iter().collect();

        while covered.len() < total_edges && !remaining.is_empty() {
            // Find seed that covers the most new edges
            let best_idx = remaining.iter().enumerate()
                .max_by_key(|(_, (_, edges))| edges.iter().filter(|e| !covered.contains(e)).count())
                .map(|(i, _)| i);

            if let Some(idx) = best_idx {
                let (id, edges) = remaining.remove(idx);
                let new_edges: usize = edges.iter().filter(|&&e| covered.insert(e)).count();
                if new_edges > 0 { selected.push(*id); }
            } else {
                break;
            }
        }
        selected
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pc_table_parse_64bit() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x4000u64.to_le_bytes()); // pc
        bytes.extend_from_slice(&0x1u64.to_le_bytes());    // flags: FUNC_ENTRY
        bytes.extend_from_slice(&0x4010u64.to_le_bytes()); // pc
        bytes.extend_from_slice(&0x2u64.to_le_bytes());    // flags: BB_ENTRY
        let table = parse_pc_table(&bytes, 8);
        assert_eq!(table.len(), 2);
        assert_eq!(table[0].pc, 0x4000);
        assert!(table[0].flags.contains(PcFlags::FUNC_ENTRY));
        assert_eq!(table[1].flags, PcFlags::BB_ENTRY);
    }

    #[test]
    fn test_coverage_tracker_new_edges() {
        let mut tracker = CoverageTracker::new(256);
        let mut snap = vec![0u8; 256];
        snap[10] = 1;
        snap[20] = 1;
        let (new, indices) = tracker.record_run(1, &snap);
        assert_eq!(new, 2);
        assert!(indices.contains(&10));

        // Second run: same coverage → no new edges
        let (new2, _) = tracker.record_run(2, &snap);
        assert_eq!(new2, 0);
    }

    #[test]
    fn test_branch_edge_index() {
        let t = BranchTuple::new(0x4000, 0x4010);
        let idx = t.edge_index(65536);
        assert!(idx < 65536);
    }

    #[test]
    fn test_cmplog_extraction() {
        let mut analyzer = CmpLogAnalyzer::default();
        let entries = vec![
            CmpEntry { pc: 0x1000, lhs: CmpOperand::U32(0xdead_beef), rhs: CmpOperand::U32(0), hit_count: 3 },
            CmpEntry { pc: 0x1008, lhs: CmpOperand::Bytes(b"PNG".to_vec()), rhs: CmpOperand::Bytes(b"GIF".to_vec()), hit_count: 1 },
        ];
        analyzer.record_entries(entries);
        let bytes = analyzer.extract_interesting_bytes();
        assert!(bytes.iter().any(|b| b == &0xdead_beef_u32.to_le_bytes().to_vec()));
    }

    #[test]
    fn test_coverage_shm_reset() {
        let shm = CoverageShm::new();
        shm.bitmap[5].store(0xff, Ordering::Relaxed);
        assert_eq!(shm.count_edges(), 1);
        shm.reset();
        assert_eq!(shm.count_edges(), 0);
    }

    #[test]
    fn test_iteration_feedback_display() {
        let fb = IterationFeedback {
            run_id: 42, input_hash: 0, input_len: 128, new_edges: 3,
            total_edges_seen: 100, new_branches: 1, has_crash: false, exec_time_us: 500,
        };
        let s = fb.to_string();
        assert!(s.contains("new_edges=3"));
        assert!(s.contains("crash=false"));
    }
}
