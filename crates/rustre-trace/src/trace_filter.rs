//! Trace filter and analysis.
//!
//! Provides [`TraceFilter`], [`FilteredTrace`], [`TraceStats`], [`TraceWindow`],
//! and [`HotPath`] analysis for execution traces.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};

// ─── InstructionType ─────────────────────────────────────────────────────────

/// Classification of a trace instruction for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstructionType {
    /// Direct or indirect call.
    Call,
    /// Return instruction.
    Return,
    /// Unconditional branch.
    Branch,
    /// Conditional branch.
    ConditionalBranch,
    /// System call / interrupt.
    SysCall,
    /// Memory read.
    Load,
    /// Memory write.
    Store,
    /// Arithmetic/logic operation.
    Alu,
    /// All other instructions.
    Other,
}

// ─── TraceEntry ──────────────────────────────────────────────────────────────

/// A single record in a trace — used by this module for filtering.
/// (More complete trace events live in the main lib.rs.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Sequential index within the raw trace.
    pub index: u64,
    /// Program counter.
    pub pc: u64,
    /// Module name this PC belongs to.
    pub module: String,
    /// Thread ID.
    pub thread_id: u64,
    /// Instruction type.
    pub insn_type: InstructionType,
    /// Optional call target (for Call instructions).
    pub call_target: Option<u64>,
    /// Optional memory address (for Load/Store).
    pub mem_addr: Option<u64>,
}

impl TraceEntry {
    /// Create a simple instruction entry.
    #[must_use]
    pub fn instruction(index: u64, pc: u64, module: impl Into<String>, thread_id: u64) -> Self {
        Self {
            index,
            pc,
            module: module.into(),
            thread_id,
            insn_type: InstructionType::Alu,
            call_target: None,
            mem_addr: None,
        }
    }

    /// Create a call entry.
    #[must_use]
    pub fn call(
        index: u64,
        pc: u64,
        target: u64,
        module: impl Into<String>,
        thread_id: u64,
    ) -> Self {
        Self {
            index,
            pc,
            module: module.into(),
            thread_id,
            insn_type: InstructionType::Call,
            call_target: Some(target),
            mem_addr: None,
        }
    }

    /// Create a return entry.
    #[must_use]
    pub fn ret(index: u64, pc: u64, module: impl Into<String>, thread_id: u64) -> Self {
        Self {
            index,
            pc,
            module: module.into(),
            thread_id,
            insn_type: InstructionType::Return,
            call_target: None,
            mem_addr: None,
        }
    }
}

impl std::str::FromStr for InstructionType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "call" => Ok(Self::Call),
            "return" | "ret" => Ok(Self::Return),
            "branch" | "jmp" => Ok(Self::Branch),
            "cbranch" | "jcc" | "conditional" | "conditionalbranch" => Ok(Self::ConditionalBranch),
            "syscall" | "int" => Ok(Self::SysCall),
            "load" => Ok(Self::Load),
            "store" => Ok(Self::Store),
            "alu" => Ok(Self::Alu),
            "other" => Ok(Self::Other),
            _ => Err(()),
        }
    }
}

// ─── AddressRangeFilter ───────────────────────────────────────────────────────

/// Filter by a set of address ranges.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressRangeFilter {
    pub ranges: Vec<(u64, u64)>,
}

impl AddressRangeFilter {
    /// Create an empty filter (passes everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a range (inclusive).
    #[must_use]
    pub fn with_range(mut self, start: u64, end: u64) -> Self {
        self.ranges.push((start, end));
        self
    }

    /// Return true if `pc` is within any of the registered ranges.
    #[must_use]
    pub fn matches(&self, pc: u64) -> bool {
        if self.ranges.is_empty() {
            return true; // empty = pass all
        }
        self.ranges.iter().any(|(s, e)| pc >= *s && pc <= *e)
    }
}

// ─── TraceFilter ─────────────────────────────────────────────────────────────

/// Multi-criteria filter for execution trace entries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceFilter {
    /// Only include entries within these address ranges.
    pub address_range: Option<AddressRangeFilter>,
    /// Only include entries for these module names.
    pub modules: Option<HashSet<String>>,
    /// Only include entries for these thread IDs.
    pub thread_ids: Option<HashSet<u64>>,
    /// Only include entries of these instruction types.
    pub instruction_types: Option<HashSet<InstructionType>>,
    /// Exclude entries from these modules.
    pub exclude_modules: Option<HashSet<String>>,
    /// Minimum trace index (inclusive).
    pub index_min: Option<u64>,
    /// Maximum trace index (inclusive).
    pub index_max: Option<u64>,
}

impl TraceFilter {
    /// Create an empty (pass-all) filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to an address range.
    #[must_use]
    pub fn in_range(mut self, start: u64, end: u64) -> Self {
        let mut rf = self.address_range.unwrap_or_default();
        rf.ranges.push((start, end));
        self.address_range = Some(rf);
        self
    }

    /// Restrict to a module.
    #[must_use]
    pub fn in_module(mut self, module: impl Into<String>) -> Self {
        self.modules
            .get_or_insert_with(HashSet::new)
            .insert(module.into());
        self
    }

    /// Restrict to a thread.
    #[must_use]
    pub fn in_thread(mut self, tid: u64) -> Self {
        self.thread_ids.get_or_insert_with(HashSet::new).insert(tid);
        self
    }

    /// Restrict to instruction types.
    #[must_use]
    pub fn of_type(mut self, t: InstructionType) -> Self {
        self.instruction_types
            .get_or_insert_with(HashSet::new)
            .insert(t);
        self
    }

    /// Exclude a module.
    #[must_use]
    pub fn exclude_module(mut self, module: impl Into<String>) -> Self {
        self.exclude_modules
            .get_or_insert_with(HashSet::new)
            .insert(module.into());
        self
    }

    /// Set index range.
    #[must_use]
    pub const fn index_range(mut self, min: u64, max: u64) -> Self {
        self.index_min = Some(min);
        self.index_max = Some(max);
        self
    }

    /// Return true if a trace entry passes this filter.
    #[must_use]
    pub fn matches(&self, entry: &TraceEntry) -> bool {
        // Index range check
        if let Some(min) = self.index_min
            && entry.index < min
        {
            return false;
        }
        if let Some(max) = self.index_max
            && entry.index > max
        {
            return false;
        }
        // Address range check
        if let Some(ref rf) = self.address_range
            && !rf.matches(entry.pc)
        {
            return false;
        }
        // Module include check
        if let Some(ref mods) = self.modules
            && !mods.contains(&entry.module)
        {
            return false;
        }
        // Module exclude check
        if let Some(ref excl) = self.exclude_modules
            && excl.contains(&entry.module)
        {
            return false;
        }
        // Thread check
        if let Some(ref tids) = self.thread_ids
            && !tids.contains(&entry.thread_id)
        {
            return false;
        }
        // Instruction type check
        if let Some(ref types) = self.instruction_types
            && !types.contains(&entry.insn_type)
        {
            return false;
        }
        true
    }
}

// ─── FilteredTrace ───────────────────────────────────────────────────────────

/// A filtered view of a trace.
#[derive(Debug, Clone)]
pub struct FilteredTrace {
    /// The filtered entries.
    pub entries: Vec<TraceEntry>,
    /// The filter that was applied.
    pub filter: TraceFilter,
}

impl FilteredTrace {
    /// Apply a filter to a slice of trace entries.
    #[must_use]
    pub fn apply(entries: &[TraceEntry], filter: TraceFilter) -> Self {
        let filtered: Vec<TraceEntry> = entries
            .iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect();
        Self {
            entries: filtered,
            filter,
        }
    }

    /// Return the number of filtered entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return unique PCs in this filtered trace.
    #[must_use]
    pub fn unique_pcs(&self) -> HashSet<u64> {
        self.entries.iter().map(|e| e.pc).collect()
    }
}

// ─── TraceStats ──────────────────────────────────────────────────────────────

/// Statistics over a trace or filtered trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStats {
    /// Total instruction count.
    pub total_instructions: u64,
    /// Number of unique PCs executed.
    pub unique_pcs: u64,
    /// Number of unique modules covered.
    pub unique_modules: u64,
    /// Number of unique threads.
    pub unique_threads: u64,
    /// Instructions per module.
    pub instructions_per_module: HashMap<String, u64>,
    /// Instructions per thread.
    pub instructions_per_thread: HashMap<u64, u64>,
    /// Count per instruction type.
    pub type_counts: HashMap<String, u64>,
    /// Top N hot PCs (pc → hit count).
    pub hot_pcs: Vec<(u64, u64)>,
}

impl TraceStats {
    /// Compute statistics from a slice of trace entries.
    #[must_use]
    pub fn compute(entries: &[TraceEntry]) -> Self {
        let mut stats = Self::default();
        let mut pc_counts: HashMap<u64, u64> = HashMap::new();
        let mut modules = HashSet::new();
        let mut threads = HashSet::new();

        for entry in entries {
            stats.total_instructions += 1;
            *pc_counts.entry(entry.pc).or_insert(0) += 1;
            modules.insert(entry.module.clone());
            threads.insert(entry.thread_id);
            *stats
                .instructions_per_module
                .entry(entry.module.clone())
                .or_insert(0) += 1;
            *stats
                .instructions_per_thread
                .entry(entry.thread_id)
                .or_insert(0) += 1;
            let type_key = format!("{:?}", entry.insn_type);
            *stats.type_counts.entry(type_key).or_insert(0) += 1;
        }

        stats.unique_pcs = pc_counts.len() as u64;
        stats.unique_modules = modules.len() as u64;
        stats.unique_threads = threads.len() as u64;

        // Top 20 hot PCs
        let mut sorted: Vec<(u64, u64)> = pc_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        stats.hot_pcs = sorted.into_iter().take(20).collect();

        stats
    }

    /// Return the most-executed module.
    #[must_use]
    pub fn hottest_module(&self) -> Option<(&str, u64)> {
        self.instructions_per_module
            .iter()
            .max_by_key(|&(_, &c)| c)
            .map(|(m, &c)| (m.as_str(), c))
    }

    /// Return the coverage percentage (unique PCs / total).
    #[must_use]
    pub fn coverage_ratio(&self) -> f64 {
        if self.total_instructions == 0 {
            0.0
        } else {
            self.unique_pcs as f64 / self.total_instructions as f64
        }
    }
}

// ─── TraceWindow ─────────────────────────────────────────────────────────────

/// A slice of a trace by time (instruction index) or instruction count.
#[derive(Debug, Clone)]
pub struct TraceWindow<'a> {
    entries: &'a [TraceEntry],
    start: usize,
    end: usize,
}

impl<'a> TraceWindow<'a> {
    /// Create a window over entries [`start_idx`, `end_idx`).
    #[must_use]
    pub fn new(entries: &'a [TraceEntry], start_idx: usize, end_idx: usize) -> Self {
        let end = end_idx.min(entries.len());
        let start = start_idx.min(end);
        Self {
            entries,
            start,
            end,
        }
    }

    /// Create a window by instruction count from the start.
    #[must_use]
    pub fn first_n(entries: &'a [TraceEntry], n: usize) -> Self {
        Self::new(entries, 0, n)
    }

    /// Create a window by instruction count from the end.
    #[must_use]
    pub fn last_n(entries: &'a [TraceEntry], n: usize) -> Self {
        let start = entries.len().saturating_sub(n);
        Self::new(entries, start, entries.len())
    }

    /// Return the entries in this window.
    #[must_use]
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries[self.start..self.end]
    }

    /// Return the number of entries in this window.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end - self.start
    }

    /// Return true if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Compute statistics for this window.
    #[must_use]
    pub fn stats(&self) -> TraceStats {
        TraceStats::compute(self.entries())
    }

    /// Return the inclusive index range covered by this window — convenient
    /// for callers that want to slice parallel arrays (e.g. annotations)
    /// using the same bounds.
    #[must_use]
    pub const fn index_range(&self) -> RangeInclusive<usize> {
        let last = if self.end == 0 { 0 } else { self.end - 1 };
        self.start..=last
    }

    /// Histogram of program counters in this window, ordered by ascending PC
    /// for stable iteration (useful when diffing two windows side-by-side).
    #[must_use]
    pub fn pc_histogram(&self) -> BTreeMap<u64, u64> {
        let mut h: BTreeMap<u64, u64> = BTreeMap::new();
        for e in self.entries() {
            *h.entry(e.pc).or_insert(0) += 1;
        }
        h
    }
}

// ─── HotPath ─────────────────────────────────────────────────────────────────

/// A hot execution path — a sequence of PCs frequently traversed together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPath {
    /// The sequence of PCs.
    pub pcs: Vec<u64>,
    /// Number of times this path was observed.
    pub hit_count: u64,
    /// Total instruction count for this path.
    pub total_instructions: u64,
}

impl HotPath {
    /// Return the length of the path (number of PCs).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pcs.len()
    }

    /// Return true if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pcs.is_empty()
    }

    /// Return instructions per hit.
    #[must_use]
    pub fn avg_instructions(&self) -> f64 {
        if self.hit_count == 0 {
            0.0
        } else {
            self.total_instructions as f64 / self.hit_count as f64
        }
    }
}

/// Analyse a trace for hot paths (sequences of consecutive PCs).
pub struct HotPathAnalyzer {
    /// Minimum sequence length to report.
    pub min_length: usize,
    /// Minimum hit count to report.
    pub min_hits: u64,
    /// Maximum number of paths to return.
    pub top_n: usize,
}

impl Default for HotPathAnalyzer {
    fn default() -> Self {
        Self {
            min_length: 3,
            min_hits: 2,
            top_n: 10,
        }
    }
}

impl HotPathAnalyzer {
    /// Create an analyser with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Find hot PC pairs (bigrams) in the trace.
    ///
    /// Returns a list of (`from_pc`, `to_pc`, count) sorted by count.
    #[must_use]
    pub fn hot_bigrams(&self, entries: &[TraceEntry]) -> Vec<(u64, u64, u64)> {
        let mut counts: HashMap<(u64, u64), u64> = HashMap::new();
        for w in entries.windows(2) {
            *counts.entry((w[0].pc, w[1].pc)).or_insert(0) += 1;
        }
        let mut sorted: Vec<(u64, u64, u64)> = counts
            .into_iter()
            .filter(|((_, _), c)| *c >= self.min_hits)
            .map(|((a, b), c)| (a, b, c))
            .collect();
        sorted.sort_by(|a, b| b.2.cmp(&a.2));
        sorted.truncate(self.top_n);
        sorted
    }

    /// Find hot PC frequencies.
    #[must_use]
    pub fn hot_pcs(&self, entries: &[TraceEntry]) -> Vec<(u64, u64)> {
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for e in entries {
            *counts.entry(e.pc).or_insert(0) += 1;
        }
        let mut sorted: Vec<(u64, u64)> = counts
            .into_iter()
            .filter(|(_, c)| *c >= self.min_hits)
            .collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(self.top_n);
        sorted
    }

    /// Detect loops: addresses that appear more than once with a small index gap.
    #[must_use]
    pub fn detect_loops(&self, entries: &[TraceEntry], max_gap: usize) -> Vec<(u64, u64)> {
        let mut loops: Vec<(u64, u64)> = Vec::new();
        let mut last_seen: HashMap<u64, usize> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            if let Some(&prev) = last_seen.get(&e.pc) {
                let gap = i - prev;
                if gap <= max_gap && gap > 0 {
                    loops.push((e.pc, gap as u64));
                }
            }
            last_seen.insert(e.pc, i);
        }
        loops.sort_by_key(|l| l.0);
        loops.dedup_by_key(|l| l.0);
        loops
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace(n: usize, base_pc: u64, module: &str) -> Vec<TraceEntry> {
        (0..n as u64)
            .map(|i| TraceEntry::instruction(i, base_pc + i * 4, module, 1))
            .collect()
    }

    fn mixed_trace() -> Vec<TraceEntry> {
        let mut entries = Vec::new();
        for i in 0..10u64 {
            entries.push(TraceEntry::instruction(
                i * 2,
                0x1000 + i * 4,
                "main.exe",
                i % 3,
            ));
            entries.push(TraceEntry {
                index: i * 2 + 1,
                pc: 0x5000,
                module: "ntdll.dll".to_owned(),
                thread_id: i % 3,
                insn_type: InstructionType::Call,
                call_target: Some(0x6000),
                mem_addr: None,
            });
        }
        entries
    }

    #[test]
    fn test_address_range_filter_matches() {
        let f = AddressRangeFilter::new().with_range(0x1000, 0x2000);
        assert!(f.matches(0x1000));
        assert!(f.matches(0x1500));
        assert!(f.matches(0x2000));
        assert!(!f.matches(0x2001));
        assert!(!f.matches(0x0FFF));
    }

    #[test]
    fn test_address_range_filter_empty_passes_all() {
        let f = AddressRangeFilter::new();
        assert!(f.matches(0xFFFF_FFFF_FFFF_FFFF));
    }

    #[test]
    fn test_trace_filter_by_module() {
        let trace = mixed_trace();
        let filter = TraceFilter::new().in_module("main.exe");
        let filtered = FilteredTrace::apply(&trace, filter);
        assert!(filtered.entries.iter().all(|e| e.module == "main.exe"));
    }

    #[test]
    fn test_trace_filter_by_thread() {
        let trace = mixed_trace();
        let filter = TraceFilter::new().in_thread(0);
        let filtered = FilteredTrace::apply(&trace, filter);
        assert!(filtered.entries.iter().all(|e| e.thread_id == 0));
    }

    #[test]
    fn test_trace_filter_exclude_module() {
        let trace = mixed_trace();
        let filter = TraceFilter::new().exclude_module("ntdll.dll");
        let filtered = FilteredTrace::apply(&trace, filter);
        assert!(filtered.entries.iter().all(|e| e.module != "ntdll.dll"));
    }

    #[test]
    fn test_trace_filter_by_type() {
        let trace = mixed_trace();
        let filter = TraceFilter::new().of_type(InstructionType::Call);
        let filtered = FilteredTrace::apply(&trace, filter);
        assert!(
            filtered
                .entries
                .iter()
                .all(|e| e.insn_type == InstructionType::Call)
        );
    }

    #[test]
    fn test_trace_filter_by_range() {
        let trace = make_trace(20, 0x1000, "test");
        let filter = TraceFilter::new().in_range(0x1000, 0x1020);
        let filtered = FilteredTrace::apply(&trace, filter);
        assert!(
            filtered
                .entries
                .iter()
                .all(|e| e.pc >= 0x1000 && e.pc <= 0x1020)
        );
    }

    #[test]
    fn test_trace_filter_by_index_range() {
        let trace = make_trace(100, 0x1000, "test");
        let filter = TraceFilter::new().index_range(10, 20);
        let filtered = FilteredTrace::apply(&trace, filter);
        assert!(
            filtered
                .entries
                .iter()
                .all(|e| e.index >= 10 && e.index <= 20)
        );
        assert_eq!(filtered.len(), 11);
    }

    #[test]
    fn test_trace_stats_compute() {
        let trace = make_trace(100, 0x1000, "main");
        let stats = TraceStats::compute(&trace);
        assert_eq!(stats.total_instructions, 100);
        assert_eq!(stats.unique_modules, 1);
        assert_eq!(stats.unique_threads, 1);
        assert!(stats.unique_pcs <= 100);
    }

    #[test]
    fn test_trace_stats_hottest_module() {
        let trace = mixed_trace();
        let stats = TraceStats::compute(&trace);
        let (module, _count) = stats.hottest_module().unwrap();
        assert!(!module.is_empty());
    }

    #[test]
    fn test_trace_stats_coverage_ratio() {
        let mut trace = make_trace(10, 0x1000, "t");
        // All same PC → ratio = 1/10
        for e in &mut trace {
            e.pc = 0x1000;
        }
        let stats = TraceStats::compute(&trace);
        assert!((stats.coverage_ratio() - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_trace_window_first_n() {
        let trace = make_trace(100, 0x1000, "t");
        let win = TraceWindow::first_n(&trace, 10);
        assert_eq!(win.len(), 10);
        assert_eq!(win.entries()[0].pc, 0x1000);
    }

    #[test]
    fn test_trace_window_last_n() {
        let trace = make_trace(100, 0x1000, "t");
        let win = TraceWindow::last_n(&trace, 5);
        assert_eq!(win.len(), 5);
    }

    #[test]
    fn test_trace_window_stats() {
        let trace = make_trace(50, 0x2000, "mod");
        let win = TraceWindow::first_n(&trace, 20);
        let stats = win.stats();
        assert_eq!(stats.total_instructions, 20);
    }

    #[test]
    fn test_hot_path_bigrams() {
        let trace = vec![
            TraceEntry::instruction(0, 0x1000, "t", 1),
            TraceEntry::instruction(1, 0x1004, "t", 1),
            TraceEntry::instruction(2, 0x1000, "t", 1),
            TraceEntry::instruction(3, 0x1004, "t", 1),
            TraceEntry::instruction(4, 0x1000, "t", 1),
            TraceEntry::instruction(5, 0x1004, "t", 1),
        ];
        let analyzer = HotPathAnalyzer {
            min_hits: 2,
            ..Default::default()
        };
        let bigrams = analyzer.hot_bigrams(&trace);
        assert!(!bigrams.is_empty());
        assert!(
            bigrams
                .iter()
                .any(|(a, b, c)| *a == 0x1000 && *b == 0x1004 && *c >= 2)
        );
    }

    #[test]
    fn test_hot_path_pcs() {
        let trace = make_trace(10, 0x1000, "t");
        let mut trace2 = trace;
        // Make PC 0x1000 appear multiple times
        for e in &mut trace2 {
            e.pc = 0x1000;
        }
        let analyzer = HotPathAnalyzer::new();
        let pcs = analyzer.hot_pcs(&trace2);
        assert!(!pcs.is_empty());
        assert_eq!(pcs[0].0, 0x1000);
    }

    #[test]
    fn test_detect_loops() {
        let trace = vec![
            TraceEntry::instruction(0, 0x1000, "t", 1),
            TraceEntry::instruction(1, 0x1004, "t", 1),
            TraceEntry::instruction(2, 0x1000, "t", 1), // loop back
            TraceEntry::instruction(3, 0x1004, "t", 1),
        ];
        let analyzer = HotPathAnalyzer::new();
        let loops = analyzer.detect_loops(&trace, 5);
        assert!(loops.iter().any(|(pc, _)| *pc == 0x1000));
    }

    #[test]
    fn test_filtered_trace_unique_pcs() {
        let trace = make_trace(20, 0x1000, "main");
        let filter = TraceFilter::new();
        let filtered = FilteredTrace::apply(&trace, filter);
        let pcs = filtered.unique_pcs();
        assert_eq!(pcs.len(), filtered.len()); // all different PCs
    }

    #[test]
    fn test_hot_path_avg_instructions() {
        let path = HotPath {
            pcs: vec![0x1000, 0x1004],
            hit_count: 10,
            total_instructions: 50,
        };
        assert_eq!(path.avg_instructions(), 5.0);
    }
}
