//! Trace hot-spot analysis: hot functions, basic-block coverage, and call frequency.
//!
//! `TraceHotSpots` provides richer statistics than the raw `CoverageMap`:
//! - Per-function execution counts and total instruction budget.
//! - Basic-block-level coverage with branch-taken ratios.
//! - Call frequency tables keyed by (caller, callee) address pairs.
//! - `FrequencyTable<K>` — a generic hit-counter map.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{TraceEvent, TraceSession};

// ─── FrequencyTable ──────────────────────────────────────────────────────────

/// Generic frequency counter.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrequencyTable<K: std::hash::Hash + Eq + Clone + Serialize> {
    counts: HashMap<K, u64>,
}

impl<K: std::hash::Hash + Eq + Clone + Serialize + for<'de> serde::Deserialize<'de>> FrequencyTable<K> {
    pub fn new() -> Self {
        Self { counts: HashMap::new() }
    }

    pub fn increment(&mut self, key: K) {
        *self.counts.entry(key).or_insert(0) += 1;
    }

    pub fn add(&mut self, key: K, n: u64) {
        *self.counts.entry(key).or_insert(0) += n;
    }

    pub fn get(&self, key: &K) -> u64 {
        self.counts.get(key).copied().unwrap_or(0)
    }

    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&K, u64)> {
        self.counts.iter().map(|(k, &v)| (k, v))
    }

    /// Return all entries sorted by count descending.
    pub fn top_n(&self, n: usize) -> Vec<(&K, u64)>
    where
        K: Ord,
    {
        let mut pairs: Vec<(&K, u64)> =
            self.counts.iter().map(|(k, &v)| (k, v)).collect();
        if n < pairs.len() {
            pairs.select_nth_unstable_by(n, |a, b| b.1.cmp(&a.1));
            pairs.truncate(n);
        }
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        pairs
    }

    /// Merge another table into this one.
    pub fn merge(&mut self, other: &Self) {
        for (k, &v) in &other.counts {
            *self.counts.entry(k.clone()).or_insert(0) += v;
        }
    }

    /// Clear all counts.
    pub fn clear(&mut self) {
        self.counts.clear();
    }
}

// ─── HotSpot ─────────────────────────────────────────────────────────────────

/// A single hot function or basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotSpot {
    /// Address of the function entry or basic-block start.
    pub address: u64,
    /// Human-readable name, if known.
    pub name: Option<String>,
    /// Total number of times this location was executed.
    pub execution_count: u64,
    /// Fraction of total instruction count (0.0–1.0).
    pub fraction: f64,
    /// Sum of instruction counts inside this region.
    pub instruction_budget: u64,
}

impl HotSpot {
    pub fn new(address: u64, execution_count: u64, total_instructions: u64) -> Self {
        let fraction = if total_instructions == 0 {
            0.0
        } else {
            execution_count as f64 / total_instructions as f64
        };
        Self {
            address,
            name: None,
            execution_count,
            fraction,
            instruction_budget: execution_count,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("0x{:x}", self.address))
    }
}

// ─── BasicBlockCoverage ──────────────────────────────────────────────────────

/// Coverage information for a single basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlockCoverage {
    pub start_addr: u64,
    pub end_addr: u64,
    pub hit_count: u64,
    pub taken_count: u64,
    pub not_taken_count: u64,
}

impl BasicBlockCoverage {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start_addr: start,
            end_addr: end,
            hit_count: 0,
            taken_count: 0,
            not_taken_count: 0,
        }
    }

    pub fn was_hit(&self) -> bool {
        self.hit_count > 0
    }

    pub fn taken_ratio(&self) -> f64 {
        let total = self.taken_count + self.not_taken_count;
        if total == 0 { 0.0 } else { self.taken_count as f64 / total as f64 }
    }
}

// ─── CoverageMap (extended) ─────────────────────────────────────────────────

/// Tracks basic-block coverage over a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasicBlockCoverageMap {
    blocks: HashMap<u64, BasicBlockCoverage>,
}

impl BasicBlockCoverageMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a hit on a basic block starting at `start`.
    pub fn record_block_hit(&mut self, start: u64, end: u64) {
        let bb = self.blocks.entry(start).or_insert_with(|| BasicBlockCoverage::new(start, end));
        bb.hit_count += 1;
    }

    /// Record a branch outcome.
    pub fn record_branch(&mut self, from: u64, taken: bool) {
        if let Some(bb) = self.blocks.get_mut(&from) {
            if taken { bb.taken_count += 1; } else { bb.not_taken_count += 1; }
        }
    }

    pub fn coverage_ratio(&self, known_block_count: usize) -> f64 {
        if known_block_count == 0 { return 0.0; }
        self.blocks.values().filter(|b| b.was_hit()).count() as f64 / known_block_count as f64
    }

    pub fn hit_count(&self) -> usize {
        self.blocks.values().filter(|b| b.was_hit()).count()
    }

    pub fn total_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub fn hottest_block(&self) -> Option<&BasicBlockCoverage> {
        self.blocks.values().max_by_key(|b| b.hit_count)
    }

    pub fn build_from_session(session: &TraceSession) -> Self {
        let mut map = Self::new();
        let mut last_instr_addr: Option<u64> = None;
        for rec in &session.records {
            match rec.event {
                TraceEvent::Instruction { addr, .. } => {
                    if let Some(prev) = last_instr_addr {
                        map.record_block_hit(prev, addr);
                    }
                    last_instr_addr = Some(addr);
                }
                TraceEvent::Branch { from, taken, .. } => {
                    map.record_branch(from, taken);
                }
                _ => {}
            }
        }
        map
    }
}

// ─── TraceHotSpots ──────────────────────────────────────────────────────────

/// Main struct for hot-spot analysis over a trace session.
pub struct TraceHotSpots {
    /// Per-address instruction frequency.
    pub instruction_freq: FrequencyTable<u64>,
    /// Per-(caller,callee) call frequency.
    pub call_freq: FrequencyTable<(u64, u64)>,
    /// Per-syscall number frequency.
    pub syscall_freq: FrequencyTable<u64>,
    /// Basic-block coverage.
    pub bb_coverage: BasicBlockCoverageMap,
    /// Total instruction events analyzed.
    pub total_instructions: u64,
    /// Total call events.
    pub total_calls: u64,
}

impl TraceHotSpots {
    pub fn new() -> Self {
        Self {
            instruction_freq: FrequencyTable::new(),
            call_freq: FrequencyTable::new(),
            syscall_freq: FrequencyTable::new(),
            bb_coverage: BasicBlockCoverageMap::new(),
            total_instructions: 0,
            total_calls: 0,
        }
    }

    /// Build hot-spot data from a session.
    pub fn build(session: &TraceSession) -> Self {
        let mut hs = Self::new();
        let mut last_instr: Option<u64> = None;

        for rec in &session.records {
            match &rec.event {
                TraceEvent::Instruction { addr, .. } => {
                    hs.instruction_freq.increment(*addr);
                    hs.total_instructions += 1;
                    if let Some(prev) = last_instr {
                        hs.bb_coverage.record_block_hit(prev, *addr);
                    }
                    last_instr = Some(*addr);
                }
                TraceEvent::Call { from, to } => {
                    hs.call_freq.increment((*from, *to));
                    hs.total_calls += 1;
                }
                TraceEvent::Syscall { number, .. } => {
                    hs.syscall_freq.increment(*number);
                }
                TraceEvent::Branch { from, taken, .. } => {
                    hs.bb_coverage.record_branch(*from, *taken);
                }
                _ => {}
            }
        }
        hs
    }

    /// Return the top-N hottest instruction addresses.
    pub fn top_hot_addresses(&self, n: usize) -> Vec<HotSpot> {
        let total = self.total_instructions;
        self.instruction_freq
            .top_n(n)
            .into_iter()
            .map(|(&addr, count)| HotSpot::new(addr, count, total))
            .collect()
    }

    /// Return the top-N most-called (caller, callee) pairs.
    pub fn top_call_edges(&self, n: usize) -> Vec<((u64, u64), u64)> {
        self.call_freq
            .top_n(n)
            .into_iter()
            .map(|(&pair, count)| (pair, count))
            .collect()
    }

    /// Return the top-N most common syscalls.
    pub fn top_syscalls(&self, n: usize) -> Vec<(u64, u64)> {
        self.syscall_freq
            .top_n(n)
            .into_iter()
            .map(|(&num, count)| (num, count))
            .collect()
    }

    /// How many unique addresses were executed.
    pub fn unique_addresses(&self) -> usize {
        self.instruction_freq.len()
    }

    /// Coverage percentage over a known total.
    pub fn coverage_percent(&self, known_total: usize) -> f64 {
        if known_total == 0 { return 100.0; }
        self.unique_addresses() as f64 / known_total as f64 * 100.0
    }

    /// Merge another `TraceHotSpots` into this one.
    pub fn merge(&mut self, other: &Self) {
        self.instruction_freq.merge(&other.instruction_freq);
        self.call_freq.merge(&other.call_freq);
        self.syscall_freq.merge(&other.syscall_freq);
        self.total_instructions += other.total_instructions;
        self.total_calls += other.total_calls;
    }

    /// Build a summary suitable for display.
    pub fn summary_text(&self, top_n: usize) -> String {
        let mut lines = vec![
            format!("=== Trace Hot-Spot Analysis ==="),
            format!("Total instructions: {}", self.total_instructions),
            format!("Unique addresses:   {}", self.unique_addresses()),
            format!("Total calls:        {}", self.total_calls),
            String::new(),
            format!("Top-{} hot addresses:", top_n),
        ];
        for hs in self.top_hot_addresses(top_n) {
            lines.push(format!(
                "  0x{:x}  {:>8} hits  ({:.2}%)",
                hs.address, hs.execution_count, hs.fraction * 100.0
            ));
        }
        lines.push(String::new());
        lines.push(format!("Top-{} call edges:", top_n));
        for ((from, to), count) in self.top_call_edges(top_n) {
            lines.push(format!("  0x{:x} → 0x{:x}  {}", from, to, count));
        }
        lines.join("\n")
    }
}

impl Default for TraceHotSpots {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TraceSession;

    fn make_session() -> TraceSession {
        let mut s = TraceSession::new("test", "x86_64");
        // Loop: 0x1000 appears 5 times
        for i in 0u64..5 {
            s.push(TraceEvent::Instruction { addr: 0x1000, size: 4 }, 1, i * 100);
        }
        // 0x1004 appears 3 times
        for i in 0u64..3 {
            s.push(TraceEvent::Instruction { addr: 0x1004, size: 4 }, 1, 1000 + i * 100);
        }
        // Two call edges
        s.push(TraceEvent::Call { from: 0x1008, to: 0x2000 }, 1, 2000);
        s.push(TraceEvent::Call { from: 0x1008, to: 0x2000 }, 1, 2100);
        s.push(TraceEvent::Call { from: 0x100c, to: 0x3000 }, 1, 2200);
        // Syscalls
        s.push(TraceEvent::Syscall { number: 1, args: vec![] }, 1, 3000);
        s.push(TraceEvent::Syscall { number: 1, args: vec![] }, 1, 3100);
        s.push(TraceEvent::Syscall { number: 60, args: vec![] }, 1, 3200);
        s
    }

    #[test]
    fn test_frequency_table_increment() {
        let mut ft: FrequencyTable<u64> = FrequencyTable::new();
        ft.increment(1);
        ft.increment(1);
        ft.increment(2);
        assert_eq!(ft.get(&1), 2);
        assert_eq!(ft.get(&2), 1);
        assert_eq!(ft.get(&99), 0);
        assert_eq!(ft.total(), 3);
    }

    #[test]
    fn test_frequency_table_top_n() {
        let mut ft: FrequencyTable<u64> = FrequencyTable::new();
        ft.add(10, 5);
        ft.add(20, 3);
        ft.add(30, 8);
        let top = ft.top_n(2);
        assert_eq!(top.len(), 2);
        assert_eq!(*top[0].0, 30);
        assert_eq!(top[0].1, 8);
    }

    #[test]
    fn test_frequency_table_merge() {
        let mut a: FrequencyTable<u64> = FrequencyTable::new();
        let mut b: FrequencyTable<u64> = FrequencyTable::new();
        a.add(1, 3);
        b.add(1, 2);
        b.add(2, 7);
        a.merge(&b);
        assert_eq!(a.get(&1), 5);
        assert_eq!(a.get(&2), 7);
    }

    #[test]
    fn test_frequency_table_clear() {
        let mut ft: FrequencyTable<u64> = FrequencyTable::new();
        ft.add(1, 10);
        ft.clear();
        assert!(ft.is_empty());
    }

    #[test]
    fn test_hot_spot_fraction() {
        let hs = HotSpot::new(0x1000, 50, 100);
        assert!((hs.fraction - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_hot_spot_zero_total() {
        let hs = HotSpot::new(0x1000, 0, 0);
        assert_eq!(hs.fraction, 0.0);
    }

    #[test]
    fn test_basic_block_coverage_hit() {
        let mut bb = BasicBlockCoverage::new(0x1000, 0x1010);
        assert!(!bb.was_hit());
        bb.hit_count = 3;
        assert!(bb.was_hit());
    }

    #[test]
    fn test_basic_block_coverage_taken_ratio() {
        let mut bb = BasicBlockCoverage::new(0x1000, 0x1010);
        bb.taken_count = 3;
        bb.not_taken_count = 1;
        assert!((bb.taken_ratio() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_bb_coverage_map_build() {
        let session = make_session();
        let map = BasicBlockCoverageMap::build_from_session(&session);
        assert!(map.total_blocks() > 0);
    }

    #[test]
    fn test_trace_hot_spots_build() {
        let session = make_session();
        let hs = TraceHotSpots::build(&session);
        assert_eq!(hs.total_instructions, 8);
        assert_eq!(hs.total_calls, 3);
        assert_eq!(hs.instruction_freq.get(&0x1000), 5);
        assert_eq!(hs.instruction_freq.get(&0x1004), 3);
    }

    #[test]
    fn test_trace_hot_spots_top_hot_addresses() {
        let session = make_session();
        let hs = TraceHotSpots::build(&session);
        let top = hs.top_hot_addresses(1);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].address, 0x1000);
        assert_eq!(top[0].execution_count, 5);
    }

    #[test]
    fn test_trace_hot_spots_top_call_edges() {
        let session = make_session();
        let hs = TraceHotSpots::build(&session);
        let edges = hs.top_call_edges(1);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].0, (0x1008, 0x2000));
        assert_eq!(edges[0].1, 2);
    }

    #[test]
    fn test_trace_hot_spots_syscall_freq() {
        let session = make_session();
        let hs = TraceHotSpots::build(&session);
        assert_eq!(hs.syscall_freq.get(&1), 2);
        assert_eq!(hs.syscall_freq.get(&60), 1);
    }

    #[test]
    fn test_trace_hot_spots_unique_addresses() {
        let session = make_session();
        let hs = TraceHotSpots::build(&session);
        assert_eq!(hs.unique_addresses(), 2); // 0x1000 and 0x1004
    }

    #[test]
    fn test_trace_hot_spots_coverage_percent() {
        let session = make_session();
        let hs = TraceHotSpots::build(&session);
        assert!((hs.coverage_percent(4) - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_trace_hot_spots_merge() {
        let session = make_session();
        let mut a = TraceHotSpots::build(&session);
        let b = TraceHotSpots::build(&session);
        a.merge(&b);
        assert_eq!(a.total_instructions, 16);
        assert_eq!(a.instruction_freq.get(&0x1000), 10);
    }

    #[test]
    fn test_trace_hot_spots_summary_text() {
        let session = make_session();
        let hs = TraceHotSpots::build(&session);
        let text = hs.summary_text(3);
        assert!(text.contains("Trace Hot-Spot Analysis"));
        assert!(text.contains("0x1000"));
    }
}
