// Register Timeline — efficient lookup of register values at any tick.
//
// Stores a sorted list of change-point records for each register.
// Binary search delivers O(log n) point queries and range queries.
// Also supports: register value history, diff between two ticks,
// detecting when a value was last/first written, and export to CSV.

use std::collections::HashMap;

pub type Tick = u64;
pub type RegVal = u64;

// ── Change point ──────────────────────────────────────────────────────────────

/// One recorded change to a register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangePoint {
    pub tick: Tick,
    pub thread_id: u32,
    pub old_value: RegVal,
    pub new_value: RegVal,
    /// Optional: instruction address that caused the change.
    pub pc: Option<u64>,
}

impl ChangePoint {
    #[must_use] 
    pub const fn delta(&self) -> i64 {
        (self.new_value as i64).wrapping_sub(self.old_value as i64)
    }
}

// ── Register timeline ─────────────────────────────────────────────────────────

/// Timeline of changes for a single register.
#[derive(Debug, Default, Clone)]
pub struct RegTimeline {
    /// Sorted by tick (invariant maintained by `record`).
    pub changes: Vec<ChangePoint>,
    /// Value assumed before the first recorded change (usually 0).
    pub initial_value: RegVal,
    pub name: String,
}

impl RegTimeline {
    #[must_use] 
    pub const fn new(name: String, initial_value: RegVal) -> Self {
        Self { changes: Vec::new(), initial_value, name }
    }

    /// Record a register change.  Must be called in tick order (or `finalize()` later).
    pub fn record(&mut self, tick: Tick, thread_id: u32, old_value: RegVal, new_value: RegVal, pc: Option<u64>) {
        self.changes.push(ChangePoint { tick, thread_id, old_value, new_value, pc });
    }

    /// Re-sort change list by tick (call after out-of-order inserts).
    pub fn finalize(&mut self) {
        self.changes.sort_by_key(|c| c.tick);
    }

    /// Return the register value at the given tick using binary search.
    #[must_use] 
    pub fn value_at(&self, tick: Tick) -> RegVal {
        // Find the last change with change.tick <= tick
        match self.changes.partition_point(|c| c.tick <= tick) {
            0 => self.initial_value,
            idx => self.changes[idx - 1].new_value,
        }
    }

    /// Return all changes in [`from_tick`, `to_tick`].
    #[must_use] 
    pub fn changes_in(&self, from: Tick, to: Tick) -> &[ChangePoint] {
        let start = self.changes.partition_point(|c| c.tick < from);
        let end   = self.changes.partition_point(|c| c.tick <= to);
        &self.changes[start..end]
    }

    /// How many times did this register change in range?
    #[must_use] 
    pub fn change_count_in(&self, from: Tick, to: Tick) -> usize {
        self.changes_in(from, to).len()
    }

    /// The tick at which the register first held `value` at or after `from`.
    #[must_use] 
    pub fn first_tick_with_value(&self, value: RegVal, from: Tick) -> Option<Tick> {
        let start = self.changes.partition_point(|c| c.tick < from);
        self.changes[start..].iter()
            .find(|c| c.new_value == value)
            .map(|c| c.tick)
    }

    /// The last tick at which the register held `value` at or before `to`.
    #[must_use] 
    pub fn last_tick_with_value(&self, value: RegVal, to: Tick) -> Option<Tick> {
        let end = self.changes.partition_point(|c| c.tick <= to);
        self.changes[..end].iter().rev()
            .find(|c| c.new_value == value)
            .map(|c| c.tick)
    }

    /// How many distinct values did the register take in range?
    #[must_use] 
    pub fn distinct_values_in(&self, from: Tick, to: Tick) -> usize {
        let mut seen = std::collections::HashSet::new();
        for cp in self.changes_in(from, to) {
            seen.insert(cp.new_value);
        }
        seen.len()
    }

    /// Total number of recorded changes.
    #[must_use] 
    pub const fn total_changes(&self) -> usize { self.changes.len() }

    /// Minimum and maximum values seen.
    #[must_use] 
    pub fn value_range(&self) -> (RegVal, RegVal) {
        let mut lo = self.initial_value;
        let mut hi = self.initial_value;
        for cp in &self.changes {
            if cp.new_value < lo { lo = cp.new_value; }
            if cp.new_value > hi { hi = cp.new_value; }
        }
        (lo, hi)
    }

    /// Check if register ever took a value in [low, high] during [from, to].
    #[must_use] 
    pub fn ever_in_range(&self, low: RegVal, high: RegVal, from: Tick, to: Tick) -> bool {
        self.changes_in(from, to).iter().any(|c| c.new_value >= low && c.new_value <= high)
    }

    /// Export changes in range as CSV rows: tick,thread,old,new,pc
    #[must_use] 
    pub fn to_csv(&self, from: Tick, to: Tick) -> String {
        let mut out = "tick,thread_id,old_value,new_value,pc\n".to_string();
        for cp in self.changes_in(from, to) {
            let pc_str = cp.pc.map_or_else(|| "N/A".into(), |a| format!("{a:#018x}"));
            out.push_str(&format!("{},{},{:#018x},{:#018x},{}\n",
                cp.tick, cp.thread_id, cp.old_value, cp.new_value, pc_str));
        }
        out
    }
}

// ── Multi-register timeline ───────────────────────────────────────────────────

/// Tracks all registers over the entire trace.
#[derive(Debug, Default)]
pub struct RegisterTimeline {
    pub timelines: HashMap<String, RegTimeline>,
    pub first_tick: Tick,
    pub last_tick: Tick,
}

impl RegisterTimeline {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Record a register change event.
    pub fn record(&mut self, tick: Tick, thread_id: u32, reg: &str, old_val: RegVal, new_val: RegVal, pc: Option<u64>) {
        self.timelines.entry(reg.to_string())
            .or_insert_with(|| RegTimeline::new(reg.to_string(), 0))
            .record(tick, thread_id, old_val, new_val, pc);
        if tick > self.last_tick { self.last_tick = tick; }
        if tick < self.first_tick || self.first_tick == 0 { self.first_tick = tick; }
    }

    /// Finalize all timelines (sort by tick).
    pub fn finalize(&mut self) {
        for tl in self.timelines.values_mut() {
            tl.finalize();
        }
    }

    /// Set initial value for a register.
    pub fn set_initial(&mut self, reg: &str, val: RegVal) {
        self.timelines.entry(reg.to_string())
            .or_insert_with(|| RegTimeline::new(reg.to_string(), 0))
            .initial_value = val;
    }

    /// Get the value of `reg` at `tick`.
    #[must_use] 
    pub fn value_at(&self, tick: Tick, reg: &str) -> Option<RegVal> {
        self.timelines.get(reg).map(|tl| tl.value_at(tick))
    }

    /// Get all register values at `tick`.
    #[must_use] 
    pub fn snapshot_at(&self, tick: Tick) -> HashMap<String, RegVal> {
        self.timelines.iter()
            .map(|(k, tl)| (k.clone(), tl.value_at(tick)))
            .collect()
    }

    /// Diff register state between two ticks.  Returns (reg, old, new) for changed regs.
    #[must_use] 
    pub fn diff_ticks(&self, tick_a: Tick, tick_b: Tick) -> Vec<(String, RegVal, RegVal)> {
        let mut diffs = Vec::new();
        for (reg, tl) in &self.timelines {
            let a = tl.value_at(tick_a);
            let b = tl.value_at(tick_b);
            if a != b {
                diffs.push((reg.clone(), a, b));
            }
        }
        diffs.sort_by(|a, b| a.0.cmp(&b.0));
        diffs
    }

    /// Find all ticks in [from, to] at which `reg == value`.
    #[must_use] 
    pub fn ticks_with_value(&self, reg: &str, value: RegVal, from: Tick, to: Tick) -> Vec<Tick> {
        let Some(tl) = self.timelines.get(reg) else { return Vec::new(); };
        tl.changes_in(from, to)
            .iter()
            .filter(|c| c.new_value == value)
            .map(|c| c.tick)
            .collect()
    }

    /// Find all registers that took value `value` at some point in [from, to].
    #[must_use] 
    pub fn regs_with_value(&self, value: RegVal, from: Tick, to: Tick) -> Vec<String> {
        self.timelines.iter()
            .filter(|(_, tl)| tl.changes_in(from, to).iter().any(|c| c.new_value == value))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Total number of register change events across all registers.
    #[must_use] 
    pub fn total_changes(&self) -> u64 {
        self.timelines.values().map(|tl| tl.total_changes() as u64).sum()
    }

    /// Return the most frequently changed registers in [from, to].
    #[must_use] 
    pub fn most_changed(&self, from: Tick, to: Tick, top_n: usize) -> Vec<(String, usize)> {
        let mut counts: Vec<(String, usize)> = self.timelines.iter()
            .map(|(k, tl)| (k.clone(), tl.change_count_in(from, to)))
            .filter(|(_, c)| *c > 0)
            .collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(top_n);
        counts
    }

    /// Detect registers that appear to act as loop counters in [from, to]:
    /// monotonically increasing or decreasing with near-constant step.
    #[must_use] 
    pub fn detect_counters(&self, from: Tick, to: Tick) -> Vec<CounterInfo> {
        let mut result = Vec::new();
        for (reg, tl) in &self.timelines {
            let changes = tl.changes_in(from, to);
            if changes.len() < 4 { continue; }
            if let Some(info) = detect_counter_pattern(reg, changes) {
                result.push(info);
            }
        }
        result
    }

    /// Export a register's changes to CSV.
    #[must_use] 
    pub fn export_csv(&self, reg: &str) -> Option<String> {
        self.timelines.get(reg).map(|tl| tl.to_csv(0, Tick::MAX))
    }
}

// ── Counter detection ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CounterInfo {
    pub reg: String,
    pub initial: RegVal,
    pub final_val: RegVal,
    pub step: i64,
    pub count: usize,
    pub from_tick: Tick,
    pub to_tick: Tick,
}

fn detect_counter_pattern(reg: &str, changes: &[ChangePoint]) -> Option<CounterInfo> {
    if changes.len() < 4 { return None; }
    // Compute deltas
    let deltas: Vec<i64> = changes.windows(2)
        .map(|w| (w[1].new_value as i64).wrapping_sub(w[0].new_value as i64))
        .collect();
    // Check if all deltas are equal (or within 2× tolerance for noise)
    let first_delta = deltas[0];
    if first_delta == 0 { return None; }
    let consistent = deltas.iter().all(|&d| d == first_delta);
    if !consistent { return None; }

    Some(CounterInfo {
        reg: reg.to_string(),
        initial: changes[0].old_value,
        final_val: changes.last().unwrap().new_value,
        step: first_delta,
        count: changes.len(),
        from_tick: changes[0].tick,
        to_tick: changes.last().unwrap().tick,
    })
}

// ── Register heat map ─────────────────────────────────────────────────────────

/// A heat map showing how often each register changed in time buckets.
pub struct RegisterHeatMap {
    pub reg: String,
    pub bucket_size: u64,
    /// `bucket_index` → change count
    pub buckets: Vec<u64>,
    pub from_tick: Tick,
}

impl RegisterHeatMap {
    #[must_use] 
    pub fn build(tl: &RegTimeline, from: Tick, to: Tick, bucket_size: u64) -> Self {
        let span = to.saturating_sub(from) + 1;
        let num_buckets = span.div_ceil(bucket_size) as usize;
        let mut buckets = vec![0u64; num_buckets];
        for cp in tl.changes_in(from, to) {
            let bucket = ((cp.tick - from) / bucket_size) as usize;
            if bucket < buckets.len() {
                buckets[bucket] += 1;
            }
        }
        Self { reg: tl.name.clone(), bucket_size, buckets, from_tick: from }
    }

    #[must_use] 
    pub fn peak_bucket(&self) -> (usize, u64) {
        self.buckets.iter().enumerate()
            .max_by_key(|(_, v)| *v)
            .map_or((0, 0), |(i, &v)| (i, v))
    }

    #[must_use] 
    pub fn peak_tick_range(&self) -> (Tick, Tick) {
        let (bucket, _) = self.peak_bucket();
        let from = self.from_tick + bucket as u64 * self.bucket_size;
        (from, from + self.bucket_size - 1)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rax_timeline() -> RegTimeline {
        let mut tl = RegTimeline::new("rax".into(), 0);
        tl.record(10, 1, 0,   100, Some(0x1000));
        tl.record(20, 1, 100, 200, Some(0x1004));
        tl.record(30, 1, 200, 300, Some(0x1008));
        tl.record(40, 1, 300, 0,   Some(0x100C));
        tl
    }

    #[test]
    fn test_value_at_initial() {
        let tl = sample_rax_timeline();
        assert_eq!(tl.value_at(5), 0);
    }

    #[test]
    fn test_value_at_exact() {
        let tl = sample_rax_timeline();
        assert_eq!(tl.value_at(10), 100);
        assert_eq!(tl.value_at(20), 200);
    }

    #[test]
    fn test_value_at_between() {
        let tl = sample_rax_timeline();
        assert_eq!(tl.value_at(15), 100);
        assert_eq!(tl.value_at(25), 200);
    }

    #[test]
    fn test_value_at_after_last() {
        let tl = sample_rax_timeline();
        assert_eq!(tl.value_at(100), 0);
    }

    #[test]
    fn test_changes_in() {
        let tl = sample_rax_timeline();
        let changes = tl.changes_in(15, 35);
        assert_eq!(changes.len(), 2); // ticks 20 and 30
    }

    #[test]
    fn test_first_tick_with_value() {
        let tl = sample_rax_timeline();
        assert_eq!(tl.first_tick_with_value(200, 0), Some(20));
        assert_eq!(tl.first_tick_with_value(999, 0), None);
    }

    #[test]
    fn test_last_tick_with_value() {
        let mut tl = RegTimeline::new("rax".into(), 0);
        tl.record(10, 1, 0, 42, None);
        tl.record(20, 1, 42, 99, None);
        tl.record(30, 1, 99, 42, None);
        assert_eq!(tl.last_tick_with_value(42, 35), Some(30));
        assert_eq!(tl.last_tick_with_value(42, 15), Some(10));
    }

    #[test]
    fn test_multi_register_diff() {
        let mut rt = RegisterTimeline::new();
        rt.record(10, 1, "rax", 0, 100, None);
        rt.record(10, 1, "rbx", 0, 200, None);
        rt.record(20, 1, "rax", 100, 150, None);
        rt.finalize();

        let diffs = rt.diff_ticks(10, 20);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].0, "rax");
        assert_eq!(diffs[0].1, 100);
        assert_eq!(diffs[0].2, 150);
    }

    #[test]
    fn test_snapshot_at() {
        let mut rt = RegisterTimeline::new();
        rt.record(5, 1, "rax", 0, 42, None);
        rt.record(15, 1, "rbx", 0, 99, None);
        rt.finalize();

        let snap = rt.snapshot_at(10);
        assert_eq!(snap.get("rax"), Some(&42));
        assert_eq!(snap.get("rbx"), Some(&0));
    }

    #[test]
    fn test_most_changed() {
        let mut rt = RegisterTimeline::new();
        for i in 0..10u64 {
            rt.record(i, 1, "rax", i, i + 1, None);
        }
        for i in 0..3u64 {
            rt.record(i, 1, "rbx", i, i + 1, None);
        }
        rt.finalize();

        let top = rt.most_changed(0, 100, 2);
        assert_eq!(top[0].0, "rax");
        assert_eq!(top[0].1, 10);
    }

    #[test]
    fn test_detect_counter() {
        let mut rt = RegisterTimeline::new();
        for i in 0..8u64 {
            rt.record(i * 10, 1, "rcx", i * 4, (i + 1) * 4, None);
        }
        rt.finalize();

        let counters = rt.detect_counters(0, 1000);
        assert_eq!(counters.len(), 1);
        assert_eq!(counters[0].step, 4);
        assert_eq!(counters[0].count, 8);
    }

    #[test]
    fn test_heat_map() {
        let mut tl = RegTimeline::new("rip".into(), 0);
        for i in 0..20u64 {
            tl.record(i * 5, 1, i * 4, (i + 1) * 4, None);
        }
        let hm = RegisterHeatMap::build(&tl, 0, 100, 25);
        assert!(!hm.buckets.is_empty());
        let (_, count) = hm.peak_bucket();
        assert!(count > 0);
    }

    #[test]
    fn test_csv_export() {
        let tl = sample_rax_timeline();
        let csv = tl.to_csv(0, 100);
        assert!(csv.contains("tick,thread_id"));
        assert!(csv.contains("10,"));
    }

    #[test]
    fn test_value_range() {
        let tl = sample_rax_timeline();
        let (lo, hi) = tl.value_range();
        assert_eq!(lo, 0);
        assert_eq!(hi, 300);
    }
}
