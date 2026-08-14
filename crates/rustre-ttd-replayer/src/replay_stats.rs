//! `replay_stats` — statistics collected from a TTD replay session.
//!
//! Provides [`ReplayStats`], [`StepDistribution`], and [`ReplayProfiler`]
//! for summarising what happened during a complete or partial replay.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

// ─── ModuleRange ─────────────────────────────────────────────────────────────

/// Address range for a loaded module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRange {
    /// Module name (e.g. "ntdll.dll").
    pub name: String,
    /// Inclusive start address.
    pub base: u64,
    /// Exclusive end address.
    pub end: u64,
}

impl ModuleRange {
    /// Create a new module range.
    #[must_use]
    pub fn new(name: impl Into<String>, base: u64, size: u64) -> Self {
        Self { name: name.into(), base, end: base.saturating_add(size) }
    }

    /// Returns `true` if `addr` falls within this module.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end
    }
}

// ─── StepDistribution ────────────────────────────────────────────────────────

/// Per-module instruction-step count distribution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepDistribution {
    /// Map of module name → instruction step count.
    pub counts: HashMap<String, u64>,
    /// Steps that could not be attributed to any known module.
    pub unresolved: u64,
}

impl StepDistribution {
    /// Create an empty distribution.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one step at `pc`, resolving it against `modules`.
    pub fn record_step(&mut self, pc: u64, modules: &[ModuleRange]) {
        match modules.iter().find(|m| m.contains(pc)) {
            Some(m) => {
                if let Some(c) = self.counts.get_mut(m.name.as_str()) {
                    *c += 1;
                } else {
                    self.counts.insert(m.name.clone(), 1);
                }
            }
            None => self.unresolved += 1,
        }
    }

    /// Total step count across all modules plus unresolved.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.values().sum::<u64>() + self.unresolved
    }

    /// Module with the highest step count, if any.
    #[must_use]
    pub fn hottest_module(&self) -> Option<(&str, u64)> {
        self.counts
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(n, &c)| (n.as_str(), c))
    }

    /// Fraction of total steps in `module_name`, or `0.0` if not found / total is 0.
    #[must_use]
    pub fn fraction(&self, module_name: &str) -> f64 {
        let t = self.total();
        if t == 0 { return 0.0; }
        let c = self.counts.get(module_name).copied().unwrap_or(0);
        c as f64 / t as f64
    }
}

// ─── ReplayStats ─────────────────────────────────────────────────────────────

/// Aggregate statistics from a completed (or in-progress) replay session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplayStats {
    /// Total number of steps executed.
    pub total_steps: u64,
    /// Wall-clock replay time in milliseconds.
    pub total_time_ms: u64,
    /// Number of unique program-counter values observed.
    pub unique_pcs: u64,
    /// Number of unique module names encountered.
    pub unique_modules: u64,
    /// Number of exceptions / signals delivered.
    pub exception_count: u64,
    /// Number of API calls (syscall entries) observed.
    pub api_call_count: u64,
    /// Number of memory write operations recorded.
    pub memory_write_count: u64,
    /// Total bytes written across all memory writes.
    pub memory_bytes_written: u64,
    /// Tick of the first event replayed.
    pub start_tick: u64,
    /// Tick of the last event replayed.
    pub end_tick: u64,
}

impl ReplayStats {
    /// Create empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Average steps per second (requires `total_time_ms > 0`).
    #[must_use]
    pub fn steps_per_second(&self) -> f64 {
        if self.total_time_ms == 0 { return 0.0; }
        self.total_steps as f64 / (self.total_time_ms as f64 / 1000.0)
    }

    /// Average bytes written per memory write operation.
    #[must_use]
    pub fn avg_write_size(&self) -> f64 {
        if self.memory_write_count == 0 { return 0.0; }
        self.memory_bytes_written as f64 / self.memory_write_count as f64
    }

    /// Tick range covered by the replay.
    #[must_use]
    pub const fn tick_range(&self) -> u64 {
        self.end_tick.saturating_sub(self.start_tick)
    }

    /// Merge another stats record into this one (additive fields).
    pub fn merge(&mut self, other: &Self) {
        self.total_steps += other.total_steps;
        self.total_time_ms += other.total_time_ms;
        self.unique_pcs = self.unique_pcs.max(other.unique_pcs);
        self.unique_modules = self.unique_modules.max(other.unique_modules);
        self.exception_count += other.exception_count;
        self.api_call_count += other.api_call_count;
        self.memory_write_count += other.memory_write_count;
        self.memory_bytes_written += other.memory_bytes_written;
        self.start_tick = self.start_tick.min(other.start_tick);
        self.end_tick = self.end_tick.max(other.end_tick);
    }
}

impl std::fmt::Display for ReplayStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ReplayStats {{")?;
        writeln!(f, "  total_steps          : {}", self.total_steps)?;
        writeln!(f, "  total_time_ms        : {}", self.total_time_ms)?;
        writeln!(f, "  unique_pcs           : {}", self.unique_pcs)?;
        writeln!(f, "  unique_modules       : {}", self.unique_modules)?;
        writeln!(f, "  exception_count      : {}", self.exception_count)?;
        writeln!(f, "  api_call_count       : {}", self.api_call_count)?;
        writeln!(f, "  memory_write_count   : {}", self.memory_write_count)?;
        writeln!(f, "  memory_bytes_written : {}", self.memory_bytes_written)?;
        writeln!(f, "  tick_range           : {}..{}", self.start_tick, self.end_tick)?;
        write!(f, "}}")
    }
}

// ─── ProfilerEntry ────────────────────────────────────────────────────────────

/// One profiling sample (tick + PC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilerEntry {
    pub tick: u64,
    pub pc: u64,
}

// ─── ReplayProfiler ───────────────────────────────────────────────────────────

/// Collects per-step profiling data during a replay session and produces
/// [`ReplayStats`] and [`StepDistribution`] at the end.
#[derive(Debug, Default)]
pub struct ReplayProfiler {
    samples: Vec<ProfilerEntry>,
    modules: Vec<ModuleRange>,
    api_call_count: u64,
    exception_count: u64,
    memory_write_count: u64,
    memory_bytes_written: u64,
    start_tick: Option<u64>,
    end_tick: u64,
    wall_start_ms: u64,
    wall_end_ms: u64,
}

impl ReplayProfiler {
    /// Create a new profiler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a loaded module.
    pub fn add_module(&mut self, module: ModuleRange) {
        self.modules.push(module);
    }

    /// Record a single step at `tick` / `pc`.
    pub fn record_step(&mut self, tick: u64, pc: u64) {
        if self.start_tick.is_none() {
            self.start_tick = Some(tick);
            self.wall_start_ms = current_ms();
        }
        self.end_tick = tick;
        self.wall_end_ms = current_ms();
        self.samples.push(ProfilerEntry { tick, pc });
    }

    /// Record an API call event.
    pub const fn record_api_call(&mut self) {
        self.api_call_count += 1;
    }

    /// Record an exception/signal delivery.
    pub const fn record_exception(&mut self) {
        self.exception_count += 1;
    }

    /// Record a memory write of `bytes` bytes.
    pub const fn record_memory_write(&mut self, bytes: u64) {
        self.memory_write_count += 1;
        self.memory_bytes_written += bytes;
    }

    /// Finalise and compute aggregate [`ReplayStats`].
    #[must_use]
    pub fn finish(&self) -> ReplayStats {
        let unique_pcs: std::collections::HashSet<u64> =
            self.samples.iter().map(|s| s.pc).collect();

        let mut mod_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for sample in &self.samples {
            if let Some(m) = self.modules.iter().find(|m| m.contains(sample.pc)) {
                mod_names.insert(&m.name);
            }
        }

        ReplayStats {
            total_steps: self.samples.len() as u64,
            total_time_ms: self.wall_end_ms.saturating_sub(self.wall_start_ms),
            unique_pcs: unique_pcs.len() as u64,
            unique_modules: mod_names.len() as u64,
            exception_count: self.exception_count,
            api_call_count: self.api_call_count,
            memory_write_count: self.memory_write_count,
            memory_bytes_written: self.memory_bytes_written,
            start_tick: self.start_tick.unwrap_or(0),
            end_tick: self.end_tick,
        }
    }

    /// Compute the step distribution over registered modules.
    #[must_use]
    pub fn distribution(&self) -> StepDistribution {
        let mut dist = StepDistribution::new();
        for sample in &self.samples {
            dist.record_step(sample.pc, &self.modules);
        }
        dist
    }

    /// Number of steps recorded so far.
    #[must_use]
    pub const fn step_count(&self) -> usize {
        self.samples.len()
    }
}

/// Return current time as milliseconds since UNIX epoch (best-effort).
fn current_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel32() -> ModuleRange {
        ModuleRange::new("kernel32.dll", 0x7ffe_0000, 0x10000)
    }

    fn ntdll() -> ModuleRange {
        ModuleRange::new("ntdll.dll", 0x7ff0_0000, 0x20000)
    }

    // ── ModuleRange ─────────────────────────────────────────────────────────

    #[test]
    fn test_module_range_contains() {
        let m = kernel32();
        assert!(m.contains(0x7ffe_0000));
        assert!(m.contains(0x7ffe_0001));
        assert!(!m.contains(0x7fff_0000));
    }

    #[test]
    fn test_module_range_boundary() {
        let m = ModuleRange::new("test", 0x1000, 0x1000);
        assert!(m.contains(0x1fff));
        assert!(!m.contains(0x2000));
    }

    // ── StepDistribution ────────────────────────────────────────────────────

    #[test]
    fn test_distribution_record_step() {
        let mut dist = StepDistribution::new();
        let mods = vec![kernel32(), ntdll()];
        dist.record_step(0x7ffe_0010, &mods); // kernel32
        dist.record_step(0x7ff0_0200, &mods); // ntdll
        dist.record_step(0x7ff0_0300, &mods); // ntdll
        dist.record_step(0x0000_DEAD, &mods); // unresolved
        assert_eq!(*dist.counts.get("kernel32.dll").unwrap(), 1);
        assert_eq!(*dist.counts.get("ntdll.dll").unwrap(), 2);
        assert_eq!(dist.unresolved, 1);
    }

    #[test]
    fn test_distribution_total() {
        let mut dist = StepDistribution::new();
        dist.counts.insert("a.dll".into(), 5);
        dist.unresolved = 3;
        assert_eq!(dist.total(), 8);
    }

    #[test]
    fn test_distribution_hottest_module() {
        let mut dist = StepDistribution::new();
        dist.counts.insert("a.dll".into(), 2);
        dist.counts.insert("b.dll".into(), 10);
        let (name, count) = dist.hottest_module().unwrap();
        assert_eq!(name, "b.dll");
        assert_eq!(count, 10);
    }

    #[test]
    fn test_distribution_fraction() {
        let mut dist = StepDistribution::new();
        dist.counts.insert("x.dll".into(), 50);
        dist.counts.insert("y.dll".into(), 50);
        let frac = dist.fraction("x.dll");
        assert!((frac - 0.5).abs() < 1e-9);
    }

    // ── ReplayStats ─────────────────────────────────────────────────────────

    #[test]
    fn test_stats_defaults() {
        let s = ReplayStats::new();
        assert_eq!(s.total_steps, 0);
        assert_eq!(s.steps_per_second(), 0.0);
    }

    #[test]
    fn test_stats_steps_per_second() {
        let mut s = ReplayStats::new();
        s.total_steps = 1000;
        s.total_time_ms = 500;
        assert!((s.steps_per_second() - 2000.0).abs() < 1e-6);
    }

    #[test]
    fn test_stats_avg_write_size() {
        let mut s = ReplayStats::new();
        s.memory_write_count = 4;
        s.memory_bytes_written = 100;
        assert!((s.avg_write_size() - 25.0).abs() < 1e-6);
    }

    #[test]
    fn test_stats_tick_range() {
        let mut s = ReplayStats::new();
        s.start_tick = 100;
        s.end_tick = 500;
        assert_eq!(s.tick_range(), 400);
    }

    #[test]
    fn test_stats_merge() {
        let mut a = ReplayStats { total_steps: 10, exception_count: 1, ..Default::default() };
        let b = ReplayStats { total_steps: 5, exception_count: 2, end_tick: 99, ..Default::default() };
        a.merge(&b);
        assert_eq!(a.total_steps, 15);
        assert_eq!(a.exception_count, 3);
        assert_eq!(a.end_tick, 99);
    }

    #[test]
    fn test_stats_display() {
        let s = ReplayStats { total_steps: 42, ..Default::default() };
        let s_str = s.to_string();
        assert!(s_str.contains("42"));
    }

    // ── ReplayProfiler ──────────────────────────────────────────────────────

    #[test]
    fn test_profiler_record_and_finish() {
        let mut p = ReplayProfiler::new();
        p.add_module(kernel32());
        p.record_step(1, 0x7ffe_0010);
        p.record_step(2, 0x7ffe_0020);
        p.record_api_call();
        p.record_exception();
        p.record_memory_write(64);
        let stats = p.finish();
        assert_eq!(stats.total_steps, 2);
        assert_eq!(stats.api_call_count, 1);
        assert_eq!(stats.exception_count, 1);
        assert_eq!(stats.memory_write_count, 1);
        assert_eq!(stats.memory_bytes_written, 64);
    }

    #[test]
    fn test_profiler_unique_pcs() {
        let mut p = ReplayProfiler::new();
        p.record_step(1, 0x1000);
        p.record_step(2, 0x1000); // duplicate
        p.record_step(3, 0x2000);
        let stats = p.finish();
        assert_eq!(stats.unique_pcs, 2);
    }

    #[test]
    fn test_profiler_distribution() {
        let mut p = ReplayProfiler::new();
        p.add_module(ntdll());
        p.record_step(1, 0x7ff0_0100); // ntdll
        p.record_step(2, 0xDEAD_0000); // unresolved
        let dist = p.distribution();
        assert_eq!(*dist.counts.get("ntdll.dll").unwrap(), 1);
        assert_eq!(dist.unresolved, 1);
    }

    #[test]
    fn test_profiler_step_count() {
        let mut p = ReplayProfiler::new();
        for i in 0..5 { p.record_step(i, 0x1000); }
        assert_eq!(p.step_count(), 5);
    }
}
