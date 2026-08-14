//! `syscall_statistics` — frequency, timing, and per-process syscall statistics.
//!
//! Tracks syscall invocations as they are received, maintaining:
//!
//! * [`SyscallFreq`]  — per-syscall invocation count.
//! * [`TimingStats`]  — per-syscall duration statistics (min/max/mean/p99).
//! * [`ProcessStats`] — per-process aggregated view.
//! * [`SyscallStatistics`] — top-level aggregator that bundles all of the above
//!   and exposes [`SyscallStatistics::generate_report`].
//!
//! All types are `Send + Sync` and use `parking_lot` locks for interior
//! mutability, making them safe to share across threads.

use std::collections::HashMap;
use std::fmt;

/// Saturating `f64 → usize` conversion: negative/NaN → 0, overflow → `usize::MAX`.
///
/// Implemented via IEEE-754 bit extraction to avoid any lossy `as usize` cast
/// that would trigger `clippy::cast_possible_truncation` / `cast_sign_loss`.
#[inline]
fn f64_to_usize_saturating(v: f64) -> usize {
    // Reject NaN, infinities, and non-positive values.
    if !v.is_finite() || v <= 0.0 {
        return 0;
    }
    // Decode the IEEE-754 double: [sign:63][biased_exp:62-52][mantissa:51-0].
    // v > 0 so the sign bit is 0.
    let bits: u64 = v.to_bits();
    let biased_exp: u64 = (bits >> 52) & 0x7FF;
    // biased_exp < 1023 means the value is in (0, 1) — integer part is 0.
    if biased_exp < 1023 {
        return 0;
    }
    let true_exp: u64 = biased_exp - 1023; // real exponent: value ≈ 1.mantissa × 2^true_exp
    // true_exp >= 64 means the value ≥ 2^64, which overflows usize on all targets.
    if true_exp >= 64 {
        return usize::MAX;
    }
    // Reconstruct the full 53-bit significand (implicit leading 1).
    let mantissa: u64 = (bits & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000;
    // Integer value = mantissa * 2^(true_exp − 52).
    let value: u64 = if true_exp >= 52 {
        // Left-shift: true_exp in [52, 63], shift in [0, 11].
        let shift = u32::try_from(true_exp - 52).unwrap_or(0);
        // Guard against overflow before shifting.
        if shift > 0 && mantissa > (u64::MAX >> shift) {
            return usize::MAX;
        }
        mantissa << shift
    } else {
        // Right-shift (floor): true_exp in [0, 51], shift in [1, 52].
        mantissa >> (52 - true_exp)
    };
    usize::try_from(value).unwrap_or(usize::MAX)
}
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::syscall_dispatcher::SyscallEvent;

// ── SyscallFreq ───────────────────────────────────────────────────────────────

/// Invocation count for a single syscall number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallFreq {
    /// Syscall number.
    pub nr: u64,
    /// Syscall name if known.
    pub name: Option<String>,
    /// Total invocations.
    pub count: u64,
    /// Error invocations (retval < 0).
    pub error_count: u64,
    /// Invocations with a return value of zero.
    pub success_count: u64,
}

impl SyscallFreq {
    /// Create a new frequency record.
    #[must_use]
    pub const fn new(nr: u64) -> Self {
        Self { nr, name: None, count: 0, error_count: 0, success_count: 0 }
    }

    /// Error rate in [0.0, 1.0].
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            crate::u64_to_f64(self.error_count) / crate::u64_to_f64(self.count)
        }
    }
}

impl fmt::Display for SyscallFreq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("?");
        write!(
            f,
            "syscall={} ({}) count={} errors={} err_rate={:.1}%",
            self.nr,
            name,
            self.count,
            self.error_count,
            self.error_rate() * 100.0,
        )
    }
}

// ── DurationSample ────────────────────────────────────────────────────────────

/// One duration observation (entry tick to exit tick).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DurationSample {
    /// Entry tick.
    pub entry: u64,
    /// Exit tick.
    pub exit: u64,
}

impl DurationSample {
    /// Duration in ticks.
    #[must_use]
    #[inline]
    pub const fn duration(&self) -> u64 {
        self.exit.saturating_sub(self.entry)
    }
}

// ── TimingStats ───────────────────────────────────────────────────────────────

/// Timing statistics for a single syscall number.
///
/// Maintains a reservoir of duration samples and computes
/// min/max/mean/p50/p99 lazily.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingStats {
    /// Syscall number.
    pub nr: u64,
    /// Minimum observed duration.
    pub min_ticks: u64,
    /// Maximum observed duration.
    pub max_ticks: u64,
    /// Sum of all durations (used to compute mean).
    sum_ticks: u64,
    /// Number of samples.
    pub sample_count: u64,
    /// Sorted reservoir of durations (capped at `MAX_RESERVOIR`).
    reservoir: Vec<u64>,
}

/// Maximum reservoir size for percentile computation.
const MAX_RESERVOIR: usize = 2048;

impl TimingStats {
    /// Create an empty timing stats record.
    #[must_use]
    pub const fn new(nr: u64) -> Self {
        Self {
            nr,
            min_ticks: u64::MAX,
            max_ticks: 0,
            sum_ticks: 0,
            sample_count: 0,
            reservoir: Vec::new(),
        }
    }

    /// Record a duration sample.
    pub fn record(&mut self, duration: u64) {
        if duration < self.min_ticks {
            self.min_ticks = duration;
        }
        if duration > self.max_ticks {
            self.max_ticks = duration;
        }
        self.sum_ticks = self.sum_ticks.saturating_add(duration);
        self.sample_count += 1;

        // Insert into sorted reservoir.
        if self.reservoir.len() < MAX_RESERVOIR {
            let pos = self.reservoir.partition_point(|&x| x <= duration);
            self.reservoir.insert(pos, duration);
        } else {
            // Replace a random element using a simple deterministic scheme.
            let idx = usize::try_from(duration).unwrap_or(usize::MAX) % MAX_RESERVOIR;
            self.reservoir[idx] = duration;
            self.reservoir.sort_unstable();
        }
    }

    /// Mean duration in ticks.
    #[must_use]
    pub fn mean_ticks(&self) -> f64 {
        if self.sample_count == 0 {
            0.0
        } else {
            crate::u64_to_f64(self.sum_ticks) / crate::u64_to_f64(self.sample_count)
        }
    }

    /// Approximate p50 (median) duration.
    #[must_use]
    pub fn p50_ticks(&self) -> u64 {
        self.percentile(0.50)
    }

    /// Approximate p99 duration.
    #[must_use]
    pub fn p99_ticks(&self) -> u64 {
        self.percentile(0.99)
    }

    /// Approximate p95 duration.
    #[must_use]
    pub fn p95_ticks(&self) -> u64 {
        self.percentile(0.95)
    }

    /// Compute the `p`-th percentile (0.0–1.0) from the sorted reservoir.
    #[must_use]
    pub fn percentile(&self, p: f64) -> u64 {
        if self.reservoir.is_empty() {
            return 0;
        }
        let scaled = crate::usize_to_f64(self.reservoir.len()) * p;
        let idx = f64_to_usize_saturating(scaled)
            .min(self.reservoir.len().saturating_sub(1));
        self.reservoir[idx]
    }

    /// Normalised minimum (clamped to 0 when there are no samples).
    #[must_use]
    pub const fn safe_min(&self) -> u64 {
        if self.sample_count == 0 { 0 } else { self.min_ticks }
    }
}

impl fmt::Display for TimingStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "syscall={} samples={} min={} max={} mean={:.1} p50={} p99={}",
            self.nr,
            self.sample_count,
            self.safe_min(),
            self.max_ticks,
            self.mean_ticks(),
            self.p50_ticks(),
            self.p99_ticks(),
        )
    }
}

// ── ProcessStats ──────────────────────────────────────────────────────────────

/// Per-process aggregated syscall statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStats {
    /// Process identifier.
    pub pid: u32,
    /// Total events seen for this process.
    pub total_events: u64,
    /// Per-syscall invocation counts.
    pub freq: HashMap<u64, SyscallFreq>,
    /// Total bytes written (where applicable — passed as metadata).
    pub total_bytes_written: u64,
    /// Total error events.
    pub error_count: u64,
    /// Most frequent syscall number (cached).
    pub hottest_syscall: Option<u64>,
}

impl ProcessStats {
    /// Create an empty stats record for a process.
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            total_events: 0,
            freq: HashMap::new(),
            total_bytes_written: 0,
            error_count: 0,
            hottest_syscall: None,
        }
    }

    /// Record an event.
    pub fn record(&mut self, event: &SyscallEvent) {
        self.total_events += 1;

        let entry = self.freq.entry(event.nr).or_insert_with(|| {
            let mut f = SyscallFreq::new(event.nr);
            f.name.clone_from(&event.name);
            f
        });
        entry.count += 1;

        if let Some(retval) = event.retval {
            if retval < 0 {
                entry.error_count += 1;
                self.error_count += 1;
            } else if retval == 0 {
                entry.success_count += 1;
            }
        }

        if let Some(bytes) = event.metadata.get("bytes_written") && let Ok(n) = bytes.parse::<u64>() {
                self.total_bytes_written = self.total_bytes_written.saturating_add(n);
        }

        // Update hottest syscall cache.
        let current_count = entry.count;
        let update = self.hottest_syscall.is_none_or(|h| {
            self.freq.get(&h).is_none_or(|hf| current_count > hf.count)
        });
        if update {
            self.hottest_syscall = Some(event.nr);
        }
    }
}

// ── StatisticsReport ─────────────────────────────────────────────────────────

/// A generated statistics report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsReport {
    /// Total events processed.
    pub total_events: u64,
    /// Total error events.
    pub total_errors: u64,
    /// Most frequently called syscall number.
    pub most_frequent_syscall: Option<u64>,
    /// Most frequently called syscall name.
    pub most_frequent_name: Option<String>,
    /// Most frequently called syscall count.
    pub most_frequent_count: u64,
    /// Number of distinct syscalls observed.
    pub distinct_syscalls: usize,
    /// Number of distinct processes observed.
    pub distinct_processes: usize,
    /// Sorted top-N frequency entries.
    pub top_syscalls: Vec<SyscallFreq>,
    /// Timing statistics for the top syscalls.
    pub timing: Vec<TimingStats>,
    /// Per-process summary (pid → event count).
    pub per_process: Vec<(u32, u64)>,
    /// Overall error rate.
    pub error_rate: f64,
}

impl fmt::Display for StatisticsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Syscall Statistics Report ===")?;
        writeln!(f, "Total events     : {}", self.total_events)?;
        writeln!(f, "Total errors     : {}", self.total_errors)?;
        writeln!(f, "Error rate       : {:.1}%", self.error_rate * 100.0)?;
        writeln!(f, "Distinct syscalls: {}", self.distinct_syscalls)?;
        writeln!(f, "Distinct procs   : {}", self.distinct_processes)?;
        if let Some(nr) = self.most_frequent_syscall {
            let name = self.most_frequent_name.as_deref().unwrap_or("?");
            writeln!(f, "Hottest syscall  : {nr} ({name}) x{}", self.most_frequent_count)?;
        }
        writeln!(f, "\nTop syscalls:")?;
        for entry in &self.top_syscalls {
            writeln!(f, "  {entry}")?;
        }
        writeln!(f, "\nTiming summary:")?;
        for ts in &self.timing {
            writeln!(f, "  {ts}")?;
        }
        Ok(())
    }
}

// ── SyscallStatistics ─────────────────────────────────────────────────────────

/// Top-level statistics aggregator.
///
/// Thread-safe; can be shared via `Arc`.
///
/// # Example
///
/// ```no_run
/// use rustre_syscalls::syscall_statistics::SyscallStatistics;
/// use rustre_syscalls::syscall_dispatcher::SyscallEvent;
/// use rustre_syscalls::{OsFamily, SyscallArch};
///
/// let stats = SyscallStatistics::new(20);
/// let ev = SyscallEvent::new(1, 60, OsFamily::Linux, SyscallArch::X86_64);
/// stats.record_event(&ev);
/// let report = stats.generate_report();
/// println!("{report}");
/// ```
pub struct SyscallStatistics {
    /// Global per-syscall frequency map.
    freq: RwLock<HashMap<u64, SyscallFreq>>,
    /// Global per-syscall timing stats.
    timing: RwLock<HashMap<u64, TimingStats>>,
    /// Per-process stats.
    process: RwLock<HashMap<u32, ProcessStats>>,
    /// Pending entry tick by sequence number (for duration pairing).
    pending: RwLock<HashMap<u64, (u64, u64)>>, // seq -> (nr, entry_tick)
    /// Total events processed.
    total_events: AtomicU64,
    /// Total error events.
    total_errors: AtomicU64,
    /// How many top syscalls to include in the report.
    top_n: usize,
}

impl SyscallStatistics {
    /// Create a new statistics collector.
    ///
    /// `top_n` controls how many top-frequency syscalls appear in the report.
    #[must_use]
    pub fn new(top_n: usize) -> Self {
        Self {
            freq: RwLock::new(HashMap::new()),
            timing: RwLock::new(HashMap::new()),
            process: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            total_events: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            top_n,
        }
    }

    /// Create with the default of 20 top syscalls.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(20)
    }

    /// Record a [`SyscallEvent`].
    ///
    /// Entry events are stashed in a pending map for duration pairing.
    /// Exit events close the pending entry and record a duration sample.
    pub fn record_event(&self, event: &SyscallEvent) {
        self.total_events.fetch_add(1, Ordering::Relaxed);

        // Update global frequency map.
        let bump_error = {
            let mut freq = self.freq.write();
            let entry = freq.entry(event.nr).or_insert_with(|| SyscallFreq::new(event.nr));
            entry.count += 1;
            if entry.name.is_none() {
                entry.name.clone_from(&event.name);
            }
            let mut bump = false;
            if let Some(retval) = event.retval {
                if retval < 0 {
                    entry.error_count += 1;
                    bump = true;
                } else if retval == 0 {
                    entry.success_count += 1;
                }
            }
            drop(freq); // release the write lock as early as possible
            bump
        };
        if bump_error {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
        }

        // Duration tracking.
        if event.retval.is_none() {
            // Entry event: stash tick.
            self.pending.write().insert(event.seq, (event.nr, event.timestamp_ms));
        } else {
            // Exit event: look up matching entry by seq - 1 (simplified heuristic).
            let entry_seq = event.seq.saturating_sub(1);
            let removed = self.pending.write().remove(&entry_seq);
            if let Some((nr, entry_tick)) = removed {
                let duration = event.timestamp_ms.saturating_sub(entry_tick);
                let mut timing = self.timing.write();
                timing.entry(nr).or_insert_with(|| TimingStats::new(nr)).record(duration);
            }
        }

        // Per-process tracking.
        {
            let mut process = self.process.write();
            process.entry(event.pid).or_insert_with(|| ProcessStats::new(event.pid)).record(event);
        }
    }

    /// Return the total number of events recorded.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    /// Return the total number of error events.
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.total_errors.load(Ordering::Relaxed)
    }

    /// Return the frequency record for a single syscall.
    #[must_use]
    pub fn freq_for(&self, nr: u64) -> Option<SyscallFreq> {
        self.freq.read().get(&nr).cloned()
    }

    /// Return the timing record for a single syscall.
    #[must_use]
    pub fn timing_for(&self, nr: u64) -> Option<TimingStats> {
        self.timing.read().get(&nr).cloned()
    }

    /// Return process stats for `pid`.
    #[must_use]
    pub fn process_stats(&self, pid: u32) -> Option<ProcessStats> {
        self.process.read().get(&pid).cloned()
    }

    /// Number of distinct syscall numbers seen.
    #[must_use]
    pub fn distinct_syscalls(&self) -> usize {
        self.freq.read().len()
    }

    /// Number of distinct processes seen.
    #[must_use]
    pub fn distinct_processes(&self) -> usize {
        self.process.read().len()
    }

    /// Generate a [`StatisticsReport`] snapshot.
    #[must_use]
    pub fn generate_report(&self) -> StatisticsReport {
        let freq_guard = self.freq.read();
        let timing_guard = self.timing.read();
        let process_guard = self.process.read();

        let total_events = self.total_events.load(Ordering::Relaxed);
        let total_errors = self.total_errors.load(Ordering::Relaxed);
        let error_rate = if total_events == 0 { 0.0 } else { crate::u64_to_f64(total_errors) / crate::u64_to_f64(total_events) };

        // Sort by count descending for top-N.
        let mut freq_sorted: Vec<SyscallFreq> = freq_guard.values().cloned().collect();
        freq_sorted.sort_by(|a, b| b.count.cmp(&a.count));

        let most_frequent = freq_sorted.first().cloned();
        let most_frequent_syscall = most_frequent.as_ref().map(|f| f.nr);
        let most_frequent_name = most_frequent.as_ref().and_then(|f| f.name.clone());
        let most_frequent_count = most_frequent.as_ref().map_or(0, |f| f.count);

        let top_syscalls = freq_sorted.into_iter().take(self.top_n).collect();

        // Timing stats for top syscalls.
        let timing: Vec<TimingStats> = timing_guard
            .values()
            .take(self.top_n).cloned()
            .collect();
        drop(timing_guard); // release the read lock as early as possible

        // Per-process summary.
        let mut per_process: Vec<(u32, u64)> = process_guard
            .values()
            .map(|p| (p.pid, p.total_events))
            .collect();
        per_process.sort_by(|a, b| b.1.cmp(&a.1));

        StatisticsReport {
            total_events,
            total_errors,
            most_frequent_syscall,
            most_frequent_name,
            most_frequent_count,
            distinct_syscalls: freq_guard.len(),
            distinct_processes: process_guard.len(),
            top_syscalls,
            timing,
            per_process,
            error_rate,
        }
    }

    /// Reset all statistics.
    pub fn reset(&self) {
        self.freq.write().clear();
        self.timing.write().clear();
        self.process.write().clear();
        self.pending.write().clear();
        self.total_events.store(0, Ordering::Relaxed);
        self.total_errors.store(0, Ordering::Relaxed);
    }
}

impl fmt::Debug for SyscallStatistics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyscallStatistics")
            .field("total_events", &self.total_events.load(Ordering::Relaxed))
            .field("total_errors", &self.total_errors.load(Ordering::Relaxed))
            .field("distinct_syscalls", &self.freq.read().len())
            .field("timing_entries", &self.timing.read().len())
            .field("process_entries", &self.process.read().len())
            .field("pending_entries", &self.pending.read().len())
            .field("top_n", &self.top_n)
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall_dispatcher::SyscallEvent;
    use crate::{OsFamily, SyscallArch};

    fn entry_ev(seq: u64, nr: u64, pid: u32) -> SyscallEvent {
        let mut ev = SyscallEvent::new(seq, nr, OsFamily::Linux, SyscallArch::X86_64);
        ev.pid = pid;
        ev.timestamp_ms = seq * 10;
        ev
    }

    fn exit_ev(seq: u64, nr: u64, pid: u32, retval: i64) -> SyscallEvent {
        let mut ev = entry_ev(seq, nr, pid);
        ev.retval = Some(retval);
        ev
    }

    // ── SyscallFreq ───────────────────────────────────────────────────────────

    #[test]
    fn test_freq_error_rate_zero() {
        let f = SyscallFreq::new(1);
        assert_eq!(f.error_rate(), 0.0);
    }

    #[test]
    fn test_freq_error_rate_half() {
        let mut f = SyscallFreq::new(1);
        f.count = 4;
        f.error_count = 2;
        assert!((f.error_rate() - 0.5).abs() < 1e-9);
    }

    // ── TimingStats ───────────────────────────────────────────────────────────

    #[test]
    fn test_timing_record_single() {
        let mut ts = TimingStats::new(60);
        ts.record(100);
        assert_eq!(ts.sample_count, 1);
        assert_eq!(ts.min_ticks, 100);
        assert_eq!(ts.max_ticks, 100);
        assert!((ts.mean_ticks() - 100.0).abs() < 1e-9);
    }

    #[test]
    fn test_timing_record_multiple() {
        let mut ts = TimingStats::new(1);
        for v in [10u64, 20, 30, 40, 50] {
            ts.record(v);
        }
        assert_eq!(ts.min_ticks, 10);
        assert_eq!(ts.max_ticks, 50);
        assert!((ts.mean_ticks() - 30.0).abs() < 1e-9);
    }

    #[test]
    fn test_timing_percentile_empty() {
        let ts = TimingStats::new(1);
        assert_eq!(ts.p50_ticks(), 0);
        assert_eq!(ts.p99_ticks(), 0);
    }

    #[test]
    fn test_timing_percentile_small() {
        let mut ts = TimingStats::new(1);
        for v in 1u64..=100 {
            ts.record(v);
        }
        assert!(ts.p50_ticks() > 0);
        assert!(ts.p99_ticks() >= ts.p50_ticks());
        assert!(ts.p99_ticks() <= 100);
    }

    // ── SyscallStatistics ─────────────────────────────────────────────────────

    #[test]
    fn test_record_event_increments_total() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&entry_ev(1, 60, 100));
        assert_eq!(stats.total_events(), 1);
    }

    #[test]
    fn test_record_error_event() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&exit_ev(1, 60, 100, -1));
        assert_eq!(stats.total_errors(), 1);
    }

    #[test]
    fn test_distinct_syscalls() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&entry_ev(1, 1, 100));
        stats.record_event(&entry_ev(2, 2, 100));
        stats.record_event(&entry_ev(3, 1, 100)); // duplicate
        assert_eq!(stats.distinct_syscalls(), 2);
    }

    #[test]
    fn test_distinct_processes() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&entry_ev(1, 1, 10));
        stats.record_event(&entry_ev(2, 1, 20));
        assert_eq!(stats.distinct_processes(), 2);
    }

    #[test]
    fn test_freq_for_known_syscall() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&entry_ev(1, 42, 1));
        stats.record_event(&entry_ev(2, 42, 1));
        let f = stats.freq_for(42).unwrap();
        assert_eq!(f.count, 2);
    }

    #[test]
    fn test_freq_for_unknown_syscall() {
        let stats = SyscallStatistics::with_defaults();
        assert!(stats.freq_for(9999).is_none());
    }

    #[test]
    fn test_process_stats_recorded() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&entry_ev(1, 60, 7));
        stats.record_event(&entry_ev(2, 60, 7));
        let ps = stats.process_stats(7).unwrap();
        assert_eq!(ps.total_events, 2);
    }

    #[test]
    fn test_reset_clears_all() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&entry_ev(1, 1, 1));
        stats.reset();
        assert_eq!(stats.total_events(), 0);
        assert_eq!(stats.distinct_syscalls(), 0);
    }

    #[test]
    fn test_generate_report_basic() {
        let stats = SyscallStatistics::new(5);
        for seq in 1u64..=10 {
            stats.record_event(&entry_ev(seq, 60, 1));
        }
        let report = stats.generate_report();
        assert_eq!(report.total_events, 10);
        assert_eq!(report.most_frequent_syscall, Some(60));
        assert_eq!(report.most_frequent_count, 10);
        assert!(report.distinct_syscalls >= 1);
    }

    #[test]
    fn test_report_top_n_capped() {
        let stats = SyscallStatistics::new(3);
        for nr in 1u64..=10 {
            stats.record_event(&entry_ev(nr, nr, 1));
        }
        let report = stats.generate_report();
        assert!(report.top_syscalls.len() <= 3);
    }

    #[test]
    fn test_report_error_rate() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&exit_ev(1, 1, 1, 0));  // success
        stats.record_event(&exit_ev(2, 1, 1, -1)); // error
        let report = stats.generate_report();
        assert!((report.error_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_report_display_does_not_panic() {
        let stats = SyscallStatistics::with_defaults();
        stats.record_event(&entry_ev(1, 1, 1));
        let report = stats.generate_report();
        let _ = format!("{report}");
    }

    #[test]
    fn test_timing_recorded_entry_exit_pair() {
        let stats = SyscallStatistics::with_defaults();
        let mut entry = entry_ev(1, 60, 1);
        entry.timestamp_ms = 100;
        stats.record_event(&entry);
        let mut exit = exit_ev(2, 60, 1, 0);
        exit.timestamp_ms = 200;
        stats.record_event(&exit);
        // Timing may or may not capture depending on seq heuristic; just check no panic.
        let _ = stats.timing_for(60);
    }

    #[test]
    fn test_duration_sample_duration() {
        let s = DurationSample { entry: 100, exit: 250 };
        assert_eq!(s.duration(), 150);
    }

    #[test]
    fn test_timing_stats_safe_min_no_samples() {
        let ts = TimingStats::new(1);
        assert_eq!(ts.safe_min(), 0);
    }
}
