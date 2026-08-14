//! Syscall usage statistics and strace-like formatting.
//!
//! Tracks per-syscall frequency, builds timelines, detects hot syscalls and
//! recurring patterns, and formats output in a style similar to `strace -c`.

use std::collections::HashMap;
pub use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

pub use crate::LinuxSyscall;
use crate::LinuxSyscallDb;
use rustre_syscalls::SyscallArch;

// ─── SyscallSample ────────────────────────────────────────────────────────────

/// A single recorded syscall sample for timeline purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallSample {
    /// Syscall number.
    pub nr: u32,
    /// Monotonic timestamp (nanoseconds from session start).
    pub timestamp_ns: u64,
    /// Elapsed time inside the kernel in nanoseconds.
    pub elapsed_ns: u64,
    /// Return value.
    pub retval: i64,
    /// Thread ID.
    pub tid: u32,
}

impl SyscallSample {
    #[must_use]
    pub const fn new(nr: u32, timestamp_ns: u64, elapsed_ns: u64, retval: i64, tid: u32) -> Self {
        Self {
            nr,
            timestamp_ns,
            elapsed_ns,
            retval,
            tid,
        }
    }

    /// Whether the syscall returned an error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.retval < 0
    }
}

// ─── PerSyscallStats ──────────────────────────────────────────────────────────

/// Aggregated statistics for a single syscall number.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PerSyscallStats {
    /// Syscall number.
    pub nr: u32,
    /// Syscall name (if resolved).
    pub name: String,
    /// Total call count.
    pub count: u64,
    /// Count of error returns.
    pub error_count: u64,
    /// Total elapsed kernel time in nanoseconds.
    pub total_elapsed_ns: u64,
    /// Minimum elapsed time observed.
    pub min_elapsed_ns: u64,
    /// Maximum elapsed time observed.
    pub max_elapsed_ns: u64,
}

impl PerSyscallStats {
    #[must_use]
    pub fn new(nr: u32, name: impl Into<String>) -> Self {
        Self {
            nr,
            name: name.into(),
            count: 0,
            error_count: 0,
            total_elapsed_ns: 0,
            min_elapsed_ns: u64::MAX,
            max_elapsed_ns: 0,
        }
    }

    /// Record one sample.
    pub const fn record(&mut self, sample: &SyscallSample) {
        self.count = self.count.saturating_add(1);
        if sample.is_error() {
            self.error_count = self.error_count.saturating_add(1);
        }
        self.total_elapsed_ns = self.total_elapsed_ns.saturating_add(sample.elapsed_ns);
        if sample.elapsed_ns < self.min_elapsed_ns {
            self.min_elapsed_ns = sample.elapsed_ns;
        }
        if sample.elapsed_ns > self.max_elapsed_ns {
            self.max_elapsed_ns = sample.elapsed_ns;
        }
    }

    /// Average elapsed time per call in nanoseconds.
    #[must_use]
    pub const fn avg_elapsed_ns(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_elapsed_ns / self.count
        }
    }

    /// Percentage of calls that returned an error, in basis points (×100).
    ///
    /// Returns `0..=10000`. Divide by 100 to get a percentage.
    #[must_use]
    pub const fn error_pct_bp(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            // Use saturating multiplication to avoid overflow when error_count is large.
            self.error_count.saturating_mul(10_000) / self.count
        }
    }
}

// ─── HotSyscall ───────────────────────────────────────────────────────────────

/// Identifies a syscall as "hot" — either by call frequency or by total
/// time spent inside the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotSyscall {
    /// Syscall number.
    pub nr: u32,
    /// Syscall name.
    pub name: String,
    /// Call count.
    pub count: u64,
    /// Total elapsed kernel time in nanoseconds.
    pub total_elapsed_ns: u64,
    /// Percentage of total calls, in basis points (×100). Divide by 100 for percent.
    pub count_pct_bp: u64,
    /// Percentage of total kernel time, in basis points (×100). Divide by 100 for percent.
    pub time_pct_bp: u64,
}

// ─── SyscallPattern ───────────────────────────────────────────────────────────

/// A detected pattern: a sequence of syscall numbers that recurs in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallPattern {
    /// The repeating sequence of syscall numbers.
    pub sequence: Vec<u32>,
    /// Number of times the sequence was observed.
    pub occurrences: usize,
    /// Human-readable description inferred from the sequence.
    pub description: String,
}

impl SyscallPattern {
    #[must_use]
    pub fn new(sequence: Vec<u32>, occurrences: usize, description: impl Into<String>) -> Self {
        Self {
            sequence,
            occurrences,
            description: description.into(),
        }
    }
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

/// A time-ordered list of syscall samples.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Timeline {
    samples: Vec<SyscallSample>,
}

impl Timeline {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a sample.
    pub fn push(&mut self, s: SyscallSample) {
        self.samples.push(s);
    }

    /// All samples in insertion order.
    #[must_use]
    pub fn samples(&self) -> &[SyscallSample] {
        &self.samples
    }

    /// Number of samples.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.samples.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Return only samples within the given nanosecond window.
    #[must_use]
    pub fn window(&self, start_ns: u64, end_ns: u64) -> Vec<&SyscallSample> {
        self.samples
            .iter()
            .filter(|s| s.timestamp_ns >= start_ns && s.timestamp_ns <= end_ns)
            .collect()
    }

    /// Sequence of syscall numbers in timeline order.
    #[must_use]
    pub fn nr_sequence(&self) -> Vec<u32> {
        let mut out = Vec::with_capacity(self.samples.len());
        out.extend(self.samples.iter().map(|s| s.nr));
        out
    }
}

// ─── StraceLikeFormatter ──────────────────────────────────────────────────────

/// Formats statistics in a style similar to `strace -c` output.
pub struct StraceLikeFormatter<'a> {
    stats: &'a SyscallStatistics,
}

impl<'a> StraceLikeFormatter<'a> {
    #[must_use]
    pub const fn new(stats: &'a SyscallStatistics) -> Self {
        Self { stats }
    }

    /// Render the summary table as a `String`.
    #[must_use]
    pub fn render(&self) -> String {
        let mut rows: Vec<&PerSyscallStats> = self.stats.per_syscall.values().collect();
        rows.sort_by(|a, b| b.total_elapsed_ns.cmp(&a.total_elapsed_ns));

        let total_elapsed: u64 = rows.iter().map(|r| r.total_elapsed_ns).sum();
        let total_calls: u64 = rows.iter().map(|r| r.count).sum();

        let mut out = String::with_capacity(128 + rows.len() * 80);
        out.push_str("% time     seconds  usecs/call     calls    errors syscall\n");
        out.push_str("------ ----------- ----------- --------- --------- ----------------\n");

        for row in &rows {
            // percent in basis-points (×100), then split into integer/fractional parts
            let pct_bp = if total_elapsed == 0 {
                0u64
            } else {
                // Saturating mul avoids overflow when total_elapsed_ns is near u64::MAX.
                row.total_elapsed_ns.saturating_mul(10_000) / total_elapsed
            };
            let pct_int = pct_bp / 100;
            let pct_frac = pct_bp % 100;
            // seconds as whole seconds + microseconds remainder
            let secs_whole = row.total_elapsed_ns / 1_000_000_000;
            let secs_frac = (row.total_elapsed_ns % 1_000_000_000) / 1_000;
            let usecs = if row.count == 0 {
                0
            } else {
                row.total_elapsed_ns / row.count / 1000
            };
            if row.error_count > 0 {
                let _ = writeln!(
                    out,
                    "{pct_int:3}.{pct_frac:02} {secs_whole:5}.{secs_frac:06} {:11} {:9} {:>9} {}",
                    usecs, row.count, row.error_count, row.name
                );
            } else {
                let _ = writeln!(
                    out,
                    "{pct_int:3}.{pct_frac:02} {secs_whole:5}.{secs_frac:06} {:11} {:9}           {}",
                    usecs, row.count, row.name
                );
            }
        }
        out.push_str("------ ----------- ----------- --------- --------- ----------------\n");
        let total_secs_whole = total_elapsed / 1_000_000_000;
        let total_secs_frac = (total_elapsed % 1_000_000_000) / 1_000;
        let _ = writeln!(out, "100.00 {total_secs_whole:5}.{total_secs_frac:06} {total_calls:>21} total");
        out
    }
}

// ─── SyscallStatistics ────────────────────────────────────────────────────────

/// Accumulates and analyses syscall statistics over a trace session.
#[derive(Debug)]
pub struct SyscallStatistics {
    /// Per-syscall aggregated stats keyed by syscall number.
    per_syscall: HashMap<u32, PerSyscallStats>,
    /// Time-ordered sample log.
    timeline: Timeline,
    /// Syscall database for name resolution.
    db: LinuxSyscallDb,
    /// Architecture (for name resolution).
    arch: SyscallArch,
}

impl Default for SyscallStatistics {
    fn default() -> Self {
        Self {
            per_syscall: HashMap::new(),
            timeline: Timeline::default(),
            db: LinuxSyscallDb::new(),
            arch: SyscallArch::X86_64,
        }
    }
}

impl SyscallStatistics {
    /// Create a new statistics collector for the given architecture.
    #[must_use]
    pub fn new(arch: SyscallArch) -> Self {
        Self {
            arch,
            db: LinuxSyscallDb::new(),
            ..Default::default()
        }
    }

    /// Record one syscall sample.
    pub fn record(&mut self, sample: SyscallSample) {
        let nr = sample.nr;
        let name = self
            .db
            .lookup(self.arch, nr)
            .map_or_else(|| format!("syscall_{nr}"), |s| s.name.clone());
        self.per_syscall
            .entry(nr)
            .or_insert_with(|| PerSyscallStats::new(nr, &name))
            .record(&sample);
        self.timeline.push(sample);
    }

    /// Return per-syscall stats for a specific syscall number.
    #[must_use]
    pub fn get(&self, nr: u32) -> Option<&PerSyscallStats> {
        self.per_syscall.get(&nr)
    }

    /// Return all per-syscall stats sorted by call count descending.
    #[must_use]
    pub fn all_by_count(&self) -> Vec<&PerSyscallStats> {
        let mut v: Vec<&PerSyscallStats> = self.per_syscall.values().collect();
        v.sort_by(|a, b| b.count.cmp(&a.count));
        v
    }

    /// Return the top-N hot syscalls by total kernel time.
    #[must_use]
    pub fn hot_by_time(&self, n: usize) -> Vec<HotSyscall> {
        let mut v: Vec<&PerSyscallStats> = Vec::with_capacity(self.per_syscall.len());
        let mut total_time: u64 = 0;
        let mut total_calls: u64 = 0;
        for s in self.per_syscall.values() {
            total_time += s.total_elapsed_ns;
            total_calls += s.count;
            v.push(s);
        }
        v.sort_by(|a, b| b.total_elapsed_ns.cmp(&a.total_elapsed_ns));
        v.into_iter()
            .take(n)
            .map(|s| HotSyscall {
                nr: s.nr,
                name: s.name.clone(),
                count: s.count,
                total_elapsed_ns: s.total_elapsed_ns,
                count_pct_bp: if total_calls == 0 {
                    0
                } else {
                    s.count.saturating_mul(10_000) / total_calls
                },
                time_pct_bp: if total_time == 0 {
                    0
                } else {
                    s.total_elapsed_ns.saturating_mul(10_000) / total_time
                },
            })
            .collect()
    }

    /// Return the top-N hot syscalls by call frequency.
    #[must_use]
    pub fn hot_by_count(&self, n: usize) -> Vec<HotSyscall> {
        let mut v: Vec<&PerSyscallStats> = Vec::with_capacity(self.per_syscall.len());
        let mut total_time: u64 = 0;
        let mut total_calls: u64 = 0;
        for s in self.per_syscall.values() {
            total_time += s.total_elapsed_ns;
            total_calls += s.count;
            v.push(s);
        }
        v.sort_by(|a, b| b.count.cmp(&a.count));
        v.into_iter()
            .take(n)
            .map(|s| HotSyscall {
                nr: s.nr,
                name: s.name.clone(),
                count: s.count,
                total_elapsed_ns: s.total_elapsed_ns,
                count_pct_bp: if total_calls == 0 {
                    0
                } else {
                    s.count.saturating_mul(10_000) / total_calls
                },
                time_pct_bp: if total_time == 0 {
                    0
                } else {
                    s.total_elapsed_ns.saturating_mul(10_000) / total_time
                },
            })
            .collect()
    }

    /// Detect recurring sequences of length `window` that appear at least
    /// `min_occurrences` times in the timeline.
    #[must_use]
    pub fn detect_patterns(&self, window: usize, min_occurrences: usize) -> Vec<SyscallPattern> {
        if window == 0 {
            return vec![];
        }
        let seq = self.timeline.nr_sequence();
        if seq.len() < window {
            return vec![];
        }

        let total_windows = seq.len() - window + 1;
        let mut counts: HashMap<Vec<u32>, usize> = HashMap::with_capacity(total_windows);
        for i in 0..=(seq.len() - window) {
            let slice = seq[i..i + window].to_vec();
            *counts.entry(slice).or_insert(0) += 1;
        }

        let mut patterns: Vec<SyscallPattern> = counts
            .into_iter()
            .filter(|(_, c)| *c >= min_occurrences)
            .map(|(seq, cnt)| {
                let desc = format!("sequence of {} syscalls repeated {} times", seq.len(), cnt);
                SyscallPattern::new(seq, cnt, desc)
            })
            .collect();
        patterns.sort_by(|a, b| b.occurrences.cmp(&a.occurrences));
        patterns
    }

    /// Return the timeline.
    #[must_use]
    pub const fn timeline(&self) -> &Timeline {
        &self.timeline
    }

    /// Total number of samples recorded.
    #[must_use]
    pub const fn total_samples(&self) -> usize {
        self.timeline.len()
    }

    /// Total distinct syscall numbers observed.
    #[must_use]
    pub fn distinct_syscalls(&self) -> usize {
        self.per_syscall.len()
    }

    /// Total elapsed kernel time across all syscalls in nanoseconds.
    #[must_use]
    pub fn total_elapsed_ns(&self) -> u64 {
        self.per_syscall.values().map(|s| s.total_elapsed_ns).sum()
    }

    /// Build a [`StraceLikeFormatter`] for this statistics object.
    #[must_use]
    pub const fn strace_formatter(&self) -> StraceLikeFormatter<'_> {
        StraceLikeFormatter::new(self)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_syscalls::SyscallArch;

    fn s(nr: u32, ts: u64, elapsed: u64, retval: i64) -> SyscallSample {
        SyscallSample::new(nr, ts, elapsed, retval, 1)
    }

    // --- SyscallSample ---

    #[test]
    fn sample_is_error_negative() {
        assert!(s(0, 0, 0, -1).is_error());
    }

    #[test]
    fn sample_not_error_zero() {
        assert!(!s(0, 0, 0, 0).is_error());
    }

    // --- PerSyscallStats ---

    #[test]
    fn per_syscall_record_accumulates() {
        let mut st = PerSyscallStats::new(0, "read");
        st.record(&s(0, 0, 100, 10));
        st.record(&s(0, 1, 200, -1));
        assert_eq!(st.count, 2);
        assert_eq!(st.error_count, 1);
        assert_eq!(st.total_elapsed_ns, 300);
        assert_eq!(st.min_elapsed_ns, 100);
        assert_eq!(st.max_elapsed_ns, 200);
    }

    #[test]
    fn per_syscall_avg_elapsed() {
        let mut st = PerSyscallStats::new(1, "write");
        st.record(&s(1, 0, 100, 0));
        st.record(&s(1, 1, 300, 0));
        assert_eq!(st.avg_elapsed_ns(), 200);
    }

    #[test]
    fn per_syscall_avg_zero_count() {
        let st = PerSyscallStats::new(1, "write");
        assert_eq!(st.avg_elapsed_ns(), 0);
    }

    #[test]
    fn per_syscall_error_pct() {
        let mut st = PerSyscallStats::new(0, "read");
        st.record(&s(0, 0, 0, -1));
        st.record(&s(0, 1, 0, 0));
        assert!((f64::from(u32::try_from(st.error_pct_bp()).unwrap_or(u32::MAX)) / 100.0 - 50.0).abs() < 1e-9);
    }

    // --- Timeline ---

    #[test]
    fn timeline_push_and_len() {
        let mut tl = Timeline::new();
        tl.push(s(0, 100, 10, 0));
        tl.push(s(1, 200, 20, 0));
        assert_eq!(tl.len(), 2);
    }

    #[test]
    fn timeline_window_filters() {
        let mut tl = Timeline::new();
        tl.push(s(0, 100, 0, 0));
        tl.push(s(1, 500, 0, 0));
        tl.push(s(2, 900, 0, 0));
        let w = tl.window(200, 800);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].nr, 1);
    }

    #[test]
    fn timeline_nr_sequence() {
        let mut tl = Timeline::new();
        tl.push(s(0, 0, 0, 0));
        tl.push(s(1, 1, 0, 0));
        tl.push(s(0, 2, 0, 0));
        assert_eq!(tl.nr_sequence(), vec![0, 1, 0]);
    }

    // --- SyscallStatistics ---

    #[test]
    fn stats_record_and_lookup() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        st.record(s(0, 0, 100, 0));
        st.record(s(0, 1, 200, 0));
        let ps = st.get(0).unwrap();
        assert_eq!(ps.count, 2);
        assert_eq!(ps.total_elapsed_ns, 300);
    }

    #[test]
    fn stats_total_samples() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        for i in 0..10u64 {
            st.record(s(u32::try_from(i % 3).unwrap(), i, 10, 0));
        }
        assert_eq!(st.total_samples(), 10);
    }

    #[test]
    fn stats_distinct_syscalls() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        st.record(s(0, 0, 0, 0));
        st.record(s(1, 1, 0, 0));
        st.record(s(0, 2, 0, 0));
        assert_eq!(st.distinct_syscalls(), 2);
    }

    #[test]
    fn stats_hot_by_count() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        for _ in 0..5 {
            st.record(s(0, 0, 10, 0));
        }
        for _ in 0..2 {
            st.record(s(1, 0, 10, 0));
        }
        let hot = st.hot_by_count(1);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].nr, 0);
        assert_eq!(hot[0].count, 5);
    }

    #[test]
    fn stats_hot_by_time() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        st.record(s(0, 0, 1000, 0));
        st.record(s(1, 1, 100, 0));
        let hot = st.hot_by_time(1);
        assert_eq!(hot[0].nr, 0);
    }

    #[test]
    fn stats_total_elapsed() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        st.record(s(0, 0, 500, 0));
        st.record(s(1, 1, 300, 0));
        assert_eq!(st.total_elapsed_ns(), 800);
    }

    #[test]
    fn stats_pattern_detection_simple() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        // push the sequence [0,1,2] three times
        for _ in 0..3 {
            st.record(s(0, 0, 0, 0));
            st.record(s(1, 1, 0, 0));
            st.record(s(2, 2, 0, 0));
        }
        let patterns = st.detect_patterns(3, 2);
        assert!(!patterns.is_empty());
        assert_eq!(patterns[0].sequence, vec![0, 1, 2]);
        assert!(patterns[0].occurrences >= 3);
    }

    #[test]
    fn stats_pattern_detection_empty_for_short_trace() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        st.record(s(0, 0, 0, 0));
        let patterns = st.detect_patterns(5, 1);
        assert!(patterns.is_empty());
    }

    #[test]
    fn stats_pattern_zero_window_returns_empty() {
        let st = SyscallStatistics::new(SyscallArch::X86_64);
        assert!(st.detect_patterns(0, 1).is_empty());
    }

    #[test]
    fn strace_formatter_renders() {
        let mut st = SyscallStatistics::new(SyscallArch::X86_64);
        st.record(s(0, 0, 1_000_000, 0));
        st.record(s(1, 1, 500_000, 0));
        let out = st.strace_formatter().render();
        assert!(out.contains("total"));
        assert!(out.contains("% time"));
    }
}
