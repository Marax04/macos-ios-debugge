//! YARA rule performance profiler.
//!
//! [`YaraPerformanceProfiler`] instruments YARA-like rule evaluation to
//! measure per-rule latency and identify hot-spots — rules that consume
//! a disproportionate share of scan time.
//!
//! The profiler uses monotonic [`Instant`] measurements to time each rule
//! independently.  After a profiling session it can produce ranked
//! [`ProfileResult`]s with suggestions for optimisation.
//!
//! Design:
//! - Each profiled scan increments a counter and accumulates elapsed time per rule.
//! - Statistics are kept in a sorted structure for O(log n) retrieval.
//! - [`ProfileResult`] provides mean, min, max, and a P95 estimate.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// RuleProfile
// ─────────────────────────────────────────────────────────────────────────────

/// Accumulated timing data for one YARA rule.
#[derive(Debug, Clone)]
pub struct RuleProfile {
    /// Rule name.
    pub name: String,
    /// Total number of times this rule was evaluated.
    pub eval_count: u64,
    /// Total accumulated wall-clock time across all evaluations.
    pub total_time: Duration,
    /// Minimum single-evaluation time.
    pub min_time: Duration,
    /// Maximum single-evaluation time.
    pub max_time: Duration,
    /// Number of times this rule produced a match.
    pub match_count: u64,
    /// Ordered sample of the last `N` durations (for percentile estimation).
    samples: Vec<Duration>,
}

impl RuleProfile {
    /// Create a new profile for a rule.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            eval_count: 0,
            total_time: Duration::ZERO,
            min_time: Duration::MAX,
            max_time: Duration::ZERO,
            match_count: 0,
            samples: Vec::new(),
        }
    }

    /// Record one evaluation that took `elapsed` and optionally produced a match.
    pub fn record(&mut self, elapsed: Duration, matched: bool) {
        self.eval_count += 1;
        self.total_time += elapsed;
        if elapsed < self.min_time {
            self.min_time = elapsed;
        }
        if elapsed > self.max_time {
            self.max_time = elapsed;
        }
        if matched {
            self.match_count += 1;
        }
        // Keep last 1 000 samples for percentile estimation
        if self.samples.len() < 1_000 {
            self.samples.push(elapsed);
        }
    }

    /// Mean evaluation time. Returns `Duration::ZERO` if never evaluated.
    #[must_use]
    pub fn mean_time(&self) -> Duration {
        if self.eval_count == 0 {
            return Duration::ZERO;
        }
        self.total_time / u32::try_from(self.eval_count).unwrap_or(u32::MAX)
    }

    /// Estimated P95 duration from the stored sample window.
    #[must_use]
    pub fn p95_time(&self) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let idx = sorted.len() * 95 / 100;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Match rate (0.0–1.0).
    #[must_use]
    pub fn match_rate(&self) -> f64 {
        if self.eval_count == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.match_count).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.eval_count).unwrap_or(u32::MAX))
    }

    /// True if `min_time` was never updated (no evaluations).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.eval_count == 0
    }
}

impl fmt::Display for RuleProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: evals={}, mean={:.3?}, min={:.3?}, max={:.3?}, p95={:.3?}, matches={}",
            self.name,
            self.eval_count,
            self.mean_time(),
            self.min_time,
            self.max_time,
            self.p95_time(),
            self.match_count
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProfileResult
// ─────────────────────────────────────────────────────────────────────────────

/// A final profiling result for one rule, including optimisation suggestions.
#[derive(Debug, Clone)]
pub struct ProfileResult {
    /// Rule name.
    pub name: String,
    /// Mean evaluation time.
    pub mean_time: Duration,
    /// Minimum evaluation time.
    pub min_time: Duration,
    /// Maximum evaluation time.
    pub max_time: Duration,
    /// Estimated P95 evaluation time.
    pub p95_time: Duration,
    /// Total evaluations.
    pub eval_count: u64,
    /// Total time consumed.
    pub total_time: Duration,
    /// Match rate 0.0–1.0.
    pub match_rate: f64,
    /// Percent of total profiling session time consumed by this rule.
    pub time_share_pct: f64,
    /// Optional optimisation hint.
    pub hint: Option<String>,
    /// Performance category.
    pub category: PerfCategory,
}

/// Performance category assigned by the profiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfCategory {
    /// Mean time under 10 µs.
    Fast,
    /// Mean time 10–100 µs.
    Moderate,
    /// Mean time 100 µs – 1 ms.
    Slow,
    /// Mean time over 1 ms.
    VerySlow,
}

impl PerfCategory {
    const fn from_mean(mean: Duration) -> Self {
        let us = mean.as_micros();
        if us < 10 {
            Self::Fast
        } else if us < 100 {
            Self::Moderate
        } else if us < 1_000 {
            Self::Slow
        } else {
            Self::VerySlow
        }
    }

    /// Short string label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fast => "FAST",
            Self::Moderate => "MODERATE",
            Self::Slow => "SLOW",
            Self::VerySlow => "VERY_SLOW",
        }
    }
}

impl fmt::Display for PerfCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl fmt::Display for ProfileResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} — mean={:.3?}, share={:.1}%",
            self.category,
            self.name,
            self.mean_time,
            self.time_share_pct
        )?;
        if let Some(hint) = &self.hint {
            write!(f, " — hint: {hint}")?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProfileSession
// ─────────────────────────────────────────────────────────────────────────────

/// A single profiling session — created by calling
/// [`YaraPerformanceProfiler::start_session`].
///
/// Use [`ProfileSession::time_rule`] to record the evaluation of each rule,
/// then [`ProfileSession::finish`] to commit results back to the profiler.
pub struct ProfileSession<'p> {
    profiler: &'p mut YaraPerformanceProfiler,
    /// Per-rule timings accumulated this session.
    timings: Vec<(String, Duration, bool)>,
    /// Wall-clock start of the session.
    session_start: Instant,
    /// Source URI being scanned.
    pub source_uri: String,
}

impl<'p> ProfileSession<'p> {
    /// Time one rule evaluation.
    ///
    /// Runs `f` and records the elapsed time for `rule_name`.
    /// `matched` should be `true` if the rule fired.
    pub fn time_rule<F>(&mut self, rule_name: &str, matched: bool, f: F)
    where
        F: FnOnce(),
    {
        let start = Instant::now();
        f();
        let elapsed = start.elapsed();
        self.timings.push((rule_name.to_string(), elapsed, matched));
    }

    /// Record a pre-measured rule evaluation.
    pub fn record_rule(&mut self, rule_name: &str, elapsed: Duration, matched: bool) {
        self.timings.push((rule_name.to_string(), elapsed, matched));
    }

    /// Commit this session's timings to the parent profiler and return the
    /// session's total wall-clock duration.
    #[must_use]
    pub fn finish(self) -> Duration {
        let elapsed = self.session_start.elapsed();
        for (name, dur, matched) in self.timings {
            self.profiler.record_evaluation(&name, dur, matched);
        }
        self.profiler.session_count += 1;
        self.profiler.total_session_time += elapsed;
        elapsed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YaraPerformanceProfiler
// ─────────────────────────────────────────────────────────────────────────────

/// Profiles YARA rule evaluation performance.
#[derive(Debug)]
pub struct YaraPerformanceProfiler {
    /// Per-rule accumulated statistics.
    profiles: HashMap<String, RuleProfile>,
    /// Total number of profiling sessions run.
    pub session_count: u64,
    /// Total wall-clock time across all sessions.
    pub total_session_time: Duration,
}

impl YaraPerformanceProfiler {
    /// Create a new empty profiler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            session_count: 0,
            total_session_time: Duration::ZERO,
        }
    }

    // ── Core recording ────────────────────────────────────────────────────────

    /// Record a single rule evaluation.
    pub fn record_evaluation(&mut self, rule_name: &str, elapsed: Duration, matched: bool) {
        self.profiles
            .entry(rule_name.to_string())
            .or_insert_with(|| RuleProfile::new(rule_name))
            .record(elapsed, matched);
    }

    /// Begin a new profiling session tied to `source_uri`.
    ///
    /// The session borrows the profiler mutably; call
    /// [`ProfileSession::finish`] to release it and commit results.
    pub fn start_session(&mut self, source_uri: impl Into<String>) -> ProfileSession<'_> {
        ProfileSession {
            profiler: self,
            timings: Vec::new(),
            session_start: Instant::now(),
            source_uri: source_uri.into(),
        }
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    /// Return a reference to the profile for `rule_name`, if it exists.
    #[must_use]
    pub fn get_profile(&self, rule_name: &str) -> Option<&RuleProfile> {
        self.profiles.get(rule_name)
    }

    /// Total wall-clock time spent evaluating all rules.
    #[must_use]
    pub fn total_rule_time(&self) -> Duration {
        self.profiles.values().map(|p| p.total_time).sum()
    }

    /// Number of rules that have been profiled.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.profiles.len()
    }

    // ── Reporting ─────────────────────────────────────────────────────────────

    /// Produce a ranked list of [`ProfileResult`]s, sorted by total time
    /// consumed (descending).
    #[must_use]
    pub fn results(&self) -> Vec<ProfileResult> {
        let grand_total = self.total_rule_time();
        let grand_total_us = grand_total.as_micros().max(1);

        let mut results: Vec<ProfileResult> = self
            .profiles
            .values()
            .map(|p| {
                let mean = p.mean_time();
                let time_share_pct =
                    f64::from(u32::try_from(p.total_time.as_micros()).unwrap_or(u32::MAX))
                    / f64::from(u32::try_from(grand_total_us).unwrap_or(u32::MAX)) * 100.0;
                let category = PerfCategory::from_mean(mean);
                let hint = build_hint(p, category);
                ProfileResult {
                    name: p.name.clone(),
                    mean_time: mean,
                    min_time: p.min_time,
                    max_time: p.max_time,
                    p95_time: p.p95_time(),
                    eval_count: p.eval_count,
                    total_time: p.total_time,
                    match_rate: p.match_rate(),
                    time_share_pct,
                    hint,
                    category,
                }
            })
            .collect();

        results.sort_unstable_by(|a, b| b.total_time.cmp(&a.total_time));
        results
    }

    /// Top-N slowest rules by mean evaluation time.
    #[must_use]
    pub fn top_slow(&self, n: usize) -> Vec<ProfileResult> {
        let mut results = self.results();
        results.sort_unstable_by(|a, b| b.mean_time.cmp(&a.mean_time));
        results.truncate(n);
        results
    }

    /// Rules that consumed more than `threshold_pct` percent of total rule time.
    #[must_use]
    pub fn hotspots(&self, threshold_pct: f64) -> Vec<ProfileResult> {
        self.results()
            .into_iter()
            .filter(|r| r.time_share_pct >= threshold_pct)
            .collect()
    }

    /// Mean evaluation time across all rules.
    #[must_use]
    pub fn global_mean_time(&self) -> Duration {
        if self.profiles.is_empty() {
            return Duration::ZERO;
        }
        let total = self.total_rule_time();
        let count: u64 = self.profiles.values().map(|p| p.eval_count).sum();
        if count == 0 {
            return Duration::ZERO;
        }
        total / u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Reset all profiling data.
    pub fn reset(&mut self) {
        self.profiles.clear();
        self.session_count = 0;
        self.total_session_time = Duration::ZERO;
    }

    /// Produce a human-readable profiling report.
    #[must_use]
    pub fn report_text(&self) -> String {
        use std::fmt::Write as _;
        let results = self.results();
        let mut out = String::new();
        out.push_str("=== YARA Performance Profile ===\n");
        let _ = writeln!(out, "Sessions   : {}", self.session_count);
        let _ = writeln!(out, "Total time : {:.3?}", self.total_session_time);
        let _ = writeln!(out, "Rules      : {}", self.rule_count());
        let _ = writeln!(out, "Global mean: {:.3?}", self.global_mean_time());
        out.push('\n');
        if results.is_empty() {
            out.push_str("(no data)\n");
        } else {
            for r in &results {
                let _ = writeln!(out, "  {r}");
            }
        }
        out
    }
}

impl Default for YaraPerformanceProfiler {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// build_hint — generate an optimisation hint for a rule
// ─────────────────────────────────────────────────────────────────────────────

fn build_hint(profile: &RuleProfile, category: PerfCategory) -> Option<String> {
    match category {
        PerfCategory::Fast => None,
        PerfCategory::Moderate => {
            if profile.match_rate() < 0.01 {
                Some(
                    "Rule rarely matches; consider moving it to a lower-priority tier.".to_string(),
                )
            } else {
                None
            }
        }
        PerfCategory::Slow => Some(format!(
            "Rule is slow (mean {:.0?}). Review pattern count and length.",
            profile.mean_time()
        )),
        PerfCategory::VerySlow => Some(format!(
            "Rule is very slow (mean {:.0?}). Profile patterns individually; consider splitting.",
            profile.mean_time()
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProfilingBenchmark — convenience wrapper for quick benchmarking
// ─────────────────────────────────────────────────────────────────────────────

/// A lightweight benchmark harness that exercises a pattern matcher against
/// sample data and records results in a [`YaraPerformanceProfiler`].
pub struct ProfilingBenchmark {
    profiler: YaraPerformanceProfiler,
    iterations: u32,
}

impl ProfilingBenchmark {
    /// Create a benchmark that runs each rule `iterations` times.
    #[must_use]
    pub fn new(iterations: u32) -> Self {
        Self {
            profiler: YaraPerformanceProfiler::new(),
            iterations,
        }
    }

    /// Benchmark a named byte-search pattern against `data`.
    ///
    /// Returns the number of matches found.
    pub fn bench_pattern(&mut self, name: &str, pattern: &[u8], data: &[u8]) -> u64 {
        let mut total_matches = 0u64;
        for _ in 0..self.iterations {
            let start = Instant::now();
            let matches = count_matches(pattern, data);
            let elapsed = start.elapsed();
            total_matches += matches;
            self.profiler.record_evaluation(name, elapsed, matches > 0);
        }
        total_matches
    }

    /// Return the internal profiler's results.
    #[must_use]
    pub fn results(&self) -> Vec<ProfileResult> {
        self.profiler.results()
    }

    /// Return the profiler's text report.
    #[must_use]
    pub fn report_text(&self) -> String {
        self.profiler.report_text()
    }
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_matches(needle: &[u8], haystack: &[u8]) -> u64 {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0u64;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if haystack[i..i + needle.len()] == *needle {
            count += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    count
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_profile_record() {
        let mut p = RuleProfile::new("Test");
        assert!(p.is_empty());
        p.record(Duration::from_micros(50), true);
        p.record(Duration::from_micros(100), false);
        assert_eq!(p.eval_count, 2);
        assert_eq!(p.match_count, 1);
        assert_eq!(p.mean_time(), Duration::from_micros(75));
        assert_eq!(p.min_time, Duration::from_micros(50));
        assert_eq!(p.max_time, Duration::from_micros(100));
    }

    #[test]
    fn test_match_rate() {
        let mut p = RuleProfile::new("R");
        p.record(Duration::from_micros(10), true);
        p.record(Duration::from_micros(10), false);
        assert!((p.match_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_p95_single_sample() {
        let mut p = RuleProfile::new("R");
        p.record(Duration::from_micros(42), false);
        assert_eq!(p.p95_time(), Duration::from_micros(42));
    }

    #[test]
    fn test_profiler_record_evaluation() {
        let mut profiler = YaraPerformanceProfiler::new();
        profiler.record_evaluation("R1", Duration::from_micros(10), false);
        profiler.record_evaluation("R1", Duration::from_micros(20), true);
        let p = profiler.get_profile("R1").unwrap();
        assert_eq!(p.eval_count, 2);
        assert_eq!(p.match_count, 1);
    }

    #[test]
    fn test_profiler_results_sorted_by_total_time() {
        let mut profiler = YaraPerformanceProfiler::new();
        profiler.record_evaluation("Fast", Duration::from_micros(1), false);
        profiler.record_evaluation("Slow", Duration::from_micros(1_000), false);
        let results = profiler.results();
        assert_eq!(results[0].name, "Slow");
        assert_eq!(results[1].name, "Fast");
    }

    #[test]
    fn test_hotspots() {
        let mut profiler = YaraPerformanceProfiler::new();
        profiler.record_evaluation("Big", Duration::from_millis(100), false);
        profiler.record_evaluation("Small", Duration::from_micros(1), false);
        let hot = profiler.hotspots(50.0);
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0].name, "Big");
    }

    #[test]
    fn test_top_slow() {
        let mut profiler = YaraPerformanceProfiler::new();
        for i in 0..5u64 {
            profiler.record_evaluation(
                &format!("R{i}"),
                Duration::from_micros(i * 10 + 1),
                false,
            );
        }
        let top = profiler.top_slow(2);
        assert_eq!(top.len(), 2);
        assert!(top[0].mean_time >= top[1].mean_time);
    }

    #[test]
    fn test_global_mean_time() {
        let mut profiler = YaraPerformanceProfiler::new();
        profiler.record_evaluation("A", Duration::from_micros(10), false);
        profiler.record_evaluation("B", Duration::from_micros(20), false);
        let mean = profiler.global_mean_time();
        assert_eq!(mean, Duration::from_micros(15));
    }

    #[test]
    fn test_reset() {
        let mut profiler = YaraPerformanceProfiler::new();
        profiler.record_evaluation("A", Duration::from_micros(10), false);
        profiler.reset();
        assert_eq!(profiler.rule_count(), 0);
        assert_eq!(profiler.session_count, 0);
    }

    #[test]
    fn test_profiling_session() {
        let mut profiler = YaraPerformanceProfiler::new();
        {
            let mut session = profiler.start_session("test.bin");
            session.record_rule("RuleA", Duration::from_micros(5), false);
            session.record_rule("RuleB", Duration::from_micros(50), true);
            let _elapsed = session.finish();
        }
        assert_eq!(profiler.session_count, 1);
        assert!(profiler.get_profile("RuleA").is_some());
        assert!(profiler.get_profile("RuleB").unwrap().match_count == 1);
    }

    #[test]
    fn test_profiling_benchmark() {
        let mut bench = ProfilingBenchmark::new(10);
        let data = b"hello world MZ end";
        let hits = bench.bench_pattern("MZ", b"MZ", data);
        assert!(hits > 0);
        let results = bench.results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].eval_count, 10);
    }

    #[test]
    fn test_pref_category() {
        assert_eq!(PerfCategory::from_mean(Duration::from_nanos(100)), PerfCategory::Fast);
        assert_eq!(PerfCategory::from_mean(Duration::from_micros(50)), PerfCategory::Moderate);
        assert_eq!(PerfCategory::from_mean(Duration::from_micros(500)), PerfCategory::Slow);
        assert_eq!(PerfCategory::from_mean(Duration::from_millis(2)), PerfCategory::VerySlow);
    }

    #[test]
    fn test_report_text_not_empty() {
        let mut profiler = YaraPerformanceProfiler::new();
        profiler.record_evaluation("UPX", Duration::from_micros(30), false);
        let text = profiler.report_text();
        assert!(text.contains("UPX"));
        assert!(text.contains("Sessions"));
    }

    #[test]
    fn test_count_matches() {
        assert_eq!(count_matches(b"AB", b"ABABAB"), 3);
        assert_eq!(count_matches(b"XX", b"AAABBB"), 0);
        assert_eq!(count_matches(b"", b"data"), 0);
    }
}
