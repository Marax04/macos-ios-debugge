//! `DemanglerBenchmark` — benchmark all demanglers across a symbol corpus.
//!
//! Measures demangling speed (nanoseconds per symbol), accuracy (fraction of
//! symbols successfully demangled), and produces a ranked `BenchmarkReport`.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::time::{Duration, Instant};

// ── DemangleTime ─────────────────────────────────────────────────────────────

/// Per-symbol demangling timing.
#[derive(Debug, Clone)]
pub struct DemangleTime {
    /// The mangled input symbol.
    pub mangled: String,
    /// The demangled output (if successful).
    pub demangled: Option<String>,
    /// Wall-clock duration for this single symbol.
    pub duration: Duration,
}

impl DemangleTime {
    /// Create a timing record for one demangled symbol.
    pub fn new(mangled: impl Into<String>, demangled: Option<String>, duration: Duration) -> Self {
        Self {
            mangled: mangled.into(),
            demangled,
            duration,
        }
    }

    /// Returns `true` if demangling succeeded.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        self.demangled.is_some()
    }

    /// Duration in nanoseconds.
    #[must_use]
    pub const fn nanos(&self) -> u128 {
        self.duration.as_nanos()
    }
}

// ── AccuracyScore ─────────────────────────────────────────────────────────────

/// Accuracy statistics for one demangler over a corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccuracyScore {
    /// Total symbols tested.
    pub total: usize,
    /// Symbols successfully demangled.
    pub successes: usize,
    /// Symbols that failed (returned None / unchanged).
    pub failures: usize,
    /// Symbols where the output matched the reference (if provided).
    pub correct: usize,
}

impl AccuracyScore {
    /// Build a score from raw counts; `failures` is derived as `total - successes`.
    #[must_use]
    pub const fn new(total: usize, successes: usize, correct: usize) -> Self {
        Self {
            total,
            successes,
            failures: total.saturating_sub(successes),
            correct,
        }
    }

    /// Fraction of symbols successfully demangled.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.successes).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
    }

    /// Fraction of symbols matching the reference output.
    #[must_use]
    pub fn accuracy(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.correct).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.total).unwrap_or(u32::MAX))
    }
}

// ── BenchmarkResult ────────────────────────────────────────────────────────────

/// Result for one demangler over a symbol corpus.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// Demangler identifier.
    pub demangler_id: String,
    /// Per-symbol timing records.
    pub timings: Vec<DemangleTime>,
    /// Accuracy statistics.
    pub accuracy: AccuracyScore,
}

impl BenchmarkResult {
    /// Mean demangling time in nanoseconds.
    #[must_use]
    pub fn mean_nanos(&self) -> f64 {
        if self.timings.is_empty() {
            return 0.0;
        }
        let sum: u128 = self.timings.iter().map(DemangleTime::nanos).sum();
        let len = self.timings.len() as u128;
        let int_mean = sum / len;
        f64::from(u32::try_from(int_mean).unwrap_or(u32::MAX))
    }

    /// Minimum demangling time across all symbols.
    pub fn min_nanos(&self) -> u128 {
        self.timings.iter().map(DemangleTime::nanos).min().unwrap_or(0)
    }

    /// Maximum demangling time.
    pub fn max_nanos(&self) -> u128 {
        self.timings.iter().map(DemangleTime::nanos).max().unwrap_or(0)
    }

    /// Median demangling time in nanoseconds.
    pub fn median_nanos(&self) -> u128 {
        if self.timings.is_empty() {
            return 0;
        }
        let mut ns: Vec<u128> = self.timings.iter().map(DemangleTime::nanos).collect();
        ns.sort_unstable();
        let mid = ns.len() / 2;
        if ns.len().is_multiple_of(2) {
            u128::midpoint(ns[mid - 1], ns[mid])
        } else {
            ns[mid]
        }
    }

    /// P99 latency in nanoseconds.
    pub fn p99_nanos(&self) -> u128 {
        if self.timings.is_empty() {
            return 0;
        }
        let mut ns: Vec<u128> = self.timings.iter().map(DemangleTime::nanos).collect();
        ns.sort_unstable();
        let idx = (ns.len() * 99 / 100).min(ns.len() - 1);
        ns[idx]
    }

    /// Total throughput in symbols per second.
    #[must_use]
    pub fn throughput_sps(&self) -> f64 {
        let mean = self.mean_nanos();
        if mean <= 0.0 {
            return f64::INFINITY;
        }
        1_000_000_000.0 / mean
    }

    /// List of symbols that failed to demangle.
    pub fn failed_symbols(&self) -> impl Iterator<Item = &str> {
        self.timings
            .iter()
            .filter(|t| !t.succeeded())
            .map(|t| t.mangled.as_str())
    }
}

// ── BenchmarkReport ───────────────────────────────────────────────────────────

/// Full benchmark report comparing all demanglers.
#[derive(Debug, Clone, Default)]
pub struct BenchmarkReport {
    /// Results per demangler, in the order they were run.
    pub results: Vec<BenchmarkResult>,
    /// ID of the fastest demangler.
    pub fastest_id: Option<String>,
    /// ID of the most accurate demangler.
    pub most_accurate_id: Option<String>,
    /// Total symbols in the corpus.
    pub corpus_size: usize,
    /// Any notes / warnings.
    pub notes: Vec<String>,
}

impl BenchmarkReport {
    /// Returns the result for a specific demangler, if present.
    #[must_use]
    pub fn result_for(&self, id: &str) -> Option<&BenchmarkResult> {
        self.results.iter().find(|r| r.demangler_id == id)
    }

    /// Returns results sorted by ascending `mean_nanos` (fastest first).
    ///
    /// # Panics
    ///
    /// Panics if `mean_nanos` returns NaN (should not occur in practice).
    #[must_use]
    pub fn ranked_by_speed(&self) -> Vec<&BenchmarkResult> {
        let mut v: Vec<&BenchmarkResult> = self.results.iter().collect();
        v.sort_by(|a, b| {
            a.mean_nanos()
                .partial_cmp(&b.mean_nanos())
                .unwrap()
        });
        v
    }

    /// Returns results sorted by descending accuracy.
    ///
    /// # Panics
    ///
    /// Panics if `success_rate` returns NaN (should not occur in practice).
    #[must_use]
    pub fn ranked_by_accuracy(&self) -> Vec<&BenchmarkResult> {
        let mut v: Vec<&BenchmarkResult> = self.results.iter().collect();
        v.sort_by(|a, b| {
            b.accuracy
                .success_rate()
                .partial_cmp(&a.accuracy.success_rate())
                .unwrap()
        });
        v
    }

    /// Markdown table of results.
    #[must_use]
    pub fn markdown_table(&self) -> String {
        let mut out = String::from("| Demangler | Mean ns | Median ns | P99 ns | Success% | Accuracy% |\n");
        out.push_str("|-----------|---------|-----------|--------|----------|----------|\n");
        for r in &self.results {
            writeln!(
                out,
                "| {} | {:.0} | {} | {} | {:.1}% | {:.1}% |",
                r.demangler_id,
                r.mean_nanos(),
                r.median_nanos(),
                r.p99_nanos(),
                r.accuracy.success_rate() * 100.0,
                r.accuracy.accuracy() * 100.0,
            ).ok();
        }
        out
    }

    /// Add a note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

// ── BenchmarkDemangler trait ──────────────────────────────────────────────────

/// Trait implemented by each demangler under test.
///
/// Named `BenchmarkDemangler` (not `Demangler`) to avoid shadowing the
/// crate-level `Demangler` trait exported from `lib.rs`.
pub trait BenchmarkDemangler: Send + Sync {
    /// Unique identifier for this demangler (e.g. `"itanium"`, `"msvc"`).
    fn id(&self) -> &str;

    /// Attempt to demangle `symbol`.  Returns `None` if not applicable.
    fn demangle(&self, symbol: &str) -> Option<String>;
}

// ── Built-in stub demanglers ──────────────────────────────────────────────────

/// Stub demangler that always succeeds (for testing).
pub struct AlwaysSucceedsDemangler {
    /// Identifier reported by [`BenchmarkDemangler::id`].
    pub id: String,
}

impl BenchmarkDemangler for AlwaysSucceedsDemangler {
    fn id(&self) -> &str {
        &self.id
    }
    fn demangle(&self, symbol: &str) -> Option<String> {
        Some(format!("demangled({symbol})"))
    }
}

/// Stub demangler that always fails (for testing).
pub struct AlwaysFailsDemangler {
    /// Identifier reported by [`BenchmarkDemangler::id`].
    pub id: String,
}

impl BenchmarkDemangler for AlwaysFailsDemangler {
    fn id(&self) -> &str {
        &self.id
    }
    fn demangle(&self, _symbol: &str) -> Option<String> {
        None
    }
}

/// Demangler that only handles symbols starting with a given prefix.
pub struct PrefixDemangler {
    /// Identifier reported by [`BenchmarkDemangler::id`].
    pub id: String,
    /// Required symbol prefix; the demangled output is the remainder.
    pub prefix: String,
}

impl BenchmarkDemangler for PrefixDemangler {
    fn id(&self) -> &str {
        &self.id
    }
    fn demangle(&self, symbol: &str) -> Option<String> {
        if symbol.starts_with(&self.prefix) {
            Some(symbol[self.prefix.len()..].to_string())
        } else {
            None
        }
    }
}

// ── DemanglerBenchmark ────────────────────────────────────────────────────────

/// Benchmark harness for multiple demanglers.
pub struct DemanglerBenchmark {
    /// Registered demanglers.
    demanglers: Vec<Box<dyn BenchmarkDemangler>>,
    /// Optional reference demangled output per symbol.
    reference: HashMap<String, String>,
    /// Number of warmup iterations before timing.
    pub warmup_iters: u32,
    /// Whether to record per-symbol timings (may be large for huge corpora).
    pub record_timings: bool,
}

impl DemanglerBenchmark {
    /// Create a new benchmark harness.
    #[must_use]
    pub fn new() -> Self {
        Self {
            demanglers: Vec::new(),
            reference: HashMap::new(),
            warmup_iters: 3,
            record_timings: true,
        }
    }

    /// Register a demangler.
    pub fn add_demangler(&mut self, d: impl BenchmarkDemangler + 'static) {
        self.demanglers.push(Box::new(d));
    }

    /// Add a reference mapping `mangled → expected_demangled`.
    pub fn add_reference(&mut self, mangled: impl Into<String>, expected: impl Into<String>) {
        self.reference.insert(mangled.into(), expected.into());
    }

    /// Add many reference entries at once.
    pub fn add_reference_batch(&mut self, entries: Vec<(String, String)>) {
        for (k, v) in entries {
            self.reference.insert(k, v);
        }
    }

    /// Set warmup iteration count.
    #[must_use]
    pub const fn with_warmup(mut self, n: u32) -> Self {
        self.warmup_iters = n;
        self
    }

    /// Run the benchmark over a symbol corpus and return a `BenchmarkReport`.
    #[must_use]
    pub fn run(&self, corpus: &[String]) -> BenchmarkReport {
        let mut report = BenchmarkReport {
            corpus_size: corpus.len(),
            ..Default::default()
        };

        let mut best_mean = f64::INFINITY;
        let mut best_accuracy = 0.0f64;

        for dem in &self.demanglers {
            // Warmup
            for _ in 0..self.warmup_iters {
                for sym in corpus {
                    let _ = dem.demangle(sym);
                }
            }

            // Timed run
            let mut timings = Vec::with_capacity(corpus.len());
            let mut successes = 0usize;
            let mut correct = 0usize;

            for sym in corpus {
                let start = Instant::now();
                let result = dem.demangle(sym);
                let elapsed = start.elapsed();

                if result.is_some() {
                    successes += 1;
                }
                if let (Some(got), Some(expected)) =
                    (&result, self.reference.get(sym.as_str()))
                {
                    if got == expected {
                        correct += 1;
                    }
                } else if result.is_none() && !self.reference.contains_key(sym.as_str()) {
                    // No reference: treat as N/A, don't penalise
                }

                if self.record_timings {
                    timings.push(DemangleTime::new(sym.clone(), result, elapsed));
                }
            }

            let accuracy =
                AccuracyScore::new(corpus.len(), successes, correct);

            let result = BenchmarkResult {
                demangler_id: dem.id().to_string(),
                timings,
                accuracy,
            };

            let mean = result.mean_nanos();
            let acc = result.accuracy.success_rate();

            if mean < best_mean {
                best_mean = mean;
                report.fastest_id = Some(dem.id().to_string());
            }
            if acc > best_accuracy {
                best_accuracy = acc;
                report.most_accurate_id = Some(dem.id().to_string());
            }

            report.results.push(result);
        }

        report
    }

    /// Run on a `&[&str]` slice for convenience.
    pub fn run_str(&self, corpus: &[&str]) -> BenchmarkReport {
        let owned: Vec<String> = corpus.iter().map(std::string::ToString::to_string).collect();
        self.run(&owned)
    }

    /// Number of registered demanglers.
    #[must_use]
    pub fn demangler_count(&self) -> usize {
        self.demanglers.len()
    }
}

impl Default for DemanglerBenchmark {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bench_with_both() -> DemanglerBenchmark {
        let mut b = DemanglerBenchmark::new().with_warmup(0);
        b.add_demangler(AlwaysSucceedsDemangler { id: "always".to_string() });
        b.add_demangler(AlwaysFailsDemangler { id: "never".to_string() });
        b
    }

    // ── DemangleTime ──────────────────────────────────────────────────────

    #[test]
    fn test_demangle_time_succeeded() {
        let t = DemangleTime::new("_Z3fooi", Some("foo(int)".to_string()), Duration::from_nanos(100));
        assert!(t.succeeded());
        assert_eq!(t.nanos(), 100);
    }

    #[test]
    fn test_demangle_time_failed() {
        let t = DemangleTime::new("plain_c_func", None, Duration::from_nanos(50));
        assert!(!t.succeeded());
    }

    // ── AccuracyScore ─────────────────────────────────────────────────────

    #[test]
    fn test_accuracy_success_rate_full() {
        let a = AccuracyScore::new(10, 10, 10);
        assert!((a.success_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_accuracy_success_rate_half() {
        let a = AccuracyScore::new(10, 5, 5);
        assert!((a.success_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_accuracy_empty_corpus() {
        let a = AccuracyScore::new(0, 0, 0);
        assert!((a.success_rate() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_accuracy_failures_computed() {
        let a = AccuracyScore::new(10, 7, 7);
        assert_eq!(a.failures, 3);
    }

    #[test]
    fn test_accuracy_score() {
        let a = AccuracyScore::new(10, 10, 8);
        assert!((a.accuracy() - 0.8).abs() < 1e-9);
    }

    // ── BenchmarkResult ───────────────────────────────────────────────────

    #[test]
    fn test_result_mean_nanos_empty() {
        let r = BenchmarkResult {
            demangler_id: "x".into(),
            timings: vec![],
            accuracy: AccuracyScore::new(0, 0, 0),
        };
        assert!(r.mean_nanos().abs() < f64::EPSILON);
    }

    #[test]
    fn test_result_mean_nanos() {
        let r = BenchmarkResult {
            demangler_id: "x".into(),
            timings: vec![
                DemangleTime::new("a", Some("A".into()), Duration::from_nanos(100)),
                DemangleTime::new("b", Some("B".into()), Duration::from_nanos(200)),
            ],
            accuracy: AccuracyScore::new(2, 2, 0),
        };
        assert!((r.mean_nanos() - 150.0).abs() < 1e-9);
    }

    #[test]
    fn test_result_min_max() {
        let r = BenchmarkResult {
            demangler_id: "x".into(),
            timings: vec![
                DemangleTime::new("a", None, Duration::from_nanos(50)),
                DemangleTime::new("b", None, Duration::from_nanos(300)),
                DemangleTime::new("c", None, Duration::from_nanos(150)),
            ],
            accuracy: AccuracyScore::new(3, 0, 0),
        };
        assert_eq!(r.min_nanos(), 50);
        assert_eq!(r.max_nanos(), 300);
    }

    #[test]
    fn test_result_median_odd() {
        let r = BenchmarkResult {
            demangler_id: "x".into(),
            timings: vec![
                DemangleTime::new("a", None, Duration::from_nanos(10)),
                DemangleTime::new("b", None, Duration::from_nanos(30)),
                DemangleTime::new("c", None, Duration::from_nanos(20)),
            ],
            accuracy: AccuracyScore::new(3, 0, 0),
        };
        assert_eq!(r.median_nanos(), 20);
    }

    #[test]
    fn test_result_median_even() {
        let r = BenchmarkResult {
            demangler_id: "x".into(),
            timings: vec![
                DemangleTime::new("a", None, Duration::from_nanos(10)),
                DemangleTime::new("b", None, Duration::from_nanos(20)),
                DemangleTime::new("c", None, Duration::from_nanos(30)),
                DemangleTime::new("d", None, Duration::from_nanos(40)),
            ],
            accuracy: AccuracyScore::new(4, 0, 0),
        };
        assert_eq!(r.median_nanos(), 25);
    }

    #[test]
    fn test_result_p99() {
        let timings: Vec<DemangleTime> = (0u64..100)
            .map(|i| DemangleTime::new("x", None, Duration::from_nanos(i + 1)))
            .collect();
        let r = BenchmarkResult {
            demangler_id: "x".into(),
            timings,
            accuracy: AccuracyScore::new(100, 0, 0),
        };
        assert!(r.p99_nanos() >= 99);
    }

    #[test]
    fn test_result_failed_symbols() {
        let r = BenchmarkResult {
            demangler_id: "x".into(),
            timings: vec![
                DemangleTime::new("ok", Some("OK".into()), Duration::default()),
                DemangleTime::new("bad", None, Duration::default()),
            ],
            accuracy: AccuracyScore::new(2, 1, 0),
        };
        let failed: Vec<&str> = r.failed_symbols().collect();
        assert_eq!(failed, vec!["bad"]);
    }

    // ── DemanglerBenchmark ────────────────────────────────────────────────

    #[test]
    fn test_run_empty_corpus() {
        let b = make_bench_with_both();
        let report = b.run_str(&[]);
        assert_eq!(report.corpus_size, 0);
        assert_eq!(report.results.len(), 2);
    }

    #[test]
    fn test_run_basic() {
        let b = make_bench_with_both();
        let report = b.run_str(&["_Z3fooi", "plain"]);
        assert_eq!(report.corpus_size, 2);
        // AlwaysSucceeds: 100% success rate
        let always = report.result_for("always").unwrap();
        assert!((always.accuracy.success_rate() - 1.0).abs() < 1e-9);
        // AlwaysFails: 0% success rate
        let never = report.result_for("never").unwrap();
        assert!((never.accuracy.success_rate() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_fastest_and_most_accurate() {
        let b = make_bench_with_both();
        let report = b.run_str(&["sym1"]);
        // fastest_id and most_accurate_id must be set
        assert!(report.fastest_id.is_some());
        assert!(report.most_accurate_id.is_some());
    }

    #[test]
    fn test_ranked_by_speed() {
        let b = make_bench_with_both();
        let report = b.run_str(&["x"]);
        let ranked = report.ranked_by_speed();
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn test_ranked_by_accuracy() {
        let b = make_bench_with_both();
        let report = b.run_str(&["x"]);
        let ranked = report.ranked_by_accuracy();
        // AlwaysSucceeds should come first
        assert_eq!(ranked[0].demangler_id, "always");
    }

    #[test]
    fn test_reference_accuracy() {
        let mut b = DemanglerBenchmark::new().with_warmup(0);
        b.add_demangler(AlwaysSucceedsDemangler { id: "s".into() });
        b.add_reference("sym", "demangled(sym)");
        let report = b.run_str(&["sym"]);
        let r = report.result_for("s").unwrap();
        assert_eq!(r.accuracy.correct, 1);
    }

    #[test]
    fn test_reference_wrong_output() {
        let mut b = DemanglerBenchmark::new().with_warmup(0);
        b.add_demangler(AlwaysSucceedsDemangler { id: "s".into() });
        b.add_reference("sym", "wrong_expected");
        let report = b.run_str(&["sym"]);
        let r = report.result_for("s").unwrap();
        assert_eq!(r.accuracy.correct, 0);
    }

    #[test]
    fn test_prefix_demangler() {
        let mut b = DemanglerBenchmark::new().with_warmup(0);
        b.add_demangler(PrefixDemangler {
            id: "prefix".into(),
            prefix: "_Z".into(),
        });
        let report = b.run_str(&["_Zfoo", "_Zbar", "plain"]);
        let r = report.result_for("prefix").unwrap();
        assert_eq!(r.accuracy.successes, 2);
        assert_eq!(r.accuracy.failures, 1);
    }

    #[test]
    fn test_add_reference_batch() {
        let mut b = DemanglerBenchmark::new();
        b.add_reference_batch(vec![
            ("a".to_string(), "A".to_string()),
            ("b".to_string(), "B".to_string()),
        ]);
        assert_eq!(b.reference.len(), 2);
    }

    #[test]
    fn test_demangler_count() {
        let mut b = DemanglerBenchmark::new();
        assert_eq!(b.demangler_count(), 0);
        b.add_demangler(AlwaysSucceedsDemangler { id: "x".into() });
        assert_eq!(b.demangler_count(), 1);
    }

    #[test]
    fn test_markdown_table_headers() {
        let b = make_bench_with_both();
        let report = b.run_str(&["x"]);
        let md = report.markdown_table();
        assert!(md.contains("Demangler"));
        assert!(md.contains("Mean ns"));
        assert!(md.contains("always"));
    }

    #[test]
    fn test_report_add_note() {
        let mut report = BenchmarkReport::default();
        report.add_note("test note");
        assert_eq!(report.notes.len(), 1);
    }

    #[test]
    fn test_throughput_sps_nonzero() {
        let r = BenchmarkResult {
            demangler_id: "x".into(),
            timings: vec![DemangleTime::new(
                "sym",
                Some("ok".into()),
                Duration::from_nanos(100),
            )],
            accuracy: AccuracyScore::new(1, 1, 0),
        };
        assert!(r.throughput_sps() > 0.0);
    }

    #[test]
    fn test_default_benchmark() {
        let b = DemanglerBenchmark::default();
        assert_eq!(b.demangler_count(), 0);
        assert_eq!(b.warmup_iters, 3);
    }

    // ── record_timings = false ────────────────────────────────────────────

    #[test]
    fn test_no_record_timings() {
        let mut b = DemanglerBenchmark::new().with_warmup(0);
        b.record_timings = false;
        b.add_demangler(AlwaysSucceedsDemangler { id: "s".into() });
        let report = b.run_str(&["x", "y"]);
        let r = report.result_for("s").unwrap();
        // timings should be empty when record_timings = false
        assert!(r.timings.is_empty());
        // but accuracy is still tracked
        assert_eq!(r.accuracy.total, 2);
    }
}
