//! YARA scan performance profiler.
//!
//! Tracks per-rule timing, per-string match time, hot-string detection, cache
//! hit rates, and produces optimization suggestions.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// Module-private cast helpers. These deliberately isolate lossy/wrapping casts
// at a boundary; precision loss for ratios and stats is acceptable.
#[inline]
fn u64_to_f64(v: u64) -> f64 {
    let lo = f64::from(u32::try_from(v & 0xFFFF_FFFF).unwrap_or(u32::MAX));
    let hi = f64::from(u32::try_from(v >> 32).unwrap_or(u32::MAX));
    hi.mul_add(4_294_967_296.0, lo)
}
#[inline]
fn usize_to_f64(v: usize) -> f64 { u64_to_f64(v as u64) }
#[inline]
fn u128_to_u64(v: u128) -> u64 { u64::try_from(v).unwrap_or(u64::MAX) }
#[inline]
fn f64_to_f32(v: f64) -> f32 {
    v.clamp(f64::from(f32::MIN), f64::from(f32::MAX))
        .to_string()
        .parse()
        .unwrap_or(0.0_f32)
}

// ── Timing primitives ─────────────────────────────────────────────────────────

/// A lightweight timer that records wall-clock durations.
#[derive(Debug, Clone)]
pub struct Timer {
    start: Option<Instant>,
    accumulated: Duration,
    samples: u64,
}

impl Timer {
    #[must_use]
    pub const fn new() -> Self {
        Self { start: None, accumulated: Duration::ZERO, samples: 0 }
    }

    /// Start timing a new interval.
    pub fn start(&mut self) {
        self.start = Some(Instant::now());
    }

    /// Stop the current interval and accumulate its duration.
    /// Returns the elapsed duration for this interval.
    pub fn stop(&mut self) -> Duration {
        if let Some(t) = self.start.take() {
            let elapsed = t.elapsed();
            self.accumulated += elapsed;
            self.samples += 1;
            elapsed
        } else {
            Duration::ZERO
        }
    }

    /// Total accumulated duration across all `start`/`stop` cycles.
    #[must_use]
    pub const fn total(&self) -> Duration {
        self.accumulated
    }

    /// Average duration per sample, or zero if no samples.
    #[must_use]
    pub fn average(&self) -> Duration {
        if self.samples == 0 {
            Duration::ZERO
        } else {
            self.accumulated / u32::try_from(self.samples).unwrap_or(u32::MAX)
        }
    }

    /// Number of completed timing intervals.
    #[must_use]
    pub const fn samples(&self) -> u64 {
        self.samples
    }

    /// Reset the timer to zero.
    pub const fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

// ── RuleProfile ───────────────────────────────────────────────────────────────

/// Performance data collected for a single YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProfile {
    /// Name of the rule.
    pub rule_name: String,
    /// Total wall-clock time spent evaluating this rule (nanoseconds).
    pub total_ns: u64,
    /// Number of times this rule was evaluated.
    pub eval_count: u64,
    /// Number of times this rule matched.
    pub match_count: u64,
    /// Per-string match durations (nanoseconds), keyed by string identifier.
    pub string_ns: HashMap<String, u64>,
    /// Per-string match counts, keyed by string identifier.
    pub string_match_counts: HashMap<String, u64>,
    /// Total bytes scanned while evaluating this rule.
    pub bytes_scanned: u64,
}

impl RuleProfile {
    #[must_use]
    pub fn new(rule_name: impl Into<String>) -> Self {
        Self {
            rule_name: rule_name.into(),
            total_ns: 0,
            eval_count: 0,
            match_count: 0,
            string_ns: HashMap::new(),
            string_match_counts: HashMap::new(),
            bytes_scanned: 0,
        }
    }

    /// Average evaluation time in nanoseconds.
    #[must_use]
    pub const fn avg_ns(&self) -> u64 {
        if self.eval_count == 0 { 0 } else { self.total_ns / self.eval_count }
    }

    /// Match rate in `[0, 1]`.
    #[must_use]
    pub fn match_rate(&self) -> f64 {
        if self.eval_count == 0 {
            0.0
        } else {
            u64_to_f64(self.match_count) / u64_to_f64(self.eval_count)
        }
    }

    /// Throughput in MB/s for this rule (0.0 if no data).
    #[must_use]
    pub fn throughput_mb_s(&self) -> f64 {
        if self.total_ns == 0 {
            return 0.0;
        }
        let bytes_f = u64_to_f64(self.bytes_scanned);
        let secs = u64_to_f64(self.total_ns) / 1e9;
        (bytes_f / (1024.0 * 1024.0)) / secs
    }

    /// Identify the slowest string (highest total ns).
    #[must_use]
    pub fn slowest_string(&self) -> Option<(&str, u64)> {
        self.string_ns
            .iter()
            .max_by_key(|&(_, &v)| v)
            .map(|(k, &v)| (k.as_str(), v))
    }

    /// Record one scan-string invocation.
    pub fn record_string(&mut self, ident: &str, elapsed_ns: u64, matched: bool) {
        *self.string_ns.entry(ident.to_string()).or_insert(0) += elapsed_ns;
        if matched {
            *self.string_match_counts.entry(ident.to_string()).or_insert(0) += 1;
        }
    }
}

// ── CacheStats ────────────────────────────────────────────────────────────────

/// Cache hit/miss statistics for the pattern-match cache.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Number of cache hits (pattern result reused from cache).
    pub hits: u64,
    /// Number of cache misses (pattern result computed from scratch).
    pub misses: u64,
    /// Number of entries currently in the cache.
    pub size: usize,
    /// Maximum cache size (capacity).
    pub capacity: usize,
}

impl CacheStats {
    /// Hit rate in `[0, 1]`, or 0 when no lookups have been made.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { u64_to_f64(self.hits) / u64_to_f64(total) }
    }

    /// Fill rate of the cache (size / capacity).
    #[must_use]
    pub fn fill_rate(&self) -> f64 {
        if self.capacity == 0 { 0.0 } else { usize_to_f64(self.size) / usize_to_f64(self.capacity) }
    }

    /// Record a cache hit.
    pub const fn record_hit(&mut self) { self.hits += 1; }

    /// Record a cache miss.
    pub const fn record_miss(&mut self) { self.misses += 1; }

    /// Reset counters.
    pub const fn reset(&mut self) {
        self.hits = 0;
        self.misses = 0;
    }
}

// ── HotString ─────────────────────────────────────────────────────────────────

/// A "hot" string — one that dominates scan time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotString {
    pub rule_name: String,
    pub string_id: String,
    pub total_ns: u64,
    pub match_count: u64,
    /// Fraction of rule-total ns consumed by this string.
    pub fraction_of_rule: f64,
}

// ── OptimizationSuggestion ────────────────────────────────────────────────────

/// A suggested optimisation derived from profiling data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSuggestion {
    pub kind: SuggestionKind,
    pub rule_name: String,
    pub detail: String,
    pub estimated_speedup: f32,
}

/// Category of optimization suggestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuggestionKind {
    /// This rule is never matching; consider disabling it.
    DisableUnusedRule,
    /// A string in this rule causes high overhead; use a hex pattern or anchoring.
    OptimizeHotString,
    /// The cache hit rate is very low; increase cache capacity.
    IncreaseCacheCapacity,
    /// Rule is slow and rarely matches; reorder condition or add anchors.
    AddAnchors,
    /// Use `nocase` on a hex pattern is inefficient; consider two hex patterns.
    AvoidNocaseHex,
    /// XOR scanning uses all 255 keys but only a narrow range appears; restrict range.
    NarrowXorRange,
    /// Rule consistently matches first string; reorder strings for early exit.
    ReorderStringsForEarlyExit,
}

// ── PerformanceProfiler ───────────────────────────────────────────────────────

/// Aggregates all timing and cache data for a YARA scan session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceProfiler {
    /// Per-rule profile data.
    pub rules: HashMap<String, RuleProfile>,
    /// Cache statistics.
    pub cache: CacheStats,
    /// Total number of files scanned in this session.
    pub files_scanned: u64,
    /// Total bytes scanned across all files.
    pub total_bytes: u64,
    /// Wall-clock duration of the entire session (nanoseconds).
    pub session_ns: u64,
    /// Active timers keyed by rule name (not serialised).
    #[serde(skip)]
    active_timers: HashMap<String, Instant>,
    /// Active string timers: (`rule_name`, `string_id`) → Instant.
    #[serde(skip)]
    string_timers: HashMap<(String, String), Instant>,
}

impl Default for PerformanceProfiler {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceProfiler {
    /// Create a new profiler.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            cache: CacheStats { capacity: 4096, ..CacheStats::default() },
            files_scanned: 0,
            total_bytes: 0,
            session_ns: 0,
            active_timers: HashMap::new(),
            string_timers: HashMap::new(),
        }
    }

    // ── Rule-level timing ─────────────────────────────────────────────────────

    /// Start timing the evaluation of `rule_name`.
    pub fn begin_rule(&mut self, rule_name: &str) {
        self.active_timers.insert(rule_name.to_string(), Instant::now());
        self.rules.entry(rule_name.to_string()).or_insert_with(|| RuleProfile::new(rule_name));
    }

    /// End timing for `rule_name`, recording whether it matched and how many
    /// bytes were scanned.
    pub fn end_rule(&mut self, rule_name: &str, matched: bool, bytes: usize) {
        let elapsed_ns = self.active_timers.remove(rule_name).map_or(0, |t| {
            u128_to_u64(t.elapsed().as_nanos())
        });
        if let Some(profile) = self.rules.get_mut(rule_name) {
            profile.total_ns += elapsed_ns;
            profile.eval_count += 1;
            if matched {
                profile.match_count += 1;
            }
            profile.bytes_scanned += u64::try_from(bytes).unwrap_or(u64::MAX);
        }
    }

    // ── String-level timing ───────────────────────────────────────────────────

    /// Start timing the scanning of string `string_id` within `rule_name`.
    pub fn begin_string(&mut self, rule_name: &str, string_id: &str) {
        self.string_timers.insert(
            (rule_name.to_string(), string_id.to_string()),
            Instant::now(),
        );
    }

    /// End timing for the given string, recording whether it matched.
    pub fn end_string(&mut self, rule_name: &str, string_id: &str, matched: bool) {
        let key = (rule_name.to_string(), string_id.to_string());
        let elapsed_ns = self.string_timers.remove(&key).map_or(0, |t| {
            u128_to_u64(t.elapsed().as_nanos())
        });
        if let Some(profile) = self.rules.get_mut(rule_name) {
            profile.record_string(string_id, elapsed_ns, matched);
        }
    }

    // ── Cache recording ───────────────────────────────────────────────────────

    /// Record a cache hit.
    pub const fn cache_hit(&mut self) { self.cache.record_hit(); }
    /// Record a cache miss.
    pub const fn cache_miss(&mut self) { self.cache.record_miss(); }
    /// Update the cache size.
    pub const fn set_cache_size(&mut self, n: usize) { self.cache.size = n; }

    // ── Session accounting ────────────────────────────────────────────────────

    /// Record that one more file has been scanned.
    pub fn record_file(&mut self, bytes: usize) {
        self.files_scanned += 1;
        self.total_bytes += u64::try_from(bytes).unwrap_or(u64::MAX);
    }

    /// Set the total session wall-clock time.
    pub const fn set_session_ns(&mut self, ns: u64) {
        self.session_ns = ns;
    }

    // ── Analysis ──────────────────────────────────────────────────────────────

    /// Return the top `n` slowest rules by total evaluation time.
    #[must_use]
    pub fn slowest_rules(&self, n: usize) -> Vec<&RuleProfile> {
        let mut profiles: Vec<&RuleProfile> = self.rules.values().collect();
        profiles.sort_by(|a, b| b.total_ns.cmp(&a.total_ns));
        profiles.truncate(n);
        profiles
    }

    /// Return the `n` hottest strings across all rules.
    #[must_use]
    pub fn hottest_strings(&self, n: usize) -> Vec<HotString> {
        let mut all: Vec<HotString> = Vec::new();
        for profile in self.rules.values() {
            for (sid, &ns) in &profile.string_ns {
                let fraction = if profile.total_ns == 0 {
                    0.0
                } else {
                    u64_to_f64(ns) / u64_to_f64(profile.total_ns)
                };
                all.push(HotString {
                    rule_name: profile.rule_name.clone(),
                    string_id: sid.clone(),
                    total_ns: ns,
                    match_count: profile.string_match_counts.get(sid).copied().unwrap_or(0),
                    fraction_of_rule: fraction,
                });
            }
        }
        all.sort_by(|a, b| b.total_ns.cmp(&a.total_ns));
        all.truncate(n);
        all
    }

    /// Derive optimization suggestions from the current profiling data.
    #[must_use]
    pub fn suggestions(&self) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        // Suggestion: disable rules that never match.
        for profile in self.rules.values() {
            if profile.eval_count >= 10 && profile.match_count == 0 {
                suggestions.push(OptimizationSuggestion {
                    kind: SuggestionKind::DisableUnusedRule,
                    rule_name: profile.rule_name.clone(),
                    detail: format!(
                        "Rule '{}' evaluated {} times with 0 matches; consider disabling.",
                        profile.rule_name, profile.eval_count
                    ),
                    estimated_speedup: estimate_speedup_from_ns(profile.total_ns, self.session_ns),
                });
            }
        }

        // Suggestion: optimise hot strings (>50% of rule time).
        for hs in self.hottest_strings(50) {
            if hs.fraction_of_rule > 0.5 && hs.total_ns > 1_000_000 {
                suggestions.push(OptimizationSuggestion {
                    kind: SuggestionKind::OptimizeHotString,
                    rule_name: hs.rule_name.clone(),
                    detail: format!(
                        "String '{}' in rule '{}' consumes {:.1}% of rule eval time.",
                        hs.string_id, hs.rule_name, hs.fraction_of_rule * 100.0
                    ),
                    estimated_speedup: 0.2,
                });
            }
        }

        // Suggestion: increase cache capacity if hit rate is low.
        if self.cache.hit_rate() < 0.5 && (self.cache.hits + self.cache.misses) > 1000 {
            suggestions.push(OptimizationSuggestion {
                kind: SuggestionKind::IncreaseCacheCapacity,
                rule_name: String::new(),
                detail: format!(
                    "Cache hit rate is {:.1}%. Consider doubling the cache capacity ({}).",
                    self.cache.hit_rate() * 100.0,
                    self.cache.capacity * 2
                ),
                estimated_speedup: 0.15,
            });
        }

        // Suggestion: add anchors to slow, rarely-matching rules.
        for profile in self.rules.values() {
            if profile.avg_ns() > 500_000 && profile.match_rate() < 0.01 && profile.eval_count >= 5 {
                suggestions.push(OptimizationSuggestion {
                    kind: SuggestionKind::AddAnchors,
                    rule_name: profile.rule_name.clone(),
                    detail: format!(
                        "Rule '{}' has {:.1}% match rate but avg {}µs — add string anchors.",
                        profile.rule_name,
                        profile.match_rate() * 100.0,
                        profile.avg_ns() / 1000
                    ),
                    estimated_speedup: 0.1,
                });
            }
        }

        // Sort suggestions by estimated speedup descending.
        suggestions.sort_by(|a, b| {
            b.estimated_speedup
                .partial_cmp(&a.estimated_speedup)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        suggestions
    }

    /// Throughput for the entire session in MB/s.
    #[must_use]
    pub fn session_throughput_mb_s(&self) -> f64 {
        if self.session_ns == 0 {
            return 0.0;
        }
        let bytes_f = u64_to_f64(self.total_bytes);
        let secs = u64_to_f64(self.session_ns) / 1e9;
        (bytes_f / (1024.0 * 1024.0)) / secs
    }

    /// Build a human-readable summary report.
    #[must_use]
    pub fn summary_report(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "=== YARA Performance Report ===\n\
             Files scanned : {}\n\
             Total bytes   : {} ({:.2} MB)\n\
             Session time  : {:.3}s\n\
             Throughput    : {:.1} MB/s\n\
             Cache hit rate: {:.1}%\n",
            self.files_scanned,
            self.total_bytes,
            u64_to_f64(self.total_bytes) / (1024.0 * 1024.0),
            u64_to_f64(self.session_ns) / 1e9,
            self.session_throughput_mb_s(),
            self.cache.hit_rate() * 100.0,
        ));

        lines.push("-- Top 10 slowest rules --".to_string());
        for p in self.slowest_rules(10) {
            lines.push(format!(
                "  {:40} total={:>10}µs  avg={:>8}µs  matches={}/{}",
                p.rule_name,
                p.total_ns / 1000,
                p.avg_ns() / 1000,
                p.match_count,
                p.eval_count,
            ));
        }

        lines.push("-- Top 10 hot strings --".to_string());
        for hs in self.hottest_strings(10) {
            lines.push(format!(
                "  {:30} in {:30}  {}µs  {:.1}%",
                hs.string_id,
                hs.rule_name,
                hs.total_ns / 1000,
                hs.fraction_of_rule * 100.0,
            ));
        }

        let suggs = self.suggestions();
        if !suggs.is_empty() {
            lines.push("-- Optimization suggestions --".to_string());
            for s in &suggs {
                lines.push(format!(
                    "  [{:?}] {} (est. +{:.0}% speedup)",
                    s.kind,
                    s.detail,
                    s.estimated_speedup * 100.0
                ));
            }
        }

        lines.join("\n")
    }

    /// Reset all profiling data.
    pub fn reset(&mut self) {
        self.rules.clear();
        self.cache.reset();
        self.files_scanned = 0;
        self.total_bytes = 0;
        self.session_ns = 0;
    }
}

fn estimate_speedup_from_ns(rule_ns: u64, session_ns: u64) -> f32 {
    if session_ns == 0 {
        return 0.0;
    }
    f64_to_f32(u64_to_f64(rule_ns) / u64_to_f64(session_ns))
}

// ── ProfiledScanSession ────────────────────────────────────────────────────────

/// Convenience wrapper that automatically starts/stops session timing.
pub struct ProfiledScanSession {
    pub profiler: PerformanceProfiler,
    session_start: Instant,
}

impl ProfiledScanSession {
    #[must_use]
    pub fn new() -> Self {
        Self {
            profiler: PerformanceProfiler::new(),
            session_start: Instant::now(),
        }
    }

    /// Finish the session and record total wall-clock time.
    #[must_use] 
    pub fn finish(mut self) -> PerformanceProfiler {
        let ns = u128_to_u64(self.session_start.elapsed().as_nanos());
        self.profiler.set_session_ns(ns);
        self.profiler
    }
}

impl Default for ProfiledScanSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_timer_basic() {
        let mut t = Timer::new();
        t.start();
        sleep(Duration::from_millis(1));
        let elapsed = t.stop();
        assert!(elapsed >= Duration::from_millis(1));
    }

    #[test]
    fn test_timer_average() {
        let mut t = Timer::new();
        for _ in 0..4 {
            t.start();
            sleep(Duration::from_micros(100));
            t.stop();
        }
        assert_eq!(t.samples(), 4);
        assert!(t.average() >= Duration::from_micros(90));
    }

    #[test]
    fn test_timer_reset() {
        let mut t = Timer::new();
        t.start();
        t.stop();
        t.reset();
        assert_eq!(t.samples(), 0);
        assert_eq!(t.total(), Duration::ZERO);
    }

    #[test]
    fn test_rule_profile_avg() {
        let mut p = RuleProfile::new("my_rule");
        p.total_ns = 1_000_000;
        p.eval_count = 4;
        assert_eq!(p.avg_ns(), 250_000);
    }

    #[test]
    fn test_rule_profile_match_rate() {
        let mut p = RuleProfile::new("r");
        p.eval_count = 10;
        p.match_count = 3;
        assert!((p.match_rate() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn test_rule_profile_throughput() {
        let mut p = RuleProfile::new("r");
        p.total_ns = 1_000_000_000; // 1 second
        p.bytes_scanned = 1024 * 1024; // 1 MB
        assert!((p.throughput_mb_s() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_rule_profile_slowest_string() {
        let mut p = RuleProfile::new("r");
        p.string_ns.insert("$a".into(), 100);
        p.string_ns.insert("$b".into(), 500);
        p.string_ns.insert("$c".into(), 200);
        let (id, ns) = p.slowest_string().unwrap();
        assert_eq!(id, "$b");
        assert_eq!(ns, 500);
    }

    #[test]
    fn test_cache_stats_hit_rate() {
        let mut c = CacheStats::default();
        for _ in 0..3 { c.record_hit(); }
        for _ in 0..1 { c.record_miss(); }
        assert!((c.hit_rate() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_cache_stats_fill_rate() {
        let c = CacheStats { size: 512, capacity: 1024, ..CacheStats::default() };
        assert!((c.fill_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_profiler_begin_end_rule() {
        let mut prof = PerformanceProfiler::new();
        prof.begin_rule("test_rule");
        sleep(Duration::from_micros(200));
        prof.end_rule("test_rule", true, 1024);
        let p = prof.rules.get("test_rule").unwrap();
        assert_eq!(p.eval_count, 1);
        assert_eq!(p.match_count, 1);
        assert!(p.total_ns > 0);
        assert_eq!(p.bytes_scanned, 1024);
    }

    #[test]
    fn test_profiler_string_timing() {
        let mut prof = PerformanceProfiler::new();
        prof.begin_rule("r");
        prof.begin_string("r", "$a");
        sleep(Duration::from_micros(50));
        prof.end_string("r", "$a", true);
        prof.end_rule("r", true, 0);
        let p = prof.rules.get("r").unwrap();
        assert!(p.string_ns.get("$a").copied().unwrap_or(0) > 0);
        assert_eq!(p.string_match_counts.get("$a").copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_profiler_cache_recording() {
        let mut prof = PerformanceProfiler::new();
        for _ in 0..10 { prof.cache_hit(); }
        for _ in 0..5 { prof.cache_miss(); }
        assert!((prof.cache.hit_rate() - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_profiler_file_accounting() {
        let mut prof = PerformanceProfiler::new();
        prof.record_file(1024);
        prof.record_file(2048);
        assert_eq!(prof.files_scanned, 2);
        assert_eq!(prof.total_bytes, 3072);
    }

    #[test]
    fn test_profiler_slowest_rules() {
        let mut prof = PerformanceProfiler::new();
        for (name, ns) in &[("slow", 1_000_000u64), ("fast", 1_000u64), ("medium", 50_000u64)] {
            let mut p = RuleProfile::new(*name);
            p.total_ns = *ns;
            p.eval_count = 1;
            prof.rules.insert(name.to_string(), p);
        }
        let top = prof.slowest_rules(2);
        assert_eq!(top[0].rule_name, "slow");
        assert_eq!(top[1].rule_name, "medium");
    }

    #[test]
    fn test_profiler_hottest_strings() {
        let mut prof = PerformanceProfiler::new();
        let mut p = RuleProfile::new("rule_a");
        p.total_ns = 1_000_000;
        p.string_ns.insert("$fast".into(), 100_000);
        p.string_ns.insert("$slow".into(), 900_000);
        prof.rules.insert("rule_a".into(), p);
        let hot = prof.hottest_strings(1);
        assert_eq!(hot[0].string_id, "$slow");
        assert!((hot[0].fraction_of_rule - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_profiler_suggestions_unused_rule() {
        let mut prof = PerformanceProfiler::new();
        let mut p = RuleProfile::new("dead_rule");
        p.eval_count = 20;
        p.match_count = 0;
        p.total_ns = 500_000;
        prof.rules.insert("dead_rule".into(), p);
        prof.session_ns = 10_000_000;
        let suggs = prof.suggestions();
        assert!(suggs.iter().any(|s| s.kind == SuggestionKind::DisableUnusedRule));
    }

    #[test]
    fn test_profiler_suggestions_hot_string() {
        let mut prof = PerformanceProfiler::new();
        let mut p = RuleProfile::new("hot_rule");
        p.total_ns = 5_000_000;
        p.eval_count = 1;
        p.string_ns.insert("$hotpattern".into(), 4_500_000);
        prof.rules.insert("hot_rule".into(), p);
        let suggs = prof.suggestions();
        assert!(suggs.iter().any(|s| s.kind == SuggestionKind::OptimizeHotString));
    }

    #[test]
    fn test_profiler_reset() {
        let mut prof = PerformanceProfiler::new();
        prof.begin_rule("r");
        prof.end_rule("r", false, 0);
        prof.record_file(1000);
        prof.reset();
        assert!(prof.rules.is_empty());
        assert_eq!(prof.files_scanned, 0);
        assert_eq!(prof.total_bytes, 0);
    }

    #[test]
    fn test_session_throughput() {
        let mut prof = PerformanceProfiler::new();
        prof.set_session_ns(1_000_000_000);
        prof.total_bytes = 2 * 1024 * 1024;
        assert!((prof.session_throughput_mb_s() - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_profiled_session_finish() {
        let session = ProfiledScanSession::new();
        sleep(Duration::from_millis(1));
        let profiler = session.finish();
        assert!(profiler.session_ns > 0);
    }
}
