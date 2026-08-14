//! Coverage feedback system for `rustre-fuzz-cov`.
//!
//! Provides:
//! - [`CoverageMap`]: edge/block/path coverage bitmaps.
//! - [`BitmapCompare`]: fast new-bit detection between two coverage maps.
//! - [`FeedbackSignal`]: interesting / not-interesting / crash classification.
//! - [`FeedbackHistory`]: ring-buffer of past signals.
//! - [`CoverageGrowthMetric`]: tracks how quickly coverage grows over time.
//! - [`FeedbackLoop`]: orchestrates the full feedback cycle.
//! - [`CoverageFeedback`]: high-level facade.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CoverageMapKind
// ---------------------------------------------------------------------------

/// The granularity / type of coverage tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CoverageMapKind {
    /// Edge coverage (branch source → target transitions).
    Edge,
    /// Basic-block coverage (individual BB visits).
    Block,
    /// Path coverage (sequences of BBs — exponentially many).
    Path,
    /// Call-site coverage.
    CallSite,
}

impl fmt::Display for CoverageMapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Edge => write!(f, "edge"),
            Self::Block => write!(f, "block"),
            Self::Path => write!(f, "path"),
            Self::CallSite => write!(f, "call_site"),
        }
    }
}

// ---------------------------------------------------------------------------
// CoverageMap
// ---------------------------------------------------------------------------

/// A fixed-size bitmap representing coverage.
///
/// Each bit represents whether a particular edge/block was executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMap {
    pub kind: CoverageMapKind,
    /// Bitmap: one byte per bucket.
    pub map: Vec<u8>,
    /// Total bits set.
    bits_set: usize,
}

impl CoverageMap {
    /// Create a zero-filled map of `size` bytes.
    #[must_use]
    pub fn new(kind: CoverageMapKind, size: usize) -> Self {
        Self {
            kind,
            map: vec![0u8; size],
            bits_set: 0,
        }
    }

    /// Standard AFL-style map (65536 bytes).
    #[must_use]
    pub fn afl_default(kind: CoverageMapKind) -> Self {
        Self::new(kind, 65536)
    }

    /// Set a bit at `index` (using AFL-style hit-count saturation).
    pub fn record_hit(&mut self, index: usize) {
        if index >= self.map.len() {
            return;
        }
        if self.map[index] == 0 {
            self.bits_set += 1;
        }
        self.map[index] = self.map[index].saturating_add(1);
    }

    /// Set an edge identified by `(from, to)` addresses.
    pub fn record_edge(&mut self, from: u64, to: u64) {
        let hash = edge_hash(from, to) % self.map.len();
        self.record_hit(hash);
    }

    /// Number of unique buckets hit.
    #[must_use]
    pub const fn coverage_count(&self) -> usize {
        self.bits_set
    }

    /// Total map size in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.map.len()
    }

    /// Coverage density (0.0–1.0).
    #[must_use]
    pub fn density(&self) -> f64 {
        if self.map.is_empty() {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.bits_set) / crate::casts::usize_to_f64(self.map.len())
    }

    /// Clear the map.
    pub fn clear(&mut self) {
        self.map.fill(0);
        self.bits_set = 0;
    }

    /// Merge `other` into `self` (bitwise OR).
    pub fn merge(&mut self, other: &Self) {
        let len = self.map.len().min(other.map.len());
        for i in 0..len {
            if self.map[i] == 0 && other.map[i] > 0 {
                self.bits_set += 1;
            }
            self.map[i] |= other.map[i];
        }
    }
}

fn edge_hash(from: u64, to: u64) -> usize {
    let h = from.wrapping_mul(0x517C_C1B7_2722_0A95) ^ to.wrapping_mul(0x6C62_272E_07BB_0142);
    crate::casts::u64_to_usize(h)
}

// ---------------------------------------------------------------------------
// BitmapCompare
// ---------------------------------------------------------------------------

/// New-bits detection result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewBitsResult {
    /// Number of bits newly set compared to the global map.
    pub new_bits: usize,
    /// Number of bits with increased hit-counts.
    pub increased_bits: usize,
    /// Indices of newly-set bits (up to `max_report` entries).
    pub new_indices: Vec<usize>,
}

impl NewBitsResult {
    /// Returns `true` if any new coverage was discovered.
    #[must_use]
    pub const fn has_new_coverage(&self) -> bool {
        self.new_bits > 0
    }
}

/// Compares a trace map against a global (corpus) map to find new coverage.
#[derive(Debug, Default)]
pub struct BitmapCompare;

impl BitmapCompare {
    /// Find bits that are set in `trace` but not in `global`.
    ///
    /// `max_report` caps the length of `new_indices` to avoid huge allocations.
    #[must_use]
    pub fn find_new_bits(
        trace: &CoverageMap,
        global: &CoverageMap,
        max_report: usize,
    ) -> NewBitsResult {
        let len = trace.map.len().min(global.map.len());
        let mut new_bits = 0;
        let mut increased_bits = 0;
        let mut new_indices = Vec::new();

        for i in 0..len {
            let t = trace.map[i];
            let g = global.map[i];
            if t > 0 {
                if g == 0 {
                    new_bits += 1;
                    if new_indices.len() < max_report {
                        new_indices.push(i);
                    }
                } else if t > g {
                    increased_bits += 1;
                }
            }
        }

        NewBitsResult {
            new_bits,
            increased_bits,
            new_indices,
        }
    }

    /// Update `global` to include all bits in `trace`.  Returns how many new
    /// bits were added.
    pub fn update_global(trace: &CoverageMap, global: &mut CoverageMap) -> usize {
        let len = trace.map.len().min(global.map.len());
        let mut added = 0;
        for i in 0..len {
            if trace.map[i] > 0 && global.map[i] == 0 {
                added += 1;
            }
            global.map[i] |= trace.map[i];
        }
        global.bits_set = global.map.iter().filter(|&&b| b > 0).count();
        added
    }
}

// ---------------------------------------------------------------------------
// FeedbackSignal
// ---------------------------------------------------------------------------

/// Classification of a fuzzing run's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedbackSignal {
    /// The input triggered new coverage — keep it in the corpus.
    Interesting {
        new_bits: usize,
        increased_hits: usize,
    },
    /// No new coverage discovered — discard.
    NotInteresting,
    /// A crash was detected.
    Crash { signal: u32, address: Option<u64> },
    /// A timeout was hit.
    Timeout { elapsed_ms: u64 },
    /// A user-specified condition was triggered.
    UserDefined { tag: String },
}

impl FeedbackSignal {
    /// Returns `true` if this signal warrants saving the input.
    #[must_use]
    pub const fn should_save(&self) -> bool {
        matches!(
            self,
            Self::Interesting { .. } | Self::Crash { .. } | Self::UserDefined { .. }
        )
    }

    /// Returns `true` if this is a crash.
    #[must_use]
    pub const fn is_crash(&self) -> bool {
        matches!(self, Self::Crash { .. })
    }

    /// Returns `true` if this is interesting (new coverage).
    #[must_use]
    pub const fn is_interesting(&self) -> bool {
        matches!(self, Self::Interesting { .. })
    }
}

impl fmt::Display for FeedbackSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interesting {
                new_bits,
                increased_hits,
            } => write!(f, "Interesting(new={new_bits}, hit+={increased_hits})"),
            Self::NotInteresting => write!(f, "NotInteresting"),
            Self::Crash { signal, address } => write!(f, "Crash(sig={signal}, addr={address:?})"),
            Self::Timeout { elapsed_ms } => write!(f, "Timeout({elapsed_ms}ms)"),
            Self::UserDefined { tag } => write!(f, "UserDefined({tag})"),
        }
    }
}

// ---------------------------------------------------------------------------
// FeedbackHistory
// ---------------------------------------------------------------------------

/// Ring-buffer of feedback signals from recent fuzzing iterations.
#[derive(Debug, Clone)]
pub struct FeedbackHistory {
    history: VecDeque<(u64, FeedbackSignal)>,
    capacity: usize,
    total_iterations: u64,
    total_interesting: u64,
    total_crashes: u64,
    total_timeouts: u64,
}

impl FeedbackHistory {
    /// Create a history ring-buffer with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(capacity),
            capacity,
            total_iterations: 0,
            total_interesting: 0,
            total_crashes: 0,
            total_timeouts: 0,
        }
    }

    /// Record a signal.
    pub fn record(&mut self, signal: FeedbackSignal) {
        self.total_iterations += 1;
        match &signal {
            FeedbackSignal::Interesting { .. } => self.total_interesting += 1,
            FeedbackSignal::Crash { .. } => self.total_crashes += 1,
            FeedbackSignal::Timeout { .. } => self.total_timeouts += 1,
            _ => {}
        }
        if self.history.len() >= self.capacity {
            self.history.pop_front();
        }
        self.history.push_back((self.total_iterations, signal));
    }

    /// Return the `n` most-recent entries.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<&(u64, FeedbackSignal)> {
        let start = self.history.len().saturating_sub(n);
        self.history.iter().skip(start).collect()
    }

    /// Interesting rate (interesting / total).
    #[must_use]
    pub fn interesting_rate(&self) -> f64 {
        if self.total_iterations == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.total_interesting) / crate::casts::u64_to_f64(self.total_iterations)
        }
    }

    /// Crash rate.
    #[must_use]
    pub fn crash_rate(&self) -> f64 {
        if self.total_iterations == 0 {
            0.0
        } else {
            crate::casts::u64_to_f64(self.total_crashes) / crate::casts::u64_to_f64(self.total_iterations)
        }
    }

    /// Number of entries in the history buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.history.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.history.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CoverageGrowthMetric
// ---------------------------------------------------------------------------

/// Tracks how coverage grows over time.
#[derive(Debug, Clone)]
pub struct CoverageGrowthMetric {
    snapshots: Vec<(u64, usize)>, // (iteration, coverage_count)
    start: Instant,
    initial_coverage: usize,
}

impl CoverageGrowthMetric {
    #[must_use]
    pub fn new(initial_coverage: usize) -> Self {
        Self {
            snapshots: vec![(0, initial_coverage)],
            start: Instant::now(),
            initial_coverage,
        }
    }

    /// Record the current coverage count at the given iteration.
    pub fn snapshot(&mut self, iteration: u64, coverage: usize) {
        self.snapshots.push((iteration, coverage));
    }

    /// Latest known coverage count.
    #[must_use]
    pub fn latest_coverage(&self) -> usize {
        self.snapshots
            .last()
            .map_or(self.initial_coverage, |(_, c)| *c)
    }

    /// Total coverage growth since the start.
    #[must_use]
    pub fn total_growth(&self) -> usize {
        self.latest_coverage().saturating_sub(self.initial_coverage)
    }

    /// Average coverage growth per 1000 iterations.
    #[must_use]
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn growth_rate_per_k(&self) -> f64 {
        if self.snapshots.len() < 2 {
            return 0.0;
        }
        let (first_iter, first_cov) = self.snapshots[0];
        let (last_iter, last_cov) = *self.snapshots.last().unwrap();
        let iter_span = crate::casts::u64_to_f64(last_iter - first_iter);
        if iter_span < 1.0 {
            return 0.0;
        }
        (crate::casts::usize_to_f64(last_cov) - crate::casts::usize_to_f64(first_cov)) / iter_span * 1000.0
    }

    /// Elapsed time.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Edges per second.
    #[must_use]
    pub fn edges_per_second(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs < 0.0001 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.total_growth()) / secs
    }
}

// ---------------------------------------------------------------------------
// FeedbackLoop
// ---------------------------------------------------------------------------

/// Orchestrates one complete feedback cycle: run → trace → compare → signal.
pub struct FeedbackLoop {
    pub global_map: CoverageMap,
    pub history: FeedbackHistory,
    pub growth: CoverageGrowthMetric,
    iteration: u64,
    pub crash_corpus: Vec<Vec<u8>>,
    pub interesting_corpus: Vec<Vec<u8>>,
}

impl FeedbackLoop {
    /// Create a new feedback loop with an edge map of the given size.
    #[must_use]
    pub fn new(map_size: usize) -> Self {
        Self {
            global_map: CoverageMap::new(CoverageMapKind::Edge, map_size),
            history: FeedbackHistory::new(10_000),
            growth: CoverageGrowthMetric::new(0),
            iteration: 0,
            crash_corpus: Vec::new(),
            interesting_corpus: Vec::new(),
        }
    }

    /// Process the result of one fuzzing iteration.
    ///
    /// `trace` is the coverage map recorded during this run.
    /// `input` is the input that produced the trace.
    /// `crashed` indicates a crash signal was received.
    /// `crash_signal` and `crash_addr` carry crash details.
    ///
    /// Returns the [`FeedbackSignal`].
    pub fn process(
        &mut self,
        trace: &CoverageMap,
        input: Vec<u8>,
        crashed: bool,
        crash_signal: u32,
        crash_addr: Option<u64>,
    ) -> FeedbackSignal {
        self.iteration += 1;
        let signal = if crashed {
            FeedbackSignal::Crash {
                signal: crash_signal,
                address: crash_addr,
            }
        } else {
            let result = BitmapCompare::find_new_bits(trace, &self.global_map, 64);
            if result.has_new_coverage() {
                FeedbackSignal::Interesting {
                    new_bits: result.new_bits,
                    increased_hits: result.increased_bits,
                }
            } else {
                FeedbackSignal::NotInteresting
            }
        };

        if signal.should_save() {
            if signal.is_crash() {
                self.crash_corpus.push(input);
            } else {
                self.interesting_corpus.push(input);
            }
            BitmapCompare::update_global(trace, &mut self.global_map);
        }

        self.growth
            .snapshot(self.iteration, self.global_map.coverage_count());
        self.history.record(signal.clone());
        signal
    }

    /// Number of iterations processed.
    #[must_use]
    pub const fn iteration_count(&self) -> u64 {
        self.iteration
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "FeedbackLoop: iter={} coverage={} interesting={} crashes={} growth/k={:.2}",
            self.iteration,
            self.global_map.coverage_count(),
            self.interesting_corpus.len(),
            self.crash_corpus.len(),
            self.growth.growth_rate_per_k(),
        )
    }
}

// ---------------------------------------------------------------------------
// CoverageFeedback (high-level facade)
// ---------------------------------------------------------------------------

/// High-level facade combining all coverage feedback components.
pub struct CoverageFeedback {
    pub feedback_loop: FeedbackLoop,
    pub kind: CoverageMapKind,
}

impl CoverageFeedback {
    /// Create with a 64 KB edge map.
    #[must_use]
    pub fn new_edge() -> Self {
        Self {
            feedback_loop: FeedbackLoop::new(65536),
            kind: CoverageMapKind::Edge,
        }
    }

    /// Create with a custom map size.
    #[must_use]
    pub fn new(kind: CoverageMapKind, map_size: usize) -> Self {
        Self {
            feedback_loop: FeedbackLoop::new(map_size),
            kind,
        }
    }

    /// Submit a trace and classify the feedback.
    pub fn submit(&mut self, trace: &CoverageMap, input: Vec<u8>, crashed: bool) -> FeedbackSignal {
        self.feedback_loop.process(trace, input, crashed, 11, None)
    }

    /// Current global coverage count.
    #[must_use]
    pub const fn coverage(&self) -> usize {
        self.feedback_loop.global_map.coverage_count()
    }

    /// Summary.
    #[must_use]
    pub fn summary(&self) -> String {
        self.feedback_loop.summary()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace(kind: CoverageMapKind, hits: &[(usize, u8)]) -> CoverageMap {
        let mut m = CoverageMap::new(kind, 256);
        for &(idx, val) in hits {
            m.map[idx] = val;
            if val > 0 {
                m.bits_set += 1;
            }
        }
        m
    }

    // ── CoverageMap ──────────────────────────────────────────────────────

    #[test]
    fn coverage_map_new_zero() {
        let m = CoverageMap::new(CoverageMapKind::Edge, 16);
        assert_eq!(m.coverage_count(), 0);
        assert_eq!(m.size(), 16);
        assert!(m.density().abs() < f64::EPSILON);
    }

    #[test]
    fn coverage_map_record_hit() {
        let mut m = CoverageMap::new(CoverageMapKind::Block, 16);
        m.record_hit(5);
        assert_eq!(m.coverage_count(), 1);
        m.record_hit(5);
        assert_eq!(m.coverage_count(), 1); // same bit, no new
    }

    #[test]
    fn coverage_map_record_edge() {
        let mut m = CoverageMap::afl_default(CoverageMapKind::Edge);
        m.record_edge(0x1000, 0x2000);
        assert!(m.coverage_count() > 0);
    }

    #[test]
    fn coverage_map_density() {
        let mut m = CoverageMap::new(CoverageMapKind::Edge, 4);
        m.record_hit(0);
        m.record_hit(1);
        assert!((m.density() - 0.5).abs() < 0.01);
    }

    #[test]
    fn coverage_map_clear() {
        let mut m = CoverageMap::new(CoverageMapKind::Edge, 8);
        m.record_hit(0);
        m.clear();
        assert_eq!(m.coverage_count(), 0);
    }

    #[test]
    fn coverage_map_merge() {
        let mut a = CoverageMap::new(CoverageMapKind::Edge, 8);
        let mut b = CoverageMap::new(CoverageMapKind::Edge, 8);
        a.record_hit(0);
        b.record_hit(1);
        a.merge(&b);
        assert_eq!(a.coverage_count(), 2);
    }

    // ── BitmapCompare ────────────────────────────────────────────────────

    #[test]
    fn bitmap_compare_no_new_bits() {
        let global = make_trace(CoverageMapKind::Edge, &[(0, 1), (1, 1)]);
        let trace = make_trace(CoverageMapKind::Edge, &[(0, 1)]);
        let result = BitmapCompare::find_new_bits(&trace, &global, 64);
        assert!(!result.has_new_coverage());
        assert_eq!(result.new_bits, 0);
    }

    #[test]
    fn bitmap_compare_finds_new_bits() {
        let global = make_trace(CoverageMapKind::Edge, &[(0, 1)]);
        let trace = make_trace(CoverageMapKind::Edge, &[(0, 1), (5, 1)]);
        let result = BitmapCompare::find_new_bits(&trace, &global, 64);
        assert!(result.has_new_coverage());
        assert_eq!(result.new_bits, 1);
        assert!(result.new_indices.contains(&5));
    }

    #[test]
    fn bitmap_compare_increased_hits() {
        let global = make_trace(CoverageMapKind::Edge, &[(0, 1)]);
        let trace = make_trace(CoverageMapKind::Edge, &[(0, 5)]);
        let result = BitmapCompare::find_new_bits(&trace, &global, 64);
        assert_eq!(result.increased_bits, 1);
        assert_eq!(result.new_bits, 0);
    }

    #[test]
    fn bitmap_compare_update_global() {
        let mut global = CoverageMap::new(CoverageMapKind::Edge, 8);
        let trace = make_trace(CoverageMapKind::Edge, &[(0, 1), (3, 1)]);
        let added = BitmapCompare::update_global(&trace, &mut global);
        assert_eq!(added, 2);
    }

    // ── FeedbackSignal ────────────────────────────────────────────────────

    #[test]
    fn feedback_signal_interesting_should_save() {
        let s = FeedbackSignal::Interesting {
            new_bits: 5,
            increased_hits: 0,
        };
        assert!(s.should_save());
        assert!(s.is_interesting());
        assert!(!s.is_crash());
    }

    #[test]
    fn feedback_signal_crash_should_save() {
        let s = FeedbackSignal::Crash {
            signal: 11,
            address: Some(0x1000),
        };
        assert!(s.should_save());
        assert!(s.is_crash());
    }

    #[test]
    fn feedback_signal_not_interesting_not_save() {
        assert!(!FeedbackSignal::NotInteresting.should_save());
    }

    #[test]
    fn feedback_signal_display() {
        let s = FeedbackSignal::Interesting {
            new_bits: 3,
            increased_hits: 1,
        };
        let d = s.to_string();
        assert!(d.contains("new=3"));
    }

    // ── FeedbackHistory ───────────────────────────────────────────────────

    #[test]
    fn feedback_history_record_and_rate() {
        let mut h = FeedbackHistory::new(100);
        h.record(FeedbackSignal::Interesting {
            new_bits: 1,
            increased_hits: 0,
        });
        h.record(FeedbackSignal::NotInteresting);
        assert_eq!(h.len(), 2);
        assert!((h.interesting_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn feedback_history_capacity_eviction() {
        let mut h = FeedbackHistory::new(2);
        for _ in 0..5 {
            h.record(FeedbackSignal::NotInteresting);
        }
        assert_eq!(h.len(), 2);
    }

    #[test]
    fn feedback_history_recent() {
        let mut h = FeedbackHistory::new(100);
        h.record(FeedbackSignal::NotInteresting);
        h.record(FeedbackSignal::Crash {
            signal: 11,
            address: None,
        });
        let recent = h.recent(1);
        assert_eq!(recent.len(), 1);
        assert!(recent[0].1.is_crash());
    }

    #[test]
    fn feedback_history_crash_rate() {
        let mut h = FeedbackHistory::new(100);
        h.record(FeedbackSignal::Crash {
            signal: 11,
            address: None,
        });
        h.record(FeedbackSignal::NotInteresting);
        h.record(FeedbackSignal::NotInteresting);
        assert!((h.crash_rate() - 1.0 / 3.0).abs() < 0.01);
    }

    // ── CoverageGrowthMetric ───────────────────────────────────────────────

    #[test]
    fn growth_metric_total_growth() {
        let mut g = CoverageGrowthMetric::new(100);
        g.snapshot(1000, 150);
        assert_eq!(g.total_growth(), 50);
    }

    #[test]
    fn growth_metric_rate() {
        let mut g = CoverageGrowthMetric::new(0);
        g.snapshot(1000, 500);
        let rate = g.growth_rate_per_k();
        assert!((rate - 500.0).abs() < 0.01);
    }

    #[test]
    fn growth_metric_no_snapshots() {
        let g = CoverageGrowthMetric::new(10);
        assert!(g.growth_rate_per_k().abs() < f64::EPSILON);
    }

    // ── FeedbackLoop ──────────────────────────────────────────────────────

    #[test]
    fn feedback_loop_new_trace_is_interesting() {
        let mut fl = FeedbackLoop::new(256);
        let mut trace = CoverageMap::new(CoverageMapKind::Edge, 256);
        trace.record_hit(42);
        let sig = fl.process(&trace, b"input".to_vec(), false, 0, None);
        assert!(sig.is_interesting());
        assert_eq!(fl.interesting_corpus.len(), 1);
    }

    #[test]
    fn feedback_loop_repeated_trace_not_interesting() {
        let mut fl = FeedbackLoop::new(256);
        let mut trace = CoverageMap::new(CoverageMapKind::Edge, 256);
        trace.record_hit(42);
        fl.process(&trace, b"a".to_vec(), false, 0, None);
        let sig2 = fl.process(&trace, b"b".to_vec(), false, 0, None);
        assert_eq!(sig2, FeedbackSignal::NotInteresting);
    }

    #[test]
    fn feedback_loop_crash_saved() {
        let mut fl = FeedbackLoop::new(256);
        let trace = CoverageMap::new(CoverageMapKind::Edge, 256);
        fl.process(&trace, b"crash_input".to_vec(), true, 11, Some(0x1000));
        assert_eq!(fl.crash_corpus.len(), 1);
    }

    #[test]
    fn feedback_loop_summary() {
        let fl = FeedbackLoop::new(256);
        let s = fl.summary();
        assert!(s.contains("FeedbackLoop"));
    }

    // ── CoverageFeedback ──────────────────────────────────────────────────

    #[test]
    fn coverage_feedback_new_edge() {
        let cf = CoverageFeedback::new_edge();
        assert_eq!(cf.kind, CoverageMapKind::Edge);
        assert_eq!(cf.coverage(), 0);
    }

    #[test]
    fn coverage_feedback_submit_interesting() {
        let mut cf = CoverageFeedback::new(CoverageMapKind::Block, 128);
        let mut trace = CoverageMap::new(CoverageMapKind::Block, 128);
        trace.record_hit(10);
        let sig = cf.submit(&trace, b"x".to_vec(), false);
        assert!(sig.is_interesting());
        assert!(cf.coverage() > 0);
    }

    #[test]
    fn coverage_feedback_summary() {
        let cf = CoverageFeedback::new_edge();
        assert!(cf.summary().contains("FeedbackLoop"));
    }

    // ── CoverageMapKind display ───────────────────────────────────────────

    #[test]
    fn coverage_map_kind_display() {
        assert_eq!(CoverageMapKind::Edge.to_string(), "edge");
        assert_eq!(CoverageMapKind::Path.to_string(), "path");
    }
}
