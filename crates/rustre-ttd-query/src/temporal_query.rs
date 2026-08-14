//! Temporal query engine for TTD traces.
//!
//! Provides time-range queries over trace positions, before/after/between
//! operators, event sequencing queries ("A happened before B"), gap analysis,
//! event frequency analysis, and sliding window aggregation over the trace
//! timeline.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};

use crate::{EventPattern, TimeRange};

// ─── TemporalError ────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TemporalError {
    #[error("invalid temporal query: {0}")]
    InvalidQuery(String),
    #[error("empty trace: cannot compute temporal properties")]
    EmptyTrace,
    #[error("window size must be > 0")]
    ZeroWindow,
    #[error("sequence must contain at least two events")]
    ShortSequence,
}

// ─── TemporalPredicate ────────────────────────────────────────────────────────

/// A predicate over a single trace event for temporal matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TemporalPredicate {
    /// Match events whose position is inside the given range.
    InRange(TimeRange),
    /// Match events whose position is strictly before `pos`.
    Before(TracePosition),
    /// Match events whose position is strictly after `pos`.
    After(TracePosition),
    /// Match events whose position is between `start` and `end` (inclusive).
    Between(TracePosition, TracePosition),
    /// Match events by pattern (delegate to `EventPattern`).
    Pattern(EventPattern),
    /// Match events on a specific thread.
    Thread(u32),
    /// Conjunction of two predicates.
    And(Box<Self>, Box<Self>),
    /// Disjunction of two predicates.
    Or(Box<Self>, Box<Self>),
    /// Negation.
    Not(Box<Self>),
    /// Always matches.
    Any,
}

impl TemporalPredicate {
    /// Returns `true` when `event` satisfies this predicate.
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        match self {
            Self::InRange(r) => r.contains(&event.position),
            Self::Before(pos) => event.position < *pos,
            Self::After(pos) => event.position > *pos,
            Self::Between(start, end) => {
                event.position >= *start && event.position <= *end
            }
            Self::Pattern(p) => p.matches(event),
            Self::Thread(tid) => event.thread_id == *tid,
            Self::And(a, b) => a.matches(event) && b.matches(event),
            Self::Or(a, b) => a.matches(event) || b.matches(event),
            Self::Not(inner) => !inner.matches(event),
            Self::Any => true,
        }
    }

    /// Convenience: `before AND pattern`.
    #[must_use]
    pub fn before_and_pattern(pos: TracePosition, pattern: EventPattern) -> Self {
        Self::And(
            Box::new(Self::Before(pos)),
            Box::new(Self::Pattern(pattern)),
        )
    }

    /// Convenience: `after AND pattern`.
    #[must_use]
    pub fn after_and_pattern(pos: TracePosition, pattern: EventPattern) -> Self {
        Self::And(
            Box::new(Self::After(pos)),
            Box::new(Self::Pattern(pattern)),
        )
    }
}

impl std::fmt::Display for TemporalPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InRange(r) => write!(f, "InRange({r})"),
            Self::Before(p) => write!(f, "Before({p})"),
            Self::After(p) => write!(f, "After({p})"),
            Self::Between(s, e) => write!(f, "Between({s}..{e})"),
            Self::Pattern(p) => write!(f, "Pattern({p})"),
            Self::Thread(t) => write!(f, "Thread({t})"),
            Self::And(a, b) => write!(f, "And({a}, {b})"),
            Self::Or(a, b) => write!(f, "Or({a}, {b})"),
            Self::Not(i) => write!(f, "Not({i})"),
            Self::Any => write!(f, "Any"),
        }
    }
}

// ─── WindowSpec ───────────────────────────────────────────────────────────────

/// Specification of a sliding window over the trace timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowSpec {
    /// Number of trace sequence ticks per window.
    pub width_ticks: u64,
    /// Advance the window by this many ticks on each slide.
    pub stride_ticks: u64,
    /// Predicate that events inside the window must satisfy.
    pub predicate: TemporalPredicate,
}

impl WindowSpec {
    #[must_use]
    pub const fn new(width_ticks: u64, stride_ticks: u64, predicate: TemporalPredicate) -> Self {
        Self {
            width_ticks,
            stride_ticks,
            predicate,
        }
    }

    /// Tumbling window: stride == width.
    #[must_use]
    pub const fn tumbling(width_ticks: u64, predicate: TemporalPredicate) -> Self {
        Self::new(width_ticks, width_ticks, predicate)
    }

    /// Sliding window: stride < width (overlapping).
    #[must_use]
    pub const fn sliding(width_ticks: u64, stride_ticks: u64, predicate: TemporalPredicate) -> Self {
        Self::new(width_ticks, stride_ticks, predicate)
    }
}

// ─── WindowBucket ─────────────────────────────────────────────────────────────

/// Aggregated statistics for one window bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowBucket {
    /// Start position of this bucket (sequence field).
    pub window_start_seq: u64,
    /// End position of this bucket (exclusive).
    pub window_end_seq: u64,
    /// Number of matching events in this window.
    pub count: u64,
    /// Minimum position of matched events (if any).
    pub min_pos: Option<TracePosition>,
    /// Maximum position of matched events (if any).
    pub max_pos: Option<TracePosition>,
    /// Thread distribution: tid -> count.
    pub thread_counts: HashMap<u32, u64>,
}

impl WindowBucket {
    fn new(window_start_seq: u64, width: u64) -> Self {
        Self {
            window_start_seq,
            window_end_seq: window_start_seq.saturating_add(width),
            count: 0,
            min_pos: None,
            max_pos: None,
            thread_counts: HashMap::new(),
        }
    }

    fn add_event(&mut self, event: &TraceEvent) {
        self.count += 1;
        let pos = event.position;
        self.min_pos = Some(match self.min_pos {
            None => pos,
            Some(m) => m.min(pos),
        });
        self.max_pos = Some(match self.max_pos {
            None => pos,
            Some(m) => m.max(pos),
        });
        *self.thread_counts.entry(event.thread_id).or_default() += 1;
    }

    /// Event density: events per tick in this window.
    #[must_use]
    pub fn density(&self) -> f64 {
        let width = self.window_end_seq.saturating_sub(self.window_start_seq);
        if width == 0 {
            0.0
        } else {
            self.count as f64 / width as f64
        }
    }
}

impl std::fmt::Display for WindowBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WindowBucket[{}..{}) count={} density={:.4}",
            self.window_start_seq,
            self.window_end_seq,
            self.count,
            self.density()
        )
    }
}

// ─── EventSequence ────────────────────────────────────────────────────────────

/// A named sequence of event patterns that must occur in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSequence {
    /// Human-readable name.
    pub name: String,
    /// Ordered list of patterns.
    pub steps: Vec<EventPattern>,
    /// If `true`, patterns must match consecutive events (no gaps allowed).
    pub strict: bool,
    /// Maximum tick gap allowed between consecutive patterns (None = unlimited).
    pub max_gap: Option<u64>,
}

impl EventSequence {
    pub fn new(name: impl Into<String>, steps: Vec<EventPattern>) -> Self {
        Self {
            name: name.into(),
            steps,
            strict: false,
            max_gap: None,
        }
    }

    #[must_use]
    pub const fn with_strict(mut self) -> Self {
        self.strict = true;
        self
    }

    #[must_use]
    pub const fn with_max_gap(mut self, max_gap: u64) -> Self {
        self.max_gap = Some(max_gap);
        self
    }
}

// ─── SequenceMatch ────────────────────────────────────────────────────────────

/// A successful match of an [`EventSequence`] against the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceMatch {
    /// Name of the matched sequence.
    pub sequence_name: String,
    /// Positions of the matched events (one per step).
    pub matched_positions: Vec<TracePosition>,
    /// The matched events themselves.
    pub matched_events: Vec<TraceEvent>,
    /// Total tick span from first to last match.
    pub span_ticks: u64,
}

impl SequenceMatch {
    #[must_use]
    pub fn first_position(&self) -> Option<TracePosition> {
        self.matched_positions.first().copied()
    }

    #[must_use]
    pub fn last_position(&self) -> Option<TracePosition> {
        self.matched_positions.last().copied()
    }
}

impl std::fmt::Display for SequenceMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SequenceMatch({}, {} steps, span={})",
            self.sequence_name,
            self.matched_positions.len(),
            self.span_ticks
        )
    }
}

// ─── GapInfo ──────────────────────────────────────────────────────────────────

/// Information about a gap between two adjacent matching events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapInfo {
    /// Position just before the gap.
    pub before: TracePosition,
    /// Position just after the gap.
    pub after: TracePosition,
    /// Length of the gap in sequence ticks.
    pub gap_ticks: u64,
    /// Number of non-matching events in the gap.
    pub intervening_events: u64,
}

impl std::fmt::Display for GapInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Gap({} → {}, ticks={}, intervening={})",
            self.before, self.after, self.gap_ticks, self.intervening_events
        )
    }
}

// ─── FrequencyBand ────────────────────────────────────────────────────────────

/// Frequency analysis result for a sequence bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyBand {
    /// Bucket start sequence.
    pub seq_start: u64,
    /// Bucket end sequence (exclusive).
    pub seq_end: u64,
    /// Raw event count in this bucket.
    pub count: u64,
    /// Events per 1000 ticks.
    pub rate_per_1k: f64,
    /// Deviation from the global mean (z-score).
    pub z_score: f64,
}

impl std::fmt::Display for FrequencyBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FreqBand[{}..{}) count={} rate={:.2} z={:.2}",
            self.seq_start, self.seq_end, self.count, self.rate_per_1k, self.z_score
        )
    }
}

// ─── TemporalResult ───────────────────────────────────────────────────────────

/// Result returned by a [`TemporalQuery`] execution.
#[derive(Debug, Clone)]
pub struct TemporalResult {
    /// Events that matched the primary predicate.
    pub matched: Vec<TraceEvent>,
    /// Gaps between matched events.
    pub gaps: Vec<GapInfo>,
    /// Sequence matches (if a sequence was requested).
    pub sequence_matches: Vec<SequenceMatch>,
    /// Sliding window buckets (if a window was requested).
    pub window_buckets: Vec<WindowBucket>,
    /// Frequency bands (if frequency analysis was requested).
    pub frequency_bands: Vec<FrequencyBand>,
    /// Execution metadata.
    pub events_scanned: u64,
    pub execution_ns: u64,
}

impl TemporalResult {
    const fn empty() -> Self {
        Self {
            matched: Vec::new(),
            gaps: Vec::new(),
            sequence_matches: Vec::new(),
            window_buckets: Vec::new(),
            frequency_bands: Vec::new(),
            events_scanned: 0,
            execution_ns: 0,
        }
    }

    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matched.len()
    }

    #[must_use]
    pub fn total_gap_ticks(&self) -> u64 {
        self.gaps.iter().map(|g| g.gap_ticks).sum()
    }

    #[must_use]
    pub fn mean_gap_ticks(&self) -> Option<f64> {
        if self.gaps.is_empty() {
            None
        } else {
            Some(self.total_gap_ticks() as f64 / self.gaps.len() as f64)
        }
    }

    #[must_use]
    pub fn max_gap(&self) -> Option<&GapInfo> {
        self.gaps.iter().max_by_key(|g| g.gap_ticks)
    }
}

impl std::fmt::Display for TemporalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TemporalResult {{ matched: {}, gaps: {}, seq_matches: {}, buckets: {} }}",
            self.matched.len(),
            self.gaps.len(),
            self.sequence_matches.len(),
            self.window_buckets.len()
        )
    }
}

// ─── TemporalQuery ────────────────────────────────────────────────────────────

/// Composable temporal query engine over a TTD trace.
///
/// Supports time-range filtering, event ordering queries, gap analysis,
/// frequency analysis, and sliding-window aggregation.
pub struct TemporalQuery<'a> {
    trace: &'a TtdTrace,
    predicate: TemporalPredicate,
    sequence: Option<EventSequence>,
    window: Option<WindowSpec>,
    frequency_bucket_size: Option<u64>,
    compute_gaps: bool,
    gap_predicate: Option<TemporalPredicate>,
}

impl<'a> TemporalQuery<'a> {
    /// Create a new query for the given trace with a primary predicate.
    pub const fn new(trace: &'a TtdTrace, predicate: TemporalPredicate) -> Self {
        Self {
            trace,
            predicate,
            sequence: None,
            window: None,
            frequency_bucket_size: None,
            compute_gaps: false,
            gap_predicate: None,
        }
    }

    /// Also search for the given event sequence.
    #[must_use]
    pub fn with_sequence(mut self, seq: EventSequence) -> Self {
        self.sequence = Some(seq);
        self
    }

    /// Also run sliding-window aggregation.
    #[must_use]
    pub fn with_window(mut self, window: WindowSpec) -> Self {
        self.window = Some(window);
        self
    }

    /// Also compute frequency bands with the given bucket size (in ticks).
    #[must_use]
    pub const fn with_frequency_analysis(mut self, bucket_size: u64) -> Self {
        self.frequency_bucket_size = Some(bucket_size);
        self
    }

    /// Also compute gaps between matched events, optionally with a different
    /// predicate for what counts as a gap-adjacent event.
    #[must_use]
    pub fn with_gap_analysis(mut self, gap_pred: Option<TemporalPredicate>) -> Self {
        self.compute_gaps = true;
        self.gap_predicate = gap_pred;
        self
    }

    /// Execute the query and return a [`TemporalResult`].
    pub fn execute(self) -> Result<TemporalResult, TemporalError> {
        let events = self.trace.all_events();
        if events.is_empty() {
            return Err(TemporalError::EmptyTrace);
        }

        let t0 = std::time::Instant::now();
        let mut result = TemporalResult::empty();
        result.events_scanned = events.len() as u64;

        // --- Primary predicate filter ---
        let matched: Vec<TraceEvent> = events
            .iter()
            .filter(|e| self.predicate.matches(e))
            .cloned()
            .collect();
        result.matched = matched;

        // --- Gap analysis ---
        if self.compute_gaps && result.matched.len() >= 2 {
            result.gaps = compute_gaps(&result.matched, &events, &self.gap_predicate);
        }

        // --- Sequence matching ---
        if let Some(seq) = &self.sequence {
            if seq.steps.len() < 2 {
                return Err(TemporalError::ShortSequence);
            }
            result.sequence_matches = find_sequences(&events, seq);
        }

        // --- Sliding window ---
        if let Some(window) = &self.window {
            if window.width_ticks == 0 {
                return Err(TemporalError::ZeroWindow);
            }
            result.window_buckets = sliding_window_aggregate(&events, window);
        }

        // --- Frequency analysis ---
        if let Some(bucket_size) = self.frequency_bucket_size {
            if bucket_size == 0 {
                return Err(TemporalError::ZeroWindow);
            }
            result.frequency_bands =
                frequency_analysis(&events, &self.predicate, bucket_size);
        }

        result.execution_ns = t0.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        Ok(result)
    }
}

// ─── compute_gaps ─────────────────────────────────────────────────────────────

fn compute_gaps(
    matched: &[TraceEvent],
    all_events: &[TraceEvent],
    gap_pred: &Option<TemporalPredicate>,
) -> Vec<GapInfo> {
    let mut gaps = Vec::new();
    for window in matched.windows(2) {
        let before = window[0].position;
        let after = window[1].position;
        let gap_ticks = after
            .sequence
            .saturating_sub(before.sequence);

        // Count non-matching events in the gap.
        let intervening_events = all_events
            .iter()
            .filter(|e| {
                e.position > before && e.position < after
                    && gap_pred.as_ref().is_none_or(|p| p.matches(e))
            })
            .count() as u64;

        gaps.push(GapInfo {
            before,
            after,
            gap_ticks,
            intervening_events,
        });
    }
    gaps
}

// ─── find_sequences ───────────────────────────────────────────────────────────

fn find_sequences(events: &[TraceEvent], seq: &EventSequence) -> Vec<SequenceMatch> {
    let mut results = Vec::new();
    if seq.steps.is_empty() {
        return results;
    }

    let mut step_idx = 0usize;
    let mut current_match: Vec<(usize, TraceEvent)> = Vec::new();

    let i_iter: Vec<(usize, &TraceEvent)> = events.iter().enumerate().collect();

    let mut i = 0usize;
    while i < i_iter.len() {
        let (ev_idx, event) = i_iter[i];
        let _ = ev_idx;

        if seq.steps[step_idx].matches(event) {
            // Check max_gap constraint with the previous matched event.
            let gap_ok = if let (Some(max_gap), Some((_, prev))) = (seq.max_gap, current_match.last()) {
                let gap = event
                    .position
                    .sequence
                    .saturating_sub(prev.position.sequence);
                gap <= max_gap
            } else {
                true
            };

            if gap_ok {
                current_match.push((i, event.clone()));
                step_idx += 1;

                if step_idx == seq.steps.len() {
                    // Full sequence matched.
                    let positions: Vec<TracePosition> =
                        current_match.iter().map(|(_, e)| e.position).collect();
                    let matched_events: Vec<TraceEvent> =
                        current_match.iter().map(|(_, e)| e.clone()).collect();
                    let span_ticks = positions
                        .last()
                        .map_or(0, |p| p.sequence)
                        .saturating_sub(positions.first().map_or(0, |p| p.sequence));

                    results.push(SequenceMatch {
                        sequence_name: seq.name.clone(),
                        matched_positions: positions,
                        matched_events,
                        span_ticks,
                    });

                    // Restart from the event after the first matched event.
                    let restart_i = current_match[0].0 + 1;
                    current_match.clear();
                    step_idx = 0;
                    i = restart_i;
                    continue;
                }

                if seq.strict {
                    // In strict mode: next event must match next pattern.
                    i += 1;
                    continue;
                }
            } else {
                // Gap too large: restart search from after first match.
                if !current_match.is_empty() {
                    let restart_i = current_match[0].0 + 1;
                    current_match.clear();
                    step_idx = 0;
                    i = restart_i;
                    continue;
                }
            }
        } else if seq.strict && step_idx > 0 {
            // Strict mode: any non-match resets the search.
            let restart_i = current_match[0].0 + 1;
            current_match.clear();
            step_idx = 0;
            i = restart_i;
            continue;
        }

        i += 1;
    }

    results
}

// ─── sliding_window_aggregate ─────────────────────────────────────────────────

fn sliding_window_aggregate(events: &[TraceEvent], spec: &WindowSpec) -> Vec<WindowBucket> {
    if events.is_empty() || spec.width_ticks == 0 || spec.stride_ticks == 0 {
        return Vec::new();
    }

    let min_seq = events.first().map_or(0, |e| e.position.sequence);
    let max_seq = events.last().map_or(0, |e| e.position.sequence);

    let mut buckets = Vec::new();
    let mut window_start = min_seq;

    while window_start <= max_seq {
        let window_end = window_start.saturating_add(spec.width_ticks);
        let mut bucket = WindowBucket::new(window_start, spec.width_ticks);

        for event in events {
            let s = event.position.sequence;
            if s >= window_start && s < window_end && spec.predicate.matches(event) {
                bucket.add_event(event);
            }
        }

        buckets.push(bucket);
        window_start = match window_start.checked_add(spec.stride_ticks) {
            Some(v) => v,
            None => break,
        };
    }

    buckets
}

// ─── frequency_analysis ───────────────────────────────────────────────────────

fn frequency_analysis(
    events: &[TraceEvent],
    predicate: &TemporalPredicate,
    bucket_size: u64,
) -> Vec<FrequencyBand> {
    if events.is_empty() || bucket_size == 0 {
        return Vec::new();
    }

    // Build bucket counts.
    let mut counts: BTreeMap<u64, u64> = BTreeMap::new();
    for event in events {
        if predicate.matches(event) {
            let bucket = event.position.sequence / bucket_size;
            *counts.entry(bucket).or_default() += 1;
        }
    }

    if counts.is_empty() {
        return Vec::new();
    }

    let values: Vec<u64> = counts.values().copied().collect();
    let mean = values.iter().sum::<u64>() as f64 / values.len() as f64;
    let variance = values
        .iter()
        .map(|v| {
            let d = *v as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / values.len() as f64;
    let std_dev = variance.sqrt();

    counts
        .into_iter()
        .map(|(bucket_idx, count)| {
            let seq_start = bucket_idx * bucket_size;
            let seq_end = seq_start + bucket_size;
            let rate_per_1k = if bucket_size > 0 {
                count as f64 / bucket_size as f64 * 1000.0
            } else {
                0.0
            };
            let z_score = if std_dev > 0.0 {
                (count as f64 - mean) / std_dev
            } else {
                0.0
            };
            FrequencyBand {
                seq_start,
                seq_end,
                count,
                rate_per_1k,
                z_score,
            }
        })
        .collect()
}

// ─── Convenience helpers ──────────────────────────────────────────────────────

/// Find all events that occurred before a given position and match a predicate.
pub fn events_before(
    trace: &TtdTrace,
    pos: TracePosition,
    pred: &TemporalPredicate,
) -> Vec<TraceEvent> {
    trace
        .all_events()
        .iter()
        .filter(|e| e.position < pos && pred.matches(e))
        .cloned()
        .collect()
}

/// Find all events that occurred after a given position and match a predicate.
pub fn events_after(
    trace: &TtdTrace,
    pos: TracePosition,
    pred: &TemporalPredicate,
) -> Vec<TraceEvent> {
    trace
        .all_events()
        .iter()
        .filter(|e| e.position > pos && pred.matches(e))
        .cloned()
        .collect()
}

/// Find all events strictly between two positions.
pub fn events_between(
    trace: &TtdTrace,
    start: TracePosition,
    end: TracePosition,
    pred: &TemporalPredicate,
) -> Vec<TraceEvent> {
    trace
        .all_events()
        .iter()
        .filter(|e| e.position > start && e.position < end && pred.matches(e))
        .cloned()
        .collect()
}

/// Check if event A occurred before event B in the trace.
///
/// Returns `Some(true)` if A happened before B, `Some(false)` if B happened
/// before A, and `None` if either predicate matches no events.
pub fn happened_before(
    trace: &TtdTrace,
    pred_a: &TemporalPredicate,
    pred_b: &TemporalPredicate,
) -> Option<bool> {
    let all = trace.all_events();
    let first_a = all
        .iter()
        .find(|e| pred_a.matches(e))
        .map(|e| e.position)?;
    let first_b = all
        .iter()
        .find(|e| pred_b.matches(e))
        .map(|e| e.position)?;
    Some(first_a < first_b)
}

/// Compute per-thread event rate (events per tick) for events matching `pred`.
pub fn per_thread_rate(
    trace: &TtdTrace,
    pred: &TemporalPredicate,
) -> HashMap<u32, f64> {
    let all_events = trace.all_events();
    if all_events.is_empty() {
        return HashMap::new();
    }
    let total_ticks = all_events
        .last()
        .map_or(1, |e| e.position.sequence)
        .max(1);

    let mut counts: HashMap<u32, u64> = HashMap::new();
    for event in &all_events {
        if pred.matches(event) {
            *counts.entry(event.thread_id).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .map(|(tid, count)| (tid, count as f64 / total_ticks as f64))
        .collect()
}

/// Find the N longest gaps between matching events.
pub fn top_n_gaps(
    trace: &TtdTrace,
    pred: &TemporalPredicate,
    n: usize,
) -> Vec<GapInfo> {
    let all_events = trace.all_events();
    let matched: Vec<TraceEvent> = all_events
        .iter()
        .filter(|e| pred.matches(e))
        .cloned()
        .collect();

    if matched.len() < 2 {
        return Vec::new();
    }

    let mut gaps = compute_gaps(&matched, &all_events, &None);
    gaps.sort_by(|a, b| b.gap_ticks.cmp(&a.gap_ticks));
    gaps.truncate(n);
    gaps
}

/// Detect bursts: windows where event count exceeds `threshold` times the mean.
pub fn detect_bursts(
    trace: &TtdTrace,
    pred: &TemporalPredicate,
    bucket_size: u64,
    threshold_multiplier: f64,
) -> Vec<FrequencyBand> {
    let bands = frequency_analysis(&trace.all_events(), pred, bucket_size);
    if bands.is_empty() {
        return Vec::new();
    }
    let mean = bands.iter().map(|b| b.count as f64).sum::<f64>() / bands.len() as f64;
    bands
        .into_iter()
        .filter(|b| b.count as f64 > mean * threshold_multiplier)
        .collect()
}

/// Returns an ordered timeline of (position, `event_kind_name`) pairs for matched events.
pub fn build_event_timeline(
    trace: &TtdTrace,
    pred: &TemporalPredicate,
) -> Vec<(TracePosition, &'static str)> {
    trace
        .all_events()
        .iter()
        .filter(|e| pred.matches(e))
        .map(|e| (e.position, event_kind_str(&e.kind)))
        .collect()
}

const fn event_kind_str(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::MemRead { .. } => "MemRead",
        EventKind::MemWrite { .. } => "MemWrite",
        EventKind::Call { .. } => "Call",
        EventKind::Return { .. } => "Return",
        EventKind::SyscallEnter { .. } => "SyscallEnter",
        EventKind::SyscallExit { .. } => "SyscallExit",
        EventKind::Exception { .. } => "Exception",
        EventKind::ThreadCreate { .. } => "ThreadCreate",
        EventKind::ThreadExit { .. } => "ThreadExit",
        EventKind::Breakpoint { .. } => "Breakpoint",
    }
}

/// Compute autocorrelation of event counts over time (lag-1 through lag-N).
///
/// Returns a vector of (lag, correlation) pairs.
pub fn event_autocorrelation(
    trace: &TtdTrace,
    pred: &TemporalPredicate,
    bucket_size: u64,
    max_lag: usize,
) -> Vec<(usize, f64)> {
    let bands = frequency_analysis(&trace.all_events(), pred, bucket_size);
    if bands.len() < 2 || max_lag == 0 {
        return Vec::new();
    }

    let values: Vec<f64> = bands.iter().map(|b| b.count as f64).collect();
    let n = values.len();
    let mean = values.iter().sum::<f64>() / n as f64;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;

    if variance == 0.0 {
        return (1..=max_lag).map(|lag| (lag, 0.0)).collect();
    }

    let mut result = Vec::with_capacity(max_lag);
    for lag in 1..=max_lag {
        if lag >= n {
            break;
        }
        let cov: f64 = values[..n - lag]
            .iter()
            .zip(values[lag..].iter())
            .map(|(a, b)| (a - mean) * (b - mean))
            .sum::<f64>()
            / (n - lag) as f64;
        result.push((lag, cov / variance));
    }
    result
}

/// Compute a running average of event density using an exponential moving average.
///
/// Returns a vector of (`bucket_start_seq`, `ema_density`) pairs.
pub fn ema_density(
    trace: &TtdTrace,
    pred: &TemporalPredicate,
    bucket_size: u64,
    alpha: f64,
) -> Vec<(u64, f64)> {
    let bands = frequency_analysis(&trace.all_events(), pred, bucket_size);
    if bands.is_empty() {
        return Vec::new();
    }

    let mut ema = bands[0].rate_per_1k;
    let mut result = vec![(bands[0].seq_start, ema)];

    for band in &bands[1..] {
        ema = (1.0 - alpha).mul_add(ema, alpha * band.rate_per_1k);
        result.push((band.seq_start, ema));
    }
    result
}

/// Compute a sliding-window maximum of event counts (for peak detection).
pub fn sliding_max_count(
    trace: &TtdTrace,
    pred: &TemporalPredicate,
    bucket_size: u64,
    window_buckets: usize,
) -> Vec<(u64, u64)> {
    let bands = frequency_analysis(&trace.all_events(), pred, bucket_size);
    if bands.is_empty() || window_buckets == 0 {
        return Vec::new();
    }

    let counts: Vec<u64> = bands.iter().map(|b| b.count).collect();
    let starts: Vec<u64> = bands.iter().map(|b| b.seq_start).collect();

    let mut deque: VecDeque<usize> = VecDeque::new();
    let mut result = Vec::with_capacity(counts.len());

    for i in 0..counts.len() {
        // Remove elements outside the window.
        while !deque.is_empty() && *deque.front().unwrap() + window_buckets <= i {
            deque.pop_front();
        }
        // Remove smaller elements from the back.
        while !deque.is_empty() && counts[*deque.back().unwrap()] <= counts[i] {
            deque.pop_back();
        }
        deque.push_back(i);
        result.push((starts[i], counts[*deque.front().unwrap()]));
    }

    result
}
