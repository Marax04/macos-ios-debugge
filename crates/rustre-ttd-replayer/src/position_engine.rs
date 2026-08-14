//! TTD position arithmetic: forward/backward navigation, position comparison,
//! distance calculation, serialization, and position range operations.
//!
//! [`TtdPosition`] is re-exported from [`crate::ttd_database`] for ergonomic
//! access; this module adds higher-level arithmetic and navigation helpers
//! on top of the raw `(sequence, step)` pair.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ttd_database::TtdPosition;

// ─── PositionDistance ─────────────────────────────────────────────────────────

/// The arithmetic distance between two TTD positions.
///
/// Within the same sequence the distance is simply the difference in step
/// values.  Across sequences we compute a sequence delta and a step delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionDistance {
    /// Difference in sequence numbers (`to.sequence - from.sequence`).
    /// May be negative for backward distances.
    pub sequence_delta: i64,
    /// Difference in step counts within the same sequence.
    /// Only meaningful when `sequence_delta == 0`.
    pub step_delta: i64,
}

impl PositionDistance {
    /// Zero distance (same position).
    pub const ZERO: Self = Self { sequence_delta: 0, step_delta: 0 };

    /// Compute the distance from `from` to `to`.
    #[must_use] 
    pub fn between(from: TtdPosition, to: TtdPosition) -> Self {
        let seq_delta = (to.sequence as i64).wrapping_sub(from.sequence as i64);
        let step_delta = if seq_delta == 0 {
            i64::from(to.step).wrapping_sub(i64::from(from.step))
        } else {
            0
        };
        Self { sequence_delta: seq_delta, step_delta }
    }

    /// True if the distance is zero (same position).
    #[must_use] 
    pub const fn is_zero(&self) -> bool {
        self.sequence_delta == 0 && self.step_delta == 0
    }

    /// True if `to` came before `from` (negative distance).
    #[must_use] 
    pub const fn is_backward(&self) -> bool {
        self.sequence_delta < 0 || (self.sequence_delta == 0 && self.step_delta < 0)
    }

    /// True if `to` came after `from` (positive distance).
    #[must_use] 
    pub const fn is_forward(&self) -> bool {
        self.sequence_delta > 0 || (self.sequence_delta == 0 && self.step_delta > 0)
    }

    /// Absolute step distance when both positions are in the same sequence.
    /// Returns `None` for cross-sequence distances.
    #[must_use] 
    pub fn intra_sequence_steps(&self) -> Option<u32> {
        if self.sequence_delta != 0 {
            return None;
        }
        self.step_delta.unsigned_abs().try_into().ok()
    }
}

impl fmt::Display for PositionDistance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.sequence_delta == 0 {
            write!(f, "Δstep={:+}", self.step_delta)
        } else {
            write!(f, "Δseq={:+} Δstep={:+}", self.sequence_delta, self.step_delta)
        }
    }
}

// ─── PositionRange ────────────────────────────────────────────────────────────

/// A half-open range of TTD positions `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionRange {
    pub start: TtdPosition,
    pub end: TtdPosition,
}

impl PositionRange {
    /// Construct a new range.  `start` must be ≤ `end`.
    #[must_use] 
    pub fn new(start: TtdPosition, end: TtdPosition) -> Self {
        debug_assert!(start <= end, "PositionRange: start > end");
        Self { start, end }
    }

    /// Construct an inclusive `[start, end]` range.
    #[must_use] 
    pub fn inclusive(start: TtdPosition, end: TtdPosition) -> Self {
        let end_excl = end.next_step();
        Self::new(start, end_excl)
    }

    /// True if `pos` falls within `[start, end)`.
    #[must_use] 
    pub fn contains(&self, pos: TtdPosition) -> bool {
        pos >= self.start && pos < self.end
    }

    /// True if `pos` falls within `[start, end]`.
    #[must_use] 
    pub fn contains_inclusive(&self, pos: TtdPosition) -> bool {
        pos >= self.start && pos <= self.end
    }

    /// True if this range overlaps another.
    #[must_use] 
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Width in sequences.
    #[must_use] 
    pub const fn sequence_span(&self) -> u64 {
        self.end.sequence.saturating_sub(self.start.sequence)
    }

    /// Midpoint (rounded down), used for binary-search pivots.
    #[must_use] 
    pub const fn midpoint(&self) -> TtdPosition {
        let mid_seq = u64::midpoint(self.start.sequence, self.end.sequence);
        let mid_step = if mid_seq == self.start.sequence && mid_seq == self.end.sequence {
            u32::midpoint(self.start.step, self.end.step)
        } else {
            0
        };
        TtdPosition::new(mid_seq, mid_step)
    }
}

impl fmt::Display for PositionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} .. {})", self.start, self.end)
    }
}

// ─── PositionIterator ─────────────────────────────────────────────────────────

/// Iterator over evenly-spaced positions within a range.
///
/// Useful for generating checkpoints or sampling positions for analysis.
pub struct PositionIterator {
    current: TtdPosition,
    end: TtdPosition,
    step_increment: u64, // total steps per advance (may span sequences)
    sequence_step: u64,
    intra_step: u32,
}

impl PositionIterator {
    /// Create an iterator that yields `count` evenly-spaced positions in `range`.
    #[must_use] 
    pub fn evenly_spaced(range: PositionRange, count: usize) -> Self {
        let total_seqs = range.end.sequence.saturating_sub(range.start.sequence).max(1);
        let seq_per_step = total_seqs / count.max(1) as u64;
        Self {
            current: range.start,
            end: range.end,
            step_increment: seq_per_step.max(1),
            sequence_step: seq_per_step.max(1),
            intra_step: 0,
        }
    }

    /// Create a simple iterator that increments sequence numbers by `seq_stride`.
    #[must_use] 
    pub fn by_sequence(start: TtdPosition, end: TtdPosition, seq_stride: u64) -> Self {
        Self {
            current: start,
            end,
            step_increment: seq_stride.max(1),
            sequence_step: seq_stride.max(1),
            intra_step: 0,
        }
    }
}

impl PositionIterator {
    /// Total step increment per advance (sequence span + intra-sequence steps).
    ///
    /// Distinct from [`Self::sequence_step`] in that it accounts for the
    /// intra-step component used when sub-instruction resolution is needed.
    #[must_use] 
    pub const fn step_increment(&self) -> u64 {
        self.step_increment
    }

    /// Estimated number of remaining yields, using `step_increment` as the stride.
    #[must_use] 
    pub fn estimated_remaining(&self) -> u64 {
        let span = self.end.sequence.saturating_sub(self.current.sequence);
        span / self.step_increment.max(1)
    }
}

impl Iterator for PositionIterator {
    type Item = TtdPosition;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end {
            return None;
        }
        let pos = self.current;
        self.current = TtdPosition::new(
            self.current.sequence.saturating_add(self.sequence_step),
            self.intra_step,
        );
        Some(pos)
    }
}

// ─── PositionEngine ───────────────────────────────────────────────────────────

/// High-level position navigation engine.
///
/// Wraps a sorted list of known positions (from a position index or event log)
/// and provides efficient forward/backward navigation, nearest-position lookup,
/// and range enumeration.
#[derive(Debug, Clone)]
pub struct PositionEngine {
    /// Known positions in ascending order.
    positions: Vec<TtdPosition>,
    /// Current cursor index into `positions`.
    cursor: usize,
    /// The position currently pointed at.
    current: TtdPosition,
}

impl PositionEngine {
    /// Create a new engine from a sorted list of known positions.
    ///
    /// Returns `None` if `positions` is empty so that callers can handle the
    /// empty-input case without an unrecoverable panic.
    #[must_use] 
    pub fn new(mut positions: Vec<TtdPosition>) -> Option<Self> {
        if positions.is_empty() {
            return None;
        }
        positions.sort_unstable();
        positions.dedup();
        let current = positions[0];
        Some(Self { positions, cursor: 0, current })
    }

    /// Total number of indexed positions.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.positions.len()
    }

    /// True if there is only one indexed position.
    #[must_use] 
    pub const fn is_single(&self) -> bool {
        self.positions.len() == 1
    }

    /// Return the current position.
    #[must_use] 
    pub const fn current(&self) -> TtdPosition {
        self.current
    }

    /// Return the first (earliest) position.
    #[must_use] 
    pub fn first(&self) -> TtdPosition {
        self.positions[0]
    }

    /// Return the last (latest) position.
    #[must_use] 
    pub fn last(&self) -> TtdPosition {
        *self.positions.last().unwrap()
    }

    /// Move to `target`, snapping to the nearest known position at or before it.
    /// Returns the position actually landed on.
    pub fn seek(&mut self, target: TtdPosition) -> TtdPosition {
        let idx = self.positions.partition_point(|&p| p <= target);
        let idx = if idx == 0 { 0 } else { idx - 1 };
        self.cursor = idx;
        self.current = self.positions[idx];
        self.current
    }

    /// Move to the exact position `target`.  Returns `None` if not in the index.
    pub fn seek_exact(&mut self, target: TtdPosition) -> Option<TtdPosition> {
        let idx = self.positions.binary_search(&target).ok()?;
        self.cursor = idx;
        self.current = target;
        Some(self.current)
    }

    /// Step forward to the next indexed position.  Returns `None` at the end.
    pub fn step_forward(&mut self) -> Option<TtdPosition> {
        if self.cursor + 1 >= self.positions.len() {
            return None;
        }
        self.cursor += 1;
        self.current = self.positions[self.cursor];
        Some(self.current)
    }

    /// Step backward to the previous indexed position.  Returns `None` at the start.
    pub fn step_backward(&mut self) -> Option<TtdPosition> {
        if self.cursor == 0 {
            return None;
        }
        self.cursor -= 1;
        self.current = self.positions[self.cursor];
        Some(self.current)
    }

    /// Move forward by `n` positions.  Clamps at the last known position.
    pub fn advance(&mut self, n: usize) -> TtdPosition {
        self.cursor = (self.cursor + n).min(self.positions.len() - 1);
        self.current = self.positions[self.cursor];
        self.current
    }

    /// Move backward by `n` positions.  Clamps at the first known position.
    pub fn retreat(&mut self, n: usize) -> TtdPosition {
        self.cursor = self.cursor.saturating_sub(n);
        self.current = self.positions[self.cursor];
        self.current
    }

    /// True if the engine is at the first position.
    #[must_use] 
    pub const fn at_start(&self) -> bool {
        self.cursor == 0
    }

    /// True if the engine is at the last position.
    #[must_use] 
    pub const fn at_end(&self) -> bool {
        self.cursor + 1 >= self.positions.len()
    }

    /// Return all positions in the given range `[lo, hi]`.
    #[must_use] 
    pub fn positions_in_range(&self, lo: TtdPosition, hi: TtdPosition) -> &[TtdPosition] {
        let start = self.positions.partition_point(|&p| p < lo);
        let end = self.positions.partition_point(|&p| p <= hi);
        &self.positions[start..end]
    }

    /// Return `n` positions preceding `pos` (exclusive), ordered latest-first.
    #[must_use] 
    pub fn n_before(&self, pos: TtdPosition, n: usize) -> Vec<TtdPosition> {
        let end = self.positions.partition_point(|&p| p < pos);
        let start = end.saturating_sub(n);
        self.positions[start..end].iter().rev().copied().collect()
    }

    /// Return `n` positions following `pos` (exclusive), ordered earliest-first.
    #[must_use] 
    pub fn n_after(&self, pos: TtdPosition, n: usize) -> Vec<TtdPosition> {
        let start = self.positions.partition_point(|&p| p <= pos);
        let end = (start + n).min(self.positions.len());
        self.positions[start..end].to_vec()
    }

    /// Distance from the current position to `target`.
    #[must_use] 
    pub fn distance_to(&self, target: TtdPosition) -> PositionDistance {
        PositionDistance::between(self.current, target)
    }

    /// Reset the cursor to the first position.
    pub fn reset(&mut self) {
        self.cursor = 0;
        self.current = self.positions[0];
    }
}

// ─── PositionSerializer ───────────────────────────────────────────────────────

/// Serialize / deserialize [`TtdPosition`] values in multiple formats.
pub struct PositionSerializer;

impl PositionSerializer {
    /// Serialize to `"seq:step"` string.
    #[must_use] 
    pub fn to_string(pos: TtdPosition) -> String {
        format!("{}:{}", pos.sequence, pos.step)
    }

    /// Deserialize from `"seq:step"` string.
    #[must_use] 
    pub fn from_string(s: &str) -> Option<TtdPosition> {
        let mut parts = s.splitn(2, ':');
        let seq: u64 = parts.next()?.parse().ok()?;
        let step: u32 = parts.next()?.parse().ok()?;
        Some(TtdPosition::new(seq, step))
    }

    /// Serialize to a compact 12-byte little-endian binary representation.
    #[must_use] 
    pub fn to_bytes(pos: TtdPosition) -> [u8; 12] {
        pos.to_bytes()
    }

    /// Deserialize from a 12-byte little-endian binary slice.
    #[must_use] 
    pub fn from_bytes(b: &[u8]) -> Option<TtdPosition> {
        if b.len() < 12 {
            return None;
        }
        let arr: &[u8; 12] = b[..12].try_into().ok()?;
        Some(TtdPosition::from_bytes(arr))
    }

    /// Serialize to a JSON object `{"seq": N, "step": N}`.
    #[must_use] 
    pub fn to_json(pos: TtdPosition) -> String {
        format!(r#"{{"seq":{},"step":{}}}"#, pos.sequence, pos.step)
    }

    /// Deserialize from a minimal JSON object (no allocator JSON crate needed).
    #[must_use] 
    pub fn from_json(s: &str) -> Option<TtdPosition> {
        // Very minimal hand-rolled JSON extractor
        fn extract_field(json: &str, field: &str) -> Option<u64> {
            let key = format!(r#""{field}":"#);
            let idx = json.find(key.as_str())?;
            let after = &json[idx + key.len()..].trim_start();
            let end = after.find(|c: char| !c.is_ascii_digit()).unwrap_or(after.len());
            after[..end].parse().ok()
        }
        let seq = extract_field(s, "seq")?;
        let step: u32 = extract_field(s, "step")?.try_into().ok()?;
        Some(TtdPosition::new(seq, step))
    }
}

// ─── NavigationHistory ────────────────────────────────────────────────────────

/// A bounded history of recently visited positions, supporting undo/redo.
#[derive(Debug, Clone)]
pub struct NavigationHistory {
    /// Past positions (most recent last), capacity-bounded.
    past: VecDeque<TtdPosition>,
    /// Future positions (for redo), most recent first.
    future: VecDeque<TtdPosition>,
    /// Maximum number of history entries.
    capacity: usize,
    /// Current position.
    current: Option<TtdPosition>,
}

impl NavigationHistory {
    /// Create a new history with the given capacity.
    #[must_use] 
    pub fn new(capacity: usize) -> Self {
        Self {
            past: VecDeque::with_capacity(capacity),
            future: VecDeque::new(),
            capacity,
            current: None,
        }
    }

    /// Record a navigation to `pos`.  Clears the redo stack.
    pub fn push(&mut self, pos: TtdPosition) {
        if let Some(prev) = self.current.replace(pos)
            && prev != pos {
                if self.past.len() >= self.capacity {
                    self.past.pop_front();
                }
                self.past.push_back(prev);
                self.future.clear();
            }
    }

    /// Undo: return the previous position, if any.
    pub fn undo(&mut self) -> Option<TtdPosition> {
        let prev = self.past.pop_back()?;
        if let Some(cur) = self.current.replace(prev) {
            self.future.push_front(cur);
        }
        self.current
    }

    /// Redo: return the next position, if any.
    pub fn redo(&mut self) -> Option<TtdPosition> {
        let next = self.future.pop_front()?;
        if let Some(cur) = self.current.replace(next) {
            self.past.push_back(cur);
        }
        self.current
    }

    /// Current position, if any.
    #[must_use] 
    pub const fn current(&self) -> Option<TtdPosition> {
        self.current
    }

    /// Number of undo steps available.
    #[must_use] 
    pub fn undo_depth(&self) -> usize {
        self.past.len()
    }

    /// Number of redo steps available.
    #[must_use] 
    pub fn redo_depth(&self) -> usize {
        self.future.len()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.past.clear();
        self.future.clear();
        self.current = None;
    }

    /// All past positions (oldest first).
    pub fn past_positions(&self) -> impl Iterator<Item = &TtdPosition> {
        self.past.iter()
    }
}

// ─── PositionCompare ──────────────────────────────────────────────────────────

/// Compare two TTD positions and return a structured result.
#[must_use] 
pub fn compare_positions(a: TtdPosition, b: TtdPosition) -> PositionComparison {
    match a.cmp(&b) {
        Ordering::Less => PositionComparison::Before(PositionDistance::between(a, b)),
        Ordering::Equal => PositionComparison::Equal,
        Ordering::Greater => PositionComparison::After(PositionDistance::between(b, a)),
    }
}

/// Result of comparing two TTD positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionComparison {
    /// `a` is strictly before `b`.
    Before(PositionDistance),
    /// `a` and `b` are equal.
    Equal,
    /// `a` is strictly after `b`.
    After(PositionDistance),
}

impl PositionComparison {
    /// True if the comparison result is `Equal`.
    #[must_use] 
    pub const fn is_equal(&self) -> bool {
        matches!(self, Self::Equal)
    }
}

impl fmt::Display for PositionComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Before(d) => write!(f, "before ({d})"),
            Self::Equal => write!(f, "equal"),
            Self::After(d) => write!(f, "after ({d})"),
        }
    }
}

// ─── PositionAnnotation ───────────────────────────────────────────────────────

/// A user-defined annotation attached to a TTD position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PositionAnnotation {
    /// The annotated position.
    pub position: TtdPosition,
    /// Short label (e.g., "crash", "`alloc_1`").
    pub label: String,
    /// Optional longer description.
    pub description: Option<String>,
    /// Color tag for display (0-7, ANSI color index).
    pub color: u8,
}

impl PositionAnnotation {
    pub fn new(position: TtdPosition, label: impl Into<String>) -> Self {
        Self { position, label: label.into(), description: None, color: 0 }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    #[must_use] 
    pub const fn with_color(mut self, color: u8) -> Self {
        self.color = color & 0x07;
        self
    }
}

impl fmt::Display for PositionAnnotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.position, self.label)?;
        if let Some(desc) = &self.description {
            write!(f, " — {desc}")?;
        }
        Ok(())
    }
}

// ─── AnnotationSet ────────────────────────────────────────────────────────────

/// A collection of position annotations, sorted by position.
#[derive(Debug, Clone, Default)]
pub struct AnnotationSet {
    annotations: Vec<PositionAnnotation>,
}

impl AnnotationSet {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an annotation.  Maintains sorted order.
    pub fn add(&mut self, ann: PositionAnnotation) {
        let idx = self.annotations.partition_point(|a| a.position <= ann.position);
        self.annotations.insert(idx, ann);
    }

    /// Find annotations at exactly `pos`.
    pub fn at(&self, pos: TtdPosition) -> impl Iterator<Item = &PositionAnnotation> {
        self.annotations.iter().filter(move |a| a.position == pos)
    }

    /// Find annotations in range `[lo, hi]`.
    pub fn in_range(
        &self,
        lo: TtdPosition,
        hi: TtdPosition,
    ) -> impl Iterator<Item = &PositionAnnotation> {
        let start = self.annotations.partition_point(|a| a.position < lo);
        let end = self.annotations.partition_point(|a| a.position <= hi);
        self.annotations[start..end].iter()
    }

    /// Remove all annotations at `pos`.
    pub fn remove_at(&mut self, pos: TtdPosition) {
        self.annotations.retain(|a| a.position != pos);
    }

    /// Total number of annotations.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.annotations.len()
    }

    /// True if empty.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }

    /// Iterate over all annotations in chronological order.
    pub fn iter(&self) -> impl Iterator<Item = &PositionAnnotation> {
        self.annotations.iter()
    }
}

// ─── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_same_sequence() {
        let a = TtdPosition::new(3, 10);
        let b = TtdPosition::new(3, 50);
        let d = PositionDistance::between(a, b);
        assert_eq!(d.sequence_delta, 0);
        assert_eq!(d.step_delta, 40);
        assert!(d.is_forward());
    }

    #[test]
    fn distance_backward() {
        let a = TtdPosition::new(5, 20);
        let b = TtdPosition::new(5, 5);
        let d = PositionDistance::between(a, b);
        assert!(d.is_backward());
    }

    #[test]
    fn range_contains() {
        let range = PositionRange::inclusive(
            TtdPosition::new(1, 0),
            TtdPosition::new(3, 0),
        );
        assert!(range.contains(TtdPosition::new(2, 100)));
        assert!(!range.contains(TtdPosition::new(0, 0)));
    }

    #[test]
    fn engine_seek_and_step() {
        let positions = vec![
            TtdPosition::new(0, 0),
            TtdPosition::new(1, 0),
            TtdPosition::new(2, 0),
            TtdPosition::new(5, 0),
        ];
        let mut engine = PositionEngine::new(positions).unwrap();
        engine.seek(TtdPosition::new(3, 0));
        assert_eq!(engine.current(), TtdPosition::new(2, 0));
        let next = engine.step_forward();
        assert_eq!(next, Some(TtdPosition::new(5, 0)));
    }

    #[test]
    fn serializer_round_trip() {
        let pos = TtdPosition::new(12345, 678);
        let s = PositionSerializer::to_string(pos);
        let back = PositionSerializer::from_string(&s).unwrap();
        assert_eq!(pos, back);
    }

    #[test]
    fn serializer_json_round_trip() {
        let pos = TtdPosition::new(99, 42);
        let json = PositionSerializer::to_json(pos);
        let back = PositionSerializer::from_json(&json).unwrap();
        assert_eq!(pos, back);
    }

    #[test]
    fn history_undo_redo() {
        let mut history = NavigationHistory::new(10);
        let p1 = TtdPosition::new(1, 0);
        let p2 = TtdPosition::new(2, 0);
        let p3 = TtdPosition::new(3, 0);
        history.push(p1);
        history.push(p2);
        history.push(p3);
        assert_eq!(history.current(), Some(p3));
        let prev = history.undo();
        assert_eq!(prev, Some(p2));
        let prev2 = history.undo();
        assert_eq!(prev2, Some(p1));
        let redo = history.redo();
        assert_eq!(redo, Some(p2));
    }

    #[test]
    fn annotation_set_range() {
        let mut set = AnnotationSet::new();
        set.add(PositionAnnotation::new(TtdPosition::new(1, 0), "a"));
        set.add(PositionAnnotation::new(TtdPosition::new(3, 0), "b"));
        set.add(PositionAnnotation::new(TtdPosition::new(5, 0), "c"));
        let results: Vec<_> = set
            .in_range(TtdPosition::new(2, 0), TtdPosition::new(4, 0))
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "b");
    }
}
