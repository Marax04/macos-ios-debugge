//! TTD position types: ordered `sequence:step` cursors, ranges, arithmetic, and sorted DB.
//!
//! A [`TtdPosition`] identifies a unique point in a Time-Travel Debug trace.
//! Positions are totally ordered: first by `sequence`, then by `step`.

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Sub};

use serde::{Deserialize, Serialize};

// ─── TtdPosition ──────────────────────────────────────────────────────────────

/// A position in a TTD trace, identified by a (sequence, step) pair.
///
/// The `sequence` number counts major "time slices" (typically one per thread
/// dispatch interval), and `step` counts individual recorded operations within
/// that slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TtdPosition {
    /// Major sequence number.
    pub sequence: u64,
    /// Minor step within the sequence.
    pub step: u64,
}

impl TtdPosition {
    /// The very beginning of any trace.
    pub const MIN: Self = Self {
        sequence: 0,
        step: 0,
    };
    /// The theoretical maximum position.
    pub const MAX: Self = Self {
        sequence: u64::MAX,
        step: u64::MAX,
    };

    /// Create a new position.
    #[must_use] 
    pub const fn new(sequence: u64, step: u64) -> Self {
        Self { sequence, step }
    }

    /// Parse from a `"sequence:step"` string.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::ParseError`] if `s` is not of the form
    /// `"sequence:step"` or if either component fails to parse as `u64`.
    pub fn parse(s: &str) -> Result<Self, PositionError> {
        let mut parts = s.splitn(2, ':');
        let seq_str = parts
            .next()
            .ok_or_else(|| PositionError::ParseError(s.to_string()))?;
        let step_str = parts
            .next()
            .ok_or_else(|| PositionError::ParseError(s.to_string()))?;
        let sequence = seq_str
            .trim()
            .parse::<u64>()
            .map_err(|_| PositionError::ParseError(s.to_string()))?;
        let step = step_str
            .trim()
            .parse::<u64>()
            .map_err(|_| PositionError::ParseError(s.to_string()))?;
        Ok(Self { sequence, step })
    }

    /// Advance by one step.
    #[must_use] 
    pub const fn next_step(self) -> Self {
        Self {
            sequence: self.sequence,
            step: self.step.saturating_add(1),
        }
    }

    /// Retreat by one step (saturating at step 0).
    #[must_use] 
    pub const fn prev_step(self) -> Self {
        Self {
            sequence: self.sequence,
            step: self.step.saturating_sub(1),
        }
    }

    /// Advance to the first step of the next sequence.
    #[must_use] 
    pub const fn next_sequence(self) -> Self {
        Self {
            sequence: self.sequence.saturating_add(1),
            step: 0,
        }
    }

    /// True if this is the very first position.
    #[must_use] 
    pub const fn is_start(&self) -> bool {
        self.sequence == 0 && self.step == 0
    }

    /// Absolute distance in steps from `other` (same sequence only).
    #[must_use] 
    pub const fn step_distance(self, other: Self) -> Option<u64> {
        if self.sequence != other.sequence {
            return None;
        }
        Some(self.step.abs_diff(other.step))
    }

    /// Convert to a flat 128-bit integer for compact serialization.
    #[must_use] 
    pub fn to_u128(self) -> u128 {
        (u128::from(self.sequence) << 64) | u128::from(self.step)
    }

    /// Reconstruct from a flat 128-bit integer.
    #[must_use] 
    pub fn from_u128(v: u128) -> Self {
        Self {
            sequence: u64::try_from(v >> 64).unwrap_or(u64::MAX),
            step: u64::try_from(v & u128::from(u64::MAX)).unwrap_or(u64::MAX),
        }
    }
}

impl PartialOrd for TtdPosition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TtdPosition {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sequence
            .cmp(&other.sequence)
            .then(self.step.cmp(&other.step))
    }
}

impl fmt::Display for TtdPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sequence, self.step)
    }
}

// ─── PositionError ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PositionError {
    ParseError(String),
    OutOfRange {
        pos: TtdPosition,
    },
    InvalidRange {
        start: TtdPosition,
        end: TtdPosition,
    },
    Overflow,
}

impl fmt::Display for PositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError(s) => write!(f, "cannot parse position: {s:?}"),
            Self::OutOfRange { pos } => write!(f, "position out of range: {pos}"),
            Self::InvalidRange { start, end } => {
                write!(f, "invalid range {start}..{end}: start > end")
            }
            Self::Overflow => write!(f, "position arithmetic overflow"),
        }
    }
}

impl std::error::Error for PositionError {}

// ─── PositionArithmetic ───────────────────────────────────────────────────────

/// Step offset for position arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StepOffset(pub i64);

impl StepOffset {
    #[must_use] 
    pub const fn forward(n: u64) -> Self {
        Self(n.cast_signed())
    }

    #[must_use] 
    pub const fn backward(n: u64) -> Self {
        Self(-n.cast_signed())
    }
}

impl Add<StepOffset> for TtdPosition {
    type Output = Result<Self, PositionError>;

    fn add(self, rhs: StepOffset) -> Self::Output {
        let new_step = i128::from(self.step) + i128::from(rhs.0);
        if new_step < 0 {
            return Err(PositionError::Overflow);
        }
        let new_step = u64::try_from(new_step).map_err(|_| PositionError::Overflow)?;
        Ok(Self {
            sequence: self.sequence,
            step: new_step,
        })
    }
}

impl Sub<Self> for TtdPosition {
    type Output = Option<StepOffset>;

    /// Returns the offset between two positions in the same sequence, or None.
    fn sub(self, rhs: Self) -> Self::Output {
        if self.sequence != rhs.sequence {
            return None;
        }
        let diff = i128::from(self.step) - i128::from(rhs.step);
        if diff.abs() > i128::from(i64::MAX) {
            return None;
        }
        Some(StepOffset(i64::try_from(diff).ok()?))
    }
}

// ─── TtdRange ─────────────────────────────────────────────────────────────────

/// A contiguous range of positions `[start, end]` within a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TtdRange {
    pub start: TtdPosition,
    pub end: TtdPosition,
}

impl TtdRange {
    /// Create a new range. Returns an error if start > end.
    ///
    /// # Errors
    ///
    /// Returns [`PositionError::InvalidRange`] if `start > end`.
    pub fn new(start: TtdPosition, end: TtdPosition) -> Result<Self, PositionError> {
        if start > end {
            return Err(PositionError::InvalidRange { start, end });
        }
        Ok(Self { start, end })
    }

    /// Create an unchecked range.
    #[must_use] 
    pub const fn new_unchecked(start: TtdPosition, end: TtdPosition) -> Self {
        Self { start, end }
    }

    /// Instantaneous range (single position).
    #[must_use] 
    pub const fn point(pos: TtdPosition) -> Self {
        Self {
            start: pos,
            end: pos,
        }
    }

    /// True if `pos` lies within this range (inclusive).
    #[must_use] 
    pub fn contains(&self, pos: TtdPosition) -> bool {
        pos >= self.start && pos <= self.end
    }

    /// True if this range overlaps with `other`.
    #[must_use] 
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Intersection of two ranges. Returns None if disjoint.
    #[must_use] 
    pub fn intersect(&self, other: &Self) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        if start <= end {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Merge two overlapping or adjacent ranges.
    #[must_use] 
    pub fn merge(&self, other: &Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }

    /// Number of sequences spanned.
    #[must_use] 
    pub const fn sequence_span(&self) -> u64 {
        self.end.sequence.saturating_sub(self.start.sequence)
    }
}

impl fmt::Display for TtdRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} .. {}]", self.start, self.end)
    }
}

// ─── PositionOrder ────────────────────────────────────────────────────────────

/// Utilities for reasoning about position ordering.
pub struct PositionOrder;

impl PositionOrder {
    /// True if `a` strictly precedes `b`.
    #[must_use] 
    pub fn comes_before(a: TtdPosition, b: TtdPosition) -> bool {
        a < b
    }

    /// True if `a` strictly follows `b`.
    #[must_use] 
    pub fn comes_after(a: TtdPosition, b: TtdPosition) -> bool {
        a > b
    }

    /// True if `a` and `b` are the same position.
    #[must_use] 
    pub fn same(a: TtdPosition, b: TtdPosition) -> bool {
        a == b
    }

    /// Sort a slice of positions in ascending order.
    pub fn sort(positions: &mut [TtdPosition]) {
        positions.sort();
    }

    /// Sort in descending order.
    pub fn sort_desc(positions: &mut [TtdPosition]) {
        positions.sort_by(|a, b| b.cmp(a));
    }

    /// Return the minimum of two positions.
    #[must_use] 
    pub fn min(a: TtdPosition, b: TtdPosition) -> TtdPosition {
        a.min(b)
    }

    /// Return the maximum of two positions.
    #[must_use] 
    pub fn max(a: TtdPosition, b: TtdPosition) -> TtdPosition {
        a.max(b)
    }
}

// ─── PositionFormatter ────────────────────────────────────────────────────────

/// Formats positions in various styles.
pub struct PositionFormatter {
    pub style: FormatStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatStyle {
    /// "seq:step"
    ColonSeparated,
    /// "seq.step"
    DotSeparated,
    /// "0xSEQ:0xSTEP" (hex)
    Hex,
    /// JSON {"sequence": N, "step": N}
    Json,
}

impl PositionFormatter {
    #[must_use] 
    pub const fn new(style: FormatStyle) -> Self {
        Self { style }
    }

    #[must_use] 
    pub fn format(&self, pos: TtdPosition) -> String {
        match self.style {
            FormatStyle::ColonSeparated => format!("{}:{}", pos.sequence, pos.step),
            FormatStyle::DotSeparated => format!("{}.{}", pos.sequence, pos.step),
            FormatStyle::Hex => format!("0x{:x}:0x{:x}", pos.sequence, pos.step),
            FormatStyle::Json => {
                format!(r#"{{"sequence":{},"step":{}}}"#, pos.sequence, pos.step)
            }
        }
    }

    #[must_use] 
    pub fn format_range(&self, r: TtdRange) -> String {
        format!("{} .. {}", self.format(r.start), self.format(r.end))
    }
}

impl Default for PositionFormatter {
    fn default() -> Self {
        Self::new(FormatStyle::ColonSeparated)
    }
}

// ─── PositionDb ───────────────────────────────────────────────────────────────

/// A sorted collection of positions supporting binary search and range queries.
#[derive(Debug, Default, Clone)]
pub struct PositionDb {
    /// Sorted list of positions (invariant: always sorted).
    positions: Vec<TtdPosition>,
}

impl PositionDb {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a position, maintaining sorted order.
    pub fn insert(&mut self, pos: TtdPosition) {
        let idx = self.positions.partition_point(|&p| p < pos);
        if self.positions.get(idx) != Some(&pos) {
            self.positions.insert(idx, pos);
        }
    }

    /// Insert many positions at once.
    pub fn insert_many(&mut self, positions: impl IntoIterator<Item = TtdPosition>) {
        for p in positions {
            self.insert(p);
        }
    }

    /// Look up a position by exact match.
    #[must_use] 
    pub fn contains(&self, pos: TtdPosition) -> bool {
        self.positions.binary_search(&pos).is_ok()
    }

    /// Find the largest position that is <= `pos` (floor).
    #[must_use] 
    pub fn floor(&self, pos: TtdPosition) -> Option<TtdPosition> {
        let idx = self.positions.partition_point(|&p| p <= pos);
        if idx == 0 {
            None
        } else {
            Some(self.positions[idx - 1])
        }
    }

    /// Find the smallest position that is >= `pos` (ceiling).
    #[must_use] 
    pub fn ceil(&self, pos: TtdPosition) -> Option<TtdPosition> {
        let idx = self.positions.partition_point(|&p| p < pos);
        self.positions.get(idx).copied()
    }

    /// All positions within a range (inclusive).
    #[must_use] 
    pub fn in_range(&self, range: TtdRange) -> &[TtdPosition] {
        let start = self.positions.partition_point(|&p| p < range.start);
        let end = self.positions.partition_point(|&p| p <= range.end);
        &self.positions[start..end]
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.positions.len()
    }

    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    #[must_use] 
    pub fn min(&self) -> Option<TtdPosition> {
        self.positions.first().copied()
    }

    #[must_use] 
    pub fn max(&self) -> Option<TtdPosition> {
        self.positions.last().copied()
    }

    #[must_use] 
    pub fn positions(&self) -> &[TtdPosition] {
        &self.positions
    }

    /// Remove a position if present.
    pub fn remove(&mut self, pos: TtdPosition) -> bool {
        if let Ok(idx) = self.positions.binary_search(&pos) {
            self.positions.remove(idx);
            true
        } else {
            false
        }
    }

    /// Rank (0-based index) of a position in the sorted list.
    #[must_use] 
    pub fn rank(&self, pos: TtdPosition) -> Option<usize> {
        self.positions.binary_search(&pos).ok()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_ordering() {
        let a = TtdPosition::new(1, 5);
        let b = TtdPosition::new(1, 10);
        let c = TtdPosition::new(2, 0);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn test_position_equal() {
        let a = TtdPosition::new(3, 7);
        let b = TtdPosition::new(3, 7);
        assert_eq!(a, b);
    }

    #[test]
    fn test_position_parse() {
        let p = TtdPosition::parse("42:100").unwrap();
        assert_eq!(p.sequence, 42);
        assert_eq!(p.step, 100);
    }

    #[test]
    fn test_position_parse_error() {
        assert!(TtdPosition::parse("not-a-position").is_err());
        assert!(TtdPosition::parse("1:abc").is_err());
    }

    #[test]
    fn test_position_display() {
        let p = TtdPosition::new(5, 20);
        assert_eq!(p.to_string(), "5:20");
    }

    #[test]
    fn test_position_next_step() {
        let p = TtdPosition::new(1, 9);
        assert_eq!(p.next_step(), TtdPosition::new(1, 10));
    }

    #[test]
    fn test_position_prev_step() {
        let p = TtdPosition::new(2, 1);
        assert_eq!(p.prev_step(), TtdPosition::new(2, 0));
    }

    #[test]
    fn test_position_prev_step_saturate() {
        let p = TtdPosition::new(1, 0);
        assert_eq!(p.prev_step(), TtdPosition::new(1, 0));
    }

    #[test]
    fn test_position_next_sequence() {
        let p = TtdPosition::new(3, 99);
        assert_eq!(p.next_sequence(), TtdPosition::new(4, 0));
    }

    #[test]
    fn test_position_to_from_u128() {
        let p = TtdPosition::new(0xABCD, 0x1234);
        assert_eq!(TtdPosition::from_u128(p.to_u128()), p);
    }

    #[test]
    fn test_step_offset_add() {
        let p = TtdPosition::new(1, 5);
        let result = (p + StepOffset::forward(3)).unwrap();
        assert_eq!(result, TtdPosition::new(1, 8));
    }

    #[test]
    fn test_step_offset_sub() {
        let p = TtdPosition::new(1, 10);
        let result = (p + StepOffset::backward(3)).unwrap();
        assert_eq!(result, TtdPosition::new(1, 7));
    }

    #[test]
    fn test_step_offset_overflow() {
        let p = TtdPosition::new(1, 0);
        let result = p + StepOffset::backward(1);
        assert!(result.is_err());
    }

    #[test]
    fn test_ttd_range_contains() {
        let r = TtdRange::new(TtdPosition::new(1, 0), TtdPosition::new(1, 100)).unwrap();
        assert!(r.contains(TtdPosition::new(1, 50)));
        assert!(r.contains(TtdPosition::new(1, 0)));
        assert!(r.contains(TtdPosition::new(1, 100)));
        assert!(!r.contains(TtdPosition::new(1, 101)));
    }

    #[test]
    fn test_ttd_range_overlaps() {
        let r1 = TtdRange::new_unchecked(TtdPosition::new(1, 0), TtdPosition::new(1, 50));
        let r2 = TtdRange::new_unchecked(TtdPosition::new(1, 30), TtdPosition::new(1, 80));
        assert!(r1.overlaps(&r2));
    }

    #[test]
    fn test_ttd_range_no_overlap() {
        let r1 = TtdRange::new_unchecked(TtdPosition::new(1, 0), TtdPosition::new(1, 20));
        let r2 = TtdRange::new_unchecked(TtdPosition::new(1, 30), TtdPosition::new(1, 50));
        assert!(!r1.overlaps(&r2));
    }

    #[test]
    fn test_ttd_range_intersect() {
        let r1 = TtdRange::new_unchecked(TtdPosition::new(0, 0), TtdPosition::new(0, 50));
        let r2 = TtdRange::new_unchecked(TtdPosition::new(0, 30), TtdPosition::new(0, 80));
        let i = r1.intersect(&r2).unwrap();
        assert_eq!(i.start, TtdPosition::new(0, 30));
        assert_eq!(i.end, TtdPosition::new(0, 50));
    }

    #[test]
    fn test_ttd_range_invalid() {
        let r = TtdRange::new(TtdPosition::new(1, 10), TtdPosition::new(1, 5));
        assert!(r.is_err());
    }

    #[test]
    fn test_position_order_comes_before() {
        let a = TtdPosition::new(1, 5);
        let b = TtdPosition::new(1, 10);
        assert!(PositionOrder::comes_before(a, b));
        assert!(!PositionOrder::comes_before(b, a));
    }

    #[test]
    fn test_position_formatter_colon() {
        let f = PositionFormatter::new(FormatStyle::ColonSeparated);
        assert_eq!(f.format(TtdPosition::new(3, 7)), "3:7");
    }

    #[test]
    fn test_position_formatter_dot() {
        let f = PositionFormatter::new(FormatStyle::DotSeparated);
        assert_eq!(f.format(TtdPosition::new(3, 7)), "3.7");
    }

    #[test]
    fn test_position_formatter_hex() {
        let f = PositionFormatter::new(FormatStyle::Hex);
        let s = f.format(TtdPosition::new(16, 255));
        assert!(s.contains("0x10") && s.contains("0xff"));
    }

    #[test]
    fn test_position_formatter_json() {
        let f = PositionFormatter::new(FormatStyle::Json);
        let s = f.format(TtdPosition::new(1, 2));
        assert!(s.contains("\"sequence\":1") && s.contains("\"step\":2"));
    }

    #[test]
    fn test_position_db_insert_and_contains() {
        let mut db = PositionDb::new();
        db.insert(TtdPosition::new(1, 5));
        db.insert(TtdPosition::new(0, 3));
        assert!(db.contains(TtdPosition::new(1, 5)));
        assert!(!db.contains(TtdPosition::new(1, 6)));
    }

    #[test]
    fn test_position_db_sorted() {
        let mut db = PositionDb::new();
        db.insert(TtdPosition::new(2, 0));
        db.insert(TtdPosition::new(0, 10));
        db.insert(TtdPosition::new(1, 5));
        let pos = db.positions();
        assert!(pos.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn test_position_db_floor() {
        let mut db = PositionDb::new();
        db.insert_many([
            TtdPosition::new(0, 0),
            TtdPosition::new(0, 5),
            TtdPosition::new(0, 10),
        ]);
        assert_eq!(
            db.floor(TtdPosition::new(0, 7)),
            Some(TtdPosition::new(0, 5))
        );
    }

    #[test]
    fn test_position_db_ceil() {
        let mut db = PositionDb::new();
        db.insert_many([
            TtdPosition::new(0, 0),
            TtdPosition::new(0, 5),
            TtdPosition::new(0, 10),
        ]);
        assert_eq!(
            db.ceil(TtdPosition::new(0, 7)),
            Some(TtdPosition::new(0, 10))
        );
    }

    #[test]
    fn test_position_db_in_range() {
        let mut db = PositionDb::new();
        for i in 0..20u64 {
            db.insert(TtdPosition::new(0, i));
        }
        let r = TtdRange::new_unchecked(TtdPosition::new(0, 5), TtdPosition::new(0, 10));
        let found = db.in_range(r);
        assert_eq!(found.len(), 6); // 5, 6, 7, 8, 9, 10
    }

    #[test]
    fn test_position_db_remove() {
        let mut db = PositionDb::new();
        db.insert(TtdPosition::new(1, 1));
        assert!(db.remove(TtdPosition::new(1, 1)));
        assert!(!db.contains(TtdPosition::new(1, 1)));
    }

    #[test]
    fn test_position_db_no_duplicates() {
        let mut db = PositionDb::new();
        db.insert(TtdPosition::new(0, 5));
        db.insert(TtdPosition::new(0, 5));
        assert_eq!(db.len(), 1);
    }
}

// ─── PositionWindow ───────────────────────────────────────────────────────────

/// A sliding window of N positions used for replay cursoring.
#[derive(Debug, Clone)]
pub struct PositionWindow {
    positions: std::collections::VecDeque<TtdPosition>,
    capacity: usize,
}

impl PositionWindow {
    #[must_use] 
    pub fn new(capacity: usize) -> Self {
        Self {
            positions: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, pos: TtdPosition) {
        if self.positions.len() == self.capacity {
            self.positions.pop_front();
        }
        self.positions.push_back(pos);
    }

    #[must_use] 
    pub fn oldest(&self) -> Option<TtdPosition> {
        self.positions.front().copied()
    }
    #[must_use] 
    pub fn newest(&self) -> Option<TtdPosition> {
        self.positions.back().copied()
    }
    #[must_use] 
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Returns `true` when [`len`](Self::len) is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    #[must_use] 
    pub fn is_full(&self) -> bool {
        self.positions.len() == self.capacity
    }

    #[must_use] 
    pub fn span(&self) -> Option<TtdRange> {
        let start = self.oldest()?;
        let end = self.newest()?;
        TtdRange::new(start, end).ok()
    }
}

// ─── PositionCheckpoint ───────────────────────────────────────────────────────

/// A named snapshot of a TTD position for quick navigation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PositionCheckpoint {
    pub name: String,
    pub position: TtdPosition,
    pub note: String,
    pub timestamp_secs: u64,
}

impl PositionCheckpoint {
    #[must_use] 
    pub fn new(name: &str, position: TtdPosition) -> Self {
        let timestamp_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            name: name.to_string(),
            position,
            note: String::new(),
            timestamp_secs,
        }
    }

    #[must_use] 
    pub fn with_note(mut self, note: &str) -> Self {
        self.note = note.to_string();
        self
    }
}

/// Ordered collection of position checkpoints.
#[derive(Debug, Default)]
pub struct CheckpointList {
    checkpoints: Vec<PositionCheckpoint>,
}

impl CheckpointList {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, cp: PositionCheckpoint) {
        self.checkpoints.push(cp);
    }

    #[must_use] 
    pub fn find(&self, name: &str) -> Option<&PositionCheckpoint> {
        self.checkpoints.iter().find(|c| c.name == name)
    }

    #[must_use] 
    pub fn nearest_before(&self, pos: TtdPosition) -> Option<&PositionCheckpoint> {
        self.checkpoints
            .iter()
            .filter(|c| c.position <= pos)
            .max_by_key(|c| c.position)
    }

    #[must_use] 
    pub const fn len(&self) -> usize {
        self.checkpoints.len()
    }
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_position_window_push_evicts() {
        let mut w = PositionWindow::new(3);
        w.push(TtdPosition::new(0, 1));
        w.push(TtdPosition::new(0, 2));
        w.push(TtdPosition::new(0, 3));
        assert!(w.is_full());
        w.push(TtdPosition::new(0, 4));
        assert_eq!(w.oldest(), Some(TtdPosition::new(0, 2)));
    }

    #[test]
    fn test_position_window_newest() {
        let mut w = PositionWindow::new(5);
        w.push(TtdPosition::new(0, 1));
        w.push(TtdPosition::new(0, 9));
        assert_eq!(w.newest(), Some(TtdPosition::new(0, 9)));
    }

    #[test]
    fn test_position_window_span() {
        let mut w = PositionWindow::new(5);
        w.push(TtdPosition::new(0, 0));
        w.push(TtdPosition::new(0, 10));
        let span = w.span().unwrap();
        assert_eq!(span.start, TtdPosition::new(0, 0));
        assert_eq!(span.end, TtdPosition::new(0, 10));
    }

    #[test]
    fn test_checkpoint_create() {
        let cp = PositionCheckpoint::new("bp1", TtdPosition::new(5, 100)).with_note("main entry");
        assert_eq!(cp.name, "bp1");
        assert_eq!(cp.note, "main entry");
        assert_eq!(cp.position, TtdPosition::new(5, 100));
    }

    #[test]
    fn test_checkpoint_list_find() {
        let mut list = CheckpointList::new();
        list.add(PositionCheckpoint::new("a", TtdPosition::new(0, 5)));
        list.add(PositionCheckpoint::new("b", TtdPosition::new(0, 10)));
        assert!(list.find("a").is_some());
        assert!(list.find("c").is_none());
    }

    #[test]
    fn test_checkpoint_list_nearest_before() {
        let mut list = CheckpointList::new();
        list.add(PositionCheckpoint::new("early", TtdPosition::new(0, 5)));
        list.add(PositionCheckpoint::new("mid", TtdPosition::new(0, 20)));
        list.add(PositionCheckpoint::new("late", TtdPosition::new(0, 50)));
        let found = list.nearest_before(TtdPosition::new(0, 25)).unwrap();
        assert_eq!(found.name, "mid");
    }

    #[test]
    fn test_position_db_min_max() {
        let mut db = PositionDb::new();
        db.insert(TtdPosition::new(3, 99));
        db.insert(TtdPosition::new(0, 0));
        db.insert(TtdPosition::new(1, 50));
        assert_eq!(db.min(), Some(TtdPosition::new(0, 0)));
        assert_eq!(db.max(), Some(TtdPosition::new(3, 99)));
    }

    #[test]
    fn test_position_db_rank() {
        let mut db = PositionDb::new();
        db.insert(TtdPosition::new(0, 0));
        db.insert(TtdPosition::new(0, 5));
        db.insert(TtdPosition::new(0, 10));
        assert_eq!(db.rank(TtdPosition::new(0, 5)), Some(1));
    }

    #[test]
    fn test_range_merge() {
        let r1 = TtdRange::new_unchecked(TtdPosition::new(0, 0), TtdPosition::new(0, 10));
        let r2 = TtdRange::new_unchecked(TtdPosition::new(0, 5), TtdPosition::new(0, 20));
        let merged = r1.merge(&r2);
        assert_eq!(merged.start, TtdPosition::new(0, 0));
        assert_eq!(merged.end, TtdPosition::new(0, 20));
    }

    #[test]
    fn test_step_offset_subtraction() {
        let a = TtdPosition::new(0, 10);
        let b = TtdPosition::new(0, 4);
        let diff = (a - b).unwrap();
        assert_eq!(diff.0, 6);
    }

    #[test]
    fn test_position_min_max_constants() {
        assert!(TtdPosition::MIN < TtdPosition::MAX);
        assert_eq!(TtdPosition::MIN, TtdPosition::new(0, 0));
    }

    #[test]
    fn test_position_order_sort() {
        let mut v = vec![
            TtdPosition::new(2, 0),
            TtdPosition::new(0, 99),
            TtdPosition::new(1, 1),
        ];
        PositionOrder::sort(&mut v);
        assert!(v.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn test_position_order_sort_desc() {
        let mut v = vec![
            TtdPosition::new(0, 1),
            TtdPosition::new(0, 5),
            TtdPosition::new(0, 3),
        ];
        PositionOrder::sort_desc(&mut v);
        assert!(v.windows(2).all(|w| w[0] > w[1]));
    }

    #[test]
    fn test_position_formatter_range() {
        let f = PositionFormatter::new(FormatStyle::ColonSeparated);
        let r = TtdRange::new_unchecked(TtdPosition::new(1, 0), TtdPosition::new(2, 5));
        let s = f.format_range(r);
        assert!(s.contains("1:0"));
        assert!(s.contains("2:5"));
    }

    #[test]
    fn test_position_to_u128_roundtrip_zero() {
        let p = TtdPosition::new(0, 0);
        assert_eq!(TtdPosition::from_u128(p.to_u128()), p);
    }

    #[test]
    fn test_position_is_start() {
        assert!(TtdPosition::MIN.is_start());
        assert!(!TtdPosition::new(0, 1).is_start());
    }

    #[test]
    fn test_position_step_distance_same_seq() {
        let a = TtdPosition::new(3, 10);
        let b = TtdPosition::new(3, 4);
        assert_eq!(a.step_distance(b), Some(6));
    }

    #[test]
    fn test_position_step_distance_different_seq() {
        let a = TtdPosition::new(1, 10);
        let b = TtdPosition::new(2, 5);
        assert_eq!(a.step_distance(b), None);
    }

    #[test]
    fn test_checkpoint_list_is_empty() {
        let list = CheckpointList::new();
        assert!(list.is_empty());
    }

    #[test]
    fn test_position_window_empty_span() {
        let w = PositionWindow::new(5);
        assert!(w.span().is_none());
    }
}
