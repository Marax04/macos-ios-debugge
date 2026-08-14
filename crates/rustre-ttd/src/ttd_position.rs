//! TTD position management: `sequence:steps` format, arithmetic, comparison,
//! ordering, ranges and deltas.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

// ─── TtdPosition ─────────────────────────────────────────────────────────────

/// A precise location in a TTD trace expressed as a `sequence:step` pair.
///
/// `sequence` monotonically increases with each recorded instruction (across
/// all threads).  `step` disambiguates multiple events that share the same
/// sequence number (e.g. multiple memory accesses within one instruction).
///
/// Positions are totally ordered: sequence comes first, then step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TtdPosition {
    /// Primary instruction sequence counter.
    pub sequence: u64,
    /// Sub-step within that instruction.
    pub step: u32,
}

impl TtdPosition {
    /// The position at the very beginning of a trace.
    pub const START: Self = Self { sequence: 0, step: 0 };

    /// The maximum representable position.
    pub const MAX: Self = Self {
        sequence: u64::MAX,
        step: u32::MAX,
    };

    /// Create a new `TtdPosition`.
    #[inline]
    #[must_use] 
    pub const fn new(sequence: u64, step: u32) -> Self {
        Self { sequence, step }
    }

    /// Create a position at the start of sequence `seq` (step = 0).
    #[inline]
    #[must_use] 
    pub const fn at_sequence(seq: u64) -> Self {
        Self::new(seq, 0)
    }

    /// Return `true` if this is the start position.
    #[inline]
    #[must_use] 
    pub fn is_start(&self) -> bool {
        *self == Self::START
    }

    /// Return the next step within the same sequence.
    ///
    /// If `step` is `u32::MAX`, saturates and returns the start of the next
    /// sequence instead.
    #[inline]
    #[must_use] 
    pub const fn next_step(&self) -> Self {
        if self.step == u32::MAX {
            Self::new(self.sequence.saturating_add(1), 0)
        } else {
            Self::new(self.sequence, self.step + 1)
        }
    }

    /// Return the start of the next sequence (step resets to 0).
    #[inline]
    #[must_use] 
    pub const fn next_sequence(&self) -> Self {
        Self::new(self.sequence.saturating_add(1), 0)
    }

    /// Return the start of the previous sequence, or `START` if already at 0.
    #[inline]
    #[must_use] 
    pub const fn prev_sequence(&self) -> Self {
        if self.sequence == 0 {
            Self::START
        } else {
            Self::new(self.sequence - 1, 0)
        }
    }

    /// Encode as a `u128` for compact storage: upper 64 bits = sequence,
    /// lower 32 bits = step (upper 32 bits of the lower half are zero).
    #[inline]
    #[must_use] 
    pub fn as_u128(self) -> u128 {
        (u128::from(self.sequence) << 64) | u128::from(self.step)
    }

    /// Reconstruct from a value returned by [`Self::as_u128`].
    #[inline]
    #[must_use] 
    pub fn from_u128(v: u128) -> Self {
        let sequence = u64::try_from(v >> 64).unwrap_or(u64::MAX);
        let step = u32::try_from(v & u128::from(u32::MAX)).unwrap_or(u32::MAX);
        Self::new(sequence, step)
    }

    /// Return `true` if this position is strictly before `other`.
    #[inline]
    #[must_use] 
    pub fn is_before(&self, other: &Self) -> bool {
        self < other
    }

    /// Return `true` if this position is strictly after `other`.
    #[inline]
    #[must_use] 
    pub fn is_after(&self, other: &Self) -> bool {
        self > other
    }

    /// Return `true` if `self` is in the half-open range `[start, end)`.
    #[inline]
    #[must_use] 
    pub fn in_range(&self, start: &Self, end: &Self) -> bool {
        self >= start && self < end
    }

    /// Return `true` if `self` is in the closed range `[start, end]`.
    #[inline]
    #[must_use] 
    pub fn in_range_inclusive(&self, start: &Self, end: &Self) -> bool {
        self >= start && self <= end
    }

    /// Compute a saturating addition of `delta.steps` to this position.
    /// Sequence wraps when `step` overflows.
    #[must_use] 
    pub fn saturating_add_delta(&self, delta: PositionDelta) -> Self {
        if delta.steps == 0 {
            return *self;
        }
        let new_step = u64::from(self.step) + delta.steps;
        let extra_seq = new_step / (u64::from(u32::MAX) + 1);
        let step_rem = u32::try_from(new_step % (u64::from(u32::MAX) + 1)).unwrap_or(u32::MAX);
        let new_seq = self.sequence.saturating_add(extra_seq);
        Self::new(new_seq, step_rem)
    }

    /// Parse `"seq:step"` notation, e.g. `"123:4"`.
    ///
    /// # Errors
    ///
    /// Returns a [`ParsePositionError`] if the format is invalid.
    pub fn parse(s: &str) -> Result<Self, ParsePositionError> {
        let (seq_str, step_str) = s
            .split_once(':')
            .ok_or_else(|| ParsePositionError::InvalidFormat(s.to_owned()))?;
        let sequence = seq_str
            .trim()
            .parse::<u64>()
            .map_err(|_| ParsePositionError::InvalidNumber(seq_str.to_owned()))?;
        let step = step_str
            .trim()
            .parse::<u32>()
            .map_err(|_| ParsePositionError::InvalidNumber(step_str.to_owned()))?;
        Ok(Self::new(sequence, step))
    }
}

impl Ord for TtdPosition {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.sequence
            .cmp(&other.sequence)
            .then(self.step.cmp(&other.step))
    }
}

impl PartialOrd for TtdPosition {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Default for TtdPosition {
    fn default() -> Self {
        Self::START
    }
}

impl fmt::Display for TtdPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sequence, self.step)
    }
}

impl FromStr for TtdPosition {
    type Err = ParsePositionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Error returned when parsing a `TtdPosition` from a string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePositionError {
    /// The string did not contain a `':'` separator.
    InvalidFormat(String),
    /// One of the numeric fields could not be parsed.
    InvalidNumber(String),
}

impl fmt::Display for ParsePositionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(s) => write!(f, "invalid position format: {s:?} (expected 'seq:step')"),
            Self::InvalidNumber(s) => write!(f, "invalid number in position: {s:?}"),
        }
    }
}

// ─── PositionDelta ────────────────────────────────────────────────────────────

/// A signed difference between two `TtdPosition`s, expressed in total steps.
///
/// Positive = forward in time; negative = backward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PositionDelta {
    /// Number of sub-steps; positive = forward, negative = backward.
    pub steps: u64,
    /// Direction: `true` = forward, `false` = backward.
    pub forward: bool,
}

impl PositionDelta {
    /// Create a zero delta.
    pub const ZERO: Self = Self { steps: 0, forward: true };

    /// Create a forward delta of `n` steps.
    #[must_use] 
    pub const fn forward(n: u64) -> Self {
        Self { steps: n, forward: true }
    }

    /// Create a backward delta of `n` steps.
    #[must_use] 
    pub const fn backward(n: u64) -> Self {
        Self { steps: n, forward: false }
    }

    /// Return `true` if the delta is zero.
    #[must_use] 
    pub const fn is_zero(&self) -> bool {
        self.steps == 0
    }

    /// Return the absolute magnitude in steps.
    #[must_use] 
    pub const fn magnitude(&self) -> u64 {
        self.steps
    }
}

impl fmt::Display for PositionDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.forward {
            write!(f, "+{}", self.steps)
        } else {
            write!(f, "-{}", self.steps)
        }
    }
}

/// Compute the delta between two positions as a `PositionDelta`.
///
/// The delta is measured in combined step units:
/// `total_steps = sequence * 2^32 + step` (approximate).
#[must_use] 
pub fn position_delta(from: TtdPosition, to: TtdPosition) -> PositionDelta {
    // Combined step count: sequence contributes 2^32 units (one full step range)
    // so that a sequence increment of 1 yields a non-zero delta when truncated
    // to u64. This matches the documented `total_steps = sequence * 2^32 + step`.
    let from_u = (u128::from(from.sequence) << 32) | u128::from(from.step);
    let to_u = (u128::from(to.sequence) << 32) | u128::from(to.step);
    if to_u >= from_u {
        PositionDelta::forward(u64::try_from(to_u - from_u).unwrap_or(u64::MAX))
    } else {
        PositionDelta::backward(u64::try_from(from_u - to_u).unwrap_or(u64::MAX))
    }
}

// ─── PositionRange ────────────────────────────────────────────────────────────

/// A half-open interval `[start, end)` over TTD positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PositionRange {
    /// Inclusive start of the range.
    pub start: TtdPosition,
    /// Exclusive end of the range.
    pub end: TtdPosition,
}

impl PositionRange {
    /// Create a new `PositionRange`.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `start > end`.
    #[must_use] 
    pub fn new(start: TtdPosition, end: TtdPosition) -> Self {
        debug_assert!(start <= end, "PositionRange: start must be <= end");
        Self { start, end }
    }

    /// Create a range covering a single sequence number.
    #[must_use] 
    pub const fn single_sequence(seq: u64) -> Self {
        Self {
            start: TtdPosition::at_sequence(seq),
            end: TtdPosition::at_sequence(seq + 1),
        }
    }

    /// Create a range starting at `start` and spanning `n` sequences forward.
    #[must_use] 
    pub const fn from_span(start: TtdPosition, n_sequences: u64) -> Self {
        let end = TtdPosition::at_sequence(start.sequence.saturating_add(n_sequences));
        Self { start, end }
    }

    /// Return `true` if `pos` is contained in `[start, end)`.
    #[must_use] 
    pub fn contains(&self, pos: TtdPosition) -> bool {
        pos >= self.start && pos < self.end
    }

    /// Return `true` if this range contains no positions.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Return the number of full sequences covered.
    #[must_use] 
    pub const fn sequence_count(&self) -> u64 {
        self.end.sequence.saturating_sub(self.start.sequence)
    }

    /// Return `true` if `other` overlaps with `self` (half-open semantics).
    #[must_use] 
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Return the intersection of `self` and `other`, or `None` if disjoint.
    #[must_use] 
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        let lo = self.start.max(other.start);
        let hi = self.end.min(other.end);
        if lo < hi { Some(Self { start: lo, end: hi }) } else { None }
    }

    /// Split the range at `pos`, returning `(before, after)` where `before` is
    /// `[start, pos)` and `after` is `[pos, end)`.  Returns `None` for the
    /// respective half when `pos` is outside the range.
    #[must_use] 
    pub fn split_at(&self, pos: TtdPosition) -> (Option<Self>, Option<Self>) {
        let before = if pos > self.start {
            Some(Self { start: self.start, end: pos.min(self.end) })
        } else {
            None
        };
        let after = if pos < self.end {
            Some(Self { start: pos.max(self.start), end: self.end })
        } else {
            None
        };
        (before, after)
    }
}

impl fmt::Display for PositionRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}

// ─── Ordering helpers ─────────────────────────────────────────────────────────

/// Return the minimum of two positions.
#[must_use] 
pub fn position_min(a: TtdPosition, b: TtdPosition) -> TtdPosition {
    a.min(b)
}

/// Return the maximum of two positions.
#[must_use] 
pub fn position_max(a: TtdPosition, b: TtdPosition) -> TtdPosition {
    a.max(b)
}

/// Sort a slice of positions in-place (ascending).
pub fn sort_positions(positions: &mut [TtdPosition]) {
    positions.sort_unstable();
}

/// Return the earliest position in a slice, or `None` if empty.
#[must_use] 
pub fn earliest(positions: &[TtdPosition]) -> Option<TtdPosition> {
    positions.iter().copied().min()
}

/// Return the latest position in a slice, or `None` if empty.
#[must_use] 
pub fn latest(positions: &[TtdPosition]) -> Option<TtdPosition> {
    positions.iter().copied().max()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering() {
        let a = TtdPosition::new(1, 0);
        let b = TtdPosition::new(1, 5);
        let c = TtdPosition::new(2, 0);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
        assert!(c > a);
    }

    #[test]
    fn test_is_start() {
        assert!(TtdPosition::START.is_start());
        assert!(!TtdPosition::new(0, 1).is_start());
    }

    #[test]
    fn test_next_step_no_overflow() {
        let p = TtdPosition::new(5, 3);
        assert_eq!(p.next_step(), TtdPosition::new(5, 4));
    }

    #[test]
    fn test_next_step_overflow_wraps_to_next_sequence() {
        let p = TtdPosition::new(5, u32::MAX);
        assert_eq!(p.next_step(), TtdPosition::new(6, 0));
    }

    #[test]
    fn test_next_sequence() {
        let p = TtdPosition::new(10, 7);
        assert_eq!(p.next_sequence(), TtdPosition::new(11, 0));
    }

    #[test]
    fn test_prev_sequence_no_underflow() {
        let p = TtdPosition::START;
        assert_eq!(p.prev_sequence(), TtdPosition::START);
    }

    #[test]
    fn test_as_u128_roundtrip() {
        let p = TtdPosition::new(0xdead_beef, 0xcafe);
        assert_eq!(TtdPosition::from_u128(p.as_u128()), p);
    }

    #[test]
    fn test_display_format() {
        let p = TtdPosition::new(42, 7);
        assert_eq!(p.to_string(), "42:7");
    }

    #[test]
    fn test_parse_roundtrip() {
        let p = TtdPosition::new(100, 5);
        let s = p.to_string();
        let parsed: TtdPosition = s.parse().unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn test_parse_bad_format() {
        assert!(TtdPosition::parse("no_colon").is_err());
        assert!(TtdPosition::parse("abc:def").is_err());
    }

    #[test]
    fn test_in_range() {
        let p = TtdPosition::new(5, 3);
        let start = TtdPosition::new(5, 0);
        let end = TtdPosition::new(5, 10);
        assert!(p.in_range(&start, &end));
        assert!(!p.in_range(&end, &TtdPosition::new(10, 0)));
    }

    #[test]
    fn test_position_range_contains() {
        let r = PositionRange::new(TtdPosition::new(3, 0), TtdPosition::new(7, 0));
        assert!(r.contains(TtdPosition::new(5, 0)));
        assert!(!r.contains(TtdPosition::new(7, 0)));
        assert!(!r.contains(TtdPosition::new(2, 99)));
    }

    #[test]
    fn test_position_range_overlaps() {
        let r1 = PositionRange::new(TtdPosition::new(0, 0), TtdPosition::new(10, 0));
        let r2 = PositionRange::new(TtdPosition::new(5, 0), TtdPosition::new(15, 0));
        let r3 = PositionRange::new(TtdPosition::new(10, 0), TtdPosition::new(20, 0));
        assert!(r1.overlaps(&r2));
        assert!(!r1.overlaps(&r3));
    }

    #[test]
    fn test_intersection() {
        let r1 = PositionRange::new(TtdPosition::new(0, 0), TtdPosition::new(10, 0));
        let r2 = PositionRange::new(TtdPosition::new(5, 0), TtdPosition::new(15, 0));
        let inter = r1.intersection(&r2).unwrap();
        assert_eq!(inter.start, TtdPosition::new(5, 0));
        assert_eq!(inter.end, TtdPosition::new(10, 0));
    }

    #[test]
    fn test_position_delta_forward() {
        let a = TtdPosition::new(2, 0);
        let b = TtdPosition::new(3, 0);
        let d = position_delta(a, b);
        assert!(d.forward);
        assert!(d.steps > 0);
    }

    #[test]
    fn test_position_delta_backward() {
        let a = TtdPosition::new(5, 0);
        let b = TtdPosition::new(3, 0);
        let d = position_delta(a, b);
        assert!(!d.forward);
        assert!(d.steps > 0);
    }

    #[test]
    fn test_sort_positions() {
        let mut v = vec![
            TtdPosition::new(3, 0),
            TtdPosition::new(1, 5),
            TtdPosition::new(1, 2),
        ];
        sort_positions(&mut v);
        assert_eq!(v[0], TtdPosition::new(1, 2));
        assert_eq!(v[1], TtdPosition::new(1, 5));
        assert_eq!(v[2], TtdPosition::new(3, 0));
    }
}
